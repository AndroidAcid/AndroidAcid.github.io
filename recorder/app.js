// Acid Recorder PWA (Waveform + Session labels + Hold-to-record)
// Records WAV by capturing processed PCM (compressor + presence shelf EQ) through an AudioWorklet.

const btnStart = document.getElementById("btnStart");
const btnStop  = document.getElementById("btnStop");
const btnSave  = document.getElementById("btnSave");
const btnHold  = document.getElementById("btnHold");

const statusText = document.getElementById("statusText");
const timeText = document.getElementById("timeText");
const levelBar = document.getElementById("levelBar");
const srTag = document.getElementById("srTag");

const sessionLabelInput = document.getElementById("sessionLabel");
const nameTag = document.getElementById("nameTag");

const scope = document.getElementById("scope");
const sctx = scope.getContext("2d", { alpha: true });

let stream = null;
let ctx = null;
let source = null;
let compressor = null;
let shelf = null;
let analyser = null;
let workletNode = null;

let recording = false;
let startAt = 0;
let rafId = 0;
let timerId = 0;

let chunks = [];          // Array<Float32Array>
let recordedSamples = 0;  // total frames
let sampleRate = 48000;

let holdActive = false;

const pad2 = (n) => String(n).padStart(2, "0");

function setUI(state){
  if (state === "idle"){
    btnStart.disabled = false;
    btnStop.disabled = true;
    btnSave.disabled = true;
    btnHold.classList.remove("isRecording");
  } else if (state === "recording"){
    btnStart.disabled = true;
    btnStop.disabled = false;
    btnSave.disabled = true;
    btnHold.classList.add("isRecording");
  } else if (state === "stopped"){
    btnStart.disabled = false;
    btnStop.disabled = true;
    btnSave.disabled = false;
    btnHold.classList.remove("isRecording");
  }
}

function setStatus(msg){ statusText.textContent = msg; }

function updateTimer(){
  const sec = Math.floor((performance.now() - startAt) / 1000);
  const mm = Math.floor(sec / 60);
  const ss = sec % 60;
  timeText.textContent = `${pad2(mm)}:${pad2(ss)}`;
}

function sanitizeLabel(label){
  // safe for filenames
  return (label || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "_")
    .replace(/[^a-z0-9_-]/g, "")
    .slice(0, 40);
}

function buildSuggestedName(){
  const label = sanitizeLabel(sessionLabelInput.value);
  const ts = new Date();
  const stamp =
    ts.getFullYear() + "-" +
    String(ts.getMonth()+1).padStart(2,"0") + "-" +
    String(ts.getDate()).padStart(2,"0") + "_" +
    String(ts.getHours()).padStart(2,"0") +
    String(ts.getMinutes()).padStart(2,"0") +
    String(ts.getSeconds()).padStart(2,"0");

  const base = label ? `acid_${label}_${stamp}` : `acid_${stamp}`;
  const name = `${base}.wav`;
  nameTag.textContent = `filename: ${name}`;
  return name;
}

sessionLabelInput.addEventListener("input", buildSuggestedName);
buildSuggestedName();

function updateMeterAndScope(){
  if (!analyser) return;

  const N = analyser.fftSize;
  const data = new Uint8Array(N);
  analyser.getByteTimeDomainData(data);

  // RMS meter
  let sum = 0;
  for (let i = 0; i < data.length; i++){
    const v = (data[i] - 128) / 128;
    sum += v * v;
  }
  const rms = Math.sqrt(sum / data.length);
  const pct = Math.min(100, Math.max(0, rms * 220));
  levelBar.style.width = pct.toFixed(1) + "%";

  // Waveform (oscilloscope)
  drawScope(data);

  rafId = requestAnimationFrame(updateMeterAndScope);
}

function drawScope(data){
  // HiDPI-ish: canvas has fixed pixel size; CSS scales it.
  const w = scope.width;
  const h = scope.height;

  // fade trail
  sctx.fillStyle = "rgba(0,0,0,0.18)";
  sctx.fillRect(0, 0, w, h);

  // center line glow-ish
  sctx.strokeStyle = "rgba(57,255,20,0.12)";
  sctx.lineWidth = 2;
  sctx.beginPath();
  sctx.moveTo(0, h/2);
  sctx.lineTo(w, h/2);
  sctx.stroke();

  // waveform
  sctx.strokeStyle = "rgba(57,255,20,0.95)";
  sctx.lineWidth = 3;
  sctx.beginPath();

  const step = data.length / w; // map samples to pixels
  for (let x = 0; x < w; x++){
    const i = Math.floor(x * step);
    const v = (data[i] - 128) / 128; // [-1,1]
    const y = (h/2) + v * (h * 0.35);
    if (x === 0) sctx.moveTo(x, y);
    else sctx.lineTo(x, y);
  }
  sctx.stroke();

  // outer glow pass
  sctx.strokeStyle = "rgba(57,255,20,0.25)";
  sctx.lineWidth = 10;
  sctx.beginPath();
  for (let x = 0; x < w; x++){
    const i = Math.floor(x * step);
    const v = (data[i] - 128) / 128;
    const y = (h/2) + v * (h * 0.35);
    if (x === 0) sctx.moveTo(x, y);
    else sctx.lineTo(x, y);
  }
  sctx.stroke();
}

function clearScope(){
  sctx.clearRect(0,0,scope.width, scope.height);
  sctx.fillStyle = "rgba(0,0,0,0.55)";
  sctx.fillRect(0,0,scope.width, scope.height);
}

async function getBestMicStream(){
  const constraints = {
    audio: {
      channelCount: 1,
      sampleRate: 48000,
      sampleSize: 16,
      echoCancellation: false,
      noiseSuppression: false,
      autoGainControl: false
    }
  };
  return await navigator.mediaDevices.getUserMedia(constraints);
}

async function ensureWorklet(ctx){
  const workletCode = `
    class CaptureProcessor extends AudioWorkletProcessor {
      process(inputs){
        const input = inputs[0];
        if (!input || input.length === 0) return true;
        const ch0 = input[0];
        if (!ch0) return true;

        const copy = new Float32Array(ch0.length);
        copy.set(ch0);

        this.port.postMessage(copy, [copy.buffer]);
        return true;
      }
    }
    registerProcessor('capture-processor', CaptureProcessor);
  `;
  const blob = new Blob([workletCode], { type: "application/javascript" });
  const url = URL.createObjectURL(blob);
  await ctx.audioWorklet.addModule(url);
  URL.revokeObjectURL(url);
}

function buildProcessingGraph(){
  compressor = ctx.createDynamicsCompressor();
  compressor.threshold.value = -28;
  compressor.knee.value = 24;
  compressor.ratio.value = 3.2;
  compressor.attack.value = 0.005;
  compressor.release.value = 0.20;

  shelf = ctx.createBiquadFilter();
  shelf.type = "highshelf";
  shelf.frequency.value = 2500;
  shelf.gain.value = 4.0;

  analyser = ctx.createAnalyser();
  analyser.fftSize = 2048;

  workletNode = new AudioWorkletNode(ctx, "capture-processor", {
    numberOfInputs: 1,
    numberOfOutputs: 0,
    channelCount: 1
  });

  workletNode.port.onmessage = (e) => {
    const f32 = new Float32Array(e.data);
    chunks.push(f32);
    recordedSamples += f32.length;
  };

  source.connect(compressor);
  compressor.connect(shelf);
  shelf.connect(analyser);
  analyser.connect(workletNode);
}

function flattenChunks(){
  const out = new Float32Array(recordedSamples);
  let offset = 0;
  for (const c of chunks){
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function floatTo16BitPCM(float32){
  const out = new Int16Array(float32.length);
  for (let i = 0; i < float32.length; i++){
    let s = Math.max(-1, Math.min(1, float32[i]));
    out[i] = s < 0 ? (s * 0x8000) : (s * 0x7fff);
  }
  return out;
}

function encodeWavMono16(samplesF32, sr){
  const pcm16 = floatTo16BitPCM(samplesF32);
  const bytesPerSample = 2;
  const numChannels = 1;
  const blockAlign = numChannels * bytesPerSample;
  const byteRate = sr * blockAlign;
  const dataSize = pcm16.length * bytesPerSample;

  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);

  let o = 0;
  const writeStr = (s) => { for (let i=0;i<s.length;i++) view.setUint8(o++, s.charCodeAt(i)); };

  writeStr("RIFF");
  view.setUint32(o, 36 + dataSize, true); o += 4;
  writeStr("WAVE");

  writeStr("fmt ");
  view.setUint32(o, 16, true); o += 4;
  view.setUint16(o, 1, true); o += 2;
  view.setUint16(o, numChannels, true); o += 2;
  view.setUint32(o, sr, true); o += 4;
  view.setUint32(o, byteRate, true); o += 4;
  view.setUint16(o, blockAlign, true); o += 2;
  view.setUint16(o, 16, true); o += 2;

  writeStr("data");
  view.setUint32(o, dataSize, true); o += 4;

  for (let i = 0; i < pcm16.length; i++, o += 2){
    view.setInt16(o, pcm16[i], true);
  }

  return new Blob([buffer], { type: "audio/wav" });
}

async function saveBlob(blob, suggestedName){
  if ("showSaveFilePicker" in window){
    const handle = await window.showSaveFilePicker({
      suggestedName,
      types: [{ description: "WAV audio", accept: { "audio/wav": [".wav"] } }]
    });
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
    return;
  }

  const a = document.createElement("a");
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = suggestedName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

async function start(){
  if (recording) return;

  if (!navigator.mediaDevices?.getUserMedia){
    setStatus("This browser can’t record audio (no getUserMedia).");
    return;
  }

  chunks = [];
  recordedSamples = 0;
  clearScope();

  try{
    stream = await getBestMicStream();

    ctx = new (window.AudioContext || window.webkitAudioContext)({
      latencyHint: "interactive",
      sampleRate: 48000
    });

    await ensureWorklet(ctx);

    sampleRate = ctx.sampleRate;
    srTag.textContent = `${sampleRate} Hz`;

    source = ctx.createMediaStreamSource(stream);
    buildProcessingGraph();

    recording = true;
    startAt = performance.now();

    setUI("recording");
    setStatus("Recording… (hold to talk, or Stop to finish)");

    timerId = setInterval(updateTimer, 250);
    updateTimer();

    cancelAnimationFrame(rafId);
    updateMeterAndScope();

  } catch (err){
    console.error(err);
    setStatus(`Mic error: ${err?.message || err}`);
    cleanup();
    setUI("idle");
  }
}

async function stop(){
  if (!recording) return;

  recording = false;
  setUI("stopped");
  setStatus("Stopped. Ready to save WAV.");
  buildSuggestedName();

  clearInterval(timerId);
  cancelAnimationFrame(rafId);
  levelBar.style.width = "0%";

  try{ workletNode?.disconnect(); } catch {}
  try{ analyser?.disconnect(); } catch {}
  try{ shelf?.disconnect(); } catch {}
  try{ compressor?.disconnect(); } catch {}
  try{ source?.disconnect(); } catch {}

  try{ await ctx?.close(); } catch {}
  ctx = null;

  try{ stream?.getTracks()?.forEach(t => t.stop()); } catch {}
  stream = null;
}

function cleanup(){
  clearInterval(timerId);
  cancelAnimationFrame(rafId);
  try{ stream?.getTracks()?.forEach(t => t.stop()); } catch {}
  stream = null;
  try{ ctx?.close(); } catch {}
  ctx = null;
  recording = false;
  levelBar.style.width = "0%";
  timeText.textContent = "00:00";
  srTag.textContent = "— Hz";
  clearScope();
}

async function save(){
  if (recordedSamples <= 0){
    setStatus("Nothing recorded yet.");
    return;
  }

  setStatus("Encoding WAV…");
  const f32 = flattenChunks();
  const wavBlob = encodeWavMono16(f32, sampleRate);

  const name = buildSuggestedName();

  try{
    await saveBlob(wavBlob, name);
    setStatus(`Saved: ${name}`);
  } catch (err){
    console.error(err);
    setStatus(`Save canceled/failed: ${err?.message || err}`);
  }
}

// Buttons
btnStart.addEventListener("click", start);
btnStop.addEventListener("click", stop);
btnSave.addEventListener("click", save);

// --- Hold-to-record (walkie talkie) ---
// We use pointer events so it works with mouse + touch + pen.
// We also prevent scrolling/selection issues.
function holdStart(e){
  e.preventDefault();
  if (holdActive) return;
  holdActive = true;

  // Start recording if not already
  if (!recording){
    start();
  }
}

function holdEnd(e){
  e.preventDefault();
  if (!holdActive) return;
  holdActive = false;

  // Stop if we are recording
  if (recording){
    stop();
  }
}

btnHold.addEventListener("pointerdown", holdStart);
btnHold.addEventListener("pointerup", holdEnd);
btnHold.addEventListener("pointercancel", holdEnd);
btnHold.addEventListener("pointerleave", (e) => {
  // If finger slides off while holding, still stop (walkie rules)
  if (holdActive) holdEnd(e);
});

// extra safety: if the user lifts finger anywhere
window.addEventListener("pointerup", (e) => {
  if (holdActive) holdEnd(e);
});

// Service worker
if ("serviceWorker" in navigator){
  window.addEventListener("load", async () => {
    try{ await navigator.serviceWorker.register("./sw.js"); } catch {}
  });
}

window.addEventListener("beforeunload", cleanup);

setUI("idle");

