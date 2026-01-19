/* EMF PWA (Magnetometer) - reads magnetic field via Generic Sensor API when available. */

const els = {
  status: document.getElementById("status"),
  mag: document.getElementById("mag"),
  x: document.getElementById("x"),
  y: document.getElementById("y"),
  z: document.getElementById("z"),
  btnStart: document.getElementById("btnStart"),
  btnStop: document.getElementById("btnStop"),
  chart: document.getElementById("chart"),
};

let sensor = null;
let running = false;

// Simple ring buffer for graph
const BUF = 220; // points
const mags = new Array(BUF).fill(null);
let idx = 0;

function fmt(n) {
  if (typeof n !== "number" || !Number.isFinite(n)) return "—";
  return n.toFixed(1);
}

function setStatus(msg) {
  els.status.textContent = msg;
}

function pushMag(v) {
  mags[idx] = v;
  idx = (idx + 1) % BUF;
}

function drawChart() {
  const ctx = els.chart.getContext("2d");
  const w = els.chart.width;
  const h = els.chart.height;

  // Clear
  ctx.clearRect(0, 0, w, h);

  // Determine min/max from data
  const data = mags.filter(v => typeof v === "number" && Number.isFinite(v));
  const min = data.length ? Math.min(...data) : 0;
  const max = data.length ? Math.max(...data) : 100;

  const pad = 14;
  const yMin = min;
  const yMax = (max === min) ? (max + 1) : max;
  const scaleY = (h - pad * 2) / (yMax - yMin);

  // Draw baseline grid-ish lines
  ctx.globalAlpha = 0.35;
  ctx.strokeStyle = "#2b385a";
  ctx.lineWidth = 1;
  for (let i = 1; i <= 3; i++) {
    const y = pad + (h - pad * 2) * (i / 4);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
  ctx.globalAlpha = 1;

  // Plot line
  ctx.strokeStyle = "#7aa2ff";
  ctx.lineWidth = 2;
  ctx.beginPath();

  for (let i = 0; i < BUF; i++) {
    const j = (idx + i) % BUF;
    const v = mags[j];
    const x = (i / (BUF - 1)) * w;

    if (typeof v !== "number") continue;

    const y = h - pad - (v - yMin) * scaleY;

    if (i === 0) ctx.moveTo(x, y);
    else ctx.lineTo(x, y);
  }
  ctx.stroke();

  // Labels
  ctx.fillStyle = "#cdd6f4";
  ctx.font = "12px system-ui, -apple-system, Segoe UI, Roboto, Arial";
  ctx.fillText(`min ${min.toFixed(1)} µT`, 10, 16);
  ctx.fillText(`max ${max.toFixed(1)} µT`, 10, 34);
}

function updateUI(x, y, z) {
  const mag = Math.sqrt(x*x + y*y + z*z);

  els.x.textContent = fmt(x);
  els.y.textContent = fmt(y);
  els.z.textContent = fmt(z);
  els.mag.textContent = fmt(mag);

  pushMag(mag);
  drawChart();
}

async function start() {
  if (running) return;

  // PWA SW registration
  if ("serviceWorker" in navigator) {
    try { await navigator.serviceWorker.register("./sw.js"); } catch {}
  }

  if (!("Magnetometer" in window)) {
    setStatus("Magnetometer API not available in this browser/device. Try Android Chrome/Edge, and ensure sensors are allowed.");
    return;
  }

  try {
    // Some browsers require secure context + permission gating
    // Permission API may or may not exist for magnetometer.
    if (navigator.permissions?.query) {
      try {
        // Not standardized everywhere; may throw.
        const p = await navigator.permissions.query({ name: "magnetometer" });
        if (p.state === "denied") {
          setStatus("Permission for magnetometer is denied in browser settings.");
          return;
        }
      } catch {
        // ignore permission query failures
      }
    }

    sensor = new Magnetometer({ frequency: 30 }); // Hz-ish; browser clamps
    sensor.addEventListener("reading", () => {
      // µT values on x/y/z (spec)
      updateUI(sensor.x, sensor.y, sensor.z);
    });
    sensor.addEventListener("error", (e) => {
      setStatus(`Sensor error: ${e.error?.name || "unknown"}`);
      stop();
    });

    sensor.start();
    running = true;
    els.btnStart.disabled = true;
    els.btnStop.disabled = false;
    setStatus("Reading magnetometer… move near a magnet or a power adapter to see changes.");

  } catch (err) {
    setStatus(`Could not start magnetometer: ${err?.message || String(err)}`);
    stop();
  }
}

function stop() {
  if (sensor) {
    try { sensor.stop(); } catch {}
    sensor = null;
  }
  running = false;
  els.btnStart.disabled = false;
  els.btnStop.disabled = true;
  setStatus("Stopped.");
}

els.btnStart.addEventListener("click", start);
els.btnStop.addEventListener("click", stop);

// Initial draw
drawChart();

