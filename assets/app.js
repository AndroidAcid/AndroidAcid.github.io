// Android Acid — site content/config
// Update these lists and the site updates automatically.

const CONFIG = {
  music: [
    {
      title: "Sound Cloud",
      desc: "Acid / Minimal Wave",
      tags: ["Acid", "Minimal Wave", "Live"],
      // SoundCloud embed: swap to any track/playlist embed URL you want
      embedUrl: "https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/soundcloud%253Atracks%253A2241053156&color=%23000000&auto_play=false&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true&visual=true",
      links: [
        { label: "Open on SoundCloud", href: "https://soundcloud.com/rgbelasco/" }
      ]
    },
    {
      title: "Band Camp",
      desc: "Acid / Minimal Wave",
      tags: ["Acid", "Minimal Wave", "Live"],
      // SoundCloud embed: swap to any track/playlist embed URL you want
      embedUrl: "https://bandcamp.com/EmbeddedPlayer/track=870727442/size=small/bgcol=333333/linkcol=0f91ff/transparent=true/",
      links: [
        { label: "Open on Bandcamp", href: "https://androidacid.bandcamp.com/" }
      ]
    },
  ],

  software: [
    {
      name: "Acid Utility #1",
      version: "v0.1",
      desc: "Coming Soon : 2026.",
      tags: ["VST3", "Windows", "Experimental"],
      links: [
        { label: "Download", href: "#" },
        { label: "Docs", href: "#" },
        { label: "Source", href: "#" }
      ]
    },
    {
      name: "Sample Pack / Presets",
      version: "2025.01",
      desc: "Coming Soon : 2026.",
      
      tags: ["Samples", "Patches", "303-ish"],
      links: [
        { label: "Download", href: "https://androidacid.com/software.html" },
        { label: "Source", href: "https://github.com/AndroidAcid/AndroidAcid.github.io" }
      ]
    },
    {
      name: "Games",
      version: "2026.01",
      desc: "Javascript Games",
      
      tags: ["Games", "Javascript", "Old-Skool"],
      links: [
        { label: "Get it", href: "#" }
      ]
    }
  ],

  gallery: [
    // Put images in /photos then list them here
    // Example: { src: "photos/studio-1.jpg", alt: "Studio desk with synths" }
    { src: "photos/5953779113233419213.jpg", alt: "Studio" },
    { src: "photos/5953779113233419236.jpg", alt: "Studio" },
    { src: "photos/5953779113233419238.jpg", alt: "Studio" },
  ]
};

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === "class") node.className = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  });
  children.forEach(c => node.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
  return node;
}

function renderMusic() {
  const grid = document.getElementById("musicGrid");
  if (!grid) return;

  CONFIG.music.forEach(item => {
    const tags = el("div", { class: "meta" },
      item.tags.map(t => el("span", { class: "pill" }, [t]))
    );

    const links = el("div", { class: "links-row" }, []);
    (item.links || []).forEach((l, idx) => {
      if (idx) links.appendChild(el("span", { class: "sep" }, ["•"]));
      links.appendChild(el("a", { class: "link", href: l.href, target: "_blank", rel: "noreferrer" }, [l.label]));
    });

    const iframe = el("iframe", {
      title: item.title,
      scrolling: "no",
      allow: "autoplay",
      src: item.embedUrl
    });

    const card = el("div", { class: "card" }, [
      el("h3", {}, [item.title]),
      el("p", { class: "muted" }, [item.desc || ""]),
      tags,
      el("div", { class: "embed" }, [iframe]),
      links
    ]);

    grid.appendChild(card);
  });
}

function renderSoftware() {
  const grid = document.getElementById("softwareGrid");
  if (!grid) return;

  CONFIG.software.forEach(item => {
    const tags = el("div", { class: "meta" },
      (item.tags || []).map(t => el("span", { class: "pill" }, [t]))
    );

    const links = el("div", { class: "links-row" }, []);
    (item.links || []).forEach((l, idx) => {
      if (idx) links.appendChild(el("span", { class: "sep" }, ["•"]));
      links.appendChild(el("a", { class: "link", href: l.href, target: "_blank", rel: "noreferrer" }, [l.label]));
    });

    const card = el("div", { class: "card" }, [
      el("h3", {}, [item.name]),
      el("p", { class: "muted small" }, [item.version || ""]),
      el("p", { class: "muted" }, [item.desc || ""]),
      tags,
      links
    ]);

    grid.appendChild(card);
  });
}

function renderGallery() {
  const gal = document.getElementById("gallery");
  if (!gal) return;

  CONFIG.gallery.forEach(p => {
    const img = el("img", { src: p.src, alt: p.alt, loading: "lazy" });
    const frame = el("div", { class: "photo" }, [img]);
    gal.appendChild(frame);
  });
}

function setupMobileMenu() {
  const btn = document.querySelector(".menu-btn");
  const nav = document.querySelector(".nav");
  if (!btn || !nav) return;

  btn.addEventListener("click", () => {
    const expanded = btn.getAttribute("aria-expanded") === "true";
    btn.setAttribute("aria-expanded", String(!expanded));

    if (!expanded) {
      nav.style.display = "flex";
      nav.style.flexDirection = "column";
      nav.style.position = "absolute";
      nav.style.right = "20px";
      nav.style.top = "68px";
      nav.style.padding = "12px";
      nav.style.background = "rgba(0,0,0,0.72)";
      nav.style.border = "1px solid rgba(0,255,102,0.18)";
      nav.style.borderRadius = "16px";
      nav.style.boxShadow = "0 0 22px rgba(0,255,102,0.12)";
    } else {
      nav.removeAttribute("style");
    }
  });
}

function setupUpdatesForm() {
  const form = document.getElementById("updatesForm");
  const msg = document.getElementById("updatesMsg");
  if (!form || !msg) return;

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const email = new FormData(form).get("email");
    msg.textContent = `Saved locally: ${email} (wire this to a real list when you're ready).`;
    form.reset();
  });
}

document.getElementById("year").textContent = String(new Date().getFullYear());
renderMusic();
renderSoftware();
renderGallery();
setupMobileMenu();
setupUpdatesForm();
