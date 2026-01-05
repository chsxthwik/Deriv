const STORAGE_KEY = "xReelsEnabled";

let enabled = true;
let lastNavAt = 0;
let toastTimer = null;
let currentEl = null;

function getViewportCenterY() {
  return Math.floor(window.innerHeight / 2);
}

function isEditableTarget(target) {
  if (!(target instanceof Element)) return false;
  if (target.closest('input, textarea, [contenteditable="true"]')) return true;
  // X uses rich editors with role="textbox"
  if (target.closest('[role="textbox"]')) return true;
  return false;
}

function getPostArticles() {
  // X timeline posts are rendered as <article role="article"> (or plain <article> in some views)
  const articles = Array.from(document.querySelectorAll("article"));
  // Filter out tiny/empty articles and keep stable order
  return articles.filter((a) => {
    const r = a.getBoundingClientRect();
    if (r.height < 120 || r.width < 200) return false;
    // Prefer real posts (tweet) but allow fallback if attributes change
    if (a.querySelector('[data-testid="tweet"]')) return true;
    if (a.querySelector('[data-testid="tweetText"]')) return true;
    if (a.getAttribute("role") === "article") return true;
    return false;
  });
}

function pickClosestToCenter(articles) {
  const centerY = getViewportCenterY();
  let best = null;
  let bestDist = Infinity;

  for (const el of articles) {
    const r = el.getBoundingClientRect();
    // consider only items at least partially on screen
    if (r.bottom < 0 || r.top > window.innerHeight) continue;
    const elCenter = r.top + r.height / 2;
    const dist = Math.abs(elCenter - centerY);
    if (dist < bestDist) {
      bestDist = dist;
      best = el;
    }
  }
  return best ?? articles[0] ?? null;
}

function markCurrent(el) {
  if (currentEl && currentEl !== el) currentEl.classList.remove("x-reels-current");
  currentEl = el;
  if (currentEl) currentEl.classList.add("x-reels-current");
}

function getNextPrev(direction) {
  const articles = getPostArticles();
  if (!articles.length) return null;

  const current = pickClosestToCenter(articles);
  if (!current) return null;
  markCurrent(current);

  const idx = articles.indexOf(current);
  if (idx === -1) return null;

  const nextIdx = Math.max(0, Math.min(articles.length - 1, idx + direction));
  return articles[nextIdx] ?? null;
}

function scrollToPost(el) {
  if (!el) return;
  markCurrent(el);
  try {
    el.scrollIntoView({ behavior: "smooth", block: "center", inline: "nearest" });
  } catch {
    // Older behavior fallback
    el.scrollIntoView(true);
  }
}

function shouldRateLimit() {
  const now = Date.now();
  if (now - lastNavAt < 650) return true;
  lastNavAt = now;
  return false;
}

function onWheel(e) {
  if (!enabled) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (isEditableTarget(e.target)) return;

  // Trackpads can fire lots of tiny deltas; ignore micro scrolls.
  if (Math.abs(e.deltaY) < 10) return;
  if (shouldRateLimit()) {
    e.preventDefault();
    return;
  }

  const direction = e.deltaY > 0 ? 1 : -1;
  const target = getNextPrev(direction);
  if (!target) return;

  e.preventDefault();
  e.stopPropagation();
  scrollToPost(target);
}

function onKeyDown(e) {
  if (!enabled) return;
  if (e.ctrlKey || e.metaKey || e.altKey) return;
  if (isEditableTarget(e.target)) return;

  let direction = 0;
  if (e.key === "ArrowDown" || e.key === "PageDown" || e.key === " ") direction = 1;
  if (e.key === "ArrowUp" || e.key === "PageUp") direction = -1;

  // Quick toggle
  if (e.key === "r" || e.key === "R") {
    e.preventDefault();
    void setEnabled(!enabled, true);
    return;
  }

  if (!direction) return;
  if (shouldRateLimit()) {
    e.preventDefault();
    return;
  }

  const target = getNextPrev(direction);
  if (!target) return;

  e.preventDefault();
  scrollToPost(target);
}

function ensureToast() {
  let el = document.getElementById("x-reels-toast");
  if (el) return el;
  el = document.createElement("div");
  el.id = "x-reels-toast";
  el.setAttribute("role", "status");
  document.documentElement.appendChild(el);
  return el;
}

function showToast(text) {
  const el = ensureToast();
  el.textContent = text;
  el.dataset.show = "1";
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    el.dataset.show = "0";
  }, 1800);
}

function applyEnabledClass() {
  document.documentElement.classList.toggle("x-reels-enabled", enabled);
}

async function setEnabled(next, announce) {
  enabled = Boolean(next);
  applyEnabledClass();
  if (!enabled) markCurrent(null);
  await chrome.storage.sync.set({ [STORAGE_KEY]: enabled });
  if (announce) showToast(enabled ? "Reels mode: ON (wheel/↑↓/space, press R to toggle)" : "Reels mode: OFF");
}

async function initState() {
  const v = await chrome.storage.sync.get({ [STORAGE_KEY]: true });
  enabled = Boolean(v[STORAGE_KEY]);
  applyEnabledClass();
  if (enabled) {
    // Mark the first visible post so the user sees focus immediately.
    const first = pickClosestToCenter(getPostArticles());
    if (first) markCurrent(first);
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (!msg) return;
  if (msg.type === "X_REELS_SET_STATE") {
    void setEnabled(Boolean(msg.enabled), true);
  }
});

// Keep focus marker roughly correct as the user navigates.
window.addEventListener(
  "scroll",
  () => {
    if (!enabled) return;
    // cheap debounce using rAF
    window.requestAnimationFrame(() => {
      const el = pickClosestToCenter(getPostArticles());
      if (el) markCurrent(el);
    });
  },
  { passive: true }
);

// Capture wheel so we can prevent default scroll.
window.addEventListener("wheel", onWheel, { passive: false, capture: true });
window.addEventListener("keydown", onKeyDown, { passive: false, capture: true });

void initState();

