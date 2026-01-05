const STORAGE_KEY = "xReelsEnabled";

async function getEnabled() {
  const v = await chrome.storage.sync.get({ [STORAGE_KEY]: true });
  return Boolean(v[STORAGE_KEY]);
}

async function setEnabled(enabled) {
  await chrome.storage.sync.set({ [STORAGE_KEY]: Boolean(enabled) });

  // Best-effort notify active tab (content script listens).
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "X_REELS_SET_STATE", enabled: Boolean(enabled) });
  } catch {
    // Non-matching URL or content script not injected.
  }
}

async function main() {
  const toggle = document.getElementById("toggle");
  toggle.checked = await getEnabled();

  toggle.addEventListener("change", async () => {
    await setEnabled(toggle.checked);
    window.close();
  });
}

void main();

