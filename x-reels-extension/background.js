const STORAGE_KEY = "xReelsEnabled";

async function getEnabled() {
  const v = await chrome.storage.sync.get({ [STORAGE_KEY]: true });
  return Boolean(v[STORAGE_KEY]);
}

async function setEnabled(enabled) {
  await chrome.storage.sync.set({ [STORAGE_KEY]: Boolean(enabled) });
}

async function updateBadge(enabled) {
  await chrome.action.setBadgeText({ text: enabled ? "ON" : "" });
  await chrome.action.setBadgeBackgroundColor({ color: "#1d9bf0" });
}

chrome.runtime.onInstalled.addListener(async () => {
  const enabled = await getEnabled();
  await updateBadge(enabled);
});

chrome.storage.onChanged.addListener(async (changes, areaName) => {
  if (areaName !== "sync") return;
  if (!changes[STORAGE_KEY]) return;
  await updateBadge(Boolean(changes[STORAGE_KEY].newValue));
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    if (!msg || msg.type !== "X_REELS_GET_STATE") return;
    const enabled = await getEnabled();
    sendResponse({ enabled });
  })();
  return true;
});

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab?.id) return;
  const enabled = await getEnabled();
  const next = !enabled;
  await setEnabled(next);
  await updateBadge(next);
  try {
    await chrome.tabs.sendMessage(tab.id, { type: "X_REELS_SET_STATE", enabled: next });
  } catch {
    // Tab may not have the content script yet (non-matching URL).
  }
});
