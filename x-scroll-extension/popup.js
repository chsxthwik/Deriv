// Popup script for X Scroll Extension

document.getElementById('activateBtn').addEventListener('click', async () => {
  const statusEl = document.getElementById('status');
  
  try {
    // Get active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab.url.includes('x.com') || tab.url.includes('twitter.com')) {
      // Already on X.com, send message to activate reels mode
      await chrome.tabs.sendMessage(tab.id, { action: 'toggleReelsMode' });
      statusEl.className = 'status success';
      statusEl.textContent = 'Reels mode activated! ✨';
      
      // Close popup after short delay
      setTimeout(() => window.close(), 1000);
    } else {
      // Open X.com
      await chrome.tabs.create({ url: 'https://x.com/home' });
      statusEl.className = 'status success';
      statusEl.textContent = 'Opening X.com...';
    }
  } catch (error) {
    statusEl.className = 'status error';
    statusEl.textContent = 'Please navigate to x.com first';
  }
});

// Check current tab on popup open
(async () => {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const btn = document.getElementById('activateBtn');
    
    if (tab.url.includes('x.com') || tab.url.includes('twitter.com')) {
      btn.textContent = 'Activate Reels Mode';
    } else {
      btn.textContent = 'Open X.com';
    }
  } catch (error) {
    console.error('Error checking tab:', error);
  }
})();
