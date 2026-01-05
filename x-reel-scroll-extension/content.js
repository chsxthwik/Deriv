// X Reels Scroll Extension

let isEnabled = false;
let observer = null;

function createToggleButton() {
  // Check if button already exists
  if (document.getElementById('x-reels-toggle')) return;

  const button = document.createElement('button');
  button.id = 'x-reels-toggle';
  button.textContent = 'Enable Reels Mode';
  button.addEventListener('click', toggleReelsMode);
  document.body.appendChild(button);
}

function toggleReelsMode() {
  isEnabled = !isEnabled;
  const html = document.documentElement;
  const button = document.getElementById('x-reels-toggle');

  if (isEnabled) {
    html.classList.add('x-reels-mode');
    button.textContent = 'Exit Reels Mode';
    button.classList.add('active');
    
    // Snap to the first visible tweet
    scrollToNearestTweet();
    
    // Optional: Add keyboard listener for navigation
    document.addEventListener('keydown', handleKeyNavigation);
  } else {
    html.classList.remove('x-reels-mode');
    button.textContent = 'Enable Reels Mode';
    button.classList.remove('active');
    
    document.removeEventListener('keydown', handleKeyNavigation);
  }
}

function scrollToNearestTweet() {
  // Finds the first tweet in viewport and aligns it
  const tweets = document.querySelectorAll('article[data-testid="tweet"]');
  for (const tweet of tweets) {
    const rect = tweet.getBoundingClientRect();
    if (rect.top >= 0 && rect.top < window.innerHeight) {
      tweet.scrollIntoView({ behavior: 'smooth', block: 'start' });
      break;
    }
  }
}

function handleKeyNavigation(e) {
  // Allow ArrowUp/Down to snap if native snap isn't working perfectly
  // or J/K for power users
  if (e.key === 'j') {
    window.scrollBy({ top: window.innerHeight, behavior: 'smooth' });
  } else if (e.key === 'k') {
    window.scrollBy({ top: -window.innerHeight, behavior: 'smooth' });
  }
}

// Watch for URL changes (SPA navigation) to re-inject button if needed
let lastUrl = location.href; 
new MutationObserver(() => {
  const url = location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    // Re-ensure button exists
    createToggleButton();
  }
  
  // Ensure button exists if DOM was wiped
  if (!document.getElementById('x-reels-toggle')) {
    createToggleButton();
  }
}).observe(document, { subtree: true, childList: true });

// Initial setup
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', createToggleButton);
} else {
  createToggleButton();
}
