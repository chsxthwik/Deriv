// X Scroll Extension - Reels Style Content Script

(function() {
  'use strict';

  let isReelsMode = false;
  let posts = [];
  let currentIndex = 0;
  let container = null;
  let observer = null;
  let isLoading = false;

  // Initialize extension
  function init() {
    // Add toggle button to page
    createToggleButton();
    
    // Listen for keyboard shortcuts
    document.addEventListener('keydown', handleKeydown);
    
    console.log('X Scroll Extension loaded');
  }

  // Create floating toggle button
  function createToggleButton() {
    if (document.querySelector('.x-scroll-toggle-btn')) return;

    const btn = document.createElement('button');
    btn.className = 'x-scroll-toggle-btn';
    btn.title = 'Toggle Reels Mode (Alt+R)';
    btn.innerHTML = `
      <svg viewBox="0 0 24 24" fill="currentColor">
        <path d="M4 6h16v2H4V6zm0 5h16v2H4v-2zm0 5h16v2H4v-2z"/>
      </svg>
    `;
    btn.addEventListener('click', toggleReelsMode);
    document.body.appendChild(btn);
  }

  // Toggle reels mode
  function toggleReelsMode() {
    if (isReelsMode) {
      exitReelsMode();
    } else {
      enterReelsMode();
    }
  }

  // Enter reels mode
  function enterReelsMode() {
    isReelsMode = true;
    document.body.classList.add('x-scroll-reels-mode');
    
    // Collect posts from timeline
    collectPosts();
    
    if (posts.length === 0) {
      alert('No posts found! Please scroll through some posts first.');
      exitReelsMode();
      return;
    }

    // Create reels container
    createReelsContainer();
    
    // Show first post
    showPost(currentIndex);
    
    // Start observing for new posts
    startObserver();
  }

  // Exit reels mode
  function exitReelsMode() {
    isReelsMode = false;
    document.body.classList.remove('x-scroll-reels-mode');
    
    // Remove container
    if (container) {
      container.remove();
      container = null;
    }
    
    // Stop observer
    if (observer) {
      observer.disconnect();
      observer = null;
    }
  }

  // Collect posts from timeline
  function collectPosts() {
    posts = [];
    
    // Find all tweet articles
    const articles = document.querySelectorAll('article[data-testid="tweet"]');
    
    articles.forEach((article, index) => {
      const postData = extractPostData(article);
      if (postData) {
        posts.push(postData);
      }
    });
    
    console.log(`Collected ${posts.length} posts`);
  }

  // Extract post data from article element
  function extractPostData(article) {
    try {
      // Get user info
      const userNameEl = article.querySelector('[data-testid="User-Name"]');
      const avatarEl = article.querySelector('img[src*="profile_images"]');
      
      // Get tweet text
      const tweetTextEl = article.querySelector('[data-testid="tweetText"]');
      
      // Get media (images/videos)
      const mediaContainer = article.querySelector('[data-testid="tweetPhoto"], [data-testid="videoPlayer"]');
      const images = article.querySelectorAll('[data-testid="tweetPhoto"] img');
      const video = article.querySelector('video');
      
      // Get engagement stats
      const replyCount = article.querySelector('[data-testid="reply"]')?.textContent || '0';
      const retweetCount = article.querySelector('[data-testid="retweet"]')?.textContent || '0';
      const likeCount = article.querySelector('[data-testid="like"]')?.textContent || '0';
      const viewCount = article.querySelector('a[href*="/analytics"]')?.textContent || '';
      
      // Get timestamp
      const timeEl = article.querySelector('time');
      const timestamp = timeEl?.getAttribute('datetime') || '';
      const timeText = timeEl?.textContent || '';
      
      // Get tweet link
      const linkEl = article.querySelector('a[href*="/status/"]');
      const tweetLink = linkEl?.href || '';

      // Extract display name and username
      let displayName = '';
      let username = '';
      
      if (userNameEl) {
        const nameSpans = userNameEl.querySelectorAll('span');
        nameSpans.forEach(span => {
          const text = span.textContent;
          if (text.startsWith('@')) {
            username = text;
          } else if (text && !text.includes('·') && text.length > 1) {
            if (!displayName) displayName = text;
          }
        });
      }

      // Get all images
      const mediaUrls = [];
      images.forEach(img => {
        if (img.src && !img.src.includes('profile_images') && !img.src.includes('emoji')) {
          mediaUrls.push(img.src);
        }
      });

      // Get video source
      let videoUrl = '';
      if (video) {
        videoUrl = video.src || video.querySelector('source')?.src || '';
      }

      return {
        displayName: displayName || 'Unknown',
        username: username || '@unknown',
        avatar: avatarEl?.src || '',
        text: tweetTextEl?.innerHTML || '',
        plainText: tweetTextEl?.textContent || '',
        images: mediaUrls,
        video: videoUrl,
        hasVideo: !!video,
        replyCount,
        retweetCount,
        likeCount,
        viewCount,
        timestamp,
        timeText,
        tweetLink,
        originalElement: article
      };
    } catch (e) {
      console.error('Error extracting post data:', e);
      return null;
    }
  }

  // Create reels container
  function createReelsContainer() {
    container = document.createElement('div');
    container.className = 'x-scroll-container';
    container.innerHTML = `
      <div class="x-scroll-counter">
        <span class="current">1</span> / <span class="total">${posts.length}</span>
      </div>
      
      <button class="x-scroll-close-btn" title="Exit (Esc)">
        <svg viewBox="0 0 24 24" fill="currentColor">
          <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
        </svg>
      </button>
      
      <div class="x-scroll-post-wrapper">
        <div class="x-scroll-post" id="x-scroll-current-post"></div>
      </div>
      
      <div class="x-scroll-nav">
        <button class="x-scroll-nav-btn" id="x-scroll-prev" title="Previous (↑)">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 4l-8 8h16l-8-8z"/>
          </svg>
        </button>
        <button class="x-scroll-nav-btn" id="x-scroll-next" title="Next (↓)">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 20l8-8H4l8 8z"/>
          </svg>
        </button>
      </div>
      
      <div class="x-scroll-progress">
        <div class="x-scroll-progress-fill" style="height: 0%"></div>
      </div>
      
      <div class="x-scroll-hint">
        <kbd>↑</kbd> <kbd>↓</kbd> or <kbd>J</kbd> <kbd>K</kbd> to navigate • <kbd>Esc</kbd> to exit • <kbd>O</kbd> open post
      </div>
    `;

    // Add event listeners
    container.querySelector('.x-scroll-close-btn').addEventListener('click', exitReelsMode);
    container.querySelector('#x-scroll-prev').addEventListener('click', () => navigatePost(-1));
    container.querySelector('#x-scroll-next').addEventListener('click', () => navigatePost(1));
    
    // Add wheel scroll
    container.addEventListener('wheel', handleWheel, { passive: false });
    
    // Add touch support
    let touchStartY = 0;
    container.addEventListener('touchstart', (e) => {
      touchStartY = e.touches[0].clientY;
    });
    container.addEventListener('touchend', (e) => {
      const touchEndY = e.changedTouches[0].clientY;
      const diff = touchStartY - touchEndY;
      if (Math.abs(diff) > 50) {
        navigatePost(diff > 0 ? 1 : -1);
      }
    });

    document.body.appendChild(container);
  }

  // Show post at index
  function showPost(index) {
    if (index < 0 || index >= posts.length) return;
    
    const post = posts[index];
    const postEl = container.querySelector('#x-scroll-current-post');
    
    // Build post HTML
    let mediaHtml = '';
    
    if (post.images.length > 0) {
      mediaHtml = `
        <div class="x-scroll-post-media">
          ${post.images.map(img => `<img src="${img}" alt="Post image" loading="lazy">`).join('')}
        </div>
      `;
    }
    
    if (post.hasVideo && post.video) {
      mediaHtml = `
        <div class="x-scroll-post-media">
          <video src="${post.video}" controls autoplay muted loop></video>
        </div>
      `;
    }

    postEl.innerHTML = `
      <div class="x-scroll-post-header">
        <img class="x-scroll-post-avatar" src="${post.avatar || 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="12" fill="%23333"/></svg>'}" alt="Avatar">
        <div class="x-scroll-post-user-info">
          <span class="x-scroll-post-name">${escapeHtml(post.displayName)}</span>
          <span class="x-scroll-post-username">${escapeHtml(post.username)}</span>
        </div>
      </div>
      
      <div class="x-scroll-post-content">${post.text}</div>
      
      ${mediaHtml}
      
      <div class="x-scroll-timestamp">${post.timeText}</div>
      
      <div class="x-scroll-post-stats">
        <div class="x-scroll-stat">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M1.751 10c0-4.42 3.584-8 8.005-8h4.366c4.49 0 8.129 3.64 8.129 8.13 0 2.96-1.607 5.68-4.196 7.11l-8.054 4.46v-3.69h-.067c-4.49.1-8.183-3.51-8.183-8.01z"/>
          </svg>
          ${post.replyCount}
        </div>
        <div class="x-scroll-stat">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M4.5 3.88l4.432 4.14-1.364 1.46L5.5 7.55V16c0 1.1.896 2 2 2H13v2H7.5c-2.209 0-4-1.79-4-4V7.55L1.432 9.48.068 8.02 4.5 3.88zM16.5 6H11V4h5.5c2.209 0 4 1.79 4 4v8.45l2.068-1.93 1.364 1.46-4.432 4.14-4.432-4.14 1.364-1.46 2.068 1.93V8c0-1.1-.896-2-2-2z"/>
          </svg>
          ${post.retweetCount}
        </div>
        <div class="x-scroll-stat">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M16.697 5.5c-1.222-.06-2.679.51-3.89 2.16l-.805 1.09-.806-1.09C9.984 6.01 8.526 5.44 7.304 5.5c-1.243.07-2.349.78-2.91 1.91-.552 1.12-.633 2.78.479 4.82 1.074 1.97 3.257 4.27 7.129 6.61 3.87-2.34 6.052-4.64 7.126-6.61 1.111-2.04 1.03-3.7.477-4.82-.561-1.13-1.666-1.84-2.908-1.91z"/>
          </svg>
          ${post.likeCount}
        </div>
        ${post.viewCount ? `
        <div class="x-scroll-stat">
          <svg viewBox="0 0 24 24" fill="currentColor">
            <path d="M8.75 21V3h2v18h-2zM18 21V8.5h2V21h-2zM4 21l.004-10h2L6 21H4zm9.248 0v-7h2v7h-2z"/>
          </svg>
          ${post.viewCount}
        </div>
        ` : ''}
      </div>
    `;

    // Update counter
    container.querySelector('.x-scroll-counter .current').textContent = index + 1;
    
    // Update progress bar
    const progress = ((index + 1) / posts.length) * 100;
    container.querySelector('.x-scroll-progress-fill').style.height = `${progress}%`;
    
    // Update navigation buttons
    container.querySelector('#x-scroll-prev').disabled = index === 0;
    container.querySelector('#x-scroll-next').disabled = index === posts.length - 1;
    
    // Load more posts if near end
    if (index >= posts.length - 3) {
      loadMorePosts();
    }

    // Animate
    postEl.style.opacity = '0';
    postEl.style.transform = 'translateY(20px)';
    requestAnimationFrame(() => {
      postEl.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
      postEl.style.opacity = '1';
      postEl.style.transform = 'translateY(0)';
    });
  }

  // Navigate to previous/next post
  function navigatePost(direction) {
    const newIndex = currentIndex + direction;
    if (newIndex >= 0 && newIndex < posts.length) {
      currentIndex = newIndex;
      showPost(currentIndex);
    }
  }

  // Handle wheel scroll
  let wheelTimeout = null;
  function handleWheel(e) {
    e.preventDefault();
    
    if (wheelTimeout) return;
    
    wheelTimeout = setTimeout(() => {
      wheelTimeout = null;
    }, 300);
    
    if (e.deltaY > 0) {
      navigatePost(1);
    } else if (e.deltaY < 0) {
      navigatePost(-1);
    }
  }

  // Handle keyboard shortcuts
  function handleKeydown(e) {
    // Alt+R to toggle reels mode
    if (e.altKey && e.key === 'r') {
      e.preventDefault();
      toggleReelsMode();
      return;
    }
    
    // Only handle other keys in reels mode
    if (!isReelsMode) return;
    
    switch(e.key) {
      case 'Escape':
        exitReelsMode();
        break;
      case 'ArrowUp':
      case 'k':
      case 'K':
        e.preventDefault();
        navigatePost(-1);
        break;
      case 'ArrowDown':
      case 'j':
      case 'J':
      case ' ':
        e.preventDefault();
        navigatePost(1);
        break;
      case 'o':
      case 'O':
        e.preventDefault();
        openCurrentPost();
        break;
      case 'Home':
        e.preventDefault();
        currentIndex = 0;
        showPost(currentIndex);
        break;
      case 'End':
        e.preventDefault();
        currentIndex = posts.length - 1;
        showPost(currentIndex);
        break;
    }
  }

  // Open current post in new view
  function openCurrentPost() {
    const post = posts[currentIndex];
    if (post && post.tweetLink) {
      window.open(post.tweetLink, '_blank');
    }
  }

  // Load more posts by scrolling the original timeline
  async function loadMorePosts() {
    if (isLoading) return;
    isLoading = true;
    
    // Scroll the hidden timeline to load more
    const timeline = document.querySelector('[data-testid="primaryColumn"]');
    if (timeline) {
      // Temporarily show to allow scroll
      const originalDisplay = timeline.style.display;
      
      // Trigger scroll on the original page
      window.scrollTo(0, document.body.scrollHeight);
      
      // Wait for new posts to load
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      // Recollect posts
      const oldCount = posts.length;
      collectPosts();
      
      // Update counter if new posts found
      if (posts.length > oldCount && container) {
        container.querySelector('.x-scroll-counter .total').textContent = posts.length;
      }
    }
    
    isLoading = false;
  }

  // Start mutation observer to detect new posts
  function startObserver() {
    const timeline = document.querySelector('[data-testid="primaryColumn"]');
    if (!timeline) return;
    
    observer = new MutationObserver((mutations) => {
      let hasNewPosts = false;
      mutations.forEach(mutation => {
        if (mutation.addedNodes.length > 0) {
          hasNewPosts = true;
        }
      });
      
      if (hasNewPosts) {
        const oldCount = posts.length;
        collectPosts();
        if (posts.length > oldCount && container) {
          container.querySelector('.x-scroll-counter .total').textContent = posts.length;
        }
      }
    });
    
    observer.observe(timeline, { childList: true, subtree: true });
  }

  // Escape HTML to prevent XSS
  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  // Wait for page to be ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    // Small delay to ensure X.com has initialized
    setTimeout(init, 1000);
  }

  // Re-init if navigating within X.com (SPA)
  let lastUrl = location.href;
  new MutationObserver(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      setTimeout(() => {
        if (!document.querySelector('.x-scroll-toggle-btn')) {
          createToggleButton();
        }
      }, 1000);
    }
  }).observe(document.body, { childList: true, subtree: true });

  // Listen for messages from popup
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'toggleReelsMode') {
      toggleReelsMode();
      sendResponse({ success: true });
    }
    return true;
  });

})();
