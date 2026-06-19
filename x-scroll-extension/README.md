# X Scroll - Reels Style Browser Extension

Browse X.com (Twitter) posts one by one like Instagram Reels! This Chrome extension transforms your X.com timeline into a full-screen, swipeable experience.

![X Scroll Extension](icons/icon128.png)

## Features

- 🎬 **Full-screen post viewing** - Each post takes up the entire screen
- 📱 **Reels-style navigation** - Scroll, swipe, or use keyboard to move between posts
- ⌨️ **Keyboard shortcuts** - Navigate with arrow keys, J/K, or spacebar
- 🖱️ **Mouse wheel support** - Scroll through posts naturally
- 📱 **Touch support** - Swipe up/down on touch devices
- 🎨 **Beautiful dark UI** - Matches X.com's dark theme
- 📊 **Post stats** - See replies, retweets, likes, and views
- 🔄 **Auto-load more** - Automatically loads more posts as you scroll

## Installation

### Method 1: Load Unpacked (Developer Mode)

1. Download or clone this repository
2. Open Chrome and go to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top-right corner)
4. Click **Load unpacked**
5. Select the `x-scroll-extension` folder
6. The extension is now installed!

### Method 2: From Source

```bash
git clone <repository-url>
cd x-scroll-extension
# Then follow steps 2-6 above
```

## Usage

### Activating Reels Mode

1. Go to [x.com](https://x.com) and make sure some posts are loaded in your timeline
2. Click the **blue floating button** (📋) at the bottom-right of the screen
3. Or press **Alt + R** to toggle reels mode
4. Or click the extension icon and press "Activate Reels Mode"

### Navigation

| Action | Method |
|--------|--------|
| Next post | `↓` / `J` / `Space` / Scroll down / Swipe up |
| Previous post | `↑` / `K` / Scroll up / Swipe down |
| Open post | `O` |
| First post | `Home` |
| Last post | `End` |
| Exit | `Esc` / Click ✕ button |

### Controls

- **Counter** (top): Shows current post number / total posts
- **Progress bar** (left): Visual indicator of position in timeline
- **Navigation buttons** (right): Click to go up/down
- **Close button** (top-right): Exit reels mode

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Alt + R` | Toggle reels mode on/off |
| `↑` or `K` | Previous post |
| `↓` or `J` | Next post |
| `Space` | Next post |
| `O` | Open current post in new tab |
| `Home` | Go to first post |
| `End` | Go to last post |
| `Esc` | Exit reels mode |

## Tips

1. **Load more posts first**: Scroll through your timeline before activating reels mode to have more posts available
2. **Posts auto-load**: When you near the end, the extension automatically tries to load more posts
3. **Works on Home timeline**: Best experienced on the main home timeline at x.com/home
4. **Media support**: Images and videos are displayed in full quality

## Troubleshooting

### Extension not appearing?
- Make sure you're on x.com or twitter.com
- Try refreshing the page
- Check if the extension is enabled in chrome://extensions/

### No posts found?
- Scroll through your timeline first to load posts
- Make sure you're on the home timeline or a profile page with tweets

### Posts not loading?
- The extension reads posts that are already loaded in the DOM
- Scroll down on the regular timeline first to load more posts

## Privacy

This extension:
- ✅ Only runs on x.com and twitter.com
- ✅ Does not collect any data
- ✅ Does not send data anywhere
- ✅ Works entirely locally in your browser

## Technical Details

- **Manifest Version**: 3
- **Permissions**: `activeTab`, `storage`
- **Host Permissions**: `x.com`, `twitter.com`

## Browser Compatibility

- ✅ Google Chrome (v88+)
- ✅ Microsoft Edge (Chromium)
- ✅ Brave Browser
- ✅ Other Chromium-based browsers

## Contributing

Feel free to submit issues and pull requests!

## License

MIT License - feel free to use and modify as you wish.

---

**Enjoy scrolling through X.com like never before! 🚀**
