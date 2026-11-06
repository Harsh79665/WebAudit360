# WebAudit 360 — Chrome Extension (Manifest V3)

**Author**: Harsh Patel  
**Version**: 1.0.0  
**Manifest Version**: 3  

Trigger instant website audits, Core Web Vitals profiling, security checks, and sustainability assessments directly from your Chrome or Chromium-based browser toolbar.

---

## Features
- **1-Click Active Tab Audit**: Instantly captures the active tab URL and launches a live audit via the WebAudit 360 API.
- **Real-Time Scorecard**: Displays overall health score (0–100) and category ratings (Performance, SEO, Accessibility, Security) inside the popup.
- **Context Menu Integration**: Right-click any link or page and select *"Audit this page with WebAudit 360"*.
- **Configurable Backend**: Configure your WebAudit 360 API Base URL (`http://localhost:8000` or production domain) and Bearer API Key (`w360_live_...`).

---

## Installation & Setup

1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode** toggle in the top-right corner.
3. Click **Load unpacked**.
4. Select the `extension/` directory in this workspace:
   `c:\Users\harsh\OneDrive\Documents\ALL PROJECTS\Harsh.dev\WebAudit360\extension`
5. The **WebAudit 360** icon will appear in your browser toolbar!

---

## API Configuration

1. Click the WebAudit 360 extension icon in your toolbar.
2. Click the gear icon (`⚙️`) in the top-right corner of the popup.
3. Enter your WebAudit 360 API URL (default: `http://localhost:8000`) and your API Key.
4. Click **Save Settings**.
