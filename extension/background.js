/**
 * WebAudit 360 — Chrome Extension Service Worker (Manifest V3)
 * Author: Harsh Patel
 */

chrome.runtime.onInstalled.addListener(() => {
  console.log("WebAudit 360 extension successfully installed.");

  // Create right-click context menu item
  chrome.contextMenus.create({
    id: "webaudit360-scan-page",
    title: "Audit this page with WebAudit 360",
    contexts: ["page", "link"]
  });
});

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === "webaudit360-scan-page") {
    const targetUrl = info.linkUrl || info.pageUrl;
    console.log("Context menu requested audit for:", targetUrl);
    // Open WebAudit 360 new-audit prefill page
    chrome.storage.sync.get(["webaudit_api_url"], (items) => {
      const baseUrl = items.webaudit_api_url || "http://localhost:8000";
      chrome.tabs.create({
        url: `${baseUrl}/new-audit.html?prefill=${encodeURIComponent(targetUrl)}`
      });
    });
  }
});
