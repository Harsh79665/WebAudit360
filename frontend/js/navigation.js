/**
 * WebAudit 360 — Animated Slide Menu & Accessible Navigation
 * Author: Harsh Patel
 * Supports desktop slide-in and mobile slide-over drawer with focus handling.
 */

export function initNavigation() {
  const menuToggleBtns = document.querySelectorAll(".menu-toggle-btn");
  const slideMenu = document.getElementById("slide-menu");
  const menuBackdrop = document.getElementById("slide-menu-backdrop");
  const closeBtn = document.getElementById("slide-menu-close");
  let previouslyFocused = null;

  if (!slideMenu || !menuBackdrop) return;

  function openMenu() {
    previouslyFocused = document.activeElement;
    slideMenu.classList.add("open");
    menuBackdrop.classList.add("open");
    document.body.style.overflow = "hidden"; // lock background scroll

    // Focus close button or first focusable element
    if (closeBtn) {
      closeBtn.focus();
    }
  }

  function closeMenu() {
    slideMenu.classList.remove("open");
    menuBackdrop.classList.remove("open");
    document.body.style.overflow = "";

    // Return focus
    if (previouslyFocused && typeof previouslyFocused.focus === "function") {
      previouslyFocused.focus();
    }
  }

  menuToggleBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const isOpen = slideMenu.classList.contains("open");
      if (isOpen) {
        closeMenu();
      } else {
        openMenu();
      }
    });
  });

  if (closeBtn) {
    closeBtn.addEventListener("click", closeMenu);
  }

  menuBackdrop.addEventListener("click", closeMenu);

  // Keyboard accessibility: Escape key closes menu
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && slideMenu.classList.contains("open")) {
      closeMenu();
    }
  });

  // Highlight current nav item based on URL
  const currentPath = window.location.pathname.split("/").pop() || "index.html";
  const allNavLinks = document.querySelectorAll(".nav-link, .slide-nav-item, .app-sidebar-link");
  allNavLinks.forEach((link) => {
    const href = link.getAttribute("href");
    if (href && (href === currentPath || (currentPath === "" && href === "index.html"))) {
      link.classList.add("active");
    }
  });
}
