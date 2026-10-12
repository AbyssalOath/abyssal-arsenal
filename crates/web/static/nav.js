// The top nav's "Menu" toggle at phone widths (style.css hides the links
// behind it below 1200px), and closing the top bar's dropdowns (Arsenals,
// Apotheosis, the user menu) and the breadcrumb's host switcher on an
// outside click or Escape. A static file because the Content-Security-Policy
// (`script-src 'self'`) blocks inline handlers.
(function () {
  "use strict";

  var nav = document.querySelector(".topnav");
  if (!nav) return;
  var toggle = nav.querySelector(".topnav-toggle");

  function setOpen(open) {
    nav.classList.toggle("nav-open", open);
    if (toggle) toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  // The top bar's dropdowns and the breadcrumb's host switcher.
  function openMenus() {
    return document.querySelectorAll(".topnav details[open], .breadcrumb details[open]");
  }

  if (toggle) {
    toggle.addEventListener("click", function () {
      setOpen(!nav.classList.contains("nav-open"));
    });
  }

  // Opening one dropdown closes the others.
  document.addEventListener("toggle", function (e) {
    var opened = e.target;
    if (!opened.open || !opened.closest(".topnav, .breadcrumb")) return;
    openMenus().forEach(function (d) {
      if (d !== opened && !d.contains(opened)) d.open = false;
    });
  }, true);

  document.addEventListener("click", function (e) {
    openMenus().forEach(function (d) {
      if (!d.contains(e.target)) d.open = false;
    });
  });

  document.addEventListener("keydown", function (e) {
    if (e.key !== "Escape") return;
    var menus = openMenus();
    if (menus.length) {
      menus.forEach(function (d) { d.open = false; });
      var summary = menus[menus.length - 1].querySelector("summary");
      if (summary) summary.focus();
      return;
    }
    if (toggle && nav.classList.contains("nav-open")) {
      setOpen(false);
      toggle.focus();
    }
  });
})();
