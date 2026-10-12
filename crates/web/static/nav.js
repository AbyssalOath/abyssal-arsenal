// The top nav's "Menu" toggle at phone widths (style.css hides the links
// behind it below 1200px). A static file because the Content-Security-Policy
// (`script-src 'self'`) blocks inline handlers.
(function () {
  "use strict";

  var toggle = document.querySelector(".topnav-toggle");
  if (!toggle) return;
  var nav = toggle.closest(".topnav");

  function setOpen(open) {
    nav.classList.toggle("nav-open", open);
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
  }

  toggle.addEventListener("click", function () {
    setOpen(!nav.classList.contains("nav-open"));
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && nav.classList.contains("nav-open")) {
      setOpen(false);
      toggle.focus();
    }
  });
})();
