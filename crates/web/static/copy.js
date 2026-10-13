// "Copy" buttons: <button data-copy="element-id"> copies that element's text.
// A static file because the Content-Security-Policy (`script-src 'self'`)
// blocks inline handlers.
(function () {
  "use strict";
  document.addEventListener("click", function (e) {
    var button = e.target.closest("button[data-copy]");
    if (!button) return;
    var source = document.getElementById(button.getAttribute("data-copy"));
    if (!source || !navigator.clipboard) return;
    navigator.clipboard.writeText(source.textContent).then(function () {
      var label = button.textContent;
      button.textContent = "Copied";
      setTimeout(function () { button.textContent = label; }, 1500);
    });
  });
})();
