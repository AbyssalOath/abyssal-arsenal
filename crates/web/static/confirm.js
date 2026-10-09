// Declarative confirmations and auto-submit, without inline JavaScript --
// the Content-Security-Policy (`script-src 'self'`) blocks `onsubmit=` /
// `onchange=` attributes outright, so they silently never ran.
//
//   <form data-confirm="Delete this?">            asks before submitting
//   <form data-confirm="Delete this?"
//         data-confirm-shred="Shred ({n} passes) and delete?">
//                                                  the second message (with
//                                                  {n} filled in) when the
//                                                  form's shred_passes > 0
//   <input type="checkbox" data-autosubmit>        submits its form on change
(function () {
  "use strict";

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form || !form.getAttribute) return;
    var message = form.getAttribute("data-confirm");
    if (!message) return;
    var shred = form.elements && form.elements.shred_passes;
    var passes = shred ? parseInt(shred.value, 10) || 0 : 0;
    var shredMessage = form.getAttribute("data-confirm-shred");
    if (passes > 0 && shredMessage) {
      message = shredMessage.replace("{n}", String(passes));
    }
    if (!window.confirm(message)) {
      e.preventDefault();
    }
  });

  document.addEventListener("change", function (e) {
    var input = e.target;
    if (input && input.hasAttribute && input.hasAttribute("data-autosubmit") && input.form) {
      input.form.requestSubmit ? input.form.requestSubmit() : input.form.submit();
    }
  });
})();
