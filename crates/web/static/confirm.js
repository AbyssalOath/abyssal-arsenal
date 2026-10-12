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
//
// Every POST form also shows that it's working once it's submitted (and the
// confirm, if any, was accepted): its submit buttons are disabled, the one
// clicked reads "Working…", and a second submit of the same form is ignored,
// so a slow action can't be fired twice by an impatient click. GET forms
// (filters, searches, downloads) are left alone, as is any form marked
// `data-no-busy`. Buttons come back if the page is restored from the
// back/forward cache, or after two minutes if the page is somehow still
// here (the load was stopped).
(function () {
  "use strict";

  var BUSY_LABEL = "Working\u2026";
  var BUSY_RESET_MS = 120000;

  function submitButtons(form) {
    return Array.prototype.filter.call(form.elements || [], function (el) {
      return (el.tagName === "BUTTON" && (el.type || "submit") === "submit") ||
        (el.tagName === "INPUT" && (el.type === "submit" || el.type === "image"));
    }).concat(form.id ? Array.prototype.slice.call(
      document.querySelectorAll('[form="' + form.id + '"][type="submit"]')) : []);
  }

  function setBusy(form, submitter) {
    form.setAttribute("data-busy", "");
    form.setAttribute("aria-busy", "true");
    var buttons = submitButtons(form);
    var labelled = submitter && buttons.indexOf(submitter) >= 0 ? submitter : buttons[0];
    // Disabled on the next tick: a button disabled now would drop out of the
    // data being submitted (its name/value, when it has one).
    window.setTimeout(function () {
      buttons.forEach(function (b) {
        if (b.disabled) return;
        b.disabled = true;
        b.setAttribute("data-busy-disabled", "");
      });
      if (labelled) {
        if (labelled.tagName === "INPUT") {
          labelled.setAttribute("data-busy-label", labelled.value);
          labelled.value = BUSY_LABEL;
        } else {
          labelled.setAttribute("data-busy-label", labelled.innerHTML);
          labelled.style.minWidth = labelled.offsetWidth + "px";
          labelled.innerHTML = '<span class="busy-spinner" aria-hidden="true"></span>' + BUSY_LABEL;
        }
      }
    }, 0);
    window.setTimeout(function () { clearBusy(form); }, BUSY_RESET_MS);
  }

  function clearBusy(form) {
    if (!form.hasAttribute("data-busy")) return;
    form.removeAttribute("data-busy");
    form.removeAttribute("aria-busy");
    submitButtons(form).forEach(function (b) {
      if (b.hasAttribute("data-busy-disabled")) {
        b.disabled = false;
        b.removeAttribute("data-busy-disabled");
      }
      if (b.hasAttribute("data-busy-label")) {
        if (b.tagName === "INPUT") b.value = b.getAttribute("data-busy-label");
        else b.innerHTML = b.getAttribute("data-busy-label");
        b.removeAttribute("data-busy-label");
        b.style.minWidth = "";
      }
    });
  }

  document.addEventListener("submit", function (e) {
    var form = e.target;
    if (!form || !form.getAttribute) return;
    if (form.hasAttribute("data-busy")) {
      e.preventDefault();
      return;
    }
    if (!confirmed(form)) {
      e.preventDefault();
      return;
    }
    var method = (form.getAttribute("method") || "get").toLowerCase();
    if (method === "post" && !form.hasAttribute("data-no-busy") && !e.defaultPrevented) {
      setBusy(form, e.submitter);
    }
  });

  // Back/forward cache: the page comes back exactly as it was left, busy
  // buttons included.
  window.addEventListener("pageshow", function (e) {
    if (!e.persisted) return;
    Array.prototype.forEach.call(document.querySelectorAll("form[data-busy]"), clearBusy);
  });

  function confirmed(form) {
    var message = form.getAttribute("data-confirm");
    if (!message) return true;
    var shred = form.elements && form.elements.shred_passes;
    var passes = shred ? parseInt(shred.value, 10) || 0 : 0;
    var shredMessage = form.getAttribute("data-confirm-shred");
    if (passes > 0 && shredMessage) {
      message = shredMessage.replace("{n}", String(passes));
    }
    return window.confirm(message);
  }

  document.addEventListener("change", function (e) {
    var input = e.target;
    if (input && input.hasAttribute && input.hasAttribute("data-autosubmit") && input.form) {
      input.form.requestSubmit ? input.form.requestSubmit() : input.form.submit();
    }
  });
})();
