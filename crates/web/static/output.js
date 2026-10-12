// "Wrap lines" and "Copy" buttons above each raw command output
// (`<pre class="cmd-output">`). Output doesn't wrap by default so tables
// keep their columns; wrapping is one click for long log lines. The choice
// is remembered per browser. A static file because the
// Content-Security-Policy (`script-src 'self'`) blocks inline scripts.
(function () {
  "use strict";

  var WRAP_KEY = "aa.cmdOutputWrap";

  function wrapPreferred() {
    try { return window.localStorage.getItem(WRAP_KEY) === "1"; } catch (e) { return false; }
  }
  function rememberWrap(on) {
    try { window.localStorage.setItem(WRAP_KEY, on ? "1" : "0"); } catch (e) { /* private mode */ }
  }

  function button(label) {
    var b = document.createElement("button");
    b.type = "button";
    b.className = "btn-secondary btn-sm";
    b.textContent = label;
    return b;
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    // Plain-HTTP fallback (navigator.clipboard needs HTTPS).
    return new Promise(function (resolve, reject) {
      var area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      var ok = false;
      try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
      document.body.removeChild(area);
      ok ? resolve() : reject();
    });
  }

  Array.prototype.forEach.call(document.querySelectorAll("pre.cmd-output"), function (pre) {
    var tools = document.createElement("div");
    tools.className = "cmd-output-tools";

    var wrap = button("Wrap lines");
    function setWrap(on) {
      pre.classList.toggle("cmd-output-wrap", on);
      wrap.setAttribute("aria-pressed", on ? "true" : "false");
      wrap.textContent = on ? "Don’t wrap" : "Wrap lines";
    }
    setWrap(wrapPreferred());
    wrap.addEventListener("click", function () {
      var on = !pre.classList.contains("cmd-output-wrap");
      setWrap(on);
      rememberWrap(on);
    });

    var copy = button("Copy");
    copy.addEventListener("click", function () {
      copyText(pre.textContent).then(function () {
        copy.textContent = "Copied";
      }, function () {
        copy.textContent = "Copy failed";
      });
      window.setTimeout(function () { copy.textContent = "Copy"; }, 1500);
    });

    tools.appendChild(wrap);
    tools.appendChild(copy);
    pre.parentNode.insertBefore(tools, pre);
  });
})();
