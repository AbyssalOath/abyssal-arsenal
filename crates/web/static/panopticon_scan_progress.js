(function () {
  "use strict";

  var bar = document.getElementById("scan-progress-bar");
  if (!bar) {
    return;
  }
  var jobId = bar.getAttribute("data-job-id");
  var statusUrl = "/arsenals/panopticon/scan/status/" + jobId + "/json";
  var viewUrl = "/arsenals/panopticon/scan/status/" + jobId + "/view";

  var fill = bar.querySelector(".progress-bar-fill");
  var pctText = document.getElementById("scan-progress-pct");
  var countText = document.getElementById("scan-progress-count");

  // The no-JS fallback (a `<meta http-equiv="refresh">` full-page reload)
  // lives inside <noscript> in the template, so a browser running this
  // script never parses or arms that timer in the first place -- nothing
  // to cancel here. Removing the tag from the DOM after the fact used to
  // be tried instead and didn't reliably work: several browsers keep an
  // already-armed meta-refresh timer running even after the element that
  // requested it is gone.

  var POLL_INTERVAL_MS = 1000;
  var consecutiveErrors = 0;

  function applyProgress(data) {
    if (!fill) {
      return;
    }
    if (data.hosts_total > 0) {
      bar.classList.remove("indeterminate");
      var percent = Math.max(0, Math.min(100, data.percent));
      fill.style.width = percent + "%";
      bar.setAttribute("aria-valuenow", String(percent));
      if (pctText) {
        pctText.textContent = percent + "%";
      }
    }
    if (countText) {
      countText.textContent = data.hosts_scanned + " / " + data.hosts_total + " hosts";
    }
  }

  function poll() {
    fetch(statusUrl, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("progress request failed: " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        consecutiveErrors = 0;
        applyProgress(data);
        if (data.status === "complete" || data.status === "failed") {
          window.location.href = viewUrl;
          return;
        }
        window.setTimeout(poll, POLL_INTERVAL_MS);
      })
      .catch(function () {
        // A network hiccup or the job vanishing mid-poll shouldn't leave
        // the page stuck silently -- fall back to a real page load, which
        // itself redirects to the results once the job is actually done
        // (see scan_status's own terminal-state redirect).
        consecutiveErrors += 1;
        if (consecutiveErrors >= 3) {
          window.location.reload();
          return;
        }
        window.setTimeout(poll, POLL_INTERVAL_MS);
      });
  }

  poll();
})();
