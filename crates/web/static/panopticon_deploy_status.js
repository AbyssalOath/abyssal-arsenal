(function () {
  "use strict";

  var bar = document.getElementById("deploy-progress-bar");
  if (!bar) {
    return;
  }
  var jobId = bar.getAttribute("data-job-id");
  var statusUrl = "/arsenals/panopticon/deploy/status/" + jobId + "/json";

  var fill = bar.querySelector(".progress-bar-fill");
  var countText = document.getElementById("deploy-progress-count");
  var messageText = document.getElementById("deploy-status-message");
  var table = document.getElementById("deploy-status-table");

  var metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
  if (metaRefresh && metaRefresh.parentNode) {
    metaRefresh.parentNode.removeChild(metaRefresh);
  }

  function badge(text, cls) {
    var span = document.createElement("span");
    span.className = "badge " + cls;
    span.textContent = text;
    return span;
  }

  function renderHostnameCell(cell, host) {
    cell.textContent = "";
    cell.appendChild(document.createTextNode(host.hostname ? host.hostname : "—"));
    if (host.hostname_is_fallback) {
      cell.appendChild(document.createTextNode(" "));
      var b = badge("IP fallback", "badge-warning");
      b.title = "Could not confirm a real hostname -- this is the IP address, showing here as a stand-in.";
      cell.appendChild(b);
    }
  }

  function renderStatusCell(cell, host) {
    cell.textContent = "";
    cell.appendChild(badge(host.state_label, host.state_class));
  }

  function renderDetailsCell(cell, host) {
    cell.textContent = "";
    if (host.failure_detail) {
      var div = document.createElement("div");
      div.className = "error-banner";
      div.style.margin = "0";
      div.textContent = host.failure_detail;
      cell.appendChild(div);
    }
    if (host.output) {
      var details = document.createElement("details");
      var summary = document.createElement("summary");
      summary.textContent = "Command output";
      var pre = document.createElement("pre");
      pre.style.whiteSpace = "pre-wrap";
      pre.style.overflowWrap = "anywhere";
      pre.style.margin = "8px 0 0";
      pre.textContent = host.output;
      details.appendChild(summary);
      details.appendChild(pre);
      cell.appendChild(details);
    }
  }

  function applyUpdate(data) {
    var percent = data.hosts_total > 0
      ? Math.round((data.hosts_terminal / data.hosts_total) * 100)
      : 100;
    if (fill) {
      fill.style.width = percent + "%";
    }
    bar.setAttribute("aria-valuenow", String(percent));
    if (countText) {
      countText.textContent = data.hosts_terminal + " / " + data.hosts_total + " hosts complete";
    }

    if (table) {
      var rows = table.querySelectorAll("tbody tr");
      rows.forEach(function (row) {
        var ip = row.getAttribute("data-ip");
        var host = null;
        for (var i = 0; i < data.hosts.length; i++) {
          if (data.hosts[i].ip_address === ip) {
            host = data.hosts[i];
            break;
          }
        }
        if (!host) {
          return;
        }
        renderHostnameCell(row.querySelector(".dh-hostname-cell"), host);
        renderStatusCell(row.querySelector(".dh-status-cell"), host);
        renderDetailsCell(row.querySelector(".dh-details-cell"), host);
      });
    }

    if (data.complete && messageText) {
      messageText.textContent = "Every host in this job has reached a final state.";
    }
  }

  var POLL_INTERVAL_MS = 1500;
  var consecutiveErrors = 0;

  function poll() {
    fetch(statusUrl, { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) {
          throw new Error("deploy status request failed: " + response.status);
        }
        return response.json();
      })
      .then(function (data) {
        consecutiveErrors = 0;
        applyUpdate(data);
        if (data.complete) {
          return;
        }
        window.setTimeout(poll, POLL_INTERVAL_MS);
      })
      .catch(function () {
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
