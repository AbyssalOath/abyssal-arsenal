(function () {
  "use strict";

  // Generic "select all" / "deselect all" wiring for the role-permission
  // and dashboard-arsenal checkbox grids on a role's page
  // (/admin/roles/:id). A button with data-select-all="<container id>"
  // checks every checkbox inside that container; data-deselect-all
  // unchecks them. Purely a convenience on top of ordinary checkboxes --
  // every checkbox still works individually with JS disabled, so nothing
  // here is required to actually use the page, just faster for a large
  // permission list.
  function wire(attr, value) {
    document.querySelectorAll("[" + attr + "]").forEach(function (button) {
      var targetId = button.getAttribute(attr);
      var container = document.getElementById(targetId);
      if (!container) {
        return;
      }
      button.addEventListener("click", function () {
        container.querySelectorAll('input[type="checkbox"]').forEach(function (checkbox) {
          checkbox.checked = value;
        });
      });
    });
  }

  wire("data-select-all", true);
  wire("data-deselect-all", false);
})();
