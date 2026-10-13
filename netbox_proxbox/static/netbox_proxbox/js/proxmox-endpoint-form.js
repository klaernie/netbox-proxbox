/*
 * Progressive disclosure for the Proxmox endpoint add/edit form.
 *
 * Read-only API settings are always visible. Settings that only matter for a
 * write-enabled or SSH-enabled endpoint are shown when they apply:
 *   - SSH credential section: access method is "API + SSH".
 *   - Template-build capability: "Allow Proxmox-side writes" is on.
 *   - Service monitoring section: writes are on and access method is "API + SSH".
 *
 * Sections are hidden with a CSS class, never by disabling inputs, so a hidden
 * field is still submitted unchanged. A section that holds a validation error,
 * or a checked option (including a "clear stored SSH secret" request) that
 * would otherwise be hidden, always stays visible so
 * the operator can see and clear it. Without scripting everything is visible.
 * Browser constraint validation is switched off while any section is hidden, so
 * a hidden field can never block submission; the server validates instead.
 */
(function (root) {
  "use strict";

  var API_SSH = "api_ssh";
  var HIDDEN_CLASS = "d-none";

  function computeVisibility(state) {
    var writes = Boolean(state.allowWrites);
    var ssh = state.accessMethod === API_SSH;
    return {
      sshCredentials:
        ssh || Boolean(state.sshHasError) || Boolean(state.sshClearChecked),
      packerBuilds:
        writes || Boolean(state.packerChecked) || Boolean(state.packerHasError),
      serviceMonitoring:
        (writes && ssh) ||
        Boolean(state.monitoringChecked) ||
        Boolean(state.monitoringHasError),
    };
  }

  function byId(doc, id) {
    return doc.getElementById(id);
  }

  function container(element, selector) {
    return element && element.closest ? element.closest(selector) : null;
  }

  function hasError(scope) {
    return Boolean(scope && scope.querySelector(".is-invalid, .has-errors, .text-danger"));
  }

  function isChecked(element) {
    return Boolean(element && element.checked);
  }

  function setHidden(element, hidden) {
    if (!element) {
      return;
    }
    element.classList.toggle(HIDDEN_CLASS, hidden);
  }

  function sync(doc) {
    var access = byId(doc, "id_access_methods");
    var writes = byId(doc, "id_allow_writes");
    if (!access || !writes) {
      return;
    }
    var sshSource = byId(doc, "id_ssh_credential_source");
    var packer = byId(doc, "id_allow_packer_template_builds");
    var monitoring = byId(doc, "id_service_monitoring_enabled");

    var sshSection = container(sshSource, ".field-group");
    var packerRow = container(packer, ".row");
    var monitoringSection = container(monitoring, ".field-group");

    var visible = computeVisibility({
      accessMethod: access.value,
      allowWrites: writes.checked,
      sshHasError: hasError(sshSection),
      sshClearChecked: isChecked(byId(doc, "id_clear_ssh_password")) ||
        isChecked(byId(doc, "id_clear_ssh_private_key")),
      packerChecked: packer ? packer.checked : false,
      packerHasError: hasError(packerRow),
      monitoringChecked: monitoring ? monitoring.checked : false,
      monitoringHasError: hasError(monitoringSection),
    });

    setHidden(sshSection, !visible.sshCredentials);
    setHidden(packerRow, !visible.packerBuilds);
    setHidden(monitoringSection, !visible.serviceMonitoring);

    // A hidden control keeps its HTML required/min/max constraints, and the
    // browser would refuse to submit the form because of a control the
    // operator cannot see. While anything is hidden the server is the only
    // validator; it re-validates every field and ignores irrelevant ones.
    var form = container(access, "form");
    if (form) {
      // API-only endpoints ignore SSH input on the server, so SSH constraints
      // must never block the browser even while an error or a checked clear
      // request keeps that section on screen.
      form.noValidate =
        access.value !== API_SSH ||
        !visible.sshCredentials ||
        !visible.packerBuilds ||
        !visible.serviceMonitoring;
    }
  }

  function init(doc) {
    var run = function () {
      sync(doc);
    };
    // Any change can alter which sections apply (the dependent checkboxes keep
    // their sections visible), and sync() is cheap, so re-evaluate on all of them.
    doc.addEventListener("change", run);
    doc.addEventListener("htmx:afterSettle", run);
    if (doc.readyState === "loading") {
      doc.addEventListener("DOMContentLoaded", run);
    } else {
      run();
    }
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { computeVisibility: computeVisibility, sync: sync };
  } else if (root && root.document) {
    init(root.document);
  }
})(typeof window !== "undefined" ? window : undefined);
