"""Behaviour and wiring tests for the Proxmox endpoint form disclosure script.

The script is driven under Node with a minimal fake DOM. Node is a required CI
tool, so a missing binary fails rather than skips.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKAGE = REPO_ROOT / "netbox_proxbox"
SCRIPT = PACKAGE / "static" / "netbox_proxbox" / "js" / "proxmox-endpoint-form.js"
TEMPLATE = PACKAGE / "templates" / "netbox_proxbox" / "proxmoxendpoint_edit.html"

_HARNESS = r"""
const { computeVisibility, sync } = require(process.argv[1]);
const scenario = JSON.parse(process.argv[2]);

function classList() {
  const names = new Set();
  return {
    toggle(name, force) { if (force) names.add(name); else names.delete(name); },
    contains: (name) => names.has(name),
  };
}
function node(extra = {}) {
  return { classList: classList(), querySelector: () => null, ...extra };
}

const sshSection = node({ querySelector: () => (scenario.sshHasError ? {} : null) });
const packerRow = node();
const monitoringSection = node();
const form = { noValidate: false };
const elements = {
  id_access_methods: { value: scenario.accessMethod, closest: () => form },
  id_allow_writes: { checked: scenario.allowWrites },
  id_ssh_credential_source: { closest: () => sshSection },
  id_clear_ssh_password: { checked: Boolean(scenario.clearSshPassword) },
  id_clear_ssh_private_key: { checked: Boolean(scenario.clearSshKey) },
  id_allow_packer_template_builds: {
    checked: scenario.packerChecked, closest: () => packerRow,
  },
  id_service_monitoring_enabled: {
    checked: scenario.monitoringChecked, closest: () => monitoringSection,
  },
};
for (const id of scenario.omit || []) delete elements[id];
sync({ getElementById: (id) => elements[id] || null });

console.log(JSON.stringify({
  pure: computeVisibility({
    accessMethod: scenario.accessMethod,
    allowWrites: scenario.allowWrites,
    packerChecked: scenario.packerChecked,
    monitoringChecked: scenario.monitoringChecked,
    sshHasError: scenario.sshHasError,
    sshClearChecked: scenario.clearSshPassword || scenario.clearSshKey,
  }),
  hidden: {
    ssh: sshSection.classList.contains("d-none"),
    packer: packerRow.classList.contains("d-none"),
    monitoring: monitoringSection.classList.contains("d-none"),
  },
  noValidate: form.noValidate,
}));
"""


@pytest.fixture
def script_copy(tmp_path: Path) -> Path:
    """Copy the script as CommonJS so an enclosing ESM package cannot change it."""
    copy = tmp_path / "proxmox-endpoint-form.cjs"
    copy.write_text(SCRIPT.read_text())
    return copy


def _run(script: Path, **scenario: object) -> dict:
    node = shutil.which("node")
    assert node, "Node is required to run the endpoint form script tests"
    base = {
        "accessMethod": "api",
        "allowWrites": False,
        "packerChecked": False,
        "monitoringChecked": False,
        "sshHasError": False,
    }
    base.update(scenario)
    completed = subprocess.run(
        [node, "-e", _HARNESS, str(script), json.dumps(base)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


def test_api_only_without_writes_hides_every_dependent_section(
    script_copy: Path,
) -> None:
    result = _run(script_copy)
    assert result["hidden"] == {"ssh": True, "packer": True, "monitoring": True}


def test_writes_reveal_template_builds_but_not_ssh_or_monitoring(
    script_copy: Path,
) -> None:
    result = _run(script_copy, allowWrites=True)
    assert result["hidden"] == {"ssh": True, "packer": False, "monitoring": True}


def test_api_plus_ssh_reveals_ssh_credentials_without_writes(script_copy: Path) -> None:
    result = _run(script_copy, accessMethod="api_ssh")
    assert result["hidden"] == {"ssh": False, "packer": True, "monitoring": True}


def test_writes_and_ssh_reveal_everything(script_copy: Path) -> None:
    result = _run(script_copy, accessMethod="api_ssh", allowWrites=True)
    assert result["hidden"] == {"ssh": False, "packer": False, "monitoring": False}


def test_checked_dependent_options_are_never_hidden(script_copy: Path) -> None:
    result = _run(script_copy, packerChecked=True, monitoringChecked=True)
    assert result["hidden"] == {"ssh": True, "packer": False, "monitoring": False}


def test_a_section_with_a_validation_error_is_never_hidden(script_copy: Path) -> None:
    result = _run(script_copy, sshHasError=True)
    assert result["hidden"]["ssh"] is False


def test_missing_controls_leave_the_form_untouched(script_copy: Path) -> None:
    result = _run(script_copy, omit=["id_access_methods"])
    assert result["hidden"] == {"ssh": False, "packer": False, "monitoring": False}


def test_template_and_view_are_wired_to_the_script() -> None:
    template = TEMPLATE.read_text()
    assert "extends 'generic/object_edit.html'" in template
    assert "netbox_proxbox/js/proxmox-endpoint-form.js" in template
    views = (PACKAGE / "views" / "endpoints" / "proxmox.py").read_text()
    assert 'template_name = "netbox_proxbox/proxmoxendpoint_edit.html"' in views


def test_script_never_disables_inputs() -> None:
    source = SCRIPT.read_text()
    assert ".disabled" not in source
    assert "disabled" not in source.replace("is disabled", "")
    assert "innerHTML" not in source


@pytest.mark.parametrize("fragment", ["d-none"])
def test_script_hides_with_a_css_class(fragment: str) -> None:
    assert fragment in SCRIPT.read_text()


def test_browser_validation_is_off_only_while_a_section_is_hidden(
    script_copy: Path,
) -> None:
    assert _run(script_copy)["noValidate"] is True
    everything = _run(script_copy, accessMethod="api_ssh", allowWrites=True)
    assert everything["noValidate"] is False


@pytest.mark.parametrize("flag", ["clearSshPassword", "clearSshKey"])
def test_a_checked_clear_ssh_secret_request_keeps_the_ssh_section_visible(
    script_copy: Path, flag: str
) -> None:
    result = _run(script_copy, **{flag: True})
    assert result["hidden"]["ssh"] is False


def test_api_only_never_re_enables_browser_validation(script_copy: Path) -> None:
    # Everything is on screen (checked options and a clear request keep their
    # sections visible) but the endpoint is API only: the server ignores SSH
    # input, so the browser must not enforce SSH constraints either.
    result = _run(
        script_copy,
        allowWrites=True,
        packerChecked=True,
        monitoringChecked=True,
        clearSshPassword=True,
    )
    assert result["hidden"] == {"ssh": False, "packer": False, "monitoring": False}
    assert result["noValidate"] is True


def test_script_re_evaluates_on_every_change_event() -> None:
    source = SCRIPT.read_text()
    assert 'doc.addEventListener("change", run);' in source
