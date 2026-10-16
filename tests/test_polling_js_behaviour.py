"""Behavioural tests for ``static/netbox_proxbox/js/polling.js`` under Node.

The module is copied next to stub ``common.js`` / ``table.js`` siblings and
driven with a scripted ``fetch``. Each scenario prints one JSON summary that
the test asserts on. Node is a required CI tool, so a missing binary fails
rather than skips.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
POLLING_JS = (
    REPO_ROOT / "netbox_proxbox" / "static" / "netbox_proxbox" / "js" / "polling.js"
)
CURSOR_A = "0123456789abcdef.1"
CURSOR_B = "0123456789abcdef.2"

_HARNESS = r"""
import { poll, startSync } from "./polling.js";

const scenario = JSON.parse(process.argv[2]);
const requests = [];
let index = 0;
globalThis.document = { cookie: "csrftoken=tok123", querySelector: () => null };
globalThis.setTimeout = (fn) => fn();
globalThis.fetch = async (url, init = {}) => {
  requests.push({ url, method: init.method || "GET", headers: init.headers || {} });
  const step = scenario.responses[Math.min(index, scenario.responses.length - 1)];
  index += 1;
  return {
    ok: step.status >= 200 && step.status < 300,
    status: step.status,
    headers: { get: (name) => (step.headers || {})[name] ?? null },
    json: async () => step.body,
  };
};

const summary = { completed: 0, errors: [], requests };
if (scenario.mode === "start") {
  summary.payload = await startSync(scenario.kind);
} else if (scenario.mode === "start_then_poll") {
  summary.payload = await startSync(scenario.kind);
  await poll(scenario.kind, {
    cursor: summary.payload.cursor,
    maxIdlePolls: scenario.maxIdlePolls,
    onComplete: () => { summary.completed += 1; },
    onError: (error) => { summary.errors.push(String(error.message || error)); },
  });
} else {
  await poll(scenario.kind, {
    cursor: scenario.cursor ?? null,
    run_id: scenario.run_id ?? null,
    maxIdlePolls: scenario.maxIdlePolls,
    onComplete: () => { summary.completed += 1; },
    onError: (error) => { summary.errors.push(String(error.message || error)); },
  });
}
console.log(JSON.stringify(summary));
"""


@pytest.fixture
def run_scenario(tmp_path: Path):
    node = shutil.which("node")
    if node is None:
        pytest.fail("Node.js is required to exercise polling.js behaviour.")
    shutil.copy(POLLING_JS, tmp_path / "polling.js")
    (tmp_path / "common.js").write_text(
        "export function getCsrfToken() { return 'tok123'; }\n", encoding="utf-8"
    )
    (tmp_path / "table.js").write_text(
        "export function populateTable() {}\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text('{"type": "module"}', encoding="utf-8")
    harness = tmp_path / "harness.js"
    harness.write_text(_HARNESS, encoding="utf-8")

    def _run(scenario: dict) -> dict:
        result = subprocess.run(
            [node, str(harness), json.dumps(scenario)],
            cwd=tmp_path,
            text=True,
            capture_output=True,
            timeout=30,
            check=True,
        )
        return json.loads(result.stdout.strip().splitlines()[-1])

    return _run


def _page(body: list, cursor: str = CURSOR_B, status: int = 200) -> dict:
    return {
        "status": status,
        "body": body,
        "headers": {"X-Proxbox-Next-Cursor": cursor},
    }


def test_empty_polls_before_the_first_message_do_not_complete(run_scenario) -> None:
    terminal = json.dumps({"object": "device", "end": True})
    summary = run_scenario(
        {
            "kind": "devices",
            "cursor": CURSOR_A,
            "maxIdlePolls": 10,
            "responses": [_page([]), _page([]), _page([terminal])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 3
    assert f"after={CURSOR_A}" in summary["requests"][0]["url"]
    assert f"after={CURSOR_B}" in summary["requests"][1]["url"]


def test_terminal_message_for_another_kind_does_not_complete(run_scenario) -> None:
    other = json.dumps({"object": "virtual_machine", "end": True})
    summary = run_scenario(
        {
            "kind": "devices",
            "maxIdlePolls": 2,
            "responses": [_page([other]), _page([]), _page([])],
        }
    )

    assert summary["completed"] == 0
    assert summary["errors"] == ["Timed out waiting for the sync to finish."]


def test_http_errors_stop_polling_with_an_error(run_scenario) -> None:
    summary = run_scenario(
        {
            "kind": "devices",
            "maxIdlePolls": 10,
            "responses": [{"status": 403, "body": {"error": "denied"}}],
        }
    )

    assert summary["completed"] == 0
    assert summary["errors"] == ["Polling failed with status 403"]
    assert len(summary["requests"]) == 1


def test_start_sync_posts_with_the_csrf_header(run_scenario) -> None:
    summary = run_scenario(
        {
            "mode": "start",
            "kind": "full-update",
            "responses": [
                {"status": 202, "body": {"queued": True, "cursor": CURSOR_A}}
            ],
        }
    )

    request = summary["requests"][0]
    assert request["method"] == "POST"
    assert request["headers"]["X-CSRFToken"] == "tok123"
    assert request["url"].endswith("/plugins/proxbox/websocket/full-update")
    assert summary["payload"]["cursor"] == CURSOR_A


def test_start_response_run_id_flows_into_polling(run_scenario) -> None:
    run_id = "flow_run_123"
    aggregate = json.dumps(
        {
            "object": "full-update",
            "end": True,
            "run_id": run_id,
            "status": "completed",
            "stages": {"virtual-machines": "skipped"},
        }
    )
    summary = run_scenario(
        {
            "mode": "start_then_poll",
            "kind": "full-update",
            "maxIdlePolls": 5,
            "responses": [
                {
                    "status": 202,
                    "body": {"queued": True, "cursor": CURSOR_A, "run_id": run_id},
                },
                _page([aggregate]),
            ],
        }
    )

    assert summary["payload"]["run_id"] == run_id
    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert f"after={CURSOR_A}" in summary["requests"][1]["url"]


def _flagged_page(header: str) -> dict:
    return {
        "status": 200,
        "body": [json.dumps({"object": "device", "end": True})],
        "headers": {"X-Proxbox-Next-Cursor": CURSOR_B, header: "1"},
    }


@pytest.mark.parametrize("header", ["X-Proxbox-Cursor-Reset", "X-Proxbox-Cursor-Gap"])
def test_cursor_loss_is_an_error_even_with_a_terminal_message(run_scenario, header):
    summary = run_scenario(
        {"kind": "devices", "maxIdlePolls": 10, "responses": [_flagged_page(header)]}
    )

    assert summary["completed"] == 0
    assert len(summary["errors"]) == 1
    assert "interrupted" in summary["errors"][0]


def test_full_update_completes_on_the_vm_stage_terminal(run_scenario) -> None:
    device_end = json.dumps({"object": "device", "end": True})
    vm_end = json.dumps({"object": "virtual_machine", "end": True})
    summary = run_scenario(
        {
            "kind": "full-update",
            "maxIdlePolls": 50,
            "responses": [_page([device_end]), _page([]), _page([vm_end])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 3


def test_correlated_terminal_requires_the_matching_run_id(run_scenario) -> None:
    run_id = "run_match_123"
    wrong = json.dumps({"object": "device", "end": True, "run_id": "run_other_456"})
    missing = json.dumps({"object": "device", "end": True})
    matching = json.dumps({"object": "device", "end": True, "run_id": run_id})
    summary = run_scenario(
        {
            "kind": "devices",
            "run_id": run_id,
            "maxIdlePolls": 10,
            "responses": [_page([wrong]), _page([missing]), _page([matching])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 3


def test_legacy_poll_ignores_correlated_broadcast_terminal(run_scenario) -> None:
    correlated = json.dumps(
        {"object": "device", "end": True, "run_id": "other_run_123"}
    )
    legacy = json.dumps({"object": "device", "end": True})
    summary = run_scenario(
        {
            "kind": "devices",
            "maxIdlePolls": 5,
            "responses": [_page([correlated]), _page([legacy])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 2


def test_dispatch_downgrade_switches_polling_to_legacy_frames(run_scenario) -> None:
    run_id = "downgrade_run_123"
    control = json.dumps(
        {
            "object": "sync-run",
            "run_id": run_id,
            "correlated": False,
        }
    )
    legacy = json.dumps({"object": "device", "end": True})
    summary = run_scenario(
        {
            "kind": "devices",
            "run_id": run_id,
            "maxIdlePolls": 5,
            "responses": [_page([control, legacy])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 1


def test_correlated_full_update_completes_on_aggregate_with_skipped_stage(
    run_scenario,
) -> None:
    run_id = "full_run_123"
    vm_end = json.dumps({"object": "virtual_machine", "end": True, "run_id": run_id})
    aggregate = json.dumps(
        {
            "object": "full-update",
            "end": True,
            "run_id": run_id,
            "status": "completed",
            "stages": {"devices": "completed", "virtual-machines": "skipped"},
        }
    )
    summary = run_scenario(
        {
            "kind": "full-update",
            "run_id": run_id,
            "maxIdlePolls": 10,
            "responses": [_page([vm_end]), _page([aggregate])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 2


def test_correlated_failed_full_update_surfaces_an_error(run_scenario) -> None:
    run_id = "failed_run_123"
    aggregate = json.dumps(
        {
            "object": "full-update",
            "end": True,
            "run_id": run_id,
            "status": "failed",
            "stages": {"devices": "completed", "virtual-machines": "failed"},
        }
    )
    summary = run_scenario(
        {
            "kind": "full-update",
            "run_id": run_id,
            "maxIdlePolls": 10,
            "responses": [_page([aggregate])],
        }
    )

    assert summary["completed"] == 0
    assert summary["errors"] == ["Full update failed: virtual-machines."]


@pytest.mark.parametrize("run_id", ["trust_run_123", None])
def test_bridge_trust_failure_surfaces_an_error(run_scenario, run_id) -> None:
    failure = {
        "object": "sync-run",
        "end": True,
        "status": "failed",
        "kind": "devices",
        "error": "WebSocket endpoint trust changed before transmission.",
    }
    if run_id is not None:
        failure["run_id"] = run_id
    summary = run_scenario(
        {
            "kind": "devices",
            "run_id": run_id,
            "maxIdlePolls": 5,
            "responses": [_page([json.dumps(failure)])],
        }
    )

    assert summary["completed"] == 0
    assert summary["errors"] == [
        "WebSocket endpoint trust changed before transmission."
    ]


def test_malformed_run_ids_and_statuses_are_ignored_until_valid_terminal(
    run_scenario,
) -> None:
    run_id = "valid_run_123"
    malformed = [
        json.dumps(
            {
                "object": "full-update",
                "end": True,
                "run_id": value,
                "status": "completed",
            }
        )
        for value in ([], {}, 7, None)
    ]
    malformed.extend(
        json.dumps(
            {
                "object": "full-update",
                "end": True,
                "run_id": run_id,
                "status": value,
            }
        )
        for value in ([], {}, 7, None)
    )
    valid = json.dumps(
        {
            "object": "full-update",
            "end": True,
            "run_id": run_id,
            "status": "completed",
            "stages": {"virtual-machines": "skipped"},
        }
    )
    summary = run_scenario(
        {
            "kind": "full-update",
            "run_id": run_id,
            "maxIdlePolls": 5,
            "responses": [_page(malformed), _page([valid])],
        }
    )

    assert summary["completed"] == 1
    assert summary["errors"] == []
    assert len(summary["requests"]) == 2


def test_full_update_waits_through_a_quiet_interval_for_the_vm_stage(
    run_scenario,
) -> None:
    device_end = json.dumps({"object": "device", "end": True})
    vm_end = json.dumps({"object": "virtual_machine", "end": True})
    summary = run_scenario(
        {
            "kind": "full-update",
            "maxIdlePolls": 50,
            "responses": [_page([device_end])] + [_page([])] * 11 + [_page([vm_end])],
        }
    )

    assert summary["completed"] == 1
    assert len(summary["requests"]) == 13


def test_full_update_silence_after_devices_is_a_timeout_not_success(
    run_scenario,
) -> None:
    device_end = json.dumps({"object": "device", "end": True})
    summary = run_scenario(
        {
            "kind": "full-update",
            "maxIdlePolls": 5,
            "responses": [_page([device_end])] + [_page([])] * 6,
        }
    )

    assert summary["completed"] == 0
    assert summary["errors"] == ["Timed out waiting for the sync to finish."]


def test_full_update_does_not_complete_on_idle_without_device_terminal(
    run_scenario,
) -> None:
    summary = run_scenario(
        {"kind": "full-update", "maxIdlePolls": 12, "responses": [_page([])] * 12}
    )

    assert summary["completed"] == 0
    assert summary["errors"] == ["Timed out waiting for the sync to finish."]
