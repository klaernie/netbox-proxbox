"""Static contracts for the build-pve-template REST action on ProxmoxEndpoint."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]


def _load_backend_helper(monkeypatch, *, changed_default=None, default_calls=None):
    schema = ModuleType("netbox_proxbox.schemas.backend_proxy")
    schema.BackendRequestContext = object
    backend_proxy = ModuleType("netbox_proxbox.services.backend_proxy")

    def get_default():
        if default_calls is not None:
            default_calls.append(True)
        return changed_default

    backend_proxy.get_fastapi_request_context = get_default
    errors = ModuleType("netbox_proxbox.views.error_utils")
    errors.extract_backend_error_detail = lambda exc: (str(exc), 502)
    errors.parse_requests_response_json = lambda response, **kwargs: (
        response.json(),
        None,
    )
    monkeypatch.setitem(sys.modules, schema.__name__, schema)
    monkeypatch.setitem(sys.modules, backend_proxy.__name__, backend_proxy)
    monkeypatch.setitem(sys.modules, errors.__name__, errors)
    path = ROOT / "netbox_proxbox/api/build_pve_template.py"
    spec = importlib.util.spec_from_file_location("_test_build_transport", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pve_template_serializer_module_exists() -> None:
    module = ROOT / "netbox_proxbox/api/serializers/pve_template.py"
    src = module.read_text()
    for token in (
        "PVETemplateBuildRequestSerializer",
        "PVETemplateBuildResponseSerializer",
        "vmid",
        "target_node",
        "pve_version_pin",
        "ssh_authorized_keys",
        "create_vm",
    ):
        assert token in src, f"missing token in pve_template.py serializer: {token!r}"


def test_pve_template_serializer_exported() -> None:
    init = (ROOT / "netbox_proxbox/api/serializers/__init__.py").read_text()
    assert "PVETemplateBuildRequestSerializer" in init
    assert "PVETemplateBuildResponseSerializer" in init


def test_build_pve_template_action_registered_on_viewset() -> None:
    views = (ROOT / "netbox_proxbox/api/views.py").read_text()
    for token in (
        'url_path="build-pve-template"',
        'url_path="cloud-image-build-pipeline"',
        "PVETemplateBuildRequestSerializer",
        "build_cloud_image_pipeline_via_backend",
        "build_pve_template_via_backend",
        "require_template_build_authorization",
        "resolve_authorized_template_build_target",
        "_PackerTemplateBuildActionPermission",
        '"endpoint_id"',
    ):
        assert token in views, f"missing token in api/views.py: {token!r}"


def test_build_pve_template_backend_helper_targets_correct_path() -> None:
    helper = (ROOT / "netbox_proxbox/api/build_pve_template.py").read_text()
    assert "/cloud/templates/images" in helper
    assert "get_fastapi_request_context" not in helper
    assert "context: BackendRequestContext" in helper
    assert "requests.post" in helper
    assert "extract_backend_error_detail" in helper
    assert "parse_requests_response_json" in helper
    assert "response.text[:500]" not in helper
    assert "build_pve_template_via_backend" in helper


def test_cloud_image_build_pipeline_serializer_supports_firewall_products() -> None:
    serializer = (ROOT / "netbox_proxbox/api/serializers/pve_template.py").read_text()
    assert "pfsense" in serializer
    assert "opnsense" in serializer
    assert "release_image" in serializer
    assert "source_tree" in serializer


def test_template_transport_stays_bound_to_resolved_backend_context(
    monkeypatch,
) -> None:
    calls: list[tuple[str, dict[str, object]]] = []

    def post(url: str, **kwargs: object) -> SimpleNamespace:
        calls.append((url, kwargs))
        return SimpleNamespace(
            status_code=201,
            json=lambda: {"queued": True},
        )

    original_context = SimpleNamespace(
        http_url="https://backend-a.example.test",
        headers={"Authorization": "Bearer backend-a"},
        verify_ssl=False,
    )
    changed_default = SimpleNamespace(
        http_url="https://backend-b.example.test",
        headers={"Authorization": "Bearer backend-b"},
        verify_ssl=True,
    )
    default_calls: list[bool] = []
    module = _load_backend_helper(
        monkeypatch,
        changed_default=changed_default,
        default_calls=default_calls,
    )
    monkeypatch.setattr(module.requests, "post", post)

    body, status = module.build_cloud_image_pipeline_via_backend(
        {"endpoint_id": 701}, context=original_context
    )

    assert changed_default.http_url not in calls[0][0]
    assert calls[0][0] == "https://backend-a.example.test/cloud/templates/images"
    assert calls[0][1]["headers"]["Authorization"] == "Bearer backend-a"
    assert calls[0][1]["verify"] is False
    assert default_calls == []
    assert body == {"queued": True}
    assert status == 201
