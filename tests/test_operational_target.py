"""Behavior tests for binding operational grants to backend endpoint ids."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types
from types import SimpleNamespace

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "netbox_proxbox" / "services" / "operational_target.py"


class _QuerySet:
    def __init__(self, endpoints: list[object]):
        self.endpoints = endpoints

    def filter(self, **kwargs):
        endpoint_id = kwargs.get("pk")
        return _QuerySet(
            [endpoint for endpoint in self.endpoints if endpoint.pk == endpoint_id]
        )

    def first(self):
        return self.endpoints[0] if self.endpoints else None


class _Manager:
    def __init__(self, *, all_endpoints: list[object], restricted: list[object]):
        self.all_endpoints = all_endpoints
        self.restricted = restricted

    def all(self):
        return _QuerySet(self.all_endpoints)

    def restrict(self, _user, action):
        assert action == "run_proxmox_action"
        return _QuerySet(self.restricted)


def _load(monkeypatch, *, endpoints, restricted, backend_ids, context_calls):
    package = types.ModuleType("netbox_proxbox")
    package.__path__ = [str(REPO_ROOT / "netbox_proxbox")]
    services = types.ModuleType("netbox_proxbox.services")
    services.__path__ = [str(REPO_ROOT / "netbox_proxbox" / "services")]
    views = types.ModuleType("netbox_proxbox.views")
    views.__path__ = [str(REPO_ROOT / "netbox_proxbox" / "views")]

    models = types.ModuleType("netbox_proxbox.models")
    models.ProxmoxEndpoint = type(
        "ProxmoxEndpoint",
        (),
        {"objects": _Manager(all_endpoints=endpoints, restricted=restricted)},
    )
    security = types.ModuleType("netbox_proxbox.operational_security")
    security.LEGACY_PROXMOX_ACTION_PERMISSION = "core.run_proxmox_action"
    backend_context = types.ModuleType("netbox_proxbox.services.backend_context")

    def get_context():
        context_calls.append("context")
        return SimpleNamespace(
            http_url="https://backend.example.test",
            headers={"Authorization": "redacted"},
            verify_ssl=True,
        )

    backend_context.get_fastapi_request_context = get_context
    endpoint_enabled = types.ModuleType("netbox_proxbox.services.endpoint_enabled")
    endpoint_enabled.endpoint_is_enabled = lambda endpoint: endpoint.enabled is True
    backend_sync = types.ModuleType("netbox_proxbox.views.backend_sync")

    def resolve_backend_endpoint_id(endpoint, **_kwargs):
        return backend_ids.get(endpoint.pk), None

    backend_sync.resolve_backend_endpoint_id = resolve_backend_endpoint_id

    for name, module in {
        "netbox_proxbox": package,
        "netbox_proxbox.services": services,
        "netbox_proxbox.views": views,
        "netbox_proxbox.models": models,
        "netbox_proxbox.operational_security": security,
        "netbox_proxbox.services.backend_context": backend_context,
        "netbox_proxbox.services.endpoint_enabled": endpoint_enabled,
        "netbox_proxbox.views.backend_sync": backend_sync,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)

    module_name = "netbox_proxbox.services.operational_target"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module


def test_granted_netbox_endpoint_translates_to_its_distinct_backend_id(monkeypatch):
    authorized = SimpleNamespace(pk=7, enabled=True, name="authorized")
    collision = SimpleNamespace(pk=9, enabled=True, name="unauthorized")
    calls: list[str] = []
    module = _load(
        monkeypatch,
        endpoints=[collision, authorized],
        restricted=[authorized],
        backend_ids={authorized.pk: 701, collision.pk: authorized.pk},
        context_calls=calls,
    )
    user = SimpleNamespace(has_perm=lambda _permission: False)

    target = module.resolve_operational_target(endpoint=authorized, user=user)

    assert target.endpoint is authorized
    assert target.backend_endpoint_id == 701
    assert target.backend_endpoint_id != authorized.pk
    assert calls == ["context"]


def test_unauthorized_collision_is_refused_before_backend_resolution(monkeypatch):
    authorized = SimpleNamespace(pk=7, enabled=True)
    collision = SimpleNamespace(pk=9, enabled=True)
    calls: list[str] = []
    module = _load(
        monkeypatch,
        endpoints=[authorized, collision],
        restricted=[authorized],
        backend_ids={authorized.pk: 701, collision.pk: authorized.pk},
        context_calls=calls,
    )
    user = SimpleNamespace(has_perm=lambda _permission: False)

    with pytest.raises(module.OperationalTargetError) as raised:
        module.resolve_operational_target(endpoint=collision, user=user)

    assert raised.value.reason == "permission_denied"
    assert calls == []


def test_disabled_endpoint_is_refused_before_backend_context(monkeypatch):
    endpoint = SimpleNamespace(pk=7, enabled=False)
    calls: list[str] = []
    module = _load(
        monkeypatch,
        endpoints=[endpoint],
        restricted=[endpoint],
        backend_ids={endpoint.pk: 701},
        context_calls=calls,
    )
    user = SimpleNamespace(has_perm=lambda _permission: False)

    with pytest.raises(module.OperationalTargetError) as raised:
        module.resolve_operational_target(endpoint=endpoint, user=user)

    assert raised.value.reason == "endpoint_disabled"
    assert calls == []
