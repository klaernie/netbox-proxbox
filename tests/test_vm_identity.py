"""Behavior tests for the canonical typed VM identity resolver."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest


MODULE_PATH = Path(__file__).resolve().parents[1] / "netbox_proxbox" / "vm_identity.py"


@pytest.fixture
def vm_identity():
    spec = importlib.util.spec_from_file_location(
        "_vm_identity_under_test", MODULE_PATH
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _vm(**state_values):
    vm = SimpleNamespace(
        pk=42,
        device=None,
        cluster=None,
        virtual_machine_type=None,
        custom_field_data={},
    )
    vm.proxbox_sync_state = SimpleNamespace(
        virtual_machine_id=vm.pk,
        **state_values,
    )
    return vm


def test_resolvers_read_every_identity_value_from_typed_state(vm_identity):
    node = SimpleNamespace(name="pve-sidecar")
    cluster = SimpleNamespace(name="cluster-sidecar")
    vm = _vm(
        proxmox_vm_id=501,
        proxmox_vm_type="lxc",
        proxmox_node=node,
        proxmox_node_name="node-fallback",
        proxmox_cluster=cluster,
        proxmox_cluster_name="cluster-fallback",
    )

    assert vm_identity.resolve_vm_vmid(vm) == "501"
    assert vm_identity.resolve_known_vm_type(vm) == "lxc"
    assert vm_identity.resolve_vm_type(vm) == "lxc"
    assert vm_identity.resolve_vm_node(vm) == "pve-sidecar"
    assert vm_identity.resolve_vm_cluster_name(vm) == "cluster-sidecar"


def test_node_prefers_sidecar_fk_then_sidecar_name_then_device(vm_identity):
    vm = _vm(
        proxmox_node=SimpleNamespace(name="pve-fk"),
        proxmox_node_name="pve-name",
    )
    vm.device = SimpleNamespace(name="pve-device")
    assert vm_identity.resolve_vm_node(vm) == "pve-fk"

    vm.proxbox_sync_state.proxmox_node = None
    assert vm_identity.resolve_vm_node(vm) == "pve-name"

    vm.proxbox_sync_state.proxmox_node_name = ""
    assert vm_identity.resolve_vm_node(vm) == "pve-device"


def test_cluster_and_type_use_typed_fallbacks_without_custom_fields(vm_identity):
    vm = _vm(
        proxmox_cluster=None,
        proxmox_cluster_name="cluster-name",
        proxmox_vm_type="",
    )
    vm.virtual_machine_type = SimpleNamespace(slug="lxc-container")

    assert vm_identity.resolve_vm_cluster_name(vm) == "cluster-name"
    assert vm_identity.resolve_known_vm_type(vm) == "lxc"


def test_removed_custom_fields_are_never_identity_fallbacks(vm_identity):
    vm = _vm(
        proxmox_vm_id=None,
        proxmox_vm_type="",
        proxmox_node=None,
        proxmox_node_name="",
    )
    vm.custom_field_data = {
        "proxmox_vm_id": 999,
        "cf_proxmox_vm_id": 998,
        "proxmox_vm_type": "lxc",
        "cf_proxmox_vm_type": "lxc",
        "proxmox_node": "legacy-node",
        "cf_proxmox_node": "legacy-node-2",
    }

    assert vm_identity.resolve_vm_vmid(vm) == ""
    assert vm_identity.resolve_known_vm_type(vm) == ""
    assert vm_identity.resolve_vm_type(vm) == "qemu"
    assert vm_identity.resolve_vm_node(vm) == ""


def test_endpoint_context_combines_typed_endpoint_vmid_and_type(vm_identity):
    endpoint = SimpleNamespace(pk=17, enabled=True)
    vm = _vm(
        endpoint=endpoint,
        endpoint_id=endpoint.pk,
        proxmox_vm_id=501,
        proxmox_vm_type="lxc",
    )

    assert vm_identity.resolve_vm_endpoint_context(vm) == (17, 501, "lxc")


def test_endpoint_context_fails_closed_for_disabled_endpoint(vm_identity):
    endpoint = SimpleNamespace(pk=17, enabled=False)
    vm = _vm(
        endpoint=endpoint,
        endpoint_id=endpoint.pk,
        proxmox_vm_id=501,
        proxmox_vm_type="qemu",
    )

    assert vm_identity.resolve_vm_endpoint_context(vm) is None


def test_endpoint_context_ignores_shared_netbox_cluster_tracking(vm_identity):
    endpoint_a = SimpleNamespace(pk=11, enabled=True)
    endpoint_b = SimpleNamespace(pk=22, enabled=True)
    tracked_cluster_a = SimpleNamespace(endpoint_id=endpoint_a.pk)
    vm = _vm(
        endpoint=endpoint_b,
        endpoint_id=endpoint_b.pk,
        proxmox_vm_id=695,
        proxmox_vm_type="qemu",
        proxmox_cluster=SimpleNamespace(endpoint_id=endpoint_b.pk),
    )
    vm.cluster = SimpleNamespace(
        proxmox_cluster_tracking=SimpleNamespace(first=lambda: tracked_cluster_a)
    )

    assert vm_identity.resolve_vm_endpoint_context(vm) == (22, 695, "qemu")


def test_endpoint_context_survives_netbox_cluster_reassignment(vm_identity):
    endpoint = SimpleNamespace(pk=22, enabled=True)
    vm = _vm(
        endpoint=endpoint,
        endpoint_id=endpoint.pk,
        proxmox_vm_id=695,
        proxmox_vm_type="qemu",
    )
    vm.cluster = SimpleNamespace(proxmox_cluster_tracking=None)

    assert vm_identity.resolve_vm_endpoint_context(vm) == (22, 695, "qemu")


@pytest.mark.parametrize("relation_name", ["proxmox_cluster", "proxmox_node"])
def test_endpoint_context_rejects_conflicting_typed_relation(
    vm_identity, relation_name
):
    endpoint = SimpleNamespace(pk=22, enabled=True)
    vm = _vm(
        endpoint=endpoint,
        endpoint_id=endpoint.pk,
        proxmox_vm_id=695,
        proxmox_vm_type="qemu",
        **{relation_name: SimpleNamespace(endpoint_id=11)},
    )

    assert vm_identity.resolve_vm_endpoint_context(vm) is None


@pytest.mark.parametrize(
    ("state_update", "endpoint_update"),
    [
        ({"endpoint": None}, {}),
        ({"endpoint_id": None}, {}),
        ({}, {"pk": 11}),
    ],
)
def test_endpoint_context_rejects_missing_or_inconsistent_endpoint(
    vm_identity, state_update, endpoint_update
):
    endpoint = SimpleNamespace(pk=22, enabled=True)
    for name, value in endpoint_update.items():
        setattr(endpoint, name, value)
    state = {
        "endpoint": endpoint,
        "endpoint_id": 22,
        "proxmox_vm_id": 695,
        "proxmox_vm_type": "qemu",
        **state_update,
    }

    assert vm_identity.resolve_vm_endpoint_context(_vm(**state)) is None


def test_endpoint_context_rejects_sync_state_owned_by_another_vm(vm_identity):
    endpoint = SimpleNamespace(pk=22, enabled=True)
    vm = _vm(
        endpoint=endpoint,
        endpoint_id=endpoint.pk,
        proxmox_vm_id=695,
        proxmox_vm_type="qemu",
    )
    vm.proxbox_sync_state.virtual_machine_id = 99

    assert vm_identity.resolve_vm_endpoint_context(vm) is None
