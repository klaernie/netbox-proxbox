"""Resolve Proxmox identity from typed VirtualMachine sync state."""

from __future__ import annotations

from collections.abc import Mapping


def _value(source: object | None, name: str) -> object | None:
    """Read an attribute from an object or a key from a serialized mapping."""
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source.get(name)
    return getattr(source, name, None)


def _sync_state(vm: object) -> object | None:
    """Return the optional VM sync-state relation without failing on a missing row."""
    try:
        return _value(vm, "proxbox_sync_state")
    except AttributeError:
        # Django raises RelatedObjectDoesNotExist when the one-to-one row is absent.
        return None


def resolve_vm_cluster_name(vm: object) -> str:
    """Return the Proxmox cluster name recorded for a NetBox VM."""
    sync_state = _sync_state(vm)
    proxmox_cluster = _value(sync_state, "proxmox_cluster")
    typed_name = _value(proxmox_cluster, "name") or _value(
        sync_state, "proxmox_cluster_name"
    )
    if typed_name:
        return str(typed_name)

    cluster = _value(vm, "cluster")
    if cluster is None:
        return ""

    from netbox_proxbox.models import ProxmoxCluster

    tracked_cluster = ProxmoxCluster.objects.filter(netbox_cluster=cluster).first()
    if tracked_cluster is not None:
        return str(tracked_cluster.name)
    return str(_value(cluster, "name") or "")


def resolve_vm_node(vm: object) -> str:
    """Return the short Proxmox node identity from typed state when available."""
    sync_state = _sync_state(vm)
    proxmox_node = _value(sync_state, "proxmox_node")
    node_name = _value(proxmox_node, "name") or _value(sync_state, "proxmox_node_name")
    if node_name:
        return str(node_name)

    device = _value(vm, "device")
    return str(_value(device, "name") or "")


def resolve_known_vm_type(vm: object) -> str:
    """Return a supported Proxmox VM type, or an empty string when unknown."""
    sync_state = _sync_state(vm)
    typed_type = str(_value(sync_state, "proxmox_vm_type") or "").strip().lower()
    if typed_type in {"qemu", "lxc"}:
        return typed_type

    vm_type = _value(vm, "virtual_machine_type")
    slug = str(_value(vm_type, "slug") or "").strip().lower()
    if "lxc" in slug:
        return "lxc"
    if "qemu" in slug:
        return "qemu"
    return ""


def resolve_vm_type(vm: object) -> str:
    """Return the VM's supported Proxmox type, defaulting to QEMU."""
    return resolve_known_vm_type(vm) or "qemu"


def _positive_int(value: object | None) -> int | None:
    """Return a positive integer without accepting booleans."""
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _linked_endpoint_matches(linked: object | None, endpoint_id: int) -> bool:
    """Require an optional typed relation to belong to the authoritative endpoint."""
    if linked is None:
        return True
    return _positive_int(_value(linked, "endpoint_id")) == endpoint_id


def resolve_vm_endpoint_context(vm: object) -> tuple[int, int, str] | None:
    """Return an internally consistent typed endpoint identity for a VM."""
    sync_state = _sync_state(vm)
    vm_id = _positive_int(_value(vm, "pk"))
    state_vm_id = _positive_int(_value(sync_state, "virtual_machine_id"))
    if vm_id is None or state_vm_id != vm_id:
        return None

    endpoint = _value(sync_state, "endpoint")
    endpoint_id = _positive_int(_value(sync_state, "endpoint_id"))
    if endpoint is None or endpoint_id is None:
        return None
    if _positive_int(_value(endpoint, "pk")) != endpoint_id:
        return None
    if _value(endpoint, "enabled") is not True:
        return None
    if not _linked_endpoint_matches(_value(sync_state, "proxmox_cluster"), endpoint_id):
        return None
    if not _linked_endpoint_matches(_value(sync_state, "proxmox_node"), endpoint_id):
        return None

    vmid = _positive_int(_value(sync_state, "proxmox_vm_id"))
    if vmid is None:
        return None
    return endpoint_id, vmid, resolve_vm_type(vm)


def resolve_vm_vmid(vm: object) -> str:
    """Return the Proxmox VM ID recorded in the typed sync-state sidecar."""
    vmid = _value(_sync_state(vm), "proxmox_vm_id")
    return str(vmid) if vmid not in (None, "") else ""


__all__ = (
    "resolve_vm_endpoint_context",
    "resolve_known_vm_type",
    "resolve_vm_cluster_name",
    "resolve_vm_node",
    "resolve_vm_type",
    "resolve_vm_vmid",
)
