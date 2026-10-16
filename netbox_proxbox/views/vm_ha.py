"""VM detail tab to show live Proxmox HA status via proxbox-api."""

from __future__ import annotations

from typing import TYPE_CHECKING

import requests
from django.http import HttpRequest
from netbox.views import generic
from utilities.views import ViewTab, register_model_view
from virtualization.models import VirtualMachine

from netbox_proxbox.services.backend_path import (
    UnsafeBackendPathSegment,
    safe_vmid,
)
from netbox_proxbox.services._endpoint_errors import translate_request_exception
from netbox_proxbox.services.backend_context import get_fastapi_request_context
from netbox_proxbox.services.endpoint_scope import (
    enabled_backend_endpoint_scope,
    viewable_enabled_endpoint_ids,
)
from netbox_proxbox.vm_identity import resolve_vm_endpoint_context, resolve_vm_vmid

if TYPE_CHECKING:
    from netbox_proxbox.schemas.backend_proxy import BackendRequestContext


def _extract_vmid(vm: VirtualMachine) -> int | None:
    raw = resolve_vm_vmid(vm)
    if raw in (None, ""):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _vm_ha_scope(
    request: HttpRequest,
    instance: VirtualMachine,
) -> tuple[int | None, int | None, str | None]:
    """Return the visible endpoint and VM ID, or a local refusal message."""
    vmid = _extract_vmid(instance)
    if vmid is None:
        return (
            None,
            None,
            "The Proxbox sync-state record has no Proxmox VM ID. "
            "Run a Proxbox sync and try again.",
        )

    resolved = resolve_vm_endpoint_context(instance)
    if resolved is None:
        return (
            None,
            vmid,
            "This VM's synchronized Proxmox endpoint identity is missing, "
            "disabled, or inconsistent. "
            "Run a Proxbox sync and try again.",
        )
    endpoint_id, vmid, _vm_type = resolved
    if endpoint_id not in set(viewable_enabled_endpoint_ids(request.user)):
        return (
            None,
            vmid,
            "This VM's Proxmox endpoint is disabled or is not visible to you.",
        )
    return endpoint_id, vmid, None


def _request_vm_ha(
    ctx: BackendRequestContext,
    *,
    endpoint_id: int,
    vmid: int,
) -> tuple[dict[str, object] | None, str | None]:
    """Fetch one endpoint-scoped HA resource and return payload or detail."""
    try:
        vmid_segment = safe_vmid(vmid)
    except UnsafeBackendPathSegment:
        return None, "The Proxmox VM ID recorded for this VM is not valid."

    url = f"{ctx.http_url}/proxmox/cluster/ha/resources/by-vm/{vmid_segment}"
    scope_params, _, scope_error = enabled_backend_endpoint_scope(
        endpoint_ids=[endpoint_id],
        base_url=ctx.http_url,
        auth_headers=ctx.headers or {},
        backend_verify_ssl=ctx.verify_ssl,
        timeout=10,
    )
    if scope_error:
        return None, scope_error
    if scope_params is None:
        return None, "No enabled Proxmox endpoints configured; skipping VM HA lookup."

    try:
        response = requests.get(
            url,
            params=scope_params,
            headers=ctx.headers or {},
            timeout=10,
            verify=ctx.verify_ssl,
            allow_redirects=False,
        )
        if response.status_code == 404:
            return (
                None,
                "Backend does not support HA endpoints — "
                "upgrade proxbox-api to v0.0.12 or later.",
            )
        response.raise_for_status()
        payload = response.json()
        return payload if isinstance(payload, dict) else None, None
    except requests.exceptions.RequestException as exc:
        return None, translate_request_exception(exc)
    except ValueError as exc:
        return None, f"Invalid HA payload from backend: {exc}"


@register_model_view(VirtualMachine, "proxmox_ha", path="proxmox-ha")
class ProxmoxVMHATabView(generic.ObjectView):
    """Live Proxmox High-Availability tab for VM details."""

    queryset = VirtualMachine.objects.all()
    template_name = "netbox_proxbox/vm_proxmox_ha.html"
    tab = ViewTab(
        label="HA",
        permission="virtualization.view_virtualmachine",
        weight=1400,
    )

    def get_queryset(self, request: HttpRequest) -> object:
        return VirtualMachine.objects.restrict(request.user, "view")

    def get_extra_context(
        self, request: HttpRequest, instance: VirtualMachine
    ) -> dict[str, object]:
        endpoint_id, vmid, detail = _vm_ha_scope(request, instance)
        context: dict[str, object] = {
            "vmid": vmid,
            "ha": None,
            "detail": detail,
        }
        if detail is not None or endpoint_id is None or vmid is None:
            return context

        ctx = get_fastapi_request_context()
        if ctx is None or not ctx.http_url:
            context["detail"] = "No FastAPI backend endpoint is configured."
            return context
        context["ha"], context["detail"] = _request_vm_ha(
            ctx,
            endpoint_id=endpoint_id,
            vmid=vmid,
        )
        return context
