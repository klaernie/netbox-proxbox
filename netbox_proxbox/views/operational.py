"""Plugin-side backend-proxy views for operational verbs (issue #376).

Trust boundary (operational-verbs.md §2.3):

  Browser ─ POST ─▶ this view (gated by endpoint operational scope)
                  │
                  └─ HTTP POST ▶ proxbox-api ``/proxmox/{vm_type}/{vmid}/{verb}``
                                  (gated by ``ProxmoxEndpoint.allow_writes``)

Each view:

1. Requires ``run_proxmox_action`` on the VM's Proxmox endpoint, or the
   deprecated literal ``core.run_proxmox_action`` compatibility permission.
2. Resolves the VM's ``(endpoint_id, vmid, vm_type)`` triple. If any
   piece is missing, surfaces a Django message and redirects back to
   the VM detail page — never reaches proxbox-api.
3. Generates a fresh ``uuid4`` ``Idempotency-Key`` per request (§4.1).
4. POSTs to proxbox-api with the resolved ``endpoint_id`` query param.
   The backend's ``allow_writes`` check completes the trust boundary;
   a 403 ``endpoint_writes_disabled`` is surfaced as a Django message.

Migrate has an extra GET (target-node picker). The picker renders
regardless of ``allow_writes`` because the operator must be able to
see why a button is disabled; only the POST triggers a write.
"""

from __future__ import annotations

import uuid
from typing import ClassVar

import requests
from django.contrib import messages
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.utils.translation import gettext_lazy as _
from django.views import View
from utilities.views import TokenConditionalLoginRequiredMixin, register_model_view
from virtualization.models import VirtualMachine

from netbox_proxbox.services.backend_path import (
    UnsafeBackendPathSegment,
    safe_vm_type,
    safe_vmid,
)
from netbox_proxbox.models import ProxmoxNode
from netbox_proxbox.services._endpoint_errors import translate_request_exception
from netbox_proxbox.services.operational_target import (
    OperationalTargetError,
    resolve_operational_target,
)
from netbox_proxbox.vm_identity import (
    resolve_vm_endpoint_context,
    resolve_vm_node,
    resolve_vm_type,
    resolve_vm_vmid,
)
from netbox_proxbox.views.proxbox_access import (
    EndpointOperationalPermissionRequiredMixin,
    TokenWriteScopeRequiredMixin,
    permission_run_proxmox_action,
    user_can_run_endpoint_action,
)

__all__ = (
    "OperationalMigrateView",
    "OperationalSnapshotView",
    "OperationalStartView",
    "OperationalStopView",
    "resolve_vm_endpoint_context",
)

_BACKEND_TIMEOUT_S = 30


class _OperationalVerbView(
    TokenConditionalLoginRequiredMixin,
    TokenWriteScopeRequiredMixin,
    EndpointOperationalPermissionRequiredMixin,
    View,
):
    """Shared dispatch path for the four operational verbs."""

    verb: ClassVar[str] = ""
    http_method_names: ClassVar[list[str]] = ["post"]

    def post(self, request: HttpRequest, pk: int | str) -> HttpResponseRedirect:
        """Forward a verb invocation to proxbox-api."""
        vm = _operational_vm_or_404(request, pk)
        return _forward_verb(request, vm, self.verb, extra_body=None)


@register_model_view(
    VirtualMachine, "proxbox_operational_start", path="proxbox-operational-start"
)
class OperationalStartView(_OperationalVerbView):
    """POST: dispatch the ``start`` verb."""

    verb = "start"


@register_model_view(
    VirtualMachine, "proxbox_operational_stop", path="proxbox-operational-stop"
)
class OperationalStopView(_OperationalVerbView):
    """POST: dispatch the ``stop`` verb."""

    verb = "stop"


@register_model_view(
    VirtualMachine, "proxbox_operational_snapshot", path="proxbox-operational-snapshot"
)
class OperationalSnapshotView(_OperationalVerbView):
    """POST: dispatch the ``snapshot`` verb. Snapshot name is server-chosen."""

    verb = "snapshot"


@register_model_view(
    VirtualMachine, "proxbox_operational_migrate", path="proxbox-operational-migrate"
)
class OperationalMigrateView(
    TokenConditionalLoginRequiredMixin,
    TokenWriteScopeRequiredMixin,
    EndpointOperationalPermissionRequiredMixin,
    View,
):
    """GET: render target-node picker. POST: dispatch the ``migrate`` verb.

    The picker is reachable regardless of ``allow_writes`` so an operator
    can see the target list. Only POST hits proxbox-api, where the
    backend's ``allow_writes`` check completes the trust boundary.
    """

    http_method_names: ClassVar[list[str]] = ["get", "post"]

    def get(self, request: HttpRequest, pk: int | str) -> HttpResponse:
        """Render the target-node picker for the migrate verb."""
        vm = _operational_vm_or_404(request, pk)
        ctx = resolve_vm_endpoint_context(vm)
        targets: list[ProxmoxNode] = []
        current_node = ""
        vmid: int | None = None
        if ctx is not None:
            endpoint_id, vmid, _vm_type = ctx
            qs = ProxmoxNode.objects.filter(endpoint_id=endpoint_id)
            current_node = _current_node_name(vm)
            if current_node:
                qs = qs.exclude(name=current_node)
            targets = list(qs.order_by("name"))
        return render(
            request,
            "netbox_proxbox/vm_migrate_picker.html",
            {
                "vm": vm,
                "targets": targets,
                "current_node": current_node,
                "vmid": vmid,
                "resolvable": ctx is not None,
                "action_url": f"{vm.get_absolute_url()}proxbox-operational-migrate/",
            },
        )

    def post(self, request: HttpRequest, pk: int | str) -> HttpResponseRedirect:
        """Forward migrate dispatch with the chosen target node."""
        vm = _operational_vm_or_404(request, pk)
        target = (request.POST.get("target") or "").strip()
        if not target:
            messages.error(
                request, _("Select a target node before submitting migrate.")
            )
            return HttpResponseRedirect(
                f"{vm.get_absolute_url()}proxbox-operational-migrate/"
            )
        online = request.POST.get("online", "").lower() in ("on", "true", "1", "yes")
        return _forward_verb(
            request,
            vm,
            "migrate",
            extra_body={"target": target, "online": online},
        )


def _operational_vm_or_404(request: HttpRequest, pk: int | str) -> VirtualMachine:
    """Return a visible VM only when its endpoint is in operational scope."""
    vm = get_object_or_404(
        VirtualMachine.objects.restrict(request.user, "view"),
        pk=pk,
    )
    resolved = resolve_vm_endpoint_context(vm)
    has_perm = getattr(request.user, "has_perm", None)
    if (
        resolved is None
        and callable(has_perm)
        and has_perm(permission_run_proxmox_action())
    ):
        return vm
    endpoint_id = resolved[0] if resolved is not None else None
    if user_can_run_endpoint_action(request.user, endpoint_id):
        return vm
    return get_object_or_404(VirtualMachine.objects.none(), pk=pk)


def _current_node_name(vm: VirtualMachine) -> str:
    """Best-effort current Proxmox node name for the VM (used to exclude self-target)."""
    return resolve_vm_node(vm)


def _forward_verb(
    request: HttpRequest,
    vm: VirtualMachine,
    verb: str,
    *,
    extra_body: dict[str, object] | None,
) -> HttpResponseRedirect:
    """POST to proxbox-api ``/proxmox/{vm_type}/{vmid}/{verb}`` and surface result."""
    redirect_to = vm.get_absolute_url()
    resolved = resolve_vm_endpoint_context(vm)
    if resolved is None:
        messages.error(
            request,
            _(
                "This VM is not linked to a Proxmox endpoint, or its Proxbox "
                "sync-state record has no Proxmox VM ID. Run a Proxbox sync; "
                "operational verbs are unavailable until the state is populated."
            ),
        )
        return HttpResponseRedirect(redirect_to)
    endpoint_id, vmid, vm_type = resolved

    try:
        vm_type_segment = safe_vm_type(vm_type)
        vmid_segment = safe_vmid(vmid)
    except UnsafeBackendPathSegment:
        messages.error(
            request,
            _(
                "The guest type or VM ID recorded for this VM is not a valid "
                "Proxmox identifier, so no backend request was made."
            ),
        )
        return HttpResponseRedirect(redirect_to)
    sync_state = getattr(vm, "proxbox_sync_state", None)
    endpoint = getattr(sync_state, "endpoint", None)
    if endpoint is None or getattr(endpoint, "pk", None) != endpoint_id:
        messages.error(
            request, _("The VM's Proxmox endpoint identity is inconsistent.")
        )
        return HttpResponseRedirect(redirect_to)
    try:
        target = resolve_operational_target(
            endpoint=endpoint,
            user=request.user,
            timeout=_BACKEND_TIMEOUT_S,
        )
    except OperationalTargetError as exc:
        messages.error(request, _(exc.detail))
        return HttpResponseRedirect(redirect_to)

    ctx = target.context
    url = f"{ctx.http_url}/proxmox/{vm_type_segment}/{vmid_segment}/{verb}"
    headers = dict(ctx.headers or {})
    headers["Idempotency-Key"] = str(uuid.uuid4())
    headers.setdefault("Content-Type", "application/json")

    try:
        response = requests.post(
            url,
            params={"endpoint_id": target.backend_endpoint_id},
            json=extra_body or {},
            headers=headers,
            timeout=_BACKEND_TIMEOUT_S,
            verify=ctx.verify_ssl,
            allow_redirects=False,
        )
    except requests.exceptions.RequestException as exc:
        messages.error(
            request,
            _("Backend request failed: {error}").format(
                error=translate_request_exception(exc)
            ),
        )
        return HttpResponseRedirect(redirect_to)

    _surface_backend_response(request, response, verb)
    return HttpResponseRedirect(redirect_to)


def _surface_backend_response(
    request: HttpRequest, response: requests.Response, verb: str
) -> None:
    """Translate a proxbox-api response into a Django flash message."""
    payload: dict[str, object] | None
    try:
        body = response.json()
        payload = body if isinstance(body, dict) else None
    except ValueError:
        payload = None

    if response.status_code in (200, 202):
        messages.success(
            request,
            _("Proxmox {verb} dispatched.").format(verb=verb),
        )
        return

    reason = (payload or {}).get("reason") if payload else None
    detail = (payload or {}).get("detail") if payload else None
    pieces = [
        _("Proxmox {verb} request failed ({status}).").format(
            verb=verb, status=response.status_code
        )
    ]
    if reason:
        pieces.append(_("Reason: {reason}.").format(reason=reason))
    if detail and detail != reason:
        pieces.append(str(detail))
    messages.error(request, " ".join(str(p) for p in pieces))
