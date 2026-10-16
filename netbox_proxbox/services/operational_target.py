"""Bind operational authorization to one enabled backend endpoint identity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from netbox_proxbox.models import ProxmoxEndpoint
from netbox_proxbox.operational_security import LEGACY_PROXMOX_ACTION_PERMISSION
from netbox_proxbox.services.backend_context import get_fastapi_request_context
from netbox_proxbox.services.endpoint_enabled import endpoint_is_enabled

if TYPE_CHECKING:
    from netbox_proxbox.schemas.backend_proxy import BackendRequestContext

ENDPOINT_OPERATIONAL_ACTION = "run_proxmox_action"


@dataclass(frozen=True, slots=True)
class OperationalTarget:
    """One authorized NetBox endpoint bound to its backend database identity."""

    endpoint: ProxmoxEndpoint
    backend_endpoint_id: int
    context: BackendRequestContext


@dataclass(frozen=True, slots=True)
class OperationalTargetError(Exception):
    """Stable local refusal raised before operational backend I/O."""

    reason: str
    detail: str
    status_code: int


def resolve_operational_target(
    *,
    endpoint: ProxmoxEndpoint,
    user: object | None = None,
    context: BackendRequestContext | None = None,
    timeout: int = 30,
) -> OperationalTarget:
    """Authorize, enable-check, and translate one exact endpoint for dispatch."""
    endpoint_id = getattr(endpoint, "pk", None)
    authorized = (
        _authorized_endpoint(user, endpoint_id) if user is not None else endpoint
    )
    if authorized is None:
        raise OperationalTargetError(
            "permission_denied",
            "Proxmox endpoint is outside the operational permission scope.",
            404,
        )
    if not endpoint_is_enabled(authorized):
        raise OperationalTargetError(
            "endpoint_disabled",
            "The selected Proxmox endpoint is disabled.",
            403,
        )

    resolved_context = context or get_fastapi_request_context()
    if resolved_context is None or not resolved_context.http_url:
        raise OperationalTargetError(
            "fastapi_endpoint_required",
            "No enabled ProxBox (FastAPI) backend is configured.",
            503,
        )

    from netbox_proxbox.views.backend_sync import (  # noqa: PLC0415
        resolve_backend_endpoint_id,
    )

    backend_endpoint_id, resolve_error = resolve_backend_endpoint_id(
        authorized,
        base_url=resolved_context.http_url.rstrip("/"),
        auth_headers=resolved_context.headers or {},
        backend_verify_ssl=bool(resolved_context.verify_ssl),
        timeout=timeout,
    )
    if backend_endpoint_id is None:
        raise OperationalTargetError(
            "backend_endpoint_unresolved",
            resolve_error or "Could not resolve this endpoint on the ProxBox backend.",
            502,
        )
    return OperationalTarget(authorized, backend_endpoint_id, resolved_context)


def _authorized_endpoint(
    user: object,
    endpoint_id: object,
) -> ProxmoxEndpoint | None:
    """Return the exact endpoint row from the actor's operational scope."""
    if endpoint_id is None:
        return None
    has_perm = getattr(user, "has_perm", None)
    if callable(has_perm) and has_perm(LEGACY_PROXMOX_ACTION_PERMISSION):
        queryset = ProxmoxEndpoint.objects.all()
    else:
        queryset = ProxmoxEndpoint.objects.restrict(user, ENDPOINT_OPERATIONAL_ACTION)
    return queryset.filter(pk=endpoint_id).first()
