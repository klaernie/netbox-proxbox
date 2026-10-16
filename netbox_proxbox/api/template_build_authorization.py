"""Local authorization and backend identity for template image build actions."""

from __future__ import annotations

from dataclasses import dataclass

from netbox_proxbox.services.operational_target import (
    OperationalTarget,
    OperationalTargetError,
    resolve_operational_target,
)
from netbox_proxbox.views.proxbox_access import user_can_run_endpoint_action


@dataclass(frozen=True, slots=True)
class TemplateBuildAuthorizationError(Exception):
    """Stable HTTP-safe denial raised before a template build is dispatched."""

    detail: str
    status_code: int


def require_template_build_authorization(user: object, endpoint: object) -> None:
    """Require operator permission plus enabled, broad, and narrow endpoint gates."""
    if not user_can_run_endpoint_action(user, getattr(endpoint, "pk", None)):
        raise TemplateBuildAuthorizationError(
            "Missing the run_proxmox_action permission on this Proxmox endpoint.",
            403,
        )
    if not bool(getattr(endpoint, "enabled", False)):
        raise TemplateBuildAuthorizationError(
            "Endpoint is disabled; template image builds are not authorized.", 403
        )
    if not bool(getattr(endpoint, "allow_writes", False)):
        raise TemplateBuildAuthorizationError(
            "Endpoint does not allow Proxmox-side writes.", 403
        )
    if not bool(getattr(endpoint, "allow_packer_template_builds", False)):
        raise TemplateBuildAuthorizationError(
            "Endpoint does not explicitly allow netbox-packer template builds.", 403
        )


def resolve_authorized_template_build_target(
    user: object, endpoint: object
) -> OperationalTarget:
    """Bind template authorization to one backend identity and transport context."""
    try:
        target = resolve_operational_target(endpoint=endpoint, user=user)
    except OperationalTargetError as exc:
        raise TemplateBuildAuthorizationError(
            exc.detail,
            exc.status_code,
        ) from exc
    return target
