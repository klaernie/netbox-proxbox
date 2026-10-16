"""Dependency-light authorization predicates for Proxmox operational actions."""

from __future__ import annotations

from typing import Protocol


LEGACY_PROXMOX_ACTION_PERMISSION = "core.run_proxmox_action"


class _EndpointQuery(Protocol):
    def filter(self, **kwargs: object) -> _EndpointQuery: ...

    def exists(self) -> bool: ...


class _EndpointObjects(Protocol):
    def all(self) -> _EndpointQuery: ...

    def restrict(self, user: object, action: str) -> _EndpointQuery: ...


def request_token_allows_write(request: object) -> bool:
    """Allow sessions and write-enabled API tokens; reject other token scopes."""
    token = getattr(request, "auth", None)
    return token is None or getattr(token, "write_enabled", None) is True


def user_has_any_operational_permission(
    user: object,
    endpoint_permission: str,
) -> bool:
    """Return whether an actor has a current or deprecated operational grant."""
    has_perm = getattr(user, "has_perm", None)
    if not callable(has_perm):
        return False
    return bool(
        has_perm(endpoint_permission) or has_perm(LEGACY_PROXMOX_ACTION_PERMISSION)
    )


def endpoint_action_is_authorized(
    user: object,
    endpoint_id: object,
    *,
    endpoint_objects: _EndpointObjects,
    endpoint_action: str,
) -> bool:
    """Apply exact endpoint scope, retaining the deprecated global grant."""
    if endpoint_id is None:
        return False
    has_perm = getattr(user, "has_perm", None)
    if callable(has_perm) and has_perm(LEGACY_PROXMOX_ACTION_PERMISSION):
        endpoints = endpoint_objects.all()
    else:
        endpoints = endpoint_objects.restrict(user, endpoint_action)
    return endpoints.filter(pk=endpoint_id).exists()
