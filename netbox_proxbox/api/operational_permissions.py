"""DRF permission adapters for endpoint-scoped Proxmox operations."""

from rest_framework.permissions import BasePermission, SAFE_METHODS
from rest_framework.request import Request

from netbox_proxbox.views.proxbox_access import (
    request_token_allows_write,
    user_has_any_endpoint_action,
)


class TokenWriteScopePermission(BasePermission):
    """Reject unsafe requests authenticated by a read-only API token."""

    message = "API token does not allow write operations."

    def has_permission(self, request: Request, view: object) -> bool:
        del view
        return request.method in SAFE_METHODS or request_token_allows_write(request)


class EndpointOperationalActionPermission(BasePermission):
    """Require a current endpoint action grant or the deprecated legacy grant."""

    message = "Missing the run_proxmox_action permission on a Proxmox endpoint."

    def has_permission(self, request: Request, view: object) -> bool:
        del view
        return bool(
            request.user.is_authenticated and user_has_any_endpoint_action(request.user)
        )
