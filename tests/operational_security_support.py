"""Path-loaded production operational predicates with queryset-only test doubles."""

from __future__ import annotations

from functools import partial
import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Callable


_MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "netbox_proxbox" / "operational_security.py"
)


def _load_security_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "_test_real_operational_security",
        _MODULE_PATH,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SECURITY = _load_security_module()


class _EndpointQuery:
    def __init__(self, endpoint_ids: set[object] | None):
        self.endpoint_ids = endpoint_ids

    def filter(self, **kwargs: object) -> _EndpointQuery:
        endpoint_id = kwargs.get("pk")
        if self.endpoint_ids is None:
            return _EndpointQuery({endpoint_id})
        return _EndpointQuery(self.endpoint_ids.intersection({endpoint_id}))

    def exists(self) -> bool:
        return self.endpoint_ids is None or bool(self.endpoint_ids)


class _EndpointObjects:
    def __init__(
        self,
        endpoint_ids: set[object] | None,
        *,
        permission: str | None,
    ) -> None:
        self.endpoint_ids = endpoint_ids
        self.permission = permission

    def all(self) -> _EndpointQuery:
        return _EndpointQuery(self.endpoint_ids)

    def restrict(self, user: object, action: str) -> _EndpointQuery:
        del action
        if self.permission is None:
            return self.all()
        has_perm = getattr(user, "has_perm", None)
        if callable(has_perm) and has_perm(self.permission):
            return self.all()
        return _EndpointQuery(set())


def endpoint_authorizer(
    *,
    endpoint_ids: set[object] | None = None,
    permission: str | None = None,
) -> Callable[[object, object], bool]:
    """Bind the real predicate to a deterministic fake endpoint queryset."""
    objects = _EndpointObjects(endpoint_ids, permission=permission)
    return partial(
        _SECURITY.endpoint_action_is_authorized,
        endpoint_objects=objects,
        endpoint_action="run_proxmox_action",
    )
