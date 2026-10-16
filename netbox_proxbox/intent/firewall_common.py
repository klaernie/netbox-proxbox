"""Shared helpers for pushing NetBox firewall objects to proxbox-api."""

from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass, field
from typing import Any
from urllib.parse import quote

from netbox_proxbox.services.backend_path import (
    UnsafeBackendPathSegment,
    safe_path_segment,
    safe_vmid,
)
from netbox_proxbox.choices import (
    FirewallScopeChoices,
    FirewallSyncStatusChoices,
    FirewallZoneChoices,
)
from netbox_proxbox.models import (
    ProxmoxEndpoint,
    ProxmoxFirewallAlias,
    ProxmoxFirewallIPSet,
    ProxmoxFirewallIPSetEntry,
    ProxmoxFirewallOptions,
    ProxmoxFirewallRule,
    ProxmoxFirewallSecurityGroup,
    ProxmoxNode,
)
from netbox_proxbox.services._endpoint_errors import translate_request_exception
from netbox_proxbox.services.endpoint_enabled import endpoint_is_enabled
from netbox_proxbox.services.endpoint_scope import enabled_backend_endpoint_scope
from netbox_proxbox.services.http_client import (
    HttpClient,
    HttpError,
    get_default_http_client,
)
from netbox_proxbox.services.operational_target import (
    OperationalTarget,
    OperationalTargetError,
    resolve_operational_target,
)
from netbox_proxbox.vm_identity import (
    resolve_vm_endpoint_context,
    resolve_vm_node,
    resolve_vm_vmid,
)

FIREWALL_PUSH_TIMEOUT_SECONDS = 30


@dataclass
class FirewallPushResult:
    """Parsed result from one proxbox-api firewall write call."""

    status: str
    endpoint_id: int | None
    path: str
    method: str
    payload: dict[str, Any] | None
    response: dict[str, Any] | None
    reason: str | None = None
    detail: str | None = None
    http_status: int = 200

    def to_response(self) -> dict[str, Any]:
        """Return a JSON-serializable API response payload."""
        return asdict(self)


@dataclass
class FirewallPreviewResult:
    """NetBox-vs-Proxmox preview for one firewall object."""

    status: str
    netbox_state: dict[str, Any]
    proxmox_state: dict[str, Any] | None = None
    differing_fields: list[str] = field(default_factory=list)
    reason: str | None = None
    detail: str | None = None

    def to_response(self) -> dict[str, Any]:
        """Return a JSON-serializable API response payload."""
        return asdict(self)


class FirewallPushError(Exception):
    """Raised when a firewall object cannot be pushed."""

    def __init__(
        self,
        reason: str,
        detail: str,
        *,
        status_code: int = 400,
        response: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail
        self.status_code = status_code
        self.response = response or {}


def validation_errors_for_rule(
    data: dict[str, Any],
    *,
    instance: object | None = None,
) -> dict[str, str]:
    """Return model/form/API validation errors for firewall rules."""
    zone = _value(data, instance, "zone")
    errors: dict[str, str] = {}

    if zone == FirewallZoneChoices.NODE and not _value(data, instance, "proxmox_node"):
        errors["proxmox_node"] = "Node-level firewall rules require a Proxmox node."

    if zone == FirewallZoneChoices.SECURITY_GROUP and not _value(
        data, instance, "security_group"
    ):
        errors["security_group"] = (
            "Security-group firewall rules require a security group."
        )

    if zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vm = _value(data, instance, "virtual_machine")
        if vm is None:
            errors["virtual_machine"] = "VM firewall rules require a virtual machine."
        elif _extract_vm_id(vm) is None:
            errors["virtual_machine"] = (
                "The virtual machine must have a Proxbox sync-state record with "
                "a Proxmox VM ID. Run a Proxbox sync."
            )

    if zone == FirewallZoneChoices.VNET and not _value(data, instance, "iface"):
        errors["iface"] = (
            "VNet firewall rules use the interface field as the VNet name."
        )

    return errors


def validation_errors_for_scoped_object(
    data: dict[str, Any],
    *,
    instance: object | None = None,
) -> dict[str, str]:
    """Return validation errors for IP sets and aliases."""
    scope = _value(data, instance, "scope")
    errors: dict[str, str] = {}

    if scope in {FirewallScopeChoices.VM_QEMU, FirewallScopeChoices.VM_LXC}:
        vm = _value(data, instance, "virtual_machine")
        if vm is None:
            errors["virtual_machine"] = "VM-scoped firewall objects require a VM."
        elif _extract_vm_id(vm) is None:
            errors["virtual_machine"] = (
                "The virtual machine must have a Proxbox sync-state record with "
                "a Proxmox VM ID. Run a Proxbox sync."
            )

    return errors


def validation_errors_for_options(
    data: dict[str, Any],
    *,
    instance: object | None = None,
) -> dict[str, str]:
    """Return validation errors for firewall options rows."""
    zone = _value(data, instance, "zone")
    errors: dict[str, str] = {}

    if zone == FirewallZoneChoices.NODE and not _value(data, instance, "proxmox_node"):
        errors["proxmox_node"] = "Node-level firewall options require a Proxmox node."

    if zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vm = _value(data, instance, "virtual_machine")
        if vm is None:
            errors["virtual_machine"] = "VM firewall options require a virtual machine."
        elif _extract_vm_id(vm) is None:
            errors["virtual_machine"] = (
                "The virtual machine must have a Proxbox sync-state record with "
                "a Proxmox VM ID. Run a Proxbox sync."
            )

    if zone in {FirewallZoneChoices.SECURITY_GROUP, FirewallZoneChoices.VNET}:
        errors["zone"] = (
            "Firewall options are only supported for datacenter, node, and VM zones."
        )

    return errors


def mark_firewall_object_stale(obj: object) -> None:
    """Mark a manually edited firewall object, or its parent, as stale."""
    target = _status_target(obj)
    if target is None:
        return
    setattr(target, "status", FirewallSyncStatusChoices.STALE)


def save_status_for_firewall_object(obj: object, status: str) -> None:
    """Persist a status update for an object that has a firewall status field."""
    target = _status_target(obj)
    if target is None:
        return
    setattr(target, "status", status)
    save = getattr(target, "save", None)
    if callable(save):
        save(update_fields=["status"])


def resolve_firewall_endpoint(obj: object) -> ProxmoxEndpoint | None:
    """Resolve an endpoint only when every firewall ownership link agrees."""
    try:
        return _require_consistent_firewall_endpoint(obj)
    except FirewallPushError:
        return None


def _require_consistent_firewall_endpoint(obj: object) -> ProxmoxEndpoint:
    """Bind firewall scope to one authoritative endpoint or fail closed."""
    endpoint = _explicit_firewall_endpoint(obj)
    if endpoint is None:
        raise FirewallPushError(
            "endpoint_required",
            "This firewall object is not explicitly linked to a Proxmox endpoint.",
            status_code=400,
        )

    scope = _firewall_scope_for_object(obj)
    if scope in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        _validate_vm_endpoint_identity(obj, endpoint)
    elif scope == FirewallZoneChoices.NODE:
        _require_matching_endpoint(
            endpoint,
            getattr(getattr(obj, "proxmox_node", None), "endpoint", None),
            "The firewall object's node belongs to a different Proxmox endpoint.",
        )
    elif scope == FirewallZoneChoices.SECURITY_GROUP:
        _require_matching_endpoint(
            endpoint,
            getattr(getattr(obj, "security_group", None), "endpoint", None),
            "The firewall object's security group belongs to a different Proxmox endpoint.",
        )
    return endpoint


def _explicit_firewall_endpoint(obj: object) -> ProxmoxEndpoint | None:
    """Return only the endpoint relation explicitly stored by the firewall row."""
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return getattr(obj.ipset, "endpoint", None)
    return getattr(obj, "endpoint", None)


def _validate_vm_endpoint_identity(obj: object, endpoint: ProxmoxEndpoint) -> None:
    """Require VM sync-state ownership and the firewall relation to agree."""
    vm = _virtual_machine_for_scope(obj)
    context = resolve_vm_endpoint_context(vm) if vm is not None else None
    if context is None:
        state_endpoint = _vm_sync_state_endpoint(vm)
        if state_endpoint is not None and not endpoint_is_enabled(state_endpoint):
            raise FirewallPushError(
                "endpoint_disabled",
                "The VM's authoritative Proxmox endpoint is disabled.",
                status_code=403,
            )
        raise FirewallPushError(
            "vm_endpoint_identity_required",
            "VM-scoped firewall operations require a complete, consistent Proxbox "
            "sync-state endpoint identity.",
            status_code=400,
        )
    authoritative_endpoint_id, _vmid, vm_type = context
    if _object_pk(endpoint) != authoritative_endpoint_id:
        raise FirewallPushError(
            "endpoint_mismatch",
            "The firewall object's endpoint does not own its virtual machine.",
            status_code=403,
        )
    expected_type = "lxc" if _firewall_scope_for_object(obj) == "vm_lxc" else "qemu"
    if vm_type != expected_type:
        raise FirewallPushError(
            "firewall_scope_mismatch",
            "The firewall object's VM scope does not match its authoritative VM type.",
            status_code=400,
        )


def _vm_sync_state_endpoint(vm: object | None) -> ProxmoxEndpoint | None:
    """Read the typed endpoint only to provide a precise local refusal reason."""
    if vm is None:
        return None
    try:
        state = getattr(vm, "proxbox_sync_state", None)
    except AttributeError:
        return None
    return getattr(state, "endpoint", None)


def _require_matching_endpoint(
    endpoint: ProxmoxEndpoint,
    related_endpoint: ProxmoxEndpoint | None,
    detail: str,
) -> None:
    """Require an explicit related object and exact endpoint agreement."""
    if related_endpoint is None or _object_pk(endpoint) != _object_pk(related_endpoint):
        raise FirewallPushError("endpoint_mismatch", detail, status_code=403)


def push_firewall_object(
    obj: object,
    *,
    actor: str,
    user: object | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    """Push one firewall object through proxbox-api."""
    supported = (
        ProxmoxFirewallSecurityGroup,
        ProxmoxFirewallRule,
        ProxmoxFirewallIPSet,
        ProxmoxFirewallIPSetEntry,
        ProxmoxFirewallAlias,
        ProxmoxFirewallOptions,
    )
    if not isinstance(obj, supported):
        raise FirewallPushError(
            "unsupported_firewall_object",
            f"{type(obj).__name__} cannot be pushed to Proxmox firewall endpoints.",
            status_code=400,
        )
    if not (actor or "").strip():
        raise FirewallPushError(
            "actor_required",
            "Firewall pushes require an authenticated actor.",
            status_code=422,
        )
    target = _firewall_operational_target(obj, user=user)
    if isinstance(obj, ProxmoxFirewallSecurityGroup):
        return push_security_group(obj, actor=actor, target=target, client=client)
    if isinstance(obj, ProxmoxFirewallRule):
        return push_rule(obj, actor=actor, target=target, client=client)
    if isinstance(obj, ProxmoxFirewallIPSet):
        return push_ipset(obj, actor=actor, target=target, client=client)
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return push_ipset_entry(obj, actor=actor, target=target, client=client)
    if isinstance(obj, ProxmoxFirewallAlias):
        return push_alias(obj, actor=actor, target=target, client=client)
    if isinstance(obj, ProxmoxFirewallOptions):
        return push_options(obj, actor=actor, target=target, client=client)

    raise AssertionError("supported firewall object was not dispatched")


def _firewall_operational_target(
    obj: object,
    *,
    user: object | None = None,
) -> OperationalTarget:
    """Resolve the firewall owner to one enabled, authorized backend target."""
    try:
        endpoint = _require_consistent_firewall_endpoint(obj)
    except FirewallPushError:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise
    if not endpoint_is_enabled(endpoint):
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "endpoint_disabled",
            "The linked Proxmox endpoint is disabled.",
            status_code=403,
        )
    if not getattr(endpoint, "allow_writes", False):
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "writes_disabled_for_endpoint",
            "Firewall writes are disabled on the linked Proxmox endpoint.",
            status_code=403,
            response={"endpoint_id": getattr(endpoint, "pk", None)},
        )
    try:
        return resolve_operational_target(endpoint=endpoint, user=user)
    except OperationalTargetError as exc:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            exc.reason,
            exc.detail,
            status_code=exc.status_code,
            response={"endpoint_id": getattr(endpoint, "pk", None)},
        ) from exc


def validate_vm_firewall_scope(
    obj: object,
    *,
    endpoint: ProxmoxEndpoint,
    vmid: int,
    node: str,
    vm_type: str,
) -> None:
    """Validate that a VM-scoped helper object matches its explicit scope."""
    expected_scope = (
        FirewallZoneChoices.VM_LXC if vm_type == "lxc" else FirewallZoneChoices.VM_QEMU
    )
    actual_scope = _firewall_scope_for_object(obj)
    if actual_scope != expected_scope:
        raise FirewallPushError(
            "firewall_scope_mismatch",
            f"Expected {expected_scope} firewall object, got {actual_scope or 'unknown'}.",
            status_code=400,
        )

    _validate_endpoint_scope(obj, endpoint)
    actual_vmid, actual_node, actual_vm_type = _vm_context(
        _virtual_machine_for_scope(obj),
        zone=expected_scope,
    )
    if (
        int(actual_vmid) != int(vmid)
        or actual_node != str(node)
        or actual_vm_type != vm_type
    ):
        raise FirewallPushError(
            "firewall_scope_mismatch",
            (
                "Firewall object VM scope does not match the requested "
                f"{vm_type}/{vmid} on node {node}."
            ),
            status_code=400,
        )


def validate_vnet_firewall_scope(
    rule: ProxmoxFirewallRule,
    *,
    endpoint: ProxmoxEndpoint,
    vnet: str,
) -> None:
    """Validate that a VNet rule belongs to the requested endpoint and VNet."""
    if rule.zone != FirewallZoneChoices.VNET:
        raise FirewallPushError(
            "firewall_scope_mismatch",
            f"Expected vnet firewall rule, got {rule.zone or 'unknown'}.",
            status_code=400,
        )
    _validate_endpoint_scope(rule, endpoint)
    actual_vnet = (rule.iface or "").strip()
    if actual_vnet != str(vnet):
        raise FirewallPushError(
            "firewall_scope_mismatch",
            f"Firewall rule VNet {actual_vnet or 'unknown'} does not match {vnet}.",
            status_code=400,
        )


def preview_firewall_object(
    obj: object,
    *,
    user: object | None = None,
    client: HttpClient | None = None,
) -> FirewallPreviewResult:
    """Fetch live Proxmox state and compare it with the NetBox object."""
    netbox_state = firewall_object_state(obj)
    try:
        endpoint = _require_consistent_firewall_endpoint(obj)
    except FirewallPushError as exc:
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason=exc.reason,
            detail=exc.detail,
        )

    if not endpoint_is_enabled(endpoint):
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason="endpoint_disabled",
            detail="The linked Proxmox endpoint is disabled.",
        )

    path, params = _preview_read_target(obj)
    if not path:
        return FirewallPreviewResult(
            status="skipped",
            netbox_state=netbox_state,
            reason="firewall_preview_not_available",
            detail="Live preview is not available for this firewall object.",
        )

    try:
        target = resolve_operational_target(endpoint=endpoint, user=user)
    except OperationalTargetError as exc:
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason=exc.reason,
            detail=exc.detail,
        )

    scope_params, backend_id_by_pk, scope_error = enabled_backend_endpoint_scope(
        base_url=target.context.http_url,
        auth_headers=target.context.headers or {},
        backend_verify_ssl=bool(target.context.verify_ssl),
        timeout=FIREWALL_PUSH_TIMEOUT_SECONDS,
        endpoint_ids=[target.endpoint.pk],
    )
    if (
        scope_error
        or scope_params is None
        or backend_id_by_pk.get(target.endpoint.pk) != target.backend_endpoint_id
    ):
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason="backend_endpoint_unresolved",
            detail=scope_error
            or "The authorized endpoint could not be bound to one backend identity.",
        )

    request_params = {**(params or {}), **scope_params}

    http_client = client or get_default_http_client()
    try:
        response = http_client.get(
            f"{target.context.http_url.rstrip('/')}{path}",
            params=request_params,
            headers=dict(target.context.headers or {}),
            verify=bool(target.context.verify_ssl),
            timeout=FIREWALL_PUSH_TIMEOUT_SECONDS,
        )
    except HttpError as exc:
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason="backend_request_failed",
            detail=translate_request_exception(exc),
        )

    payload = _response_json(response)
    if response.status_code >= 400:
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason=str(_payload_value(payload, "reason") or "firewall_preview_failed"),
            detail=str(_payload_value(payload, "detail") or response.text),
        )

    proxmox_state = _select_proxmox_state(obj, payload, target.endpoint)
    if proxmox_state is not None and not _state_matches_backend_target(
        proxmox_state, target.backend_endpoint_id
    ):
        return FirewallPreviewResult(
            status="error",
            netbox_state=netbox_state,
            reason="backend_endpoint_mismatch",
            detail="The backend returned firewall state for a different endpoint.",
        )
    differing_fields = _differing_fields(netbox_state, proxmox_state or {})
    return FirewallPreviewResult(
        status="ready" if proxmox_state is not None else "missing",
        netbox_state=netbox_state,
        proxmox_state=proxmox_state,
        differing_fields=differing_fields,
        reason=None if proxmox_state is not None else "proxmox_object_not_found",
        detail=None
        if proxmox_state is not None
        else "No matching live Proxmox object was found.",
    )


def firewall_object_state(obj: object) -> dict[str, Any]:
    """Return comparable NetBox state for a firewall object."""
    if isinstance(obj, ProxmoxFirewallSecurityGroup):
        return _drop_empty({"name": obj.name, "comment": obj.comment})
    if isinstance(obj, ProxmoxFirewallRule):
        return _rule_payload(obj)
    if isinstance(obj, ProxmoxFirewallIPSet):
        return _drop_empty({"name": obj.name, "comment": obj.comment})
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return _drop_empty(
            {"cidr": obj.cidr, "comment": obj.comment, "nomatch": obj.nomatch}
        )
    if isinstance(obj, ProxmoxFirewallAlias):
        return _drop_empty({"name": obj.name, "cidr": obj.cidr, "comment": obj.comment})
    if isinstance(obj, ProxmoxFirewallOptions):
        return _drop_empty(
            {
                "enable": obj.enable,
                "policy_in": obj.policy_in,
                "policy_out": obj.policy_out,
                **dict(obj.options or {}),
            }
        )
    return {}


def push_security_group(
    group: ProxmoxFirewallSecurityGroup,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    payload = _drop_empty({"group": group.name, "comment": group.comment})
    return _call_firewall_backend(
        group,
        method="post",
        path="/proxmox/firewall/datacenter/groups",
        payload=payload,
        actor=actor,
        target=target,
        client=client,
    )


def push_rule(
    rule: ProxmoxFirewallRule,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    method, path = _rule_push_target(rule)
    return _call_firewall_backend(
        rule,
        method=method,
        path=path,
        payload=_rule_payload(rule),
        actor=actor,
        target=target,
        client=client,
    )


def push_ipset(
    ipset: ProxmoxFirewallIPSet,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    path, _params = _scoped_collection_path(ipset, "ipsets")
    payload = _drop_empty({"name": ipset.name, "comment": ipset.comment})
    return _call_firewall_backend(
        ipset,
        method="post",
        path=path,
        payload=payload,
        actor=actor,
        target=target,
        client=client,
    )


def push_ipset_entry(
    entry: ProxmoxFirewallIPSetEntry,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    path, _params = _ipset_entry_path(entry)
    payload = _drop_empty(
        {"cidr": entry.cidr, "comment": entry.comment, "nomatch": entry.nomatch}
    )
    method = "put" if _has_remote_marker(entry) else "post"
    return _call_firewall_backend(
        entry,
        method=method,
        path=path if method == "post" else f"{path}/{_ipset_entry_segment(entry.cidr)}",
        payload=payload,
        actor=actor,
        target=target,
        client=client,
    )


def push_alias(
    alias: ProxmoxFirewallAlias,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    collection, _params = _scoped_collection_path(alias, "aliases")
    method = "put" if _has_remote_marker(alias) else "post"
    path = (
        collection
        if method == "post"
        else _path_add_segments(collection, _path_segment(str(alias.name)))
    )
    payload = _drop_empty(
        {
            "name": alias.name,
            "cidr": alias.cidr,
            "comment": alias.comment,
        }
    )
    return _call_firewall_backend(
        alias,
        method=method,
        path=path,
        payload=payload,
        actor=actor,
        target=target,
        client=client,
    )


def push_options(
    options: ProxmoxFirewallOptions,
    *,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    path = _options_path(options)
    payload = _drop_empty(
        {
            "enable": options.enable,
            "policy_in": options.policy_in,
            "policy_out": options.policy_out,
            "options": dict(options.options or {}),
        }
    )
    return _call_firewall_backend(
        options,
        method="put",
        path=path,
        payload=payload,
        actor=actor,
        target=target,
        client=client,
    )


def _call_firewall_backend(
    obj: object,
    *,
    method: str,
    path: str,
    payload: dict[str, Any] | None,
    actor: str,
    target: OperationalTarget | None = None,
    client: HttpClient | None = None,
) -> FirewallPushResult:
    actor_value = (actor or "").strip()
    if not actor_value:
        raise FirewallPushError(
            "actor_required",
            "Firewall pushes require an authenticated actor.",
            status_code=422,
        )

    try:
        endpoint = _require_consistent_firewall_endpoint(obj)
    except FirewallPushError:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise
    if not endpoint_is_enabled(endpoint):
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "endpoint_disabled",
            "The linked Proxmox endpoint is disabled.",
            status_code=403,
        )
    if target is None:
        target = _firewall_operational_target(obj)
    elif target.endpoint.pk != getattr(endpoint, "pk", None):
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "endpoint_mismatch",
            "The authorized endpoint does not own this firewall object.",
            status_code=403,
        )
    endpoint = target.endpoint
    if not getattr(endpoint, "allow_writes", False):
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "writes_disabled_for_endpoint",
            "Firewall writes are disabled on the linked Proxmox endpoint.",
            status_code=403,
            response={"endpoint_id": getattr(endpoint, "pk", None)},
        )

    context = target.context

    headers = dict(context.headers or {})
    headers["X-Proxbox-Actor"] = actor_value
    headers.setdefault("Content-Type", "application/json")
    endpoint_id = target.backend_endpoint_id
    separator = "&" if "?" in path else "?"
    url = f"{context.http_url.rstrip('/')}{path}{separator}endpoint_id={endpoint_id}"
    http_client = client or get_default_http_client()

    try:
        response = getattr(http_client, method)(
            url,
            json=payload or {},
            headers=headers,
            verify=bool(context.verify_ssl),
            timeout=FIREWALL_PUSH_TIMEOUT_SECONDS,
        )
    except HttpError as exc:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        raise FirewallPushError(
            "backend_request_failed",
            translate_request_exception(exc),
            status_code=502,
        ) from exc

    body = _response_json(response)
    if response.status_code >= 400:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ERROR)
        reason = _payload_value(body, "reason") or "proxmox_firewall_push_failed"
        detail = _payload_value(body, "detail") or response.text
        raise FirewallPushError(
            str(reason),
            str(detail),
            status_code=response.status_code,
            response=body if isinstance(body, dict) else {},
        )

    result = FirewallPushResult(
        status=str(_payload_value(body, "status") or "pushed"),
        endpoint_id=endpoint_id,
        path=path,
        method=method,
        payload=payload,
        response=body if isinstance(body, dict) else None,
        reason=_payload_value(body, "reason"),
        detail=_payload_value(body, "detail"),
        http_status=response.status_code,
    )
    if result.status == "skipped":
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.STALE)
    else:
        save_status_for_firewall_object(obj, FirewallSyncStatusChoices.ACTIVE)
    return result


def _preview_read_target(obj: object) -> tuple[str, dict[str, str] | None]:
    if isinstance(obj, ProxmoxFirewallSecurityGroup):
        return "/proxmox/firewall/datacenter/groups", None
    if isinstance(obj, ProxmoxFirewallRule):
        return _rule_preview_target(obj)
    if isinstance(obj, ProxmoxFirewallIPSet):
        return _scoped_preview_target(obj, "ipsets")
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return _scoped_preview_target(obj.ipset, "ipsets")
    if isinstance(obj, ProxmoxFirewallAlias):
        return _scoped_preview_target(obj, "aliases")
    if isinstance(obj, ProxmoxFirewallOptions):
        return _options_preview_target(obj)
    return "", None


def _rule_preview_target(
    rule: ProxmoxFirewallRule,
) -> tuple[str, dict[str, str] | None]:
    if rule.zone == FirewallZoneChoices.DATACENTER:
        return "/proxmox/firewall/datacenter/rules", None
    if rule.zone == FirewallZoneChoices.SECURITY_GROUP:
        return "/proxmox/firewall/datacenter/groups", None
    if rule.zone == FirewallZoneChoices.NODE:
        return (
            f"/proxmox/firewall/nodes/{_path_segment(_node_name(rule.proxmox_node))}/rules",
            None,
        )
    if rule.zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(rule.virtual_machine, zone=rule.zone)
        return (
            f"/proxmox/firewall/vms/{vmid}/rules",
            {"node": node, "vm_type": vm_type},
        )
    if rule.zone == FirewallZoneChoices.VNET:
        return "", None
    return "", None


def _scoped_preview_target(
    obj: ProxmoxFirewallIPSet | ProxmoxFirewallAlias,
    noun: str,
) -> tuple[str, dict[str, str] | None]:
    if obj.scope == FirewallScopeChoices.DATACENTER:
        return f"/proxmox/firewall/datacenter/{noun}", None
    if obj.scope in {FirewallScopeChoices.VM_QEMU, FirewallScopeChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(obj.virtual_machine, scope=obj.scope)
        return (
            f"/proxmox/firewall/vms/{vmid}/{noun}",
            {"node": node, "vm_type": vm_type},
        )
    return "", None


def _options_preview_target(
    options: ProxmoxFirewallOptions,
) -> tuple[str, dict[str, str] | None]:
    if options.zone == FirewallZoneChoices.DATACENTER:
        return "/proxmox/firewall/datacenter/options", None
    if options.zone == FirewallZoneChoices.NODE:
        return (
            f"/proxmox/firewall/nodes/{_path_segment(_node_name(options.proxmox_node))}/options",
            None,
        )
    if options.zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(options.virtual_machine, zone=options.zone)
        return (
            f"/proxmox/firewall/vms/{vmid}/options",
            {"node": node, "vm_type": vm_type},
        )
    return "", None


def _select_proxmox_state(
    obj: object,
    payload: object,
    endpoint: ProxmoxEndpoint,
) -> dict[str, Any] | None:
    cluster_name = getattr(endpoint, "name", None)
    if isinstance(obj, ProxmoxFirewallOptions):
        return payload if isinstance(payload, dict) else None
    if isinstance(obj, ProxmoxFirewallSecurityGroup):
        return _find_item(payload, name=obj.name, cluster_name=cluster_name)
    if isinstance(obj, ProxmoxFirewallRule):
        if obj.zone == FirewallZoneChoices.SECURITY_GROUP:
            group = getattr(obj.security_group, "name", None)
            sg_state = _find_item(payload, name=group, cluster_name=cluster_name)
            return _find_item((sg_state or {}).get("rules"), pos=obj.pos)
        return _find_item(payload, pos=obj.pos, cluster_name=cluster_name)
    if isinstance(obj, ProxmoxFirewallIPSet):
        return _find_item(payload, name=obj.name, cluster_name=cluster_name)
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        ipset_state = _find_item(
            payload, name=obj.ipset.name, cluster_name=cluster_name
        )
        return _find_item((ipset_state or {}).get("entries"), cidr=obj.cidr)
    if isinstance(obj, ProxmoxFirewallAlias):
        return _find_item(payload, name=obj.name, cluster_name=cluster_name)
    return None


def _state_matches_backend_target(
    state: dict[str, Any], backend_endpoint_id: int
) -> bool:
    """Reject response state carrying a different backend endpoint identity."""
    identity_fields = ("backend_endpoint_id", "proxmox_endpoint_id", "endpoint_id")
    for field_name in identity_fields:
        if field_name in state:
            return _coerce_int(state.get(field_name)) == backend_endpoint_id
    return True


def _find_item(
    payload: object,
    *,
    cluster_name: str | None = None,
    name: str | None = None,
    pos: int | None = None,
    cidr: str | None = None,
) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        items = [payload]
    elif isinstance(payload, list):
        items = [item for item in payload if isinstance(item, dict)]
    else:
        return None

    for item in items:
        if cluster_name and item.get("cluster_name") not in {None, cluster_name}:
            continue
        if name is not None and (item.get("name") or item.get("group")) != name:
            continue
        if pos is not None and _coerce_int(item.get("pos")) != int(pos):
            continue
        if cidr is not None and item.get("cidr") != cidr:
            continue
        return item
    return None


def _differing_fields(
    netbox_state: dict[str, Any],
    proxmox_state: dict[str, Any],
) -> list[str]:
    fields = sorted(set(netbox_state) | set(proxmox_state))
    differing: list[str] = []
    for field_name in fields:
        netbox_value = _normalize_compare_value(netbox_state.get(field_name))
        proxmox_value = _normalize_compare_value(
            proxmox_state.get(field_name)
            if field_name != "icmp-type"
            else proxmox_state.get("icmp-type") or proxmox_state.get("icmp_type")
        )
        if netbox_value != proxmox_value:
            differing.append(field_name)
    return differing


def _normalize_compare_value(value: Any) -> Any:
    if isinstance(value, bool):
        return int(value)
    if value is None:
        return ""
    return value


def _coerce_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _rule_push_target(rule: ProxmoxFirewallRule) -> tuple[str, str]:
    create = not _has_remote_marker(rule)
    suffix = "" if create else f"/{int(rule.pos)}"
    method = "post" if create else "put"

    if rule.zone == FirewallZoneChoices.DATACENTER:
        return method, f"/proxmox/firewall/datacenter/rules{suffix}"

    if rule.zone == FirewallZoneChoices.NODE:
        node_name = _node_name(rule.proxmox_node)
        return (
            method,
            f"/proxmox/firewall/nodes/{_path_segment(node_name)}/rules{suffix}",
        )

    if rule.zone == FirewallZoneChoices.SECURITY_GROUP:
        group_name = getattr(rule.security_group, "name", None)
        if not group_name:
            raise FirewallPushError(
                "security_group_required",
                "Security-group firewall rules require a security group.",
                status_code=400,
            )
        return (
            method,
            "/proxmox/firewall/datacenter/groups/"
            f"{_path_segment(str(group_name))}/rules{suffix}",
        )

    if rule.zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(rule.virtual_machine, zone=rule.zone)
        return (
            method,
            f"/proxmox/firewall/vms/{vmid}/rules{suffix}"
            f"?node={quote(node, safe='')}&vm_type={vm_type}",
        )

    if rule.zone == FirewallZoneChoices.VNET:
        vnet = (rule.iface or "").strip()
        if not vnet:
            raise FirewallPushError(
                "vnet_required",
                "VNet firewall rules require the interface field to hold the VNet name.",
                status_code=400,
            )
        return method, f"/proxmox/firewall/vnets/{_path_segment(vnet)}/rules{suffix}"

    raise FirewallPushError(
        "unsupported_firewall_zone",
        f"Unsupported firewall rule zone: {rule.zone}",
        status_code=400,
    )


def _scoped_collection_path(
    obj: ProxmoxFirewallIPSet | ProxmoxFirewallAlias,
    noun: str,
) -> tuple[str, dict[str, str]]:
    if obj.scope == FirewallScopeChoices.DATACENTER:
        return f"/proxmox/firewall/datacenter/{noun}", {}
    if obj.scope in {FirewallScopeChoices.VM_QEMU, FirewallScopeChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(obj.virtual_machine, scope=obj.scope)
        return (
            f"/proxmox/firewall/vms/{vmid}/{noun}"
            f"?node={quote(node, safe='')}&vm_type={vm_type}",
            {"node": node, "vm_type": vm_type},
        )
    raise FirewallPushError(
        "unsupported_firewall_scope",
        f"Unsupported firewall scope: {obj.scope}",
        status_code=400,
    )


def _ipset_entry_path(entry: ProxmoxFirewallIPSetEntry) -> tuple[str, dict[str, str]]:
    ipset = entry.ipset
    collection, params = _scoped_collection_path(ipset, "ipsets")
    return _path_add_segments(
        collection, _path_segment(str(ipset.name)), "entries"
    ), params


def _options_path(options: ProxmoxFirewallOptions) -> str:
    if options.zone == FirewallZoneChoices.DATACENTER:
        return "/proxmox/firewall/datacenter/options"
    if options.zone == FirewallZoneChoices.NODE:
        node_name = _node_name(options.proxmox_node)
        return f"/proxmox/firewall/nodes/{_path_segment(node_name)}/options"
    if options.zone in {FirewallZoneChoices.VM_QEMU, FirewallZoneChoices.VM_LXC}:
        vmid, node, vm_type = _vm_context(options.virtual_machine, zone=options.zone)
        return (
            f"/proxmox/firewall/vms/{vmid}/options?node={quote(node, safe='')}"
            f"&vm_type={vm_type}"
        )
    raise FirewallPushError(
        "unsupported_firewall_options_zone",
        "Firewall options pushes are only supported for datacenter, node, and VM zones.",
        status_code=400,
    )


def _path_add_segments(path: str, *segments: str) -> str:
    """Append path segments before any query string."""
    base, separator, query = path.partition("?")
    updated = "/".join(
        [base.rstrip("/"), *[segment.strip("/") for segment in segments]]
    )
    return f"{updated}{separator}{query}" if separator else updated


def _rule_payload(rule: ProxmoxFirewallRule) -> dict[str, Any]:
    return _drop_empty(
        {
            "pos": rule.pos,
            "type": rule.rule_type,
            "action": rule.action,
            "enable": rule.enable,
            "macro": rule.macro,
            "iface": rule.iface,
            "source": rule.source,
            "dest": rule.dest,
            "proto": rule.proto,
            "dport": rule.dport,
            "sport": rule.sport,
            "log": rule.log,
            "icmp-type": rule.icmp_type,
            "comment": rule.comment,
            "digest": rule.digest,
        }
    )


def _drop_empty(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value not in (None, "")}


def _has_remote_marker(obj: object) -> bool:
    if getattr(obj, "digest", ""):
        return True
    raw = getattr(obj, "raw_config", None) or {}
    return bool(isinstance(raw, dict) and raw)


def _value(data: dict[str, Any], instance: object | None, field: str) -> Any:
    if field in data:
        return data[field]
    if instance is not None:
        return getattr(instance, field, None)
    return None


def _extract_vm_id(vm: object | None) -> int | None:
    if vm is None:
        return None
    try:
        return int(resolve_vm_vmid(vm))
    except (TypeError, ValueError):
        return None


def _vm_node_name(vm: object | None) -> str:
    if vm is None:
        return ""
    return resolve_vm_node(vm).strip()


def _ipset_entry_segment(cidr: object) -> str:
    """Encode an IP-set entry key: an IP address/network or an alias name."""
    text = str(cidr if cidr is not None else "").strip()
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        # Proxmox also accepts alias names as IP-set entries.
        return _path_segment(text)
    return quote(text, safe="")


def _path_segment(value: object) -> str:
    """Return ``value`` as a validated, encoded backend path segment.

    ``quote()`` alone keeps ``..``, so an editable name such as a security
    group called ``..`` would collapse the authenticated backend URL onto a
    different firewall route.
    """
    try:
        return safe_path_segment(value)
    except UnsafeBackendPathSegment:
        raise FirewallPushError(
            "invalid_identifier",
            "A firewall object name, node name, or VNet name is not a valid "
            "Proxmox identifier, so no backend request was made.",
            status_code=400,
        ) from None


def _vm_context(
    vm: object | None,
    *,
    zone: str | None = None,
    scope: str | None = None,
) -> tuple[int, str, str]:
    vmid = _extract_vm_id(vm)
    node = _vm_node_name(vm)
    vm_type = "lxc" if (zone or scope) in {"vm_lxc"} else "qemu"
    if vmid is None:
        raise FirewallPushError(
            "vmid_required",
            "VM-scoped firewall pushes require a Proxmox VM ID in the Proxbox "
            "sync-state record. Run a Proxbox sync.",
            status_code=400,
        )
    if not node:
        raise FirewallPushError(
            "vm_node_required",
            "VM-scoped firewall pushes require a Proxmox node name on the VM.",
            status_code=400,
        )
    try:
        safe_vmid_value = int(safe_vmid(vmid))
    except UnsafeBackendPathSegment:
        raise FirewallPushError(
            "vmid_invalid",
            "The Proxmox VM ID recorded for this VM is not a valid identifier.",
            status_code=400,
        ) from None
    return safe_vmid_value, node, vm_type


def _node_name(node: ProxmoxNode | None) -> str:
    name = (getattr(node, "name", "") or "").strip()
    if not name:
        raise FirewallPushError(
            "node_required",
            "Node-level firewall pushes require a Proxmox node.",
            status_code=400,
        )
    return name


def _status_target(obj: object) -> object | None:
    if hasattr(obj, "status"):
        return obj
    ipset = getattr(obj, "ipset", None)
    if ipset is not None and hasattr(ipset, "status"):
        return ipset
    return None


def _response_json(response: object) -> object:
    try:
        return response.json()
    except ValueError:
        return None


def _payload_value(payload: object, key: str) -> Any:
    if isinstance(payload, dict):
        detail = payload.get("detail")
        if key in payload:
            return payload[key]
        if isinstance(detail, dict):
            return detail.get(key)
    return None


def _firewall_scope_for_object(obj: object) -> str | None:
    if isinstance(obj, ProxmoxFirewallRule):
        return obj.zone
    if isinstance(obj, ProxmoxFirewallOptions):
        return obj.zone
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return getattr(obj.ipset, "scope", None)
    if isinstance(obj, (ProxmoxFirewallIPSet, ProxmoxFirewallAlias)):
        return obj.scope
    return None


def _virtual_machine_for_scope(obj: object) -> object | None:
    if isinstance(obj, ProxmoxFirewallIPSetEntry):
        return getattr(obj.ipset, "virtual_machine", None)
    return getattr(obj, "virtual_machine", None)


def _validate_endpoint_scope(obj: object, endpoint: ProxmoxEndpoint) -> None:
    actual_endpoint = resolve_firewall_endpoint(obj)
    if _object_pk(actual_endpoint) != _object_pk(endpoint):
        raise FirewallPushError(
            "firewall_scope_mismatch",
            "Firewall object endpoint does not match the requested Proxmox endpoint.",
            status_code=400,
        )


def _object_pk(obj: object | None) -> object:
    if obj is None:
        return None
    return getattr(obj, "pk", getattr(obj, "id", obj))
