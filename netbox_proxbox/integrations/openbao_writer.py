"""Persist queued endpoint material through the provider transaction owner."""

from __future__ import annotations

from functools import wraps
from typing import Any, Callable

from django.core.exceptions import ValidationError
from django.db import router, transaction
from django.views.decorators.debug import sensitive_variables

from .openbao_pending import SLOTS, PendingCredential, consume_credentials
from .openbao_transaction import (
    current_endpoint_material_context,
    endpoint_material_transaction,
)


def install_endpoint_material_writer() -> None:
    """Install after encryption guards so endpoint persistence owns material."""
    from netbox_proxbox.models import ProxmoxEndpoint

    original = ProxmoxEndpoint.save
    if getattr(original, "_proxbox_openbao_writer", False):
        return

    @wraps(original)
    @sensitive_variables()
    def save(instance: Any, *args: Any, **kwargs: Any) -> Any:
        return save_endpoint(instance, original, args, kwargs)

    save._proxbox_openbao_writer = True
    ProxmoxEndpoint.save = save


def _restore_references(endpoint: Any, references: dict[str, Any]) -> None:
    for name, value in references.items():
        setattr(endpoint, name, value)


def _database_alias(endpoint: Any, kwargs: dict[str, Any]) -> str:
    return kwargs.get("using") or router.db_for_write(type(endpoint), instance=endpoint)


def _endpoint_assignment_rows(model: type, endpoint: Any, alias: str) -> Any:
    return model.objects.using(alias).filter(
        assigned_object_type__app_label=endpoint._meta.app_label,
        assigned_object_type__model=endpoint._meta.model_name,
        assigned_object_id=endpoint.pk,
    )


def _delete_legacy_assignment_only_endpoint(
    endpoint: Any,
    assignments: Any,
    original: Callable,
    args: tuple,
    kwargs: dict[str, Any],
    alias: str,
) -> tuple[int, dict[str, int]]:
    """Authorize and delete non-secret links without a provider transaction."""
    from netbox.context import current_request

    from .openbao_assignments import fresh_material_actor, _require_scope

    with transaction.atomic(using=alias):
        request = current_request.get()
        request_user = getattr(request, "user", None)
        actor = fresh_material_actor(
            request_user or getattr(endpoint, "_openbao_actor_user", None)
        )
        locked = list(assignments.select_for_update().order_by("pk"))
        for assignment in locked:
            _require_scope(assignment, actor, "delete")
        assignments.filter(pk__in=[assignment.pk for assignment in locked]).delete()
        return original(*args, **kwargs)


def _requires_owner(
    endpoint: Any,
    pending: dict[str, PendingCredential] | bool,
    kwargs: dict[str, Any],
) -> bool:
    if pending:
        return True
    if endpoint.pk is None:
        return False
    watched = (*SLOTS, "ssh_auth_method", "ssh_credential_source")
    update_fields = kwargs.get("update_fields")
    if update_fields is not None:
        return bool(set(update_fields).intersection(watched))
    previous = type(endpoint).objects.filter(pk=endpoint.pk).values(*watched).first()
    return previous is not None and any(
        getattr(endpoint, name) != previous[name] for name in watched
    )


def _validate_reference_mutations(
    context: Any,
    endpoint: Any,
    pending: dict[str, PendingCredential],
) -> None:
    previous = context.endpoints.get(endpoint.pk)
    if previous is None:
        return
    direct = [
        name
        for name in SLOTS
        if name not in pending and getattr(endpoint, name) != getattr(previous, name)
    ]
    if direct:
        raise ValidationError(
            "OpenBao credential UUID references cannot be rebound directly: "
            + ", ".join(direct)
            + ". Use the credential material setters or clear operation."
        )


def _validate_partial_assignment_state(
    context: Any,
    endpoint: Any,
    pending: dict[str, PendingCredential],
    kwargs: dict[str, Any],
) -> None:
    update_fields = kwargs.get("update_fields")
    if update_fields is None:
        return
    previous = context.endpoints.get(endpoint.pk)
    if previous is None:
        if pending:
            raise ValidationError(
                "OpenBao material cannot be created with a partial endpoint save."
            )
        return
    included = set(update_fields)
    selectors = ("ssh_auth_method", "ssh_credential_source")
    omitted_changes = [
        name
        for name in selectors
        if name not in included and getattr(endpoint, name) != getattr(previous, name)
    ]
    if omitted_changes:
        raise ValidationError(
            "OpenBao assignment selectors changed outside update_fields: "
            + ", ".join(omitted_changes)
            + "."
        )


_DELETE_WITHOUT_PROVIDER = (
    "OpenBao credential references remain on this endpoint, but netbox-openbao "
    "is not installed and enabled. Restore netbox-openbao and clear the "
    "endpoint credentials before deleting the endpoint."
)
_STORAGE_CONFLICT = (
    "The endpoint storage selection changed after material was supplied."
)


@sensitive_variables()
def delete_endpoint(
    endpoint: Any,
    original: Callable,
    args: tuple,
    kwargs: dict[str, Any],
) -> tuple[int, dict[str, int]]:
    """Unlink owned assignments and delete the endpoint in one transaction."""
    from .openbao import is_netbox_openbao_installed

    references = {name: getattr(endpoint, name) for name in SLOTS}
    has_references = any(references.values())
    if not is_netbox_openbao_installed():
        if has_references:
            raise ValidationError(_DELETE_WITHOUT_PROVIDER)
        return original(*args, **kwargs)
    from netbox_openbao.models import CredentialAssignment
    from netbox_proxbox.choices import CredentialStorageBackendChoices

    alias = _database_alias(endpoint, kwargs)
    assignments = _endpoint_assignment_rows(CredentialAssignment, endpoint, alias)
    has_assignments = assignments.exists()
    if not (has_references or has_assignments):
        return original(*args, **kwargs)
    if (
        not has_references
        and endpoint.credential_storage_backend
        == CredentialStorageBackendChoices.LEGACY_ENCRYPTED
    ):
        return _delete_legacy_assignment_only_endpoint(
            endpoint, assignments, original, args, kwargs, alias
        )
    if alias != "default":
        raise ValidationError(
            "OpenBao endpoint material requires the default database transaction owner."
        )
    try:
        with endpoint_material_transaction([endpoint]) as context:
            context.admit(endpoint)
            endpoint.purge_openbao_credentials()
            endpoint.save(update_fields=list(SLOTS), using="default")
            from .openbao_assignments import (
                fresh_material_actor,
                remove_endpoint_assignments,
            )

            actor = fresh_material_actor(getattr(endpoint, "_openbao_actor_user", None))
            remove_endpoint_assignments(context, endpoint, actor=actor)
            return original(*args, **kwargs)
    except BaseException:
        _restore_references(endpoint, references)
        raise


@sensitive_variables()
def save_endpoint(
    endpoint: Any,
    original: Callable,
    args: tuple,
    kwargs: dict[str, Any],
) -> Any:
    from .openbao import endpoint_uses_openbao_storage

    pending = consume_credentials(endpoint)
    references = {name: getattr(endpoint, name) for name in SLOTS}
    if not endpoint_uses_openbao_storage(endpoint):
        if pending:
            raise ValidationError(_STORAGE_CONFLICT)
        return original(endpoint, *args, **kwargs)
    if (
        not _requires_owner(endpoint, pending, kwargs)
        and current_endpoint_material_context() is None
    ):
        return original(endpoint, *args, **kwargs)
    if _database_alias(endpoint, kwargs) != "default":
        raise ValidationError(
            "OpenBao endpoint material requires the default database transaction owner."
        )
    try:
        with endpoint_material_transaction(
            [endpoint], allow_new=endpoint.pk is None
        ) as context:
            return _save_owned(context, endpoint, pending, original, args, kwargs)
    except BaseException:
        _restore_references(endpoint, references)
        raise


@sensitive_variables()
def _save_owned(
    context: Any,
    endpoint: Any,
    pending: dict[str, PendingCredential],
    original: Callable,
    args: tuple,
    kwargs: dict[str, Any],
) -> Any:
    from .openbao import validate_locked_openbao_storage
    from .openbao_assignments import (
        apply_endpoint_material,
        reconcile_endpoint_assignments,
        resolve_transaction_actor,
    )

    context.admit(endpoint)
    locked = context.endpoints.get(endpoint.pk)
    update_fields = kwargs.get("update_fields")
    writes_override = update_fields is None or "credential_storage_backend" in {
        str(field) for field in update_fields
    }
    endpoint_override = (
        getattr(endpoint, "credential_storage_backend", "")
        if locked is None or writes_override
        else getattr(locked, "credential_storage_backend", "")
    )
    validate_locked_openbao_storage(
        context.settings,
        endpoint_override=endpoint_override,
        conflict_message=_STORAGE_CONFLICT,
    )
    _validate_reference_mutations(context, endpoint, pending)
    _validate_partial_assignment_state(context, endpoint, pending, kwargs)
    actor = resolve_transaction_actor(
        pending,
        getattr(endpoint, "_openbao_actor_user", None),
    )
    result = original(endpoint, *args, **kwargs)
    if pending:
        apply_endpoint_material(context, endpoint, pending, actor=actor)
        original(endpoint, update_fields=list(pending), using="default")
    reconcile_endpoint_assignments(
        context,
        endpoint,
        actor=actor,
    )
    return result
