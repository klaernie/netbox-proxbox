"""Fail-closed guards for node OpenBao references outside model save paths."""

from __future__ import annotations

from collections.abc import Iterable
from contextvars import ContextVar
from functools import wraps
from typing import Any, Callable

from django.core.exceptions import ValidationError
from django.db import router, transaction
from django.db.models import Q
from django.db.models.signals import pre_delete

from .openbao_node_pending import SLOTS

_CLEANUP_MESSAGE = (
    "OpenBao node references or assignments remain. Use the supported node "
    "credential cleanup path before bulk mutation, deletion, or storage switching."
)
_PROVIDER_MESSAGE = (
    "OpenBao node references remain, but netbox-openbao is unavailable. Restore "
    "the provider and run the supported cleanup path before continuing."
)
_ENDPOINT_CLEANUP_MESSAGE = (
    "OpenBao endpoint references or assignments remain. Use the supported "
    "endpoint credential cleanup path before bulk deletion."
)
_BACKEND_MISSING = object()
_LOCKED_ENDPOINT_WRITE_ALIASES: ContextVar[frozenset[str]] = ContextVar(
    "proxbox_locked_endpoint_write_aliases",
    default=frozenset(),
)


def _reference_filter(prefix: str = "") -> Q:
    query = Q()
    for name in SLOTS:
        query |= Q(**{f"{prefix}{name}__isnull": False})
    return query


def _provider_assignment_model() -> type:
    from .openbao import is_netbox_openbao_installed

    if not is_netbox_openbao_installed():
        raise ValidationError(_PROVIDER_MESSAGE)
    try:
        from netbox_openbao.models import CredentialAssignment
    except ImportError as exc:
        raise ValidationError(_PROVIDER_MESSAGE) from exc
    return CredentialAssignment


def _owner_scope(queryset: Any) -> Any:
    from netbox_proxbox.models import NodeSSHCredential

    return NodeSSHCredential.objects.using(queryset.db).filter(
        pk__in=queryset.values("pk")
    )


def _owners_have_state(queryset: Any) -> bool:
    owners = _owner_scope(queryset)
    if owners.filter(_reference_filter()).exists():
        return True
    device_ids = owners.exclude(node__netbox_device_id=None).values_list(
        "node__netbox_device_id", flat=True
    )
    if not device_ids.exists():
        return False
    try:
        assignments = _provider_assignment_model()
    except ValidationError:
        return False
    return (
        assignments.objects.using(owners.db)
        .filter(
            assigned_object_type__app_label="dcim",
            assigned_object_type__model="device",
            assigned_object_id__in=device_ids,
            purpose="login",
        )
        .exists()
    )


def _nodes_have_state(queryset: Any) -> bool:
    from netbox_proxbox.models import NodeSSHCredential

    owners = NodeSSHCredential.objects.using(queryset.db).filter(
        node_id__in=queryset.values("pk")
    )
    return _owners_have_state(owners)


def _endpoints_have_state(queryset: Any, *, inherited_only: bool = False) -> bool:
    from netbox_proxbox.models import NodeSSHCredential

    if inherited_only:
        queryset = queryset.filter(credential_storage_backend="")
    owners = NodeSSHCredential.objects.using(queryset.db).filter(
        node__endpoint_id__in=queryset.values("pk")
    )
    return _owners_have_state(owners)


def _device_has_state(device: Any) -> bool:
    from netbox_proxbox.models import NodeSSHCredential

    using = device._state.db or "default"
    owners = NodeSSHCredential.objects.using(using).filter(
        node__netbox_device_id=device.pk
    )
    if _owners_have_state(owners):
        return True
    try:
        assignments = _provider_assignment_model()
    except ValidationError:
        return False
    return (
        assignments.objects.using(using)
        .filter(
            assigned_object_type__app_label="dcim",
            assigned_object_type__model="device",
            assigned_object_id=device.pk,
        )
        .exists()
    )


def _raise_if_queryset_affected(queryset: Any) -> None:
    from netbox_proxbox.models import NodeSSHCredential, ProxmoxEndpoint, ProxmoxNode

    if queryset.model is NodeSSHCredential and _owners_have_state(queryset):
        raise ValidationError(_CLEANUP_MESSAGE)
    if queryset.model is ProxmoxNode and _nodes_have_state(queryset):
        raise ValidationError(_CLEANUP_MESSAGE)
    if queryset.model is ProxmoxEndpoint and _endpoints_have_state(queryset):
        raise ValidationError(_CLEANUP_MESSAGE)


def _automatic_storage_backend() -> str:
    from netbox_proxbox.choices import CredentialStorageBackendChoices
    from netbox_proxbox.integrations.openbao import is_netbox_openbao_installed

    return (
        CredentialStorageBackendChoices.OPENBAO
        if is_netbox_openbao_installed()
        else CredentialStorageBackendChoices.LEGACY_ENCRYPTED
    )


def _settings_selection_keeps_openbao(value: Any) -> bool:
    """Resolve a blank global selection as the automatic companion default."""
    from netbox_proxbox.choices import CredentialStorageBackendChoices

    if value == CredentialStorageBackendChoices.OPENBAO:
        return True
    if value in (None, ""):
        return _automatic_storage_backend() == CredentialStorageBackendChoices.OPENBAO
    return False


def _global_storage_backend(using: str) -> str:
    """Read the effective global selection from the write database."""
    from netbox_proxbox.models import ProxboxPluginSettings

    value = (
        ProxboxPluginSettings.objects.using(using)
        .values_list("credential_storage_backend", flat=True)
        .get(singleton_key="default")
    )
    return value or _automatic_storage_backend()


def _endpoint_selection_keeps_openbao(value: Any, *, using: str) -> bool:
    """Resolve endpoint inheritance through the effective global selection."""
    from netbox_proxbox.choices import CredentialStorageBackendChoices

    if value == CredentialStorageBackendChoices.OPENBAO:
        return True
    if value in (None, ""):
        return _global_storage_backend(using) == CredentialStorageBackendChoices.OPENBAO
    return False


def _guard_update(queryset: Any, updates: dict[str, Any]) -> None:
    from netbox_proxbox.models import (
        NodeSSHCredential,
        ProxmoxEndpoint,
        ProxmoxNode,
    )

    fields = set(updates)
    if queryset.model is NodeSSHCredential:
        _guard_owner_update(queryset, fields)
    elif queryset.model is ProxmoxNode:
        _guard_node_update(queryset, fields)
    elif queryset.model is ProxmoxEndpoint:
        _guard_endpoint_update(queryset, updates)


def _guard_owner_update(queryset: Any, fields: set[str]) -> None:
    if fields.intersection(SLOTS) or _owners_have_state(queryset):
        raise ValidationError(_CLEANUP_MESSAGE)


def _guard_node_update(queryset: Any, fields: set[str]) -> None:
    watched = {"endpoint", "endpoint_id", "netbox_device", "netbox_device_id"}
    if fields.intersection(watched):
        _raise_if_queryset_affected(queryset)


def _guard_endpoint_update(queryset: Any, updates: dict[str, Any]) -> None:
    backend = updates.get("credential_storage_backend", _BACKEND_MISSING)
    if backend is _BACKEND_MISSING or _endpoint_selection_keeps_openbao(
        backend, using=queryset.db
    ):
        return
    _raise_if_queryset_affected(queryset)


def _guard_settings_update(updates: dict[str, Any], *, using: str = "default") -> None:
    from netbox_proxbox.models import ProxmoxEndpoint

    backend = updates.get("credential_storage_backend", _BACKEND_MISSING)
    if backend is _BACKEND_MISSING or _settings_selection_keeps_openbao(backend):
        return
    inherited = ProxmoxEndpoint.objects.using(using).filter(
        credential_storage_backend=""
    )
    if _endpoints_have_state(inherited):
        raise ValidationError(_CLEANUP_MESSAGE)


def _guard_bulk_objects(queryset: Any, objects: list[Any], fields: set[str]) -> None:
    from netbox_proxbox.models import NodeSSHCredential

    if queryset.model is not NodeSSHCredential:
        _guard_non_owner_bulk(queryset, objects, fields)
        return
    proposed_references = any(
        getattr(obj, name, None) is not None for obj in objects for name in SLOTS
    )
    pks = [obj.pk for obj in objects if obj.pk is not None]
    affected = bool(pks) and _owners_have_state(queryset.filter(pk__in=pks))
    if proposed_references or fields.intersection(SLOTS) or affected:
        raise ValidationError(_CLEANUP_MESSAGE)


def _guard_non_owner_bulk(
    queryset: Any,
    objects: list[Any],
    fields: set[str],
) -> None:
    from netbox_proxbox.models import ProxmoxEndpoint

    if not fields:
        return
    pks = [obj.pk for obj in objects if obj.pk is not None]
    updates = (
        {name: getattr(objects[0], name, None) for name in fields} if objects else {}
    )
    if (
        queryset.model is ProxmoxEndpoint
        and "credential_storage_backend" in fields
        and any(
            not _endpoint_selection_keeps_openbao(
                obj.credential_storage_backend,
                using=queryset.db,
            )
            for obj in objects
        )
    ):
        updates["credential_storage_backend"] = "legacy_encrypted"
    _guard_update(queryset.filter(pk__in=pks), updates)


def _locked_endpoint_storage_write(
    queryset: Any,
    guard: Callable[[], None],
    write: Callable[[], Any],
) -> Any:
    """Keep the settings-first lock through an endpoint storage write."""
    from .openbao_single_guards import _lock_settings_singleton

    using = queryset.db
    locked_aliases = _LOCKED_ENDPOINT_WRITE_ALIASES.get()
    if using in locked_aliases:
        return write()
    with transaction.atomic(using=using):
        _lock_settings_singleton(using)
        guard()
        token = _LOCKED_ENDPOINT_WRITE_ALIASES.set(locked_aliases | {using})
        try:
            return write()
        finally:
            _LOCKED_ENDPOINT_WRITE_ALIASES.reset(token)


def _install_queryset_guards(queryset_type: type) -> None:
    if vars(queryset_type).get("_proxbox_node_openbao_guards_installed", False):
        return
    original_update = queryset_type.update
    original_bulk_update = queryset_type.bulk_update
    original_bulk_create = queryset_type.bulk_create
    original_delete = queryset_type.delete
    original_raw_delete = queryset_type._raw_delete

    @wraps(original_update)
    def guarded_update(queryset: Any, **updates: Any) -> int:
        from netbox_proxbox.models import ProxmoxEndpoint

        queryset._for_write = True
        if (
            queryset.model is ProxmoxEndpoint
            and "credential_storage_backend" in updates
        ):
            return _locked_endpoint_storage_write(
                queryset,
                lambda: _guard_endpoint_update(queryset, updates),
                lambda: original_update(queryset, **updates),
            )
        _guard_update(queryset, updates)
        return original_update(queryset, **updates)

    @wraps(original_bulk_update)
    def guarded_bulk_update(
        queryset: Any,
        objs: Iterable[Any],
        fields: Iterable[str],
        *args: Any,
        **kwargs: Any,
    ) -> int:
        from netbox_proxbox.models import ProxmoxEndpoint

        materialized = list(objs)
        normalized = {str(name) for name in fields}
        queryset._for_write = True
        if (
            queryset.model is ProxmoxEndpoint
            and "credential_storage_backend" in normalized
        ):
            return _locked_endpoint_storage_write(
                queryset,
                lambda: _guard_bulk_objects(queryset, materialized, normalized),
                lambda: original_bulk_update(
                    queryset, materialized, tuple(normalized), *args, **kwargs
                ),
            )
        _guard_bulk_objects(queryset, materialized, normalized)
        return original_bulk_update(
            queryset, materialized, tuple(normalized), *args, **kwargs
        )

    @wraps(original_bulk_create)
    def guarded_bulk_create(
        queryset: Any,
        objs: Iterable[Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        materialized = list(objs)
        queryset._for_write = True
        fields = {str(name) for name in (kwargs.get("update_fields") or ())}
        _guard_bulk_objects(queryset, materialized, fields)
        return original_bulk_create(queryset, materialized, *args, **kwargs)

    @wraps(original_delete)
    def guarded_delete(queryset: Any) -> Any:
        _raise_if_queryset_affected(queryset)
        return original_delete(queryset)

    @wraps(original_raw_delete)
    def guarded_raw_delete(queryset: Any, using: str) -> int:
        _raise_if_queryset_affected(queryset)
        return original_raw_delete(queryset, using)

    queryset_type.update = guarded_update
    queryset_type.bulk_update = guarded_bulk_update
    queryset_type.bulk_create = guarded_bulk_create
    queryset_type.delete = guarded_delete
    queryset_type._raw_delete = guarded_raw_delete
    queryset_type._proxbox_node_openbao_guards_installed = True


def _guard_endpoint_save(original: Callable) -> Callable:
    @wraps(original)
    def guarded(instance: Any, *args: Any, **kwargs: Any) -> Any:
        from netbox_proxbox.choices import CredentialStorageBackendChoices
        from netbox_proxbox.integrations.openbao import (
            effective_credential_storage_backend,
        )
        from netbox_proxbox.integrations.openbao_pending import (
            has_pending_credentials,
        )
        from netbox_proxbox.integrations.openbao_transaction import (
            current_endpoint_material_context,
        )
        from netbox_proxbox.integrations.openbao_writer import _requires_owner
        from .openbao_single_guards import _lock_settings_singleton

        update_fields = kwargs.get("update_fields")
        if instance.pk is None or (
            update_fields is not None
            and "credential_storage_backend"
            not in {str(field) for field in update_fields}
        ):
            return original(instance, *args, **kwargs)
        using_value = kwargs.get("using")
        using = (
            using_value
            if isinstance(using_value, str)
            else router.db_for_write(type(instance), instance=instance)
        )
        backend = instance.credential_storage_backend
        if backend == CredentialStorageBackendChoices.OPENBAO:
            return original(instance, *args, **kwargs)
        requires_material_owner = effective_credential_storage_backend(
            instance
        ) == CredentialStorageBackendChoices.OPENBAO and _requires_owner(
            instance,
            has_pending_credentials(instance),
            kwargs,
        )
        if requires_material_owner:
            # The material writer enters the provider owner in autocommit and
            # takes the settings lock inside that durable transaction.
            return original(instance, *args, **kwargs)

        def guard_and_write() -> Any:
            _lock_settings_singleton(using)
            queryset = type(instance).objects.using(using).filter(pk=instance.pk)
            if not _endpoint_selection_keeps_openbao(backend, using=using):
                _raise_if_queryset_affected(queryset)
            return original(instance, *args, **kwargs)

        if current_endpoint_material_context() is not None:
            return guard_and_write()
        with transaction.atomic(using=using):
            return guard_and_write()

    return guarded


def _guard_parent_delete(sender: type, instance: Any, **_kwargs: Any) -> None:
    from dcim.models import Device
    from netbox_proxbox.models import ProxmoxEndpoint, ProxmoxNode

    if sender is Device and _device_has_state(instance):
        raise ValidationError(_CLEANUP_MESSAGE)
    if sender is ProxmoxNode and _nodes_have_state(
        sender.objects.using(instance._state.db or "default").filter(pk=instance.pk)
    ):
        raise ValidationError(_CLEANUP_MESSAGE)
    if sender is ProxmoxEndpoint and _endpoint_delete_has_state(sender, instance):
        raise ValidationError(_ENDPOINT_CLEANUP_MESSAGE)


def _endpoint_delete_has_state(sender: type, instance: Any) -> bool:
    """Return whether deleting an endpoint row would strand OpenBao state.

    The supported ``ProxmoxEndpoint.delete()`` path clears the row's own
    references and assignments before its original model delete sends
    ``pre_delete``. Queryset and bulk deletion reach this signal without that
    cleanup, so any remaining reference or assignment refuses deletion.
    """
    from netbox_proxbox.integrations.openbao import (
        endpoint_holds_openbao_references,
    )

    if endpoint_holds_openbao_references(instance) or _endpoints_have_state(
        sender.objects.filter(pk=instance.pk)
    ):
        return True
    try:
        assignments = _provider_assignment_model()
    except ValidationError:
        return False
    return (
        assignments.objects.using(instance._state.db or "default")
        .filter(
            assigned_object_type__app_label=instance._meta.app_label,
            assigned_object_type__model=instance._meta.model_name,
            assigned_object_id=instance.pk,
        )
        .exists()
    )


def install_node_material_guards() -> None:
    """Install bulk, raw-delete, parent-cascade, and downgrade guards."""
    from dcim.models import Device
    from netbox_proxbox.models import (
        NodeSSHCredential,
        ProxmoxEndpoint,
        ProxmoxNode,
    )

    queryset_types = {
        type(manager.all())
        for model in (
            NodeSSHCredential,
            ProxmoxNode,
            ProxmoxEndpoint,
        )
        for manager in (model._default_manager, model._base_manager)
    }
    for queryset_type in sorted(
        queryset_types,
        key=lambda candidate: len(candidate.__mro__),
        reverse=True,
    ):
        _install_queryset_guards(queryset_type)
    if not getattr(ProxmoxEndpoint.save, "_proxbox_node_downgrade_guard", False):
        ProxmoxEndpoint.save = _guard_endpoint_save(ProxmoxEndpoint.save)
        ProxmoxEndpoint.save._proxbox_node_downgrade_guard = True
    for model in (Device, ProxmoxNode, ProxmoxEndpoint):
        pre_delete.connect(
            _guard_parent_delete,
            sender=model,
            weak=False,
            dispatch_uid=f"proxbox_openbao_node_parent_guard_{model._meta.label_lower}",
        )
