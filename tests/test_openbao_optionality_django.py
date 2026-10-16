"""Real model, Fernet, form, and migration contracts for optional OpenBao storage."""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import sys
from threading import Event, Thread
import types
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from cryptography.fernet import Fernet
import pytest

from tests.test_proxmox_endpoint_allowed_tenants import _require_harness

pytestmark = pytest.mark.django_db


class _PrimaryReplicaRouter:
    def db_for_read(self, _model, **_hints):
        return "openbao_replica"

    def db_for_write(self, _model, **_hints):
        return "default"


class _SecondaryWriteRouter:
    def db_for_read(self, _model, **_hints):
        return "default"

    def db_for_write(self, _model, **_hints):
        return "openbao_secondary"


@contextmanager
def _independent_secondary_database(test_id: str):
    """Replace the registered mirror with an independently populated clone."""
    from django.db import connection, connections

    from tests.django_database_names import disposable_database_name
    from tests.django_support import (
        ForwardOnlyMigrationTestCase,
        _ensure_harness_session,
    )

    alias = "openbao_secondary"
    primary_name = str(connection.settings_dict["NAME"])
    database_name = disposable_database_name("test", test_id)
    original_settings = deepcopy(connections.databases[alias])
    _ensure_harness_session()
    for database in connections.all():
        database.close()
        close_pool = getattr(database, "close_pool", None)
        if close_pool is not None:
            close_pool()
    ForwardOnlyMigrationTestCase._switch_default_database("postgres")
    try:
        ForwardOnlyMigrationTestCase._create_database(
            database_name,
            template=primary_name,
        )
    finally:
        ForwardOnlyMigrationTestCase._switch_default_database(primary_name)

    secondary = connections["default"].copy(alias=alias)
    secondary.settings_dict["NAME"] = database_name
    secondary.settings_dict["TEST"] = {
        **secondary.settings_dict.get("TEST", {}),
        "MIRROR": None,
        "NAME": database_name,
    }
    connections.databases[alias] = secondary.settings_dict
    connections[alias] = secondary
    try:
        assert connections[alias].settings_dict["NAME"] != primary_name
        assert connections[alias].settings_dict["TEST"]["MIRROR"] is None
        yield alias
    finally:
        connections[alias].close()
        connections.databases[alias] = original_settings
        restored = connections["default"].copy(alias=alias)
        restored.settings_dict.update(original_settings)
        connections[alias] = restored
        ForwardOnlyMigrationTestCase._switch_default_database("postgres")
        try:
            ForwardOnlyMigrationTestCase._drop_database(database_name)
        finally:
            ForwardOnlyMigrationTestCase._switch_default_database(primary_name)


@pytest.fixture
def optionality_models(pytestconfig, request):
    _require_harness(pytestconfig)
    request.getfixturevalue("db")
    from netbox_proxbox.models import ProxboxPluginSettings, ProxmoxEndpoint

    return ProxboxPluginSettings, ProxmoxEndpoint


def test_fresh_settings_and_all_four_credentials_use_real_fernet(
    optionality_models, settings
):
    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    Settings.objects.all().delete()
    configuration = Settings.get_solo()
    assert configuration.credential_storage_backend == ""
    key = Fernet.generate_key().decode("ascii")
    configuration.encryption_key = key
    configuration.save()
    endpoint = Endpoint(name="credential-test", username="root@pam", enabled=False)
    endpoint.password = "api-password"
    endpoint.token_value = "api-token"
    endpoint.set_ssh_password("ssh-password", key=key)
    endpoint.set_ssh_private_key("ssh-private-key", key=key)
    endpoint.save()
    endpoint.refresh_from_db()
    for field, plaintext in (
        ("password_enc", "api-password"),
        ("token_value_enc", "api-token"),
        ("ssh_password_enc", "ssh-password"),
        ("ssh_private_key_enc", "ssh-private-key"),
    ):
        ciphertext = getattr(endpoint, field)
        assert ciphertext != plaintext
        assert Fernet(key.encode()).decrypt(ciphertext.encode()).decode() == plaintext
    assert endpoint.password == "api-password"
    assert endpoint.token_value == "api-token"
    assert endpoint.get_ssh_password(key=key) == "ssh-password"
    assert endpoint.get_ssh_private_key(key=key) == "ssh-private-key"
    assert endpoint.openbao_password_credential_uuid is None
    assert endpoint.openbao_token_credential_uuid is None
    assert endpoint.openbao_ssh_password_credential_uuid is None
    assert endpoint.openbao_ssh_keypair_credential_uuid is None


@pytest.mark.parametrize(
    "kind", ["password", "token_value", "ssh_password", "ssh_private_key"]
)
def test_explicit_openbao_writes_fail_closed_without_plugin(
    optionality_models, settings, kind
):
    from django.core.exceptions import ValidationError

    _, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    endpoint = Endpoint(
        name="explicit-openbao", enabled=False, credential_storage_backend="openbao"
    )
    with pytest.raises(ValidationError, match="netbox-openbao"):
        if kind.startswith("ssh_"):
            getattr(endpoint, f"set_{kind}")(
                "must-not-store", key=Fernet.generate_key().decode()
            )
        else:
            setattr(endpoint, kind, "must-not-store")
    for field in (
        "password_enc",
        "token_value_enc",
        "ssh_password_enc",
        "ssh_private_key_enc",
    ):
        assert getattr(endpoint, field) == ""


def test_endpoint_serializer_applies_explicit_legacy_storage_override(
    optionality_models, settings
):
    from netbox_proxbox.api.serializers.endpoints import ProxmoxEndpointSerializer

    Settings, _ = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = "openbao"
    configuration.encryption_key = Fernet.generate_key().decode("ascii")
    configuration.save(update_fields=("credential_storage_backend", "encryption_key"))

    serializer = ProxmoxEndpointSerializer(
        data={
            "name": "legacy-api-fixture",
            "domain": "pve.example.test",
            "port": 8006,
            "mode": "cluster",
            "username": "root@pam",
            "token_name": "e2e",
            "token_value": "e2e-secret",
            "credential_storage_backend": "legacy_encrypted",
            "verify_ssl": False,
        }
    )

    assert serializer.is_valid(), serializer.errors
    endpoint = serializer.save()
    assert endpoint.credential_storage_backend == "legacy_encrypted"
    assert endpoint.token_value == "e2e-secret"
    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"


def test_automatic_settings_form_and_serializer_accept_blank(optionality_models):
    from netbox_proxbox.forms.settings import ProxboxPluginSettingsForm
    from netbox_proxbox.api.serializers.settings import ProxboxPluginSettingsSerializer

    field = ProxboxPluginSettingsForm.base_fields["credential_storage_backend"]
    assert field.clean("") == ""
    assert list(field.choices)[0] == ("", "Automatic (enabled plugins)")
    serializer = ProxboxPluginSettingsSerializer()
    assert serializer.fields["credential_storage_backend"].run_validation("") == ""


def test_settings_storage_serializer_create_update_and_patch_contract(
    optionality_models,
    settings,
):
    from netbox_proxbox.api.serializers.settings import ProxboxPluginSettingsSerializer

    Settings, _Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    Settings.objects.all().delete()
    create = ProxboxPluginSettingsSerializer(
        data={"credential_storage_backend": "legacy_encrypted"}
    )
    assert create.is_valid(), create.errors
    configuration = create.save()
    assert configuration.credential_storage_backend == "legacy_encrypted"

    update = ProxboxPluginSettingsSerializer(
        configuration,
        data={"credential_storage_backend": ""},
    )
    assert update.is_valid(), update.errors
    configuration = update.save()
    assert configuration.credential_storage_backend == ""

    patch = ProxboxPluginSettingsSerializer(
        configuration,
        data={"sync_job_timeout": 7201},
        partial=True,
    )
    assert patch.is_valid(), patch.errors
    configuration = patch.save()
    assert configuration.credential_storage_backend == ""
    assert configuration.sync_job_timeout == 7201

    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    configuration.refresh_from_db()
    unchanged = ProxboxPluginSettingsSerializer(
        configuration,
        data={"credential_storage_backend": "openbao"},
    )
    assert unchanged.is_valid(), unchanged.errors
    assert unchanged.save().credential_storage_backend == "openbao"

    for forged in ("unknown-provider", "OPENBAO", None, 7):
        serializer = ProxboxPluginSettingsSerializer(
            configuration,
            data={"credential_storage_backend": forged},
            partial=True,
        )
        assert not serializer.is_valid()
        assert "credential_storage_backend" in serializer.errors

    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="legacy_encrypted"
    )
    configuration.refresh_from_db()
    unavailable = ProxboxPluginSettingsSerializer(
        configuration,
        data={"credential_storage_backend": "openbao"},
        partial=True,
    )
    assert not unavailable.is_valid()
    assert "credential_storage_backend" in unavailable.errors


def test_endpoint_storage_serializer_create_update_and_patch_contract(
    optionality_models,
    settings,
):
    from netbox_proxbox.api.serializers.endpoints import ProxmoxEndpointSerializer

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = "legacy_encrypted"
    configuration.encryption_key = Fernet.generate_key().decode("ascii")
    configuration.save(update_fields=("credential_storage_backend", "encryption_key"))
    create = ProxmoxEndpointSerializer(
        data={
            "name": "serializer-storage-create",
            "domain": "create.example.test",
            "mode": "undefined",
            "enabled": False,
            "credential_storage_backend": "legacy_encrypted",
        }
    )
    assert create.is_valid(), create.errors
    endpoint = create.save()
    assert endpoint.credential_storage_backend == "legacy_encrypted"

    update = ProxmoxEndpointSerializer(
        endpoint,
        data={
            "name": endpoint.name,
            "domain": endpoint.domain,
            "mode": endpoint.mode,
            "enabled": False,
            "credential_storage_backend": "",
        },
    )
    assert update.is_valid(), update.errors
    endpoint = update.save()
    assert endpoint.credential_storage_backend == ""

    patch = ProxmoxEndpointSerializer(
        endpoint,
        data={"name": "serializer-storage-patched"},
        partial=True,
    )
    assert patch.is_valid(), patch.errors
    endpoint = patch.save()
    assert endpoint.credential_storage_backend == ""

    Endpoint.objects.filter(pk=endpoint.pk).update(credential_storage_backend="openbao")
    endpoint.refresh_from_db()
    unchanged = ProxmoxEndpointSerializer(
        endpoint,
        data={"credential_storage_backend": "openbao"},
        partial=True,
    )
    assert unchanged.is_valid(), unchanged.errors
    assert unchanged.save().credential_storage_backend == "openbao"

    for forged in ("unknown-provider", "OPENBAO", None, 7):
        serializer = ProxmoxEndpointSerializer(
            endpoint,
            data={"credential_storage_backend": forged},
            partial=True,
        )
        assert not serializer.is_valid()
        assert "credential_storage_backend" in serializer.errors

    Endpoint.objects.filter(pk=endpoint.pk).update(
        credential_storage_backend="legacy_encrypted"
    )
    endpoint.refresh_from_db()
    unavailable = ProxmoxEndpointSerializer(
        endpoint,
        data={"credential_storage_backend": "openbao"},
        partial=True,
    )
    assert not unavailable.is_valid()
    assert "credential_storage_backend" in unavailable.errors


@pytest.mark.parametrize("with_reference", [False, True])
@pytest.mark.django_db(transaction=True)
def test_0105_resets_only_unreferenced_implicit_openbao_default(
    pytestconfig, with_reference
):
    _require_harness(pytestconfig)
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor
    from netbox_proxbox.models import ProxmoxEndpoint, ProxboxPluginSettings

    before = ("netbox_proxbox", "0104_security_hardening")
    after = ("netbox_proxbox", "0105_reset_implicit_openbao_storage_default")
    executor = MigrationExecutor(connection)
    latest = executor.loader.graph.leaf_nodes()
    try:
        settings_row, _created = ProxboxPluginSettings.objects.update_or_create(
            singleton_key="default",
            defaults={"credential_storage_backend": "openbao"},
        )
        endpoint = None
        if with_reference:
            endpoint = ProxmoxEndpoint.objects.create(
                name="0105-reference",
                domain="pve.example.test",
                enabled=False,
                openbao_password_credential_uuid=(
                    "11111111-1111-4111-8111-111111111111"
                ),
            )
        executor.migrate([before])
        old_apps = executor.loader.project_state([before]).apps
        old_settings = old_apps.get_model("netbox_proxbox", "ProxboxPluginSettings")
        old_settings.objects.filter(pk=settings_row.pk).update(
            credential_storage_backend="openbao"
        )
        executor = MigrationExecutor(connection)
        executor.migrate([after])
        new_apps = executor.loader.project_state([after]).apps
        migrated_settings = new_apps.get_model(
            "netbox_proxbox", "ProxboxPluginSettings"
        )
        assert migrated_settings.objects.get(
            pk=settings_row.pk
        ).credential_storage_backend == ("openbao" if endpoint is not None else "")
    finally:
        MigrationExecutor(connection).migrate(latest)


@pytest.mark.django_db(
    transaction=True,
    databases=["default", "openbao_migration"],
)
def test_0105_checks_every_reference_on_nondefault_alias_and_replays(
    pytestconfig,
):
    _require_harness(pytestconfig)
    from importlib import import_module

    from django.apps import apps
    from django.db import connections
    from netbox_proxbox.models import (
        FastAPIEndpoint,
        FirecrackerHost,
        FirecrackerHostPool,
        NodeSSHCredential,
        PBSEndpoint,
        PDMEndpoint,
        ProxmoxEndpoint,
        ProxmoxNode,
        ProxboxPluginSettings,
        ProxmoxVMCloudInit,
    )
    from virtualization.models import VirtualMachine

    alias = "openbao_migration"
    migration = import_module(
        "netbox_proxbox.migrations.0105_reset_implicit_openbao_storage_default"
    )
    connections[alias].close()
    connections[alias] = connections["default"].copy(alias=alias)
    settings_row = ProxboxPluginSettings.objects.using(alias).create(
        singleton_key="default",
        credential_storage_backend="legacy_encrypted",
    )
    endpoint = ProxmoxEndpoint.objects.using(alias).create(
        name="0105-all-fields-endpoint",
        enabled=False,
        credential_storage_backend="legacy_encrypted",
    )
    explicit_openbao = ProxmoxEndpoint.objects.using(alias).create(
        name="0105-explicit-openbao",
        enabled=False,
        credential_storage_backend="openbao",
    )
    node = ProxmoxNode.objects.using(alias).create(
        endpoint=endpoint,
        name="0105-all-fields-node",
        ip_address="127.0.0.1",
    )
    node_credential = NodeSSHCredential.objects.using(alias).create(
        node=node,
        username="migration-test",
        known_host_fingerprint="SHA256:" + "A" * 43,
    )
    fastapi = FastAPIEndpoint.objects.using(alias).create(
        name="0105-all-fields-fastapi",
        domain="fastapi.example.test",
        enabled=False,
    )
    pbs = PBSEndpoint.objects.using(alias).create(
        name="0105-all-fields-pbs",
        token_id="root@pam!migration",
        enabled=False,
    )
    pdm = PDMEndpoint.objects.using(alias).create(
        name="0105-all-fields-pdm",
        token_id="root@pam!migration",
        enabled=False,
    )
    pool = FirecrackerHostPool.objects.using(alias).create(
        name="0105 pool",
        slug="0105-pool",
    )
    firecracker = FirecrackerHost.objects.using(alias).create(
        pool=pool,
        name="0105-all-fields-firecracker",
        agent_base_url="https://firecracker.example.test",
    )
    vm = VirtualMachine.objects.using(alias).create(
        name="0105-all-fields-vm",
        status="active",
    )
    cloud_init = ProxmoxVMCloudInit.objects.using(alias).create(virtual_machine=vm)
    owners = {
        "ProxmoxEndpoint": endpoint,
        "NodeSSHCredential": node_credential,
        "FastAPIEndpoint": fastapi,
        "PBSEndpoint": pbs,
        "PDMEndpoint": pdm,
        "FirecrackerHost": firecracker,
        "ProxmoxVMCloudInit": cloud_init,
    }
    schema_editor = SimpleNamespace(connection=connections[alias])

    def raw_reference(owner, field_name: str, value: object) -> None:
        field = owner._meta.get_field(field_name)
        quote = connections[alias].ops.quote_name
        with connections[alias].cursor() as cursor:
            cursor.execute(
                f"UPDATE {quote(owner._meta.db_table)} "
                f"SET {quote(field.column)} = %s WHERE id = %s",
                [value, owner.pk],
            )

    original_overrides = {
        endpoint.pk: endpoint.credential_storage_backend,
        explicit_openbao.pk: explicit_openbao.credential_storage_backend,
    }
    for index, (model_name, fields) in enumerate(
        migration.OPENBAO_REFERENCE_FIELDS.items(), start=1
    ):
        owner = owners[model_name]
        for field_name in fields:
            ProxboxPluginSettings.objects.using(alias).filter(
                pk=settings_row.pk
            ).update(credential_storage_backend="openbao")
            reference = f"00000000-0000-4000-8000-{index:012d}"
            raw_reference(owner, field_name, reference)

            migration.reset_implicit_openbao_storage_default(apps, schema_editor)

            settings_row.refresh_from_db(using=alias)
            assert settings_row.credential_storage_backend == "openbao"
            raw_reference(owner, field_name, None)
            index += 1

    migration.reset_implicit_openbao_storage_default(apps, schema_editor)
    settings_row.refresh_from_db(using=alias)
    assert settings_row.credential_storage_backend == ""
    migration.reset_implicit_openbao_storage_default(apps, schema_editor)
    settings_row.refresh_from_db(using=alias)
    assert settings_row.credential_storage_backend == ""
    assert (
        dict(
            ProxmoxEndpoint.objects.using(alias)
            .filter(pk__in=original_overrides)
            .values_list("pk", "credential_storage_backend")
        )
        == original_overrides
    )


@pytest.mark.parametrize("allow_writes", [False, True])
def test_automatic_endpoint_form_encrypts_password_without_openbao(
    optionality_models, settings, allow_writes
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm

    Settings, _Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = ""
    configuration.encryption_key = Fernet.generate_key().decode("ascii")
    configuration.save(update_fields=("credential_storage_backend", "encryption_key"))
    form = ProxmoxEndpointForm(
        data={
            "name": f"automatic-{allow_writes}",
            "domain": "pve.example.test",
            "port": 8006,
            "username": "root@pam",
            "password": "form-password",
            "credential_storage_backend": "",
            "mode": "undefined",
            "allow_writes": allow_writes,
            "ssh_credential_source": "dedicated",
            "ssh_port": 22,
            "ssh_auth_method": "password",
            "access_methods": "api",
            "service_monitoring_interval_minutes": 5,
        }
    )
    assert form.is_valid(), form.errors.as_data()
    endpoint = form.save()
    assert endpoint.password_enc
    assert endpoint.password_enc != "form-password"
    assert endpoint.password == "form-password"


def test_absent_openbao_selection_forms_reject_new_and_accept_stored(
    optionality_models, settings
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.forms.settings import ProxboxPluginSettingsForm

    _Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    settings_form = ProxboxPluginSettingsForm(
        data={"credential_storage_backend": "openbao"},
        current_storage_backend="",
    )
    assert "openbao" not in [
        choice[0]
        for choice in settings_form.fields["credential_storage_backend"].widget.choices
    ]
    assert 'value="openbao"' not in str(settings_form["credential_storage_backend"])
    assert not settings_form.is_valid()
    stored_settings_form = ProxboxPluginSettingsForm(
        data={"credential_storage_backend": "openbao"},
        current_storage_backend="openbao",
    )
    stored_settings_form.full_clean()
    assert "credential_storage_backend" not in stored_settings_form.errors

    endpoint = _saved_openbao_endpoint(Endpoint)
    endpoint_form = ProxmoxEndpointForm(
        instance=endpoint,
        data=_edit_data(endpoint, password="replacement-password"),
    )
    endpoint_form.full_clean()
    assert "credential_storage_backend" in endpoint_form.fields
    assert "credential_storage_backend" in endpoint_form.errors
    assert "allow_writes" not in endpoint_form.errors


class _UnregisteredOpenBaoModels(types.ModuleType):
    """Mimic a pip-installed netbox-openbao whose app is not in PLUGINS."""

    def __getattr__(self, name: str) -> object:
        raise RuntimeError(
            f"Model class netbox_openbao.models.{name} doesn't declare an "
            "explicit app_label and isn't in an application in INSTALLED_APPS."
        )


@pytest.mark.parametrize("allow_writes", [False, True])
def test_installed_but_disabled_openbao_package_is_never_imported(
    optionality_models, settings, monkeypatch, allow_writes
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm

    Settings, _Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    monkeypatch.setitem(
        sys.modules,
        "netbox_openbao.models",
        _UnregisteredOpenBaoModels("netbox_openbao.models"),
    )
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = ""
    configuration.encryption_key = Fernet.generate_key().decode("ascii")
    configuration.save()
    form = ProxmoxEndpointForm(
        data={
            "name": f"disabled-package-{allow_writes}",
            "domain": "pve.example.test",
            "port": 8006,
            "username": "root@pam",
            "password": "form-password",
            "credential_storage_backend": "",
            "mode": "undefined",
            "allow_writes": allow_writes,
            "ssh_credential_source": "dedicated",
            "ssh_port": 22,
            "ssh_auth_method": "password",
            "access_methods": "api",
            "service_monitoring_interval_minutes": 5,
        }
    )
    assert form.is_valid(), form.errors.as_data()
    endpoint = form.save()
    assert endpoint.password == "form-password"


def test_w106_reports_unavailable_explicit_openbao(optionality_models, settings):
    from netbox_proxbox.security_checks import insecure_transport_check

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = ""
    configuration.save(update_fields=("credential_storage_backend",))
    Endpoint.objects.filter(credential_storage_backend="openbao").delete()
    ids = {warning.id for warning in insecure_transport_check(databases=["default"])}
    assert "netbox_proxbox.W106" not in ids
    configuration.credential_storage_backend = "openbao"
    configuration.save(update_fields=("credential_storage_backend",))
    ids = {warning.id for warning in insecure_transport_check(databases=["default"])}
    assert "netbox_proxbox.W106" in ids

    configuration.credential_storage_backend = ""
    configuration.save(update_fields=("credential_storage_backend",))
    endpoint = Endpoint.objects.create(
        name="endpoint-only-openbao",
        enabled=False,
        credential_storage_backend="openbao",
    )
    warnings = insecure_transport_check(databases=["default"])
    w106 = [warning for warning in warnings if warning.id == "netbox_proxbox.W106"]
    assert len(w106) == 1
    assert "endpoint-only-openbao" in str(w106[0].msg)
    assert "plugin settings" not in str(w106[0].msg)

    settings.PLUGINS = ["netbox_proxbox", "netbox_openbao"]
    ids = {warning.id for warning in insecure_transport_check(databases=["default"])}
    assert "netbox_proxbox.W106" not in ids
    settings.PLUGINS = ["netbox_proxbox"]
    endpoint.delete()


@pytest.mark.parametrize("saved", ["openbao", "legacy_encrypted"])
@pytest.mark.django_db(transaction=True)
def test_forward_migration_preserves_explicit_storage_choices(pytestconfig, saved):
    _require_harness(pytestconfig)
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor
    from netbox_proxbox.choices import CredentialStorageBackendChoices
    from netbox_proxbox.models import ProxboxPluginSettings

    before = ("netbox_proxbox", "0093_proxmox_metrics_source_mode")
    after = ("netbox_proxbox", "0094_automatic_credential_storage_default")
    executor = MigrationExecutor(connection)
    latest = executor.loader.graph.leaf_nodes()
    try:
        # Seed the row at the current leaf before migrating backwards. The
        # idempotent additive migration contract deliberately retains newer
        # physical columns on rollback, so an older historical model cannot
        # safely insert a row that omits their non-null values.
        current_row, _created = ProxboxPluginSettings.objects.update_or_create(
            singleton_key="default",
            defaults={"credential_storage_backend": saved},
        )
        executor.migrate([before])
        old_settings = executor.loader.project_state([before]).apps.get_model(
            "netbox_proxbox", "ProxboxPluginSettings"
        )
        row = old_settings.objects.get(pk=current_row.pk)
        row.credential_storage_backend = saved
        row.save(update_fields=["credential_storage_backend"])
        executor = MigrationExecutor(connection)
        executor.migrate([after])
        new_settings = executor.loader.project_state([after]).apps.get_model(
            "netbox_proxbox", "ProxboxPluginSettings"
        )
        assert new_settings.objects.get(pk=row.pk).credential_storage_backend == saved
        assert new_settings._meta.get_field("credential_storage_backend").default == ""
        fresh_state = executor.loader.project_state(
            [("netbox_proxbox", "0083_openbao_credential_storage")]
        )
        fresh_settings = fresh_state.apps.get_model(
            "netbox_proxbox", "ProxboxPluginSettings"
        )
        assert (
            fresh_settings._meta.get_field("credential_storage_backend").default
            == CredentialStorageBackendChoices.OPENBAO
        )
    finally:
        MigrationExecutor(connection).migrate(latest)


@pytest.mark.parametrize("token_selected", [False, True])
def test_backend_and_export_support_single_openbao_auth_method(
    optionality_models, token_selected
):
    from netbox_proxbox.integrations import openbao
    from netbox_proxbox.views.backend_sync import _proxmox_backend_payload
    from netbox_proxbox.services.connection_authority import (
        approve_connection_target,
        connection_target_fingerprint,
    )
    from netbox_proxbox.views.endpoints.proxmox_export import (
        _serialize_proxmox_endpoint,
    )
    from tests.django_support import make_user

    _, Endpoint = optionality_models
    actor = make_user("single-auth-export-superuser", is_superuser=True)
    endpoint = Endpoint(
        name="single-auth",
        domain="pve.example.test",
        enabled=True,
        credential_storage_backend="openbao",
    )
    endpoint.token_name = "token-name" if token_selected else ""
    endpoint.openbao_password_credential_uuid = (
        None if token_selected else "11111111-1111-4111-8111-111111111111"
    )
    endpoint.openbao_token_credential_uuid = (
        "22222222-2222-4222-8222-222222222222" if token_selected else None
    )
    endpoint.save()
    payload = (
        {"token": "token-secret"} if token_selected else {"password": "password-secret"}
    )
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=object()),
        patch.object(openbao, "reveal_credential_material", return_value=payload),
    ):
        approve_connection_target(
            endpoint,
            user=actor,
            fingerprint=connection_target_fingerprint(endpoint),
        )
        backend = _proxmox_backend_payload(endpoint)
        exported = _serialize_proxmox_endpoint(
            endpoint, include_sensitive=True, user=actor
        )
    assert backend["password"] == (None if token_selected else "password-secret")
    assert backend["token_value"] == ("token-secret" if token_selected else None)
    assert exported["password"] == ("" if token_selected else "password-secret")
    assert exported["token_value"] == ("token-secret" if token_selected else "")


@pytest.mark.parametrize("token_selected", [False, True])
def test_edit_form_preserves_single_openbao_auth_method(
    optionality_models, token_selected
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = Endpoint(
        name="single-auth-edit",
        domain="pve.example.test",
        port=8006,
        username="root@pam",
        enabled=False,
        credential_storage_backend="openbao",
        token_name="api-token" if token_selected else "",
        openbao_password_credential_uuid=None
        if token_selected
        else "11111111-1111-4111-8111-111111111111",
        openbao_token_credential_uuid="22222222-2222-4222-8222-222222222222"
        if token_selected
        else None,
    )
    endpoint.save()
    form = ProxmoxEndpointForm(
        instance=endpoint,
        data={
            "name": endpoint.name,
            "domain": endpoint.domain,
            "port": 8006,
            "username": "root@pam",
            "token_name": endpoint.token_name,
            "credential_storage_backend": "openbao",
            "mode": "undefined",
            "ssh_credential_source": "dedicated",
            "ssh_port": 22,
            "ssh_auth_method": "password",
            "access_methods": "api",
            "service_monitoring_interval_minutes": 5,
        },
    )
    material = (
        {"token": "token-secret"} if token_selected else {"password": "password-secret"}
    )
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=object()),
        patch.object(openbao, "reveal_credential_material", return_value=material),
        patch.object(openbao, "openbao_prerequisites_errors", return_value=[]),
    ):
        assert form.is_valid(), form.errors.as_data()
    assert form.cleaned_data["password"] == (
        "" if token_selected else "password-secret"
    )
    assert form.cleaned_data["token_value"] == (
        "token-secret" if token_selected else ""
    )


def _saved_openbao_endpoint(Endpoint, name="optionality", **overrides):
    values = {
        "name": name,
        "domain": "pve.example.test",
        "port": 8006,
        "username": "root@pam",
        "enabled": False,
        "credential_storage_backend": "openbao",
    }
    values.update(overrides)
    endpoint = Endpoint(**values)
    endpoint.save()
    return endpoint


def _edit_data(endpoint, **overrides):
    values = {
        "name": endpoint.name,
        "domain": endpoint.domain,
        "port": 8006,
        "username": "root@pam",
        "token_name": endpoint.token_name,
        "credential_storage_backend": endpoint.credential_storage_backend,
        "mode": "undefined",
        "ssh_credential_source": "dedicated",
        "ssh_port": 22,
        "ssh_auth_method": "password",
        "access_methods": "api",
        "service_monitoring_interval_minutes": 5,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize("existing_reference", [False, True])
def test_edit_form_repairs_missing_auth_but_rejects_stale_counterpart(
    optionality_models, existing_reference
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        openbao_password_credential_uuid="11111111-1111-4111-8111-111111111111"
        if existing_reference
        else None,
    )
    form = ProxmoxEndpointForm(
        instance=endpoint,
        data=_edit_data(endpoint, token_name="replacement", token_value="new-token"),
    )
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=None),
        patch.object(openbao, "openbao_prerequisites_errors", return_value=[]),
    ):
        assert form.is_valid() is not existing_reference, form.errors.as_data()
    if existing_reference:
        assert "password" in form.errors
    else:
        assert form.cleaned_data["password"] == ""
        assert form.cleaned_data["token_value"] == "new-token"


@pytest.mark.parametrize("clear", ["clear_password", "clear_token"])
def test_edit_form_clears_before_selection_and_preserves_original_store(
    optionality_models, clear
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        token_name="existing-token",
        openbao_password_credential_uuid="11111111-1111-4111-8111-111111111111",
        openbao_token_credential_uuid="22222222-2222-4222-8222-222222222222",
    )
    actor = object()
    form = ProxmoxEndpointForm(
        instance=endpoint,
        request_user=actor,
        data=_edit_data(
            endpoint, **{clear: True, "credential_storage_backend": "legacy_encrypted"}
        ),
    )
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=object()),
        patch.object(
            openbao,
            "reveal_credential_material",
            return_value={"password": "kept-password", "token": "kept-token"},
        ) as reveal,
        patch.object(openbao, "openbao_prerequisites_errors", return_value=[]),
    ):
        assert form.is_valid(), form.errors.as_data()
    reveal.assert_called_once()
    assert form._request_user is actor
    assert endpoint._openbao_actor_user is actor
    assert form.cleaned_data["password"] == (
        "" if clear == "clear_password" else "kept-password"
    )
    assert form.cleaned_data["token_value"] == (
        "kept-token" if clear == "clear_password" else ""
    )
    assert form.cleaned_data["token_name"] == (
        "existing-token" if clear == "clear_password" else ""
    )


def test_edit_form_reports_missing_address_after_preservation(optionality_models):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(Endpoint)
    form = ProxmoxEndpointForm(
        instance=endpoint,
        data=_edit_data(
            endpoint, domain="", token_name="new-token", token_value="value"
        ),
    )
    with patch.object(openbao, "openbao_prerequisites_errors", return_value=[]):
        assert not form.is_valid()
    assert "domain" in form.errors
    assert "ip_address" in form.errors


@pytest.mark.parametrize("failure", ["missing", "deleted", "denied"])
def test_endpoint_list_serializes_failed_openbao_ssh_readiness(
    optionality_models, failure
):
    from netbox_proxbox.api.serializers.endpoints import ProxmoxEndpointSerializer
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        ssh_credential_source="reuse_endpoint",
        access_methods="api_ssh",
        ssh_known_host_fingerprint="SHA256:test",
        openbao_password_credential_uuid=None
        if failure == "missing"
        else "11111111-1111-4111-8111-111111111111",
    )
    endpoint.allow_writes = True
    with (
        patch.object(
            openbao,
            "_credential_for_uuid",
            return_value=None if failure == "deleted" else object(),
        ),
        patch.object(
            openbao,
            "reveal_credential_material",
            side_effect=PermissionError("secret-canary"),
        ),
        patch.object(Endpoint, "effective_rpc_enabled", return_value=True),
    ):
        assert endpoint.has_ssh_terminal_credentials is False
        assert endpoint.service_monitoring_eligible is False
        data = ProxmoxEndpointSerializer(
            [endpoint], many=True, context={"request": None}
        ).data
    assert data[0]["has_ssh_terminal_credentials"] is False
    assert data[0]["service_monitoring_eligible"] is False
    assert "secret-canary" not in str(data)


@pytest.fixture
def endpoint_readiness_openbao_estate(optionality_models):
    from django.contrib.auth import get_user_model
    from django.contrib.contenttypes.models import ContentType
    from netbox_proxbox.integrations.openbao import is_netbox_openbao_installed
    from users.models import Group, ObjectPermission

    if not is_netbox_openbao_installed():
        pytest.skip("The native metadata estate requires enabled netbox-openbao.")
    from netbox_openbao.models import Credential, CredentialPolicy, SecretEngine

    _, Endpoint = optionality_models
    engine = SecretEngine.objects.create(
        name=f"Serializer readiness {uuid4()}",
        slug=f"serializer-readiness-{uuid4()}",
        api_url="https://bao.invalid:8200",
        kv_mount="secret",
    )
    policy = CredentialPolicy.objects.create(
        name=f"Serializer readiness {uuid4()}",
        slug=f"serializer-readiness-{uuid4()}",
        engine=engine,
        openbao_policy="netbox-proxbox-readiness",
    )
    allowed_group = Group.objects.create(name=f"readiness-allowed-{uuid4()}")
    denied_group = Group.objects.create(name=f"readiness-denied-{uuid4()}")
    reveal_permission = ObjectPermission.objects.create(
        name=f"Readiness reveal {uuid4()}", actions=["reveal"]
    )
    reveal_permission.object_types.add(ContentType.objects.get_for_model(Credential))
    user_model = get_user_model()
    authorized = user_model.objects.create_user(username=f"authorized-{uuid4()}")
    reveal_permission.users.add(authorized)
    authorized.groups.add(allowed_group)
    denied = user_model.objects.create_user(username=f"denied-{uuid4()}")
    policy_denied = user_model.objects.create_user(username=f"policy-denied-{uuid4()}")
    reveal_permission.users.add(policy_denied)
    policy_denied.groups.add(denied_group)
    superuser = user_model.objects.create_superuser(
        username=f"superuser-{uuid4()}", email="", password=None
    )

    def credential(credential_type: str):
        credential_uuid = uuid4()
        return Credential.objects.create(
            name=f"Readiness {credential_uuid}",
            uuid=credential_uuid,
            credential_type=credential_type,
            policy=policy,
            engine=engine,
            path=f"credentials/{credential_uuid}",
        )

    return SimpleNamespace(
        Endpoint=Endpoint,
        policy=policy,
        allowed_group=allowed_group,
        authorized=authorized,
        denied=denied,
        policy_denied=policy_denied,
        superuser=superuser,
        credential=credential,
    )


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("missing", False),
        ("deleted", False),
        ("denied", False),
        ("authorized", True),
        ("wrong_type", False),
        ("policy_denied", False),
    ],
)
def test_endpoint_serializer_uses_authorized_openbao_metadata(
    endpoint_readiness_openbao_estate, case, expected
):
    from netbox_proxbox.api.serializers.endpoints import ProxmoxEndpointSerializer
    from netbox_proxbox.integrations import openbao

    estate = endpoint_readiness_openbao_estate
    actor = estate.authorized
    reference = None
    if case != "missing":
        credential = estate.credential(
            "api-token" if case == "wrong_type" else "password"
        )
        reference = credential.uuid
        if case == "deleted":
            credential.delete()
        elif case == "denied":
            actor = estate.denied
        elif case == "policy_denied":
            estate.policy.groups.add(estate.allowed_group)
            actor = estate.policy_denied
    endpoint = _saved_openbao_endpoint(
        estate.Endpoint,
        ssh_credential_source="reuse_endpoint",
        access_methods="api_ssh",
        ssh_known_host_fingerprint="SHA256:test",
        openbao_password_credential_uuid=reference,
        rpc_enabled=True,
    )
    endpoint.allow_writes = True
    request = _endpoint_readiness_request(actor)

    with patch.object(
        openbao,
        "reveal_credential_material",
        side_effect=AssertionError("serialization must not reveal material"),
    ) as reveal:
        data = ProxmoxEndpointSerializer(
            [endpoint], many=True, context={"request": request}
        ).data[0]

    assert data["has_ssh_terminal_credentials"] is expected
    assert data["service_monitoring_eligible"] is expected
    assert data["has_ssh_password"] is False
    assert data["has_ssh_private_key"] is False
    reveal.assert_not_called()


def _endpoint_readiness_request(actor):
    from django.test import RequestFactory

    request = RequestFactory().get("/", HTTP_HOST="localhost")
    request.user = actor
    return request


@pytest.mark.parametrize("endpoint_count", [1, 3])
def test_endpoint_serializer_openbao_metadata_query_is_list_wide(
    endpoint_readiness_openbao_estate, endpoint_count
):
    from django.db import connection
    from django.test.utils import CaptureQueriesContext
    from netbox_proxbox.api.serializers.endpoints import ProxmoxEndpointSerializer
    from netbox_proxbox.integrations import openbao

    estate = endpoint_readiness_openbao_estate
    password = estate.credential("password")
    ssh_password = estate.credential("ssh-password")
    keypair = estate.credential("ssh-keypair")
    endpoints = [
        _saved_openbao_endpoint(
            estate.Endpoint,
            f"metadata-{index}",
            ssh_credential_source="dedicated",
            ssh_auth_method="key" if index == 2 else "password",
            ssh_username="root",
            ssh_known_host_fingerprint="SHA256:test",
            openbao_password_credential_uuid=password.uuid,
            openbao_ssh_password_credential_uuid=ssh_password.uuid,
            openbao_ssh_keypair_credential_uuid=keypair.uuid,
            rpc_enabled=True,
        )
        for index in range(endpoint_count)
    ]
    endpoints.append(
        _saved_openbao_endpoint(
            estate.Endpoint,
            name="metadata-legacy",
            credential_storage_backend="legacy_encrypted",
        )
    )
    request = _endpoint_readiness_request(estate.superuser)

    with (
        patch.object(
            openbao,
            "reveal_credential_material",
            side_effect=AssertionError("serialization must not reveal material"),
        ) as reveal,
        CaptureQueriesContext(connection) as captured,
    ):
        data = ProxmoxEndpointSerializer(
            endpoints, many=True, context={"request": request}
        ).data

    metadata_queries = [
        query["sql"]
        for query in captured.captured_queries
        if "netbox_openbao_credential" in query["sql"].lower()
    ]
    assert len(metadata_queries) == 1
    assert [item["has_ssh_password"] for item in data[:endpoint_count]] == [
        True
    ] * endpoint_count
    assert [item["has_ssh_private_key"] for item in data[:endpoint_count]] == [
        True
    ] * endpoint_count
    assert [item["has_ssh_terminal_credentials"] for item in data[:endpoint_count]] == [
        True
    ] * endpoint_count
    reveal.assert_not_called()

    legacy = endpoints[-1]
    with CaptureQueriesContext(connection) as legacy_queries:
        ProxmoxEndpointSerializer(
            [legacy], many=True, context={"request": request}
        ).data
    assert not [
        query["sql"]
        for query in legacy_queries.captured_queries
        if "netbox_openbao_credential" in query["sql"].lower()
    ]


@pytest.mark.parametrize("eligibility_raises", [False, True])
def test_monitoring_failure_does_not_skip_next_healthy_endpoint(
    optionality_models, eligibility_raises
):
    from django.core.exceptions import ValidationError
    from netbox_proxbox import jobs
    from netbox_proxbox.integrations import openbao, rpc

    _, Endpoint = optionality_models
    broken = _saved_openbao_endpoint(
        Endpoint, "a-broken", ssh_credential_source="reuse_endpoint"
    )
    healthy = _saved_openbao_endpoint(
        Endpoint,
        "b-healthy",
        ssh_credential_source="dedicated",
        ssh_username="root",
        ssh_auth_method="password",
        openbao_ssh_password_credential_uuid="22222222-2222-4222-8222-222222222222",
    )
    Endpoint.objects.filter(pk__in=[broken.pk, healthy.pk]).update(
        enabled=True,
        allow_writes=True,
        access_methods="api_ssh",
        service_monitoring_enabled=True,
        ssh_known_host_fingerprint="SHA256:test",
    )
    original = Endpoint.service_monitoring_eligible.fget

    def eligibility(endpoint):
        if eligibility_raises and endpoint.pk == broken.pk:
            raise ValidationError("Credential readiness failed.")
        return original(endpoint)

    job = jobs.ProxmoxServiceMonitoringJob.__new__(jobs.ProxmoxServiceMonitoringJob)
    job.job = SimpleNamespace(user=None)
    with (
        patch.object(Endpoint, "service_monitoring_eligible", property(eligibility)),
        patch.object(Endpoint, "effective_rpc_enabled", return_value=True),
        patch.object(openbao, "_credential_for_uuid", return_value=None),
        patch.object(rpc, "project_completed_collections", return_value=0),
        patch.object(rpc, "collect_systemctl_services") as collect,
    ):
        job.run()
    assert [call.args[0].pk for call in collect.call_args_list] == [healthy.pk]
    broken.refresh_from_db()
    assert broken.service_monitoring_last_status == "failed"
    assert broken.service_monitoring_last_error


def _install_rpc_backend_selection_stubs(monkeypatch, *, selected: bool):
    """Install an optional-companion surface with two public RPC backends."""
    execution_creates = []
    enqueue_calls = []

    class _Rows(list):
        def first(self):
            return self[0] if self else None

    class _ProcedureManager:
        def filter(self, **kwargs):
            assert kwargs == {
                "name": "os.linux.proxmox.show_systemctl_services",
                "enabled": True,
            }
            return _Rows([SimpleNamespace(pk=701)])

    class _ExecutionManager:
        def create(self, **kwargs):
            execution_creates.append(kwargs)
            return SimpleNamespace(pk=702)

    class _BackendManager:
        def values_list(self, *args, **kwargs):
            assert args == ("pk",)
            assert kwargs == {"flat": True}
            return _Rows([111, 222])

    class _RpcPluginSettings:
        @classmethod
        def get_solo(cls):
            backend = SimpleNamespace(pk=222) if selected else None
            return SimpleNamespace(backend=backend)

    class _RPCExecutionJob:
        @classmethod
        def enqueue(cls, **kwargs):
            enqueue_calls.append(kwargs)

    rpc_package = types.ModuleType("netbox_rpc")
    rpc_package.__path__ = []
    rpc_jobs = types.ModuleType("netbox_rpc.jobs")
    rpc_jobs.RPCExecutionJob = _RPCExecutionJob
    rpc_models = types.ModuleType("netbox_rpc.models")
    rpc_models.RPCProcedure = type("RPCProcedure", (), {"objects": _ProcedureManager()})
    rpc_models.RPCExecution = type("RPCExecution", (), {"objects": _ExecutionManager()})
    rpc_models.RPCBackend = type("RPCBackend", (), {"objects": _BackendManager()})
    rpc_models.RpcPluginSettings = _RpcPluginSettings
    monkeypatch.setitem(sys.modules, "netbox_rpc", rpc_package)
    monkeypatch.setitem(sys.modules, "netbox_rpc.jobs", rpc_jobs)
    monkeypatch.setitem(sys.modules, "netbox_rpc.models", rpc_models)
    return execution_creates, enqueue_calls


@pytest.mark.parametrize("entrypoint", ["api", "ui", "scheduled"])
@pytest.mark.parametrize("selected", [True, False])
def test_service_monitoring_entrypoints_resolve_selected_backend_and_fail_ambiguity(
    optionality_models,
    monkeypatch,
    entrypoint,
    selected,
):
    """Exercise all production callers through selected and ambiguous backends."""
    from django.test import RequestFactory
    from netbox_proxbox.api.views import ProxmoxServiceMonitoringRefreshAPIView
    from netbox_proxbox.integrations import rpc
    from netbox_proxbox.jobs import ProxmoxServiceMonitoringJob
    from netbox_proxbox.models import ProxmoxServiceCollection
    from netbox_proxbox.views.endpoints import proxmox as endpoint_views
    from tests.django_support import make_user

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        f"rpc-selection-{entrypoint}-{selected}",
        enabled=True,
        allow_writes=True,
        access_methods="api_ssh",
        service_monitoring_enabled=True,
    )
    user = make_user(
        username=f"rpc-selection-{entrypoint}-{selected}",
        is_staff=True,
        is_superuser=True,
    )
    execution_creates, enqueue_calls = _install_rpc_backend_selection_stubs(
        monkeypatch,
        selected=selected,
    )
    before = ProxmoxServiceCollection.objects.count()

    with (
        patch.object(
            Endpoint, "service_monitoring_eligible", property(lambda _e: True)
        ),
        patch.object(rpc, "project_completed_collections", return_value=0),
    ):
        if entrypoint == "api":
            request = RequestFactory().post("/api/services/refresh/")
            request.user = user
            response = ProxmoxServiceMonitoringRefreshAPIView().post(
                request,
                endpoint.pk,
            )
            assert response.status_code == (202 if selected else 503)
        elif entrypoint == "ui":
            request = RequestFactory().post("/services/refresh/")
            request.user = user
            with (
                patch.object(endpoint_views.messages, "success") as success,
                patch.object(endpoint_views.messages, "error") as error,
                patch.object(
                    endpoint_views.ProxmoxEndpointServicesView,
                    "_services_url",
                    return_value="/services/",
                ),
            ):
                response = endpoint_views.ProxmoxEndpointServicesView().post(
                    request,
                    endpoint.pk,
                )
            assert response.status_code == 302
            assert success.called is selected
            assert error.called is not selected
        else:
            job = ProxmoxServiceMonitoringJob.__new__(ProxmoxServiceMonitoringJob)
            job.job = SimpleNamespace(user=user)
            job.run()

    created = ProxmoxServiceCollection.objects.count() - before
    assert created == (1 if selected else 0)
    assert len(execution_creates) == (1 if selected else 0)
    assert len(enqueue_calls) == (1 if selected else 0)
    if selected:
        assert execution_creates[0]["backend_id"] == 222
        assert enqueue_calls[0]["backend_pk"] == 222


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("missing", 503),
        ("token", 422),
        ("denied", 503),
        ("healthy", 200),
        ("unpinned", 404),
    ],
)
def test_ssh_reuse_response_contains_expected_openbao_failure(
    optionality_models, mode, expected
):
    from netbox_proxbox.api import ssh_credentials
    from netbox_proxbox.integrations import openbao
    from tests.django_support import make_user

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        enabled=True,
        ssh_credential_source="reuse_endpoint",
        access_methods="api_ssh",
        token_name="api-token" if mode == "token" else "",
        openbao_password_credential_uuid="11111111-1111-4111-8111-111111111111"
        if mode in {"denied", "healthy", "unpinned"}
        else None,
        ssh_known_host_fingerprint="SHA256:" + "A" * 43 if mode == "healthy" else "",
    )
    user = make_user("ssh-reader", is_staff=True, is_superuser=True)
    request = SimpleNamespace(user=user, is_secure=lambda: True)
    with (
        patch.object(
            openbao,
            "_credential_for_uuid",
            return_value=None if mode == "missing" else object(),
        ),
        patch.object(
            openbao,
            "reveal_credential_material",
            side_effect=PermissionError("secret-canary") if mode == "denied" else None,
            return_value={"password": "usable-password"},
        ) as reveal,
    ):
        response = ssh_credentials.ProxmoxEndpointSSHCredentialSecretsAPIView().get(
            request, endpoint.pk
        )
    assert response.status_code == expected
    if mode == "healthy":
        assert response.data["password"] == "usable-password"
        assert response.data["private_key"] == ""
    else:
        assert "password" not in response.data
    assert bool(reveal.call_count) is (mode in {"denied", "healthy", "unpinned"})
    if reveal.called:
        reveal.assert_called_once()
        assert reveal.call_args.kwargs["user"] is user
    assert "secret-canary" not in str(response.data)


def test_ssh_reuse_response_disabled_endpoint_refuses_without_credential_reveal(
    optionality_models,
):
    from netbox_proxbox.api import ssh_credentials
    from netbox_proxbox.integrations import openbao
    from tests.django_support import make_user

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        ssh_credential_source="reuse_endpoint",
        access_methods="api_ssh",
        openbao_password_credential_uuid="11111111-1111-4111-8111-111111111111",
        ssh_known_host_fingerprint="SHA256:" + "A" * 43,
    )
    user = make_user("ssh-disabled-endpoint", is_staff=True, is_superuser=True)
    request = SimpleNamespace(user=user, is_secure=lambda: True)
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=object()),
        patch.object(
            openbao,
            "reveal_credential_material",
            return_value={"password": "must-not-leak"},
        ) as reveal,
    ):
        response = ssh_credentials.ProxmoxEndpointSSHCredentialSecretsAPIView().get(
            request, endpoint.pk
        )
    assert response.status_code == 403
    assert "password" not in response.data
    reveal.assert_not_called()
    assert "must-not-leak" not in str(response.data)


def test_reuse_form_contains_failed_preservation_in_all_readiness_checks(
    optionality_models,
):
    from django.core.exceptions import ValidationError
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointForm
    from netbox_proxbox.integrations import openbao

    _, Endpoint = optionality_models
    endpoint = _saved_openbao_endpoint(
        Endpoint,
        ssh_credential_source="reuse_endpoint",
        ssh_known_host_fingerprint="SHA256:" + "A" * 43,
        openbao_password_credential_uuid="11111111-1111-4111-8111-111111111111",
    )
    form = ProxmoxEndpointForm(
        instance=endpoint,
        data=_edit_data(
            endpoint,
            token_name="new-token",
            token_value="new-value",
            allow_writes=True,
            access_methods="api_ssh",
            ssh_credential_source="reuse_endpoint",
            ssh_known_host_fingerprint=endpoint.ssh_known_host_fingerprint,
            service_monitoring_enabled=True,
        ),
    )
    with (
        patch.object(openbao, "_credential_for_uuid", return_value=None),
        patch.object(openbao, "openbao_prerequisites_errors", return_value=[]),
        patch.object(Endpoint, "effective_rpc_enabled", return_value=True),
    ):
        assert not form.is_valid()
        assert "password" in form.errors
        assert "ssh_credential_source" in form.errors
        assert "service_monitoring_enabled" in form.errors
        endpoint.service_monitoring_enabled = False
        with pytest.raises(ValidationError) as raised:
            endpoint.clean()
    assert "ssh_credential_source" in raised.value.message_dict


def test_settings_page_renders_every_required_and_storage_field(
    optionality_models, settings
):
    from django.test import Client

    from netbox_proxbox.forms.settings import ProxboxPluginSettingsForm
    from tests.django_support import make_user

    Settings, _Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = ""
    configuration.save(update_fields=("credential_storage_backend",))
    client = Client()
    client.force_login(make_user("storage-settings-admin", is_superuser=True))

    response = client.get("/plugins/proxbox/settings/")

    assert response.status_code == 200
    html = response.content.decode()
    form = ProxboxPluginSettingsForm(current_storage_backend="")
    unrendered = [
        name
        for name, field in form.fields.items()
        if field.required and f'name="{name}"' not in html
    ]
    assert unrendered == []
    for name in (
        "credential_storage_backend",
        "openbao_policy_slug",
        "openbao_service_username",
    ):
        assert f'name="{name}"' in html
    assert 'value="openbao"' not in html


def test_settings_downgrade_refuses_inherited_endpoint_openbao_reference(
    optionality_models, settings
):
    from django.core.exceptions import ValidationError

    from netbox_proxbox.forms.settings import ProxboxPluginSettingsForm

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    Endpoint.objects.create(
        name="inherited-reference",
        domain="pve.example.test",
        enabled=False,
        credential_storage_backend="",
        openbao_password_credential_uuid="22222222-2222-4222-8222-222222222222",
    )
    configuration.refresh_from_db()

    for selection in ("", "legacy_encrypted"):
        form = ProxboxPluginSettingsForm(
            data={"credential_storage_backend": selection},
            current_storage_backend="openbao",
        )
        form.full_clean()
        assert "OpenBao references or assignments remain" in str(
            form.errors.get("credential_storage_backend")
        )
        configuration.credential_storage_backend = selection
        with pytest.raises(ValidationError):
            configuration.save()
    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"


def test_endpoint_inheritance_uses_explicit_global_legacy_selection(
    optionality_models,
    monkeypatch,
):
    from django.core.exceptions import ValidationError
    from django.db import connection
    from netbox_proxbox.integrations import openbao
    from netbox_proxbox.models import NodeSSHCredential, ProxmoxNode

    Settings, Endpoint = optionality_models
    configuration = Settings.get_solo()
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="legacy_encrypted"
    )
    endpoint = Endpoint.objects.create(
        name="explicit-openbao-over-global-legacy",
        enabled=False,
        credential_storage_backend="openbao",
    )
    node = ProxmoxNode.objects.create(
        endpoint=endpoint,
        name="explicit-openbao-over-global-legacy-node",
        ip_address="127.0.0.1",
    )
    owner = NodeSSHCredential.objects.create(
        node=node,
        username="storage-guard",
        known_host_fingerprint="SHA256:" + "A" * 43,
    )
    table = connection.ops.quote_name(owner._meta.db_table)
    column = connection.ops.quote_name("openbao_password_credential_uuid")
    with connection.cursor() as cursor:
        cursor.execute(
            f"UPDATE {table} SET {column} = %s WHERE id = %s",
            ["77777777-7777-4777-8777-777777777777", owner.pk],
        )
    monkeypatch.setattr(openbao, "is_netbox_openbao_installed", lambda: True)

    with pytest.raises(ValidationError, match="cleanup path"):
        Endpoint.objects.filter(pk=endpoint.pk).update(credential_storage_backend="")

    endpoint.refresh_from_db()
    owner.refresh_from_db()
    assert endpoint.credential_storage_backend == "openbao"
    assert owner.openbao_password_credential_uuid is not None


@pytest.mark.django_db(
    transaction=True,
    databases=["default", "openbao_replica"],
)
def test_settings_update_locks_and_checks_the_write_router_database(
    pytestconfig,
):
    _require_harness(pytestconfig)
    from django.db import connections
    from django.test import override_settings
    from netbox_proxbox.models import ProxboxPluginSettings

    alias = "openbao_replica"
    connections[alias].close()
    connections[alias] = connections["default"].copy(alias=alias)
    configuration = ProxboxPluginSettings.get_solo()
    ProxboxPluginSettings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    observed = {"default": [], alias: []}

    def capture(database):
        def wrapper(execute, sql, params, many, context):
            observed[database].append(sql)
            return execute(sql, params, many, context)

        return wrapper

    with (
        connections["default"].cursor() as cursor,
        connections["default"].execute_wrapper(capture("default")),
        connections[alias].execute_wrapper(capture(alias)),
        override_settings(DATABASE_ROUTERS=[_PrimaryReplicaRouter()]),
    ):
        cursor.execute("SET lock_timeout TO '500ms'")
        queryset = ProxboxPluginSettings.objects.filter(pk=configuration.pk)
        assert queryset.db == alias
        assert queryset.update(credential_storage_backend="legacy_encrypted") == 1
        cursor.execute("SET lock_timeout TO DEFAULT")

    default_sql = "\n".join(observed["default"]).upper()
    assert "FOR UPDATE" in default_sql
    assert "UPDATE" in default_sql
    assert observed[alias] == []
    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "legacy_encrypted"


@pytest.mark.django_db(
    transaction=True,
    databases=["default", "openbao_secondary"],
)
def test_settings_writes_do_not_scan_an_unrelated_primary_database(
    pytestconfig,
    request,
):
    _require_harness(pytestconfig)
    from django.db import connection
    from django.test import override_settings
    from netbox_proxbox.models import (
        NodeSSHCredential,
        ProxmoxEndpoint,
        ProxmoxNode,
        ProxboxPluginSettings,
    )

    configuration = ProxboxPluginSettings.get_solo()
    ProxboxPluginSettings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    with _independent_secondary_database(request.node.nodeid) as alias:
        endpoint = ProxmoxEndpoint.objects.create(
            name="unrelated-primary-node-state",
            enabled=False,
            credential_storage_backend="",
        )
        node = ProxmoxNode.objects.create(
            endpoint=endpoint,
            name="unrelated-primary-node",
            ip_address="127.0.0.1",
        )
        owner = NodeSSHCredential.objects.create(
            node=node,
            username="secondary-router-guard",
            known_host_fingerprint="SHA256:" + "B" * 43,
        )
        table = connection.ops.quote_name(owner._meta.db_table)
        column = connection.ops.quote_name("openbao_password_credential_uuid")
        with connection.cursor() as cursor:
            cursor.execute(
                f"UPDATE {table} SET {column} = %s WHERE id = %s",
                ["66666666-6666-4666-8666-666666666666", owner.pk],
            )

        with override_settings(DATABASE_ROUTERS=[_SecondaryWriteRouter()]):
            for operation in ("save", "update", "bulk_update"):
                ProxboxPluginSettings.objects.using(alias).filter(
                    singleton_key="default"
                ).update(credential_storage_backend="openbao")
                current = ProxboxPluginSettings.objects.using(alias).get(
                    singleton_key="default"
                )
                current.credential_storage_backend = "legacy_encrypted"
                if operation == "save":
                    current.save(update_fields=["credential_storage_backend"])
                elif operation == "update":
                    ProxboxPluginSettings.objects.filter(pk=current.pk).update(
                        credential_storage_backend="legacy_encrypted"
                    )
                else:
                    ProxboxPluginSettings.objects.bulk_update(
                        [current], ["credential_storage_backend"]
                    )
                assert (
                    ProxboxPluginSettings.objects.using(alias)
                    .get(pk=current.pk)
                    .credential_storage_backend
                    == "legacy_encrypted"
                )

    configuration.refresh_from_db()
    owner.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"
    assert owner.openbao_password_credential_uuid is not None


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("manager_name", ["default", "base"])
def test_storage_conflict_upsert_is_rejected_during_first_reference(
    optionality_models,
    settings,
    manager_name,
):
    from django.core.exceptions import ValidationError
    from django.db import connections, transaction

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    manager = Settings.objects if manager_name == "default" else Settings._base_manager
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    endpoint = Endpoint.objects.create(
        name="conflict-upsert-first-reference",
        enabled=False,
        credential_storage_backend="",
    )
    reference_written = Event()
    allow_reference_commit = Event()
    upsert_finished = Event()
    provider_errors: list[BaseException] = []
    upsert_errors: list[BaseException] = []

    def create_reference() -> None:
        try:
            connections["default"].close()
            with transaction.atomic():
                Settings.objects.select_for_update().get(pk=configuration.pk)
                table = connections["default"].ops.quote_name(endpoint._meta.db_table)
                column = connections["default"].ops.quote_name(
                    "openbao_password_credential_uuid"
                )
                with connections["default"].cursor() as cursor:
                    cursor.execute(
                        f"UPDATE {table} SET {column} = %s WHERE id = %s",
                        ["88888888-8888-4888-8888-888888888888", endpoint.pk],
                    )
                reference_written.set()
                if not allow_reference_commit.wait(timeout=30):
                    raise RuntimeError("timed out waiting to commit the reference")
        except BaseException as exc:  # pragma: no cover - asserted in caller
            provider_errors.append(exc)
        finally:
            connections["default"].close()

    def conflict_upsert() -> None:
        try:
            connections["default"].close()
            manager.bulk_create(
                [
                    Settings(
                        singleton_key="default",
                        credential_storage_backend="legacy_encrypted",
                    )
                ],
                update_conflicts=True,
                update_fields=["credential_storage_backend"],
                unique_fields=["singleton_key"],
            )
        except BaseException as exc:  # pragma: no cover - asserted in caller
            upsert_errors.append(exc)
        finally:
            upsert_finished.set()
            connections["default"].close()

    provider = Thread(target=create_reference, daemon=True)
    provider.start()
    assert reference_written.wait(timeout=30), provider_errors
    upsert = Thread(target=conflict_upsert, daemon=True)
    upsert.start()
    assert upsert_finished.wait(timeout=10)
    assert len(upsert_errors) == 1
    assert isinstance(upsert_errors[0], ValidationError)
    assert "Conflict upserts cannot change" in str(upsert_errors[0])
    allow_reference_commit.set()
    provider.join(timeout=30)
    upsert.join(timeout=30)

    assert not provider.is_alive()
    assert not upsert.is_alive()
    assert provider_errors == []
    configuration.refresh_from_db()
    endpoint.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"
    assert endpoint.openbao_password_credential_uuid is not None


@pytest.mark.parametrize("operation", ["update", "bulk_update", "conflict_upsert"])
def test_base_manager_settings_writes_refuse_existing_reference(
    optionality_models,
    settings,
    operation,
):
    from django.core.exceptions import ValidationError

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    Endpoint.objects.create(
        name=f"base-manager-existing-reference-{operation}",
        enabled=False,
        credential_storage_backend="",
        openbao_password_credential_uuid="55555555-5555-4555-8555-555555555555",
    )
    configuration.credential_storage_backend = "legacy_encrypted"

    with pytest.raises(ValidationError):
        if operation == "update":
            Settings._base_manager.filter(pk=configuration.pk).update(
                credential_storage_backend="legacy_encrypted"
            )
        elif operation == "bulk_update":
            Settings._base_manager.bulk_update(
                [configuration], ["credential_storage_backend"]
            )
        else:
            Settings._base_manager.bulk_create(
                [
                    Settings(
                        singleton_key="default",
                        credential_storage_backend="legacy_encrypted",
                    )
                ],
                update_conflicts=True,
                update_fields=["credential_storage_backend"],
                unique_fields=["singleton_key"],
            )

    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"


@pytest.mark.parametrize("manager_name", ["default", "base"])
def test_validated_settings_bulk_update_persists_without_references(
    optionality_models,
    settings,
    manager_name,
):
    Settings, _Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = "legacy_encrypted"
    manager = Settings.objects if manager_name == "default" else Settings._base_manager

    assert manager.bulk_update([configuration], ["credential_storage_backend"]) == 1

    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "legacy_encrypted"


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize(
    ("manager_name", "operation"),
    [
        ("default", "save"),
        ("default", "update"),
        ("default", "bulk_update"),
        ("base", "update"),
        ("base", "bulk_update"),
    ],
)
def test_settings_downgrade_serializes_after_first_reference_without_companion(
    optionality_models,
    settings,
    manager_name,
    operation,
):
    from django.core.exceptions import ValidationError
    from django.db import connections, transaction

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    manager = Settings.objects if manager_name == "default" else Settings._base_manager
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    endpoint = Endpoint.objects.create(
        name="concurrent-inherited-reference",
        enabled=False,
        credential_storage_backend="",
    )
    reference_written = Event()
    allow_reference_commit = Event()
    downgrade_started = Event()
    downgrade_finished = Event()
    provider_errors: list[BaseException] = []
    downgrade_errors: list[BaseException] = []

    def create_reference_in_provider_lock_order() -> None:
        try:
            connections["default"].close()
            with transaction.atomic():
                Settings.objects.select_for_update().get(pk=configuration.pk)
                table = connections["default"].ops.quote_name(endpoint._meta.db_table)
                column = connections["default"].ops.quote_name(
                    "openbao_password_credential_uuid"
                )
                with connections["default"].cursor() as cursor:
                    cursor.execute(
                        f"UPDATE {table} SET {column} = %s WHERE id = %s",
                        ["99999999-9999-4999-8999-999999999999", endpoint.pk],
                    )
                reference_written.set()
                if not allow_reference_commit.wait(timeout=30):
                    raise RuntimeError("timed out waiting to commit the reference")
        except BaseException as exc:  # pragma: no cover - asserted in caller
            provider_errors.append(exc)
        finally:
            connections["default"].close()

    def downgrade() -> None:
        try:
            connections["default"].close()
            downgrade_started.set()
            current = manager.get(pk=configuration.pk)
            current.credential_storage_backend = "legacy_encrypted"
            if operation == "save":
                current.save(update_fields=["credential_storage_backend"])
            elif operation == "update":
                manager.filter(pk=current.pk).update(
                    credential_storage_backend="legacy_encrypted"
                )
            else:
                manager.bulk_update([current], ["credential_storage_backend"])
        except BaseException as exc:  # pragma: no cover - asserted in caller
            downgrade_errors.append(exc)
        finally:
            downgrade_finished.set()
            connections["default"].close()

    provider = Thread(target=create_reference_in_provider_lock_order, daemon=True)
    provider.start()
    assert reference_written.wait(timeout=30), provider_errors
    downgrader = Thread(target=downgrade, daemon=True)
    downgrader.start()
    assert downgrade_started.wait(timeout=10)
    assert not downgrade_finished.wait(timeout=0.25)
    allow_reference_commit.set()
    provider.join(timeout=30)
    downgrader.join(timeout=30)

    assert not provider.is_alive()
    assert not downgrader.is_alive()
    assert provider_errors == []
    assert len(downgrade_errors) == 1
    assert isinstance(downgrade_errors[0], ValidationError)
    configuration.refresh_from_db()
    endpoint.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"
    assert endpoint.openbao_password_credential_uuid is not None


@pytest.mark.parametrize("disabled_package", [False, True])
def test_endpoint_delete_does_not_require_the_companion(
    optionality_models, settings, monkeypatch, disabled_package
):
    from django.core.exceptions import ValidationError

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    if disabled_package:
        monkeypatch.setitem(
            sys.modules,
            "netbox_openbao.models",
            _UnregisteredOpenBaoModels("netbox_openbao.models"),
        )
    else:
        monkeypatch.setitem(sys.modules, "netbox_openbao", None)
        monkeypatch.setitem(sys.modules, "netbox_openbao.models", None)
    configuration = Settings.get_solo()
    configuration.credential_storage_backend = ""
    configuration.encryption_key = Fernet.generate_key().decode("ascii")
    configuration.save()
    plain = Endpoint(name="plain-delete", domain="pve.example.test", enabled=False)
    plain.password = "api-password"
    plain.save()
    plain_pk = plain.pk

    plain.delete()

    assert not Endpoint.objects.filter(pk=plain_pk).exists()
    referenced = Endpoint.objects.create(
        name="referenced-delete",
        domain="pve2.example.test",
        enabled=False,
        credential_storage_backend="legacy_encrypted",
        openbao_token_credential_uuid="33333333-3333-4333-8333-333333333333",
    )
    with pytest.raises(ValidationError, match="netbox-openbao is not installed"):
        referenced.delete()
    assert Endpoint.objects.filter(pk=referenced.pk).exists()


def test_narrow_endpoint_form_reports_storage_error_without_crashing(
    optionality_models, settings
):
    from netbox_proxbox.forms.proxmox import ProxmoxEndpointSSHSettingsForm

    _Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    endpoint = _saved_openbao_endpoint(
        Endpoint, name="narrow-storage", allow_writes=True
    )
    form = ProxmoxEndpointSSHSettingsForm(
        instance=endpoint,
        data={
            "ssh_credential_source": "dedicated",
            "ssh_port": 22,
            "ssh_auth_method": "password",
        },
    )

    assert not form.is_valid()
    assert "netbox-openbao" in " ".join(form.non_field_errors())


def _settings_post_data(form) -> dict[str, object]:
    """Return POST data equivalent to submitting the rendered settings form."""
    data: dict[str, object] = {}
    for name, field in form.fields.items():
        value = form.initial.get(name, field.initial)
        if value is None or value is False:
            continue
        if value is True:
            data[name] = "on"
        elif hasattr(value, "pk"):
            data[name] = value.pk
        else:
            data[name] = value
    return data


def test_settings_post_refusal_is_a_field_error_not_a_server_error(
    optionality_models, settings
):
    from django.test import Client

    from tests.django_support import make_user

    Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    configuration = Settings.get_solo()
    Settings.objects.filter(pk=configuration.pk).update(
        credential_storage_backend="openbao"
    )
    Endpoint.objects.create(
        name="post-inherited-reference",
        domain="pve.example.test",
        enabled=False,
        credential_storage_backend="",
        openbao_password_credential_uuid="44444444-4444-4444-8444-444444444444",
    )
    client = Client()
    client.force_login(make_user("storage-post-admin", is_superuser=True))
    page = client.get("/plugins/proxbox/settings/")
    assert page.status_code == 200
    data = _settings_post_data(page.context["form"])
    data["credential_storage_backend"] = "legacy_encrypted"

    response = client.post("/plugins/proxbox/settings/", data)

    assert response.status_code == 200
    assert "OpenBao references or assignments remain" in response.content.decode()
    configuration.refresh_from_db()
    assert configuration.credential_storage_backend == "openbao"


@pytest.mark.parametrize("disabled_package", [False, True])
def test_queryset_delete_refuses_endpoint_openbao_references(
    optionality_models, settings, monkeypatch, disabled_package
):
    from django.core.exceptions import ValidationError
    from django.db import transaction

    _Settings, Endpoint = optionality_models
    settings.PLUGINS = ["netbox_proxbox"]
    if disabled_package:
        monkeypatch.setitem(
            sys.modules,
            "netbox_openbao.models",
            _UnregisteredOpenBaoModels("netbox_openbao.models"),
        )
    referenced = Endpoint.objects.create(
        name="queryset-referenced",
        domain="pve.example.test",
        enabled=False,
        credential_storage_backend="legacy_encrypted",
        openbao_token_credential_uuid="55555555-5555-4555-8555-555555555555",
    )
    plain = Endpoint.objects.create(
        name="queryset-plain",
        domain="pve2.example.test",
        enabled=False,
        credential_storage_backend="legacy_encrypted",
    )

    with pytest.raises(ValidationError), transaction.atomic():
        Endpoint.objects.filter(pk=referenced.pk).delete()
    Endpoint.objects.filter(pk=plain.pk).delete()

    assert Endpoint.objects.filter(pk=referenced.pk).exists()
    assert not Endpoint.objects.filter(pk=plain.pk).exists()
