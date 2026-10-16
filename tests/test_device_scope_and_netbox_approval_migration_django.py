"""Real-Django migration coverage for endpoint-scoped device identity."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

from tests.netbox_test_paths import netbox_source_roots


REPO_ROOT = Path(__file__).resolve().parents[1]
for candidate in (REPO_ROOT, *netbox_source_roots(REPO_ROOT)):
    candidate_string = str(candidate)
    if candidate.exists() and candidate_string not in sys.path:
        sys.path.insert(0, candidate_string)

_REQUIRE_DJANGO = os.environ.get("NETBOX_PROXBOX_REQUIRE_DJANGO", "").lower() in (
    "1",
    "true",
    "yes",
)

try:
    import django
except ModuleNotFoundError:
    if _REQUIRE_DJANGO:
        raise
    pytest.skip("Django is unavailable.", allow_module_level=True)

if not hasattr(django, "__path__"):
    pytest.skip("The mocked suite does not provide Django.", allow_module_level=True)

os.environ.setdefault("NETBOX_CONFIGURATION", "tests.netbox_test_configuration")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")

try:
    django.setup()
except Exception as exc:  # pragma: no cover - external harness availability
    if _REQUIRE_DJANGO:
        raise
    pytest.skip(
        f"NetBox test environment is unavailable: {exc}", allow_module_level=True
    )

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site  # noqa: E402
from tests.django_support import ForwardOnlyMigrationTestCase  # noqa: E402


class DeviceScopeAndNetBoxApprovalMigrationTest(ForwardOnlyMigrationTestCase):
    """Prove 0106's null scope, revocation, rollback, and reapply behavior."""

    migrate_from = (
        "netbox_proxbox",
        "0105_reset_implicit_openbao_storage_default",
    )
    migration_floor = migrate_from
    migrate_to = (
        "netbox_proxbox",
        "0106_device_sync_scope_and_netbox_token_approval",
    )

    @staticmethod
    def _core_devices() -> tuple[Device, Device]:
        site = Site.objects.create(
            name="scope-migration-site", slug="scope-migration-site"
        )
        manufacturer = Manufacturer.objects.create(
            name="scope-migration-maker", slug="scope-migration-maker"
        )
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer,
            model="scope-migration-type",
            slug="scope-migration-type",
        )
        role = DeviceRole.objects.create(
            name="scope-migration-role", slug="scope-migration-role"
        )
        return tuple(
            Device.objects.create(
                name=name,
                site=site,
                device_type=device_type,
                role=role,
            )
            for name in ("scope-with-endpoint", "scope-without-endpoint")
        )

    def test_forward_rollback_and_reapply_preserve_security_contracts(self) -> None:
        devices = self._core_devices()

        apps_before = self._migrate_to(self.migrate_from)
        EndpointBefore = apps_before.get_model("netbox_proxbox", "ProxmoxEndpoint")
        NetBoxEndpointBefore = apps_before.get_model("netbox_proxbox", "NetBoxEndpoint")
        DeviceStateBefore = apps_before.get_model(
            "netbox_proxbox", "ProxboxDeviceSyncState"
        )
        proxmox_endpoint = EndpointBefore.objects.create(
            name="scope-existing-endpoint",
            approved_connection_target_fingerprint="p" * 64,
        )
        endpoint_state = DeviceStateBefore.objects.create(
            device_id=devices[0].pk,
            endpoint=proxmox_endpoint,
        )
        null_state = DeviceStateBefore.objects.create(device_id=devices[1].pk)
        approved_netbox = NetBoxEndpointBefore.objects.create(
            name="scope-approved-netbox",
            approved_connection_target_fingerprint="n" * 64,
        )
        blank_netbox = NetBoxEndpointBefore.objects.create(name="scope-blank-netbox")

        apps_after = self._migrate_to(self.migrate_to)
        DeviceStateAfter = apps_after.get_model(
            "netbox_proxbox", "ProxboxDeviceSyncState"
        )
        NetBoxEndpointAfter = apps_after.get_model("netbox_proxbox", "NetBoxEndpoint")
        EndpointAfter = apps_after.get_model("netbox_proxbox", "ProxmoxEndpoint")
        self.assertIsNone(
            DeviceStateAfter.objects.get(pk=endpoint_state.pk).proxmox_endpoint_raw_id
        )
        self.assertIsNone(
            DeviceStateAfter.objects.get(pk=null_state.pk).proxmox_endpoint_raw_id
        )
        self.assertEqual(
            NetBoxEndpointAfter.objects.get(
                pk=approved_netbox.pk
            ).approved_connection_target_fingerprint,
            "",
        )
        self.assertEqual(
            NetBoxEndpointAfter.objects.get(
                pk=blank_netbox.pk
            ).approved_connection_target_fingerprint,
            "",
        )
        self.assertEqual(
            EndpointAfter.objects.get(
                pk=proxmox_endpoint.pk
            ).approved_connection_target_fingerprint,
            "p" * 64,
        )

        apps_rollback = self._migrate_to(self.migrate_from)
        DeviceStateRollback = apps_rollback.get_model(
            "netbox_proxbox", "ProxboxDeviceSyncState"
        )
        self.assertNotIn(
            "proxmox_endpoint_raw_id",
            {field.name for field in DeviceStateRollback._meta.get_fields()},
        )
        self.assertEqual(
            apps_rollback.get_model("netbox_proxbox", "NetBoxEndpoint")
            .objects.get(pk=approved_netbox.pk)
            .approved_connection_target_fingerprint,
            "",
        )

        apps_reapplied = self._migrate_to(self.migrate_to)
        self.assertIsNone(
            apps_reapplied.get_model("netbox_proxbox", "ProxboxDeviceSyncState")
            .objects.get(pk=endpoint_state.pk)
            .proxmox_endpoint_raw_id,
        )
