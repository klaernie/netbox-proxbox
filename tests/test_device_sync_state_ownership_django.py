"""Real-Django device sync-state endpoint ownership contracts."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import inspect
import os
from pathlib import Path
import sys
from threading import Barrier

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
from core.choices import ObjectChangeActionChoices  # noqa: E402
from core.models import ObjectChange  # noqa: E402
from django.contrib.contenttypes.models import ContentType  # noqa: E402
from django.db import close_old_connections, connections  # noqa: E402
from django.test import TestCase, TransactionTestCase  # noqa: E402
from django.urls import reverse  # noqa: E402
from users.models import ObjectPermission, Token  # noqa: E402

try:  # noqa: E402
    from users.constants import TOKEN_PREFIX
except ImportError:  # pragma: no cover - NetBox 4.5 v1 compatibility
    TOKEN_PREFIX = ""

from netbox_proxbox.api.serializers.sync_state import (  # noqa: E402
    EndpointOwnershipConflict,
    ProxboxDeviceSyncStateSerializer,
)
from netbox_proxbox.models import ProxboxDeviceSyncState  # noqa: E402
from tests.django_support import make_user  # noqa: E402


_AUTH_HEADER_ATTR = "_proxbox_ownership_test_auth_header"


def _auth_header_value(token: Token) -> str:
    cached = getattr(token, _AUTH_HEADER_ATTR, "")
    if cached:
        return cached
    if int(getattr(token, "version", 1) or 1) == 2:
        plaintext = getattr(token, "token", None)
        if not plaintext:
            raise AssertionError("NetBox v2 API token plaintext was not captured.")
        return f"Bearer {TOKEN_PREFIX}{token.key}.{plaintext}"
    value = getattr(token, "key", None) or getattr(token, "plaintext", None)
    return f"Token {value}"


def _api_token(user) -> Token:
    token = Token.objects.create(user=user)
    setattr(token, _AUTH_HEADER_ATTR, _auth_header_value(token))
    return token


def _device(name: str) -> Device:
    site = Site.objects.create(name=f"{name}-site", slug=f"{name}-site")
    manufacturer = Manufacturer.objects.create(
        name=f"{name}-manufacturer",
        slug=f"{name}-manufacturer",
    )
    device_type = DeviceType.objects.create(
        manufacturer=manufacturer,
        model=f"{name}-type",
        slug=f"{name}-type",
    )
    role = DeviceRole.objects.create(name=f"{name}-role", slug=f"{name}-role")
    return Device.objects.create(
        name=name,
        site=site,
        device_type=device_type,
        role=role,
    )


class DeviceSyncStateOwnershipAPITests(TestCase):
    """Expose atomic endpoint ownership through the REST contract."""

    @classmethod
    def setUpTestData(cls) -> None:
        cls.device = _device("ownership-api-device")
        cls.user = make_user("ownership-api-user", is_staff=True)
        cls.token = _api_token(cls.user)
        sidecar_permission = ObjectPermission.objects.create(
            name="ownership-api-sidecar-rw",
            actions=["view", "add", "change"],
        )
        sidecar_permission.object_types.add(
            ContentType.objects.get_for_model(ProxboxDeviceSyncState)
        )
        sidecar_permission.users.add(cls.user)
        parent_permission = ObjectPermission.objects.create(
            name="ownership-api-device-view",
            actions=["view"],
        )
        parent_permission.object_types.add(ContentType.objects.get_for_model(Device))
        parent_permission.users.add(cls.user)

    def setUp(self) -> None:
        self.auth_headers = {"HTTP_AUTHORIZATION": _auth_header_value(self.token)}

    @staticmethod
    def _detail_url(row: ProxboxDeviceSyncState) -> str:
        return reverse(
            "plugins-api:netbox_proxbox-api:proxboxdevicesyncstate-detail",
            args=[row.pk],
        )

    @staticmethod
    def _list_url() -> str:
        return reverse("plugins-api:netbox_proxbox-api:proxboxdevicesyncstate-list")

    @staticmethod
    def _changes_for(row: ProxboxDeviceSyncState):
        return ObjectChange.objects.filter(
            changed_object_type=ContentType.objects.get_for_model(row),
            changed_object_id=row.pk,
        )

    def test_null_scope_claim_records_locked_snapshot_and_message(self) -> None:
        row = ProxboxDeviceSyncState.objects.create(device=self.device)
        response = self.client.patch(
            self._detail_url(row),
            data={
                "proxmox_endpoint_raw_id": 701,
                "changelog_message": "Claimed after placement verification",
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 200, response.content)
        row.refresh_from_db()
        self.assertEqual(row.proxmox_endpoint_raw_id, 701)
        change = self._changes_for(row).get()
        self.assertEqual(change.action, ObjectChangeActionChoices.ACTION_UPDATE)
        self.assertIsNone(change.prechange_data["proxmox_endpoint_raw_id"])
        self.assertEqual(change.postchange_data["proxmox_endpoint_raw_id"], 701)
        self.assertEqual(change.message, "Claimed after placement verification")

    def test_create_preserves_changelog_message(self) -> None:
        response = self.client.post(
            self._list_url(),
            data={
                "device": {"id": self.device.pk},
                "proxmox_endpoint_raw_id": 701,
                "changelog_message": "Created after placement verification",
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 201, response.content)
        row = ProxboxDeviceSyncState.objects.get(device=self.device)
        change = self._changes_for(row).get()
        self.assertEqual(change.action, ObjectChangeActionChoices.ACTION_CREATE)
        self.assertEqual(change.message, "Created after placement verification")
        self.assertEqual(change.postchange_data["proxmox_endpoint_raw_id"], 701)

    def test_same_scope_can_be_rewritten(self) -> None:
        row = ProxboxDeviceSyncState.objects.create(
            device=self.device,
            proxmox_endpoint_raw_id=701,
        )
        response = self.client.patch(
            self._detail_url(row),
            data={"proxmox_endpoint_raw_id": 701, "proxmox_notes": "refreshed"},
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 200, response.content)
        row.refresh_from_db()
        self.assertEqual(row.proxmox_endpoint_raw_id, 701)
        self.assertEqual(row.proxmox_notes, "refreshed")

    def test_different_scope_returns_stable_ownership_conflict(self) -> None:
        row = ProxboxDeviceSyncState.objects.create(
            device=self.device,
            proxmox_endpoint_raw_id=701,
        )
        response = self.client.patch(
            self._detail_url(row),
            data={
                "proxmox_endpoint_raw_id": 702,
                "changelog_message": "Must not be recorded",
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(
            response.json(),
            {
                "proxmox_endpoint_raw_id": ["endpoint_ownership_conflict"],
                "code": "endpoint_ownership_conflict",
            },
        )
        row.refresh_from_db()
        self.assertEqual(row.proxmox_endpoint_raw_id, 701)
        self.assertFalse(self._changes_for(row).exists())

    def test_create_for_foreign_claim_returns_ownership_conflict(self) -> None:
        ProxboxDeviceSyncState.objects.create(
            device=self.device,
            proxmox_endpoint_raw_id=701,
        )
        response = self.client.post(
            self._list_url(),
            data={
                "device": {"id": self.device.pk},
                "proxmox_endpoint_raw_id": 702,
            },
            content_type="application/json",
            **self.auth_headers,
        )
        self.assertEqual(response.status_code, 409, response.content)
        self.assertEqual(response.json()["code"], "endpoint_ownership_conflict")
        self.assertEqual(
            response.json()["proxmox_endpoint_raw_id"],
            ["endpoint_ownership_conflict"],
        )


class DeviceSyncStateOwnershipConcurrencyTests(TransactionTestCase):
    """Use independent PostgreSQL connections to serialize competing claims."""

    def setUp(self) -> None:
        self.device = _device("ownership-concurrent-device")
        self.row = ProxboxDeviceSyncState.objects.create(device=self.device)

    def _claim(self, raw_id: int, barrier: Barrier) -> tuple[str, int | str, str]:
        close_old_connections()
        try:
            stale = ProxboxDeviceSyncState.objects.get(pk=self.row.pk)
            serializer = ProxboxDeviceSyncStateSerializer(
                stale,
                data={"proxmox_endpoint_raw_id": raw_id},
                partial=True,
            )
            if not serializer.is_valid():
                return "validation_error", str(serializer.errors), ""
            barrier.wait(timeout=10)
            try:
                claimed = serializer.save()
            except EndpointOwnershipConflict as exc:
                return "conflict", exc.status_code, str(exc.detail["code"])
            return "claimed", int(claimed.proxmox_endpoint_raw_id), ""
        finally:
            connections.close_all()

    def test_two_workers_cannot_overwrite_a_committed_claim(self) -> None:
        barrier = Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self._claim, raw_id, barrier) for raw_id in (701, 702)
            ]
            results = [future.result(timeout=30) for future in futures]

        self.assertEqual(
            sorted(result[0] for result in results),
            ["claimed", "conflict"],
        )
        self.assertIn(
            ("conflict", 409, "endpoint_ownership_conflict"),
            results,
        )
        self.row.refresh_from_db()
        self.assertIn(self.row.proxmox_endpoint_raw_id, (701, 702))

    def test_claim_update_keeps_the_row_lock_contract(self) -> None:
        source = inspect.getsource(ProxboxDeviceSyncStateSerializer.update)
        self.assertIn("transaction.atomic()", source)
        self.assertIn("select_for_update()", source)
