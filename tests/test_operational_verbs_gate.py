"""Tests for the operational-verbs permission compatibility contract.

Pins the two halves of the gate contract:

1. ``ProxmoxEndpoint.allow_writes`` exists, defaults to ``False``.
2. The deprecated ``core.run_proxmox_action`` permission row remains present
   for compatibility.
3. New grants use the endpoint-scoped ``run_proxmox_action`` action.

The literal permission string remains accepted additively, but ordinary NetBox
ObjectPermissions cannot produce it and must use the endpoint action instead.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
NETBOX_ROOT = REPO_ROOT.parent / "netbox" / "netbox"

for candidate in (REPO_ROOT, NETBOX_ROOT):
    candidate_str = str(candidate)
    if candidate.exists() and candidate_str not in sys.path:
        sys.path.insert(0, candidate_str)

try:
    import django
except ModuleNotFoundError:
    pytest.skip(
        "Django/NetBox test dependencies are not installed in this environment.",
        allow_module_level=True,
    )

os.environ.setdefault("NETBOX_CONFIGURATION", "tests.netbox_test_configuration")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")

try:
    django.setup()
except Exception as exc:  # pragma: no cover - depends on external test services
    pytest.skip(
        f"NetBox test environment is not available: {exc}", allow_module_level=True
    )

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from netbox_proxbox.models import ProxmoxEndpoint
from netbox_proxbox.views.proxbox_access import (
    PROXMOX_ACTION_PERMISSION,
    permission_run_endpoint_action,
    permission_run_proxmox_action,
    user_can_run_endpoint_action,
)


class ProxmoxActionPermissionContractTest(TestCase):
    """The literal ``core.run_proxmox_action`` string must round-trip through Django."""

    def test_permission_string_helper(self):
        self.assertEqual(PROXMOX_ACTION_PERMISSION, "core.run_proxmox_action")
        self.assertEqual(permission_run_proxmox_action(), "core.run_proxmox_action")
        self.assertEqual(
            permission_run_endpoint_action(),
            "netbox_proxbox.run_proxmox_action_proxmoxendpoint",
        )

    def test_legacy_permission_migration_remains(self):
        migration_source = (
            REPO_ROOT / "netbox_proxbox/migrations/_v0_0_15_release_data.py"
        ).read_text(encoding="utf-8")
        self.assertIn('PERM_CODENAME = "run_proxmox_action"', migration_source)
        self.assertIn('PERM_CT_APP_LABEL = "core"', migration_source)
        self.assertIn('PERM_CT_MODEL = "objecttype"', migration_source)

    def test_legacy_permission_row_exists(self):
        content_type = ContentType.objects.get(app_label="core", model="objecttype")
        self.assertTrue(
            Permission.objects.filter(
                content_type=content_type,
                codename="run_proxmox_action",
            ).exists()
        )

    def test_legacy_permission_result_remains_additively_accepted(self):
        endpoint = ProxmoxEndpoint.objects.create(name="legacy-compatible")

        class LegacyBackendActor:
            @staticmethod
            def has_perm(permission: str) -> bool:
                return permission == "core.run_proxmox_action"

        self.assertTrue(user_can_run_endpoint_action(LegacyBackendActor(), endpoint.pk))


class ProxmoxEndpointAllowWritesTest(TestCase):
    """``ProxmoxEndpoint.allow_writes`` defaults to False (write gate closed)."""

    def test_default_is_false(self):
        endpoint = ProxmoxEndpoint.objects.create(name="lab-cluster")
        self.assertFalse(endpoint.allow_writes)

    def test_field_persists(self):
        endpoint = ProxmoxEndpoint.objects.create(
            name="prod-cluster", allow_writes=True
        )
        endpoint.refresh_from_db()
        self.assertTrue(endpoint.allow_writes)
