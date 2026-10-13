"""API-only Proxmox endpoints must never be blocked by SSH credential input."""

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
    pytest.skip(
        "Django/NetBox test dependencies are not installed in this environment.",
        allow_module_level=True,
    )

# The mocked suite installs ``django`` as a plain module; only a real package
# can run these database-backed checks.
if not hasattr(django, "__path__"):
    pytest.skip(
        "The mocked suite does not provide a real Django package.",
        allow_module_level=True,
    )

os.environ.setdefault("NETBOX_CONFIGURATION", "tests.netbox_test_configuration")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")

try:
    django.setup()
except Exception as exc:  # pragma: no cover - depends on external test services
    if _REQUIRE_DJANGO:
        raise
    pytest.skip(
        f"NetBox test environment is not available: {exc}", allow_module_level=True
    )

from cryptography.fernet import Fernet
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from netbox_proxbox.choices import ProxmoxAccessMethodChoices
from netbox_proxbox.forms.proxmox import (
    ProxmoxEndpointForm,
    ProxmoxEndpointSSHCredentialFormMixin,
)
from netbox_proxbox.models import ProxboxPluginSettings, ProxmoxEndpoint
from tests.django_support import make_user
from netbox_proxbox.models.ssh_credential import (
    AUTH_METHOD_KEY,
    SSH_CRED_SOURCE_DEDICATED,
)


def _form_data(**overrides: str) -> dict[str, str]:
    data = {
        "name": "api-only-pve",
        "domain": "pve.example.com",
        "port": "8006",
        "username": "proxbox@pve",
        "password": "endpoint-secret",
        "token_name": "",
        "token_value": "",
        "credential_storage_backend": "legacy_encrypted",
        "verify_ssl": "on",
        "enabled": "on",
        "allow_writes": "",
        "access_methods": ProxmoxAccessMethodChoices.API,
        "environment": "",
        "service_monitoring_interval_minutes": "5",
        "ssh_credential_source": SSH_CRED_SOURCE_DEDICATED,
        "ssh_username": "",
        "ssh_port": "22",
        "ssh_auth_method": AUTH_METHOD_KEY,
        "ssh_known_host_fingerprint": "",
    }
    data.update(overrides)
    return data


class ApiOnlyEndpointIgnoresSshInputTest(TestCase):
    def setUp(self) -> None:
        # Select local encrypted storage explicitly: Automatic storage resolves
        # to OpenBao in the OpenBao matrix profile, which needs provider setup
        # that has nothing to do with these checks.
        settings_obj = ProxboxPluginSettings.get_solo()
        settings_obj.encryption_key = Fernet.generate_key().decode()
        settings_obj.credential_storage_backend = "legacy_encrypted"
        settings_obj.save(
            update_fields=("encryption_key", "credential_storage_backend")
        )

    def _assert_valid(self, **overrides: str) -> ProxmoxEndpointForm:
        form = ProxmoxEndpointForm(data=_form_data(**overrides))
        self.assertTrue(form.is_valid(), form.errors.as_data())
        return form

    def test_junk_ssh_values_do_not_block_an_api_only_endpoint(self):
        self._assert_valid(
            ssh_username="fake",
            ssh_known_host_fingerprint="not-a-fingerprint",
            ssh_port="0",
        )

    def test_blank_and_missing_ssh_fields_do_not_block_an_api_only_endpoint(self):
        data = _form_data()
        for name in ProxmoxEndpointSSHCredentialFormMixin.ssh_credential_field_names:
            data.pop(name, None)
        form = ProxmoxEndpointForm(data=data)
        self.assertTrue(form.is_valid(), form.errors.as_data())

    def test_api_only_save_ignores_submitted_ssh_input(self):
        form = self._assert_valid(
            ssh_username="fake",
            ssh_known_host_fingerprint="not-a-fingerprint",
            ssh_password="ignored-secret",
        )
        endpoint = form.save()
        endpoint.refresh_from_db()
        self.assertEqual(endpoint.ssh_username, "")
        self.assertEqual(endpoint.ssh_known_host_fingerprint, "")
        self.assertEqual(endpoint.ssh_password_enc, "")

    def test_switching_to_api_only_still_honors_clear_ssh_secret_requests(self):
        key = Fernet.generate_key().decode()
        settings_obj = ProxboxPluginSettings.get_solo()
        settings_obj.encryption_key = key
        settings_obj.credential_storage_backend = "legacy_encrypted"
        settings_obj.save(
            update_fields=("encryption_key", "credential_storage_backend")
        )
        endpoint = ProxmoxEndpoint.objects.create(
            name="clear-on-switch",
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API_SSH,
            ssh_username="root",
            ssh_known_host_fingerprint="SHA256:" + "A" * 43,
        )
        endpoint.set_ssh_password("old-ssh-secret", key=key)
        endpoint.set_ssh_private_key("old-key-material", key=key)
        endpoint.save()
        endpoint.refresh_from_db()
        self.assertTrue(endpoint.ssh_password_enc)
        self.assertTrue(endpoint.ssh_private_key_enc)

        form = ProxmoxEndpointForm(
            data=_form_data(
                clear_ssh_password="on",
                clear_ssh_private_key="on",
            ),
            instance=endpoint,
        )
        self.assertTrue(form.is_valid(), form.errors.as_data())
        form.save()
        endpoint.refresh_from_db()
        self.assertEqual(endpoint.ssh_password_enc, "")
        self.assertEqual(endpoint.ssh_private_key_enc, "")
        # Only the explicit clears were applied; other SSH settings are kept.
        self.assertEqual(endpoint.ssh_username, "root")

    def test_ssh_validation_still_applies_to_api_plus_ssh(self):
        form = ProxmoxEndpointForm(
            data=_form_data(
                access_methods=ProxmoxAccessMethodChoices.API_SSH,
                ssh_username="fake",
            )
        )
        self.assertFalse(form.is_valid())
        self.assertIn("ssh_known_host_fingerprint", form.errors)

    def test_model_clean_ignores_partial_ssh_data_for_api_only(self):
        endpoint = ProxmoxEndpoint(
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API,
            ssh_username="fake",
        )
        endpoint.clean()

    def test_model_clean_ignores_a_placeholder_fingerprint_for_api_only(self):
        endpoint = ProxmoxEndpoint(
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API,
            ssh_known_host_fingerprint="not-a-fingerprint",
        )
        endpoint.clean()
        self.assertEqual(endpoint.ssh_known_host_fingerprint, "not-a-fingerprint")

    def test_model_clean_rejects_a_placeholder_fingerprint_for_api_plus_ssh(self):
        endpoint = ProxmoxEndpoint(
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API_SSH,
            ssh_known_host_fingerprint="not-a-fingerprint",
        )
        with self.assertRaises(ValidationError):
            endpoint.clean()

    def test_editing_an_api_only_endpoint_with_a_stored_placeholder_succeeds(self):
        endpoint = ProxmoxEndpoint.objects.create(
            name="stored-placeholder",
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API,
        )
        ProxmoxEndpoint.objects.filter(pk=endpoint.pk).update(
            ssh_username="fake", ssh_known_host_fingerprint="not-a-fingerprint"
        )
        endpoint.refresh_from_db()
        endpoint.full_clean(exclude=["ip_address"])

    def test_model_clean_still_validates_partial_ssh_data_for_api_plus_ssh(self):
        endpoint = ProxmoxEndpoint(
            domain="pve.example.com",
            username="proxbox@pve",
            access_methods=ProxmoxAccessMethodChoices.API_SSH,
            ssh_username="fake",
        )
        with self.assertRaises(ValidationError) as caught:
            endpoint.clean()
        self.assertIn("ssh_known_host_fingerprint", caught.exception.message_dict)


class EndpointEditPageDisclosureTest(TestCase):
    def test_add_page_renders_the_sections_and_the_disclosure_script(self):
        user = make_user("endpoint-form-admin", password="pw", is_superuser=True)
        self.client.force_login(user)
        response = self.client.get(
            reverse("plugins:netbox_proxbox:proxmoxendpoint_add")
        )
        self.assertEqual(response.status_code, 200)
        html = response.content.decode()
        for fragment in (
            "Connection and credentials (read-only API access)",
            "Write access (opt-in)",
            "SSH credential access (API + SSH only)",
            "netbox_proxbox/js/proxmox-endpoint-form.js",
            'id="id_access_methods"',
            'id="id_allow_writes"',
            'id="id_ssh_credential_source"',
            'id="id_allow_packer_template_builds"',
            'id="id_service_monitoring_enabled"',
        ):
            self.assertIn(fragment, html)
