"""Real-Django tests: device sync-state identity filters used by proxbox-api."""

from __future__ import annotations

import os
from pathlib import Path
import sys

import pytest

from tests.netbox_test_paths import netbox_source_roots


REPO_ROOT = Path(__file__).resolve().parents[1]
NETBOX_ROOTS = netbox_source_roots(REPO_ROOT)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

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

# The mocked suite deliberately installs ``django`` as a plain module. Do not
# add the real NetBox source tree to sys.path in that process: doing so would
# make other harness-detection tests see a half-real, half-stub environment.
if not hasattr(django, "__path__"):
    pytest.skip(
        "The mocked suite does not provide a real Django package.",
        allow_module_level=True,
    )

for candidate_path in NETBOX_ROOTS:
    candidate_string = str(candidate_path)
    if candidate_path.exists() and candidate_string not in sys.path:
        sys.path.insert(0, candidate_string)

os.environ.setdefault("NETBOX_CONFIGURATION", "tests.netbox_test_configuration")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "netbox.settings")

try:
    django.setup()
except Exception as exc:  # pragma: no cover - external test harness availability
    if _REQUIRE_DJANGO:
        raise
    pytest.skip(
        f"NetBox test environment is not available: {exc}",
        allow_module_level=True,
    )

from dcim.models import Device, DeviceRole, DeviceType, Manufacturer, Site  # noqa: E402
from django.http import QueryDict  # noqa: E402
from django.test import TestCase  # noqa: E402

from netbox_proxbox.filtersets import ProxboxDeviceSyncStateFilterSet  # noqa: E402
from netbox_proxbox.models import ProxboxDeviceSyncState  # noqa: E402


class DeviceSyncStateIdentityFilterTests(TestCase):
    """proxbox-api resolves a node's device by exact node and cluster name."""

    @classmethod
    def setUpTestData(cls) -> None:
        site = Site.objects.create(name="filter-site", slug="filter-site")
        manufacturer = Manufacturer.objects.create(name="filter-m", slug="filter-m")
        device_type = DeviceType.objects.create(
            manufacturer=manufacturer, model="filter-t", slug="filter-t"
        )
        role = DeviceRole.objects.create(name="filter-r", slug="filter-r")
        for device_name, cluster, node, endpoint_raw_id in (
            ("scoped-current", "e2e-cluster", "pve01", 101),
            ("scoped-other", "e2e-cluster", "pve01", 202),
            ("operator-renamed-pve01", "e2e-cluster", "pve01", None),
            ("e2e-cluster-pve02", "e2e-cluster", "pve02", 102),
        ):
            device = Device.objects.create(
                name=device_name,
                site=site,
                device_type=device_type,
                role=role,
            )
            ProxboxDeviceSyncState.objects.create(
                device=device,
                proxmox_node_name=node,
                proxmox_cluster_name=cluster,
                proxmox_endpoint_raw_id=endpoint_raw_id,
            )

    def _filter(self, **params: object) -> list[str]:
        # Mirror an HTTP query string, as NetBox multi-value filters expect.
        query = QueryDict(mutable=True)
        for key, value in params.items():
            query[key] = str(value)
        filterset = ProxboxDeviceSyncStateFilterSet(
            query, queryset=ProxboxDeviceSyncState.objects.all()
        )
        self.assertTrue(filterset.is_valid(), filterset.errors)
        return sorted(row.device.name for row in filterset.qs)

    def test_node_and_cluster_name_select_all_correlated_candidates(self) -> None:
        self.assertEqual(
            self._filter(proxmox_node_name="pve01", proxmox_cluster_name="e2e-cluster"),
            ["operator-renamed-pve01", "scoped-current", "scoped-other"],
        )

    def test_names_match_exactly_not_by_substring(self) -> None:
        self.assertEqual(self._filter(proxmox_node_name="pve0"), [])
        self.assertEqual(
            self._filter(proxmox_cluster_name="e2e-cluster"),
            [
                "e2e-cluster-pve02",
                "operator-renamed-pve01",
                "scoped-current",
                "scoped-other",
            ],
        )

    def test_endpoint_raw_id_includes_exact_and_unclaimed_but_excludes_other(
        self,
    ) -> None:
        self.assertEqual(
            self._filter(
                proxmox_node_name="pve01",
                proxmox_cluster_name="e2e-cluster",
                proxmox_endpoint_raw_id=101,
            ),
            ["operator-renamed-pve01", "scoped-current"],
        )

    def test_renamed_legacy_device_remains_discoverable_with_endpoint_scope(
        self,
    ) -> None:
        self.assertEqual(
            self._filter(
                proxmox_node_name="pve01",
                proxmox_cluster_name="e2e-cluster",
                proxmox_endpoint_raw_id=303,
            ),
            ["operator-renamed-pve01"],
        )

    def test_omitted_endpoint_raw_id_keeps_all_scoped_and_legacy_rows(self) -> None:
        self.assertEqual(
            self._filter(proxmox_cluster_name="e2e-cluster"),
            [
                "e2e-cluster-pve02",
                "operator-renamed-pve01",
                "scoped-current",
                "scoped-other",
            ],
        )
