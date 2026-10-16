"""Tests for netbox_test_configuration."""

from copy import deepcopy
import os

from netbox.configuration_testing import *  # noqa: F403
from netbox.configuration_testing import PLUGINS as BASE_PLUGINS

PLUGINS = [*BASE_PLUGINS, "netbox_proxbox"]
if os.environ.get("NETBOX_PROXBOX_TEST_OPENBAO") == "1":
    PLUGINS.extend(("netbox_rpc", "netbox_openbao"))
elif os.environ.get("NETBOX_PROXBOX_TEST_ALL_COMPANIONS") == "1":
    PLUGINS.extend(("netbox_ceph", "netbox_pbs", "netbox_pdm", "netbox_packer"))
elif os.environ.get("NETBOX_PROXBOX_TEST_PDM") == "1":
    PLUGINS.append("netbox_pdm")

# Local isolated harnesses may bind their disposable services away from the
# standard ports. CI leaves these unset and retains NetBox's stock test values.
if database_host := os.environ.get("NETBOX_TEST_DB_HOST"):
    DATABASES["default"]["HOST"] = database_host  # noqa: F405
if database_port := os.environ.get("NETBOX_TEST_DB_PORT"):
    DATABASES["default"]["PORT"] = int(database_port)  # noqa: F405
if redis_host := os.environ.get("NETBOX_TEST_REDIS_HOST"):
    for redis_config in REDIS.values():  # noqa: F405
        redis_config["HOST"] = redis_host
if redis_port := os.environ.get("NETBOX_TEST_REDIS_PORT"):
    for redis_config in REDIS.values():  # noqa: F405
        redis_config["PORT"] = int(redis_port)

# Exercise migration data operations through a non-default alias without
# provisioning a second database. Django's test runner mirrors the isolated
# default test database under this alias.
DATABASES["openbao_migration"] = deepcopy(DATABASES["default"])  # noqa: F405
DATABASES["openbao_migration"]["TEST"] = {"MIRROR": "default"}  # noqa: F405

# Keep a distinct connection wrapper for primary/replica routing tests while
# sharing the isolated harness database.
DATABASES["openbao_replica"] = deepcopy(DATABASES["default"])  # noqa: F405
DATABASES["openbao_replica"]["TEST"] = {"MIRROR": "default"}  # noqa: F405

# Register an alias with Django's test allow-list. The routing regression
# replaces this mirror with an independently cloned database before querying it
# and restores the harmless mirror during cleanup.
DATABASES["openbao_secondary"] = deepcopy(DATABASES["default"])  # noqa: F405
DATABASES["openbao_secondary"]["TEST"] = {"MIRROR": "default"}  # noqa: F405
