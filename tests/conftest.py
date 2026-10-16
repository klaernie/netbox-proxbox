"""Tests for conftest."""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.django_stubs import django_stub_modules
from tests.choices_stubs import attach_credential_storage_backend_choices
from tests.operational_security_support import endpoint_authorizer


class HttpResponse:
    def __init__(self, status: int = 200, content: str | None = None):
        self.status_code = status
        self.content = content
        self._headers = {}

    def __setitem__(self, key, value):
        self._headers[key] = value

    def __getitem__(self, key):
        return self._headers[key]


class HttpResponseRedirect(HttpResponse):
    def __init__(self, redirect_to: str, status: int = 302):
        super().__init__(status=status)
        self.url = redirect_to
        self["Location"] = redirect_to


class JsonResponse(HttpResponse):
    def __init__(self, payload=None, status: int = 200, safe: bool = True):
        super().__init__(status=status, content=payload)
        self.payload = payload
        self.safe = safe

    def json(self):
        return self.payload


class StreamingHttpResponse(HttpResponse):
    def __init__(
        self, streaming_content=None, status: int = 200, content_type: str | None = None
    ):
        super().__init__(status=status)
        self.streaming_content = streaming_content
        self.content_type = content_type


class HttpRequest:
    pass


class Http404(Exception):
    pass


class View:
    """Minimal Django CBV stub for plugin view tests."""

    http_method_names = [
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "trace",
    ]

    @classmethod
    def as_view(cls, **initkwargs):
        def view(request, *args, **kwargs):
            self = cls(**initkwargs)
            self.request = request
            self.args = args
            self.kwargs = kwargs
            return self.dispatch(request, *args, **kwargs)

        view.view_class = cls
        view.view_initkwargs = initkwargs
        return view

    def dispatch(self, request, *args, **kwargs):
        if request is None:
            request = SimpleNamespace(
                method="GET",
                user=SimpleNamespace(
                    is_authenticated=True,
                    has_perms=lambda *a, **k: True,
                    has_perm=lambda *a, **k: True,
                ),
            )
        method = (getattr(request, "method", "GET") or "GET").lower()
        if method in self.http_method_names:
            handler = getattr(self, method, self.http_method_not_allowed)
            return handler(request, *args, **kwargs)
        return self.http_method_not_allowed(request, *args, **kwargs)

    def http_method_not_allowed(self, request, *args, **kwargs):
        return HttpResponse(status=405)


class DummyPluginConfig:
    pass


class MessagesStub:
    def __init__(self):
        self.calls = []

    def success(self, request, message):
        self.calls.append(("success", message))

    def warning(self, request, message):
        self.calls.append(("warning", message))

    def error(self, request, message):
        self.calls.append(("error", message))


@dataclass
class ResponseStub:
    payload: object
    status_code: int = 200
    ok: bool = True
    error: Exception | None = None

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.error:
            raise self.error
        if not self.ok or self.status_code >= 400:
            raise RuntimeError(f"http {self.status_code}")


def _manager(*, first=None, objects_by_pk=None, does_not_exist=None):
    objects_by_pk = objects_by_pk or {}

    class Manager:
        def restrict(self, user, action):
            return self

        def first(self):
            return first

        def exists(self):
            return first is not None or bool(objects_by_pk)

        def filter(self, *args, **kwargs):
            return self

        def values_list(self, field_name, flat=False):
            values = []
            if objects_by_pk:
                values = [
                    getattr(obj, field_name, pk) for pk, obj in objects_by_pk.items()
                ]
            elif first is not None:
                values = [getattr(first, field_name, getattr(first, "pk", None))]
            if flat:
                return values
            return [(value,) for value in values]

        def count(self):
            return 0

        def aggregate(self, **kwargs):
            return {k: 0 for k in kwargs}

        def order_by(self, *args, **kwargs):
            return self

        def iterator(self, chunk_size=64):
            return iter(self)

        def get(self, *args, **kwargs):
            pk = kwargs.get("pk")
            if pk is None and args:
                pk = args[0]
            if pk in objects_by_pk:
                return objects_by_pk[pk]
            raise does_not_exist()

        def __iter__(self):
            if objects_by_pk:
                return iter(objects_by_pk.values())
            if first is not None:
                return iter([first])
            return iter([])

    return Manager()


def _make_model_class(name: str, *, first=None, objects_by_pk=None):
    does_not_exist = type("DoesNotExist", (Exception,), {})
    cls = type(name, (), {"DoesNotExist": does_not_exist})
    _mn = {
        "FastAPIEndpoint": "fastapiendpoint",
        "NetBoxEndpoint": "netboxendpoint",
        "ProxmoxEndpoint": "proxmoxendpoint",
    }.get(name, name.lower())
    cls._meta = SimpleNamespace(app_label="netbox_proxbox", model_name=_mn)
    cls.objects = _manager(
        first=first,
        objects_by_pk=objects_by_pk,
        does_not_exist=does_not_exist,
    )
    return cls


def _stub_get_object_or_404(klass, *args, **kwargs):
    try:
        if hasattr(klass, "get"):
            return klass.get(*args, **kwargs)
    except Exception as exc:
        if type(exc).__name__ == "DoesNotExist":
            raise Http404 from exc
        raise
    raise Http404()


def _stub_backend_auth_headers(obj):
    token = (getattr(obj, "token", "") or "").strip()
    if not token:
        return {}
    if token.startswith(("Bearer ", "Token ")):
        return {"Authorization": token}
    return {"Authorization": f"Bearer {token}"}


def _default_fastapi_url(_obj):
    return {
        "http_url": "https://proxbox.local:8800",
        "ip_address_url": "https://10.0.0.5:8800",
        "verify_ssl": True,
        "websocket_url": "wss://proxbox.local:8801/ws",
    }


def _stub_ip_address_host(value):
    return str(value).split("/")[0] if value else "127.0.0.1"


def _resolve_vm_type_stub(vm: object) -> str:
    sync_state = getattr(vm, "proxbox_sync_state", None)
    typed_type = str(getattr(sync_state, "proxmox_vm_type", "") or "").lower()
    if typed_type in {"lxc", "qemu"}:
        return typed_type
    vm_type_obj = getattr(vm, "virtual_machine_type", None)
    if vm_type_obj and hasattr(vm_type_obj, "slug"):
        slug = str(vm_type_obj.slug)
        if "lxc" in slug:
            return "lxc"
        if "qemu" in slug:
            return "qemu"
    return "qemu"


def _build_model_stub_modules(
    *,
    fastapi_endpoint,
    netbox_endpoint,
    proxmox_endpoint,
    proxbox_settings,
):
    models_module = types.ModuleType("netbox_proxbox.models")
    endpoint_rows = (
        ("FastAPIEndpoint", fastapi_endpoint),
        ("NetBoxEndpoint", netbox_endpoint),
        ("ProxmoxEndpoint", proxmox_endpoint),
    )
    for name, endpoint in endpoint_rows:
        models_module.__dict__[name] = _make_model_class(
            name,
            first=endpoint,
            objects_by_pk={1: endpoint} if endpoint is not None else {},
        )

    for name in (
        "ProxmoxCluster",
        "ProxmoxNode",
        "ProxmoxStorage",
        "ProxmoxStorageVirtualDisk",
        "BackupRoutine",
        "Replication",
        "VMBackup",
        "VMSnapshot",
        "VMTaskHistory",
    ):
        models_module.__dict__[name] = _make_model_class(name)

    settings = proxbox_settings
    if settings is None:
        settings = SimpleNamespace(
            backend_log_file_path="/var/log/proxbox.log",
            primary_ip_preference="ipv4",
            encryption_key="",
            save=lambda **kwargs: None,
        )

    class _ProxboxPluginSettings:
        @classmethod
        def get_solo(cls):
            return settings

    _ProxboxPluginSettings._meta = SimpleNamespace(
        app_label="netbox_proxbox",
        model_name="proxboxpluginsettings",
    )
    models_module.ProxboxPluginSettings = _ProxboxPluginSettings

    virtualization_module = types.ModuleType("virtualization")
    virtualization_models_module = types.ModuleType("virtualization.models")
    virtualization_models_module.Cluster = _make_model_class("Cluster")
    virtualization_models_module.VirtualMachine = _make_model_class("VirtualMachine")
    virtualization_module.models = virtualization_models_module
    return models_module, virtualization_module, virtualization_models_module


def _build_utils_stub_module(get_fastapi_url):
    utils_module = types.ModuleType("netbox_proxbox.utils")
    utils_module.get_fastapi_url = get_fastapi_url or _default_fastapi_url
    utils_module.get_backend_auth_headers = _stub_backend_auth_headers
    utils_module.get_ip_address_host = _stub_ip_address_host
    utils_module.resolve_vm_type = _resolve_vm_type_stub
    return utils_module


def _stub_http_timeout_for_sync_path(path):
    if "virtualization/virtual-machines" in path or "full-update" in path:
        return (5, 3600)
    return 5


class _StubNoReverseMatch(Exception):
    pass


class _StubQ:
    def __init__(self, *args, **kwargs):
        pass

    def __or__(self, other):
        return self


class _StubCount:
    def __init__(self, *args, **kwargs):
        pass


class _StubJobRunner:
    pass


class _StubAccessMixin:
    def handle_no_permission(self):
        return HttpResponse(status=403)


class _StubLoginRequiredMixin:
    pass


class _StubConditionalLoginRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class _StubTokenConditionalLoginRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class _StubContentTypePermissionRequiredMixin:
    additional_permissions = []

    def get_required_permission(self):
        return "stub.view_stub"

    def has_permission(self):
        return True

    def dispatch(self, request, *args, **kwargs):
        if not self.has_permission():
            return HttpResponse(status=403)
        return super().dispatch(request, *args, **kwargs)


def _stub_register_model_view(*args, **kwargs):
    def decorator(view_cls):
        return view_cls

    return decorator


def _stub_get_viewname(model, action=None, rest_api=False):
    meta = getattr(model, "_meta", None)
    app_label = getattr(meta, "app_label", "netbox_proxbox")
    model_name = getattr(meta, "model_name", "stub")
    viewname = f"{app_label}:{model_name}"
    if app_label == "netbox_proxbox":
        viewname = f"plugins:{viewname}"
    if action:
        viewname = f"{viewname}_{action}"
    return viewname


class _StubQueue:
    def fetch_job(self, jid):
        return None


class _StubInvalidJobOperation(Exception):
    pass


class _StubJob:
    pass


class _StubJobStatus:
    QUEUED = "queued"
    DEFERRED = "deferred"
    SCHEDULED = "scheduled"
    STARTED = "started"


class _StubTable:
    def __init__(self, queryset=None, *args, **kwargs):
        self.queryset = queryset

    def configure(self, request):
        pass


class _StubChoiceSet:
    pass


class _StubSyncTypeChoices(_StubChoiceSet):
    BACKUP_ROUTINES = "backup-routines"
    REPLICATIONS = "replications"
    TASK_HISTORY = "task-history"
    VIRTUAL_MACHINES = "virtual-machines"
    STORAGE = "storage"
    VIRTUAL_MACHINES_DISKS = "vm-disks"
    VIRTUAL_MACHINES_BACKUPS = "vm-backups"
    VIRTUAL_MACHINES_SNAPSHOTS = "vm-snapshots"
    DEVICES = "devices"
    NETWORK_INTERFACES = "network-interfaces"
    VM_INTERFACES = "vm-interfaces"
    IP_ADDRESSES = "ip-addresses"
    SDN = "sdn"
    ALL = "all"


class _StubProxmoxModeChoices(_StubChoiceSet):
    PROXMOX_MODE_UNDEFINED = "undefined"
    PROXMOX_MODE_STANDALONE = "standalone"
    PROXMOX_MODE_CLUSTER = "cluster"


class _StubProxboxSyncJob:
    @classmethod
    def enqueue(cls, **kwargs):
        raise RuntimeError("ProxboxSyncJob.enqueue must be patched in tests")


class _StubScheduleSyncForm:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def load_plugin_module(
    module_name: str,
    *,
    monkeypatch,
    fastapi_endpoint=None,
    netbox_endpoint=None,
    proxmox_endpoint=None,
    proxbox_settings=None,
    get_fastapi_url=None,
):
    django_module = types.ModuleType("django")
    django_http = types.ModuleType("django.http")
    django_http.HttpRequest = HttpRequest
    django_http.HttpResponse = HttpResponse
    django_http.HttpResponseRedirect = HttpResponseRedirect
    django_http.JsonResponse = JsonResponse
    django_http.StreamingHttpResponse = StreamingHttpResponse
    django_http.Http404 = Http404

    django_shortcuts = types.ModuleType("django.shortcuts")
    django_shortcuts.render = lambda request, template_name, context=None: {
        "template": template_name,
        "context": context or {},
    }
    django_shortcuts.redirect = lambda name: {"redirect": name}

    django_shortcuts.get_object_or_404 = _stub_get_object_or_404

    django_views = types.ModuleType("django.views")
    django_views.View = View

    django_views_decorators = types.ModuleType("django.views.decorators")
    django_views_debug = types.ModuleType("django.views.decorators.debug")
    django_views_debug.sensitive_post_parameters = lambda *_params: lambda func: func
    django_views_debug.sensitive_variables = lambda *_params: lambda func: func
    django_views_http = types.ModuleType("django.views.decorators.http")
    django_views_http.require_GET = lambda func: func
    django_views_http.require_http_methods = lambda methods: lambda func: func

    django_urls = types.ModuleType("django.urls")
    django_urls.reverse = lambda *args, **kwargs: "/dummy/"

    django_urls.NoReverseMatch = _StubNoReverseMatch

    django_contrib = types.ModuleType("django.contrib")
    django_messages = MessagesStub()
    django_contrib.messages = django_messages

    django_utils = types.ModuleType("django.utils")
    django_utils_decorators = types.ModuleType("django.utils.decorators")
    django_utils_decorators.method_decorator = lambda _decorator, **_kwargs: (
        lambda value: value
    )
    django_utils_html = types.ModuleType("django.utils.html")

    def _format_html(*args, **kwargs):
        return "".join(str(a) for a in args)

    django_utils_html.format_html = _format_html

    django_utils_text = types.ModuleType("django.utils.text")
    django_utils_text.format_lazy = lambda *parts: "".join(str(p) for p in parts)

    django_utils_translation = types.ModuleType("django.utils.translation")
    django_utils_translation.gettext = lambda x: x
    django_utils_translation.gettext_lazy = lambda x: x

    django_utils_safestring = types.ModuleType("django.utils.safestring")
    django_utils_safestring.mark_safe = lambda value: value

    django_utils_timezone = types.ModuleType("django.utils.timezone")
    django_utils_timezone.now = lambda: __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    )
    django_utils.timezone = django_utils_timezone

    django_db_models = types.ModuleType("django.db.models")

    django_db_models.Q = _StubQ
    django_db_models.Count = _StubCount

    # `django.db` itself, not just `django.db.models`.  Registering only the
    # submodule is enough for `from django.db.models import Q` (the full dotted
    # name is already in sys.modules, so the parent is never imported), but
    # `from django.db import DatabaseError` resolves the *parent* package and
    # dies with ModuleNotFoundError because the `django` stub has no __path__.
    # Shared with the other five stub loaders — see `tests/django_stubs.py`.
    _django_stubs = django_stub_modules(models_module=django_db_models)
    django_db = _django_stubs["django.db"]
    django_utils_crypto = _django_stubs["django.utils.crypto"]

    utilities_datetime = types.ModuleType("utilities.datetime")
    utilities_datetime.local_now = lambda: __import__("datetime").datetime(
        2026, 1, 1, 1, 0, 0, tzinfo=__import__("datetime").timezone.utc
    )

    netbox_constants = types.ModuleType("netbox.constants")
    netbox_constants.RQ_QUEUE_DEFAULT = "default"

    netbox_jobs = types.ModuleType("netbox.jobs")

    netbox_jobs.JobRunner = _StubJobRunner

    django_auth = types.ModuleType("django.contrib.auth")
    django_auth_decorators = types.ModuleType("django.contrib.auth.decorators")
    django_auth_decorators.login_required = lambda func: func
    django_auth_mixins = types.ModuleType("django.contrib.auth.mixins")

    django_auth_mixins.AccessMixin = _StubAccessMixin
    django_auth_mixins.LoginRequiredMixin = _StubLoginRequiredMixin
    django_contrib.auth = django_auth

    utilities_permissions = types.ModuleType("utilities.permissions")
    utilities_permissions.get_permission_for_model = lambda model, action: (
        f"{getattr(model._meta, 'app_label', 'stub')}.{action}_"
        f"{getattr(model._meta, 'model_name', 'stub')}"
    )

    utilities_views = types.ModuleType("utilities.views")

    utilities_views.get_viewname = _stub_get_viewname
    utilities_views.ConditionalLoginRequiredMixin = _StubConditionalLoginRequiredMixin
    utilities_views.TokenConditionalLoginRequiredMixin = (
        _StubTokenConditionalLoginRequiredMixin
    )
    utilities_views.ContentTypePermissionRequiredMixin = (
        _StubContentTypePermissionRequiredMixin
    )
    utilities_views.register_model_view = _stub_register_model_view

    netbox_module = types.ModuleType("netbox")
    netbox_plugins = types.ModuleType("netbox.plugins")
    netbox_plugins.PluginConfig = DummyPluginConfig

    (
        models_module,
        virtualization_module,
        virtualization_models_module,
    ) = _build_model_stub_modules(
        fastapi_endpoint=fastapi_endpoint,
        netbox_endpoint=netbox_endpoint,
        proxmox_endpoint=proxmox_endpoint,
        proxbox_settings=proxbox_settings,
    )
    core_module = types.ModuleType("core")
    core_choices = types.ModuleType("core.choices")
    core_choices.JobStatusChoices = SimpleNamespace(
        ENQUEUED_STATE_CHOICES=("pending", "scheduled", "running"),
        TERMINAL_STATE_CHOICES=("completed", "errored", "failed"),
        STATUS_PENDING="pending",
        STATUS_SCHEDULED="scheduled",
        STATUS_RUNNING="running",
        STATUS_COMPLETED="completed",
        STATUS_ERRORED="errored",
        STATUS_FAILED="failed",
        STATUS_CANCELED="canceled",
    )
    core_models = types.ModuleType("core.models")
    core_models.Job = _make_model_class("Job")
    core_utils = types.ModuleType("core.utils")
    core_utils.stop_rq_job = lambda job_id: []
    core_module.choices = core_choices
    core_module.models = core_models
    utils_module = _build_utils_stub_module(get_fastapi_url)

    backend_auth_module = types.ModuleType("netbox_proxbox.services.backend_auth")
    backend_auth_module.ensure_backend_key_registered = lambda *args, **kwargs: (
        True,
        "stubbed",
    )
    backend_auth_module.http_timeout_for_sync_path = _stub_http_timeout_for_sync_path
    backend_auth_module.wait_for_backend_ready = lambda *args, **kwargs: (
        True,
        "stubbed",
    )

    stub_modules = {
        "django": django_module,
        "django.http": django_http,
        "django.shortcuts": django_shortcuts,
        "django.views": django_views,
        "django.views.decorators": django_views_decorators,
        "django.views.decorators.debug": django_views_debug,
        "django.views.decorators.http": django_views_http,
        "django.urls": django_urls,
        "django.utils": django_utils,
        "django.utils.decorators": django_utils_decorators,
        "django.utils.html": django_utils_html,
        "django.utils.text": django_utils_text,
        "django.utils.timezone": django_utils_timezone,
        "django.utils.translation": django_utils_translation,
        "django.utils.safestring": django_utils_safestring,
        "django.utils.crypto": django_utils_crypto,
        "django.db": django_db,
        "django.db.models": django_db_models,
        "utilities.datetime": utilities_datetime,
        "netbox.constants": netbox_constants,
        "netbox.jobs": netbox_jobs,
        "django.contrib": django_contrib,
        "django.contrib.auth": django_auth,
        "django.contrib.auth.decorators": django_auth_decorators,
        "django.contrib.auth.mixins": django_auth_mixins,
        "django.contrib.messages": django_messages,
        "core": core_module,
        "core.choices": core_choices,
        "core.models": core_models,
        "core.utils": core_utils,
        "netbox": netbox_module,
        "netbox.plugins": netbox_plugins,
        "netbox_proxbox.models": models_module,
        "virtualization": virtualization_module,
        "virtualization.models": virtualization_models_module,
        "netbox_proxbox.utils": utils_module,
        "netbox_proxbox.services.backend_auth": backend_auth_module,
        "utilities.permissions": utilities_permissions,
        "utilities.views": utilities_views,
    }

    django_rq_mod = types.ModuleType("django_rq")

    django_rq_mod.get_queue = lambda queue_name: _StubQueue()
    stub_modules["django_rq"] = django_rq_mod

    rq_root = types.ModuleType("rq")
    rq_exceptions = types.ModuleType("rq.exceptions")

    rq_exceptions.InvalidJobOperation = _StubInvalidJobOperation

    rq_job_mod = types.ModuleType("rq.job")

    rq_job_mod.Job = _StubJob
    rq_job_mod.JobStatus = _StubJobStatus

    stub_modules["rq"] = rq_root
    stub_modules["rq.exceptions"] = rq_exceptions
    stub_modules["rq.job"] = rq_job_mod

    # Stub netbox_proxbox.tables so home_context.py can import table classes
    # without django_tables2 being installed in the test environment.
    _tables_stub = types.ModuleType("netbox_proxbox.tables")
    _tables_stub.ProxmoxEndpointTable = _StubTable
    _tables_stub.NetBoxEndpointTable = _StubTable
    _tables_stub.FastAPIEndpointTable = _StubTable
    stub_modules["netbox_proxbox.tables"] = _tables_stub

    for name, module in stub_modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    repo = Path(__file__).resolve().parents[1]

    utilities_root = types.ModuleType("utilities")
    monkeypatch.setitem(sys.modules, "utilities", utilities_root)
    utilities_choices_mod = types.ModuleType("utilities.choices")

    utilities_choices_mod.ChoiceSet = _StubChoiceSet
    monkeypatch.setitem(sys.modules, "utilities.choices", utilities_choices_mod)

    nbp_root = types.ModuleType("netbox_proxbox")
    nbp_root.__path__ = [str(repo / "netbox_proxbox")]
    nbp_root.ProxboxConfig = SimpleNamespace(default_settings={})
    monkeypatch.setitem(sys.modules, "netbox_proxbox", nbp_root)

    nbp_choices = types.ModuleType("netbox_proxbox.choices")

    nbp_choices.ProxmoxModeChoices = _StubProxmoxModeChoices
    nbp_choices.SyncTypeChoices = _StubSyncTypeChoices
    attach_credential_storage_backend_choices(nbp_choices)
    nbp_choices.NetBoxTokenVersionChoices = SimpleNamespace(V1="v1", V2="v2")
    nbp_choices.ReplicationStatusChoices = SimpleNamespace(
        ACTIVE="active", STALE="stale"
    )
    nbp_choices.ProxmoxVMTypeChoices = SimpleNamespace(QEMU="qemu", LXC="lxc")
    monkeypatch.setitem(sys.modules, "netbox_proxbox.choices", nbp_choices)

    nbp_jobs = types.ModuleType("netbox_proxbox.jobs")

    nbp_jobs.ProxboxSyncJob = _StubProxboxSyncJob
    nbp_jobs.PROXBOX_SYNC_QUEUE_NAME = "default"
    nbp_jobs.is_proxbox_sync_job = lambda job: True
    nbp_jobs.proxbox_sync_params_from_job = lambda job: {"sync_types": ["all"]}
    monkeypatch.setitem(sys.modules, "netbox_proxbox.jobs", nbp_jobs)

    forms_package = types.ModuleType("netbox_proxbox.forms")
    forms_package.__path__ = [str(repo / "netbox_proxbox" / "forms")]
    monkeypatch.setitem(sys.modules, "netbox_proxbox.forms", forms_package)

    schedule_sync_stub = types.ModuleType("netbox_proxbox.forms.schedule_sync")

    schedule_sync_stub.ScheduleSyncForm = _StubScheduleSyncForm
    monkeypatch.setitem(
        sys.modules, "netbox_proxbox.forms.schedule_sync", schedule_sync_stub
    )

    schedule_hints_stub = types.ModuleType("netbox_proxbox.schedule_hints")
    schedule_hints_stub.has_recurring_proxbox_sync_all = lambda user: True
    schedule_hints_stub.quick_schedule_home_form_kwargs = lambda: {}
    monkeypatch.setitem(
        sys.modules, "netbox_proxbox.schedule_hints", schedule_hints_stub
    )

    package_name = "netbox_proxbox.views"
    package_module = types.ModuleType(package_name)
    package_module.__path__ = [str(repo / "netbox_proxbox" / "views")]
    monkeypatch.setitem(sys.modules, package_name, package_module)

    proxbox_access = types.ModuleType("netbox_proxbox.views.proxbox_access")
    proxbox_access.permission_enqueue_proxbox_sync = lambda: "stub.enqueue_proxbox_sync"
    proxbox_access.permission_change_proxbox_plugin_settings = lambda: (
        "stub.change_proxboxpluginsettings"
    )
    proxbox_access.permission_reset_encrypted_secrets = lambda: (
        "stub.reset_encrypted_secrets_proxboxpluginsettings"
    )
    proxbox_access.permission_run_proxmox_action = lambda: "core.run_proxmox_action"
    proxbox_access.EndpointOperationalPermissionRequiredMixin = (
        _StubContentTypePermissionRequiredMixin
    )
    proxbox_access.TokenWriteScopeRequiredMixin = type(
        "TokenWriteScopeRequiredMixin", (), {}
    )
    proxbox_access.user_can_run_endpoint_action = endpoint_authorizer()
    proxbox_access.permission_view_fastapi_endpoint = lambda: (
        "stub.view_fastapiendpoint"
    )
    proxbox_access.user_may_access_proxbox_dashboard = lambda user: True
    monkeypatch.setitem(
        sys.modules, "netbox_proxbox.views.proxbox_access", proxbox_access
    )

    sys.modules.pop(module_name, None)
    sys.modules.pop("netbox_proxbox.services.service_status", None)
    sys.modules.pop("netbox_proxbox.services.backend_proxy", None)
    sys.modules.pop("netbox_proxbox.services", None)
    relative_parts = module_name.split(".")[2:]
    module_path = (
        Path(__file__).resolve().parents[1]
        / "netbox_proxbox"
        / "views"
        / Path(*relative_parts)
    ).with_suffix(".py")
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    module._messages_stub = django_messages
    return module


@pytest.fixture
def fastapi_endpoint():
    return SimpleNamespace(
        id=1,
        name="proxbox-api",
        domain="proxbox.local",
        ip_address="10.0.0.5/24",
        port=8800,
        verify_ssl=True,
        token="backend-token",
        websocket_port=8801,
        websocket_domain="proxbox.local",
        use_websocket=True,
    )


@pytest.fixture
def netbox_endpoint():
    return SimpleNamespace(
        id=1,
        pk=1,
        name="netbox",
        domain="netbox.local",
        ip_address=SimpleNamespace(address="10.0.0.20/24"),
        port=443,
        token=SimpleNamespace(key="token-1"),
        effective_token_value="token-1",
        effective_token_version="v1",
        token_key="",
        token_secret="",
        verify_ssl=True,
    )


@pytest.fixture
def proxmox_endpoint():
    return SimpleNamespace(
        id=1,
        pk=1,
        name="pve01",
        domain="pve.local",
        ip_address="10.0.0.30/24",
        port=8006,
        username="root@pam",
        password="secret",
        token_name="proxbox2",
        token_value="token-secret",
        verify_ssl=False,
    )
