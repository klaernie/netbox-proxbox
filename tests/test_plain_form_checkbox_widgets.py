"""Source and unit contracts for Bootstrap checkbox rendering on plain forms."""

from __future__ import annotations

import ast
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[1]
FORMS_PATH = REPO_ROOT / "netbox_proxbox" / "forms"
WIDGETS_PATH = FORMS_PATH / "widgets.py"


def _base_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _plain_form_classes() -> list[tuple[Path, ast.ClassDef]]:
    classes: list[tuple[Path, ast.ClassDef]] = []
    for path in sorted(FORMS_PATH.glob("*.py")):
        module = ast.parse(path.read_text(), filename=str(path))
        classes.extend(
            (path, node)
            for node in module.body
            if isinstance(node, ast.ClassDef)
            and not node.name.endswith("Mixin")
            and any(_base_name(base) == "Form" for base in node.bases)
        )
    return classes


def _attribute_names(node: ast.AST) -> set[str]:
    return {child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)}


def _base_names(node: ast.ClassDef) -> set[str]:
    return {name for base in node.bases if (name := _base_name(base)) is not None}


def test_all_plain_form_boolean_fields_use_bootstrap_checkbox_rendering():
    """Every plain form with BooleanField declarations must opt into the mixin."""
    uncovered: list[str] = []
    for path, class_node in _plain_form_classes():
        if "BooleanField" not in _attribute_names(class_node):
            continue
        if "BootstrapCheckboxFormMixin" not in _base_names(class_node):
            uncovered.append(f"{path.name}:{class_node.name}")

    assert not uncovered, f"plain forms have unstyled BooleanFields: {uncovered}"


def test_plain_form_checkbox_select_multiple_widgets_are_bootstrap_compatible():
    """Raw CheckboxSelectMultiple widgets require the same plain-form mixin."""
    uncovered: list[str] = []
    for path, class_node in _plain_form_classes():
        names = _attribute_names(class_node)
        if "CheckboxSelectMultiple" not in names:
            continue
        if "BootstrapCheckboxFormMixin" not in _base_names(class_node):
            uncovered.append(f"{path.name}:{class_node.name}")

    assert not uncovered, f"plain forms have unstyled checkbox lists: {uncovered}"


def test_settings_and_recovery_forms_share_checkbox_rendering_mixin():
    module = ast.parse(
        (FORMS_PATH / "settings.py").read_text(),
        filename=str(FORMS_PATH / "settings.py"),
    )
    classes = {
        node.name: node for node in module.body if isinstance(node, ast.ClassDef)
    }

    for name in (
        "ProxboxPluginSettingsForm",
        "EncryptionKeyRotationForm",
        "EncryptedSecretResetForm",
    ):
        assert "BootstrapCheckboxFormMixin" in _base_names(classes[name])


def test_checkbox_mixin_preserves_classes_and_styles_every_widget(monkeypatch):
    class Widget:
        def __init__(self, attrs=None):
            self.attrs = dict(attrs or {})

    class CheckboxInput(Widget):
        def __init__(self, attrs=None, check_test=None):
            super().__init__(attrs)
            self.check_test = check_test

    class CheckboxSelectMultiple(Widget):
        def __init__(self, attrs=None):
            super().__init__(attrs)
            self.choices = ()

        def create_option(self, *args, **kwargs):
            return {}

    forms = types.ModuleType("django.forms")
    forms.Widget = Widget
    forms.CheckboxInput = CheckboxInput
    forms.CheckboxSelectMultiple = CheckboxSelectMultiple
    django = types.ModuleType("django")
    django.forms = forms
    monkeypatch.setitem(sys.modules, "django", django)
    monkeypatch.setitem(sys.modules, "django.forms", forms)

    spec = importlib.util.spec_from_file_location("_checkbox_widgets", WIDGETS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class BaseForm:
        def __init__(self, *args, **kwargs):
            multiple = CheckboxSelectMultiple({"data-test": "kept"})
            multiple.choices = (("one", "One"),)
            self.fields = {
                "first": SimpleNamespace(widget=CheckboxInput()),
                "second": SimpleNamespace(
                    widget=CheckboxInput({"class": "existing form-check-input"})
                ),
                "multiple": SimpleNamespace(widget=multiple, choices=multiple.choices),
            }

    class TestForm(module.BootstrapCheckboxFormMixin, BaseForm):
        pass

    form = TestForm()
    for name in ("first", "second"):
        assert isinstance(form.fields[name].widget, module.BootstrapCheckboxInput)
        assert form.fields[name].widget.template_name.endswith(
            "bootstrap_checkbox_input.html"
        )
        classes = form.fields[name].widget.attrs.get("class", "").split()
        assert "form-check-input" not in classes
    assert "existing" in form.fields["second"].widget.attrs["class"].split()
    multiple = form.fields["multiple"].widget
    assert isinstance(multiple, module.BootstrapFormCheckboxSelectMultiple)
    assert multiple.attrs["data-test"] == "kept"
    assert tuple(multiple.choices) == (("one", "One"),)

    checkbox_template = (
        REPO_ROOT
        / "netbox_proxbox/templates/netbox_proxbox/widgets/bootstrap_checkbox_input.html"
    ).read_text()
    assert checkbox_template.count('class="form-check-input') == 1
