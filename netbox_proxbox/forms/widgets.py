"""Form widgets used by Proxbox plugin forms."""

from __future__ import annotations

from django import forms

__all__ = (
    "BootstrapCheckboxFormMixin",
    "BootstrapCheckboxInput",
    "BootstrapCheckboxSelectMultiple",
    "BootstrapFormCheckboxSelectMultiple",
)


class BootstrapCheckboxInput(forms.CheckboxInput):
    """Checkbox input with stable Bootstrap markup across supported NetBox versions."""

    template_name = "netbox_proxbox/widgets/bootstrap_checkbox_input.html"


class BootstrapCheckboxSelectMultiple(forms.CheckboxSelectMultiple):
    """
    Checkbox list using NetBox ``form-check`` / ``form-check-input`` / ``form-check-label``
    pattern (same as core templates such as ``object_list.html``).
    """

    template_name = "netbox_proxbox/widgets/bootstrap_checkbox_select.html"
    option_template_name = "netbox_proxbox/widgets/bootstrap_checkbox_option.html"

    def create_option(
        self,
        name: str,
        value: object,
        label: object,
        selected: bool,
        index: int,
        subindex: int | None = None,
        attrs: dict[str, object] | None = None,
    ) -> dict[str, object]:
        # form-check-input is rendered in bootstrap_checkbox_option.html (NetBox attrs.html skips class).
        """Create option."""
        return super().create_option(
            name, value, label, selected, index, subindex=subindex, attrs=attrs
        )


class BootstrapFormCheckboxSelectMultiple(BootstrapCheckboxSelectMultiple):
    """Generic Bootstrap checkbox list for ordinary ``render_field`` rows."""

    template_name = "netbox_proxbox/widgets/bootstrap_form_checkbox_select.html"


class BootstrapCheckboxFormMixin:
    """Apply NetBox-compatible Bootstrap classes to plain Django form checkboxes."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._style_checkbox_widgets()

    def _style_checkbox_widgets(self) -> None:
        """Style current fields, including fields added dynamically by subclasses."""
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput) and not isinstance(
                widget, BootstrapCheckboxInput
            ):
                attrs = widget.attrs.copy()
                classes = str(attrs.get("class", "")).split()
                classes = [name for name in classes if name != "form-check-input"]
                if classes:
                    attrs["class"] = " ".join(classes)
                else:
                    attrs.pop("class", None)
                field.widget = BootstrapCheckboxInput(
                    attrs=attrs,
                    check_test=widget.check_test,
                )
            elif isinstance(widget, forms.CheckboxSelectMultiple) and not isinstance(
                widget, BootstrapCheckboxSelectMultiple
            ):
                replacement = BootstrapFormCheckboxSelectMultiple(
                    attrs=widget.attrs.copy()
                )
                replacement.choices = field.choices
                field.widget = replacement
