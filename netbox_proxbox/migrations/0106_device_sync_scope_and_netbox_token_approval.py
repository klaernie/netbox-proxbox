"""Add device sync scope and require NetBox token reapproval.

Existing device rows deliberately remain unscoped. Historical backend IDs do
not establish current ownership after a backend restore, reseed, or ID reuse;
the active backend must stamp its current endpoint ID during reconciliation.
"""

from django.db import migrations, models

from ._idempotent_ops import add_field_idempotent


def clear_netbox_endpoint_approvals(apps, schema_editor) -> None:
    """Revoke approvals whose legacy fingerprint omitted token identity."""
    alias = schema_editor.connection.alias
    netbox_endpoint = apps.get_model("netbox_proxbox", "NetBoxEndpoint")
    netbox_endpoint.objects.using(alias).exclude(
        approved_connection_target_fingerprint=""
    ).update(approved_connection_target_fingerprint="")


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_proxbox", "0105_reset_implicit_openbao_storage_default"),
    ]

    operations = [
        add_field_idempotent(
            "proxboxdevicesyncstate",
            "proxmox_endpoint_raw_id",
            models.IntegerField(blank=True, null=True),
        ),
        migrations.RunPython(
            clear_netbox_endpoint_approvals,
            migrations.RunPython.noop,
        ),
    ]
