# Version 0.0.29.post6

## Summary

This maintenance release prevents paginated guest virtual machine interface
address and synchronization job requests from failing because their querysets
were unordered. It also restores correct checkbox rendering on the plugin's
plain settings, recovery, and data-protection forms.

The release pairs with `proxbox-api 0.0.27.post4`, which hardens node Device
identity resolution. The plugin and backend may be upgraded in either order.
This release adds no database migration; migration
`0106_device_sync_scope_and_netbox_token_approval` remains the schema tip.

## Release identity

The package and plugin source both identify this maintenance release as
`0.0.29.post6`.

## Deterministic paginated querysets

Guest virtual machine interface address REST and UI lists now use stable
relationship and primary-key ordering. Synchronization job lists now use stable
descending creation-time and primary-key ordering. This prevents NetBox 4.6
from raising `QuerySetNotOrdered` when these endpoints are paginated.

The fix is scoped to the affected viewset querysets. It does not add model
ordering or change the database schema. A source contract now audits every
registered REST viewset and rejects a paginated model queryset without explicit
or model-provided ordering.

## Plain-form checkbox rendering

Boolean fields and checkbox lists on the plugin settings, encrypted-secret
recovery, and Data Protection pages now render with Bootstrap's
`form-check-input` class instead of the text-input `form-control` class. Their
selected state and layout are therefore drawn consistently across supported
NetBox versions.

## Upgrade notes

1. Upgrade the separately deployed backend to `proxbox-api 0.0.27.post4` and
   install `netbox-proxbox 0.0.29.post6`. Either service may be upgraded first.
2. No plugin migration is required for this release. Running the normal
   `python manage.py migrate netbox_proxbox` command remains safe and reports no
   new migration after `0106_device_sync_scope_and_netbox_token_approval`.
3. Run `python manage.py collectstatic --no-input` and restart every NetBox
   application and worker process.
4. Verify a paginated guest interface address request, the synchronization job
   list, and checkboxes on the settings and Data Protection pages.

## Compatibility baseline

Current backend-runtime pairing: netbox-proxbox 0.0.29.post6 <-> proxbox-api 0.0.27.post4 <-> proxmox-sdk 0.0.15 <-> netbox-sdk 0.0.13. This netbox-sdk version is proxbox-api's REST dependency only and does not provide the semantic MCP bridge.

| NetBox | netbox-proxbox | proxbox-api | netbox-sdk | proxmox-sdk |
|---|---|---|---|---|
| 4.5.8-4.7.0 GA | v0.0.29.post6 | v0.0.27.post4 | v0.0.13 | v0.0.15 |

The plugin declares NetBox `4.5.8` through `4.7.99`; continuous integration
verifies the listed GA range through NetBox `4.7.0`.

## Known limitations

- The ordering contract covers registered REST viewsets. It does not impose
  global model ordering on unrelated ORM consumers.
- The checkbox fix applies to the plugin's plain Django forms; NetBox-native
  model forms retain their existing widget handling.
- The OCI appliance remains a testing topology, not a production deployment.
