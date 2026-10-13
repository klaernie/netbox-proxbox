# Version 0.0.29.post4

## Summary

This maintenance release fixes saving a Proxmox endpoint that uses API access
only, and makes the endpoint form show which settings are read-only and which
are write-enabled. It adds no database migration.

## Release identity

The package and plugin source both identify this maintenance release as
`0.0.29.post4`.

## API-only endpoints no longer need SSH credentials

An endpoint whose access method is "API only" could not be saved without SSH
credentials, even though it never opens an SSH connection. The form and the
model now skip SSH validation entirely for API-only endpoints and discard any
SSH values submitted with them. SSH credentials are validated only when the
access method is "API + SSH". Existing endpoints keep their stored values.

## Clearer endpoint form

The endpoint form is grouped into sections that say what each one is for:

- Connection and credentials: read-only API access.
- Write access: opt-in, with the write-enabled settings.
- Access methods.
- SSH credential access: only for "API + SSH" endpoints.
- Service monitoring: needs write access and "API + SSH".

Write-enabled and SSH sections are hidden until the setting that needs them is
turned on. A section that holds an error, a checked option, or a pending
clear-credential request stays visible so that no submitted value is hidden.
See [Proxmox endpoint form](../configuration/proxmox-endpoint-form.md).

## NetBox compatibility

The supported NetBox range is unchanged: the plugin declares NetBox `4.5.8`
through `4.7.99`, and continuous integration verifies NetBox `4.5.8` through the
`4.7.0` GA release.

## Upgrade

Upgrade from any `0.0.29` release with the usual package upgrade and
`manage.py migrate`; this release adds no migration.

## Compatibility baseline

Current backend-runtime pairing: netbox-proxbox 0.0.29.post4 <-> proxbox-api 0.0.23.post3 <-> proxmox-sdk 0.0.15 <-> netbox-sdk 0.0.13. This netbox-sdk version is proxbox-api's REST dependency only and does not provide the semantic MCP bridge.

| NetBox | netbox-proxbox | proxbox-api | netbox-sdk | proxmox-sdk |
|---|---|---|---|---|
| 4.5.8-4.7.0 GA | v0.0.29.post4 | v0.0.23.post3 | v0.0.13 | v0.0.15 |
