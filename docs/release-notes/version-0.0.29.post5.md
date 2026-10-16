# Version 0.0.29.post5

## Summary

This maintenance release makes Proxmox reads and writes endpoint-exact, lets
non-superusers receive endpoint-scoped operational permissions, adds a
capture-only operating mode, and correlates WebSocket completion with the
backend run that produced it. It also hardens device ownership, remote NetBox
connection approval, SSH credential handling, and the release pipeline.

The release pairs with `proxbox-api 0.0.27.post3` and includes one database
migration: `0106_device_sync_scope_and_netbox_token_approval`.

## Release identity

The package and plugin source both identify this maintenance release as
`0.0.29.post5`.

## Endpoint-exact HA reads

The virtual machine HA tab and per-VM HA API now query only the Proxmox
endpoint recorded by the VM's authoritative typed sync state. Linked cluster
and node rows must agree with that endpoint, and the caller must be able to view
both the NetBox VM and the enabled endpoint. Missing, conflicting, disabled, or
hidden identity is refused before backend I/O.

`GET /api/plugins/proxbox/ha/vm/{vmid}/` now requires
`virtual_machine_id={netbox_vm_pk}`. The plugin verifies that the selected VM's
synchronized Proxmox VM ID matches `{vmid}` before contacting the backend.

## Grantable operational actions

Operational verbs, firewall actions, tags, template builds, packer builds, and
instance creation now use the `run_proxmox_action` custom action on the exact
owning `ProxmoxEndpoint`. The authorized NetBox endpoint is translated to
proxbox-api's independent endpoint ID and remains bound to the dispatch. A
disabled or conflicting endpoint is refused without backend resolution or
network I/O, including firewall previews.

Create a NetBox ObjectPermission with these values:

- Object type: **Proxbox > Proxmox endpoint**.
- Actions: `view` when endpoint visibility is required, plus
  `run_proxmox_action`. Template-build REST actions also require `add`.
- Users or groups: the intended operators.
- Constraints: the permitted endpoint set, such as `{"pk": 17}` or
  `{"name": "lab-pve"}`.

Use separate constrained grants for different endpoint sets. An unconstrained
grant covers every Proxmox endpoint. The literal `core.run_proxmox_action`
permission remains an additive, deprecated compatibility path and should not be
used for new grants. Unsafe requests authenticated by an API token additionally
require `write_enabled=True`; session authentication is unchanged.

## SSH credential handling

Creating a Proxmox endpoint with **reuse endpoint username/password** now
recognizes the submitted password during model validation without storing it
early. This also fixes adding a password to a token-only endpoint and creating
an endpoint with service monitoring enabled. API and serializer paths still
reject reuse when neither a stored nor pending password exists.

An SSH terminal request for a disabled endpoint now returns HTTP 409 before
credential access, provider reads, writes, or backend I/O. This applies to
endpoint and node targets and to stored, one-shot, and newly stored credentials.
The credential, save, readiness, and terminal paths were split into small typed
helpers so each modified function remains within the repository's complexity
limit.

## Capture-only NetBox instances

Set `PLUGINS_CONFIG["netbox_proxbox"]["automatic_background_tasks"]` to the
boolean `False` to retain Proxbox inventory models, APIs, explicit sync jobs,
integrity handlers, and audit records while suppressing startup discovery and
stock one-minute service-monitor registration. An existing stock unowned,
unscoped monitor drains without polling or re-enqueueing. User-created, custom,
or scoped jobs are preserved. Restart every application and worker process
after changing this setting.

## Run-correlated WebSocket completion

When the connected backend advertises `ws_run_id: 1`, each sync command carries
a run identifier and only a matching aggregate terminal may complete it. Failed
aggregate status reaches the browser as an error, while malformed, foreign, and
late frames cannot release another run. Endpoint trust is revalidated before
every transmission and retry.

The plugin and `proxbox-api 0.0.27.post3` may be upgraded in either order. A
backend without the capability continues to receive legacy bare commands. In a
mixed-version rolling deployment, one attributable rejected envelope is retried
once in legacy form and later commands on that connection remain legacy.

## Device ownership and connection approval

Migration `0106_device_sync_scope_and_netbox_token_approval` adds nullable
`proxmox_endpoint_raw_id` to device sync state. Existing rows remain null and
unclaimed because historical identifiers cannot prove present endpoint
ownership. Consumers must corroborate cluster, site, and placement before
adopting a legacy candidate. Claims lock the sidecar row atomically: a null or
same-ID claim succeeds, while changing a committed owner returns HTTP 409 with
`endpoint_ownership_conflict`.

Remote NetBox connection approval now binds the effective token version and
the non-secret token reference or key selected for transmission. Token changes
therefore require explicit reapproval. The migration clears existing NetBox
endpoint approvals once without approving any target; Proxmox endpoint
approvals are unchanged. Review and approve each affected NetBox endpoint
through its connection-authority panel after migration.

## Release pipeline

The public mirror now carries only the authoritative `main` branch, and the
mocked CI job installs the CLI extra required by its tests. OCI release
validation requires both package indexes to expose a usable source archive or
compatible pure-Python wheel, resolves the backend version from the unique
release row in `COMPATIBILITY.md`, smoke-tests the amd64 manifest from the final
multi-architecture index, and publishes that same tested digest without a
rebuild.

## OpenBao storage guards

Switching the credential storage backend, changing an endpoint storage override,
or deleting an owner now locks the settings state first and validates the final
state on the write database, so primary/replica routing is respected. A blank
endpoint override is resolved against the locked global selection. Both the
default and base managers are guarded, including bulk updates and conflict
upserts. Deleting an owner is refused while provider assignments remain, even
without an owned material reference; a legacy endpoint holding only assignment
relations is cleaned up inside the surrounding transaction after every
assignment deletion is authorized. No migration is involved.

## Upgrade notes

1. Upgrade the separately deployed backend to `proxbox-api 0.0.27.post3` and
   install `netbox-proxbox 0.0.29.post5`. Either service may be upgraded first.
2. Run `python manage.py migrate netbox_proxbox`; this applies only
   `0106_device_sync_scope_and_netbox_token_approval` for this release.
3. Run `python manage.py collectstatic --no-input` and restart every NetBox
   application and worker process.
4. Review and explicitly reapprove every remote NetBox endpoint whose approval
   was cleared. Do not infer approval from backend health.
5. Create or review endpoint-constrained `run_proxmox_action` ObjectPermissions
   for non-superuser operators, and enable `write_enabled` only on API tokens
   that are authorized for unsafe actions.
6. Verify one endpoint-scoped HA read, one permitted operational action, and one
   full synchronization before returning the installation to service.

## Compatibility baseline

Current backend-runtime pairing: netbox-proxbox 0.0.29.post5 <-> proxbox-api 0.0.27.post3 <-> proxmox-sdk 0.0.15 <-> netbox-sdk 0.0.13. This netbox-sdk version is proxbox-api's REST dependency only and does not provide the semantic MCP bridge.

| NetBox | netbox-proxbox | proxbox-api | netbox-sdk | proxmox-sdk |
|---|---|---|---|---|
| 4.5.8-4.7.0 GA | v0.0.29.post5 | v0.0.27.post3 | v0.0.13 | v0.0.15 |

The plugin declares NetBox `4.5.8` through `4.7.99`; continuous integration
verifies the listed GA range through NetBox `4.7.0`.

## Known limitations

- Legacy device sync-state rows remain deliberately unclaimed until the paired
  backend corroborates and stamps their endpoint identity.
- Backends without run-correlation capability retain legacy virtual-machine
  terminal completion and the 600-second idle latch.
- Changing `automatic_background_tasks` requires a restart of all application
  and worker processes; it does not cancel explicit or user-owned jobs.
- The OCI appliance remains a testing topology, not a production deployment.
