# Proxmox Endpoint Form

The Proxmox endpoint add and edit form separates read-only settings from the
settings that only matter when writes or SSH are enabled.

| Section | Always shown | What it controls |
|---|---|---|
| Connection and credentials (read-only API access) | Yes | Address, port, API username, password or API token, TLS verification, site, tenant, tags. This is everything an inventory-only endpoint needs. |
| Write access (opt-in) | Yes | **Allow Proxmox-side writes**. The **Allow netbox-packer template builds** option appears only after writes are enabled, or while it is already checked. |
| Access methods | Yes | **API only** (default) or **API + SSH**. |
| SSH credential access (API + SSH only) | Only for API + SSH | Dedicated or reused SSH credential, pinned host-key fingerprint, and the browser SSH terminal login. |
| Service monitoring (needs write access and API + SSH) | Only with writes enabled and API + SSH | Systemd service collection through netbox-rpc. |

A section stays visible when it holds a validation error, and an option that is
already checked is never hidden, so you can always see and clear it. Hidden
fields are still submitted unchanged, and the browser's own field checks are switched off while a section is hidden so a hidden field can never block saving. If JavaScript is unavailable, every
section is shown.

When reuse mode and service monitoring are enabled together, a password entered
on the same create or edit submission satisfies validation without being copied
onto the model as a validation side effect. Runtime readiness still becomes true
only after the credential has been persisted successfully.

## API-only endpoints do not need SSH

An endpoint with **API only** access never opens an SSH session. The form
ignores every SSH field for it, so a leftover or placeholder SSH value cannot
block saving, and the submitted SSH values are not stored. Switching the
endpoint to **API + SSH** applies the full SSH validation again: a username, a
pinned host-key fingerprint, and a matching password or private key.
