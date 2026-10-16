# Plugin Package Guide

The `netbox_proxbox` package must remain a self-contained public NetBox plugin.
Imports at module load time may use NetBox, Django, declared dependencies, and
this package only. Optional companion integrations must be imported lazily and
must degrade safely when absent.

Keep secrets encrypted at rest and out of serializers, templates, change logs,
exceptions, and ordinary exports. Keep network access bounded by destination
validation, redirect refusal for credentialed requests, timeouts, and TLS
verification. Preserve NetBox object permissions on every UI and API action.

OpenBao's outer material transaction must be entered while the connection is in
autocommit. Inside the provider-owned durable transaction, lock the settings
singleton before every owner, assignment, or credential row. The order among
those downstream rows is transaction-specific; do not introduce an application
atomic block before the outer provider transaction or lock any downstream row
before the settings singleton.
After acquiring the graph, each endpoint, node SSH, single-secret, and
cloud-init writer must revalidate the effective backend from the locked settings
and owner snapshot before any provider or assignment write. Storage-changing
querysets must mark themselves for write before resolving their database alias,
bind final guards to that alias, and reject conflict upserts. Instrument both
the default and base manager queryset classes. A validated literal
`bulk_update()` may use only a context-local permit for Django's internally
generated `Case`/`Cast` update; caller-supplied expressions remain invalid.
Blank endpoint overrides inherit the effective global selection from the locked
settings row on that write database, not the companion-dependent Automatic
default in isolation.

Model or serializer changes require focused source-contract tests and real-Django
coverage when behavior depends on the ORM, database constraints, permissions, or
template rendering. Persisted changes require additive migrations.

Supported deletion of an explicitly legacy endpoint with assignment-only state
must delete only those non-secret assignment relations through the plain ORM in
the current application transaction. It must not enter a provider material
transaction. Resolve the current request actor freshly and authorize deletion
of every exact assignment before deleting any row; denial preserves the
endpoint and all assignments. Endpoint deletion with OpenBao references retains
provider-owned cleanup, and remaining assignment-only state at `pre_delete`
still proves an unsupported queryset, bulk, or cascade deletion.

The public semantic bridge API and agent-safety contract are documented in
[`docs/api/semantic-mcp-bridge.md`](../docs/api/semantic-mcp-bridge.md).

`security_checks.py` registers database-tagged Django system checks
(`netbox_proxbox.W101`–`W107`, plus `W100` when an inspection fails for any
reason other than unmigrated tables; `W105` reports a NetBox token configured
for proxbox-api that cannot read the plugin settings) for enabled backend endpoints on plain HTTP or
unverified TLS, enabled Proxmox endpoints without TLS verification, and a
legacy raw plugin encryption key. `W106` reports explicit OpenBao storage while
netbox-openbao is not enabled. `W107` reports a backend token user without
the sensitive-data grant that proxbox-api needs to read the runtime key; the
grant is never created automatically. They run for `migrate` and
`check --database default` only, return nothing before the plugin tables exist,
and never rewrite rows; new endpoints default to HTTPS and TLS verification.
