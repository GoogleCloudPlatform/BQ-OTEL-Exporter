# Migration guide

This page is the migration path that the exporter's deprecation warnings and
schema version changes point to. It has two halves, because the component has
two compatibility surfaces:

- the **configuration** that operators write in the collector YAML, and
- the **BigQuery table schema** that downstream queries, views and dbt models
  read.

Both follow the Collector's
[component stability rules](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#beta)
for a beta component. The policies themselves are summarised in
[`CONTRIBUTING.md`](../CONTRIBUTING.md); this page carries the migration
steps for each concrete change. [`docs/config-inventory.md`](config-inventory.md)
lists every configuration key with its type, default, release and stability.

## Configuration keys

### Policy

A configuration key is renamed or removed only through the deprecation
mechanism in `config_deprecation.go`:

1. **Release N** introduces the replacement key (if any), registers the old
   key in `deprecatedConfigKeys`, and adds a section to this page. The old
   key keeps working: its value is applied to the replacement and the exporter
   logs one `WARN` at startup.
2. **Release N+1** keeps the old key accepted, with the same warning.
3. **Release N+2 at the earliest, and no sooner than six months after
   release N**, the old key may be removed. From then on it is an unknown key
   and the collector refuses to start with it set.

New keys always carry a default that keeps existing deployments unchanged, so
upgrading never requires editing the configuration. Keys classified as
`experimental` in the inventory may have their *default or bounds* retuned in
any release (recorded in `CHANGELOG.md`); their *names* follow the same
deprecation path as stable keys.

The release that deprecates a key is a tagged release of this repository
while the component lives here, and a contrib release
(`opentelemetry-collector-contrib` `v0.X.0`) once it has moved. The N+2 rule
counts releases on whichever train the component ships on; the six-month
floor applies regardless.

### What the warning looks like

Each deprecated key that is set produces exactly one warning when the first
exporter built from that configuration block is created, however many
pipelines (traces, logs, metrics) share the block:

```text
WARN  configuration key "write.old_key" is deprecated; its value was applied
      to "write.new_key" (deprecated in v0.0.4, removal no earlier than v0.0.6):
      https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/migration.md#<anchor>
      {"deprecated_key": "write.old_key", "replacement_key": "write.new_key",
       "deprecated_in": "v0.0.4", "removal_earliest": "v0.0.6",
       "migration_guide": "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/migration.md#<anchor>"}
```

A key removed without a replacement logs
`configuration key "..." is deprecated and has no effect; remove it` with the
same fields minus `replacement_key`, and its value is dropped.

Setting **both** the deprecated key and its replacement is a configuration
error, not a warning: the collector fails to start with
`<old> is deprecated and replaced by <new>, but both are set; remove <old>`.
Two values for one setting are ambiguous, and a startup failure is cheaper
than a silent guess.

### Worked example: renaming a key

No key has been renamed or removed yet; the registry is empty. When the first
rename ships, its section will look like this (the key names below are
illustrative, not real):

> #### `write.old_key` → `write.new_key` (deprecated in v0.0.4)
>
> `write.old_key` was renamed to `write.new_key` because …. Replace
>
> ```yaml
> exporters:
>   bigquery:
>     write:
>       old_key: 4
> ```
>
> with
>
> ```yaml
> exporters:
>   bigquery:
>     write:
>       new_key: 4
> ```
>
> The old key keeps working, with a startup warning, until at least v0.0.6
> and no sooner than six months after v0.0.4.

The matching registry entry is one line in `config_deprecation.go`:

```go
{OldPath: "write.old_key", NewPath: "write.new_key", DeprecatedIn: "v0.0.4", RemovalEarliest: "v0.0.6", Anchor: "writeold_key--writenew_key-deprecated-in-v004"},
```

`config_inventory_test.go` fails until the entry, the heading this `Anchor`
names, and the row in the inventory's deprecated-keys table all exist.

### Deprecated configuration keys

None yet. Sections are added here, newest first, as keys are deprecated.

## BigQuery table schema

### Policy

The table layout written by the exporter is a versioned contract. Its version
is `internal/schema.Version` (currently `v0alpha3`), stamped on every
BigQuery table via the four `otel_schema_*` table metadata labels
(`otel_schema_major`, `otel_schema_minor`, `otel_schema_patch`,
`otel_schema_variant`) rather than repeated as a per-row `schema_version`
column, so existing and newly provisioned tables can be identified and validated
against the running binary.

- **Within a schema version** only additive changes are allowed: a new
  `NULLABLE` column, a new companion view, or a new search index. Existing
  columns keep their name, type and mode. Readers that select columns by name
  keep working; `SELECT *` consumers see a new column.
- **A rename, retype, removal or mode change** of a column needs a new schema
  version, a section on this page with the migration steps, and tooling to
  move existing data where that is feasible (`cmd/bq-otel-backfill` is the
  starting point). The exporter never alters an existing table in place.
- While the version starts with `v0alpha`, documented breaking corrections
  are still allowed between versions; the freeze criteria and the `v1`
  identity are tracked in
  [`docs/schema-rationale.md`](schema-rationale.md).

Schema versions are independent of the library's Go module version and of the
contrib release version: a contrib release bumps `v0.X.0` for every component
whether or not this exporter's schema changed. The mapping is recorded here:
each schema version lists the first release of this repository (and, once
donated, the first contrib release) that writes it.

### Schema version history

| Schema version | First release | Change type | Migration |
| --- | --- | --- | --- |
| `v0alpha2` | v0.0.1 | initial tagged contract | legacy pre-v1 layout with `*_schema` sidecars, per-row `schema_version`, `record_fingerprint`, and 7-field `payload_refs` |
| `v0alpha3` | unreleased (`v1.0.0-candidate`) | breaking alpha cutover (`otel_schema_*` labels `0.3.0/default`) | See [`v0alpha2` → `v0alpha3`](#v0alpha2--v0alpha3) below. |

### Upgrading across a schema version change

When a release moves `internal/schema.Version`:

1. Read the section for the new version on this page. It names the columns
   that changed and whether `cmd/bq-otel-backfill` can carry existing rows
   across.
2. Stop the pipelines writing the old tables, or point the new collector at
   fresh table names (`traces.table`, `logs.table`, `metrics.table`,
   `quarantine.table`) so old and new tables coexist during the cut-over.
3. Let the exporter create the new tables (`auto_create.tables: true`) or
   create them beforehand from the table definitions in
   [`internal/schema/schema.go`](../internal/schema/schema.go) (`cmd/bq-otel-backfill`
   requires the destination tables to exist).
4. Run the backfill if the section says the data can be migrated, and repoint
   views and dashboards at the new tables.

Tables written by earlier `v0alpha*` builds are rejected at startup with an
actionable migration error pointing here and are not written to or rewritten
in place by a newer exporter; they stay queryable under their old table layout
until you migrate or drop them.

#### `v0alpha2` → `v0alpha3`

`v0alpha3` (`v1.0.0-candidate`) is a breaking schema cutover across all four
tables (`otel_spans`, `otel_logs`, `otel_metrics`, `otel_quarantine`).

**Breaking column and metadata changes**

- **Table metadata labels replace `schema_version`**: Removed the per-row
  `schema_version` column from all four tables and replaced it with the four
  BigQuery table metadata labels (`otel_schema_major=0`, `otel_schema_minor=3`,
  `otel_schema_patch=0`, `otel_schema_variant=default`). Because BigQuery caps
  table resources at 64 labels and 4 slots are reserved for `otel_schema_*`,
  the customer label cap (`labels`, `traces.labels`, `logs.labels`,
  `metrics.labels`, `quarantine.labels`) drops from `64` to `60` keys.
- **Removed `*_schema` JSON type-sidecar columns**: Dropped
  `attributes_schema`, `resource.attributes_schema`,
  `instrumentation_scope.attributes_schema`, `events.attributes_schema`,
  `links.attributes_schema`, `body_schema`, `metric_metadata_schema`, and
  `exemplars.filtered_attributes_schema`.
- **Removed `otel_logs.record_fingerprint`**: Dropped `record_fingerprint` from
  `otel_logs`.
- **Replaced `payload_refs` with native BigQuery `ObjectRef` `object_refs`**:
  Replaced the 7-field `payload_refs` array on `otel_spans` and `otel_logs`
  with the 4-field `object_refs` array
  (`STRUCT<uri STRING, version STRING, authorizer STRING, details JSON>`), with
  `details` holding `"gcs_metadata"` only.
- **Relaxed `otel_logs.insert_id`**: Changed `otel_logs.insert_id` from
  `REQUIRED` to `NULLABLE`, paired with `logs.synthesize_insert_id` (default
  `true`).

**Startup behavior on existing `v0alpha2` tables**

The `v0alpha3` exporter refuses to start against existing `v0alpha2` tables
(including legacy tables whose `schema_version` column was manually relaxed to
`NULLABLE`) with an actionable error linking to this guide, and never alters
existing tables in place.

**Cutover and backfill steps**

1. **Align collector and Terraform revisions**: At unreleased revisions carrying
   `v0alpha3`, `deploy/terraform/` provisions `v0alpha3` tables while the
   pinned `0.1.0` release image writes `v0alpha2` and fails closed at startup
   when `auto_create.tables` is `false`. Build and push a collector image from
   the matching revision (see [`deploy/README.md`](../deploy/README.md#quick-start)).
2. **Provision fresh `v0alpha3` tables**: Create the `v0alpha3` tables in a new
   dataset or under new table names (`traces.table`, `logs.table`,
   `metrics.table`, `quarantine.table`) using `auto_create.tables: true` or the
   matching revision of `deploy/terraform/`.
3. **Backfill or bridge historical data**: `cmd/bq-otel-backfill` re-ingests
   archived OTLP/JSONL export files into pre-created `v0alpha3` tables; it does
   not rewrite existing `v0alpha2` BigQuery tables in place. Historical
   `v0alpha2` tables stay queryable read-only under their old layout during
   retention overlap, or you can bridge retention windows with a `UNION ALL`
   projection view or an `INSERT INTO ... SELECT ...` SQL projection into the
   new `v0alpha3` tables.
4. **Update downstream queries and views**: Repoint dashboards and companion
   views (`_dedup`, `v_gen_ai_*`, `v_mcp_*`) at the `v0alpha3` tables, which
   query `object_refs` and omit the dropped `*_schema`, `schema_version`, and
   `record_fingerprint` columns.
