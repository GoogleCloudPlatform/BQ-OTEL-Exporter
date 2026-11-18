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
is `internal/schema.Version` (currently `v1.0.0`), stamped on every
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
- **SemVer guarantee (`v1.0.0` freeze):** Within `1.x` minor releases, only
  additive `NULLABLE` or `REPEATED` columns and new views, TVFs, or search
  indexes are permitted; any breaking column removal, rename, retype, or mode
  tightening requires `v2.0.0`. See
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
| `v0alpha3` | unreleased (`v1.0.0-candidate`) | breaking alpha cutover (`otel_schema_*` labels `0.3.0/default`) | See [`v0alpha3` → `v1.0.0`](#v0alpha3--v100) below. |
| `v1.0.0` | unreleased | frozen v1 schema contract (`otel_schema_*` labels `1.0.0/default`) | Zero-rewrite label promotion from `v0alpha3`; full cutover from `v0alpha2` via [`v0alpha2` → `v1.0.0`](#v0alpha2--v100). |

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

#### `v0alpha3` → `v1.0.0`

`v0alpha3` (`0.3.0/default`) and `v1.0.0` (`1.0.0/default`) share an identical
physical column, companion-view, and TVF layout across all four tables (`0` row
rewrites). Both schema versions admit each other bidirectionally at collector
startup and in `bq-otel-validate` during rolling upgrades (`v1.0.0` logs an
informational promotion hint when attached to a `0.3.0/default` table).

To promote an existing `v0alpha3` table in place while preserving any custom
table labels, update only the four `otel_schema_*` labels on each provisioned
table (or run `terraform apply` with the updated `deploy/terraform/` module):

```bash
bq update --set_label otel_schema_major:1 --set_label otel_schema_minor:0 --set_label otel_schema_patch:0 --set_label otel_schema_variant:default my-project:otel_v1.otel_logs
```

<a id="v0alpha2--v0alpha3"></a>

#### `v0alpha2` → `v1.0.0`

`v1.0.0` (staged via `v0alpha3`) is a breaking schema cutover across all four
tables (`otel_spans`, `otel_logs`, `otel_metrics`, `otel_quarantine`).

**Breaking column and metadata changes**

- **Table metadata labels replace `schema_version`**: Removed the per-row
  `schema_version` column from all four tables and replaced it with the four
  BigQuery table metadata labels (`otel_schema_major=1`, `otel_schema_minor=0`,
  `otel_schema_patch=0`, `otel_schema_variant=default`). Because BigQuery caps
  table resources at 64 labels and 4 slots are reserved for `otel_schema_*`,
  the customer label cap (`labels`, `traces.labels`, `logs.labels`,
  `metrics.labels`, `quarantine.labels`) drops from `64` to `60` keys.
- **Removed `*_schema` JSON type-sidecar columns**: Dropped
  `attributes_schema`, `resource.attributes_schema`,
  `instrumentation_scope.attributes_schema`, `events.attributes_schema`,
  `links.attributes_schema`, `metric_metadata_schema`, and
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

The `v1.0.0` exporter refuses to start against existing `v0alpha2` tables
(including legacy tables whose `schema_version` column was manually relaxed to
`NULLABLE`) with an actionable error linking to this guide, and never alters
existing tables in place.

**Cutover and backfill steps**

1. **Align collector and Terraform revisions**: At unreleased revisions carrying
   `v1.0.0`, `deploy/terraform/` provisions `v1.0.0` tables while the
   pinned `0.1.0` release image writes `v0alpha2` and fails closed at startup
   when `auto_create.tables` is `false`. Build and push a collector image from
   the matching revision (see [`deploy/README.md`](../deploy/README.md#quick-start)).
2. **Provision fresh `v1.0.0` tables**: Create the `v1.0.0` tables in a new
   dataset or under new table names (`traces.table`, `logs.table`,
   `metrics.table`, `quarantine.table`) using `auto_create.tables: true` or the
   matching revision of `deploy/terraform/`. Apply that revision from a
   separate Terraform state or workspace (for example a new workspace with a
   new `dataset_id`): run against the state that manages the `v0alpha2`
   tables, it plans to replace all four tables, because their columns changed.
   Do not turn off `deletion_protection` to get past that plan; the
   replacement deletes the `v0alpha2` tables and their data.
3. **Backfill or bridge historical data**: `cmd/bq-otel-backfill` re-ingests
   archived OTLP/JSONL export files into pre-created `v1.0.0` tables; it does
   not rewrite existing `v0alpha2` BigQuery tables in place. Historical
   `v0alpha2` tables stay queryable read-only under their old layout during
   retention overlap, or you can bridge retention windows with a `UNION ALL`
   projection view or an `INSERT INTO ... SELECT ...` SQL projection into the
   new `v1.0.0` tables (see the [SQL migration runbook](#sql-migration-runbook)
   below).
4. **Update downstream queries and views**: Repoint dashboards and companion
   views (`_dedup`, `otel_spans_as_allspans`, `otel_logs_as_alllogs`,
   `v_gen_ai_*`, `v_mcp_*`) at the `v1.0.0` tables, which query `object_refs`
   and omit the dropped `*_schema`, `schema_version`, and `record_fingerprint`
   columns.

#### SQL migration runbook

These steps carry the rows of the `v0alpha2` tables into fresh `v1.0.0`
tables (step 3 above) and keep the old tables for a rollback.

##### 1. Side-by-side dataset isolation (prevent companion-view clobbering)

Deploy `v1` (`v1.0.0`) into a **separate BigQuery dataset** (for example
`otel_v1` alongside `otel_v0alpha2`, or distinct table names with Terraform
views isolated per dataset). Never point a `v1` collector with
`auto_create.companion_views: true` or a `v1` Terraform workspace at the live
`v0alpha2` dataset while legacy `v0alpha2` pipelines are active: reconciling
companion views (`otel_spans_as_allspans`, `otel_logs_as_alllogs`, `v_gen_ai_*`)
in place would break queries expecting the `v0alpha2` table contract before
backfill completes.

##### 2. Protect historical `v0alpha2` tables during the rollback window

Keep `v0alpha2` tables protected for a **14–30 day retention and soak window**
by setting `lifecycle { prevent_destroy = true }` in Terraform on the legacy
`otel_spans`, `otel_logs`, `otel_metrics`, and `otel_quarantine` resources
before applying any new dataset module.

##### 3. Table-to-table SQL migration (`v0alpha2` → `v1`)

Provision the empty `v1` (`v1.0.0`) destination tables first (via collector
startup with `auto_create.tables: true`, Terraform, or `internal/schema` DDLs),
then backfill historical partitions using the parity-tested projections from
[`internal/schema/migration.go`](../internal/schema/migration.go). Every array
rebuild (`events`, `links`, `object_refs`, `exemplars`) numbers the source
elements `WITH OFFSET AS pos` and ends in `ORDER BY pos`, because BigQuery does
not otherwise guarantee that an array rebuilt from `UNNEST` keeps the
element order (exemplar position, event and link order):

```sql
-- Spans: drops *_schema and schema_version; projects payload_refs[].object_ref -> object_refs
INSERT INTO `my-project.otel_v1.otel_spans` (
  start_time, start_time_unix_nano, end_time, end_time_unix_nano,
  receive_time, receive_time_unix_nano, duration_nano,
  trace_id, span_id, parent_span_id, trace_state, flags,
  name, kind, kind_name, status, attributes, dropped_attributes_count,
  service_name, resource, resource_schema_url, instrumentation_scope, scope_schema_url,
  events, dropped_events_count, links, dropped_links_count, object_refs
)
SELECT
  start_time, start_time_unix_nano, end_time, end_time_unix_nano,
  receive_time, receive_time_unix_nano, duration_nano,
  trace_id, span_id, parent_span_id, trace_state, flags,
  name, kind, kind_name, status, attributes, dropped_attributes_count,
  service_name,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  ARRAY(SELECT AS STRUCT e.time, e.time_unix_nano, e.name, e.attributes, e.dropped_attributes_count FROM UNNEST(events) AS e WITH OFFSET AS pos ORDER BY pos) AS events,
  dropped_events_count,
  ARRAY(SELECT AS STRUCT l.trace_id, l.span_id, l.trace_state, l.flags, l.attributes, l.dropped_attributes_count FROM UNNEST(links) AS l WITH OFFSET AS pos ORDER BY pos) AS links,
  dropped_links_count,
  ARRAY(SELECT AS STRUCT p.object_ref.uri AS uri, p.object_ref.version AS version, p.object_ref.authorizer AS authorizer, p.object_ref.details AS details FROM UNNEST(payload_refs) AS p WITH OFFSET AS pos WHERE p.object_ref.uri IS NOT NULL AND p.object_ref.uri != '' ORDER BY pos) AS object_refs
FROM `my-project.otel_v0alpha2.otel_spans`;

-- Logs: drops *_schema, record_fingerprint, and schema_version; preserves insert_id; projects payload_refs -> object_refs
INSERT INTO `my-project.otel_v1.otel_logs` (
  timestamp, timestamp_source, time_unix_nano, observed_timestamp, observed_time_unix_nano,
  receive_time, receive_time_unix_nano, trace_id, span_id, flags,
  event_name, severity_number, severity_text, body, attributes, dropped_attributes_count,
  service_name, resource, resource_schema_url, instrumentation_scope, scope_schema_url,
  object_refs, log_name, insert_id
)
SELECT
  timestamp, timestamp_source, time_unix_nano, observed_timestamp, observed_time_unix_nano,
  receive_time, receive_time_unix_nano, trace_id, span_id, flags,
  event_name, severity_number, severity_text, body, attributes, dropped_attributes_count,
  service_name,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  ARRAY(SELECT AS STRUCT p.object_ref.uri AS uri, p.object_ref.version AS version, p.object_ref.authorizer AS authorizer, p.object_ref.details AS details FROM UNNEST(payload_refs) AS p WITH OFFSET AS pos WHERE p.object_ref.uri IS NOT NULL AND p.object_ref.uri != '' ORDER BY pos) AS object_refs,
  log_name,
  COALESCE(NULLIF(insert_id, ''), record_fingerprint) AS insert_id
FROM `my-project.otel_v0alpha2.otel_logs` AS otel_logs;

-- Metrics: drops *_schema and schema_version; preserves point_fingerprint and exemplars
INSERT INTO `my-project.otel_v1.otel_metrics` (
  timestamp, time_unix_nano, start_time, start_time_unix_nano, receive_time, receive_time_unix_nano,
  service_name, metric_name, metric_description, metric_unit, metric_type,
  aggregation_temporality, is_monotonic, flags, attributes, metric_metadata,
  value_type, value_double, value_int64, count, sum, min, max,
  explicit_bounds, bucket_counts, exp_scale, exp_zero_count, exp_zero_threshold,
  exp_positive, exp_negative, summary_quantiles, exemplars,
  resource, resource_schema_url, instrumentation_scope, scope_schema_url, point_fingerprint
)
SELECT
  timestamp, time_unix_nano, start_time, start_time_unix_nano, receive_time, receive_time_unix_nano,
  service_name, metric_name, metric_description, metric_unit, metric_type,
  aggregation_temporality, is_monotonic, flags, attributes, metric_metadata,
  value_type, value_double, value_int64, count, sum, min, max,
  explicit_bounds, bucket_counts, exp_scale, exp_zero_count, exp_zero_threshold,
  exp_positive, exp_negative, summary_quantiles,
  ARRAY(SELECT AS STRUCT ex.time, ex.time_unix_nano, ex.value_double, ex.value_int64, ex.span_id, ex.trace_id, ex.filtered_attributes FROM UNNEST(exemplars) AS ex WITH OFFSET AS pos ORDER BY pos) AS exemplars,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  point_fingerprint
FROM `my-project.otel_v0alpha2.otel_metrics` AS otel_metrics;

-- Quarantine: drops schema_version and guards the REQUIRED payload_ref.uri field
INSERT INTO `my-project.otel_v1.otel_quarantine` (
  ingest_time, signal, error_code, error_message, service_name, trace_id, span_id,
  raw_payload, raw_attributes, payload_ref, exporter_instance
)
SELECT
  ingest_time, signal, error_code, error_message, service_name, trace_id, span_id,
  raw_payload, raw_attributes,
  IF(payload_ref IS NOT NULL AND NULLIF(payload_ref.uri, '') IS NOT NULL, STRUCT(payload_ref.uri AS uri, payload_ref.version AS version, payload_ref.authorizer AS authorizer, payload_ref.details AS details), NULL) AS payload_ref,
  exporter_instance
FROM `my-project.otel_v0alpha2.otel_quarantine` AS otel_quarantine;
```

**Copy in windows.** `otel_spans` is partitioned by hour by default, and one
BigQuery job can modify at most 4,000 partitions, so a statement that copies
more than about 166 days of spans fails, as does one into an
`HOUR`-partitioned `otel_logs` or `otel_metrics`. Add a half-open window on the
partition column to each statement, for example
`WHERE start_time >= TIMESTAMP '2026-01-01' AND start_time < TIMESTAMP '2026-03-01'`
(`timestamp` for logs and metrics, `ingest_time` for quarantine), and run
consecutive windows.

**Lift the destination's partition expiration before copying old windows.**
BigQuery marks every partition older than a table's partition expiration as
expired as soon as a copy or insert writes to it, while actual deletion runs
asynchronously in the background: the statement succeeds, and a completeness or
row-count check run right after the copy can still see the rows and look
complete even though BigQuery will delete those expired partitions later. The
`v1` `otel_quarantine` table is created with `partition_expiration_days = 30`,
and you may have set a shorter expiration on other `v1` tables than on their
`v0alpha2` sources. Before you copy a window older than a destination's
expiration, raise or clear that expiration; setting it back later expires those
partitions again:

```sql
ALTER TABLE `my-project.otel_v1.otel_quarantine`
SET OPTIONS (partition_expiration_days = NULL);
```

**Bound the logs, metrics, and quarantine copies by how the collectors
moved.** Copy a `v0alpha2` row only if `v1` does not have the same record:
`v1` derives ID-less log `insert_id` values and metric `point_fingerprint`
values with different hashes, so `otel_logs_dedup` and `otel_metrics_dedup`
cannot collapse a record written to both datasets, and `otel_quarantine` has
no dedup view at all. Every row only `v0alpha2` has must be copied, or it is
lost when the `v0alpha2` dataset is dropped. Spans need no bound:
`otel_spans_dedup` collapses copies on `start_time`, `start_time_unix_nano`,
`service_name`, `trace_id`, `span_id`, and `name`, which both versions write
alike, so copy every span window in full.

Wait until the last `v0alpha2` writer has stopped (including queue drain and
in-flight retries), then, **before the first copy**, record when each service's
records started reaching `v1`, in a table that outlives the copy (in a dataset
of your own, here `otel_migration`; for quarantine, use `ingest_time` in place
of both `timestamp` and `receive_time`). Build this cutoff table once before any
historical window is copied and **do not rebuild it afterward**: once the first
historical window lands in `otel_v1`, `MIN(receive_time)` over `otel_v1` drops
to the backfilled window's oldest `receive_time`, so rebuilding the cutoff
table afterward would cause `receive_time >= c.cutoff` to skip remaining
historical windows. The `WHERE` clause keeps every row; it is there for a `v1`
table that requires a partition filter:

```sql
CREATE TABLE `my-project.otel_migration.v1_cutoffs_logs` AS
SELECT service_name, MIN(receive_time) AS cutoff
FROM `my-project.otel_v1.otel_logs`
WHERE timestamp >= TIMESTAMP '1970-01-01'
GROUP BY service_name;
```

Then append this filter to each window of the logs statement, which names its
source table `otel_logs`. It keeps a row unless the row's service was already
writing to `v1` when the row was received. Match `service_name` with equality
plus `IS NULL` rather than `IS NOT DISTINCT FROM` so BigQuery can plan
equality/hash joins while still keeping `NULL` and `''` apart. Do the same for
metrics and quarantine with cutoff tables of their own (`otel_metrics.receive_time`,
`otel_quarantine.ingest_time`):

```sql
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_migration.v1_cutoffs_logs` AS c
    WHERE (c.service_name = otel_logs.service_name OR (c.service_name IS NULL AND otel_logs.service_name IS NULL))
      AND otel_logs.receive_time >= c.cutoff
  )
```

- This assumes that from a service's first `v1` row on, `v1` received every
  record of that service: the collectors handling it switched at the same
  moment, or from then on they wrote each record to both datasets. During a
  rolling update or canary, old `v0alpha2` replicas keep running and draining
  their queues and in-flight retries after new `v1` replicas start. Because
  `receive_time` is set at transform time, rows an old replica drains after a
  new replica starts land past the new replica's start time: for example, if
  collector A switches at 12:00, some traffic is mirrored by 17:00, new
  collector B starts on `v1` at 18:00, and B's old `v0alpha2` replica drains a
  legacy-only row at 18:02 before exiting at 18:05, a cutoff at `18:00` skips
  the 18:02 row.
- Only keep a cutoff for a service if continuous mirrored coverage holds from
  that cutoff onward (every record of that service written to `v0alpha2` at or
  after the cutoff was also written to `v1`) **and** set the cutoff strictly
  after all legacy-only writes for that service have finished — including queue
  drain and in-flight retries — so no legacy-only row has
  `receive_time >= cutoff` (in the example above, `18:05:00 UTC` after all old
  replicas exit, provided continuous mirroring covered every replica past
  drain). Records written to both datasets before that cutoff appear twice in
  `v1`, while every legacy-only row is copied as long as the kept cutoff is
  strictly later than every legacy-only write:

  ```sql
  UPDATE `my-project.otel_migration.v1_cutoffs_logs`
  SET cutoff = TIMESTAMP '2026-03-02 18:05:00 UTC'
  WHERE service_name = 'checkout';
  ```

- Whenever continuous mirrored coverage cannot be shown, or during a standard
  non-mirrored rolling update, **delete that service's row from the cutoff
  table** so its full `v0alpha2` history is copied, accepting duplicates from
  any overlap window:

  ```sql
  DELETE FROM `my-project.otel_migration.v1_cutoffs_logs`
  WHERE service_name = 'checkout';
  ```

- The cutoff row of records without a service has a `NULL` `service_name`,
  which no `service_name = ...` comparison matches: update or delete it with
  `WHERE service_name IS NULL` instead. A `''` service name is a row of its
  own, which `service_name = ''` matches.

- If no record was ever written to both datasets, nothing can be counted
  twice: delete every row of the cutoff table, so the filter copies—and the
  completeness checks below verify—every `v0alpha2` row.
- Do not bound every service by the first `v1` row of the whole table. That is
  right only when all collectors switched at the same moment. In a staggered
  or canary cutover, collectors still on `v0alpha2` keep writing rows that
  never reach `v1`: if collector A switched at 12:00 and B wrote `v0alpha2`
  until 18:00, B's rows from 12:00 to 18:00 would match no window.
- An empty `v1` table, such as an `otel_quarantine` table that has not received
  a rejection yet, gives an empty cutoff table, and the filter copies every
  row. Comparing with `(SELECT MIN(receive_time) FROM ...)` directly does not
  work there: `MIN` over no rows is `NULL`, `receive_time < NULL` is never
  true, and the copy succeeds with zero rows.

**Check every window before dropping `v0alpha2`.** Run the record-identity
checks below for `otel_logs`, `otel_metrics`, and `otel_spans`, and the count
check for `otel_quarantine`, over the whole copied range with explicit
partition bounds inside every `FROM`, `NOT EXISTS`, and `UNION ALL` branch (for
tables with `require_partition_filter = true`). Drop `otel_v0alpha2` only when
every check returns zero rows.

For `otel_logs` and `otel_metrics`, these `NOT EXISTS` checks match each
below-cutoff `v0alpha2` row against `otel_v1` by its copied record identity, so
they verify that **every `v0alpha2` row selected for copying** landed in
`otel_v1` — even after a cutoff was moved forward or the cutoff table was
emptied (where a pure count check could be masked by native `v1` rows from
another collector in the same window). However, **no check keyed on the cutoff
table can prove a too-early cutoff right**, because a row excluded by a wrong
cutoff sits outside the below-cutoff set; keep each cutoff strictly later than
every legacy-only write (or delete that service's cutoff row).

```sql
-- Logs: list below-cutoff v0alpha2 records missing from otel_v1
SELECT DATE(l.timestamp) AS day, l.service_name, COUNT(*) AS missing_logs
FROM `my-project.otel_v0alpha2.otel_logs` AS l
WHERE l.timestamp >= TIMESTAMP '2026-01-01' AND l.timestamp < TIMESTAMP '2026-03-01'
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_migration.v1_cutoffs_logs` AS c
    WHERE (c.service_name = l.service_name OR (c.service_name IS NULL AND l.service_name IS NULL))
      AND l.receive_time >= c.cutoff
  )
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_v1.otel_logs` AS n
    WHERE n.timestamp >= TIMESTAMP '2026-01-01' AND n.timestamp < TIMESTAMP '2026-03-01'
      AND n.timestamp = l.timestamp
      AND n.time_unix_nano = l.time_unix_nano
      AND n.receive_time = l.receive_time
      AND n.receive_time_unix_nano = l.receive_time_unix_nano
      AND (n.service_name = l.service_name OR (n.service_name IS NULL AND l.service_name IS NULL))
      AND n.log_name = l.log_name
      AND (
        n.insert_id = COALESCE(NULLIF(l.insert_id, ''), l.record_fingerprint)
        OR (
          n.insert_id IS NULL
          AND COALESCE(NULLIF(l.insert_id, ''), l.record_fingerprint) IS NULL
        )
      )
  )
GROUP BY day, l.service_name
ORDER BY day, l.service_name;

-- Metrics: list below-cutoff v0alpha2 data points missing from otel_v1
SELECT DATE(m.timestamp) AS day, m.service_name, COUNT(*) AS missing_metrics
FROM `my-project.otel_v0alpha2.otel_metrics` AS m
WHERE m.timestamp >= TIMESTAMP '2026-01-01' AND m.timestamp < TIMESTAMP '2026-03-01'
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_migration.v1_cutoffs_metrics` AS c
    WHERE (c.service_name = m.service_name OR (c.service_name IS NULL AND m.service_name IS NULL))
      AND m.receive_time >= c.cutoff
  )
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_v1.otel_metrics` AS n
    WHERE n.timestamp >= TIMESTAMP '2026-01-01' AND n.timestamp < TIMESTAMP '2026-03-01'
      AND n.timestamp = m.timestamp
      AND n.time_unix_nano = m.time_unix_nano
      AND n.receive_time = m.receive_time
      AND n.receive_time_unix_nano = m.receive_time_unix_nano
      AND (n.service_name = m.service_name OR (n.service_name IS NULL AND m.service_name IS NULL))
      AND n.metric_name = m.metric_name
      AND n.point_fingerprint = m.point_fingerprint
  )
GROUP BY day, m.service_name
ORDER BY day, m.service_name;
```

`otel_quarantine` has no unique row ID or fingerprint column, so it uses a
per-day, per-service count check instead. This is a **lower-bound check only**:
it catches a copy that landed fewer `v1` rows than `v0alpha2` had below the
cutoff (or skipped more `v0alpha2` rows than `v1` received after the cutoff),
but it cannot detect missing copied rows if native `v1` quarantine rows for the
same service and day mask the shortfall.

```sql
-- Quarantine: lower-bound per-day, per-service count check
WITH rows_by_source AS (
  SELECT 'v0alpha2' AS source, service_name, ingest_time
  FROM `my-project.otel_v0alpha2.otel_quarantine`
  WHERE ingest_time >= TIMESTAMP '2026-01-01' AND ingest_time < TIMESTAMP '2026-03-01'
  UNION ALL
  SELECT 'v1' AS source, service_name, ingest_time
  FROM `my-project.otel_v1.otel_quarantine`
  WHERE ingest_time >= TIMESTAMP '2026-01-01' AND ingest_time < TIMESTAMP '2026-03-01'
)
SELECT
  DATE(r.ingest_time) AS day,
  r.service_name,
  COUNTIF(r.source = 'v0alpha2' AND (c.cutoff IS NULL OR r.ingest_time < c.cutoff)) AS v0alpha2_to_copy,
  COUNTIF(r.source = 'v1' AND (c.cutoff IS NULL OR r.ingest_time < c.cutoff)) AS v1_before_cutoff,
  COUNTIF(r.source = 'v0alpha2' AND r.ingest_time >= c.cutoff) AS v0alpha2_skipped,
  COUNTIF(r.source = 'v1' AND r.ingest_time >= c.cutoff) AS v1_after_cutoff
FROM rows_by_source AS r
LEFT JOIN `my-project.otel_migration.v1_cutoffs_quarantine` AS c
  ON (c.service_name = r.service_name OR (c.service_name IS NULL AND r.service_name IS NULL))
GROUP BY day, r.service_name
HAVING v1_before_cutoff < v0alpha2_to_copy OR v0alpha2_skipped > v1_after_cutoff
ORDER BY day, r.service_name;
```

For spans, list the `v0alpha2` spans that `v1` lacks, matched on the identity
that `otel_spans_dedup` uses:

```sql
SELECT DATE(s.start_time) AS day, COUNT(*) AS missing_spans
FROM `my-project.otel_v0alpha2.otel_spans` AS s
WHERE s.start_time >= TIMESTAMP '2026-01-01' AND s.start_time < TIMESTAMP '2026-03-01'
  AND NOT EXISTS (
    SELECT 1
    FROM `my-project.otel_v1.otel_spans` AS n
    WHERE n.start_time >= TIMESTAMP '2026-01-01' AND n.start_time < TIMESTAMP '2026-03-01'
      AND n.start_time = s.start_time
      AND n.start_time_unix_nano = s.start_time_unix_nano
      AND (n.service_name = s.service_name OR (n.service_name IS NULL AND s.service_name IS NULL))
      AND n.trace_id = s.trace_id
      AND n.span_id = s.span_id
      AND n.name = s.name
  )
GROUP BY day
ORDER BY day;
```

##### 4. Rollback runbook (14–30 day retention window)

1. Point collector deployments back to `dataset: otel_v0alpha2` and roll back the
   exporter binary/image to the `v0alpha2` release.
2. Repoint Dataform `vars.source_dataset` and dashboard queries to
   `otel_v0alpha2`.
3. Any telemetry written solely to `otel_v1` during the canary window can be
   replayed into `otel_v0alpha2` from GCS OTLP JSONL archives using the `v0alpha2`
   build of `bq-otel-backfill` (or queried directly in `otel_v1` during the soak
   period). Remove `prevent_destroy` and drop `otel_v0alpha2` only after the
   14–30 day retention window closes with zero rollback triggers and the window
   checks in step 3 of the SQL migration runbook return no rows for any table.
