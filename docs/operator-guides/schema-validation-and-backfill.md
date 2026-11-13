# Schema Validation and Backfill Runbook

This guide covers two CLIs: `bq-otel-validate` for live schema conformance
checks and `bq-otel-backfill` for safe historical data append from Cloud
Storage.

## bq-otel-validate

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-project` | string | `""` | BigQuery project that holds `-dataset`; the view dry runs run as query jobs in it (required). |
| `-dataset` | string | `""` | BigQuery dataset the exporter writes to (required). |
| `-location` | string | `""` | BigQuery dataset and dry-run query job location (auto-detected from dataset metadata when empty). |
| `-signals` | string | `traces,logs,metrics` | Comma-separated signals whose tables and companion views are checked: traces, logs, metrics. |
| `-quarantine` | bool | `true` | Check the quarantine table (`-quarantine=false` when the deployment does not enable quarantine). |
| `-traces-table` | string | `otel_spans` | Span table (the exporter's `traces.table`). |
| `-logs-table` | string | `otel_logs` | Log table (the exporter's `logs.table`). |
| `-metrics-table` | string | `otel_metrics` | Metric table (the exporter's `metrics.table`). |
| `-quarantine-table` | string | `otel_quarantine` | Quarantine table (the exporter's `quarantine.table`). |
| `-checks` | string | `schema,views,iam,storage-write` | Comma-separated checks to run: schema, views, iam, storage-write. |
| `-format` | string | `text` | Report format: text or json. |
| `-timeout` | duration | `5m` | Time limit for the whole run. |
| `-probe-timeout` | duration | (default) | Time limit for the Storage Write API reachability probe. |

### Validating After Deploy

```bash
bq-otel-validate \
  -project=my-project \
  -dataset=otel
```

### JSON Report for CI

```bash
bq-otel-validate \
  -project=my-project \
  -dataset=otel \
  -format=json \
  -checks=schema,views
```

### Skipping Quarantine Check

```bash
bq-otel-validate \
  -project=my-project \
  -dataset=otel \
  -quarantine=false
```

### Custom Partitioning and Clustering (`auto_create.tables: false`)

`bq-otel-validate` accepts custom table layouts that remain compatible with the
exporter's ingestion contract:

- **`WARN` (`exit 0`, conformant)**: Alternative compatible partition granularity
  (`HOUR` vs `DAY`) on the canonical partitioning column (`timestamp` for logs
  and metrics, `start_time` for spans), or custom `CLUSTER BY` columns (or no
  clustering).
- **`FAIL` (`exit 1`, non-conformant)**: Missing `TimePartitioning`, wrong
  partitioning column (such as `_PARTITIONTIME` or `receive_time` instead of
  `timestamp`), or incompatible column schema.

For high-volume log workloads that require `HOUR` partitioning or custom log
clustering today, pre-create the table and run the exporter with
`auto_create.tables: false`:

```sql
CREATE TABLE IF NOT EXISTS `my-project.otel.otel_logs` (
  -- Copy the canonical column definitions from internal/schema LogsDDL
  timestamp TIMESTAMP NOT NULL,
  ...
)
PARTITION BY TIMESTAMP_TRUNC(timestamp, HOUR)
CLUSTER BY log_name, service_name;
```

```yaml
exporters:
  bigquery:
    project: my-project
    dataset: otel
    auto_create:
      dataset: false
      tables: false
```

When `auto_create.tables` is `false`:
1. **Operator owns DDL & views**: You are responsible for creating and
   maintaining the destination tables, `*_dedup` views, companion views, and
   search indexes (ensure any custom `CLUSTER BY` columns also appear in your
   `*_dedup` window if queries read through the dedup view).
2. **`transformprocessor` cannot populate extra promoted columns**: The
   exporter's protobuf encoder derives a fixed descriptor from the destination
   table schema and populates only the canonical columns built by
   `internal/transform`. Extra `NULLABLE` columns added to a pre-created table
   always remain `NULL` on ingested rows (while `int64` values inside the
   `attributes` `JSON` column are encoded as decimal strings).

## bq-otel-backfill

### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-source-gcs-prefix` | string | `""` | `gs://bucket/prefix` whose `.jsonl` and `.jsonl.gz` objects are appended; end it with `/` to select one folder (required). |
| `-project` | string | `""` | BigQuery project that holds `-dataset` (required). |
| `-dataset` | string | `""` | BigQuery dataset the exporter writes to (required). |
| `-signal` | string | `auto` | Signal to append: traces, logs, metrics, or auto for every signal found. |
| `-batch-size` | int | (default) | Rows per append. |
| `-max-workers` | int | (default) | Objects read and appended at once. |
| `-traces-table` | string | `otel_spans` | Span table (the exporter's `traces.table`). |
| `-logs-table` | string | `otel_logs` | Log table (the exporter's `logs.table`). |
| `-metrics-table` | string | `otel_metrics` | Metric table (the exporter's `metrics.table`). |
| `-redact` | bool | `false` | Enable client-side redaction (the exporter's `redaction.enabled`); when omitted, enabled implicitly if any other `-redact-*` flag is set. |
| `-redact-keys` | string | `""` | Comma-separated attribute keys masked in addition to the defaults (the exporter's `redaction.blocked_keys`). |
| `-redact-disable-default-keys` | bool | `false` | Disable the built-in blocked key list so only `-redact-keys` apply (the exporter's `redaction.disable_default_keys`). |
| `-redact-mask-replacement` | string | `""` | Replacement text for redacted values (the exporter's `redaction.mask_replacement`; defaults to `[REDACTED]`). |
| `-redact-log-body` | bool | `false` | Apply the value patterns to log bodies (the exporter's `redaction.redact_log_body`). |
| `-redact-value-pattern` | string (repeatable) | `""` | RE2 expression whose matches are masked inside string values (the exporter's `redaction.blocked_value_patterns`); repeat for more. |
| `-log-name-attribute` | string | `""` | The exporter's `logs.log_name_attribute`. |
| `-insert-id-attribute` | string | `""` | The exporter's `logs.insert_id_attribute`. |
| `-max-attempts` | int | (default) | Attempts at one append or one Cloud Storage request before the object fails. |
| `-max-line-bytes` | int | (default) | Longest line read; a longer line is reported and skipped. |
| `-format` | string | `text` | Report format: text or json. |
| `-progress` | bool | `true` | Print a line to stderr as each object finishes. |

### Backfilling from Cloud Storage

```bash
bq-otel-backfill \
  -source-gcs-prefix=gs://my-bucket/historical-otlp/ \
  -project=my-project \
  -dataset=otel \
  -signal=auto \
  -batch-size=500 \
  -max-workers=8
```

### Backfill with Redaction

```bash
bq-otel-backfill \
  -source-gcs-prefix=gs://my-bucket/historical-otlp/ \
  -project=my-project \
  -dataset=otel \
  -redact \
  -redact-keys=ssn,credit_card,api_key \
  -redact-value-pattern='\\b\\d{4}\\d{4}\\d{4}\\d{4}\\b' \
  -redact-log-body
```

### Backfill with Custom Log Name and Insert ID

```bash
bq-otel-backfill \
  -source-gcs-prefix=gs://my-bucket/historical-otlp/ \
  -project=my-project \
  -dataset=otel \
  -signal=logs \
  -log-name-attribute=logger.name \
  -insert-id-attribute=event_id
```
