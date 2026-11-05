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
