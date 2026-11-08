# Operator Guides

This directory contains production runbooks for the four operator CLIs shipped with
the BigQuery OpenTelemetry Exporter, plus a deployment and migration guide covering
custom OCB and container builds today and upstream `otelcol-contrib` and standalone
`otelcol-google` distributions after Contrib Alpha.

## CLIs at a Glance

| CLI | Binary | Purpose |
|-----|--------|---------|
| `bq-quarantine-replay` | `cmd/bq-quarantine-replay` | Inspect, dry-run validate, and replay quarantined OTLP rows from the BigQuery dead-letter table back to an OTLP receiver. |
| `bq-otel-validate` | `cmd/bq-otel-validate` | Live BigQuery schema, view, IAM, and Storage Write API conformance checks for the exporter's tables. |
| `bq-otel-backfill` | `cmd/bq-otel-backfill` | Append historical OTLP JSONL files from Cloud Storage into the exporter's BigQuery tables with redaction and retry. |
| `bq-otel-testbench` | `cmd/bq-otel-testbench` | Synthetic OTLP load generation and BigQuery Storage Write stream sizing against a fake or live BigQuery sink. |

## Runbooks

- [Quarantine Replay and DLQ](quarantine-replay-and-dlq.md) — Dead-letter inspection, dry-run validation, bounded rate-limited replay, idempotent deduplication, and error triage.
- [Schema Validation and Backfill](schema-validation-and-backfill.md) — Live table/view/TVF schema conformance checks, partition/clustering verification, safe historical schema backfill and migration.
- [Load Testbench and Sizing](load-testbench-and-sizing.md) — Synthetic OTLP trace/log/metric/GenAI load generation, Storage Write stream sizing, memory/CPU envelope tuning.
- [OCB, Standalone otelcol-google, and Contrib Migration](ocb-otelcol-google-to-contrib-migration.md) — Deploying today with custom OCB builds or container templates, and migrating to upstream `otelcol-contrib` or standalone `otelcol-google` after Contrib Alpha.

## Operational Workflows

```
bq-otel-validate  →  (schema passes?)  →  deploy collector
                        ↓ no
                   fix table/view/TVF schema

collector running  →  (quarantine grows?)  →  bq-quarantine-replay  →  fix root cause
                        ↓ no
                   healthy pipeline

historical data  →  bq-otel-backfill  →  bq-otel-validate  →  done

capacity planning  →  bq-otel-testbench  →  tune stream_pool_size  →  deploy
```
