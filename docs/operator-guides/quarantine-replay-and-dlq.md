# Quarantine Replay and DLQ Runbook

The `bq-quarantine-replay` CLI reads quarantined rows from the BigQuery
`otel_quarantine` table (or a JSONL/JSON array file export), filters them by
signal, error code, and time window, reconstructs OTLP traces, logs, and
metrics, and writes replayed OTLP JSON envelopes to a file or sends them to an
OTLP/HTTP receiver.

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-input` | string | `-` | Path to quarantine JSONL or JSON array file (`-` for stdin). |
| `-output` | string | `-` | Path to write replayed OTLP JSONL (`-` for stdout). |
| `-signal` | string | `""` | Optional comma-separated signal filter (`spans`, `logs`, `metrics`). |
| `-error-code` | string | `""` | Optional comma-separated error_code filter (e.g. `OVERSIZE_ROW,ROW_ERROR`). |
| `-since` | string | `""` | Optional inclusive lower bound on ingest_time (RFC3339). |
| `-until` | string | `""` | Optional inclusive upper bound on ingest_time (RFC3339). |
| `-fetch-gcs` | bool | `false` | Fetch offloaded `payload_ref` objects from `gs://` when `raw_payload` is empty. |
| `-dry-run` | bool | `false` | Validate and count matching records without emitting output. |
| `-bq-project` | string | `""` | Read rows straight from BigQuery instead of `-input`: the project that holds `-bq-dataset` and runs the query job. |
| `-bq-dataset` | string | `""` | BigQuery dataset that holds the quarantine table (with `-bq-project`). |
| `-bq-table` | string | `otel_quarantine` | BigQuery quarantine table (with `-bq-project` and `-bq-dataset`). |
| `-otlp-endpoint` | string | `""` | Send replayed batches to this OTLP/HTTP receiver instead of `-output`, e.g. `http://localhost:4318`. |
| `-rate-limit` | float64 | `0` | Maximum records replayed per second (0 means no limit). |
| `-checkpoint-file` | string | `""` | File that records the run's progress; a rerun with the same file, source, and filters resumes after the last handled record. |

## Workflows

### Inspecting the DLQ

```bash
# Dry-run count of all quarantined rows in the last 24 hours
bq-quarantine-replay \
  -bq-project=my-project \
  -bq-dataset=otel \
  -dry-run \
  -since=$(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%SZ)
```

### Replaying to a File

```bash
bq-quarantine-replay \
  -bq-project=my-project \
  -bq-dataset=otel \
  -signal=spans \
  -error-code=OVERSIZE_ROW \
  -output=/tmp/replay.jsonl \
  -rate-limit=100
```

### Replaying to an OTLP Receiver

```bash
bq-quarantine-replay \
  -bq-project=my-project \
  -bq-dataset=otel \
  -otlp-endpoint=http://localhost:4318 \
  -rate-limit=200 \
  -checkpoint-file=/tmp/replay.ckpt
```

### Resuming a Crashed Run

```bash
# Rerun with the same -checkpoint-file to resume from the last handled record
bq-quarantine-replay \
  -bq-project=my-project \
  -bq-dataset=otel \
  -otlp-endpoint=http://localhost:4318 \
  -checkpoint-file=/tmp/replay.ckpt
```

### Fetching Offloaded Payloads

When `raw_payload` is empty and `payload_ref` points to a GCS object, use
`-fetch-gcs` to download the original payload:

```bash
bq-quarantine-replay \
  -bq-project=my-project \
  -bq-dataset=otel \
  -fetch-gcs \
  -output=/tmp/replay.jsonl
```

## Error Triage

| Error code | Meaning | Suggested action |
|------------|---------|------------------|
| `OVERSIZE_ROW` | Row exceeded BigQuery 10 MB limit | Enable `offload.cache_size` or reduce batch size |
| `ROW_ERROR` | Schema mismatch or invalid encoding | Run `bq-otel-validate` to check schema conformance |
| `QUOTA_EXCEEDED` | BigQuery write quota exhausted | Reduce `-rate-limit` or request quota increase |
