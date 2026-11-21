# Load Testbench and Sizing Runbook

The `bq-otel-testbench` CLI generates synthetic OTLP trace, log, metric, and
GenAI load and measures BigQuery Storage Write API throughput against a fake
in-memory sink (`bqfake`), a live BigQuery dataset (`live`), or an external
OpenTelemetry Collector subprocess (`collector`).

## Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `-mode` | string | `bqfake` | Sink mode: `bqfake`, `live`, or `collector` (drives an external Collector subprocess over OTLP gRPC into an in-process `bqfake` sink by default, or into BigQuery when `-collector-allow-live` is set). |
| `-collector-bin` | string | `""` | Path to built OpenTelemetry Collector binary (required when `-mode=collector`). |
| `-collector-config` | string | `example/otel-collector-high-volume-logs.yaml` | Base Collector YAML config file rewritten with loopback OTLP/metrics endpoints and `bigquery` exporter settings for `-mode=collector` (supports named signal pipelines such as `logs/access`, enforces a single pipeline and single `bigquery` exporter for the benchmarked signal, and isolates active `file_storage` extension `directory` and `compaction.directory` paths per run). |
| `-collector-allow-live` | bool | `false` | Allow `-mode=collector` to write to a live BigQuery dataset instead of the default in-process `bqfake` sink (carries the exporter's configured `endpoint` and `credentials` settings onto parent BigQuery dataset/storage REST calls; signals sharing an `-ephemeral-dataset` must agree on identity and endpoint settings). |
| `-signals` | string | `""` | Comma-separated OTLP signals to benchmark (defaults to `logs` when `-mode=collector` uses the default logs config and `-workload-profile` is unset, and otherwise defaults to `traces` for `genai-mixed` or `logs` for `access-logs`). |
| `-workload-profile` | string | `""` | Synthetic workload profile: `genai-mixed` or `access-logs` (trace-less HTTP/edge/VPC logs); defaults to `access-logs` when `-mode=collector` uses the default logs config and `-signals` is unset, and `genai-mixed` otherwise. |
| `-resource-attrs` | int | `0` | Number of resource attributes per `ResourceLogs` in `access-logs` profile (`0` defaults to `12` GKE/K8s metadata attributes; max `256`). |
| `-upstream-insert-id` | bool | `false` | Attach `logging.googleapis.com/insertId` to synthetic `access-logs` records. |
| `-rate` | int | `0` | Target records/sec per signal (0 = unthrottled max throughput). |
| `-duration` | duration | `0` | Steady-state benchmark duration per signal (`0` defaults to `2s`, or `60s` when `-soak` is set; must be `>= 60s` if set with `-soak`). |
| `-soak` | bool | `false` | Enable `>= 60s` steady-state soak preset with warmup discard to eliminate cold-start skew (rejects explicit `-duration < 60s`). |
| `-max-procs` | int | `0` | Optional `runtime.GOMAXPROCS` cap for CPU-bounded benchmarks (`0` = unchanged). |
| `-cpuprofile` | string | `""` | Optional file path to write Go pprof CPU profile. |
| `-memprofile` | string | `""` | Optional file path to write Go pprof heap memory profile. |
| `-batch-size` | int | `500` | Records per batch. |
| `-workers` | int | `4` | Concurrent producer workers. |
| `-stream-pool-size` | int | `0` | BigQuery Write API `stream_pool_size` (1..16; `0` = default `4` in `bqfake`/`live`, or inherits Collector YAML value in `-mode=collector`). |
| `-stream-pool-sweep` | string | `""` | Optional comma-separated `stream_pool_size` sweep (e.g. 1,2,4,8,16). |
| `-connection-pool-size` | int | `0` | BigQuery Write API gRPC `connection_pool_size` (1..16; `0` = default `4` in `bqfake`/`live`, or inherits Collector YAML value in `-mode=collector`). |
| `-max-inflight-requests` | int | `0` | Maximum in-flight AppendRows requests per stream (1..65536; `0` = default `32` in `bqfake`/`live`, or inherits Collector YAML value in `-mode=collector`). |
| `-max-request-bytes` | int | `0` | Maximum serialized ProtoRows payload bytes per request (`0` = default `8388608` in `bqfake`/`live`, or inherits Collector YAML value in `-mode=collector`). |
| `-compression` | string | `""` | Optional gRPC compressor (empty or `gzip`). |
| `-redaction` | bool | `false` | Enable Step-0 sensitive-data redaction and plant synthetic secrets. |
| `-plant-secrets` | bool | `false` | Plant synthetic secret attributes even when redaction is disabled. |
| `-backpressure` | bool | `false` | Enable AIMD adaptive write backpressure. |
| `-payload-bytes` | int | `0` | Synthetic payload byte length (`0` defaults to `1024` for `genai-mixed`, `128` for `access-logs`). |
| `-unique-payloads` | bool | `false` | Generate unique sequence prefixes per payload (disables dedup hits). |
| `-offload-dir` | string | `""` | Optional local directory sink to benchmark SHA-256 content-addressed offload (supported only in in-process `bqfake` or `live` modes; rejected in `collector` mode). |
| `-offload-gcs-bucket` | string | `""` | Optional GCS bucket name for native exporter payload offloading (requires `-mode=live` or `-mode=collector -collector-allow-live`). |
| `-offload-threshold-bytes` | int | `4096` | Byte threshold when `-offload-dir` or `-offload-gcs-bucket` is enabled. |
| `-simulate-ack-delay` | duration | `0` | Inject `FaultDelayedAck` into `bqfake` on batch 1 and every 3rd batch (supported in `bqfake` and non-live `collector` modes; rejected with `-mode=live` or `-collector-allow-live`). |
| `-simulate-throttle-every` | int | `0` | Inject `FaultResourceExhausted` into `bqfake` every N batches (supported in `bqfake` and non-live `collector` modes; rejected with `-mode=live` or `-collector-allow-live`). |
| `-call-timeout` | duration | `0` | Optional per-batch Consume* timeout override. |
| `-allow-partial-failures` | bool | `false` | Allow non-zero failed batches, rejected/quarantined/replayed rows, delivery shortfalls or surplus rows, collector warmup gate failures, and steady-state drain timeouts when at least one batch succeeds and at least one row is delivered/acknowledged (strict mode requires exact submitted-vs-delivered/acknowledged equality). |
| `-project` | string | `""` | GCP project ID (required when `-mode=live` or `-mode=collector -collector-allow-live`; defaults to loopback `bench-project` when `-mode=collector` without `-collector-allow-live`). |
| `-dataset` | string | `""` | BigQuery dataset ID (required when `-mode=live` or `-mode=collector -collector-allow-live` and `-ephemeral-dataset=false`; must be empty when `-ephemeral-dataset=true`; defaults to loopback `otel_bench` when `-mode=collector` without `-collector-allow-live`). |
| `-location` | string | `US` | BigQuery dataset location. |
| `-ephemeral-dataset` | bool | `false` | Auto-create a unique `otel_bench_<timestamp>_<random_hex>` dataset in live mode and delete it on teardown. |
| `-format` | string | `both` | Output format: markdown, json, or both. |
| `-json-out` | string | `""` | Optional file path to write JSON benchmark report. |

## Workflows

### Quick Local Benchmark (bqfake)

```bash
bq-otel-testbench \
  -mode=bqfake \
  -signals=traces,logs,metrics \
  -duration=10s \
  -batch-size=500 \
  -workers=8
```

### Stream Pool Sizing Sweep

```bash
bq-otel-testbench \
  -mode=bqfake \
  -stream-pool-sweep=1,2,4,8,16 \
  -duration=30s \
  -rate=10000
```

### Live BigQuery Benchmark with Ephemeral Dataset

```bash
bq-otel-testbench \
  -mode=live \
  -project=my-project \
  -ephemeral-dataset \
  -location=US \
  -signals=traces,logs,metrics \
  -duration=60s \
  -stream-pool-size=8 \
  -format=both \
  -json-out=/tmp/bench.json
```

### Simulating BigQuery Throttling

```bash
bq-otel-testbench \
  -mode=bqfake \
  -simulate-throttle-every=5 \
  -simulate-ack-delay=2s \
  -backpressure \
  -duration=30s
```

### Benchmarking with Redaction Overhead

```bash
bq-otel-testbench \
  -mode=bqfake \
  -redaction \
  -plant-secrets \
  -payload-bytes=4096 \
  -duration=20s
```

### Offload Performance

```bash
# Local directory offload
bq-otel-testbench \
  -mode=bqfake \
  -offload-dir=/tmp/offload \
  -offload-threshold-bytes=2048 \
  -duration=15s

# GCS offload (live mode)
bq-otel-testbench \
  -mode=live \
  -project=my-project \
  -ephemeral-dataset \
  -offload-gcs-bucket=my-offload-bucket \
  -offload-threshold-bytes=4096 \
  -duration=30s
```

### Access-Log Soak & CPU Profiling (`-workload-profile=access-logs`)

Use `-workload-profile=access-logs` with `-soak`, `-max-procs`, and `-cpuprofile`
to isolate steady-state access-log throughput, per-row field-family wire bytes,
and CPU hotspots:

```bash
bq-otel-testbench \
  -mode=bqfake \
  -workload-profile=access-logs \
  -resource-attrs=12 \
  -upstream-insert-id=false \
  -soak \
  -max-procs=4 \
  -batch-size=500 \
  -workers=4 \
  -cpuprofile=/tmp/access_logs_cpu.pprof \
  -memprofile=/tmp/access_logs_mem.pprof
```

### Full-Collector Trimming Pipeline Soak (`-mode=collector` / `NV-17`)

Use `./scripts/run_collector_soak.sh` (or `bq-otel-testbench -mode=collector` directly)
to measure whole-Collector CPU, RSS, and 5-layer wire byte reduction across
`receivers.otlp`, the `resource`/`attributes`/`transform` trimming processors,
`batch`, and `bigquery` against an in-process `bqfake` sink:

```bash
./scripts/run_collector_soak.sh

bq-otel-testbench \
  -mode=collector \
  -collector-bin=./otelcol-bq-dist/otelcol-bq \
  -collector-config=example/otel-collector-high-volume-logs.yaml \
  -workload-profile=access-logs \
  -resource-attrs=16 \
  -signals=logs \
  -soak \
  -duration=65s \
  -max-procs=4 \
  -batch-size=500 \
  -workers=4 \
  -stream-pool-size=8 \
  -connection-pool-size=8 \
  -max-inflight-requests=32 \
  -max-request-bytes=8388608
```

`./scripts/run_collector_soak.sh` rebuilds `./otelcol-bq-dist/otelcol-bq` from
current sources by default (set `REBUILD_COLLECTOR=0` to reuse an existing
binary). Prebuilt `access-logs` worker slots use a 12-record pod/status cycle
(`lcm(4 pods, 6 statuses) = 12` so small batch sizes down to `-batch-size=1`
emit `503`/`ERROR` records and all 3 pod services), canonical `seq % 12`
epoch restamping (preserving `(service_name, severity_number)` sequence alignment
at 1 Tier-1 bitmap chunk per `65,536` sequences across reused templates), and
pacer-locked prebuilt ordinal reservation alongside `batchRows` so concurrent
paced reservations preserve parent-child ordering. Unique-row tracking in
`bqfake` is enabled once per signal before any warmup phase and measured via
steady-state boundary deltas so steady-state replays of warmup rows are rejected
rather than counted as new deliveries; fault-simulated `-mode=collector` runs
preserve `-unique-payloads=false` payload bodies across `-simulate-ack-delay` and
`-simulate-throttle-every` comparisons and check estimated steady-state volume
against `MaxTrackedGeneratedRowsForSignal` and the `256 MiB` per-tracker exact-tag
byte budget (`DefaultMaxExactTagBytes`, `len(tag) + 16` bytes per entry):
untagged Tier-1 generated rows (`edge-` logs and spans) scale across `1,024`
`8 KiB` sequence-bitmap chunks (sparse below `512` slots per chunk) =
`67,108,864` sequence positions (`~66.5M–67.1M` rows in `<= 8 MiB` of dense
bitmap storage per table—for example `~66.5M` rows at `-batch-size=500` due to
`504`-sequence stride rounding minus any warmup chunk), exact-tagged Tier-1
generated rows (synthesized `id1:` logs when `-upstream-insert-id=false`, and
`metrics` `fp1:` rows) use sparse-to-dense chunks (sparse below `8,192` slots per
chunk, promoting to `[65536]string` = `1 MiB` header array + `8 KiB` bitmap per
dense chunk on 64-bit, up to `256` chunks / `16,777,216` bitmap positions = up
to `~258 MiB` of dense header/bitmap arrays) paired with `DefaultMaxExactTagBytes`
which bounds preflight capacity to `6,391,320` synthesized `id1:` log rows
(`42 B`/entry) and `3,195,660` `fp1:` metric rows (`84 B`/entry) unless capped
lower by a custom fake limit, and Tier-2, NULL-`insert_id` fallback, and
colliding multi-tag tracking is capped at `2,000,000` keys
(`DefaultMaxUniqueAckedRows`) per tracker, while dynamically paced
`-mode=collector` runs (`-rate` below batch-cap throughput) bypass prebuilt-pool
budget limits that are not allocated. When a run hits a strict drain timeout
(including when Collector shutdown subsequently fails or `-simulate-throttle-every`
fails to fire in either `bqfake` or `collector` mode), saturates `bqfake`
unique-row tracking at steady-state cutoff (setting `unique_delivery_verified:
false`), or violates the strict two-sided lossless delivery gate (strict runs
without fault simulation require `acknowledged_rows == records_submitted` with
`0` replays, strict fault-simulated runs with `unique_delivery_verified: true`
require `delivered_rows == records_submitted` and
`records_submitted <= acknowledged_rows <= delivered_rows + replayed_rows`, and
both in-process `bqfake` and `collector` warmups enforce matching raw-commit,
distinct-commit, and ack bounds), `bq-otel-testbench` still emits the
cutoff `SignalResult` (with `incomplete_drain: true` on drain timeouts)
alongside `-json-out`, `-memprofile`, and the formatted report before exiting
non-zero.

## 5-Layer Byte Accounting and Quota Math

### The 5 Byte Layers

Every sizing and TCO calculation separates five distinct byte layers:

1. **Source Content Bytes (`source_content_bytes_per_row`)**: Raw log/span/metric content bytes before OTLP protobuf framing or BigQuery row encoding.
2. **OTLP Wire Bytes (`otlp_bytes_per_row`)**: Serialized OTLP protobuf batch bytes divided by record count (`ResourceLogs`/`ScopeLogs` shared across the batch).
3. **Encoded `ProtoRows` Bytes (`proto_rows_bytes_per_row`)**: Serialized Storage Write API `ProtoRows` bytes per row (`otelcol_exporter_bigquery_append_bytes`), including per-row repeated `resource` and `instrumentation_scope` structs (sidecar-free under `v1.0.0`). This is the **Storage Write API billing and throughput quota basis**. In benchmark reports, `wire_mb_per_sec` (`Encoded-Row MiB/s`) measures acknowledged single-attempt `ProtoRows` bytes per second (`bytes_per_row * delivered_rows / elapsed_seconds`) rather than retry-inflated `otelcol_exporter_bigquery_append_bytes` across attempts; in live Collector runs (`-mode=collector -collector-allow-live`), `bytes_per_row_unavailable` is `true` and `wire_mb_per_sec` is `0` (rendered as `unavailable` in Markdown) whenever retries, send failures, partial delivery/rejections, or a missing/zero `otelcol_exporter_bigquery_append_bytes` metric prevent measuring single-attempt bytes (and `INFORMATION_SCHEMA.TABLE_STORAGE` REST queries are skipped when a custom writer `endpoint.url` or `endpoint.without_authentication` omits `endpoint.admin_url`).
4. **BigQuery Logical Bytes (`bq_logical_bytes_per_row`)**: Uncompressed column storage reported by `INFORMATION_SCHEMA.TABLE_STORAGE.total_logical_bytes` in `-mode=live`. Governs logical storage billing and the search-index free management cap (`20 TB` single-region / `100 TB` `US`/`EU`).
5. **BigQuery Physical Bytes (`bq_physical_bytes_per_row`)**: Capacitor compressed storage reported by `INFORMATION_SCHEMA.TABLE_STORAGE` in `-mode=live`: current-row physical footprint (`max(active_physical_bytes - time_travel_physical_bytes, 0) + long_term_physical_bytes`), plus `time_travel_physical_bytes` (7-day time-travel, included inside `active_physical_bytes`) and `fail_safe_physical_bytes` (7-day fail-safe billed under `PHYSICAL` billing).

> **Latency Metrics in `-mode=collector`**: `latency` (`p50_ms`, `p95_ms`, `p99_ms`) measures client-to-Collector OTLP gRPC export round-trip latency, whereas Storage Write API `AppendRows` append-ack latency is reported in `telemetry.append_result_wait_mean_ms`.

### High-Volume Rate & Storage Write API Quota Reference

- **Decimal rate equivalence**: `20 decimal TB/day = 231.5 MB/s (231.48 MB/s) = 600 TB/month` (30d), whereas `300 MB/s = 25.92 TB/day = 777.6 TB/month` (`750 TB/month = 25 TB/day = 289.35 MB/s`).
- **Regional vs. multi-region Write API throughput quota**: The default Storage Write API throughput quota is **`300 MB/s` in single regions** (`231.5 MB/s` fits within default headroom; `300 MB/s` equals the cap) and **`3 GB/s` in `US` and `EU` multi-regions** (`300 MB/s` is `10%` of the multi-region default).
- **Quota scoping**: Throughput quota is enforced against the **destination project** (where the BigQuery tables live), whereas concurrent connection quota is enforced against the **client project** (`credentials.quota_project` or ADC project).
- **gRPC `gzip` compression (`-compression=gzip`)**: Compresses bytes on the network transport only; it does **not** reduce billed Storage Write API ingestion bytes or throughput quota consumption.
- **`AppendRows` per-request limit (`NV-20`)**: Live BigQuery `_default` stream testing verified a **`20 MB`** request ceiling (`11.30 MiB` accepted; `20.10 MiB` rejected with `InvalidArgument`), while the exporter enforces a conservative **`10 MB`** (`10,000,000 B`) ceiling (`write.max_request_bytes` default `8 MiB`) to keep `2x` framing headroom.
- **Day-1 `BACKGROUND` slot reservation (`ADR-15`)**: BigQuery manages search indexes without extra slot charges only up to `20 TB` (single-region) or `100 TB` (`US`/`EU`) org-wide logical base-table size. At `20 TB/day`, single-region search-indexed tables require a **`BACKGROUND` reservation on Day 1**.

### Collector Pod Sizing, Safe HPA, & Persistent Queue Scale-Down Discipline (`ADR-19`)

- **Exporter CPU vs. Collector pod fleet (`NV-17`)**:
  - **Standalone Collector soak (`-mode=collector`)**: In the `67.23s` `GOMAXPROCS=4` `-resource-attrs=16` `otelcol-bq` (`./otelcol-bq-dist/otelcol-bq` built via `example/otelcol-builder.yaml`) full-pipeline loopback soak (`./scripts/run_collector_soak.sh` with `example/otel-collector-high-volume-logs.yaml` against `bqfake`), the standalone Collector sustained **`85,666.31 rows/s`** at **`0.44` whole-Collector CPU cores per `10,000 rows/s`** (`3.77` cores, `94.3%` of `GOMAXPROCS=4`) and **`371.54 MiB` peak RSS** (`592.72 B/row` inbound OTLP -> `925.80 B/row` trimmed `ProtoRows`, `-38.9%` vs. `1,515.79 B/row` untrimmed at `70,211.39 rows/s` / `0.50` cores per `10,000 rows/s`).
  - **Single-process `bqfake` soak (`-mode=bqfake`)**: Under `GOMAXPROCS=4` (`-soak`, measured at commit `6ff4c96`, `60.64s` / `60.08s`, `-stream-pool-size=8`, `-connection-pool-size=8`, `unique_delivery_verified: true`), `mode=bqfake` sustained **`27,291.66 rows/s`** (`1,033.97 B/row` at `-resource-attrs=8`, **`1.18` cores per `10,000 rows/s`**, `973.04 MiB` peak RSS / `610.45 MiB` heap snapshot, `60.64s`) and **`27,539.28 rows/s`** (`1,514.97 B/row` at `-resource-attrs=16`, **`1.14` cores per `10,000 rows/s`**, `995.49 MiB` peak RSS / `683.35 MiB` heap snapshot, `60.08s`). Single-process `mode=bqfake`'s CPU and peak RSS include `NewGenerator` batch construction, client-side `ResolveLogInsertIDs` reconciliation (`SubmittedKeySet`), and the in-process `bqfake` exact-string `insert_id` verification trackers alongside `bigqueryexporter`, whereas `mode=live` measures combined in-process load generator (producer) + `bigqueryexporter` CPU and RSS without an in-process fake server, and isolated `mode=collector` isolates standalone Collector CPU and RSS for production fleet sizing.
  - **Single-process live BigQuery (`-mode=live`, combined producer + exporter)**: Current-code `protowire` live `US` `access-logs` runs (`-ephemeral-dataset=true`, `GOMAXPROCS=24`, `-workers=8`, `-stream-pool-size=8`, `-connection-pool-size=8`, `20s` [`20.05s` / `20.09s`], `ephemeral_dataset_deleted: true`) sustained **`45,767.57`–`46,547.25 rows/s`** at **`0.55`–`0.57` combined in-process load generator (producer) + exporter CPU cores per `10,000 rows/s`** and **`92.79`–`107.32 MiB` combined process peak RSS** (`0.57` combined cores / `92.79 MiB` peak RSS at `-resource-attrs=8`, `1,034.80 B/row`, `45,767.57 rows/s`, `20.05s`; `0.55` combined cores / `107.32 MiB` peak RSS at `-resource-attrs=16`, `1,515.79 B/row`, `46,547.25 rows/s`, `20.09s`), replacing the older pre-`protowire` `1.24–1.66` `genai-mixed` combined producer + exporter figure. Because `-mode=live` samples both `NewGenerator` (load producer) and `bigqueryexporter` in one PID, treat these as combined producer + exporter measurements rather than standalone exporter figures so Collector fleets are not over-sized.
  - **Fleet sizing rule of thumb**: Combining `0.44–0.50` standalone Collector loopback CPU with live TLS/WAN `AppendRows` headroom yields **`~0.60–0.70` active whole-Collector CPU cores per `10,000 rows/s`** — **`~8–14` active CPU cores** (**`~12–22` provisioned vCPU** at `65%` HPA target CPU utilization) at `300 MB/s` (`1,500–2,400 B/row` = `125,000–200,000 rows/s`), or **`~15.0–17.5` active CPU cores** (**`~23–27` provisioned vCPU** at `65%` HPA target CPU utilization, e.g., `6–14` pods × `2–4` vCPU) at `20 TB/day` (`231.5 MB/s`) on trimmed access logs (`925.80 B/row` = `~250,000 rows/s` [`250,034 rows/s`]).
- **Safe autoscaling rules (`deploy/helm/bigquery-otel-collector/templates/hpa.yaml`, `values-high-volume-logs.yaml`)**:
  - Keep `sending_queue.sizer: requests` with `queue_size: 10000` (so single batches above 10,000 records take `1` slot and are never rejected on an empty queue, while 10,000 request slots cover the 900s retry horizon) and enable `sending_queue.batch` explicitly (off by default in the exporter, with `sizer: items`, explicit `min_size: 0`, and `sending_queue.batch.max_size: 0` when `logs.synthesize_insert_id: true` so pre-transform splits do not reset intra-batch `insert_id` ordinals), `write.stream_pool_size: 8`, `write.backpressure.enabled: true`, and a capped `maxReplicas`.
  - Scale HPA/KEDA **strictly** on pod CPU utilization, admitted input rate (via a metrics adapter applying `rate()` over the cumulative counter `otelcol_receiver_accepted_log_records`; see [`deploy/README.md`](../../deploy/README.md)), and/or `sending_queue` depth (`otelcol_exporter_queue_size`, measured in `sending_queue.sizer` units — `requests` by default and in `values-high-volume-logs.yaml`, where `targetAverageValue: "500"` is 500 requests). Note that `exporterhelper` `v0.165.0` does **not** emit a queue oldest-item age metric.
  - **NEVER scale on `otelcol_exporter_bigquery_backpressure_level`**: it is disabled by default and rises on BigQuery destination congestion or quota exhaustion, so scaling out adds concurrent writers against the same bottleneck (`templates/hpa.yaml` fails template rendering if any metric name contains `backpressure_level`). Wire `backpressure_level` and quota warnings strictly as alerts.
- **Per-pod PVC, persistent-queue, and stateless scale-down discipline**:
  - Multi-replica autoscaled deployments with durable queues must use `persistentQueue.enabled: true` (`StatefulSet` with per-pod `volumeClaimTemplates`) rather than sharing a single `ReadWriteOnce` PVC (`persistence.enabled: true` is restricted to single-replica `Deployment`s with `strategy.type: Recreate` and is rejected when combined with `autoscaling.enabled: true` or `replicaCount > 1`).
  - Because `exporterhelper` `v0.165.0` persistent bbolt queues stop reading immediately on pod `Shutdown` rather than draining during `terminationGracePeriodSeconds` (which bounds in-flight `AppendRows` completion), `templates/hpa.yaml` enforces `behavior.scaleDown.selectPolicy: Disabled` when `persistentQueue.enabled: true`. Scale down `StatefulSet` ordinals manually only after confirming `otelcol_exporter_queue_size == 0` so unread items are never stranded on a removed ordinal's PVC. In stateless mode (`persistentQueue.enabled: false`), automatic scale-in drains in-memory queues only up to `terminationGracePeriodSeconds` and drops remaining in-memory items if a destination outage exceeds that window; set `autoscaling.behavior.scaleDown.selectPolicy: Disabled` or enable `persistentQueue.enabled: true` if zero-drop scale-in protection during outages is required.

## Verified 1 TiB/day High-Volume CUJ Benchmark Sweep (v0.0.2)

The following 4 profiles were measured on a 24-vCPU `linux/amd64` host with
`go1.26.8` in `bqfake` mode (no GCP credentials required). All profiles exceed
the 1 TiB/day sustained Storage Write throughput target.

### Profile Summary

| Profile | Combined MiB/s | Projected GiB/day | Projected TiB/day | Exceeds 1 TiB/day? |
|---|---:|---:|---:|---|
| P1: Traces (1 KiB payload, no redaction) | 45.87 | 3,963 | **3.87** | 3.87x |
| P2: Logs (1 KiB payload, no redaction) | 36.18 | 3,127 | **3.05** | 3.05x |
| P3: Metrics (1 KiB payload, no redaction) | 21.31 | 1,841 | **1.80** | 1.80x |
| P4: GenAI CUJ (32 KiB payload, redaction + offload) | 17.15 | 1,482 | **1.45** | 1.45x |

### P1: High-Throughput Traces

```bash
GOTOOLCHAIN=local go run ./cmd/bq-otel-testbench \
  --mode=bqfake --signals=traces --duration=3s --batch-size=500 \
  --workers=8 --stream-pool-size=8 --payload-bytes=1024 --format=markdown
```

| Signal | Stream Pool | Achieved Rows/s | Encoded-Row MiB/s | Bytes/Row | p50 (ms) | p95 (ms) | p99 (ms) | CPU Cores / 10k rows/s | Heap Alloc (MiB) | Peak RSS (MiB) | Acked | Rejected | Failed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `traces` | 8 | 16,620.7 | 45.87 | 2,894 | 231.97 | 309.71 | 349.35 | 4.79 | 470.95 | 611.0 | 52,000 | 0 | 0 |

**Projected sustained rate**: 45.87 MiB/s = 3,963 GiB/day (3.87 TiB/day) -- exceeds 1 TiB/day by 3.87x.

### P2: High-Throughput Logs

```bash
GOTOOLCHAIN=local go run ./cmd/bq-otel-testbench \
  --mode=bqfake --signals=logs --duration=3s --batch-size=500 \
  --workers=8 --stream-pool-size=8 --payload-bytes=1024 --format=markdown
```

| Signal | Stream Pool | Achieved Rows/s | Encoded-Row MiB/s | Bytes/Row | p50 (ms) | p95 (ms) | p99 (ms) | CPU Cores / 10k rows/s | Heap Alloc (MiB) | Peak RSS (MiB) | Acked | Rejected | Failed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `logs` | 8 | 15,910.7 | 36.18 | 2,384 | 232.72 | 342.67 | 361.59 | 4.80 | 381.80 | 480.2 | 49,500 | 0 | 0 |

**Projected sustained rate**: 36.18 MiB/s = 3,127 GiB/day (3.05 TiB/day) -- exceeds 1 TiB/day by 3.05x.

### P3: High-Throughput Metrics

```bash
GOTOOLCHAIN=local go run ./cmd/bq-otel-testbench \
  --mode=bqfake --signals=metrics --duration=3s --batch-size=500 \
  --workers=8 --stream-pool-size=8 --payload-bytes=1024 --format=markdown
```

| Signal | Stream Pool | Achieved Rows/s | Encoded-Row MiB/s | Bytes/Row | p50 (ms) | p95 (ms) | p99 (ms) | CPU Cores / 10k rows/s | Heap Alloc (MiB) | Peak RSS (MiB) | Acked | Rejected | Failed |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `metrics` | 8 | 17,845.2 | 21.31 | 1,252 | 216.19 | 274.72 | 285.99 | 4.81 | 305.82 | 522.7 | 57,000 | 0 | 0 |

**Projected sustained rate**: 21.31 MiB/s = 1,841 GiB/day (1.80 TiB/day) -- exceeds 1 TiB/day by 1.80x.

### P4: GenAI Agent Telemetry CUJ (32 KiB payloads, redaction + offload)

```bash
mkdir -p /tmp/t6-offload && \
GOTOOLCHAIN=local go run ./cmd/bq-otel-testbench \
  --mode=bqfake --signals=traces,logs,metrics --duration=3s --batch-size=500 \
  --workers=8 --stream-pool-size=8 --payload-bytes=32768 \
  --redaction --offload-dir=/tmp/t6-offload --offload-threshold-bytes=8192 \
  --format=markdown
```

| Signal | Stream Pool | Redaction | Achieved Rows/s | Encoded-Row MiB/s | Bytes/Row | p50 (ms) | p95 (ms) | p99 (ms) | CPU Cores / 10k rows/s | Heap Alloc (MiB) | Peak RSS (MiB) | Acked | Rejected | Failed | Redacted |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `traces` | 8 | true | 969.0 | 1.85 | 1,997 | 2,972.61 | 3,738.52 | 3,971.58 | 62.27 | 121.64 | 193.9 | 5,500 | 0 | 0 | 2,750 |
| `logs` | 8 | true | 859.8 | 1.22 | 1,486 | 4,327.71 | 4,633.98 | 4,648.20 | 75.34 | 72.17 | 194.1 | 4,000 | 0 | 0 | 2,000 |
| `metrics` | 8 | true | 11,474.6 | 14.08 | 1,287 | 319.27 | 580.02 | 635.11 | 5.37 | 238.83 | 367.7 | 37,000 | 0 | 0 | 18,500 |

**Projected combined sustained rate** (all 3 signals): 17.15 MiB/s = 1,482 GiB/day (1.45 TiB/day) -- exceeds 1 TiB/day by 1.45x even with 32 KiB payloads, redaction enabled, and offload active.

**Redaction effectiveness**: 23,250 synthetic secrets redacted across traces/logs/metrics. Zero rejected rows, zero batch failures.

### Conclusion

The exporter sustains >=1 TiB/day across all 4 profiles, including the worst-case GenAI CUJ profile with 32 KiB payloads, redaction, and GCS offload enabled. The 1 TiB/day target = ~12.1 MB/sec sustained Storage Write throughput; the measured minimum (Profile 4 combined) is 17.15 MB/sec, providing 1.42x headroom above the target.
