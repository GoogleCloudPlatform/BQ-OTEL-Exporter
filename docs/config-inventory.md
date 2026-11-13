# Configuration inventory

This page lists every configuration key the BigQuery exporter accepts, with
its Go type, the default that `createDefaultConfig()` assigns, the release
that introduced it, and its stability class. It is the inventory that the
Collector's
[component stability rules](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#beta)
ask a beta component to have, and `config_inventory_test.go` keeps it honest:
the key set, types and defaults below are compared with the `Config` struct
and its defaults on every test run, and a key cannot leave `Config` without a
deprecation entry and a section in [`docs/migration.md`](migration.md).

The exporter declares **93 keys**: 80 stable and **13 experimental**. Keys
added after `v0.0.1` record the release that introduced them; the per-key
history before tagging is in `git log -S` over `config.go`.

## Reading the table

- **Key** is the dotted path under the `bigquery` exporter block, so
  `write.stream_pool_size` is

  ```yaml
  exporters:
    bigquery:
      write:
        stream_pool_size: 4
  ```

- **Type** is the Go type of the field. Durations accept Go duration strings
  (`10s`, `2m`); `configopaque.String` is a string that the collector masks
  when it prints the configuration.
- **Default** is the value when the key is absent. `unset` is a nil map or
  slice (no entries); `""` is the empty string, which for most keys means
  "not configured". `see notes` marks a block whose keys and defaults belong
  to an upstream Collector package.
- **Since** is the first tagged release that accepted the key.
- **Stability** is one of:
  - `stable`: the key keeps its meaning and its default within the beta line.
    A rename or removal goes through the deprecation mechanism described in
    [`docs/migration.md`](migration.md#configuration-keys): the old key keeps
    working with a startup `WARN` for at least one more release and is
    removed no earlier than two releases and six months later.
  - `experimental`: a write-path tuning knob. Its default or bounds may be
    retuned in any release, with a `CHANGELOG.md` entry; its name still
    follows the deprecation path above if it is renamed or removed.

## Keys

| Key | Type | Default | Since | Stability | Notes |
| --- | --- | --- | --- | --- | --- |
| `timeout` | `time.Duration` | `5s` | v0.0.1 | stable | Upstream `exporterhelper` timeout for every startup and export attempt; must be positive. |
| `sending_queue` | `configoptional.Optional[queuebatch.Config]` | `see notes` | v0.0.1 | stable | Upstream `exporterhelper` queue; enabled with upstream defaults except `num_consumers`, which this exporter sets to `8` to match `write.max_inflight_requests`. |
| `retry_on_failure` | `configretry.BackOffConfig` | `see notes` | v0.0.1 | stable | Upstream `configretry` backoff; enabled with upstream defaults except `max_elapsed_time`, which this exporter sets to `900s` (15m) so a ten-minute outage does not expire queued data. |
| `project` | `string` | `""` | v0.0.1 | stable | Required. Google Cloud project that owns the destination dataset. |
| `dataset` | `string` | `""` | v0.0.1 | stable | Required. Destination dataset ID (letters, digits, underscores). |
| `location` | `string` | `""` | v0.0.1 | stable | Dataset location; used only when `auto_create.dataset` creates the dataset. |
| `kms_key_name` | `string` | `""` | v0.0.1 | stable | Default Cloud KMS key (`projects/{p}/locations/{l}/keyRings/{r}/cryptoKeys/{k}`) for auto-created datasets and tables. |
| `labels` | `map[string]string` | `unset` | v0.0.1 | stable | Default resource labels for auto-created datasets, tables and views; at most 64 after merging per-table labels. |
| `traces.table` | `string` | `"otel_spans"` | v0.0.1 | stable | Spans table ID in the dataset. |
| `traces.partition_expiration_days` | `int` | `0` | v0.0.1 | stable | Partition expiry for the auto-created spans table; `0` keeps partitions forever. |
| `traces.require_partition_filter` | `bool` | `false` | v0.0.1 | stable | Sets `require_partition_filter` on the auto-created spans table; see `auto_create.allow_unprunable_views`. |
| `traces.kms_key_name` | `string` | `""` | v0.0.1 | stable | Per-table KMS key overriding the top-level `kms_key_name`. |
| `traces.labels` | `map[string]string` | `unset` | v0.0.1 | stable | Per-table labels merged over the top-level `labels`. |
| `traces.max_staleness` | `string` | `""` | v0.0.1 | stable | `max_staleness` option for the auto-created spans table, as a duration between `1s` and `168h`. |
| `logs.table` | `string` | `"otel_logs"` | v0.0.1 | stable | Logs table ID in the dataset. |
| `logs.partition_expiration_days` | `int` | `0` | v0.0.1 | stable | Partition expiry for the auto-created logs table; `0` keeps partitions forever. |
| `logs.require_partition_filter` | `bool` | `false` | v0.0.1 | stable | Sets `require_partition_filter` on the auto-created logs table. |
| `logs.kms_key_name` | `string` | `""` | v0.0.1 | stable | Per-table KMS key overriding the top-level `kms_key_name`. |
| `logs.labels` | `map[string]string` | `unset` | v0.0.1 | stable | Per-table labels merged over the top-level `labels`. |
| `logs.max_staleness` | `string` | `""` | v0.0.1 | stable | `max_staleness` option for the auto-created logs table, as a duration between `1s` and `168h`. |
| `logs.log_name_attribute` | `string` | `""` | v0.0.1 | stable | Log record attribute that supplies the `log_name` column; falls back to well-known attributes, then the service name, then `default`. |
| `logs.insert_id_attribute` | `string` | `""` | v0.0.1 | stable | Log record attribute that supplies `insert_id`; falls back to well-known attributes, then a synthesized hash when `logs.synthesize_insert_id` is enabled. Values must be unique per record. |
| `logs.synthesize_insert_id` | `bool` | `true` | v0.2.0 | stable | Derives a compact content-hash `insert_id` for log records lacking an upstream `insert_id` attribute; setting `false` emits `NULL` for ID-less logs under the v1 contract and withdraws retry deduplication guarantees for those records. |
| `metrics.table` | `string` | `"otel_metrics"` | v0.0.1 | stable | Metrics table ID in the dataset. |
| `metrics.partition_expiration_days` | `int` | `0` | v0.0.1 | stable | Partition expiry for the auto-created metrics table; `0` keeps partitions forever. |
| `metrics.require_partition_filter` | `bool` | `false` | v0.0.1 | stable | Sets `require_partition_filter` on the auto-created metrics table. |
| `metrics.kms_key_name` | `string` | `""` | v0.0.1 | stable | Per-table KMS key overriding the top-level `kms_key_name`. |
| `metrics.labels` | `map[string]string` | `unset` | v0.0.1 | stable | Per-table labels merged over the top-level `labels`. |
| `metrics.max_staleness` | `string` | `""` | v0.0.1 | stable | `max_staleness` option for the auto-created metrics table, as a duration between `1s` and `168h`. |
| `credentials.file` | `string` | `""` | v0.0.1 | stable | Path to a Google credentials JSON file. At most one of `file`, `json` and `impersonate_service_account` may be set; the default is application default credentials. |
| `credentials.json` | `configopaque.String` | `""` | v0.0.1 | stable | Inline credentials JSON, masked in configuration dumps. |
| `credentials.impersonate_service_account` | `string` | `""` | v0.0.1 | stable | Target principal for service account impersonation from the ambient credentials. |
| `credentials.impersonate_delegates` | `[]string` | `unset` | v0.0.1 | stable | Delegation chain for impersonation; requires `credentials.impersonate_service_account`. |
| `credentials.quota_project` | `string` | `""` | v0.0.1 | stable | Project billed for API quota when it differs from `project`. |
| `credentials.universe_domain` | `string` | `""` | v0.0.1 | stable | Universe domain override (default `googleapis.com`) for Sovereign Cloud and Trusted Partner Cloud. |
| `endpoint.url` | `string` | `""` | v0.0.1 | stable | Alternate Storage Write API gRPC endpoint (emulator, Private Service Connect, Sovereign Cloud). |
| `endpoint.admin_url` | `string` | `""` | v0.0.1 | stable | Alternate BigQuery REST v2 endpoint for startup metadata checks and DDL. |
| `endpoint.insecure` | `bool` | `false` | v0.0.1 | stable | Disables TLS; accepted only for a loopback `endpoint.url`. |
| `endpoint.without_authentication` | `bool` | `false` | v0.0.1 | stable | Sends no credentials; accepted only for a loopback `endpoint.url`. |
| `auto_create.dataset` | `bool` | `false` | v0.0.1 | stable | Creates the dataset at startup if absent. |
| `auto_create.tables` | `bool` | `false` | v0.0.1 | stable | Creates the signal tables and their `_dedup` views at startup if absent. |
| `auto_create.companion_views` | `bool` | `false` | v0.0.1 | stable | Creates and reconciles the companion views (`v_gen_ai_*`, `v_mcp_*`, `otel_spans_as_allspans`); requires `auto_create.tables`. |
| `auto_create.allow_unprunable_views` | `bool` | `false` | v0.0.1 | stable | Also creates the cross-signal views that cannot be partition-pruned when the spans table requires a partition filter; otherwise they are skipped with a warning. |
| `auto_create.search_indexes` | `bool` | `false` | v0.0.1 | stable | Runs `CREATE SEARCH INDEX IF NOT EXISTS` on the signal tables; requires `auto_create.tables` and `bigquery.jobs.create`. |
| `write.max_request_bytes` | `int` | `8388608` | v0.0.1 | stable | Serialized-request size at which a batch is split before `AppendRows` (8 MiB); must stay below the API's 10 MB limit. |
| `write.max_row_bytes` | `int` | `1048576` | v0.0.1 | stable | Largest serialized row accepted (1 MiB); larger rows are rejected and, if enabled, quarantined. |
| `write.max_inflight_requests` | `int` | `8` | v0.0.1 | stable | Upper bound on concurrent unacknowledged `AppendRows` requests per stream. |
| `write.max_inflight_bytes` | `int` | `67108864` | v0.0.1 | stable | Upper bound on bytes held by unacknowledged requests (64 MiB). |
| `write.stream_pool_size` | `int` | `1` | v0.0.1 | experimental | Number of default-stream writers per table, `1` to `16`; above `1` each writer gets its own connection. |
| `write.enable_multiplexing` | `bool` | `true` | v0.0.1 | experimental | Shares gRPC connections across default streams when `write.stream_pool_size` is `1`. |
| `write.connection_pool_size` | `int` | `4` | v0.0.1 | experimental | gRPC connection pool size for the Storage Write client; raised to `write.stream_pool_size` when that is larger. |
| `write.compression` | `string` | `""` | v0.0.1 | experimental | gRPC compressor for `AppendRows`: empty (none) or `gzip`. |
| `write.keepalive.time` | `time.Duration` | `0s` | v0.0.1 | experimental | Idle time before the client sends a keepalive ping; `0s` leaves the gRPC default. |
| `write.keepalive.timeout` | `time.Duration` | `0s` | v0.0.1 | experimental | Time to wait for a keepalive ack; `0s` leaves the gRPC default. |
| `write.keepalive.permit_without_stream` | `bool` | `false` | v0.0.1 | experimental | Sends keepalive pings even with no active RPC. |
| `write.backpressure.enabled` | `bool` | `false` | v0.0.1 | experimental | Turns on adaptive (AIMD) request sizing and in-flight concurrency control under Storage Write API congestion. |
| `write.backpressure.min_request_bytes` | `int` | `1048576` | v0.0.1 | experimental | AIMD floor for the effective request size (1 MiB); must be positive and at most `write.max_request_bytes` when enabled. |
| `write.backpressure.min_inflight_requests` | `int` | `1` | v0.0.1 | experimental | AIMD floor for effective in-flight requests; `1` to `write.max_inflight_requests` when enabled. |
| `write.backpressure.decrease_factor` | `float64` | `0.5` | v0.0.1 | experimental | Multiplicative decrease applied on throttle or slow-ack signals; strictly between `0` and `1`. |
| `write.backpressure.recovery_interval` | `time.Duration` | `10s` | v0.0.1 | experimental | Minimum time between additive recovery steps on clean acknowledgements; positive when enabled. |
| `write.backpressure.latency_threshold` | `time.Duration` | `2s` | v0.0.1 | experimental | Acknowledgement latency that counts as a slow ack; `0s` disables latency-based decrease. |
| `limits.max_attribute_count` | `int` | `1024` | v0.0.1 | stable | Attributes kept per record, event or link before truncation is recorded. |
| `limits.max_event_count` | `int` | `1024` | v0.0.1 | stable | Span events kept per span. |
| `limits.max_link_count` | `int` | `1024` | v0.0.1 | stable | Span links kept per span. |
| `limits.max_nesting_depth` | `int` | `16` | v0.0.1 | stable | Maximum depth of nested attribute values. |
| `limits.max_collection_size` | `int` | `4096` | v0.0.1 | stable | Maximum entries in a nested map or slice attribute value. |
| `limits.max_attribute_key_bytes` | `int` | `1024` | v0.0.1 | stable | Longest attribute key accepted, in bytes. |
| `limits.max_value_bytes` | `int` | `262144` | v0.0.1 | stable | Longest string or serialized attribute value kept inline (256 KiB) before truncation or offload. |
| `quarantine.enabled` | `bool` | `false` | v0.0.1 | stable | Writes permanently rejected records to the dead-letter table instead of only counting them. |
| `quarantine.table` | `string` | `"otel_quarantine"` | v0.0.1 | stable | Quarantine table ID in the dataset; must be non-empty when enabled. |
| `quarantine.partition_expiration_days` | `int` | `30` | v0.0.1 | stable | Partition expiry for the auto-created quarantine table. |
| `quarantine.require_partition_filter` | `bool` | `false` | v0.0.1 | stable | Sets `require_partition_filter` on the auto-created quarantine table. |
| `quarantine.kms_key_name` | `string` | `""` | v0.0.1 | stable | Per-table KMS key overriding the top-level `kms_key_name`. |
| `quarantine.labels` | `map[string]string` | `unset` | v0.0.1 | stable | Per-table labels merged over the top-level `labels`. |
| `quarantine.max_staleness` | `string` | `""` | v0.0.1 | stable | `max_staleness` option for the auto-created quarantine table, as a duration between `1s` and `168h`. |
| `quarantine.metadata_only` | `bool` | `false` | v0.0.1 | stable | Omits `raw_payload`, `raw_attributes` and `payload_ref` from quarantine rows. |
| `quarantine.max_raw_payload_bytes` | `int` | `8388608` | v0.0.1 | stable | Longest `raw_payload` written to a quarantine row (8 MiB); positive when enabled. |
| `quarantine.timeout` | `time.Duration` | `5s` | v0.0.1 | stable | Bound on each best-effort quarantine append; positive when enabled. |
| `offload.enabled` | `bool` | `false` | v0.0.1 | stable | Offloads oversized span and log values and quarantine payloads to Cloud Storage, recording `ObjectRef`s in BigQuery. |
| `offload.bucket` | `string` | `""` | v0.0.1 | stable | Destination bucket name without `gs://`; required when enabled. |
| `offload.prefix` | `string` | `"otel-offload"` | v0.0.1 | stable | Object key prefix within the bucket. |
| `offload.authorizer` | `string` | `""` | v0.0.1 | stable | BigQuery connection resource recorded in `ObjectRef.authorizer`. |
| `offload.min_bytes` | `int` | `262144` | v0.0.1 | stable | Smallest value offloaded (256 KiB); positive when enabled. |
| `offload.max_object_bytes` | `int` | `67108864` | v0.0.1 | stable | Largest value eligible for offload (64 MiB). |
| `offload.max_concurrency` | `int` | `8` | v0.0.1 | stable | Concurrent uploads within one offload batch; positive when enabled. |
| `offload.cache_size` | `int` | `4096` | v0.0.1 | stable | Entries in the in-memory cache of content-addressed object generations; `0` disables cross-batch caching. |
| `offload.timeout` | `time.Duration` | `10s` | v0.0.1 | stable | Bound on each object upload attempt; positive when enabled. |
| `redaction.enabled` | `bool` | `false` | v0.0.1 | stable | Scrubs sensitive attribute keys and string values before offload, limits, fingerprinting and quarantine. |
| `redaction.blocked_keys` | `[]string` | `unset` | v0.0.1 | stable | Attribute keys (case-insensitive, `*` globs) whose whole value is masked; merged with the built-in list. |
| `redaction.disable_default_keys` | `bool` | `false` | v0.0.1 | stable | Drops the built-in key list so only `redaction.blocked_keys` applies. |
| `redaction.blocked_value_patterns` | `[]string` | `unset` | v0.0.1 | stable | RE2 patterns; every match inside a string value is masked. |
| `redaction.mask_replacement` | `string` | `"[REDACTED]"` | v0.0.1 | stable | Replacement text for masked keys and matches. |
| `redaction.redact_log_body` | `bool` | `false` | v0.0.1 | stable | Also scans string, map and slice log bodies. |

## Deprecated keys

Keys that have been renamed or removed. Each row corresponds to one entry in
`deprecatedConfigKeys` (`config_deprecation.go`) and one section in
[`docs/migration.md`](migration.md); the old key is accepted, with a startup
`WARN`, until at least the release in the "Earliest removal" column.

| Old key | Replacement | Deprecated in | Earliest removal | Migration anchor |
| --- | --- | --- | --- | --- |
| none | | | | |
