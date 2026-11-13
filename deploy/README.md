# Deployment Templates

This directory contains reference deployment templates for the BigQuery OTel
Exporter custom Collector. Each subdirectory targets a different deployment
model.

## Structure

```
deploy/
  helm/bigquery-otel-collector/   Helm chart for Kubernetes / GKE
  cloudrun/service.yaml            Cloud Run v2 service manifest
  terraform/                       Terraform module for BigQuery provisioning
  continuous-queries/              Continuous Query SQL templates for real-time alerting
```

## Deployment Models

See [docs/deployment-models.md](../docs/deployment-models.md) for a detailed
comparison of the four deployment models:

| Model | Template | Best for |
|:---|:---|:---|
| **A. Sidecar** | Helm chart (1 replica, DaemonSet) | Single-node K8s, pod-local collector |
| **B. Collector Gateway** | Helm chart (N replicas) | Multi-node K8s, central ingestion |
| **C. Cloud Run** | `deploy/cloudrun/` | Serverless, auto-scaling, no K8s |
| **D. Docker Compose** | `example/docker-compose.yml` | Development, single-host |

## Quick Start

> **Important (Schema Skew on Unreleased Revisions)**: At this revision,
> `deploy/terraform/` provisions **`v0alpha3`** BigQuery tables (stamped with
> `otel_schema_*` labels `0.3.0/default`), whereas the pinned `0.1.0` collector
> release image in `deploy/helm/bigquery-otel-collector/values.yaml`
> (`Chart.yaml` `appVersion: "0.1.0"`) and `deploy/cloudrun/service.yaml` writes
> **`v0alpha2`**. Because `auto_create.tables` is `false` on both deployment
> paths, running the `0.1.0` release image against `deploy/terraform/` tables
> fails closed at startup during schema validation. Until the next tagged
> release bumps the pinned image tags, operators deploying from this revision
> **must build and push a collector image from the same revision** (and override
> `image.repository`/`image.tag` in Helm or `image` in
> `deploy/cloudrun/service.yaml`), or check out the `v0.1.0` tag to deploy with
> the `0.1.0` release image.

### Kubernetes / GKE with Helm

Requires Helm v3.4+ (`>= 3.4.0`).

Override `image.repository` and `image.tag` to point at a collector image
built from the same revision as `deploy/terraform/` (`v0alpha3`); the chart's
pinned `0.1.0` tag writes `v0alpha2` and fails startup validation against
`v0alpha3` tables.

```bash
# Provision BigQuery tables first (v0alpha3 at this revision)
cd deploy/terraform
terraform init
terraform apply -var="project_id=my-project"

# Install the collector using an image built from the same revision
helm install otel-collector deploy/helm/bigquery-otel-collector \
  --set bigquery.project=my-project \
  --set bigquery.dataset=otel \
  --set image.repository=us-central1-docker.pkg.dev/my-project/otel/bq-otel-collector \
  --set image.tag=dev
```

Helm chart defaults (`deploy/helm/bigquery-otel-collector/values.yaml` and `templates/deployment.yaml`):

- `goMemLimit: "400MiB"` injects `GOMEMLIMIT` below the default `512Mi` container memory limit (`resources.limits.memory`).
- `startupProbe` (active when `healthCheck.enabled: true`) polls `httpGet` `/` on port `health` (`healthCheck.port`, default `13133`) with `initialDelaySeconds: 5`, `periodSeconds: 5`, and `failureThreshold: 12`, giving startup `auto_create` DDL up to 60s after the initial delay before liveness/readiness probes fail the pod.
- Pod template annotation `checksum/config` hashes `configmap.yaml` so ConfigMap updates roll pods automatically.
- `podSecurityContext.seccompProfile.type: RuntimeDefault` pairs with container `securityContext` (`runAsNonRoot: true`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `capabilities.drop: [ALL]`).

### Cloud Run

Update `spec.template.spec.containers[0].image` in `deploy/cloudrun/service.yaml`
to a collector image built from the same revision as `deploy/terraform/`
(`v0alpha3`); the manifest's pinned `0.1.0` tag writes `v0alpha2` and fails
startup validation against `v0alpha3` tables.

```bash
# Provision BigQuery and IAM (v0alpha3 at this revision)
cd deploy/terraform
terraform apply -var="project_id=my-project"

# Deploy the collector (after updating image to a same-revision build)
gcloud run services replace deploy/cloudrun/service.yaml
```

`deploy/cloudrun/service.yaml` sets `GOMEMLIMIT=400MiB` against `resources.limits.memory: 512Mi` (`cpu: "1"`) and configures `startupProbe` on `httpGet` `/` port `13133` with `initialDelaySeconds: 5`, `periodSeconds: 10`, and `failureThreshold: 23` so cold-start `auto_create` DDL stays inside Cloud Run's startup probe window.

### Terraform Managed Views, Alerting CMEK, and Looker Studio Template

- **View lifecycle**: Terraform-managed BigQuery views in `deploy/terraform/main.tf` and `deploy/terraform/governance.tf` set `deletion_protection = false` so view replacement (such as toggling `allow_unprunable_views`) and `terraform destroy` succeed without manual overrides.
- **Alerting table CMEK**: When `enable_continuous_queries` is enabled alongside `kms_key_name`, the `otel_alerts` table includes `encryption_configuration` referencing `var.kms_key_name` and waits on `google_kms_crypto_key_iam_member.bq_encryptor`.
- **Looker Studio Linking API**: Set `looker_studio_template_report_id`, `looker_studio_template_project_id`, and `looker_studio_template_dataset_id` (all `default = ""`) to emit `looker_studio_create_url`; `looker_studio_template_project_id` and `looker_studio_template_dataset_id` are required whenever `looker_studio_template_report_id` is non-empty (see [dashboards/looker_studio/README.md](../dashboards/looker_studio/README.md)).

### Authentication

All deployment models use Google Cloud authentication:

- **Application Default Credentials (ADC)**: Default. The collector discovers
  credentials from the environment (metadata server, env var, or well-known
  file).
- **Workload Identity Federation (GKE)**: Annotate the Kubernetes ServiceAccount
  with the GCP service account email (see `values.yaml`).
- **Service Account Key (anywhere)**: Set `GOOGLE_APPLICATION_CREDENTIALS` to
  the key file path.
- **Impersonation**: Set `credentials.impersonate_service_account` in the
  collector config.

## IAM Permissions

Terraform creates the dataset and every table and view, so by default it
grants the collector's service account one custom role, `otelCollectorWriter`,
on that dataset only:

| Permission | Purpose |
|:---|:---|
| `bigquery.datasets.get` | Startup dataset metadata validation |
| `bigquery.tables.get` | Startup table schema validation |
| `bigquery.tables.updateData` | Append rows via Storage Write API |

Run the collector with `auto_create` off on this path. The Cloud Run manifest
turns off the image's default `auto_create` with `--set` flags, and the Helm
chart leaves it off unless you set `bigquery.autoCreate*`.

A collector that creates or reconciles its own tables, views, or search
indexes needs more. Set `-var="grant_auto_create=true"` to grant it:

| Permission | Scope | Purpose |
|:---|:---|:---|
| `bigquery.tables.create` | Dataset | `auto_create.tables` / `companion_views`: create missing tables and views |
| `bigquery.tables.update` | Dataset | `auto_create.tables` / `companion_views`: reconcile additive columns and stale view definitions |
| `bigquery.tables.createIndex` | Dataset | `auto_create.search_indexes` |
| `bigquery.jobs.create` | Project | `auto_create.search_indexes`: run the `CREATE SEARCH INDEX` job |

`auto_create.dataset` is never needed here, because Terraform creates the dataset.

## Persistent Queue

For crash-replay durability, enable the `file_storage` extension:

- **Helm (multi-replica / HPA `StatefulSet`)**: Set `persistentQueue.enabled: true`. Renders a `StatefulSet` with per-pod `volumeClaimTemplates` (`ReadWriteOnce` per pod ordinal) so replicas never contend on a shared claim or bbolt lock.
- **Helm (single-replica `Deployment`)**: Set `persistence.enabled: true` (`templates/pvc.yaml`). Renders `strategy.type: Recreate` on the `Deployment` so config/image updates release the `ReadWriteOnce` claim and bbolt lock before starting the replacement pod. Mutually exclusive with `persistentQueue.enabled: true`, `autoscaling.enabled: true`, and `replicaCount > 1` (enforced by Helm `fail` guards).
- **Cloud Run**: Not supported (stateless).
- **Docker Compose**: Uncomment the `file_storage` extension in the example
  config and mount a volume.

See [docs/deployment-models.md](../docs/deployment-models.md) for more details.

## Safe Autoscaling (HPA), Persistent Queue Scale-Down, and Metrics Adapter Rules

When enabling `autoscaling.enabled: true` (`deploy/helm/bigquery-otel-collector/templates/hpa.yaml` and `values-high-volume-logs.yaml`):

1. **Scale only on workload demand, never destination backpressure**:
   - Supported `v0.165.0` HPA metrics are pod CPU utilization (`targetCPUUtilizationPercentage`), admitted input rate (`admittedRateMetric`), and `sending_queue` depth (`queueDepthMetric` over `otelcol_exporter_queue_size`, or utilization against `otelcol_exporter_queue_capacity`), bounded by a hard `maxReplicas` cap. Note that `exporterhelper` `v0.165.0` does **not** emit a queue oldest-item age metric.
   - `otelcol_exporter_queue_size` and `otelcol_exporter_queue_capacity` report in the unit of `sendingQueue.sizer` (`requests` by default and in `values-high-volume-logs.yaml`, where `queueSize: 10000` requests holds ~667–1,000s of pod traffic across the 900s retry horizon at 10–15 requests/s/pod, any single oversized batch occupies `1` slot, and `queueDepthMetric.targetAverageValue: "500"` targets 500 queued/in-flight requests per pod). If you override `sendingQueue.sizer` to `items` or `bytes`, size `sendingQueue.queueSize` for the full 900s retry horizon and re-express `queueDepthMetric.targetAverageValue` in that same unit.
   - **Never** scale on `otelcol_exporter_bigquery_backpressure_level` (`templates/hpa.yaml` fails template rendering if any metric name contains `backpressure_level`): adaptive backpressure rises on BigQuery congestion or quota exhaustion, where adding writers worsens throttling. Wire `backpressure_level` and quota exhaustion strictly as alerts.
2. **Apply `rate()` in your metrics adapter for `otelcol_receiver_accepted_log_records`**:
   - OpenTelemetry Collector receivers expose `otelcol_receiver_accepted_log_records` (exported to Prometheus as `otelcol_receiver_accepted_log_records_total` when type suffixes are enabled, or `otelcol_receiver_accepted_log_records` without suffixes) as a **monotonic cumulative counter**.
   - Before setting `autoscaling.admittedRateMetric.enabled: true`, configure your Kubernetes `custom.metrics.k8s.io` adapter (`prometheus-adapter` or Google Cloud Managed Service for Prometheus `custom-metrics-stackdriver-adapter`) to expose per-pod admitted records/sec via `rate()`:

   ```yaml
   # prometheus-adapter rules.custom example:
   rules:
     custom:
       - seriesQuery: '{__name__=~"otelcol_receiver_accepted_log_records(_total)?",namespace!="",pod!=""}'
         resources:
           overrides:
             namespace: { resource: namespace }
             pod: { resource: pod }
         name:
           matches: "^otelcol_receiver_accepted_log_records(_total)?$"
           as: "otelcol_receiver_accepted_log_records"
         metricsQuery: 'sum(rate(<<.Series>>{<<.LabelMatchers>>}[2m])) by (<<.GroupBy>>)'
   ```

3. **Disable automatic HPA scale-down over persistent queues (`selectPolicy: Disabled`) and understand stateless scale-in**:
   - In `exporterhelper` `v0.165.0`, `persistentQueue.Shutdown` stops reading immediately (`pq.stopped` is checked before `ReadIndex != WriteIndex`) rather than draining queued items during `terminationGracePeriodSeconds` (unlike the in-memory queue, which drains on shutdown). During a BigQuery slowdown, pod CPU can drop while the on-disk queue grows; scaling down a `StatefulSet` ordinal strands unread batches on that ordinal's PVC until the ordinal scales up again.
   - `templates/hpa.yaml` automatically sets `spec.behavior.scaleDown.selectPolicy: Disabled` whenever `persistentQueue.enabled: true` (and rejects any non-`Disabled` override). Perform `StatefulSet` scale-downs manually only after confirming `otelcol_exporter_queue_size == 0` on the highest ordinals. Note that lowering `autoscaling.maxReplicas` below the active replica count (or setting `autoscaling.enabled: false` while scaled out) bypasses `behavior.scaleDown.selectPolicy: Disabled` and scales pods down immediately, stranding unshipped PVC queue data unless those replicas are drained first.
   - When `persistentQueue.enabled: false` (stateless `Deployment` HPA), automatic scale-in remains enabled by default (`stabilizationWindowSeconds: 300`) and relies on `terminationGracePeriodSeconds` for `memoryQueue.Shutdown` to drain queued in-memory batches. During a destination outage that exceeds `terminationGracePeriodSeconds`, a terminated pod drops whatever remains queued in memory when the grace period expires. Operators who require zero-drop scale-in protection during prolonged destination outages should either set `autoscaling.behavior.scaleDown.selectPolicy: Disabled` (honored by `templates/hpa.yaml` in stateless mode as well) or enable `persistentQueue.enabled: true`.
4. **Keep `sendingQueue.batch.maxSize: 0` when synthesizing log `insert_id` (and explicit `minSize: 0` default)**:
   - Pre-transform `sending_queue.batch.max_size` splits a single OTLP log batch before `transform.LogRows`, resetting intra-batch `insert_id` ordinals across split boundaries and collapsing identical ID-less records in `otel_logs_dedup`. Leave `sendingQueue.batch.maxSize: 0` (the exporter's post-transform `write.max_request_bytes` splitter still bounds every `AppendRows` RPC), or set `bigquery.logs.synthesizeInsertID: false` only when records carry explicit unique upstream insert IDs (`templates/configmap.yaml` fails render if `maxSize > 0` while `synthesizeInsertID` is enabled).
   - `templates/configmap.yaml` explicitly renders `min_size` (defaulting `sendingQueue.batch.minSize` to `0` rather than `exporterhelper`'s `8192` default, and failing render if `maxSize > 0 && minSize > maxSize`) so setting a smaller `maxSize` (such as `4000`) when `bigquery.logs.synthesizeInsertID: false` passes Collector startup validation.

## Storage Write API Stream Pool

Set `write.streamPoolSize` (Helm) or `exporters.bigquery.write.stream_pool_size`
(collector config / Cloud Run `--set`) between `1` and `16` to open multiple
default-stream `ManagedStream` slots per destination table. When
`stream_pool_size > 1`, each table's writer pool automatically uses `N`
dedicated per-stream `AppendRows` connections and sizes its gRPC connection pool
to `max(connection_pool_size, stream_pool_size)`.

## Enterprise Governance

When Terraform provisions the tables, Terraform governs their partitioning
granularity, clustering, retention, partition filter requirement, CMEK key,
labels, max staleness, create-only search indexes, and optional `BACKGROUND`
reservation through the variables below. The collector's table options
(`partition_granularity`, `clustering`, `partition_expiration_days`,
`require_partition_filter`, `kms_key_name`, `labels`, `max_staleness`,
`search_index.columns`, and `search_index.analyzer` for each signal and for
quarantine, and the top-level `kms_key_name` and `labels`) apply only to a
dataset, table, or search index that the collector creates itself with
`auto_create.dataset`, `auto_create.tables`, `auto_create.companion_views`, or
`auto_create.search_indexes`. The collector never changes them on one that
already exists, so on tables Terraform created, the same options in the
collector config, the Helm values, or the Cloud Run overrides have no effect.
Set them here instead. BigQuery cannot change the time partitioning of an
existing table, so a new partitioning granularity needs a new table. It can
change a table's clustering columns in place, which Terraform does when
`spans_clustering` or `logs_clustering` changes, and it clusters the data
written after the change by the new columns. A table keeps its single search
index until the index is dropped; see [Search Index Jobs](#search-index-jobs).

### CMEK Encryption

Set `kms_key_name` in the Terraform module to encrypt the BigQuery dataset and
all tables with a Cloud KMS key. The key must be in the dataset's location: a
dataset in the `US` multi-region needs a key in `locations/us`, one in the `EU`
multi-region a key in `locations/europe`, and one in a region such as
`us-central1` a key in that same region, `locations/us-central1`. The module
creates the dataset in `US` unless you set `location`, so a regional key needs
the matching `location`:

```bash
terraform apply \
  -var="project_id=my-project" \
  -var="location=us-central1" \
  -var="kms_key_name=projects/my-project/locations/us-central1/keyRings/otel/cryptoKeys/bq"
```

Terraform also grants the BigQuery encryption service agent
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on the key automatically. When
`kms_key_name` is empty (the default), the dataset uses Google-managed
encryption.

### Max Staleness

Set `max_staleness` in the Terraform module to set BigQuery's `max_staleness`
option on the tables: the maximum staleness of the data a query over a table
may return. Within that window, BigQuery can answer a query from the changes it
has already applied instead of applying pending changes, such as change data
capture upserts and deletes, at query time. The option bounds how stale results
may be; it does not exclude recent partitions from queries.

```bash
terraform apply \
  -var="project_id=my-project" \
  -var="max_staleness=15m"
```

The value is either a Go duration, as the collector's `max_staleness` options
take it, in whole seconds from `1s` to `168h` (for example `30s`, `15m`, or
`1h30m`), or a BigQuery SQL interval string (for example `0-0 0 0:15:0`).
Terraform converts a duration to the interval the collector writes for it, so
`15m` is sent as `0-0 0 0:15:0`, and rejects a duration outside that range or
one that is not a whole number of seconds. An interval string is passed to
BigQuery as given; only its format is checked. The option is applied to all
four signal and quarantine tables, never to views.

### Partition Retention and Partition Filters

Set these variables in the Terraform module to expire old partitions and to
require a partition filter on queries:

| Variable | Default | Applies to |
|:---|:---|:---|
| `spans_partition_expiration_days` | `0` | `otel_spans` (hourly partitions on `start_time`) |
| `logs_partition_expiration_days` | `0` | `otel_logs` (daily or hourly partitions on `timestamp` via `logs_partition_type`, default `DAY`) |
| `metrics_partition_expiration_days` | `0` | `otel_metrics` (daily partitions on `timestamp`) |
| `quarantine_partition_expiration_days` | `30` | `otel_quarantine` (daily partitions on `ingest_time`) |
| `require_partition_filter` | `false` | All four tables (and `otel_alerts` when `enable_continuous_queries` is `true`) |
| `allow_unprunable_views` | `false` | `v_gen_ai_logs`, `v_gen_ai_metric_exemplars`, and `v_gen_ai_agent_trajectory`: create them even with `require_partition_filter=true` |
| `logs_partition_type` | `"DAY"` | `otel_logs` creation-time partitioning granularity (`DAY` or `HOUR`) |
| `spans_clustering` | `["service_name", "trace_id", "name"]` | `otel_spans` clustering (1–4 columns from `otel_spans_dedup` window) |
| `logs_clustering` | `["service_name", "trace_id", "severity_number"]` | `otel_logs` clustering (1–4 columns from `otel_logs_dedup` window) |
| `enable_search_indexes` | `false` | Create-only `CREATE SEARCH INDEX IF NOT EXISTS` jobs (`logs_search_index_columns`, `logs_search_index_analyzer`) |
| `search_index_job_wait_timeout_seconds` | `300` | Seconds `terraform apply` waits for each search index job to finish (`0` does not wait); see [Search Index Jobs](#search-index-jobs) |
| `enable_background_reservation` | `false` | Enterprise/Enterprise Plus `BACKGROUND` reservation (`background_reservation_slots`, default `50`) for search index maintenance |

```bash
terraform apply \
  -var="project_id=my-project" \
  -var="spans_partition_expiration_days=365" \
  -var="logs_partition_expiration_days=90" \
  -var="metrics_partition_expiration_days=90"
```

An expiration is a whole number of days, and `0` leaves partitions without
expiration. This matches the collector's `partition_expiration_days` options
for both the signal tables and the quarantine table (when explicitly configured
to `0`; leaving `quarantine.partition_expiration_days` unset in the collector
defaults to 30 days). BigQuery allows at most 10,000 partitions per table, which is
about 416 days of hourly `otel_spans` partitions, so with the default `0` the
spans table eventually reaches that limit; set
`spans_partition_expiration_days` to 416 or less to stay under it.

With `require_partition_filter=true`, BigQuery rejects a query over these
tables, over `otel_alerts` (partitioned daily on `event_time`, when
`enable_continuous_queries=true`), or over the views built on them, that has no
filter BigQuery can use to skip partitions. See "Filtering the GenAI views by
time" under
[Operating v0alpha3 tables](../README.md#operating-v0alpha3-tables) for the
columns the views take. Queries over `v_gen_ai_logs`,
`v_gen_ai_metric_exemplars`, and `v_gen_ai_agent_trajectory` are rejected even
with a filter, because each joins `otel_spans` on a time window that depends on
each row, and no such filter reaches all of their scans of `otel_spans`. The
module therefore does not create those three views while
`require_partition_filter=true` unless `allow_unprunable_views=true`, and a
`v_gen_ai_logs` that an earlier apply created is destroyed on the next apply.
Leave `require_partition_filter` off for a deployment that queries those views.
The collector does the same: a collector started with
`auto_create.companion_views: true` against an `otel_spans` table that requires
a partition filter skips those three views with a warning, creates the other
companion views, and starts; set `auto_create.allow_unprunable_views: true`
(Helm: `bigquery.autoCreateAllowUnprunableViews: true`) to create the three
views anyway. The collector reads the table's metadata to decide, and its own
`traces.require_partition_filter` counts only while `otel_spans` does not exist
yet, because that option applies only when the collector creates the table.
`v_mcp_spans` and `v_mcp_tool_usage` read `otel_spans_dedup` once without
row-dependent window joins, so both remain queryable with a `start_time` or
`usage_hour` filter when `require_partition_filter=true`. `v_mcp_tool_usage`
aggregates at the per-span observation grain (`span_kind` separates `CLIENT`
and `SERVER` spans into distinct rows, and session-only or resource-only MCP
spans without `mcp.method.name` group under `mcp_method_name IS NULL`).

### Search Index Jobs

With `enable_search_indexes=true`, the module runs one BigQuery job per signal
table. Each job runs a script that creates the table's search index only when
`INFORMATION_SCHEMA.SEARCH_INDEXES` lists no index on the table. BigQuery
allows a table one search index, so a table that already has one, under any
name, keeps it, and the job succeeds without changing it. If the `CREATE SEARCH
INDEX` statement fails because another creator, such as a collector with
`auto_create.search_indexes`, indexed the table first, the job succeeds as well;
any other error fails the job.

- **The apply waits for each job.** The provider records a job as soon as
  BigQuery accepts it, so the module then waits, for up to
  `search_index_job_wait_timeout_seconds` (default `300`), until BigQuery
  reports the job done. `terraform apply` fails with BigQuery's reason and
  message when the job ends with an error (for example `accessDenied`, a
  quota, or a table that does not support search indexes), and fails when the
  job is not done in time. After a timeout, run `terraform apply` again: it
  waits for the same job and submits no new one.
- **A failed job keeps failing Terraform.** Once a job has ended with an
  error, every later `terraform plan` and `terraform apply` fails with that
  error until the job is retried.
- **Retry with `-replace`.** After fixing the cause, run
  `terraform apply -replace='google_bigquery_job.otel_logs_search_index[0]'`
  (or the spans or metrics job). Every job, including a retry, gets a fresh
  job ID, because BigQuery keeps job IDs in its job history; the
  `search_index_job_ids` output shows the current ones.
- **The job follows its table.** Terraform replaces a table's job, which
  indexes the new table, whenever BigQuery has created the table anew: when
  `spans_table`, `logs_table`, or `metrics_table` changes, when the table is
  replaced for any other reason, and when the table was deleted outside
  Terraform, whether Terraform creates it again or finds it already created
  again. The module tells by the table's creation time, so updating a table
  in place (clustering, labels, partition expiration) leaves its job alone.
- **A changed index definition is reported, not applied.** Changing
  `logs_search_index_columns` or `logs_search_index_analyzer` after the logs
  job has run plans no job change and leaves the existing index as it is.
  Every plan and apply then warns, through the `search_index_definitions`
  check, that the job ran with a different definition. To rebuild the index,
  drop it with `DROP SEARCH INDEX` first, then retry the logs job with
  `-replace`. Replacing the job without dropping the index only ends the
  warning, because the job leaves an existing index alone. To keep the index,
  set the variables back.

The wait runs `scripts/wait_for_bigquery_job.py` on the machine that runs
Terraform, which therefore needs `python3` on its `PATH`. The script polls
BigQuery's `jobs.get` with an access token for the provider's own credentials
(the `google_client_config` data source) and, like the provider, sends its
requests to `GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT` when that is set. Terraform
records the token in its state, marked sensitive, as it records every data
source result. The token expires within an hour, which is why the wait is at
most 3600 seconds.

Where `python3` is not available, the script cannot reach BigQuery the way the
provider does (for example through client-certificate access), or the state
must not hold an access token, set `search_index_job_wait_timeout_seconds=0`.
Terraform then reads no token and nothing waits for the jobs: an apply can end
while a job is still running, in which case the `search_index_jobs_finished`
check warns, and a job that fails afterwards fails the next `terraform plan`
instead of the apply that created it.

### Labels

Set `labels` in the Terraform module to apply labels to the dataset, all
tables, and all views for cost allocation and governance:

```bash
terraform apply \
  -var="project_id=my-project" \
  -var='labels={environment="production",team="observability"}'
```

### GCS Offload IAM

Set `offload_bucket` in the Terraform module to grant the collector service
account `roles/storage.objectCreator` and `roles/storage.objectViewer` on the
bucket so the collector can upload large payloads and verify them:

```bash
terraform apply \
  -var="project_id=my-project" \
  -var="offload_bucket=my-otel-offload-bucket"
```

The bucket must already exist. Configure a GCS lifecycle policy to manage
retention of offloaded objects.

### Metrics Pipeline

All deployment templates wire the `metrics` pipeline by default, writing to
`otel_metrics`. Disable it by removing the `metrics:` entry from
`service.pipelines` in the collector config.

### Quarantine and Replay

Enable the quarantine dead-letter table by setting `quarantine.enabled: true`
in the collector config. Use `cmd/bq-quarantine-replay` to replay quarantined
records after fixing the underlying issue.

### Redaction

Enable client-side PII and secret redaction by setting `redaction.enabled: true`
in the collector config. Redaction runs at Step 0, before offload,
fingerprinting, and quarantine.

### Column-Level Security and Data Masking

Some STRING columns carry text from the telemetry as it was sent, which can
include prompts, responses, or error details: `otel_spans.status.message`,
`otel_logs.severity_text`, and `otel_quarantine.raw_payload` and
`error_message`. Set `enable_column_level_security=true` in the Terraform
module to put them behind a policy tag and a data masking policy:

| Variable | Default | Purpose |
|:---|:---|:---|
| `enable_column_level_security` | `false` | Create the taxonomy, policy tag, data masking policy, reader bindings, and redacted views, and attach the tag to the columns above |
| `policy_taxonomy_display_name` | `otel_telemetry_sensitivity` | Display name of the taxonomy, which must be unique among the taxonomies of the project and location |
| `masking_rule` | `SHA256` | What a Masked Reader reads in place of a value: `SHA256` (its SHA-256 hash), `ALWAYS_NULL`, or `DEFAULT_MASKING_VALUE` (an empty string) |
| `fine_grained_reader_members` | `[]` | Principals granted the Fine-Grained Reader role on the policy tag |
| `masked_reader_members` | `[]` | Principals granted the Masked Reader role on the data masking policy |

```bash
terraform apply \
  -var="project_id=my-project" \
  -var="enable_column_level_security=true" \
  -var='fine_grained_reader_members=["group:otel-admins@example.com"]' \
  -var='masked_reader_members=["group:otel-analysts@example.com"]'
```

Enable the Data Catalog API (`datacatalog.googleapis.com`) and the BigQuery
Data Policy API (`bigquerydatapolicy.googleapis.com`) in the project first.
The identity that runs Terraform also needs to create taxonomies and data
policies and set their IAM policies, and `bigquery.tables.setCategory` on the
tables to attach the tag. The `policy_tag_id` and `data_policy_id` outputs
name the policy tag and the data masking policy, and are `null` while the
option is off. Try the option on a scratch project before you turn it on for
an existing deployment.

Three layers keep this text from readers who should not see it:

1. **Collector redaction.** With `redaction.enabled: true` in the collector
   config, the collector scrubs PII and secrets before it writes a row (see
   [Redaction](#redaction)).
2. **Policy tag and data masking.** BigQuery returns a tagged column to a
   reader as the table below shows.
3. **Redacted views.** `v_otel_spans_redacted` and `v_otel_logs_redacted` read
   `otel_spans_dedup` and `otel_logs_dedup` but return `NULL` for every tagged
   column and every JSON column, including those inside records, and leave out
   `events`, `links`, and `object_refs`.

| Reader | Tagged columns |
|:---|:---|
| Fine-Grained Reader, with or without Masked Reader | Read as stored |
| Masked Reader only | Read masked by `masking_rule` |
| Neither role | A query that reads one fails with an access denied error |

Each binding is authoritative for its role: Terraform removes any other member
of that role on the policy tag or the data masking policy. The roles decide
only what a reader gets from the tagged columns; a reader still needs read
access to the tables, as without this option. Views do not lift these rules:
the `_dedup` views (`otel_spans_dedup`, `otel_logs_dedup`) and the companion
views, TVFs, and marts that reference `status.message` or `severity_text` read
the tagged columns too:

- **`otel_spans.status.message`:** `otel_spans_as_allspans` (`status.message`),
  `v_gen_ai_spans`, `v_gen_ai_agent_trajectory`, `tvf_gen_ai_agent_trajectory`,
  and `v_mcp_spans` (`status_message`), and `v_gen_ai_metric_exemplars` and
  `tvf_gen_ai_metric_exemplars` (`span_status_message`).
- **`otel_logs.severity_text`:** `otel_logs_as_alllogs` (`otel_severity_text`,
  plus `severity` and `severity_number` via the `severity_text` fallback when
  `severity_number` is `0`, `NULL`, or outside `1..24`), `v_gen_ai_logs` and
  `tvf_gen_ai_logs` (`severity_text`), and the opt-in Dataform log rollup
  `m_otel_log_volume_rollup` (`otel_log_marts`, whose refresh query reads
  `otel_logs.severity_text` for the same fallback while storing only canonical
  `severity` and `severity_number`; grant the Dataform identity Fine-Grained
  Reader so fallback resolution sees unmasked text, as Masked Reader masks
  `severity_text` before the `CASE` expression runs and maps unset-number rows
  to `DEFAULT`).

Exporting quarantined rows for `cmd/bq-quarantine-replay` reads `raw_payload`,
so only a Fine-Grained Reader exports the original payloads.

No JSON column is tagged, including `attributes`, `body`, and
`otel_quarantine.raw_attributes`, so a reader who can read a table reads its
JSON columns. The redacted views are ordinary views in the same dataset:
BigQuery checks a query over one against the reader's own access to the
tables it reads. They keep the JSON columns out of a query's results, but do
not stop a reader who can read the tables from reading those columns there.
To keep a reader off the tables, give the reader views like these in a
separate dataset, authorized on this one.

Terraform grants the collector neither role, because it only appends rows.
The collector's role does not include `bigquery.tables.setCategory`, which
changing a column's policy tags takes, and the collector never changes them: a
collector that runs with `auto_create.tables` (see
[IAM Permissions](#iam-permissions)) sends each column's policy tags back as
they are in the schema update that adds missing columns, and a restart against
a table that already has every column sends no update.

### Real-Time Alerting (Continuous Queries)

[`deploy/continuous-queries/`](continuous-queries/README.md) ships three
stateless per-span BigQuery Continuous Query templates
(`tool_error_rate_alert.sql`, `token_budget_burn.sql`, and
`agent_latency_p95.sql`) that evaluate new rows on `otel_spans` via
`APPENDS(TABLE ...)` and export alerts to Cloud Pub/Sub (with `INSERT INTO` and
Preview `TUMBLE` window variants in the directory README). Because BigQuery
`APPENDS` reads base tables and views using `QUALIFY` or window functions are
ineligible, the templates read `otel_spans` directly rather than
`otel_spans_dedup` or `v_gen_ai_*`.

Each template includes an `AND start_time >= TIMESTAMP('1970-01-01 00:00:00+00')`
filter so queries satisfy BigQuery's `require_partition_filter = true`
requirement without dropping late-arriving, backfilled, or quarantine-replayed
spans (this constant epoch bound satisfies the static filter requirement rather
than pruning historical partitions; `APPENDS` itself bounds scan volume by
commit timestamp `_CHANGE_TIMESTAMP`, whereas `start_time` is the OTLP event
timestamp preserved across late arrivals and `cmd/bq-quarantine-replay`, with a
30-day default retention on `otel_quarantine`). BigQuery Continuous Queries do
not support tables with column-level security policy tags, so Terraform enforces
a precondition that `enable_column_level_security` is `false` when
`enable_continuous_queries` is `true`.

Set `enable_continuous_queries=true` in the Terraform module (with
`service_account_id` at most 27 characters so `<service_account_id>-cq` fits
Google Cloud's 30-character limit) to provision the
`otel_alerts` table, Pub/Sub topic, dedicated service account
(`<service_account_id>-cq`), IAM bindings, and Enterprise `CONTINUOUS`
reservation assignment:

| Variable | Default | Purpose |
|:---|:---|:---|
| `enable_continuous_queries` | `false` | Create `otel_alerts`, the Pub/Sub alert topic, the Continuous Queries service account and IAM bindings, and the `CONTINUOUS` reservation assignment |
| `continuous_query_slot_capacity` | `100` | Baseline slot capacity for the `CONTINUOUS` reservation (whole multiple of 50 from 50 to 500) |
| `continuous_query_edition` | `ENTERPRISE` | BigQuery edition for the `CONTINUOUS` reservation: `ENTERPRISE` or `ENTERPRISE_PLUS` |
| `continuous_query_max_turn_input_tokens` | `100000` | Stateless per-span input token threshold rendered into `token_budget_burn.sql` |
| `continuous_query_max_turn_output_tokens` | `32000` | Stateless per-span output token threshold rendered into `token_budget_burn.sql` |
| `continuous_query_max_turn_duration_ms` | `30000` | Stateless per-span duration threshold in milliseconds rendered into `agent_latency_p95.sql` |
| `alerts_deletion_protection` | `false` | Deletion protection on the `otel_alerts` table |
| `alerts_partition_expiration_days` | `0` | Partition expiration in days for `otel_alerts` (`0` means no expiration) |

Run from the repository root (or omit `-chdir=deploy/terraform` if already
inside `deploy/terraform`):

```bash
terraform -chdir=deploy/terraform apply \
  -var="project_id=my-project" \
  -var="enable_continuous_queries=true"
```

Enable `bigquery.googleapis.com`, `bigqueryreservation.googleapis.com`,
`pubsub.googleapis.com`, and `iam.googleapis.com` first. Provisioning
`continuous_query_slot_capacity = 100` creates 100 always-on baseline
Enterprise slots; create a Pub/Sub subscription on `otel-alerts-<dataset_id>`
(or the sanitized topic in `otel_alerts_pubsub_topic_id`) to consume published
alerts. Terraform renders the SQL templates into
`continuous_queries_rendered_sql` and prints ready-to-run stdin-piped
`bq query --continuous=true` commands in `continuous_queries_bq_cli_commands`.
See [`deploy/continuous-queries/README.md`](continuous-queries/README.md) for
IAM roles, replay/watermark/150-day runtime limits, and downstream
deduplication on `alert_id`.
