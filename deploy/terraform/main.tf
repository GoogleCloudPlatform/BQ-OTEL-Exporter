# Terraform module provisioning the BigQuery destination tables, companion
# views, and least-privilege IAM role for the OTel Collector (v0alpha3).
#
# This module provisions ONLY the storage layer. The collector itself is
# deployed via the Helm chart (deploy/helm/), Cloud Run (deploy/cloudrun/),
# or Docker Compose (example/docker-compose.yml).

provider "google" {
  project = var.project_id
  region  = var.location
}

locals {
  otel_schema_labels = {
    otel_schema_major   = "0"
    otel_schema_minor   = "3"
    otel_schema_patch   = "0"
    otel_schema_variant = "default"
  }
  resource_fields = [
    { name = "attributes", type = "JSON", mode = "NULLABLE" },
    { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
  ]
  instrumentation_scope_fields = [
    { name = "name", type = "STRING", mode = "NULLABLE" },
    { name = "version", type = "STRING", mode = "NULLABLE" },
    { name = "attributes", type = "JSON", mode = "NULLABLE" },
    { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
  ]
  object_ref_fields = [
    { name = "uri", type = "STRING", mode = "REQUIRED" },
    { name = "version", type = "STRING", mode = "NULLABLE" },
    { name = "authorizer", type = "STRING", mode = "NULLABLE" },
    { name = "details", type = "JSON", mode = "NULLABLE" },
  ]

  # The provider passes max_staleness to the API unchanged, and the API takes
  # only a SQL interval string, so a Go duration is converted to the interval
  # the exporter writes for it: everything in the hours, minutes and seconds,
  # so 15m is 0-0 0 0:15:0 and 48h is 0-0 0 48:0:0. timeadd parses the
  # duration with the exporter's grammar, and formatdate reads the elapsed
  # days, hours, minutes and seconds back from the epoch it was added to,
  # which holds because variables.tf keeps a duration to whole seconds from 1s
  # to 168h. An interval is passed through as given, and an empty value leaves
  # the option unset.
  max_staleness_epoch = "2000-01-01T00:00:00Z"
  max_staleness_end   = try(timeadd(local.max_staleness_epoch, var.max_staleness), local.max_staleness_epoch)
  max_staleness = (
    var.max_staleness == "" ? null :
    startswith(var.max_staleness, "0-0 ") ? var.max_staleness :
    format("0-0 0 %d:%s:%s",
      (tonumber(formatdate("D", local.max_staleness_end)) - 1) * 24 + tonumber(formatdate("h", local.max_staleness_end)),
      formatdate("m", local.max_staleness_end),
      formatdate("s", local.max_staleness_end),
    )
  )
}

# --- Dataset ---

resource "google_bigquery_dataset" "otel" {
  dataset_id = var.dataset_id
  location   = var.location

  dynamic "default_encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = var.labels

  # With CMEK, BigQuery must be allowed to use the key before it creates an
  # encrypted dataset or table, so a first apply grants it first. Without
  # CMEK the grant has no instances and this orders nothing.
  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

# --- Signal Tables (v0alpha3 contract matching internal/schema/schema.go) ---
#
# Each table takes its partition expiration from its own
# *_partition_expiration_days variable, where 0 leaves partitions without
# expiration. require_partition_filter is set on the table itself, because the
# time_partitioning argument of that name is deprecated.

# otel_spans: 28-column v0alpha3 span table, hourly-partitioned on start_time,
# clustered by (service_name, trace_id, name).
resource "google_bigquery_table" "otel_spans" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = var.spans_table

  time_partitioning {
    type          = "HOUR"
    field         = "start_time"
    expiration_ms = var.spans_partition_expiration_days > 0 ? var.spans_partition_expiration_days * 86400000 : null
  }

  require_partition_filter = var.require_partition_filter

  clustering = ["service_name", "trace_id", "name"]

  max_staleness = local.max_staleness

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(var.labels, local.otel_schema_labels)

  schema = jsonencode([
    { name = "start_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "start_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "end_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "end_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "receive_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "receive_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "duration_nano", type = "INT64", mode = "REQUIRED" },
    { name = "trace_id", type = "STRING", mode = "REQUIRED" },
    { name = "span_id", type = "STRING", mode = "REQUIRED" },
    { name = "parent_span_id", type = "STRING", mode = "NULLABLE" },
    { name = "trace_state", type = "STRING", mode = "NULLABLE" },
    { name = "flags", type = "INT64", mode = "NULLABLE" },
    { name = "name", type = "STRING", mode = "REQUIRED" },
    { name = "kind", type = "INT64", mode = "REQUIRED" },
    { name = "kind_name", type = "STRING", mode = "NULLABLE" },
    {
      name = "status"
      type = "RECORD"
      mode = "NULLABLE"
      fields = [
        { name = "code", type = "INT64", mode = "NULLABLE" },
        { name = "code_name", type = "STRING", mode = "NULLABLE" },
        merge({ name = "message", type = "STRING", mode = "NULLABLE" }, local.sensitive_column),
      ]
    },
    { name = "attributes", type = "JSON", mode = "NULLABLE" },
    { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
    { name = "service_name", type = "STRING", mode = "NULLABLE" },
    { name = "resource", type = "RECORD", mode = "NULLABLE", fields = local.resource_fields },
    { name = "resource_schema_url", type = "STRING", mode = "NULLABLE" },
    { name = "instrumentation_scope", type = "RECORD", mode = "NULLABLE", fields = local.instrumentation_scope_fields },
    { name = "scope_schema_url", type = "STRING", mode = "NULLABLE" },
    {
      name = "events"
      type = "RECORD"
      mode = "REPEATED"
      fields = [
        { name = "time", type = "TIMESTAMP", mode = "NULLABLE" },
        { name = "time_unix_nano", type = "INT64", mode = "NULLABLE" },
        { name = "name", type = "STRING", mode = "NULLABLE" },
        { name = "attributes", type = "JSON", mode = "NULLABLE" },
        { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
      ]
    },
    { name = "dropped_events_count", type = "INT64", mode = "NULLABLE" },
    {
      name = "links"
      type = "RECORD"
      mode = "REPEATED"
      fields = [
        { name = "trace_id", type = "STRING", mode = "NULLABLE" },
        { name = "span_id", type = "STRING", mode = "NULLABLE" },
        { name = "trace_state", type = "STRING", mode = "NULLABLE" },
        { name = "flags", type = "INT64", mode = "NULLABLE" },
        { name = "attributes", type = "JSON", mode = "NULLABLE" },
        { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
      ]
    },
    { name = "dropped_links_count", type = "INT64", mode = "NULLABLE" },
    { name = "object_refs", type = "RECORD", mode = "REPEATED", fields = local.object_ref_fields },
  ])

  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

# otel_logs: 24-column v0alpha3 log table, daily-partitioned on timestamp,
# clustered by (service_name, trace_id, severity_number).
resource "google_bigquery_table" "otel_logs" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = var.logs_table

  time_partitioning {
    type          = "DAY"
    field         = "timestamp"
    expiration_ms = var.logs_partition_expiration_days > 0 ? var.logs_partition_expiration_days * 86400000 : null
  }

  require_partition_filter = var.require_partition_filter

  clustering = ["service_name", "trace_id", "severity_number"]

  max_staleness = local.max_staleness

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(var.labels, local.otel_schema_labels)

  schema = jsonencode([
    { name = "timestamp", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "timestamp_source", type = "STRING", mode = "REQUIRED" },
    { name = "time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "observed_timestamp", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "observed_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "receive_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "receive_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "trace_id", type = "STRING", mode = "NULLABLE" },
    { name = "span_id", type = "STRING", mode = "NULLABLE" },
    { name = "flags", type = "INT64", mode = "NULLABLE" },
    { name = "event_name", type = "STRING", mode = "NULLABLE" },
    { name = "severity_number", type = "INT64", mode = "NULLABLE" },
    merge({ name = "severity_text", type = "STRING", mode = "NULLABLE" }, local.sensitive_column),
    { name = "body", type = "JSON", mode = "NULLABLE" },
    { name = "attributes", type = "JSON", mode = "NULLABLE" },
    { name = "dropped_attributes_count", type = "INT64", mode = "NULLABLE" },
    { name = "service_name", type = "STRING", mode = "NULLABLE" },
    { name = "resource", type = "RECORD", mode = "NULLABLE", fields = local.resource_fields },
    { name = "resource_schema_url", type = "STRING", mode = "NULLABLE" },
    { name = "instrumentation_scope", type = "RECORD", mode = "NULLABLE", fields = local.instrumentation_scope_fields },
    { name = "scope_schema_url", type = "STRING", mode = "NULLABLE" },
    { name = "object_refs", type = "RECORD", mode = "REPEATED", fields = local.object_ref_fields },
    { name = "log_name", type = "STRING", mode = "REQUIRED" },
    { name = "insert_id", type = "STRING", mode = "NULLABLE" },
  ])

  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

# otel_metrics: 37-column v0alpha3 metric data-point table, daily-partitioned on
# timestamp, clustered by (service_name, metric_name, metric_type).
resource "google_bigquery_table" "otel_metrics" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = var.metrics_table

  time_partitioning {
    type          = "DAY"
    field         = "timestamp"
    expiration_ms = var.metrics_partition_expiration_days > 0 ? var.metrics_partition_expiration_days * 86400000 : null
  }

  require_partition_filter = var.require_partition_filter

  clustering = ["service_name", "metric_name", "metric_type"]

  max_staleness = local.max_staleness

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(var.labels, local.otel_schema_labels)

  schema = jsonencode([
    { name = "timestamp", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "start_time", type = "TIMESTAMP", mode = "NULLABLE" },
    { name = "start_time_unix_nano", type = "INT64", mode = "NULLABLE" },
    { name = "receive_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "receive_time_unix_nano", type = "INT64", mode = "REQUIRED" },
    { name = "service_name", type = "STRING", mode = "NULLABLE" },
    { name = "metric_name", type = "STRING", mode = "REQUIRED" },
    { name = "metric_description", type = "STRING", mode = "NULLABLE" },
    { name = "metric_unit", type = "STRING", mode = "NULLABLE" },
    { name = "metric_type", type = "STRING", mode = "REQUIRED" },
    { name = "aggregation_temporality", type = "STRING", mode = "NULLABLE" },
    { name = "is_monotonic", type = "BOOL", mode = "NULLABLE" },
    { name = "flags", type = "INT64", mode = "NULLABLE" },
    { name = "attributes", type = "JSON", mode = "NULLABLE" },
    { name = "metric_metadata", type = "JSON", mode = "NULLABLE" },
    { name = "value_type", type = "STRING", mode = "NULLABLE" },
    { name = "value_double", type = "FLOAT64", mode = "NULLABLE" },
    { name = "value_int64", type = "INT64", mode = "NULLABLE" },
    { name = "count", type = "INT64", mode = "NULLABLE" },
    { name = "sum", type = "FLOAT64", mode = "NULLABLE" },
    { name = "min", type = "FLOAT64", mode = "NULLABLE" },
    { name = "max", type = "FLOAT64", mode = "NULLABLE" },
    { name = "explicit_bounds", type = "FLOAT64", mode = "REPEATED" },
    { name = "bucket_counts", type = "INT64", mode = "REPEATED" },
    { name = "exp_scale", type = "INT64", mode = "NULLABLE" },
    { name = "exp_zero_count", type = "INT64", mode = "NULLABLE" },
    { name = "exp_zero_threshold", type = "FLOAT64", mode = "NULLABLE" },
    {
      name = "exp_positive"
      type = "RECORD"
      mode = "NULLABLE"
      fields = [
        { name = "offset", type = "INT64", mode = "NULLABLE" },
        { name = "bucket_counts", type = "INT64", mode = "REPEATED" },
      ]
    },
    {
      name = "exp_negative"
      type = "RECORD"
      mode = "NULLABLE"
      fields = [
        { name = "offset", type = "INT64", mode = "NULLABLE" },
        { name = "bucket_counts", type = "INT64", mode = "REPEATED" },
      ]
    },
    {
      name = "summary_quantiles"
      type = "RECORD"
      mode = "REPEATED"
      fields = [
        { name = "quantile", type = "FLOAT64", mode = "NULLABLE" },
        { name = "value", type = "FLOAT64", mode = "NULLABLE" },
      ]
    },
    {
      name = "exemplars"
      type = "RECORD"
      mode = "REPEATED"
      fields = [
        { name = "time", type = "TIMESTAMP", mode = "NULLABLE" },
        { name = "time_unix_nano", type = "INT64", mode = "NULLABLE" },
        { name = "value_double", type = "FLOAT64", mode = "NULLABLE" },
        { name = "value_int64", type = "INT64", mode = "NULLABLE" },
        { name = "span_id", type = "STRING", mode = "NULLABLE" },
        { name = "trace_id", type = "STRING", mode = "NULLABLE" },
        { name = "filtered_attributes", type = "JSON", mode = "NULLABLE" },
      ]
    },
    { name = "resource", type = "RECORD", mode = "NULLABLE", fields = local.resource_fields },
    { name = "resource_schema_url", type = "STRING", mode = "NULLABLE" },
    { name = "instrumentation_scope", type = "RECORD", mode = "NULLABLE", fields = local.instrumentation_scope_fields },
    { name = "scope_schema_url", type = "STRING", mode = "NULLABLE" },
    { name = "point_fingerprint", type = "STRING", mode = "REQUIRED" },
  ])

  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

# otel_quarantine: 11-column v0alpha3 quarantine (dead-letter) table,
# daily-partitioned on ingest_time with a 30-day partition expiration by
# default, clustered by (signal, error_code, service_name).
resource "google_bigquery_table" "otel_quarantine" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = var.quarantine_table

  time_partitioning {
    type          = "DAY"
    field         = "ingest_time"
    expiration_ms = var.quarantine_partition_expiration_days > 0 ? var.quarantine_partition_expiration_days * 86400000 : null
  }

  require_partition_filter = var.require_partition_filter

  clustering = ["signal", "error_code", "service_name"]

  max_staleness = local.max_staleness

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = merge(var.labels, local.otel_schema_labels)

  schema = jsonencode([
    { name = "ingest_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "signal", type = "STRING", mode = "REQUIRED" },
    { name = "error_code", type = "STRING", mode = "REQUIRED" },
    merge({ name = "error_message", type = "STRING", mode = "REQUIRED" }, local.sensitive_column),
    { name = "service_name", type = "STRING", mode = "NULLABLE" },
    { name = "trace_id", type = "STRING", mode = "NULLABLE" },
    { name = "span_id", type = "STRING", mode = "NULLABLE" },
    merge({ name = "raw_payload", type = "STRING", mode = "NULLABLE" }, local.sensitive_column),
    { name = "raw_attributes", type = "JSON", mode = "NULLABLE" },
    { name = "payload_ref", type = "RECORD", mode = "NULLABLE", fields = local.object_ref_fields },
    { name = "exporter_instance", type = "STRING", mode = "NULLABLE" },
  ])

  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

# --- Deduplication & Companion Views (matching internal/schema/schema.go) ---

resource "google_bigquery_table" "otel_spans_dedup" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "${var.spans_table}_dedup"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT *
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans.table_id}`
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY
          start_time,
          start_time_unix_nano,
          service_name,
          trace_id,
          span_id,
          name
        ORDER BY
          end_time_unix_nano DESC,
          receive_time_unix_nano DESC
      ) = 1
    EOT
  }
}

resource "google_bigquery_table" "otel_logs_dedup" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "${var.logs_table}_dedup"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT *
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_logs.table_id}`
      QUALIFY insert_id IS NULL OR ROW_NUMBER() OVER (
        PARTITION BY
          timestamp,
          time_unix_nano,
          service_name,
          trace_id,
          span_id,
          severity_number,
          log_name,
          insert_id
        ORDER BY
          receive_time_unix_nano DESC,
          receive_time DESC
      ) = 1
    EOT
  }
}

resource "google_bigquery_table" "otel_metrics_dedup" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "${var.metrics_table}_dedup"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT *
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_metrics.table_id}`
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY
          timestamp,
          time_unix_nano,
          service_name,
          metric_name,
          metric_type,
          point_fingerprint
        ORDER BY
          receive_time_unix_nano DESC
      ) = 1
    EOT
  }
}

resource "google_bigquery_table" "otel_spans_as_allspans" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "otel_spans_as_allspans"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT
        trace_id,
        span_id,
        trace_state,
        parent_span_id,
        name,
        kind,
        start_time,
        start_time_unix_nano,
        end_time,
        end_time_unix_nano,
        receive_time,
        receive_time_unix_nano,
        duration_nano,
        attributes,
        dropped_attributes_count,
        events,
        dropped_events_count,
        links,
        dropped_links_count,
        STRUCT(status.code AS code, status.message AS message) AS status,
        resource,
        resource_schema_url,
        instrumentation_scope,
        scope_schema_url
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}`
    EOT
  }
}

resource "google_bigquery_table" "otel_logs_as_alllogs" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "otel_logs_as_alllogs"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      -- otel_logs_as_alllogs reads raw ${google_bigquery_table.otel_logs.table_id} directly (unlike otel_spans_as_allspans,
      -- which reads otel_spans_dedup) so BigQuery search-index and cluster predicates
      -- reach base-table storage without a ROW_NUMBER() barrier.
      -- Compatibility caveat: JSON-synthesized STRUCT fields (http_request.*,
      -- resource.type, resource.labels) provide Cloud Logging _AllLogs SQL migration
      -- compatibility rather than physical column pruning or performance parity, and
      -- producer-omitted fields remain NULL.
      SELECT
        timestamp,
        receive_time AS receive_timestamp,
        log_name,
        (
          SELECT
            IF(
              raw_log_id IS NULL OR STRPOS(raw_log_id, '%') = 0,
              raw_log_id,
              (
                SELECT STRING_AGG(
                  IF(
                    STARTS_WITH(part, '%') AND LENGTH(part) > 1,
                    COALESCE(SAFE_CAST(SAFE.FROM_HEX(REPLACE(part, '%', '')) AS STRING), part),
                    part
                  ),
                  '' ORDER BY pos
                )
                FROM UNNEST(REGEXP_EXTRACT_ALL(raw_log_id, r'(?:%[0-9A-Fa-f]{2})+|[^%]+|%')) AS part WITH OFFSET AS pos
              )
            )
          FROM UNNEST([COALESCE(NULLIF(REGEXP_EXTRACT(log_name, '/logs/([^/]+)$'), ''), log_name)]) AS raw_log_id
        ) AS log_id,
        insert_id,
        ['DEFAULT', 'DEBUG', 'INFO', 'NOTICE', 'WARNING', 'ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY'][OFFSET(DIV(
        CASE
          WHEN severity_number BETWEEN 1 AND 8 THEN 100
          WHEN severity_number BETWEEN 9 AND 12 THEN IF(UPPER(TRIM(severity_text)) = 'NOTICE', 300, 200)
          WHEN severity_number BETWEEN 13 AND 16 THEN 400
          WHEN severity_number BETWEEN 17 AND 20 THEN 500
          WHEN severity_number BETWEEN 21 AND 24 THEN
            CASE UPPER(TRIM(severity_text)) WHEN 'ALERT' THEN 700 WHEN 'EMERGENCY' THEN 800 ELSE 600 END
          ELSE
            CASE
              WHEN UPPER(TRIM(severity_text)) IN ('TRACE', 'TRACE2', 'TRACE3', 'TRACE4', 'DEBUG', 'DEBUG2', 'DEBUG3', 'DEBUG4') THEN 100
              WHEN UPPER(TRIM(severity_text)) IN ('INFO', 'INFO2', 'INFO3', 'INFO4') THEN 200
              WHEN UPPER(TRIM(severity_text)) = 'NOTICE' THEN 300
              WHEN UPPER(TRIM(severity_text)) IN ('WARN', 'WARN2', 'WARN3', 'WARN4', 'WARNING') THEN 400
              WHEN UPPER(TRIM(severity_text)) IN ('ERROR', 'ERROR2', 'ERROR3', 'ERROR4') THEN 500
              WHEN UPPER(TRIM(severity_text)) IN ('FATAL', 'FATAL2', 'FATAL3', 'FATAL4', 'CRITICAL') THEN 600
              WHEN UPPER(TRIM(severity_text)) = 'ALERT' THEN 700
              WHEN UPPER(TRIM(severity_text)) = 'EMERGENCY' THEN 800
              ELSE 0
            END
        END,
          100
        ))] AS severity,
        CASE
          WHEN severity_number BETWEEN 1 AND 8 THEN 100
          WHEN severity_number BETWEEN 9 AND 12 THEN IF(UPPER(TRIM(severity_text)) = 'NOTICE', 300, 200)
          WHEN severity_number BETWEEN 13 AND 16 THEN 400
          WHEN severity_number BETWEEN 17 AND 20 THEN 500
          WHEN severity_number BETWEEN 21 AND 24 THEN
            CASE UPPER(TRIM(severity_text)) WHEN 'ALERT' THEN 700 WHEN 'EMERGENCY' THEN 800 ELSE 600 END
          ELSE
            CASE
              WHEN UPPER(TRIM(severity_text)) IN ('TRACE', 'TRACE2', 'TRACE3', 'TRACE4', 'DEBUG', 'DEBUG2', 'DEBUG3', 'DEBUG4') THEN 100
              WHEN UPPER(TRIM(severity_text)) IN ('INFO', 'INFO2', 'INFO3', 'INFO4') THEN 200
              WHEN UPPER(TRIM(severity_text)) = 'NOTICE' THEN 300
              WHEN UPPER(TRIM(severity_text)) IN ('WARN', 'WARN2', 'WARN3', 'WARN4', 'WARNING') THEN 400
              WHEN UPPER(TRIM(severity_text)) IN ('ERROR', 'ERROR2', 'ERROR3', 'ERROR4') THEN 500
              WHEN UPPER(TRIM(severity_text)) IN ('FATAL', 'FATAL2', 'FATAL3', 'FATAL4', 'CRITICAL') THEN 600
              WHEN UPPER(TRIM(severity_text)) = 'ALERT' THEN 700
              WHEN UPPER(TRIM(severity_text)) = 'EMERGENCY' THEN 800
              ELSE 0
            END
        END AS severity_number,
        severity_number AS otel_severity_number,
        severity_text AS otel_severity_text,
        JSON_VALUE(body, '$') AS text_payload,
        IF(
          body IS NOT NULL AND JSON_VALUE(body, '$') IS NULL AND TO_JSON_STRING(body) != 'null',
          body,
          CAST(NULL AS JSON)
        ) AS json_payload,
        attributes AS labels,
        attributes,
        STRUCT(
          COALESCE(
            JSON_VALUE(resource.attributes, '$."gcp.resource_type"'),
            JSON_VALUE(resource.attributes, '$."cloud.platform"'),
            JSON_VALUE(resource.attributes, '$."service.name"'),
            service_name
          ) AS type,
          resource.attributes AS labels
        ) AS resource,
        IF(
          COALESCE(
            JSON_VALUE(attributes, '$."http.request.method"'),
            JSON_VALUE(attributes, '$."http.method"'),
            JSON_VALUE(attributes, '$."url.full"'),
            JSON_VALUE(attributes, '$."http.url"'),
            JSON_VALUE(attributes, '$."url.path"'),
            JSON_VALUE(attributes, '$."http.target"'),
            JSON_VALUE(attributes, '$."user_agent.original"'),
            JSON_VALUE(attributes, '$."http.user_agent"'),
            JSON_VALUE(attributes, '$."client.address"'),
            JSON_VALUE(attributes, '$."http.client_ip"'),
            JSON_VALUE(attributes, '$."net.peer.ip"'),
            JSON_VALUE(attributes, '$."server.address"'),
            JSON_VALUE(attributes, '$."net.host.ip"'),
            JSON_VALUE(attributes, '$."http.request.header.referer"'),
            JSON_VALUE(attributes, '$."http.referer"'),
            JSON_VALUE(attributes, '$."network.protocol.version"'),
            JSON_VALUE(attributes, '$."http.flavor"')
          ) IS NOT NULL
          OR LAX_INT64(attributes['http.response.status_code']) IS NOT NULL
          OR LAX_INT64(attributes['http.status_code']) IS NOT NULL
          OR LAX_INT64(attributes['http.request.body.size']) IS NOT NULL
          OR LAX_INT64(attributes['http.request_content_length']) IS NOT NULL
          OR LAX_INT64(attributes['http.response.body.size']) IS NOT NULL
          OR LAX_INT64(attributes['http.response_content_length']) IS NOT NULL,
          STRUCT(
            COALESCE(JSON_VALUE(attributes, '$."http.request.method"'), JSON_VALUE(attributes, '$."http.method"')) AS request_method,
            COALESCE(JSON_VALUE(attributes, '$."url.full"'), JSON_VALUE(attributes, '$."http.url"'), JSON_VALUE(attributes, '$."url.path"'), JSON_VALUE(attributes, '$."http.target"')) AS request_url,
            COALESCE(LAX_INT64(attributes['http.request.body.size']), LAX_INT64(attributes['http.request_content_length'])) AS request_size,
            COALESCE(LAX_INT64(attributes['http.response.status_code']), LAX_INT64(attributes['http.status_code'])) AS status,
            COALESCE(LAX_INT64(attributes['http.response.body.size']), LAX_INT64(attributes['http.response_content_length'])) AS response_size,
            COALESCE(JSON_VALUE(attributes, '$."user_agent.original"'), JSON_VALUE(attributes, '$."http.user_agent"')) AS user_agent,
            COALESCE(JSON_VALUE(attributes, '$."client.address"'), JSON_VALUE(attributes, '$."http.client_ip"'), JSON_VALUE(attributes, '$."net.peer.ip"')) AS remote_ip,
            COALESCE(JSON_VALUE(attributes, '$."server.address"'), JSON_VALUE(attributes, '$."net.host.ip"')) AS server_ip,
            COALESCE(JSON_VALUE(attributes, '$."http.request.header.referer"'), JSON_VALUE(attributes, '$."http.referer"')) AS referer,
            COALESCE(JSON_VALUE(attributes, '$."network.protocol.version"'), JSON_VALUE(attributes, '$."http.flavor"')) AS protocol
          ),
          NULL
        ) AS http_request,
        trace_id AS trace,
        span_id,
        ((flags & 1) = 1) AS trace_sampled
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_logs.table_id}`
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_spans" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_spans"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT
        start_time,
        end_time,
        duration_nano,
        ROUND(duration_nano / 1e6, 3) AS duration_ms,
        trace_id,
        span_id,
        parent_span_id,
        service_name,
        name AS span_name,
        kind AS span_kind,
        status.code AS status_code,
        status.message AS status_message,
        JSON_VALUE(attributes, '$."gen_ai.operation.name"') AS gen_ai_operation_name,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.system"'),
          JSON_VALUE(attributes, '$."gen_ai.provider.name"')
        ) AS gen_ai_system,
        JSON_VALUE(attributes, '$."gen_ai.request.model"') AS gen_ai_request_model,
        JSON_VALUE(attributes, '$."gen_ai.response.model"') AS gen_ai_response_model,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(attributes, '$."gcp.vertex.agent.name"'),
          service_name
        ) AS gen_ai_agent_name,
        JSON_VALUE(attributes, '$."gen_ai.agent.id"') AS gen_ai_agent_id,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.conversation.id"'),
          JSON_VALUE(attributes, '$."gcp.vertex.agent.session_id"')
        ) AS gen_ai_conversation_id,
        LAX_INT64(attributes['gen_ai.usage.input_tokens']) AS gen_ai_usage_input_tokens,
        LAX_INT64(attributes['gen_ai.usage.output_tokens']) AS gen_ai_usage_output_tokens,
        LAX_FLOAT64(attributes['gen_ai.request.temperature']) AS gen_ai_request_temperature,
        JSON_VALUE(attributes, '$."gen_ai.response.finish_reasons"[0]') AS gen_ai_response_finish_reason,
        JSON_VALUE(attributes, '$."gen_ai.tool.name"') AS gen_ai_tool_name,
        JSON_VALUE(attributes, '$."gen_ai.tool.call.id"') AS gen_ai_tool_call_id,
        JSON_VALUE(attributes, '$."gcp.vertex.agent.event_id"') AS adk_event_id,
        COALESCE(
          JSON_VALUE(attributes, '$."gcp.vertex.agent.session_id"'),
          JSON_VALUE(attributes, '$."gen_ai.conversation.id"')
        ) AS adk_session_id,
        JSON_VALUE(attributes, '$."gcp.vertex.agent.invocation_id"') AS adk_invocation_id,
        COALESCE(
          JSON_VALUE(attributes, '$."user.id"'),
          JSON_VALUE(attributes, '$."gen_ai.user.id"')
        ) AS adk_user_id,
        object_refs,
        attributes,
        resource,
        instrumentation_scope,
        events,
        links,
        JSON_VALUE(attributes, '$."gen_ai.provider.name"') AS gen_ai_provider_name,
        COALESCE(
          LAX_INT64(attributes['gen_ai.usage.cache_read.input_tokens']),
          LAX_INT64(attributes['gen_ai.usage.cache_read_input_tokens'])
        ) AS gen_ai_usage_cache_read_input_tokens,
        COALESCE(
          LAX_INT64(attributes['gen_ai.usage.cache_creation.input_tokens']),
          LAX_INT64(attributes['gen_ai.usage.cache_creation_input_tokens'])
        ) AS gen_ai_usage_cache_creation_input_tokens,
        COALESCE(
          LAX_INT64(attributes['gen_ai.usage.reasoning.output_tokens']),
          LAX_INT64(attributes['gen_ai.usage.reasoning_tokens'])
        ) AS gen_ai_usage_reasoning_tokens,
        LAX_FLOAT64(attributes['gen_ai.request.top_p']) AS gen_ai_request_top_p,
        LAX_INT64(attributes['gen_ai.request.top_k']) AS gen_ai_request_top_k,
        LAX_INT64(attributes['gen_ai.request.max_tokens']) AS gen_ai_request_max_tokens,
        JSON_VALUE(attributes, '$."gen_ai.output.type"') AS gen_ai_output_type,
        JSON_VALUE(attributes, '$."gen_ai.tool.type"') AS gen_ai_tool_type,
        JSON_VALUE(attributes, '$."gen_ai.tool.description"') AS gen_ai_tool_description,
        JSON_VALUE(attributes, '$."gen_ai.agent.description"') AS gen_ai_agent_description,
        JSON_VALUE(attributes, '$."gen_ai.agent.parent.id"') AS gen_ai_agent_parent_id,
        JSON_VALUE(attributes, '$."gen_ai.data_source.id"') AS gen_ai_data_source_id,
        JSON_VALUE(attributes, '$."gen_ai.evaluation.name"') AS gen_ai_evaluation_name,
        COALESCE(
          LAX_FLOAT64(attributes['gen_ai.evaluation.score.value']),
          LAX_FLOAT64(attributes['gen_ai.evaluation.score'])
        ) AS gen_ai_evaluation_score,
        JSON_VALUE(attributes, '$."error.type"') AS error_type,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.main_agent.id"'),
          JSON_VALUE(resource.attributes, '$."gen_ai.main_agent.id"')
        ) AS gen_ai_main_agent_id,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.main_agent.name"'),
          JSON_VALUE(resource.attributes, '$."gen_ai.main_agent.name"')
        ) AS gen_ai_main_agent_name,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.main_agent.description"'),
          JSON_VALUE(resource.attributes, '$."gen_ai.main_agent.description"')
        ) AS gen_ai_main_agent_description,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.agent.version"'),
          JSON_VALUE(resource.attributes, '$."gen_ai.agent.version"')
        ) AS gen_ai_agent_version,
        JSON_VALUE(attributes, '$."gen_ai.response.id"') AS gen_ai_response_id,
        LAX_FLOAT64(attributes['gen_ai.response.time_to_first_chunk']) AS gen_ai_response_time_to_first_chunk
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}`
      WHERE JSON_VALUE(attributes, '$."gen_ai.operation.name"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."gen_ai.system"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."gen_ai.provider.name"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."gen_ai.main_agent.name"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."gen_ai.main_agent.id"') IS NOT NULL
    EOT
  }
}

# Earlier releases created v_gen_ai_logs without count; keep that view as
# instance 0 rather than replacing it.
moved {
  from = google_bigquery_table.v_gen_ai_logs
  to   = google_bigquery_table.v_gen_ai_logs[0]
}

resource "google_bigquery_table" "v_gen_ai_logs" {
  # BigQuery rejects every query over this view while otel_spans requires a
  # partition filter, so it is left out then unless allow_unprunable_views.
  count = (!var.require_partition_filter || var.allow_unprunable_views) ? 1 : 0

  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_logs"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<-EOT
      SELECT
        l.timestamp,
        l.receive_time,
        l.trace_id,
        l.span_id,
        l.service_name,
        COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) AS event_name,
        l.severity_number,
        l.severity_text,
        COALESCE(JSON_VALUE(l.attributes, '$."gen_ai.operation.name"'), JSON_VALUE(s.attributes, '$."gen_ai.operation.name"')) AS gen_ai_operation_name,
        COALESCE(
          JSON_VALUE(l.attributes, '$."gen_ai.system"'),
          JSON_VALUE(l.attributes, '$."gen_ai.provider.name"'),
          JSON_VALUE(s.attributes, '$."gen_ai.system"'),
          JSON_VALUE(s.attributes, '$."gen_ai.provider.name"')
        ) AS gen_ai_system,
        COALESCE(
          JSON_VALUE(l.attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(l.attributes, '$."gcp.vertex.agent.name"'),
          JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"')
        ) AS gen_ai_agent_name,
        COALESCE(
          JSON_VALUE(l.attributes, '$."gcp.vertex.agent.session_id"'),
          JSON_VALUE(l.attributes, '$."gen_ai.conversation.id"'),
          JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
          JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
        ) AS adk_session_id,
        COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.invocation_id"')) AS adk_invocation_id,
        COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.event_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.event_id"')) AS adk_event_id,
        COALESCE(
          JSON_VALUE(l.attributes, '$."user.id"'),
          JSON_VALUE(l.attributes, '$."gen_ai.user.id"'),
          JSON_VALUE(s.attributes, '$."user.id"'),
          JSON_VALUE(s.attributes, '$."gen_ai.user.id"')
        ) AS adk_user_id,
        l.body,
        l.object_refs,
        l.attributes,
        l.resource,
        l.instrumentation_scope,
        JSON_VALUE(l.attributes, '$."error.type"') AS error_type
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_logs_dedup.table_id}` l
      LEFT JOIN `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}` s
        ON l.trace_id = s.trace_id
        AND l.span_id = s.span_id
        AND l.service_name IS NOT DISTINCT FROM s.service_name
        AND s.start_time BETWEEN TIMESTAMP_SUB(l.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(l.timestamp, INTERVAL 1 HOUR)
      WHERE COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) LIKE 'gen_ai.%'
         OR JSON_VALUE(l.attributes, '$."gen_ai.system"') IS NOT NULL
         OR JSON_VALUE(l.attributes, '$."gen_ai.provider.name"') IS NOT NULL
         OR JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_model_costs" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_model_costs"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      WITH cost_spans AS (
        SELECT
          TIMESTAMP_TRUNC(s.start_time, HOUR) AS usage_hour,
          s.service_name,
          s.trace_id,
          s.span_id,
          s.parent_span_id,
          s.gen_ai_agent_name,
          s.gen_ai_provider_name,
          s.gen_ai_system,
          s.gen_ai_request_model,
          s.gen_ai_response_model,
          s.gen_ai_operation_name,
          s.status_code,
          s.duration_ms,
          s.gen_ai_usage_input_tokens,
          s.gen_ai_usage_output_tokens,
          s.gen_ai_usage_cache_read_input_tokens,
          s.gen_ai_usage_cache_creation_input_tokens,
          s.gen_ai_usage_reasoning_tokens,
          s.error_type
        FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_spans.table_id}` AS s
      ),
      cost_windows AS (
        SELECT
          s.*,
          ARRAY_AGG(
            IF(
              s.parent_span_id IS NOT NULL
              AND (s.gen_ai_usage_input_tokens IS NOT NULL OR s.gen_ai_usage_output_tokens IS NOT NULL),
              s.parent_span_id,
              NULL
            )
          ) OVER (
            PARTITION BY s.usage_hour, s.service_name, s.trace_id
          ) AS token_parent_span_ids
        FROM cost_spans AS s
      ),
      cost_agg AS (
        SELECT
          s.usage_hour,
          s.service_name,
          s.gen_ai_agent_name,
          COALESCE(s.gen_ai_provider_name, s.gen_ai_system) AS provider,
          COALESCE(s.gen_ai_response_model, s.gen_ai_request_model) AS model,
          COUNT(*) AS call_count,
          COUNTIF(s.status_code = 2) AS error_count,
          SUM(COALESCE(s.gen_ai_usage_input_tokens, 0)) AS total_input_tokens,
          SUM(COALESCE(s.gen_ai_usage_output_tokens, 0)) AS total_output_tokens,
          SUM(COALESCE(s.gen_ai_usage_cache_read_input_tokens, 0)) AS total_cache_read_input_tokens,
          SUM(COALESCE(s.gen_ai_usage_cache_creation_input_tokens, 0)) AS total_cache_creation_input_tokens,
          SUM(COALESCE(s.gen_ai_usage_reasoning_tokens, 0)) AS total_reasoning_tokens,
          APPROX_QUANTILES(s.duration_ms, 100)[OFFSET(50)] AS p50_duration_ms,
          APPROX_QUANTILES(s.duration_ms, 100)[OFFSET(95)] AS p95_duration_ms,
          APPROX_QUANTILES(s.duration_ms, 100)[OFFSET(99)] AS p99_duration_ms,
          COUNTIF(s.error_type IS NOT NULL) AS typed_error_count,
          APPROX_TOP_COUNT(s.error_type, 6) AS raw_top_error_types
        FROM cost_windows AS s
        WHERE NOT EXISTS (
            SELECT 1 FROM UNNEST(s.token_parent_span_ids) AS token_parent_span_id
            WHERE token_parent_span_id = s.span_id
          )
          AND (
            s.gen_ai_operation_name IN ('chat', 'generate_content', 'text_completion', 'embeddings')
            OR s.gen_ai_request_model IS NOT NULL
          )
          AND (
            COALESCE(s.gen_ai_operation_name, '') NOT IN ('invoke_agent', 'create_agent', 'execute_tool')
            OR s.gen_ai_usage_input_tokens IS NOT NULL
            OR s.gen_ai_usage_output_tokens IS NOT NULL
          )
        GROUP BY 1, 2, 3, 4, 5
      )
      SELECT
        * EXCEPT (raw_top_error_types),
        ARRAY(
          SELECT AS STRUCT x.value, x.count
          FROM UNNEST(raw_top_error_types) AS x
          WHERE x.value IS NOT NULL
          ORDER BY x.count DESC, x.value ASC
          LIMIT 5
        ) AS top_error_types
      FROM cost_agg
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_sessions" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_sessions"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      WITH session_spans AS (
        SELECT
          s.service_name,
          DATE(s.start_time) AS session_start_date,
          COALESCE(s.adk_session_id, s.gen_ai_conversation_id) AS session_id,
          s.adk_user_id,
          s.gen_ai_agent_name,
          s.start_time,
          s.end_time,
          s.trace_id,
          s.span_id,
          s.parent_span_id,
          s.adk_invocation_id,
          s.gen_ai_operation_name,
          s.gen_ai_tool_name,
          s.gen_ai_request_model,
          s.status_code,
          s.gen_ai_usage_input_tokens,
          s.gen_ai_usage_output_tokens,
          s.gen_ai_usage_cache_read_input_tokens,
          s.gen_ai_usage_cache_creation_input_tokens,
          s.gen_ai_usage_reasoning_tokens,
          s.error_type
        FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_spans.table_id}` AS s
        WHERE COALESCE(s.adk_session_id, s.gen_ai_conversation_id) IS NOT NULL
      ),
      session_windows AS (
        SELECT
          s.*,
          ARRAY_AGG(
            IF(
              s.parent_span_id IS NOT NULL
              AND (s.gen_ai_usage_input_tokens IS NOT NULL OR s.gen_ai_usage_output_tokens IS NOT NULL),
              s.parent_span_id,
              NULL
            )
          ) OVER (
            PARTITION BY s.service_name, s.session_start_date, s.session_id, s.trace_id
          ) AS token_parent_span_ids
        FROM session_spans AS s
      ),
      session_calls AS (
        SELECT
          s.*,
          NOT EXISTS (
            SELECT 1 FROM UNNEST(s.token_parent_span_ids) AS token_parent_span_id
            WHERE token_parent_span_id = s.span_id
          ) AS is_token_leaf,
          COALESCE(
            NOT EXISTS (
              SELECT 1 FROM UNNEST(s.token_parent_span_ids) AS token_parent_span_id
              WHERE token_parent_span_id = s.span_id
            )
            AND (
              s.gen_ai_operation_name IN ('chat', 'generate_content', 'text_completion', 'embeddings')
              OR s.gen_ai_request_model IS NOT NULL
            )
            AND (
              COALESCE(s.gen_ai_operation_name, '') NOT IN ('invoke_agent', 'create_agent', 'execute_tool')
              OR s.gen_ai_usage_input_tokens IS NOT NULL
              OR s.gen_ai_usage_output_tokens IS NOT NULL
            ), FALSE
          ) AS is_llm_call
        FROM session_windows AS s
      ),
      session_agg AS (
        SELECT
          session_id,
          ANY_VALUE(adk_user_id) AS user_id,
          service_name,
          ANY_VALUE(gen_ai_agent_name) AS agent_name,
          MIN(start_time) AS session_start_time,
          MAX(end_time) AS session_end_time,
          TIMESTAMP_DIFF(MAX(end_time), MIN(start_time), MILLISECOND) AS session_duration_ms,
          COUNT(DISTINCT trace_id) AS turn_count,
          COUNT(DISTINCT adk_invocation_id) AS invocation_count,
          COUNTIF(gen_ai_operation_name = 'execute_tool' OR gen_ai_tool_name IS NOT NULL) AS tool_call_count,
          COUNTIF(status_code = 2) AS error_count,
          SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_input_tokens, 0), 0)) AS total_input_tokens,
          SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_output_tokens, 0), 0)) AS total_output_tokens,
          SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_cache_read_input_tokens, 0), 0)) AS total_cache_read_input_tokens,
          SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_reasoning_tokens, 0), 0)) AS total_reasoning_tokens,
          session_start_date,
          SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_cache_creation_input_tokens, 0), 0)) AS total_cache_creation_input_tokens,
          COUNTIF(is_llm_call) AS llm_call_count,
          COUNTIF(gen_ai_operation_name = 'invoke_agent') AS agent_invocation_count,
          COUNTIF(error_type IS NOT NULL) AS typed_error_count,
          APPROX_TOP_COUNT(error_type, 6) AS raw_top_error_types
        FROM session_calls
        GROUP BY service_name, session_start_date, session_id
      )
      SELECT
        * EXCEPT (raw_top_error_types),
        ARRAY(
          SELECT AS STRUCT x.value, x.count
          FROM UNNEST(raw_top_error_types) AS x
          WHERE x.value IS NOT NULL
          ORDER BY x.count DESC, x.value ASC
          LIMIT 5
        ) AS top_error_types
      FROM session_agg
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_metrics" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_metrics"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      SELECT
        timestamp,
        start_time,
        receive_time,
        service_name,
        metric_name,
        metric_description,
        metric_unit,
        metric_type,
        aggregation_temporality,
        is_monotonic,
        JSON_VALUE(attributes, '$."gen_ai.operation.name"') AS gen_ai_operation_name,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.system"'),
          JSON_VALUE(attributes, '$."gen_ai.provider.name"')
        ) AS gen_ai_system,
        JSON_VALUE(attributes, '$."gen_ai.provider.name"') AS gen_ai_provider_name,
        JSON_VALUE(attributes, '$."gen_ai.request.model"') AS gen_ai_request_model,
        JSON_VALUE(attributes, '$."gen_ai.response.model"') AS gen_ai_response_model,
        JSON_VALUE(attributes, '$."gen_ai.token.type"') AS gen_ai_token_type,
        JSON_VALUE(attributes, '$."error.type"') AS error_type,
        value_type,
        value_double,
        value_int64,
        count,
        sum,
        min,
        max,
        explicit_bounds,
        bucket_counts,
        exp_scale,
        exp_zero_count,
        exp_zero_threshold,
        exp_positive,
        exp_negative,
        summary_quantiles,
        exemplars,
        attributes,
        resource,
        instrumentation_scope,
        JSON_VALUE(attributes, '$."gen_ai.token.modality"') AS gen_ai_token_modality,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(attributes, '$."gen_ai.main_agent.name"'),
          JSON_VALUE(resource.attributes, '$."gen_ai.main_agent.name"')
        ) AS gen_ai_agent_name,
        CASE
          WHEN metric_name = 'gen_ai.client.inference.usage.input_tokens' THEN 'input'
          WHEN metric_name = 'gen_ai.client.inference.usage.output_tokens' THEN 'output'
          WHEN metric_name = 'gen_ai.client.inference.usage.cache_read.input_tokens' THEN 'cache_read_input'
          WHEN metric_name = 'gen_ai.client.inference.usage.cache_write.input_tokens' THEN 'cache_write_input'
          WHEN metric_name = 'gen_ai.client.inference.usage.reasoning.output_tokens' THEN 'reasoning_output'
          ELSE JSON_VALUE(attributes, '$."gen_ai.token.type"')
        END AS gen_ai_inference_usage_dimension,
        time_unix_nano,
        point_fingerprint
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_metrics_dedup.table_id}`
      WHERE metric_name LIKE 'gen_ai.%'
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_metric_exemplars" {
  # Like v_gen_ai_logs, left out while otel_spans requires a partition filter
  # unless allow_unprunable_views.
  count = (!var.require_partition_filter || var.allow_unprunable_views) ? 1 : 0

  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_metric_exemplars"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      SELECT
        m.timestamp AS metric_timestamp,
        m.service_name,
        m.metric_name,
        m.metric_unit,
        m.metric_type,
        m.gen_ai_operation_name,
        m.gen_ai_system,
        m.gen_ai_request_model,
        m.gen_ai_response_model,
        m.gen_ai_agent_name,
        m.gen_ai_token_type,
        m.gen_ai_token_modality,
        m.error_type AS metric_error_type,
        ex.time AS exemplar_timestamp,
        ex.value_double AS exemplar_value_double,
        ex.value_int64 AS exemplar_value_int64,
        ex.trace_id AS trace_id,
        ex.span_id AS span_id,
        ex.filtered_attributes AS exemplar_filtered_attributes,
        s.start_time AS span_start_time,
        s.end_time AS span_end_time,
        s.duration_nano AS span_duration_nano,
        ROUND(s.duration_nano / 1e6, 3) AS span_duration_ms,
        s.name AS span_name,
        s.status.code AS span_status_code,
        s.status.message AS span_status_message,
        COALESCE(
          JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"'),
          JSON_VALUE(s.resource.attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(s.attributes, '$."gen_ai.main_agent.name"'),
          JSON_VALUE(s.resource.attributes, '$."gen_ai.main_agent.name"')
        ) AS span_gen_ai_agent_name,
        JSON_VALUE(s.attributes, '$."gen_ai.tool.name"') AS span_gen_ai_tool_name,
        COALESCE(
          JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
          JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
        ) AS adk_session_id,
        JSON_VALUE(s.attributes, '$."error.type"') AS span_error_type
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_metrics.table_id}` m,
      UNNEST(m.exemplars) AS ex WITH OFFSET AS exemplar_ordinal
      LEFT JOIN `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}` s
        ON s.trace_id = ex.trace_id
        AND s.span_id = ex.span_id
        AND s.service_name IS NOT DISTINCT FROM m.service_name
        AND s.start_time BETWEEN TIMESTAMP_SUB(m.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(m.timestamp, INTERVAL 1 HOUR)
      WHERE ex.trace_id IS NOT NULL
        AND ex.span_id IS NOT NULL
        AND ex.trace_id != ''
        AND ex.span_id != ''
      QUALIFY ROW_NUMBER() OVER (
        PARTITION BY m.timestamp, m.time_unix_nano, m.service_name, m.metric_name, m.metric_type, m.point_fingerprint, exemplar_ordinal
        ORDER BY s.end_time DESC, s.start_time DESC, s.receive_time DESC, s.name ASC
      ) = 1
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_tool_usage" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_tool_usage"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      WITH tool_agg AS (
        SELECT
          TIMESTAMP_TRUNC(start_time, HOUR) AS usage_hour,
          service_name,
          gen_ai_agent_name,
          gen_ai_tool_name,
          gen_ai_tool_type,
          COUNT(*) AS call_count,
          COUNTIF(status_code = 2) AS error_count,
          SAFE_DIVIDE(COUNTIF(status_code = 2), COUNT(*)) AS error_rate,
          APPROX_QUANTILES(duration_ms, 100)[OFFSET(50)] AS p50_duration_ms,
          APPROX_QUANTILES(duration_ms, 100)[OFFSET(95)] AS p95_duration_ms,
          COUNTIF(error_type IS NOT NULL) AS typed_error_count,
          APPROX_TOP_COUNT(error_type, 6) AS raw_top_error_types
        FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_spans.table_id}`
        WHERE gen_ai_tool_name IS NOT NULL OR gen_ai_operation_name = 'execute_tool'
        GROUP BY 1, 2, 3, 4, 5
      )
      SELECT
        * EXCEPT (raw_top_error_types),
        ARRAY(
          SELECT AS STRUCT x.value, x.count
          FROM UNNEST(raw_top_error_types) AS x
          WHERE x.value IS NOT NULL
          ORDER BY x.count DESC, x.value ASC
          LIMIT 5
        ) AS top_error_types
      FROM tool_agg
    EOT
  }
}

resource "google_bigquery_table" "v_gen_ai_agent_trajectory" {
  # Like v_gen_ai_logs, left out while otel_spans requires a partition filter
  # unless allow_unprunable_views: it joins each span to its parent and child
  # spans on a window that depends on each row.
  count = (!var.require_partition_filter || var.allow_unprunable_views) ? 1 : 0

  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_gen_ai_agent_trajectory"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      WITH
        spans AS (
          SELECT
            start_time,
            end_time,
            duration_nano,
            duration_ms,
            trace_id,
            span_id,
            parent_span_id,
            service_name,
            span_name,
            span_kind,
            status_code,
            status_message,
            gen_ai_operation_name,
            gen_ai_system,
            gen_ai_provider_name,
            gen_ai_request_model,
            gen_ai_response_model,
            gen_ai_agent_id,
            gen_ai_agent_name,
            gen_ai_agent_version,
            gen_ai_main_agent_id,
            gen_ai_main_agent_name,
            gen_ai_tool_name,
            gen_ai_tool_call_id,
            gen_ai_usage_input_tokens,
            gen_ai_usage_output_tokens,
            gen_ai_usage_reasoning_tokens,
            adk_session_id,
            adk_invocation_id,
            adk_user_id,
            error_type,
            COALESCE(
              JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
              JSON_VALUE(attributes, '$."gcp.vertex.agent.name"')
            ) AS declared_agent_name,
            COALESCE(
              JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
              JSON_VALUE(attributes, '$."gcp.vertex.agent.name"'),
              IF(gen_ai_operation_name IN ('invoke_agent', 'create_agent'), gen_ai_agent_name, NULL)
            ) AS agent_path_name
          FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_spans.table_id}`
          QUALIFY ROW_NUMBER() OVER (
            PARTITION BY trace_id, service_name, span_id
            ORDER BY start_time ASC, end_time DESC, span_name ASC, duration_nano DESC
          ) = 1
        ),
        topo_raw AS (
          SELECT
            trace_id,
            service_name,
            ARRAY_AGG(
              STRUCT(
                start_time,
                span_id,
                parent_span_id,
                (parent_span_id IS NOT NULL AND parent_span_id != '') AS has_parent_id,
                (gen_ai_operation_name IN ('invoke_agent', 'create_agent')) AS is_agent_op,
                (declared_agent_name IS NOT NULL) AS has_declared_agent,
                COALESCE(declared_agent_name, gen_ai_agent_name) AS resolved_agent_name,
                agent_path_name,
                (gen_ai_usage_input_tokens IS NOT NULL) AS has_in,
                (gen_ai_usage_output_tokens IS NOT NULL) AS has_out,
                (gen_ai_usage_reasoning_tokens IS NOT NULL) AS has_reas
              )
              ORDER BY start_time ASC, span_id ASC
            ) AS topo_nodes
          FROM spans
          GROUP BY trace_id, service_name
        ),
        topo_edges AS (
          SELECT
            g.trace_id,
            g.service_name,
            g.topo_nodes,
            ARRAY(
              SELECT AS STRUCT
                p_idx AS raw_parent_idx,
                IF(
                  p_idx IS NOT NULL
                    AND p.start_time BETWEEN TIMESTAMP_SUB(n.start_time, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(n.start_time, INTERVAL 1 HOUR),
                  p_idx,
                  CAST(NULL AS INT64)
                ) AS tree_parent_idx
              FROM UNNEST(g.topo_nodes) AS n
                WITH OFFSET AS n_idx
              LEFT JOIN UNNEST(g.topo_nodes) AS p
                WITH OFFSET AS p_idx
                ON n.has_parent_id
                AND p.span_id = n.parent_span_id
              ORDER BY n_idx ASC
            ) AS edges
          FROM topo_raw AS g
        ),
        topo_walks AS (
          SELECT
            g.trace_id,
            g.service_name,
            g.topo_nodes,
            g.edges,
            ARRAY(
              SELECT AS STRUCT
                ARRAY(
                  SELECT anc_idx
                  FROM UNNEST([
                    n_idx,
                    e0.tree_parent_idx,
                    e1.tree_parent_idx,
                    e2.tree_parent_idx,
                    e3.tree_parent_idx,
                    e4.tree_parent_idx,
                    e5.tree_parent_idx,
                    e6.tree_parent_idx,
                    e7.tree_parent_idx,
                    e8.tree_parent_idx,
                    e9.tree_parent_idx,
                    e10.tree_parent_idx,
                    e11.tree_parent_idx,
                    e12.tree_parent_idx,
                    e13.tree_parent_idx,
                    e14.tree_parent_idx,
                    e15.tree_parent_idx
                  ]) AS anc_idx
                    WITH OFFSET AS hop_ord
                  WHERE anc_idx IS NOT NULL
                  ORDER BY hop_ord DESC
                ) AS root_to_self,
                IF(
                  e16.tree_parent_idx IS NULL,
                  (
                    SELECT COUNT(anc_idx)
                    FROM UNNEST([
                      e0.tree_parent_idx,
                      e1.tree_parent_idx,
                      e2.tree_parent_idx,
                      e3.tree_parent_idx,
                      e4.tree_parent_idx,
                      e5.tree_parent_idx,
                      e6.tree_parent_idx,
                      e7.tree_parent_idx,
                      e8.tree_parent_idx,
                      e9.tree_parent_idx,
                      e10.tree_parent_idx,
                      e11.tree_parent_idx,
                      e12.tree_parent_idx,
                      e13.tree_parent_idx,
                      e14.tree_parent_idx,
                      e15.tree_parent_idx
                    ]) AS anc_idx
                  ),
                  17
                ) AS depth
              FROM UNNEST(g.edges) AS e0
                WITH OFFSET AS n_idx
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e0.tree_parent_idx)]]) AS e1 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e1.tree_parent_idx)]]) AS e2 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e2.tree_parent_idx)]]) AS e3 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e3.tree_parent_idx)]]) AS e4 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e4.tree_parent_idx)]]) AS e5 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e5.tree_parent_idx)]]) AS e6 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e6.tree_parent_idx)]]) AS e7 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e7.tree_parent_idx)]]) AS e8 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e8.tree_parent_idx)]]) AS e9 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e9.tree_parent_idx)]]) AS e10 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e10.tree_parent_idx)]]) AS e11 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e11.tree_parent_idx)]]) AS e12 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e12.tree_parent_idx)]]) AS e13 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e13.tree_parent_idx)]]) AS e14 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e14.tree_parent_idx)]]) AS e15 ON TRUE
              LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e15.tree_parent_idx)]]) AS e16 ON TRUE
              ORDER BY n_idx ASC
            ) AS tree_info
          FROM topo_edges AS g
        ),
        topo_emitted AS (
          SELECT
            g.trace_id,
            g.service_name,
            g.topo_nodes,
            g.edges,
            g.tree_info,
            ARRAY(
              SELECT
                IF(
                  ti.depth <= 16
                    AND e.raw_parent_idx IS NOT NULL
                    AND e.raw_parent_idx != n_idx
                    AND g.tree_info[SAFE_OFFSET(e.raw_parent_idx)].depth <= 16,
                  e.raw_parent_idx,
                  CAST(NULL AS INT64)
                )
              FROM UNNEST(g.edges) AS e
                WITH OFFSET AS n_idx
              INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
              ORDER BY n_idx ASC
            ) AS emitted_parent_idxs
          FROM topo_walks AS g
        ),
        topo_ancestors AS (
          SELECT
            g.trace_id,
            g.service_name,
            g.topo_nodes,
            g.edges,
            g.tree_info,
            ARRAY(
              SELECT AS STRUCT
                ARRAY(
                  SELECT DISTINCT anc_idx
                  FROM UNNEST([
                    p1, p2, p3, p4, p5, p6, p7, p8,
                    p9, p10, p11, p12, p13, p14, p15, p16,
                    p17, p18, p19, p20, p21, p22, p23, p24,
                    p25, p26, p27, p28, p29, p30, p31, p32
                  ]) AS anc_idx
                  WHERE anc_idx IS NOT NULL
                    AND anc_idx != n_idx
                ) AS anc_idxs
              FROM UNNEST(g.emitted_parent_idxs) AS p1
                WITH OFFSET AS n_idx
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p1)]]) AS p2 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p2)]]) AS p3 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p3)]]) AS p4 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p4)]]) AS p5 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p5)]]) AS p6 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p6)]]) AS p7 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p7)]]) AS p8 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p8)]]) AS p9 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p9)]]) AS p10 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p10)]]) AS p11 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p11)]]) AS p12 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p12)]]) AS p13 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p13)]]) AS p14 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p14)]]) AS p15 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p15)]]) AS p16 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p16)]]) AS p17 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p17)]]) AS p18 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p18)]]) AS p19 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p19)]]) AS p20 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p20)]]) AS p21 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p21)]]) AS p22 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p22)]]) AS p23 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p23)]]) AS p24 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p24)]]) AS p25 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p25)]]) AS p26 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p26)]]) AS p27 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p27)]]) AS p28 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p28)]]) AS p29 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p29)]]) AS p30 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p30)]]) AS p31 ON TRUE
              LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p31)]]) AS p32 ON TRUE
              ORDER BY n_idx ASC
            ) AS emitted_ancs
          FROM topo_emitted AS g
        ),
        topo_cov AS (
          SELECT
            g.trace_id,
            g.service_name,
            g.topo_nodes,
            g.edges,
            g.tree_info,
            ARRAY(
              SELECT AS STRUCT
                anc_idx,
                LOGICAL_OR(d_node.has_in) AS has_input,
                LOGICAL_OR(d_node.has_out) AS has_output,
                LOGICAL_OR(d_node.has_reas) AS has_reasoning
              FROM UNNEST(g.emitted_ancs) AS d_anc
                WITH OFFSET AS d_idx
              INNER JOIN UNNEST([g.topo_nodes[OFFSET(d_idx)]]) AS d_node ON TRUE
              INNER JOIN UNNEST(d_anc.anc_idxs) AS anc_idx
              INNER JOIN UNNEST([g.topo_nodes[OFFSET(anc_idx)]]) AS a_node ON TRUE
              WHERE (d_node.has_in OR d_node.has_out OR d_node.has_reas)
                AND (
                  d_idx NOT IN UNNEST(g.emitted_ancs[OFFSET(anc_idx)].anc_idxs)
                  OR d_node.start_time > a_node.start_time
                  OR (d_node.start_time = a_node.start_time AND d_node.span_id > a_node.span_id)
                )
              GROUP BY anc_idx
            ) AS cov_rows
          FROM topo_ancestors AS g
        ),
        resolved_topology AS (
          SELECT
            g.trace_id,
            g.service_name,
            n.span_id,
            ti.depth,
            g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].span_id AS root_span_id,
            COALESCE(
              (
                SELECT g.topo_nodes[OFFSET(p_idx)].span_id
                FROM UNNEST(ti.root_to_self) AS p_idx
                  WITH OFFSET AS pos
                WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
                ORDER BY pos DESC
                LIMIT 1
              ),
              (
                SELECT g.topo_nodes[OFFSET(p_idx)].span_id
                FROM UNNEST(ti.root_to_self) AS p_idx
                  WITH OFFSET AS pos
                WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
                ORDER BY pos ASC
                LIMIT 1
              )
            ) AS nearest_agent_span_id,
            IF(
              EXISTS (
                SELECT 1
                FROM UNNEST(ti.root_to_self) AS p_idx
                WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
              ),
              (
                SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
                FROM UNNEST(ti.root_to_self) AS p_idx
                  WITH OFFSET AS pos
                WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
                ORDER BY pos DESC
                LIMIT 1
              ),
              (
                SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
                FROM UNNEST(ti.root_to_self) AS p_idx
                  WITH OFFSET AS pos
                WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
                ORDER BY pos ASC
                LIMIT 1
              )
            ) AS nearest_agent_name,
            ARRAY(
              SELECT g.topo_nodes[OFFSET(p_idx)].agent_path_name
              FROM UNNEST(ti.root_to_self) AS p_idx
                WITH OFFSET AS pos
              WHERE g.topo_nodes[OFFSET(p_idx)].agent_path_name IS NOT NULL
                AND (
                  pos = 0
                  OR g.topo_nodes[OFFSET(p_idx)].agent_path_name IS DISTINCT FROM (
                    SELECT g.topo_nodes[OFFSET(prev_idx)].agent_path_name
                    FROM UNNEST(ti.root_to_self) AS prev_idx
                      WITH OFFSET AS prev_pos
                    WHERE prev_pos < pos
                      AND g.topo_nodes[OFFSET(prev_idx)].agent_path_name IS NOT NULL
                    ORDER BY prev_pos DESC
                    LIMIT 1
                  )
                )
              ORDER BY pos ASC
            ) AS agent_path,
            g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].has_parent_id AS is_orphan,
            IF(
              EXISTS (
                SELECT 1
                FROM UNNEST(g.edges) AS ce
                WHERE ce.raw_parent_idx = n_idx
              ),
              n.span_id,
              CAST(NULL AS STRING)
            ) AS leaf_parent_span_id,
            COALESCE(cov.has_input, FALSE) AS cov_has_input,
            COALESCE(cov.has_output, FALSE) AS cov_has_output,
            COALESCE(cov.has_reasoning, FALSE) AS cov_has_reasoning
          FROM topo_cov AS g
          INNER JOIN UNNEST(g.topo_nodes) AS n
            WITH OFFSET AS n_idx
          INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
          LEFT JOIN UNNEST(g.cov_rows) AS cov
            ON cov.anc_idx = n_idx
          WHERE ti.depth <= 16
        ),
        trajectory AS (
          SELECT
            s.start_time,
            s.end_time,
            s.duration_nano,
            s.duration_ms,
            s.trace_id,
            s.span_id,
            s.parent_span_id,
            s.service_name,
            s.span_name,
            s.span_kind,
            s.status_code,
            s.status_message,
            s.gen_ai_operation_name,
            s.gen_ai_system,
            s.gen_ai_provider_name,
            s.gen_ai_request_model,
            s.gen_ai_response_model,
            s.gen_ai_agent_id,
            s.gen_ai_agent_name,
            s.gen_ai_agent_version,
            s.gen_ai_main_agent_id,
            s.gen_ai_main_agent_name,
            s.gen_ai_tool_name,
            s.gen_ai_tool_call_id,
            s.gen_ai_usage_input_tokens,
            s.gen_ai_usage_output_tokens,
            s.gen_ai_usage_reasoning_tokens,
            s.adk_session_id,
            s.adk_invocation_id,
            s.adk_user_id,
            s.error_type,
            r.depth,
            r.root_span_id,
            r.nearest_agent_span_id,
            r.nearest_agent_name,
            r.agent_path,
            r.is_orphan,
            r.leaf_parent_span_id,
            r.cov_has_input,
            r.cov_has_output,
            r.cov_has_reasoning
          FROM resolved_topology AS r
          INNER JOIN spans AS s
            ON s.trace_id = r.trace_id
            AND s.span_id = r.span_id
            AND s.service_name IS NOT DISTINCT FROM r.service_name
        )
      SELECT
        t.start_time,
        t.end_time,
        t.duration_nano,
        t.duration_ms,
        t.trace_id,
        t.span_id,
        t.parent_span_id,
        t.service_name,
        t.span_name,
        t.span_kind,
        t.status_code,
        t.status_message,
        t.gen_ai_operation_name,
        t.gen_ai_system,
        t.gen_ai_provider_name,
        t.gen_ai_request_model,
        t.gen_ai_response_model,
        t.gen_ai_agent_id,
        t.gen_ai_agent_name,
        t.gen_ai_agent_version,
        t.gen_ai_main_agent_id,
        t.gen_ai_main_agent_name,
        t.gen_ai_tool_name,
        t.gen_ai_tool_call_id,
        IF(
          COALESCE(token_leaf_check.has_input, FALSE)
          AND (
            (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
            OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
          ),
          CAST(NULL AS INT64),
          t.gen_ai_usage_input_tokens
        ) AS gen_ai_usage_input_tokens,
        IF(
          COALESCE(token_leaf_check.has_output, FALSE)
          AND (
            (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
            OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
          ),
          CAST(NULL AS INT64),
          t.gen_ai_usage_output_tokens
        ) AS gen_ai_usage_output_tokens,
        IF(
          COALESCE(token_leaf_check.has_reasoning, FALSE)
          AND (
            (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
            OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
          ),
          CAST(NULL AS INT64),
          t.gen_ai_usage_reasoning_tokens
        ) AS gen_ai_usage_reasoning_tokens,
        t.adk_session_id,
        t.adk_invocation_id,
        t.adk_user_id,
        t.error_type,
        t.depth,
        t.root_span_id,
        t.nearest_agent_span_id,
        t.nearest_agent_name,
        t.agent_path,
        t.is_orphan,
        ROW_NUMBER() OVER (
          PARTITION BY t.trace_id, t.service_name
          ORDER BY t.start_time ASC, t.span_id ASC
        ) AS step_index,
        (leaf_check.span_id IS NULL) AS is_leaf,
        (
          (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
          OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
          OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
        ) AS is_token_leaf
      FROM trajectory AS t
      LEFT JOIN UNNEST([STRUCT(t.leaf_parent_span_id AS span_id)]) AS leaf_check
        ON leaf_check.span_id IS NOT NULL
      LEFT JOIN UNNEST([
        STRUCT(
          t.cov_has_input AS has_input,
          t.cov_has_output AS has_output,
          t.cov_has_reasoning AS has_reasoning
        )
      ]) AS token_leaf_check
        ON TRUE
    EOT
  }
}

resource "google_bigquery_table" "v_mcp_spans" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_mcp_spans"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      SELECT
        start_time,
        end_time,
        duration_nano,
        ROUND(duration_nano / 1e6, 3) AS duration_ms,
        trace_id,
        span_id,
        parent_span_id,
        service_name,
        name AS span_name,
        kind AS span_kind,
        status.code AS status_code,
        status.message AS status_message,
        -- Promoted OTel MCP & JSON-RPC semantic convention attributes (v1.40.0)
        JSON_VALUE(attributes, '$."mcp.method.name"') AS mcp_method_name,
        JSON_VALUE(attributes, '$."mcp.protocol.version"') AS mcp_protocol_version,
        JSON_VALUE(attributes, '$."mcp.session.id"') AS mcp_session_id,
        JSON_VALUE(attributes, '$."mcp.resource.uri"') AS mcp_resource_uri,
        JSON_VALUE(attributes, '$."jsonrpc.request.id"') AS jsonrpc_request_id,
        JSON_VALUE(attributes, '$."rpc.response.status_code"') AS rpc_response_status_code,
        -- Promoted GenAI correlation attributes for dual-tagged MCP spans
        JSON_VALUE(attributes, '$."gen_ai.operation.name"') AS gen_ai_operation_name,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.system"'),
          JSON_VALUE(attributes, '$."gen_ai.provider.name"')
        ) AS gen_ai_system,
        JSON_VALUE(attributes, '$."gen_ai.tool.name"') AS gen_ai_tool_name,
        JSON_VALUE(attributes, '$."gen_ai.tool.call.id"') AS gen_ai_tool_call_id,
        JSON_VALUE(attributes, '$."gen_ai.prompt.name"') AS gen_ai_prompt_name,
        COALESCE(
          JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
          JSON_VALUE(attributes, '$."gcp.vertex.agent.name"'),
          JSON_VALUE(attributes, '$."gen_ai.main_agent.name"')
        ) AS gen_ai_agent_name,
        JSON_VALUE(attributes, '$."error.type"') AS error_type,
        -- Server endpoint correlation
        JSON_VALUE(attributes, '$."server.address"') AS server_address,
        LAX_INT64(attributes['server.port']) AS server_port,
        JSON_VALUE(attributes, '$."network.transport"') AS network_transport,
        -- MCP classification and v_gen_ai_spans overlap flag
        COALESCE(JSON_VALUE(attributes, '$."mcp.method.name"') = 'tools/call', FALSE) AS is_tool_call,
        (
          JSON_VALUE(attributes, '$."gen_ai.operation.name"') IS NOT NULL
          OR JSON_VALUE(attributes, '$."gen_ai.system"') IS NOT NULL
          OR JSON_VALUE(attributes, '$."gen_ai.provider.name"') IS NOT NULL
          OR JSON_VALUE(attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
          OR JSON_VALUE(attributes, '$."gen_ai.main_agent.name"') IS NOT NULL
          OR JSON_VALUE(attributes, '$."gen_ai.main_agent.id"') IS NOT NULL
        ) AS also_in_gen_ai_view,
        -- Multimodal ObjectRef array and raw bags
        object_refs,
        attributes,
        resource,
        instrumentation_scope
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}`
      WHERE JSON_VALUE(attributes, '$."mcp.method.name"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."mcp.session.id"') IS NOT NULL
         OR JSON_VALUE(attributes, '$."mcp.resource.uri"') IS NOT NULL
    EOT
  }
}

resource "google_bigquery_table" "v_mcp_tool_usage" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = "v_mcp_tool_usage"

  deletion_protection = false
  labels              = var.labels

  view {
    use_legacy_sql = false
    query          = <<EOT
      WITH mcp_tool_agg AS (
        SELECT
          TIMESTAMP_TRUNC(start_time, HOUR) AS usage_hour,
          service_name,
          mcp_method_name,
          mcp_protocol_version,
          gen_ai_tool_name,
          COALESCE(gen_ai_tool_name, mcp_resource_uri, gen_ai_prompt_name) AS mcp_target_name,
          span_kind,
          server_address,
          COUNT(*) AS call_count,
          COUNTIF(also_in_gen_ai_view) AS gen_ai_tagged_call_count,
          COUNTIF(status_code = 2 OR error_type IS NOT NULL) AS error_count,
          COUNTIF(error_type IS NOT NULL) AS typed_error_count,
          APPROX_TOP_COUNT(error_type, 6) AS raw_top_error_types,
          SAFE_DIVIDE(COUNTIF(status_code = 2 OR error_type IS NOT NULL), COUNT(*)) AS error_rate,
          ROUND(AVG(duration_ms), 3) AS avg_duration_ms,
          APPROX_QUANTILES(duration_ms, 100)[OFFSET(50)] AS p50_duration_ms,
          APPROX_QUANTILES(duration_ms, 100)[OFFSET(95)] AS p95_duration_ms,
          APPROX_QUANTILES(duration_ms, 100)[OFFSET(99)] AS p99_duration_ms
        FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_mcp_spans.table_id}`
        GROUP BY usage_hour, service_name, mcp_method_name, mcp_protocol_version, gen_ai_tool_name, mcp_target_name, span_kind, server_address
      )
      SELECT
        usage_hour,
        service_name,
        mcp_method_name,
        mcp_protocol_version,
        gen_ai_tool_name,
        mcp_target_name,
        span_kind,
        server_address,
        call_count,
        gen_ai_tagged_call_count,
        error_count,
        typed_error_count,
        ARRAY(
          SELECT AS STRUCT x.value, x.count
          FROM UNNEST(raw_top_error_types) AS x
          WHERE x.value IS NOT NULL
          ORDER BY x.count DESC, x.value ASC
          LIMIT 5
        ) AS top_error_types,
        error_rate,
        avg_duration_ms,
        p50_duration_ms,
        p95_duration_ms,
        p99_duration_ms
      FROM mcp_tool_agg
    EOT
  }
}

# --- Bounded-Window Table-Valued Functions (partition-prunable under require_partition_filter = true) ---
#
# When require_partition_filter = true is set on otel_spans, otel_logs, or
# otel_metrics, BigQuery's static partition-filter validator cannot push an
# outer WHERE predicate through the per-row [-24h, +1h] span join window of
# v_gen_ai_logs and v_gen_ai_metric_exemplars or the recursive CTE of
# v_gen_ai_agent_trajectory. The two Table-Valued Functions tvf_gen_ai_logs
# and tvf_gen_ai_metric_exemplars accept two arguments (start_ts TIMESTAMP,
# end_ts TIMESTAMP) and push static partition predicates directly into the
# underlying deduplication / GenAI views. The trajectory TVF
# tvf_gen_ai_agent_trajectory accepts four arguments (start_ts TIMESTAMP,
# end_ts TIMESTAMP, context_start_ts TIMESTAMP, context_end_ts TIMESTAMP)
# where the first pair bounds the emitted segment and the second pair bounds
# the recursive ancestor context. All three succeed with full partition
# pruning even when require_partition_filter = true.

resource "google_bigquery_routine" "tvf_gen_ai_logs" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.otel.dataset_id
  routine_id   = "tvf_gen_ai_logs"
  routine_type = "TABLE_VALUED_FUNCTION"
  language     = "SQL"
  description  = "Bounded-window partition-prunable counterpart of v_gen_ai_logs accepting (start_ts, end_ts)."

  arguments {
    name      = "start_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  arguments {
    name      = "end_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  definition_body = <<-EOT
    SELECT
      l.timestamp,
      l.receive_time,
      l.trace_id,
      l.span_id,
      l.service_name,
      COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) AS event_name,
      l.severity_number,
      l.severity_text,
      COALESCE(JSON_VALUE(l.attributes, '$."gen_ai.operation.name"'), JSON_VALUE(s.attributes, '$."gen_ai.operation.name"')) AS gen_ai_operation_name,
      COALESCE(
        JSON_VALUE(l.attributes, '$."gen_ai.system"'),
        JSON_VALUE(l.attributes, '$."gen_ai.provider.name"'),
        JSON_VALUE(s.attributes, '$."gen_ai.system"'),
        JSON_VALUE(s.attributes, '$."gen_ai.provider.name"')
      ) AS gen_ai_system,
      COALESCE(
        JSON_VALUE(l.attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(l.attributes, '$."gcp.vertex.agent.name"'),
        JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"')
      ) AS gen_ai_agent_name,
      COALESCE(
        JSON_VALUE(l.attributes, '$."gcp.vertex.agent.session_id"'),
        JSON_VALUE(l.attributes, '$."gen_ai.conversation.id"'),
        JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
        JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
      ) AS adk_session_id,
      COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.invocation_id"')) AS adk_invocation_id,
      COALESCE(JSON_VALUE(l.attributes, '$."gcp.vertex.agent.event_id"'), JSON_VALUE(s.attributes, '$."gcp.vertex.agent.event_id"')) AS adk_event_id,
      COALESCE(
        JSON_VALUE(l.attributes, '$."user.id"'),
        JSON_VALUE(l.attributes, '$."gen_ai.user.id"'),
        JSON_VALUE(s.attributes, '$."user.id"'),
        JSON_VALUE(s.attributes, '$."gen_ai.user.id"')
      ) AS adk_user_id,
      l.body,
      l.object_refs,
      l.attributes,
      l.resource,
      l.instrumentation_scope,
      JSON_VALUE(l.attributes, '$."error.type"') AS error_type
    FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_logs_dedup.table_id}` AS l
    LEFT JOIN (
      SELECT *
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}`
      WHERE start_time >= TIMESTAMP_SUB(start_ts, INTERVAL 24 HOUR)
        AND start_time <= TIMESTAMP_ADD(end_ts, INTERVAL 1 HOUR)
    ) AS s
      ON l.trace_id = s.trace_id
      AND l.span_id = s.span_id
      AND l.service_name IS NOT DISTINCT FROM s.service_name
      AND s.start_time BETWEEN TIMESTAMP_SUB(l.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(l.timestamp, INTERVAL 1 HOUR)
    WHERE l.timestamp >= start_ts
      AND l.timestamp < end_ts
      AND (
        COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) LIKE 'gen_ai.%'
        OR JSON_VALUE(l.attributes, '$."gen_ai.system"') IS NOT NULL
        OR JSON_VALUE(l.attributes, '$."gen_ai.provider.name"') IS NOT NULL
        OR JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
      )
  EOT
}

resource "google_bigquery_routine" "tvf_gen_ai_metric_exemplars" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.otel.dataset_id
  routine_id   = "tvf_gen_ai_metric_exemplars"
  routine_type = "TABLE_VALUED_FUNCTION"
  language     = "SQL"
  description  = "Bounded-window partition-prunable counterpart of v_gen_ai_metric_exemplars accepting (start_ts, end_ts)."

  arguments {
    name      = "start_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  arguments {
    name      = "end_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  definition_body = <<-EOT
    SELECT
      m.timestamp AS metric_timestamp,
      m.service_name,
      m.metric_name,
      m.metric_unit,
      m.metric_type,
      m.gen_ai_operation_name,
      m.gen_ai_system,
      m.gen_ai_request_model,
      m.gen_ai_response_model,
      m.gen_ai_agent_name,
      m.gen_ai_token_type,
      m.gen_ai_token_modality,
      m.error_type AS metric_error_type,
      ex.time AS exemplar_timestamp,
      ex.value_double AS exemplar_value_double,
      ex.value_int64 AS exemplar_value_int64,
      ex.trace_id AS trace_id,
      ex.span_id AS span_id,
      ex.filtered_attributes AS exemplar_filtered_attributes,
      s.start_time AS span_start_time,
      s.end_time AS span_end_time,
      s.duration_nano AS span_duration_nano,
      ROUND(s.duration_nano / 1e6, 3) AS span_duration_ms,
      s.name AS span_name,
      s.status.code AS span_status_code,
      s.status.message AS span_status_message,
      COALESCE(
        JSON_VALUE(s.attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(s.attributes, '$."gcp.vertex.agent.name"'),
        JSON_VALUE(s.resource.attributes, '$."gen_ai.agent.name"'),
        JSON_VALUE(s.attributes, '$."gen_ai.main_agent.name"'),
        JSON_VALUE(s.resource.attributes, '$."gen_ai.main_agent.name"')
      ) AS span_gen_ai_agent_name,
      JSON_VALUE(s.attributes, '$."gen_ai.tool.name"') AS span_gen_ai_tool_name,
      COALESCE(
        JSON_VALUE(s.attributes, '$."gcp.vertex.agent.session_id"'),
        JSON_VALUE(s.attributes, '$."gen_ai.conversation.id"')
      ) AS adk_session_id,
      JSON_VALUE(s.attributes, '$."error.type"') AS span_error_type
    FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_metrics.table_id}` AS m
    INNER JOIN UNNEST(m.exemplars) AS ex
      WITH OFFSET AS exemplar_ordinal
    LEFT JOIN (
      SELECT *
      FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.otel_spans_dedup.table_id}`
      WHERE start_time >= TIMESTAMP_SUB(start_ts, INTERVAL 24 HOUR)
        AND start_time <= TIMESTAMP_ADD(end_ts, INTERVAL 1 HOUR)
    ) AS s
      ON s.trace_id = ex.trace_id
      AND s.span_id = ex.span_id
      AND s.service_name IS NOT DISTINCT FROM m.service_name
      AND s.start_time BETWEEN TIMESTAMP_SUB(m.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(m.timestamp, INTERVAL 1 HOUR)
    WHERE m.timestamp >= start_ts
      AND m.timestamp < end_ts
      AND ex.trace_id IS NOT NULL
      AND ex.span_id IS NOT NULL
      AND ex.trace_id != ''
      AND ex.span_id != ''
    QUALIFY ROW_NUMBER() OVER (
      PARTITION BY m.timestamp, m.time_unix_nano, m.service_name, m.metric_name, m.metric_type, m.point_fingerprint, exemplar_ordinal
      ORDER BY s.end_time DESC, s.start_time DESC, s.receive_time DESC, s.name ASC
    ) = 1
  EOT
}

resource "google_bigquery_routine" "tvf_gen_ai_agent_trajectory" {
  project      = var.project_id
  dataset_id   = google_bigquery_dataset.otel.dataset_id
  routine_id   = "tvf_gen_ai_agent_trajectory"
  routine_type = "TABLE_VALUED_FUNCTION"
  language     = "SQL"
  description  = "Caller-bounded context-horizon partition-prunable counterpart of v_gen_ai_agent_trajectory accepting (start_ts, end_ts, context_start_ts, context_end_ts)."

  arguments {
    name      = "start_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  arguments {
    name      = "end_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  arguments {
    name      = "context_start_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  arguments {
    name      = "context_end_ts"
    data_type = jsonencode({ typeKind = "TIMESTAMP" })
  }

  definition_body = <<-EOT
    WITH
      spans AS (
        SELECT
          start_time,
          end_time,
          duration_nano,
          duration_ms,
          trace_id,
          span_id,
          parent_span_id,
          service_name,
          span_name,
          span_kind,
          status_code,
          status_message,
          gen_ai_operation_name,
          gen_ai_system,
          gen_ai_provider_name,
          gen_ai_request_model,
          gen_ai_response_model,
          gen_ai_agent_id,
          gen_ai_agent_name,
          gen_ai_agent_version,
          gen_ai_main_agent_id,
          gen_ai_main_agent_name,
          gen_ai_tool_name,
          gen_ai_tool_call_id,
          gen_ai_usage_input_tokens,
          gen_ai_usage_output_tokens,
          gen_ai_usage_reasoning_tokens,
          adk_session_id,
          adk_invocation_id,
          adk_user_id,
          error_type,
          COALESCE(
            JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
            JSON_VALUE(attributes, '$."gcp.vertex.agent.name"')
          ) AS declared_agent_name,
          COALESCE(
            JSON_VALUE(attributes, '$."gen_ai.agent.name"'),
            JSON_VALUE(attributes, '$."gcp.vertex.agent.name"'),
            IF(gen_ai_operation_name IN ('invoke_agent', 'create_agent'), gen_ai_agent_name, NULL)
          ) AS agent_path_name
        FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.${google_bigquery_table.v_gen_ai_spans.table_id}`
        WHERE start_time >= context_start_ts
          AND start_time < context_end_ts
        QUALIFY ROW_NUMBER() OVER (
          PARTITION BY trace_id, service_name, span_id
          ORDER BY start_time ASC, end_time DESC, span_name ASC, duration_nano DESC
        ) = 1
      ),
      topo_raw AS (
        SELECT
          trace_id,
          service_name,
          ARRAY_AGG(
            STRUCT(
              start_time,
              span_id,
              parent_span_id,
              (parent_span_id IS NOT NULL AND parent_span_id != '') AS has_parent_id,
              (gen_ai_operation_name IN ('invoke_agent', 'create_agent')) AS is_agent_op,
              (declared_agent_name IS NOT NULL) AS has_declared_agent,
              COALESCE(declared_agent_name, gen_ai_agent_name) AS resolved_agent_name,
              agent_path_name,
              (gen_ai_usage_input_tokens IS NOT NULL) AS has_in,
              (gen_ai_usage_output_tokens IS NOT NULL) AS has_out,
              (gen_ai_usage_reasoning_tokens IS NOT NULL) AS has_reas
            )
            ORDER BY start_time ASC, span_id ASC
          ) AS topo_nodes
        FROM spans
        GROUP BY trace_id, service_name
      ),
      topo_edges AS (
        SELECT
          g.trace_id,
          g.service_name,
          g.topo_nodes,
          ARRAY(
            SELECT AS STRUCT
              p_idx AS raw_parent_idx,
              IF(
                p_idx IS NOT NULL
                  AND p.start_time BETWEEN TIMESTAMP_SUB(n.start_time, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(n.start_time, INTERVAL 1 HOUR),
                p_idx,
                CAST(NULL AS INT64)
              ) AS tree_parent_idx
            FROM UNNEST(g.topo_nodes) AS n
              WITH OFFSET AS n_idx
            LEFT JOIN UNNEST(g.topo_nodes) AS p
              WITH OFFSET AS p_idx
              ON n.has_parent_id
              AND p.span_id = n.parent_span_id
            ORDER BY n_idx ASC
          ) AS edges
        FROM topo_raw AS g
      ),
      topo_walks AS (
        SELECT
          g.trace_id,
          g.service_name,
          g.topo_nodes,
          g.edges,
          ARRAY(
            SELECT AS STRUCT
              ARRAY(
                SELECT anc_idx
                FROM UNNEST([
                  n_idx,
                  e0.tree_parent_idx,
                  e1.tree_parent_idx,
                  e2.tree_parent_idx,
                  e3.tree_parent_idx,
                  e4.tree_parent_idx,
                  e5.tree_parent_idx,
                  e6.tree_parent_idx,
                  e7.tree_parent_idx,
                  e8.tree_parent_idx,
                  e9.tree_parent_idx,
                  e10.tree_parent_idx,
                  e11.tree_parent_idx,
                  e12.tree_parent_idx,
                  e13.tree_parent_idx,
                  e14.tree_parent_idx,
                  e15.tree_parent_idx
                ]) AS anc_idx
                  WITH OFFSET AS hop_ord
                WHERE anc_idx IS NOT NULL
                ORDER BY hop_ord DESC
              ) AS root_to_self,
              IF(
                e16.tree_parent_idx IS NULL,
                (
                  SELECT COUNT(anc_idx)
                  FROM UNNEST([
                    e0.tree_parent_idx,
                    e1.tree_parent_idx,
                    e2.tree_parent_idx,
                    e3.tree_parent_idx,
                    e4.tree_parent_idx,
                    e5.tree_parent_idx,
                    e6.tree_parent_idx,
                    e7.tree_parent_idx,
                    e8.tree_parent_idx,
                    e9.tree_parent_idx,
                    e10.tree_parent_idx,
                    e11.tree_parent_idx,
                    e12.tree_parent_idx,
                    e13.tree_parent_idx,
                    e14.tree_parent_idx,
                    e15.tree_parent_idx
                  ]) AS anc_idx
                ),
                17
              ) AS depth
            FROM UNNEST(g.edges) AS e0
              WITH OFFSET AS n_idx
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e0.tree_parent_idx)]]) AS e1 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e1.tree_parent_idx)]]) AS e2 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e2.tree_parent_idx)]]) AS e3 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e3.tree_parent_idx)]]) AS e4 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e4.tree_parent_idx)]]) AS e5 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e5.tree_parent_idx)]]) AS e6 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e6.tree_parent_idx)]]) AS e7 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e7.tree_parent_idx)]]) AS e8 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e8.tree_parent_idx)]]) AS e9 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e9.tree_parent_idx)]]) AS e10 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e10.tree_parent_idx)]]) AS e11 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e11.tree_parent_idx)]]) AS e12 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e12.tree_parent_idx)]]) AS e13 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e13.tree_parent_idx)]]) AS e14 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e14.tree_parent_idx)]]) AS e15 ON TRUE
            LEFT JOIN UNNEST([g.edges[SAFE_OFFSET(e15.tree_parent_idx)]]) AS e16 ON TRUE
            ORDER BY n_idx ASC
          ) AS tree_info
        FROM topo_edges AS g
      ),
      topo_emitted AS (
        SELECT
          g.trace_id,
          g.service_name,
          g.topo_nodes,
          g.edges,
          g.tree_info,
          ARRAY(
            SELECT
              IF(
                ti.depth <= 16
                  AND e.raw_parent_idx IS NOT NULL
                  AND e.raw_parent_idx != n_idx
                  AND g.tree_info[SAFE_OFFSET(e.raw_parent_idx)].depth <= 16,
                e.raw_parent_idx,
                CAST(NULL AS INT64)
              )
            FROM UNNEST(g.edges) AS e
              WITH OFFSET AS n_idx
            INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
            ORDER BY n_idx ASC
          ) AS emitted_parent_idxs
        FROM topo_walks AS g
      ),
      topo_ancestors AS (
        SELECT
          g.trace_id,
          g.service_name,
          g.topo_nodes,
          g.edges,
          g.tree_info,
          ARRAY(
            SELECT AS STRUCT
              ARRAY(
                SELECT DISTINCT anc_idx
                FROM UNNEST([
                  p1, p2, p3, p4, p5, p6, p7, p8,
                  p9, p10, p11, p12, p13, p14, p15, p16,
                  p17, p18, p19, p20, p21, p22, p23, p24,
                  p25, p26, p27, p28, p29, p30, p31, p32
                ]) AS anc_idx
                WHERE anc_idx IS NOT NULL
                  AND anc_idx != n_idx
              ) AS anc_idxs
            FROM UNNEST(g.emitted_parent_idxs) AS p1
              WITH OFFSET AS n_idx
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p1)]]) AS p2 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p2)]]) AS p3 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p3)]]) AS p4 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p4)]]) AS p5 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p5)]]) AS p6 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p6)]]) AS p7 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p7)]]) AS p8 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p8)]]) AS p9 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p9)]]) AS p10 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p10)]]) AS p11 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p11)]]) AS p12 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p12)]]) AS p13 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p13)]]) AS p14 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p14)]]) AS p15 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p15)]]) AS p16 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p16)]]) AS p17 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p17)]]) AS p18 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p18)]]) AS p19 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p19)]]) AS p20 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p20)]]) AS p21 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p21)]]) AS p22 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p22)]]) AS p23 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p23)]]) AS p24 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p24)]]) AS p25 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p25)]]) AS p26 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p26)]]) AS p27 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p27)]]) AS p28 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p28)]]) AS p29 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p29)]]) AS p30 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p30)]]) AS p31 ON TRUE
            LEFT JOIN UNNEST([g.emitted_parent_idxs[SAFE_OFFSET(p31)]]) AS p32 ON TRUE
            ORDER BY n_idx ASC
          ) AS emitted_ancs
        FROM topo_emitted AS g
      ),
      topo_cov AS (
        SELECT
          g.trace_id,
          g.service_name,
          g.topo_nodes,
          g.edges,
          g.tree_info,
          ARRAY(
            SELECT AS STRUCT
              anc_idx,
              LOGICAL_OR(d_node.has_in) AS has_input,
              LOGICAL_OR(d_node.has_out) AS has_output,
              LOGICAL_OR(d_node.has_reas) AS has_reasoning
            FROM UNNEST(g.emitted_ancs) AS d_anc
              WITH OFFSET AS d_idx
            INNER JOIN UNNEST([g.topo_nodes[OFFSET(d_idx)]]) AS d_node ON TRUE
            INNER JOIN UNNEST(d_anc.anc_idxs) AS anc_idx
            INNER JOIN UNNEST([g.topo_nodes[OFFSET(anc_idx)]]) AS a_node ON TRUE
            WHERE (d_node.has_in OR d_node.has_out OR d_node.has_reas)
              AND (
                d_idx NOT IN UNNEST(g.emitted_ancs[OFFSET(anc_idx)].anc_idxs)
                OR d_node.start_time > a_node.start_time
                OR (d_node.start_time = a_node.start_time AND d_node.span_id > a_node.span_id)
              )
            GROUP BY anc_idx
          ) AS cov_rows
        FROM topo_ancestors AS g
      ),
      resolved_topology AS (
        SELECT
          g.trace_id,
          g.service_name,
          n.span_id,
          ti.depth,
          g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].span_id AS root_span_id,
          COALESCE(
            (
              SELECT g.topo_nodes[OFFSET(p_idx)].span_id
              FROM UNNEST(ti.root_to_self) AS p_idx
                WITH OFFSET AS pos
              WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
              ORDER BY pos DESC
              LIMIT 1
            ),
            (
              SELECT g.topo_nodes[OFFSET(p_idx)].span_id
              FROM UNNEST(ti.root_to_self) AS p_idx
                WITH OFFSET AS pos
              WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
              ORDER BY pos ASC
              LIMIT 1
            )
          ) AS nearest_agent_span_id,
          IF(
            EXISTS (
              SELECT 1
              FROM UNNEST(ti.root_to_self) AS p_idx
              WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
            ),
            (
              SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
              FROM UNNEST(ti.root_to_self) AS p_idx
                WITH OFFSET AS pos
              WHERE g.topo_nodes[OFFSET(p_idx)].is_agent_op
              ORDER BY pos DESC
              LIMIT 1
            ),
            (
              SELECT g.topo_nodes[OFFSET(p_idx)].resolved_agent_name
              FROM UNNEST(ti.root_to_self) AS p_idx
                WITH OFFSET AS pos
              WHERE g.topo_nodes[OFFSET(p_idx)].has_declared_agent
              ORDER BY pos ASC
              LIMIT 1
            )
          ) AS nearest_agent_name,
          ARRAY(
            SELECT g.topo_nodes[OFFSET(p_idx)].agent_path_name
            FROM UNNEST(ti.root_to_self) AS p_idx
              WITH OFFSET AS pos
            WHERE g.topo_nodes[OFFSET(p_idx)].agent_path_name IS NOT NULL
              AND (
                pos = 0
                OR g.topo_nodes[OFFSET(p_idx)].agent_path_name IS DISTINCT FROM (
                  SELECT g.topo_nodes[OFFSET(prev_idx)].agent_path_name
                  FROM UNNEST(ti.root_to_self) AS prev_idx
                    WITH OFFSET AS prev_pos
                  WHERE prev_pos < pos
                    AND g.topo_nodes[OFFSET(prev_idx)].agent_path_name IS NOT NULL
                  ORDER BY prev_pos DESC
                  LIMIT 1
                )
              )
            ORDER BY pos ASC
          ) AS agent_path,
          g.topo_nodes[OFFSET(ti.root_to_self[OFFSET(0)])].has_parent_id AS is_orphan,
          ROW_NUMBER() OVER (
            PARTITION BY g.trace_id, g.service_name
            ORDER BY n.start_time ASC, n.span_id ASC
          ) AS step_index,
          IF(
            EXISTS (
              SELECT 1
              FROM UNNEST(g.edges) AS ce
              WHERE ce.raw_parent_idx = n_idx
            ),
            n.span_id,
            CAST(NULL AS STRING)
          ) AS leaf_parent_span_id,
          COALESCE(cov.has_input, FALSE) AS cov_has_input,
          COALESCE(cov.has_output, FALSE) AS cov_has_output,
          COALESCE(cov.has_reasoning, FALSE) AS cov_has_reasoning
        FROM topo_cov AS g
        INNER JOIN UNNEST(g.topo_nodes) AS n
          WITH OFFSET AS n_idx
        INNER JOIN UNNEST([g.tree_info[OFFSET(n_idx)]]) AS ti ON TRUE
        LEFT JOIN UNNEST(g.cov_rows) AS cov
          ON cov.anc_idx = n_idx
        WHERE ti.depth <= 16
      ),
      trajectory AS (
        SELECT
          s.start_time,
          s.end_time,
          s.duration_nano,
          s.duration_ms,
          s.trace_id,
          s.span_id,
          s.parent_span_id,
          s.service_name,
          s.span_name,
          s.span_kind,
          s.status_code,
          s.status_message,
          s.gen_ai_operation_name,
          s.gen_ai_system,
          s.gen_ai_provider_name,
          s.gen_ai_request_model,
          s.gen_ai_response_model,
          s.gen_ai_agent_id,
          s.gen_ai_agent_name,
          s.gen_ai_agent_version,
          s.gen_ai_main_agent_id,
          s.gen_ai_main_agent_name,
          s.gen_ai_tool_name,
          s.gen_ai_tool_call_id,
          s.gen_ai_usage_input_tokens,
          s.gen_ai_usage_output_tokens,
          s.gen_ai_usage_reasoning_tokens,
          s.adk_session_id,
          s.adk_invocation_id,
          s.adk_user_id,
          s.error_type,
          r.depth,
          r.root_span_id,
          r.nearest_agent_span_id,
          r.nearest_agent_name,
          r.agent_path,
          r.is_orphan,
          r.step_index,
          r.leaf_parent_span_id,
          r.cov_has_input,
          r.cov_has_output,
          r.cov_has_reasoning
        FROM resolved_topology AS r
        INNER JOIN spans AS s
          ON s.trace_id = r.trace_id
          AND s.span_id = r.span_id
          AND s.service_name IS NOT DISTINCT FROM r.service_name
      )
    SELECT
      t.start_time,
      t.end_time,
      t.duration_nano,
      t.duration_ms,
      t.trace_id,
      t.span_id,
      t.parent_span_id,
      t.service_name,
      t.span_name,
      t.span_kind,
      t.status_code,
      t.status_message,
      t.gen_ai_operation_name,
      t.gen_ai_system,
      t.gen_ai_provider_name,
      t.gen_ai_request_model,
      t.gen_ai_response_model,
      t.gen_ai_agent_id,
      t.gen_ai_agent_name,
      t.gen_ai_agent_version,
      t.gen_ai_main_agent_id,
      t.gen_ai_main_agent_name,
      t.gen_ai_tool_name,
      t.gen_ai_tool_call_id,
      IF(
        COALESCE(token_leaf_check.has_input, FALSE)
        AND (
          (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
          OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
        ),
        CAST(NULL AS INT64),
        t.gen_ai_usage_input_tokens
      ) AS gen_ai_usage_input_tokens,
      IF(
        COALESCE(token_leaf_check.has_output, FALSE)
        AND (
          (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
          OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
        ),
        CAST(NULL AS INT64),
        t.gen_ai_usage_output_tokens
      ) AS gen_ai_usage_output_tokens,
      IF(
        COALESCE(token_leaf_check.has_reasoning, FALSE)
        AND (
          (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
          OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
        ),
        CAST(NULL AS INT64),
        t.gen_ai_usage_reasoning_tokens
      ) AS gen_ai_usage_reasoning_tokens,
      t.adk_session_id,
      t.adk_invocation_id,
      t.adk_user_id,
      t.error_type,
      t.depth,
      t.root_span_id,
      t.nearest_agent_span_id,
      t.nearest_agent_name,
      t.agent_path,
      t.is_orphan,
      t.step_index,
      (leaf_check.span_id IS NULL) AS is_leaf,
      (
        (t.gen_ai_usage_input_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_input, FALSE))
        OR (t.gen_ai_usage_output_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_output, FALSE))
        OR (t.gen_ai_usage_reasoning_tokens IS NOT NULL AND NOT COALESCE(token_leaf_check.has_reasoning, FALSE))
      ) AS is_token_leaf
    FROM trajectory AS t
    LEFT JOIN UNNEST([STRUCT(t.leaf_parent_span_id AS span_id)]) AS leaf_check
      ON leaf_check.span_id IS NOT NULL
    LEFT JOIN UNNEST([
      STRUCT(
        t.cov_has_input AS has_input,
        t.cov_has_output AS has_output,
        t.cov_has_reasoning AS has_reasoning
      )
    ]) AS token_leaf_check
      ON TRUE
    WHERE t.start_time >= start_ts
      AND t.start_time < end_ts
  EOT
}

# --- IAM: least privilege ---
#
# This module provisions the dataset and every table and view, so by default
# the collector's service account gets only the data path, and only on this
# dataset: read the dataset and table metadata it validates at startup, and
# append rows. Nothing is granted at project scope.

resource "google_project_iam_custom_role" "otel_collector_writer" {
  role_id     = "otelCollectorWriter"
  title       = "OTel BigQuery Collector Writer"
  description = "Startup metadata reads and Storage Write appends for the BigQuery OTel exporter"
  permissions = [
    # Read dataset/table metadata for startup validation.
    "bigquery.datasets.get",
    "bigquery.tables.get",
    # Append rows via the Storage Write API.
    "bigquery.tables.updateData",
  ]
}

resource "google_service_account" "otel_collector" {
  account_id   = var.service_account_id
  display_name = "OTel BigQuery Collector"
}

resource "google_bigquery_dataset_iam_member" "otel_collector_writer" {
  dataset_id = google_bigquery_dataset.otel.dataset_id
  role       = google_project_iam_custom_role.otel_collector_writer.id
  member     = "serviceAccount:${google_service_account.otel_collector.email}"
}

# Optional (var.grant_auto_create): what the exporter's auto_create options
# need on top of the data path, for a collector that creates or reconciles
# tables and views or creates search indexes itself. The table permissions
# stay on this dataset; only running the CREATE SEARCH INDEX query job needs a
# project-level grant. auto_create.dataset is never needed, because this module
# creates the dataset.

resource "google_project_iam_custom_role" "otel_collector_provisioner" {
  count       = var.grant_auto_create ? 1 : 0
  role_id     = "otelCollectorProvisioner"
  title       = "OTel BigQuery Collector Provisioner"
  description = "Table, view, and search index creation for the BigQuery OTel exporter's auto_create"
  permissions = [
    # Create missing tables and views; reconcile additive columns.
    "bigquery.tables.create",
    "bigquery.tables.update",
    # CREATE SEARCH INDEX on the signal tables.
    "bigquery.tables.createIndex",
  ]
}

resource "google_bigquery_dataset_iam_member" "otel_collector_provisioner" {
  count      = var.grant_auto_create ? 1 : 0
  dataset_id = google_bigquery_dataset.otel.dataset_id
  role       = google_project_iam_custom_role.otel_collector_provisioner[0].id
  member     = "serviceAccount:${google_service_account.otel_collector.email}"
}

resource "google_project_iam_custom_role" "otel_collector_jobs" {
  count       = var.grant_auto_create ? 1 : 0
  role_id     = "otelCollectorJobs"
  title       = "OTel BigQuery Collector Jobs"
  description = "Runs the BigQuery OTel exporter's CREATE SEARCH INDEX query jobs"
  permissions = [
    "bigquery.jobs.create",
  ]
}

resource "google_project_iam_member" "otel_collector_jobs" {
  count   = var.grant_auto_create ? 1 : 0
  project = var.project_id
  role    = google_project_iam_custom_role.otel_collector_jobs[0].id
  member  = "serviceAccount:${google_service_account.otel_collector.email}"
}

# --- Optional GCS offload bucket IAM ---
#
# When offload is enabled, the collector uploads large payloads to a GCS bucket
# and writes BigQuery ObjectRef references. The collector service account needs
# objectCreator (to upload) and objectViewer (to verify uploads) on the bucket.

resource "google_storage_bucket_iam_member" "otel_collector_offload_creator" {
  count  = var.offload_bucket == "" ? 0 : 1
  bucket = var.offload_bucket
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.otel_collector.email}"
}

resource "google_storage_bucket_iam_member" "otel_collector_offload_viewer" {
  count  = var.offload_bucket == "" ? 0 : 1
  bucket = var.offload_bucket
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.otel_collector.email}"
}

# --- Optional CMEK: grant the BigQuery service agent encrypt/decrypt on the KMS key ---
#
# When CMEK is enabled, the BigQuery service agent
# (serviceAccount:bq-<project-number>@bigquery-encryption.iam.gserviceaccount.com)
# needs roles/cloudkms.cryptoKeyEncrypterDecrypter on the KMS key. This module
# grants it automatically when kms_key_name is set.

data "google_bigquery_default_service_account" "bq_cmek" {
  project = var.project_id
}

resource "google_kms_crypto_key_iam_member" "bq_encryptor" {
  count         = var.kms_key_name == "" ? 0 : 1
  crypto_key_id = var.kms_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_bigquery_default_service_account.bq_cmek.email}"
}

# --- Optional Continuous Queries alerting infrastructure ---
#
# When enable_continuous_queries is set, this module provisions the alert sink
# table (otel_alerts), the Pub/Sub alert topic, a dedicated service account for
# Continuous Query jobs, least-privilege IAM bindings, and an Enterprise or
# Enterprise Plus reservation assignment with job_type = "CONTINUOUS".
# otel_alerts inherits the dataset's default encryption when CMEK is enabled.

locals {
  cq_dataset_norm = trim(replace(lower(var.dataset_id), "/[^a-z0-9]+/", "-"), "-")
  cq_dataset_slug = local.cq_dataset_norm != "" ? local.cq_dataset_norm : "ds"
  cq_dataset_hash = substr(sha256(var.dataset_id), 0, 8)
  # Always starts with "otel-cq-" ([a-z]), contains only [a-z0-9-], ends with [a-z0-9],
  # is at most 8 + 47 + 1 + 8 = 64 chars, and never collides across case/underscore/truncation variants.
  continuous_query_reservation_name = (
    can(regex("^[a-z](?:[a-z0-9_]*[a-z0-9])?$", var.dataset_id)) && !can(regex("_[0-9a-f]{8}$", var.dataset_id)) && length("otel-cq-${replace(var.dataset_id, "_", "-")}") <= 55
    ? "otel-cq-${replace(var.dataset_id, "_", "-")}"
    : "otel-cq-${trim(substr(local.cq_dataset_slug, 0, min(length(local.cq_dataset_slug), 47)), "-")}-${local.cq_dataset_hash}"
  )
  # Always starts with "otel-alerts-" (letter, not "goog"), contains only [a-z0-9_-],
  # is between 13 and 255 chars, and never collides across case/underscore/truncation variants.
  otel_alerts_topic_name = (
    can(regex("^[a-z](?:[a-z0-9_]*[a-z0-9])?$", var.dataset_id)) && !can(regex("_[0-9a-f]{8}$", var.dataset_id)) && length("otel-alerts-${var.dataset_id}") <= 240
    ? "otel-alerts-${var.dataset_id}"
    : "otel-alerts-${trim(substr(local.cq_dataset_slug, 0, min(length(local.cq_dataset_slug), 234)), "-")}-${local.cq_dataset_hash}"
  )
}

resource "google_bigquery_table" "otel_alerts" {
  count = var.enable_continuous_queries ? 1 : 0

  dataset_id               = google_bigquery_dataset.otel.dataset_id
  table_id                 = "otel_alerts"
  deletion_protection      = var.alerts_deletion_protection
  require_partition_filter = var.require_partition_filter

  time_partitioning {
    type          = "DAY"
    field         = "event_time"
    expiration_ms = var.alerts_partition_expiration_days > 0 ? var.alerts_partition_expiration_days * 86400000 : null
  }

  clustering = ["alert_kind", "service_name"]

  dynamic "encryption_configuration" {
    for_each = var.kms_key_name == "" ? [] : [1]
    content {
      kms_key_name = var.kms_key_name
    }
  }

  labels = var.labels

  schema = jsonencode([
    { name = "alert_id", type = "STRING", mode = "REQUIRED" },
    { name = "alert_kind", type = "STRING", mode = "REQUIRED" },
    { name = "event_time", type = "TIMESTAMP", mode = "REQUIRED" },
    { name = "service_name", type = "STRING", mode = "NULLABLE" },
    { name = "trace_id", type = "STRING", mode = "REQUIRED" },
    { name = "span_id", type = "STRING", mode = "REQUIRED" },
    { name = "payload", type = "JSON", mode = "NULLABLE" },
  ])

  depends_on = [google_kms_crypto_key_iam_member.bq_encryptor]
}

resource "google_pubsub_topic" "otel_alerts" {
  count = var.enable_continuous_queries ? 1 : 0

  name   = local.otel_alerts_topic_name
  labels = var.labels

  lifecycle {
    precondition {
      condition     = can(regex("^[A-Za-z][A-Za-z0-9_~+.%-]{2,254}$", local.otel_alerts_topic_name)) && !can(regex("^(?i)goog", local.otel_alerts_topic_name)) && length(local.otel_alerts_topic_name) <= 255
      error_message = "Derived Pub/Sub topic name ${local.otel_alerts_topic_name} must start with a letter, not begin with goog, and be 3 to 255 characters."
    }
  }
}

resource "google_service_account" "continuous_queries" {
  count = var.enable_continuous_queries ? 1 : 0

  account_id   = "${var.service_account_id}-cq"
  display_name = "OTel BigQuery Continuous Queries"

  lifecycle {
    precondition {
      condition     = length(var.service_account_id) <= 27
      error_message = "service_account_id must be at most 27 characters when enable_continuous_queries is true so the derived ${var.service_account_id}-cq account ID stays within Google Cloud's 30-character limit."
    }
  }
}

resource "google_bigquery_dataset_iam_member" "continuous_queries_viewer" {
  count = var.enable_continuous_queries ? 1 : 0

  dataset_id = google_bigquery_dataset.otel.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "serviceAccount:${google_service_account.continuous_queries[0].email}"
}

resource "google_bigquery_table_iam_member" "continuous_queries_alerts_writer" {
  count = var.enable_continuous_queries ? 1 : 0

  project    = var.project_id
  dataset_id = google_bigquery_dataset.otel.dataset_id
  table_id   = google_bigquery_table.otel_alerts[0].table_id
  role       = "roles/bigquery.dataEditor"
  member     = "serviceAccount:${google_service_account.continuous_queries[0].email}"
}

resource "google_pubsub_topic_iam_member" "continuous_queries_publisher" {
  count = var.enable_continuous_queries ? 1 : 0

  topic  = google_pubsub_topic.otel_alerts[0].name
  role   = "roles/pubsub.publisher"
  member = "serviceAccount:${google_service_account.continuous_queries[0].email}"
}

resource "google_pubsub_topic_iam_member" "continuous_queries_pubsub_viewer" {
  count = var.enable_continuous_queries ? 1 : 0

  topic  = google_pubsub_topic.otel_alerts[0].name
  role   = "roles/pubsub.viewer"
  member = "serviceAccount:${google_service_account.continuous_queries[0].email}"
}

resource "google_project_iam_member" "continuous_queries_jobs" {
  count   = var.enable_continuous_queries ? 1 : 0
  project = var.project_id
  role    = "roles/bigquery.jobUser"
  member  = "serviceAccount:${google_service_account.continuous_queries[0].email}"
}

resource "google_bigquery_reservation" "continuous_queries" {
  count = var.enable_continuous_queries ? 1 : 0

  name              = local.continuous_query_reservation_name
  location          = var.location
  slot_capacity     = var.continuous_query_slot_capacity
  edition           = var.continuous_query_edition
  ignore_idle_slots = false

  lifecycle {
    precondition {
      condition     = !var.enable_column_level_security
      error_message = "BigQuery Continuous Queries do not support tables with column-level security policy tags (enable_column_level_security must be false when enable_continuous_queries is true)."
    }
    precondition {
      condition     = can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", local.continuous_query_reservation_name)) && length(local.continuous_query_reservation_name) <= 64
      error_message = "Derived BigQuery reservation name ${local.continuous_query_reservation_name} must match ^[a-z][a-z0-9-]{0,62}[a-z0-9]$ and be at most 64 characters."
    }
  }
}

resource "google_bigquery_reservation_assignment" "continuous_queries" {
  count = var.enable_continuous_queries ? 1 : 0

  assignee    = "projects/${var.project_id}"
  job_type    = "CONTINUOUS"
  reservation = google_bigquery_reservation.continuous_queries[0].id
  location    = var.location
}
