variable "project_id" {
  description = "Google Cloud project ID that owns the BigQuery dataset"
  type        = string
}

variable "dataset_id" {
  description = "BigQuery dataset ID for OTel telemetry"
  type        = string
  default     = "otel"
}

variable "location" {
  description = "BigQuery dataset location (e.g. US, us-central1, eu)"
  type        = string
  default     = "US"

  validation {
    condition     = can(regex("^[A-Za-z]{2,20}(-[A-Za-z0-9]+)*$", var.location))
    error_message = "Location must be a valid BigQuery location (letters and hyphens, e.g. US, us-central1, eu)."
  }
}

variable "spans_table" {
  description = "Table name for OTel spans"
  type        = string
  default     = "otel_spans"
}

variable "logs_table" {
  description = "Table name for OTel logs"
  type        = string
  default     = "otel_logs"
}

variable "metrics_table" {
  description = "Table name for OTel metrics"
  type        = string
  default     = "otel_metrics"
}

variable "quarantine_table" {
  description = "Table name for the dead-letter quarantine table"
  type        = string
  default     = "otel_quarantine"
}

variable "service_account_id" {
  description = "Service account ID for the collector (6 to 30 characters; at most 27 when enable_continuous_queries is true so -cq fits within 30)"
  type        = string
  default     = "otel-collector"

  validation {
    condition     = length(var.service_account_id) >= 6 && length(var.service_account_id) <= 30 && can(regex("^[a-z][-a-z0-9]{4,28}[a-z0-9]$", var.service_account_id))
    error_message = "service_account_id must be 6 to 30 lowercase letters, digits, or hyphens, starting with a letter and ending with a letter or digit."
  }
}

variable "grant_auto_create" {
  description = "Also grant what the exporter's auto_create options need: creating and reconciling tables and views on this dataset, and creating search indexes. Off by default because this module provisions every table and view itself."
  type        = bool
  default     = false
}

# --- Enterprise governance ---

variable "kms_key_name" {
  description = "Cloud KMS key resource name for CMEK encryption of the BigQuery dataset and tables. Leave empty to use Google-managed encryption. When set, also grants the BigQuery service agent decrypt permission on the key."
  type        = string
  default     = ""

  validation {
    condition = var.kms_key_name == "" ? true : can(regex(
      "^projects/[^/\\s]+/locations/[^/\\s]+/keyRings/[^/\\s]+/cryptoKeys/[^/\\s]+$",
      var.kms_key_name
    ))
    error_message = "kms_key_name must be a full Cloud KMS key resource name (projects/<project>/locations/<location>/keyRings/<keyRing>/cryptoKeys/<key>)."
  }
}

variable "labels" {
  description = "Labels applied to the BigQuery dataset and all provisioned tables and views for cost allocation and governance."
  type        = map(string)
  default     = {}

  validation {
    condition     = alltrue([for k in keys(var.labels) : !startswith(lower(k), "otel_schema_")])
    error_message = "labels keys must not start with the reserved prefix \"otel_schema_\" (case-insensitive)."
  }

  validation {
    condition     = length(var.labels) <= 60
    error_message = "labels may contain at most 60 entries so BigQuery's 64-label table limit accommodates the 4 reserved otel_schema_* labels."
  }
}

variable "offload_bucket" {
  description = "GCS bucket name for optional large-payload offloading. When set, grants the collector service account objectCreator and objectViewer on the bucket. The bucket must already exist."
  type        = string
  default     = ""
}

variable "max_staleness" {
  description = "BigQuery max_staleness option of the signal and quarantine tables, never views: the maximum staleness of the data a query over a table may return. Within it, BigQuery can answer a query from the changes it has already applied instead of applying pending changes, such as change data capture upserts and deletes, at query time. It does not exclude partitions from queries. Either a Go duration, as the exporter's max_staleness options take it, in whole seconds from 1s to 168h (e.g. 15m, 1h30m, 30s), or a BigQuery SQL interval string (e.g. 0-0 0 0:15:0), which is passed through as given. Leave empty to disable."
  type        = string
  default     = ""

  validation {
    condition     = var.max_staleness == "" ? true : can(regex("^(0-0 [0-9]+ [0-9]+:[0-9]+:[0-9]+|([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+)$", var.max_staleness))
    error_message = "max_staleness must be a Go duration string (e.g. 15m, 1h30m, 30s), a BigQuery SQL interval string (e.g. 0-0 0 0:15:0), or empty."
  }

  # main.tf converts a duration through timeadd, which parses it as the
  # exporter does but drops fractional seconds from its result. A duration is
  # therefore a whole number of seconds exactly when adding just under one more
  # second leaves that result unchanged. The bounds are the exporter's.
  validation {
    condition = !can(regex("^([0-9]+(\\.[0-9]+)?(ns|us|µs|ms|s|m|h))+$", var.max_staleness)) ? true : try(
      timecmp(timeadd("2000-01-01T00:00:00Z", var.max_staleness), "2000-01-01T00:00:01Z") >= 0 &&
      timecmp(timeadd("2000-01-01T00:00:00Z", var.max_staleness), "2000-01-08T00:00:00Z") <= 0 &&
      timeadd("2000-01-01T00:00:00Z", var.max_staleness) == timeadd("2000-01-01T00:00:00Z", "${var.max_staleness}999999999ns"),
      false
    )
    error_message = "A max_staleness duration must be a whole number of seconds from 1s to 168h, the range the exporter accepts."
  }
}

# --- Partition retention and partition filters ---
#
# These govern the tables this module creates. The collector's per-table
# options of the same names apply only to tables the collector creates itself.

variable "spans_partition_expiration_days" {
  description = "Partition expiration in days for otel_spans; 0 means no expiration."
  type        = number
  default     = 0

  validation {
    condition     = var.spans_partition_expiration_days >= 0 && floor(var.spans_partition_expiration_days) == var.spans_partition_expiration_days
    error_message = "spans_partition_expiration_days must be a whole number of days, 0 or more."
  }
}

variable "logs_partition_expiration_days" {
  description = "Partition expiration in days for otel_logs; 0 means no expiration."
  type        = number
  default     = 0

  validation {
    condition     = var.logs_partition_expiration_days >= 0 && floor(var.logs_partition_expiration_days) == var.logs_partition_expiration_days
    error_message = "logs_partition_expiration_days must be a whole number of days, 0 or more."
  }
}

variable "metrics_partition_expiration_days" {
  description = "Partition expiration in days for otel_metrics; 0 means no expiration."
  type        = number
  default     = 0

  validation {
    condition     = var.metrics_partition_expiration_days >= 0 && floor(var.metrics_partition_expiration_days) == var.metrics_partition_expiration_days
    error_message = "metrics_partition_expiration_days must be a whole number of days, 0 or more."
  }
}

variable "quarantine_partition_expiration_days" {
  description = "Partition expiration in days for otel_quarantine; default 30 days, 0 means no expiration."
  type        = number
  default     = 30

  validation {
    condition     = var.quarantine_partition_expiration_days >= 0 && floor(var.quarantine_partition_expiration_days) == var.quarantine_partition_expiration_days
    error_message = "quarantine_partition_expiration_days must be a whole number of days, 0 or more."
  }
}

variable "require_partition_filter" {
  description = "Require a partition filter on queries against the partitioned signal and quarantine tables. A query over a view must then filter on a column BigQuery can use to skip partitions, and a query over v_gen_ai_logs, v_gen_ai_metric_exemplars, or v_gen_ai_agent_trajectory is rejected even then, so those three views are created only with allow_unprunable_views (see deploy/README.md)."
  type        = bool
  default     = false
}

variable "allow_unprunable_views" {
  description = "Create v_gen_ai_logs, v_gen_ai_metric_exemplars, and v_gen_ai_agent_trajectory even when require_partition_filter is true. They join otel_spans on a time window that depends on each row, which BigQuery cannot use to skip partitions, so it rejects every query over them while otel_spans requires a partition filter, and the module leaves them out then unless this is set. Matches the collector's auto_create.allow_unprunable_views and the Helm chart's bigquery.autoCreateAllowUnprunableViews."
  type        = bool
  default     = false
}

# --- Table layout, search indexes, and BACKGROUND indexing reservation ---

variable "logs_partition_type" {
  description = "Creation-time time partitioning granularity for otel_logs (DAY or HOUR). Existing BigQuery tables cannot be repartitioned in place."
  type        = string
  default     = "DAY"

  validation {
    condition     = contains(["DAY", "HOUR"], var.logs_partition_type)
    error_message = "logs_partition_type must be DAY or HOUR."
  }
}

variable "spans_clustering" {
  description = "1 to 4 clustering columns for otel_spans, strictly bounded to the otel_spans_dedup PARTITION BY window (service_name, trace_id, span_id, name)."
  type        = list(string)
  default     = ["service_name", "trace_id", "name"]

  validation {
    condition = (
      length(var.spans_clustering) >= 1 &&
      length(var.spans_clustering) <= 4 &&
      length(distinct(var.spans_clustering)) == length(var.spans_clustering) &&
      alltrue([for c in var.spans_clustering : contains(["service_name", "trace_id", "span_id", "name"], c)])
    )
    error_message = "spans_clustering must list 1 to 4 unique columns from the otel_spans_dedup PARTITION BY window (service_name, trace_id, span_id, name)."
  }
}

variable "logs_clustering" {
  description = "1 to 4 clustering columns for otel_logs, strictly bounded to the otel_logs_dedup PARTITION BY window (service_name, log_name, severity_number, trace_id, span_id, insert_id); JSON columns such as attributes and body are rejected by BigQuery."
  type        = list(string)
  default     = ["service_name", "trace_id", "severity_number"]

  validation {
    condition = (
      length(var.logs_clustering) >= 1 &&
      length(var.logs_clustering) <= 4 &&
      length(distinct(var.logs_clustering)) == length(var.logs_clustering) &&
      alltrue([for c in var.logs_clustering : contains(["service_name", "log_name", "severity_number", "trace_id", "span_id", "insert_id"], c)])
    )
    error_message = "logs_clustering must list 1 to 4 unique columns from the otel_logs_dedup PARTITION BY window (service_name, log_name, severity_number, trace_id, span_id, insert_id)."
  }
}

variable "enable_search_indexes" {
  description = "Run create-only CREATE SEARCH INDEX IF NOT EXISTS DDL jobs on otel_spans, otel_logs, and otel_metrics. BigQuery limits each base table to 1 search index and 1 analyzer; edits after initial creation never drop or rebuild an existing index."
  type        = bool
  default     = false
}

variable "logs_search_index_columns" {
  description = "Columns indexed on otel_logs when enable_search_indexes is true, or [\"ALL COLUMNS\"] to index all supported STRING and JSON columns."
  type        = list(string)
  default     = ["trace_id", "span_id"]

  validation {
    condition = (
      length(var.logs_search_index_columns) >= 1 &&
      length(distinct(var.logs_search_index_columns)) == length(var.logs_search_index_columns) &&
      (
        (length(var.logs_search_index_columns) == 1 && var.logs_search_index_columns[0] == "ALL COLUMNS") ||
        alltrue([for c in var.logs_search_index_columns : contains(["timestamp_source", "trace_id", "span_id", "event_name", "severity_text", "body", "attributes", "service_name", "resource", "resource_schema_url", "instrumentation_scope", "scope_schema_url", "object_refs", "log_name", "insert_id"], c)])
      )
    )
    error_message = "logs_search_index_columns must be [\"ALL COLUMNS\"] or 1+ unique indexable otel_logs STRING, JSON, or STRUCT columns."
  }
}

variable "logs_search_index_analyzer" {
  description = "Analyzer for the otel_logs search index when enable_search_indexes is true: NO_OP_ANALYZER, LOG_ANALYZER, or PATTERN_ANALYZER."
  type        = string
  default     = "NO_OP_ANALYZER"

  validation {
    condition     = contains(["NO_OP_ANALYZER", "LOG_ANALYZER", "PATTERN_ANALYZER"], var.logs_search_index_analyzer)
    error_message = "logs_search_index_analyzer must be NO_OP_ANALYZER, LOG_ANALYZER, or PATTERN_ANALYZER."
  }
}

variable "search_index_job_wait_timeout_seconds" {
  description = "Seconds terraform apply waits for each search index job to finish when enable_search_indexes is true, failing if the job ends with an error or is still unfinished by then (1 to 3600), or 0 to not wait. The wait runs scripts/wait_for_bigquery_job.py with python3 on the machine that runs Terraform."
  type        = number
  default     = 300

  validation {
    condition     = var.search_index_job_wait_timeout_seconds >= 0 && var.search_index_job_wait_timeout_seconds <= 3600 && floor(var.search_index_job_wait_timeout_seconds) == var.search_index_job_wait_timeout_seconds
    error_message = "search_index_job_wait_timeout_seconds must be a whole number of seconds from 0 to 3600."
  }
}

variable "enable_background_reservation" {
  description = "Provision an Enterprise or Enterprise Plus BigQuery reservation and BACKGROUND assignment so search index maintenance runs on dedicated slots (Day-1 prerequisite when base-table logical bytes exceed the free 20 TB regional / 100 TB US-EU org cap)."
  type        = bool
  default     = false
}

variable "background_reservation_slots" {
  description = "Baseline slot capacity for the BACKGROUND reservation when enable_background_reservation is true (whole multiple of 50, at least 50)."
  type        = number
  default     = 50

  validation {
    condition     = var.background_reservation_slots >= 50 && var.background_reservation_slots % 50 == 0 && floor(var.background_reservation_slots) == var.background_reservation_slots
    error_message = "background_reservation_slots must be a whole multiple of 50 (at least 50)."
  }
}

variable "background_reservation_edition" {
  description = "BigQuery edition for the BACKGROUND reservation when enable_background_reservation is true: ENTERPRISE or ENTERPRISE_PLUS."
  type        = string
  default     = "ENTERPRISE"

  validation {
    condition     = contains(["ENTERPRISE", "ENTERPRISE_PLUS"], var.background_reservation_edition)
    error_message = "background_reservation_edition must be ENTERPRISE or ENTERPRISE_PLUS."
  }
}

# --- Column-level security and data masking ---
#
# Off by default. governance.tf creates these resources only when
# enable_column_level_security is set.

variable "enable_column_level_security" {
  description = "Create a policy tag taxonomy, a policy tag, and a data masking policy on the tag; attach the tag to the sensitive STRING columns (otel_spans.status.message, otel_logs.severity_text, otel_quarantine.raw_payload and otel_quarantine.error_message); and create the redacted views. Needs the Data Catalog and BigQuery Data Policy APIs enabled in the project."
  type        = bool
  default     = false
}

variable "policy_taxonomy_display_name" {
  description = "Display name of the policy tag taxonomy. A display name must be unique among the taxonomies of a project and location, so give each deployment that shares them its own."
  type        = string
  default     = "otel_telemetry_sensitivity"
}

variable "masking_rule" {
  description = "Predefined masking rule of the data masking policy, which decides what a Masked Reader sees in place of a tagged value: SHA256 a SHA-256 hash of the value, ALWAYS_NULL a NULL, and DEFAULT_MASKING_VALUE the default masking value of the column type, an empty string for STRING."
  type        = string
  default     = "SHA256"

  validation {
    condition     = contains(["SHA256", "ALWAYS_NULL", "DEFAULT_MASKING_VALUE"], var.masking_rule)
    error_message = "masking_rule must be SHA256, ALWAYS_NULL, or DEFAULT_MASKING_VALUE."
  }
}

variable "fine_grained_reader_members" {
  description = "Principals (for example group:otel-admins@example.com) granted the Fine-Grained Reader role on the policy tag, who read the tagged columns unmasked. The binding is authoritative for that role on the tag. Used only when enable_column_level_security is set."
  type        = list(string)
  default     = []
}

variable "masked_reader_members" {
  description = "Principals granted the Masked Reader role on the data masking policy, who read the tagged columns masked by masking_rule. The binding is authoritative for that role on the policy. Used only when enable_column_level_security is set."
  type        = list(string)
  default     = []
}

# --- Real-time alerting (Continuous Queries) ---
#
# Off by default. When enable_continuous_queries is set, main.tf provisions the
# otel_alerts sink table, Pub/Sub alert topic, dedicated service account,
# least-privilege IAM bindings, and Enterprise CONTINUOUS reservation.
# The shipped SQL templates are stateless per-span filters; see
# deploy/continuous-queries/README.md for INSERT INTO and TUMBLE window variants.

variable "enable_continuous_queries" {
  description = "Provision the opt-in Continuous Queries alerting infrastructure: the otel_alerts table, Pub/Sub alert topic, service account, IAM bindings, and Enterprise CONTINUOUS slot reservation. Needs the BigQuery Reservation, Cloud Pub/Sub, and IAM APIs enabled, and cannot be combined with enable_column_level_security."
  type        = bool
  default     = false
}

variable "continuous_query_slot_capacity" {
  description = "Baseline slot capacity of the BigQuery reservation created for CONTINUOUS jobs when enable_continuous_queries is set (whole multiple of 50 from 50 to 500; each continuous query job needs at least 10 slots to start, while Enterprise reservation baseline capacity is configured in multiples of 50 up to the 500-slot CONTINUOUS cap)."
  type        = number
  default     = 100

  validation {
    condition     = var.continuous_query_slot_capacity >= 50 && var.continuous_query_slot_capacity <= 500 && var.continuous_query_slot_capacity % 50 == 0 && floor(var.continuous_query_slot_capacity) == var.continuous_query_slot_capacity
    error_message = "continuous_query_slot_capacity must be a whole multiple of 50 between 50 and 500."
  }
}

variable "continuous_query_edition" {
  description = "BigQuery edition for the CONTINUOUS reservation when enable_continuous_queries is set: ENTERPRISE or ENTERPRISE_PLUS."
  type        = string
  default     = "ENTERPRISE"

  validation {
    condition     = contains(["ENTERPRISE", "ENTERPRISE_PLUS"], var.continuous_query_edition)
    error_message = "continuous_query_edition must be ENTERPRISE or ENTERPRISE_PLUS."
  }
}

variable "continuous_query_max_turn_input_tokens" {
  description = "Stateless per-span input token threshold rendered into deploy/continuous-queries/token_budget_burn.sql."
  type        = number
  default     = 100000

  validation {
    condition     = var.continuous_query_max_turn_input_tokens > 0 && floor(var.continuous_query_max_turn_input_tokens) == var.continuous_query_max_turn_input_tokens
    error_message = "continuous_query_max_turn_input_tokens must be a positive whole number."
  }
}

variable "continuous_query_max_turn_output_tokens" {
  description = "Stateless per-span output token threshold rendered into deploy/continuous-queries/token_budget_burn.sql."
  type        = number
  default     = 32000

  validation {
    condition     = var.continuous_query_max_turn_output_tokens > 0 && floor(var.continuous_query_max_turn_output_tokens) == var.continuous_query_max_turn_output_tokens
    error_message = "continuous_query_max_turn_output_tokens must be a positive whole number."
  }
}

variable "continuous_query_max_turn_duration_ms" {
  description = "Stateless per-span duration threshold in milliseconds rendered into deploy/continuous-queries/agent_latency_p95.sql."
  type        = number
  default     = 30000

  validation {
    condition     = var.continuous_query_max_turn_duration_ms > 0 && floor(var.continuous_query_max_turn_duration_ms) == var.continuous_query_max_turn_duration_ms
    error_message = "continuous_query_max_turn_duration_ms must be a positive whole number."
  }
}

variable "alerts_deletion_protection" {
  description = "Deletion protection on the otel_alerts table when enable_continuous_queries is set."
  type        = bool
  default     = false
}

variable "alerts_partition_expiration_days" {
  description = "Partition expiration in days for otel_alerts when enable_continuous_queries is set; 0 means no expiration."
  type        = number
  default     = 0

  validation {
    condition     = var.alerts_partition_expiration_days >= 0 && floor(var.alerts_partition_expiration_days) == var.alerts_partition_expiration_days
    error_message = "alerts_partition_expiration_days must be a whole number of days, 0 or more."
  }
}

# --- Looker Studio dashboard template ---
#
# Off by default. When looker_studio_template_report_id is set, outputs.tf
# renders looker_studio_create_url: a Looker Studio Linking API URL that copies
# the published template report and rewrites the project and dataset names in
# its six custom-query data sources to this module's project and dataset. The
# template's queries were built against a sandbox project and dataset, because
# Looker Studio validates a custom query when it is saved; the two
# looker_studio_template_* name variables record those sandbox names so the
# rewrite can find them. See dashboards/looker_studio/README.md.

variable "looker_studio_template_report_id" {
  description = "ID of the published Looker Studio template report that the looker_studio_create_url output copies: the value after /reporting/ in the template report's URL. Leave empty (the default) to skip the output. See dashboards/looker_studio/README.md for how to publish the template."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]*$", var.looker_studio_template_report_id))
    error_message = "looker_studio_template_report_id must be empty or contain only letters, digits, underscores, and hyphens: the ID from the template report's URL, not the whole URL."
  }
}

variable "looker_studio_template_project_id" {
  description = "Project ID that the published Looker Studio template report's custom queries name: the sandbox project the template was built against. The looker_studio_create_url output replaces it with project_id. Required when looker_studio_template_report_id is set. See dashboards/looker_studio/README.md."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9_.:-]*$", var.looker_studio_template_project_id))
    error_message = "looker_studio_template_project_id may contain only letters, digits, underscores, periods, colons, and hyphens."
  }
}

variable "looker_studio_template_dataset_id" {
  description = "Dataset ID that the published Looker Studio template report's custom queries name: the sandbox dataset the template was built against. The looker_studio_create_url output replaces it with the module's dataset. Required when looker_studio_template_report_id is set. See dashboards/looker_studio/README.md."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[A-Za-z0-9_]*$", var.looker_studio_template_dataset_id))
    error_message = "looker_studio_template_dataset_id may contain only letters, digits, and underscores."
  }
}
