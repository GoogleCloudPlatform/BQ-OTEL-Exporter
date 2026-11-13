// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"

// VersionV1Candidate is the candidate schema version staged ahead of the
// v1.0.0 freeze. It carries the exact physical column layout of v1.0.0 while
// stamping otel_schema_major="0", otel_schema_minor="3", otel_schema_patch="0".
const VersionV1Candidate = "v0alpha3"

const ddlV1LabelsClause = `labels = [
    ('otel_schema_major', '0'),
    ('otel_schema_minor', '3'),
    ('otel_schema_patch', '0'),
    ('otel_schema_variant', 'default')
  ]`

// SpansDDLV1 creates the v0alpha3 / v1.0.0-candidate span table.
const SpansDDLV1 = `
CREATE TABLE IF NOT EXISTS ` + "`%[1]s.%[2]s.%[3]s`" + ` (
  -- Time family
  start_time                         TIMESTAMP NOT NULL,
  start_time_unix_nano               INT64     NOT NULL,
  end_time                           TIMESTAMP NOT NULL,
  end_time_unix_nano                 INT64     NOT NULL,
  receive_time                       TIMESTAMP NOT NULL,
  receive_time_unix_nano             INT64     NOT NULL,
  duration_nano                      INT64     NOT NULL,
  -- Identity family
  trace_id                           STRING    NOT NULL,
  span_id                            STRING    NOT NULL,
  parent_span_id                     STRING,
  trace_state                        STRING,
  flags                              INT64,
  -- Span payload family
  name                               STRING    NOT NULL,
  kind                               INT64     NOT NULL,
  kind_name                          STRING,
  status STRUCT<
    code                             INT64,
    code_name                        STRING,
    message                          STRING
  >,
  attributes                         JSON,
  dropped_attributes_count           INT64,
  -- Resource & Instrumentation Scope family
  service_name                       STRING,
  resource STRUCT<
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  resource_schema_url                STRING,
  instrumentation_scope STRUCT<
    name                             STRING,
    version                          STRING,
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  scope_schema_url                   STRING,
  -- Signal detail: Inline Events & Links
  events ARRAY<STRUCT<
    time                             TIMESTAMP,
    time_unix_nano                   INT64,
    name                             STRING,
    attributes                       JSON,
    dropped_attributes_count         INT64
  >>,
  dropped_events_count               INT64,
  links ARRAY<STRUCT<
    trace_id                         STRING,
    span_id                          STRING,
    trace_state                      STRING,
    flags                            INT64,
    attributes                       JSON,
    dropped_attributes_count         INT64
  >>,
  dropped_links_count                INT64,
  -- Multimodal & Oversized Payload Offloading via BigQuery ObjectRef
  object_refs ARRAY<STRUCT<
    uri                              STRING    NOT NULL,
    version                          STRING,
    authorizer                       STRING,
    details                          JSON
  >>
)
PARTITION BY TIMESTAMP_TRUNC(start_time, HOUR)
CLUSTER BY service_name, trace_id, name
OPTIONS (
  ` + ddlV1LabelsClause + `
);
`

// LogsDDLV1 creates the v0alpha3 / v1.0.0-candidate log table.
const LogsDDLV1 = `
CREATE TABLE IF NOT EXISTS ` + "`%[1]s.%[2]s.%[3]s`" + ` (
  -- Time family
  timestamp                          TIMESTAMP NOT NULL,
  timestamp_source                   STRING    NOT NULL,
  time_unix_nano                     INT64     NOT NULL,
  observed_timestamp                 TIMESTAMP,
  observed_time_unix_nano            INT64     NOT NULL,
  receive_time                       TIMESTAMP NOT NULL,
  receive_time_unix_nano             INT64     NOT NULL,
  -- Identity & Correlation family
  trace_id                           STRING,
  span_id                            STRING,
  flags                              INT64,
  -- Log payload family
  event_name                         STRING,
  severity_number                    INT64,
  severity_text                      STRING,
  body                               JSON,
  attributes                         JSON,
  dropped_attributes_count           INT64,
  -- Resource & Instrumentation Scope family
  service_name                       STRING,
  resource STRUCT<
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  resource_schema_url                STRING,
  instrumentation_scope STRUCT<
    name                             STRING,
    version                          STRING,
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  scope_schema_url                   STRING,
  -- Multimodal & Oversized Payload Offloading via BigQuery ObjectRef
  object_refs ARRAY<STRUCT<
    uri                              STRING    NOT NULL,
    version                          STRING,
    authorizer                       STRING,
    details                          JSON
  >>,
  -- Dedup Identity family
  log_name                           STRING    NOT NULL,
  insert_id                          STRING
)
PARTITION BY DATE(timestamp)
CLUSTER BY service_name, trace_id, severity_number
OPTIONS (
  ` + ddlV1LabelsClause + `
);
`

// MetricsDDLV1 creates the v0alpha3 / v1.0.0-candidate metric data-point table.
const MetricsDDLV1 = `
CREATE TABLE IF NOT EXISTS ` + "`%[1]s.%[2]s.%[3]s`" + ` (
  -- Time family
  timestamp                          TIMESTAMP NOT NULL,
  time_unix_nano                     INT64     NOT NULL,
  start_time                         TIMESTAMP,
  start_time_unix_nano               INT64,
  receive_time                       TIMESTAMP NOT NULL,
  receive_time_unix_nano             INT64     NOT NULL,
  -- Metric identity & metadata
  service_name                       STRING,
  metric_name                        STRING    NOT NULL,
  metric_description                 STRING,
  metric_unit                        STRING,
  metric_type                        STRING    NOT NULL,
  aggregation_temporality            STRING,
  is_monotonic                       BOOL,
  flags                              INT64,
  attributes                         JSON,
  metric_metadata                    JSON,
  -- Scalar values (GAUGE / SUM)
  value_type                         STRING,
  value_double                       FLOAT64,
  value_int64                        INT64,
  -- Distribution values (HISTOGRAM / EXPONENTIAL_HISTOGRAM / SUMMARY)
  count                              INT64,
  sum                                FLOAT64,
  min                                FLOAT64,
  max                                FLOAT64,
  explicit_bounds                    ARRAY<FLOAT64>,
  bucket_counts                      ARRAY<INT64>,
  exp_scale                          INT64,
  exp_zero_count                     INT64,
  exp_zero_threshold                 FLOAT64,
  exp_positive STRUCT<
    offset                           INT64,
    bucket_counts                    ARRAY<INT64>
  >,
  exp_negative STRUCT<
    offset                           INT64,
    bucket_counts                    ARRAY<INT64>
  >,
  summary_quantiles ARRAY<STRUCT<
    quantile                         FLOAT64,
    value                            FLOAT64
  >>,
  -- Exemplars (trace/span correlation)
  exemplars ARRAY<STRUCT<
    time                             TIMESTAMP,
    time_unix_nano                   INT64,
    value_double                     FLOAT64,
    value_int64                      INT64,
    span_id                          STRING,
    trace_id                         STRING,
    filtered_attributes              JSON
  >>,
  -- Resource & Instrumentation Scope family
  resource STRUCT<
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  resource_schema_url                STRING,
  instrumentation_scope STRUCT<
    name                             STRING,
    version                          STRING,
    attributes                       JSON,
    dropped_attributes_count         INT64
  >,
  scope_schema_url                   STRING,
  -- Dedup identity
  point_fingerprint                  STRING    NOT NULL
)
PARTITION BY DATE(timestamp)
CLUSTER BY service_name, metric_name, metric_type
OPTIONS (
  ` + ddlV1LabelsClause + `
);
`

// QuarantineDDLV1 creates the v0alpha3 / v1.0.0-candidate quarantine table.
const QuarantineDDLV1 = `
CREATE TABLE IF NOT EXISTS ` + "`%[1]s.%[2]s.%[3]s`" + ` (
  ingest_time                        TIMESTAMP NOT NULL,
  signal                             STRING    NOT NULL, -- 'spans' | 'logs' | 'metrics'
  error_code                         STRING    NOT NULL, -- e.g. 'INVALID_SPAN_ID', 'MISSING_END_TIME', 'OVERSIZE_ROW'
  error_message                      STRING    NOT NULL,
  service_name                       STRING,
  trace_id                           STRING,
  span_id                            STRING,
  raw_payload                        STRING,             -- serialized OTLP JSON/proto up to 8 MiB
  raw_attributes                     JSON,
  payload_ref STRUCT<
    uri                              STRING    NOT NULL,
    version                          STRING,
    authorizer                       STRING,
    details                          JSON
  >,                                                     -- populated when raw_payload > 8 MiB is offloaded to GCS
  exporter_instance                  STRING
)
PARTITION BY DATE(ingest_time)
CLUSTER BY signal, error_code, service_name
OPTIONS (
  partition_expiration_days = 30,
  ` + ddlV1LabelsClause + `
);
`

// SpansDedupViewDDLV1 is the v1-candidate span deduplication view DDL.
const SpansDedupViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s.%[3]s_dedup`" + ` AS
` + SpansDedupViewQueryV1 + `;
`

// SpansDedupViewQueryV1 is shared by operator-run DDL and metadata-API view
// creation for the v1-candidate span contract.
const SpansDedupViewQueryV1 = `
SELECT *
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
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
`

// LogsDedupViewDDLV1 is the v1-candidate log deduplication view DDL.
const LogsDedupViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s.%[3]s_dedup`" + ` AS
` + LogsDedupViewQueryV1 + `;
`

// LogsDedupViewQueryV1 preserves NULL insert_id rows (emitted when
// logs.synthesize_insert_id is false) while maintaining partition pruning over
// timestamp.
const LogsDedupViewQueryV1 = `
SELECT *
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
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
`

// MetricsDedupViewDDLV1 is the v1-candidate metric deduplication view DDL.
const MetricsDedupViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s.%[3]s_dedup`" + ` AS
` + MetricsDedupViewQueryV1 + `;
`

// MetricsDedupViewQueryV1 is shared by operator-run DDL and metadata-API view
// creation for the v1-candidate metric contract.
const MetricsDedupViewQueryV1 = `
SELECT *
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
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
`
