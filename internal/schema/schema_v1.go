// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"

import "strings"

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

// SpansAsAllSpansViewDDLV1 creates otel_spans_as_allspans over the
// v1-candidate span deduplication view, omitting the dropped v0alpha2
// attributes_schema column so every column resolves against SpansDDLV1.
const SpansAsAllSpansViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s." + SpansAsAllSpansViewName + "`" + ` AS
` + SpansAsAllSpansViewQueryV1 + `;
`

// SpansAsAllSpansViewQueryV1 is shared by operator-run DDL and metadata-API
// view creation for the v1-candidate span contract.
const SpansAsAllSpansViewQueryV1 = `
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
FROM ` + "`%[1]s.%[2]s.%[3]s_dedup`" + `
`

// GenAISpansViewDDLV1 creates v_gen_ai_spans over the v1-candidate span
// deduplication view, projecting object_refs in place of dropped payload_refs.
const GenAISpansViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s." + GenAISpansViewName + "`" + ` AS
` + GenAISpansViewQueryV1 + `;
`

// GenAISpansViewQueryV1 is shared by operator-run DDL and metadata-API view
// creation for the v1-candidate span contract.
const GenAISpansViewQueryV1 = `
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
  -- Promoted OTel GenAI semantic convention fields (Plain JSON)
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
  -- ADK / Vertex Agent Analytics attributes
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
  -- Multimodal ObjectRef array and raw bags
  object_refs,
  attributes,
  resource,
  instrumentation_scope,
  events,
  links,
  -- Promoted OTel GenAI v1.37.0+, v1.40.0, v1.41.0, and semantic-conventions-genai@f3c6d0c9 fields
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
FROM ` + "`%[1]s.%[2]s.%[3]s_dedup`" + `
WHERE JSON_VALUE(attributes, '$."gen_ai.operation.name"') IS NOT NULL
   OR JSON_VALUE(attributes, '$."gen_ai.system"') IS NOT NULL
   OR JSON_VALUE(attributes, '$."gen_ai.provider.name"') IS NOT NULL
   OR JSON_VALUE(attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
   OR JSON_VALUE(attributes, '$."gen_ai.main_agent.name"') IS NOT NULL
   OR JSON_VALUE(attributes, '$."gen_ai.main_agent.id"') IS NOT NULL
`

// MCPSpansViewQueryV1 projects object_refs in place of dropped payload_refs
// while preserving every promoted MCP semantic convention column and predicate
// of MCPSpansViewQuery.
var MCPSpansViewQueryV1 = strings.ReplaceAll(MCPSpansViewQuery, "payload_refs", "object_refs")

// MCPSpansViewDDLV1 creates v_mcp_spans over the v1-candidate span
// deduplication view.
var MCPSpansViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s." + MCPSpansViewName + "`" + ` AS
` + MCPSpansViewQueryV1 + `;
`

// GenAILogsViewDDLV1 creates v_gen_ai_logs over the v1-candidate log and span
// deduplication views, projecting l.object_refs in place of dropped
// l.payload_refs.
const GenAILogsViewDDLV1 = `
CREATE OR REPLACE VIEW ` + "`%[1]s.%[2]s." + GenAILogsViewName + "`" + ` AS
` + GenAILogsViewQueryV1 + `;
`

// GenAILogsViewQueryV1 is shared by operator-run DDL and metadata-API view
// creation for the v1-candidate log contract.
const GenAILogsViewQueryV1 = `
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
FROM ` + "`%[1]s.%[2]s.%[3]s_dedup`" + ` l
LEFT JOIN ` + "`%[1]s.%[2]s.%[4]s_dedup`" + ` s
  ON l.trace_id = s.trace_id
  AND l.span_id = s.span_id
  AND l.service_name IS NOT DISTINCT FROM s.service_name
  AND s.start_time BETWEEN TIMESTAMP_SUB(l.timestamp, INTERVAL 24 HOUR) AND TIMESTAMP_ADD(l.timestamp, INTERVAL 1 HOUR)
WHERE COALESCE(NULLIF(l.event_name, ''), JSON_VALUE(l.attributes, '$."event.name"')) LIKE 'gen_ai.%%'
   OR JSON_VALUE(l.attributes, '$."gen_ai.system"') IS NOT NULL
   OR JSON_VALUE(l.attributes, '$."gen_ai.provider.name"') IS NOT NULL
   OR JSON_VALUE(l.attributes, '$."gcp.vertex.agent.invocation_id"') IS NOT NULL
`
