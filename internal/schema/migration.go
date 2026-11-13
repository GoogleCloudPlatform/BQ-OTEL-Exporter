// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"fmt"
	"strings"
)

// SpansMigrationSQLV0Alpha2ToV1 copies spans from a v0alpha2 table to a fresh
// v0alpha3 / v1 destination table, dropping *_schema sidecars and schema_version
// and projecting payload_refs[].object_ref into object_refs.
const SpansMigrationSQLV0Alpha2ToV1 = `
INSERT INTO ` + "`%[4]s.%[5]s.%[6]s`" + ` (
  start_time, start_time_unix_nano, end_time, end_time_unix_nano,
  receive_time, receive_time_unix_nano, duration_nano,
  trace_id, span_id, parent_span_id, trace_state, flags,
  name, kind, kind_name, status, attributes, dropped_attributes_count,
  service_name, resource, resource_schema_url, instrumentation_scope, scope_schema_url,
  events, dropped_events_count, links, dropped_links_count, object_refs
)
SELECT
  start_time, start_time_unix_nano, end_time, end_time_unix_nano,
  receive_time, receive_time_unix_nano, duration_nano,
  trace_id, span_id, parent_span_id, trace_state, flags,
  name, kind, kind_name, status, attributes, dropped_attributes_count,
  service_name,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  ARRAY(SELECT AS STRUCT e.time, e.time_unix_nano, e.name, e.attributes, e.dropped_attributes_count FROM UNNEST(events) AS e) AS events,
  dropped_events_count,
  ARRAY(SELECT AS STRUCT l.trace_id, l.span_id, l.trace_state, l.flags, l.attributes, l.dropped_attributes_count FROM UNNEST(links) AS l) AS links,
  dropped_links_count,
  ARRAY(SELECT AS STRUCT p.object_ref.uri AS uri, p.object_ref.version AS version, p.object_ref.authorizer AS authorizer, p.object_ref.details AS details FROM UNNEST(payload_refs) AS p WHERE p.object_ref.uri IS NOT NULL AND p.object_ref.uri != '') AS object_refs
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
`

// LogsMigrationSQLV0Alpha2ToV1 copies logs from a v0alpha2 table to a fresh
// v0alpha3 / v1 destination table, dropping *_schema sidecars,
// record_fingerprint, and schema_version, projecting payload_refs[].object_ref
// into object_refs, and preserving historical insert_id values.
const LogsMigrationSQLV0Alpha2ToV1 = `
INSERT INTO ` + "`%[4]s.%[5]s.%[6]s`" + ` (
  timestamp, timestamp_source, time_unix_nano, observed_timestamp, observed_time_unix_nano,
  receive_time, receive_time_unix_nano, trace_id, span_id, flags,
  event_name, severity_number, severity_text, body, attributes, dropped_attributes_count,
  service_name, resource, resource_schema_url, instrumentation_scope, scope_schema_url,
  object_refs, log_name, insert_id
)
SELECT
  timestamp, timestamp_source, time_unix_nano, observed_timestamp, observed_time_unix_nano,
  receive_time, receive_time_unix_nano, trace_id, span_id, flags,
  event_name, severity_number, severity_text, body, attributes, dropped_attributes_count,
  service_name,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  ARRAY(SELECT AS STRUCT p.object_ref.uri AS uri, p.object_ref.version AS version, p.object_ref.authorizer AS authorizer, p.object_ref.details AS details FROM UNNEST(payload_refs) AS p WHERE p.object_ref.uri IS NOT NULL AND p.object_ref.uri != '') AS object_refs,
  log_name,
  COALESCE(NULLIF(insert_id, ''), record_fingerprint) AS insert_id
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
`

// MetricsMigrationSQLV0Alpha2ToV1 copies metric points from a v0alpha2 table to
// a fresh v0alpha3 / v1 destination table, dropping *_schema sidecars and
// schema_version while preserving point_fingerprint and exemplars.
const MetricsMigrationSQLV0Alpha2ToV1 = `
INSERT INTO ` + "`%[4]s.%[5]s.%[6]s`" + ` (
  timestamp, time_unix_nano, start_time, start_time_unix_nano, receive_time, receive_time_unix_nano,
  service_name, metric_name, metric_description, metric_unit, metric_type,
  aggregation_temporality, is_monotonic, flags, attributes, metric_metadata,
  value_type, value_double, value_int64, count, sum, min, max,
  explicit_bounds, bucket_counts, exp_scale, exp_zero_count, exp_zero_threshold,
  exp_positive, exp_negative, summary_quantiles, exemplars,
  resource, resource_schema_url, instrumentation_scope, scope_schema_url, point_fingerprint
)
SELECT
  timestamp, time_unix_nano, start_time, start_time_unix_nano, receive_time, receive_time_unix_nano,
  service_name, metric_name, metric_description, metric_unit, metric_type,
  aggregation_temporality, is_monotonic, flags, attributes, metric_metadata,
  value_type, value_double, value_int64, count, sum, min, max,
  explicit_bounds, bucket_counts, exp_scale, exp_zero_count, exp_zero_threshold,
  exp_positive, exp_negative, summary_quantiles,
  ARRAY(SELECT AS STRUCT ex.time, ex.time_unix_nano, ex.value_double, ex.value_int64, ex.span_id, ex.trace_id, ex.filtered_attributes FROM UNNEST(exemplars) AS ex) AS exemplars,
  IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource,
  resource_schema_url,
  IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope,
  scope_schema_url,
  point_fingerprint
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
`

// QuarantineMigrationSQLV0Alpha2ToV1 copies quarantined records from a v0alpha2
// table to a fresh v0alpha3 / v1 destination table, dropping schema_version and
// enforcing the REQUIRED payload_ref.uri contract.
const QuarantineMigrationSQLV0Alpha2ToV1 = `
INSERT INTO ` + "`%[4]s.%[5]s.%[6]s`" + ` (
  ingest_time, signal, error_code, error_message, service_name, trace_id, span_id,
  raw_payload, raw_attributes, payload_ref, exporter_instance
)
SELECT
  ingest_time, signal, error_code, error_message, service_name, trace_id, span_id,
  raw_payload, raw_attributes,
  IF(payload_ref IS NOT NULL AND NULLIF(payload_ref.uri, '') IS NOT NULL, STRUCT(payload_ref.uri AS uri, payload_ref.version AS version, payload_ref.authorizer AS authorizer, payload_ref.details AS details), NULL) AS payload_ref,
  exporter_instance
FROM ` + "`%[1]s.%[2]s.%[3]s`" + `
`

// MigrationSQLV0Alpha2ToV1 formats the v0alpha2 -> v1 INSERT INTO ... SELECT
// migration queries using matching source and destination table names across
// distinct side-by-side projects or datasets.
func MigrationSQLV0Alpha2ToV1(
	srcProject, srcDataset, dstProject, dstDataset,
	spansTable, logsTable, metricsTable, quarantineTable string,
) (map[string]string, error) {
	return MigrationSQLV0Alpha2ToV1Pair(
		srcProject, srcDataset, spansTable, logsTable, metricsTable, quarantineTable,
		dstProject, dstDataset, spansTable, logsTable, metricsTable, quarantineTable,
	)
}

// MigrationSQLV0Alpha2ToV1Pair formats the v0alpha2 -> v1 INSERT INTO ... SELECT
// migration queries when source and destination table names differ (for example
// during integration tests).
func MigrationSQLV0Alpha2ToV1Pair(
	srcProject, srcDataset, srcSpans, srcLogs, srcMetrics, srcQuarantine,
	dstProject, dstDataset, dstSpans, dstLogs, dstMetrics, dstQuarantine string,
) (map[string]string, error) {
	if srcProject == "" || srcDataset == "" || dstProject == "" || dstDataset == "" {
		return nil, fmt.Errorf("migration project and dataset names must be non-empty")
	}
	for _, tbl := range []struct {
		name  string
		value string
	}{
		{"srcSpans", srcSpans},
		{"srcLogs", srcLogs},
		{"srcMetrics", srcMetrics},
		{"srcQuarantine", srcQuarantine},
		{"dstSpans", dstSpans},
		{"dstLogs", dstLogs},
		{"dstMetrics", dstMetrics},
		{"dstQuarantine", dstQuarantine},
	} {
		if tbl.value == "" {
			return nil, fmt.Errorf("migration table name %s must be non-empty", tbl.name)
		}
	}
	if srcProject == dstProject && srcDataset == dstDataset &&
		(srcSpans == dstSpans || srcLogs == dstLogs || srcMetrics == dstMetrics || srcQuarantine == dstQuarantine) {
		return nil, fmt.Errorf("v0alpha2 -> v1 migration requires distinct source and destination tables or side-by-side dataset isolation")
	}
	return map[string]string{
		"otel_spans":      strings.TrimSpace(fmt.Sprintf(SpansMigrationSQLV0Alpha2ToV1, srcProject, srcDataset, srcSpans, dstProject, dstDataset, dstSpans)),
		"otel_logs":       strings.TrimSpace(fmt.Sprintf(LogsMigrationSQLV0Alpha2ToV1, srcProject, srcDataset, srcLogs, dstProject, dstDataset, dstLogs)),
		"otel_metrics":    strings.TrimSpace(fmt.Sprintf(MetricsMigrationSQLV0Alpha2ToV1, srcProject, srcDataset, srcMetrics, dstProject, dstDataset, dstMetrics)),
		"otel_quarantine": strings.TrimSpace(fmt.Sprintf(QuarantineMigrationSQLV0Alpha2ToV1, srcProject, srcDataset, srcQuarantine, dstProject, dstDataset, dstQuarantine)),
	}, nil
}
