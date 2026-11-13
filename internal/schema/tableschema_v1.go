// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"

import (
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
)

// SpansTableSchemaV1 is the v0alpha3 / v1.0.0-candidate span contract: 28
// columns, grouped by family in the same order as SpansDDLV1.
//
// Relative to v0alpha2 it removes all *_schema sidecar columns and the per-row
// schema_version column (replaced by otel_schema_* table labels), and replaces
// payload_refs with native BigQuery ObjectRef-compatible object_refs.
func SpansTableSchemaV1() *storagepb.TableSchema {
	return &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		// Time family.
		f("start_time", ts, req),
		f("start_time_unix_nano", i64, req),
		f("end_time", ts, req),
		f("end_time_unix_nano", i64, req),
		f("receive_time", ts, req),
		f("receive_time_unix_nano", i64, req),
		f("duration_nano", i64, req),

		// Identity family.
		f("trace_id", str, req),
		f("span_id", str, req),
		f("parent_span_id", str, opt),
		f("trace_state", str, opt),
		f("flags", i64, opt),

		// Span payload family.
		f("name", str, req),
		f("kind", i64, req),
		f("kind_name", str, opt),
		record("status", opt,
			f("code", i64, opt),
			f("code_name", str, opt),
			f("message", str, opt),
		),
		f("attributes", jsn, opt),
		f("dropped_attributes_count", i64, opt),

		// Resource and instrumentation scope family.
		f("service_name", str, opt),
		resourceRecordV1(),
		f("resource_schema_url", str, opt),
		scopeRecordV1(),
		f("scope_schema_url", str, opt),

		// Signal detail: inline events and links.
		record("events", rep,
			f("time", ts, opt),
			f("time_unix_nano", i64, opt),
			f("name", str, opt),
			f("attributes", jsn, opt),
			f("dropped_attributes_count", i64, opt),
		),
		f("dropped_events_count", i64, opt),
		record("links", rep,
			f("trace_id", str, opt),
			f("span_id", str, opt),
			f("trace_state", str, opt),
			f("flags", i64, opt),
			f("attributes", jsn, opt),
			f("dropped_attributes_count", i64, opt),
		),
		f("dropped_links_count", i64, opt),

		// Multimodal and oversized payload offloading via native BigQuery ObjectRef.
		objectRefsRecordV1("object_refs", rep),
	}}
}

func resourceRecordV1() *storagepb.TableFieldSchema {
	return record("resource", opt,
		f("attributes", jsn, opt),
		f("dropped_attributes_count", i64, opt),
	)
}

func scopeRecordV1() *storagepb.TableFieldSchema {
	return record("instrumentation_scope", opt,
		f("name", str, opt),
		f("version", str, opt),
		f("attributes", jsn, opt),
		f("dropped_attributes_count", i64, opt),
	)
}

// objectRefsRecordV1 builds the 4-field native BigQuery ObjectRef STRUCT used by
// object_refs (REPEATED) on spans/logs and payload_ref (NULLABLE) on quarantine.
func objectRefsRecordV1(name string, mode storagepb.TableFieldSchema_Mode) *storagepb.TableFieldSchema {
	return record(name, mode,
		f("uri", str, req),
		f("version", str, opt),
		f("authorizer", str, opt),
		f("details", jsn, opt),
	)
}

// LogsTableSchemaV1 is the v0alpha3 / v1.0.0-candidate log contract: 24
// columns, grouped by family in the same order as LogsDDLV1.
//
// Relative to v0alpha2 it removes all *_schema sidecars, record_fingerprint, and
// schema_version, replaces payload_refs with object_refs, and makes insert_id
// NULLABLE while keeping all time-family integer/source columns REQUIRED.
func LogsTableSchemaV1() *storagepb.TableSchema {
	return &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		// Time family.
		f("timestamp", ts, req),
		f("timestamp_source", str, req),
		f("time_unix_nano", i64, req),
		f("observed_timestamp", ts, opt),
		f("observed_time_unix_nano", i64, req),
		f("receive_time", ts, req),
		f("receive_time_unix_nano", i64, req),

		// Identity and correlation family.
		f("trace_id", str, opt),
		f("span_id", str, opt),
		f("flags", i64, opt),

		// Log payload family.
		f("event_name", str, opt),
		f("severity_number", i64, opt),
		f("severity_text", str, opt),
		f("body", jsn, opt),
		f("attributes", jsn, opt),
		f("dropped_attributes_count", i64, opt),

		// Resource and instrumentation scope family.
		f("service_name", str, opt),
		resourceRecordV1(),
		f("resource_schema_url", str, opt),
		scopeRecordV1(),
		f("scope_schema_url", str, opt),

		// Multimodal and oversized payload offloading via native BigQuery ObjectRef.
		objectRefsRecordV1("object_refs", rep),

		// Dedup identity family.
		f("log_name", str, req),
		f("insert_id", str, opt),
	}}
}

// MetricsTableSchemaV1 is the v0alpha3 / v1.0.0-candidate metric data-point
// contract: 37 columns, grouped by family in the same order as MetricsDDLV1.
//
// Relative to v0alpha2 it removes all *_schema sidecars (including nested
// exemplar, resource, and scope sidecars) and schema_version.
func MetricsTableSchemaV1() *storagepb.TableSchema {
	return &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		// Time family.
		f("timestamp", ts, req),
		f("time_unix_nano", i64, req),
		f("start_time", ts, opt),
		f("start_time_unix_nano", i64, opt),
		f("receive_time", ts, req),
		f("receive_time_unix_nano", i64, req),

		// Metric identity and metadata.
		f("service_name", str, opt),
		f("metric_name", str, req),
		f("metric_description", str, opt),
		f("metric_unit", str, opt),
		f("metric_type", str, req),
		f("aggregation_temporality", str, opt),
		f("is_monotonic", bl, opt),
		f("flags", i64, opt),
		f("attributes", jsn, opt),
		f("metric_metadata", jsn, opt),

		// Scalar values (GAUGE / SUM).
		f("value_type", str, opt),
		f("value_double", f64, opt),
		f("value_int64", i64, opt),

		// Distribution values (HISTOGRAM / EXPONENTIAL_HISTOGRAM / SUMMARY).
		f("count", i64, opt),
		f("sum", f64, opt),
		f("min", f64, opt),
		f("max", f64, opt),
		f("explicit_bounds", f64, rep),
		f("bucket_counts", i64, rep),
		f("exp_scale", i64, opt),
		f("exp_zero_count", i64, opt),
		f("exp_zero_threshold", f64, opt),
		record("exp_positive", opt,
			f("offset", i64, opt),
			f("bucket_counts", i64, rep),
		),
		record("exp_negative", opt,
			f("offset", i64, opt),
			f("bucket_counts", i64, rep),
		),
		record("summary_quantiles", rep,
			f("quantile", f64, opt),
			f("value", f64, opt),
		),

		// Exemplars (trace/span correlation).
		record("exemplars", rep,
			f("time", ts, opt),
			f("time_unix_nano", i64, opt),
			f("value_double", f64, opt),
			f("value_int64", i64, opt),
			f("span_id", str, opt),
			f("trace_id", str, opt),
			f("filtered_attributes", jsn, opt),
		),

		// Resource and instrumentation scope family.
		resourceRecordV1(),
		f("resource_schema_url", str, opt),
		scopeRecordV1(),
		f("scope_schema_url", str, opt),

		// Dedup identity.
		f("point_fingerprint", str, req),
	}}
}

// QuarantineTableSchemaV1 is the v0alpha3 / v1.0.0-candidate quarantine
// dead-letter contract: 11 columns, in the same order as QuarantineDDLV1.
func QuarantineTableSchemaV1() *storagepb.TableSchema {
	return &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		f("ingest_time", ts, req),
		f("signal", str, req),
		f("error_code", str, req),
		f("error_message", str, req),
		f("service_name", str, opt),
		f("trace_id", str, opt),
		f("span_id", str, opt),
		f("raw_payload", str, opt),
		f("raw_attributes", jsn, opt),
		objectRefsRecordV1("payload_ref", opt),
		f("exporter_instance", str, opt),
	}}
}
