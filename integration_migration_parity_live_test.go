// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// TestLiveMigrationSQLParityV0Alpha2ToV1 creates ephemeral v0alpha2 and v1
// side-by-side tables in BigQuery (guarded by BQ_PROJECT / BQ_DATASET),
// executes the v0alpha2 -> v1 INSERT INTO ... SELECT migration SQL from
// internal/schema, and verifies parity with live v1 exporter writes across all
// dedup keys and payloads.
func TestLiveMigrationSQLParityV0Alpha2ToV1(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	dataset := os.Getenv("BQ_DATASET")
	if project == "" || dataset == "" {
		t.Skip("BQ_PROJECT and BQ_DATASET must be set for live migration parity test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	client, err := bq.NewClient(ctx, project)
	if err != nil {
		t.Fatalf("bigquery.NewClient: %v", err)
	}
	defer func() { _ = client.Close() }()

	suffix := fmt.Sprintf("mig_%d", time.Now().UnixNano())
	v2Spans := "otel_spans_v2_" + suffix
	v1Spans := "otel_spans_v1_" + suffix
	v2Logs := "otel_logs_v2_" + suffix
	v1Logs := "otel_logs_v1_" + suffix
	v2Metrics := "otel_metrics_v2_" + suffix
	v1Metrics := "otel_metrics_v1_" + suffix
	v2Quarantine := "otel_quarantine_v2_" + suffix
	v1Quarantine := "otel_quarantine_v1_" + suffix

	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanCancel()
		for _, tbl := range []string{v2Spans, v1Spans, v2Logs, v1Logs, v2Metrics, v1Metrics, v2Quarantine, v1Quarantine} {
			_ = client.Dataset(dataset).Table(tbl).Delete(cleanCtx)
		}
	})

	runSQL := func(sql string) {
		t.Helper()
		job, err := client.Query(sql).Run(ctx)
		if err != nil {
			t.Fatalf("run query:\n%s\nerr: %v", sql, err)
		}
		st, err := job.Wait(ctx)
		if err != nil {
			t.Fatalf("wait query:\n%s\nerr: %v", sql, err)
		}
		if err := st.Err(); err != nil {
			t.Fatalf("query status:\n%s\nerr: %v", sql, err)
		}
	}

	// Create v1 destination tables via canonical DDL templates.
	runSQL(fmt.Sprintf(schema.SpansDDL, project, dataset, v1Spans))
	runSQL(fmt.Sprintf(schema.LogsDDL, project, dataset, v1Logs))
	runSQL(fmt.Sprintf(schema.MetricsDDL, project, dataset, v1Metrics))
	runSQL(fmt.Sprintf(schema.QuarantineDDL, project, dataset, v1Quarantine))

	// Create ephemeral v0alpha2 source tables carrying dropped sidecar columns.
	runSQL(fmt.Sprintf(`
CREATE TABLE %s.%s.%s (
  start_time TIMESTAMP NOT NULL,
  start_time_unix_nano INT64 NOT NULL,
  end_time TIMESTAMP NOT NULL,
  end_time_unix_nano INT64 NOT NULL,
  receive_time TIMESTAMP NOT NULL,
  receive_time_unix_nano INT64 NOT NULL,
  duration_nano INT64 NOT NULL,
  trace_id STRING NOT NULL,
  span_id STRING NOT NULL,
  parent_span_id STRING,
  trace_state STRING,
  flags INT64,
  name STRING NOT NULL,
  kind INT64 NOT NULL,
  kind_name STRING,
  status STRUCT<code INT64, code_name STRING, message STRING>,
  attributes JSON,
  attributes_schema JSON,
  dropped_attributes_count INT64,
  service_name STRING,
  resource STRUCT<attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  resource_schema_url STRING,
  instrumentation_scope STRUCT<name STRING, version STRING, attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  scope_schema_url STRING,
  events ARRAY<STRUCT<time TIMESTAMP, time_unix_nano INT64, name STRING, attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>>,
  dropped_events_count INT64,
  links ARRAY<STRUCT<trace_id STRING, span_id STRING, trace_state STRING, flags INT64, attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>>,
  dropped_links_count INT64,
  payload_refs ARRAY<STRUCT<attribute_path STRING, part_index INT64, mime_type STRING, storage_mode STRING, byte_size INT64, sha256 STRING, object_ref STRUCT<uri STRING, version STRING, authorizer STRING, details JSON>>>,
  schema_version STRING NOT NULL
) PARTITION BY DATE(start_time)`, "`"+project, dataset, v2Spans+"`"))

	runSQL(fmt.Sprintf(`
CREATE TABLE %s.%s.%s (
  timestamp TIMESTAMP NOT NULL,
  timestamp_source STRING NOT NULL,
  time_unix_nano INT64 NOT NULL,
  observed_timestamp TIMESTAMP,
  observed_time_unix_nano INT64 NOT NULL,
  receive_time TIMESTAMP NOT NULL,
  receive_time_unix_nano INT64 NOT NULL,
  trace_id STRING,
  span_id STRING,
  flags INT64,
  event_name STRING,
  severity_number INT64,
  severity_text STRING,
  body JSON,
  attributes JSON,
  attributes_schema JSON,
  dropped_attributes_count INT64,
  service_name STRING,
  resource STRUCT<attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  resource_schema_url STRING,
  instrumentation_scope STRUCT<name STRING, version STRING, attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  scope_schema_url STRING,
  payload_refs ARRAY<STRUCT<attribute_path STRING, part_index INT64, mime_type STRING, storage_mode STRING, byte_size INT64, sha256 STRING, object_ref STRUCT<uri STRING, version STRING, authorizer STRING, details JSON>>>,
  log_name STRING NOT NULL,
  insert_id STRING NOT NULL,
  record_fingerprint STRING,
  schema_version STRING NOT NULL
) PARTITION BY DATE(timestamp)`, "`"+project, dataset, v2Logs+"`"))

	runSQL(fmt.Sprintf(`
CREATE TABLE %s.%s.%s (
  timestamp TIMESTAMP NOT NULL,
  time_unix_nano INT64 NOT NULL,
  start_time TIMESTAMP,
  start_time_unix_nano INT64,
  receive_time TIMESTAMP NOT NULL,
  receive_time_unix_nano INT64 NOT NULL,
  service_name STRING,
  metric_name STRING NOT NULL,
  metric_description STRING,
  metric_unit STRING,
  metric_type STRING NOT NULL,
  aggregation_temporality STRING,
  is_monotonic BOOL,
  flags INT64,
  attributes JSON,
  attributes_schema JSON,
  metric_metadata JSON,
  metric_metadata_schema JSON,
  value_type STRING,
  value_double FLOAT64,
  value_int64 INT64,
  count INT64,
  sum FLOAT64,
  min FLOAT64,
  max FLOAT64,
  explicit_bounds ARRAY<FLOAT64>,
  bucket_counts ARRAY<INT64>,
  exp_scale INT64,
  exp_zero_count INT64,
  exp_zero_threshold FLOAT64,
  exp_positive STRUCT<offset INT64, bucket_counts ARRAY<INT64>>,
  exp_negative STRUCT<offset INT64, bucket_counts ARRAY<INT64>>,
  summary_quantiles ARRAY<STRUCT<quantile FLOAT64, value FLOAT64>>,
  exemplars ARRAY<STRUCT<time TIMESTAMP, time_unix_nano INT64, value_double FLOAT64, value_int64 INT64, span_id STRING, trace_id STRING, filtered_attributes JSON, filtered_attributes_schema JSON>>,
  resource STRUCT<attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  resource_schema_url STRING,
  instrumentation_scope STRUCT<name STRING, version STRING, attributes JSON, attributes_schema JSON, dropped_attributes_count INT64>,
  scope_schema_url STRING,
  point_fingerprint STRING NOT NULL,
  schema_version STRING NOT NULL
) PARTITION BY DATE(timestamp)`, "`"+project, dataset, v2Metrics+"`"))

	runSQL(fmt.Sprintf(`
CREATE TABLE %s.%s.%s (
  ingest_time TIMESTAMP NOT NULL,
  signal STRING NOT NULL,
  error_code STRING NOT NULL,
  error_message STRING NOT NULL,
  service_name STRING,
  trace_id STRING,
  span_id STRING,
  raw_payload STRING,
  raw_attributes JSON,
  payload_ref STRUCT<uri STRING, version STRING, authorizer STRING, details JSON>,
  exporter_instance STRING,
  schema_version STRING NOT NULL
) PARTITION BY DATE(ingest_time)`, "`"+project, dataset, v2Quarantine+"`"))

	// Seed representative rows into all four v0alpha2 tables and run MigrationSQLV0Alpha2ToV1Pair.
	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  TIMESTAMP '2026-08-12 10:00:00+00', 1786528800000000000,
  TIMESTAMP '2026-08-12 10:00:01+00', 1786528801000000000,
  TIMESTAMP '2026-08-12 10:00:02+00', 1786528802000000000,
  1000000000, '102030405060708090a0b0c0d0e0f001', '0102030405060708', NULL, NULL, 1,
  'live-parity-span', 2, 'CLIENT', STRUCT(1, 'OK', NULL),
  JSON '{"k":"v"}', JSON '{"k":"string"}', 0, 'parity-svc',
  STRUCT(JSON '{"service.name":"parity-svc"}', JSON '{"service.name":"string"}', 0), NULL,
  STRUCT('tracer', '1.0', JSON '{}', JSON '{}', 0), NULL,
  [], 0, [], 0,
  [STRUCT('attributes.prompt', 0, 'application/json', 'object_ref', 1024, 'abcd', STRUCT('gs://bucket/p.json', '1', 'conn', JSON '{}'))],
  'v0alpha2'
)`, "`"+project, dataset, v2Spans+"`"))

	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  TIMESTAMP '2026-08-12 10:00:00+00', 'event', 1786528800000000000,
  TIMESTAMP '2026-08-12 10:00:00+00', 1786528800000000000,
  TIMESTAMP '2026-08-12 10:00:02+00', 1786528802000000000,
  '102030405060708090a0b0c0d0e0f001', '0102030405060708', 1,
  'gen_ai.user.message', 9, 'INFO', JSON '"hi"', JSON '{"k":"v"}', JSON '{"k":"string"}', 0, 'parity-svc',
  STRUCT(JSON '{"service.name":"parity-svc"}', JSON '{"service.name":"string"}', 0), NULL,
  STRUCT('logger', '1.0', JSON '{}', JSON '{}', 0), NULL,
  [STRUCT('body', 0, 'text/plain', 'object_ref', 64, 'ef01', STRUCT('gs://bucket/l.txt', '1', 'conn', JSON '{}'))],
  'parity-svc', 'upstream-1', 'fp1:00', 'v0alpha2'
), (
  TIMESTAMP '2026-08-12 10:01:00+00', 'event', 1786528860000000000,
  TIMESTAMP '2026-08-12 10:01:00+00', 1786528860000000000,
  TIMESTAMP '2026-08-12 10:01:02+00', 1786528862000000000,
  '102030405060708090a0b0c0d0e0f002', '0102030405060709', 0,
  NULL, 9, 'INFO', JSON '"fallback"', JSON '{}', JSON '{}', 0, 'parity-svc',
  NULL, NULL,
  NULL, NULL,
  [],
  'parity-svc', '', 'fp1:abcdef', 'v0alpha2'
)`, "`"+project, dataset, v2Logs+"`"))

	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  TIMESTAMP '2026-08-12 10:00:00+00', 1786528800000000000,
  TIMESTAMP '2026-08-12 09:59:00+00', 1786528740000000000,
  TIMESTAMP '2026-08-12 10:00:02+00', 1786528802000000000,
  'parity-svc', 'gen_ai.client.token.usage', NULL, '{token}', 'SUM',
  'CUMULATIVE', TRUE, 0, JSON '{"gen_ai.token.type":"input"}', JSON '{"gen_ai.token.type":"string"}', JSON '{}', JSON '{}',
  'INT64', NULL, 128, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL,
  NULL, NULL, [],
  [STRUCT(TIMESTAMP '2026-08-12 10:00:00+00', 1786528800000000000, NULL, 128, '0102030405060708', '102030405060708090a0b0c0d0e0f001', JSON '{}', JSON '{}')],
  STRUCT(JSON '{"service.name":"parity-svc"}', JSON '{"service.name":"string"}', 0), NULL,
  STRUCT('meter', '1.0', JSON '{}', JSON '{}', 0), NULL,
  'fp1:metric01', 'v0alpha2'
)`, "`"+project, dataset, v2Metrics+"`"))

	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  TIMESTAMP '2026-08-12 10:00:00+00', 'logs', 'OVERSIZE_ROW', 'too large',
  'parity-svc', '102030405060708090a0b0c0d0e0f001', '0102030405060708',
  NULL, JSON '{}', STRUCT('gs://bucket/q.json', '1', 'conn', JSON '{}'), 'exp-1', 'v0alpha2'
), (
  TIMESTAMP '2026-08-12 10:01:00+00', 'logs', 'INVALID_ID', 'bad id',
  'parity-svc', NULL, NULL,
  '{}', JSON '{}', STRUCT('', NULL, NULL, NULL), 'exp-1', 'v0alpha2'
)`, "`"+project, dataset, v2Quarantine+"`"))

	// Verify same-table self-overwrite guard rejects identical project/dataset/table inputs.
	if _, err := schema.MigrationSQLV0Alpha2ToV1(
		project, dataset, project, dataset,
		v1Spans, v1Logs, v1Metrics, v1Quarantine,
	); err == nil {
		t.Fatal("MigrationSQLV0Alpha2ToV1(same project/dataset/tables) succeeded, want self-overwrite error")
	}

	srcStmts, err := schema.MigrationSQLV0Alpha2ToV1Pair(
		project, dataset, v2Spans, v2Logs, v2Metrics, v2Quarantine,
		project, dataset, v1Spans, v1Logs, v1Metrics, v1Quarantine,
	)
	if err != nil {
		t.Fatalf("MigrationSQLV0Alpha2ToV1Pair: %v", err)
	}
	for _, tbl := range []string{"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"} {
		runSQL(srcStmts[tbl])
	}

	querySingleRow := func(sql string) []bq.Value {
		t.Helper()
		it, err := client.Query(sql).Read(ctx)
		if err != nil {
			t.Fatalf("query migrated rows:\n%s\nerr: %v", sql, err)
		}
		var vals []bq.Value
		err = it.Next(&vals)
		if errors.Is(err, iterator.Done) {
			t.Fatalf("no rows returned for query:\n%s", sql)
		}
		if err != nil {
			t.Fatalf("read migrated row:\n%s\nerr: %v", sql, err)
		}
		return vals
	}

	// Verify migrated rows across all four v1 destination tables.
	spanVals := querySingleRow(fmt.Sprintf(
		"SELECT trace_id, ARRAY_LENGTH(object_refs) FROM `%s.%s.%s` WHERE start_time >= TIMESTAMP('2026-08-12 00:00:00+00')",
		project, dataset, v1Spans,
	))
	if len(spanVals) != 2 || spanVals[1] != int64(1) {
		t.Fatalf("migrated span row = %v, want 1 object_ref", spanVals)
	}

	logFallbackVals := querySingleRow(fmt.Sprintf(
		"SELECT insert_id, resource IS NULL, instrumentation_scope IS NULL FROM `%s.%s.%s` WHERE timestamp = TIMESTAMP('2026-08-12 10:01:00+00')",
		project, dataset, v1Logs,
	))
	if len(logFallbackVals) != 3 || logFallbackVals[0] != "fp1:abcdef" || logFallbackVals[1] != true || logFallbackVals[2] != true {
		t.Fatalf("migrated fallback log row = %v, want [fp1:abcdef true true]", logFallbackVals)
	}

	metricVals := querySingleRow(fmt.Sprintf(
		"SELECT point_fingerprint, ARRAY_LENGTH(exemplars) FROM `%s.%s.%s` WHERE timestamp = TIMESTAMP('2026-08-12 10:00:00+00')",
		project, dataset, v1Metrics,
	))
	if len(metricVals) != 2 || metricVals[0] != "fp1:metric01" || metricVals[1] != int64(1) {
		t.Fatalf("migrated metric row = %v, want [fp1:metric01 1]", metricVals)
	}

	quarantineNullVals := querySingleRow(fmt.Sprintf(
		"SELECT error_code, payload_ref IS NULL FROM `%s.%s.%s` WHERE ingest_time = TIMESTAMP('2026-08-12 10:01:00+00')",
		project, dataset, v1Quarantine,
	))
	if len(quarantineNullVals) != 2 || quarantineNullVals[0] != "INVALID_ID" || quarantineNullVals[1] != true {
		t.Fatalf("migrated quarantine empty-uri row = %v, want [INVALID_ID true]", quarantineNullVals)
	}
}
