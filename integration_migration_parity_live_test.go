// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

// liveMigrationEnv is the ephemeral dataset a live migration test owns, and
// the day its fixture rows sit on.
type liveMigrationEnv struct {
	ctx              context.Context
	client           *bq.Client
	project, dataset string
	// day is midnight UTC of the day before the test runs, well inside the
	// 30-day partition expiration of the v1 otel_quarantine table: BigQuery
	// expires a partition older than that as soon as a row is written to it,
	// so fixture rows on a fixed date silently vanish once it is 30 days old.
	day time.Time
}

// newLiveMigrationEnv gates a live migration test on BQ_PROJECT, failing
// rather than skipping under REQUIRE_LIVE_BQ=1, and creates an ephemeral
// dataset the test owns in BQ_LOCATION (default US). Cleanup deletes the
// dataset with its contents and confirms that it is gone.
func newLiveMigrationEnv(t *testing.T, prefix string) *liveMigrationEnv {
	t.Helper()
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live v0alpha2 -> v1 migration test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	// Registered first so LIFO cleanup deletes the dataset, closes the client,
	// and confirms the deletion before ctx is canceled.
	t.Cleanup(cancel)
	dataset := testsupport.UniqueEphemeralDatasetID(prefix)
	// Registered before NewLiveBigQueryAdmin so it runs after the dataset is
	// deleted and the admin client is closed.
	t.Cleanup(func() {
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer verifyCancel()
		verifyAdmin, _, cleanupVerify := testsupport.NewLiveBigQueryClient(verifyCtx, t, project)
		defer cleanupVerify()
		_, metaErr := verifyAdmin.Dataset(dataset).Metadata(verifyCtx)
		var apiErr *googleapi.Error
		if !errors.As(metaErr, &apiErr) || apiErr.Code != http.StatusNotFound {
			t.Errorf("ephemeral dataset %s.%s metadata after cleanup = %v, want HTTP 404", project, dataset, metaErr)
		}
	})
	client := testsupport.NewLiveBigQueryAdmin(ctx, t, project, dataset, location)
	client.Location = location

	now := time.Now().UTC()
	return &liveMigrationEnv{
		ctx:     ctx,
		client:  client,
		project: project,
		dataset: dataset,
		day:     time.Date(now.Year(), now.Month(), now.Day()-1, 0, 0, 0, 0, time.UTC),
	}
}

var migrationFixturePlaceholderRE = regexp.MustCompile(`\{\{(?:(ts|ns) (\d\d:\d\d:\d\d)|(day|next_day))\}\}`)

// fixtureSQL expands the fixture placeholders in sql: {{ts HH:MM:SS}} becomes
// the TIMESTAMP literal of that time on e.day and {{ns HH:MM:SS}} its Unix
// time in nanoseconds, while {{day}} and {{next_day}} become the TIMESTAMP
// literals of the start of e.day and of the day after it.
func (e *liveMigrationEnv) fixtureSQL(t *testing.T, sql string) string {
	t.Helper()
	literal := func(at time.Time) string {
		return "TIMESTAMP '" + at.Format("2006-01-02 15:04:05") + "+00'"
	}
	out := migrationFixturePlaceholderRE.ReplaceAllStringFunc(sql, func(placeholder string) string {
		m := migrationFixturePlaceholderRE.FindStringSubmatch(placeholder)
		switch m[3] {
		case "day":
			return literal(e.day)
		case "next_day":
			return literal(e.day.AddDate(0, 0, 1))
		}
		clock, err := time.Parse(time.TimeOnly, m[2])
		if err != nil {
			t.Fatalf("fixture placeholder %s: %v", placeholder, err)
		}
		at := time.Date(e.day.Year(), e.day.Month(), e.day.Day(), clock.Hour(), clock.Minute(), clock.Second(), 0, time.UTC)
		if m[1] == "ns" {
			return strconv.FormatInt(at.UnixNano(), 10)
		}
		return literal(at)
	})
	if strings.Contains(out, "{{") {
		t.Fatalf("unexpanded fixture placeholder in:\n%s", out)
	}
	return out
}

// TestLiveMigrationSQLParityV0Alpha2ToV1 creates side-by-side v0alpha2 and v1
// tables in an ephemeral BigQuery dataset, executes the v0alpha2 -> v1
// INSERT INTO ... SELECT migration SQL from internal/schema, and verifies
// parity with live v1 exporter writes across all dedup keys and payloads.
func TestLiveMigrationSQLParityV0Alpha2ToV1(t *testing.T) {
	env := newLiveMigrationEnv(t, "otel_migration_parity_it")
	ctx, client, project, dataset := env.ctx, env.client, env.project, env.dataset

	suffix := fmt.Sprintf("mig_%d", time.Now().UnixNano())
	v2Spans := "otel_spans_v2_" + suffix
	v1Spans := "otel_spans_v1_" + suffix
	v2Logs := "otel_logs_v2_" + suffix
	v1Logs := "otel_logs_v1_" + suffix
	v2Metrics := "otel_metrics_v2_" + suffix
	v1Metrics := "otel_metrics_v1_" + suffix
	v2Quarantine := "otel_quarantine_v2_" + suffix
	v1Quarantine := "otel_quarantine_v1_" + suffix

	runSQL := func(sql string) {
		t.Helper()
		sql = env.fixtureSQL(t, sql)
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
	createEphemeralV0Alpha2Tables(runSQL, project, dataset, v2Spans, v2Logs, v2Metrics, v2Quarantine)

	// Seed representative rows into all four v0alpha2 tables and run MigrationSQLV0Alpha2ToV1Pair.
	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  {{ts 10:00:00}}, {{ns 10:00:00}},
  {{ts 10:00:01}}, {{ns 10:00:01}},
  {{ts 10:00:02}}, {{ns 10:00:02}},
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
  {{ts 10:00:00}}, 'event', {{ns 10:00:00}},
  {{ts 10:00:00}}, {{ns 10:00:00}},
  {{ts 10:00:02}}, {{ns 10:00:02}},
  '102030405060708090a0b0c0d0e0f001', '0102030405060708', 1,
  'gen_ai.user.message', 9, 'INFO', JSON '"hi"', JSON '{"k":"v"}', JSON '{"k":"string"}', 0, 'parity-svc',
  STRUCT(JSON '{"service.name":"parity-svc"}', JSON '{"service.name":"string"}', 0), NULL,
  STRUCT('logger', '1.0', JSON '{}', JSON '{}', 0), NULL,
  [STRUCT('body', 0, 'text/plain', 'object_ref', 64, 'ef01', STRUCT('gs://bucket/l.txt', '1', 'conn', JSON '{}'))],
  'parity-svc', 'upstream-1', 'fp1:00', 'v0alpha2'
), (
  {{ts 10:01:00}}, 'event', {{ns 10:01:00}},
  {{ts 10:01:00}}, {{ns 10:01:00}},
  {{ts 10:01:02}}, {{ns 10:01:02}},
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
  {{ts 10:00:00}}, {{ns 10:00:00}},
  {{ts 09:59:00}}, {{ns 09:59:00}},
  {{ts 10:00:02}}, {{ns 10:00:02}},
  'parity-svc', 'gen_ai.client.token.usage', NULL, '{token}', 'SUM',
  'CUMULATIVE', TRUE, 0, JSON '{"gen_ai.token.type":"input"}', JSON '{"gen_ai.token.type":"string"}', JSON '{}', JSON '{}',
  'INT64', NULL, 128, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL,
  NULL, NULL, [],
  [STRUCT({{ts 10:00:00}}, {{ns 10:00:00}}, CAST(NULL AS FLOAT64), 128, '0102030405060708', '102030405060708090a0b0c0d0e0f001', JSON '{}', JSON '{}')],
  STRUCT(JSON '{"service.name":"parity-svc"}', JSON '{"service.name":"string"}', 0), NULL,
  STRUCT('meter', '1.0', JSON '{}', JSON '{}', 0), NULL,
  'fp1:metric01', 'v0alpha2'
)`, "`"+project, dataset, v2Metrics+"`"))

	runSQL(fmt.Sprintf(`
INSERT INTO %s.%s.%s
VALUES (
  {{ts 10:00:00}}, 'logs', 'OVERSIZE_ROW', 'too large',
  'parity-svc', '102030405060708090a0b0c0d0e0f001', '0102030405060708',
  NULL, JSON '{}', STRUCT('gs://bucket/q.json', '1', 'conn', JSON '{}'), 'exp-1', 'v0alpha2'
), (
  {{ts 10:01:00}}, 'logs', 'INVALID_ID', 'bad id',
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
		sql = env.fixtureSQL(t, sql)
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
		"SELECT trace_id, ARRAY_LENGTH(object_refs) FROM `%s.%s.%s` WHERE start_time >= {{day}}",
		project, dataset, v1Spans,
	))
	if len(spanVals) != 2 || spanVals[1] != int64(1) {
		t.Fatalf("migrated span row = %v, want 1 object_ref", spanVals)
	}

	logFallbackVals := querySingleRow(fmt.Sprintf(
		"SELECT insert_id, resource IS NULL, instrumentation_scope IS NULL FROM `%s.%s.%s` WHERE timestamp = {{ts 10:01:00}}",
		project, dataset, v1Logs,
	))
	if len(logFallbackVals) != 3 || logFallbackVals[0] != "fp1:abcdef" || logFallbackVals[1] != true || logFallbackVals[2] != true {
		t.Fatalf("migrated fallback log row = %v, want [fp1:abcdef true true]", logFallbackVals)
	}

	metricVals := querySingleRow(fmt.Sprintf(
		"SELECT point_fingerprint, ARRAY_LENGTH(exemplars) FROM `%s.%s.%s` WHERE timestamp = {{ts 10:00:00}}",
		project, dataset, v1Metrics,
	))
	if len(metricVals) != 2 || metricVals[0] != "fp1:metric01" || metricVals[1] != int64(1) {
		t.Fatalf("migrated metric row = %v, want [fp1:metric01 1]", metricVals)
	}

	quarantineNullVals := querySingleRow(fmt.Sprintf(
		"SELECT error_code, payload_ref IS NULL FROM `%s.%s.%s` WHERE ingest_time = {{ts 10:01:00}}",
		project, dataset, v1Quarantine,
	))
	if len(quarantineNullVals) != 2 || quarantineNullVals[0] != "INVALID_ID" || quarantineNullVals[1] != true {
		t.Fatalf("migrated quarantine empty-uri row = %v, want [INVALID_ID true]", quarantineNullVals)
	}
}

func createEphemeralV0Alpha2Tables(runSQL func(string), project, dataset, v2Spans, v2Logs, v2Metrics, v2Quarantine string) {
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
}

// TestLiveMigrationCutoffsAndChecksV0Alpha2ToV1 exercises the cutoff tables,
// equality+IS-NULL copy filters, rolling-update drain cutoff, record-identity
// NOT EXISTS completeness checks (logs, metrics, spans), and quarantine count
// check documented in docs/migration.md against BigQuery, in an ephemeral
// dataset.
func TestLiveMigrationCutoffsAndChecksV0Alpha2ToV1(t *testing.T) {
	env := newLiveMigrationEnv(t, "otel_migration_cutoffs_it")
	ctx, client, project, dataset := env.ctx, env.client, env.project, env.dataset

	suffix := fmt.Sprintf("migchk_%d", time.Now().UnixNano())
	v2Spans := "otel_spans_v2_" + suffix
	v1Spans := "otel_spans_v1_" + suffix
	v2Logs := "otel_logs_v2_" + suffix
	v1Logs := "otel_logs_v1_" + suffix
	v2Metrics := "otel_metrics_v2_" + suffix
	v1Metrics := "otel_metrics_v1_" + suffix
	v2Quarantine := "otel_quarantine_v2_" + suffix
	v1Quarantine := "otel_quarantine_v1_" + suffix
	cutLogs := "v1_cutoffs_logs_" + suffix
	cutMetrics := "v1_cutoffs_metrics_" + suffix
	cutQuarantine := "v1_cutoffs_quarantine_" + suffix

	runSQL := func(sql string) {
		t.Helper()
		sql = env.fixtureSQL(t, sql)
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

	queryRows := func(sql string) [][]bq.Value {
		t.Helper()
		sql = env.fixtureSQL(t, sql)
		it, err := client.Query(sql).Read(ctx)
		if err != nil {
			t.Fatalf("query rows:\n%s\nerr: %v", sql, err)
		}
		var rows [][]bq.Value
		for {
			var vals []bq.Value
			err := it.Next(&vals)
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				t.Fatalf("read row:\n%s\nerr: %v", sql, err)
			}
			rows = append(rows, vals)
		}
		return rows
	}

	runSQL(fmt.Sprintf(schema.SpansDDL, project, dataset, v1Spans))
	runSQL(fmt.Sprintf(schema.LogsDDL, project, dataset, v1Logs))
	runSQL(fmt.Sprintf(schema.MetricsDDL, project, dataset, v1Metrics))
	runSQL(fmt.Sprintf(schema.QuarantineDDL, project, dataset, v1Quarantine))
	createEphemeralV0Alpha2Tables(runSQL, project, dataset, v2Spans, v2Logs, v2Metrics, v2Quarantine)

	// Seed v1 native rows (collector A at 12:00, new collector B at 18:00/18:04,
	// NULL service_name at 13:00, empty '' service_name at 15:00).
	runSQL(fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` (
  timestamp, timestamp_source, time_unix_nano, observed_timestamp, observed_time_unix_nano,
  receive_time, receive_time_unix_nano, trace_id, span_id, flags,
  event_name, severity_number, severity_text, body, attributes, dropped_attributes_count,
  service_name, resource, resource_schema_url, instrumentation_scope, scope_schema_url,
  object_refs, log_name, insert_id
) VALUES
({{ts 12:00:00}}, 'event', {{ns 12:00:00}}, {{ts 12:00:00}}, {{ns 12:00:00}}, {{ts 12:00:00}}, {{ns 12:00:00}}, 'ta', 'sa', 1, NULL, 9, 'INFO', JSON '"a"', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', 'v1-1200'),
({{ts 18:00:00}}, 'event', {{ns 18:00:00}}, {{ts 18:00:00}}, {{ns 18:00:00}}, {{ts 18:00:00}}, {{ns 18:00:00}}, 'tb1', 'sb1', 1, NULL, 9, 'INFO', JSON '"b1"', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', 'v1-1800'),
({{ts 18:04:00}}, 'event', {{ns 18:04:00}}, {{ts 18:04:00}}, {{ns 18:04:00}}, {{ts 18:04:00}}, {{ns 18:04:00}}, 'tb2', 'sb2', 1, NULL, 9, 'INFO', JSON '"b2"', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', 'v1-1804'),
({{ts 18:06:00}}, 'event', {{ns 18:06:00}}, {{ts 18:06:00}}, {{ns 18:06:00}}, {{ts 18:06:00}}, {{ns 18:06:00}}, 't3', 's3', 1, NULL, 9, 'INFO', JSON '"post"', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', 'v1-1806'),
({{ts 13:00:00}}, 'event', {{ns 13:00:00}}, {{ts 13:00:00}}, {{ns 13:00:00}}, {{ts 13:00:00}}, {{ns 13:00:00}}, 'tn', 'sn', 1, NULL, 9, 'INFO', JSON '"n"', JSON '{}', 0, NULL, NULL, NULL, NULL, NULL, [], 'app', 'v1-null'),
({{ts 15:00:00}}, 'event', {{ns 15:00:00}}, {{ts 15:00:00}}, {{ns 15:00:00}}, {{ts 15:00:00}}, {{ns 15:00:00}}, 'te', 'se', 1, NULL, 9, 'INFO', JSON '"e"', JSON '{}', 0, '', NULL, NULL, NULL, NULL, [], 'app', 'v1-empty')`,
		project, dataset, v1Logs))

	// Seed v0alpha2 rows: drained 18:02 checkout row, post-drain 18:06 row,
	// NULL service_name with empty insert_id + NULL record_fingerprint at 12:30,
	// and '' service_name at 14:00 (between NULL cutoff 13:00 and '' cutoff 15:00).
	runSQL(fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` VALUES
({{ts 18:02:00}}, 'event', {{ns 18:02:00}}, {{ts 18:02:00}}, {{ns 18:02:00}}, {{ts 18:02:00}}, {{ns 18:02:00}}, 't2', 's2', 1, NULL, 9, 'INFO', JSON '"drained"', JSON '{}', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', '', 'v2-fp-1802', 'v0alpha2'),
({{ts 18:06:00}}, 'event', {{ns 18:06:00}}, {{ts 18:06:00}}, {{ns 18:06:00}}, {{ts 18:06:00}}, {{ns 18:06:00}}, 't3', 's3', 1, NULL, 9, 'INFO', JSON '"post"', JSON '{}', JSON '{}', 0, 'checkout', NULL, NULL, NULL, NULL, [], 'app', '', 'v2-fp-1806', 'v0alpha2'),
({{ts 12:30:00}}, 'event', {{ns 12:30:00}}, {{ts 12:30:00}}, {{ns 12:30:00}}, {{ts 12:30:00}}, {{ns 12:30:00}}, 't4', 's4', 1, NULL, 9, 'INFO', JSON '"nullsvc"', JSON '{}', JSON '{}', 0, NULL, NULL, NULL, NULL, NULL, [], 'app', '', NULL, 'v0alpha2'),
({{ts 14:00:00}}, 'event', {{ns 14:00:00}}, {{ts 14:00:00}}, {{ns 14:00:00}}, {{ts 14:00:00}}, {{ns 14:00:00}}, 't5', 's5', 1, NULL, 9, 'INFO', JSON '"emptysvc"', JSON '{}', JSON '{}', 0, '', NULL, NULL, NULL, NULL, [], 'app', '', 'v2-fp-empty', 'v0alpha2')`,
		project, dataset, v2Logs))

	// Seed metrics and quarantine (empty v1 destinations) + spans across NULL/''/checkout.
	runSQL(fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` VALUES
({{ts 18:02:00}}, {{ns 18:02:00}}, NULL, NULL, {{ts 18:02:00}}, {{ns 18:02:00}}, 'checkout', 'm1', NULL, NULL, 'GAUGE', NULL, NULL, 0, JSON '{}', JSON '{}', JSON '{}', JSON '{}', 'INT64', NULL, 1, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL, NULL, 'v2-mfp-1802', 'v0alpha2'),
({{ts 14:00:00}}, {{ns 14:00:00}}, NULL, NULL, {{ts 14:00:00}}, {{ns 14:00:00}}, NULL, 'm1', NULL, NULL, 'GAUGE', NULL, NULL, 0, JSON '{}', JSON '{}', JSON '{}', JSON '{}', 'INT64', NULL, 2, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL, NULL, NULL, [], [], NULL, NULL, NULL, NULL, 'v2-mfp-null', 'v0alpha2')`,
		project, dataset, v2Metrics))

	runSQL(fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` VALUES
({{ts 12:30:00}}, 'logs', 'ERR1', 'm', NULL, NULL, NULL, NULL, JSON '{}', NULL, 'exp1', 'v0alpha2'),
({{ts 14:00:00}}, 'logs', 'ERR2', 'm', '', NULL, NULL, NULL, JSON '{}', NULL, 'exp1', 'v0alpha2')`,
		project, dataset, v2Quarantine))

	runSQL(fmt.Sprintf(`
INSERT INTO `+"`%s.%s.%s`"+` VALUES
({{ts 12:30:00}}, {{ns 12:30:00}}, {{ts 12:30:01}}, {{ns 12:30:01}}, {{ts 12:30:02}}, {{ns 12:30:02}}, 1000000000, 't1', 's1', NULL, NULL, 1, 'op', 2, 'CLIENT', NULL, JSON '{}', JSON '{}', 0, NULL, NULL, NULL, NULL, NULL, [], 0, [], 0, [], 'v0alpha2'),
({{ts 14:00:00}}, {{ns 14:00:00}}, {{ts 14:00:01}}, {{ns 14:00:01}}, {{ts 14:00:02}}, {{ns 14:00:02}}, 1000000000, 't2', 's2', NULL, NULL, 1, 'op', 2, 'CLIENT', NULL, JSON '{}', JSON '{}', 0, '', NULL, NULL, NULL, NULL, [], 0, [], 0, [], 'v0alpha2')`,
		project, dataset, v2Spans))

	// Create cutoff tables before the first copy, and move checkout's cutoff past drain (18:05:00).
	runSQL(fmt.Sprintf(
		"CREATE TABLE `%s.%s.%s` AS SELECT service_name, MIN(receive_time) AS cutoff FROM `%s.%s.%s` WHERE timestamp >= TIMESTAMP '1970-01-01' GROUP BY service_name",
		project, dataset, cutLogs, project, dataset, v1Logs))
	runSQL(fmt.Sprintf(
		"UPDATE `%s.%s.%s` SET cutoff = {{ts 18:05:00}} WHERE service_name = 'checkout'",
		project, dataset, cutLogs))
	runSQL(fmt.Sprintf(
		"CREATE TABLE `%s.%s.%s` AS SELECT service_name, MIN(receive_time) AS cutoff FROM `%s.%s.%s` WHERE timestamp >= TIMESTAMP '1970-01-01' GROUP BY service_name",
		project, dataset, cutMetrics, project, dataset, v1Metrics))
	runSQL(fmt.Sprintf(
		"CREATE TABLE `%s.%s.%s` AS SELECT service_name, MIN(ingest_time) AS cutoff FROM `%s.%s.%s` WHERE ingest_time >= TIMESTAMP '1970-01-01' GROUP BY service_name",
		project, dataset, cutQuarantine, project, dataset, v1Quarantine))

	logsIdentityCheckSQL := fmt.Sprintf(`
SELECT DATE(l.timestamp) AS day, l.service_name, COUNT(*) AS missing_logs
FROM `+"`%s.%s.%s`"+` AS l
WHERE l.timestamp >= {{day}} AND l.timestamp < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS c
    WHERE (c.service_name = l.service_name OR (c.service_name IS NULL AND l.service_name IS NULL))
      AND l.receive_time >= c.cutoff
  )
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS n
    WHERE n.timestamp >= {{day}} AND n.timestamp < {{next_day}}
      AND n.timestamp = l.timestamp
      AND n.time_unix_nano = l.time_unix_nano
      AND n.receive_time = l.receive_time
      AND n.receive_time_unix_nano = l.receive_time_unix_nano
      AND (n.service_name = l.service_name OR (n.service_name IS NULL AND l.service_name IS NULL))
      AND n.log_name = l.log_name
      AND (
        n.insert_id = COALESCE(NULLIF(l.insert_id, ''), l.record_fingerprint)
        OR (n.insert_id IS NULL AND COALESCE(NULLIF(l.insert_id, ''), l.record_fingerprint) IS NULL)
      )
  )
GROUP BY day, l.service_name
ORDER BY day, l.service_name`, project, dataset, v2Logs, project, dataset, cutLogs, project, dataset, v1Logs)

	// Before copying, the logs identity check must detect all 3 below-cutoff rows
	// despite native v1 rows already existing for checkout/NULL/''.
	if missingBefore := queryRows(logsIdentityCheckSQL); len(missingBefore) != 3 {
		t.Fatalf("logs identity check before copy returned %d groups (%v), want 3", len(missingBefore), missingBefore)
	}

	// Execute cutoff-filtered copies for logs, metrics, quarantine, plus full spans copy.
	srcStmts, err := schema.MigrationSQLV0Alpha2ToV1Pair(
		project, dataset, v2Spans, v2Logs, v2Metrics, v2Quarantine,
		project, dataset, v1Spans, v1Logs, v1Metrics, v1Quarantine,
	)
	if err != nil {
		t.Fatalf("MigrationSQLV0Alpha2ToV1Pair: %v", err)
	}
	runSQL(srcStmts["otel_spans"] + " WHERE start_time >= {{day}} AND start_time < {{next_day}}")
	runSQL(srcStmts["otel_logs"] + fmt.Sprintf(` AS otel_logs
WHERE timestamp >= {{day}} AND timestamp < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS c
    WHERE (c.service_name = otel_logs.service_name OR (c.service_name IS NULL AND otel_logs.service_name IS NULL))
      AND otel_logs.receive_time >= c.cutoff
  )`, project, dataset, cutLogs))
	runSQL(srcStmts["otel_metrics"] + fmt.Sprintf(` AS otel_metrics
WHERE timestamp >= {{day}} AND timestamp < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS c
    WHERE (c.service_name = otel_metrics.service_name OR (c.service_name IS NULL AND otel_metrics.service_name IS NULL))
      AND otel_metrics.receive_time >= c.cutoff
  )`, project, dataset, cutMetrics))
	runSQL(srcStmts["otel_quarantine"] + fmt.Sprintf(` AS otel_quarantine
WHERE ingest_time >= {{day}} AND ingest_time < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS c
    WHERE (c.service_name = otel_quarantine.service_name OR (c.service_name IS NULL AND otel_quarantine.service_name IS NULL))
      AND otel_quarantine.ingest_time >= c.cutoff
  )`, project, dataset, cutQuarantine))

	// Verify all 4 completeness checks return 0 rows after copy.
	if rows := queryRows(logsIdentityCheckSQL); len(rows) != 0 {
		t.Errorf("logs identity check after copy returned %v, want 0 rows", rows)
	}
	metricsIdentityCheckSQL := fmt.Sprintf(`
SELECT DATE(m.timestamp) AS day, m.service_name, COUNT(*) AS missing_metrics
FROM `+"`%s.%s.%s`"+` AS m
WHERE m.timestamp >= {{day}} AND m.timestamp < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS c
    WHERE (c.service_name = m.service_name OR (c.service_name IS NULL AND m.service_name IS NULL))
      AND m.receive_time >= c.cutoff
  )
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS n
    WHERE n.timestamp >= {{day}} AND n.timestamp < {{next_day}}
      AND n.timestamp = m.timestamp
      AND n.time_unix_nano = m.time_unix_nano
      AND n.receive_time = m.receive_time
      AND n.receive_time_unix_nano = m.receive_time_unix_nano
      AND (n.service_name = m.service_name OR (n.service_name IS NULL AND m.service_name IS NULL))
      AND n.metric_name = m.metric_name
      AND n.point_fingerprint = m.point_fingerprint
  )
GROUP BY day, m.service_name`, project, dataset, v2Metrics, project, dataset, cutMetrics, project, dataset, v1Metrics)
	if rows := queryRows(metricsIdentityCheckSQL); len(rows) != 0 {
		t.Errorf("metrics identity check after copy returned %v, want 0 rows", rows)
	}

	quarantineCheckSQL := fmt.Sprintf(`
WITH rows_by_source AS (
  SELECT 'v0alpha2' AS source, service_name, ingest_time
  FROM `+"`%s.%s.%s`"+`
  WHERE ingest_time >= {{day}} AND ingest_time < {{next_day}}
  UNION ALL
  SELECT 'v1' AS source, service_name, ingest_time
  FROM `+"`%s.%s.%s`"+`
  WHERE ingest_time >= {{day}} AND ingest_time < {{next_day}}
)
SELECT
  DATE(r.ingest_time) AS day,
  r.service_name,
  COUNTIF(r.source = 'v0alpha2' AND (c.cutoff IS NULL OR r.ingest_time < c.cutoff)) AS v0alpha2_to_copy,
  COUNTIF(r.source = 'v1' AND (c.cutoff IS NULL OR r.ingest_time < c.cutoff)) AS v1_before_cutoff,
  COUNTIF(r.source = 'v0alpha2' AND r.ingest_time >= c.cutoff) AS v0alpha2_skipped,
  COUNTIF(r.source = 'v1' AND r.ingest_time >= c.cutoff) AS v1_after_cutoff
FROM rows_by_source AS r
LEFT JOIN `+"`%s.%s.%s`"+` AS c
  ON (c.service_name = r.service_name OR (c.service_name IS NULL AND r.service_name IS NULL))
GROUP BY day, r.service_name
HAVING v1_before_cutoff < v0alpha2_to_copy OR v0alpha2_skipped > v1_after_cutoff`, project, dataset, v2Quarantine, project, dataset, v1Quarantine, project, dataset, cutQuarantine)
	if rows := queryRows(quarantineCheckSQL); len(rows) != 0 {
		t.Errorf("quarantine count check after copy returned %v, want 0 rows", rows)
	}

	spansCheckSQL := fmt.Sprintf(`
SELECT DATE(s.start_time) AS day, COUNT(*) AS missing_spans
FROM `+"`%s.%s.%s`"+` AS s
WHERE s.start_time >= {{day}} AND s.start_time < {{next_day}}
  AND NOT EXISTS (
    SELECT 1 FROM `+"`%s.%s.%s`"+` AS n
    WHERE n.start_time >= {{day}} AND n.start_time < {{next_day}}
      AND n.start_time = s.start_time
      AND n.start_time_unix_nano = s.start_time_unix_nano
      AND (n.service_name = s.service_name OR (n.service_name IS NULL AND s.service_name IS NULL))
      AND n.trace_id = s.trace_id
      AND n.span_id = s.span_id
      AND n.name = s.name
  )
GROUP BY day`, project, dataset, v2Spans, project, dataset, v1Spans)
	if rows := queryRows(spansCheckSQL); len(rows) != 0 {
		t.Errorf("spans identity check after copy returned %v, want 0 rows", rows)
	}

	// Verify drained 18:02 checkout row and empty-insert_id NULL-fingerprint row landed.
	drainedRows := queryRows(fmt.Sprintf(
		"SELECT COUNT(*) FROM `%s.%s.%s` WHERE timestamp >= {{day}} AND insert_id = 'v2-fp-1802'",
		project, dataset, v1Logs))
	if len(drainedRows) != 1 || drainedRows[0][0] != int64(1) {
		t.Fatalf("drained checkout row count = %v, want 1", drainedRows)
	}
}
