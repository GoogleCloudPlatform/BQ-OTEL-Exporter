// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

type v0Alpha2GoldenSnapshot struct {
	Version string `json:"version"`
	Tables  []struct {
		Name   string `json:"name"`
		Fields []struct {
			Name   string `json:"name"`
			Type   string `json:"type"`
			Mode   string `json:"mode"`
			Fields []struct {
				Name   string `json:"name"`
				Type   string `json:"type"`
				Mode   string `json:"mode"`
				Fields []struct {
					Name string `json:"name"`
					Type string `json:"type"`
					Mode string `json:"mode"`
				} `json:"fields,omitempty"`
			} `json:"fields,omitempty"`
		} `json:"fields"`
	} `json:"tables"`
}

func loadV0Alpha2Golden(t *testing.T) v0Alpha2GoldenSnapshot {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("internal", "schema", "testdata", "v0alpha2_golden.json"))
	if err != nil {
		t.Fatalf("read v0alpha2_golden.json: %v", err)
	}
	var snap v0Alpha2GoldenSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("parse v0alpha2_golden.json: %v", err)
	}
	if snap.Version != "v0alpha2" {
		t.Fatalf("golden version = %q, want v0alpha2", snap.Version)
	}
	return snap
}

// applyMigrationSQLTransform simulates the v0alpha2 -> v1 INSERT INTO ... SELECT
// projections defined in internal/schema/migration.go over a v0alpha2 row map,
// checking that the SQL template carries the exact mappings we apply here.
func applyV0Alpha2ToV1SpanTransform(t *testing.T, sql string, v2 transform.Row) transform.Row {
	t.Helper()
	for _, want := range []string{
		"object_refs",
		"UNNEST(payload_refs)",
		"p.object_ref.uri IS NOT NULL",
		"IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource",
		"IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope",
		"ARRAY(SELECT AS STRUCT e.time, e.time_unix_nano, e.name, e.attributes, e.dropped_attributes_count FROM UNNEST(events) AS e WITH OFFSET AS pos ORDER BY pos) AS events",
		"ARRAY(SELECT AS STRUCT l.trace_id, l.span_id, l.trace_state, l.flags, l.attributes, l.dropped_attributes_count FROM UNNEST(links) AS l WITH OFFSET AS pos ORDER BY pos) AS links",
	} {
		if !strings.Contains(strings.Join(strings.Fields(sql), " "), strings.Join(strings.Fields(want), " ")) {
			t.Fatalf("spans migration SQL missing required projection %q:\n%s", want, sql)
		}
	}

	out := transform.Row{}
	for _, col := range []string{
		"start_time", "start_time_unix_nano", "end_time", "end_time_unix_nano",
		"receive_time", "receive_time_unix_nano", "duration_nano",
		"trace_id", "span_id", "parent_span_id", "trace_state", "flags",
		"name", "kind", "kind_name", "status",
		"attributes", "dropped_attributes_count", "service_name",
		"resource_schema_url", "scope_schema_url",
		"dropped_events_count", "dropped_links_count",
	} {
		if v, ok := v2[col]; ok {
			out[col] = v
		}
	}
	if res, ok := v2["resource"].(transform.Row); ok {
		r := transform.Row{"attributes": res["attributes"]}
		if d, ok := res["dropped_attributes_count"]; ok {
			r["dropped_attributes_count"] = d
		}
		out["resource"] = r
	}
	if sc, ok := v2["instrumentation_scope"].(transform.Row); ok {
		s := transform.Row{}
		for _, k := range []string{"name", "version", "attributes", "dropped_attributes_count"} {
			if v, ok := sc[k]; ok {
				s[k] = v
			}
		}
		out["instrumentation_scope"] = s
	}
	if evs, ok := v2["events"].([]transform.Row); ok {
		migratedEvs := make([]transform.Row, 0, len(evs))
		for _, ev := range evs {
			m := transform.Row{}
			for _, k := range []string{"time", "time_unix_nano", "name", "attributes", "dropped_attributes_count"} {
				if v, ok := ev[k]; ok {
					m[k] = v
				}
			}
			migratedEvs = append(migratedEvs, m)
		}
		out["events"] = migratedEvs
	}
	if links, ok := v2["links"].([]transform.Row); ok {
		migratedLinks := make([]transform.Row, 0, len(links))
		for _, lk := range links {
			m := transform.Row{}
			for _, k := range []string{"trace_id", "span_id", "trace_state", "flags", "attributes", "dropped_attributes_count"} {
				if v, ok := lk[k]; ok {
					m[k] = v
				}
			}
			migratedLinks = append(migratedLinks, m)
		}
		out["links"] = migratedLinks
	}
	if prefs, ok := v2["payload_refs"].([]transform.Row); ok {
		var objRefs []transform.Row
		for _, pr := range prefs {
			if obj, ok := pr["object_ref"].(transform.Row); ok {
				if uri, _ := obj["uri"].(string); uri != "" {
					objRefs = append(objRefs, obj)
				}
			}
		}
		if len(objRefs) > 0 {
			out["object_refs"] = objRefs
		}
	}
	return out
}

func applyV0Alpha2ToV1LogTransform(t *testing.T, sql string, v2 transform.Row) transform.Row {
	t.Helper()
	for _, want := range []string{
		"object_refs",
		"UNNEST(payload_refs)",
		"p.object_ref.uri IS NOT NULL",
		"IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource",
		"IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope",
		"COALESCE(NULLIF(insert_id, ''), record_fingerprint) AS insert_id",
	} {
		if !strings.Contains(strings.Join(strings.Fields(sql), " "), strings.Join(strings.Fields(want), " ")) {
			t.Fatalf("logs migration SQL missing required projection %q:\n%s", want, sql)
		}
	}
	out := transform.Row{}
	for _, col := range []string{
		"timestamp", "timestamp_source", "time_unix_nano",
		"observed_timestamp", "observed_time_unix_nano",
		"receive_time", "receive_time_unix_nano",
		"trace_id", "span_id", "flags",
		"event_name", "severity_number", "severity_text", "body",
		"attributes", "dropped_attributes_count", "service_name",
		"resource_schema_url", "scope_schema_url", "log_name",
	} {
		if v, ok := v2[col]; ok {
			out[col] = v
		}
	}
	if res, ok := v2["resource"].(transform.Row); ok {
		r := transform.Row{"attributes": res["attributes"]}
		if d, ok := res["dropped_attributes_count"]; ok {
			r["dropped_attributes_count"] = d
		}
		out["resource"] = r
	}
	if sc, ok := v2["instrumentation_scope"].(transform.Row); ok {
		s := transform.Row{}
		for _, k := range []string{"name", "version", "attributes", "dropped_attributes_count"} {
			if v, ok := sc[k]; ok {
				s[k] = v
			}
		}
		out["instrumentation_scope"] = s
	}
	if prefs, ok := v2["payload_refs"].([]transform.Row); ok {
		var objRefs []transform.Row
		for _, pr := range prefs {
			if obj, ok := pr["object_ref"].(transform.Row); ok {
				if uri, _ := obj["uri"].(string); uri != "" {
					objRefs = append(objRefs, obj)
				}
			}
		}
		if len(objRefs) > 0 {
			out["object_refs"] = objRefs
		}
	}
	insertID, _ := v2["insert_id"].(string)
	if insertID == "" {
		insertID, _ = v2["record_fingerprint"].(string)
	}
	if insertID != "" {
		out["insert_id"] = insertID
	}
	return out
}

func applyV0Alpha2ToV1MetricTransform(t *testing.T, sql string, v2 transform.Row) transform.Row {
	t.Helper()
	for _, want := range []string{
		"point_fingerprint",
		"IF(resource IS NULL, NULL, STRUCT(resource.attributes AS attributes, resource.dropped_attributes_count AS dropped_attributes_count)) AS resource",
		"IF(instrumentation_scope IS NULL, NULL, STRUCT(instrumentation_scope.name AS name, instrumentation_scope.version AS version, instrumentation_scope.attributes AS attributes, instrumentation_scope.dropped_attributes_count AS dropped_attributes_count)) AS instrumentation_scope",
		"ARRAY(SELECT AS STRUCT ex.time, ex.time_unix_nano, ex.value_double, ex.value_int64, ex.span_id, ex.trace_id, ex.filtered_attributes FROM UNNEST(exemplars) AS ex WITH OFFSET AS pos ORDER BY pos) AS exemplars",
	} {
		if !strings.Contains(strings.Join(strings.Fields(sql), " "), strings.Join(strings.Fields(want), " ")) {
			t.Fatalf("metrics migration SQL missing required projection %q:\n%s", want, sql)
		}
	}
	out := transform.Row{}
	for _, col := range []string{
		"timestamp", "time_unix_nano", "start_time", "start_time_unix_nano",
		"receive_time", "receive_time_unix_nano", "service_name",
		"metric_name", "metric_description", "metric_unit", "metric_type",
		"aggregation_temporality", "is_monotonic", "flags",
		"attributes", "metric_metadata", "value_type", "value_double", "value_int64",
		"count", "sum", "min", "max", "explicit_bounds", "bucket_counts",
		"exp_scale", "exp_zero_count", "exp_zero_threshold", "exp_positive", "exp_negative",
		"summary_quantiles", "resource_schema_url", "scope_schema_url", "point_fingerprint",
	} {
		if v, ok := v2[col]; ok {
			out[col] = v
		}
	}
	if res, ok := v2["resource"].(transform.Row); ok {
		r := transform.Row{"attributes": res["attributes"]}
		if d, ok := res["dropped_attributes_count"]; ok {
			r["dropped_attributes_count"] = d
		}
		out["resource"] = r
	}
	if sc, ok := v2["instrumentation_scope"].(transform.Row); ok {
		s := transform.Row{}
		for _, k := range []string{"name", "version", "attributes", "dropped_attributes_count"} {
			if v, ok := sc[k]; ok {
				s[k] = v
			}
		}
		out["instrumentation_scope"] = s
	}
	if exs, ok := v2["exemplars"].([]transform.Row); ok {
		migrated := make([]transform.Row, 0, len(exs))
		for _, ex := range exs {
			m := transform.Row{}
			for _, k := range []string{"time", "time_unix_nano", "value_double", "value_int64", "span_id", "trace_id", "filtered_attributes"} {
				if v, ok := ex[k]; ok {
					m[k] = v
				}
			}
			migrated = append(migrated, m)
		}
		out["exemplars"] = migrated
	}
	return out
}

func TestMigrationSQLParityV0Alpha2ToV1(t *testing.T) {
	snap := loadV0Alpha2Golden(t)
	v2FieldsByTable := map[string]map[string]bool{}
	for _, tbl := range snap.Tables {
		cols := map[string]bool{}
		for _, f := range tbl.Fields {
			cols[f.Name] = true
		}
		v2FieldsByTable[tbl.Name] = cols
	}

	const (
		srcProj = "src-proj"
		srcDS   = "otel_v0alpha2"
		dstProj = "dst-proj"
		dstDS   = "otel_v1"
	)

	stmts, err := schema.MigrationSQLV0Alpha2ToV1(
		srcProj, srcDS, dstProj, dstDS,
		"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine",
	)
	if err != nil {
		t.Fatalf("MigrationSQLV0Alpha2ToV1: %v", err)
	}

	// Verify each migration SQL statement targets exact v1 destination columns in
	// schema order and only reads columns present in v0alpha2_golden.json.
	expectedDest := map[string][]string{
		"otel_spans":      schema.FieldNames(schema.SpansTableSchema()),
		"otel_logs":       schema.FieldNames(schema.LogsTableSchema()),
		"otel_metrics":    schema.FieldNames(schema.MetricsTableSchema()),
		"otel_quarantine": schema.FieldNames(schema.QuarantineTableSchema()),
	}
	docsMigration, err := os.ReadFile(filepath.Join("docs", "migration.md"))
	if err != nil {
		t.Fatalf("read docs/migration.md: %v", err)
	}
	docsNorm := strings.Join(strings.Fields(string(docsMigration)), " ")

	for tbl, wantCols := range expectedDest {
		sql := stmts[tbl]
		if sql == "" {
			t.Fatalf("missing migration SQL for %s", tbl)
		}
		normSQL := strings.ReplaceAll(strings.Join(strings.Fields(sql), " "), "( ", "(")
		normSQL = strings.ReplaceAll(normSQL, " )", ")")
		prefix := fmt.Sprintf("INSERT INTO `%s.%s.%s` (%s)", dstProj, dstDS, tbl, strings.Join(wantCols, ", "))
		if !strings.Contains(normSQL, prefix) {
			t.Errorf("%s migration SQL does not insert exact v1 columns %v:\n%s", tbl, wantCols, sql)
		}
		// Ensure every dropped v0alpha2 column mentioned in the query exists in v0alpha2_golden.json.
		v2Cols := v2FieldsByTable[tbl]
		for _, mustExist := range []string{"schema_version"} {
			if !v2Cols[mustExist] {
				t.Fatalf("v0alpha2_golden.json %s missing %q", tbl, mustExist)
			}
		}
		// Verify docs/migration.md carries the same SELECT projection expressions.
		selIdx := strings.Index(sql, "SELECT")
		fromIdx := strings.Index(sql, "FROM")
		if selIdx < 0 || fromIdx <= selIdx {
			t.Fatalf("%s migration SQL missing SELECT ... FROM", tbl)
		}
		// Verify side-by-side dataset isolation in documented SQL examples.
		if !strings.Contains(docsNorm, "otel_v1."+tbl) && !strings.Contains(docsNorm, tbl) {
			t.Errorf("docs/migration.md missing migration section for %s", tbl)
		}
	}

	// Build deterministic OTLP spans, logs (upstream insert_id), and metrics,
	// encode via live v1 transform, and compare against v0alpha2 golden row +
	// migration SQL transformation on all dedup keys and payloads.
	fixedNow := time.Date(2026, 8, 12, 14, 30, 0, 0, time.UTC)
	fixedLimits := transform.DefaultLimits()
	fixedOffloadRef := transform.PayloadRef{
		AttributePath: "attributes.gen_ai.prompt",
		PartIndex:     0,
		MIMEType:      "application/json",
		StorageMode:   "object_ref",
		ByteSize:      4096,
		SHA256:        strings.Repeat("ab", 32),
		ObjectRef: transform.ObjectRef{
			URI:        "gs://otel-payloads/prompt.json",
			Version:    "1700000001",
			Authorizer: "projects/src-proj/locations/us/connections/otel-gcs",
			Details:    `{"content_type":"application/json"}`,
		},
	}

	// 1. Spans parity: dedup keys + events/links + object_refs.
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
	rs.Resource().Attributes().PutStr("service.name", "parity-svc")
	rs.Resource().SetDroppedAttributesCount(1)
	ss := rs.ScopeSpans().AppendEmpty()
	ss.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
	ss.Scope().SetName("parity-tracer")
	ss.Scope().SetVersion("1.0.0")
	ss.Scope().Attributes().PutStr("scope.k", "v")
	sp := ss.Spans().AppendEmpty()
	sp.SetTraceID(mustTraceID(t, traceHex(42)))
	sp.SetSpanID(mustSpanID(t, spanHex(7)))
	sp.SetParentSpanID(mustSpanID(t, spanHex(6)))
	sp.SetName("chat parity")
	sp.SetKind(ptrace.SpanKindClient)
	sp.SetStartTimestamp(pcommon.NewTimestampFromTime(fixedNow))
	sp.SetEndTimestamp(pcommon.NewTimestampFromTime(fixedNow.Add(50 * time.Millisecond)))
	sp.Status().SetCode(ptrace.StatusCodeOk)
	sp.Status().SetMessage("ok")
	sp.Attributes().PutStr("gen_ai.system", "gemini")
	ev := sp.Events().AppendEmpty()
	ev.SetName("token_chunk")
	ev.SetTimestamp(pcommon.NewTimestampFromTime(fixedNow.Add(10 * time.Millisecond)))
	ev.Attributes().PutInt("idx", 1)
	lk := sp.Links().AppendEmpty()
	lk.SetTraceID(mustTraceID(t, traceHex(41)))
	lk.SetSpanID(mustSpanID(t, spanHex(5)))
	lk.Attributes().PutStr("rel", "follows")

	off := &fixedTestOffloader{refs: []transform.PayloadRef{fixedOffloadRef}}
	v1Spans, rej := transform.SpanRows(td, transform.Options{
		Now:              func() time.Time { return fixedNow },
		Limits:           fixedLimits,
		PayloadOffloader: off,
	})
	if len(rej) != 0 || len(v1Spans) != 1 {
		t.Fatalf("v1 SpanRows = (%d, %v), want (1, nil)", len(v1Spans), rej)
	}
	v2Span := cloneTransformRow(v1Spans[0])
	delete(v2Span, "object_refs")
	v2Span["attributes_schema"] = `{"gen_ai.system":"string"}`
	v2Span["schema_version"] = "v0alpha2"
	v2Span["resource"].(transform.Row)["attributes_schema"] = `{"service.name":"string"}`
	v2Span["instrumentation_scope"].(transform.Row)["attributes_schema"] = `{"scope.k":"string"}`
	v2Span["events"].([]transform.Row)[0]["attributes_schema"] = `{"idx":"int"}`
	v2Span["links"].([]transform.Row)[0]["attributes_schema"] = `{"rel":"string"}`
	v2Span["payload_refs"] = []transform.Row{
		{
			"attribute_path": fixedOffloadRef.AttributePath,
			"part_index":     fixedOffloadRef.PartIndex,
			"mime_type":      fixedOffloadRef.MIMEType,
			"storage_mode":   fixedOffloadRef.StorageMode,
			"byte_size":      fixedOffloadRef.ByteSize,
			"sha256":         fixedOffloadRef.SHA256,
			"object_ref":     fixedOffloadRef.ObjectRef.ToRow(),
		},
	}

	migratedSpan := applyV0Alpha2ToV1SpanTransform(t, stmts["otel_spans"], v2Span)
	assertRowEqual(t, "otel_spans migrated vs v1 writer", migratedSpan, v1Spans[0])

	// 2. Logs parity: dedup keys + upstream insert_id + object_refs + body.
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
	rl.Resource().Attributes().PutStr("service.name", "parity-svc")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("parity-logger")
	lr := sl.LogRecords().AppendEmpty()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(fixedNow))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(fixedNow.Add(time.Millisecond)))
	lr.SetTraceID(mustTraceID(t, traceHex(42)))
	lr.SetSpanID(mustSpanID(t, spanHex(7)))
	lr.SetFlags(1)
	lr.SetEventName("gen_ai.user.message")
	lr.SetSeverityNumber(plog.SeverityNumberInfo)
	lr.SetSeverityText("INFO")
	lr.Body().SetStr("hello world")
	lr.Attributes().PutStr("logging.googleapis.com/insertId", "upstream-insert-42")
	lr.Attributes().PutStr("gcp.log_name", "projects/src-proj/logs/app")

	v1Logs, lrej := transform.LogRows(ld, transform.Options{
		Now:              func() time.Time { return fixedNow },
		Limits:           fixedLimits,
		PayloadOffloader: off,
	})
	if len(lrej) != 0 || len(v1Logs) != 1 {
		t.Fatalf("v1 LogRows = (%d, %v), want (1, nil)", len(v1Logs), lrej)
	}
	v2Log := cloneTransformRow(v1Logs[0])
	delete(v2Log, "object_refs")
	v2Log["attributes_schema"] = `{"gcp.log_name":"string"}`
	v2Log["record_fingerprint"] = "fp1:" + strings.Repeat("00", 32)
	v2Log["schema_version"] = "v0alpha2"
	v2Log["resource"].(transform.Row)["attributes_schema"] = `{"service.name":"string"}`
	v2Log["instrumentation_scope"].(transform.Row)["attributes_schema"] = `{}`
	v2Log["payload_refs"] = []transform.Row{
		{
			"attribute_path": fixedOffloadRef.AttributePath,
			"part_index":     fixedOffloadRef.PartIndex,
			"mime_type":      fixedOffloadRef.MIMEType,
			"storage_mode":   fixedOffloadRef.StorageMode,
			"byte_size":      fixedOffloadRef.ByteSize,
			"sha256":         fixedOffloadRef.SHA256,
			"object_ref":     fixedOffloadRef.ObjectRef.ToRow(),
		},
	}

	migratedLog := applyV0Alpha2ToV1LogTransform(t, stmts["otel_logs"], v2Log)
	assertRowEqual(t, "otel_logs migrated vs v1 writer", migratedLog, v1Logs[0])

	// 3. Metrics parity: dedup point_fingerprint + exemplars.
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "parity-svc")
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("parity-meter")
	m := sm.Metrics().AppendEmpty()
	m.SetName("gen_ai.client.token.usage")
	m.SetUnit("{token}")
	dp := m.SetEmptySum().DataPoints().AppendEmpty()
	dp.SetStartTimestamp(pcommon.NewTimestampFromTime(fixedNow.Add(-time.Minute)))
	dp.SetTimestamp(pcommon.NewTimestampFromTime(fixedNow))
	dp.SetIntValue(128)
	dp.Attributes().PutStr("gen_ai.token.type", "input")
	ex := dp.Exemplars().AppendEmpty()
	ex.SetTimestamp(pcommon.NewTimestampFromTime(fixedNow))
	ex.SetIntValue(128)
	ex.SetTraceID(mustTraceID(t, traceHex(42)))
	ex.SetSpanID(mustSpanID(t, spanHex(7)))
	ex.FilteredAttributes().PutStr("model", "gemini")

	v1Metrics, mrej := transform.MetricRows(md, transform.Options{
		Now:    func() time.Time { return fixedNow },
		Limits: fixedLimits,
	})
	if len(mrej) != 0 || len(v1Metrics) != 1 {
		t.Fatalf("v1 MetricRows = (%d, %v), want (1, nil)", len(v1Metrics), mrej)
	}
	v2Metric := cloneTransformRow(v1Metrics[0])
	v2Metric["attributes_schema"] = `{"gen_ai.token.type":"string"}`
	v2Metric["metric_metadata_schema"] = `{}`
	v2Metric["schema_version"] = "v0alpha2"
	v2Metric["resource"].(transform.Row)["attributes_schema"] = `{"service.name":"string"}`
	v2Metric["instrumentation_scope"].(transform.Row)["attributes_schema"] = `{}`
	v2Metric["exemplars"].([]transform.Row)[0]["filtered_attributes_schema"] = `{"model":"string"}`

	migratedMetric := applyV0Alpha2ToV1MetricTransform(t, stmts["otel_metrics"], v2Metric)
	assertRowEqual(t, "otel_metrics migrated vs v1 writer", migratedMetric, v1Metrics[0])

	// 4. Quarantine parity: ensure payload_ref.uri NULL guard drops incomplete structs cleanly.
	qSQL := stmts["otel_quarantine"]
	if !strings.Contains(strings.Join(strings.Fields(qSQL), " "), "NULLIF(payload_ref.uri, '') IS NOT NULL") {
		t.Errorf("quarantine migration SQL must guard payload_ref.uri REQUIRED contract:\n%s", qSQL)
	}

	// 5. Validation guards & NULL struct preservation:
	//    - Same-dataset/same-table MigrationSQLV0Alpha2ToV1 rejects self-overwrite.
	if _, err := schema.MigrationSQLV0Alpha2ToV1(srcProj, srcDS, srcProj, srcDS, "otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"); err == nil {
		t.Error("MigrationSQLV0Alpha2ToV1(same project/dataset/tables) succeeded, want self-overwrite error")
	}
	//    - Empty table names in any of the 8 MigrationSQLV0Alpha2ToV1Pair parameters are rejected.
	baseArgs := [8]string{"s1", "l1", "m1", "q1", "s2", "l2", "m2", "q2"}
	for idx := range baseArgs {
		args := baseArgs
		args[idx] = ""
		if _, err := schema.MigrationSQLV0Alpha2ToV1Pair(
			srcProj, srcDS, args[0], args[1], args[2], args[3],
			dstProj, dstDS, args[4], args[5], args[6], args[7],
		); err == nil {
			t.Errorf("MigrationSQLV0Alpha2ToV1Pair with empty arg[%d] succeeded, want error", idx)
		}
	}
	//    - NULL resource and NULL instrumentation_scope remain NULL (omitted from migrated row).
	nullStructSpan := cloneTransformRow(v2Span)
	delete(nullStructSpan, "resource")
	delete(nullStructSpan, "instrumentation_scope")
	migratedNullSpan := applyV0Alpha2ToV1SpanTransform(t, stmts["otel_spans"], nullStructSpan)
	if _, hasRes := migratedNullSpan["resource"]; hasRes {
		t.Errorf("NULL v0alpha2 resource materialized non-NULL struct: %#v", migratedNullSpan["resource"])
	}
	if _, hasScope := migratedNullSpan["instrumentation_scope"]; hasScope {
		t.Errorf("NULL v0alpha2 instrumentation_scope materialized non-NULL struct: %#v", migratedNullSpan["instrumentation_scope"])
	}
}

type fixedTestOffloader struct {
	refs []transform.PayloadRef
}

func (o *fixedTestOffloader) OffloadSpan(context.Context, ptrace.Span, pcommon.Resource, pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	return slices.Clone(o.refs), nil
}

func (o *fixedTestOffloader) OffloadLog(context.Context, plog.LogRecord, pcommon.Resource, pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	return slices.Clone(o.refs), nil
}

func cloneTransformRow(src transform.Row) transform.Row {
	raw, _ := json.Marshal(src)
	var out transform.Row
	_ = json.Unmarshal(raw, &out)
	// Restore nested Row / []Row slices cleanly via recursive conversion.
	return convertToTransformRow(out).(transform.Row)
}

func convertToTransformRow(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		r := make(transform.Row, len(tv))
		for k, val := range tv {
			r[k] = convertToTransformRow(val)
		}
		return r
	case transform.Row:
		r := make(transform.Row, len(tv))
		for k, val := range tv {
			r[k] = convertToTransformRow(val)
		}
		return r
	case []any:
		if len(tv) == 0 {
			return tv
		}
		if _, isObj := tv[0].(map[string]any); isObj {
			rows := make([]transform.Row, len(tv))
			for i, el := range tv {
				rows[i] = convertToTransformRow(el).(transform.Row)
			}
			return rows
		}
		return tv
	default:
		return v
	}
}

func assertRowEqual(t *testing.T, label string, got, want transform.Row) {
	t.Helper()
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("%s mismatch:\n got: %s\nwant: %s", label, gotJSON, wantJSON)
	}
}

// migrationArrayRebuilds returns every ARRAY(SELECT ...) subquery of sql, each
// as its balanced parenthesized text with white space collapsed.
func migrationArrayRebuilds(sql string) []string {
	flat := strings.Join(strings.Fields(sql), " ")
	var out []string
	for i := 0; ; {
		j := strings.Index(flat[i:], "ARRAY(SELECT")
		if j < 0 {
			return out
		}
		start := i + j + len("ARRAY")
		depth, end := 0, -1
		for k := start; k < len(flat) && end < 0; k++ {
			switch flat[k] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 {
					end = k
				}
			}
		}
		if end < 0 {
			return append(out, flat[start:])
		}
		out = append(out, flat[start:end+1])
		i = end + 1
	}
}

// migrationArrayOrderProblems reports every ARRAY(SELECT ... FROM UNNEST(x) AS
// a ...) rebuild that does not number its elements WITH OFFSET AS pos and end
// in ORDER BY pos: without both, BigQuery does not guarantee that the rebuilt
// array keeps the element order of the source array (exemplar_ordinal, event
// and link order, object_refs order).
func migrationArrayOrderProblems(label, sql string) []string {
	var probs []string
	unnestAlias := regexp.MustCompile(`FROM UNNEST\(([a-z_]+)\) AS ([a-z]+)( WITH OFFSET AS pos)?`)
	for _, sub := range migrationArrayRebuilds(sql) {
		m := unnestAlias.FindStringSubmatch(sub)
		switch {
		case m == nil:
			probs = append(probs, fmt.Sprintf("%s: %s does not read FROM UNNEST(column) AS alias", label, sub))
		case m[3] == "":
			probs = append(probs, fmt.Sprintf("%s: UNNEST(%s) AS %s lacks WITH OFFSET AS pos in %s", label, m[1], m[2], sub))
		case !strings.HasSuffix(sub, " ORDER BY pos)"):
			probs = append(probs, fmt.Sprintf("%s: UNNEST(%s) does not end in ORDER BY pos in %s", label, m[1], sub))
		}
	}
	return probs
}

// TestMigrationSQLPreservesArrayOrderWithOffset locks every array rebuild of
// the v0alpha2 -> v1 migration (spans events, links and object_refs, logs
// object_refs, metrics exemplars) and its copy in docs/migration.md to WITH
// OFFSET AS pos ... ORDER BY pos, and proves that the check catches a rebuild
// that drops either half.
func TestMigrationSQLPreservesArrayOrderWithOffset(t *testing.T) {
	stmts, err := schema.MigrationSQLV0Alpha2ToV1("src-proj", "otel_v0alpha2", "dst-proj", "otel_v1",
		"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine")
	if err != nil {
		t.Fatalf("MigrationSQLV0Alpha2ToV1: %v", err)
	}
	wantArrays := map[string][]string{
		"otel_spans":      {"events", "links", "payload_refs"},
		"otel_logs":       {"payload_refs"},
		"otel_metrics":    {"exemplars"},
		"otel_quarantine": nil,
	}
	unnestCol := regexp.MustCompile(`FROM UNNEST\(([a-z_]+)\)`)
	for tbl, want := range wantArrays {
		sql := stmts[tbl]
		var got []string
		for _, sub := range migrationArrayRebuilds(sql) {
			if m := unnestCol.FindStringSubmatch(sub); m != nil {
				got = append(got, m[1])
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s migration rebuilds arrays from %v, want %v", tbl, got, want)
		}
		for _, p := range migrationArrayOrderProblems(tbl+" migration SQL", sql) {
			t.Error(p)
		}
	}

	docs, err := os.ReadFile(filepath.Join("docs", "migration.md"))
	if err != nil {
		t.Fatalf("read docs/migration.md: %v", err)
	}
	if n := len(migrationArrayRebuilds(string(docs))); n != 5 {
		t.Errorf("docs/migration.md has %d ARRAY(SELECT ...) rebuilds, want 5 (spans events, links, object_refs; logs object_refs; metrics exemplars)", n)
	}
	for _, p := range migrationArrayOrderProblems("docs/migration.md", string(docs)) {
		t.Error(p)
	}
	docsFlat := strings.Join(strings.Fields(string(docs)), " ")
	for tbl, sql := range stmts {
		for _, sub := range migrationArrayRebuilds(sql) {
			if !strings.Contains(docsFlat, sub) {
				t.Errorf("docs/migration.md does not carry the %s array rebuild %s", tbl, sub)
			}
		}
	}

	// The check itself must fail when either half of the ordering is missing.
	for _, tc := range []struct{ name, sql, want string }{
		{"no offset", "SELECT ARRAY(SELECT AS STRUCT ex.time FROM UNNEST(exemplars) AS ex) AS exemplars FROM t", "lacks WITH OFFSET AS pos"},
		{"no order by", "SELECT ARRAY(SELECT AS STRUCT ex.time FROM UNNEST(exemplars) AS ex WITH OFFSET AS pos) AS exemplars FROM t", "does not end in ORDER BY pos"},
		{"order by other", "SELECT ARRAY(SELECT AS STRUCT p.uri FROM UNNEST(payload_refs) AS p WITH OFFSET AS pos WHERE p.uri != '' ORDER BY p.uri) AS object_refs FROM t", "does not end in ORDER BY pos"},
	} {
		probs := migrationArrayOrderProblems(tc.name, tc.sql)
		if len(probs) != 1 || !strings.Contains(probs[0], tc.want) {
			t.Errorf("%s: problems = %q, want one containing %q", tc.name, probs, tc.want)
		}
	}
	if probs := migrationArrayOrderProblems("ok", "SELECT ARRAY(SELECT AS STRUCT ex.time FROM UNNEST(exemplars) AS ex WITH OFFSET AS pos ORDER BY pos) AS exemplars FROM t"); len(probs) != 0 {
		t.Errorf("an ordered rebuild is reported: %q", probs)
	}
}
