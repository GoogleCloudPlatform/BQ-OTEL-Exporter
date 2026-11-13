// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"google.golang.org/protobuf/proto"
)

const candidateGoldenSchemaPath = "testdata/v0alpha3_candidate_golden.json"

var ddlLabelEntryRE = regexp.MustCompile(`\(\s*'([a-z0-9_-]+)'\s*,\s*'([a-z0-9_-]+)'\s*\)`)

func parseDDLLabels(ddl string) map[string]string {
	idx := strings.Index(ddl, "labels = [")
	if idx < 0 {
		return nil
	}
	sub := ddl[idx:]
	end := strings.Index(sub, "]")
	if end < 0 {
		return nil
	}
	block := sub[:end]
	matches := ddlLabelEntryRE.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make(map[string]string, len(matches))
	for _, m := range matches {
		out[m[1]] = m[2]
	}
	return out
}

func TestV1CandidateColumnCountsAndContractInvariants(t *testing.T) {
	spans := SpansTableSchemaV1()
	logs := LogsTableSchemaV1()
	metrics := MetricsTableSchemaV1()
	quarantine := QuarantineTableSchemaV1()

	if got := len(spans.GetFields()); got != 28 {
		t.Errorf("otel_spans v1 column count = %d, want 28", got)
	}
	if got := len(logs.GetFields()); got != 24 {
		t.Errorf("otel_logs v1 column count = %d, want 24", got)
	}
	if got := len(metrics.GetFields()); got != 37 {
		t.Errorf("otel_metrics v1 column count = %d, want 37", got)
	}
	if got := len(quarantine.GetFields()); got != 11 {
		t.Errorf("otel_quarantine v1 column count = %d, want 11", got)
	}

	// Verify zero *_schema sidecars, zero record_fingerprint, zero schema_version,
	// and zero payload_refs across all 4 tables recursively.
	var walk func(tbl string, fields []*storagepb.TableFieldSchema)
	walk = func(tbl string, fields []*storagepb.TableFieldSchema) {
		for _, fld := range fields {
			name := fld.GetName()
			if strings.HasSuffix(name, "_schema") || name == "schema_version" || name == "record_fingerprint" || name == "payload_refs" {
				t.Errorf("%s still contains removed field %q", tbl, name)
			}
			walk(tbl, fld.GetFields())
		}
	}
	walk("otel_spans", spans.GetFields())
	walk("otel_logs", logs.GetFields())
	walk("otel_metrics", metrics.GetFields())
	walk("otel_quarantine", quarantine.GetFields())

	// Verify ADR-08: trace_state and links[].trace_state stay STRING;
	// timestamp_source, receive_time, receive_time_unix_nano, time_unix_nano,
	// and observed_time_unix_nano stay REQUIRED; insert_id is NULLABLE.
	findCol := func(s *storagepb.TableSchema, name string) *storagepb.TableFieldSchema {
		for _, fld := range s.GetFields() {
			if fld.GetName() == name {
				return fld
			}
		}
		t.Fatalf("column %q not found", name)
		return nil
	}

	if fld := findCol(spans, "trace_state"); fld.GetType() != storagepb.TableFieldSchema_STRING {
		t.Errorf("otel_spans.trace_state type = %s, want STRING", fld.GetType())
	}
	if fld := findCol(spans, "flags"); fld.GetType() != storagepb.TableFieldSchema_INT64 {
		t.Errorf("otel_spans.flags type = %s, want INT64", fld.GetType())
	}
	if fld := findCol(spans, "scope_schema_url"); fld.GetType() != storagepb.TableFieldSchema_STRING {
		t.Errorf("otel_spans.scope_schema_url type = %s, want STRING", fld.GetType())
	}

	for _, reqCol := range []string{"timestamp", "timestamp_source", "time_unix_nano", "observed_time_unix_nano", "receive_time", "receive_time_unix_nano", "log_name"} {
		if fld := findCol(logs, reqCol); fld.GetMode() != storagepb.TableFieldSchema_REQUIRED {
			t.Errorf("otel_logs.%s mode = %s, want REQUIRED", reqCol, fld.GetMode())
		}
	}
	if fld := findCol(logs, "observed_timestamp"); fld.GetMode() != storagepb.TableFieldSchema_NULLABLE {
		t.Errorf("otel_logs.observed_timestamp mode = %s, want NULLABLE", fld.GetMode())
	}
	if fld := findCol(logs, "insert_id"); fld.GetMode() != storagepb.TableFieldSchema_NULLABLE {
		t.Errorf("otel_logs.insert_id mode = %s, want NULLABLE", fld.GetMode())
	}

	// Verify ADR-11: object_refs is REPEATED 4-field native ObjectRef with uri REQUIRED.
	for name, tbl := range map[string]*storagepb.TableSchema{"otel_spans": spans, "otel_logs": logs} {
		refs := findCol(tbl, "object_refs")
		if refs.GetType() != storagepb.TableFieldSchema_STRUCT || refs.GetMode() != storagepb.TableFieldSchema_REPEATED {
			t.Errorf("%s.object_refs = (%s, %s), want (STRUCT, REPEATED)", name, refs.GetType(), refs.GetMode())
		}
		wantChildren := []struct {
			name string
			typ  storagepb.TableFieldSchema_Type
			mode storagepb.TableFieldSchema_Mode
		}{
			{"uri", storagepb.TableFieldSchema_STRING, storagepb.TableFieldSchema_REQUIRED},
			{"version", storagepb.TableFieldSchema_STRING, storagepb.TableFieldSchema_NULLABLE},
			{"authorizer", storagepb.TableFieldSchema_STRING, storagepb.TableFieldSchema_NULLABLE},
			{"details", storagepb.TableFieldSchema_JSON, storagepb.TableFieldSchema_NULLABLE},
		}
		if len(refs.GetFields()) != len(wantChildren) {
			t.Fatalf("%s.object_refs child count = %d, want %d", name, len(refs.GetFields()), len(wantChildren))
		}
		for i, wc := range wantChildren {
			got := refs.GetFields()[i]
			if got.GetName() != wc.name || got.GetType() != wc.typ || got.GetMode() != wc.mode {
				t.Errorf("%s.object_refs[%d] = (%s, %s, %s), want (%s, %s, %s)",
					name, i, got.GetName(), got.GetType(), got.GetMode(), wc.name, wc.typ, wc.mode)
			}
		}
	}

	// Verify quarantine payload_ref matches object_refs element shape.
	qRef := findCol(quarantine, "payload_ref")
	sRef := findCol(spans, "object_refs")
	qClone := proto.Clone(qRef).(*storagepb.TableFieldSchema)
	qClone.Name = sRef.GetName()
	qClone.Mode = sRef.GetMode()
	if !proto.Equal(qClone, sRef) {
		t.Errorf("otel_quarantine.payload_ref %v does not match object_refs element %v", qRef, sRef)
	}
}

func TestV1CandidateDDLMatchesTableSchemaAndLabels(t *testing.T) {
	wantLabels := ContractLabels(ContractV1Candidate)
	for _, tc := range []struct {
		name string
		ddl  string
		want *storagepb.TableSchema
	}{
		{"spans", SpansDDLV1, SpansTableSchemaV1()},
		{"logs", LogsDDLV1, LogsTableSchemaV1()},
		{"metrics", MetricsDDLV1, MetricsTableSchemaV1()},
		{"quarantine", QuarantineDDLV1, QuarantineTableSchemaV1()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDDL(tc.ddl)
			if err != nil {
				t.Fatal(err)
			}
			if diff := schemaDiff(got, tc.want); diff != "" {
				t.Fatal(diff)
			}
			gotLabels := parseDDLLabels(tc.ddl)
			if !maps.Equal(gotLabels, wantLabels) {
				t.Fatalf("%s DDL labels = %v, want %v", tc.name, gotLabels, wantLabels)
			}
		})
	}
}

func TestV1CandidateDedupViewsAndAccessPaths(t *testing.T) {
	// Spans dedup keeps start_time, start_time_unix_nano, service_name, trace_id, span_id, name.
	spansQ := strings.Join(strings.Fields(SpansDedupViewQueryV1), " ")
	wantSpans := "QUALIFY ROW_NUMBER() OVER ( PARTITION BY start_time, start_time_unix_nano, service_name, trace_id, span_id, name ORDER BY end_time_unix_nano DESC, receive_time_unix_nano DESC ) = 1"
	if !strings.Contains(spansQ, wantSpans) {
		t.Errorf("SpansDedupViewQueryV1 = %q, want %q", spansQ, wantSpans)
	}

	// Logs dedup preserves NULL insert_id rows and breaks ties by receive_time_unix_nano DESC, receive_time DESC.
	logsQ := strings.Join(strings.Fields(LogsDedupViewQueryV1), " ")
	wantLogs := "QUALIFY insert_id IS NULL OR ROW_NUMBER() OVER ( PARTITION BY timestamp, time_unix_nano, service_name, trace_id, span_id, severity_number, log_name, insert_id ORDER BY receive_time_unix_nano DESC, receive_time DESC ) = 1"
	if !strings.Contains(logsQ, wantLogs) {
		t.Errorf("LogsDedupViewQueryV1 = %q, want %q", logsQ, wantLogs)
	}

	for _, tc := range []struct {
		name     string
		tableDDL string
		indexDDL string
		view     string
		contract *storagepb.TableSchema
	}{
		{"spans", SpansDDLV1, SpansSearchIndexDDL, SpansDedupViewQueryV1, SpansTableSchemaV1()},
		{"logs", LogsDDLV1, LogsSearchIndexDDL, LogsDedupViewQueryV1, LogsTableSchemaV1()},
		{"metrics", MetricsDDLV1, MetricsSearchIndexDDL, MetricsDedupViewQueryV1, MetricsTableSchemaV1()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			format := func(tmpl string) string { return fmt.Sprintf(tmpl, "proj", "ds", "tbl") }
			tableDDL := format(tc.tableDDL)
			tp, clustering, err := parseDDLLayout(tableDDL)
			if err != nil {
				t.Fatal(err)
			}
			m := searchIndexRE.FindStringSubmatch(format(tc.indexDDL))
			if m == nil {
				t.Fatalf("failed to parse search index DDL")
			}
			paths := accessPaths{partition: tp.Field, cluster: clustering}
			if m[1] == "ALL COLUMNS" {
				paths.indexAll = true
			} else {
				paths.index = splitColumns(m[1])
			}
			window, err := windowKeys(format(tc.view))
			if err != nil {
				t.Fatal(err)
			}
			if missing := uncoveredAccessPaths(window, paths); len(missing) > 0 {
				t.Errorf("v1 dedup window %v does not cover access paths %v", window, missing)
			}
			inTable := map[string]bool{}
			for _, col := range FieldNames(tc.contract) {
				inTable[col] = true
			}
			for _, key := range window {
				if !inTable[key] {
					t.Errorf("window key %q is not a column in %s v1", key, tc.name)
				}
			}
		})
	}
}

func TestV1CandidateDestinationMetadataStampsLabels(t *testing.T) {
	wantLabels := ContractLabels(ContractV1Candidate)
	userLabels := map[string]string{
		"env":               "prod",
		"otel_schema_major": "99", // reserved label must not override contract label
	}
	md, viewQ, err := DestinationMetadataForContract(
		ContractV1Candidate, SpansTableSchemaV1(), "proj", "ds", "otel_spans", DestinationOptions{Labels: userLabels},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := md.Labels; got["env"] != "prod" || got[LabelSchemaMajor] != wantLabels[LabelSchemaMajor] ||
		got[LabelSchemaMinor] != wantLabels[LabelSchemaMinor] || got[LabelSchemaPatch] != wantLabels[LabelSchemaPatch] ||
		got[LabelSchemaVariant] != wantLabels[LabelSchemaVariant] {
		t.Fatalf("DestinationMetadataForContract labels = %v, want user env=prod + contract %v", got, wantLabels)
	}
	if !strings.Contains(viewQ, "FROM `proj.ds.otel_spans`") {
		t.Errorf("unexpected view query: %s", viewQ)
	}

	qmd, err := QuarantineDestinationMetadataForContract(ContractV1Candidate, DestinationOptions{
		PartitionExpirationDays: DefaultQuarantinePartitionExpirationDays,
		Labels:                  map[string]string{"tier": "quarantine"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if qmd.Labels["tier"] != "quarantine" || qmd.Labels[LabelSchemaMajor] != "0" || qmd.Labels[LabelSchemaMinor] != "3" {
		t.Fatalf("QuarantineDestinationMetadataForContract labels = %v", qmd.Labels)
	}
}

func TestSchemaLabelsParsingAndReservedKeys(t *testing.T) {
	for _, k := range []string{"otel_schema_major", "otel_schema_minor", "otel_schema_patch", "otel_schema_variant", "otel_schema_custom", "OTEL_SCHEMA_FOO"} {
		if !IsReservedSchemaLabelKey(k) {
			t.Errorf("IsReservedSchemaLabelKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{"env", "team", "otel_env", "schema_version"} {
		if IsReservedSchemaLabelKey(k) {
			t.Errorf("IsReservedSchemaLabelKey(%q) = true, want false", k)
		}
	}

	if parsed, err := ParseSchemaLabels(map[string]string{"env": "prod"}); err != nil || parsed.Present {
		t.Fatalf("ParseSchemaLabels(non-schema) = (%+v, %v), want Present=false, nil", parsed, err)
	}

	for _, bad := range []map[string]string{
		{"otel_schema_major": "0"},
		{"otel_schema_major": "0", "otel_schema_minor": "3", "otel_schema_patch": "0"},
		{"otel_schema_major": "01", "otel_schema_minor": "3", "otel_schema_patch": "0", "otel_schema_variant": "default"},
		{"otel_schema_major": "0", "otel_schema_minor": "x", "otel_schema_patch": "0", "otel_schema_variant": "default"},
		{"otel_schema_major": "0", "otel_schema_minor": "3", "otel_schema_patch": "-1", "otel_schema_variant": "default"},
		{"otel_schema_major": "0", "otel_schema_minor": "3", "otel_schema_patch": "0", "otel_schema_variant": ""},
	} {
		if _, err := ParseSchemaLabels(bad); err == nil {
			t.Errorf("ParseSchemaLabels(%v) succeeded, want error", bad)
		}
	}
}

func TestCompatibilityDifferencesRequiredNullableDirection(t *testing.T) {
	want := &storagepb.TableSchema{Fields: []*storagepb.TableFieldSchema{
		{Name: "req_col", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_REQUIRED},
		{Name: "opt_col", Type: storagepb.TableFieldSchema_STRING, Mode: storagepb.TableFieldSchema_NULLABLE},
	}}

	// REQUIRED -> NULLABLE relaxation on destination table MUST be accepted (ADR-12).
	relaxed := proto.Clone(want).(*storagepb.TableSchema)
	relaxed.Fields[0].Mode = storagepb.TableFieldSchema_NULLABLE
	if diffs := CompatibilityDifferences(want, relaxed); len(diffs) != 0 {
		t.Fatalf("REQUIRED -> NULLABLE relaxation reported incompatibilities %v, want none", diffs)
	}

	// NULLABLE -> REQUIRED tightening on destination table MUST be rejected.
	tightened := proto.Clone(want).(*storagepb.TableSchema)
	tightened.Fields[1].Mode = storagepb.TableFieldSchema_REQUIRED
	diffs := CompatibilityDifferences(want, tightened)
	if len(diffs) != 1 || !strings.Contains(diffs[0], "opt_col has mode REQUIRED, want NULLABLE") {
		t.Fatalf("NULLABLE -> REQUIRED tightening diffs = %v, want opt_col mode mismatch", diffs)
	}
}

// TestADR09AdmissionMatrix tests every cell of the ADR-09 / P1-2 admission matrix.
func TestADR09AdmissionMatrix(t *testing.T) {
	baseV1 := LogsTableSchemaV1()
	baseV1BQ, err := ToBigQuery(baseV1)
	if err != nil {
		t.Fatal(err)
	}
	baseV0BQ, err := ToBigQuery(LogsTableSchema())
	if err != nil {
		t.Fatal(err)
	}

	makeMD := func(s bq.Schema, labels map[string]string) *bq.TableMetadata {
		return &bq.TableMetadata{
			FullID: "proj:ds.otel_logs",
			Schema: s,
			Labels: maps.Clone(labels),
		}
	}

	withExtraField := func(name string, required bool) bq.Schema {
		out := slices.Clone(baseV1BQ)
		out = append(out, &bq.FieldSchema{Name: name, Type: bq.StringFieldType, Required: required})
		return out
	}

	withChangedMode := func(col string, required bool) bq.Schema {
		out := make(bq.Schema, len(baseV1BQ))
		for i, fld := range baseV1BQ {
			cp := *fld
			if cp.Name == col {
				cp.Required = required
			}
			out[i] = &cp
		}
		return out
	}

	cases := []struct {
		name            string
		writerMajor     int
		writerMinor     int
		writerVersion   string
		md              *bq.TableMetadata
		wantErrSubstr   string
		wantWarnSubstrs []string
	}{
		{
			name:            "missing labels with matching v1 structure admits with warning",
			writerMajor:     0,
			writerMinor:     3,
			writerVersion:   VersionV1Candidate,
			md:              makeMD(baseV1BQ, nil),
			wantWarnSubstrs: []string{"missing otel_schema_* labels"},
		},
		{
			name:          "missing labels with v0alpha2 shape fails fast linking migration.md",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(baseV0BQ, nil),
			wantErrSubstr: "docs/migration.md",
		},
		{
			name:          "0.3.0 table with 0.3.0 writer admits cleanly",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(baseV1BQ, ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "1.0.0 table with 0.3.0 writer admits cleanly (bidirectional rolling upgrade/rollback)",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "1", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
		},
		{
			name:          "0.3.0 table with 1.0.0 writer admits with bq update promotion command warning",
			writerMajor:   1,
			writerMinor:   0,
			writerVersion: "v1.0.0",
			md:            makeMD(baseV1BQ, ContractLabels(ContractV1Candidate)),
			wantWarnSubstrs: []string{
				"bq update --set_label",
				"otel_schema_major:1",
				"proj:ds.otel_logs",
			},
		},
		{
			name:          "1.0.0 table with 1.0.0 writer admits cleanly",
			writerMajor:   1,
			writerMinor:   0,
			writerVersion: "v1.0.0",
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "1", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
		},
		{
			name:          "1.2.0 table ahead of 1.0.0 writer admits with warning",
			writerMajor:   1,
			writerMinor:   0,
			writerVersion: "v1.0.0",
			md: makeMD(withExtraField("future_col", false), map[string]string{
				LabelSchemaMajor: "1", LabelSchemaMinor: "2", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
			wantWarnSubstrs: []string{"1.2.0 are ahead of writer v1.0.0"},
		},
		{
			name:          "1.0.0 table behind 1.2.0 writer admits with warning when structure matches",
			writerMajor:   1,
			writerMinor:   2,
			writerVersion: "v1.2.0",
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "1", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
			wantWarnSubstrs: []string{"1.0.0 are behind writer v1.2.0"},
		},
		{
			name:          "2.0.0 major mismatch fails fast even with identical structure",
			writerMajor:   1,
			writerMinor:   0,
			writerVersion: "v1.0.0",
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "2", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
			wantErrSubstr: "incompatible with writer v1.0.0",
		},
		{
			name:          "0.2.0 minor mismatch fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "0", LabelSchemaMinor: "2", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
			wantErrSubstr: "incompatible with writer v0alpha3",
		},
		{
			name:          "unknown otel_schema_variant fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "0", LabelSchemaMinor: "3", LabelSchemaPatch: "0", LabelSchemaVariant: "lean",
			}),
			wantErrSubstr: "unsupported otel_schema_variant",
		},
		{
			name:          "extra nullable field admits",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(withExtraField("custom_nullable", false), ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "extra required field fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(withExtraField("custom_required", true), ContractLabels(ContractV1Candidate)),
			wantErrSubstr: "extra REQUIRED field",
		},
		{
			name:          "REQUIRED to NULLABLE relaxation on destination table admits",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(withChangedMode("time_unix_nano", false), ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "NULLABLE to REQUIRED tightening on destination table fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: VersionV1Candidate,
			md:            makeMD(withChangedMode("insert_id", true), ContractLabels(ContractV1Candidate)),
			wantErrSubstr: "insert_id has mode REQUIRED, want NULLABLE",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warnings, err := ValidateTableLabelsAndStructureForVersion(
				tc.writerMajor, tc.writerMinor, tc.writerVersion, baseV1, tc.md, "destination table proj.ds.otel_logs",
			)
			if tc.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Fatalf("err = %v, want substring %q", err, tc.wantErrSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.wantWarnSubstrs) == 0 {
				if len(warnings) != 0 {
					t.Fatalf("unexpected warnings: %v", warnings)
				}
				return
			}
			joined := strings.Join(warnings, "\n")
			for _, sub := range tc.wantWarnSubstrs {
				if !strings.Contains(joined, sub) {
					t.Fatalf("warnings = %q, want substring %q", joined, sub)
				}
			}
		})
	}
}

func buildV1CandidateSnapshot() (SchemaSnapshot, error) {
	const (
		proj         = "proj"
		ds           = "ds"
		spansTbl     = "otel_spans"
		logsTbl      = "otel_logs"
		metricsTbl   = "otel_metrics"
		quarantineTb = "otel_quarantine"
	)

	type signalSpec struct {
		name         string
		schema       *storagepb.TableSchema
		dedupDDL     string
		searchIdxDDL string
	}
	signals := []signalSpec{
		{spansTbl, SpansTableSchemaV1(), SpansDedupViewDDLV1, SpansSearchIndexDDL},
		{logsTbl, LogsTableSchemaV1(), LogsDedupViewDDLV1, LogsSearchIndexDDL},
		{metricsTbl, MetricsTableSchemaV1(), MetricsDedupViewDDLV1, MetricsSearchIndexDDL},
	}

	tables := make([]TableSnapshot, 0, 4)
	dedupDigests := make(map[string]string, len(signals))
	for _, sig := range signals {
		fields, err := fieldsToSnapshots(sig.schema.GetFields())
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s fields: %w", sig.name, err)
		}
		md, dedupQuery, err := DestinationMetadataForContract(ContractV1Candidate, sig.schema, proj, ds, sig.name, DestinationOptions{})
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s metadata: %w", sig.name, err)
		}
		dedupName, _, err := parseViewDDL(fmt.Sprintf(sig.dedupDDL, proj, ds, sig.name))
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s dedup DDL: %w", sig.name, err)
		}
		dedupDigests[dedupName] = sqlDigestHex(dedupQuery)
		searchIdx, err := parseSearchIndexSnapshot(fmt.Sprintf(sig.searchIdxDDL, proj, ds, sig.name))
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s search index DDL: %w", sig.name, err)
		}
		tp, clustering, err := extractLayoutSnapshot(md)
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s layout: %w", sig.name, err)
		}
		tables = append(tables, TableSnapshot{
			Name:             sig.name,
			Fields:           fields,
			TimePartitioning: tp,
			Clustering:       clustering,
			Labels:           md.Labels,
			DedupView:        dedupName,
			SearchIndex:      searchIdx,
		})
	}

	qFields, err := fieldsToSnapshots(QuarantineTableSchemaV1().GetFields())
	if err != nil {
		return SchemaSnapshot{}, fmt.Errorf("%s fields: %w", quarantineTb, err)
	}
	qMD, err := QuarantineDestinationMetadataForContract(ContractV1Candidate, DestinationOptions{
		PartitionExpirationDays: DefaultQuarantinePartitionExpirationDays,
	})
	if err != nil {
		return SchemaSnapshot{}, fmt.Errorf("%s metadata: %w", quarantineTb, err)
	}
	qTP, qClustering, err := extractLayoutSnapshot(qMD)
	if err != nil {
		return SchemaSnapshot{}, fmt.Errorf("%s layout: %w", quarantineTb, err)
	}
	tables = append(tables, TableSnapshot{
		Name:             quarantineTb,
		Fields:           qFields,
		TimePartitioning: qTP,
		Clustering:       qClustering,
		Labels:           qMD.Labels,
	})

	companionViews, viewDigests, err := collectCompanionViewsForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl, metricsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}
	companionTVFs, tvfDigests, err := collectCompanionTVFsForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}

	return SchemaSnapshot{
		Version:              VersionV1Candidate,
		Tables:               tables,
		CompanionViews:       companionViews,
		CompanionTVFs:        companionTVFs,
		DedupViewDigests:     dedupDigests,
		CompanionViewDigests: viewDigests,
		CompanionTVFDigests:  tvfDigests,
	}, nil
}

func buildV1CandidateDDLSnapshot() (SchemaSnapshot, error) {
	const (
		proj         = "proj"
		ds           = "ds"
		spansTbl     = "otel_spans"
		logsTbl      = "otel_logs"
		metricsTbl   = "otel_metrics"
		quarantineTb = "otel_quarantine"
	)

	type ddlSpec struct {
		name         string
		tableDDL     string
		dedupDDL     string
		searchIdxDDL string
	}
	specs := []ddlSpec{
		{spansTbl, SpansDDLV1, SpansDedupViewDDLV1, SpansSearchIndexDDL},
		{logsTbl, LogsDDLV1, LogsDedupViewDDLV1, LogsSearchIndexDDL},
		{metricsTbl, MetricsDDLV1, MetricsDedupViewDDLV1, MetricsSearchIndexDDL},
		{quarantineTb, QuarantineDDLV1, "", ""},
	}

	tables := make([]TableSnapshot, 0, len(specs))
	dedupDigests := make(map[string]string, 3)
	for _, sp := range specs {
		parsedSchema, err := parseDDL(sp.tableDDL)
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("parse %s DDL: %w", sp.name, err)
		}
		fields, err := fieldsToSnapshots(parsedSchema.GetFields())
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s DDL fields: %w", sp.name, err)
		}
		tp, clustering, err := parseDDLLayout(sp.tableDDL)
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s DDL layout: %w", sp.name, err)
		}
		labels := parseDDLLabels(sp.tableDDL)
		var dedupView string
		if sp.dedupDDL != "" {
			var body string
			dedupView, body, err = parseViewDDL(fmt.Sprintf(sp.dedupDDL, proj, ds, sp.name))
			if err != nil {
				return SchemaSnapshot{}, fmt.Errorf("%s dedup DDL: %w", sp.name, err)
			}
			dedupDigests[dedupView] = sqlDigestHex(body)
		}
		var searchIdx *SearchIndexSnapshot
		if sp.searchIdxDDL != "" {
			searchIdx, err = parseSearchIndexSnapshot(fmt.Sprintf(sp.searchIdxDDL, proj, ds, sp.name))
			if err != nil {
				return SchemaSnapshot{}, fmt.Errorf("%s search index DDL: %w", sp.name, err)
			}
		}
		tables = append(tables, TableSnapshot{
			Name:             sp.name,
			Fields:           fields,
			TimePartitioning: tp,
			Clustering:       clustering,
			Labels:           labels,
			DedupView:        dedupView,
			SearchIndex:      searchIdx,
		})
	}

	companionViews, viewDigests, err := collectDDLCompanionViewsForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl, metricsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}
	companionTVFs, tvfDigests, err := collectCompanionTVFsForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}

	return SchemaSnapshot{
		Version:              VersionV1Candidate,
		Tables:               tables,
		CompanionViews:       companionViews,
		CompanionTVFs:        companionTVFs,
		DedupViewDigests:     dedupDigests,
		CompanionViewDigests: viewDigests,
		CompanionTVFDigests:  tvfDigests,
	}, nil
}

func TestV1CandidateGoldenMatchesContract(t *testing.T) {
	current, err := buildV1CandidateSnapshot()
	if err != nil {
		t.Fatalf("buildV1CandidateSnapshot: %v", err)
	}
	ddlCurrent, err := buildV1CandidateDDLSnapshot()
	if err != nil {
		t.Fatalf("buildV1CandidateDDLSnapshot: %v", err)
	}

	currentJSON := marshalCanonicalSnapshot(t, current)
	ddlJSON := marshalCanonicalSnapshot(t, ddlCurrent)
	if !bytes.Equal(currentJSON, ddlJSON) {
		t.Fatalf("TableSchemaV1 snapshot and DDLV1 snapshot diverged:\n--- TableSchema ---\n%s\n--- DDL ---\n%s",
			string(currentJSON), string(ddlJSON))
	}

	raw, err := os.ReadFile(filepath.Clean(candidateGoldenSchemaPath))
	if err != nil {
		t.Fatalf("read %s: %v", candidateGoldenSchemaPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var golden SchemaSnapshot
	if err := dec.Decode(&golden); err != nil {
		t.Fatalf("decode %s: %v", candidateGoldenSchemaPath, err)
	}
	goldenJSON := marshalCanonicalSnapshot(t, golden)
	if !bytes.Equal(bytes.TrimSpace(raw), bytes.TrimSpace(goldenJSON)) {
		t.Fatalf("%s is not canonically formatted", candidateGoldenSchemaPath)
	}
	if !bytes.Equal(goldenJSON, currentJSON) {
		t.Fatalf("v1 candidate schema drifted from %s:\n%s", candidateGoldenSchemaPath, string(currentJSON))
	}
}

var (
	sqlSingleQuotedRE = regexp.MustCompile(`'(?:[^'\\]|\\.)*'`)
	sqlBacktickedRE   = regexp.MustCompile("`[^`]+`")
	sqlIdentPathRE    = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\b`)
	sqlAsAliasRE      = regexp.MustCompile(`(?i)\bAS\s+[a-zA-Z_][a-zA-Z0-9_]*\b`)
)

func buildSchemaFieldPathSet(s *storagepb.TableSchema) map[string]bool {
	paths := make(map[string]bool)
	var walk func(prefix string, fields []*storagepb.TableFieldSchema)
	walk = func(prefix string, fields []*storagepb.TableFieldSchema) {
		for _, fld := range fields {
			if fld == nil {
				continue
			}
			p := fld.GetName()
			if prefix != "" {
				p = prefix + "." + p
			}
			paths[p] = true
			walk(p, fld.GetFields())
		}
	}
	walk("", s.GetFields())
	return paths
}

func stripSQLCommentsAndLiterals(sql string) string {
	cleaned := stripSQLComments(sql)
	cleaned = sqlSingleQuotedRE.ReplaceAllString(cleaned, "''")
	cleaned = sqlBacktickedRE.ReplaceAllString(cleaned, "``")
	return cleaned
}

var sqlNonColumnKeywords = map[string]bool{
	"SELECT": true, "AS": true, "FROM": true, "WHERE": true, "AND": true, "OR": true,
	"IS": true, "NOT": true, "NULL": true, "COALESCE": true, "NULLIF": true,
	"IF": true, "CASE": true, "WHEN": true, "THEN": true, "ELSE": true, "END": true,
	"IN": true, "LIKE": true, "BETWEEN": true, "TRUE": true, "FALSE": true,
	"CAST": true, "STRUCT": true, "ARRAY": true, "UNNEST": true, "OFFSET": true,
	"SAFE_OFFSET": true, "ORDINAL": true, "INT64": true, "FLOAT64": true,
	"STRING": true, "JSON": true, "BOOL": true, "TIMESTAMP": true, "DATE": true,
	"ROUND": true, "JSON_VALUE": true, "LAX_INT64": true, "LAX_FLOAT64": true,
	"TIMESTAMP_SUB": true, "TIMESTAMP_ADD": true, "INTERVAL": true, "HOUR": true,
	"DISTINCT": true, "LEFT": true, "JOIN": true, "ON": true,
}

func splitTopLevelSQLComma(s string) []string {
	var parts []string
	depth := 0
	inQuote := false
	start := 0
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch == '\'' {
			inQuote = !inQuote
			continue
		}
		if inQuote {
			continue
		}
		switch ch {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func findInvalidSingleTableColumns(sql string, validPaths map[string]bool) []string {
	cleaned := stripSQLCommentsAndLiterals(sql)
	upper := strings.ToUpper(cleaned)
	selIdx := strings.Index(upper, "SELECT")
	fromIdx := strings.Index(upper, "FROM")
	if selIdx < 0 || fromIdx < 0 || fromIdx <= selIdx {
		return []string{"missing SELECT ... FROM structure"}
	}
	selectBody := cleaned[selIdx+len("SELECT") : fromIdx]
	whereBody := ""
	if whereIdx := strings.Index(upper[fromIdx:], "WHERE"); whereIdx >= 0 {
		whereBody = cleaned[fromIdx+whereIdx+len("WHERE"):]
	}

	var exprs []string
	for _, item := range splitTopLevelSQLComma(selectBody) {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		exprs = append(exprs, sqlAsAliasRE.ReplaceAllString(trimmed, ""))
	}
	if whereBody != "" {
		exprs = append(exprs, whereBody)
	}

	var invalid []string
	for _, expr := range exprs {
		for _, tok := range sqlIdentPathRE.FindAllString(expr, -1) {
			if sqlNonColumnKeywords[strings.ToUpper(tok)] {
				continue
			}
			if !validPaths[tok] {
				invalid = append(invalid, tok)
			}
		}
	}
	return invalid
}

func findInvalidAliasedColumns(sql string, aliasSchemas map[string]map[string]bool) []string {
	cleaned := stripSQLCommentsAndLiterals(sql)
	var invalid []string
	for _, tok := range sqlIdentPathRE.FindAllString(cleaned, -1) {
		head, rest, hasDot := strings.Cut(tok, ".")
		if !hasDot {
			continue
		}
		validPaths, ok := aliasSchemas[head]
		if !ok {
			continue
		}
		if !validPaths[rest] {
			invalid = append(invalid, tok)
		}
	}
	return invalid
}

func TestV1CandidateCompanionViewsAndTVFsMatchV1Columns(t *testing.T) {
	const (
		proj       = "proj"
		ds         = "ds"
		spansTbl   = "otel_spans"
		logsTbl    = "otel_logs"
		metricsTbl = "otel_metrics"
	)

	spansPaths := buildSchemaFieldPathSet(SpansTableSchemaV1())
	logsPaths := buildSchemaFieldPathSet(LogsTableSchemaV1())
	metricsPaths := buildSchemaFieldPathSet(MetricsTableSchemaV1())

	// Collect every v1 companion view and TVF query.
	allQueries := make(map[string]string)
	for name, md := range CompanionViewsMetadataForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl, true) {
		allQueries[name] = md.ViewQuery
	}
	for name, md := range CompanionViewsMetadataForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl, false) {
		allQueries[name] = md.ViewQuery
	}
	for name, md := range MetricsCompanionViewsMetadataForContract(ContractV1Candidate, proj, ds, metricsTbl) {
		allQueries[name] = md.ViewQuery
	}
	allQueries[GenAIMetricExemplarsViewName] = MetricExemplarsCompanionViewMetadataForContract(ContractV1Candidate, proj, ds, spansTbl).ViewQuery
	for name, q := range CompanionTVFQueriesForContract(ContractV1Candidate, proj, ds, spansTbl, logsTbl) {
		allQueries[name] = q
	}

	droppedV0Columns := map[string]bool{
		"attributes_schema":          true,
		"resource_attributes_schema": true,
		"scope_attributes_schema":    true,
		"body_schema":                true,
		"metric_metadata_schema":     true,
		"filtered_attributes_schema": true,
		"payload_refs":               true,
		"record_fingerprint":         true,
		"schema_version":             true,
	}

	for name, sql := range allQueries {
		cleaned := stripSQLCommentsAndLiterals(sql)
		for _, tok := range sqlIdentPathRE.FindAllString(cleaned, -1) {
			for _, part := range strings.Split(tok, ".") {
				if droppedV0Columns[part] {
					t.Errorf("v1 artifact %s references dropped v0alpha2 column %q", name, tok)
				}
			}
		}
	}

	// Single-table base dedup readers must resolve every referenced column against V1 schemas.
	for _, tc := range []struct {
		name       string
		sql        string
		validPaths map[string]bool
	}{
		{SpansAsAllSpansViewName, allQueries[SpansAsAllSpansViewName], spansPaths},
		{GenAISpansViewName, allQueries[GenAISpansViewName], spansPaths},
		{MCPSpansViewName, allQueries[MCPSpansViewName], spansPaths},
		{GenAIMetricsViewName, allQueries[GenAIMetricsViewName], metricsPaths},
	} {
		if bad := findInvalidSingleTableColumns(tc.sql, tc.validPaths); len(bad) > 0 {
			t.Errorf("v1 %s references unknown base columns: %v", tc.name, bad)
		}
	}

	// Aliased cross-signal views & TVFs must resolve every l.* / s.* column against V1 schemas.
	for _, tc := range []struct {
		name    string
		sql     string
		schemas map[string]map[string]bool
	}{
		{GenAILogsViewName, allQueries[GenAILogsViewName], map[string]map[string]bool{"l": logsPaths, "s": spansPaths}},
		{GenAILogsTVFName, allQueries[GenAILogsTVFName], map[string]map[string]bool{"l": logsPaths, "s": spansPaths}},
		{GenAIMetricExemplarsViewName, allQueries[GenAIMetricExemplarsViewName], map[string]map[string]bool{"s": spansPaths}},
		{GenAIMetricExemplarsTVFName, allQueries[GenAIMetricExemplarsTVFName], map[string]map[string]bool{"s": spansPaths}},
	} {
		if bad := findInvalidAliasedColumns(tc.sql, tc.schemas); len(bad) > 0 {
			t.Errorf("v1 %s references unknown aliased base columns: %v", tc.name, bad)
		}
	}

	// Negative controls: v0alpha2 queries must fail conformance checks against v1 schemas.
	v0SpansViews := CompanionViewsMetadataForContract(ContractV0Alpha2, proj, ds, spansTbl, logsTbl, true)
	if bad := findInvalidSingleTableColumns(v0SpansViews[SpansAsAllSpansViewName].ViewQuery, spansPaths); !slices.Contains(bad, "attributes_schema") {
		t.Fatalf("expected v0alpha2 otel_spans_as_allspans to fail v1 conformance on attributes_schema, got %v", bad)
	}
	if bad := findInvalidSingleTableColumns(v0SpansViews[GenAISpansViewName].ViewQuery, spansPaths); !slices.Contains(bad, "payload_refs") {
		t.Fatalf("expected v0alpha2 v_gen_ai_spans to fail v1 conformance on payload_refs, got %v", bad)
	}
	if bad := findInvalidSingleTableColumns(v0SpansViews[MCPSpansViewName].ViewQuery, spansPaths); !slices.Contains(bad, "payload_refs") {
		t.Fatalf("expected v0alpha2 v_mcp_spans to fail v1 conformance on payload_refs, got %v", bad)
	}
	v0LogsViews := CompanionViewsMetadataForContract(ContractV0Alpha2, proj, ds, spansTbl, logsTbl, false)
	if bad := findInvalidAliasedColumns(v0LogsViews[GenAILogsViewName].ViewQuery, map[string]map[string]bool{"l": logsPaths, "s": spansPaths}); !slices.Contains(bad, "l.payload_refs") {
		t.Fatalf("expected v0alpha2 v_gen_ai_logs to fail v1 conformance on l.payload_refs, got %v", bad)
	}
}

func TestContractLabelCapAndReservedKeyStripping(t *testing.T) {
	makeLabels := func(n int) map[string]string {
		out := make(map[string]string, n)
		for i := range n {
			out[fmt.Sprintf("k%d", i)] = "v"
		}
		return out
	}

	// ContractV1Candidate allows 60 customer labels (+ 4 reserved = 64).
	md60, _, err := DestinationMetadataForContract(
		ContractV1Candidate, SpansTableSchemaV1(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(60)},
	)
	if err != nil {
		t.Fatalf("60 customer labels under ContractV1Candidate failed: %v", err)
	}
	if len(md60.Labels) != MaxBigQueryLabels {
		t.Fatalf("merged label count = %d, want %d", len(md60.Labels), MaxBigQueryLabels)
	}

	if _, _, err := DestinationMetadataForContract(
		ContractV1Candidate, SpansTableSchemaV1(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(61)},
	); err == nil || !strings.Contains(err.Error(), "64-label limit") || !strings.Contains(err.Error(), "4 reserved") {
		t.Fatalf("61 customer labels err = %v, want 64-label limit and 4 reserved error", err)
	}

	if _, err := QuarantineDestinationMetadataForContract(
		ContractV1Candidate, DestinationOptions{Labels: makeLabels(61)},
	); err == nil || !strings.Contains(err.Error(), "64-label limit") {
		t.Fatalf("quarantine 61 customer labels err = %v, want 64-label limit error", err)
	}

	// ContractV0Alpha2 retains the full 64 customer-label allowance; 65 fails.
	md64, _, err := DestinationMetadataForContract(
		ContractV0Alpha2, SpansTableSchema(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(64)},
	)
	if err != nil {
		t.Fatalf("64 customer labels under ContractV0Alpha2 failed: %v", err)
	}
	if len(md64.Labels) != MaxBigQueryLabels {
		t.Fatalf("v0alpha2 label count = %d, want %d", len(md64.Labels), MaxBigQueryLabels)
	}
	if _, _, err := DestinationMetadataForContract(
		ContractV0Alpha2, SpansTableSchema(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(65)},
	); err == nil || !strings.Contains(err.Error(), "64-label limit") {
		t.Fatalf("65 customer labels under ContractV0Alpha2 err = %v, want 64-label limit error", err)
	}

	// Programmatic reserved otel_schema_* keys (such as otel_schema_custom) are stripped.
	for _, c := range []Contract{ContractV0Alpha2, ContractV1Candidate} {
		tbl := SpansTableSchemaForContract(c)
		md, _, err := DestinationMetadataForContract(c, tbl, "proj", "ds", "otel_spans", DestinationOptions{
			Labels: map[string]string{
				"env":                "prod",
				"otel_schema_custom": "injected",
				"OTEL_SCHEMA_EXTRA":  "injected",
			},
		})
		if err != nil {
			t.Fatalf("DestinationMetadataForContract(%s) error: %v", c, err)
		}
		if _, exists := md.Labels["otel_schema_custom"]; exists {
			t.Errorf("%s leaked programmatic otel_schema_custom label", c)
		}
		if _, exists := md.Labels["OTEL_SCHEMA_EXTRA"]; exists {
			t.Errorf("%s leaked programmatic OTEL_SCHEMA_EXTRA label", c)
		}
		if md.Labels["env"] != "prod" {
			t.Errorf("%s dropped non-reserved label env: %v", c, md.Labels)
		}
	}
}

func TestValidateTableLabels(t *testing.T) {
	if _, err := ValidateTableLabels(ContractV0Alpha2, &bq.TableMetadata{
		Labels: map[string]string{
			LabelSchemaMajor: "1", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
		},
	}, "destination table proj.ds.otel_logs"); err == nil || !strings.Contains(err.Error(), "incompatible with schema v0alpha2") {
		t.Fatalf("expected v0alpha2 to reject otel_schema_* labels, got %v", err)
	}

	warnings, err := ValidateTableLabels(ContractV1Candidate, &bq.TableMetadata{}, "destination table proj.ds.otel_logs")
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "missing otel_schema_* labels") {
		t.Fatalf("unlabeled under v1 = (%v, %v), want missing-label warning", warnings, err)
	}

	for _, tc := range []struct {
		name   string
		labels map[string]string
		want   string
	}{
		{
			name:   "unsupported variant",
			labels: map[string]string{LabelSchemaMajor: "0", LabelSchemaMinor: "3", LabelSchemaPatch: "0", LabelSchemaVariant: "lean"},
			want:   "unsupported otel_schema_variant",
		},
		{
			name:   "major 2.0.0",
			labels: map[string]string{LabelSchemaMajor: "2", LabelSchemaMinor: "0", LabelSchemaPatch: "0", LabelSchemaVariant: "default"},
			want:   "incompatible with writer v0alpha3",
		},
		{
			name:   "minor 0.2.0",
			labels: map[string]string{LabelSchemaMajor: "0", LabelSchemaMinor: "2", LabelSchemaPatch: "0", LabelSchemaVariant: "default"},
			want:   "incompatible with writer v0alpha3",
		},
		{
			name:   "malformed major",
			labels: map[string]string{LabelSchemaMajor: "abc", LabelSchemaMinor: "3", LabelSchemaPatch: "0", LabelSchemaVariant: "default"},
			want:   "invalid otel_schema_* labels",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateTableLabels(ContractV1Candidate, &bq.TableMetadata{Labels: tc.labels}, "destination table proj.ds.otel_logs")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
