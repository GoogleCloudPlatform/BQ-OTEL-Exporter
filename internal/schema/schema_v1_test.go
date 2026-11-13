// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"google.golang.org/protobuf/proto"
)

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
	spans := SpansTableSchema()
	logs := LogsTableSchema()
	metrics := MetricsTableSchema()
	quarantine := QuarantineTableSchema()

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
		{"spans", SpansDDL, SpansTableSchema()},
		{"logs", LogsDDL, LogsTableSchema()},
		{"metrics", MetricsDDL, MetricsTableSchema()},
		{"quarantine", QuarantineDDL, QuarantineTableSchema()},
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
	spansQ := strings.Join(strings.Fields(SpansDedupViewQuery), " ")
	wantSpans := "QUALIFY ROW_NUMBER() OVER ( PARTITION BY start_time, start_time_unix_nano, service_name, trace_id, span_id, name ORDER BY end_time_unix_nano DESC, receive_time_unix_nano DESC ) = 1"
	if !strings.Contains(spansQ, wantSpans) {
		t.Errorf("SpansDedupViewQuery = %q, want %q", spansQ, wantSpans)
	}

	// Logs dedup preserves NULL insert_id rows and breaks ties by receive_time_unix_nano DESC, receive_time DESC.
	logsQ := strings.Join(strings.Fields(LogsDedupViewQuery), " ")
	wantLogs := "QUALIFY insert_id IS NULL OR ROW_NUMBER() OVER ( PARTITION BY timestamp, time_unix_nano, service_name, trace_id, span_id, severity_number, log_name, insert_id ORDER BY receive_time_unix_nano DESC, receive_time DESC ) = 1"
	if !strings.Contains(logsQ, wantLogs) {
		t.Errorf("LogsDedupViewQuery = %q, want %q", logsQ, wantLogs)
	}

	for _, tc := range []struct {
		name     string
		tableDDL string
		indexDDL string
		view     string
		contract *storagepb.TableSchema
	}{
		{"spans", SpansDDL, SpansSearchIndexDDL, SpansDedupViewQuery, SpansTableSchema()},
		{"logs", LogsDDL, LogsSearchIndexDDL, LogsDedupViewQuery, LogsTableSchema()},
		{"metrics", MetricsDDL, MetricsSearchIndexDDL, MetricsDedupViewQuery, MetricsTableSchema()},
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
			allowedCluster, err := AllowedClusteringColumns(tc.contract)
			if err != nil {
				t.Fatalf("AllowedClusteringColumns(%s): %v", tc.name, err)
			}
			windowSet := map[string]bool{}
			for _, key := range window {
				windowSet[key] = true
			}
			for _, col := range allowedCluster {
				if !windowSet[col] {
					t.Errorf("%s AllowedClusteringColumns includes %q which is not in dedup PARTITION BY window %v", tc.name, col, window)
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
		ContractV1Candidate, SpansTableSchema(), "proj", "ds", "otel_spans", DestinationOptions{Labels: userLabels},
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
	baseV1 := LogsTableSchema()
	baseV1BQ, err := ToBigQuery(baseV1)
	if err != nil {
		t.Fatal(err)
	}
	baseV0BQ := slices.Clone(baseV1BQ)
	baseV0BQ = append(baseV0BQ,
		&bq.FieldSchema{Name: "attributes_schema", Type: bq.JSONFieldType},
		&bq.FieldSchema{Name: "record_fingerprint", Type: bq.StringFieldType},
		&bq.FieldSchema{Name: "schema_version", Type: bq.StringFieldType, Required: true},
	)

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
			writerVersion:   Version,
			md:              makeMD(baseV1BQ, nil),
			wantWarnSubstrs: []string{"missing otel_schema_* labels"},
		},
		{
			name:          "missing labels with v0alpha2 shape fails fast linking migration.md",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md:            makeMD(baseV0BQ, nil),
			wantErrSubstr: "docs/migration.md",
		},
		{
			name:          "0.3.0 table with 0.3.0 writer admits cleanly",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md:            makeMD(baseV1BQ, ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "1.0.0 table with 0.3.0 writer admits cleanly (bidirectional rolling upgrade/rollback)",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
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
			writerVersion: Version,
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "0", LabelSchemaMinor: "2", LabelSchemaPatch: "0", LabelSchemaVariant: "default",
			}),
			wantErrSubstr: "incompatible with writer v0alpha3",
		},
		{
			name:          "unknown otel_schema_variant fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md: makeMD(baseV1BQ, map[string]string{
				LabelSchemaMajor: "0", LabelSchemaMinor: "3", LabelSchemaPatch: "0", LabelSchemaVariant: "lean",
			}),
			wantErrSubstr: "unsupported otel_schema_variant",
		},
		{
			name:          "extra nullable field admits",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md:            makeMD(withExtraField("custom_nullable", false), ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "extra required field fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md:            makeMD(withExtraField("custom_required", true), ContractLabels(ContractV1Candidate)),
			wantErrSubstr: "extra REQUIRED field",
		},
		{
			name:          "REQUIRED to NULLABLE relaxation on destination table admits",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
			md:            makeMD(withChangedMode("time_unix_nano", false), ContractLabels(ContractV1Candidate)),
		},
		{
			name:          "NULLABLE to REQUIRED tightening on destination table fails fast",
			writerMajor:   0,
			writerMinor:   3,
			writerVersion: Version,
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
	"REGEXP_EXTRACT": true, "TO_JSON_STRING": true,
	"TIMESTAMP_SUB": true, "TIMESTAMP_ADD": true, "INTERVAL": true, "HOUR": true,
	"DISTINCT": true, "LEFT": true, "JOIN": true, "ON": true,
	"WITH": true, "ORDER": true, "BY": true,
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

// sqlTopLevelKeyword returns the byte offset of the first occurrence of the
// keyword kw (upper-case) in upper that sits outside every parenthesis, or -1.
func sqlTopLevelKeyword(upper, kw string) int {
	depth := 0
	for i := 0; i < len(upper); i++ {
		switch upper[i] {
		case '(':
			depth++
			continue
		case ')':
			if depth > 0 {
				depth--
			}
			continue
		}
		if depth != 0 || !strings.HasPrefix(upper[i:], kw) {
			continue
		}
		before := i == 0 || !isSQLIdentByte(upper[i-1])
		after := i+len(kw) == len(upper) || !isSQLIdentByte(upper[i+len(kw)])
		if before && after {
			return i
		}
	}
	return -1
}

func isSQLIdentByte(c byte) bool {
	return c == '_' || c == '.' || ('0' <= c && c <= '9') || ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z')
}

// sqlUnnestAliasRE finds the names a correlated subquery binds over an array:
// UNNEST(...) AS name [WITH OFFSET AS pos].
var sqlUnnestAliasRE = regexp.MustCompile(`(?i)\)\s+AS\s+([a-z_][a-z0-9_]*)(?:\s+WITH\s+OFFSET\s+AS\s+([a-z_][a-z0-9_]*))?`)

// sqlFunctionCallRE matches an identifier path that is called, such as
// STRING_AGG( or SAFE.FROM_HEX(; it names a function, not a column.
var sqlFunctionCallRE = regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\s*\(`)

// sqlUnnestAliases returns the names that FROM UNNEST(...) AS name [WITH OFFSET
// AS pos] binds anywhere in cleaned, so a scalar subquery of a SELECT item may
// read its own array element and offset.
func sqlUnnestAliases(cleaned string) map[string]bool {
	aliases := map[string]bool{}
	upper := strings.ToUpper(cleaned)
	for i := 0; ; {
		j := strings.Index(upper[i:], "UNNEST")
		if j < 0 {
			return aliases
		}
		start := i + j + len("UNNEST")
		open := strings.IndexByte(cleaned[start:], '(')
		if open < 0 {
			return aliases
		}
		depth, end := 0, -1
		for k := start + open; k < len(cleaned) && end < 0; k++ {
			switch cleaned[k] {
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
			return aliases
		}
		if m := sqlUnnestAliasRE.FindStringSubmatchIndex(cleaned[end:]); m != nil && m[0] == 0 {
			aliases[cleaned[end+m[2]:end+m[3]]] = true
			if m[4] >= 0 {
				aliases[cleaned[end+m[4]:end+m[5]]] = true
			}
		}
		i = end
	}
}

func findInvalidSingleTableColumns(sql string, validPaths map[string]bool) []string {
	cleaned := stripSQLCommentsAndLiterals(sql)
	upper := strings.ToUpper(cleaned)
	selIdx := sqlTopLevelKeyword(upper, "SELECT")
	fromIdx := sqlTopLevelKeyword(upper, "FROM")
	if selIdx < 0 || fromIdx < 0 || fromIdx <= selIdx {
		return []string{"missing SELECT ... FROM structure"}
	}
	selectBody := cleaned[selIdx+len("SELECT") : fromIdx]
	whereBody := ""
	if whereIdx := sqlTopLevelKeyword(upper[fromIdx:], "WHERE"); whereIdx >= 0 {
		whereBody = cleaned[fromIdx+whereIdx+len("WHERE"):]
	}
	local := sqlUnnestAliases(selectBody)

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
		calls := map[int]bool{}
		for _, m := range sqlFunctionCallRE.FindAllStringIndex(expr, -1) {
			calls[m[0]] = true
		}
		for _, loc := range sqlIdentPathRE.FindAllStringIndex(expr, -1) {
			tok := expr[loc[0]:loc[1]]
			if sqlNonColumnKeywords[strings.ToUpper(tok)] || calls[loc[0]] || local[tok] {
				continue
			}
			if strings.EqualFold(tok, "r") && strings.HasPrefix(expr[loc[1]:], "'") {
				continue // the prefix of a raw string literal r'...'
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

	spansPaths := buildSchemaFieldPathSet(SpansTableSchema())
	logsPaths := buildSchemaFieldPathSet(LogsTableSchema())
	metricsPaths := buildSchemaFieldPathSet(MetricsTableSchema())

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
		{LogsAsAllLogsViewName, allQueries[LogsAsAllLogsViewName], logsPaths},
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

	// Negative controls: legacy v0alpha2 queries referencing dropped columns must fail conformance checks.
	if bad := findInvalidSingleTableColumns("SELECT trace_id, attributes_schema, payload_refs FROM `proj.ds.otel_spans_dedup`", spansPaths); !slices.Contains(bad, "attributes_schema") || !slices.Contains(bad, "payload_refs") {
		t.Fatalf("expected legacy v0alpha2 single-table query to fail v1 conformance on dropped columns, got %v", bad)
	}
	if bad := findInvalidAliasedColumns("SELECT l.body, l.payload_refs FROM `proj.ds.otel_logs_dedup` l", map[string]map[string]bool{"l": logsPaths, "s": spansPaths}); !slices.Contains(bad, "l.payload_refs") {
		t.Fatalf("expected legacy v0alpha2 aliased query to fail v1 conformance on l.payload_refs, got %v", bad)
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
		ContractV1Candidate, SpansTableSchema(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(60)},
	)
	if err != nil {
		t.Fatalf("60 customer labels under ContractV1Candidate failed: %v", err)
	}
	if len(md60.Labels) != MaxBigQueryLabels {
		t.Fatalf("merged label count = %d, want %d", len(md60.Labels), MaxBigQueryLabels)
	}

	if _, _, err := DestinationMetadataForContract(
		ContractV1Candidate, SpansTableSchema(), "proj", "ds", "otel_spans",
		DestinationOptions{Labels: makeLabels(61)},
	); err == nil || !strings.Contains(err.Error(), "64-label limit") || !strings.Contains(err.Error(), "4 reserved") {
		t.Fatalf("61 customer labels err = %v, want 64-label limit and 4 reserved error", err)
	}

	if _, err := QuarantineDestinationMetadataForContract(
		ContractV1Candidate, DestinationOptions{Labels: makeLabels(61)},
	); err == nil || !strings.Contains(err.Error(), "64-label limit") {
		t.Fatalf("quarantine 61 customer labels err = %v, want 64-label limit error", err)
	}

	// Programmatic reserved otel_schema_* keys (such as otel_schema_custom) are stripped.
	tbl := SpansTableSchemaForContract(ContractV1Candidate)
	md, _, err := DestinationMetadataForContract(ContractV1Candidate, tbl, "proj", "ds", "otel_spans", DestinationOptions{
		Labels: map[string]string{
			"env":                "prod",
			"otel_schema_custom": "injected",
			"OTEL_SCHEMA_EXTRA":  "injected",
		},
	})
	if err != nil {
		t.Fatalf("DestinationMetadataForContract(%s) error: %v", ContractV1Candidate, err)
	}
	if _, exists := md.Labels["otel_schema_custom"]; exists {
		t.Errorf("leaked programmatic otel_schema_custom label")
	}
	if _, exists := md.Labels["OTEL_SCHEMA_EXTRA"]; exists {
		t.Errorf("leaked programmatic OTEL_SCHEMA_EXTRA label")
	}
	if md.Labels["env"] != "prod" {
		t.Errorf("dropped non-reserved label env: %v", md.Labels)
	}
}

func TestValidateTableLabels(t *testing.T) {
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

func snapshotFieldsToBQSchema(fields []FieldSnapshot) bq.Schema {
	out := make(bq.Schema, 0, len(fields))
	for _, f := range fields {
		typ := bq.FieldType(f.Type)
		switch f.Type {
		case "INT64":
			typ = bq.IntegerFieldType
		case "FLOAT64":
			typ = bq.FloatFieldType
		case "STRUCT":
			typ = bq.RecordFieldType
		case "BOOL":
			typ = bq.BooleanFieldType
		}
		fs := &bq.FieldSchema{
			Name:     f.Name,
			Type:     typ,
			Required: f.Mode == "REQUIRED",
			Repeated: f.Mode == "REPEATED",
		}
		if len(f.Fields) > 0 {
			fs.Schema = snapshotFieldsToBQSchema(f.Fields)
		}
		out = append(out, fs)
	}
	return out
}

func TestValidateRejectsLegacyV0Alpha2ShapeUnconditionally(t *testing.T) {
	raw, err := os.ReadFile("testdata/v0alpha2_golden.json")
	if err != nil {
		t.Fatalf("reading testdata/v0alpha2_golden.json: %v", err)
	}
	var snap SchemaSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		t.Fatalf("unmarshaling testdata/v0alpha2_golden.json: %v", err)
	}
	legacyByName := make(map[string]bq.Schema, len(snap.Tables))
	for _, tbl := range snap.Tables {
		legacyByName[tbl.Name] = snapshotFieldsToBQSchema(tbl.Fields)
	}

	relaxSchemaVersion := func(in bq.Schema) bq.Schema {
		out := make(bq.Schema, len(in))
		for i, f := range in {
			cp := *f
			if cp.Name == "schema_version" {
				cp.Required = false
			}
			out[i] = &cp
		}
		return out
	}

	for _, tc := range []struct {
		name  string
		table string
		want  *storagepb.TableSchema
	}{
		{name: "otel_metrics with NULLABLE schema_version", table: "otel_metrics", want: MetricsTableSchema()},
		{name: "otel_quarantine with NULLABLE schema_version", table: "otel_quarantine", want: QuarantineTableSchema()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relaxedBQ := relaxSchemaVersion(legacyByName[tc.table])
			havePB, err := FromBigQuery(relaxedBQ)
			if err != nil {
				t.Fatalf("FromBigQuery: %v", err)
			}
			if diffs := CompatibilityDifferences(tc.want, havePB); len(diffs) != 0 {
				t.Fatalf("precondition failed: expected empty CompatibilityDifferences for %s with NULLABLE schema_version, got %v", tc.name, diffs)
			}

			for labelSetName, labels := range map[string]map[string]string{
				"unlabeled": nil,
				"0.3.0":     ContractLabels(ContractV1Candidate),
			} {
				t.Run(labelSetName, func(t *testing.T) {
					md := &bq.TableMetadata{
						FullID: "proj:ds." + tc.table,
						Schema: relaxedBQ,
						Labels: labels,
					}
					_, err := ValidateTableLabelsAndStructure(ContractV1Candidate, tc.want, md, "table proj.ds."+tc.table)
					if err == nil {
						t.Fatal("ValidateTableLabelsAndStructure succeeded on legacy v0alpha2 schema, want rejection")
					}
					if !strings.Contains(err.Error(), "v0alpha2") || !strings.Contains(err.Error(), migrationGuideURL) {
						t.Fatalf("err = %v, want v0alpha2 and %s", err, migrationGuideURL)
					}
				})
			}
		})
	}

	t.Run("nested resource.attributes_schema NULLABLE only", func(t *testing.T) {
		spansBQ, err := ToBigQuery(SpansTableSchema())
		if err != nil {
			t.Fatal(err)
		}
		var patched bq.Schema
		for _, f := range spansBQ {
			cp := *f
			if cp.Name == "resource" {
				cp.Schema = append(slices.Clone(cp.Schema), &bq.FieldSchema{
					Name: "attributes_schema",
					Type: bq.JSONFieldType,
				})
			}
			patched = append(patched, &cp)
		}
		havePB, err := FromBigQuery(patched)
		if err != nil {
			t.Fatal(err)
		}
		if diffs := CompatibilityDifferences(SpansTableSchema(), havePB); len(diffs) != 0 {
			t.Fatalf("precondition failed: expected empty CompatibilityDifferences, got %v", diffs)
		}
		md := &bq.TableMetadata{
			FullID: "proj:ds.otel_spans",
			Schema: patched,
			Labels: ContractLabels(ContractV1Candidate),
		}
		_, err = ValidateTableLabelsAndStructure(ContractV1Candidate, SpansTableSchema(), md, "destination table proj.ds.otel_spans")
		if err == nil || !strings.Contains(err.Error(), "v0alpha2") || !strings.Contains(err.Error(), migrationGuideURL) {
			t.Fatalf("err = %v, want v0alpha2 and %s", err, migrationGuideURL)
		}
	})

	t.Run("positive control extra benign NULLABLE column passes", func(t *testing.T) {
		spansBQ, err := ToBigQuery(SpansTableSchema())
		if err != nil {
			t.Fatal(err)
		}
		withCustom := append(slices.Clone(spansBQ), &bq.FieldSchema{
			Name: "custom_note",
			Type: bq.StringFieldType,
		})
		md := &bq.TableMetadata{
			FullID: "proj:ds.otel_spans",
			Schema: withCustom,
			Labels: ContractLabels(ContractV1Candidate),
		}
		warnings, err := ValidateTableLabelsAndStructure(ContractV1Candidate, SpansTableSchema(), md, "destination table proj.ds.otel_spans")
		if err != nil {
			t.Fatalf("unexpected error on valid v0alpha3 table with extra NULLABLE column: %v", err)
		}
		if len(warnings) != 0 {
			t.Fatalf("unexpected warnings: %v", warnings)
		}
	})
}
