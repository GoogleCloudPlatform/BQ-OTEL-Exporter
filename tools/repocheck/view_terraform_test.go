// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

func TestTerraformBoundedWindowTVFsMatchSchemaContract(t *testing.T) {
	const (
		confProject = "p"
		confDataset = "d"
		confSpans   = "otel_spans"
		confLogs    = "otel_logs"
	)
	tf := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	replacer := strings.NewReplacer(
		"${var.project_id}", confProject,
		"${google_bigquery_dataset.otel.dataset_id}", confDataset,
		"${google_bigquery_table.otel_spans_dedup.table_id}", confSpans+"_dedup",
		"${google_bigquery_table.otel_logs_dedup.table_id}", confLogs+"_dedup",
		"${google_bigquery_table.v_gen_ai_spans.table_id}", schema.GenAISpansViewName,
		"${google_bigquery_table.v_gen_ai_metrics.table_id}", schema.GenAIMetricsViewName,
	)
	tf = replacer.Replace(tf)

	wantQueries := schema.CompanionTVFQueries(confProject, confDataset, confSpans, confLogs)
	argRe := regexp.MustCompile(`(?s)arguments\s*\{\s*name\s*=\s*"([^"]+)"\s*data_type\s*=\s*jsonencode\(\{\s*typeKind\s*=\s*"([^"]+)"\s*\}\)\s*\}`)
	for tvfName, wantQuery := range wantQueries {
		blockRe := regexp.MustCompile(`(?s)resource "google_bigquery_routine" "` + regexp.QuoteMeta(tvfName) + `" \{(.*?)\n\}`)
		bm := blockRe.FindStringSubmatch(tf)
		if bm == nil {
			t.Fatalf("deploy/terraform/main.tf missing google_bigquery_routine %q", tvfName)
		}
		block := bm[1]
		if !regexp.MustCompile(`routine_id\s*=\s*"` + regexp.QuoteMeta(tvfName) + `"`).MatchString(block) {
			t.Errorf("Terraform routine %s missing routine_id = %q", tvfName, tvfName)
		}
		if !regexp.MustCompile(`routine_type\s*=\s*"TABLE_VALUED_FUNCTION"`).MatchString(block) {
			t.Errorf("Terraform routine %s missing routine_type = \"TABLE_VALUED_FUNCTION\"", tvfName)
		}
		if !regexp.MustCompile(`language\s*=\s*"SQL"`).MatchString(block) {
			t.Errorf("Terraform routine %s missing language = \"SQL\"", tvfName)
		}
		args := argRe.FindAllStringSubmatch(block, -1)
		if tvfName == schema.GenAIAgentTrajectoryTVFName {
			if len(args) != 4 ||
				args[0][1] != "start_ts" || args[0][2] != "TIMESTAMP" ||
				args[1][1] != "end_ts" || args[1][2] != "TIMESTAMP" ||
				args[2][1] != "context_start_ts" || args[2][2] != "TIMESTAMP" ||
				args[3][1] != "context_end_ts" || args[3][2] != "TIMESTAMP" {
				t.Errorf("Terraform routine %s arguments = %v, want [(start_ts TIMESTAMP), (end_ts TIMESTAMP), (context_start_ts TIMESTAMP), (context_end_ts TIMESTAMP)]", tvfName, args)
			}
		} else if len(args) != 2 ||
			args[0][1] != "start_ts" || args[0][2] != "TIMESTAMP" ||
			args[1][1] != "end_ts" || args[1][2] != "TIMESTAMP" {
			t.Errorf("Terraform routine %s arguments = %v, want [(start_ts TIMESTAMP), (end_ts TIMESTAMP)]", tvfName, args)
		}

		bodyRe := regexp.MustCompile(`(?s)definition_body\s*=\s*<<-?EOT\n(.*?)\n\s*EOT`)
		m := bodyRe.FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("deploy/terraform/main.tf routine %q missing definition_body heredoc", tvfName)
		}
		gotTokens := strings.Fields(testsupport.StripSQLComments(m[1]))
		wantTokens := strings.Fields(testsupport.StripSQLComments(wantQuery))
		if !slices.Equal(gotTokens, wantTokens) {
			t.Errorf("Terraform routine %s definition_body drifted from schema.CompanionTVFQueries:\ngot:\n%s\nwant:\n%s",
				tvfName, strings.Join(gotTokens, " "), strings.Join(wantTokens, " "))
		}
	}
}

func TestTerraformOtelAlertsSchemaMatchesDDL(t *testing.T) {
	tf := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	re := regexp.MustCompile(`(?s)resource "google_bigquery_table" "otel_alerts" \{(.*?)schema\s*=\s*jsonencode\(\[(.*?)\]\)`)
	m := re.FindStringSubmatch(tf)
	if m == nil {
		t.Fatal("deploy/terraform/main.tf missing google_bigquery_table.otel_alerts schema")
	}
	header := m[1]
	if !regexp.MustCompile(`type\s*=\s*"DAY"`).MatchString(header) || !regexp.MustCompile(`field\s*=\s*"event_time"`).MatchString(header) {
		t.Errorf("otel_alerts time_partitioning missing DAY on event_time:\n%s", header)
	}
	if !strings.Contains(header, `clustering = ["alert_kind", "service_name"]`) {
		t.Errorf("otel_alerts clustering missing [\"alert_kind\", \"service_name\"]:\n%s", header)
	}
	fieldRe := regexp.MustCompile(`\{\s*name\s*=\s*"([^"]+)",\s*type\s*=\s*"([^"]+)",\s*mode\s*=\s*"([^"]+)"\s*\}`)
	matches := fieldRe.FindAllStringSubmatch(m[2], -1)

	type colSpec struct{ name, typ, mode string }
	want := []colSpec{
		{"alert_id", "STRING", "REQUIRED"},
		{"alert_kind", "STRING", "REQUIRED"},
		{"event_time", "TIMESTAMP", "REQUIRED"},
		{"service_name", "STRING", "NULLABLE"},
		{"trace_id", "STRING", "REQUIRED"},
		{"span_id", "STRING", "REQUIRED"},
		{"payload", "JSON", "NULLABLE"},
	}
	if len(matches) != len(want) {
		t.Fatalf("otel_alerts schema has %d columns, want %d: %v", len(matches), len(want), matches)
	}
	var colNames []string
	for i, w := range want {
		got := colSpec{matches[i][1], matches[i][2], matches[i][3]}
		if got != w {
			t.Errorf("otel_alerts column[%d] = %+v, want %+v", i, got, w)
		}
		colNames = append(colNames, w.name)
	}

	cqReadme := testsupport.ReadRepoText(t, "deploy/continuous-queries/README.md")
	wantInsertCols := strings.Join(colNames, ", ")
	if !strings.Contains(cqReadme, wantInsertCols) {
		t.Errorf("deploy/continuous-queries/README.md INSERT INTO otel_alerts column list does not contain %q", wantInsertCols)
	}
}
