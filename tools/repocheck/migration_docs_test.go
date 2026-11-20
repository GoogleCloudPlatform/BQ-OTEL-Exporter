// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
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
	raw := testsupport.ReadRepoText(t, filepath.Join("internal", "schema", "testdata", "v0alpha2_golden.json"))
	var snap v0Alpha2GoldenSnapshot
	if err := json.Unmarshal([]byte(raw), &snap); err != nil {
		t.Fatalf("parse v0alpha2_golden.json: %v", err)
	}
	if snap.Version != "v0alpha2" {
		t.Fatalf("golden version = %q, want v0alpha2", snap.Version)
	}
	return snap
}

// TestMigrationDocsCutoffsAndChecksContract verifies that the SQL runbook in
// docs/migration.md keeps the expected table aliases, avoids IS NOT DISTINCT
// FROM in favor of equality + IS NULL, documents the rolling-update drain and
// no-rebuild invariants, and references only columns that exist in the v0alpha2
// and v1.0.0 golden schemas.
func TestMigrationDocsCutoffsAndChecksContract(t *testing.T) {
	doc := testsupport.ReadRepoText(t, filepath.Join("docs", "migration.md"))

	for _, want := range []string{
		"FROM `my-project.otel_v0alpha2.otel_logs` AS otel_logs",
		"FROM `my-project.otel_v0alpha2.otel_metrics` AS otel_metrics",
		"FROM `my-project.otel_v0alpha2.otel_quarantine` AS otel_quarantine",
		"(c.service_name = otel_logs.service_name OR (c.service_name IS NULL AND otel_logs.service_name IS NULL))",
		"(n.service_name = l.service_name OR (n.service_name IS NULL AND l.service_name IS NULL))",
		"(n.service_name = m.service_name OR (n.service_name IS NULL AND m.service_name IS NULL))",
		"(n.service_name = s.service_name OR (n.service_name IS NULL AND s.service_name IS NULL))",
		"(c.service_name = r.service_name OR (c.service_name IS NULL AND r.service_name IS NULL))",
		"COALESCE(NULLIF(l.insert_id, ''), l.record_fingerprint)",
		"DELETE FROM `my-project.otel_migration.v1_cutoffs_logs`",
		"do not rebuild it afterward",
		"AS missing_logs",
		"AS missing_metrics",
		"AS missing_spans",
		"SELECT 'v0alpha2' AS source, service_name, ingest_time",
		"SELECT 'v1' AS source, service_name, ingest_time",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/migration.md missing expected runbook fragment %q", want)
		}
	}

	// Copying an old window into a table whose partition expiration it is past
	// silently loses the rows (BigQuery marks those partitions expired right
	// away and deletes them asynchronously in the background, so a check run
	// right after the copy can still see them), so the runbook must name the
	// quarantine default the DDL really uses, explain the asynchronous background
	// deletion, show how to lift it, and say how to address the NULL
	// service_name cutoff row.
	quarantineExpiration := fmt.Sprintf("partition_expiration_days = %d", schema.DefaultQuarantinePartitionExpirationDays)
	if ddl := schema.QuarantineDDL; !strings.Contains(ddl, quarantineExpiration) {
		t.Fatalf("schema.QuarantineDDL does not set %s", quarantineExpiration)
	}
	for _, want := range []string{
		"with `" + quarantineExpiration + "`",
		"asynchronously in the background",
		"SET OPTIONS (partition_expiration_days = NULL);",
		"`WHERE service_name IS NULL`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/migration.md missing expected runbook fragment %q", want)
		}
	}

	v2Snap := loadV0Alpha2Golden(t)
	v3Raw := testsupport.ReadRepoText(t, filepath.Join("internal", "schema", "testdata", "v1.0.0_golden.json"))
	var v3Snap v0Alpha2GoldenSnapshot
	if err := json.Unmarshal([]byte(v3Raw), &v3Snap); err != nil {
		t.Fatalf("parse v1.0.0_golden.json: %v", err)
	}

	colsByTable := func(snap v0Alpha2GoldenSnapshot) map[string]map[string]bool {
		out := make(map[string]map[string]bool, len(snap.Tables))
		for _, tbl := range snap.Tables {
			cols := make(map[string]bool, len(tbl.Fields))
			for _, f := range tbl.Fields {
				cols[f.Name] = true
			}
			out[tbl.Name] = cols
		}
		return out
	}
	v2Cols := colsByTable(v2Snap)
	v3Cols := colsByTable(v3Snap)

	sqlBlocks := extractSQLCodeBlocks(doc)
	if len(sqlBlocks) < 7 {
		t.Fatalf("extracted %d SQL blocks from docs/migration.md, want >= 7", len(sqlBlocks))
	}
	for i, block := range sqlBlocks {
		if strings.Contains(strings.ToUpper(strings.Join(strings.Fields(block), " ")), "IS NOT DISTINCT FROM") {
			t.Errorf("docs/migration.md SQL block #%d must avoid IS NOT DISTINCT FROM and use equality + IS NULL predicates", i+1)
		}
	}

	// Validate aliased column references in the copy filter and completeness checks.
	checkAliasCols := func(label, sqlText string, aliasMap map[string]map[string]bool) []string {
		var problems []string
		colRef := regexp.MustCompile(`\b([a-z_]+)\.([a-z_]+)\b`)
		for _, match := range colRef.FindAllStringSubmatch(sqlText, -1) {
			alias, col := match[1], match[2]
			allowed, tracked := aliasMap[alias]
			if !tracked {
				continue
			}
			if !allowed[col] {
				problems = append(problems, fmt.Sprintf("%s references unknown column %s.%s", label, alias, col))
			}
		}
		return problems
	}

	cutoffCols := map[string]bool{"service_name": true, "cutoff": true}
	var checkedLogsCheck, checkedMetricsCheck, checkedSpansCheck, checkedQuarantineCheck bool
	for _, block := range sqlBlocks {
		for stmt := range strings.SplitSeq(block, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			switch {
			case strings.Contains(stmt, "AS missing_logs"):
				checkedLogsCheck = true
				for _, p := range checkAliasCols("logs completeness check", stmt, map[string]map[string]bool{
					"l": v2Cols["otel_logs"],
					"n": v3Cols["otel_logs"],
					"c": cutoffCols,
				}) {
					t.Error(p)
				}
			case strings.Contains(stmt, "AS missing_metrics"):
				checkedMetricsCheck = true
				for _, p := range checkAliasCols("metrics completeness check", stmt, map[string]map[string]bool{
					"m": v2Cols["otel_metrics"],
					"n": v3Cols["otel_metrics"],
					"c": cutoffCols,
				}) {
					t.Error(p)
				}
			case strings.Contains(stmt, "AS missing_spans"):
				checkedSpansCheck = true
				for _, p := range checkAliasCols("spans completeness check", stmt, map[string]map[string]bool{
					"s": v2Cols["otel_spans"],
					"n": v3Cols["otel_spans"],
				}) {
					t.Error(p)
				}
			case strings.Contains(stmt, "v0alpha2_to_copy"):
				checkedQuarantineCheck = true
				for _, p := range checkAliasCols("quarantine count check", stmt, map[string]map[string]bool{
					"r": {"source": true, "service_name": true, "ingest_time": true},
					"c": cutoffCols,
				}) {
					t.Error(p)
				}
			case strings.Contains(stmt, "v1_cutoffs_logs") && strings.Contains(stmt, "otel_logs.receive_time"):
				for _, p := range checkAliasCols("logs cutoff filter", stmt, map[string]map[string]bool{
					"otel_logs": v2Cols["otel_logs"],
					"c":         cutoffCols,
				}) {
					t.Error(p)
				}
			}
		}
	}
	if !checkedLogsCheck || !checkedMetricsCheck || !checkedSpansCheck || !checkedQuarantineCheck {
		t.Fatalf("did not locate all completeness checks (logs=%v metrics=%v spans=%v quarantine=%v)",
			checkedLogsCheck, checkedMetricsCheck, checkedSpansCheck, checkedQuarantineCheck)
	}

	// Negative control: the column validator must catch a dropped v0alpha2 column on v1 alias n.
	bad := checkAliasCols("negative control", "SELECT 1 FROM v1 n WHERE n.record_fingerprint = l.record_fingerprint", map[string]map[string]bool{
		"l": v2Cols["otel_logs"],
		"n": v3Cols["otel_logs"],
	})
	if len(bad) != 1 || !strings.Contains(bad[0], "n.record_fingerprint") {
		t.Fatalf("negative control problems = %v, want 1 error for n.record_fingerprint", bad)
	}
}

func extractSQLCodeBlocks(md string) []string {
	var blocks []string
	var buf strings.Builder
	inSQL := false
	for line := range strings.SplitSeq(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if !inSQL {
			if trimmed == "```sql" {
				inSQL = true
				buf.Reset()
			}
			continue
		}
		if trimmed == "```" {
			inSQL = false
			blocks = append(blocks, buf.String())
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	return blocks
}
