// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	bq "cloud.google.com/go/bigquery"
	"gopkg.in/yaml.v3"

	bqi "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/bigquery"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// TestReadmeQuotesStartupErrors keeps the README's startup-error table tied to
// the messages the exporter actually returns. Credential and Compose messages
// come from other code and are proven by the collector-example CI job instead.
func TestReadmeQuotesStartupErrors(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	ctx := context.Background()

	cfg := validConfig()
	e := newTestSignalExporter(cfg, cfg.Traces.Table, schema.SpansTableSchema())
	missingDataset := e.prepareDestination(ctx, &fakeDestinationAdmin{datasetMetadataErr: notFound()})
	missingTable := e.prepareDestination(ctx, &fakeDestinationAdmin{
		datasetMetadata:  &bq.DatasetMetadata{},
		tableMetadataErr: notFound(),
	})

	createCfg := validConfig()
	createCfg.AutoCreate.Tables = true
	denied := forbidden()
	createDenied := newTestSignalExporter(createCfg, createCfg.Traces.Table, schema.SpansTableSchema()).
		prepareDestination(ctx, &fakeDestinationAdmin{
			datasetMetadata:  &bq.DatasetMetadata{},
			tableMetadataErr: notFound(),
			createTableErr:   denied,
		})

	for _, err := range []error{missingDataset, missingTable, createDenied} {
		if err == nil {
			t.Fatal("prepareDestination succeeded; want a startup error")
		}
	}
	for name, want := range map[string]string{
		"missing dataset": missingDataset.Error(),
		"missing table":   missingTable.Error(),
		// The README quotes the exporter's prefix; BigQuery supplies the rest.
		"create denied": strings.TrimSpace(strings.TrimSuffix(createDenied.Error(), denied.Error())),
		"append denied": bqi.PermissionHint(e.tableID()),
	} {
		if !strings.Contains(readme, "`"+want+"`") {
			t.Errorf("README does not quote the %s error %q", name, want)
		}
	}
}

func TestReadmeReflectsV0Alpha2Contract(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)

	spansIndexDDL := strings.TrimSpace(fmt.Sprintf(schema.SpansSearchIndexDDL, "my-project", "otel", "otel_spans"))
	logsIndexDDL := strings.TrimSpace(fmt.Sprintf(schema.LogsSearchIndexDDL, "my-project", "otel", "otel_logs"))

	for _, required := range []string{
		"logs.log_name_attribute",
		"logs.insert_id_attribute",
		"metrics.table",
		"otel_metrics",
		"otel_metrics_dedup",
		"auto_create.companion_views",
		"auto_create.search_indexes",
		"quarantine.enabled",
		"quarantine.table",
		"require_partition_filter",
		"credentials.json",
		"credentials.impersonate_delegates",
		"credentials.quota_project",
		"credentials.universe_domain",
		"endpoint.admin_url",
		"attributes_schema",
		"payload_refs",
		"otel_spans_as_allspans",
		"v_gen_ai_spans",
		"v_gen_ai_model_costs",
		"v_gen_ai_sessions",
		"v_gen_ai_tool_usage",
		"v_gen_ai_logs",
		"otel_quarantine",
		"otelcol_exporter_bigquery_quarantined_rows",
		"otelcol_exporter_bigquery_append_bytes",
		"redaction.enabled",
		"redaction.blocked_keys",
		"redaction.blocked_value_patterns",
		"otelcol_exporter_bigquery_redacted_values",
		"offload.cache_size",
		"otelcol_exporter_bigquery_offload_dedup_hits",
		"write.backpressure.enabled",
		"otelcol_exporter_bigquery_backpressure_level",
		"otelcol_exporter_bigquery_effective_request_bytes",
		"otelcol_exporter_bigquery_backpressure_events",
		"v0alpha2",
		"Operating v0alpha2 tables",
		"TIMESTAMP_TRUNC(start_time, HOUR)",
		"10,000",
		"416",
		"partition_expiration_days",
		"ALTER TABLE",
		"CREATE SEARCH INDEX",
		"otel_spans_trace_lookup_idx",
		"otel_logs_trace_lookup_idx",
		"otel_metrics_trace_lookup_idx",
		"NO_OP_ANALYZER",
		"bigquery.jobs.create",
		spansIndexDDL,
		logsIndexDDL,
	} {
		if !strings.Contains(readme, required) {
			t.Errorf("README.md is missing v0alpha2 contract token %q", required)
		}
	}

	for _, retired := range []string{
		"source_record_namespace",
		"source_record_id_attribute",
		"otlp-protojson-v1",
		"attributes_fingerprint",
	} {
		if strings.Contains(readme, retired) {
			t.Errorf("README.md still references retired v0alpha1 token %q", retired)
		}
	}
}

type readmeMetadataMetric struct {
	Unit       string   `yaml:"unit"`
	Attributes []string `yaml:"attributes"`
	Sum        *struct {
		Monotonic bool   `yaml:"monotonic"`
		ValueType string `yaml:"value_type"`
	} `yaml:"sum"`
	Gauge *struct {
		ValueType string `yaml:"value_type"`
	} `yaml:"gauge"`
	Histogram *struct {
		ValueType string `yaml:"value_type"`
	} `yaml:"histogram"`
}

func (m readmeMetadataMetric) typeLabel() string {
	switch {
	case m.Sum != nil && m.Sum.Monotonic:
		return fmt.Sprintf("Counter (%s)", m.Sum.ValueType)
	case m.Sum != nil && !m.Sum.Monotonic:
		return fmt.Sprintf("UpDownCounter (%s)", m.Sum.ValueType)
	case m.Gauge != nil:
		return fmt.Sprintf("Gauge (%s)", m.Gauge.ValueType)
	case m.Histogram != nil:
		return fmt.Sprintf("Histogram (%s)", m.Histogram.ValueType)
	default:
		return "unknown"
	}
}

type readmeMetadataDoc struct {
	Telemetry struct {
		Metrics map[string]readmeMetadataMetric `yaml:"metrics"`
	} `yaml:"telemetry"`
}

type readmeTelemetryRow struct {
	Metric  string
	Type    string
	Unit    string
	Attrs   []string
	Meaning string
}

func splitMarkdownRow(line string) []string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimPrefix(trimmed, "|")
	trimmed = strings.TrimSuffix(trimmed, "|")
	parts := strings.Split(trimmed, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func isMarkdownSeparatorRow(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		if len(c) < 3 {
			return false
		}
		dashes := 0
		for _, r := range c {
			switch r {
			case '-':
				dashes++
			case ':':
			default:
				return false
			}
		}
		if dashes < 3 {
			return false
		}
	}
	return true
}

func unwrapInlineCode(cell string) (string, bool) {
	c := strings.TrimSpace(cell)
	if len(c) < 2 || !strings.HasPrefix(c, "`") || !strings.HasSuffix(c, "`") {
		return "", false
	}
	inner := c[1 : len(c)-1]
	if strings.Contains(inner, "`") {
		return "", false
	}
	return strings.TrimSpace(inner), true
}

func parseReadmeMetricAttrs(spec string) ([]string, error) {
	if spec == "none" {
		return nil, nil
	}
	if !strings.HasPrefix(spec, "{") || !strings.HasSuffix(spec, "}") {
		return nil, fmt.Errorf("attributes %q must be `none` or `{attr1, attr2}`", spec)
	}
	inner := strings.TrimSpace(spec[1 : len(spec)-1])
	if inner == "" {
		return nil, fmt.Errorf("empty attribute braces %q; use `none`", spec)
	}
	seen := map[string]bool{}
	var attrs []string
	for _, part := range strings.Split(inner, ",") {
		attr := strings.TrimSpace(part)
		if attr == "" {
			return nil, fmt.Errorf("empty attribute in %q", spec)
		}
		if seen[attr] {
			return nil, fmt.Errorf("duplicate attribute %q in %q", attr, spec)
		}
		seen[attr] = true
		attrs = append(attrs, attr)
	}
	slices.Sort(attrs)
	return attrs, nil
}

func formatAttrSet(attrs []string) string {
	if len(attrs) == 0 {
		return "none"
	}
	sorted := slices.Clone(attrs)
	slices.Sort(sorted)
	return "{" + strings.Join(sorted, ", ") + "}"
}

func parseReadmeSelfTelemetrySection(readme string) ([]readmeTelemetryRow, string, error) {
	const anchor = "Use these content-free self-telemetry instruments"
	idx := strings.Index(readme, anchor)
	if idx < 0 {
		return nil, "", fmt.Errorf("README.md is missing self-telemetry intro %q", anchor)
	}
	lines := strings.Split(strings.ReplaceAll(readme[idx:], "\r\n", "\n"), "\n")

	headerIdx := -1
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "|") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 || headerIdx+1 >= len(lines) {
		return nil, "", fmt.Errorf("README.md self-telemetry markdown table not found after intro")
	}

	header := splitMarkdownRow(lines[headerIdx])
	wantHeader := []string{"Metric", "Type", "Unit", "Attributes", "Meaning"}
	if !slices.Equal(header, wantHeader) {
		return nil, "", fmt.Errorf("self-telemetry table header = %v, want %v", header, wantHeader)
	}
	sep := splitMarkdownRow(lines[headerIdx+1])
	if len(sep) != len(wantHeader) || !isMarkdownSeparatorRow(sep) {
		return nil, "", fmt.Errorf("self-telemetry table separator row %v is malformed", sep)
	}

	var rows []readmeTelemetryRow
	i := headerIdx + 2
	for ; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, "|") {
			break
		}
		cells := splitMarkdownRow(trimmed)
		if len(cells) != len(wantHeader) {
			return nil, "", fmt.Errorf("self-telemetry row %q has %d cells, want %d", trimmed, len(cells), len(wantHeader))
		}
		metricName, ok := unwrapInlineCode(cells[0])
		if !ok || metricName == "" {
			return nil, "", fmt.Errorf("self-telemetry metric cell %q must be single inline code", cells[0])
		}
		typeLabel, ok := unwrapInlineCode(cells[1])
		if !ok || typeLabel == "" {
			return nil, "", fmt.Errorf("self-telemetry type cell %q for %s must be single inline code", cells[1], metricName)
		}
		unit, ok := unwrapInlineCode(cells[2])
		if !ok || unit == "" {
			return nil, "", fmt.Errorf("self-telemetry unit cell %q for %s must be single inline code", cells[2], metricName)
		}
		attrsRaw, ok := unwrapInlineCode(cells[3])
		if !ok || attrsRaw == "" {
			return nil, "", fmt.Errorf("self-telemetry attributes cell %q for %s must be single inline code", cells[3], metricName)
		}
		attrs, err := parseReadmeMetricAttrs(attrsRaw)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", metricName, err)
		}
		if cells[4] == "" {
			return nil, "", fmt.Errorf("%s: meaning cell is empty", metricName)
		}
		rows = append(rows, readmeTelemetryRow{
			Metric:  metricName,
			Type:    typeLabel,
			Unit:    unit,
			Attrs:   attrs,
			Meaning: cells[4],
		})
	}

	var proseLines []string
	for ; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			break
		}
		proseLines = append(proseLines, lines[i])
	}
	return rows, strings.Join(proseLines, "\n"), nil
}

func extractTelemetryGoMetricNames(telemetryGo string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/metadata/telemetry.go", telemetryGo, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing internal/metadata/telemetry.go: %w", err)
	}
	var names []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for idx, ident := range vs.Names {
				if !strings.HasPrefix(ident.Name, "name") || idx >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[idx].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(lit.Value)
				if err != nil || !strings.HasPrefix(val, dashPromPrefix) {
					continue
				}
				names = append(names, val)
			}
		}
	}
	slices.Sort(names)
	return names, nil
}

func validateReadmeSelfTelemetry(readme, metadataYAML, telemetryGo, grafanaJSON string) []string {
	var problems []string

	var md readmeMetadataDoc
	if err := yaml.Unmarshal([]byte(metadataYAML), &md); err != nil {
		return []string{fmt.Sprintf("metadata.yaml: %v", err)}
	}
	if len(md.Telemetry.Metrics) == 0 {
		return []string{"metadata.yaml declares no metrics"}
	}

	rows, prose, err := parseReadmeSelfTelemetrySection(readme)
	if err != nil {
		return []string{err.Error()}
	}

	readmeRows := make(map[string]readmeTelemetryRow, len(rows))
	for _, row := range rows {
		if _, dup := readmeRows[row.Metric]; dup {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry table lists duplicate metric %s", row.Metric))
			continue
		}
		readmeRows[row.Metric] = row
	}

	metaNames := make([]string, 0, len(md.Telemetry.Metrics))
	for name := range md.Telemetry.Metrics {
		metaNames = append(metaNames, name)
	}
	slices.Sort(metaNames)

	for _, name := range metaNames {
		spec := md.Telemetry.Metrics[name]
		row, ok := readmeRows[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry table is missing metric %s declared in metadata.yaml", name))
			continue
		}
		if wantType := spec.typeLabel(); row.Type != wantType {
			problems = append(problems, fmt.Sprintf("README.md metric %s type = %q, metadata.yaml declares %q", name, row.Type, wantType))
		}
		if row.Unit != spec.Unit {
			problems = append(problems, fmt.Sprintf("README.md metric %s unit = %q, metadata.yaml declares %q", name, row.Unit, spec.Unit))
		}
		wantAttrs := slices.Clone(spec.Attributes)
		slices.Sort(wantAttrs)
		if !slices.Equal(row.Attrs, wantAttrs) {
			problems = append(problems, fmt.Sprintf("README.md metric %s attributes = %s, metadata.yaml declares %s", name, formatAttrSet(row.Attrs), formatAttrSet(wantAttrs)))
		}
		if name == "otelcol_exporter_bigquery_offload_dedup_hits" &&
			(!strings.Contains(row.Meaning, "intra-batch") || !strings.Contains(row.Meaning, "cross-batch")) {
			problems = append(problems, "README.md offload_dedup_hits meaning must describe both intra-batch coalescing and cross-batch LRU caches")
		}
	}

	readmeNames := make([]string, 0, len(readmeRows))
	for name := range readmeRows {
		readmeNames = append(readmeNames, name)
	}
	slices.Sort(readmeNames)
	for _, name := range readmeNames {
		if _, ok := md.Telemetry.Metrics[name]; !ok {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry table lists metric %s not declared in metadata.yaml", name))
		}
	}

	if strings.Contains(strings.ToLower(prose), "both current-value instruments") {
		problems = append(problems, `README.md still claims "Both current-value instruments" instead of describing all four non-counter instruments`)
	}
	for _, required := range []string{
		"inflight_requests",
		"unresolved_results",
		"backpressure_level",
		"effective_request_bytes",
		"write.max_request_bytes",
	} {
		if !strings.Contains(prose, required) {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose is missing %q", required))
		}
	}

	if telemetryGo != "" {
		goNames, err := extractTelemetryGoMetricNames(telemetryGo)
		if err != nil {
			problems = append(problems, err.Error())
		} else {
			goSet := map[string]bool{}
			for _, n := range goNames {
				goSet[n] = true
			}
			for _, n := range metaNames {
				if !goSet[n] {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go is missing constant for %s", n))
				}
			}
			for _, n := range goNames {
				if _, ok := md.Telemetry.Metrics[n]; !ok {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go declares %s absent from metadata.yaml", n))
				}
			}
		}
	}

	if grafanaJSON != "" {
		files := dashFileSet{"metadata.yaml": metadataYAML, dashGrafanaProm: grafanaJSON}
		g, p := dashDecodeGrafana(files, dashGrafanaProm)
		problems = append(problems, p...)
		dashMD, err := dashDecodeMetadata(files)
		if err != nil {
			problems = append(problems, err.Error())
		} else if g != nil {
			grafanaSet := map[string]bool{}
			for _, pn := range g.Panels {
				if pn.Type == "row" {
					continue
				}
				for _, tgt := range pn.Targets {
					rs, _ := dashCheckPromExpr(dashMD, tgt.Expr, tgt.LegendFormat)
					for _, r := range rs {
						grafanaSet[r.metric] = true
					}
				}
			}
			for m := range grafanaSet {
				if _, ok := readmeRows[m]; !ok {
					problems = append(problems, fmt.Sprintf("Grafana dashboard reads %s missing from README.md self-telemetry table", m))
				}
			}
			for m := range readmeRows {
				if !grafanaSet[m] {
					problems = append(problems, fmt.Sprintf("README.md self-telemetry table lists %s absent from Grafana collector dashboard", m))
				}
			}
		}
	}

	return problems
}

func TestReadmeSelfTelemetryMatchesMetadataAndTelemetry(t *testing.T) {
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	metaBytes, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	telemetryBytes, err := os.ReadFile("internal/metadata/telemetry.go")
	if err != nil {
		t.Fatal(err)
	}
	grafanaBytes, err := os.ReadFile(dashGrafanaProm)
	if err != nil {
		t.Fatal(err)
	}

	problems := validateReadmeSelfTelemetry(
		string(readmeBytes),
		string(metaBytes),
		string(telemetryBytes),
		string(grafanaBytes),
	)
	for _, problem := range problems {
		t.Error(problem)
	}
}

func TestReadmeSelfTelemetryRejectsMutations(t *testing.T) {
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	metaBytes, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	telemetryBytes, err := os.ReadFile("internal/metadata/telemetry.go")
	if err != nil {
		t.Fatal(err)
	}
	grafanaBytes, err := os.ReadFile(dashGrafanaProm)
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeBytes)
	meta := string(metaBytes)
	telemetryGo := string(telemetryBytes)
	grafanaJSON := string(grafanaBytes)

	cases := []struct {
		name     string
		mutate   func(string) string
		wantSubs string
	}{
		{
			name: "missing metric row fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_acknowledged_rows` | `Counter (int)` | `{row}` | `none` | Rows acknowledged by BigQuery Storage Write API `AppendRows`. |\n",
					"",
					1,
				)
			},
			wantSubs: "missing metric otelcol_exporter_bigquery_acknowledged_rows",
		},
		{
			name: "bogus attribute on append_bytes fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_append_bytes` | `Counter (int)` | `By` | `none` |",
					"| `otelcol_exporter_bigquery_append_bytes` | `Counter (int)` | `By` | `{signal}` |",
					1,
				)
			},
			wantSubs: "otelcol_exporter_bigquery_append_bytes attributes = {signal}, metadata.yaml declares none",
		},
		{
			name: "omitted attribute on quarantined_rows fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_quarantined_rows` | `Counter (int)` | `{row}` | `{reason}` |",
					"| `otelcol_exporter_bigquery_quarantined_rows` | `Counter (int)` | `{row}` | `none` |",
					1,
				)
			},
			wantSubs: "otelcol_exporter_bigquery_quarantined_rows attributes = none, metadata.yaml declares {reason}",
		},
		{
			name: "unlisted metric row fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_unresolved_results` | `UpDownCounter (int)` | `{result}` | `none` | Results still being drained after their original attempt ended. |",
					"| `otelcol_exporter_bigquery_unresolved_results` | `UpDownCounter (int)` | `{result}` | `none` | Results still being drained after their original attempt ended. |\n| `otelcol_exporter_bigquery_bogus_metric` | `Counter (int)` | `{row}` | `none` | Bogus metric. |",
					1,
				)
			},
			wantSubs: "otelcol_exporter_bigquery_bogus_metric not declared in metadata.yaml",
		},
		{
			name: "wrong unit fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_append_result_wait` | `Histogram (double)` | `s` | `none` |",
					"| `otelcol_exporter_bigquery_append_result_wait` | `Histogram (double)` | `ms` | `none` |",
					1,
				)
			},
			wantSubs: `otelcol_exporter_bigquery_append_result_wait unit = "ms", metadata.yaml declares "s"`,
		},
		{
			name: "stale current-value prose fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"Of the four non-counter current-value instruments",
					"Both current-value instruments",
					1,
				)
			},
			wantSubs: "Both current-value instruments",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(readme)
			if mutated == readme {
				t.Fatalf("mutation %q did not change README.md", tc.name)
			}
			problems := validateReadmeSelfTelemetry(mutated, meta, telemetryGo, grafanaJSON)
			for _, p := range problems {
				if strings.Contains(p, tc.wantSubs) {
					return
				}
			}
			t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
		})
	}
}

func TestChangelogPreTagStabilityWording(t *testing.T) {
	changelogBytes, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	changelog := string(changelogBytes)
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(readmeBytes)

	if !regexp.MustCompile(`(?m)^## \[Unreleased\]$`).MatchString(changelog) {
		t.Error("CHANGELOG.md missing Keep a Changelog ## [Unreleased] heading")
	}
	if !regexp.MustCompile(`(?m)^## \[0\.0\.1\] - 2026-11-03$`).MatchString(changelog) {
		t.Error("CHANGELOG.md must keep ## [0.0.1] - 2026-11-03 without Alpha Release suffix")
	}
	if regexp.MustCompile(`(?m)^## \[0\.1\.0\]`).MatchString(changelog) {
		t.Error("CHANGELOG.md must not add ## [0.1.0] heading before release tagging")
	}
	for _, forbidden := range []string{
		"upstream GA",
		"Alpha Release",
		"alpha semantic release",
		"v0.0.1 alpha section",
	} {
		if strings.Contains(changelog, forbidden) {
			t.Errorf("CHANGELOG.md contains misleading pre-tag stability phrase %q", forbidden)
		}
		if strings.Contains(readme, forbidden) {
			t.Errorf("README.md contains misleading pre-tag stability phrase %q", forbidden)
		}
	}
}
