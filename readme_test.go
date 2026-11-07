// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"bytes"
	"context"
	"encoding/json"
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
	"unicode/utf8"

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

// readmeMetadataMetric is one telemetry metric of metadata.yaml. It is
// decoded with unknown fields rejected, so a key this check does not model
// (a misspelled enabled, an async flag) fails the check instead of being
// ignored.
type readmeMetadataMetric struct {
	Enabled     *bool    `yaml:"enabled"`
	Stability   string   `yaml:"stability"`
	Description string   `yaml:"description"`
	Unit        string   `yaml:"unit"`
	Attributes  []string `yaml:"attributes"`
	Sum         *struct {
		ValueType string `yaml:"value_type"`
		Monotonic *bool  `yaml:"monotonic"`
	} `yaml:"sum"`
	Gauge *struct {
		ValueType string `yaml:"value_type"`
	} `yaml:"gauge"`
	Histogram *struct {
		ValueType        string    `yaml:"value_type"`
		BucketBoundaries []float64 `yaml:"bucket_boundaries"`
	} `yaml:"histogram"`
}

func (m readmeMetadataMetric) typeLabel() string {
	switch {
	case m.Sum != nil && m.Sum.Monotonic != nil && *m.Sum.Monotonic:
		return fmt.Sprintf("Counter (%s)", m.Sum.ValueType)
	case m.Sum != nil && m.Sum.Monotonic != nil:
		return fmt.Sprintf("UpDownCounter (%s)", m.Sum.ValueType)
	case m.Gauge != nil:
		return fmt.Sprintf("Gauge (%s)", m.Gauge.ValueType)
	case m.Histogram != nil:
		return fmt.Sprintf("Histogram (%s)", m.Histogram.ValueType)
	default:
		return "unknown"
	}
}

func (m readmeMetadataMetric) isUpDownCounter() bool {
	return m.Sum != nil && m.Sum.Monotonic != nil && !*m.Sum.Monotonic
}

// specProblems checks the parts of a metric that the README table and
// internal/metadata/telemetry.go depend on.
func (m readmeMetadataMetric) specProblems(name string) []string {
	var problems []string
	if m.Enabled == nil || !*m.Enabled {
		problems = append(problems, fmt.Sprintf("metadata.yaml metric %s is not enabled: true; internal/metadata/telemetry.go always constructs it and README.md documents it as emitted", name))
	}
	kinds, valueType := 0, ""
	if m.Sum != nil {
		kinds++
		valueType = m.Sum.ValueType
		if m.Sum.Monotonic == nil {
			problems = append(problems, fmt.Sprintf("metadata.yaml metric %s sum must set monotonic", name))
		}
	}
	if m.Gauge != nil {
		kinds++
		valueType = m.Gauge.ValueType
	}
	if m.Histogram != nil {
		kinds++
		valueType = m.Histogram.ValueType
	}
	switch {
	case kinds != 1:
		problems = append(problems, fmt.Sprintf("metadata.yaml metric %s must declare exactly one of sum, gauge or histogram", name))
	case valueType != "int" && valueType != "double":
		problems = append(problems, fmt.Sprintf("metadata.yaml metric %s value_type is %q, want int or double", name, valueType))
	}
	return problems
}

// decodeReadmeMetadata decodes the telemetry block of metadata.yaml with
// unknown fields rejected. The rest of the file is left to mdatagen.
func decodeReadmeMetadata(metadataYAML string) (map[string]readmeMetadataMetric, error) {
	var top struct {
		Telemetry yaml.Node `yaml:"telemetry"`
	}
	if err := yaml.Unmarshal([]byte(metadataYAML), &top); err != nil {
		return nil, fmt.Errorf("metadata.yaml: %w", err)
	}
	if top.Telemetry.Kind == 0 {
		return nil, nil
	}
	raw, err := yaml.Marshal(&top.Telemetry)
	if err != nil {
		return nil, fmt.Errorf("metadata.yaml telemetry: %w", err)
	}
	var telemetry struct {
		Metrics map[string]readmeMetadataMetric `yaml:"metrics"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&telemetry); err != nil {
		return nil, fmt.Errorf("metadata.yaml telemetry: %w", err)
	}
	return telemetry.Metrics, nil
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

// readmeSelfTelemetrySection is the parsed self-telemetry table of README.md
// and the prose between the table and the next heading.
type readmeSelfTelemetrySection struct {
	Rows  []readmeTelemetryRow
	Prose string
	// TableStart and TableEnd bound the table's lines (header through last
	// row) as indexes into the README's lines.
	TableStart, TableEnd int
}

var readmeATXHeadingRE = regexp.MustCompile(`^#{1,6}(?:\s|$)`)

func readmeLines(readme string) []string {
	return strings.Split(strings.ReplaceAll(readme, "\r\n", "\n"), "\n")
}

// markdownTableLike reports whether a line renders as part of a table: it
// starts with a pipe, or it has a pipe that is neither escaped nor inside
// inline code. GitHub does not need a leading pipe to treat a line as a row.
func markdownTableLike(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "|") {
		return true
	}
	for i := 0; i < len(s); {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			// A code span runs from a backtick string to the next backtick
			// string of the same length; an unmatched run is literal text.
			n := 0
			for i+n < len(s) && s[i+n] == '`' {
				n++
			}
			end := -1
			for j := i + n; j < len(s); {
				if s[j] != '`' {
					j++
					continue
				}
				m := 0
				for j+m < len(s) && s[j+m] == '`' {
					m++
				}
				if m == n {
					end = j + m
					break
				}
				j += m
			}
			if end < 0 {
				i += n
			} else {
				i = end
			}
		case '|':
			return true
		default:
			i++
		}
	}
	return false
}

func parseReadmeSelfTelemetrySection(readme string) (readmeSelfTelemetrySection, error) {
	const anchor = "Use these content-free self-telemetry instruments"
	lines := readmeLines(readme)
	start := slices.IndexFunc(lines, func(line string) bool { return strings.Contains(line, anchor) })
	if start < 0 {
		return readmeSelfTelemetrySection{}, fmt.Errorf("README.md is missing self-telemetry intro %q", anchor)
	}

	headerIdx := -1
	for i := start; i < len(lines); i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "|") {
			headerIdx = i
			break
		}
	}
	if headerIdx < 0 || headerIdx+1 >= len(lines) {
		return readmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry markdown table not found after intro")
	}

	header := splitMarkdownRow(lines[headerIdx])
	wantHeader := []string{"Metric", "Type", "Unit", "Attributes", "Meaning"}
	if !slices.Equal(header, wantHeader) {
		return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table header = %v, want %v", header, wantHeader)
	}
	sep := splitMarkdownRow(lines[headerIdx+1])
	if len(sep) != len(wantHeader) || !isMarkdownSeparatorRow(sep) {
		return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table separator row %v is malformed", sep)
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
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry row %q has %d cells, want %d", trimmed, len(cells), len(wantHeader))
		}
		metricName, ok := unwrapInlineCode(cells[0])
		if !ok || metricName == "" {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry metric cell %q must be single inline code", cells[0])
		}
		typeLabel, ok := unwrapInlineCode(cells[1])
		if !ok || typeLabel == "" {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry type cell %q for %s must be single inline code", cells[1], metricName)
		}
		unit, ok := unwrapInlineCode(cells[2])
		if !ok || unit == "" {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry unit cell %q for %s must be single inline code", cells[2], metricName)
		}
		attrsRaw, ok := unwrapInlineCode(cells[3])
		if !ok || attrsRaw == "" {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry attributes cell %q for %s must be single inline code", cells[3], metricName)
		}
		attrs, err := parseReadmeMetricAttrs(attrsRaw)
		if err != nil {
			return readmeSelfTelemetrySection{}, fmt.Errorf("%s: %w", metricName, err)
		}
		if cells[4] == "" {
			return readmeSelfTelemetrySection{}, fmt.Errorf("%s: meaning cell is empty", metricName)
		}
		rows = append(rows, readmeTelemetryRow{
			Metric:  metricName,
			Type:    typeLabel,
			Unit:    unit,
			Attrs:   attrs,
			Meaning: cells[4],
		})
	}
	tableEnd := i

	// GitHub ends a table only at a blank line or another block, so a
	// non-blank line right after the last row renders as one more row.
	if i < len(lines) {
		if next := strings.TrimSpace(lines[i]); next != "" && !readmeATXHeadingRE.MatchString(next) {
			return readmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry table is followed directly by %q; GitHub renders that line as a table row, so leave a blank line", next)
		}
	}

	var proseLines []string
	for ; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			break
		}
		if markdownTableLike(trimmed) {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry section contains orphaned markdown table row %q after table ended", trimmed)
		}
		proseLines = append(proseLines, lines[i])
	}
	return readmeSelfTelemetrySection{
		Rows:       rows,
		Prose:      strings.Join(proseLines, "\n"),
		TableStart: headerIdx,
		TableEnd:   tableEnd,
	}, nil
}

var readmeMetricNameRE = regexp.MustCompile(dashPromPrefix + `[a-z0-9_]+`)

// readmeStrayTelemetryRows reports every line outside the self-telemetry
// table that renders as a table row and names a self-telemetry metric,
// wherever it sits in README.md. Fenced code never renders as a table.
func readmeStrayTelemetryRows(readme string, section readmeSelfTelemetrySection) []string {
	var problems []string
	fence := ""
	for i, line := range readmeLines(readme) {
		trimmed := strings.TrimSpace(line)
		if fence != "" {
			if strings.HasPrefix(trimmed, fence) {
				fence = ""
			}
			continue
		}
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			fence = trimmed[:3]
			continue
		}
		if i >= section.TableStart && i < section.TableEnd || !markdownTableLike(trimmed) {
			continue
		}
		for _, name := range readmeMetricNameRE.FindAllString(trimmed, -1) {
			problems = append(problems, fmt.Sprintf("README.md line %d is a table row naming %s outside the self-telemetry table", i+1, name))
		}
	}
	return problems
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

// The recovery prose after the self-telemetry table says, for every
// current-value instrument (an UpDownCounter or a gauge in metadata.yaml),
// what it returns to after recovery, in one of these forms:
//
//	`a` and `b` (`UpDownCounter`) should return to zero ...
//	`x` (<description>) recovers toward `<target>`
//	`y` (<description>) recovers to `<target>`, not zero
//
// Each instrument is bound to its own claim. Any other "recover(s) to",
// "recovers toward" or "return(s) to" wording is reported, so a claim cannot
// be restated, negated or contradicted outside the checked forms.
var (
	readmeZeroClaimRE    = regexp.MustCompile("((?:`[a-z0-9_]+`(?:, and |, | and ))*`[a-z0-9_]+`) \\(`UpDownCounter`\\) should return to zero")
	readmeGaugeClaimRE   = regexp.MustCompile("`([a-z0-9_]+)` \\(([^()]*)\\) recovers (toward|to) `([^`]+)`(, not zero)?")
	readmeRecoveryVerbRE = regexp.MustCompile(`(?i)\brecover(?:s|ed|ing)? (?:to|toward)\b|\breturns? to\b`)
	readmeCountClaimRE   = regexp.MustCompile(`\bOf the ([a-z]+) non-counter current-value instruments\b`)
	readmeCodeNameRE     = regexp.MustCompile("`([a-z0-9_]+)`")
)

// readmeGaugeRecoveryTargets is the value each gauge returns to once the
// writer is uncongested. A gauge added to metadata.yaml needs an entry.
var readmeGaugeRecoveryTargets = map[string]string{
	"otelcol_exporter_bigquery_backpressure_level":      "0.0",
	"otelcol_exporter_bigquery_effective_request_bytes": "write.max_request_bytes",
}

// readmeGaugeUnitWording is how the recovery prose describes a gauge of
// each metadata.yaml unit.
var readmeGaugeUnitWording = map[string]string{
	"1":  "dimensionless `1` gauge",
	"By": "byte gauge",
}

var readmeNumberWords = map[string]int{
	"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
	"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
}

func validateReadmeRecoveryProse(prose string, metrics map[string]readmeMetadataMetric) []string {
	var problems []string
	text := strings.Join(strings.Fields(prose), " ")
	if strings.Contains(strings.ToLower(text), "both current-value instruments") {
		problems = append(problems, `README.md still claims "Both current-value instruments" instead of describing all four non-counter instruments`)
	}

	var upDown, gauges []string
	for name, spec := range metrics {
		switch {
		case spec.Gauge != nil:
			gauges = append(gauges, name)
		case spec.isUpDownCounter():
			upDown = append(upDown, name)
		}
	}
	slices.Sort(upDown)
	slices.Sort(gauges)

	if m := readmeCountClaimRE.FindStringSubmatch(text); m == nil {
		problems = append(problems, `README.md self-telemetry recovery prose must open with "Of the <count> non-counter current-value instruments"`)
	} else if n, ok := readmeNumberWords[m[1]]; !ok || n != len(upDown)+len(gauges) {
		problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts %q non-counter current-value instruments, metadata.yaml declares %d", m[1], len(upDown)+len(gauges)))
	}

	masked := []byte(text)
	mask := func(from, to int) {
		for i := from; i < to; i++ {
			masked[i] = ' '
		}
	}
	claims := map[string]int{}
	for _, loc := range readmeZeroClaimRE.FindAllStringSubmatchIndex(text, -1) {
		mask(loc[0], loc[1])
		for _, m := range readmeCodeNameRE.FindAllStringSubmatch(text[loc[2]:loc[3]], -1) {
			short, name := m[1], dashPromPrefix+m[1]
			claims[name]++
			spec, ok := metrics[name]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose names %s, which metadata.yaml does not declare", short))
			case !spec.isUpDownCounter():
				problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose says %s returns to zero as an UpDownCounter, but metadata.yaml declares it as %s", short, spec.typeLabel()))
			}
		}
	}
	for _, loc := range readmeGaugeClaimRE.FindAllStringSubmatchIndex(text, -1) {
		mask(loc[0], loc[1])
		short, desc, prep, target := text[loc[2]:loc[3]], text[loc[4]:loc[5]], text[loc[6]:loc[7]], text[loc[8]:loc[9]]
		notZero := loc[10] >= 0
		name := dashPromPrefix + short
		claims[name]++
		spec, ok := metrics[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose names %s, which metadata.yaml does not declare", short))
			continue
		}
		if spec.Gauge == nil {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose claims %s recovers %s %q, but metadata.yaml declares it as %s, not a gauge", short, prep, target, spec.typeLabel()))
			continue
		}
		want, ok := readmeGaugeRecoveryTargets[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("no recovery target is declared for gauge %s; add it to readmeGaugeRecoveryTargets", name))
			continue
		}
		if target != want {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose binds %s to %q, want %q", short, target, want))
		}
		if wording, ok := readmeGaugeUnitWording[spec.Unit]; !ok {
			problems = append(problems, fmt.Sprintf("no recovery wording is declared for gauge unit %q of %s; add it to readmeGaugeUnitWording", spec.Unit, name))
		} else if !strings.HasPrefix(desc, wording) {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose describes %s as %q, but metadata.yaml declares unit %q (%s)", short, desc, spec.Unit, wording))
		}
		switch zero := want == "0" || want == "0.0"; {
		case !zero && !notZero:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose must say %s recovers to `%s`, not zero", short, want))
		case zero && notZero:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose says %s recovers to `%s`, not zero, which contradicts itself", short, want))
		}
	}
	for _, name := range append(slices.Clone(upDown), gauges...) {
		switch n := claims[name]; {
		case n == 0:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has no recovery claim for %s", strings.TrimPrefix(name, dashPromPrefix)))
		case n > 1:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has %d recovery claims for %s, want exactly one", n, strings.TrimPrefix(name, dashPromPrefix)))
		}
	}
	targets := make([]string, 0, len(readmeGaugeRecoveryTargets))
	for name := range readmeGaugeRecoveryTargets {
		targets = append(targets, name)
	}
	slices.Sort(targets)
	for _, name := range targets {
		if spec, ok := metrics[name]; !ok || spec.Gauge == nil {
			problems = append(problems, fmt.Sprintf("readmeGaugeRecoveryTargets lists %s, which metadata.yaml does not declare as a gauge", name))
		}
	}
	for _, loc := range readmeRecoveryVerbRE.FindAllIndex(masked, -1) {
		from, to := max(0, loc[0]-40), min(len(text), loc[1]+40)
		for from > 0 && !utf8.RuneStart(text[from]) {
			from--
		}
		for to < len(text) && !utf8.RuneStart(text[to]) {
			to++
		}
		problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has a recovery statement outside the checked forms: %q", text[from:to]))
	}
	return problems
}

// readmeGoInstrument is one instrument constructor call in
// internal/metadata/telemetry.go, such as m.Int64Counter(nameX, opts...).
type readmeGoInstrument struct {
	Name       string
	TypeLabel  string
	Units      []string
	Boundaries []float64
	Line       int
}

// readmeGoRecording is one Add or Record call on an instrument field, such as
// t.X.Add(ctx, n, metric.WithAttributes(attribute.String(AttrReason, r))).
type readmeGoRecording struct {
	Field string
	Attrs []string
	// Known is false when an option is not a literal WithAttributes list.
	Known bool
	Line  int
}

var readmeGoCtorRE = regexp.MustCompile(`^(Int64|Float64)(Observable)?(Counter|UpDownCounter|Gauge|Histogram)$`)

func readmeFloatLit(e ast.Expr) (float64, bool) {
	neg := false
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.SUB {
		neg, e = true, u.X
	}
	lit, ok := e.(*ast.BasicLit)
	if !ok || (lit.Kind != token.INT && lit.Kind != token.FLOAT) {
		return 0, false
	}
	f, err := strconv.ParseFloat(lit.Value, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		f = -f
	}
	return f, true
}

// readTelemetryGo reads what internal/metadata/telemetry.go constructs and
// records: each constructor call with its unit and bucket boundaries, the
// field each constructor result is assigned to, and the attribute keys of
// each recording call.
func readTelemetryGo(src string) ([]readmeGoInstrument, map[string]string, []readmeGoRecording, []string) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "internal/metadata/telemetry.go", src, 0)
	if err != nil {
		return nil, nil, nil, []string{fmt.Sprintf("parsing internal/metadata/telemetry.go: %v", err)}
	}
	consts := map[string]string{}
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
			for i, ident := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil {
						consts[ident.Name] = v
					}
				}
			}
		}
	}
	str := func(e ast.Expr) (string, bool) {
		switch e := e.(type) {
		case *ast.BasicLit:
			if e.Kind == token.STRING {
				v, err := strconv.Unquote(e.Value)
				return v, err == nil
			}
		case *ast.Ident:
			v, ok := consts[e.Name]
			return v, ok
		}
		return "", false
	}
	line := func(n ast.Node) int { return fset.Position(n.Pos()).Line }
	optionName := func(e ast.Expr) (*ast.CallExpr, string) {
		call, ok := e.(*ast.CallExpr)
		if !ok {
			return nil, ""
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return call, ""
		}
		return call, sel.Sel.Name
	}

	var (
		problems    []string
		instruments []readmeGoInstrument
		recordings  []readmeGoRecording
		fields      = map[string]string{}
	)
	ast.Inspect(file, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			// t.X, err = m.Int64Counter(nameX, ...) ties field X to nameX.
			if len(n.Lhs) == 0 || len(n.Rhs) != 1 {
				return true
			}
			call, ok := n.Rhs[0].(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || !readmeGoCtorRE.MatchString(sel.Sel.Name) {
				return true
			}
			field, ok := n.Lhs[0].(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if name, ok := str(call.Args[0]); ok {
				fields[field.Sel.Name] = name
			}
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if m := readmeGoCtorRE.FindStringSubmatch(sel.Sel.Name); m != nil {
				if m[2] != "" {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: %s is an observable instrument, which this check does not model", line(n), sel.Sel.Name))
					return true
				}
				name, resolved := "", false
				if len(n.Args) > 0 {
					name, resolved = str(n.Args[0])
				}
				if !resolved || name == "" {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: cannot resolve the metric name passed to %s", line(n), sel.Sel.Name))
					return true
				}
				valueType := map[string]string{"Int64": "int", "Float64": "double"}[m[1]]
				inst := readmeGoInstrument{Name: name, TypeLabel: fmt.Sprintf("%s (%s)", m[3], valueType), Line: line(n)}
				for _, arg := range n.Args[1:] {
					opt, optName := optionName(arg)
					switch optName {
					case "WithUnit":
						if len(opt.Args) == 1 {
							if unit, ok := str(opt.Args[0]); ok {
								inst.Units = append(inst.Units, unit)
								continue
							}
						}
						problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: cannot resolve the unit of %s", line(opt), name))
					case "WithExplicitBucketBoundaries":
						for _, b := range opt.Args {
							f, ok := readmeFloatLit(b)
							if !ok {
								problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: cannot read the bucket boundaries of %s", line(opt), name))
								break
							}
							inst.Boundaries = append(inst.Boundaries, f)
						}
					case "WithDescription":
					default:
						problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: cannot read an option of %s", line(arg), name))
					}
				}
				instruments = append(instruments, inst)
				return true
			}
			// t.X.Add(ctx, v, opts...) or t.X.Record(ctx, v, opts...).
			if sel.Sel.Name != "Add" && sel.Sel.Name != "Record" {
				return true
			}
			inner, ok := sel.X.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if _, ok := inner.X.(*ast.Ident); !ok {
				return true
			}
			rec := readmeGoRecording{Field: inner.Sel.Name, Known: true, Line: line(n)}
			for _, arg := range n.Args[min(2, len(n.Args)):] {
				opt, optName := optionName(arg)
				if optName != "WithAttributes" {
					rec.Known = false
					continue
				}
				for _, a := range opt.Args {
					kv, ok := a.(*ast.CallExpr)
					if !ok || len(kv.Args) == 0 {
						rec.Known = false
						continue
					}
					kvSel, ok := kv.Fun.(*ast.SelectorExpr)
					if !ok {
						rec.Known = false
						continue
					}
					if pkg, ok := kvSel.X.(*ast.Ident); !ok || pkg.Name != "attribute" {
						rec.Known = false
						continue
					}
					key, ok := str(kv.Args[0])
					if !ok {
						rec.Known = false
						continue
					}
					rec.Attrs = append(rec.Attrs, key)
				}
			}
			slices.Sort(rec.Attrs)
			recordings = append(recordings, rec)
		}
		return true
	})
	return instruments, fields, recordings, problems
}

// validateTelemetryGoInstruments checks that internal/metadata/telemetry.go
// constructs every metadata.yaml metric exactly once with the declared kind,
// value type, unit and bucket boundaries, and records it only with the
// declared attribute keys.
func validateTelemetryGoInstruments(telemetryGo string, metrics map[string]readmeMetadataMetric, metaNames []string) []string {
	instruments, fields, recordings, problems := readTelemetryGo(telemetryGo)
	constructed := map[string][]readmeGoInstrument{}
	for _, inst := range instruments {
		if _, ok := metrics[inst.Name]; !ok {
			problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d constructs %s, which metadata.yaml does not declare", inst.Line, inst.Name))
			continue
		}
		constructed[inst.Name] = append(constructed[inst.Name], inst)
	}
	recorded := map[string][]readmeGoRecording{}
	for _, rec := range recordings {
		if name, ok := fields[rec.Field]; ok {
			recorded[name] = append(recorded[name], rec)
		}
	}
	for _, name := range metaNames {
		spec := metrics[name]
		switch insts := constructed[name]; len(insts) {
		case 0:
			problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go never constructs %s declared in metadata.yaml", name))
		case 1:
			inst := insts[0]
			if want := spec.typeLabel(); inst.TypeLabel != want {
				problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go constructs %s as %s, metadata.yaml declares %s", name, inst.TypeLabel, want))
			}
			unit := ""
			if n := len(inst.Units); n > 0 {
				unit = inst.Units[n-1]
				if n > 1 {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go sets %d units on %s", n, name))
				}
			}
			if unit != spec.Unit {
				problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go sets unit %q on %s, metadata.yaml declares %q", unit, name, spec.Unit))
			}
			var wantBounds []float64
			if spec.Histogram != nil {
				wantBounds = spec.Histogram.BucketBoundaries
			}
			if !slices.Equal(inst.Boundaries, wantBounds) {
				problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go sets bucket boundaries %v on %s, metadata.yaml declares %v", inst.Boundaries, name, wantBounds))
			}
		default:
			problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go constructs %s %d times", name, len(insts)))
		}

		recs := recorded[name]
		if len(recs) == 0 {
			problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go never records %s, so its attributes cannot be checked", name))
		}
		wantAttrs := slices.Clone(spec.Attributes)
		slices.Sort(wantAttrs)
		for _, rec := range recs {
			if !rec.Known {
				problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d: cannot verify the attributes %s is recorded with", rec.Line, name))
				continue
			}
			if !slices.Equal(rec.Attrs, wantAttrs) {
				problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go line %d records %s with attributes %s, metadata.yaml declares %s", rec.Line, name, formatAttrSet(rec.Attrs), formatAttrSet(wantAttrs)))
			}
		}
	}
	return problems
}

// readmeGrafanaQuery is one query of a dashboard panel at any depth.
type readmeGrafanaQuery struct {
	Panel, RefID, Expr, Legend string
}

// readmeGrafanaQueries walks the whole dashboard model, so panels nested in
// (collapsed) rows and queries attached to rows themselves are checked too.
// It also returns how many "expr" fields sit anywhere other than in a panel
// target: none of those would reach a check.
func readmeGrafanaQueries(grafanaJSON string) ([]readmeGrafanaQuery, int, error) {
	var root any
	if err := json.Unmarshal([]byte(grafanaJSON), &root); err != nil {
		return nil, 0, err
	}
	var queries []readmeGrafanaQuery
	exprs, targetExprs := 0, 0
	var walk func(v any)
	walk = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			if _, ok := v["expr"]; ok {
				exprs++
			}
			if targets, ok := v["targets"].([]any); ok {
				title, _ := v["title"].(string)
				for _, tg := range targets {
					target, ok := tg.(map[string]any)
					if !ok {
						continue
					}
					if _, ok := target["expr"]; ok {
						targetExprs++
					}
					q := readmeGrafanaQuery{Panel: title}
					q.Expr, _ = target["expr"].(string)
					q.Legend, _ = target["legendFormat"].(string)
					q.RefID, _ = target["refId"].(string)
					queries = append(queries, q)
				}
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				walk(v[k])
			}
		case []any:
			for _, e := range v {
				walk(e)
			}
		}
	}
	walk(root)
	return queries, exprs - targetExprs, nil
}

func validateReadmeSelfTelemetry(readme, metadataYAML, telemetryGo, grafanaJSON string) []string {
	var problems []string

	metrics, err := decodeReadmeMetadata(metadataYAML)
	if err != nil {
		return []string{err.Error()}
	}
	if len(metrics) == 0 {
		return []string{"metadata.yaml declares no metrics"}
	}

	section, err := parseReadmeSelfTelemetrySection(readme)
	if err != nil {
		return []string{err.Error()}
	}
	problems = append(problems, readmeStrayTelemetryRows(readme, section)...)

	readmeRows := make(map[string]readmeTelemetryRow, len(section.Rows))
	for _, row := range section.Rows {
		if _, dup := readmeRows[row.Metric]; dup {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry table lists duplicate metric %s", row.Metric))
			continue
		}
		readmeRows[row.Metric] = row
	}

	metaNames := make([]string, 0, len(metrics))
	for name := range metrics {
		metaNames = append(metaNames, name)
	}
	slices.Sort(metaNames)

	for _, name := range metaNames {
		spec := metrics[name]
		problems = append(problems, spec.specProblems(name)...)
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
		if _, ok := metrics[name]; !ok {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry table lists metric %s not declared in metadata.yaml", name))
		}
	}

	problems = append(problems, validateReadmeRecoveryProse(section.Prose, metrics)...)

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
				if _, ok := metrics[n]; !ok {
					problems = append(problems, fmt.Sprintf("internal/metadata/telemetry.go declares %s absent from metadata.yaml", n))
				}
			}
		}
		problems = append(problems, validateTelemetryGoInstruments(telemetryGo, metrics, metaNames)...)
	}

	if grafanaJSON != "" {
		files := dashFileSet{"metadata.yaml": metadataYAML, dashGrafanaProm: grafanaJSON}
		g, p := dashDecodeGrafana(files, dashGrafanaProm)
		problems = append(problems, p...)
		dashMD, err := dashDecodeMetadata(files)
		if err != nil {
			problems = append(problems, err.Error())
		} else if g != nil {
			queries, outside, err := readmeGrafanaQueries(grafanaJSON)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s: %v", dashGrafanaProm, err))
			}
			if outside > 0 {
				problems = append(problems, fmt.Sprintf("%s: %d expr field(s) outside panel targets are not checked", dashGrafanaProm, outside))
			}
			grafanaSet := map[string]bool{}
			for _, q := range queries {
				rs, promProblems := dashCheckPromExpr(dashMD, q.Expr, q.Legend)
				for _, msg := range promProblems {
					problems = append(problems, fmt.Sprintf("%s: panel %q: query %s: %s", dashGrafanaProm, q.Panel, q.RefID, msg))
				}
				for _, r := range rs {
					grafanaSet[r.metric] = true
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
		name            string
		mutate          func(string) string
		mutateMeta      func(string) string
		mutateTelemetry func(string) string
		mutateGrafana   func(string) string
		wantSubs        string
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
		{
			name: "orphaned table row after blank line fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| `otelcol_exporter_bigquery_unresolved_results` | `UpDownCounter (int)` | `{result}` | `none` | Results still being drained after their original attempt ended. |\n",
					"| `otelcol_exporter_bigquery_unresolved_results` | `UpDownCounter (int)` | `{result}` | `none` | Results still being drained after their original attempt ended. |\n\n| bq.exporter.orphaned | counter | 1 | desc |\n",
					1,
				)
			},
			wantSubs: "orphaned markdown table row",
		},
		{
			name: "effective_request_bytes recovers to zero prose fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"`write.max_request_bytes`, not zero",
					"`write.max_request_bytes`, zero",
					1,
				)
			},
			wantSubs: "`write.max_request_bytes`, not zero",
		},
		{
			name: "broken grafana PromQL expression forwards dashCheckPromExpr problem",
			mutateGrafana: func(s string) string {
				return strings.Replace(
					s,
					`, instance=~\"$instance\"`,
					"",
					1,
				)
			},
			wantSubs: `is not filtered on instance=~"$instance"`,
		},

		// Recovery prose: each current-value instrument is bound to its own
		// recovery target, so keeping the required words is not enough.
		{
			name: "swapped gauge recovery targets fail",
			mutate: func(s string) string {
				s = strings.Replace(s, "`backpressure_level` (dimensionless", "`effective_request_bytes` (dimensionless", 1)
				return strings.Replace(s, "`effective_request_bytes` (byte gauge) recovers to", "`backpressure_level` (byte gauge) recovers to", 1)
			},
			wantSubs: `binds backpressure_level to "write.max_request_bytes", want "0.0"`,
		},
		{
			name: "swapped gauge descriptions fail",
			mutate: func(s string) string {
				return strings.Replace(s, "(dimensionless `1` gauge in `[0.0, 1.0]`)", "(byte gauge)", 1)
			},
			wantSubs: `describes backpressure_level as "byte gauge"`,
		},
		{
			name: "negated gauge description fails",
			mutate: func(s string) string {
				return strings.Replace(s, "`effective_request_bytes` (byte gauge)", "`effective_request_bytes` (not a byte gauge)", 1)
			},
			wantSubs: `describes effective_request_bytes as "not a byte gauge"`,
		},
		{
			name: "second contradictory recovery claim fails",
			mutate: func(s string) string {
				return strings.Replace(s, "`write.max_request_bytes`, not zero.",
					"`write.max_request_bytes`, not zero. After a restart, `effective_request_bytes` (byte gauge) recovers toward `0`.", 1)
			},
			wantSubs: "has 2 recovery claims for effective_request_bytes",
		},
		{
			name: "negated gauge recovery claim fails",
			mutate: func(s string) string {
				return strings.Replace(s, "`[0.0, 1.0]`) recovers toward", "`[0.0, 1.0]`) never recovers toward", 1)
			},
			wantSubs: "no recovery claim for backpressure_level",
		},
		{
			name: "recovery claim moved to a counter fails",
			mutate: func(s string) string {
				return strings.Replace(s, "and `effective_request_bytes` (byte gauge) recovers to", "and `append_bytes` (byte gauge) recovers to", 1)
			},
			wantSubs: `claims append_bytes recovers to "write.max_request_bytes", but metadata.yaml declares it as Counter (int)`,
		},
		{
			name: "return-to-zero claim naming a gauge fails",
			mutate: func(s string) string {
				return strings.Replace(s, "`unresolved_results` (`UpDownCounter`) should return to zero", "`backpressure_level` (`UpDownCounter`) should return to zero", 1)
			},
			wantSubs: "says backpressure_level returns to zero as an UpDownCounter, but metadata.yaml declares it as Gauge (double)",
		},
		{
			name: "wrong current-value instrument count fails",
			mutate: func(s string) string {
				return strings.Replace(s, "Of the four non-counter current-value instruments", "Of the three non-counter current-value instruments", 1)
			},
			wantSubs: `counts "three" non-counter current-value instruments, metadata.yaml declares 4`,
		},
		{
			name: "free-form recovery statement fails",
			mutate: func(s string) string {
				return strings.Replace(s, "`write.max_request_bytes`, not zero.",
					"`write.max_request_bytes`, not zero. `inflight_requests` recovers to its high-water mark.", 1)
			},
			wantSubs: "recovery statement outside the checked forms",
		},

		// Table debris: a row is recognized by its unescaped pipes, not by a
		// leading pipe, and wherever it sits in README.md.
		{
			name: "orphaned table row without leading pipe fails",
			mutate: func(s string) string {
				return strings.Replace(s,
					"Results still being drained after their original attempt ended. |\n",
					"Results still being drained after their original attempt ended. |\n\n`otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` | `{row}` | `none` | Orphaned split row. |\n",
					1)
			},
			wantSubs: "orphaned markdown table row",
		},
		{
			name: "orphaned table row under a later heading fails",
			mutate: func(s string) string {
				return strings.Replace(s, "\n### Timeout and concurrency envelope",
					"\n### Detached notes\n\n| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` | `{row}` | `none` | Orphaned split row. |\n\n### Timeout and concurrency envelope",
					1)
			},
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name: "prose glued to the table fails",
			mutate: func(s string) string {
				return strings.Replace(s,
					"Results still being drained after their original attempt ended. |\n\nOf the four",
					"Results still being drained after their original attempt ended. |\nOf the four",
					1)
			},
			wantSubs: "renders that line as a table row",
		},
		{
			name: "hash-led line glued to the table fails",
			mutate: func(s string) string {
				return strings.Replace(s,
					"Results still being drained after their original attempt ended. |\n\nOf the four",
					"Results still being drained after their original attempt ended. |\n#1 signal: watch `inflight_requests`.\n\nOf the four",
					1)
			},
			wantSubs: "renders that line as a table row",
		},

		// internal/metadata/telemetry.go: what is constructed and recorded,
		// not only which name constants exist.
		{
			name: "telemetry.go constructor kind drift fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "m.Int64Counter(nameAcknowledgedRows,", "m.Int64UpDownCounter(nameAcknowledgedRows,", 1)
			},
			wantSubs: "constructs otelcol_exporter_bigquery_acknowledged_rows as UpDownCounter (int), metadata.yaml declares Counter (int)",
		},
		{
			name: "telemetry.go value type drift fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "m.Float64Histogram(nameAppendResultWait,", "m.Int64Histogram(nameAppendResultWait,", 1)
			},
			wantSubs: "constructs otelcol_exporter_bigquery_append_result_wait as Histogram (int), metadata.yaml declares Histogram (double)",
		},
		{
			name: "telemetry.go unit drift fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "Storage Write API.\"),\n\t\tmetric.WithUnit(\"{row}\")", "Storage Write API.\"),\n\t\tmetric.WithUnit(\"{rows}\")", 1)
			},
			wantSubs: `sets unit "{rows}" on otelcol_exporter_bigquery_acknowledged_rows, metadata.yaml declares "{row}"`,
		},
		{
			name: "telemetry.go missing unit fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "\n\t\tmetric.WithUnit(\"s\"),", "", 1)
			},
			wantSubs: `sets unit "" on otelcol_exporter_bigquery_append_result_wait, metadata.yaml declares "s"`,
		},
		{
			name: "telemetry.go histogram boundary drift fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "WithExplicitBucketBoundaries(0.001, 0.01, 0.1, 1, 5, 30, 70, 120)", "WithExplicitBucketBoundaries(0.001, 0.01, 0.1, 1, 5, 30, 60, 120)", 1)
			},
			wantSubs: "sets bucket boundaries [0.001 0.01 0.1 1 5 30 60 120] on otelcol_exporter_bigquery_append_result_wait",
		},
		{
			name: "telemetry.go recorded attribute drift fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s,
					"t.RejectedRows.Add(ctx, int64(n), metric.WithAttributes(attribute.String(AttrReason, reason)))",
					"t.RejectedRows.Add(ctx, int64(n), metric.WithAttributes(attribute.String(AttrClass, reason)))",
					1)
			},
			wantSubs: "records otelcol_exporter_bigquery_rejected_rows with attributes {class}, metadata.yaml declares {reason}",
		},
		{
			name: "telemetry.go attributes built elsewhere fail",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s,
					"t.Retries.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrClass, class)))",
					"t.Retries.Add(ctx, 1, retryAttributes(class))",
					1)
			},
			wantSubs: "cannot verify the attributes otelcol_exporter_bigquery_retries is recorded with",
		},
		{
			name: "telemetry.go instrument never recorded fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "\tt.UncertainAckReplays.Add(ctx, 1)\n", "", 1)
			},
			wantSubs: "never records otelcol_exporter_bigquery_uncertain_ack_replays",
		},
		{
			name: "telemetry.go computed metric name fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "m.Int64Counter(nameAcknowledgedRows,", "m.Int64Counter(scopedName(nameAcknowledgedRows),", 1)
			},
			wantSubs: "cannot resolve the metric name passed to Int64Counter",
		},
		{
			name: "telemetry.go constructor reusing another name fails",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, "m.Int64Counter(nameRejectedRows,", "m.Int64Counter(nameAcknowledgedRows,", 1)
			},
			wantSubs: "never constructs otelcol_exporter_bigquery_rejected_rows",
		},

		// Grafana: every query at any depth is checked, and none may sit
		// where the walk does not look.
		{
			name: "broken PromQL in a panel nested under a collapsed row fails",
			mutateGrafana: func(s string) string {
				return readmeEditGrafana(s, func(root map[string]any) bool {
					target, ok := readmeBrokenTargetClone(root, "Acknowledged rows/s", "N")
					row, rowOK := readmeFirstGrafanaRow(root)
					if !ok || !rowOK {
						return false
					}
					row["collapsed"] = true
					row["panels"] = []any{map[string]any{
						"type":    "timeseries",
						"title":   "Nested probe",
						"targets": []any{target},
					}}
					return true
				})
			},
			wantSubs: `panel "Nested probe": query N: otelcol_exporter_bigquery_acknowledged_rows is not filtered on instance=~"$instance"`,
		},
		{
			name: "broken PromQL attached to a row panel fails",
			mutateGrafana: func(s string) string {
				return readmeEditGrafana(s, func(root map[string]any) bool {
					target, ok := readmeBrokenTargetClone(root, "Acknowledged rows/s", "R")
					row, rowOK := readmeFirstGrafanaRow(root)
					if !ok || !rowOK {
						return false
					}
					row["title"] = "Row probe"
					row["targets"] = []any{target}
					return true
				})
			},
			wantSubs: `panel "Row probe": query R: otelcol_exporter_bigquery_acknowledged_rows is not filtered on instance=~"$instance"`,
		},
		{
			name: "PromQL outside panel targets fails",
			mutateGrafana: func(s string) string {
				return readmeEditGrafana(s, func(root map[string]any) bool {
					annotations, ok := root["annotations"].(map[string]any)
					if !ok {
						return false
					}
					list, _ := annotations["list"].([]any)
					annotations["list"] = append(list, map[string]any{"name": "Probe", "expr": "up"})
					return true
				})
			},
			wantSubs: "expr field(s) outside panel targets are not checked",
		},

		// metadata.yaml: decoded strictly, and every metric must be enabled
		// because telemetry.go constructs all of them unconditionally.
		{
			name: "disabled metadata metric fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: false\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows is not enabled: true",
		},
		{
			name: "metadata metric without enabled fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    otelcol_exporter_bigquery_acknowledged_rows:\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows is not enabled: true",
		},
		{
			name: "misspelled metadata field fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    otelcol_exporter_bigquery_acknowledged_rows:\n      enable: false\n      enabled: true\n", 1)
			},
			wantSubs: "field enable not found",
		},
		{
			name: "metadata metric with two instrument kinds fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    otelcol_exporter_bigquery_acknowledged_rows:\n      enabled: true\n      gauge:\n        value_type: int\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows must declare exactly one of sum, gauge or histogram",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutatedReadme := readme
			if tc.mutate != nil {
				mutatedReadme = tc.mutate(readme)
				if mutatedReadme == readme {
					t.Fatalf("mutation %q did not change README.md", tc.name)
				}
			}
			mutatedMeta := meta
			if tc.mutateMeta != nil {
				mutatedMeta = tc.mutateMeta(meta)
				if mutatedMeta == meta {
					t.Fatalf("mutation %q did not change metadata.yaml", tc.name)
				}
			}
			mutatedTelemetry := telemetryGo
			if tc.mutateTelemetry != nil {
				mutatedTelemetry = tc.mutateTelemetry(telemetryGo)
				if mutatedTelemetry == telemetryGo {
					t.Fatalf("mutation %q did not change internal/metadata/telemetry.go", tc.name)
				}
			}
			mutatedGrafana := grafanaJSON
			if tc.mutateGrafana != nil {
				mutatedGrafana = tc.mutateGrafana(grafanaJSON)
				if mutatedGrafana == grafanaJSON {
					t.Fatalf("mutation %q did not change %s", tc.name, dashGrafanaProm)
				}
			}
			problems := validateReadmeSelfTelemetry(mutatedReadme, mutatedMeta, mutatedTelemetry, mutatedGrafana)
			for _, p := range problems {
				if strings.Contains(p, tc.wantSubs) {
					return
				}
			}
			t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
		})
	}
}

// readmeEditGrafana decodes a dashboard model, applies edit, and re-encodes
// it. It returns raw unchanged when the model does not decode or edit finds
// nothing to change, so the caller's "did not change" check fails loudly.
func readmeEditGrafana(raw string, edit func(root map[string]any) bool) string {
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return raw
	}
	if !edit(root) {
		return raw
	}
	out, err := json.Marshal(root)
	if err != nil {
		return raw
	}
	return string(out)
}

// readmeBrokenTargetClone copies the first query of the top-level panel
// titled panelTitle that is filtered on instance=~"$instance", drops that
// filter and sets refID.
func readmeBrokenTargetClone(root map[string]any, panelTitle, refID string) (map[string]any, bool) {
	panels, _ := root["panels"].([]any)
	for _, p := range panels {
		panel, _ := p.(map[string]any)
		if panel["title"] != panelTitle {
			continue
		}
		targets, _ := panel["targets"].([]any)
		for _, tg := range targets {
			target, _ := tg.(map[string]any)
			expr, _ := target["expr"].(string)
			if !strings.Contains(expr, `, instance=~"$instance"`) {
				continue
			}
			clone := make(map[string]any, len(target))
			for k, v := range target {
				clone[k] = v
			}
			clone["expr"] = strings.Replace(expr, `, instance=~"$instance"`, "", 1)
			clone["refId"] = refID
			return clone, true
		}
	}
	return nil, false
}

// readmeFirstGrafanaRow returns the first top-level row panel.
func readmeFirstGrafanaRow(root map[string]any) (map[string]any, bool) {
	panels, _ := root["panels"].([]any)
	for _, p := range panels {
		if panel, _ := p.(map[string]any); panel["type"] == "row" {
			return panel, true
		}
	}
	return nil, false
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
