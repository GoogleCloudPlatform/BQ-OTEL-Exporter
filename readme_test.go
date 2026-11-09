// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/build"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"gopkg.in/yaml.v3"

	bqi "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/bigquery"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

func readmeNormalizeEOL(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// TestReadmeQuotesStartupErrors keeps the README's startup-error table tied to
// the messages the exporter actually returns. Credential and Compose messages
// come from other code and are proven by the collector-example CI job instead.
func TestReadmeQuotesStartupErrors(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := readmeNormalizeEOL(string(raw))
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
	readme := readmeNormalizeEOL(string(raw))

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
	metadataYAML = readmeNormalizeEOL(metadataYAML)
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

func readmeTrailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// readmeSplitTableRow splits a GitHub Flavored Markdown table row into
// trimmed cells. One leading and one trailing pipe are dropped, and an
// escaped pipe (\|) stays inside its cell. As on GitHub, an unescaped pipe
// inside a code span still ends the cell.
func readmeSplitTableRow(line string) []string {
	s := strings.TrimPrefix(strings.TrimSpace(line), "|")
	if strings.HasSuffix(s, "|") && readmeTrailingBackslashes(s[:len(s)-1])%2 == 0 {
		s = s[:len(s)-1]
	}
	var cells []string
	var cell strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			if s[i+1] == '|' {
				cell.WriteByte('|')
			} else {
				cell.WriteByte(s[i])
				cell.WriteByte(s[i+1])
			}
			i++
		case s[i] == '|':
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(s[i])
		}
	}
	return append(cells, strings.TrimSpace(cell.String()))
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

// readmeMDKind is the kind of a leaf block of a GitHub Flavored Markdown
// document.
type readmeMDKind int

const (
	readmeMDParagraph readmeMDKind = iota
	readmeMDHeading
	readmeMDThematicBreak
	readmeMDFencedCode
	readmeMDIndentedCode
	readmeMDHTML
	readmeMDTable
)

var readmeMDKindNames = map[readmeMDKind]string{
	readmeMDParagraph:     "paragraph",
	readmeMDHeading:       "heading",
	readmeMDThematicBreak: "break",
	readmeMDFencedCode:    "fence",
	readmeMDIndentedCode:  "indented",
	readmeMDHTML:          "html",
	readmeMDTable:         "table",
}

// readmeMDBlock is one leaf block of a GitHub Flavored Markdown document as
// GitHub renders it. Lines are the block's lines with block quote markers and
// list item indentation removed, and LineNos their 0-based line numbers. A
// heading's one line is its text. A table's lines are its header row and its
// body rows, which Cells holds split into cells; its delimiter row is Delim.
type readmeMDBlock struct {
	Kind    readmeMDKind
	Lines   []string
	LineNos []int
	Depth   int // block quotes and list items around the block
	Level   int // heading level
	Delim   string
	Cells   [][]string
}

// text returns the block's text on one line.
func (b readmeMDBlock) text() string {
	return strings.Join(strings.Fields(strings.Join(b.Lines, " ")), " ")
}

// readmeMDContainer is an open block quote or list item.
type readmeMDContainer struct {
	quote          bool // a block quote; otherwise a list item
	indent         int  // the column a list item's content starts at
	emptyFirstLine bool // a list item whose marker line had no content
}

// readmeMDParser splits a document into leaf blocks by the block rules of
// the GitHub Flavored Markdown spec (https://github.github.com/gfm/): block
// quotes and list items with lazy paragraph continuation, ATX and setext
// headings, thematic breaks, fenced and indented code, HTML blocks,
// paragraphs and tables. Inline content is not parsed. The self-telemetry
// section and the README-wide stray-row check both read README.md through
// this one parser, so they agree on what renders as code, a table or prose.
type readmeMDParser struct {
	containers []readmeMDContainer
	leaf       *readmeMDBlock
	fenceChar  byte
	fenceLen   int
	htmlEnd    *regexp.Regexp // end condition of an HTML block of kinds 1 to 5
	blocks     []readmeMDBlock
}

var (
	readmeATXRE           = regexp.MustCompile(`^(#{1,6})(?:[ ]+|$)(.*)$`)
	readmeATXCloseRE      = regexp.MustCompile(`(?:^|[ ]+)#+[ ]*$`)
	readmeSetextRE        = regexp.MustCompile(`^(=+|-+)[ ]*$`)
	readmeThematicBreakRE = regexp.MustCompile(`^(?:(?:\*[ ]*){3,}|(?:-[ ]*){3,}|(?:_[ ]*){3,})$`)
	readmeDelimCellRE     = regexp.MustCompile(`^:?-+:?$`)
	readmeHTMLRawRE       = regexp.MustCompile(`(?i)^<(script|pre|style|textarea)(?:[ \t>]|$)`)
	readmeHTMLRawEndREs   = map[string]*regexp.Regexp{
		"script":   regexp.MustCompile(`(?i)</script>`),
		"pre":      regexp.MustCompile(`(?i)</pre>`),
		"style":    regexp.MustCompile(`(?i)</style>`),
		"textarea": regexp.MustCompile(`(?i)</textarea>`),
	}
	readmeHTMLCommentEnd = regexp.MustCompile(`-->`)
	readmeHTMLPIEnd      = regexp.MustCompile(`\?>`)
	readmeHTMLDeclRE     = regexp.MustCompile(`^<![A-Za-z]`)
	readmeHTMLDeclEnd    = regexp.MustCompile(`>`)
	readmeHTMLCDATAEnd   = regexp.MustCompile(`\]\]>`)
	readmeHTMLBlockTagRE = regexp.MustCompile(`(?i)^</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[ >]|/>|$)`)
	readmeHTMLTagLineRE  = regexp.MustCompile("^(?:<[A-Za-z][A-Za-z0-9-]*(?:[ ]+[A-Za-z_:][A-Za-z0-9_.:-]*(?:[ ]*=[ ]*(?:[^ \"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*[ ]*/?>|</[A-Za-z][A-Za-z0-9-]*[ ]*>)[ ]*$")
)

func readmeLines(readme string) []string {
	return strings.Split(readmeNormalizeEOL(readme), "\n")
}

// readmeExpandTabs expands tabs to the next multiple of four columns, the
// tab stop the spec uses for block structure.
func readmeExpandTabs(line string) string {
	if !strings.Contains(line, "\t") {
		return line
	}
	var b strings.Builder
	col := 0
	for _, r := range line {
		if r == '\t' {
			n := 4 - col%4
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		col++
	}
	return b.String()
}

func readmeIndent(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// readmeParseMarkdown returns the leaf blocks of a GitHub Flavored Markdown
// document in order.
func readmeParseMarkdown(doc string) []readmeMDBlock {
	var p readmeMDParser
	for no, line := range readmeLines(doc) {
		p.line(no, readmeExpandTabs(line))
	}
	p.closeLeaf()
	return p.blocks
}

func (p *readmeMDParser) line(no int, line string) {
	rest, matched := line, 0
match:
	for idx, c := range p.containers {
		ind := readmeIndent(rest)
		switch {
		case c.quote && ind <= 3 && ind < len(rest) && rest[ind] == '>':
			rest = strings.TrimPrefix(rest[ind+1:], " ")
		case c.quote:
			break match
		case strings.TrimSpace(rest) == "":
			if c.emptyFirstLine {
				break match
			}
			rest = ""
		case ind >= c.indent:
			p.containers[idx].emptyFirstLine = false
			rest = rest[c.indent:]
		default:
			break match
		}
		matched++
	}
	blank := strings.TrimSpace(rest) == ""

	if p.leaf != nil && matched == len(p.containers) {
		switch p.leaf.Kind {
		case readmeMDFencedCode:
			p.add(no, rest)
			if readmeClosesFence(rest, p.fenceChar, p.fenceLen) {
				p.closeLeaf()
			}
			return
		case readmeMDHTML:
			if p.htmlEnd == nil && blank {
				p.closeLeaf()
				return
			}
			p.add(no, rest)
			if p.htmlEnd != nil && p.htmlEnd.MatchString(rest) {
				p.closeLeaf()
			}
			return
		case readmeMDIndentedCode:
			if blank || readmeIndent(rest) >= 4 {
				p.add(no, rest)
				return
			}
			p.closeLeaf()
		}
	}

	if matched < len(p.containers) {
		// A lazy continuation line extends an open paragraph without its
		// block quote markers or list indentation; any other line closes
		// the containers it does not continue.
		if p.leaf != nil && p.leaf.Kind == readmeMDParagraph && !blank && !readmeStartsBlock(rest) {
			p.add(no, strings.TrimSpace(rest))
			return
		}
		p.closeLeaf()
		p.containers = p.containers[:matched]
	}
	p.start(no, rest)
}

// start opens the containers and the leaf block that begin on a line, or
// adds the line to the open paragraph or table.
func (p *readmeMDParser) start(no int, rest string) {
	for {
		inPara := p.leaf != nil && p.leaf.Kind == readmeMDParagraph
		inTable := p.leaf != nil && p.leaf.Kind == readmeMDTable
		if strings.TrimSpace(rest) == "" {
			if inPara || inTable {
				p.closeLeaf()
			}
			return
		}
		ind := readmeIndent(rest)
		if ind >= 4 {
			if inPara {
				p.add(no, strings.TrimSpace(rest))
				return
			}
			// Indented code also ends a table.
			p.closeLeaf()
			p.push(readmeMDIndentedCode, no, rest)
			return
		}
		s := rest[ind:]
		if s[0] == '>' {
			p.closeLeaf()
			p.containers = append(p.containers, readmeMDContainer{quote: true})
			rest = strings.TrimPrefix(s[1:], " ")
			continue
		}
		if m := readmeATXRE.FindStringSubmatch(s); m != nil {
			p.closeLeaf()
			p.push(readmeMDHeading, no, strings.TrimSpace(readmeATXCloseRE.ReplaceAllString(m[2], "")))
			p.leaf.Level = len(m[1])
			p.closeLeaf()
			return
		}
		if c, n, ok := readmeOpensFence(s); ok {
			p.closeLeaf()
			p.push(readmeMDFencedCode, no, rest)
			p.fenceChar, p.fenceLen = c, n
			return
		}
		if end, ok := readmeStartsHTML(s, inPara); ok {
			p.closeLeaf()
			p.push(readmeMDHTML, no, rest)
			p.htmlEnd = end
			if end != nil && end.MatchString(s) {
				p.closeLeaf()
			}
			return
		}
		if m := readmeSetextRE.FindStringSubmatch(s); m != nil && inPara {
			p.leaf.Kind, p.leaf.Level = readmeMDHeading, 2
			if m[1][0] == '=' {
				p.leaf.Level = 1
			}
			p.closeLeaf()
			return
		}
		if readmeThematicBreakRE.MatchString(s) {
			p.closeLeaf()
			p.push(readmeMDThematicBreak, no, s)
			p.closeLeaf()
			return
		}
		if width, content, ok := readmeListMarker(s, inPara); ok {
			p.closeLeaf()
			p.containers = append(p.containers, readmeMDContainer{
				indent:         ind + width,
				emptyFirstLine: strings.TrimSpace(content) == "",
			})
			rest = content
			continue
		}
		if inPara {
			// The paragraph's last line becomes the header row when this
			// line is a delimiter row with the same number of cells.
			if delim, ok := readmeTableDelimiter(s); ok {
				if header := readmeSplitTableRow(p.leaf.Lines[len(p.leaf.Lines)-1]); len(header) == len(delim) {
					p.startTable(s, header)
					return
				}
			}
			p.add(no, strings.TrimSpace(rest))
			return
		}
		if inTable {
			// Any line that starts no other block is one more row, with or
			// without pipes.
			p.add(no, strings.TrimSpace(rest))
			p.leaf.Cells = append(p.leaf.Cells, readmeSplitTableRow(rest))
			return
		}
		p.closeLeaf()
		p.push(readmeMDParagraph, no, strings.TrimSpace(rest))
		return
	}
}

func (p *readmeMDParser) push(kind readmeMDKind, no int, line string) {
	p.leaf = &readmeMDBlock{Kind: kind, Depth: len(p.containers), Lines: []string{line}, LineNos: []int{no}}
}

func (p *readmeMDParser) add(no int, line string) {
	p.leaf.Lines = append(p.leaf.Lines, line)
	p.leaf.LineNos = append(p.leaf.LineNos, no)
}

func (p *readmeMDParser) startTable(delim string, header []string) {
	para := p.leaf
	last := len(para.Lines) - 1
	table := readmeMDBlock{
		Kind:    readmeMDTable,
		Depth:   para.Depth,
		Delim:   delim,
		Lines:   []string{para.Lines[last]},
		LineNos: []int{para.LineNos[last]},
		Cells:   [][]string{header},
	}
	para.Lines, para.LineNos = para.Lines[:last], para.LineNos[:last]
	if last > 0 {
		p.closeLeaf()
	}
	p.leaf = &table
}

func (p *readmeMDParser) closeLeaf() {
	if p.leaf == nil {
		return
	}
	b := *p.leaf
	if b.Kind == readmeMDIndentedCode {
		for n := len(b.Lines); n > 0 && strings.TrimSpace(b.Lines[n-1]) == ""; n = len(b.Lines) {
			b.Lines, b.LineNos = b.Lines[:n-1], b.LineNos[:n-1]
		}
	}
	p.blocks = append(p.blocks, b)
	p.leaf, p.htmlEnd = nil, nil
}

// readmeOpensFence reports whether s, indentation removed, opens a fenced
// code block: three or more backticks whose info string has no backtick, or
// three or more tildes.
func readmeOpensFence(s string) (byte, int, bool) {
	if s == "" || (s[0] != '`' && s[0] != '~') {
		return 0, 0, false
	}
	c, n := s[0], 0
	for n < len(s) && s[n] == c {
		n++
	}
	if n < 3 || (c == '`' && strings.Contains(s[n:], "`")) {
		return 0, 0, false
	}
	return c, n, true
}

// readmeClosesFence reports whether line closes a fence of n c characters:
// at most three spaces of indentation, at least n of the same character, and
// nothing after them but spaces.
func readmeClosesFence(line string, c byte, n int) bool {
	ind := readmeIndent(line)
	if ind > 3 {
		return false
	}
	s := line[ind:]
	m := 0
	for m < len(s) && s[m] == c {
		m++
	}
	return m >= n && strings.TrimRight(s[m:], " ") == ""
}

// readmeStartsHTML reports whether s starts an HTML block and returns the
// end condition of kinds 1 to 5; kinds 6 and 7 end at a blank line and kind 7
// cannot interrupt a paragraph.
func readmeStartsHTML(s string, inPara bool) (*regexp.Regexp, bool) {
	if m := readmeHTMLRawRE.FindStringSubmatch(s); m != nil {
		return readmeHTMLRawEndREs[strings.ToLower(m[1])], true
	}
	switch {
	case strings.HasPrefix(s, "<!--"):
		return readmeHTMLCommentEnd, true
	case strings.HasPrefix(s, "<?"):
		return readmeHTMLPIEnd, true
	case strings.HasPrefix(s, "<![CDATA["):
		return readmeHTMLCDATAEnd, true
	case readmeHTMLDeclRE.MatchString(s):
		return readmeHTMLDeclEnd, true
	case readmeHTMLBlockTagRE.MatchString(s):
		return nil, true
	case !inPara && readmeHTMLTagLineRE.MatchString(s):
		return nil, true
	}
	return nil, false
}

// readmeListMarker reports whether s starts a list item and returns the
// width of the marker and its spacing, which is where the item's content
// starts, and the content on this line. Inside a paragraph only a non-empty
// bullet item or an ordered item numbered 1 can start.
func readmeListMarker(s string, inPara bool) (int, string, bool) {
	n := 0
	if s[0] == '-' || s[0] == '+' || s[0] == '*' {
		n = 1
	} else {
		for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
			n++
		}
		if n == 0 || n >= len(s) || (s[n] != '.' && s[n] != ')') || (inPara && s[:n] != "1") {
			return 0, "", false
		}
		n++
	}
	after := s[n:]
	if strings.TrimSpace(after) == "" {
		if inPara {
			return 0, "", false
		}
		return n + 1, "", true
	}
	if after[0] != ' ' {
		return 0, "", false
	}
	if spaces := readmeIndent(after); spaces < 5 {
		return n + spaces, after[spaces:], true
	}
	return n + 1, after[1:], true
}

// readmeTableDelimiter reports whether s is a table delimiter row and
// returns its cells.
func readmeTableDelimiter(s string) ([]string, bool) {
	cells := readmeSplitTableRow(s)
	for _, c := range cells {
		if !readmeDelimCellRE.MatchString(c) {
			return nil, false
		}
	}
	return cells, true
}

// readmeStartsBlock reports whether a line starts a block that interrupts a
// paragraph, which keeps it from being a lazy continuation line.
func readmeStartsBlock(line string) bool {
	ind := readmeIndent(line)
	if ind >= 4 || ind == len(line) {
		return false
	}
	s := line[ind:]
	if s[0] == '>' || readmeATXRE.MatchString(s) || readmeThematicBreakRE.MatchString(s) {
		return true
	}
	if _, _, ok := readmeOpensFence(s); ok {
		return true
	}
	if _, ok := readmeStartsHTML(s, true); ok {
		return true
	}
	_, _, ok := readmeListMarker(s, true)
	return ok
}

// readmeSkipCodeSpan returns the index just past the code span that opens
// with the backtick run at s[i], or past the run itself when no run of the
// same length closes it, in which case the run is literal text.
func readmeSkipCodeSpan(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}
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
			return j + m
		}
		j += m
	}
	return i + n
}

// readmeFirstPipe returns the index of the first pipe in s that is neither
// escaped nor inside a code span, or -1.
func readmeFirstPipe(s string) int {
	for i := 0; i < len(s); {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			i = readmeSkipCodeSpan(s, i)
		case '|':
			return i
		default:
			i++
		}
	}
	return -1
}

// readmeSelfTelemetrySection is the self-telemetry table of README.md and the
// blocks from its intro paragraph up to the next heading of level 3 or higher.
type readmeSelfTelemetrySection struct {
	Rows   []readmeTelemetryRow
	Blocks []readmeMDBlock
	// Intro and Table index the intro paragraph and the table in Blocks, and
	// Blocks[Intro:End] (excluding Table) are the section's blocks.
	Intro, Table, End int
}

const (
	readmeSelfTelemetryIntro     = "Use these content-free self-telemetry instruments"
	readmeSelfTelemetryIntroFull = "Use these content-free self-telemetry instruments (declared in `metadata.yaml` and `internal/metadata/telemetry.go`) to detect a stuck path:"
)

var readmeSelfTelemetryHeader = []string{"Metric", "Type", "Unit", "Attributes", "Meaning"}

func parseReadmeSelfTelemetrySection(readme string) (readmeSelfTelemetrySection, error) {
	blocks := readmeParseMarkdown(readme)
	intro := slices.IndexFunc(blocks, func(b readmeMDBlock) bool {
		return b.Kind == readmeMDParagraph && b.Depth == 0 && strings.Contains(b.text(), readmeSelfTelemetryIntro)
	})
	if intro < 0 {
		return readmeSelfTelemetrySection{}, fmt.Errorf("README.md is missing self-telemetry intro %q", readmeSelfTelemetryIntro)
	}
	table := -1
	for i := intro + 1; i < len(blocks) && table < 0; i++ {
		if blocks[i].Kind == readmeMDHeading && blocks[i].Depth == 0 {
			break
		}
		if blocks[i].Kind == readmeMDTable && blocks[i].Depth == 0 {
			table = i
		}
	}
	if table < 0 {
		return readmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry markdown table not found after intro")
	}

	tb := blocks[table]
	if header := tb.Cells[0]; !slices.Equal(header, readmeSelfTelemetryHeader) {
		return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table header = %v, want %v", header, readmeSelfTelemetryHeader)
	}
	if sep := readmeSplitTableRow(tb.Delim); len(sep) != len(readmeSelfTelemetryHeader) || !isMarkdownSeparatorRow(sep) {
		return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table separator row %v is malformed", sep)
	}

	var rows []readmeTelemetryRow
	for r := 1; r < len(tb.Lines); r++ {
		line, cells := tb.Lines[r], tb.Cells[r]
		// GitHub ends a table only at a blank line or the start of another
		// block, so prose right under the last row renders as a row.
		if !strings.HasPrefix(line, "|") {
			return readmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry table is followed directly by %q; GitHub renders that line as a table row, so leave a blank line", line)
		}
		if len(cells) != len(readmeSelfTelemetryHeader) {
			return readmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry row %q has %d cells, want %d", line, len(cells), len(readmeSelfTelemetryHeader))
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

	end := table + 1
	for end < len(blocks) && (blocks[end].Kind != readmeMDHeading || blocks[end].Depth > 0 || blocks[end].Level > 3) {
		end++
	}
	return readmeSelfTelemetrySection{Rows: rows, Blocks: blocks, Intro: intro, Table: table, End: end}, nil
}

// prose returns the rendered text of the self-telemetry section outside the
// intro sentence and table, one entry per paragraph, heading, HTML block or
// table cell, wherever block quotes or lists put it. Code is not prose.
func (s readmeSelfTelemetrySection) prose() []string {
	var units []string
	for i := s.Intro; i < s.End; i++ {
		if i == s.Table {
			continue
		}
		b := s.Blocks[i]
		if i == s.Intro {
			if rest := strings.TrimSpace(strings.Replace(b.text(), readmeSelfTelemetryIntroFull, "", 1)); rest != "" {
				units = append(units, rest)
			}
			continue
		}
		switch b.Kind {
		case readmeMDParagraph, readmeMDHeading, readmeMDHTML:
			units = append(units, b.text())
		case readmeMDTable:
			for _, row := range b.Cells {
				units = append(units, row...)
			}
		}
	}
	return units
}

var (
	readmeMetricNameRE     = regexp.MustCompile(dashPromPrefix + `[a-z0-9_]+`)
	readmeMetricNameOnlyRE = regexp.MustCompile(`^` + dashPromPrefix + `[a-z0-9_]+$`)
)

// readmeRowLike reports whether a paragraph line reads as a table row cut off
// from its table: it starts with a pipe and has a second one, or the text
// before its first pipe is only a self-telemetry metric name.
func readmeRowLike(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "|") {
		return strings.Contains(s[1:], "|")
	}
	i := readmeFirstPipe(s)
	if i < 0 {
		return false
	}
	first := strings.TrimSpace(s[:i])
	if inner, ok := unwrapInlineCode(first); ok {
		first = inner
	}
	return readmeMetricNameOnlyRE.MatchString(first)
}

// readmeStrayTelemetryRows reports self-telemetry rows outside the
// self-telemetry table: rows of any other rendered table, at any depth, that
// declare a metric or repeat the table header, and paragraph lines that read
// as rows cut off from a table. Inside the self-telemetry section every such
// line is debris; elsewhere only lines naming a metric are. Code never
// renders as a table, and prose that merely contains a pipe is not a row.
func readmeStrayTelemetryRows(section readmeSelfTelemetrySection) []string {
	var problems []string
	for i, b := range section.Blocks {
		inSection := i >= section.Intro && i < section.End && i != section.Table
		switch {
		case b.Kind == readmeMDTable && i != section.Table:
			for r, cells := range b.Cells {
				if r == 0 && slices.Equal(cells, readmeSelfTelemetryHeader) {
					problems = append(problems, fmt.Sprintf("README.md line %d starts another self-telemetry table outside the self-telemetry table", b.LineNos[r]+1))
					continue
				}
				for _, cell := range cells {
					for _, name := range readmeMetricNameRE.FindAllString(cell, -1) {
						problems = append(problems, fmt.Sprintf("README.md line %d is a table row naming %s outside the self-telemetry table", b.LineNos[r]+1, name))
					}
				}
			}
		case b.Kind == readmeMDParagraph:
			for k, line := range b.Lines {
				if !readmeRowLike(line) {
					continue
				}
				if inSection {
					problems = append(problems, fmt.Sprintf("self-telemetry section contains orphaned markdown table row %q after table ended", line))
					continue
				}
				for _, name := range readmeMetricNameRE.FindAllString(line, -1) {
					problems = append(problems, fmt.Sprintf("README.md line %d is a table row naming %s outside the self-telemetry table", b.LineNos[k]+1, name))
				}
			}
		}
	}
	return problems
}

// The recovery prose after the self-telemetry table is parsed sentence by
// sentence. Every sentence must be one of three checked forms or carry no
// recovery claim at all:
//
//	Of the <count> non-counter current-value instruments, `a` and `b`
//	(`UpDownCounter`) should return to zero after recovery or clean shutdown.
//
//	When `write.backpressure.enabled` is `true`, `x` (<unit wording>[ in
//	`<range>`]) recovers toward `<zero target>` and `y` (<unit wording>)
//	recovers to `<target>`, not zero.
//
//	A sustained nonzero `a` or `b` count, rising timeout/retirement/
//	uncertain-ack counters, or queue drops indicates “accepted by the
//	collector, not yet confirmed by BigQuery.”
//
// A form must match the whole sentence, so a negation, qualifier or changed
// condition anywhere in it ("it is false that", "before recovery", "remain
// nonzero") leaves the sentence unchecked, and an unchecked sentence may not
// use recovery wording, name a current-value instrument next to a negation
// or a value, negate another statement, or count instruments. Each
// instrument is then bound to its own claim and target, a range in a gauge
// description must repeat the range in the gauge's table row, and the
// instrument count is stated once. Paragraphs, headings, HTML blocks and
// table cells are read wherever block quotes or lists put them; code blocks
// are not prose.
const (
	readmeNameAndList       = "`[a-z0-9_]+`(?:(?:, |,? and )`[a-z0-9_]+`)*"
	readmeNameOrList        = "`[a-z0-9_]+`(?:(?:, |,? or )`[a-z0-9_]+`)*"
	readmeCountWordPattern  = `(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:-(?:one|two|three|four|five|six|seven|eight|nine))?|zero|both|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|hundred|[0-9]+`
	readmeSubsetWordPattern = `(?:twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety)(?:-(?:one|two|three|four|five|six|seven|eight|nine))?|zero|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|hundred|[0-9]+`
)

var (
	readmeZeroSentenceRE = regexp.MustCompile("^Of the ([A-Za-z0-9]+(?:-[A-Za-z0-9]+)?) non-counter current-value instruments, (" + readmeNameAndList +
		") \\(`UpDownCounter`\\) should return to zero after recovery or clean shutdown\\.$")
	readmeDiagnosticSentenceRE = regexp.MustCompile("^A sustained nonzero (" + readmeNameOrList +
		") count, rising timeout/retirement/uncertain-ack counters, or queue drops indicates [“\"]accepted by the collector, not yet confirmed by BigQuery\\.[”\"]$")
	// The lenient forms find claims inside sentences that match no checked
	// form, so their instruments, targets and wording are still reported.
	readmeZeroClaimRE      = regexp.MustCompile("((?:`[a-z0-9_]+`(?:, and |, | and ))*`[a-z0-9_]+`) \\(`UpDownCounter`\\) should return to zero")
	readmeGaugeClaimRE     = regexp.MustCompile("`([a-z0-9_]+)` \\(([^()]*)\\) recovers (toward|to) `([^`]+)`(, not zero)?")
	readmeCodeNameRE       = regexp.MustCompile("`([a-z0-9_]+)`")
	readmeCountClaimRE     = regexp.MustCompile(`(?i)\b(` + readmeCountWordPattern + `)((?:[ -]+[a-z]+){0,6}?)[ -]+instruments?\b`)
	readmeSubsetCountRE    = regexp.MustCompile(`^(?i)(?:only\s+)?(` + readmeSubsetWordPattern + `)\s+of\s+the\s+(?:(` + readmeCountWordPattern + `)\s+)?(?:(?:non-counter|current-value)\s+)+instruments?\s+(?:is\s+(?:an?\s+)?|are\s+)(gauges?|` + "`updowncounters?`" + `|` + "`updowncounter`s" + `|updowncounters?|counters?|histograms?)\.$`)
	readmeReversalRE       = regexp.MustCompile(`(?i)\b(?:it is false|is false|are false|is not true|isn't true|are not true|aren't true|not the case|untrue|incorrect|the opposite|disregard|ignore (?:the|this|that|these|those|above|previous)|contrary to|contradict(?:s|ed|ing)?|only (?:in|when|if|after|during|under|on)|dry-run|unbounded(?:ly)?|indefinite(?:ly)?|forever)\b`)
	readmeNegationVerbRE   = regexp.MustCompile(`(?i)\b(?:neither|none of|never|cannot|can't|won't|does not|doesn't|do not|don't|did not|didn't|should not|shouldn't|will not|fails? to|unable to|rarely|seldom|barely|hardly|without|instead of)\b`)
	readmeNegationTargetRE = regexp.MustCompile("(?i)\\b(?:zero|nonzero|non-zero|positive|negative|elevated|floor|ceiling|bound(?:s|ed)?|idle|shutdown|restart(?:s|ed)?|recovery|clear(?:s|ed|ing)?|drain(?:s|ed|ing)?|return(?:s|ed|ing)?|recover(?:s|ed|ing)?|stay(?:s|ed|ing)?|remain(?:s|ed|ing)?|climb(?:s|ed|ing)?|grow(?:s|ed|ing)?|rise(?:s|n)?|rising|accurate|valid|true|correct|holds?|appl(?:y|ies)|claim|statement|sentence|guidance|above|previous|preceding|[0-9]+(?:\\.[0-9]+)?)\\b|`[0-9][0-9.]*`|`write\\.[^`]+`")
	readmePolarityRE       = regexp.MustCompile("(?i)\\b(?:not|never|no|none|nor|neither|cannot|false|untrue|incorrect|wrong|opposite|unless|except|without|instead|rarely|seldom|barely|hardly|fails?|unable|positive|negative|floor|ceiling|idle|forever|indefinite(?:ly)?|unbounded(?:ly)?|zero|nonzero|non-zero|recovery|shutdown|restart(?:s|ed)?|[0-9]+(?:\\.[0-9]+)?)\\b|n't\\b|`[0-9][0-9.]*`|`write\\.[^`]+`")
	// Wording that states what an instrument returns to.
	readmeRecoveryWordingREs = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\brecover(?:s|ed|ing)?\b`),
		regexp.MustCompile(`(?i)\breturn(?:s|ed|ing)?(?: [a-z]+){0,2} (?:to|toward)\b`),
		regexp.MustCompile(`(?i)\b(?:go|goes|going|went|gone|come|comes|coming|came|get|gets|got|getting|fall|falls|fell|falling|drop|drops|dropped|dropping|settle|settles|settled|settling) back\b`),
		regexp.MustCompile(`(?i)\b(?:reset|resets|resetting|revert|reverts|reverted|reverting|decay|decays|decayed|decaying|converge|converges|converged|converging|settle|settles|settled|settling)\b`),
		regexp.MustCompile(`(?i)\b(?:drop|drops|dropped|dropping|fall|falls|fell|falling|sink|sinks|sank|sinking) (?:to|toward)\b`),
		regexp.MustCompile(`(?i)\b(?:drain|drains|drained|draining|reach|reaches|reached|reaching|climb|climbs|climbed|climbing|grow|grows|grew|growing|rise|rises|rose|rising|increase|increases|increased|increasing|decrease|decreases|decreased|decreasing)\b`),
		regexp.MustCompile(`(?i)\b(?:stay|stays|stayed|staying|remain|remains|remained|remaining|stuck|hold|holds|held|holding|keep|keeps|kept|keeping|linger|lingers|lingered|lingering) (?:at |above |below |near )?(?:non-?zero|zero|positive|negative|elevated|high|low|constant|flat|unchanged|pinned|bounded|unbounded|[0-9]+(?:\.[0-9]+)?|` + "`[0-9][0-9.]*`" + `)\b`),
	}
	readmeCountStopwords = map[string]bool{
		"as": true, "at": true, "by": true, "for": true, "from": true,
		"in": true, "on": true, "than": true, "to": true, "with": true,
	}
)

// readmeGaugeSentenceRE is the checked gauge sentence. A description is the
// gauge's unit wording, optionally followed by a range in code.
var readmeGaugeSentenceRE = sync.OnceValue(func() *regexp.Regexp {
	wordings := slices.Sorted(maps.Values(readmeGaugeUnitWording))
	for i, w := range wordings {
		wordings[i] = regexp.QuoteMeta(w)
	}
	desc := "(?:" + strings.Join(wordings, "|") + ")(?: in `[^`]+`)?"
	claim := "`[a-z0-9_]+` \\(" + desc + "\\) recovers (?:toward|to) `[^`]+`(?:, not zero)?"
	return regexp.MustCompile("^When `write\\.backpressure\\.enabled` is `true`, " + claim + "(?:(?:, |,? and )" + claim + ")*\\.$")
})

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
	"zero": 0, "both": 2, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
	"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
	"thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16, "seventeen": 17,
	"eighteen": 18, "nineteen": 19, "twenty": 20, "thirty": 30, "forty": 40,
	"fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90, "hundred": 100,
}

func readmeEndsAbbrev(prefix string) bool {
	lower := strings.ToLower(prefix)
	for _, abbrev := range []string{"e.g.", "i.e.", "cf.", "vs."} {
		if strings.HasSuffix(lower, abbrev) && (len(lower) == len(abbrev) || lower[len(lower)-len(abbrev)-1] == ' ' || lower[len(lower)-len(abbrev)-1] == '(') {
			return true
		}
	}
	return false
}

// readmeSentences splits one block of prose into sentences. A sentence ends
// at a period, question mark or exclamation mark outside code spans,
// followed by any closing quotes or brackets and then a space or the end.
func readmeSentences(text string) []string {
	var out []string
	start := 0
	for i := 0; i < len(text); {
		switch text[i] {
		case '`':
			i = readmeSkipCodeSpan(text, i)
			continue
		case '.', '!', '?':
			if text[i] == '.' && readmeEndsAbbrev(text[:i+1]) {
				i++
				continue
			}
			j := i + 1
			for j < len(text) {
				k := 0
				for _, closer := range []string{"”", "’", "\"", "'", ")", "]", "*", "_"} {
					if strings.HasPrefix(text[j:], closer) {
						k = len(closer)
						break
					}
				}
				if k == 0 {
					break
				}
				j += k
			}
			if j == len(text) || text[j] == ' ' {
				if s := strings.TrimSpace(text[start:j]); s != "" {
					out = append(out, s)
				}
				start, i = j, j
				continue
			}
		}
		i++
	}
	if s := strings.TrimSpace(text[start:]); s != "" {
		out = append(out, s)
	}
	return out
}

func readmeParseCountWord(word string) (int, bool) {
	lower := strings.ToLower(word)
	if n, ok := readmeNumberWords[lower]; ok {
		return n, true
	}
	if tensWord, onesWord, ok := strings.Cut(lower, "-"); ok {
		tens, okT := readmeNumberWords[tensWord]
		ones, okO := readmeNumberWords[onesWord]
		if okT && okO && tens >= 20 && tens <= 90 && tens%10 == 0 && ones >= 1 && ones <= 9 {
			return tens + ones, true
		}
	}
	n, err := strconv.Atoi(word)
	return n, err == nil
}

// validateReadmeRecoveryProse checks the recovery prose units against
// metadata.yaml; meanings holds the table's meaning cell of each metric, which
// any range a gauge description states must repeat.
func validateReadmeRecoveryProse(units []string, metrics map[string]readmeMetadataMetric, meanings map[string]string) []string {
	var problems []string
	if strings.Contains(strings.ToLower(strings.Join(units, " ")), "both current-value instruments") {
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
	currentValue := append(slices.Clone(upDown), gauges...)
	want := len(currentValue)
	short := func(name string) string { return strings.TrimPrefix(name, dashPromPrefix) }

	// Unchecked sentences may not name a current-value instrument next to
	// a negation, a recovery condition or a value, including any recovery
	// target in code.
	var mentionRE *regexp.Regexp
	if len(currentValue) > 0 {
		alts := make([]string, len(currentValue))
		for i, name := range currentValue {
			alts[i] = regexp.QuoteMeta(short(name))
		}
		mentionRE = regexp.MustCompile(`\b(?:` + regexp.QuoteMeta(dashPromPrefix) + `)?(?:` + strings.Join(alts, "|") + `)\b`)
	}
	var targetSpans []string
	for _, target := range readmeGaugeRecoveryTargets {
		targetSpans = append(targetSpans, "`"+target+"`")
	}
	slices.Sort(targetSpans)

	claims := map[string]int{}  // every claim, in a checked form or not
	checked := map[string]int{} // claims in checked forms
	zeroSentences, countClaims := 0, 0
	addZeroClaims := func(list string, inForm bool) {
		for _, m := range readmeCodeNameRE.FindAllStringSubmatch(list, -1) {
			name := dashPromPrefix + m[1]
			claims[name]++
			if inForm {
				checked[name]++
			}
			spec, ok := metrics[name]
			switch {
			case !ok:
				problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose names %s, which metadata.yaml does not declare", m[1]))
			case !spec.isUpDownCounter():
				problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose says %s returns to zero as an UpDownCounter, but metadata.yaml declares it as %s", m[1], spec.typeLabel()))
			}
		}
	}
	addGaugeClaim := func(m []string, inForm bool) {
		shortName, desc, prep, target, notZero := m[1], m[2], m[3], m[4], m[5] != ""
		name := dashPromPrefix + shortName
		claims[name]++
		if inForm {
			checked[name]++
		}
		spec, ok := metrics[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose names %s, which metadata.yaml does not declare", shortName))
			return
		}
		if spec.Gauge == nil {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose claims %s recovers %s %q, but metadata.yaml declares it as %s, not a gauge", shortName, prep, target, spec.typeLabel()))
			return
		}
		wantTarget, ok := readmeGaugeRecoveryTargets[name]
		if !ok {
			problems = append(problems, fmt.Sprintf("no recovery target is declared for gauge %s; add it to readmeGaugeRecoveryTargets", name))
			return
		}
		if target != wantTarget {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose binds %s to %q, want %q", shortName, target, wantTarget))
		}
		wording, known := readmeGaugeUnitWording[spec.Unit]
		statedRange, ranged := strings.CutPrefix(strings.TrimPrefix(desc, wording), " in ")
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf("no recovery wording is declared for gauge unit %q of %s; add it to readmeGaugeUnitWording", spec.Unit, name))
		case !strings.HasPrefix(desc, wording):
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose describes %s as %q, but metadata.yaml declares unit %q (%s)", shortName, desc, spec.Unit, wording))
		case ranged && !strings.Contains(meanings[name], statedRange):
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose describes %s with the range %s, which its self-telemetry table row does not state", shortName, statedRange))
		}
		switch zero := wantTarget == "0" || wantTarget == "0.0"; {
		case !zero && !notZero:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose must say %s recovers to `%s`, not zero", shortName, wantTarget))
		case zero && notZero:
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose says %s recovers to `%s`, not zero, which contradicts itself", shortName, wantTarget))
		}
	}

	for _, unit := range units {
		for _, s := range readmeSentences(unit) {
			if sub := readmeSubsetCountRE.FindStringSubmatch(s); sub != nil {
				subWord, totalWord, kindRaw := sub[1], sub[2], strings.ToLower(strings.ReplaceAll(sub[3], "`", ""))
				if totalWord != "" {
					if total, ok := readmeParseCountWord(totalWord); !ok || total != want {
						problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts %q non-counter current-value instruments, metadata.yaml declares %d", totalWord, want))
					}
				}
				var wantKind int
				var kindDesc string
				switch {
				case strings.HasPrefix(kindRaw, "gauge"):
					wantKind, kindDesc = len(gauges), "gauges"
				case strings.HasPrefix(kindRaw, "updowncounter"):
					wantKind, kindDesc = len(upDown), "UpDownCounters"
				case strings.HasPrefix(kindRaw, "counter"):
					wantKind, kindDesc = 0, "counters"
				case strings.HasPrefix(kindRaw, "histogram"):
					wantKind, kindDesc = 0, "histograms"
				}
				if subCount, ok := readmeParseCountWord(subWord); !ok || subCount != wantKind {
					problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts %q current-value %s, metadata.yaml declares %d", subWord, kindDesc, wantKind))
				}
				continue
			}
			zeroForm := readmeZeroSentenceRE.FindStringSubmatch(s)
			countedOpening := false
			for _, loc := range readmeCountClaimRE.FindAllStringSubmatchIndex(s, -1) {
				stop := false
				for _, word := range strings.FieldsFunc(s[loc[4]:loc[5]], func(r rune) bool { return r == ' ' || r == '-' }) {
					stop = stop || readmeCountStopwords[strings.ToLower(word)]
				}
				if stop {
					continue
				}
				countClaims++
				word := s[loc[2]:loc[3]]
				n, ok := readmeParseCountWord(word)
				if !ok || n != want {
					problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts %q non-counter current-value instruments, metadata.yaml declares %d", word, want))
				}
				if zeroForm == nil || loc[2] != len("Of the ") {
					problems = append(problems, fmt.Sprintf(`README.md self-telemetry recovery prose counts instruments outside the opening "Of the <count> non-counter current-value instruments" clause: %q`, s))
				} else {
					countedOpening = true
				}
			}
			switch {
			case zeroForm != nil:
				zeroSentences++
				if !countedOpening {
					if n, ok := readmeParseCountWord(zeroForm[1]); !ok || n != want {
						problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts %q non-counter current-value instruments, metadata.yaml declares %d", zeroForm[1], want))
					}
				}
				addZeroClaims(zeroForm[2], true)
			case readmeGaugeSentenceRE().MatchString(s):
				for _, m := range readmeGaugeClaimRE.FindAllStringSubmatch(s, -1) {
					addGaugeClaim(m, true)
				}
			case readmeDiagnosticSentenceRE.MatchString(s):
				for _, m := range readmeCodeNameRE.FindAllStringSubmatch(readmeDiagnosticSentenceRE.FindStringSubmatch(s)[1], -1) {
					if spec, ok := metrics[dashPromPrefix+m[1]]; !ok || !spec.isUpDownCounter() {
						problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose reads a sustained nonzero %s count as unconfirmed data, but metadata.yaml does not declare it as an UpDownCounter", m[1]))
					}
				}
			default:
				for _, m := range readmeZeroClaimRE.FindAllStringSubmatch(s, -1) {
					addZeroClaims(m[1], false)
				}
				for _, m := range readmeGaugeClaimRE.FindAllStringSubmatch(s, -1) {
					addGaugeClaim(m, false)
				}
				problems = append(problems, readmeUncheckedSentenceProblems(s, mentionRE, targetSpans)...)
			}
		}
	}

	switch {
	case zeroSentences == 0:
		problems = append(problems, `README.md self-telemetry recovery prose must state "Of the <count> non-counter current-value instruments, <UpDownCounters> (`+"`UpDownCounter`"+`) should return to zero after recovery or clean shutdown."`)
	case countClaims > 1:
		problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose counts the instruments %d times, want exactly once", countClaims))
	case countClaims == 0:
		problems = append(problems, "README.md self-telemetry recovery prose does not state the non-counter current-value instrument count")
	}
	for _, name := range currentValue {
		if checked[name] == 0 {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has no recovery claim for %s in a checked sentence form", short(name)))
		}
		if n := claims[name]; n > 1 {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has %d recovery claims for %s, want exactly one", n, short(name)))
		}
	}
	targets := slices.Sorted(maps.Keys(readmeGaugeRecoveryTargets))
	for _, name := range targets {
		if spec, ok := metrics[name]; !ok || spec.Gauge == nil {
			problems = append(problems, fmt.Sprintf("readmeGaugeRecoveryTargets lists %s, which metadata.yaml does not declare as a gauge", name))
		}
	}
	return problems
}

// readmeUncheckedSentenceProblems reports what a sentence that matches no
// checked recovery form may not say.
func readmeUncheckedSentenceProblems(s string, mentionRE *regexp.Regexp, targetSpans []string) []string {
	var problems []string
	norm := strings.ReplaceAll(s, "’", "'")
	hasRecovery := false
	for _, re := range readmeRecoveryWordingREs {
		if re.MatchString(norm) {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose has a recovery statement outside the checked forms: %q", s))
			hasRecovery = true
			break
		}
	}
	negatedTarget := hasRecovery || readmeNegationTargetRE.MatchString(norm) || (mentionRE != nil && mentionRE.MatchString(norm))
	if !negatedTarget {
		for _, span := range targetSpans {
			if strings.Contains(norm, span) {
				negatedTarget = true
				break
			}
		}
	}
	if readmeReversalRE.MatchString(norm) || (readmeNegationVerbRE.MatchString(norm) && negatedTarget) {
		problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose negates or contradicts a statement outside the checked forms: %q", s))
	}
	if mentionRE == nil {
		return problems
	}
	if name := mentionRE.FindString(norm); name != "" {
		word := readmePolarityRE.FindString(norm)
		for _, span := range targetSpans {
			if word == "" && strings.Contains(norm, span) {
				word = span
			}
		}
		if word != "" {
			problems = append(problems, fmt.Sprintf("README.md self-telemetry recovery prose names %s next to %q outside the checked recovery forms: %q", name, word, s))
		}
	}
	return problems
}

// readmeGoInstrument is one instrument constructor call in internal/metadata,
// such as m.Int64Counter(nameX, opts...).
type readmeGoInstrument struct {
	Name       string
	TypeLabel  string
	Units      []string
	Boundaries []float64
	Where      string
}

// readmeGoRecording is one Add or Record call on a Telemetry instrument, such
// as t.X.Add(ctx, n, metric.WithAttributes(attribute.String(AttrReason, r))).
type readmeGoRecording struct {
	Field string
	Attrs []string
	// Known is false when an option is not a literal WithAttributes list
	// whose keys are constants; Why says what could not be read.
	Known bool
	Why   string
	Where string
}

// readmeTelemetryModel is what internal/metadata constructs and records,
// read with full type information.
type readmeTelemetryModel struct {
	loaded      bool
	instruments []readmeGoInstrument
	fields      map[string]string // Telemetry field -> metric name
	recordings  []readmeGoRecording
	names       []string // metric-name constants
	problems    []string
}

const (
	readmeMetricPkgPath    = "go.opentelemetry.io/otel/metric"
	readmeAttributePkgPath = "go.opentelemetry.io/otel/attribute"
	readmeMetadataPkgPath  = "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
)

var readmeGoCtorRE = regexp.MustCompile(`^(Int64|Float64)(Observable)?(Counter|UpDownCounter|Gauge|Histogram)$`)

// readmeAttributeConstructors are the attribute functions, and the methods
// of attribute.Key of the same names, that build one key-value pair.
var readmeAttributeConstructors = map[string]bool{
	"String": true, "Bool": true, "Int": true, "Int64": true, "Float64": true, "Stringer": true,
	"StringSlice": true, "BoolSlice": true, "IntSlice": true, "Int64Slice": true, "Float64Slice": true,
}

// readmeTelemetry type-checks internal/metadata from source. The packages it
// imports are read from the export data the go command builds for them, with
// the same race and tag settings as this test binary so that a test run finds
// them in the build cache. Models are cached by source.
var readmeTelemetry struct {
	sync.Mutex
	fset    *token.FileSet
	exports map[string]string // import path -> export data file
	imp     types.Importer
	models  map[[sha256.Size]byte]readmeTelemetryModel
}

// readmeGoListBuildFlags returns the build flags of this test binary that
// change compiled packages, so `go list -export` reuses its build.
func readmeGoListBuildFlags() []string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	var flags []string
	for _, s := range info.Settings {
		switch s.Key {
		case "-race", "-msan", "-asan", "-trimpath":
			if s.Value == "true" {
				flags = append(flags, s.Key)
			}
		case "-tags", "-gcflags":
			if s.Value != "" {
				flags = append(flags, s.Key+"="+s.Value)
			}
		}
	}
	return flags
}

// readmeLoadExports adds the export data files of paths to readmeTelemetry.
// The caller holds the lock.
func readmeLoadExports(paths []string) error {
	var missing []string
	for _, p := range paths {
		if _, ok := readmeTelemetry.exports[p]; !ok && p != "unsafe" {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("the go command is needed to load export data: %w", err)
	}
	args := append([]string{"list", "-e", "-export", "-f", "{{.ImportPath}}\t{{.Export}}\t{{with .Error}}{{.Err}}{{end}}"}, readmeGoListBuildFlags()...)
	args = append(args, missing...)
	cmd := exec.Command(goBin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	for _, line := range strings.Split(string(out), "\n") {
		path, rest, ok := strings.Cut(strings.TrimRight(line, "\r"), "\t")
		if !ok {
			continue
		}
		export, listErr, _ := strings.Cut(rest, "\t")
		if export == "" {
			return fmt.Errorf("go list has no export data for %s: %s", path, listErr)
		}
		readmeTelemetry.exports[path] = export
	}
	for _, p := range missing {
		if _, ok := readmeTelemetry.exports[p]; !ok {
			return fmt.Errorf("go list did not report package %s", p)
		}
	}
	return nil
}

// readmeTelemetryInit prepares readmeTelemetry. The caller holds the lock.
func readmeTelemetryInit() {
	if readmeTelemetry.fset != nil {
		return
	}
	readmeTelemetry.fset = token.NewFileSet()
	readmeTelemetry.exports = map[string]string{}
	readmeTelemetry.models = map[[sha256.Size]byte]readmeTelemetryModel{}
	readmeTelemetry.imp = importer.ForCompiler(readmeTelemetry.fset, "gc", func(path string) (io.ReadCloser, error) {
		file, ok := readmeTelemetry.exports[path]
		if !ok {
			return nil, fmt.Errorf("no export data for %s", path)
		}
		return os.Open(file)
	})
}

// readTelemetryPackage returns the telemetry model of the internal/metadata
// package made of files, keyed by file name.
func readTelemetryPackage(files map[string]string) readmeTelemetryModel {
	readmeTelemetry.Lock()
	defer readmeTelemetry.Unlock()
	readmeTelemetryInit()
	h := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(files)) {
		h.Write([]byte(strconv.Quote(name) + " " + strconv.Quote(files[name]) + "\n"))
	}
	var key [sha256.Size]byte
	h.Sum(key[:0])
	if model, ok := readmeTelemetry.models[key]; ok {
		return model
	}
	model := analyzeTelemetryPackage(files)
	readmeTelemetry.models[key] = model
	return model
}

func analyzeTelemetryPackage(files map[string]string) readmeTelemetryModel {
	model := readmeTelemetryModel{fields: map[string]string{}}
	fset := readmeTelemetry.fset
	var parsed []*ast.File
	imports := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(files)) {
		path := "internal/metadata/" + name
		f, err := parser.ParseFile(fset, path, files[name], parser.SkipObjectResolution)
		if err != nil {
			model.problems = append(model.problems, fmt.Sprintf("parsing %s: %v", path, err))
			return model
		}
		parsed = append(parsed, f)
		for _, spec := range f.Imports {
			p, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				continue
			}
			imports[p] = true
			if p == "unsafe" || p == "reflect" {
				model.problems = append(model.problems, fmt.Sprintf("%s imports %s, which can reach Telemetry instruments without a checkable call", path, p))
			}
		}
	}
	if err := readmeLoadExports(slices.Sorted(maps.Keys(imports))); err != nil {
		model.problems = append(model.problems, fmt.Sprintf("cannot type-check internal/metadata, so its telemetry cannot be verified: %v", err))
		return model
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{
		Importer: readmeTelemetry.imp,
		Error: func(err error) {
			model.problems = append(model.problems, fmt.Sprintf("internal/metadata does not type-check, so its telemetry cannot be fully verified: %v", err))
		},
	}
	pkg, _ := conf.Check(readmeMetadataPkgPath, fset, parsed, info)
	if pkg == nil {
		return model
	}
	model.loaded = true
	a := &readmeTelemetryAnalysis{
		fset:     fset,
		files:    parsed,
		info:     info,
		pkg:      pkg,
		model:    &model,
		parents:  map[ast.Node]ast.Node{},
		fields:   map[*types.Var]bool{},
		defs:     map[*types.Var]ast.Expr{},
		multiDef: map[*types.Var]bool{},
		writes:   map[*types.Var]int{},
		allowed:  map[ast.Node]bool{},
		assigns:  map[string][]string{},
	}
	a.run()
	return model
}

// readmeTelemetryAnalysis finds every instrument constructor and every Add or
// Record call in internal/metadata through type information, so neither a
// local alias, nor parentheses, nor a local variable shadowing a key constant
// changes what it sees. Each recording call's receiver must resolve to one
// Telemetry instrument field, directly or through local aliases that are
// assigned once, and anything it cannot account for is reported, never
// skipped.
type readmeTelemetryAnalysis struct {
	fset  *token.FileSet
	files []*ast.File
	info  *types.Info
	pkg   *types.Package
	model *readmeTelemetryModel

	parents  map[ast.Node]ast.Node
	fields   map[*types.Var]bool     // Telemetry fields of an otel metric type
	defs     map[*types.Var]ast.Expr // local variables defined from one value
	multiDef map[*types.Var]bool     // local variables defined any other way
	writes   map[*types.Var]int      // later assignments or address-of
	allowed  map[ast.Node]bool       // uses accounted for by a checked call
	assigns  map[string][]string     // Telemetry field -> constructed metric names
}

func (a *readmeTelemetryAnalysis) where(n ast.Node) string {
	pos := a.fset.Position(n.Pos())
	return fmt.Sprintf("%s line %d", pos.Filename, pos.Line)
}

func (a *readmeTelemetryAnalysis) problem(format string, args ...any) {
	a.model.problems = append(a.model.problems, fmt.Sprintf(format, args...))
}

// outer returns n with any parentheses around it.
func (a *readmeTelemetryAnalysis) outer(n ast.Node) ast.Node {
	for {
		p, ok := a.parents[n].(*ast.ParenExpr)
		if !ok {
			return n
		}
		n = p
	}
}

// callee returns the function or method a call statically calls.
func (a *readmeTelemetryAnalysis) callee(call *ast.CallExpr) *types.Func {
	return readmeCallFunc(a.info, call)
}

func readmeCallFunc(info *types.Info, call *ast.CallExpr) *types.Func {
	switch fun := ast.Unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := info.Uses[fun].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		if s := info.Selections[fun]; s != nil {
			if s.Kind() != types.MethodVal {
				return nil
			}
			fn, _ := s.Obj().(*types.Func)
			return fn
		}
		fn, _ := info.Uses[fun.Sel].(*types.Func)
		return fn
	}
	return nil
}

func readmeInPkg(obj types.Object, path string) bool {
	return obj.Pkg() != nil && obj.Pkg().Path() == path
}

// readmeFuncIn reports whether fn is a function or method of package path.
func readmeFuncIn(fn *types.Func, path string) bool {
	return fn != nil && readmeInPkg(fn, path)
}

// readmeRecvIs reports whether fn is a method of the named type pkg.name.
func readmeRecvIs(fn *types.Func, pkg, name string) bool {
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return false
	}
	t := recv.Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := types.Unalias(t).(*types.Named)
	return ok && named.Obj().Name() == name && readmeInPkg(named.Obj(), pkg)
}

func (a *readmeTelemetryAnalysis) run() {
	obj, _ := a.pkg.Scope().Lookup("Telemetry").(*types.TypeName)
	if obj == nil {
		a.problem("internal/metadata declares no Telemetry type")
		return
	}
	st, ok := obj.Type().Underlying().(*types.Struct)
	if !ok {
		a.problem("internal/metadata Telemetry is not a struct")
		return
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		if named, ok := types.Unalias(f.Type()).(*types.Named); ok && readmeInPkg(named.Obj(), readmeMetricPkgPath) {
			a.fields[f] = true
		}
	}
	for _, name := range a.pkg.Scope().Names() {
		if c, ok := a.pkg.Scope().Lookup(name).(*types.Const); ok && c.Val().Kind() == constant.String {
			if v := constant.StringVal(c.Val()); strings.HasPrefix(v, dashPromPrefix) {
				a.model.names = append(a.model.names, v)
			}
		}
	}
	slices.Sort(a.model.names)

	for _, f := range a.files {
		var stack []ast.Node
		ast.Inspect(f, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			if len(stack) > 0 {
				a.parents[n] = stack[len(stack)-1]
			}
			stack = append(stack, n)
			a.collectLocal(n)
			return true
		})
	}
	for _, f := range a.files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.CallExpr:
				a.call(n)
			case *ast.CompositeLit:
				if tv, ok := a.info.Types[n]; ok && types.Identical(tv.Type, obj.Type()) && len(n.Elts) > 0 {
					a.problem("%s sets Telemetry fields in a composite literal; construct each instrument with t.<Field>, err = m.<Kind>(...)", a.where(n))
				}
			}
			return true
		})
	}
	a.checkUses()

	recordedFields := map[string]bool{}
	for _, rec := range a.model.recordings {
		recordedFields[rec.Field] = true
	}
	for _, f := range slices.SortedFunc(maps.Keys(a.fields), func(x, y *types.Var) int { return strings.Compare(x.Name(), y.Name()) }) {
		switch names := a.assigns[f.Name()]; len(names) {
		case 0:
			if recordedFields[f.Name()] {
				a.problem("internal/metadata records Telemetry.%s but never constructs it", f.Name())
			}
		case 1:
			a.model.fields[f.Name()] = names[0]
		default:
			a.problem("internal/metadata constructs Telemetry.%s %d times (%s); construct it exactly once", f.Name(), len(names), strings.Join(names, ", "))
		}
	}
}

// collectLocal records how local variables are defined and written.
func (a *readmeTelemetryAnalysis) collectLocal(n ast.Node) {
	written := func(e ast.Expr) {
		if id, ok := ast.Unparen(e).(*ast.Ident); ok {
			if v, ok := a.info.Uses[id].(*types.Var); ok {
				a.writes[v]++
			}
		}
	}
	switch n := n.(type) {
	case *ast.AssignStmt:
		for i, lhs := range n.Lhs {
			id, ok := ast.Unparen(lhs).(*ast.Ident)
			if !ok {
				continue
			}
			if v, ok := a.info.Defs[id].(*types.Var); ok && n.Tok == token.DEFINE {
				if len(n.Lhs) == len(n.Rhs) {
					a.defs[v] = n.Rhs[i]
				} else {
					a.multiDef[v] = true
				}
				continue
			}
			written(lhs)
		}
	case *ast.ValueSpec:
		for i, id := range n.Names {
			if v, ok := a.info.Defs[id].(*types.Var); ok {
				if len(n.Values) == len(n.Names) {
					a.defs[v] = n.Values[i]
				} else {
					a.multiDef[v] = true
				}
			}
		}
	case *ast.UnaryExpr:
		if n.Op == token.AND {
			written(n.X)
		}
	case *ast.IncDecStmt:
		written(n.X)
	case *ast.RangeStmt:
		for _, e := range []ast.Expr{n.Key, n.Value} {
			id, ok := e.(*ast.Ident)
			if !ok {
				continue
			}
			if v, ok := a.info.Defs[id].(*types.Var); ok {
				a.multiDef[v] = true
			} else {
				written(id)
			}
		}
	}
}

// aliasField returns the Telemetry field a local variable was defined from,
// directly or through other local variables, ignoring later writes.
func (a *readmeTelemetryAnalysis) aliasField(v *types.Var, depth int) *types.Var {
	def, ok := a.defs[v]
	if !ok || depth > 8 || v.Parent() == a.pkg.Scope() {
		return nil
	}
	switch e := ast.Unparen(def).(type) {
	case *ast.SelectorExpr:
		if s := a.info.Selections[e]; s != nil && s.Kind() == types.FieldVal {
			if f, ok := s.Obj().(*types.Var); ok && a.fields[f] {
				return f
			}
		}
	case *ast.Ident:
		if w, ok := a.info.Uses[e].(*types.Var); ok && !w.IsField() {
			return a.aliasField(w, depth+1)
		}
	}
	return nil
}

// resolve returns the Telemetry instrument field that e denotes, or why it
// denotes no single field.
func (a *readmeTelemetryAnalysis) resolve(e ast.Expr, depth int) (*types.Var, string) {
	switch e := ast.Unparen(e).(type) {
	case *ast.SelectorExpr:
		if s := a.info.Selections[e]; s != nil && s.Kind() == types.FieldVal {
			if f, ok := s.Obj().(*types.Var); ok && a.fields[f] {
				return f, ""
			}
		}
		return nil, fmt.Sprintf("%s is not a Telemetry instrument field", types.ExprString(e))
	case *ast.Ident:
		v, ok := a.info.Uses[e].(*types.Var)
		switch {
		case !ok || v.IsField() || v.Parent() == a.pkg.Scope():
			return nil, fmt.Sprintf("%s is not a local variable", e.Name)
		case a.multiDef[v]:
			return nil, fmt.Sprintf("%s is not defined from a single value", e.Name)
		case a.defs[v] == nil:
			return nil, fmt.Sprintf("%s is a parameter or a variable defined without a value", e.Name)
		case a.writes[v] > 0:
			return nil, fmt.Sprintf("%s is reassigned or has its address taken", e.Name)
		case depth > 8:
			return nil, fmt.Sprintf("%s starts an alias chain that is too long", e.Name)
		}
		return a.resolve(a.defs[v], depth+1)
	}
	return nil, fmt.Sprintf("%s is neither a Telemetry instrument field nor a local alias of one", types.ExprString(e))
}

// call checks a call into go.opentelemetry.io/otel/metric.
func (a *readmeTelemetryAnalysis) call(call *ast.CallExpr) {
	fn := a.callee(call)
	if !readmeFuncIn(fn, readmeMetricPkgPath) || fn.Type().(*types.Signature).Recv() == nil {
		return
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return
	}
	switch {
	case fn.Name() == "Add" || fn.Name() == "Record":
		a.allowed[sel.Sel] = true
		a.recording(call, sel, fn)
	case readmeRecvIs(fn, readmeMetricPkgPath, "Meter"):
		a.allowed[sel.Sel] = true
		a.constructor(call, fn)
	case readmeRecvIs(fn, readmeMetricPkgPath, "MeterProvider") && fn.Name() == "Meter":
		a.allowed[sel.Sel] = true
	}
}

func (a *readmeTelemetryAnalysis) recording(call *ast.CallExpr, sel *ast.SelectorExpr, fn *types.Func) {
	where := a.where(call)
	field, why := a.resolve(sel.X, 0)
	if field == nil {
		a.problem("%s: cannot tell which Telemetry instrument this %s call records: %s; call t.<Field>.%s directly or through a local alias assigned once", where, fn.Name(), why, fn.Name())
		return
	}
	a.allowed[ast.Unparen(sel.X)] = true
	rec := readmeGoRecording{Field: field.Name(), Known: true, Where: where}
	if call.Ellipsis.IsValid() {
		rec.Known, rec.Why = false, "its options are a spread slice"
	} else {
		for _, arg := range call.Args[min(2, len(call.Args)):] {
			keys, why := a.attributeKeys(arg)
			if why != "" {
				rec.Known, rec.Why = false, why
				continue
			}
			rec.Attrs = append(rec.Attrs, keys...)
		}
	}
	slices.Sort(rec.Attrs)
	a.model.recordings = append(a.model.recordings, rec)
}

// attributeKeys returns the attribute keys of one recording option, which
// must be a metric.WithAttributes call listing attribute constructors whose
// keys are constants.
func (a *readmeTelemetryAnalysis) attributeKeys(opt ast.Expr) ([]string, string) {
	call, ok := ast.Unparen(opt).(*ast.CallExpr)
	if !ok {
		return nil, fmt.Sprintf("option %s is not a metric.WithAttributes call", types.ExprString(opt))
	}
	fn := a.callee(call)
	if !readmeFuncIn(fn, readmeMetricPkgPath) || fn.Name() != "WithAttributes" || fn.Type().(*types.Signature).Recv() != nil {
		return nil, fmt.Sprintf("option %s is not a metric.WithAttributes call", types.ExprString(opt))
	}
	a.allowed[ast.Unparen(call.Fun).(*ast.SelectorExpr).Sel] = true
	if call.Ellipsis.IsValid() {
		return nil, "metric.WithAttributes receives a spread slice"
	}
	var keys []string
	for _, arg := range call.Args {
		kv, ok := ast.Unparen(arg).(*ast.CallExpr)
		if !ok {
			return nil, fmt.Sprintf("attribute %s is not built in the call", types.ExprString(arg))
		}
		kfn := a.callee(kv)
		var key ast.Expr
		switch {
		case !readmeFuncIn(kfn, readmeAttributePkgPath) || !readmeAttributeConstructors[kfn.Name()]:
			return nil, fmt.Sprintf("attribute %s is not built by an attribute constructor", types.ExprString(arg))
		case kfn.Type().(*types.Signature).Recv() == nil && len(kv.Args) == 2:
			key = kv.Args[0]
		case readmeRecvIs(kfn, readmeAttributePkgPath, "Key"):
			key = ast.Unparen(kv.Fun).(*ast.SelectorExpr).X
		default:
			return nil, fmt.Sprintf("attribute %s is not built by an attribute constructor", types.ExprString(arg))
		}
		tv := a.info.Types[key]
		if tv.Value == nil || tv.Value.Kind() != constant.String {
			return nil, fmt.Sprintf("attribute key %s is not a constant", types.ExprString(key))
		}
		keys = append(keys, constant.StringVal(tv.Value))
	}
	return keys, ""
}

func (a *readmeTelemetryAnalysis) constructor(call *ast.CallExpr, fn *types.Func) {
	where := a.where(call)
	m := readmeGoCtorRE.FindStringSubmatch(fn.Name())
	if m == nil {
		a.problem("%s: metric.Meter.%s is not an instrument constructor this check models", where, fn.Name())
		return
	}
	if m[2] != "" {
		a.problem("%s: %s is an observable instrument, which this check does not model", where, fn.Name())
		return
	}
	name := ""
	if len(call.Args) > 0 {
		if tv := a.info.Types[call.Args[0]]; tv.Value != nil && tv.Value.Kind() == constant.String {
			name = constant.StringVal(tv.Value)
		}
	}
	if name == "" {
		a.problem("%s: cannot resolve the metric name passed to %s", where, fn.Name())
		return
	}
	valueType := map[string]string{"Int64": "int", "Float64": "double"}[m[1]]
	inst := readmeGoInstrument{Name: name, TypeLabel: fmt.Sprintf("%s (%s)", m[3], valueType), Where: where}
	if call.Ellipsis.IsValid() {
		a.problem("%s: cannot read the options of %s: they are a spread slice", where, name)
	}
	for _, arg := range call.Args[1:] {
		opt, ok := ast.Unparen(arg).(*ast.CallExpr)
		var ofn *types.Func
		if ok {
			ofn = a.callee(opt)
		}
		if !readmeFuncIn(ofn, readmeMetricPkgPath) || ofn.Type().(*types.Signature).Recv() != nil {
			a.problem("%s: cannot read an option of %s", a.where(arg), name)
			continue
		}
		a.allowed[ast.Unparen(opt.Fun).(*ast.SelectorExpr).Sel] = true
		switch ofn.Name() {
		case "WithUnit":
			if len(opt.Args) == 1 {
				if tv := a.info.Types[opt.Args[0]]; tv.Value != nil && tv.Value.Kind() == constant.String {
					inst.Units = append(inst.Units, constant.StringVal(tv.Value))
					continue
				}
			}
			a.problem("%s: cannot resolve the unit of %s", a.where(opt), name)
		case "WithExplicitBucketBoundaries":
			for _, b := range opt.Args {
				tv := a.info.Types[b]
				if opt.Ellipsis.IsValid() || tv.Value == nil || (tv.Value.Kind() != constant.Int && tv.Value.Kind() != constant.Float) {
					a.problem("%s: cannot read the bucket boundaries of %s", a.where(opt), name)
					break
				}
				f, _ := constant.Float64Val(constant.ToFloat(tv.Value))
				inst.Boundaries = append(inst.Boundaries, f)
			}
		case "WithDescription":
		default:
			a.problem("%s: cannot read an option of %s", a.where(arg), name)
		}
	}
	a.model.instruments = append(a.model.instruments, inst)

	// The instrument must land straight in one Telemetry field:
	// t.Field, err = m.Kind(name, ...).
	o := a.outer(call)
	as, ok := a.parents[o].(*ast.AssignStmt)
	var field *types.Var
	var lhs *ast.SelectorExpr
	if ok && as.Tok == token.ASSIGN && len(as.Lhs) == 2 && len(as.Rhs) == 1 && as.Rhs[0] == o {
		if lhs, ok = ast.Unparen(as.Lhs[0]).(*ast.SelectorExpr); ok {
			field, _ = a.resolve(lhs, 0)
		}
	}
	if field == nil {
		a.problem("%s: %s is not assigned straight to a Telemetry field as t.<Field>, err = m.%s(...)", where, name, fn.Name())
		return
	}
	a.allowed[lhs] = true
	a.assigns[field.Name()] = append(a.assigns[field.Name()], name)
}

// aliasDefinition reports whether n is the whole value a local alias of a
// Telemetry instrument is defined from.
func (a *readmeTelemetryAnalysis) aliasDefinition(n ast.Node) bool {
	o := a.outer(n)
	var names []*ast.Ident
	var values []ast.Expr
	switch p := a.parents[o].(type) {
	case *ast.AssignStmt:
		if p.Tok != token.DEFINE || len(p.Lhs) != len(p.Rhs) {
			return false
		}
		for _, l := range p.Lhs {
			id, _ := l.(*ast.Ident)
			names = append(names, id)
		}
		values = p.Rhs
	case *ast.ValueSpec:
		names, values = p.Names, p.Values
	default:
		return false
	}
	for i, value := range values {
		if value != o || i >= len(names) || names[i] == nil {
			continue
		}
		v, ok := a.info.Defs[names[i]].(*types.Var)
		return ok && a.aliasField(v, 0) != nil
	}
	return false
}

// checkUses reports every use of a Telemetry instrument field, of a local
// alias of one, and of an otel metric function or method that no checked
// constructor or recording call accounts for: an instrument passed on,
// stored, compared, written or turned into a method value would otherwise
// escape the check.
func (a *readmeTelemetryAnalysis) checkUses() {
	ids := slices.SortedFunc(maps.Keys(a.info.Uses), func(x, y *ast.Ident) int { return int(x.Pos() - y.Pos()) })
	for _, id := range ids {
		switch obj := a.info.Uses[id].(type) {
		case *types.Var:
			switch {
			case a.fields[obj]:
				sel, ok := a.parents[id].(*ast.SelectorExpr)
				if ok && sel.Sel == id && (a.allowed[sel] || a.aliasDefinition(sel)) {
					continue
				}
				a.problem("%s uses Telemetry.%s outside a checked constructor or Add/Record call", a.where(id), obj.Name())
			case !obj.IsField() && a.aliasField(obj, 0) != nil:
				if a.allowed[id] || a.aliasDefinition(id) {
					continue
				}
				a.problem("%s uses %s, a local alias of a Telemetry instrument, outside a checked Add/Record call", a.where(id), id.Name)
			}
		case *types.Func:
			if readmeInPkg(obj, readmeMetricPkgPath) && !a.allowed[id] {
				a.problem("%s uses %s outside a checked constructor or recording call", a.where(id), obj.FullName())
			}
		}
	}
}

// validateTelemetryGoInstruments checks that internal/metadata constructs
// every metadata.yaml metric exactly once with the declared kind, value
// type, unit and bucket boundaries, and records it only with the declared
// attribute keys.
func validateTelemetryGoInstruments(telemetry map[string]string, metrics map[string]readmeMetadataMetric, metaNames []string) []string {
	model := readTelemetryPackage(telemetry)
	problems := slices.Clone(model.problems)
	if !model.loaded {
		return problems
	}
	nameSet := map[string]bool{}
	for _, n := range model.names {
		nameSet[n] = true
		if _, ok := metrics[n]; !ok {
			problems = append(problems, fmt.Sprintf("internal/metadata declares metric-name constant %s absent from metadata.yaml", n))
		}
	}
	for _, n := range metaNames {
		if !nameSet[n] {
			problems = append(problems, fmt.Sprintf("internal/metadata is missing a metric-name constant for %s", n))
		}
	}

	constructed := map[string][]readmeGoInstrument{}
	for _, inst := range model.instruments {
		if _, ok := metrics[inst.Name]; !ok {
			problems = append(problems, fmt.Sprintf("%s constructs %s, which metadata.yaml does not declare", inst.Where, inst.Name))
			continue
		}
		constructed[inst.Name] = append(constructed[inst.Name], inst)
	}
	recorded := map[string][]readmeGoRecording{}
	for _, rec := range model.recordings {
		if name, ok := model.fields[rec.Field]; ok {
			recorded[name] = append(recorded[name], rec)
		}
	}
	for _, name := range metaNames {
		spec := metrics[name]
		switch insts := constructed[name]; len(insts) {
		case 0:
			problems = append(problems, fmt.Sprintf("internal/metadata never constructs %s declared in metadata.yaml", name))
		case 1:
			inst := insts[0]
			if want := spec.typeLabel(); inst.TypeLabel != want {
				problems = append(problems, fmt.Sprintf("%s constructs %s as %s, metadata.yaml declares %s", inst.Where, name, inst.TypeLabel, want))
			}
			unit := ""
			if n := len(inst.Units); n > 0 {
				unit = inst.Units[n-1]
				if n > 1 {
					problems = append(problems, fmt.Sprintf("%s sets %d units on %s", inst.Where, n, name))
				}
			}
			if unit != spec.Unit {
				problems = append(problems, fmt.Sprintf("%s sets unit %q on %s, metadata.yaml declares %q", inst.Where, unit, name, spec.Unit))
			}
			var wantBounds []float64
			if spec.Histogram != nil {
				wantBounds = spec.Histogram.BucketBoundaries
			}
			if !slices.Equal(inst.Boundaries, wantBounds) {
				problems = append(problems, fmt.Sprintf("%s sets bucket boundaries %v on %s, metadata.yaml declares %v", inst.Where, inst.Boundaries, name, wantBounds))
			}
		default:
			problems = append(problems, fmt.Sprintf("internal/metadata constructs %s %d times", name, len(insts)))
		}

		recs := recorded[name]
		if len(recs) == 0 {
			problems = append(problems, fmt.Sprintf("internal/metadata never records %s, so its attributes cannot be checked", name))
		}
		wantAttrs := slices.Clone(spec.Attributes)
		slices.Sort(wantAttrs)
		for _, rec := range recs {
			if !rec.Known {
				problems = append(problems, fmt.Sprintf("%s: cannot verify the attributes %s is recorded with: %s", rec.Where, name, rec.Why))
				continue
			}
			if !slices.Equal(rec.Attrs, wantAttrs) {
				problems = append(problems, fmt.Sprintf("%s records %s with attributes %s, metadata.yaml declares %s", rec.Where, name, formatAttrSet(rec.Attrs), formatAttrSet(wantAttrs)))
			}
		}
	}
	return problems
}

const readmeModulePath = "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"

func readmeBuildContext() build.Context {
	ctxt := build.Default
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "-tags" && s.Value != "" {
				ctxt.BuildTags = strings.Split(s.Value, ",")
			}
		}
	}
	return ctxt
}

// readmeMetadataImporters returns the non-test Go files that build here, keyed
// by file name, of every package of this module other than internal/metadata
// that imports internal/metadata, keyed by import path.
func readmeMetadataImporters(t *testing.T) map[string]map[string]string {
	t.Helper()
	bctx := readmeBuildContext()
	pkgs := map[string]map[string]string{}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if path != "." && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
				return filepath.SkipDir
			}
			return nil
		}
		dir := filepath.Dir(path)
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || filepath.ToSlash(dir) == "internal/metadata" {
			return nil
		}
		if ok, err := bctx.MatchFile(dir, name); err != nil || !ok {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		importPath := readmeModulePath
		if dir != "." {
			importPath += "/" + filepath.ToSlash(dir)
		}
		if pkgs[importPath] == nil {
			pkgs[importPath] = map[string]string{}
		}
		pkgs[importPath][name] = readmeNormalizeEOL(string(raw))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path, files := range pkgs {
		imports := false
		for name, src := range files {
			f, err := parser.ParseFile(token.NewFileSet(), name, src, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, spec := range f.Imports {
				imports = imports || spec.Path.Value == strconv.Quote(readmeMetadataPkgPath)
			}
		}
		if !imports {
			delete(pkgs, path)
		}
	}
	return pkgs
}

// readmeIsInstrumentField reports whether v is a Telemetry field holding an
// otel metric instrument.
func readmeIsInstrumentField(v *types.Var) bool {
	named, ok := types.Unalias(v.Type()).(*types.Named)
	return v.IsField() && readmeInPkg(v, readmeMetadataPkgPath) && ok && readmeInPkg(named.Obj(), readmeMetricPkgPath)
}

func readmeTypeExposesTelemetry(t types.Type) bool {
	seen := map[types.Type]bool{}
	var walk func(types.Type) bool
	walk = func(t types.Type) bool {
		if t == nil {
			return false
		}
		t = types.Unalias(t)
		if seen[t] {
			return false
		}
		seen[t] = true
		switch u := t.(type) {
		case *types.Named:
			if readmeInPkg(u.Obj(), readmeMetadataPkgPath) && u.Obj().Name() == "Telemetry" {
				return true
			}
			if walk(u.Underlying()) {
				return true
			}
			for i := 0; i < u.NumMethods(); i++ {
				if u.Method(i).Exported() && walk(u.Method(i).Type()) {
					return true
				}
			}
			return false
		case *types.Pointer:
			return walk(u.Elem())
		case *types.Slice:
			return walk(u.Elem())
		case *types.Array:
			return walk(u.Elem())
		case *types.Chan:
			return walk(u.Elem())
		case *types.Map:
			return walk(u.Key()) || walk(u.Elem())
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				if walk(u.Field(i).Type()) {
					return true
				}
			}
			return false
		case *types.Tuple:
			for i := 0; i < u.Len(); i++ {
				if walk(u.At(i).Type()) {
					return true
				}
			}
			return false
		case *types.Signature:
			return walk(u.Params()) || walk(u.Results())
		case *types.TypeParam:
			return walk(u.Constraint())
		case *types.Union:
			for i := 0; i < u.Len(); i++ {
				if walk(u.Term(i).Type()) {
					return true
				}
			}
			return false
		case *types.Interface:
			for i := 0; i < u.NumMethods(); i++ {
				if walk(u.Method(i).Type()) {
					return true
				}
			}
			for i := 0; i < u.NumEmbeddeds(); i++ {
				if walk(u.EmbeddedType(i)) {
					return true
				}
			}
			return false
		}
		return false
	}
	return walk(t)
}

type readmeTypeTerm struct {
	tilde bool
	typ   types.Type
	under types.Type
}

type readmeTypeSet struct {
	universal bool
	terms     []readmeTypeTerm
}

func readmeAppendTypeTerm(dst []readmeTypeTerm, add readmeTypeTerm) []readmeTypeTerm {
	for _, cur := range dst {
		if cur.tilde != add.tilde {
			continue
		}
		if cur.tilde && types.Identical(cur.under, add.under) {
			return dst
		}
		if !cur.tilde && types.Identical(cur.typ, add.typ) {
			return dst
		}
	}
	return append(dst, add)
}

func readmeIntersectTypeSets(a, b readmeTypeSet) readmeTypeSet {
	if a.universal {
		return b
	}
	if b.universal {
		return a
	}
	var out readmeTypeSet
	for _, ta := range a.terms {
		for _, tb := range b.terms {
			if !types.Identical(ta.under, tb.under) {
				continue
			}
			switch {
			case ta.tilde && tb.tilde:
				out.terms = readmeAppendTypeTerm(out.terms, ta)
			case ta.tilde && !tb.tilde:
				out.terms = readmeAppendTypeTerm(out.terms, tb)
			case !ta.tilde && tb.tilde:
				out.terms = readmeAppendTypeTerm(out.terms, ta)
			case types.Identical(ta.typ, tb.typ):
				out.terms = readmeAppendTypeTerm(out.terms, ta)
			}
		}
	}
	return out
}

// readmeCoreType returns the underlying type of t or, for a type parameter,
// the underlying type that every type in its constraint's normalized type set
// shares (intersecting embedded interface elements and uniting union terms),
// including compatible directed channels. It returns nil when there is no
// single such core type.
func readmeCoreType(t types.Type) types.Type {
	if t == nil {
		return nil
	}
	tp, ok := types.Unalias(t).(*types.TypeParam)
	if !ok {
		return t.Underlying()
	}
	active := map[types.Type]bool{}
	var typeSet func(types.Type) readmeTypeSet
	typeSet = func(c types.Type) readmeTypeSet {
		c = types.Unalias(c)
		if active[c] {
			return readmeTypeSet{universal: true}
		}
		active[c] = true
		defer delete(active, c)

		if union, ok := c.(*types.Union); ok {
			var out readmeTypeSet
			for i := 0; i < union.Len(); i++ {
				tm := union.Term(i)
				if tm.Tilde() {
					u := types.Unalias(tm.Type()).Underlying()
					out.terms = readmeAppendTypeTerm(out.terms, readmeTypeTerm{
						tilde: true,
						typ:   u,
						under: u,
					})
					continue
				}
				sub := typeSet(tm.Type())
				if sub.universal {
					return readmeTypeSet{universal: true}
				}
				for _, st := range sub.terms {
					out.terms = readmeAppendTypeTerm(out.terms, st)
				}
			}
			return out
		}
		if iface, ok := c.Underlying().(*types.Interface); ok {
			cur := readmeTypeSet{universal: true}
			for i := 0; i < iface.NumEmbeddeds(); i++ {
				cur = readmeIntersectTypeSets(cur, typeSet(iface.EmbeddedType(i)))
			}
			if !cur.universal && iface.NumMethods() > 0 {
				var filtered []readmeTypeTerm
				for _, tm := range cur.terms {
					if tm.tilde || types.Implements(tm.typ, iface) {
						filtered = append(filtered, tm)
					}
				}
				cur.terms = filtered
			}
			return cur
		}
		return readmeTypeSet{terms: []readmeTypeTerm{{
			tilde: false,
			typ:   c,
			under: c.Underlying(),
		}}}
	}

	ts := typeSet(tp.Constraint())
	if ts.universal || len(ts.terms) == 0 {
		return nil
	}
	first := ts.terms[0].under
	allIdentical := true
	for _, tm := range ts.terms[1:] {
		if !types.Identical(tm.under, first) {
			allIdentical = false
			break
		}
	}
	if allIdentical {
		return first
	}
	firstChan, ok := first.(*types.Chan)
	if !ok {
		return nil
	}
	canSend, canRecv := true, true
	for _, tm := range ts.terms {
		ch, ok := tm.under.(*types.Chan)
		if !ok || !types.Identical(ch.Elem(), firstChan.Elem()) {
			return nil
		}
		switch ch.Dir() {
		case types.SendOnly:
			canRecv = false
		case types.RecvOnly:
			canSend = false
		}
	}
	switch {
	case canSend && canRecv:
		return types.NewChan(types.SendRecv, firstChan.Elem())
	case canSend:
		return types.NewChan(types.SendOnly, firstChan.Elem())
	case canRecv:
		return types.NewChan(types.RecvOnly, firstChan.Elem())
	default:
		return nil
	}
}

// readmeRangeTypes returns the types of the key and value that a range over a
// value of type x yields. It returns nil for a slot it does not yield, and for
// an integer key, which cannot hold a Telemetry.
func readmeRangeTypes(x types.Type) (key, value types.Type) {
	switch u := readmeCoreType(x).(type) {
	case *types.Slice:
		return nil, u.Elem()
	case *types.Array:
		return nil, u.Elem()
	case *types.Pointer:
		if a, ok := readmeCoreType(u.Elem()).(*types.Array); ok {
			return nil, a.Elem()
		}
	case *types.Map:
		return u.Key(), u.Elem()
	case *types.Chan:
		return u.Elem(), nil
	case *types.Signature: // an iterator: func(yield func(K, V) bool)
		if u.Params().Len() == 1 {
			if yield, ok := readmeCoreType(u.Params().At(0).Type()).(*types.Signature); ok {
				if p := yield.Params(); p.Len() > 0 {
					key = p.At(0).Type()
					if p.Len() > 1 {
						value = p.At(1).Type()
					}
				}
				return key, value
			}
		}
	}
	return nil, nil
}

// readmeOutsideMetadataProblems type-checks the packages that import
// internal/metadata and reports every use of a Telemetry instrument field in
// them, since a recording there would bypass the check of internal/metadata,
// and every exported API that hands a Telemetry to other packages, which no
// package outside this set could otherwise reach.
func readmeOutsideMetadataProblems(pkgs map[string]map[string]string) []string {
	readmeTelemetry.Lock()
	defer readmeTelemetry.Unlock()
	readmeTelemetryInit()
	fset := readmeTelemetry.fset
	var problems []string
	where := func(pos token.Pos) string {
		p := fset.Position(pos)
		return fmt.Sprintf("%s line %d", p.Filename, p.Line)
	}
	for _, path := range slices.Sorted(maps.Keys(pkgs)) {
		files := pkgs[path]
		dir := strings.TrimPrefix(strings.TrimPrefix(path, readmeModulePath), "/")
		var parsed []*ast.File
		imports := map[string]bool{}
		for _, name := range slices.Sorted(maps.Keys(files)) {
			f, err := parser.ParseFile(fset, filepath.ToSlash(filepath.Join(dir, name)), files[name], parser.SkipObjectResolution)
			if err != nil {
				problems = append(problems, fmt.Sprintf("parsing %s: %v", filepath.ToSlash(filepath.Join(dir, name)), err))
				continue
			}
			parsed = append(parsed, f)
			for _, spec := range f.Imports {
				if p, err := strconv.Unquote(spec.Path.Value); err == nil {
					if p == "unsafe" {
						problems = append(problems, fmt.Sprintf("%s imports unsafe in a package that imports internal/metadata", where(spec.Pos())))
					}
					imports[p] = true
				}
			}
		}
		if err := readmeLoadExports(slices.Sorted(maps.Keys(imports))); err != nil {
			problems = append(problems, fmt.Sprintf("cannot type-check %s, so its use of Telemetry cannot be verified: %v", path, err))
			continue
		}
		info := &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Instances:  map[*ast.Ident]types.Instance{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
		}
		conf := types.Config{
			Importer: readmeTelemetry.imp,
			Error: func(err error) {
				problems = append(problems, fmt.Sprintf("%s does not type-check, so its use of Telemetry cannot be fully verified: %v", path, err))
			},
		}
		pkg, _ := conf.Check(path, fset, parsed, info)
		sels := slices.SortedFunc(maps.Keys(info.Selections), func(x, y *ast.SelectorExpr) int { return int(x.Pos() - y.Pos()) })
		for _, sel := range sels {
			if v, ok := info.Selections[sel].Obj().(*types.Var); ok && readmeIsInstrumentField(v) {
				problems = append(problems, fmt.Sprintf("%s uses Telemetry.%s directly; record self-telemetry only through the Telemetry methods in internal/metadata, which the README check reads", where(sel.Sel.Pos()), v.Name()))
			}
		}
		if pkg == nil {
			continue
		}
		exposes := readmeTypeExposesTelemetry
		for _, id := range slices.SortedFunc(maps.Keys(info.Instances), func(x, y *ast.Ident) int { return int(x.Pos() - y.Pos()) }) {
			inst := info.Instances[id]
			if inst.TypeArgs == nil {
				continue
			}
			for i := 0; i < inst.TypeArgs.Len(); i++ {
				if targ := inst.TypeArgs.At(i); exposes(targ) {
					problems = append(problems, fmt.Sprintf("%s instantiates generic %s with type argument %s, which exposes metadata.Telemetry", where(id.Pos()), id.Name, types.TypeString(targ, nil)))
				}
			}
		}
		checkBoxed := func(pos token.Pos, dst, src types.Type) {
			if dst != nil && src != nil && types.IsInterface(dst) && exposes(src) {
				problems = append(problems, fmt.Sprintf("%s boxes %s into interface %s, which can hand a metadata.Telemetry to other packages or reflection", where(pos), types.TypeString(src, nil), types.TypeString(dst, nil)))
			}
		}
		// checkTuple checks each slot of a multi-value expression (a call, or
		// a comma-ok form) against the destination dst(i) it is assigned to,
		// and reports whether expr has such a type.
		checkTuple := func(expr ast.Expr, dst func(i int) types.Type) bool {
			tuple, ok := info.Types[expr].Type.(*types.Tuple)
			if !ok {
				return false
			}
			for i := 0; i < tuple.Len(); i++ {
				checkBoxed(expr.Pos(), dst(i), tuple.At(i).Type())
			}
			return true
		}
		// lhsType returns the type a value assigned to e is converted to.
		// The blank identifier keeps nothing, and a variable that := defines
		// takes the value's own type; a variable it reuses keeps its type,
		// which info.Types does not record.
		lhsType := func(e ast.Expr) types.Type {
			if id, ok := e.(*ast.Ident); ok {
				if id.Name == "_" || info.Defs[id] != nil {
					return nil
				}
				if obj := info.Uses[id]; obj != nil {
					return obj.Type()
				}
			}
			return info.Types[e].Type
		}
		for _, f := range parsed {
			var sigStack []*types.Signature
			ast.Inspect(f, func(n ast.Node) bool {
				if n == nil {
					if len(sigStack) > 0 {
						sigStack = sigStack[:len(sigStack)-1]
					}
					return false
				}
				switch n := n.(type) {
				case *ast.FuncDecl:
					var sig *types.Signature
					if obj, ok := info.Defs[n.Name].(*types.Func); ok {
						sig, _ = obj.Type().(*types.Signature)
					}
					sigStack = append(sigStack, sig)
					return true
				case *ast.FuncLit:
					sig, _ := readmeCoreType(info.Types[n.Type].Type).(*types.Signature)
					sigStack = append(sigStack, sig)
					return true
				case *ast.ReturnStmt:
					var curSig *types.Signature
					for i := len(sigStack) - 1; i >= 0; i-- {
						if sigStack[i] != nil {
							curSig = sigStack[i]
							break
						}
					}
					if curSig != nil {
						res := curSig.Results()
						if len(n.Results) == res.Len() {
							for i, expr := range n.Results {
								checkBoxed(expr.Pos(), res.At(i).Type(), info.Types[expr].Type)
							}
						} else if len(n.Results) == 1 {
							checkTuple(n.Results[0], func(i int) types.Type {
								if i < res.Len() {
									return res.At(i).Type()
								}
								return nil
							})
						}
					}
				case *ast.AssignStmt:
					if len(n.Lhs) == len(n.Rhs) {
						for i := range n.Lhs {
							checkBoxed(n.Rhs[i].Pos(), lhsType(n.Lhs[i]), info.Types[n.Rhs[i]].Type)
						}
					} else if len(n.Rhs) == 1 {
						checkTuple(n.Rhs[0], func(i int) types.Type {
							if i < len(n.Lhs) {
								return lhsType(n.Lhs[i])
							}
							return nil
						})
					}
				case *ast.ValueSpec:
					if len(n.Values) == 1 && len(n.Names) > 1 {
						checkTuple(n.Values[0], func(i int) types.Type {
							if i < len(n.Names) && n.Names[i].Name != "_" {
								if obj := info.Defs[n.Names[i]]; obj != nil {
									return obj.Type()
								}
							}
							return nil
						})
					} else {
						for i, val := range n.Values {
							if i < len(n.Names) {
								if obj := info.Defs[n.Names[i]]; obj != nil {
									checkBoxed(val.Pos(), obj.Type(), info.Types[val].Type)
								}
							}
						}
					}
				case *ast.CompositeLit:
					// A composite literal converts each element, map key and
					// value, and struct field to its destination type.
					lit := types.Unalias(info.Types[n].Type)
					if p, ok := lit.(*types.Pointer); ok { // an elided &T{...} element
						lit = types.Unalias(p.Elem())
					}
					dstName := "<unknown>"
					if lit != nil {
						dstName = types.TypeString(lit, nil)
					}
					var elem types.Type
					switch u := readmeCoreType(lit).(type) {
					case *types.Slice:
						elem = u.Elem()
					case *types.Array:
						elem = u.Elem()
					case *types.Map:
						for _, elt := range n.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								checkBoxed(kv.Key.Pos(), u.Key(), info.Types[kv.Key].Type)
								checkBoxed(kv.Value.Pos(), u.Elem(), info.Types[kv.Value].Type)
							}
						}
					case *types.Struct:
						for i, elt := range n.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								if key, ok := kv.Key.(*ast.Ident); ok {
									var fieldType types.Type
									if field, ok := info.Uses[key].(*types.Var); ok && field.IsField() {
										fieldType = field.Type()
									} else {
										for j := 0; j < u.NumFields(); j++ {
											if f := u.Field(j); f.Name() == key.Name {
												fieldType = f.Type()
												break
											}
										}
									}
									if fieldType != nil {
										checkBoxed(kv.Value.Pos(), fieldType, info.Types[kv.Value].Type)
									} else if valType := info.Types[kv.Value].Type; exposes(valType) {
										problems = append(problems, fmt.Sprintf("%s places %s in struct field %s of %s whose field type cannot be resolved", where(kv.Value.Pos()), types.TypeString(valType, nil), key.Name, dstName))
									}
								}
							} else if i < u.NumFields() {
								checkBoxed(elt.Pos(), u.Field(i).Type(), info.Types[elt].Type)
							}
						}
					default:
						for _, elt := range n.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								if keyType := info.Types[kv.Key].Type; exposes(keyType) {
									problems = append(problems, fmt.Sprintf("%s places %s in composite literal of %s whose destination type cannot be resolved", where(kv.Key.Pos()), types.TypeString(keyType, nil), dstName))
								}
								if valType := info.Types[kv.Value].Type; exposes(valType) {
									problems = append(problems, fmt.Sprintf("%s places %s in composite literal of %s whose destination type cannot be resolved", where(kv.Value.Pos()), types.TypeString(valType, nil), dstName))
								}
								continue
							}
							if eltType := info.Types[elt].Type; exposes(eltType) {
								problems = append(problems, fmt.Sprintf("%s places %s in composite literal of %s whose destination type cannot be resolved", where(elt.Pos()), types.TypeString(eltType, nil), dstName))
							}
						}
					}
					if elem != nil {
						for _, elt := range n.Elts {
							if kv, ok := elt.(*ast.KeyValueExpr); ok {
								elt = kv.Value
							}
							checkBoxed(elt.Pos(), elem, info.Types[elt].Type)
						}
					}
				case *ast.SendStmt:
					if ch, ok := readmeCoreType(info.Types[n.Chan].Type).(*types.Chan); ok {
						checkBoxed(n.Value.Pos(), ch.Elem(), info.Types[n.Value].Type)
					}
				case *ast.RangeStmt:
					// for k, v = range x assigns the iteration values to the
					// variables k and v; := defines new ones of the same types.
					key, value := readmeRangeTypes(info.Types[n.X].Type)
					if n.Key != nil {
						checkBoxed(n.Key.Pos(), lhsType(n.Key), key)
					}
					if n.Value != nil {
						checkBoxed(n.Value.Pos(), lhsType(n.Value), value)
					}
				case *ast.IndexExpr:
					if m, ok := readmeCoreType(info.Types[n.X].Type).(*types.Map); ok {
						checkBoxed(n.Index.Pos(), m.Key(), info.Types[n.Index].Type)
					}
				case *ast.CallExpr:
					tv := info.Types[n.Fun]
					if tv.IsType() && len(n.Args) == 1 {
						checkBoxed(n.Args[0].Pos(), tv.Type, info.Types[n.Args[0]].Type)
					}
					if fn := readmeCallFunc(info, n); fn != nil && readmeInPkg(fn, "reflect") {
						for _, arg := range n.Args {
							if exposes(info.Types[arg].Type) {
								problems = append(problems, fmt.Sprintf("%s passes %s to reflect.%s, which can read Telemetry instrument fields without going through Telemetry methods", where(arg.Pos()), types.TypeString(info.Types[arg].Type, nil), fn.Name()))
							}
						}
					}
					if sig, ok := readmeCoreType(tv.Type).(*types.Signature); ok {
						params := sig.Params()
						paramAt := func(i int) types.Type {
							switch {
							case params.Len() == 0:
								return nil
							case sig.Variadic() && i >= params.Len()-1 && !n.Ellipsis.IsValid():
								if sl, ok := readmeCoreType(params.At(params.Len() - 1).Type()).(*types.Slice); ok {
									return sl.Elem()
								}
								return nil
							case i < params.Len():
								return params.At(i).Type()
							}
							return nil
						}
						// f(g()) binds each result of g to a parameter of f.
						if len(n.Args) != 1 || !checkTuple(n.Args[0], paramAt) {
							for i, arg := range n.Args {
								checkBoxed(arg.Pos(), paramAt(i), info.Types[arg].Type)
							}
						}
					} else if tv.IsBuiltin() {
						if id, ok := ast.Unparen(n.Fun).(*ast.Ident); ok && id.Name == "append" && len(n.Args) >= 2 && !n.Ellipsis.IsValid() {
							if sl, ok := readmeCoreType(info.Types[n.Args[0]].Type).(*types.Slice); ok {
								for _, arg := range n.Args[1:] {
									checkBoxed(arg.Pos(), sl.Elem(), info.Types[arg].Type)
								}
							}
						}
					}
				}
				sigStack = append(sigStack, nil)
				return true
			})
		}
		for _, name := range pkg.Scope().Names() {
			obj := pkg.Scope().Lookup(name)
			if obj.Exported() && exposes(obj.Type()) {
				problems = append(problems, fmt.Sprintf("%s: %s.%s hands a metadata.Telemetry to other packages, which the README check does not read", where(obj.Pos()), path, name))
			}
			tn, ok := obj.(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			if st, ok := named.Underlying().(*types.Struct); ok {
				for i := 0; i < st.NumFields(); i++ {
					if f := st.Field(i); f.Exported() && exposes(f.Type()) {
						problems = append(problems, fmt.Sprintf("%s: field %s.%s hands a metadata.Telemetry to other packages, which the README check does not read", where(f.Pos()), name, f.Name()))
					}
				}
			}
			for i := 0; i < named.NumMethods(); i++ {
				if m := named.Method(i); m.Exported() && exposes(m.Type()) {
					problems = append(problems, fmt.Sprintf("%s: method %s.%s hands a metadata.Telemetry to other packages, which the README check does not read", where(m.Pos()), name, m.Name()))
				}
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

func validateReadmeSelfTelemetry(readme, metadataYAML string, telemetry map[string]string, grafanaJSON string) []string {
	readme = readmeNormalizeEOL(readme)
	metadataYAML = readmeNormalizeEOL(metadataYAML)
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
	problems = append(problems, readmeStrayTelemetryRows(section)...)
	for i, b := range section.Blocks {
		if i == section.Table || b.Kind == readmeMDFencedCode || b.Kind == readmeMDIndentedCode {
			continue
		}
		for k, line := range b.Lines {
			for _, name := range readmeMetricNameRE.FindAllString(line, -1) {
				if _, ok := metrics[name]; !ok {
					problems = append(problems, fmt.Sprintf("README.md line %d names metric %s not declared in metadata.yaml", b.LineNos[k]+1, name))
				}
			}
		}
	}

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

	meanings := make(map[string]string, len(section.Rows))
	for _, row := range section.Rows {
		meanings[row.Metric] = row.Meaning
	}
	problems = append(problems, validateReadmeRecoveryProse(section.prose(), metrics, meanings)...)

	if len(telemetry) > 0 {
		problems = append(problems, validateTelemetryGoInstruments(telemetry, metrics, metaNames)...)
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

// readmeTelemetryFiles reads the non-test Go files of internal/metadata that
// build for this platform, keyed by file name.
func readmeTelemetryFiles(t *testing.T) map[string]string {
	t.Helper()
	bctx := readmeBuildContext()
	dir := filepath.Join("internal", "metadata")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if ok, err := bctx.MatchFile(dir, name); err != nil || !ok {
			if err != nil {
				t.Fatal(err)
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		files[name] = readmeNormalizeEOL(string(raw))
	}
	if _, ok := files["telemetry.go"]; !ok {
		t.Fatal("internal/metadata/telemetry.go not found")
	}
	return files
}

// readmeSelfTelemetryInputs reads every input of validateReadmeSelfTelemetry.
func readmeSelfTelemetryInputs(t *testing.T) (readme, meta string, telemetry map[string]string, grafana string) {
	t.Helper()
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return readmeNormalizeEOL(string(raw))
	}
	return read("README.md"), read("metadata.yaml"), readmeTelemetryFiles(t), read(dashGrafanaProm)
}

func TestReadmeSelfTelemetryMatchesMetadataAndTelemetry(t *testing.T) {
	readme, meta, telemetry, grafana := readmeSelfTelemetryInputs(t)
	for _, problem := range validateReadmeSelfTelemetry(readme, meta, telemetry, grafana) {
		t.Error(problem)
	}
}

func TestReadmeSelfTelemetryRejectsMutations(t *testing.T) {
	readme, meta, telemetry, grafanaJSON := readmeSelfTelemetryInputs(t)

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
			mutatedTelemetry := telemetry
			if tc.mutateTelemetry != nil {
				mutatedTelemetry = maps.Clone(telemetry)
				mutatedTelemetry["telemetry.go"] = tc.mutateTelemetry(telemetry["telemetry.go"])
				if mutatedTelemetry["telemetry.go"] == telemetry["telemetry.go"] {
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

// TestReadmeSelfTelemetryReviewProbes keeps the review probes against the
// validator: every evasion must be rejected for the stated reason, and every
// valid edit must pass with no problem at all.
func TestReadmeSelfTelemetryReviewProbes(t *testing.T) {
	readme, meta, telemetry, grafana := readmeSelfTelemetryInputs(t)
	const (
		introLine  = readmeSelfTelemetryIntroFull + "\n"
		lastRow    = "Results still being drained after their original attempt ended. |\n"
		proseEnd   = "not yet confirmed by\nBigQuery.”\n"
		laterHead  = "### Timeout and concurrency envelope\n"
		retryLine  = "\tt.Retries.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrClass, class)))\n"
		rejectLine = "\tt.RejectedRows.Add(ctx, int64(n), metric.WithAttributes(attribute.String(AttrReason, reason)))\n"
	)
	after := func(anchor, text string) func(string) string {
		return func(s string) string { return strings.Replace(s, anchor, anchor+text, 1) }
	}
	replace := func(old, with string) func(string) string {
		return func(s string) string { return strings.Replace(s, old, with, 1) }
	}
	extraFile := "package metadata\n\nimport (\n\t\"context\"\n\n\t\"go.opentelemetry.io/otel/attribute\"\n\t\"go.opentelemetry.io/otel/metric\"\n)\n\n" +
		"// RecordRetryReason records a retry under a reason.\nfunc (t *Telemetry) RecordRetryReason(ctx context.Context, reason string) {\n" +
		"\tt.Retries.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, reason)))\n}\n"

	cases := []struct {
		name            string
		mutate          func(string) string
		mutateTelemetry func(string) string
		addTelemetry    map[string]string
		// wantSubs is a problem the edit must produce. An empty wantSubs
		// marks a valid edit, which must produce no problem.
		wantSubs string
	}{
		// Recovery claims are parsed as whole sentences.
		{
			name:     "negated gauge claim",
			mutate:   replace("`true`,\n`backpressure_level` (dimensionless", "`true`,\nit is false that `backpressure_level` (dimensionless"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "opposite recovery condition",
			mutate:   replace("should return to zero after recovery or\nclean shutdown.", "should return to zero before recovery, but remain nonzero after recovery or clean shutdown."),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "prefixed negation in the count sentence",
			mutate:   replace("instruments, `inflight_requests` and\n", "instruments, it is false that `inflight_requests` and\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "contradictory count appended to the recovery paragraph",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Of the three non-counter current-value instruments.\n"),
			wantSubs: `counts "three" non-counter current-value instruments, metadata.yaml declares 4`,
		},
		{
			name:     "contradictory count in a new paragraph",
			mutate:   after(proseEnd, "\nOf the three non-counter current-value instruments.\n"),
			wantSubs: "counts the instruments 2 times, want exactly once",
		},
		{
			name:     "free-standing negated recovery",
			mutate:   after(proseEnd, "\n`backpressure_level` does not recover.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "statement negating the previous one",
			mutate:   after(proseEnd, "\nThe previous sentence is false.\n"),
			wantSubs: "negates or contradicts a statement outside the checked forms",
		},
		{
			name:     "current-value instrument named next to a value",
			mutate:   after(proseEnd, "\nAfter a restart, `inflight_requests` stays at `3`.\n"),
			wantSubs: "names inflight_requests next to",
		},
		{
			name:     "negation inside a gauge description",
			mutate:   replace("`effective_request_bytes` (byte gauge)", "`effective_request_bytes` (byte gauge, which never recovers)"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "range in a gauge description that the table does not state",
			mutate:   replace("(dimensionless `1` gauge in `[0.0, 1.0]`)", "(dimensionless `1` gauge in `[0.0, 100.0]`)"),
			wantSubs: "describes backpressure_level with the range `[0.0, 100.0]`, which its self-telemetry table row does not state",
		},
		{
			name:     "changed backpressure condition",
			mutate:   replace("When `write.backpressure.enabled` is `true`,", "When `write.backpressure.enabled` is `false`,"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "second recovery claim in a block quote",
			mutate:   after(proseEnd, "\n> `backpressure_level` (dimensionless `1` gauge) recovers toward `1.0`.\n"),
			wantSubs: "has 2 recovery claims for backpressure_level",
		},
		{
			name:     "pronoun neither ever reaches zero",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Neither ever reaches zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "metric-free none of these metrics ever reaches zero",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" None of these metrics ever reaches zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "pronoun dry-run qualifier",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" That holds only in dry-run mode.\n"),
			wantSubs: "negates or contradicts a statement outside the checked forms",
		},
		{
			name:     "pronoun both stay positive forever",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Under sustained load, both stay positive forever.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "pronoun all four climb unboundedly",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" In production, all four climb unboundedly.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "named metric fails to drain",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" `inflight_requests` fails to drain.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "named metric rarely reaches floor",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" `backpressure_level` rarely reaches its floor.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "named metric stays positive without manual intervention",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Without manual intervention, `inflight_requests` stays positive.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "named metric only drains when idle",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" `inflight_requests` only drains when idle.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "named metric stays at unquoted number",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Under load, `backpressure_level` stays at 1.0.\n"),
			wantSubs: "names backpressure_level next to",
		},
		{
			name:     "named metric climbs to wrong config key",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Actually, `effective_request_bytes` climbs to `write.backpressure.min_request_bytes`.\n"),
			wantSubs: "names effective_request_bytes next to",
		},
		{
			name:     "named metric grows indefinitely instead of draining",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Instead of draining, `unresolved_results` grows indefinitely.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "contradiction placed before table",
			mutate:   replace(introLine, introLine+"\nNone of these instruments recover; `inflight_requests` never returns to zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "contradiction appended to intro paragraph",
			mutate:   replace(introLine, strings.TrimSuffix(introLine, "\n")+" Note that `inflight_requests` never returns to zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:   "valid: true subset gauge count omitting total",
			mutate: replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Only two of the current-value instruments are gauges.\n"),
		},
		{
			name:   "valid: true subset gauge count stating total",
			mutate: replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Two of the four current-value instruments are gauges.\n"),
		},
		{
			name:   "valid: true subset UpDownCounter count stating total",
			mutate: replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Two of the four current-value instruments are UpDownCounters.\n"),
		},
		{
			name:     "false subset gauge count with three of four",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Three of the four current-value instruments are gauges.\n"),
			wantSubs: `counts "Three" current-value gauges, metadata.yaml declares 2`,
		},
		{
			name:     "false subset gauge count with only three",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Only three of the current-value instruments are gauges.\n"),
			wantSubs: `counts "three" current-value gauges, metadata.yaml declares 2`,
		},
		{
			name:     "false singular subset gauge count",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Only one of the current-value instruments is a gauge.\n"),
			wantSubs: `counts "one" current-value gauges, metadata.yaml declares 2`,
		},
		{
			name:     "false total count inside subset gauge statement",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Two of the five current-value instruments are gauges.\n"),
			wantSubs: `counts "five" non-counter current-value instruments, metadata.yaml declares 4`,
		},
		{
			name:     "subset prefix with recovery claim",
			mutate:   replace(proseEnd, strings.TrimSuffix(proseEnd, "\n")+" Two of the four current-value instruments never return to zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "twenty word total count claim",
			mutate:   replace("Of the four non-counter", "Of the twenty non-counter"),
			wantSubs: `counts "twenty" non-counter current-value instruments, metadata.yaml declares 4`,
		},
		{
			name:     "zero word count claim",
			mutate:   replace("Of the four non-counter", "Of the zero non-counter"),
			wantSubs: `counts "zero" non-counter current-value instruments, metadata.yaml declares 4`,
		},
		{
			name:   "valid: operational warning imperative without recovery wording",
			mutate: after(proseEnd, "\nDo not use these instruments as billing counters.\n"),
		},
		{
			name:     "negative imperative naming instrument return to zero",
			mutate:   after(proseEnd, "\nDo not expect `inflight_requests` to return to zero.\n"),
			wantSubs: "recovery statement outside the checked forms",
		},
		{
			name:     "negative imperative contradicting previous statement",
			mutate:   after(proseEnd, "\nDo not assume the previous statement holds.\n"),
			wantSubs: "negates or contradicts a statement outside the checked forms",
		},
		{
			name:     "negation claiming condition does not apply in production",
			mutate:   after(proseEnd, "\nThat does not apply in production.\n"),
			wantSubs: "negates or contradicts a statement outside the checked forms",
		},
		{
			name:   "valid: prose sentence with e.g. abbreviation",
			mutate: after(proseEnd, "\nSee e.g. the Collector troubleshooting guide for Prometheus scrape configuration.\n"),
		},
		{
			name:   "valid: reordered UpDownCounter names",
			mutate: replace("instruments, `inflight_requests` and\n`unresolved_results` (`UpDownCounter`)", "instruments, `unresolved_results` and\n`inflight_requests` (`UpDownCounter`)"),
		},
		{
			name: "valid: reordered gauge claims",
			mutate: replace("`backpressure_level` (dimensionless `1` gauge in `[0.0, 1.0]`) recovers toward\n`0.0` and `effective_request_bytes` (byte gauge) recovers to\n`write.max_request_bytes`, not zero.",
				"`effective_request_bytes` (byte gauge) recovers to\n`write.max_request_bytes`, not zero, and `backpressure_level` (dimensionless `1` gauge in `[0.0, 1.0]`) recovers toward `0.0`."),
		},
		{
			name:   "valid: gauge claims in two sentences",
			mutate: replace("recovers toward\n`0.0` and `effective_request_bytes`", "recovers toward\n`0.0`. When `write.backpressure.enabled` is `true`, `effective_request_bytes`"),
		},
		{
			name:   "valid: recovers to a zero target",
			mutate: replace("recovers toward\n`0.0`", "recovers to\n`0.0`"),
		},
		{
			name: "valid: rewrapped recovery paragraph",
			mutate: func(s string) string {
				start, end := strings.Index(s, "Of the four non-counter"), strings.Index(s, proseEnd)
				if start < 0 || end < start {
					return s
				}
				end += len(proseEnd) - 1
				return s[:start] + strings.ReplaceAll(s[start:end], "\n", " ") + s[end:]
			},
		},
		{
			name:   "valid: unrelated sentence in the section",
			mutate: after(proseEnd, "\nThe Grafana collector dashboard charts these instruments per collector instance.\n"),
		},

		// Markdown is read as GitHub renders it.
		{
			name:     "stray table after inline triple backticks",
			mutate:   after(laterHead, "\n```example```\n\n| Metric | Type |\n| --- | --- |\n| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "stray table inside a block quote",
			mutate:   after(laterHead, "\n> | Metric | Type |\n> | --- | --- |\n> | `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "stray table inside a list item",
			mutate:   after(laterHead, "\n- Extra metrics:\n\n  | Metric | Type |\n  | --- | --- |\n  | `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "second self-telemetry table header",
			mutate:   after(laterHead, "\n| Metric | Type | Unit | Attributes | Meaning |\n| --- | --- | --- | --- | --- |\n| `x` | `Counter (int)` | `1` | `none` | x |\n"),
			wantSubs: "starts another self-telemetry table",
		},
		{
			name:     "table split by a blank line",
			mutate:   replace("| `otelcol_exporter_bigquery_retries` |", "\n| `otelcol_exporter_bigquery_retries` |"),
			wantSubs: "orphaned markdown table row",
		},
		{
			name:   "valid: shorter fence inside a longer fence",
			mutate: after(laterHead, "\n````markdown\n```\n| `otelcol_exporter_bigquery_retries` | `Counter (int)` | `{failure}` | `{class}` | Example row. |\n```\n````\n"),
		},
		{
			name:   "valid: fence line with text after the backticks does not close",
			mutate: after(laterHead, "\n```text\nexample\n```not a closing fence\n| `otelcol_exporter_bigquery_retries` | still code |\n```\n"),
		},
		{
			name:   "valid: table inside pre block ignoring mismatched style close tag",
			mutate: after(laterHead, "\n<pre>\n</style>\n| Metric | Type |\n| --- | --- |\n| `otelcol_exporter_bigquery_retries` | `Counter (int)` |\n</pre>\n"),
		},
		{
			name:     "stray table after matching pre close tag",
			mutate:   after(laterHead, "\n<pre>\nexample\n</pre>\n| Metric | Type |\n| --- | --- |\n| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:   "valid: fenced shell example in the section",
			mutate: after(proseEnd, "\n```sh\ncurl -s localhost:8888/metrics | grep otelcol_exporter_bigquery_retries\n```\n"),
		},
		{
			name:   "valid: inline pipe prose in the section",
			mutate: after(proseEnd, "\nFor diagnostics, choose traces | logs in the signal selector.\n"),
		},
		{
			name:   "valid: block quote ends the table",
			mutate: replace(lastRow+"\n", lastRow+"> This note is outside the table.\n\n"),
		},
		{
			name:   "valid: block quote replaces the blank line after the table",
			mutate: replace(lastRow+"\n", lastRow+"> This note is outside the table.\n"),
		},
		{
			name:   "valid: notation-only pipe paragraph later in README",
			mutate: after(laterHead, "\n`otelcol_exporter_bigquery_inflight_requests` uses left | right as notation only.\n"),
		},
		{
			name:   "valid: notation-only pipe paragraph in the section",
			mutate: after(proseEnd, "\n`otelcol_exporter_bigquery_inflight_requests` uses left | right as notation only.\n"),
		},
		{
			name:     "double-backslash pipe header in stray table",
			mutate:   after(laterHead, "\nCol \\\\| Metric | Type\n--- | --- | ---\nrow | `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)`\n\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "stray table metric in second column",
			mutate:   after(laterHead, "\n| Signal | Metric | Type |\n| --- | --- | --- |\n| traces | `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "stray table metric with badge suffix in cell",
			mutate:   after(laterHead, "\n| Metric | Type |\n| --- | --- |\n| `otelcol_exporter_bigquery_orphan_metric` (alpha) | `Counter (int)` |\n\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:     "empty list item followed by blank line before decoy table",
			mutate:   after(introLine, "\n-\n\n  | Wrong | Table |\n  | --- | --- |\n  | 1 | 2 |\n"),
			wantSubs: "self-telemetry table header = [Wrong Table]",
		},
		{
			name:     "empty list item followed by blank line before heading",
			mutate:   replace("\nOf the four non-counter", "\n-\n\n  ### Early Section End\n\n`inflight_requests` never returns to zero.\n\nOf the four non-counter"),
			wantSubs: "no recovery claim for inflight_requests",
		},
		{
			name:     "HTML comment line before stray table",
			mutate:   after(laterHead, "\n<!-- note -->\n| Metric | Type |\n| --- | --- |\n| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:   "valid: tilde fence with backticks in info string",
			mutate: after(laterHead, "\n~~~sh `otelcol_exporter_bigquery_orphan_metric`\n| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n~~~\n\n"),
		},
		{
			name:     "compact blockquote stray table",
			mutate:   after(laterHead, "\n>| Metric | Type |\n>| --- | --- |\n>| `otelcol_exporter_bigquery_orphan_metric` | `Counter (int)` |\n\n"),
			wantSubs: "naming otelcol_exporter_bigquery_orphan_metric outside the self-telemetry table",
		},
		{
			name:   "valid: escaped pipe inside code span in table cell",
			mutate: replace("Rows acknowledged by BigQuery Storage Write API `AppendRows`.", "Rows acknowledged (`ok \\| retry`) by BigQuery Storage Write API `AppendRows`."),
		},

		// Recordings are resolved with type information.
		{
			name:            "shadowed attribute key constant",
			mutateTelemetry: replace(retryLine, "\tAttrClass := \"reason\"\n"+retryLine),
			wantSubs:        "attribute key AttrClass is not a constant",
		},
		{
			name:            "additional bad alias recording",
			mutateTelemetry: after(retryLine, "\tretry := t.Retries\n\tretry.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, class)))\n"),
			wantSubs:        "records otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		},
		{
			name:            "additional bad parenthesized recording",
			mutateTelemetry: after(retryLine, "\t(t.Retries).Add(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, class)))\n"),
			wantSubs:        "records otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		},
		{
			name:            "aliased recording with an undeclared attribute",
			mutateTelemetry: after(rejectLine, "\trejected := t.RejectedRows\n\trejected.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrClass, reason)))\n"),
			wantSubs:        "records otelcol_exporter_bigquery_rejected_rows with attributes {class}, metadata.yaml declares {reason}",
		},
		{
			name:            "local constant shadowing a key",
			mutateTelemetry: replace(retryLine, "\tconst AttrClass = \"reason\"\n"+retryLine),
			wantSubs:        "records otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		},
		{
			name:            "alias reassigned before recording",
			mutateTelemetry: after(retryLine, "\tretry := t.Retries\n\tretry = t.RejectedRows\n\tretry.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, class)))\n"),
			wantSubs:        "retry is reassigned or has its address taken",
		},
		{
			name: "instrument passed to a helper",
			mutateTelemetry: func(s string) string {
				return strings.Replace(s, retryLine, "\taddClass(ctx, t.Retries, class)\n", 1) +
					"\nfunc addClass(ctx context.Context, c metric.Int64Counter, class string) {\n\tc.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, class)))\n}\n"
			},
			wantSubs: "cannot tell which Telemetry instrument this Add call records",
		},
		{
			name:            "method value recording",
			mutateTelemetry: replace(retryLine, "\tadd := t.Retries.Add\n\tadd(ctx, 1, metric.WithAttributes(attribute.String(AttrReason, class)))\n"),
			wantSubs:        "uses Telemetry.Retries outside a checked constructor or Add/Record call",
		},
		{
			name:            "spread recording options",
			mutateTelemetry: replace(retryLine, "\topts := []metric.AddOption{metric.WithAttributes(attribute.String(AttrReason, class))}\n\tt.Retries.Add(ctx, 1, opts...)\n"),
			wantSubs:        "cannot verify the attributes otelcol_exporter_bigquery_retries is recorded with: its options are a spread slice",
		},
		{
			name:            "instrument overwritten after construction",
			mutateTelemetry: replace("\treturn t, nil\n}", "\tt.Retries = t.RejectedRows\n\treturn t, nil\n}"),
			wantSubs:        "uses Telemetry.Retries outside a checked constructor or Add/Record call",
		},
		{
			name:         "recording in another file of the package",
			addTelemetry: map[string]string{"extra.go": extraFile},
			wantSubs:     "internal/metadata/extra.go line 12 records otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		},
		{
			name:            "observable instrument",
			mutateTelemetry: replace("m.Int64Counter(nameStreamRetirements,", "m.Int64ObservableCounter(nameStreamRetirements,"),
			wantSubs:        "Int64ObservableCounter is an observable instrument",
		},
		{
			name:            "valid: recording through a local alias",
			mutateTelemetry: replace(retryLine, "\tretries := t.Retries\n\tretries.Add(ctx, 1, metric.WithAttributes(attribute.String(AttrClass, class)))\n"),
		},
		{
			name:            "valid: parenthesized receiver",
			mutateTelemetry: replace(retryLine, "\t(t.Retries).Add(ctx, 1, metric.WithAttributes(attribute.String(AttrClass, class)))\n"),
		},
		{
			name:            "valid: attribute.Key constructor",
			mutateTelemetry: replace(retryLine, "\tt.Retries.Add(ctx, 1, metric.WithAttributes(attribute.Key(AttrClass).String(class)))\n"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutatedReadme := readme
			if tc.mutate != nil {
				if mutatedReadme = tc.mutate(readme); mutatedReadme == readme {
					t.Fatal("the probe did not change README.md")
				}
			}
			mutatedTelemetry := telemetry
			if tc.mutateTelemetry != nil || tc.addTelemetry != nil {
				mutatedTelemetry = maps.Clone(telemetry)
				maps.Copy(mutatedTelemetry, tc.addTelemetry)
			}
			if tc.mutateTelemetry != nil {
				if mutatedTelemetry["telemetry.go"] = tc.mutateTelemetry(telemetry["telemetry.go"]); mutatedTelemetry["telemetry.go"] == telemetry["telemetry.go"] {
					t.Fatal("the probe did not change internal/metadata/telemetry.go")
				}
			}
			problems := validateReadmeSelfTelemetry(mutatedReadme, meta, mutatedTelemetry, grafana)
			if tc.wantSubs == "" {
				for _, p := range problems {
					t.Errorf("valid edit rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}

// TestReadmeSelfTelemetryRecordedOnlyInMetadata keeps every recording where
// the static check reads it: no other package of this module touches a
// Telemetry instrument field or hands a Telemetry on.
func TestReadmeSelfTelemetryRecordedOnlyInMetadata(t *testing.T) {
	pkgs := readmeMetadataImporters(t)
	if _, ok := pkgs[readmeModulePath]; !ok {
		t.Fatalf("found no package importing internal/metadata in %v; the check would read nothing", slices.Sorted(maps.Keys(pkgs)))
	}
	for _, p := range readmeOutsideMetadataProblems(pkgs) {
		t.Error(p)
	}

	// tupleHelpers return a Telemetry in one slot of a multi-value result.
	const tupleHelpers = "\nvar probeTelemetry *metadata.Telemetry\n" +
		"\nfunc probeTelemetryPair() (*metadata.Telemetry, error) { return probeTelemetry, nil }\n" +
		"\nfunc probeErrTelemetry() (error, *metadata.Telemetry) { return nil, probeTelemetry }\n" +
		"\nfunc probeCountTelemetry() (int, *metadata.Telemetry) { return 1, probeTelemetry }\n"
	const boxedTelemetry = "boxes *github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata.Telemetry into interface "
	for _, tc := range []struct {
		name     string
		mutate   func(string) string
		add      string
		wantSubs string
		// valid marks source that must produce no problem at all.
		valid bool
	}{
		{
			name:     "direct recording from the exporter",
			add:      "\nfunc (e *signalExporter) probeRetry(ctx context.Context) {\n\te.tel.Retries.Add(ctx, 1)\n}\n",
			wantSubs: "uses Telemetry.Retries directly; record self-telemetry only through the Telemetry methods",
		},
		{
			name:     "exported Telemetry accessor",
			add:      "\n// ProbeTelemetry returns the exporter's telemetry.\nfunc (e *signalExporter) ProbeTelemetry() *metadata.Telemetry { return e.tel }\n",
			wantSubs: "method signalExporter.ProbeTelemetry hands a metadata.Telemetry to other packages",
		},
		{
			name: "reflection on Telemetry instrument field",
			mutate: func(src string) string {
				src = strings.Replace(src, "\"context\"\n", "\"context\"\n\t\"reflect\"\n", 1)
				return src + "\nfunc (e *signalExporter) stealthReflect() any {\n\treturn reflect.ValueOf(e.tel).Elem().FieldByName(\"Retries\").Interface()\n}\n"
			},
			wantSubs: "passes *github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata.Telemetry to reflect.ValueOf",
		},
		{
			name:     "exported function returning Telemetry boxed in any",
			add:      "\n// StealthLeak returns telemetry disguised as any.\nfunc StealthLeak(e *signalExporter) any { return e.tel }\n",
			wantSubs: "boxes *github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata.Telemetry into interface any",
		},
		{
			name:     "exported struct indirectly holding Telemetry",
			add:      "\ntype stealthHolder struct { tel *metadata.Telemetry }\n// ExportedStealth exposes holder.\ntype ExportedStealth struct { H stealthHolder }\n",
			wantSubs: "ExportedStealth hands a metadata.Telemetry to other packages",
		},
		{
			name: "unsafe import in package importing metadata",
			mutate: func(src string) string {
				src = strings.Replace(src, "\"context\"\n", "\"context\"\n\t\"unsafe\"\n", 1)
				return src + "\nvar _ = unsafe.Sizeof(0)\n"
			},
			wantSubs: "imports unsafe in a package that imports internal/metadata",
		},

		// Composite literals convert each element, map key and value, and
		// struct field to its destination type, so a Telemetry stored in an
		// interface slot there is boxed just like in an assignment.
		{
			name: "reflection recording through a boxed slice element",
			mutate: func(src string) string {
				src = strings.Replace(src, "\"context\"\n", "\"context\"\n\t\"reflect\"\n\n\t\"go.opentelemetry.io/otel/attribute\"\n\t\"go.opentelemetry.io/otel/metric\"\n", 1)
				return src + "\nfunc (e *signalExporter) reviewOpaqueRecord(ctx context.Context) {\n" +
					"\tvalues := []any{e.tel}\n" +
					"\tinstrument := reflect.ValueOf(values[0]).Elem().FieldByName(\"Retries\").Interface().(metric.Int64Counter)\n" +
					"\tinstrument.Add(ctx, 1, metric.WithAttributes(attribute.String(\"reason\", \"unavailable\")))\n}\n"
			},
			wantSubs: boxedTelemetry + "any",
		},
		{name: "slice literal element", add: "\nfunc (e *signalExporter) ReviewLeak() []any { return []any{e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "map literal value", add: "\nfunc (e *signalExporter) ReviewLeak() map[string]any { return map[string]any{\"tel\": e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "keyed struct literal field", add: "\nfunc (e *signalExporter) ReviewLeak() any { return struct{ Value any }{Value: e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "positional struct literal field", add: "\nfunc (e *signalExporter) probePositional() struct{ Value any } { return struct{ Value any }{e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "named struct literal field", add: "\ntype probeHolder struct{ v any }\n\nfunc (e *signalExporter) probeNamed() probeHolder { return probeHolder{v: e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "array literal element", add: "\nfunc (e *signalExporter) probeArray() [1]any { return [1]any{e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "indexed slice literal element", add: "\nfunc (e *signalExporter) probeIndexed() []any { return []any{3: e.tel} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "map literal key", add: "\nfunc (e *signalExporter) probeMapKey() map[any]bool { return map[any]bool{e.tel: true} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "element of a nested literal with elided type", add: "\nfunc (e *signalExporter) probeNested() [][]any { return [][]any{{e.tel}} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "field of an elided pointer element", add: "\nfunc (e *signalExporter) probeElided() []*struct{ V any } { return []*struct{ V any }{{V: e.tel}} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "element of a named interface type", add: "\ntype probeBox interface{}\n\nfunc (e *signalExporter) probeNamedIface() []probeBox { return []probeBox{e.tel} }\n", wantSubs: boxedTelemetry + "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter.probeBox"},
		{name: "element holding Telemetry in a struct", add: "\nfunc (e *signalExporter) probeIndirect() []any { return []any{struct{ t *metadata.Telemetry }{e.tel}} }\n", wantSubs: "boxes struct{t *github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata.Telemetry} into interface any"},
		{name: "literal of a type-parameter slice type", add: "\nfunc probeParamLit[S ~[]any](v *metadata.Telemetry) S { return S{v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "literal of a type-parameter map type", add: "\nfunc probeParamMap[M ~map[string]any](v *metadata.Telemetry) M { return M{\"k\": v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "valid literal of a type-parameter type without Telemetry", add: "\nfunc probeParamValues[S ~[]any]() S { return S{1, \"x\"} }\n", valid: true},
		{name: "valid literal with a concrete Telemetry element", add: "\nfunc (e *signalExporter) probeConcrete() int { tels := []*metadata.Telemetry{e.tel}; return len(tels) }\n", valid: true},
		{name: "valid literals boxing values without Telemetry", add: "\nfunc probeBoxedValues() []any { return []any{1, \"two\", map[string]any{\"k\": true}, struct{ V any }{V: 3.0}} }\n", valid: true},
		{name: "valid struct literal with a plain interface field", add: "\nfunc probeStructValue() struct{ V any } { return struct{ V any }{V: \"x\"} }\n", valid: true},

		// A forwarded multi-value expression (a call, or a comma-ok form)
		// assigns each slot to its own destination, so each slot is checked.
		{
			name:     "forwarded multi-value return",
			add:      "\nvar reviewTelemetry *metadata.Telemetry\n\nfunc reviewTelemetrySource() (*metadata.Telemetry, error) {\n\treturn reviewTelemetry, nil\n}\n\n// StealthForward exposes Telemetry through an interface in a multi-value return.\nfunc StealthForward() (any, error) {\n\treturn reviewTelemetrySource()\n}\n",
			wantSubs: boxedTelemetry + "any",
		},
		{name: "forwarded return in a function literal", add: tupleHelpers + "\nfunc probeForwardLit() func() (any, error) { return func() (any, error) { return probeTelemetryPair() } }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded multi-value assignment", add: tupleHelpers + "\nfunc probeAssign() { var leaked any; var err error; leaked, err = probeTelemetryPair(); _, _ = leaked, err }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded define reusing an interface variable", add: tupleHelpers + "\nfunc probeDefine() { var leaked any; leaked, err := probeTelemetryPair(); _, _ = leaked, err }\n", wantSubs: boxedTelemetry + "any"},
		{name: "define reusing an interface variable", add: "\nfunc (e *signalExporter) probeDefineEqual() { var leaked any; leaked, n := e.tel, 1; _, _ = leaked, n }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded var declaration", add: tupleHelpers + "\nfunc probeVarSpec() { var leaked, err any = probeTelemetryPair(); _, _ = leaked, err }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded var declaration with a blank first slot", add: tupleHelpers + "\nfunc probeBlankSpec() { var _, leaked any = probeErrTelemetry(); _ = leaked }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded package-level var declaration", add: tupleHelpers + "\nvar probeLeaked, probeErr any = probeTelemetryPair()\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded call arguments", add: tupleHelpers + "\nfunc probeSink(n int, v any) {}\n\nfunc probeForwardCall() { probeSink(probeCountTelemetry()) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "forwarded variadic call arguments", add: tupleHelpers + "\nfunc probeSinkAll(n int, vs ...any) {}\n\nfunc probeForwardVariadic() { probeSinkAll(probeCountTelemetry()) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "comma-ok map index into an interface", add: "\nfunc probeCommaMap(m map[string]*metadata.Telemetry) { var leaked any; var ok bool; leaked, ok = m[\"x\"]; _, _ = leaked, ok }\n", wantSubs: boxedTelemetry + "any"},
		{name: "comma-ok receive into an interface", add: "\nfunc probeCommaRecv(ch chan *metadata.Telemetry) { var leaked any; var ok bool; leaked, ok = <-ch; _, _ = leaked, ok }\n", wantSubs: boxedTelemetry + "any"},
		{name: "comma-ok type assertion into an interface", add: "\nfunc probeCommaAssert(x any) { var leaked any; var ok bool; leaked, ok = x.(*metadata.Telemetry); _, _ = leaked, ok }\n", wantSubs: boxedTelemetry + "any"},
		{name: "comma-ok var declaration", add: "\nfunc probeCommaSpec(m map[string]*metadata.Telemetry) { var leaked, ok any = m[\"x\"]; _, _ = leaked, ok }\n", wantSubs: boxedTelemetry + "any"},
		{name: "valid forwarded return of concrete results", add: tupleHelpers + "\nfunc probeForwardConcrete() (*metadata.Telemetry, error) { return probeTelemetryPair() }\n", valid: true},
		{name: "valid forwarded return boxing values without Telemetry", add: "\nfunc probeIntPair() (int, error) { return 1, nil }\n\nfunc probeForwardInts() (any, error) { return probeIntPair() }\n", valid: true},
		{name: "valid multi-value assignment to concrete variables", add: tupleHelpers + "\nfunc probeAssignConcrete() { var tel *metadata.Telemetry; var err error; tel, err = probeTelemetryPair(); _, _ = tel, err }\n", valid: true},
		{name: "valid multi-value define of new variables", add: tupleHelpers + "\nfunc probeDefineNew() { tel, err := probeTelemetryPair(); _, _ = tel, err }\n", valid: true},
		{name: "valid forwarded call into concrete parameters", add: tupleHelpers + "\nfunc probeConcreteSink(n int, t *metadata.Telemetry) {}\n\nfunc probeForwardConcreteCall() { probeConcreteSink(probeCountTelemetry()) }\n", valid: true},
		{name: "valid comma-ok into concrete variables", add: "\nfunc probeCommaConcrete(m map[string]*metadata.Telemetry) { tel, ok := m[\"x\"]; _, _ = tel, ok }\n", valid: true},

		// Channel sends, range assignments to existing variables and map
		// index keys convert their value to the destination type too.
		{name: "channel send into an interface channel", add: "\nfunc (e *signalExporter) probeSend(ch chan any) { ch <- e.tel }\n", wantSubs: boxedTelemetry + "any"},
		{name: "select send case into an interface channel", add: "\nfunc (e *signalExporter) probeSelect(ch chan any) {\n\tselect {\n\tcase ch <- e.tel:\n\tdefault:\n\t}\n}\n", wantSubs: boxedTelemetry + "any"},
		{name: "range value assigned to an interface variable", add: "\nfunc (e *signalExporter) probeRange() any {\n\tvar x any\n\tfor _, x = range []*metadata.Telemetry{e.tel} {\n\t}\n\treturn x\n}\n", wantSubs: boxedTelemetry + "any"},
		{name: "range key assigned to an interface variable", add: "\nfunc (e *signalExporter) probeRangeKey() any {\n\tvar x any\n\tfor x = range map[*metadata.Telemetry]bool{e.tel: true} {\n\t}\n\treturn x\n}\n", wantSubs: boxedTelemetry + "any"},
		{name: "map index key of an interface key type", add: "\nfunc (e *signalExporter) probeIndexKey(m map[any]bool) { m[e.tel] = true }\n", wantSubs: boxedTelemetry + "any"},
		{name: "valid channel send of a concrete Telemetry", add: "\nfunc (e *signalExporter) probeSendConcrete(ch chan *metadata.Telemetry) { ch <- e.tel }\n", valid: true},
		{name: "valid range defining new variables", add: "\nfunc (e *signalExporter) probeRangeDefine() int {\n\tn := 0\n\tfor _, t := range []*metadata.Telemetry{e.tel} {\n\t\tif t != nil {\n\t\t\tn++\n\t\t}\n\t}\n\treturn n\n}\n", valid: true},
		{name: "valid map index with a concrete key type", add: "\nfunc (e *signalExporter) probeIndexConcrete(m map[*metadata.Telemetry]bool) { m[e.tel] = true }\n", valid: true},
		{name: "union and matching embedded constraint slice literal", add: "\nfunc probeUnionEmbedLit[S interface{ ~[]any | ~[]int; ~[]any }](v *metadata.Telemetry) S { return S{v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "union with non-tilde slice intersected with tilde literal", add: "\nfunc probeExactEmbedLit[S interface{ []any | ~[]int; ~[]any }](v *metadata.Telemetry) S { return S{v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "named defined slice intersected with tilde literal", add: "\ntype probeAnySlice []any\n\nfunc probeNamedEmbedLit[S interface{ probeAnySlice; ~[]any }](v *metadata.Telemetry) S { return S{v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "nested embedded interface intersection literal", add: "\ntype probeInnerSliceIface interface{ ~[]any | ~[]int }\n\nfunc probeNestedEmbedLit[S interface{ probeInnerSliceIface; ~[]any }](v *metadata.Telemetry) S { return S{v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "type-parameter struct composite literal field", add: "\nfunc probeParamStructLit[S ~struct{ V any }](v *metadata.Telemetry) S { return S{V: v} }\n", wantSubs: boxedTelemetry + "any"},
		{name: "directed channel union send", add: "\nfunc probeChanUnionSend[C chan any | chan<- any](ch C, v *metadata.Telemetry) { ch <- v }\n", wantSubs: boxedTelemetry + "any"},
		{name: "type parameter constrained directly to Telemetry boxed in any", add: "\nfunc probeParamTelemetry[T *metadata.Telemetry](v T) any { return v }\n", wantSubs: "boxes T into interface any"},
		{name: "type parameter constrained to struct holding Telemetry boxed in any", add: "\nfunc probeParamStructTelemetry[T ~struct{ t *metadata.Telemetry }](v T) any { return v }\n", wantSubs: "boxes T into interface any"},
		{name: "type parameter union containing Telemetry boxed in any", add: "\nfunc probeParamUnionTelemetry[T *metadata.Telemetry | int](v T) any { return v }\n", wantSubs: "boxes T into interface any"},
		{name: "named function type parameter boxing Telemetry", add: "\ntype probeSinkFn func(any)\n\nfunc probeNamedFuncCall(f probeSinkFn, v *metadata.Telemetry) { f(v) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "type parameter function boxing Telemetry", add: "\nfunc probeParamFuncCall[F ~func(any)](f F, v *metadata.Telemetry) { f(v) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "append builtin boxing Telemetry into interface slice", add: "\nfunc (e *signalExporter) probeAppendLeak() []any { return append([]any(nil), e.tel) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "append builtin boxing Telemetry into type-parameter slice", add: "\nfunc probeParamAppendLeak[S ~[]any](s S, v *metadata.Telemetry) S { return append(s, v) }\n", wantSubs: boxedTelemetry + "any"},
		{name: "generic function instantiation exposing Telemetry", add: "\nfunc probeGenWrap[T any](v T) any { return v }\n\nfunc (e *signalExporter) probeGenLeak() { _ = probeGenWrap(e.tel) }\n", wantSubs: "instantiates generic probeGenWrap with type argument *github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata.Telemetry"},
		{name: "valid unconstrained generic wrapper definition", add: "\nfunc probeValidBox[T any](v T) any { return v }\n", valid: true},
		{name: "valid intersection constraint slice without Telemetry", add: "\nfunc probeValidIntersectSlice[S interface{ ~[]int | ~[]string; ~[]int }]() S { return S{1, 2} }\n", valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := maps.Clone(pkgs)
			mutated[readmeModulePath] = maps.Clone(pkgs[readmeModulePath])
			if tc.mutate != nil {
				mutated[readmeModulePath]["exporter.go"] = tc.mutate(pkgs[readmeModulePath]["exporter.go"])
			} else {
				mutated[readmeModulePath]["exporter.go"] += tc.add
			}
			problems := readmeOutsideMetadataProblems(mutated)
			// A probe that does not compile would be rejected for the wrong
			// reason, so it fails the test instead.
			for _, p := range problems {
				if strings.Contains(p, "does not type-check") || strings.Contains(p, "cannot type-check") {
					t.Fatalf("probe source does not type-check: %v", problems)
				}
			}
			if tc.valid {
				for _, p := range problems {
					t.Errorf("valid source rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}

// readmeSampleArg returns a value for one parameter of a Telemetry method.
func readmeSampleArg(typ reflect.Type) (reflect.Value, bool) {
	switch typ {
	case reflect.TypeFor[context.Context]():
		return reflect.ValueOf(context.Background()), true
	case reflect.TypeFor[time.Duration]():
		return reflect.ValueOf(1500 * time.Millisecond), true
	}
	switch typ.Kind() {
	case reflect.String:
		return reflect.ValueOf("sample").Convert(typ), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(int64(3)).Convert(typ), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflect.ValueOf(uint64(3)).Convert(typ), true
	case reflect.Float32, reflect.Float64:
		return reflect.ValueOf(0.5).Convert(typ), true
	case reflect.Bool:
		return reflect.ValueOf(true).Convert(typ), true
	}
	return reflect.Value{}, false
}

// readmeCallTelemetryMethods calls every exported method of tel once with
// sample arguments, so a recording added to any of them is emitted.
func readmeCallTelemetryMethods(t *testing.T, tel *metadata.Telemetry) int {
	t.Helper()
	v := reflect.ValueOf(tel)
	called := 0
	for i := 0; i < v.NumMethod(); i++ {
		method := v.Type().Method(i)
		args := []reflect.Value{v}
		for j := 1; j < method.Type.NumIn(); j++ {
			arg, ok := readmeSampleArg(method.Type.In(j))
			if !ok || method.Type.IsVariadic() {
				t.Errorf("cannot build a %s argument for (*metadata.Telemetry).%s; extend readmeSampleArg so the emission check calls it", method.Type.In(j), method.Name)
				args = nil
				break
			}
			args = append(args, arg)
		}
		if args != nil {
			method.Func.Call(args)
			called++
		}
	}
	return called
}

// readmeEmissionShape returns the metadata.yaml type label of collected
// data, the sorted attribute keys of each data point, and each histogram
// point's bucket boundaries.
func readmeEmissionShape(data metricdata.Aggregation) (string, [][]string, [][]float64) {
	keys := func(set attribute.Set) []string {
		var out []string
		for _, kv := range set.ToSlice() {
			out = append(out, string(kv.Key))
		}
		slices.Sort(out)
		return out
	}
	var sets [][]string
	var bounds [][]float64
	switch d := data.(type) {
	case metricdata.Sum[int64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, keys(dp.Attributes))
		}
		if d.IsMonotonic {
			return "Counter (int)", sets, nil
		}
		return "UpDownCounter (int)", sets, nil
	case metricdata.Sum[float64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, keys(dp.Attributes))
		}
		if d.IsMonotonic {
			return "Counter (double)", sets, nil
		}
		return "UpDownCounter (double)", sets, nil
	case metricdata.Gauge[int64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, keys(dp.Attributes))
		}
		return "Gauge (int)", sets, nil
	case metricdata.Gauge[float64]:
		for _, dp := range d.DataPoints {
			sets = append(sets, keys(dp.Attributes))
		}
		return "Gauge (double)", sets, nil
	case metricdata.Histogram[int64]:
		for _, dp := range d.DataPoints {
			sets, bounds = append(sets, keys(dp.Attributes)), append(bounds, dp.Bounds)
		}
		return "Histogram (int)", sets, bounds
	case metricdata.Histogram[float64]:
		for _, dp := range d.DataPoints {
			sets, bounds = append(sets, keys(dp.Attributes)), append(bounds, dp.Bounds)
		}
		return "Histogram (double)", sets, bounds
	}
	return fmt.Sprintf("unsupported %T", data), nil, nil
}

// readmeEmissionProblems compares collected self-telemetry with
// metadata.yaml: every metric is declared and has the declared unit, kind
// and bucket boundaries, every data point carries exactly the declared
// attribute keys, and every declared metric is emitted.
func readmeEmissionProblems(rm metricdata.ResourceMetrics, metrics map[string]readmeMetadataMetric) []string {
	var problems []string
	seen := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			spec, ok := metrics[m.Name]
			if !ok {
				problems = append(problems, fmt.Sprintf("Telemetry emits %s, which metadata.yaml does not declare", m.Name))
				continue
			}
			if seen[m.Name] {
				problems = append(problems, fmt.Sprintf("Telemetry emits %s from more than one instrument", m.Name))
			}
			seen[m.Name] = true
			if m.Unit != spec.Unit {
				problems = append(problems, fmt.Sprintf("Telemetry emits %s with unit %q, metadata.yaml declares %q", m.Name, m.Unit, spec.Unit))
			}
			kind, keySets, bounds := readmeEmissionShape(m.Data)
			if want := spec.typeLabel(); kind != want {
				problems = append(problems, fmt.Sprintf("Telemetry emits %s as %s, metadata.yaml declares %s", m.Name, kind, want))
			}
			wantAttrs := slices.Sorted(slices.Values(spec.Attributes))
			for _, keys := range keySets {
				if !slices.Equal(keys, wantAttrs) {
					problems = append(problems, fmt.Sprintf("Telemetry emits %s with attributes %s, metadata.yaml declares %s", m.Name, formatAttrSet(keys), formatAttrSet(wantAttrs)))
				}
			}
			for _, b := range bounds {
				if spec.Histogram == nil || !slices.Equal(b, spec.Histogram.BucketBoundaries) {
					problems = append(problems, fmt.Sprintf("Telemetry emits %s with bucket boundaries %v, which metadata.yaml does not declare", m.Name, b))
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(metrics)) {
		if !seen[name] {
			problems = append(problems, fmt.Sprintf("no exported Telemetry method emits %s declared in metadata.yaml", name))
		}
	}
	return problems
}

// TestReadmeSelfTelemetryEmissionMatchesMetadata collects what the SDK
// receives when every exported Telemetry method runs, which covers every
// recording path the static check reads, and compares it with metadata.yaml.
func TestReadmeSelfTelemetryEmissionMatchesMetadata(t *testing.T) {
	raw, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := decodeReadmeMetadata(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	tel, err := metadata.NewTelemetry(provider)
	if err != nil {
		t.Fatal(err)
	}
	if readmeCallTelemetryMethods(t, tel) == 0 {
		t.Fatal("called no exported Telemetry method")
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, p := range readmeEmissionProblems(rm, metrics) {
		t.Error(p)
	}
}

// TestReadmeSelfTelemetryEmissionRejectsDrift proves the emission check fails
// on what the review's source mutations emit: an undeclared attribute on a
// declared metric and an undeclared metric.
func TestReadmeSelfTelemetryEmissionRejectsDrift(t *testing.T) {
	raw, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := decodeReadmeMetadata(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	ctx := context.Background()
	m := provider.Meter("probe")
	retries, err := m.Int64Counter("otelcol_exporter_bigquery_retries", metric.WithUnit("{failure}"))
	if err != nil {
		t.Fatal(err)
	}
	retries.Add(ctx, 1, metric.WithAttributes(attribute.String("class", "unavailable")))
	retries.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", "unavailable")))
	undeclared, err := m.Int64Counter("otelcol_exporter_bigquery_undeclared")
	if err != nil {
		t.Fatal(err)
	}
	undeclared.Add(ctx, 1)
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	problems := readmeEmissionProblems(rm, metrics)
	for _, want := range []string{
		"Telemetry emits otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		"Telemetry emits otelcol_exporter_bigquery_undeclared, which metadata.yaml does not declare",
		"no exported Telemetry method emits otelcol_exporter_bigquery_acknowledged_rows declared in metadata.yaml",
	} {
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, want) }) {
			t.Errorf("missing problem %q in %v", want, problems)
		}
	}
	if slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, "with attributes {class}") }) {
		t.Errorf("the declared attribute set was reported: %v", problems)
	}
}

func TestReadmeMarkdownBlocks(t *testing.T) {
	for _, tc := range []struct {
		name, doc string
		want      []string
	}{
		{"inline triple backticks are not a fence", "```example```\n\n| a | b |\n| - | - |\n| c | d |\n", []string{"paragraph@0", "table@0:2"}},
		{"a shorter run does not close a longer fence", "````\n```\n| a | b |\n| - | - |\n```\n````\n", []string{"fence@0"}},
		{"a closing fence takes no info string", "```\ncode\n``` more\n| a | b |\n| - | - |\n```\nafter\n", []string{"fence@0", "paragraph@0"}},
		{"tilde fence", "~~~\n| a | b |\n| - | - |\n~~~\n", []string{"fence@0"}},
		{"tildes do not close a backtick fence", "```\n~~~\n| a | b |\n| - | - |\n", []string{"fence@0"}},
		{"an unclosed fence runs to the end", "```\n| a | b |\n| - | - |\n", []string{"fence@0"}},
		{"a four-space fence is indented code", "    ```\n    | a | b |\n", []string{"indented@0"}},
		{"a paragraph line under a table is a row", "| a | b |\n| - | - |\n| c | d |\nbar\n\nbar\n", []string{"table@0:3", "paragraph@0"}},
		{"a block quote ends a table", "| a | b |\n| - | - |\n| c | d |\n> quote\n", []string{"table@0:2", "paragraph@1"}},
		{"a heading ends a table", "| a | b |\n| - | - |\n| c | d |\n# H\n", []string{"table@0:2", "heading@0"}},
		{"a list item ends a table", "| a | b |\n| - | - |\n| c | d |\n- item\n", []string{"table@0:2", "paragraph@1"}},
		{"a fence ends a table", "| a | b |\n| - | - |\n| c | d |\n```\nx\n```\n", []string{"table@0:2", "fence@0"}},
		{"a thematic break ends a table", "| a | b |\n| - | - |\n| c | d |\n***\n", []string{"table@0:2", "break@0"}},
		{"an HTML block ends a table", "| a | b |\n| - | - |\n| c | d |\n<div>\n", []string{"table@0:2", "html@0"}},
		{"indented code ends a table", "| a | b |\n| - | - |\n| c | d |\n    code\n", []string{"table@0:2", "indented@0"}},
		{"header and delimiter cell counts must match", "| a | b |\n| - | - | - |\n", []string{"paragraph@0"}},
		{"a table under a paragraph line", "intro\n| a | b |\n| - | - |\n", []string{"paragraph@0", "table@0:1"}},
		{"a table in a block quote", "> | a | b |\n> | - | - |\n> | c | d |\n", []string{"table@1:2"}},
		{"a table in a list item", "- item\n\n  | a | b |\n  | - | - |\n  | c | d |\n", []string{"paragraph@1", "table@1:2"}},
		{"empty list item ends on blank line", "-\n\n  | a | b |\n  | - | - |\n  | c | d |\n", []string{"table@0:2"}},
		{"lazy continuation stays in the block quote", "> quote\nlazy\n\nafter\n", []string{"paragraph@1", "paragraph@0"}},
		{"setext heading", "Title\n---\n", []string{"heading@0"}},
		{"pipe prose is a paragraph", "choose traces | logs\n", []string{"paragraph@0"}},
		{"HTML comment line", "<!-- c -->\n| a | b |\n| - | - |\n", []string{"html@0", "table@0:1"}},
		{"type-1 pre ignores mismatched style close tag", "<pre>\n</style>\n| a | b |\n| - | - |\n</pre>\n| x | y |\n| - | - |\n", []string{"html@0", "table@0:1"}},
		{"type-1 style closes case-insensitively on matching tag", "<STYLE type=\"text/css\">\n</pre>\n</StYlE>\n| x | y |\n| - | - |\n", []string{"html@0", "table@0:1"}},
		{"type-1 textarea ignores mismatched script close tag", "<textarea>\n</script>\n</textarea>\n| x | y |\n| - | - |\n", []string{"html@0", "table@0:1"}},
		{"type-1 script ignores mismatched pre close tag", "<script>\n</pre>\n</script>\n| x | y |\n| - | - |\n", []string{"html@0", "table@0:1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, b := range readmeParseMarkdown(tc.doc) {
				s := fmt.Sprintf("%s@%d", readmeMDKindNames[b.Kind], b.Depth)
				if b.Kind == readmeMDTable {
					s += fmt.Sprintf(":%d", len(b.Cells))
				}
				got = append(got, s)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("blocks = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReadmeCoreTypeAndUnresolvedCompositeLit(t *testing.T) {
	anyType := types.Universe.Lookup("any").Type()
	sliceAny := types.NewSlice(anyType)
	sliceInt := types.NewSlice(types.Typ[types.Int])
	fakePkg := types.NewPackage("example.com/probe", "probe")
	mySlice1 := types.NewNamed(types.NewTypeName(token.NoPos, fakePkg, "mySlice1", nil), sliceAny, nil)
	mySlice2 := types.NewNamed(types.NewTypeName(token.NoPos, fakePkg, "mySlice2", nil), sliceAny, nil)

	completeIface := func(embeddeds ...types.Type) *types.Interface {
		iface := types.NewInterfaceType(nil, embeddeds)
		iface.Complete()
		return iface
	}
	tpWith := func(name string, embeddeds ...types.Type) *types.TypeParam {
		return types.NewTypeParam(types.NewTypeName(token.NoPos, fakePkg, name, nil), completeIface(embeddeds...))
	}

	if got := readmeCoreType(tpWith("S",
		types.NewUnion([]*types.Term{types.NewTerm(true, sliceAny), types.NewTerm(true, sliceInt)}),
		types.NewUnion([]*types.Term{types.NewTerm(true, sliceAny)}),
	)); !types.Identical(got, sliceAny) {
		t.Fatalf("intersected union core type = %v, want []any", got)
	}
	if got := readmeCoreType(tpWith("S",
		mySlice1,
		types.NewUnion([]*types.Term{types.NewTerm(true, sliceAny)}),
	)); !types.Identical(got, sliceAny) {
		t.Fatalf("defined + tilde core type = %v, want []any", got)
	}
	if got := readmeCoreType(tpWith("S", mySlice1, mySlice2)); got != nil {
		t.Fatalf("disjoint defined types core type = %v, want nil", got)
	}
	if got := readmeCoreType(tpWith("S",
		types.NewUnion([]*types.Term{types.NewTerm(true, sliceAny), types.NewTerm(true, sliceInt)}),
	)); got != nil {
		t.Fatalf("divergent union core type = %v, want nil", got)
	}
	chanGot, ok := readmeCoreType(tpWith("C",
		types.NewUnion([]*types.Term{
			types.NewTerm(false, types.NewChan(types.SendRecv, anyType)),
			types.NewTerm(false, types.NewChan(types.SendOnly, anyType)),
		}),
	)).(*types.Chan)
	if !ok || chanGot.Dir() != types.SendOnly || !types.Identical(chanGot.Elem(), anyType) {
		t.Fatalf("channel union core type = %v, want chan<- any", chanGot)
	}
	if got := readmeCoreType(tpWith("C",
		types.NewUnion([]*types.Term{
			types.NewTerm(false, types.NewChan(types.SendOnly, anyType)),
			types.NewTerm(false, types.NewChan(types.RecvOnly, anyType)),
		}),
	)); got != nil {
		t.Fatalf("conflicting channel union core type = %v, want nil", got)
	}

	pkgs := readmeMetadataImporters(t)
	mutated := maps.Clone(pkgs)
	mutated[readmeModulePath] = maps.Clone(pkgs[readmeModulePath])
	mutated[readmeModulePath]["exporter.go"] += "\nfunc unresolvedLit[S ~[]any | ~[]int](v *metadata.Telemetry) S { return S{v} }\n"
	problems := readmeOutsideMetadataProblems(mutated)
	const wantSub = "whose destination type cannot be resolved"
	if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, wantSub) }) {
		t.Fatalf("expected fail-closed problem containing %q, got %v", wantSub, problems)
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

var (
	changelogVersionHeadingRE = regexp.MustCompile(`^## \[([^\]]*)\](.*)$`)
	changelogSemverRE         = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	changelogDatedSuffixRE    = regexp.MustCompile(`^ - ([0-9]{4}-[0-9]{2}-[0-9]{2})$`)
)

// changelogStabilityProblems reports misleading stability wording in
// CHANGELOG.md and README.md. A release section may be added once it is
// dated the Keep a Changelog way, as in "## [0.1.0] - 2026-11-20", which is
// the heading prepare-release.yml requires before it tags; the heading may
// carry nothing after the date, so no release heading can call itself GA,
// Stable or an Alpha Release, and neither file may claim a GA or stable
// release while the component is in development.
func changelogStabilityProblems(changelog, readme string) []string {
	changelog = readmeNormalizeEOL(changelog)
	readme = readmeNormalizeEOL(readme)
	var problems []string
	if !regexp.MustCompile(`(?m)^## \[Unreleased\]$`).MatchString(changelog) {
		problems = append(problems, "CHANGELOG.md missing Keep a Changelog ## [Unreleased] heading")
	}
	if !regexp.MustCompile(`(?m)^## \[0\.0\.1\] - 2026-11-03$`).MatchString(changelog) {
		problems = append(problems, "CHANGELOG.md must keep ## [0.0.1] - 2026-11-03 without Alpha Release suffix")
	}
	for i, line := range readmeLines(changelog) {
		m := changelogVersionHeadingRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version, suffix := m[1], m[2]
		date := changelogDatedSuffixRE.FindStringSubmatch(suffix)
		switch {
		case version == "Unreleased":
			if suffix != "" {
				problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q must read exactly \"## [Unreleased]\"", i+1, line))
			}
		case !changelogSemverRE.MatchString(version):
			problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q does not name a semantic version", i+1, line))
		case date == nil:
			problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q must read \"## [%s] - YYYY-MM-DD\" with nothing after the date; a release heading carries no stability label such as GA, Stable or Alpha Release", i+1, line, version))
		default:
			if _, err := time.Parse(time.DateOnly, date[1]); err != nil {
				problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q has an invalid date: %v", i+1, line, err))
			}
		}
	}
	files := []struct{ name, text string }{{"CHANGELOG.md", changelog}, {"README.md", readme}}
	for _, forbidden := range []string{
		"upstream GA",
		"Alpha Release",
		"alpha semantic release",
		"v0.0.1 alpha section",
	} {
		for _, f := range files {
			if strings.Contains(f.text, forbidden) {
				problems = append(problems, fmt.Sprintf("%s contains misleading pre-tag stability phrase %q", f.name, forbidden))
			}
		}
	}
	for _, claim := range []string{"GA release", "general availability", "generally available", "stable release"} {
		for _, f := range files {
			if strings.Contains(strings.ToLower(f.text), strings.ToLower(claim)) {
				problems = append(problems, fmt.Sprintf("%s claims %q, but the component is in development and no release is GA or stable", f.name, claim))
			}
		}
	}
	return problems
}

func readmeChangelogInputs(t *testing.T) (changelog, readme string) {
	t.Helper()
	changelogBytes, err := os.ReadFile("CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	readmeBytes, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	return readmeNormalizeEOL(string(changelogBytes)), readmeNormalizeEOL(string(readmeBytes))
}

func TestChangelogPreTagStabilityWording(t *testing.T) {
	changelog, readme := readmeChangelogInputs(t)
	for _, problem := range changelogStabilityProblems(changelog, readme) {
		t.Error(problem)
	}
	t.Run("CRLF line endings pass self-telemetry and changelog checks", func(t *testing.T) {
		_, meta, telemetry, grafana := readmeSelfTelemetryInputs(t)
		crlfReadme := strings.ReplaceAll(readme, "\n", "\r\n")
		crlfMeta := strings.ReplaceAll(meta, "\n", "\r\n")
		crlfChangelog := strings.ReplaceAll(changelog, "\n", "\r\n")
		crlfTelemetry := maps.Clone(telemetry)
		for k, v := range crlfTelemetry {
			crlfTelemetry[k] = strings.ReplaceAll(v, "\n", "\r\n")
		}
		for _, problem := range validateReadmeSelfTelemetry(crlfReadme, crlfMeta, crlfTelemetry, grafana) {
			t.Errorf("validateReadmeSelfTelemetry with CRLF: %s", problem)
		}
		for _, problem := range changelogStabilityProblems(crlfChangelog, crlfReadme) {
			t.Errorf("changelogStabilityProblems with CRLF: %s", problem)
		}
	})
}

// TestChangelogStabilityRejectsMutations cuts release sections the way the
// v0.1.0 release preparation will: a dated section passes, and a heading or
// entry that claims a stability level fails.
func TestChangelogStabilityRejectsMutations(t *testing.T) {
	changelog, readme := readmeChangelogInputs(t)
	const unreleased = "## [Unreleased]\n"
	for _, tc := range []struct {
		name, insert string
		// wantSubs is the problem the section must produce; empty marks a
		// valid section, which must produce none.
		wantSubs string
	}{
		{name: "valid: dated 0.1.0 section", insert: "\n## [0.1.0] - 2026-11-20\n\n- Pre-donation library release; component stability remains `development`, not GA.\n"},
		{name: "undated 0.1.0 heading", insert: "\n## [0.1.0]\n", wantSubs: `must read "## [0.1.0] - YYYY-MM-DD"`},
		{name: "GA label on the heading", insert: "\n## [0.1.0] - 2026-11-20 (GA)\n", wantSubs: "carries no stability label"},
		{name: "Stable label on the heading", insert: "\n## [0.1.0] - 2026-11-20 - Stable\n", wantSubs: "carries no stability label"},
		{name: "invalid date", insert: "\n## [0.1.0] - 2026-13-01\n", wantSubs: "has an invalid date"},
		{name: "not a semantic version", insert: "\n## [v0.1]\n", wantSubs: "does not name a semantic version"},
		{name: "general availability entry", insert: "\n## [0.1.0] - 2026-11-20\n\n- General availability of the exporter.\n", wantSubs: `claims "general availability"`},
		{name: "stable release entry", insert: "\n## [1.0.0] - 2026-11-20\n\n- First stable release.\n", wantSubs: `claims "stable release"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(changelog, unreleased, unreleased+tc.insert, 1)
			if mutated == changelog {
				t.Fatal("the section was not inserted")
			}
			problems := changelogStabilityProblems(mutated, readme)
			if tc.wantSubs == "" {
				for _, p := range problems {
					t.Errorf("valid section rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}

const (
	docsSchemaRationaleRelPath = "docs/schema-rationale.md"
	docsAgentFrameworksRelPath = "docs/agent-frameworks.md"
	deployReadMeRelPath        = "deploy/README.md"
)

func docsAndDeployAlignmentProblems(schemaRationale, agentFrameworks, deployREADME, exposureYAML, changelog string) []string {
	schemaRationale = readmeNormalizeEOL(schemaRationale)
	agentFrameworks = readmeNormalizeEOL(agentFrameworks)
	deployREADME = readmeNormalizeEOL(deployREADME)
	exposureYAML = readmeNormalizeEOL(exposureYAML)
	changelog = readmeNormalizeEOL(changelog)

	var problems []string
	forbiddenTrajectoryTokens := []string{
		"WITH RECURSIVE",
		"visited_span_ids",
		"hop0..hop32",
		"hop0",
		"rooted_chains",
		"emitted_ancestors",
		"recursive self-join",
		"recursive CTE",
	}
	requiredTrajectoryTokens := []string{
		"v_gen_ai_agent_trajectory",
		"topo_raw",
		"array graph",
		"resolved_topology",
	}

	for _, doc := range []struct {
		path string
		body string
	}{
		{path: docsSchemaRationaleRelPath, body: schemaRationale},
		{path: docsAgentFrameworksRelPath, body: agentFrameworks},
	} {
		normalizedBody := strings.Join(strings.Fields(doc.body), " ")
		for _, stale := range forbiddenTrajectoryTokens {
			if strings.Contains(normalizedBody, stale) {
				problems = append(problems, doc.path+" still contains stale trajectory term "+stale)
			}
		}
		for _, want := range requiredTrajectoryTokens {
			if !strings.Contains(normalizedBody, want) {
				problems = append(problems, doc.path+" is missing single-scan array graph token "+want)
			}
		}
	}

	requiredDeployTokens := []string{
		"goMemLimit",
		"startupProbe",
		"GOMEMLIMIT",
		"checksum/config",
		"seccompProfile",
		"looker_studio_template_report_id",
		"looker_studio_template_project_id",
		"looker_studio_template_dataset_id",
		"looker_studio_create_url",
		"deletion_protection = false",
		"otel_alerts",
	}
	for _, want := range requiredDeployTokens {
		if !strings.Contains(deployREADME, want) {
			problems = append(problems, deployReadMeRelPath+" is missing required parameter "+want)
		}
	}

	var exposureTemplate struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Body        []any  `yaml:"body"`
	}
	if err := yaml.Unmarshal([]byte(exposureYAML), &exposureTemplate); err != nil {
		problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml invalid YAML: "+err.Error())
	} else {
		if strings.TrimSpace(exposureTemplate.Name) == "" {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty name")
		}
		if strings.TrimSpace(exposureTemplate.Description) == "" {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty description")
		}
		if len(exposureTemplate.Body) == 0 {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty body")
		}
	}

	if !strings.Contains(changelog, "## [0.1.0] - 2026-11-09") {
		problems = append(problems, "CHANGELOG.md missing release heading ## [0.1.0] - 2026-11-09")
	}
	return problems
}

func TestDocsAndDeployReadmeStayAlignedWithCurrentArchitecture(t *testing.T) {
	readDoc := func(rel string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.FromSlash(rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return readmeNormalizeEOL(string(raw))
	}

	problems := docsAndDeployAlignmentProblems(
		readDoc(docsSchemaRationaleRelPath),
		readDoc(docsAgentFrameworksRelPath),
		readDoc(deployReadMeRelPath),
		readDoc(".github/ISSUE_TEMPLATE/alpha_exposure_report.yml"),
		readDoc("CHANGELOG.md"),
	)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestDocsAndDeployAlignmentRejectsMutations(t *testing.T) {
	readDoc := func(rel string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.FromSlash(rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return readmeNormalizeEOL(string(raw))
	}

	baseSchema := readDoc(docsSchemaRationaleRelPath)
	baseFrameworks := readDoc(docsAgentFrameworksRelPath)
	baseDeploy := readDoc(deployReadMeRelPath)
	baseExposure := readDoc(".github/ISSUE_TEMPLATE/alpha_exposure_report.yml")
	baseChangelog := readDoc("CHANGELOG.md")

	cases := []struct {
		name      string
		schema    string
		frame     string
		deploy    string
		exposure  string
		changelog string
		wantSubs  string
	}{
		{
			name:      "clean_baseline",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
		},
		{
			name:      "stale_with_recursive_in_schema_rationale",
			schema:    baseSchema + "\nWITH RECURSIVE trajectory\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "WITH RECURSIVE",
		},
		{
			name:      "stale_wrapped_with_recursive_in_schema_rationale",
			schema:    baseSchema + "\nWITH\nRECURSIVE trajectory\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "WITH RECURSIVE",
		},
		{
			name:      "stale_hop0_hop32_in_schema_rationale",
			schema:    baseSchema + "\nhop0..hop32\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "hop0..hop32",
		},
		{
			name:      "stale_visited_span_ids_in_agent_frameworks",
			schema:    baseSchema,
			frame:     baseFrameworks + "\nvisited_span_ids\n",
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "visited_span_ids",
		},
		{
			name:      "missing_topo_raw_in_agent_frameworks",
			schema:    baseSchema,
			frame:     strings.ReplaceAll(baseFrameworks, "topo_raw", "removed_cte"),
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "topo_raw",
		},
		{
			name:      "missing_goMemLimit_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "goMemLimit", "memoryLimit"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "goMemLimit",
		},
		{
			name:      "missing_startupProbe_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "startupProbe", "probe"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "startupProbe",
		},
		{
			name:      "missing_GOMEMLIMIT_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "GOMEMLIMIT", "MEM"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "GOMEMLIMIT",
		},
		{
			name:      "missing_looker_studio_template_dataset_id_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "looker_studio_template_dataset_id", "removed_var"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "looker_studio_template_dataset_id",
		},
		{
			name:      "missing_v010_heading_in_changelog",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: strings.ReplaceAll(baseChangelog, "## [0.1.0] - 2026-11-09", "## [Unreleased]"),
			wantSubs:  "CHANGELOG.md missing release heading ## [0.1.0] - 2026-11-09",
		},
		{
			name:      "empty_description_in_alpha_exposure_template",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  strings.Replace(baseExposure, `description: "Report pre-donation custom OCB/standalone usage or alpha-phase production exposure to track upstream beta-promotion evidence."`, `description: ""`, 1),
			changelog: baseChangelog,
			wantSubs:  "alpha_exposure_report.yml missing non-empty description",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := docsAndDeployAlignmentProblems(tc.schema, tc.frame, tc.deploy, tc.exposure, tc.changelog)
			if tc.wantSubs == "" {
				for _, p := range problems {
					t.Errorf("valid baseline rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}
