// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

// TestReadmeQuotesStartupErrors keeps the README's startup-error table tied to
// the messages the exporter actually returns. Credential and Compose messages
// come from other code and are proven by the collector-example CI job instead.
func TestReadmeQuotesStartupErrors(t *testing.T) {
	raw, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := testsupport.NormalizeEOL(string(raw))
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
	readme := testsupport.NormalizeEOL(string(raw))

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
		"object_refs",
		"otel_schema_major",
		"logs.synthesize_insert_id",
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
		"v1.0.0",
		"Operating v1.0.0 tables",
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
			t.Errorf("README.md is missing v1.0.0 contract token %q", required)
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

// readmeMdatagenPrefix is what mdatagen puts in front of a key of
// telemetry.metrics to name the metric, in the code it generates and in
// documentation.md. The keys of metadata.yaml therefore omit it, while the
// instruments that internal/metadata/telemetry.go builds by hand, the README
// table and the dashboards all carry it.
const readmeMdatagenPrefix = "otelcol_"

// readmeMetadataAttribute is one top-level attribute declaration of
// metadata.yaml. Unknown fields are rejected so misspelled or unmodeled keys
// (including name_override and semantic_convention) fail loudly instead of
// silently diverging from README.md, telemetry.go, or documentation.md.
type readmeMetadataAttribute struct {
	Description string   `yaml:"description"`
	Type        string   `yaml:"type"`
	Enum        []string `yaml:"enum"`
}

func (a readmeMetadataAttribute) docTypeLabel() (string, error) {
	switch a.Type {
	case "string":
		return "Str", nil
	case "int":
		return "Int", nil
	case "double":
		return "Double", nil
	case "bool":
		return "Bool", nil
	case "bytes":
		return "Bytes", nil
	case "slice":
		return "Slice", nil
	case "map":
		return "Map", nil
	default:
		return "", fmt.Errorf("unsupported metadata.yaml attribute type %q", a.Type)
	}
}

func (a readmeMetadataAttribute) docValues() (string, error) {
	typeLabel, err := a.docTypeLabel()
	if err != nil {
		return "", err
	}
	if len(a.Enum) > 0 {
		return fmt.Sprintf("%s: ``%s``", typeLabel, strings.Join(a.Enum, "``, ``")), nil
	}
	return "Any " + typeLabel, nil
}

// decodeReadmeMetadata decodes the telemetry and top-level attributes blocks of
// metadata.yaml with unknown fields rejected. Metrics are returned keyed by
// the name the exporter emits each of them under: the metadata.yaml key behind
// readmeMdatagenPrefix. A key that already carries the prefix is an error,
// because mdatagen would add it a second time. The unknown fields include
// the prefix with which mdatagen lets a metric override the default, and
// attribute overrides such as name_override or semantic_convention, so the
// default metric prefix and raw attribute keys are the only forms in play. The
// rest of the file is left to mdatagen.
func decodeReadmeMetadata(metadataYAML string) (map[string]readmeMetadataMetric, map[string]readmeMetadataAttribute, error) {
	metadataYAML = testsupport.NormalizeEOL(metadataYAML)
	var top struct {
		Telemetry  yaml.Node `yaml:"telemetry"`
		Attributes yaml.Node `yaml:"attributes"`
	}
	if err := yaml.Unmarshal([]byte(metadataYAML), &top); err != nil {
		return nil, nil, fmt.Errorf("metadata.yaml: %w", err)
	}
	var attrs map[string]readmeMetadataAttribute
	if top.Attributes.Kind != 0 {
		rawAttrs, err := yaml.Marshal(&top.Attributes)
		if err != nil {
			return nil, nil, fmt.Errorf("metadata.yaml attributes: %w", err)
		}
		dec := yaml.NewDecoder(bytes.NewReader(rawAttrs))
		dec.KnownFields(true)
		if err := dec.Decode(&attrs); err != nil {
			return nil, nil, fmt.Errorf("metadata.yaml attributes: %w", err)
		}
		for _, key := range slices.Sorted(maps.Keys(attrs)) {
			if _, err := attrs[key].docTypeLabel(); err != nil {
				return nil, nil, fmt.Errorf("metadata.yaml attribute %s: %w", key, err)
			}
		}
	}
	if top.Telemetry.Kind == 0 {
		return nil, attrs, nil
	}
	raw, err := yaml.Marshal(&top.Telemetry)
	if err != nil {
		return nil, nil, fmt.Errorf("metadata.yaml telemetry: %w", err)
	}
	var telemetry struct {
		Metrics map[string]readmeMetadataMetric `yaml:"metrics"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&telemetry); err != nil {
		return nil, nil, fmt.Errorf("metadata.yaml telemetry: %w", err)
	}
	emitted := make(map[string]readmeMetadataMetric, len(telemetry.Metrics))
	for _, key := range slices.Sorted(maps.Keys(telemetry.Metrics)) {
		if strings.HasPrefix(key, readmeMdatagenPrefix) {
			return nil, nil, fmt.Errorf("metadata.yaml telemetry metric %s must omit the %s prefix: mdatagen adds it, and would name the metric %s", key, readmeMdatagenPrefix, readmeMdatagenPrefix+key)
		}
		emitted[readmeMdatagenPrefix+key] = telemetry.Metrics[key]
	}
	return emitted, attrs, nil
}

var (
	readmeMetricNameRE     = regexp.MustCompile(testsupport.PromMetricPrefix + `[a-z0-9_]+`)
	readmeMetricNameOnlyRE = regexp.MustCompile(`^` + testsupport.PromMetricPrefix + `[a-z0-9_]+$`)
)

// readmeRowLike reports whether a paragraph line reads as a table row cut off
// from its table: it starts with a pipe and has a second one, or the text
// before its first pipe is only a self-telemetry metric name.
func readmeRowLike(line string) bool {
	s := strings.TrimSpace(line)
	if strings.HasPrefix(s, "|") {
		return strings.Contains(s[1:], "|")
	}
	i := testsupport.FirstMarkdownPipe(s)
	if i < 0 {
		return false
	}
	first := strings.TrimSpace(s[:i])
	if inner, ok := testsupport.UnwrapInlineCode(first); ok {
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
func readmeStrayTelemetryRows(section testsupport.ReadmeSelfTelemetrySection) []string {
	var problems []string
	wantHeader := testsupport.ReadmeSelfTelemetryHeader()
	for i, b := range section.Blocks {
		inSection := i >= section.Intro && i < section.End && i != section.Table
		switch {
		case b.Kind == testsupport.MarkdownTable && i != section.Table:
			for r, cells := range b.Cells {
				if r == 0 && slices.Equal(cells, wantHeader) {
					problems = append(problems, fmt.Sprintf("README.md line %d starts another self-telemetry table outside the self-telemetry table", b.LineNos[r]+1))
					continue
				}
				for _, cell := range cells {
					for _, name := range readmeMetricNameRE.FindAllString(cell, -1) {
						problems = append(problems, fmt.Sprintf("README.md line %d is a table row naming %s outside the self-telemetry table", b.LineNos[r]+1, name))
					}
				}
			}
		case b.Kind == testsupport.MarkdownParagraph:
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
			i = testsupport.SkipMarkdownCodeSpan(text, i)
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
	short := func(name string) string { return strings.TrimPrefix(name, testsupport.PromMetricPrefix) }

	// Unchecked sentences may not name a current-value instrument next to
	// a negation, a recovery condition or a value, including any recovery
	// target in code.
	var mentionRE *regexp.Regexp
	if len(currentValue) > 0 {
		alts := make([]string, len(currentValue))
		for i, name := range currentValue {
			alts[i] = regexp.QuoteMeta(short(name))
		}
		mentionRE = regexp.MustCompile(`\b(?:` + regexp.QuoteMeta(testsupport.PromMetricPrefix) + `)?(?:` + strings.Join(alts, "|") + `)\b`)
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
			name := testsupport.PromMetricPrefix + m[1]
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
		name := testsupport.PromMetricPrefix + shortName
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
					if spec, ok := metrics[testsupport.PromMetricPrefix+m[1]]; !ok || !spec.isUpDownCounter() {
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
			if v := constant.StringVal(c.Val()); strings.HasPrefix(v, testsupport.PromMetricPrefix) {
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
				problems = append(problems, fmt.Sprintf("%s records %s with attributes %s, metadata.yaml declares %s", rec.Where, name, testsupport.FormatAttrSet(rec.Attrs), testsupport.FormatAttrSet(wantAttrs)))
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
		pkgs[importPath][name] = testsupport.NormalizeEOL(string(raw))
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

func validateReadmeSelfTelemetry(readme, metadataYAML string, telemetry map[string]string) []string {
	readme = testsupport.NormalizeEOL(readme)
	metadataYAML = testsupport.NormalizeEOL(metadataYAML)
	var problems []string

	metrics, _, err := decodeReadmeMetadata(metadataYAML)
	if err != nil {
		return []string{err.Error()}
	}
	if len(metrics) == 0 {
		return []string{"metadata.yaml declares no metrics"}
	}

	section, err := testsupport.ParseReadmeSelfTelemetrySection(readme)
	if err != nil {
		return []string{err.Error()}
	}
	problems = append(problems, readmeStrayTelemetryRows(section)...)
	for i, b := range section.Blocks {
		if i == section.Table || b.Kind == testsupport.MarkdownFencedCode || b.Kind == testsupport.MarkdownIndentedCode {
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

	readmeRows := make(map[string]testsupport.ReadmeTelemetryRow, len(section.Rows))
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
			problems = append(problems, fmt.Sprintf("README.md metric %s attributes = %s, metadata.yaml declares %s", name, testsupport.FormatAttrSet(row.Attrs), testsupport.FormatAttrSet(wantAttrs)))
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
	problems = append(problems, validateReadmeRecoveryProse(section.Prose(), metrics, meanings)...)

	if len(telemetry) > 0 {
		problems = append(problems, validateTelemetryGoInstruments(telemetry, metrics, metaNames)...)
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
		files[name] = testsupport.NormalizeEOL(string(raw))
	}
	if _, ok := files["telemetry.go"]; !ok {
		t.Fatal("internal/metadata/telemetry.go not found")
	}
	return files
}

// readmeSelfTelemetryInputs reads every input of validateReadmeSelfTelemetry.
func readmeSelfTelemetryInputs(t *testing.T) (readme, meta string, telemetry map[string]string) {
	t.Helper()
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return testsupport.NormalizeEOL(string(raw))
	}
	return read("README.md"), read("metadata.yaml"), readmeTelemetryFiles(t)
}

func TestReadmeSelfTelemetryMatchesMetadataAndTelemetry(t *testing.T) {
	readme, meta, telemetry := readmeSelfTelemetryInputs(t)
	for _, problem := range validateReadmeSelfTelemetry(readme, meta, telemetry) {
		t.Error(problem)
	}
	t.Run("CRLF line endings pass self-telemetry checks", func(t *testing.T) {
		crlfReadme := strings.ReplaceAll(readme, "\n", "\r\n")
		crlfMeta := strings.ReplaceAll(meta, "\n", "\r\n")
		crlfTelemetry := maps.Clone(telemetry)
		for k, v := range crlfTelemetry {
			crlfTelemetry[k] = strings.ReplaceAll(v, "\n", "\r\n")
		}
		for _, problem := range validateReadmeSelfTelemetry(crlfReadme, crlfMeta, crlfTelemetry) {
			t.Errorf("validateReadmeSelfTelemetry with CRLF: %s", problem)
		}
	})
}

// validateDocumentationMD checks that the ### headings under ## Internal
// Telemetry in documentation.md match otelcol_ + every key of
// telemetry.metrics in metadata.yaml in sorted order, and that each metric's
// description, summary table (unit, metric type, value type, monotonicity,
// stability), and #### Attributes subsection (header, attribute names,
// descriptions, Values, and Semantic Convention columns) match metadata.yaml.
func validateDocumentationMD(docMD, metadataYAML string) []string {
	docMD = testsupport.NormalizeEOL(docMD)
	metadataYAML = testsupport.NormalizeEOL(metadataYAML)

	metrics, attrs, err := decodeReadmeMetadata(metadataYAML)
	if err != nil {
		return []string{err.Error()}
	}
	if len(metrics) == 0 {
		return []string{"metadata.yaml declares no metrics"}
	}
	wantHeadings := slices.Sorted(maps.Keys(metrics))

	blocks := testsupport.ParseMarkdown(docMD)
	sectionIdx := -1
	var problems []string
	for i, b := range blocks {
		if b.Kind == testsupport.MarkdownHeading && b.Depth == 0 && b.Level == 2 && b.Text() == "Internal Telemetry" {
			if sectionIdx >= 0 {
				problems = append(problems, "documentation.md has multiple ## Internal Telemetry headings")
			} else {
				sectionIdx = i
			}
		}
	}
	if sectionIdx < 0 {
		return append(problems, "documentation.md is missing ## Internal Telemetry heading")
	}

	type docMetricSection struct {
		name   string
		blocks []testsupport.MarkdownBlock
	}
	var sections []docMetricSection
	var gotHeadings []string
	seen := map[string]bool{}
	for i := sectionIdx + 1; i < len(blocks); i++ {
		b := blocks[i]
		if b.Kind == testsupport.MarkdownHeading && b.Depth == 0 && b.Level <= 2 {
			break
		}
		if b.Kind == testsupport.MarkdownHeading && b.Depth == 0 && b.Level == 3 {
			h := b.Text()
			gotHeadings = append(gotHeadings, h)
			if seen[h] {
				problems = append(problems, fmt.Sprintf("documentation.md lists duplicate ### metric heading %q", h))
			}
			seen[h] = true
			if _, ok := metrics[h]; !ok {
				problems = append(problems, fmt.Sprintf("documentation.md ### heading %q is not declared in metadata.yaml telemetry.metrics", h))
			}
			sections = append(sections, docMetricSection{name: h})
			continue
		}
		if len(sections) > 0 {
			sections[len(sections)-1].blocks = append(sections[len(sections)-1].blocks, b)
		}
	}

	for _, want := range wantHeadings {
		if !seen[want] {
			problems = append(problems, fmt.Sprintf("documentation.md is missing ### heading %q declared in metadata.yaml", want))
		}
	}
	if len(problems) == 0 && !slices.Equal(gotHeadings, wantHeadings) {
		problems = append(problems, fmt.Sprintf("documentation.md ### headings = %v, want %v in sorted order", gotHeadings, wantHeadings))
	}

	validated := map[string]bool{}
	for _, sec := range sections {
		if validated[sec.name] {
			continue
		}
		spec, ok := metrics[sec.name]
		if !ok {
			continue
		}
		validated[sec.name] = true
		problems = append(problems, validateDocumentationMetricSection(sec.name, spec, attrs, sec.blocks)...)
	}
	return problems
}

func docTitleWord(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// validateDocumentationMetricSection checks a single metric subsection in
// documentation.md against metadata.yaml: the description paragraph, the
// metadata summary table (unit, metric type, value type, monotonicity,
// stability), and, when the metric declares attributes, the #### Attributes
// table header (Name, Description, Values, Semantic Convention), attribute
// names, attribute descriptions, attribute Values (type and enum) cells, and
// Semantic Convention cells (expected to be "-").
func validateDocumentationMetricSection(name string, spec readmeMetadataMetric, attrs map[string]readmeMetadataAttribute, blocks []testsupport.MarkdownBlock) []string {
	var problems []string

	wantDesc := strings.Join(strings.Fields(spec.Description), " ")
	var descPara *testsupport.MarkdownBlock
	var summaryTable *testsupport.MarkdownBlock
	attrHeadingIdx := -1
	for i := range blocks {
		b := &blocks[i]
		if b.Depth != 0 {
			continue
		}
		if b.Kind == testsupport.MarkdownHeading && b.Level == 4 && b.Text() == "Attributes" {
			if attrHeadingIdx >= 0 {
				problems = append(problems, fmt.Sprintf("documentation.md metric %s has multiple #### Attributes headings", name))
			} else {
				attrHeadingIdx = i
			}
			continue
		}
		if attrHeadingIdx >= 0 {
			continue
		}
		if descPara == nil && summaryTable == nil && b.Kind == testsupport.MarkdownParagraph {
			descPara = b
			continue
		}
		if summaryTable == nil && b.Kind == testsupport.MarkdownTable {
			summaryTable = b
		}
	}

	if wantDesc != "" {
		if descPara == nil {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s is missing description paragraph", name))
		} else if gotDesc := descPara.Text(); gotDesc != wantDesc {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s description = %q, metadata.yaml declares %q", name, gotDesc, wantDesc))
		}
	}

	var wantHeader []string
	var wantMetricType, wantValueType, wantMonotonic string
	switch {
	case spec.Sum != nil:
		wantHeader = []string{"Unit", "Metric Type", "Value Type", "Monotonic", "Stability"}
		wantMetricType = "Sum"
		wantValueType = docTitleWord(spec.Sum.ValueType)
		if spec.Sum.Monotonic != nil {
			wantMonotonic = strconv.FormatBool(*spec.Sum.Monotonic)
		}
	case spec.Gauge != nil:
		wantHeader = []string{"Unit", "Metric Type", "Value Type", "Stability"}
		wantMetricType = "Gauge"
		wantValueType = docTitleWord(spec.Gauge.ValueType)
	case spec.Histogram != nil:
		wantHeader = []string{"Unit", "Metric Type", "Value Type", "Stability"}
		wantMetricType = "Histogram"
		wantValueType = docTitleWord(spec.Histogram.ValueType)
	}

	switch {
	case summaryTable == nil:
		problems = append(problems, fmt.Sprintf("documentation.md metric %s is missing metadata summary table", name))
	case len(summaryTable.Cells) != 2:
		problems = append(problems, fmt.Sprintf("documentation.md metric %s summary table has %d rows, want 2 (header and 1 data row)", name, len(summaryTable.Cells)))
	case wantHeader != nil && !slices.Equal(summaryTable.Cells[0], wantHeader):
		problems = append(problems, fmt.Sprintf("documentation.md metric %s summary table header = %v, want %v", name, summaryTable.Cells[0], wantHeader))
	case len(summaryTable.Cells[1]) != len(summaryTable.Cells[0]):
		problems = append(problems, fmt.Sprintf("documentation.md metric %s summary table row has %d cells, want %d", name, len(summaryTable.Cells[1]), len(summaryTable.Cells[0])))
	case wantHeader != nil:
		row := map[string]string{}
		for i, col := range summaryTable.Cells[0] {
			row[col] = summaryTable.Cells[1][i]
		}
		if row["Unit"] != spec.Unit {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s unit = %q, metadata.yaml declares %q", name, row["Unit"], spec.Unit))
		}
		if row["Metric Type"] != wantMetricType {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s metric type = %q, metadata.yaml declares %q", name, row["Metric Type"], wantMetricType))
		}
		if row["Value Type"] != wantValueType {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s value type = %q, metadata.yaml declares %q", name, row["Value Type"], wantValueType))
		}
		if spec.Sum != nil && spec.Sum.Monotonic != nil && row["Monotonic"] != wantMonotonic {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s monotonic = %q, metadata.yaml declares %q", name, row["Monotonic"], wantMonotonic))
		}
		if spec.Stability != "" {
			wantStability := docTitleWord(spec.Stability)
			if row["Stability"] != wantStability {
				problems = append(problems, fmt.Sprintf("documentation.md metric %s stability = %q, metadata.yaml declares %q", name, row["Stability"], wantStability))
			}
		}
	}

	var wantAttrs []string
	wantAttrSpecs := make(map[string]readmeMetadataAttribute, len(spec.Attributes))
	for _, key := range spec.Attributes {
		attrSpec, ok := attrs[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("metadata.yaml metric %s references undeclared attribute %q", name, key))
			wantAttrs = append(wantAttrs, key)
			continue
		}
		wantAttrs = append(wantAttrs, key)
		wantAttrSpecs[key] = attrSpec
	}
	slices.Sort(wantAttrs)
	switch {
	case len(wantAttrs) == 0 && attrHeadingIdx >= 0:
		problems = append(problems, fmt.Sprintf("documentation.md metric %s has #### Attributes subsection, but metadata.yaml declares none", name))
	case len(wantAttrs) > 0 && attrHeadingIdx < 0:
		problems = append(problems, fmt.Sprintf("documentation.md metric %s is missing #### Attributes subsection (metadata.yaml declares %s)", name, testsupport.FormatAttrSet(wantAttrs)))
	case len(wantAttrs) > 0 && attrHeadingIdx >= 0:
		var attrTable *testsupport.MarkdownBlock
		for i := attrHeadingIdx + 1; i < len(blocks); i++ {
			b := &blocks[i]
			if b.Depth != 0 {
				continue
			}
			if b.Kind == testsupport.MarkdownHeading {
				break
			}
			if b.Kind == testsupport.MarkdownTable {
				attrTable = b
				break
			}
		}
		wantAttrHeader := []string{"Name", "Description", "Values", "Semantic Convention"}
		if attrTable == nil || len(attrTable.Cells) < 2 || len(attrTable.Cells[0]) == 0 || attrTable.Cells[0][0] != "Name" {
			problems = append(problems, fmt.Sprintf("documentation.md metric %s #### Attributes subsection is missing attribute table", name))
		} else {
			if !slices.Equal(attrTable.Cells[0], wantAttrHeader) {
				problems = append(problems, fmt.Sprintf("documentation.md metric %s #### Attributes table header = %v, want %v", name, attrTable.Cells[0], wantAttrHeader))
			}
			var gotAttrs []string
			seenAttr := map[string]bool{}
			for _, r := range attrTable.Cells[1:] {
				if len(r) == 0 || strings.TrimSpace(r[0]) == "" {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s has empty attribute name in #### Attributes table", name))
					continue
				}
				attrName := strings.TrimSpace(r[0])
				if seenAttr[attrName] {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s lists duplicate attribute %q in #### Attributes table", name, attrName))
					continue
				}
				seenAttr[attrName] = true
				gotAttrs = append(gotAttrs, attrName)
				if len(r) != len(wantAttrHeader) {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s #### Attributes row for %q has %d cells, want %d", name, attrName, len(r), len(wantAttrHeader)))
					continue
				}
				attrSpec, ok := wantAttrSpecs[attrName]
				if !ok {
					continue
				}
				wantAttrDesc := strings.Join(strings.Fields(attrSpec.Description), " ")
				if gotAttrDesc := strings.Join(strings.Fields(r[1]), " "); gotAttrDesc != wantAttrDesc {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s attribute %s description = %q, metadata.yaml declares %q", name, attrName, gotAttrDesc, wantAttrDesc))
				}
				wantValues, err := attrSpec.docValues()
				if err != nil {
					problems = append(problems, fmt.Sprintf("metadata.yaml metric %s attribute %s: %v", name, attrName, err))
				} else if r[2] != wantValues {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s attribute %s values = %q, metadata.yaml declares %q", name, attrName, r[2], wantValues))
				}
				if r[3] != "-" {
					problems = append(problems, fmt.Sprintf("documentation.md metric %s attribute %s semantic convention = %q, want %q", name, attrName, r[3], "-"))
				}
			}
			slices.Sort(gotAttrs)
			if !slices.Equal(gotAttrs, wantAttrs) {
				problems = append(problems, fmt.Sprintf("documentation.md metric %s attributes = %s, metadata.yaml declares %s", name, testsupport.FormatAttrSet(gotAttrs), testsupport.FormatAttrSet(wantAttrs)))
			}
		}
	}

	return problems
}

func TestDocumentationMDMatchesMetadataYAML(t *testing.T) {
	docRaw, err := os.ReadFile("documentation.md")
	if err != nil {
		t.Fatal(err)
	}
	metaRaw, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	docMD := testsupport.NormalizeEOL(string(docRaw))
	metaYAML := testsupport.NormalizeEOL(string(metaRaw))

	for _, problem := range validateDocumentationMD(docMD, metaYAML) {
		t.Error(problem)
	}

	for _, tc := range []struct {
		name     string
		mutate   func(string) string
		wantSubs string
	}{
		{
			name: "missing Internal Telemetry heading fails",
			mutate: func(s string) string {
				return strings.Replace(s, "## Internal Telemetry\n", "## Telemetry\n", 1)
			},
			wantSubs: "missing ## Internal Telemetry heading",
		},
		{
			name: "missing metric heading fails",
			mutate: func(s string) string {
				return strings.Replace(s, "### otelcol_exporter_bigquery_acknowledged_rows\n", "", 1)
			},
			wantSubs: `missing ### heading "otelcol_exporter_bigquery_acknowledged_rows"`,
		},
		{
			name: "hand-edited unprefixed metric heading fails",
			mutate: func(s string) string {
				return strings.Replace(s, "### otelcol_exporter_bigquery_acknowledged_rows\n", "### exporter_bigquery_acknowledged_rows\n", 1)
			},
			wantSubs: `### heading "exporter_bigquery_acknowledged_rows" is not declared in metadata.yaml`,
		},
		{
			name: "double-prefixed metric heading fails",
			mutate: func(s string) string {
				return strings.Replace(s, "### otelcol_exporter_bigquery_acknowledged_rows\n", "### otelcol_otelcol_exporter_bigquery_acknowledged_rows\n", 1)
			},
			wantSubs: `### heading "otelcol_otelcol_exporter_bigquery_acknowledged_rows" is not declared in metadata.yaml`,
		},
		{
			name: "duplicate metric heading fails",
			mutate: func(s string) string {
				return s + "\n### otelcol_exporter_bigquery_unresolved_results\n"
			},
			wantSubs: `duplicate ### metric heading "otelcol_exporter_bigquery_unresolved_results"`,
		},
		{
			name: "out-of-order metric headings fail",
			mutate: func(s string) string {
				s = strings.Replace(s, "### otelcol_exporter_bigquery_acknowledged_rows\n", "### SWAP_TMP\n", 1)
				s = strings.Replace(s, "### otelcol_exporter_bigquery_append_bytes\n", "### otelcol_exporter_bigquery_acknowledged_rows\n", 1)
				return strings.Replace(s, "### SWAP_TMP\n", "### otelcol_exporter_bigquery_append_bytes\n", 1)
			},
			wantSubs: "in sorted order",
		},
		{
			name: "stale description fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"Rows acknowledged by the BigQuery Storage Write API. Incremented only after acknowledgement, never at enqueue time, so it can be compared against what the producer sent.",
					"Rows sent to BigQuery.",
					1,
				)
			},
			wantSubs: `otelcol_exporter_bigquery_acknowledged_rows description = "Rows sent to BigQuery."`,
		},
		{
			name: "stale unit fails",
			mutate: func(s string) string {
				return strings.Replace(s, "| {row} | Sum | Int | true | Development |", "| {item} | Sum | Int | true | Development |", 1)
			},
			wantSubs: `otelcol_exporter_bigquery_acknowledged_rows unit = "{item}", metadata.yaml declares "{row}"`,
		},
		{
			name: "stale metric type fails",
			mutate: func(s string) string {
				return strings.Replace(s, "| s | Histogram | Double | Development |", "| s | Gauge | Double | Development |", 1)
			},
			wantSubs: `otelcol_exporter_bigquery_append_result_wait metric type = "Gauge", metadata.yaml declares "Histogram"`,
		},
		{
			name: "stale monotonicity fails",
			mutate: func(s string) string {
				return strings.Replace(s, "| {request} | Sum | Int | false | Development |", "| {request} | Sum | Int | true | Development |", 1)
			},
			wantSubs: `otelcol_exporter_bigquery_inflight_requests monotonic = "true", metadata.yaml declares "false"`,
		},
		{
			name: "missing Attributes subsection fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| {hit} | Sum | Int | true | Development |\n\n#### Attributes\n\n| Name | Description | Values | Semantic Convention |\n| ---- | ----------- | ------ | ------------------- |\n| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``metrics``, ``spans`` | - |\n",
					"| {hit} | Sum | Int | true | Development |\n",
					1,
				)
			},
			wantSubs: `otelcol_exporter_bigquery_offload_dedup_hits is missing #### Attributes subsection`,
		},
		{
			name: "unexpected Attributes subsection fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| {row} | Sum | Int | true | Development |\n",
					"| {row} | Sum | Int | true | Development |\n\n#### Attributes\n\n| Name | Description | Values | Semantic Convention |\n| ---- | ----------- | ------ | ------------------- |\n| extra | Extra attribute. | Any Str | - |\n",
					1,
				)
			},
			wantSubs: `otelcol_exporter_bigquery_acknowledged_rows has #### Attributes subsection, but metadata.yaml declares none`,
		},
		{
			name: "drifted attribute name fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| {hit} | Sum | Int | true | Development |\n\n#### Attributes\n\n| Name | Description | Values | Semantic Convention |\n| ---- | ----------- | ------ | ------------------- |\n| signal |",
					"| {hit} | Sum | Int | true | Development |\n\n#### Attributes\n\n| Name | Description | Values | Semantic Convention |\n| ---- | ----------- | ------ | ------------------- |\n| kind |",
					1,
				)
			},
			wantSubs: `otelcol_exporter_bigquery_offload_dedup_hits attributes = {kind}, metadata.yaml declares {signal}`,
		},
		{
			name: "stale attribute description fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``metrics``, ``spans`` | - |",
					"| signal | Stale signal description. | Str: ``logs``, ``metrics``, ``spans`` | - |",
					1,
				)
			},
			wantSubs: `attribute signal description = "Stale signal description."`,
		},
		{
			name: "stale attribute enum values fail",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``metrics``, ``spans`` | - |",
					"| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``spans`` | - |",
					1,
				)
			},
			wantSubs: `attribute signal values = "Str: ` + "``logs``, ``spans``" + `"`,
		},
		{
			name: "stale non-enum attribute values fail",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| table | The configured destination BigQuery table ID for the signal writer. Bounded by configuration (one table per signal exporter). | Any Str | - |",
					"| table | The configured destination BigQuery table ID for the signal writer. Bounded by configuration (one table per signal exporter). | Any Int | - |",
					1,
				)
			},
			wantSubs: `attribute table values = "Any Int", metadata.yaml declares "Any Str"`,
		},
		{
			name: "stale Attributes table header fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| Name | Description | Values | Semantic Convention |",
					"| Name | Description | Allowed | Semantic Convention |",
					1,
				)
			},
			wantSubs: `#### Attributes table header = [Name Description Allowed Semantic Convention]`,
		},
		{
			name: "stale attribute semantic convention fails",
			mutate: func(s string) string {
				return strings.Replace(
					s,
					"| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``metrics``, ``spans`` | - |",
					"| signal | The pipeline signal the exporter instance serves. Bounded by construction; this enumeration is the whole domain. | Str: ``logs``, ``metrics``, ``spans`` | signal |",
					1,
				)
			},
			wantSubs: `attribute signal semantic convention = "signal", want "-"`,
		},
		{
			name: "valid: ### heading under a later ## section is ignored",
			mutate: func(s string) string {
				return s + "\n## Other Section\n\n### Not A Metric\n"
			},
		},
		{
			name: "valid: ### inside a fenced code block is ignored",
			mutate: func(s string) string {
				return s + "\n```markdown\n### otelcol_exporter_bigquery_bogus\n```\n"
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(docMD)
			if mutated == docMD {
				t.Fatalf("mutation %q did not change documentation.md", tc.name)
			}
			problems := validateDocumentationMD(mutated, metaYAML)
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

func TestReadmeSelfTelemetryRejectsMutations(t *testing.T) {
	readme, meta, telemetry := readmeSelfTelemetryInputs(t)

	cases := []struct {
		name            string
		mutate          func(string) string
		mutateMeta      func(string) string
		mutateTelemetry func(string) string
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

		// metadata.yaml: decoded strictly, and every metric must be enabled
		// because telemetry.go constructs all of them unconditionally.
		{
			name: "disabled metadata metric fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    exporter_bigquery_acknowledged_rows:\n      enabled: false\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows is not enabled: true",
		},
		{
			name: "metadata metric without enabled fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    exporter_bigquery_acknowledged_rows:\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows is not enabled: true",
		},
		{
			name: "misspelled metadata field fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    exporter_bigquery_acknowledged_rows:\n      enable: false\n      enabled: true\n", 1)
			},
			wantSubs: "field enable not found",
		},
		{
			name: "metadata metric with two instrument kinds fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n      gauge:\n        value_type: int\n", 1)
			},
			wantSubs: "metadata.yaml metric otelcol_exporter_bigquery_acknowledged_rows must declare exactly one of sum, gauge or histogram",
		},

		// metadata.yaml: a key is the emitted name without the otelcol_
		// prefix, which mdatagen adds exactly once and no metric overrides.
		{
			name: "metadata key that keeps the otelcol_ prefix fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n", "    otelcol_exporter_bigquery_acknowledged_rows:\n", 1)
			},
			wantSubs: "metadata.yaml telemetry metric otelcol_exporter_bigquery_acknowledged_rows must omit the otelcol_ prefix: mdatagen adds it, and would name the metric otelcol_otelcol_exporter_bigquery_acknowledged_rows",
		},
		{
			name: "metadata metric that overrides the mdatagen prefix fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n", "    exporter_bigquery_acknowledged_rows:\n      enabled: true\n      prefix: bq_\n", 1)
			},
			wantSubs: "field prefix not found",
		},
		{
			name: "metadata attribute that sets name_override fails",
			mutateMeta: func(s string) string {
				return strings.Replace(s, "  signal:\n    description:", "  signal:\n    name_override: otel.signal\n    description:", 1)
			},
			wantSubs: "field name_override not found",
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
			problems := validateReadmeSelfTelemetry(mutatedReadme, mutatedMeta, mutatedTelemetry)
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
	readme, meta, telemetry := readmeSelfTelemetryInputs(t)
	const (
		introLine  = testsupport.ReadmeSelfTelemetryIntroFull + "\n"
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
			problems := validateReadmeSelfTelemetry(mutatedReadme, meta, mutatedTelemetry)
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
					problems = append(problems, fmt.Sprintf("Telemetry emits %s with attributes %s, metadata.yaml declares %s", m.Name, testsupport.FormatAttrSet(keys), testsupport.FormatAttrSet(wantAttrs)))
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
	metrics, _, err := decodeReadmeMetadata(string(raw))
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
// declared metric and an undeclared metric. A declared metric emitted under
// its metadata.yaml key, without the otelcol_ prefix, counts as undeclared.
func TestReadmeSelfTelemetryEmissionRejectsDrift(t *testing.T) {
	raw, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatal(err)
	}
	metrics, _, err := decodeReadmeMetadata(string(raw))
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
	unprefixed, err := m.Int64Counter("exporter_bigquery_retries", metric.WithUnit("{failure}"))
	if err != nil {
		t.Fatal(err)
	}
	unprefixed.Add(ctx, 1, metric.WithAttributes(attribute.String("class", "unavailable")))
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	problems := readmeEmissionProblems(rm, metrics)
	for _, want := range []string{
		"Telemetry emits otelcol_exporter_bigquery_retries with attributes {reason}, metadata.yaml declares {class}",
		"Telemetry emits otelcol_exporter_bigquery_undeclared, which metadata.yaml does not declare",
		"Telemetry emits exporter_bigquery_retries, which metadata.yaml does not declare",
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
			for _, b := range testsupport.ParseMarkdown(tc.doc) {
				s := fmt.Sprintf("%s@%d", b.Kind.String(), b.Depth)
				if b.Kind == testsupport.MarkdownTable {
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
