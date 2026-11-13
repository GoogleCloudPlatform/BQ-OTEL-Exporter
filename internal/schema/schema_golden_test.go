// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
)

const goldenSchemaPath = "testdata/v0alpha2_golden.json"

// SchemaSnapshot captures the complete versioned BigQuery schema contract for
// golden comparison, backward-compatibility verification, and live
// INFORMATION_SCHEMA parity checks.
type SchemaSnapshot struct {
	Version              string            `json:"version"`
	Tables               []TableSnapshot   `json:"tables"`
	CompanionViews       []string          `json:"companion_views"`
	CompanionTVFs        []string          `json:"companion_tvfs"`
	DedupViewDigests     map[string]string `json:"dedup_view_digests"`
	CompanionViewDigests map[string]string `json:"companion_view_digests"`
	CompanionTVFDigests  map[string]string `json:"companion_tvf_digests"`
}

// TableSnapshot captures one physical destination table and its coupled
// access-path artifacts.
type TableSnapshot struct {
	Name             string                   `json:"name"`
	Fields           []FieldSnapshot          `json:"fields"`
	TimePartitioning TimePartitioningSnapshot `json:"time_partitioning"`
	Clustering       []string                 `json:"clustering"`
	DedupView        string                   `json:"dedup_view,omitempty"`
	SearchIndex      *SearchIndexSnapshot     `json:"search_index,omitempty"`
}

// FieldSnapshot captures one column or nested STRUCT field in canonical
// GoogleSQL type notation.
type FieldSnapshot struct {
	Name                   string          `json:"name"`
	Type                   string          `json:"type"`
	Mode                   string          `json:"mode"`
	MaxLength              int64           `json:"max_length"`
	Precision              int64           `json:"precision,omitempty"`
	Scale                  int64           `json:"scale,omitempty"`
	DefaultValueExpression string          `json:"default_value_expression,omitempty"`
	TimestampPrecision     int64           `json:"timestamp_precision,omitempty"`
	RangeElementType       string          `json:"range_element_type,omitempty"`
	Fields                 []FieldSnapshot `json:"fields,omitempty"`
}

// TimePartitioningSnapshot captures a table's partitioning column, granularity,
// partition-filter enforcement default, and partition TTL.
type TimePartitioningSnapshot struct {
	Type                   string `json:"type"`
	Field                  string `json:"field"`
	RequirePartitionFilter bool   `json:"require_partition_filter"`
	ExpirationDays         int    `json:"expiration_days,omitempty"`
}

// SearchIndexSnapshot captures a table's trace/attribute lookup search index.
type SearchIndexSnapshot struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns,omitempty"`
	AllColumns bool     `json:"all_columns,omitempty"`
	Analyzer   string   `json:"analyzer"`
}

var (
	ddlViewHeaderRE = regexp.MustCompile("(?s)^CREATE OR REPLACE VIEW `[^`]+\\.[^`]+\\.([^`]+)` AS\\s*(.+);\\s*$")
	ddlSearchRE     = regexp.MustCompile(
		"(?s)CREATE SEARCH INDEX IF NOT EXISTS `([^`]+)`\\s+ON `[^`]+` \\(([^)]+)\\)\\s+OPTIONS \\(analyzer = '([^']+)'\\);",
	)
	ddlPartitionHourRE       = regexp.MustCompile(`PARTITION BY TIMESTAMP_TRUNC\(([a-zA-Z0-9_]+),\s*HOUR\)`)
	ddlPartitionDayRE        = regexp.MustCompile(`PARTITION BY DATE\(([a-zA-Z0-9_]+)\)`)
	ddlClusterByRE           = regexp.MustCompile(`(?m)^CLUSTER BY ([a-zA-Z0-9_, ]+?);?$`)
	ddlPartitionExpirationRE = regexp.MustCompile(`partition_expiration_days\s*=\s*([0-9]+)`)
	ddlRequirePartFilterRE   = regexp.MustCompile(`require_partition_filter\s*=\s*(true|false)`)
)

var storageTypeToGoogleSQL = map[storagepb.TableFieldSchema_Type]string{
	storagepb.TableFieldSchema_STRING:     "STRING",
	storagepb.TableFieldSchema_INT64:      "INT64",
	storagepb.TableFieldSchema_DOUBLE:     "FLOAT64",
	storagepb.TableFieldSchema_STRUCT:     "STRUCT",
	storagepb.TableFieldSchema_BYTES:      "BYTES",
	storagepb.TableFieldSchema_BOOL:       "BOOL",
	storagepb.TableFieldSchema_TIMESTAMP:  "TIMESTAMP",
	storagepb.TableFieldSchema_DATE:       "DATE",
	storagepb.TableFieldSchema_TIME:       "TIME",
	storagepb.TableFieldSchema_DATETIME:   "DATETIME",
	storagepb.TableFieldSchema_GEOGRAPHY:  "GEOGRAPHY",
	storagepb.TableFieldSchema_NUMERIC:    "NUMERIC",
	storagepb.TableFieldSchema_BIGNUMERIC: "BIGNUMERIC",
	storagepb.TableFieldSchema_INTERVAL:   "INTERVAL",
	storagepb.TableFieldSchema_JSON:       "JSON",
	storagepb.TableFieldSchema_RANGE:      "RANGE",
}

var storageModeToContract = map[storagepb.TableFieldSchema_Mode]string{
	storagepb.TableFieldSchema_NULLABLE: "NULLABLE",
	storagepb.TableFieldSchema_REQUIRED: "REQUIRED",
	storagepb.TableFieldSchema_REPEATED: "REPEATED",
}

func sqlDigestHex(sql string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(sql)))
	return hex.EncodeToString(sum[:])
}

func buildCurrentSchemaSnapshot() (SchemaSnapshot, error) {
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
		{spansTbl, SpansTableSchema(), SpansDedupViewDDL, SpansSearchIndexDDL},
		{logsTbl, LogsTableSchema(), LogsDedupViewDDL, LogsSearchIndexDDL},
		{metricsTbl, MetricsTableSchema(), MetricsDedupViewDDL, MetricsSearchIndexDDL},
	}

	tables := make([]TableSnapshot, 0, 4)
	dedupDigests := make(map[string]string, len(signals))
	for _, sig := range signals {
		fields, err := fieldsToSnapshots(sig.schema.GetFields())
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s fields: %w", sig.name, err)
		}
		md, dedupQuery, err := DestinationMetadata(sig.schema, proj, ds, sig.name)
		if err != nil {
			return SchemaSnapshot{}, fmt.Errorf("%s metadata: %w", sig.name, err)
		}
		if strings.TrimSpace(dedupQuery) == "" {
			return SchemaSnapshot{}, fmt.Errorf("%s dedup query is empty", sig.name)
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
			DedupView:        dedupName,
			SearchIndex:      searchIdx,
		})
	}

	qFields, err := fieldsToSnapshots(QuarantineTableSchema().GetFields())
	if err != nil {
		return SchemaSnapshot{}, fmt.Errorf("%s fields: %w", quarantineTb, err)
	}
	qMD, err := QuarantineDestinationMetadata()
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
	})

	companionViews, viewDigests, err := collectCompanionViews(proj, ds, spansTbl, logsTbl, metricsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}
	companionTVFs, tvfDigests, err := collectCompanionTVFs(proj, ds, spansTbl, logsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}

	return SchemaSnapshot{
		Version:              Version,
		Tables:               tables,
		CompanionViews:       companionViews,
		CompanionTVFs:        companionTVFs,
		DedupViewDigests:     dedupDigests,
		CompanionViewDigests: viewDigests,
		CompanionTVFDigests:  tvfDigests,
	}, nil
}

// buildDDLSchemaSnapshot derives a second independent SchemaSnapshot directly
// from the SQL DDL constants in schema.go and tvf.go so mutations to operator
// DDL (even when tableschema.go is untouched) fail the golden contract check.
func buildDDLSchemaSnapshot() (SchemaSnapshot, error) {
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
		{spansTbl, SpansDDL, SpansDedupViewDDL, SpansSearchIndexDDL},
		{logsTbl, LogsDDL, LogsDedupViewDDL, LogsSearchIndexDDL},
		{metricsTbl, MetricsDDL, MetricsDedupViewDDL, MetricsSearchIndexDDL},
		{quarantineTb, QuarantineDDL, "", ""},
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
			DedupView:        dedupView,
			SearchIndex:      searchIdx,
		})
	}

	companionViews, viewDigests, err := collectDDLCompanionViews(proj, ds, spansTbl, logsTbl, metricsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}
	companionTVFs, tvfDigests, err := collectCompanionTVFs(proj, ds, spansTbl, logsTbl)
	if err != nil {
		return SchemaSnapshot{}, err
	}

	return SchemaSnapshot{
		Version:              Version,
		Tables:               tables,
		CompanionViews:       companionViews,
		CompanionTVFs:        companionTVFs,
		DedupViewDigests:     dedupDigests,
		CompanionViewDigests: viewDigests,
		CompanionTVFDigests:  tvfDigests,
	}, nil
}

func fieldsToSnapshots(in []*storagepb.TableFieldSchema) ([]FieldSnapshot, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]FieldSnapshot, 0, len(in))
	for _, f := range in {
		if f == nil {
			return nil, fmt.Errorf("nil field in schema")
		}
		typ, ok := storageTypeToGoogleSQL[f.GetType()]
		if !ok {
			return nil, fmt.Errorf("field %q has unsupported storage type %s", f.GetName(), f.GetType())
		}
		mode, ok := storageModeToContract[f.GetMode()]
		if !ok {
			return nil, fmt.Errorf("field %q has unsupported mode %s", f.GetName(), f.GetMode())
		}
		var tsPrecision int64
		if f.GetTimestampPrecision() != nil {
			tsPrecision = f.GetTimestampPrecision().GetValue()
		}
		var rangeElem string
		if f.GetRangeElementType() != nil {
			elemSQL, elemOK := storageTypeToGoogleSQL[f.GetRangeElementType().GetType()]
			if !elemOK {
				return nil, fmt.Errorf("field %q has unsupported range element type %s", f.GetName(), f.GetRangeElementType().GetType())
			}
			rangeElem = elemSQL
		}
		children, err := fieldsToSnapshots(f.GetFields())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.GetName(), err)
		}
		out = append(out, FieldSnapshot{
			Name:                   f.GetName(),
			Type:                   typ,
			Mode:                   mode,
			MaxLength:              f.GetMaxLength(),
			Precision:              f.GetPrecision(),
			Scale:                  f.GetScale(),
			DefaultValueExpression: f.GetDefaultValueExpression(),
			TimestampPrecision:     tsPrecision,
			RangeElementType:       rangeElem,
			Fields:                 children,
		})
	}
	return out, nil
}

func extractLayoutSnapshot(md *bq.TableMetadata) (TimePartitioningSnapshot, []string, error) {
	if md == nil || md.TimePartitioning == nil {
		return TimePartitioningSnapshot{}, nil, fmt.Errorf("missing TimePartitioning metadata")
	}
	if md.Clustering == nil || len(md.Clustering.Fields) == 0 {
		return TimePartitioningSnapshot{}, nil, fmt.Errorf("missing Clustering metadata")
	}
	tp := TimePartitioningSnapshot{
		Type:                   string(md.TimePartitioning.Type),
		Field:                  md.TimePartitioning.Field,
		RequirePartitionFilter: md.RequirePartitionFilter,
		ExpirationDays:         int(md.TimePartitioning.Expiration / (24 * time.Hour)),
	}
	return tp, slices.Clone(md.Clustering.Fields), nil
}

func stripSQLComments(ddl string) string {
	lines := strings.Split(ddl, "\n")
	for i, line := range lines {
		line, _, _ = strings.Cut(line, "--")
		lines[i] = strings.TrimRight(line, " \t\r")
	}
	return strings.Join(lines, "\n")
}

func parseDDLLayout(ddl string) (TimePartitioningSnapshot, []string, error) {
	cleaned := stripSQLComments(ddl)
	var tp TimePartitioningSnapshot
	switch {
	case ddlPartitionHourRE.MatchString(cleaned):
		m := ddlPartitionHourRE.FindStringSubmatch(cleaned)
		tp.Type = string(bq.HourPartitioningType)
		tp.Field = m[1]
	case ddlPartitionDayRE.MatchString(cleaned):
		m := ddlPartitionDayRE.FindStringSubmatch(cleaned)
		tp.Type = string(bq.DayPartitioningType)
		tp.Field = m[1]
	default:
		return TimePartitioningSnapshot{}, nil, fmt.Errorf("no PARTITION BY clause found")
	}
	if m := ddlPartitionExpirationRE.FindStringSubmatch(cleaned); m != nil {
		days, err := strconv.Atoi(m[1])
		if err != nil {
			return TimePartitioningSnapshot{}, nil, fmt.Errorf("parse partition_expiration_days: %w", err)
		}
		tp.ExpirationDays = days
	}
	if m := ddlRequirePartFilterRE.FindStringSubmatch(cleaned); m != nil {
		tp.RequirePartitionFilter = m[1] == "true"
	}
	cm := ddlClusterByRE.FindStringSubmatch(cleaned)
	if cm == nil {
		return TimePartitioningSnapshot{}, nil, fmt.Errorf("no CLUSTER BY clause found")
	}
	return tp, splitColumns(cm[1]), nil
}

func parseViewDDL(ddl string) (string, string, error) {
	m := ddlViewHeaderRE.FindStringSubmatch(strings.TrimSpace(ddl))
	if m == nil {
		return "", "", fmt.Errorf("no CREATE OR REPLACE VIEW header in DDL")
	}
	return m[1], m[2], nil
}

func parseSearchIndexSnapshot(ddl string) (*SearchIndexSnapshot, error) {
	m := ddlSearchRE.FindStringSubmatch(strings.TrimSpace(ddl))
	if m == nil {
		return nil, fmt.Errorf("no CREATE SEARCH INDEX statement matched in %q", ddl)
	}
	idx := &SearchIndexSnapshot{
		Name:     m[1],
		Analyzer: m[3],
	}
	colsRaw := strings.TrimSpace(m[2])
	if colsRaw == "ALL COLUMNS" {
		idx.AllColumns = true
	} else {
		idx.Columns = splitColumns(colsRaw)
	}
	return idx, nil
}

func collectCompanionViews(proj, ds, spansTbl, logsTbl, metricsTbl string) ([]string, map[string]string, error) {
	digests := make(map[string]string)
	addOne := func(name string, md *bq.TableMetadata) error {
		if md == nil || strings.TrimSpace(md.ViewQuery) == "" {
			return fmt.Errorf("companion view %q has empty ViewQuery", name)
		}
		if _, dup := digests[name]; dup {
			return fmt.Errorf("duplicate companion view %q in metadata builders", name)
		}
		digests[name] = sqlDigestHex(md.ViewQuery)
		return nil
	}
	addMap := func(m map[string]*bq.TableMetadata) error {
		for name, md := range m {
			if err := addOne(name, md); err != nil {
				return err
			}
		}
		return nil
	}
	if err := addMap(CompanionViewsMetadata(proj, ds, spansTbl, logsTbl, true)); err != nil {
		return nil, nil, err
	}
	if err := addMap(CompanionViewsMetadata(proj, ds, spansTbl, logsTbl, false)); err != nil {
		return nil, nil, err
	}
	if err := addMap(MetricsCompanionViewsMetadata(proj, ds, metricsTbl)); err != nil {
		return nil, nil, err
	}
	if err := addOne(GenAIMetricExemplarsViewName, MetricExemplarsCompanionViewMetadata(proj, ds, spansTbl)); err != nil {
		return nil, nil, err
	}

	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, digests, nil
}

func collectDDLCompanionViews(proj, ds, spansTbl, logsTbl, metricsTbl string) ([]string, map[string]string, error) {
	formattedDDLs := []string{
		fmt.Sprintf(SpansAsAllSpansViewDDL, proj, ds, spansTbl),
		fmt.Sprintf(GenAISpansViewDDL, proj, ds, spansTbl),
		fmt.Sprintf(GenAILogsViewDDL, proj, ds, logsTbl, spansTbl),
		fmt.Sprintf(GenAIMetricsViewDDL, proj, ds, metricsTbl),
		fmt.Sprintf(GenAIMetricExemplarsViewDDL, proj, ds, spansTbl),
		fmt.Sprintf(GenAIModelCostsViewDDL, proj, ds),
		fmt.Sprintf(GenAISessionsViewDDL, proj, ds),
		fmt.Sprintf(GenAIToolUsageViewDDL, proj, ds),
		fmt.Sprintf(GenAIAgentTrajectoryViewDDL, proj, ds),
		fmt.Sprintf(MCPSpansViewDDL, proj, ds, spansTbl),
		fmt.Sprintf(MCPToolUsageViewDDL, proj, ds),
	}
	digests := make(map[string]string, len(formattedDDLs))
	for _, ddl := range formattedDDLs {
		name, body, err := parseViewDDL(ddl)
		if err != nil {
			return nil, nil, fmt.Errorf("parse companion view DDL: %w", err)
		}
		if _, dup := digests[name]; dup {
			return nil, nil, fmt.Errorf("duplicate companion view %q in DDL constants", name)
		}
		digests[name] = sqlDigestHex(body)
	}
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	slices.Sort(names)
	return names, digests, nil
}

func collectCompanionTVFs(proj, ds, spansTbl, logsTbl string) ([]string, map[string]string, error) {
	ddls := CompanionTVFDDLs(proj, ds, spansTbl, logsTbl)
	if len(ddls) == 0 {
		return nil, nil, fmt.Errorf("CompanionTVFDDLs returned no routines")
	}
	names := make([]string, 0, len(ddls))
	digests := make(map[string]string, len(ddls))
	for name, ddl := range ddls {
		if !strings.Contains(ddl, "CREATE OR REPLACE TABLE FUNCTION") {
			return nil, nil, fmt.Errorf("TVF %q DDL missing CREATE OR REPLACE TABLE FUNCTION", name)
		}
		names = append(names, name)
		digests[name] = sqlDigestHex(ddl)
	}
	slices.Sort(names)
	return names, digests, nil
}

type compatibilityOptions struct {
	AllowBreakingMajorTransition bool
}

type compatPolicy struct {
	allowColumnAdditions    bool
	allowRequiredToNullable bool
	allowNewTables          bool
	allowNewViewsAndTVFs    bool
	forbidViewDigestChanges bool
}

type parsedSchemaVersion struct {
	raw   string
	major int
	minor int
	patch int
	alpha int
}

func parseStrictNonNegInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty integer")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("non-digit character in %q", s)
		}
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zero in %q", s)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("invalid non-negative integer %q", s)
	}
	return n, nil
}

func parseSchemaVersion(raw string) (parsedSchemaVersion, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return parsedSchemaVersion{}, fmt.Errorf("schema version is empty")
	}
	if strings.HasPrefix(v, "v0alpha") {
		rest := strings.TrimPrefix(v, "v0alpha")
		n, err := parseStrictNonNegInt(rest)
		if err != nil || n <= 0 {
			return parsedSchemaVersion{}, fmt.Errorf("invalid alpha schema version %q", raw)
		}
		return parsedSchemaVersion{raw: v, major: 0, alpha: n}, nil
	}
	if !strings.HasPrefix(v, "v") {
		return parsedSchemaVersion{}, fmt.Errorf("schema version %q must start with 'v'", raw)
	}
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) != 3 {
		return parsedSchemaVersion{}, fmt.Errorf("schema version %q must match v<major>.<minor>.<patch> or v0alpha<N>", raw)
	}
	maj, err := parseStrictNonNegInt(parts[0])
	if err != nil {
		return parsedSchemaVersion{}, fmt.Errorf("invalid major version in %q: %w", raw, err)
	}
	minVer, err := parseStrictNonNegInt(parts[1])
	if err != nil {
		return parsedSchemaVersion{}, fmt.Errorf("invalid minor version in %q: %w", raw, err)
	}
	pat, err := parseStrictNonNegInt(parts[2])
	if err != nil {
		return parsedSchemaVersion{}, fmt.Errorf("invalid patch version in %q: %w", raw, err)
	}
	return parsedSchemaVersion{raw: v, major: maj, minor: minVer, patch: pat}, nil
}

func compareSchemaVersions(a, b parsedSchemaVersion) int {
	if a.major != b.major {
		return cmp.Compare(a.major, b.major)
	}
	if a.major == 0 {
		if a.alpha > 0 && b.alpha > 0 {
			return cmp.Compare(a.alpha, b.alpha)
		}
		if a.alpha > 0 {
			return -1
		}
		if b.alpha > 0 {
			return 1
		}
	}
	if a.minor != b.minor {
		return cmp.Compare(a.minor, b.minor)
	}
	return cmp.Compare(a.patch, b.patch)
}

// checkSchemaBackwardCompatibility checks whether current is backward-compatible
// with baseline under the exporter's BigQuery contract rules.
//
// Within the same numeric series (same major >= 0 with alpha == 0, or unchanged
// v0alphaN):
//   - Column removals, renames, type changes, NULLABLE -> REQUIRED tightening,
//     and column reordering are always forbidden.
//   - Minor bumps (minor > baseline.minor) allow appending NULLABLE/REPEATED
//     columns at the tail, REQUIRED -> NULLABLE relaxation, and additive
//     optional tables, companion views, or TVFs.
//   - Patch bumps (minor == baseline.minor && patch > baseline.patch) forbid
//     even column, table, view, or TVF additions and REQUIRED -> NULLABLE
//     relaxation.
//
// Major transitions (major != baseline.major) or pre-release alpha transitions
// (baseline.alpha > 0 || current.alpha > 0 with version change) are rejected
// unless opts.AllowBreakingMajorTransition is true.
func checkSchemaBackwardCompatibility(baseline, current SchemaSnapshot) []string {
	return checkSchemaBackwardCompatibilityWithOptions(baseline, current, compatibilityOptions{})
}

func checkSchemaBackwardCompatibilityWithOptions(baseline, current SchemaSnapshot, opts compatibilityOptions) []string {
	if strings.TrimSpace(baseline.Version) == "" {
		return []string{"baseline schema version is empty"}
	}
	if strings.TrimSpace(current.Version) == "" {
		return []string{"current schema version is empty"}
	}
	baseVer, err := parseSchemaVersion(baseline.Version)
	if err != nil {
		return []string{fmt.Sprintf("baseline %v", err)}
	}
	curVer, err := parseSchemaVersion(current.Version)
	if err != nil {
		return []string{fmt.Sprintf("current %v", err)}
	}
	if compareSchemaVersions(curVer, baseVer) < 0 {
		return []string{fmt.Sprintf("schema version downgraded from %s to %s", baseline.Version, current.Version)}
	}

	isMajorOrAlphaTransition := curVer.major != baseVer.major || ((baseVer.alpha > 0 || curVer.alpha > 0) && curVer.raw != baseVer.raw)
	if isMajorOrAlphaTransition {
		if !opts.AllowBreakingMajorTransition {
			return []string{fmt.Sprintf(
				"schema version transition %s -> %s crosses a major or pre-1.0 boundary without AllowBreakingMajorTransition",
				baseline.Version, current.Version,
			)}
		}
		return nil
	}

	policy := compatPolicy{
		allowColumnAdditions: true,
		allowNewTables:       true,
		allowNewViewsAndTVFs: true,
	}
	if baseVer.alpha == 0 {
		switch {
		case curVer.minor > baseVer.minor:
			policy.allowRequiredToNullable = true
		case curVer.patch > baseVer.patch:
			policy.allowColumnAdditions = false
			policy.allowNewTables = false
			policy.allowNewViewsAndTVFs = false
			policy.forbidViewDigestChanges = true
		}
	}

	var violations []string

	curTables := make(map[string]TableSnapshot, len(current.Tables))
	for _, tbl := range current.Tables {
		if _, dup := curTables[tbl.Name]; dup {
			violations = append(violations, fmt.Sprintf("duplicate table %q in current snapshot", tbl.Name))
			continue
		}
		curTables[tbl.Name] = tbl
	}

	baseTableNames := make(map[string]bool, len(baseline.Tables))
	for _, baseTbl := range baseline.Tables {
		baseTableNames[baseTbl.Name] = true
		curTbl, ok := curTables[baseTbl.Name]
		if !ok {
			violations = append(violations, fmt.Sprintf("table %q was removed without bumping schema.Version (%s)", baseTbl.Name, current.Version))
			continue
		}
		violations = append(violations, checkTableBackwardCompatibility(baseTbl, curTbl, policy)...)
	}

	for _, curTbl := range current.Tables {
		if baseTableNames[curTbl.Name] {
			continue
		}
		if !policy.allowNewTables {
			violations = append(violations, fmt.Sprintf("table %q was added in patch bump %s -> %s (patch bumps forbid table additions)", curTbl.Name, baseline.Version, current.Version))
			continue
		}
		violations = append(violations, validateNewTable(curTbl)...)
	}

	baseViews := make(map[string]bool, len(baseline.CompanionViews))
	for _, v := range baseline.CompanionViews {
		baseViews[v] = true
	}
	curViews := make(map[string]bool, len(current.CompanionViews))
	for _, v := range current.CompanionViews {
		if curViews[v] {
			violations = append(violations, fmt.Sprintf("duplicate companion view %q in current snapshot", v))
			continue
		}
		curViews[v] = true
		if !policy.allowNewViewsAndTVFs && !baseViews[v] {
			violations = append(violations, fmt.Sprintf("companion view %q was added in patch bump %s -> %s", v, baseline.Version, current.Version))
		}
	}
	for _, baseView := range baseline.CompanionViews {
		if !curViews[baseView] {
			violations = append(violations, fmt.Sprintf("companion view %q was removed without bumping schema.Version (%s)", baseView, current.Version))
		}
	}

	baseTVFs := make(map[string]bool, len(baseline.CompanionTVFs))
	for _, tvf := range baseline.CompanionTVFs {
		baseTVFs[tvf] = true
	}
	curTVFs := make(map[string]bool, len(current.CompanionTVFs))
	for _, tvf := range current.CompanionTVFs {
		if curTVFs[tvf] {
			violations = append(violations, fmt.Sprintf("duplicate companion TVF %q in current snapshot", tvf))
			continue
		}
		curTVFs[tvf] = true
		if !policy.allowNewViewsAndTVFs && !baseTVFs[tvf] {
			violations = append(violations, fmt.Sprintf("companion TVF %q was added in patch bump %s -> %s", tvf, baseline.Version, current.Version))
		}
	}
	for _, baseTVF := range baseline.CompanionTVFs {
		if !curTVFs[baseTVF] {
			violations = append(violations, fmt.Sprintf("companion TVF %q was removed without bumping schema.Version (%s)", baseTVF, current.Version))
		}
	}

	if policy.forbidViewDigestChanges {
		violations = append(violations, checkDigestMapUnchanged("dedup_view_digests", baseline.DedupViewDigests, current.DedupViewDigests, baseline.Version, current.Version)...)
		violations = append(violations, checkDigestMapUnchanged("companion_view_digests", baseline.CompanionViewDigests, current.CompanionViewDigests, baseline.Version, current.Version)...)
		violations = append(violations, checkDigestMapUnchanged("companion_tvf_digests", baseline.CompanionTVFDigests, current.CompanionTVFDigests, baseline.Version, current.Version)...)
	}

	return violations
}

func checkDigestMapUnchanged(kind string, base, cur map[string]string, baseVer, curVer string) []string {
	var violations []string
	for name, baseDigest := range base {
		curDigest, ok := cur[name]
		if !ok {
			violations = append(violations, fmt.Sprintf("%s[%q] was removed in patch bump %s -> %s", kind, name, baseVer, curVer))
			continue
		}
		if curDigest != baseDigest {
			violations = append(violations, fmt.Sprintf("%s[%q] SQL digest changed in patch bump %s -> %s", kind, name, baseVer, curVer))
		}
	}
	for name := range cur {
		if _, ok := base[name]; !ok {
			violations = append(violations, fmt.Sprintf("%s[%q] was added in patch bump %s -> %s", kind, name, baseVer, curVer))
		}
	}
	slices.Sort(violations)
	return violations
}

func checkTableBackwardCompatibility(base, cur TableSnapshot, policy compatPolicy) []string {
	var violations []string
	violations = append(violations, checkFieldsBackwardCompatibility(base.Name, base.Fields, cur.Fields, policy)...)

	if cur.TimePartitioning.Field != base.TimePartitioning.Field {
		violations = append(violations, fmt.Sprintf(
			"table %s: time_partitioning.field changed from %q to %q",
			base.Name, base.TimePartitioning.Field, cur.TimePartitioning.Field,
		))
	}
	if cur.TimePartitioning.Type != base.TimePartitioning.Type {
		violations = append(violations, fmt.Sprintf(
			"table %s: time_partitioning.type changed from %q to %q",
			base.Name, base.TimePartitioning.Type, cur.TimePartitioning.Type,
		))
	}
	if cur.TimePartitioning.RequirePartitionFilter != base.TimePartitioning.RequirePartitionFilter {
		violations = append(violations, fmt.Sprintf(
			"table %s: time_partitioning.require_partition_filter changed from %t to %t",
			base.Name, base.TimePartitioning.RequirePartitionFilter, cur.TimePartitioning.RequirePartitionFilter,
		))
	}
	if cur.TimePartitioning.ExpirationDays != base.TimePartitioning.ExpirationDays {
		violations = append(violations, fmt.Sprintf(
			"table %s: time_partitioning.expiration_days changed from %d to %d",
			base.Name, base.TimePartitioning.ExpirationDays, cur.TimePartitioning.ExpirationDays,
		))
	}

	if !slices.Equal(base.Clustering, cur.Clustering) {
		violations = append(violations, fmt.Sprintf(
			"table %s: clustering columns changed from %v to %v",
			base.Name, base.Clustering, cur.Clustering,
		))
	}

	if base.DedupView != "" && cur.DedupView != base.DedupView {
		violations = append(violations, fmt.Sprintf(
			"table %s: dedup_view changed from %q to %q",
			base.Name, base.DedupView, cur.DedupView,
		))
	}

	switch {
	case base.SearchIndex != nil && cur.SearchIndex == nil:
		violations = append(violations, fmt.Sprintf(
			"table %s: search_index %q was removed",
			base.Name, base.SearchIndex.Name,
		))
	case base.SearchIndex != nil && cur.SearchIndex != nil:
		if cur.SearchIndex.Name != base.SearchIndex.Name {
			violations = append(violations, fmt.Sprintf(
				"table %s: search_index.name changed from %q to %q",
				base.Name, base.SearchIndex.Name, cur.SearchIndex.Name,
			))
		}
		if cur.SearchIndex.AllColumns != base.SearchIndex.AllColumns ||
			!slices.Equal(cur.SearchIndex.Columns, base.SearchIndex.Columns) {
			violations = append(violations, fmt.Sprintf(
				"table %s: search_index columns changed from (all=%t, cols=%v) to (all=%t, cols=%v)",
				base.Name,
				base.SearchIndex.AllColumns, base.SearchIndex.Columns,
				cur.SearchIndex.AllColumns, cur.SearchIndex.Columns,
			))
		}
		if cur.SearchIndex.Analyzer != base.SearchIndex.Analyzer {
			violations = append(violations, fmt.Sprintf(
				"table %s: search_index.analyzer changed from %q to %q",
				base.Name, base.SearchIndex.Analyzer, cur.SearchIndex.Analyzer,
			))
		}
	case base.SearchIndex == nil && cur.SearchIndex != nil:
		violations = append(violations, validateSearchIndex(base.Name, *cur.SearchIndex)...)
	}

	return violations
}

func validateSearchIndex(tableName string, idx SearchIndexSnapshot) []string {
	var violations []string
	if strings.TrimSpace(idx.Name) == "" {
		violations = append(violations, fmt.Sprintf("table %s: search_index.name is empty", tableName))
	}
	if strings.TrimSpace(idx.Analyzer) == "" {
		violations = append(violations, fmt.Sprintf("table %s: search_index.analyzer is empty", tableName))
	}
	if !idx.AllColumns && len(idx.Columns) == 0 {
		violations = append(violations, fmt.Sprintf("table %s: search_index must specify columns or all_columns", tableName))
	}
	return violations
}

func checkFieldsBackwardCompatibility(prefix string, baseFields, curFields []FieldSnapshot, policy compatPolicy) []string {
	var violations []string

	curByName := make(map[string]FieldSnapshot, len(curFields))
	curIndex := make(map[string]int, len(curFields))
	for idx, f := range curFields {
		if _, dup := curByName[f.Name]; dup {
			violations = append(violations, fmt.Sprintf("%s.%s: duplicate column definition", prefix, f.Name))
			continue
		}
		curByName[f.Name] = f
		curIndex[f.Name] = idx
	}

	baseNames := make(map[string]bool, len(baseFields))
	lastCurPos := -1
	lastRetainedName := ""
	maxRetainedPos := -1

	for _, baseField := range baseFields {
		baseNames[baseField.Name] = true
		fieldPath := prefix + "." + baseField.Name
		curField, ok := curByName[baseField.Name]
		if !ok {
			violations = append(violations, fmt.Sprintf("%s: column was removed", fieldPath))
			continue
		}

		pos := curIndex[baseField.Name]
		if pos > maxRetainedPos {
			maxRetainedPos = pos
		}
		if pos < lastCurPos {
			violations = append(violations, fmt.Sprintf(
				"%s: column order changed relative to %s.%s",
				fieldPath, prefix, lastRetainedName,
			))
		} else {
			lastCurPos = pos
			lastRetainedName = baseField.Name
		}

		if curField.Type != baseField.Type {
			violations = append(violations, fmt.Sprintf(
				"%s: column type changed from %s to %s",
				fieldPath, baseField.Type, curField.Type,
			))
		}
		if curField.Mode != baseField.Mode {
			if !policy.allowRequiredToNullable || baseField.Mode != "REQUIRED" || curField.Mode != "NULLABLE" {
				violations = append(violations, fmt.Sprintf(
					"%s: column mode changed from %s to %s",
					fieldPath, baseField.Mode, curField.Mode,
				))
			}
		}
		if curField.MaxLength != baseField.MaxLength {
			violations = append(violations, fmt.Sprintf(
				"%s: column max_length changed from %d to %d",
				fieldPath, baseField.MaxLength, curField.MaxLength,
			))
		}
		if curField.Precision != baseField.Precision {
			violations = append(violations, fmt.Sprintf(
				"%s: column precision changed from %d to %d",
				fieldPath, baseField.Precision, curField.Precision,
			))
		}
		if curField.Scale != baseField.Scale {
			violations = append(violations, fmt.Sprintf(
				"%s: column scale changed from %d to %d",
				fieldPath, baseField.Scale, curField.Scale,
			))
		}
		if curField.DefaultValueExpression != baseField.DefaultValueExpression {
			violations = append(violations, fmt.Sprintf(
				"%s: column default_value_expression changed from %q to %q",
				fieldPath, baseField.DefaultValueExpression, curField.DefaultValueExpression,
			))
		}
		if curField.TimestampPrecision != baseField.TimestampPrecision {
			violations = append(violations, fmt.Sprintf(
				"%s: column timestamp_precision changed from %d to %d",
				fieldPath, baseField.TimestampPrecision, curField.TimestampPrecision,
			))
		}
		if curField.RangeElementType != baseField.RangeElementType {
			violations = append(violations, fmt.Sprintf(
				"%s: column range_element_type changed from %q to %q",
				fieldPath, baseField.RangeElementType, curField.RangeElementType,
			))
		}

		if baseField.Type == "STRUCT" && curField.Type == "STRUCT" {
			violations = append(violations,
				checkFieldsBackwardCompatibility(fieldPath, baseField.Fields, curField.Fields, policy)...)
		}
	}

	for idx, curField := range curFields {
		if baseNames[curField.Name] {
			continue
		}
		fieldPath := prefix + "." + curField.Name
		if !policy.allowColumnAdditions {
			violations = append(violations, fmt.Sprintf(
				"%s: newly added column is forbidden on a patch bump",
				fieldPath,
			))
			continue
		}
		if idx < maxRetainedPos {
			violations = append(violations, fmt.Sprintf(
				"%s: newly added column must be appended after existing columns (at index %d < %d) so ReconcileAdditiveSchema and cold creation agree",
				fieldPath, idx, maxRetainedPos,
			))
		}
		violations = append(violations, checkAdditiveField(fieldPath, curField)...)
	}

	return violations
}

func checkAdditiveField(fieldPath string, fld FieldSnapshot) []string {
	var violations []string
	if fld.Mode != "NULLABLE" && fld.Mode != "REPEATED" {
		violations = append(violations, fmt.Sprintf(
			"%s: newly added column has mode %s; only NULLABLE or REPEATED columns are additive without bumping schema.Version",
			fieldPath, fld.Mode,
		))
	}
	if fld.Type == "STRUCT" {
		if len(fld.Fields) == 0 {
			violations = append(violations, fmt.Sprintf("%s: STRUCT column must declare at least one child field", fieldPath))
		}
		seen := make(map[string]bool, len(fld.Fields))
		for _, child := range fld.Fields {
			if seen[child.Name] {
				violations = append(violations, fmt.Sprintf("%s.%s: duplicate column definition", fieldPath, child.Name))
				continue
			}
			seen[child.Name] = true
			violations = append(violations, checkAdditiveField(fieldPath+"."+child.Name, child)...)
		}
	}
	return violations
}

func validateNewTable(tbl TableSnapshot) []string {
	if len(tbl.Fields) == 0 {
		return []string{fmt.Sprintf("table %s: newly added table has no columns", tbl.Name)}
	}
	var violations []string
	seen := make(map[string]bool, len(tbl.Fields))
	var validateStruct func(prefix string, f FieldSnapshot)
	validateStruct = func(prefix string, f FieldSnapshot) {
		if f.Type == "STRUCT" {
			if len(f.Fields) == 0 {
				violations = append(violations, fmt.Sprintf("%s: STRUCT column must declare at least one child field", prefix))
				return
			}
			childSeen := make(map[string]bool, len(f.Fields))
			for _, c := range f.Fields {
				if childSeen[c.Name] {
					violations = append(violations, fmt.Sprintf("%s.%s: duplicate column definition", prefix, c.Name))
					continue
				}
				childSeen[c.Name] = true
				validateStruct(prefix+"."+c.Name, c)
			}
		}
	}
	for _, f := range tbl.Fields {
		if seen[f.Name] {
			violations = append(violations, fmt.Sprintf("%s.%s: duplicate column definition", tbl.Name, f.Name))
			continue
		}
		seen[f.Name] = true
		validateStruct(tbl.Name+"."+f.Name, f)
	}
	if tbl.SearchIndex != nil {
		violations = append(violations, validateSearchIndex(tbl.Name, *tbl.SearchIndex)...)
	}
	return violations
}

func loadGoldenSchemaSnapshot(t *testing.T) (SchemaSnapshot, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(goldenSchemaPath))
	if err != nil {
		t.Fatalf("read golden schema snapshot %s: %v", goldenSchemaPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var snap SchemaSnapshot
	if err := dec.Decode(&snap); err != nil {
		t.Fatalf("decode golden schema snapshot %s: %v", goldenSchemaPath, err)
	}
	return snap, raw
}

func marshalCanonicalSnapshot(t *testing.T, snap SchemaSnapshot) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(snap); err != nil {
		t.Fatalf("marshal schema snapshot: %v", err)
	}
	return buf.Bytes()
}

func cloneSchemaSnapshot(t *testing.T, in SchemaSnapshot) SchemaSnapshot {
	t.Helper()
	raw := marshalCanonicalSnapshot(t, in)
	var out SchemaSnapshot
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal cloned snapshot: %v", err)
	}
	return out
}

func TestGoldenSchemaMatchesCurrentContract(t *testing.T) {
	golden, goldenRaw := loadGoldenSchemaSnapshot(t)

	current, err := buildCurrentSchemaSnapshot()
	if err != nil {
		t.Fatalf("build current schema snapshot: %v", err)
	}
	ddlCurrent, err := buildDDLSchemaSnapshot()
	if err != nil {
		t.Fatalf("build DDL schema snapshot: %v", err)
	}

	if violations := checkSchemaBackwardCompatibility(golden, current); len(violations) > 0 {
		t.Fatalf(
			"breaking schema change(s) detected against %s (version %s):\n  - %s\n"+
				"Breaking changes within %s are forbidden; either restore backward compatibility or bump schema.Version with a documented migration.",
			goldenSchemaPath, golden.Version, strings.Join(violations, "\n  - "), golden.Version,
		)
	}
	if violations := checkSchemaBackwardCompatibility(golden, ddlCurrent); len(violations) > 0 {
		t.Fatalf(
			"breaking operator DDL change(s) detected against %s (version %s):\n  - %s\n"+
				"Keep internal/schema/schema.go and internal/schema/tableschema.go aligned with the %s golden contract.",
			goldenSchemaPath, golden.Version, strings.Join(violations, "\n  - "), golden.Version,
		)
	}

	if err := checkExactGoldenParity(golden, goldenRaw, current, ddlCurrent); err != nil {
		t.Fatal(err)
	}
}

func checkExactGoldenParity(golden SchemaSnapshot, goldenRaw []byte, current, ddlCurrent SchemaSnapshot) error {
	var buf bytes.Buffer
	marshal := func(snap SchemaSnapshot) ([]byte, error) {
		buf.Reset()
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(snap); err != nil {
			return nil, err
		}
		return bytes.Clone(buf.Bytes()), nil
	}

	currentJSON, err := marshal(current)
	if err != nil {
		return fmt.Errorf("marshal current snapshot: %w", err)
	}
	ddlJSON, err := marshal(ddlCurrent)
	if err != nil {
		return fmt.Errorf("marshal DDL snapshot: %w", err)
	}
	if !bytes.Equal(currentJSON, ddlJSON) {
		return fmt.Errorf(
			"TableSchema snapshot and operator DDL snapshot diverged:\n--- TableSchema ---\n%s\n--- DDL ---\n%s",
			string(currentJSON), string(ddlJSON),
		)
	}

	normalizedGolden, err := marshal(golden)
	if err != nil {
		return fmt.Errorf("marshal golden snapshot: %w", err)
	}
	if !bytes.Equal(bytes.TrimSpace(goldenRaw), bytes.TrimSpace(normalizedGolden)) {
		return fmt.Errorf("%s is not canonically formatted; re-format with 2-space JSON indentation", goldenSchemaPath)
	}

	if !bytes.Equal(normalizedGolden, currentJSON) {
		return fmt.Errorf(
			"unrecorded schema drift against %s:\n"+
				"1. If this is an intentional additive change (new NULLABLE/REPEATED column, companion view, or TVF) within %s, update internal/schema/%s to record the new contract.\n"+
				"2. If this changes schema.Version (%q -> %q), add or update the versioned golden snapshot only after completing the release gate.\n"+
				"Current canonical snapshot:\n%s",
			goldenSchemaPath, golden.Version, goldenSchemaPath, golden.Version, current.Version, string(currentJSON),
		)
	}
	return nil
}

func TestUnrecordedAdditiveDriftFailsExactParity(t *testing.T) {
	baseline, err := buildCurrentSchemaSnapshot()
	if err != nil {
		t.Fatalf("build baseline snapshot: %v", err)
	}
	baselineRaw := marshalCanonicalSnapshot(t, baseline)

	t.Run("unrecorded additive column", func(t *testing.T) {
		candidate := cloneSchemaSnapshot(t, baseline)
		candidate.Tables[0].Fields = append(candidate.Tables[0].Fields, FieldSnapshot{
			Name: "unrecorded_nullable_col",
			Type: "STRING",
			Mode: "NULLABLE",
		})
		if violations := checkSchemaBackwardCompatibility(baseline, candidate); len(violations) != 0 {
			t.Fatalf("additive NULLABLE column should pass backward-compatibility check, got %v", violations)
		}
		err := checkExactGoldenParity(baseline, baselineRaw, candidate, candidate)
		if err == nil || !strings.Contains(err.Error(), "unrecorded schema drift") {
			t.Fatalf("checkExactGoldenParity error = %v, want unrecorded schema drift instructions", err)
		}
	})

	t.Run("unrecorded companion view SQL digest drift", func(t *testing.T) {
		candidate := cloneSchemaSnapshot(t, baseline)
		candidate.CompanionViewDigests[GenAISpansViewName] = sqlDigestHex("SELECT 1")
		err := checkExactGoldenParity(baseline, baselineRaw, candidate, candidate)
		if err == nil || !strings.Contains(err.Error(), "unrecorded schema drift") {
			t.Fatalf("checkExactGoldenParity error = %v, want unrecorded schema drift on SQL digest", err)
		}
	})
}

func TestCheckSchemaBackwardCompatibility(t *testing.T) {
	baseline, err := buildCurrentSchemaSnapshot()
	if err != nil {
		t.Fatalf("build baseline snapshot: %v", err)
	}

	findTable := func(s *SchemaSnapshot, name string) *TableSnapshot {
		for i := range s.Tables {
			if s.Tables[i].Name == name {
				return &s.Tables[i]
			}
		}
		t.Fatalf("table %q not found", name)
		return nil
	}
	findField := func(fields []FieldSnapshot, name string) *FieldSnapshot {
		for i := range fields {
			if fields[i].Name == name {
				return &fields[i]
			}
		}
		t.Fatalf("field %q not found", name)
		return nil
	}

	tests := []struct {
		name          string
		mutate        func(s *SchemaSnapshot)
		wantSubstring string
	}{
		{
			name:          "identical contract is compatible",
			mutate:        func(_ *SchemaSnapshot) {},
			wantSubstring: "",
		},
		{
			name: "removing top-level column fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool {
					return f.Name == "trace_state"
				})
			},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name: "removing nested RECORD column fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				status := findField(tbl.Fields, "status")
				status.Fields = slices.DeleteFunc(status.Fields, func(f FieldSnapshot) bool {
					return f.Name == "code_name"
				})
			},
			wantSubstring: "otel_spans.status.code_name: column was removed",
		},
		{
			name: "removing deeply nested repeated RECORD column fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				refs := findField(tbl.Fields, "payload_refs")
				objRef := findField(refs.Fields, "object_ref")
				objRef.Fields = slices.DeleteFunc(objRef.Fields, func(f FieldSnapshot) bool {
					return f.Name == "uri"
				})
			},
			wantSubstring: "otel_spans.payload_refs.object_ref.uri: column was removed",
		},
		{
			name: "changing column type STRING to INT64 fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "parent_span_id")
				fld.Type = "INT64"
			},
			wantSubstring: "otel_spans.parent_span_id: column type changed from STRING to INT64",
		},
		{
			name: "changing column type JSON to STRING fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "attributes")
				fld.Type = "STRING"
			},
			wantSubstring: "otel_logs.attributes: column type changed from JSON to STRING",
		},
		{
			name: "changing nested column type FLOAT64 to INT64 fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_metrics")
				quantiles := findField(tbl.Fields, "summary_quantiles")
				val := findField(quantiles.Fields, "value")
				val.Type = "INT64"
			},
			wantSubstring: "otel_metrics.summary_quantiles.value: column type changed from FLOAT64 to INT64",
		},
		{
			name: "tightening mode NULLABLE to REQUIRED fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "service_name")
				fld.Mode = "REQUIRED"
			},
			wantSubstring: "otel_spans.service_name: column mode changed from NULLABLE to REQUIRED",
		},
		{
			name: "changing mode REPEATED to NULLABLE fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "events")
				fld.Mode = "NULLABLE"
			},
			wantSubstring: "otel_spans.events: column mode changed from REPEATED to NULLABLE",
		},
		{
			name: "changing mode NULLABLE to REPEATED fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "event_name")
				fld.Mode = "REPEATED"
			},
			wantSubstring: "otel_logs.event_name: column mode changed from NULLABLE to REPEATED",
		},
		{
			name: "changing mode REQUIRED to NULLABLE fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "trace_id")
				fld.Mode = "NULLABLE"
			},
			wantSubstring: "otel_spans.trace_id: column mode changed from REQUIRED to NULLABLE",
		},
		{
			name: "adding new REQUIRED top-level column fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{
					Name: "tenant_id",
					Type: "STRING",
					Mode: "REQUIRED",
				})
			},
			wantSubstring: "otel_spans.tenant_id: newly added column has mode REQUIRED",
		},
		{
			name: "adding new REQUIRED nested column inside STRUCT fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				status := findField(tbl.Fields, "status")
				status.Fields = append(status.Fields, FieldSnapshot{
					Name: "sub_code",
					Type: "INT64",
					Mode: "REQUIRED",
				})
			},
			wantSubstring: "otel_spans.status.sub_code: newly added column has mode REQUIRED",
		},
		{
			name: "inserting NULLABLE column before existing columns fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.Insert(tbl.Fields, 0, FieldSnapshot{
					Name: "prepended_nullable",
					Type: "STRING",
					Mode: "NULLABLE",
				})
			},
			wantSubstring: "otel_spans.prepended_nullable: newly added column must be appended after existing columns",
		},
		{
			name: "changing max_length fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "trace_id")
				fld.MaxLength = 32
			},
			wantSubstring: "otel_spans.trace_id: column max_length changed from 0 to 32",
		},
		{
			name: "changing timestamp_precision fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "start_time")
				fld.TimestampPrecision = 12
			},
			wantSubstring: "otel_spans.start_time: column timestamp_precision changed from 0 to 12",
		},
		{
			name: "changing default_value_expression fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "kind_name")
				fld.DefaultValueExpression = "'INTERNAL'"
			},
			wantSubstring: `otel_spans.kind_name: column default_value_expression changed from "" to "'INTERNAL'"`,
		},
		{
			name: "changing partitioning column fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.TimePartitioning.Field = "end_time"
			},
			wantSubstring: `table otel_spans: time_partitioning.field changed from "start_time" to "end_time"`,
		},
		{
			name: "changing partitioning type fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.TimePartitioning.Type = "DAY"
			},
			wantSubstring: `table otel_spans: time_partitioning.type changed from "HOUR" to "DAY"`,
		},
		{
			name: "enabling require_partition_filter by default fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_logs")
				tbl.TimePartitioning.RequirePartitionFilter = true
			},
			wantSubstring: "table otel_logs: time_partitioning.require_partition_filter changed from false to true",
		},
		{
			name: "changing partition expiration days fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_quarantine")
				tbl.TimePartitioning.ExpirationDays = 7
			},
			wantSubstring: "table otel_quarantine: time_partitioning.expiration_days changed from 30 to 7",
		},
		{
			name: "reordering clustering columns fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.Clustering = []string{"trace_id", "service_name", "name"}
			},
			wantSubstring: "table otel_spans: clustering columns changed from [service_name trace_id name] to [trace_id service_name name]",
		},
		{
			name: "reordering existing columns fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				for i := range tbl.Fields {
					if tbl.Fields[i].Name == "trace_id" && i+1 < len(tbl.Fields) {
						tbl.Fields[i], tbl.Fields[i+1] = tbl.Fields[i+1], tbl.Fields[i]
						break
					}
				}
			},
			wantSubstring: "otel_spans.span_id: column order changed relative to otel_spans.trace_id",
		},
		{
			name: "removing base table fails",
			mutate: func(s *SchemaSnapshot) {
				s.Tables = slices.DeleteFunc(s.Tables, func(tbl TableSnapshot) bool {
					return tbl.Name == "otel_quarantine"
				})
			},
			wantSubstring: `table "otel_quarantine" was removed`,
		},
		{
			name: "removing dedup view fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.DedupView = ""
			},
			wantSubstring: `table otel_spans: dedup_view changed from "otel_spans_dedup" to ""`,
		},
		{
			name: "removing search index fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_logs")
				tbl.SearchIndex = nil
			},
			wantSubstring: `table otel_logs: search_index "otel_logs_trace_lookup_idx" was removed`,
		},
		{
			name: "changing search index columns fails",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.SearchIndex.Columns = []string{"trace_id"}
			},
			wantSubstring: "table otel_spans: search_index columns changed",
		},
		{
			name: "removing companion view fails",
			mutate: func(s *SchemaSnapshot) {
				s.CompanionViews = slices.DeleteFunc(s.CompanionViews, func(v string) bool {
					return v == GenAIAgentTrajectoryViewName
				})
			},
			wantSubstring: `companion view "v_gen_ai_agent_trajectory" was removed`,
		},
		{
			name: "duplicate companion view fails",
			mutate: func(s *SchemaSnapshot) {
				s.CompanionViews = append(s.CompanionViews, GenAISpansViewName)
			},
			wantSubstring: `duplicate companion view "v_gen_ai_spans"`,
		},
		{
			name: "removing companion TVF fails",
			mutate: func(s *SchemaSnapshot) {
				s.CompanionTVFs = slices.DeleteFunc(s.CompanionTVFs, func(v string) bool {
					return v == GenAILogsTVFName
				})
			},
			wantSubstring: `companion TVF "tvf_gen_ai_logs" was removed`,
		},
		{
			name: "adding NULLABLE top-level and nested columns at the end is allowed",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_spans")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{
					Name: "is_truncated",
					Type: "BOOL",
					Mode: "NULLABLE",
				})
				status := findField(tbl.Fields, "status")
				status.Fields = append(status.Fields, FieldSnapshot{
					Name: "detail_uri",
					Type: "STRING",
					Mode: "NULLABLE",
				})
			},
			wantSubstring: "",
		},
		{
			name: "adding REPEATED top-level slice and STRUCT slice at the end is allowed",
			mutate: func(s *SchemaSnapshot) {
				tbl := findTable(s, "otel_logs")
				tbl.Fields = append(tbl.Fields,
					FieldSnapshot{
						Name: "tags",
						Type: "STRING",
						Mode: "REPEATED",
					},
					FieldSnapshot{
						Name: "attachments",
						Type: "STRUCT",
						Mode: "REPEATED",
						Fields: []FieldSnapshot{
							{Name: "mime_type", Type: "STRING", Mode: "NULLABLE"},
						},
					},
				)
			},
			wantSubstring: "",
		},
		{
			name: "adding companion view and companion TVF is allowed",
			mutate: func(s *SchemaSnapshot) {
				s.CompanionViews = append(s.CompanionViews, "v_gen_ai_evals")
				s.CompanionTVFs = append(s.CompanionTVFs, "tvf_gen_ai_evals")
			},
			wantSubstring: "",
		},
		{
			name: "bumping schema.Version across alpha versions fails without AllowBreakingMajorTransition",
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0alpha3"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool {
					return f.Name == "trace_state"
				})
			},
			wantSubstring: "crosses a major or pre-1.0 boundary without AllowBreakingMajorTransition",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneSchemaSnapshot(t, baseline)
			tc.mutate(&candidate)
			violations := checkSchemaBackwardCompatibility(baseline, candidate)
			if tc.wantSubstring == "" {
				if len(violations) > 0 {
					t.Fatalf("unexpected backward-compatibility violations:\n  - %s", strings.Join(violations, "\n  - "))
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("expected violation containing %q, got none", tc.wantSubstring)
			}
			joined := strings.Join(violations, "\n")
			if !strings.Contains(joined, tc.wantSubstring) {
				t.Fatalf("violations = %q, want substring %q", joined, tc.wantSubstring)
			}
		})
	}
}

func TestCheckSchemaBackwardCompatibilitySemVer(t *testing.T) {
	baseV0, err := buildCurrentSchemaSnapshot()
	if err != nil {
		t.Fatalf("build baseline snapshot: %v", err)
	}
	baseV0Alpha3 := cloneSchemaSnapshot(t, baseV0)
	baseV0Alpha3.Version = "v0alpha3"
	baseV010 := cloneSchemaSnapshot(t, baseV0)
	baseV010.Version = "v0.1.0"
	baseV1 := cloneSchemaSnapshot(t, baseV0)
	baseV1.Version = "v1.0.0"

	findTable := func(s *SchemaSnapshot, name string) *TableSnapshot {
		for i := range s.Tables {
			if s.Tables[i].Name == name {
				return &s.Tables[i]
			}
		}
		t.Fatalf("table %q not found", name)
		return nil
	}
	findField := func(fields []FieldSnapshot, name string) *FieldSnapshot {
		for i := range fields {
			if fields[i].Name == name {
				return &fields[i]
			}
		}
		t.Fatalf("field %q not found", name)
		return nil
	}

	t.Run("parseSchemaVersion rejects malformed and accepts valid formats", func(t *testing.T) {
		for _, valid := range []string{"v0alpha1", "v0alpha2", "v0alpha10", "v0.1.0", "v0.1.1", "v1.0.0", "v1.2.3", "v2.0.0"} {
			if _, err := parseSchemaVersion(valid); err != nil {
				t.Errorf("parseSchemaVersion(%q) unexpected error: %v", valid, err)
			}
		}
		for _, invalid := range []string{"", "1.0.0", "v1.0", "v0alpha0", "v0alpha", "v01.0.0", "v1.0.-1", "v1.0.-0", "v+1.0.0", "v-0.1.0", "v0alpha+2", "v0alpha-1", "v1.0.0-beta"} {
			if _, err := parseSchemaVersion(invalid); err == nil {
				t.Errorf("parseSchemaVersion(%q) succeeded, want error", invalid)
			}
		}
	})

	cases := []struct {
		name          string
		baseline      SchemaSnapshot
		mutate        func(s *SchemaSnapshot)
		opts          compatibilityOptions
		wantSubstring string
	}{
		{
			name:     "v1.0.0 to v1.1.0 allows tail NULLABLE append",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_logs")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{Name: "custom_note", Type: "STRING", Mode: "NULLABLE"})
			},
		},
		{
			name:     "v1.0.0 to v1.1.0 allows REQUIRED to NULLABLE relaxation",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "insert_id")
				fld.Mode = "NULLABLE"
			},
		},
		{
			name:     "v1.0.0 to v1.1.0 allows additive companion view and TVF",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				s.CompanionViews = append(s.CompanionViews, "v_access_logs")
				s.CompanionTVFs = append(s.CompanionTVFs, "tvf_access_logs")
			},
		},
		{
			name:     "v1.0.0 to v1.1.0 forbids dropping column",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name:     "v1.0.0 to v1.1.0 forbids renaming column",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_spans")
				fld := findField(tbl.Fields, "trace_state")
				fld.Name = "trace_state_v2"
			},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name:     "v1.0.0 to v1.1.0 forbids changing column type",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "attributes")
				fld.Type = "STRING"
			},
			wantSubstring: "otel_logs.attributes: column type changed from JSON to STRING",
		},
		{
			name:     "v1.0.0 to v1.1.0 forbids tightening NULLABLE to REQUIRED",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "service_name")
				fld.Mode = "REQUIRED"
			},
			wantSubstring: "otel_logs.service_name: column mode changed from NULLABLE to REQUIRED",
		},
		{
			name:     "v1.0.0 to v1.1.0 forbids reordering columns",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.1.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields[0], tbl.Fields[1] = tbl.Fields[1], tbl.Fields[0]
			},
			wantSubstring: "column order changed relative to",
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump forbids adding NULLABLE column",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
				tbl := findTable(s, "otel_logs")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{Name: "patch_col", Type: "STRING", Mode: "NULLABLE"})
			},
			wantSubstring: "otel_logs.patch_col: newly added column is forbidden on a patch bump",
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump forbids REQUIRED to NULLABLE relaxation",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
				tbl := findTable(s, "otel_logs")
				fld := findField(tbl.Fields, "insert_id")
				fld.Mode = "NULLABLE"
			},
			wantSubstring: "otel_logs.insert_id: column mode changed from REQUIRED to NULLABLE",
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump forbids modifying companion view SQL digest",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
				s.CompanionViewDigests[GenAISpansViewName] = sqlDigestHex("SELECT 1")
			},
			wantSubstring: `companion_view_digests["v_gen_ai_spans"] SQL digest changed in patch bump v1.0.0 -> v1.0.1`,
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump forbids modifying dedup view SQL digest",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
				s.DedupViewDigests["otel_logs_dedup"] = sqlDigestHex("SELECT 1")
			},
			wantSubstring: `dedup_view_digests["otel_logs_dedup"] SQL digest changed in patch bump v1.0.0 -> v1.0.1`,
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump forbids modifying companion TVF SQL digest",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
				s.CompanionTVFDigests[GenAILogsTVFName] = sqlDigestHex("SELECT 1")
			},
			wantSubstring: `companion_tvf_digests["tvf_gen_ai_logs"] SQL digest changed in patch bump v1.0.0 -> v1.0.1`,
		},
		{
			name:     "v1.0.0 to v1.0.1 patch bump passes when contract is unchanged",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.1"
			},
		},
		{
			name:     "v1.0.0 to v2.0.0 fails without AllowBreakingMajorTransition",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v2.0.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			wantSubstring: "crosses a major or pre-1.0 boundary without AllowBreakingMajorTransition",
		},
		{
			name:     "v1.0.0 to v2.0.0 succeeds with AllowBreakingMajorTransition",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v2.0.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			opts: compatibilityOptions{AllowBreakingMajorTransition: true},
		},
		{
			name:     "v0alpha2 to v0alpha3 succeeds with AllowBreakingMajorTransition",
			baseline: baseV0,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0alpha3"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			opts: compatibilityOptions{AllowBreakingMajorTransition: true},
		},
		{
			name:     "v0alpha2 to v0.1.0 allows breaking with AllowBreakingMajorTransition",
			baseline: baseV0,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.1.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			opts: compatibilityOptions{AllowBreakingMajorTransition: true},
		},
		{
			name:     "v0alpha3 to v1.0.0 allows breaking with AllowBreakingMajorTransition",
			baseline: baseV0Alpha3,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v1.0.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			opts: compatibilityOptions{AllowBreakingMajorTransition: true},
		},
		{
			name:     "v0.1.0 to v0.1.1 numeric patch bump rejects column drop",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.1.1"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name:     "v0.1.0 to v0.1.1 numeric patch bump rejects column drop even with AllowBreakingMajorTransition",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.1.1"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			opts:          compatibilityOptions{AllowBreakingMajorTransition: true},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name:     "v0.1.0 to v0.1.1 numeric patch bump forbids adding NULLABLE column",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.1.1"
				tbl := findTable(s, "otel_logs")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{Name: "patch_col", Type: "STRING", Mode: "NULLABLE"})
			},
			wantSubstring: "otel_logs.patch_col: newly added column is forbidden on a patch bump",
		},
		{
			name:     "v0.1.0 to v0.1.1 numeric patch bump passes when contract is unchanged",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.1.1"
			},
		},
		{
			name:     "v0.1.0 to v0.2.0 numeric minor bump rejects column drop",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.2.0"
				tbl := findTable(s, "otel_spans")
				tbl.Fields = slices.DeleteFunc(tbl.Fields, func(f FieldSnapshot) bool { return f.Name == "trace_state" })
			},
			wantSubstring: "otel_spans.trace_state: column was removed",
		},
		{
			name:     "v0.1.0 to v0.2.0 numeric minor bump allows tail NULLABLE append",
			baseline: baseV010,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0.2.0"
				tbl := findTable(s, "otel_logs")
				tbl.Fields = append(tbl.Fields, FieldSnapshot{Name: "custom_note", Type: "STRING", Mode: "NULLABLE"})
			},
		},
		{
			name:     "version downgrade fails even with AllowBreakingMajorTransition",
			baseline: baseV1,
			mutate: func(s *SchemaSnapshot) {
				s.Version = "v0alpha3"
			},
			opts:          compatibilityOptions{AllowBreakingMajorTransition: true},
			wantSubstring: "schema version downgraded from v1.0.0 to v0alpha3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := cloneSchemaSnapshot(t, tc.baseline)
			tc.mutate(&candidate)
			violations := checkSchemaBackwardCompatibilityWithOptions(tc.baseline, candidate, tc.opts)
			if tc.wantSubstring == "" {
				if len(violations) > 0 {
					t.Fatalf("unexpected violations: %v", violations)
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("expected violation containing %q, got none", tc.wantSubstring)
			}
			if joined := strings.Join(violations, "\n"); !strings.Contains(joined, tc.wantSubstring) {
				t.Fatalf("violations = %q, want substring %q", joined, tc.wantSubstring)
			}
		})
	}
}
