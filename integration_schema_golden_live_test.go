// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/zap"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

type goldenSchemaContract struct {
	Version              string                `json:"version"`
	Tables               []goldenTableContract `json:"tables"`
	CompanionViews       []string              `json:"companion_views"`
	CompanionTVFs        []string              `json:"companion_tvfs"`
	DedupViewDigests     map[string]string     `json:"dedup_view_digests"`
	CompanionViewDigests map[string]string     `json:"companion_view_digests"`
	CompanionTVFDigests  map[string]string     `json:"companion_tvf_digests"`
}

type goldenTableContract struct {
	Name             string                     `json:"name"`
	Fields           []goldenFieldContract      `json:"fields"`
	TimePartitioning goldenPartitioningContract `json:"time_partitioning"`
	Clustering       []string                   `json:"clustering"`
	DedupView        string                     `json:"dedup_view,omitempty"`
	SearchIndex      *goldenSearchIndexContract `json:"search_index,omitempty"`
}

type goldenFieldContract struct {
	Name                   string                `json:"name"`
	Type                   string                `json:"type"`
	Mode                   string                `json:"mode"`
	MaxLength              int64                 `json:"max_length"`
	Precision              int64                 `json:"precision,omitempty"`
	Scale                  int64                 `json:"scale,omitempty"`
	DefaultValueExpression string                `json:"default_value_expression,omitempty"`
	TimestampPrecision     int64                 `json:"timestamp_precision,omitempty"`
	RangeElementType       string                `json:"range_element_type,omitempty"`
	Fields                 []goldenFieldContract `json:"fields,omitempty"`
}

type goldenPartitioningContract struct {
	Type                   string `json:"type"`
	Field                  string `json:"field"`
	RequirePartitionFilter bool   `json:"require_partition_filter"`
	ExpirationDays         int    `json:"expiration_days,omitempty"`
}

type goldenSearchIndexContract struct {
	Name       string   `json:"name"`
	Columns    []string `json:"columns,omitempty"`
	AllColumns bool     `json:"all_columns,omitempty"`
	Analyzer   string   `json:"analyzer"`
}

func (f goldenFieldContract) googleSQLDataType() string {
	base := f.Type
	switch {
	case f.Type == "STRUCT":
		parts := make([]string, 0, len(f.Fields))
		for _, child := range f.Fields {
			parts = append(parts, child.Name+" "+child.googleSQLDataType())
		}
		base = "STRUCT<" + strings.Join(parts, ", ") + ">"
	case f.Type == "RANGE" && f.RangeElementType != "":
		base = fmt.Sprintf("RANGE<%s>", f.RangeElementType)
	case (f.Type == "STRING" || f.Type == "BYTES") && f.MaxLength > 0:
		base = fmt.Sprintf("%s(%d)", f.Type, f.MaxLength)
	case (f.Type == "NUMERIC" || f.Type == "BIGNUMERIC") && f.Precision > 0:
		if f.Scale > 0 {
			base = fmt.Sprintf("%s(%d, %d)", f.Type, f.Precision, f.Scale)
		} else {
			base = fmt.Sprintf("%s(%d)", f.Type, f.Precision)
		}
	}
	if f.Mode == "REPEATED" {
		return "ARRAY<" + base + ">"
	}
	return base
}

func (f goldenFieldContract) expectedIsNullable() string {
	if f.Mode == "NULLABLE" {
		return "YES"
	}
	return "NO"
}

type goldenExpectedFieldPath struct {
	columnName string
	fieldPath  string
	dataType   string
}

func flattenGoldenFieldPaths(topFields []goldenFieldContract) []goldenExpectedFieldPath {
	var out []goldenExpectedFieldPath
	var walk func(rootCol, prefix string, fields []goldenFieldContract)
	walk = func(rootCol, prefix string, fields []goldenFieldContract) {
		for _, f := range fields {
			col := rootCol
			if col == "" {
				col = f.Name
			}
			path := f.Name
			if prefix != "" {
				path = prefix + "." + f.Name
			}
			out = append(out, goldenExpectedFieldPath{
				columnName: col,
				fieldPath:  path,
				dataType:   f.googleSQLDataType(),
			})
			if f.Type == "STRUCT" && len(f.Fields) > 0 {
				walk(col, path, f.Fields)
			}
		}
	}
	walk("", "", topFields)
	return out
}

func quotedBaseTableSQLList(tables []goldenTableContract) string {
	quoted := make([]string, 0, len(tables))
	for _, tbl := range tables {
		quoted = append(quoted, fmt.Sprintf("'%s'", tbl.Name))
	}
	return strings.Join(quoted, ", ")
}

func loadGoldenContractForIntegration(t *testing.T) goldenSchemaContract {
	t.Helper()
	goldenPath := filepath.Join("internal", "schema", "testdata", "v0alpha3_candidate_golden.json")
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden schema %s: %v", goldenPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var contract goldenSchemaContract
	if err := dec.Decode(&contract); err != nil {
		t.Fatalf("decode golden schema %s: %v", goldenPath, err)
	}
	if contract.Version != schema.Version {
		t.Fatalf("golden version = %q, want %q", contract.Version, schema.Version)
	}
	return contract
}

// resolveIntegrationQuotaProject returns an explicit quota project override
// only when requested via BQ_QUOTA_PROJECT or GOOGLE_CLOUD_QUOTA_PROJECT.
// Keyless Workload Identity Federation and service-account credentials omit
// quota_project_id, so returning empty preserves zero X-Goog-User-Project
// header injection for CI runners granted only roles/bigquery.user while
// keeping intentional cross-project ADC configurations intact.
func resolveIntegrationQuotaProject() string {
	for _, envKey := range []string{"BQ_QUOTA_PROJECT", "GOOGLE_CLOUD_QUOTA_PROJECT"} {
		if explicit := strings.TrimSpace(os.Getenv(envKey)); explicit != "" {
			return explicit
		}
	}
	return ""
}

// TestLiveBigQueryInformationSchemaMatchesGolden provisions a unique ephemeral
// dataset via auto_create, appends real Storage Write API rows across traces,
// logs, metrics, and quarantine, and verifies 1:1 parity between live BigQuery
// INFORMATION_SCHEMA metadata and internal/schema/testdata/v0alpha3_candidate_golden.json.
func TestLiveBigQueryInformationSchemaMatchesGolden(t *testing.T) {
	project := strings.TrimSpace(os.Getenv("BQ_PROJECT"))
	if project == "" {
		if strings.TrimSpace(os.Getenv("REQUIRE_LIVE_BQ")) == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live BigQuery INFORMATION_SCHEMA golden parity test")
	}
	location := strings.TrimSpace(os.Getenv("BQ_LOCATION"))
	if location == "" {
		location = "US"
	}

	golden := loadGoldenContractForIntegration(t)

	// Bound ctx under Go's default 10m test timeout so LIFO t.Cleanup always
	// deletes the owned ephemeral dataset even when -timeout is not raised.
	ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute+20*time.Second)
	// Register cancel first so LIFO t.Cleanup shuts down exporters, deletes
	// the owned ephemeral dataset, verifies deletion, and closes the client
	// before ctx is canceled.
	t.Cleanup(cancel)

	dataset := uniqueEphemeralDatasetID("otel_schema_golden_it")
	quotaProject := resolveIntegrationQuotaProject()
	t.Logf("provisioning ephemeral dataset %s.%s in %s", project, dataset, location)

	var httpOpts []option.ClientOption
	if quotaProject != "" {
		httpOpts = append(httpOpts, option.WithQuotaProject(quotaProject))
	}
	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, []string{bigqueryapi.BigqueryScope}, httpOpts...)
	if err != nil {
		t.Fatalf("create BigQuery HTTP client: %v", err)
	}
	admin, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery client: %v", err)
	}
	admin.Location = location
	t.Cleanup(func() {
		if closeErr := admin.Close(); closeErr != nil {
			t.Errorf("close BigQuery client: %v", closeErr)
		}
		closeHTTP()
	})

	var ownedDataset atomic.Bool
	// Registered before startAndRegisterColdStartCleanup so LIFO runs this
	// check immediately AFTER DeleteWithContents completes.
	t.Cleanup(func() {
		if !ownedDataset.Load() {
			return
		}
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer verifyCancel()
		_, metaErr := admin.Dataset(dataset).Metadata(verifyCtx)
		if metaErr == nil {
			t.Errorf("ephemeral dataset %s.%s still exists after cleanup", project, dataset)
			return
		}
		var apiErr *googleapi.Error
		if !errors.As(metaErr, &apiErr) || apiErr.Code != http.StatusNotFound {
			t.Errorf("verify deletion of ephemeral dataset %s.%s: got %v, want HTTP 404 NotFound", project, dataset, metaErr)
		}
	})

	cfg := validConfig()
	cfg.Project = project
	cfg.Dataset = dataset
	cfg.Location = location
	cfg.Credentials.QuotaProject = quotaProject
	cfg.AutoCreate.Dataset = true
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = true
	cfg.AutoCreate.SearchIndexes = true
	cfg.Quarantine.Enabled = true
	settings := component.TelemetrySettings{
		Logger:        zap.NewNop(),
		MeterProvider: noop.NewMeterProvider(),
	}

	traces, err := newTracesExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newTracesExporter: %v", err)
	}
	startAndRegisterColdStartCleanup(
		ctx,
		func(ctx context.Context) error { return traces.start(ctx, nil) },
		traces.signalExporter,
		t.Cleanup,
		func(err error) { t.Errorf("%v", err) },
		admin,
		dataset,
		func(format string, args ...any) {
			ownedDataset.Store(traces.createdDataset.Load())
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
			_ = traces.shutdown(shutCtx)
			shutCancel()
			t.Fatalf(format, args...)
		},
	)
	ownedDataset.Store(traces.createdDataset.Load())
	t.Cleanup(func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer shutCancel()
		if shutErr := traces.shutdown(shutCtx); shutErr != nil {
			t.Errorf("traces shutdown: %v", shutErr)
		}
	})
	if !traces.createdDataset.Load() {
		t.Fatalf("expected cold-created dataset %s.%s (createdDataset=false)", project, dataset)
	}

	logs, err := newLogsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newLogsExporter: %v", err)
	}
	if err := logs.start(ctx, nil); err != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = logs.shutdown(shutCtx)
		shutCancel()
		t.Fatalf("logs start: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer shutCancel()
		if shutErr := logs.shutdown(shutCtx); shutErr != nil {
			t.Errorf("logs shutdown: %v", shutErr)
		}
	})

	metrics, err := newMetricsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newMetricsExporter: %v", err)
	}
	if err := metrics.start(ctx, nil); err != nil {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
		_ = metrics.shutdown(shutCtx)
		shutCancel()
		t.Fatalf("metrics start: %v", err)
	}
	t.Cleanup(func() {
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer shutCancel()
		if shutErr := metrics.shutdown(shutCtx); shutErr != nil {
			t.Errorf("metrics shutdown: %v", shutErr)
		}
	})

	// Provision the three bounded-window companion TVFs alongside the
	// auto-created tables, dedup views, companion views, and search indexes.
	for tvfName, ddl := range schema.CompanionTVFDDLs(project, dataset, cfg.Traces.Table, cfg.Logs.Table) {
		job, runErr := admin.Query(ddl).Run(ctx)
		if runErr != nil {
			t.Fatalf("create TVF %s: %v", tvfName, runErr)
		}
		st, waitErr := job.Wait(ctx)
		if waitErr != nil {
			t.Fatalf("wait TVF %s: %v", tvfName, waitErr)
		}
		if stErr := st.Err(); stErr != nil {
			t.Fatalf("TVF %s DDL status: %v", tvfName, stErr)
		}
	}

	now := time.Now().UTC()
	if err := traces.pushTraceData(ctx, buildGoldenParityTraces(now)); err != nil {
		t.Fatalf("pushTraceData: %v", err)
	}
	if err := logs.pushLogData(ctx, buildGoldenParityLogs(now)); err != nil {
		t.Fatalf("pushLogData: %v", err)
	}
	if err := metrics.pushMetricsData(ctx, buildGoldenParityMetrics(now)); err != nil {
		t.Fatalf("pushMetricsData: %v", err)
	}

	for _, tbl := range []string{cfg.Traces.Table, cfg.Logs.Table, cfg.Metrics.Table, cfg.Quarantine.Table} {
		if err := waitForRows(ctx, admin, project, dataset, tbl); err != nil {
			t.Fatalf("waitForRows(%s): %v", tbl, err)
		}
	}

	assertLiveColumnsAndFieldPaths(ctx, t, admin, project, dataset, golden)
	assertLiveSearchIndexesMatchGolden(ctx, t, admin, project, dataset, golden)
	assertLiveViewsAndRoutinesMatchGolden(ctx, t, admin, project, dataset, golden)
	assertLiveTablesLayoutAndPartitions(ctx, t, admin, project, dataset, cfg, golden)
}

func buildGoldenParityTraces(now time.Time) ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "golden-parity-svc")
	spans := rs.ScopeSpans().AppendEmpty().Spans()

	valid := spans.AppendEmpty()
	valid.SetName("chat golden-model")
	valid.SetTraceID(pcommon.TraceID{1})
	valid.SetSpanID(pcommon.SpanID{1})
	valid.SetStartTimestamp(pcommon.NewTimestampFromTime(now.Add(-500 * time.Millisecond)))
	valid.SetEndTimestamp(pcommon.NewTimestampFromTime(now))
	valid.Status().SetCode(ptrace.StatusCodeOk)
	attrs := valid.Attributes()
	attrs.PutStr("gen_ai.operation.name", "chat")
	attrs.PutStr("gen_ai.system", "test.genai")
	attrs.PutStr("gen_ai.provider.name", "test.genai")
	attrs.PutStr("gen_ai.request.model", "test-model-1")
	attrs.PutStr("gen_ai.response.model", "test-model-1")
	attrs.PutStr("gen_ai.agent.name", "golden-planner")
	attrs.PutStr("gen_ai.conversation.id", "sess-golden-1")
	attrs.PutStr("gen_ai.tool.name", "lookup_schema")
	attrs.PutStr("mcp.method.name", "tools/call")
	attrs.PutInt("gen_ai.usage.input_tokens", 12)
	attrs.PutInt("gen_ai.usage.output_tokens", 6)

	// Zero TraceID and SpanID triggers pre-append rejection so a real row is
	// written via Storage Write API to otel_quarantine as well.
	quarantined := spans.AppendEmpty()
	quarantined.SetName("invalid-span-for-quarantine")
	quarantined.SetStartTimestamp(pcommon.NewTimestampFromTime(now.Add(-100 * time.Millisecond)))
	quarantined.SetEndTimestamp(pcommon.NewTimestampFromTime(now))

	return td
}

func buildGoldenParityLogs(now time.Time) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "golden-parity-svc")
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(pcommon.NewTimestampFromTime(now))
	rec.SetEventName("gen_ai.choice")
	rec.SetTraceID(pcommon.TraceID{1})
	rec.SetSpanID(pcommon.SpanID{1})
	rec.Attributes().PutStr("gen_ai.system", "test.genai")
	rec.Body().SetStr("golden schema parity log")
	return ld
}

func buildGoldenParityMetrics(now time.Time) pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "golden-parity-svc")
	m := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName("gen_ai.client.inference.usage.input_tokens")
	m.SetUnit("{token}")
	sum := m.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	sum.SetIsMonotonic(true)
	dp := sum.DataPoints().AppendEmpty()
	dp.SetStartTimestamp(pcommon.NewTimestampFromTime(now.Add(-time.Second)))
	dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
	dp.SetIntValue(12)
	dp.Attributes().PutStr("gen_ai.system", "test.genai")
	dp.Attributes().PutStr("gen_ai.agent.name", "golden-planner")
	dp.Attributes().PutStr("gen_ai.token.modality", "text")
	ex := dp.Exemplars().AppendEmpty()
	ex.SetTimestamp(pcommon.NewTimestampFromTime(now))
	ex.SetIntValue(12)
	ex.SetTraceID(pcommon.TraceID{1})
	ex.SetSpanID(pcommon.SpanID{1})
	return md
}

func assertLiveTablesLayoutAndPartitions(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	project, dataset string,
	cfg *Config,
	golden goldenSchemaContract,
) {
	t.Helper()
	baseTableFilter := quotedBaseTableSQLList(golden.Tables)

	type liveTableInfo struct {
		tableType string
		ddl       string
	}
	tablesByName := make(map[string]liveTableInfo)
	tblRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, table_type, ddl FROM `%s.%s.INFORMATION_SCHEMA.TABLES`",
		project, dataset,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.TABLES: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := tblRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.TABLES: %v", nextErr)
		}
		name, _ := vals[0].(string)
		ttype, _ := vals[1].(string)
		ddl, _ := vals[2].(string)
		tablesByName[name] = liveTableInfo{tableType: ttype, ddl: ddl}
	}

	gotBaseTables := make([]string, 0, len(golden.Tables))
	for name, info := range tablesByName {
		if info.tableType == "BASE TABLE" {
			gotBaseTables = append(gotBaseTables, name)
		}
	}
	slices.Sort(gotBaseTables)

	wantBaseTables := make([]string, 0, len(golden.Tables))
	for _, tbl := range golden.Tables {
		wantBaseTables = append(wantBaseTables, tbl.Name)
	}
	slices.Sort(wantBaseTables)
	if !slices.Equal(gotBaseTables, wantBaseTables) {
		t.Fatalf("INFORMATION_SCHEMA.TABLES base tables = %v, want %v", gotBaseTables, wantBaseTables)
	}

	optionsByTable := make(map[string]map[string]string)
	optRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, option_name, option_value FROM `%s.%s.INFORMATION_SCHEMA.TABLE_OPTIONS` WHERE table_name IN (%s)",
		project, dataset, baseTableFilter,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.TABLE_OPTIONS: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := optRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.TABLE_OPTIONS: %v", nextErr)
		}
		tbl, _ := vals[0].(string)
		optName, _ := vals[1].(string)
		optVal, _ := vals[2].(string)
		if optionsByTable[tbl] == nil {
			optionsByTable[tbl] = make(map[string]string)
		}
		optionsByTable[tbl][optName] = optVal
	}

	partitionsByTable := loadOrMaterializeLivePartitions(ctx, t, client, project, dataset, cfg, golden.Tables, baseTableFilter)

	for _, wantTbl := range golden.Tables {
		info := tablesByName[wantTbl.Name]
		var wantPartClause string
		switch wantTbl.TimePartitioning.Type {
		case "HOUR":
			wantPartClause = fmt.Sprintf("PARTITION BY TIMESTAMP_TRUNC(%s, HOUR)", wantTbl.TimePartitioning.Field)
		case "DAY":
			wantPartClause = fmt.Sprintf("PARTITION BY DATE(%s)", wantTbl.TimePartitioning.Field)
		default:
			t.Fatalf("table %s: unsupported golden partition type %q", wantTbl.Name, wantTbl.TimePartitioning.Type)
		}
		if !strings.Contains(info.ddl, wantPartClause) {
			t.Errorf("table %s INFORMATION_SCHEMA.TABLES.ddl missing %q:\n%s", wantTbl.Name, wantPartClause, info.ddl)
		}

		wantClusterClause := "CLUSTER BY " + strings.Join(wantTbl.Clustering, ", ")
		if !strings.Contains(info.ddl, wantClusterClause) {
			t.Errorf("table %s INFORMATION_SCHEMA.TABLES.ddl missing %q:\n%s", wantTbl.Name, wantClusterClause, info.ddl)
		}

		opts := optionsByTable[wantTbl.Name]
		gotRPF := strings.EqualFold(strings.TrimSpace(opts["require_partition_filter"]), "true")
		if gotRPF != wantTbl.TimePartitioning.RequirePartitionFilter {
			t.Errorf(
				"table %s require_partition_filter = %t (raw %q), want %t",
				wantTbl.Name, gotRPF, opts["require_partition_filter"], wantTbl.TimePartitioning.RequirePartitionFilter,
			)
		}

		rawExp := strings.TrimSpace(opts["partition_expiration_days"])
		if wantTbl.TimePartitioning.ExpirationDays == 0 {
			if rawExp != "" {
				t.Errorf("table %s partition_expiration_days = %q, want unset", wantTbl.Name, rawExp)
			}
		} else {
			parsedExp, parseErr := strconv.ParseFloat(rawExp, 64)
			if parseErr != nil || math.Abs(parsedExp-float64(wantTbl.TimePartitioning.ExpirationDays)) > 1e-6 {
				t.Errorf(
					"table %s partition_expiration_days = %q, want %d",
					wantTbl.Name, rawExp, wantTbl.TimePartitioning.ExpirationDays,
				)
			}
		}

		parts := partitionsByTable[wantTbl.Name]
		if len(parts) == 0 {
			t.Errorf("table %s has 0 rows in INFORMATION_SCHEMA.PARTITIONS after live write", wantTbl.Name)
			continue
		}
		wantPIDLen := 8
		if wantTbl.TimePartitioning.Type == "HOUR" {
			wantPIDLen = 10
		}
		matchedConcretePartition := false
		for _, p := range parts {
			if p.partitionID == "__STREAMING_UNPARTITIONED__" || p.partitionID == "__NULL__" {
				continue
			}
			if len(p.partitionID) != wantPIDLen || !isAllASCIIDigits(p.partitionID) {
				t.Errorf(
					"table %s partition_id = %q, want %d-digit %s partition ID",
					wantTbl.Name, p.partitionID, wantPIDLen, wantTbl.TimePartitioning.Type,
				)
				continue
			}
			if p.totalRows >= 1 {
				matchedConcretePartition = true
			}
		}
		if !matchedConcretePartition {
			t.Errorf(
				"table %s INFORMATION_SCHEMA.PARTITIONS rows = %+v, want >= 1 materialized %d-digit %s partition",
				wantTbl.Name, parts, wantPIDLen, wantTbl.TimePartitioning.Type,
			)
		}
	}
}

type livePartitionRow struct {
	partitionID string
	totalRows   int64
}

// loadOrMaterializeLivePartitions reads INFORMATION_SCHEMA.PARTITIONS and, when
// Storage Write API rows are still buffered in write-optimized streaming
// storage prior to asynchronous Capacitor compaction, executes a minimal DML
// INSERT across the four base tables so BigQuery materializes concrete
// Capacitor partition metadata immediately without multi-minute compaction
// waits. All Storage Write API view/TVF checks have already completed before
// this helper runs.
func loadOrMaterializeLivePartitions(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	project, dataset string,
	cfg *Config,
	tables []goldenTableContract,
	baseTableFilter string,
) map[string][]livePartitionRow {
	t.Helper()
	readOnce := func() map[string][]livePartitionRow {
		partitionsByTable := make(map[string][]livePartitionRow, len(tables))
		partRows, err := client.Query(fmt.Sprintf(
			"SELECT table_name, partition_id, total_rows FROM `%s.%s.INFORMATION_SCHEMA.PARTITIONS` WHERE table_name IN (%s)",
			project, dataset, baseTableFilter,
		)).Read(ctx)
		if err != nil {
			t.Fatalf("query INFORMATION_SCHEMA.PARTITIONS: %v", err)
		}
		for {
			var vals []bq.Value
			nextErr := partRows.Next(&vals)
			if errors.Is(nextErr, iterator.Done) {
				break
			}
			if nextErr != nil {
				t.Fatalf("read INFORMATION_SCHEMA.PARTITIONS: %v", nextErr)
			}
			tbl, _ := vals[0].(string)
			pid, _ := vals[1].(string)
			total, _ := vals[2].(int64)
			partitionsByTable[tbl] = append(partitionsByTable[tbl], livePartitionRow{
				partitionID: pid,
				totalRows:   total,
			})
		}
		return partitionsByTable
	}

	hasConcretePartition := func(rows []livePartitionRow) bool {
		for _, r := range rows {
			if isAllASCIIDigits(r.partitionID) && r.totalRows >= 1 {
				return true
			}
		}
		return false
	}

	initial := readOnce()
	allConcrete := true
	for _, tbl := range tables {
		if !hasConcretePartition(initial[tbl.Name]) {
			allConcrete = false
			break
		}
	}
	if allConcrete {
		return initial
	}

	materializeSQL := fmt.Sprintf(`
		INSERT INTO `+"`%s.%s.%s`"+` (
			start_time, start_time_unix_nano, end_time, end_time_unix_nano,
			receive_time, receive_time_unix_nano, duration_nano,
			trace_id, span_id, name, kind, service_name
		) VALUES (
			CURRENT_TIMESTAMP(), 1000, CURRENT_TIMESTAMP(), 2000,
			CURRENT_TIMESTAMP(), 3000, 1000,
			'f1f2f3f4f5f6f7f8f9fafbfcfdfeff00', 'f1f2f3f4f5f6f7f8',
			'partition-probe', 1, 'golden-parity-svc'
		);
		INSERT INTO `+"`%s.%s.%s`"+` (
			timestamp, timestamp_source, time_unix_nano, observed_time_unix_nano,
			receive_time, receive_time_unix_nano, log_name, insert_id, service_name
		) VALUES (
			CURRENT_TIMESTAMP(), 'event_time', 1000, 1000,
			CURRENT_TIMESTAMP(), 3000, 'otel', 'partition-probe-log', 'golden-parity-svc'
		);
		INSERT INTO `+"`%s.%s.%s`"+` (
			timestamp, time_unix_nano, receive_time, receive_time_unix_nano,
			service_name, metric_name, metric_type, point_fingerprint
		) VALUES (
			CURRENT_TIMESTAMP(), 1000, CURRENT_TIMESTAMP(), 3000,
			'golden-parity-svc', 'otel.partition.probe', 'SUM', 'fp1:partition-probe'
		);
		INSERT INTO `+"`%s.%s.%s`"+` (
			ingest_time, signal, error_code, error_message, service_name
		) VALUES (
			CURRENT_TIMESTAMP(), 'traces', 'PARTITION_PROBE', 'probe row', 'golden-parity-svc'
		);
	`,
		project, dataset, cfg.Traces.Table,
		project, dataset, cfg.Logs.Table,
		project, dataset, cfg.Metrics.Table,
		project, dataset, cfg.Quarantine.Table,
	)
	job, err := client.Query(materializeSQL).Run(ctx)
	if err != nil {
		t.Fatalf("materialize partitions DML: %v", err)
	}
	st, err := job.Wait(ctx)
	if err != nil {
		t.Fatalf("wait materialize partitions DML: %v", err)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("materialize partitions DML status: %v", err)
	}
	return readOnce()
}

func isAllASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func assertLiveColumnsAndFieldPaths(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	project, dataset string,
	golden goldenSchemaContract,
) {
	t.Helper()
	baseTableFilter := quotedBaseTableSQLList(golden.Tables)

	type liveColumn struct {
		name              string
		ordinal           int64
		isNullable        string
		dataType          string
		isPartitioningCol string
		clusteringOrdinal int64
	}
	colsByTable := make(map[string][]liveColumn)
	colRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, column_name, ordinal_position, is_nullable, data_type, is_partitioning_column, clustering_ordinal_position "+
			"FROM `%s.%s.INFORMATION_SCHEMA.COLUMNS` WHERE table_name IN (%s) ORDER BY table_name, ordinal_position",
		project, dataset, baseTableFilter,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.COLUMNS: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := colRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.COLUMNS: %v", nextErr)
		}
		tbl, _ := vals[0].(string)
		colName, _ := vals[1].(string)
		ord, _ := vals[2].(int64)
		nullable, _ := vals[3].(string)
		dtype, _ := vals[4].(string)
		isPart, _ := vals[5].(string)
		var clusterOrd int64
		if vals[6] != nil {
			clusterOrd, _ = vals[6].(int64)
		}
		colsByTable[tbl] = append(colsByTable[tbl], liveColumn{
			name:              colName,
			ordinal:           ord,
			isNullable:        nullable,
			dataType:          dtype,
			isPartitioningCol: isPart,
			clusteringOrdinal: clusterOrd,
		})
	}

	pathsByTable := make(map[string]map[string]goldenExpectedFieldPath)
	fpRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, column_name, field_path, data_type "+
			"FROM `%s.%s.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` WHERE table_name IN (%s)",
		project, dataset, baseTableFilter,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.COLUMN_FIELD_PATHS: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := fpRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.COLUMN_FIELD_PATHS: %v", nextErr)
		}
		tbl, _ := vals[0].(string)
		colName, _ := vals[1].(string)
		fpath, _ := vals[2].(string)
		dtype, _ := vals[3].(string)
		if pathsByTable[tbl] == nil {
			pathsByTable[tbl] = make(map[string]goldenExpectedFieldPath)
		}
		pathsByTable[tbl][fpath] = goldenExpectedFieldPath{
			columnName: colName,
			fieldPath:  fpath,
			dataType:   dtype,
		}
	}

	for _, wantTbl := range golden.Tables {
		gotCols := colsByTable[wantTbl.Name]
		if len(gotCols) != len(wantTbl.Fields) {
			t.Fatalf(
				"table %s INFORMATION_SCHEMA.COLUMNS count = %d, want %d",
				wantTbl.Name, len(gotCols), len(wantTbl.Fields),
			)
		}

		wantClusterOrd := make(map[string]int64, len(wantTbl.Clustering))
		for idx, c := range wantTbl.Clustering {
			wantClusterOrd[c] = int64(idx + 1)
		}

		for i, wantFld := range wantTbl.Fields {
			got := gotCols[i]
			wantOrd := int64(i + 1)
			if got.ordinal != wantOrd {
				t.Errorf("table %s col[%d] ordinal_position = %d, want %d", wantTbl.Name, i, got.ordinal, wantOrd)
			}
			if got.name != wantFld.Name {
				t.Errorf("table %s col[%d] column_name = %q, want %q", wantTbl.Name, i, got.name, wantFld.Name)
			}
			wantType := wantFld.googleSQLDataType()
			if got.dataType != wantType {
				t.Errorf("table %s.%s data_type = %q, want %q", wantTbl.Name, wantFld.Name, got.dataType, wantType)
			}
			wantNull := wantFld.expectedIsNullable()
			if got.isNullable != wantNull {
				t.Errorf("table %s.%s is_nullable = %q, want %q (mode %s)", wantTbl.Name, wantFld.Name, got.isNullable, wantNull, wantFld.Mode)
			}
			wantPart := "NO"
			if wantFld.Name == wantTbl.TimePartitioning.Field {
				wantPart = "YES"
			}
			if got.isPartitioningCol != wantPart {
				t.Errorf("table %s.%s is_partitioning_column = %q, want %q", wantTbl.Name, wantFld.Name, got.isPartitioningCol, wantPart)
			}
			if got.clusteringOrdinal != wantClusterOrd[wantFld.Name] {
				t.Errorf(
					"table %s.%s clustering_ordinal_position = %d, want %d",
					wantTbl.Name, wantFld.Name, got.clusteringOrdinal, wantClusterOrd[wantFld.Name],
				)
			}
		}

		wantPaths := flattenGoldenFieldPaths(wantTbl.Fields)
		gotPaths := maps.Clone(pathsByTable[wantTbl.Name])
		if gotPaths == nil {
			gotPaths = make(map[string]goldenExpectedFieldPath)
		}
		for _, wp := range wantPaths {
			gp, ok := gotPaths[wp.fieldPath]
			if !ok {
				t.Errorf("table %s missing field_path %q in INFORMATION_SCHEMA.COLUMN_FIELD_PATHS", wantTbl.Name, wp.fieldPath)
				continue
			}
			if gp.columnName != wp.columnName {
				t.Errorf("table %s field_path %q column_name = %q, want %q", wantTbl.Name, wp.fieldPath, gp.columnName, wp.columnName)
			}
			if gp.dataType != wp.dataType {
				t.Errorf("table %s field_path %q data_type = %q, want %q", wantTbl.Name, wp.fieldPath, gp.dataType, wp.dataType)
			}
			delete(gotPaths, wp.fieldPath)
		}
		if len(gotPaths) > 0 {
			extra := make([]string, 0, len(gotPaths))
			for k := range gotPaths {
				extra = append(extra, k)
			}
			slices.Sort(extra)
			t.Errorf("table %s has unexpected field_paths in INFORMATION_SCHEMA.COLUMN_FIELD_PATHS: %v", wantTbl.Name, extra)
		}
	}
}

func assertLiveSearchIndexesMatchGolden(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	project, dataset string,
	golden goldenSchemaContract,
) {
	t.Helper()

	type liveSearchIndex struct {
		name   string
		status string
		ddl    string
	}
	gotByTable := make(map[string]liveSearchIndex)
	rows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, index_name, index_status, ddl FROM `%s.%s.INFORMATION_SCHEMA.SEARCH_INDEXES`",
		project, dataset,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.SEARCH_INDEXES: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := rows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.SEARCH_INDEXES: %v", nextErr)
		}
		tbl, _ := vals[0].(string)
		idxName, _ := vals[1].(string)
		status, _ := vals[2].(string)
		ddl, _ := vals[3].(string)
		gotByTable[tbl] = liveSearchIndex{name: idxName, status: status, ddl: ddl}
	}

	colRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, index_name, index_column_name FROM `%s.%s.INFORMATION_SCHEMA.SEARCH_INDEX_COLUMNS`",
		project, dataset,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.SEARCH_INDEX_COLUMNS: %v", err)
	}
	indexedColsByTable := make(map[string][]string)
	for {
		var vals []bq.Value
		nextErr := colRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.SEARCH_INDEX_COLUMNS: %v", nextErr)
		}
		tbl, _ := vals[0].(string)
		col, _ := vals[2].(string)
		if !slices.Contains(indexedColsByTable[tbl], col) {
			indexedColsByTable[tbl] = append(indexedColsByTable[tbl], col)
		}
	}

	for _, wantTbl := range golden.Tables {
		got, exists := gotByTable[wantTbl.Name]
		if wantTbl.SearchIndex == nil {
			if exists {
				t.Errorf("table %s has unexpected search index %q", wantTbl.Name, got.name)
			}
			continue
		}
		if !exists {
			t.Errorf("table %s missing expected search index %q", wantTbl.Name, wantTbl.SearchIndex.Name)
			continue
		}
		if got.name != wantTbl.SearchIndex.Name {
			t.Errorf("table %s search index name = %q, want %q", wantTbl.Name, got.name, wantTbl.SearchIndex.Name)
		}
		if got.status != "ACTIVE" && got.status != "PENDING" && got.status != "TEMPORARILY DISABLED" {
			t.Errorf("table %s search index status = %q, want ACTIVE/PENDING/TEMPORARILY DISABLED", wantTbl.Name, got.status)
		}
		if !strings.Contains(got.ddl, wantTbl.SearchIndex.Analyzer) {
			t.Errorf("table %s search index DDL %q missing analyzer %q", wantTbl.Name, got.ddl, wantTbl.SearchIndex.Analyzer)
		}
		if wantTbl.SearchIndex.AllColumns {
			if !strings.Contains(strings.ToUpper(got.ddl), "ALL COLUMNS") {
				t.Errorf("table %s search index DDL %q missing ALL COLUMNS", wantTbl.Name, got.ddl)
			}
		} else {
			gotCols := slices.Clone(indexedColsByTable[wantTbl.Name])
			slices.Sort(gotCols)
			wantCols := slices.Clone(wantTbl.SearchIndex.Columns)
			slices.Sort(wantCols)
			if !slices.Equal(gotCols, wantCols) {
				t.Errorf("table %s SEARCH_INDEX_COLUMNS = %v, want %v", wantTbl.Name, gotCols, wantCols)
			}
		}
		delete(gotByTable, wantTbl.Name)
	}
	if len(gotByTable) > 0 {
		t.Errorf("unexpected extra search indexes in INFORMATION_SCHEMA.SEARCH_INDEXES: %+v", gotByTable)
	}
}

func assertLiveViewsAndRoutinesMatchGolden(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	project, dataset string,
	golden goldenSchemaContract,
) {
	t.Helper()

	wantViews := make([]string, 0, len(golden.CompanionViews)+len(golden.Tables))
	wantViews = append(wantViews, golden.CompanionViews...)
	for _, tbl := range golden.Tables {
		if tbl.DedupView != "" {
			wantViews = append(wantViews, tbl.DedupView)
		}
	}
	slices.Sort(wantViews)

	gotViews := make([]string, 0, len(wantViews))
	viewRows, err := client.Query(fmt.Sprintf(
		"SELECT table_name, view_definition FROM `%s.%s.INFORMATION_SCHEMA.VIEWS`",
		project, dataset,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.VIEWS: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := viewRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.VIEWS: %v", nextErr)
		}
		vname, _ := vals[0].(string)
		vdef, _ := vals[1].(string)
		if strings.TrimSpace(vdef) == "" {
			t.Errorf("view %s has empty view_definition in INFORMATION_SCHEMA.VIEWS", vname)
		}
		gotViews = append(gotViews, vname)
	}
	slices.Sort(gotViews)
	if !slices.Equal(gotViews, wantViews) {
		t.Fatalf("INFORMATION_SCHEMA.VIEWS = %v, want %v", gotViews, wantViews)
	}

	for _, viewName := range wantViews {
		whereClause := viewLiveFilterClause(viewName)
		sql := fmt.Sprintf("SELECT * FROM `%s.%s.%s` WHERE %s LIMIT 1", project, dataset, viewName, whereClause)
		count, qErr := executeAndCountRows(ctx, client, sql)
		if qErr != nil {
			t.Errorf("live execution of view %s failed: %v\nSQL: %s", viewName, qErr, sql)
			continue
		}
		if count < 1 {
			t.Errorf("live execution of view %s returned %d rows, want >= 1 from seeded telemetry", viewName, count)
		}
	}

	wantTVFs := slices.Clone(golden.CompanionTVFs)
	slices.Sort(wantTVFs)

	gotTVFs := make([]string, 0, len(wantTVFs))
	routineRows, err := client.Query(fmt.Sprintf(
		"SELECT routine_name, routine_type, ddl FROM `%s.%s.INFORMATION_SCHEMA.ROUTINES`",
		project, dataset,
	)).Read(ctx)
	if err != nil {
		t.Fatalf("query INFORMATION_SCHEMA.ROUTINES: %v", err)
	}
	for {
		var vals []bq.Value
		nextErr := routineRows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			break
		}
		if nextErr != nil {
			t.Fatalf("read INFORMATION_SCHEMA.ROUTINES: %v", nextErr)
		}
		rname, _ := vals[0].(string)
		rtype, _ := vals[1].(string)
		rddl, _ := vals[2].(string)
		if rtype != "TABLE FUNCTION" {
			t.Errorf("routine %s routine_type = %q, want TABLE FUNCTION", rname, rtype)
		}
		if strings.TrimSpace(rddl) == "" {
			t.Errorf("routine %s has empty ddl in INFORMATION_SCHEMA.ROUTINES", rname)
		}
		gotTVFs = append(gotTVFs, rname)
	}
	slices.Sort(gotTVFs)
	if !slices.Equal(gotTVFs, wantTVFs) {
		t.Fatalf("INFORMATION_SCHEMA.ROUTINES = %v, want %v", gotTVFs, wantTVFs)
	}

	execTVFs := slices.Clone(wantTVFs)
	slices.SortFunc(execTVFs, func(a, b string) int {
		if a == schema.GenAIAgentTrajectoryTVFName && b != schema.GenAIAgentTrajectoryTVFName {
			return 1
		}
		if b == schema.GenAIAgentTrajectoryTVFName && a != schema.GenAIAgentTrajectoryTVFName {
			return -1
		}
		return strings.Compare(a, b)
	})
	for _, tvfName := range execTVFs {
		callArgs := "TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR), TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE)"
		if tvfName == schema.GenAIAgentTrajectoryTVFName {
			callArgs = "TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR), TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 5 MINUTE), " +
				"TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR), TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)"
		}
		sql := fmt.Sprintf(
			"SELECT * FROM `%s.%s.%s`(%s) WHERE service_name IS NOT NULL LIMIT 1",
			project, dataset, tvfName, callArgs,
		)
		startTVF := time.Now()
		count, qErr := executeAndCountRows(ctx, client, sql)
		t.Logf("TVF %s live SELECT completed in %s (rows=%d, err=%v)", tvfName, time.Since(startTVF).Round(time.Millisecond), count, qErr)
		if qErr != nil {
			t.Errorf("live execution of TVF %s failed: %v\nSQL: %s", tvfName, qErr, sql)
			continue
		}
		if count < 1 {
			t.Errorf("live execution of TVF %s returned %d rows, want >= 1 from seeded telemetry", tvfName, count)
		}
	}
}

func viewLiveFilterClause(viewName string) string {
	switch viewName {
	case "otel_spans_dedup",
		schema.SpansAsAllSpansViewName,
		schema.GenAISpansViewName,
		schema.GenAIAgentTrajectoryViewName,
		schema.MCPSpansViewName:
		return "start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR)"
	case "otel_logs_dedup",
		"otel_metrics_dedup",
		schema.LogsAsAllLogsViewName,
		schema.GenAILogsViewName,
		schema.GenAIMetricsViewName:
		return "timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR)"
	case schema.GenAIMetricExemplarsViewName:
		return "metric_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR)"
	case schema.GenAIModelCostsViewName,
		schema.GenAIToolUsageViewName,
		schema.MCPToolUsageViewName:
		return "usage_hour >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR)"
	case schema.GenAISessionsViewName:
		return "session_start_date >= DATE_SUB(CURRENT_DATE(), INTERVAL 2 DAY)"
	default:
		return "TRUE"
	}
}

func executeAndCountRows(ctx context.Context, client *bq.Client, sql string) (int, error) {
	rows, err := client.Query(sql).Read(ctx)
	if err != nil {
		return 0, err
	}
	count := 0
	for {
		var vals []bq.Value
		nextErr := rows.Next(&vals)
		if errors.Is(nextErr, iterator.Done) {
			return count, nil
		}
		if nextErr != nil {
			return count, nextErr
		}
		count++
	}
}
