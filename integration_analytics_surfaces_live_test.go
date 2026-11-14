// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// TestLiveAnalyticsDataformAndDashboardsBigQuery executes all shipped analytics
// SQL surfaces (Dataform full-refresh, incremental, and assertions; Looker Studio
// custom queries and report_spec.yaml schema alignment; Grafana BigQuery panels
// and self-telemetry Prometheus queries) against real BigQuery data seeded via
// NewFactory().
func TestLiveAnalyticsDataformAndDashboardsBigQuery(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live analytics surfaces test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)

	env := newAnalyticsLiveEnv(ctx, t, project, location)
	exps := env.startExporters(ctx, t)
	env.provisionTVFsAndAlerts(ctx, t)
	env.seedBatch1AndWait(ctx, t, exps)

	t.Run("DataformFullRefreshAndIncrementalDAG", func(t *testing.T) {
		env.verifyDataformDAGAndAssertions(ctx, t, exps)
	})
	t.Run("LookerStudioQueriesExecuteAndMatchMarts", func(t *testing.T) {
		env.verifyLookerStudioSurfaces(ctx, t, exps)
	})
	t.Run("GrafanaDashboardsMatchLiveViewsAndSelfTelemetry", func(t *testing.T) {
		env.verifyGrafanaBigQueryAndPrometheus(ctx, t, exps)
	})
}

type analyticsLiveEnv struct {
	project        string
	location       string
	srcDataset     string
	martDataset    string
	assertDataset  string
	runID          string
	now            time.Time
	todayMidnight  time.Time
	recentBase     time.Time
	svcPrimary     string
	svcMidnight    string
	svcEmptyUser   string
	secretMarker   string
	srcCreated     bool
	batch2Seeded   bool
	martsPopulated bool
	admin          *bq.Client
	reader         *sdkmetric.ManualReader
}

type analyticsLiveExporters struct {
	traces  exporter.Traces
	logs    exporter.Logs
	metrics exporter.Metrics
}

func newAnalyticsLiveEnv(ctx context.Context, t *testing.T, project, location string) *analyticsLiveEnv {
	t.Helper()
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("random run ID: %v", err)
	}
	runID := hex.EncodeToString(nonce[:])

	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, []string{bigqueryapi.BigqueryScope})
	if err != nil {
		t.Fatalf("create BigQuery HTTP client: %v", err)
	}
	admin, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery client: %v", err)
	}
	// Register closing admin/HTTP first so LIFO cleanups delete datasets first.
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close BigQuery client: %v", err)
		}
		closeHTTP()
	})

	now := time.Now().UTC().Truncate(time.Millisecond)
	todayMidnight := now.Truncate(24 * time.Hour)
	// Keep the +2m..+5m midnight fixture in the past relative to CURRENT_TIMESTAMP() / stg_run_window when running right after 00:00 UTC.
	if now.Sub(todayMidnight) < 10*time.Minute {
		todayMidnight = todayMidnight.Add(-24 * time.Hour)
	}
	env := &analyticsLiveEnv{
		project:       project,
		location:      location,
		srcDataset:    uniqueEphemeralDatasetID("otel_analytics_it"),
		martDataset:   uniqueEphemeralDatasetID("otel_analytics_marts_it"),
		assertDataset: uniqueEphemeralDatasetID("otel_analytics_assert_it"),
		runID:         runID,
		now:           now,
		todayMidnight: todayMidnight,
		recentBase:    now.Add(-10 * time.Minute),
		svcPrimary:    "it-analytics-primary-" + runID,
		svcMidnight:   "it-analytics-midnight-" + runID,
		svcEmptyUser:  "it-analytics-nouser-" + runID,
		secretMarker:  "sk-live-secret-" + runID,
		admin:         admin,
	}

	// Ensure source dataset does not pre-exist so AutoCreate.Dataset exercises creation safely.
	assertDatasetNotFound404(ctx, t, admin, env.srcDataset)
	t.Cleanup(func() {
		if !env.srcCreated {
			return
		}
		deleteDatasetAndVerify404(t, admin, env.srcDataset)
	})
	for _, ds := range []string{env.martDataset, env.assertDataset} {
		createOwnedDatasetWith404Cleanup(ctx, t, admin, ds, location)
	}
	return env
}

func assertDatasetNotFound404(ctx context.Context, t *testing.T, admin *bq.Client, dataset string) {
	t.Helper()
	_, err := admin.Dataset(dataset).Metadata(ctx)
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != stdhttp.StatusNotFound {
		t.Fatalf("expected HTTP 404 before creating ephemeral dataset %s, got err=%v", dataset, err)
	}
}

func deleteDatasetAndVerify404(t *testing.T, admin *bq.Client, dataset string) {
	t.Helper()
	cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := admin.Dataset(dataset).DeleteWithContents(cleanCtx); err != nil {
		t.Errorf("delete ephemeral dataset %s: %v", dataset, err)
		return
	}
	_, err := admin.Dataset(dataset).Metadata(cleanCtx)
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != stdhttp.StatusNotFound {
		t.Errorf("post-delete metadata check for %s = %v, want HTTP 404", dataset, err)
	}
}

func createOwnedDatasetWith404Cleanup(ctx context.Context, t *testing.T, admin *bq.Client, dataset, location string) {
	t.Helper()
	if err := admin.Dataset(dataset).Create(ctx, &bq.DatasetMetadata{Location: location}); err != nil {
		t.Fatalf("create dataset %s: %v", dataset, err)
	}
	t.Cleanup(func() {
		deleteDatasetAndVerify404(t, admin, dataset)
	})
}

func (e *analyticsLiveEnv) startExporters(ctx context.Context, t *testing.T) analyticsLiveExporters {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		sCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := mp.Shutdown(sCtx); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	e.reader = reader

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Project = e.project
	cfg.Dataset = e.srcDataset
	cfg.Location = e.location
	cfg.AutoCreate = AutoCreateConfig{
		Dataset:              true,
		Tables:               true,
		CompanionViews:       true,
		AllowUnprunableViews: true,
	}
	cfg.Quarantine = QuarantineConfig{
		Enabled:                 true,
		Table:                   "otel_quarantine",
		PartitionExpirationDays: 30,
		MaxRawPayloadBytes:      8388608,
		Timeout:                 5 * time.Second,
	}
	cfg.Limits.MaxAttributeCount = 64
	cfg.Write.Compression = "gzip"
	cfg.Write.Backpressure.Enabled = true
	cfg.Redaction = RedactionConfig{
		Enabled:              true,
		MaskReplacement:      "[REDACTED]",
		BlockedValuePatterns: []string{`sk-live-secret-[0-9a-f]+`},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	set := exportertest.NewNopSettings(factory.Type())
	set.Logger = zap.NewNop()
	set.MeterProvider = mp

	tExp, err := factory.CreateTraces(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}
	lExp, err := factory.CreateLogs(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateLogs: %v", err)
	}
	mExp, err := factory.CreateMetrics(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateMetrics: %v", err)
	}

	stop := func(name string, fn func(context.Context) error) {
		t.Cleanup(func() {
			sCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := fn(sCtx); err != nil {
				t.Errorf("shutdown %s exporter: %v", name, err)
			}
		})
	}
	// Mark srcCreated true immediately before Start so any partial creation is cleaned up.
	e.srcCreated = true
	if err := tExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start traces exporter: %v", err)
	}
	stop("traces", tExp.Shutdown)
	if err := lExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start logs exporter: %v", err)
	}
	stop("logs", lExp.Shutdown)
	if err := mExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start metrics exporter: %v", err)
	}
	stop("metrics", mExp.Shutdown)

	return analyticsLiveExporters{traces: tExp, logs: lExp, metrics: mExp}
}

func (e *analyticsLiveEnv) provisionTVFsAndAlerts(ctx context.Context, t *testing.T) {
	t.Helper()
	tvfs := schema.CompanionTVFDDLs(e.project, e.srcDataset, "otel_spans", "otel_logs")
	for name, ddl := range tvfs {
		e.mustExecSQL(ctx, t, "create TVF "+name, ddl)
	}

	alertsMD := &bq.TableMetadata{
		TimePartitioning: &bq.TimePartitioning{
			Type:  bq.DayPartitioningType,
			Field: "event_time",
		},
		Clustering: &bq.Clustering{
			Fields: []string{"alert_kind", "service_name"},
		},
		Schema: bq.Schema{
			{Name: "alert_id", Type: bq.StringFieldType, Required: true},
			{Name: "alert_kind", Type: bq.StringFieldType, Required: true},
			{Name: "event_time", Type: bq.TimestampFieldType, Required: true},
			{Name: "service_name", Type: bq.StringFieldType},
			{Name: "trace_id", Type: bq.StringFieldType, Required: true},
			{Name: "span_id", Type: bq.StringFieldType, Required: true},
			{Name: "payload", Type: bq.JSONFieldType},
		},
	}
	if err := e.admin.Dataset(e.srcDataset).Table("otel_alerts").Create(ctx, alertsMD); err != nil {
		t.Fatalf("create otel_alerts: %v", err)
	}
}

func analyticsTraceID(tag byte) pcommon.TraceID {
	var id pcommon.TraceID
	for i := range id {
		id[i] = tag
	}
	return id
}

func analyticsSpanID(tag byte) pcommon.SpanID {
	var id pcommon.SpanID
	for i := range id {
		id[i] = tag
	}
	return id
}

var (
	analyticsTraceMain       = analyticsTraceID(0xa1)
	analyticsSpanRoot        = analyticsSpanID(0xb1)
	analyticsSpanSubagent    = analyticsSpanID(0xb2)
	analyticsSpanToolErr     = analyticsSpanID(0xb3)
	analyticsSpanChat        = analyticsSpanID(0xb4)
	analyticsTracePrimaryErr = analyticsTraceID(0xa3)
	analyticsTraceMCP        = analyticsTraceID(0xa2)
	analyticsSpanMCPDual     = analyticsSpanID(0xc1)
	analyticsSpanMCPServer   = analyticsSpanID(0xc2)
	analyticsTraceMidD1      = analyticsTraceID(0xd1)
	analyticsTraceMidD2a     = analyticsTraceID(0xd2)
	analyticsTraceMidD2b     = analyticsTraceID(0xd3)
	analyticsTraceMidD2c     = analyticsTraceID(0xd4)
	analyticsTraceMidD2d     = analyticsTraceID(0xd5)
	analyticsTraceEmptyUser  = analyticsTraceID(0xe1)
	analyticsTraceQuarantine = analyticsTraceID(0xf1)
	analyticsTraceInc        = analyticsTraceID(0xe2)
)

func (e *analyticsLiveEnv) buildBatch1Traces() ptrace.Traces {
	td := ptrace.NewTraces()

	// 1. Primary service: multi-agent hierarchy + MCP calls.
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("it-analytics-scope")

	root := ss.Spans().AppendEmpty()
	root.SetTraceID(analyticsTraceMain)
	root.SetSpanID(analyticsSpanRoot)
	root.SetName("invoke_agent planner")
	root.SetKind(ptrace.SpanKindInternal)
	root.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase))
	root.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(2 * time.Second)))
	root.Status().SetCode(ptrace.StatusCodeOk)
	root.Attributes().PutStr("gen_ai.operation.name", "invoke_agent")
	root.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	root.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	root.Attributes().PutStr("gen_ai.agent.name", "planner")
	root.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	root.Attributes().PutStr("gcp.vertex.agent.invocation_id", "inv-p1")
	root.Attributes().PutStr("user.id", "user-alice")
	root.Attributes().PutInt("gen_ai.usage.input_tokens", 100)
	root.Attributes().PutInt("gen_ai.usage.output_tokens", 40)

	sub := ss.Spans().AppendEmpty()
	sub.SetTraceID(analyticsTraceMain)
	sub.SetSpanID(analyticsSpanSubagent)
	sub.SetParentSpanID(analyticsSpanRoot)
	sub.SetName("invoke_agent researcher")
	sub.SetKind(ptrace.SpanKindInternal)
	sub.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(100 * time.Millisecond)))
	sub.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(1800 * time.Millisecond)))
	sub.Status().SetCode(ptrace.StatusCodeOk)
	sub.Attributes().PutStr("gen_ai.operation.name", "invoke_agent")
	sub.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	sub.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	sub.Attributes().PutStr("gen_ai.agent.name", "researcher")
	sub.Attributes().PutStr("gen_ai.main_agent.name", "planner")
	sub.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	sub.Attributes().PutStr("gcp.vertex.agent.invocation_id", "inv-p1")
	sub.Attributes().PutStr("user.id", "user-alice")

	toolErr := ss.Spans().AppendEmpty()
	toolErr.SetTraceID(analyticsTraceMain)
	toolErr.SetSpanID(analyticsSpanToolErr)
	toolErr.SetParentSpanID(analyticsSpanSubagent)
	toolErr.SetName("execute_tool web_search")
	toolErr.SetKind(ptrace.SpanKindInternal)
	toolErr.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(200 * time.Millisecond)))
	toolErr.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(700 * time.Millisecond)))
	toolErr.Status().SetCode(ptrace.StatusCodeError)
	toolErr.Status().SetMessage("upstream timed out")
	toolErr.Attributes().PutStr("gen_ai.operation.name", "execute_tool")
	toolErr.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	toolErr.Attributes().PutStr("gen_ai.tool.name", "web_search")
	toolErr.Attributes().PutStr("gen_ai.tool.type", "function")
	toolErr.Attributes().PutStr("gen_ai.agent.name", "researcher")
	toolErr.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	toolErr.Attributes().PutStr("user.id", "user-alice")
	toolErr.Attributes().PutStr("error.type", "TOOL_TIMEOUT")
	toolErr.Attributes().PutStr("api_key", "secret-key-should-redact")
	toolErr.Attributes().PutStr("debug.note", "Bearer "+e.secretMarker)
	ev := toolErr.Events().AppendEmpty()
	ev.SetName("gen_ai.tool.error")
	ev.SetTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(690 * time.Millisecond)))
	ev.Attributes().PutStr("reason", "timeout")

	chat := ss.Spans().AppendEmpty()
	chat.SetTraceID(analyticsTraceMain)
	chat.SetSpanID(analyticsSpanChat)
	chat.SetParentSpanID(analyticsSpanSubagent)
	chat.SetName("chat gemini-2.5-pro")
	chat.SetKind(ptrace.SpanKindClient)
	chat.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(800 * time.Millisecond)))
	chat.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(1600 * time.Millisecond)))
	chat.Status().SetCode(ptrace.StatusCodeOk)
	chat.Attributes().PutStr("gen_ai.operation.name", "chat")
	chat.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	chat.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	chat.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	chat.Attributes().PutStr("gen_ai.response.model", "gemini-2.5-pro")
	chat.Attributes().PutStr("gen_ai.agent.name", "researcher")
	chat.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	chat.Attributes().PutStr("user.id", "user-alice")
	chat.Attributes().PutInt("gen_ai.usage.input_tokens", 100)
	chat.Attributes().PutInt("gen_ai.usage.output_tokens", 40)
	chat.Attributes().PutInt("gen_ai.usage.cache_read_input_tokens", 20)
	chat.Attributes().PutInt("gen_ai.usage.cache_creation_input_tokens", 5)
	chat.Attributes().PutInt("gen_ai.usage.reasoning_tokens", 15)

	llmErr := ss.Spans().AppendEmpty()
	llmErr.SetTraceID(analyticsTracePrimaryErr)
	llmErr.SetSpanID(analyticsSpanID(0xb5))
	llmErr.SetName("chat gemini-2.5-pro")
	llmErr.SetKind(ptrace.SpanKindClient)
	llmErr.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(2500 * time.Millisecond)))
	llmErr.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(2700 * time.Millisecond)))
	llmErr.Status().SetCode(ptrace.StatusCodeError)
	llmErr.Attributes().PutStr("gen_ai.operation.name", "chat")
	llmErr.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	llmErr.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	llmErr.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	llmErr.Attributes().PutStr("gen_ai.agent.name", "planner")
	llmErr.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	llmErr.Attributes().PutStr("user.id", "user-alice")
	llmErr.Attributes().PutStr("error.type", "RATE_LIMIT_EXCEEDED")

	mcpDual := ss.Spans().AppendEmpty()
	mcpDual.SetTraceID(analyticsTraceMCP)
	mcpDual.SetSpanID(analyticsSpanMCPDual)
	mcpDual.SetName("tools/call bq_query")
	mcpDual.SetKind(ptrace.SpanKindClient)
	mcpDual.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(3 * time.Second)))
	mcpDual.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(3200 * time.Millisecond)))
	mcpDual.Status().SetCode(ptrace.StatusCodeOk)
	mcpDual.Attributes().PutStr("mcp.method.name", "tools/call")
	mcpDual.Attributes().PutStr("mcp.protocol.version", "2025-03-26")
	mcpDual.Attributes().PutStr("mcp.tool.name", "bq_query")
	mcpDual.Attributes().PutStr("server.address", "mcp.example.internal")
	mcpDual.Attributes().PutStr("gen_ai.operation.name", "execute_tool")
	mcpDual.Attributes().PutStr("gen_ai.tool.name", "bq_query")
	mcpDual.Attributes().PutStr("gen_ai.tool.type", "mcp")
	mcpDual.Attributes().PutStr("gen_ai.agent.name", "researcher")

	mcpSrv := ss.Spans().AppendEmpty()
	mcpSrv.SetTraceID(analyticsTraceMCP)
	mcpSrv.SetSpanID(analyticsSpanMCPServer)
	mcpSrv.SetParentSpanID(analyticsSpanMCPDual)
	mcpSrv.SetName("resources/read")
	mcpSrv.SetKind(ptrace.SpanKindServer)
	mcpSrv.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(3050 * time.Millisecond)))
	mcpSrv.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(3150 * time.Millisecond)))
	mcpSrv.Status().SetCode(ptrace.StatusCodeError)
	mcpSrv.Attributes().PutStr("mcp.method.name", "resources/read")
	mcpSrv.Attributes().PutStr("mcp.protocol.version", "2025-03-26")
	mcpSrv.Attributes().PutStr("mcp.resource.uri", "bq://example/ds/tbl")
	mcpSrv.Attributes().PutStr("server.address", "mcp.example.internal")
	mcpSrv.Attributes().PutStr("error.type", "NOT_FOUND")

	// 2. Midnight-crossing service: 1 turn on yesterday 23:50-23:52 UTC (120s) +
	//    4 turns on today 00:02-00:05 UTC => total 5 turns, 900_000 ms duration.
	rsMid := td.ResourceSpans().AppendEmpty()
	rsMid.Resource().Attributes().PutStr("service.name", e.svcMidnight)
	ssMid := rsMid.ScopeSpans().AppendEmpty()
	ssMid.Scope().SetName("it-analytics-midnight")

	midSessID := "sess-midnight-" + e.runID
	addMidSpan := func(trID pcommon.TraceID, spID byte, startOff, endOff time.Duration, inTok, outTok int64) {
		sp := ssMid.Spans().AppendEmpty()
		sp.SetTraceID(trID)
		sp.SetSpanID(analyticsSpanID(spID))
		sp.SetName("chat gemini-2.5-flash")
		sp.SetKind(ptrace.SpanKindClient)
		sp.SetStartTimestamp(pcommon.NewTimestampFromTime(e.todayMidnight.Add(startOff)))
		sp.SetEndTimestamp(pcommon.NewTimestampFromTime(e.todayMidnight.Add(endOff)))
		sp.Status().SetCode(ptrace.StatusCodeOk)
		sp.Attributes().PutStr("gen_ai.operation.name", "chat")
		sp.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
		sp.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
		sp.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-flash")
		sp.Attributes().PutStr("gen_ai.agent.name", "midnight-worker")
		sp.Attributes().PutStr("gcp.vertex.agent.session_id", midSessID)
		sp.Attributes().PutStr("user.id", "user-midnight")
		sp.Attributes().PutInt("gen_ai.usage.input_tokens", inTok)
		sp.Attributes().PutInt("gen_ai.usage.output_tokens", outTok)
	}
	addMidSpan(analyticsTraceMidD1, 0xd1, -10*time.Minute, -8*time.Minute, 50, 25)
	addMidSpan(analyticsTraceMidD2a, 0xd2, 2*time.Minute, 2*time.Minute+30*time.Second, 10, 5)
	addMidSpan(analyticsTraceMidD2b, 0xd3, 3*time.Minute, 3*time.Minute+20*time.Second, 10, 5)
	addMidSpan(analyticsTraceMidD2c, 0xd4, 4*time.Minute, 4*time.Minute+10*time.Second, 10, 5)
	addMidSpan(analyticsTraceMidD2d, 0xd5, 4*time.Minute+40*time.Second, 5*time.Minute, 10, 5)

	// 3. Empty user_id service: verifies NULLIF(user_id, '') exclusion in Grafana.
	rsEmpty := td.ResourceSpans().AppendEmpty()
	rsEmpty.Resource().Attributes().PutStr("service.name", e.svcEmptyUser)
	spEmpty := rsEmpty.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	spEmpty.SetTraceID(analyticsTraceEmptyUser)
	spEmpty.SetSpanID(analyticsSpanID(0xe1))
	spEmpty.SetName("chat gemini-2.5-flash")
	spEmpty.SetKind(ptrace.SpanKindClient)
	spEmpty.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(4 * time.Second)))
	spEmpty.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(4500 * time.Millisecond)))
	spEmpty.Status().SetCode(ptrace.StatusCodeOk)
	spEmpty.Attributes().PutStr("gen_ai.operation.name", "chat")
	spEmpty.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	spEmpty.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	spEmpty.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-flash")
	spEmpty.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-emptyuser-"+e.runID)
	spEmpty.Attributes().PutStr("user.id", "")
	spEmpty.Attributes().PutInt("gen_ai.usage.input_tokens", 20)
	spEmpty.Attributes().PutInt("gen_ai.usage.output_tokens", 10)

	// 4. Over-limit span routed to otel_quarantine (66 > MaxAttributeCount=64).
	rsQ := td.ResourceSpans().AppendEmpty()
	rsQ.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	spQ := rsQ.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	spQ.SetTraceID(analyticsTraceQuarantine)
	spQ.SetSpanID(analyticsSpanID(0xf1))
	spQ.SetName("quarantine_trigger")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(5 * time.Second)))
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(5100 * time.Millisecond)))
	for i := 0; i < 66; i++ {
		spQ.Attributes().PutInt(fmt.Sprintf("extra.attr.%d", i), int64(i))
	}

	return td
}

func (e *analyticsLiveEnv) buildBatch2IncrementalTraces() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("it-analytics-inc")

	// Deliberate replay of spanChat (different end time? identical start/span/trace -> deduped).
	dup := ss.Spans().AppendEmpty()
	dup.SetTraceID(analyticsTraceMain)
	dup.SetSpanID(analyticsSpanChat)
	dup.SetParentSpanID(analyticsSpanSubagent)
	dup.SetName("chat gemini-2.5-pro")
	dup.SetKind(ptrace.SpanKindClient)
	dup.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(800 * time.Millisecond)))
	dup.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(1600 * time.Millisecond)))
	dup.Status().SetCode(ptrace.StatusCodeOk)
	dup.Attributes().PutStr("gen_ai.operation.name", "chat")
	dup.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	dup.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	dup.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	dup.Attributes().PutStr("gen_ai.response.model", "gemini-2.5-pro")
	dup.Attributes().PutStr("gen_ai.agent.name", "researcher")
	dup.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	dup.Attributes().PutStr("user.id", "user-alice")
	dup.Attributes().PutInt("gen_ai.usage.input_tokens", 100)
	dup.Attributes().PutInt("gen_ai.usage.output_tokens", 40)
	dup.Attributes().PutInt("gen_ai.usage.cache_read_input_tokens", 20)
	dup.Attributes().PutInt("gen_ai.usage.cache_creation_input_tokens", 5)
	dup.Attributes().PutInt("gen_ai.usage.reasoning_tokens", 15)

	// Fresh incremental span inside the 3h lookback window.
	inc := ss.Spans().AppendEmpty()
	inc.SetTraceID(analyticsTraceInc)
	inc.SetSpanID(analyticsSpanID(0xe2))
	inc.SetName("chat gemini-2.5-pro")
	inc.SetKind(ptrace.SpanKindClient)
	incStart := e.now.Add(-2 * time.Minute)
	inc.SetStartTimestamp(pcommon.NewTimestampFromTime(incStart))
	inc.SetEndTimestamp(pcommon.NewTimestampFromTime(incStart.Add(300 * time.Millisecond)))
	inc.Status().SetCode(ptrace.StatusCodeOk)
	inc.Attributes().PutStr("gen_ai.operation.name", "chat")
	inc.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	inc.Attributes().PutStr("gen_ai.provider.name", "gcp.vertex_ai")
	inc.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	inc.Attributes().PutStr("gen_ai.agent.name", "planner")
	inc.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-inc-"+e.runID)
	inc.Attributes().PutStr("user.id", "user-bob")
	inc.Attributes().PutInt("gen_ai.usage.input_tokens", 30)
	inc.Attributes().PutInt("gen_ai.usage.output_tokens", 12)

	return td
}

func (e *analyticsLiveEnv) buildAnalyticsLogs() plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(900 * time.Millisecond)))
	rec.SetObservedTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(900 * time.Millisecond)))
	rec.SetEventName("gen_ai.choice")
	rec.SetSeverityText("INFO")
	rec.SetTraceID(analyticsTraceMain)
	rec.SetSpanID(analyticsSpanChat)
	rec.Body().SetStr("final answer synthesized cleanly")
	rec.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	rec.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	rec.Attributes().PutStr("gcp.vertex.agent.session_id", "sess-primary-"+e.runID)
	return ld
}

func (e *analyticsLiveEnv) buildAnalyticsMetrics() pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("it-analytics-scope")

	mStart := pcommon.NewTimestampFromTime(e.recentBase)
	mTime := pcommon.NewTimestampFromTime(e.recentBase.Add(1600 * time.Millisecond))

	tok := sm.Metrics().AppendEmpty()
	tok.SetName("gen_ai.client.token.usage")
	tok.SetUnit("{token}")
	sum := tok.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	sum.SetIsMonotonic(true)
	sp := sum.DataPoints().AppendEmpty()
	sp.SetStartTimestamp(mStart)
	sp.SetTimestamp(mTime)
	sp.SetIntValue(100)
	sp.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	sp.Attributes().PutStr("gen_ai.token.type", "input")
	sp.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	sEx := sp.Exemplars().AppendEmpty()
	sEx.SetTimestamp(mTime)
	sEx.SetIntValue(100)
	sEx.SetTraceID(analyticsTraceMain)
	sEx.SetSpanID(analyticsSpanChat)

	dur := sm.Metrics().AppendEmpty()
	dur.SetName("gen_ai.client.operation.duration")
	dur.SetUnit("s")
	hist := dur.SetEmptyHistogram()
	hist.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	hp := hist.DataPoints().AppendEmpty()
	hp.SetStartTimestamp(mStart)
	hp.SetTimestamp(mTime)
	hp.SetCount(1)
	hp.SetSum(0.8)
	hp.SetMin(0.8)
	hp.SetMax(0.8)
	hp.ExplicitBounds().FromRaw([]float64{0.25, 0.5, 1.0})
	hp.BucketCounts().FromRaw([]uint64{0, 0, 1, 0})
	hp.Attributes().PutStr("gen_ai.operation.name", "chat")
	hp.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	hEx := hp.Exemplars().AppendEmpty()
	hEx.SetTimestamp(mTime)
	hEx.SetDoubleValue(0.8)
	hEx.SetTraceID(analyticsTraceMain)
	hEx.SetSpanID(analyticsSpanChat)
	hEx.FilteredAttributes().PutStr("gen_ai.agent.name", "researcher")

	return md
}

func (e *analyticsLiveEnv) seedAlertsTable(ctx context.Context, t *testing.T) {
	t.Helper()
	t1 := e.recentBase.Add(750 * time.Millisecond)
	t2 := e.recentBase.Add(1650 * time.Millisecond)
	t3 := e.recentBase.Add(2200 * time.Millisecond)
	trMain := hex.EncodeToString(analyticsTraceMain[:])
	spTool := hex.EncodeToString(analyticsSpanToolErr[:])
	spChat := hex.EncodeToString(analyticsSpanChat[:])
	spRoot := hex.EncodeToString(analyticsSpanRoot[:])

	sql := fmt.Sprintf("INSERT INTO `%s.%s.otel_alerts` (alert_id, alert_kind, event_time, service_name, trace_id, span_id, payload) VALUES "+
		"(@id1, 'TOOL_ERROR', @t1, @svc, @tr, @spTool, TO_JSON(STRUCT('execute_tool web_search' AS span_name, 'execute_tool' AS operation_name, 'researcher' AS agent_name, 'web_search' AS tool_name, 'TOOL_TIMEOUT' AS error_type, 2 AS status_code, @sess AS session_id, 500.0 AS duration_ms))),"+
		"(@id1, 'TOOL_ERROR', TIMESTAMP_ADD(@t1, INTERVAL 10 SECOND), @svc, @tr, @spTool, TO_JSON(STRUCT('execute_tool web_search' AS span_name, 'execute_tool' AS operation_name, 'researcher' AS agent_name, 'web_search' AS tool_name, 'TOOL_TIMEOUT' AS error_type, 2 AS status_code, @sess AS session_id, 500.0 AS duration_ms))),"+
		"(@id2, 'TOKEN_BUDGET_BURN', @t2, @svc, @tr, @spChat, TO_JSON(STRUCT('chat gemini-2.5-pro' AS span_name, 'chat' AS operation_name, 'researcher' AS agent_name, @sess AS session_id, 'gemini-2.5-pro' AS request_model, 'gemini-2.5-pro' AS response_model, 100 AS input_tokens, 40 AS output_tokens, 15 AS reasoning_tokens))),"+
		"(@id3, 'AGENT_LATENCY_HIGH', @t3, @svc, @tr, @spRoot, TO_JSON(STRUCT('invoke_agent planner' AS span_name, 'invoke_agent' AS operation_name, 'planner' AS agent_name, @sess AS session_id, 2000.0 AS duration_ms)))",
		e.project, e.srcDataset)

	params := []bq.QueryParameter{
		{Name: "id1", Value: "alert-tool-" + e.runID},
		{Name: "id2", Value: "alert-token-" + e.runID},
		{Name: "id3", Value: "alert-lat-" + e.runID},
		{Name: "t1", Value: t1},
		{Name: "t2", Value: t2},
		{Name: "t3", Value: t3},
		{Name: "svc", Value: e.svcPrimary},
		{Name: "tr", Value: trMain},
		{Name: "spTool", Value: spTool},
		{Name: "spChat", Value: spChat},
		{Name: "spRoot", Value: spRoot},
		{Name: "sess", Value: "sess-primary-" + e.runID},
	}
	e.mustExecSQL(ctx, t, "seed otel_alerts", sql, params...)
}

func (e *analyticsLiveEnv) seedBatch1AndWait(ctx context.Context, t *testing.T, exps analyticsLiveExporters) {
	t.Helper()
	if err := exps.traces.ConsumeTraces(ctx, e.buildBatch1Traces()); err != nil {
		t.Fatalf("ConsumeTraces batch1: %v", err)
	}
	if err := exps.logs.ConsumeLogs(ctx, e.buildAnalyticsLogs()); err != nil {
		t.Fatalf("ConsumeLogs batch1: %v", err)
	}
	if err := exps.metrics.ConsumeMetrics(ctx, e.buildAnalyticsMetrics()); err != nil {
		t.Fatalf("ConsumeMetrics batch1: %v", err)
	}
	e.seedAlertsTable(ctx, t)

	// Wait until streamed spans, logs, metrics, exemplars, and quarantine rows are visible.
	e.waitForCount(ctx, t, "otel_spans_dedup batch1 count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_spans_dedup`", e.project, e.srcDataset), 13)
	e.waitForCount(ctx, t, "otel_quarantine count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_quarantine`", e.project, e.srcDataset), 1)
	e.waitForCount(ctx, t, "v_gen_ai_metric_exemplars count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.v_gen_ai_metric_exemplars`", e.project, e.srcDataset), 2)
	e.waitForCount(ctx, t, "otel_logs_dedup batch1 count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_logs_dedup`", e.project, e.srcDataset), 1)

	// Execute all 3 companion TVFs live cleanly to prove bounded TVF execution.
	winStart := e.todayMidnight.Add(-1 * time.Hour)
	winEnd := e.now.Add(5 * time.Minute)
	for _, tvf := range []struct {
		name  string
		query string
		want  int
	}{
		{
			name:  schema.GenAILogsTVFName,
			query: fmt.Sprintf("SELECT trace_id, span_id FROM `%s.%s.%s`(@s, @e)", e.project, e.srcDataset, schema.GenAILogsTVFName),
			want:  1,
		},
		{
			name:  schema.GenAIMetricExemplarsTVFName,
			query: fmt.Sprintf("SELECT metric_name, trace_id FROM `%s.%s.%s`(@s, @e)", e.project, e.srcDataset, schema.GenAIMetricExemplarsTVFName),
			want:  2,
		},
		{
			name:  schema.GenAIAgentTrajectoryTVFName,
			query: fmt.Sprintf("SELECT span_id, depth FROM `%s.%s.%s`(@s, @e, TIMESTAMP_SUB(@s, INTERVAL 24 HOUR), TIMESTAMP_ADD(@e, INTERVAL 1 HOUR))", e.project, e.srcDataset, schema.GenAIAgentTrajectoryTVFName),
			want:  6, // spans on primary/empty traces >= 6
		},
	} {
		rows, _ := e.mustQueryRows(ctx, t, "TVF "+tvf.name, tvf.query,
			bq.QueryParameter{Name: "s", Value: winStart},
			bq.QueryParameter{Name: "e", Value: winEnd},
		)
		if len(rows) < tvf.want {
			t.Fatalf("TVF %s returned %d rows, want >= %d", tvf.name, len(rows), tvf.want)
		}
	}
}

func (e *analyticsLiveEnv) mustExecSQL(ctx context.Context, t *testing.T, label, sql string, params ...bq.QueryParameter) {
	t.Helper()
	q := e.admin.Query(sql)
	q.Location = e.location
	q.Parameters = params
	job, err := q.Run(ctx)
	if err != nil {
		t.Fatalf("%s run failed: %v\nSQL:\n%s", label, err, sql)
	}
	st, err := job.Wait(ctx)
	if err != nil {
		t.Fatalf("%s wait failed: %v\nSQL:\n%s", label, err, sql)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("%s job status failed: %v\nSQL:\n%s", label, err, sql)
	}
}

func (e *analyticsLiveEnv) mustQueryRows(ctx context.Context, t *testing.T, label, sql string, params ...bq.QueryParameter) ([][]bq.Value, bq.Schema) {
	t.Helper()
	q := e.admin.Query(sql)
	q.Location = e.location
	q.Parameters = params
	it, err := q.Read(ctx)
	if err != nil {
		t.Fatalf("%s query failed: %v\nSQL:\n%s", label, err, sql)
	}
	var out [][]bq.Value
	for {
		var row []bq.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			return out, it.Schema
		}
		if err != nil {
			t.Fatalf("%s iterate failed: %v\nSQL:\n%s", label, err, sql)
		}
		out = append(out, row)
	}
}

func (e *analyticsLiveEnv) waitForCount(ctx context.Context, t *testing.T, label, sql string, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last int64
	for {
		rows, _ := e.mustQueryRows(ctx, t, label, sql)
		if len(rows) == 1 && len(rows[0]) == 1 {
			last, _ = rows[0][0].(int64)
		}
		if last >= want {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("%s count = %d after waiting, want >= %d", label, last, want)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s aborted while waiting (last=%d, want >= %d): %v", label, last, want, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

// --- Dataform runtime .sqlx parser, compiler & executor ----------------------

type dataformAction struct {
	name          string
	actionType    string
	database      string
	schema        string
	dependencies  []string
	partitionBy   string
	clusterBy     []string
	preStatements []string
	mainQuery     string
	postStmts     []string
	disabled      bool              // the config's disabled expression, evaluated with vars
	vars          map[string]string // the compilation variables
}

type dataformWorkflowSettings struct {
	Vars map[string]string `yaml:"vars"`
}

// dataformLiveVarOverrides are the --vars the live run compiles with: the log
// rollup is opt-in (vars.enable_log_volume_rollup), and the live run enables it
// so that its SQL runs in BigQuery too.
var dataformLiveVarOverrides = map[string]string{"enable_log_volume_rollup": "true"}

var (
	dataformVarNameRE  = regexp.MustCompile(`name:\s*dataform\.projectConfig\.vars\.([A-Za-z_][A-Za-z0-9_]*)(?:\s*\|\|\s*"([^"]*)")?`)
	dataformDisabledRE = regexp.MustCompile(`disabled:\s*dataform\.projectConfig\.vars\.([A-Za-z_][A-Za-z0-9_]*)\s*!==\s*"([^"]*)"`)
	dataformVarRefRE   = regexp.MustCompile(`ref\(\s*dataform\.projectConfig\.vars\.([A-Za-z_][A-Za-z0-9_]*)(?:\s*\|\|\s*"([^"]*)")?\s*\)`)
)

func loadDataformActions(t *testing.T, srcProject, srcDataset, martProject, martDataset string) ([]dataformAction, map[string]dataformAction) {
	t.Helper()
	rawSettings, err := os.ReadFile(filepath.Join("deploy", "dataform", "workflow_settings.yaml"))
	if err != nil {
		t.Fatalf("read workflow_settings.yaml: %v", err)
	}
	var ws dataformWorkflowSettings
	if err := yaml.Unmarshal(rawSettings, &ws); err != nil {
		t.Fatalf("parse workflow_settings.yaml: %v", err)
	}
	var paths []string
	err = filepath.WalkDir(filepath.Join("deploy", "dataform", "definitions"), func(p string, d os.DirEntry, wErr error) error {
		if wErr != nil {
			return wErr
		}
		if !d.IsDir() && strings.HasSuffix(p, ".sqlx") {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk deploy/dataform/definitions: %v", err)
	}
	sort.Strings(paths)
	vars := map[string]string{}
	for k, v := range ws.Vars {
		vars[k] = v
	}
	for k, v := range dataformLiveVarOverrides {
		vars[k] = v
	}

	byName := make(map[string]dataformAction, len(paths))
	var actions []dataformAction
	for _, p := range paths {
		act := parseSQLXAction(t, p, srcProject, srcDataset, martProject, martDataset, vars)
		byName[act.name] = act
		actions = append(actions, act)
	}
	return actions, byName
}

func parseSQLXAction(t *testing.T, path, srcProject, srcDataset, martProject, martDataset string, vars map[string]string) dataformAction {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	cfgBody, preBody, postBody, mainBody := splitSQLXBlocks(t, path, string(raw))

	baseName := strings.TrimSuffix(filepath.Base(path), ".sqlx")
	act := dataformAction{
		name:     baseName,
		database: martProject,
		schema:   martDataset,
		vars:     vars,
	}

	if m := regexp.MustCompile(`type:\s*"([^"]+)"`).FindStringSubmatch(cfgBody); len(m) == 2 {
		act.actionType = m[1]
	}
	if m := regexp.MustCompile(`name:\s*"([^"]+)"`).FindStringSubmatch(cfgBody); len(m) == 2 {
		act.name = m[1]
	}
	if m := dataformVarNameRE.FindStringSubmatch(cfgBody); len(m) == 3 {
		val := vars[m[1]]
		if val == "" {
			val = m[2]
		}
		if val == "" {
			t.Fatalf("%s: name variable %s is not set", path, m[1])
		}
		act.name = val
	}
	if m := dataformDisabledRE.FindStringSubmatch(cfgBody); len(m) == 3 {
		act.disabled = vars[m[1]] != m[2]
	} else if strings.Contains(cfgBody, "disabled:") {
		t.Fatalf("%s: unsupported disabled expression", path)
	}
	if act.actionType == "declaration" {
		act.database = srcProject
		act.schema = srcDataset
	}
	if m := regexp.MustCompile(`dependencies:\s*\[([^\]]*)\]`).FindStringSubmatch(cfgBody); len(m) == 2 {
		for _, item := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			act.dependencies = append(act.dependencies, item[1])
		}
	}
	if m := regexp.MustCompile(`partitionBy:\s*"([^"]+)"`).FindStringSubmatch(cfgBody); len(m) == 2 {
		act.partitionBy = m[1]
	}
	if m := regexp.MustCompile(`clusterBy:\s*\[([^\]]*)\]`).FindStringSubmatch(cfgBody); len(m) == 2 {
		for _, item := range regexp.MustCompile(`"([^"]+)"`).FindAllStringSubmatch(m[1], -1) {
			act.clusterBy = append(act.clusterBy, item[1])
		}
	}

	act.preStatements = splitDataformStatements(preBody)
	act.mainQuery = strings.TrimSpace(mainBody)
	act.postStmts = splitDataformStatements(postBody)
	return act
}

func splitDataformStatements(body string) []string {
	if strings.TrimSpace(body) == "" {
		return nil
	}
	parts := regexp.MustCompile(`(?m)^\s*---\s*$`).Split(body, -1)
	var out []string
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func splitSQLXBlocks(t *testing.T, path, src string) (cfg, pre, post, main string) {
	t.Helper()
	var mainBuf strings.Builder
	i := 0
	for i < len(src) {
		// Skip SQL/C comments into main buffer cleanly without mistaking keywords inside comments.
		if strings.HasPrefix(src[i:], "/*") {
			end := strings.Index(src[i+2:], "*/")
			if end < 0 {
				t.Fatalf("%s: unclosed block comment", path)
			}
			mainBuf.WriteString(src[i : i+2+end+2])
			i += 2 + end + 2
			continue
		}
		if strings.HasPrefix(src[i:], "--") {
			nl := strings.IndexByte(src[i:], '\n')
			if nl < 0 {
				mainBuf.WriteString(src[i:])
				i = len(src)
			} else {
				mainBuf.WriteString(src[i : i+nl+1])
				i += nl + 1
			}
			continue
		}
		if kw, body, nextIdx, ok := tryMatchSQLXBlock(src, i); ok {
			switch kw {
			case "config":
				cfg = body
			case "pre_operations":
				pre = body
			case "post_operations":
				post = body
			}
			i = nextIdx
			continue
		}
		mainBuf.WriteByte(src[i])
		i++
	}
	return cfg, pre, post, mainBuf.String()
}

func tryMatchSQLXBlock(src string, i int) (keyword, body string, nextIdx int, ok bool) {
	if i > 0 {
		prev := src[i-1]
		if (prev >= 'a' && prev <= 'z') || (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
			return "", "", i, false
		}
	}
	for _, kw := range []string{"config", "pre_operations", "post_operations"} {
		if !strings.HasPrefix(src[i:], kw) {
			continue
		}
		j := i + len(kw)
		for j < len(src) && (src[j] == ' ' || src[j] == '\t' || src[j] == '\r' || src[j] == '\n') {
			j++
		}
		if j < len(src) && src[j] == '{' {
			inner, endIdx := scanBraceBlock(src, j)
			return kw, inner, endIdx, true
		}
	}
	return "", "", i, false
}

func scanBraceBlock(src string, openIdx int) (string, int) {
	depth := 0
	for i := openIdx; i < len(src); i++ {
		switch src[i] {
		case '\'', '"', '`':
			i = scanQuotedLiteral(src, i, src[i])
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[openIdx+1 : i], i + 1
			}
		case '/':
			if i+1 < len(src) && src[i+1] == '*' {
				if end := strings.Index(src[i+2:], "*/"); end >= 0 {
					i = i + 2 + end + 1
				}
			}
		case '-':
			if i+1 < len(src) && src[i+1] == '-' {
				if nl := strings.IndexByte(src[i:], '\n'); nl >= 0 {
					i += nl
				} else {
					i = len(src) - 1
				}
			}
		}
	}
	return src[openIdx+1:], len(src)
}

func scanQuotedLiteral(src string, start int, quote byte) int {
	for i := start + 1; i < len(src); i++ {
		if src[i] == '\\' {
			i++
			continue
		}
		if quote == '`' && i+1 < len(src) && src[i] == '$' && src[i+1] == '{' {
			_, end := scanBraceBlock(src, i+1)
			i = end - 1
			continue
		}
		if src[i] == quote {
			return i
		}
	}
	return len(src) - 1
}

func topologicalOrderDataform(t *testing.T, actions []dataformAction, byName map[string]dataformAction) []dataformAction {
	t.Helper()
	deps := make(map[string][]string, len(actions))
	refRe := regexp.MustCompile(`ref\(\s*"([^"]+)"\s*\)`)
	for _, a := range actions {
		seen := map[string]bool{}
		for _, d := range a.dependencies {
			seen[d] = true
		}
		for _, text := range append(append([]string{a.mainQuery}, a.preStatements...), a.postStmts...) {
			for _, m := range refRe.FindAllStringSubmatch(text, -1) {
				seen[m[1]] = true
			}
			for _, m := range dataformVarRefRE.FindAllStringSubmatch(text, -1) {
				val := a.vars[m[1]]
				if val == "" {
					val = m[2]
				}
				seen[val] = true
			}
		}
		for d := range seen {
			if _, ok := byName[d]; ok {
				deps[a.name] = append(deps[a.name], d)
			}
		}
		sort.Strings(deps[a.name])
	}

	var ordered []dataformAction
	state := map[string]int{} // 0=unvisited, 1=visiting, 2=done
	var visit func(name string)
	visit = func(name string) {
		if state[name] == 2 {
			return
		}
		if state[name] == 1 {
			t.Fatalf("cycle detected in Dataform DAG at %s", name)
		}
		state[name] = 1
		for _, d := range deps[name] {
			visit(d)
		}
		state[name] = 2
		ordered = append(ordered, byName[name])
	}
	for _, a := range actions {
		visit(a.name)
	}
	return ordered
}

func renderDataformTemplate(t *testing.T, tpl string, self dataformAction, byName map[string]dataformAction, incremental bool, runTimestamp string) string {
	t.Helper()
	var out strings.Builder
	i := 0
	for i < len(tpl) {
		if i+1 < len(tpl) && tpl[i] == '$' && tpl[i+1] == '{' {
			expr, nextIdx := scanBraceBlock(tpl, i+1)
			out.WriteString(evalDataformExpr(t, strings.TrimSpace(expr), self, byName, incremental, runTimestamp))
			i = nextIdx
			continue
		}
		out.WriteByte(tpl[i])
		i++
	}
	return out.String()
}

func evalDataformExpr(t *testing.T, expr string, self dataformAction, byName map[string]dataformAction, incremental bool, runTimestamp string) string {
	t.Helper()
	switch {
	case expr == "self()":
		return fmt.Sprintf("`%s.%s.%s`", self.database, self.schema, self.name)
	case strings.HasPrefix(expr, "ref("):
		m := regexp.MustCompile(`^ref\(\s*"([^"]+)"\s*\)$`).FindStringSubmatch(expr)
		if vm := dataformVarRefRE.FindStringSubmatch(expr); len(vm) == 3 && vm[0] == expr {
			val := self.vars[vm[1]]
			if val == "" {
				val = vm[2]
			}
			m = []string{expr, val}
		}
		if len(m) != 2 {
			t.Fatalf("unsupported ref expression: %q", expr)
		}
		target, ok := byName[m[1]]
		if !ok {
			t.Fatalf("unresolved ref(%q)", m[1])
		}
		return fmt.Sprintf("`%s.%s.%s`", target.database, target.schema, target.name)
	case strings.Contains(expr, "dataform.projectConfig.vars.run_timestamp"):
		b, _ := json.Marshal(runTimestamp)
		return string(b)
	case strings.HasPrefix(expr, "when("):
		args := splitTopLevelArgs(strings.TrimSuffix(strings.TrimPrefix(expr, "when("), ")"))
		if len(args) < 2 || len(args) > 3 {
			t.Fatalf("unexpected when() arity in %q", expr)
		}
		if strings.TrimSpace(args[0]) != "incremental()" {
			t.Fatalf("unsupported when() condition: %q", args[0])
		}
		var chosen string
		if incremental {
			chosen = unquoteJSTemplate(strings.TrimSpace(args[1]))
		} else if len(args) == 3 {
			chosen = unquoteJSTemplate(strings.TrimSpace(args[2]))
		}
		return renderDataformTemplate(t, chosen, self, byName, incremental, runTimestamp)
	default:
		t.Fatalf("unsupported Dataform template expression: %q", expr)
		return ""
	}
}

func splitTopLevelArgs(s string) []string {
	var args []string
	depthParen, depthBrace := 0, 0
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\'', '"', '`':
			i = scanQuotedLiteral(s, i, s[i])
		case '(':
			depthParen++
		case ')':
			depthParen--
		case '{':
			depthBrace++
		case '}':
			depthBrace--
		case ',':
			if depthParen == 0 && depthBrace == 0 {
				args = append(args, s[start:i])
				start = i + 1
			}
		}
	}
	return append(args, s[start:])
}

func unquoteJSTemplate(s string) string {
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		return s[1 : len(s)-1]
	}
	return s
}

func compileActionScript(t *testing.T, act dataformAction, byName map[string]dataformAction, incremental bool) string {
	t.Helper()
	var stmts []string
	appendNonEmpty := func(raw string) {
		rendered := strings.TrimSpace(renderDataformTemplate(t, raw, act, byName, incremental, ""))
		trimmed := strings.TrimRight(rendered, " \t\r\n;")
		if isEmptyOrCommentOnlySQL(trimmed) {
			return
		}
		stmts = append(stmts, trimmed+"\n;")
	}
	for _, pre := range act.preStatements {
		appendNonEmpty(pre)
	}

	mainSQL := strings.TrimRight(strings.TrimSpace(renderDataformTemplate(t, act.mainQuery, act, byName, incremental, "")), " \t\r\n;")
	selfFQN := fmt.Sprintf("`%s.%s.%s`", act.database, act.schema, act.name)
	if !incremental {
		var hdr strings.Builder
		hdr.WriteString("CREATE OR REPLACE TABLE ")
		hdr.WriteString(selfFQN)
		if act.partitionBy != "" {
			hdr.WriteString("\nPARTITION BY ")
			hdr.WriteString(act.partitionBy)
		}
		if len(act.clusterBy) > 0 {
			hdr.WriteString("\nCLUSTER BY ")
			hdr.WriteString(strings.Join(act.clusterBy, ", "))
		}
		hdr.WriteString("\nAS\n")
		hdr.WriteString(mainSQL)
		hdr.WriteString("\n;")
		stmts = append(stmts, hdr.String())
	} else {
		stmts = append(stmts, fmt.Sprintf("INSERT INTO %s\n%s\n;", selfFQN, mainSQL))
	}

	for _, post := range act.postStmts {
		appendNonEmpty(post)
	}
	return strings.Join(stmts, "\n\n")
}

func isEmptyOrCommentOnlySQL(sql string) bool {
	i := 0
	for i < len(sql) {
		switch {
		case sql[i] == ' ' || sql[i] == '\t' || sql[i] == '\r' || sql[i] == '\n':
			i++
		case strings.HasPrefix(sql[i:], "--"):
			nl := strings.IndexByte(sql[i:], '\n')
			if nl < 0 {
				return true
			}
			i += nl + 1
		case strings.HasPrefix(sql[i:], "/*"):
			end := strings.Index(sql[i+2:], "*/")
			if end < 0 {
				return true
			}
			i += 2 + end + 2
		default:
			return false
		}
	}
	return true
}

func (e *analyticsLiveEnv) runDataformModelsPass(ctx context.Context, t *testing.T, ordered []dataformAction, byName map[string]dataformAction, incremental bool) {
	t.Helper()
	for _, act := range ordered {
		if act.actionType != "incremental" || act.disabled {
			continue
		}
		script := compileActionScript(t, act, byName, incremental)
		e.mustExecSQL(ctx, t, fmt.Sprintf("dataform(%s, inc=%t)", act.name, incremental), script)
	}
}

func (e *analyticsLiveEnv) assertZeroDataformViolations(ctx context.Context, t *testing.T, byName map[string]dataformAction) {
	t.Helper()
	for _, name := range []string{"assert_no_orphan_tokens", "assert_no_unhandled_cycles"} {
		act, ok := byName[name]
		if !ok {
			t.Fatalf("missing Dataform assertion %s", name)
		}
		sql := renderDataformTemplate(t, act.mainQuery, act, byName, false, "")
		rows, _ := e.mustQueryRows(ctx, t, "assertion "+name, sql)
		if len(rows) != 0 {
			t.Fatalf("Dataform assertion %s returned %d violation(s), want 0: %#v", name, len(rows), rows)
		}
	}
}

func (e *analyticsLiveEnv) ensureBatch2Seeded(ctx context.Context, t *testing.T, exps analyticsLiveExporters) {
	t.Helper()
	if e.batch2Seeded {
		return
	}
	if err := exps.traces.ConsumeTraces(ctx, e.buildBatch2IncrementalTraces()); err != nil {
		t.Fatalf("ConsumeTraces batch2: %v", err)
	}
	e.waitForCount(ctx, t, "otel_spans_dedup batch2 count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_spans_dedup`", e.project, e.srcDataset), 14)
	e.batch2Seeded = true
}

func (e *analyticsLiveEnv) ensureMartsPopulated(ctx context.Context, t *testing.T) {
	t.Helper()
	if e.martsPopulated {
		return
	}
	actions, byName := loadDataformActions(t, e.project, e.srcDataset, e.project, e.martDataset)
	ordered := topologicalOrderDataform(t, actions, byName)
	e.runDataformModelsPass(ctx, t, ordered, byName, false)
	e.assertZeroDataformViolations(ctx, t, byName)
	e.martsPopulated = true
}

func (e *analyticsLiveEnv) verifyDataformDAGAndAssertions(ctx context.Context, t *testing.T, exps analyticsLiveExporters) {
	t.Helper()
	actions, byName := loadDataformActions(t, e.project, e.srcDataset, e.project, e.martDataset)
	ordered := topologicalOrderDataform(t, actions, byName)

	// 1. Full refresh pass against Batch 1.
	e.runDataformModelsPass(ctx, t, ordered, byName, false)
	e.assertZeroDataformViolations(ctx, t, byName)

	// Verify stg_run_window committed, all marts populated, and token-leaf rollup exact.
	rwRows, _ := e.mustQueryRows(ctx, t, "stg_run_window commit check",
		fmt.Sprintf("SELECT is_committed, window_start FROM `%s.%s.stg_run_window`", e.project, e.martDataset))
	if len(rwRows) != 1 || rwRows[0][0] != true {
		t.Fatalf("stg_run_window after full refresh = %#v, want 1 row with is_committed=true", rwRows)
	}
	// The log rollup commits its own window, independently of the trace marts.
	logsWindow := func(label string) (bool, time.Time) {
		rows, _ := e.mustQueryRows(ctx, t, label,
			fmt.Sprintf("SELECT is_committed, window_start FROM `%s.%s.stg_logs_run_window`", e.project, e.martDataset))
		if len(rows) != 1 {
			t.Fatalf("%s: stg_logs_run_window = %#v, want 1 row", label, rows)
		}
		committed, _ := rows[0][0].(bool)
		start, _ := rows[0][1].(time.Time)
		return committed, start
	}
	if committed, start := logsWindow("stg_logs_run_window full refresh check"); !committed || !start.Equal(time.Unix(0, 0)) {
		t.Fatalf("stg_logs_run_window after full refresh = (%v, %v), want committed at the epoch", committed, start)
	}
	// error_count never exceeds log_count and is zero exactly on the rows
	// grouped below ERROR.
	rollupRows, _ := e.mustQueryRows(ctx, t, "m_otel_log_volume_rollup consistency",
		fmt.Sprintf("SELECT COUNTIF(error_count > log_count OR (severity IN ('ERROR', 'CRITICAL', 'ALERT', 'EMERGENCY')) != (error_count = log_count) OR severity_number != 100 * (CASE severity WHEN 'DEFAULT' THEN 0 WHEN 'DEBUG' THEN 1 WHEN 'INFO' THEN 2 WHEN 'NOTICE' THEN 3 WHEN 'WARNING' THEN 4 WHEN 'ERROR' THEN 5 WHEN 'CRITICAL' THEN 6 WHEN 'ALERT' THEN 7 WHEN 'EMERGENCY' THEN 8 END)) FROM `%s.%s.m_otel_log_volume_rollup`", e.project, e.martDataset))
	if bad, _ := rollupRows[0][0].(int64); bad != 0 {
		t.Fatalf("m_otel_log_volume_rollup has %d rows whose severity, severity_number and error_count disagree", bad)
	}
	for _, mart := range []string{
		"stg_spans_dedup",
		"m_gen_ai_model_costs_hourly",
		"m_gen_ai_sessions_daily",
		"m_mcp_tool_usage_hourly",
		"m_gen_ai_agent_trajectory",
	} {
		rows, _ := e.mustQueryRows(ctx, t, "count "+mart,
			fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s`", e.project, e.martDataset, mart))
		cnt, _ := rows[0][0].(int64)
		if cnt < 1 {
			t.Fatalf("mart %s COUNT(*) = %d, want >= 1", mart, cnt)
		}
	}

	trajCheck, _ := e.mustQueryRows(ctx, t, "trajectory token integrity check",
		fmt.Sprintf("SELECT COUNT(*), COALESCE(SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_input_tokens, 0), 0)), 0), COALESCE(SUM(IF(is_token_leaf, COALESCE(gen_ai_usage_reasoning_tokens, 0), 0)), 0) FROM `%s.%s.m_gen_ai_agent_trajectory` WHERE trace_id = @tid",
			e.project, e.martDataset),
		bq.QueryParameter{Name: "tid", Value: hex.EncodeToString(analyticsTraceMain[:])},
	)
	if trajCheck[0][0].(int64) != 4 || trajCheck[0][1].(int64) != 100 || trajCheck[0][2].(int64) != 15 {
		t.Fatalf("trajectory traceMain summary (rows, leaf_in, leaf_reason) = %#v, want [4 100 15]", trajCheck[0])
	}

	// 2. Check-can-fail: prove assertions detect injected violations on scratch copies.
	e.verifyAssertionMutantsCanFail(ctx, t, byName)

	// 3. Batch 2 (replay + new span) -> Incremental pass #1 -> Incremental pass #2 (idempotent).
	e.ensureBatch2Seeded(ctx, t, exps)

	e.runDataformModelsPass(ctx, t, ordered, byName, true)
	e.assertZeroDataformViolations(ctx, t, byName)
	// The second (incremental) run of the log rollup starts at the bounded
	// lookback, not the epoch, and commits again.
	if committed, start := logsWindow("stg_logs_run_window incremental check"); !committed || !start.After(time.Now().Add(-5*time.Hour)) {
		t.Fatalf("stg_logs_run_window after an incremental pass = (%v, %v), want committed at the bounded lookback cutoff", committed, start)
	}

	incCounts1 := e.captureMartSnapshot(ctx, t)
	if incCounts1["m_gen_ai_agent_trajectory"] <= trajCheck[0][0].(int64) {
		t.Fatalf("expected trajectory rows > %d after batch2 incremental pass, got %d", trajCheck[0][0].(int64), incCounts1["m_gen_ai_agent_trajectory"])
	}

	martComparableSelect := func(dataset, table, kind string) string {
		fqn := fmt.Sprintf("`%s.%s.%s`", e.project, dataset, table)
		switch kind {
		case "stg_spans_dedup":
			return "SELECT * FROM " + fqn
		case "m_gen_ai_sessions_daily":
			// user_id and agent_name use ANY_VALUE in v_gen_ai_sessions.
			return "SELECT * EXCEPT (user_id, agent_name, top_error_types), TO_JSON_STRING(top_error_types) AS top_error_types_json FROM " + fqn
		case "m_gen_ai_agent_trajectory":
			return "SELECT * EXCEPT (agent_path), TO_JSON_STRING(agent_path) AS agent_path_json FROM " + fqn
		default:
			return "SELECT * EXCEPT (top_error_types), TO_JSON_STRING(top_error_types) AS top_error_types_json FROM " + fqn
		}
	}
	e.assertZeroExceptDistinct(ctx, t, "m_gen_ai_agent_trajectory vs v_gen_ai_agent_trajectory",
		martComparableSelect(e.martDataset, "m_gen_ai_agent_trajectory", "m_gen_ai_agent_trajectory"),
		fmt.Sprintf("SELECT * EXCEPT (status_message, agent_path), TO_JSON_STRING(agent_path) AS agent_path_json FROM `%s.%s.v_gen_ai_agent_trajectory`", e.project, e.srcDataset))

	incMarts := []string{
		"stg_spans_dedup",
		"m_gen_ai_model_costs_hourly",
		"m_gen_ai_sessions_daily",
		"m_mcp_tool_usage_hourly",
		"m_gen_ai_agent_trajectory",
	}
	for _, mart := range incMarts {
		e.mustExecSQL(ctx, t, "snapshot pass1 "+mart, fmt.Sprintf(
			"CREATE OR REPLACE TABLE `%s.%s._snap_inc1_%s` AS SELECT * FROM `%s.%s.%s`",
			e.project, e.assertDataset, mart, e.project, e.martDataset, mart))
	}

	// Rerun incremental with zero new telemetry: counts and full row-sets must match 1:1 (idempotent).
	e.runDataformModelsPass(ctx, t, ordered, byName, true)
	e.assertZeroDataformViolations(ctx, t, byName)
	incCounts2 := e.captureMartSnapshot(ctx, t)
	for mart, want := range incCounts1 {
		if incCounts2[mart] != want {
			t.Fatalf("non-idempotent incremental pass on %s: pass1=%d, pass2=%d", mart, want, incCounts2[mart])
		}
	}
	for _, mart := range incMarts {
		e.assertZeroExceptDistinct(ctx, t, "idempotent incremental pass "+mart,
			martComparableSelect(e.assertDataset, "_snap_inc1_"+mart, mart),
			martComparableSelect(e.martDataset, mart, mart))
	}
	e.martsPopulated = true
}

func (e *analyticsLiveEnv) assertZeroExceptDistinct(ctx context.Context, t *testing.T, label, leftSQL, rightSQL string, params ...bq.QueryParameter) {
	t.Helper()
	diffSQL := fmt.Sprintf("((%s\n) EXCEPT DISTINCT (%s\n)) UNION ALL ((%s\n) EXCEPT DISTINCT (%s\n))", leftSQL, rightSQL, rightSQL, leftSQL)
	diffRows, _ := e.mustQueryRows(ctx, t, label+" except_distinct", diffSQL, params...)
	if len(diffRows) != 0 {
		t.Fatalf("%s EXCEPT DISTINCT returned %d mismatched row(s), want 0: %#v", label, len(diffRows), diffRows)
	}
}

func (e *analyticsLiveEnv) captureMartSnapshot(ctx context.Context, t *testing.T) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, mart := range []string{
		"stg_spans_dedup",
		"m_gen_ai_model_costs_hourly",
		"m_gen_ai_sessions_daily",
		"m_mcp_tool_usage_hourly",
		"m_gen_ai_agent_trajectory",
	} {
		rows, _ := e.mustQueryRows(ctx, t, "snapshot "+mart,
			fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s`", e.project, e.martDataset, mart))
		out[mart] = rows[0][0].(int64)
	}
	return out
}

func (e *analyticsLiveEnv) verifyAssertionMutantsCanFail(ctx context.Context, t *testing.T, baseByName map[string]dataformAction) {
	t.Helper()
	mutantByName := make(map[string]dataformAction, len(baseByName))
	for k, v := range baseByName {
		if v.actionType != "declaration" {
			v.schema = e.assertDataset
		}
		mutantByName[k] = v
	}

	cloneTables := func() {
		for _, tbl := range []string{"stg_run_window", "stg_spans_dedup", "m_gen_ai_agent_trajectory"} {
			e.mustExecSQL(ctx, t, "clone "+tbl, fmt.Sprintf(
				"CREATE OR REPLACE TABLE `%s.%s.%s` AS SELECT * FROM `%s.%s.%s`",
				e.project, e.assertDataset, tbl, e.project, e.martDataset, tbl))
		}
	}

	// Mutant 1: Flip parent rollup span (analyticsSpanRoot) to is_token_leaf = TRUE => orphan tokens assertion catches double count.
	cloneTables()
	e.mustExecSQL(ctx, t, "inject double-counted leaf mutant", fmt.Sprintf(
		"UPDATE `%s.%s.m_gen_ai_agent_trajectory` SET is_token_leaf = TRUE WHERE span_id = @sid AND trace_id = @tid",
		e.project, e.assertDataset),
		bq.QueryParameter{Name: "sid", Value: hex.EncodeToString(analyticsSpanRoot[:])},
		bq.QueryParameter{Name: "tid", Value: hex.EncodeToString(analyticsTraceMain[:])},
	)
	orphanSQL := renderDataformTemplate(t, mutantByName["assert_no_orphan_tokens"].mainQuery, mutantByName["assert_no_orphan_tokens"], mutantByName, false, "")
	orphanRows, _ := e.mustQueryRows(ctx, t, "mutant assert_no_orphan_tokens", orphanSQL)
	if len(orphanRows) < 1 {
		t.Fatalf("mutant assert_no_orphan_tokens returned 0 violations, want >= 1")
	}
	if v, _ := orphanRows[0][3].(string); v != "token_double_counted_with_child" {
		t.Fatalf("mutant assert_no_orphan_tokens violation = %q, want token_double_counted_with_child", v)
	}

	// Mutant 2: Insert staged span missing from trajectory (simulating dropped parent cycle) => unhandled cycles assertion catches it.
	cloneTables()
	e.mustExecSQL(ctx, t, "inject dropped cycle span mutant", fmt.Sprintf(
		"INSERT INTO `%s.%s.stg_spans_dedup` SELECT start_time, end_time, duration_nano, duration_ms, trace_id, 'cycle_dropped_span' AS span_id, 'cycle_peer_span' AS parent_span_id, service_name, span_name, span_kind, status_code, gen_ai_operation_name, gen_ai_system, gen_ai_provider_name, gen_ai_request_model, gen_ai_response_model, gen_ai_agent_id, gen_ai_agent_name, gen_ai_agent_version, gen_ai_main_agent_id, gen_ai_main_agent_name, gen_ai_tool_name, gen_ai_tool_call_id, gen_ai_usage_input_tokens, gen_ai_usage_output_tokens, gen_ai_usage_reasoning_tokens, adk_session_id, adk_invocation_id, adk_user_id, error_type, declared_agent_name, agent_path_name FROM `%s.%s.stg_spans_dedup` LIMIT 1",
		e.project, e.assertDataset, e.project, e.assertDataset))
	cycleSQL := renderDataformTemplate(t, mutantByName["assert_no_unhandled_cycles"].mainQuery, mutantByName["assert_no_unhandled_cycles"], mutantByName, false, "")
	cycleRows, _ := e.mustQueryRows(ctx, t, "mutant assert_no_unhandled_cycles", cycleSQL)
	if len(cycleRows) < 1 {
		t.Fatalf("mutant assert_no_unhandled_cycles returned 0 violations, want >= 1")
	}
	if v, _ := cycleRows[0][4].(string); v != "span_missing_from_trajectory" {
		t.Fatalf("mutant assert_no_unhandled_cycles violation = %q, want span_missing_from_trajectory", v)
	}
}

// --- Looker Studio queries & report_spec.yaml alignment --------------------

type analyticsReportSpec struct {
	DataSources map[string]struct {
		Query            string            `yaml:"query"`
		Views            []string          `yaml:"views"`
		Marts            map[string]string `yaml:"marts"`
		DateField        string            `yaml:"date_field"`
		CalculatedFields []struct {
			Name string   `yaml:"name"`
			Uses []string `yaml:"uses"`
		} `yaml:"calculated_fields"`
	} `yaml:"data_sources"`
	Pages []struct {
		ID         string `yaml:"id"`
		DataSource string `yaml:"data_source"`
		Controls   []struct {
			Field string `yaml:"field"`
		} `yaml:"controls"`
		Components []struct {
			ID         string   `yaml:"id"`
			Dimensions []string `yaml:"dimensions"`
			Metrics    []struct {
				Field string `yaml:"field"`
			} `yaml:"metrics"`
			Filters []struct {
				Field string `yaml:"field"`
			} `yaml:"filters"`
			Sort *struct {
				Field string `yaml:"field"`
			} `yaml:"sort"`
		} `yaml:"components"`
	} `yaml:"pages"`
}

func (e *analyticsLiveEnv) verifyLookerStudioSurfaces(ctx context.Context, t *testing.T, exps analyticsLiveExporters) {
	t.Helper()
	e.ensureBatch2Seeded(ctx, t, exps)
	e.ensureMartsPopulated(ctx, t)
	rawSpec, err := os.ReadFile(filepath.Join("dashboards", "looker_studio", "report_spec.yaml"))
	if err != nil {
		t.Fatalf("read report_spec.yaml: %v", err)
	}
	var spec analyticsReportSpec
	if err := yaml.Unmarshal(rawSpec, &spec); err != nil {
		t.Fatalf("parse report_spec.yaml: %v", err)
	}

	startStr := e.todayMidnight.Add(-48 * time.Hour).Format("20060102")
	endStr := e.now.Format("20060102")
	params := []bq.QueryParameter{
		{Name: "DS_START_DATE", Value: startStr},
		{Name: "DS_END_DATE", Value: endStr},
	}

	colsByDS := map[string]map[string]bq.FieldType{}
	for dsID, ds := range spec.DataSources {
		rawSQL, err := os.ReadFile(filepath.Join("dashboards", "looker_studio", ds.Query))
		if err != nil {
			t.Fatalf("read %s: %v", ds.Query, err)
		}
		boundSQL := strings.NewReplacer(
			"YOUR_PROJECT_ID", e.project,
			"YOUR_DATASET_ID", e.srcDataset,
		).Replace(string(rawSQL))

		rows, bqSchema := e.mustQueryRows(ctx, t, "looker "+dsID+" ("+filepath.Base(ds.Query)+")", boundSQL, params...)
		if len(rows) < 1 {
			t.Fatalf("Looker query %s returned 0 rows, want >= 1", ds.Query)
		}

		emptyParams := []bq.QueryParameter{
			{Name: "DS_START_DATE", Value: "19990101"},
			{Name: "DS_END_DATE", Value: "19990102"},
		}
		emptyRows, _ := e.mustQueryRows(ctx, t, "looker empty "+dsID+" ("+filepath.Base(ds.Query)+")", boundSQL, emptyParams...)
		if len(emptyRows) != 0 {
			t.Errorf("Looker query %s empty window 19990101..19990102 returned %d rows, want 0", ds.Query, len(emptyRows))
		}

		colMap := map[string]bq.FieldType{}
		for _, f := range bqSchema {
			colMap[f.Name] = f.Type
			if f.Repeated || f.Type == bq.RecordFieldType || f.Type == bq.JSONFieldType {
				t.Errorf("Looker query %s outputs unsupported column %s (%s, repeated=%t)", ds.Query, f.Name, f.Type, f.Repeated)
			}
		}
		colsByDS[dsID] = colMap

		if ds.DateField != "" {
			if _, ok := colMap[ds.DateField]; !ok {
				t.Errorf("data source %s missing date_field %q in BigQuery output", dsID, ds.DateField)
			}
		}

		// Verify content-specific KPI assertions & Dataform mart parity.
		e.verifyLookerDSContentAndMartParity(ctx, t, dsID, string(rawSQL), rows, bqSchema, ds.Marts, params)
	}

	// Verify every field referenced in report_spec.yaml pages exists in BigQuery output or calculated fields.
	for _, page := range spec.Pages {
		ds := spec.DataSources[page.DataSource]
		colMap := colsByDS[page.DataSource]
		calcSet := map[string]bool{}
		for _, cf := range ds.CalculatedFields {
			calcSet[cf.Name] = true
			for _, u := range cf.Uses {
				if _, ok := colMap[u]; !ok {
					t.Errorf("%s calculated field %s uses %q which query does not output", page.DataSource, cf.Name, u)
				}
			}
		}
		checkField := func(loc, field string) {
			if field == "" {
				return
			}
			if _, ok := colMap[field]; !ok && !calcSet[field] {
				t.Errorf("page %s %s references unknown field %q", page.ID, loc, field)
			}
		}
		for _, ctrl := range page.Controls {
			checkField("control", ctrl.Field)
		}
		for _, comp := range page.Components {
			for _, d := range comp.Dimensions {
				checkField(comp.ID+".dimension", d)
			}
			for _, m := range comp.Metrics {
				checkField(comp.ID+".metric", m.Field)
			}
			for _, fl := range comp.Filters {
				checkField(comp.ID+".filter", fl.Field)
			}
			if comp.Sort != nil {
				checkField(comp.ID+".sort", comp.Sort.Field)
			}
		}
	}
}

func (e *analyticsLiveEnv) verifyLookerDSContentAndMartParity(
	ctx context.Context,
	t *testing.T,
	dsID, rawSQL string,
	rows [][]bq.Value,
	bqSchema bq.Schema,
	marts map[string]string,
	params []bq.QueryParameter,
) {
	t.Helper()
	colIdx := map[string]int{}
	for i, f := range bqSchema {
		colIdx[f.Name] = i
	}

	switch dsID {
	case "ds0":
		// Verify gemini-2.5-pro input/reasoning tokens and error rollup across (agent, hour) rows.
		var foundPro, foundRateLimit bool
		var sumInput, sumReasoning, sumErrors int64
		for _, r := range rows {
			if m, _ := r[colIdx["model"]].(string); m == "gemini-2.5-pro" {
				foundPro = true
				inTok, _ := r[colIdx["total_input_tokens"]].(int64)
				reasonTok, _ := r[colIdx["total_reasoning_tokens"]].(int64)
				errCnt, _ := r[colIdx["error_count"]].(int64)
				sumInput += inTok
				sumReasoning += reasonTok
				sumErrors += errCnt
				if topErr, _ := r[colIdx["top_error_types"]].(string); strings.Contains(topErr, "RATE_LIMIT_EXCEEDED") {
					foundRateLimit = true
				}
			}
		}
		if !foundPro {
			t.Errorf("ds0 missing gemini-2.5-pro row")
		}
		if sumInput != 130 {
			t.Errorf("ds0 gemini-2.5-pro sum(total_input_tokens) = %d, want 130 (batch1 100 + batch2 30)", sumInput)
		}
		if sumReasoning != 15 {
			t.Errorf("ds0 gemini-2.5-pro sum(total_reasoning_tokens) = %d, want 15", sumReasoning)
		}
		if sumErrors < 1 || !foundRateLimit {
			t.Errorf("ds0 gemini-2.5-pro errors=%d, foundRateLimit=%t, want >=1 with RATE_LIMIT_EXCEEDED", sumErrors, foundRateLimit)
		}
	case "ds1":
		// Midnight session appears on 2 distinct UTC dates (1 row per date).
		midRows := 0
		for _, r := range rows {
			if s, _ := r[colIdx["session_id"]].(string); s == "sess-midnight-"+e.runID {
				midRows++
			}
		}
		if midRows != 2 {
			t.Errorf("ds1 midnight session row count = %d, want 2 (1 per UTC date)", midRows)
		}
	case "ds2":
		var sawMCP, sawGenAI, sawDual bool
		for _, r := range rows {
			src, _ := r[colIdx["source"]].(string)
			method, _ := r[colIdx["mcp_method_name"]].(string)
			tagged, _ := r[colIdx["gen_ai_tagged_call_count"]].(int64)
			mcpOnly, _ := r[colIdx["mcp_only_call_count"]].(int64)
			if src == "mcp" {
				sawMCP = true
				if method == "tools/call" && tagged == 1 && mcpOnly == 0 {
					sawDual = true
				}
			}
			if src == "gen_ai" {
				sawGenAI = true
			}
		}
		if !sawMCP || !sawGenAI || !sawDual {
			t.Errorf("ds2 flags sawMCP=%t sawGenAI=%t sawDual=%t, want all true", sawMCP, sawGenAI, sawDual)
		}
	case "ds3":
		var sawPath bool
		for _, r := range rows {
			if ap, _ := r[colIdx["agent_path"]].(string); ap == "planner > researcher" {
				sawPath = true
			}
		}
		if !sawPath {
			t.Errorf("ds3 missing expected 'planner > researcher' agent_path row")
		}
	case "ds4":
		// 4 inserted rows with 1 duplicate alert_id => 3 deduplicated rows across all 3 alert kinds.
		if len(rows) != 3 {
			t.Errorf("ds4 deduplicated alert count = %d, want 3", len(rows))
		}
		kinds := map[string]bool{}
		for _, r := range rows {
			if k, _ := r[colIdx["alert_kind"]].(string); k != "" {
				kinds[k] = true
			}
		}
		for _, wantKind := range []string{"TOOL_ERROR", "TOKEN_BUDGET_BURN", "AGENT_LATENCY_HIGH"} {
			if !kinds[wantKind] {
				t.Errorf("ds4 missing deduplicated alert_kind %s (got %v)", wantKind, kinds)
			}
		}
	case "ds5":
		if len(rows) < 2 {
			t.Errorf("ds5 metric_exemplars row count = %d, want >= 2", len(rows))
		}
	}

	// Execute against Dataform mart tables for marts-backed data sources and confirm row-set parity.
	if len(marts) > 0 {
		viewSQL := strings.TrimRight(strings.ReplaceAll(strings.ReplaceAll(rawSQL, "YOUR_PROJECT_ID", e.project), "YOUR_DATASET_ID", e.srcDataset), " \t\r\n;")
		repl := []string{"YOUR_PROJECT_ID", e.project}
		for viewName, martName := range marts {
			repl = append(repl, "YOUR_DATASET_ID."+viewName, e.martDataset+"."+martName)
		}
		// Remaining views (e.g. ds2 second UNION branch v_gen_ai_tool_usage) resolve to srcDataset.
		repl = append(repl, "YOUR_DATASET_ID", e.srcDataset)
		martSQL := strings.TrimRight(strings.NewReplacer(repl...).Replace(rawSQL), " \t\r\n;")
		martRows, _ := e.mustQueryRows(ctx, t, "looker mart "+dsID, martSQL, params...)
		if len(martRows) != len(rows) {
			t.Errorf("looker %s mart parity row count = %d, companion view row count = %d", dsID, len(martRows), len(rows))
		}
		wrap := func(q string) string {
			if dsID == "ds1" {
				// user_id and agent_name use ANY_VALUE in v_gen_ai_sessions.
				return fmt.Sprintf("SELECT * EXCEPT (user_id, agent_name) FROM (%s\n)", q)
			}
			return q
		}
		e.assertZeroExceptDistinct(ctx, t, "looker "+dsID+" view vs mart", wrap(viewSQL), wrap(martSQL), params...)
	}
}

// --- Grafana BigQuery & Prometheus verification ----------------------------

type analyticsGrafanaDashboard struct {
	Templating struct {
		List []struct {
			Name  string          `json:"name"`
			Type  string          `json:"type"`
			Query json.RawMessage `json:"query"`
		} `json:"list"`
	} `json:"templating"`
	Panels []analyticsGrafanaPanel `json:"panels"`
}

type analyticsGrafanaPanel struct {
	ID      int                     `json:"id"`
	Title   string                  `json:"title"`
	Type    string                  `json:"type"`
	Panels  []analyticsGrafanaPanel `json:"panels"`
	Targets []struct {
		RawSQL string `json:"rawSql"`
		Expr   string `json:"expr"`
	} `json:"targets"`
}

type analyticsMetadataYAML struct {
	Telemetry struct {
		Metrics map[string]struct {
			Unit       string `yaml:"unit"`
			Attributes []string
			Sum        *struct {
				ValueType string `yaml:"value_type"`
				Monotonic bool   `yaml:"monotonic"`
			} `yaml:"sum"`
			Gauge *struct {
				ValueType string `yaml:"value_type"`
			} `yaml:"gauge"`
			Histogram *struct {
				ValueType string `yaml:"value_type"`
			} `yaml:"histogram"`
		} `yaml:"metrics"`
		Resource map[string]any `yaml:"resource"`
	} `yaml:"telemetry"`
}

func (e *analyticsLiveEnv) verifyGrafanaBigQueryAndPrometheus(ctx context.Context, t *testing.T, exps analyticsLiveExporters) {
	t.Helper()
	e.ensureBatch2Seeded(ctx, t, exps)
	rawBQ, err := os.ReadFile(filepath.Join("dashboards", "grafana", "genai-and-mcp-overview.json"))
	if err != nil {
		t.Fatalf("read genai-and-mcp-overview.json: %v", err)
	}
	var bqDash analyticsGrafanaDashboard
	if err := json.Unmarshal(rawBQ, &bqDash); err != nil {
		t.Fatalf("parse genai-and-mcp-overview.json: %v", err)
	}

	fromMs := strconv.FormatInt(e.todayMidnight.Add(-48*time.Hour).UnixMilli(), 10)
	toMs := strconv.FormatInt(e.now.Add(15*time.Minute).UnixMilli(), 10)

	expandGrafanaSQL := func(raw string, services []string) string {
		svcJSON, _ := json.Marshal(services)
		s := strings.NewReplacer(
			"${VAR_PROJECT}", e.project,
			"${VAR_DATASET}", e.srcDataset,
			"${__from}", fromMs,
			"${__to}", toMs,
			"${service:json}", string(svcJSON),
		).Replace(raw)
		return regexp.MustCompile(`\$__timeFilter\(([^)]+)\)`).ReplaceAllString(
			s, fmt.Sprintf("($1 BETWEEN TIMESTAMP_MILLIS(%s) AND TIMESTAMP_MILLIS(%s))", fromMs, toMs),
		)
	}

	// 1. Execute template variable `service` query and confirm all 3 synthetic services appear cleanly.
	var varSQL string
	for _, tv := range bqDash.Templating.List {
		if tv.Name == "service" {
			var qObj struct {
				RawSQL string `json:"rawSql"`
			}
			if err := json.Unmarshal(tv.Query, &qObj); err != nil {
				t.Fatalf("parse service templating query: %v", err)
			}
			varSQL = qObj.RawSQL
		}
	}
	if varSQL == "" {
		t.Fatal("missing service template variable rawSql in genai-and-mcp-overview.json")
	}
	svcRows, _ := e.mustQueryRows(ctx, t, "grafana service variable", expandGrafanaSQL(varSQL, []string{"__all"}))
	seenSvcs := map[string]bool{}
	for _, r := range svcRows {
		if s, _ := r[0].(string); s != "" {
			seenSvcs[s] = true
		}
	}
	for _, want := range []string{e.svcPrimary, e.svcMidnight, e.svcEmptyUser} {
		if !seenSvcs[want] {
			t.Errorf("grafana service variable missing %q (got %v)", want, seenSvcs)
		}
	}

	// 2. Flatten and execute ALL 24 panel BigQuery queries under `__all`.
	var panels []analyticsGrafanaPanel
	var collect func([]analyticsGrafanaPanel)
	collect = func(ps []analyticsGrafanaPanel) {
		for _, p := range ps {
			if len(p.Targets) > 0 {
				panels = append(panels, p)
			}
			collect(p.Panels)
		}
	}
	collect(bqDash.Panels)
	if len(panels) != 24 {
		t.Fatalf("grafana BigQuery target panel count = %d, want 24", len(panels))
	}

	panelSQL := map[int]string{}
	for _, p := range panels {
		if len(p.Targets) == 0 || p.Targets[0].RawSQL == "" {
			t.Fatalf("panel %d (%s) missing rawSql", p.ID, p.Title)
		}
		panelSQL[p.ID] = p.Targets[0].RawSQL
		rows, _ := e.mustQueryRows(ctx, t, fmt.Sprintf("grafana panel %d (%s)", p.ID, p.Title), expandGrafanaSQL(p.Targets[0].RawSQL, []string{"__all"}))
		if len(rows) < 1 {
			t.Errorf("grafana panel %d (%s) returned 0 rows under __all", p.ID, p.Title)
		}
	}

	// 3. Prove midnight-crossing session correctness (Panel 13, 14, 15, 16) + empty user exclusion + alert dedup.
	p13Mid, _ := e.mustQueryRows(ctx, t, "panel 13 midnight svc", expandGrafanaSQL(panelSQL[13], []string{e.svcMidnight}))
	if len(p13Mid) != 1 || p13Mid[0][0].(int64) != 1 || p13Mid[0][1].(int64) != 1 {
		t.Fatalf("panel 13 midnight svc = %#v, want [sessions=1, active_users=1]", p13Mid)
	}
	p14Mid, _ := e.mustQueryRows(ctx, t, "panel 14 midnight svc", expandGrafanaSQL(panelSQL[14], []string{e.svcMidnight}))
	if len(p14Mid) != 1 || p14Mid[0][0].(float64) != 5.0 || p14Mid[0][1].(float64) != 900000.0 {
		t.Fatalf("panel 14 midnight svc = %#v, want [avg_turns=5.0, avg_duration_ms=900000.0]", p14Mid)
	}
	p16Mid, _ := e.mustQueryRows(ctx, t, "panel 16 midnight svc", expandGrafanaSQL(panelSQL[16], []string{e.svcMidnight}))
	if len(p16Mid) != 1 || p16Mid[0][0].(string) != "04-06" || p16Mid[0][1].(int64) != 1 {
		t.Fatalf("panel 16 midnight svc = %#v, want single bucket ['04-06', 1]", p16Mid)
	}

	p13All, _ := e.mustQueryRows(ctx, t, "panel 13 all svcs", expandGrafanaSQL(panelSQL[13], []string{"__all"}))
	p16All, _ := e.mustQueryRows(ctx, t, "panel 16 all svcs", expandGrafanaSQL(panelSQL[16], []string{"__all"}))
	var sumBuckets int64
	for _, r := range p16All {
		sumBuckets += r[1].(int64)
	}
	if sumBuckets != p13All[0][0].(int64) {
		t.Fatalf("SUM(panel 16 sessions)=%d != panel 13 COUNT(DISTINCT (service_name, session_id))=%d", sumBuckets, p13All[0][0].(int64))
	}
	// Empty-window semantics under unknown service filter: Panel 13 returns [0, 0],
	// Panel 14 returns 1 row [NULL, NULL], Panel 16 returns 0 rows.
	nonexistentSvc := "svc-nonexistent-" + e.runID
	p13EmptySvc, _ := e.mustQueryRows(ctx, t, "panel 13 empty window", expandGrafanaSQL(panelSQL[13], []string{nonexistentSvc}))
	if len(p13EmptySvc) != 1 || len(p13EmptySvc[0]) != 2 || p13EmptySvc[0][0] != int64(0) || p13EmptySvc[0][1] != int64(0) {
		t.Fatalf("panel 13 empty window = %#v, want [[0, 0]]", p13EmptySvc)
	}
	p14EmptySvc, _ := e.mustQueryRows(ctx, t, "panel 14 empty window", expandGrafanaSQL(panelSQL[14], []string{nonexistentSvc}))
	if len(p14EmptySvc) != 1 || len(p14EmptySvc[0]) != 2 || p14EmptySvc[0][0] != nil || p14EmptySvc[0][1] != nil {
		t.Fatalf("panel 14 empty window = %#v, want 1 row [[<nil>, <nil>]]", p14EmptySvc)
	}
	p16EmptySvc, _ := e.mustQueryRows(ctx, t, "panel 16 empty window", expandGrafanaSQL(panelSQL[16], []string{nonexistentSvc}))
	if len(p16EmptySvc) != 0 {
		t.Fatalf("panel 16 empty window returned %d rows (%#v), want 0", len(p16EmptySvc), p16EmptySvc)
	}
	// svcPrimary ("user-alice", plus batch2 "user-bob"), svcMidnight ("user-midnight"), svcEmptyUser ("") => 3 active users across 4 sessions.
	if p13All[0][0].(int64) != 4 {
		t.Fatalf("panel 13 all svcs sessions = %d, want 4", p13All[0][0].(int64))
	}
	if p13All[0][1].(int64) != 3 {
		t.Fatalf("panel 13 all svcs active_users = %d, want 3 (empty user_id excluded)", p13All[0][1].(int64))
	}
	p13Empty, _ := e.mustQueryRows(ctx, t, "panel 13 empty user svc", expandGrafanaSQL(panelSQL[13], []string{e.svcEmptyUser}))
	if p13Empty[0][1].(int64) != 0 {
		t.Fatalf("panel 13 svcEmptyUser active_users = %d, want 0", p13Empty[0][1].(int64))
	}
	p26All, _ := e.mustQueryRows(ctx, t, "panel 26 alerts", expandGrafanaSQL(panelSQL[26], []string{"__all"}))
	if p26All[0][0].(int64) != 3 {
		t.Fatalf("panel 26 deduplicated alerts = %d, want 3", p26All[0][0].(int64))
	}

	// 4. Cross-verify collector-self-telemetry.json PromQL metrics & labels against metadata.yaml + live ManualReader.
	e.verifyPrometheusSelfTelemetryContract(ctx, t)
}

func (e *analyticsLiveEnv) verifyPrometheusSelfTelemetryContract(ctx context.Context, t *testing.T) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := e.reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect live ManualReader metrics: %v", err)
	}
	rawMD, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatalf("read metadata.yaml: %v", err)
	}
	var md analyticsMetadataYAML
	if err := yaml.Unmarshal(rawMD, &md); err != nil {
		t.Fatalf("parse metadata.yaml: %v", err)
	}

	rawProm, err := os.ReadFile(filepath.Join("dashboards", "grafana", "collector-self-telemetry.json"))
	if err != nil {
		t.Fatalf("read collector-self-telemetry.json: %v", err)
	}
	var promDash analyticsGrafanaDashboard
	if err := json.Unmarshal(rawProm, &promDash); err != nil {
		t.Fatalf("parse collector-self-telemetry.json: %v", err)
	}

	// Index live emitted OTel metrics and their emitted attribute keys.
	liveMetrics := map[string]map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			attrs := liveMetrics[m.Name]
			if attrs == nil {
				attrs = map[string]bool{}
				liveMetrics[m.Name] = attrs
			}
			addAttrSet := func(set attribute.Set) {
				for _, kv := range set.ToSlice() {
					attrs[string(kv.Key)] = true
				}
			}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Sum[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Histogram[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.ExponentialHistogram[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.ExponentialHistogram[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Summary:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			default:
				t.Errorf("unhandled metricdata.Aggregation type %T for metric %s", m.Data, m.Name)
			}
		}
	}

	// Verify core active self-telemetry instruments were actually emitted live during the test.
	for _, mustEmit := range []string{
		"otelcol_exporter_bigquery_acknowledged_rows",
		"otelcol_exporter_bigquery_rejected_rows",
		"otelcol_exporter_bigquery_quarantined_rows",
		"otelcol_exporter_bigquery_redacted_values",
		"otelcol_exporter_bigquery_append_result_wait",
		"otelcol_exporter_bigquery_inflight_requests",
		"otelcol_exporter_bigquery_backpressure_level",
		"otelcol_exporter_bigquery_effective_request_bytes",
		"otelcol_exporter_bigquery_append_bytes",
	} {
		if _, ok := liveMetrics[mustEmit]; !ok {
			t.Errorf("live ManualReader did not emit expected self-telemetry metric %s", mustEmit)
		}
	}

	// Verify every PromQL query selector & grouping label matches metadata.yaml and live emitted labels.
	nameRe := regexp.MustCompile(`__name__=~"([^"]+)"`)
	byRe := regexp.MustCompile(`(?:sum|max)\s+by\s*\(([^)]+)\)`)
	suffixStripRe := regexp.MustCompile(`(\([^)]*\)\??|_bucket|_total)$`)

	var collectPromExprs func([]analyticsGrafanaPanel) []string
	collectPromExprs = func(ps []analyticsGrafanaPanel) []string {
		var out []string
		for _, p := range ps {
			for _, tg := range p.Targets {
				if tg.Expr != "" {
					out = append(out, tg.Expr)
				}
			}
			out = append(out, collectPromExprs(p.Panels)...)
		}
		return out
	}

	exprs := collectPromExprs(promDash.Panels)
	if len(exprs) == 0 {
		t.Fatal("no PromQL target expressions found in collector-self-telemetry.json")
	}
	for _, expr := range exprs {
		nm := nameRe.FindStringSubmatch(expr)
		if len(nm) != 2 {
			t.Errorf("PromQL expression missing __name__ regex selector: %q", expr)
			continue
		}
		base := nm[1]
		for {
			next := suffixStripRe.ReplaceAllString(base, "")
			if next == base {
				break
			}
			base = next
		}
		decl, ok := md.Telemetry.Metrics[base]
		if !ok {
			t.Errorf("PromQL references undeclared metric %q (from %q)", base, nm[1])
			continue
		}
		for _, bm := range byRe.FindAllStringSubmatch(expr, -1) {
			for _, lbl := range strings.Split(bm[1], ",") {
				lbl = strings.TrimSpace(lbl)
				if lbl == "instance" || lbl == "le" {
					continue
				}
				if !slices.Contains(decl.Attributes, lbl) {
					t.Errorf("PromQL groups %s by undeclared attribute %q (declared: %v)", base, lbl, decl.Attributes)
				}
				if emittedAttrs, active := liveMetrics[base]; active && !emittedAttrs[lbl] {
					t.Errorf("live metric %s did not emit label %q required by PromQL %q (emitted: %v)", base, lbl, expr, emittedAttrs)
				}
			}
		}
	}
}
