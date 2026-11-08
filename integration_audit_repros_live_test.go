// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/validate"
)

// TestLiveAuditFixesEndToEndBigQuery exercises the production fixes against live
// BigQuery through NewFactory():
//  1. Redacted log/metric batches across split slices with a transient slice-1
//     fault replay cleanly via PreserveLogOrdinalPeers / PreserveMetricOrdinalPeers
//     using post-redaction identity, persisting both distinct peers in the
//     _dedup views without leaking raw tokens.
//  2. Envelope-aware splitting keeps every wire AppendRowsRequest (including
//     WriteStream and ProtoSchema overhead) within Write.MaxRequestBytes.
//  3. validate.Run verifies all tables, all three _dedup views, all 11
//     companion views, and all three optional companion TVFs when deployed.
func TestLiveAuditFixesEndToEndBigQuery(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live BigQuery audit fixes integration test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	// Cancel last (LIFO cleanup) so ephemeral dataset cleanup finishes first.
	t.Cleanup(cancel)

	dataset := uniqueEphemeralDatasetID("otel_audit_fixes_it")
	admin := newLiveBigQueryAdmin(ctx, t, project, dataset, location)

	var (
		logsFaultInjected    atomic.Bool
		metricsFaultInjected atomic.Bool
		spansRequestCount    atomic.Int64
		maxSpansWireBytes    atomic.Int64
	)

	origNewMWClient := newManagedWriterClient
	t.Cleanup(func() { newManagedWriterClient = origNewMWClient })
	interceptor := func(
		sCtx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		cs, err := streamer(sCtx, desc, cc, method, opts...)
		if err != nil || !strings.HasSuffix(method, "/AppendRows") {
			return cs, err
		}
		return &auditLiveClientStream{
			ClientStream:         cs,
			logsTable:            defaultLogsTable,
			metricsTable:         defaultMetricsTable,
			spansTable:           defaultSpansTable,
			logsFaultInjected:    &logsFaultInjected,
			metricsFaultInjected: &metricsFaultInjected,
			spansRequestCount:    &spansRequestCount,
			maxSpansWireBytes:    &maxSpansWireBytes,
		}, nil
	}
	newManagedWriterClient = func(cCtx context.Context, projectID string, opts ...option.ClientOption) (*managedwriter.Client, error) {
		wrapped := append(append([]option.ClientOption(nil), opts...),
			option.WithGRPCDialOption(grpc.WithChainStreamInterceptor(interceptor)),
		)
		return origNewMWClient(cCtx, projectID, wrapped...)
	}

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Project = project
	cfg.Dataset = dataset
	cfg.Location = location
	cfg.AutoCreate.Dataset = false
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = true
	cfg.Quarantine.Enabled = true
	cfg.TimeoutSettings.Timeout = 30 * time.Second
	cfg.QueueSettings = configoptional.None[exporterhelper.QueueBatchConfig]()
	cfg.BackOffConfig.Enabled = true
	cfg.BackOffConfig.InitialInterval = 100 * time.Millisecond
	cfg.BackOffConfig.MaxInterval = time.Second
	cfg.BackOffConfig.MaxElapsedTime = 60 * time.Second
	cfg.Redaction.Enabled = true
	cfg.Redaction.RedactLogBody = true
	cfg.Redaction.BlockedValuePatterns = []string{`sk-live-[0-9a-f]+`}
	cfg.Write.MaxInflightRequests = 1
	cfg.Write.MaxRequestBytes = 16384
	cfg.Write.MaxRowBytes = 8192
	cfg.Write.MaxInflightBytes = 131072

	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	tracesExp, err := factory.CreateTraces(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}
	logsExp, err := factory.CreateLogs(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatalf("CreateLogs: %v", err)
	}
	metricsExp, err := factory.CreateMetrics(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatalf("CreateMetrics: %v", err)
	}

	host := componenttest.NewNopHost()
	if err := tracesExp.Start(ctx, host); err != nil {
		t.Fatalf("tracesExp.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := tracesExp.Shutdown(context.Background()); err != nil {
			t.Errorf("tracesExp.Shutdown: %v", err)
		}
	})
	if err := logsExp.Start(ctx, host); err != nil {
		t.Fatalf("logsExp.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := logsExp.Shutdown(context.Background()); err != nil {
			t.Errorf("logsExp.Shutdown: %v", err)
		}
	})
	if err := metricsExp.Start(ctx, host); err != nil {
		t.Fatalf("metricsExp.Start: %v", err)
	}
	t.Cleanup(func() {
		if err := metricsExp.Shutdown(context.Background()); err != nil {
			t.Errorf("metricsExp.Shutdown: %v", err)
		}
	})

	pad := strings.Repeat("p", 7500)
	now := time.Now().UTC()

	// 1. Logs: 2 records differing ONLY in redacted secret, split across 2 slices.
	ld := plog.NewLogs()
	lrSlice := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for _, secret := range []string{"sk-live-aaaa1111", "sk-live-bbbb2222"} {
		rec := lrSlice.AppendEmpty()
		rec.SetTimestamp(pcommon.NewTimestampFromTime(now))
		rec.SetObservedTimestamp(pcommon.NewTimestampFromTime(now))
		rec.SetSeverityText("INFO")
		rec.Body().SetStr("live audit secret " + secret)
		rec.Attributes().PutStr("pad", pad)
		rec.Attributes().PutInt("peer_slot_unchanged", 1)
	}
	if err := logsExp.ConsumeLogs(ctx, ld); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	if !logsFaultInjected.Load() {
		t.Fatal("expected slice-1 transient fault injection on logs stream, but none fired")
	}

	// 2. Metrics: 2 data points differing ONLY in redacted secret, split across 2 slices.
	md := pmetric.NewMetrics()
	sm := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty()
	m := sm.Metrics().AppendEmpty()
	m.SetName("live.audit.redacted.peers")
	m.SetUnit("1")
	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for _, secret := range []string{"sk-live-aaaa1111", "sk-live-bbbb2222"} {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetStartTimestamp(pcommon.NewTimestampFromTime(now.Add(-time.Second)))
		dp.SetTimestamp(pcommon.NewTimestampFromTime(now))
		dp.SetIntValue(42)
		dp.Attributes().PutStr("note", "token="+secret)
		dp.Attributes().PutStr("pad", pad)
	}
	if err := metricsExp.ConsumeMetrics(ctx, md); err != nil {
		t.Fatalf("ConsumeMetrics: %v", err)
	}
	if !metricsFaultInjected.Load() {
		t.Fatal("expected slice-1 transient fault injection on metrics stream, but none fired")
	}

	// 3. Traces: 3 padded spans verifying envelope-aware splitting keeps every
	// wire AppendRowsRequest within cfg.Write.MaxRequestBytes.
	td := ptrace.NewTraces()
	spans := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
	var traceID pcommon.TraceID
	copy(traceID[:], []byte("1234567890abcdef"))
	for i := range 3 {
		sp := spans.AppendEmpty()
		sp.SetTraceID(traceID)
		var spanID pcommon.SpanID
		spanID[7] = byte(i + 1)
		sp.SetSpanID(spanID)
		sp.SetName(fmt.Sprintf("envelope-split-span-%d", i))
		sp.SetStartTimestamp(pcommon.NewTimestampFromTime(now))
		sp.SetEndTimestamp(pcommon.NewTimestampFromTime(now.Add(time.Millisecond)))
		sp.Attributes().PutStr("pad", pad)
	}
	if err := tracesExp.ConsumeTraces(ctx, td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if gotReqs := spansRequestCount.Load(); gotReqs < 3 {
		t.Fatalf("spans AppendRows wire requests = %d, want >= 3 with envelope-aware split", gotReqs)
	}
	if maxWire := maxSpansWireBytes.Load(); maxWire > int64(cfg.Write.MaxRequestBytes) {
		t.Fatalf("max spans AppendRowsRequest wire size = %d, exceeds MaxRequestBytes=%d", maxWire, cfg.Write.MaxRequestBytes)
	}

	// Verify real BigQuery _dedup tables landed all rows cleanly with zero raw tokens.
	if err := waitForRowCount(ctx, admin, project, dataset, cfg.Logs.Table+"_dedup", 2); err != nil {
		t.Fatalf("otel_logs_dedup row count: %v", err)
	}
	if err := waitForRowCount(ctx, admin, project, dataset, cfg.Metrics.Table+"_dedup", 2); err != nil {
		t.Fatalf("otel_metrics_dedup row count: %v", err)
	}
	if err := waitForRowCount(ctx, admin, project, dataset, cfg.Traces.Table+"_dedup", 3); err != nil {
		t.Fatalf("otel_spans_dedup row count: %v", err)
	}

	verifyLogsSQL := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total,
			COUNT(DISTINCT record_fingerprint) AS distinct_fps,
			COUNTIF(CONTAINS_SUBSTR(TO_JSON_STRING(body), 'sk-live-') OR CONTAINS_SUBSTR(TO_JSON_STRING(attributes), 'sk-live-')) AS raw_leaks,
			COUNTIF(CONTAINS_SUBSTR(TO_JSON_STRING(body), '[REDACTED]')) AS redacted_bodies
		FROM `+"`%s.%s.%s_dedup`", project, dataset, cfg.Logs.Table)
	assertLiveAggregateQuery(ctx, t, admin, "otel_logs_dedup", verifyLogsSQL, 2, 2, 0, 2)

	verifyMetricsSQL := fmt.Sprintf(`
		SELECT
			COUNT(*) AS total,
			COUNT(DISTINCT point_fingerprint) AS distinct_fps,
			COUNTIF(CONTAINS_SUBSTR(TO_JSON_STRING(attributes), 'sk-live-')) AS raw_leaks,
			COUNTIF(CONTAINS_SUBSTR(TO_JSON_STRING(attributes), '[REDACTED]')) AS redacted_attrs
		FROM `+"`%s.%s.%s_dedup`", project, dataset, cfg.Metrics.Table)
	assertLiveAggregateQuery(ctx, t, admin, "otel_metrics_dedup", verifyMetricsSQL, 2, 2, 0, 2)

	// 4. Provision all 3 companion TVFs and validate the dataset end-to-end.
	for tvfName, ddl := range schema.CompanionTVFDDLs(project, dataset, cfg.Traces.Table, cfg.Logs.Table) {
		job, err := admin.Query(ddl).Run(ctx)
		if err != nil {
			t.Fatalf("create TVF %s: %v", tvfName, err)
		}
		st, err := job.Wait(ctx)
		if err != nil {
			t.Fatalf("wait TVF %s: %v", tvfName, err)
		}
		if err := st.Err(); err != nil {
			t.Fatalf("TVF %s DDL status: %v", tvfName, err)
		}
	}

	// Restore default writer constructor before validate.Run opens its probe.
	newManagedWriterClient = origNewMWClient
	report, err := validate.Run(ctx, validate.Config{
		Project: project,
		Dataset: dataset,
	})
	if err != nil {
		t.Fatalf("validate.Run: %v", err)
	}
	if !report.Conforms || report.Summary.Fail != 0 || report.Summary.Warn != 0 || report.Summary.Skip != 0 {
		t.Fatalf("validate.Run report non-conformant: conforms=%v summary=%+v checks=%+v",
			report.Conforms, report.Summary, report.Checks)
	}
	wantPassViews := []string{
		cfg.Traces.Table + "_dedup",
		cfg.Logs.Table + "_dedup",
		cfg.Metrics.Table + "_dedup",
		schema.GenAILogsTVFName,
		schema.GenAIMetricExemplarsTVFName,
		schema.GenAIAgentTrajectoryTVFName,
	}
	gotChecks := make(map[string]validate.Status, len(report.Checks))
	for _, c := range report.Checks {
		if c.Category == validate.CategoryViews {
			gotChecks[c.Name] = c.Status
		}
	}
	for _, name := range wantPassViews {
		if gotChecks[name] != validate.StatusPass {
			t.Fatalf("validate view/TVF check %q = %q, want %q", name, gotChecks[name], validate.StatusPass)
		}
	}
}

func assertLiveAggregateQuery(
	ctx context.Context,
	t *testing.T,
	client *bq.Client,
	label, sql string,
	wantTotal, wantDistinctFPs, wantLeaks, wantRedacted int64,
) {
	t.Helper()
	it, err := client.Query(sql).Read(ctx)
	if err != nil {
		t.Fatalf("query %s: %v", label, err)
	}
	var row []bq.Value
	err = it.Next(&row)
	if err != nil && !errors.Is(err, iterator.Done) {
		t.Fatalf("read %s: %v", label, err)
	}
	if len(row) != 4 {
		t.Fatalf("%s returned %d columns, want 4", label, len(row))
	}
	total, _ := row[0].(int64)
	distinctFPs, _ := row[1].(int64)
	leaks, _ := row[2].(int64)
	redacted, _ := row[3].(int64)
	if total != wantTotal || distinctFPs != wantDistinctFPs || leaks != wantLeaks || redacted != wantRedacted {
		t.Fatalf("%s aggregate = (total=%d, distinct_fps=%d, leaks=%d, redacted=%d), want (%d, %d, %d, %d)",
			label, total, distinctFPs, leaks, redacted,
			wantTotal, wantDistinctFPs, wantLeaks, wantRedacted)
	}
}

type auditLiveClientStream struct {
	grpc.ClientStream
	logsTable            string
	metricsTable         string
	spansTable           string
	logsFaultInjected    *atomic.Bool
	metricsFaultInjected *atomic.Bool
	spansRequestCount    *atomic.Int64
	maxSpansWireBytes    *atomic.Int64

	mu     sync.Mutex
	target string
	sends  int
}

func (s *auditLiveClientStream) SendMsg(m any) error {
	req, ok := m.(*storagepb.AppendRowsRequest)
	if !ok {
		return s.ClientStream.SendMsg(m)
	}

	s.mu.Lock()
	if ws := req.GetWriteStream(); ws != "" {
		s.target = ws
	}
	target := s.target
	s.sends++
	sendSeq := s.sends
	s.mu.Unlock()

	wireSize := int64(proto.Size(req))
	if strings.Contains(target, "/tables/"+s.spansTable+"/") {
		s.spansRequestCount.Add(1)
		for {
			prev := s.maxSpansWireBytes.Load()
			if wireSize <= prev || s.maxSpansWireBytes.CompareAndSwap(prev, wireSize) {
				break
			}
		}
	}
	if strings.Contains(target, "/tables/"+s.logsTable+"/") && sendSeq == 2 && s.logsFaultInjected.CompareAndSwap(false, true) {
		return status.Error(codes.Unavailable, "injected live slice-1 transient failure for logs")
	}
	if strings.Contains(target, "/tables/"+s.metricsTable+"/") && sendSeq == 2 && s.metricsFaultInjected.CompareAndSwap(false, true) {
		return status.Error(codes.Unavailable, "injected live slice-1 transient failure for metrics")
	}
	return s.ClientStream.SendMsg(m)
}
