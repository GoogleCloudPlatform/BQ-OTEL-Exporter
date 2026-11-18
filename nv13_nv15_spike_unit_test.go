// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
)

const spikeAccessLogBody128B = "2026-11-17T12:00:00Z GET /api/v1/agents/sessions/turn HTTP/2.0 200 1428B 18.4ms envoy-ingress upstream=10.24.18.9:8443 status=ok"

type spikeTableStorageStats struct {
	TotalRows           int64
	TotalLogicalBytes   int64
	ActivePhysicalBytes int64
	TotalPhysicalBytes  int64
}

func readSingleTableGetStorageStats(
	ctx context.Context, rawSvc *bigqueryapi.Service, project, dataset, table string,
) (spikeTableStorageStats, error) {
	tbl, err := rawSvc.Tables.Get(project, dataset, table).Context(ctx).Do()
	if err != nil {
		return spikeTableStorageStats{}, fmt.Errorf("tables.get %s.%s.%s: %w", project, dataset, table, err)
	}
	var totalRows int64
	if tbl.NumRows <= math.MaxInt64 {
		totalRows = int64(tbl.NumRows)
	} else {
		totalRows = math.MaxInt64
	}
	logicalBytes := tbl.NumTotalLogicalBytes
	if logicalBytes <= 0 {
		logicalBytes = tbl.NumBytes
	}
	return spikeTableStorageStats{
		TotalRows:           totalRows,
		TotalLogicalBytes:   logicalBytes,
		ActivePhysicalBytes: tbl.NumActivePhysicalBytes,
		TotalPhysicalBytes:  tbl.NumTotalPhysicalBytes,
	}, nil
}

func pollTablesGetStorageStats(
	ctx context.Context,
	rawSvc *bigqueryapi.Service,
	project, dataset, untrimmedPhys, trimmedPhys string,
	wantRows int64,
	timeout, interval time.Duration,
) (spikeTableStorageStats, spikeTableStorageStats, error) {
	deadline := time.Now().Add(timeout)
	for {
		u, err := readSingleTableGetStorageStats(ctx, rawSvc, project, dataset, untrimmedPhys)
		if err != nil {
			return spikeTableStorageStats{}, spikeTableStorageStats{}, err
		}
		tr, err := readSingleTableGetStorageStats(ctx, rawSvc, project, dataset, trimmedPhys)
		if err != nil {
			return spikeTableStorageStats{}, spikeTableStorageStats{}, err
		}
		if u.TotalRows == wantRows && tr.TotalRows == wantRows &&
			u.TotalLogicalBytes > 0 && tr.TotalLogicalBytes > 0 &&
			u.ActivePhysicalBytes > 0 && tr.ActivePhysicalBytes > 0 {
			return u, tr, nil
		}
		remaining := time.Until(deadline)
		if interval <= 0 || remaining <= 0 {
			return u, tr, nil
		}
		wait := interval
		if remaining < wait {
			wait = remaining
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return u, tr, ctx.Err()
		case <-timer.C:
		}
	}
}

func validateNV15SoakDuration(d time.Duration) error {
	if d < 60*time.Second {
		return fmt.Errorf("must be >= 60s, got %s", d)
	}
	return nil
}

type nv15LostAckInterceptor struct {
	Armed             atomic.Bool
	Injected          atomic.Bool
	StreamsOpened     atomic.Int64
	InjectedBatchRows atomic.Int64
}

func (ic *nv15LostAckInterceptor) StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil || !strings.HasSuffix(method, "/AppendRows") {
			return cs, err
		}
		ic.StreamsOpened.Add(1)
		return &nv15LostAckStream{
			ClientStream: cs,
			parent:       ic,
		}, nil
	}
}

type nv15LostAckStream struct {
	grpc.ClientStream
	parent      *nv15LostAckInterceptor
	poisoned    atomic.Bool
	mu          sync.Mutex
	pendingRows []int
}

func (s *nv15LostAckStream) SendMsg(m any) error {
	if s.poisoned.Load() {
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	rowCount := 0
	if req, ok := m.(*storagepb.AppendRowsRequest); ok {
		rowCount = len(req.GetProtoRows().GetRows().GetSerializedRows())
	}
	s.mu.Lock()
	s.pendingRows = append(s.pendingRows, rowCount)
	s.mu.Unlock()

	if err := s.ClientStream.SendMsg(m); err != nil {
		s.mu.Lock()
		if n := len(s.pendingRows); n > 0 {
			s.pendingRows = s.pendingRows[:n-1]
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *nv15LostAckStream) RecvMsg(m any) error {
	if s.poisoned.Load() {
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	err := s.ClientStream.RecvMsg(m)
	rowCount := 0
	s.mu.Lock()
	if len(s.pendingRows) > 0 {
		rowCount = s.pendingRows[0]
		s.pendingRows = s.pendingRows[1:]
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if resp, ok := m.(*storagepb.AppendRowsResponse); ok && resp.GetError() != nil {
		return nil
	}
	if s.parent.Armed.Load() && rowCount > 0 && s.parent.Injected.CompareAndSwap(false, true) {
		s.parent.InjectedBatchRows.Store(int64(rowCount))
		s.poisoned.Store(true)
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	return nil
}

func buildNV15LogsBatch(batchSeq, batchSize int, baseTS time.Time) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	resAttrs := rl.Resource().Attributes()
	resAttrs.PutStr("service.name", "nv15-default-stream-soak")
	resAttrs.PutStr("cloud.region", "us-central1")

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nv15.soak.logger")
	sl.Scope().SetVersion("1.0.0")
	records := sl.LogRecords()
	records.EnsureCapacity(batchSize)

	for i := range batchSize {
		seq := batchSeq*batchSize + i
		recTS := baseTS.Add(time.Duration(seq) * time.Microsecond)
		lr := records.AppendEmpty()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(recTS))
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(recTS.Add(500 * time.Nanosecond)))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")
		lr.Body().SetStr(spikeAccessLogBody128B)

		attrs := lr.Attributes()
		attrs.PutInt("soak.batch_seq", int64(batchSeq))
		attrs.PutInt("soak.record_seq", int64(seq))
		attrs.PutStr("http.request.method", "GET")
		attrs.PutInt("http.response.status_code", 200)
	}
	return ld
}

func TestNV13TablesGetWithoutProjectTableStoragePermission(t *testing.T) {
	var (
		returnPhysicalBytes atomic.Bool
		tablesGetCalls      atomic.Int64
		jobsCalls           atomic.Int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/jobs") {
			jobsCalls.Add(1)
			t.Errorf("unexpected BigQuery jobs request %s %s: INFORMATION_SCHEMA.TABLE_STORAGE must never be queried", r.Method, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if encErr := json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": http.StatusForbidden, "message": "Access Denied: BigQuery jobs.create"},
			}); encErr != nil {
				t.Errorf("encode 403 response: %v", encErr)
			}
			return
		}
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var tbl *bigqueryapi.Table
		switch r.URL.Path {
		case "/bigquery/v2/projects/test-proj/datasets/ds/tables/otel_logs_untrimmed_phys":
			tablesGetCalls.Add(1)
			tbl = &bigqueryapi.Table{
				NumRows:              100_000,
				NumBytes:             48_000_000,
				NumTotalLogicalBytes: 48_000_000,
			}
			if returnPhysicalBytes.Load() {
				tbl.NumActivePhysicalBytes = 6_000_000
				tbl.NumTotalPhysicalBytes = 6_000_000
			}
		case "/bigquery/v2/projects/test-proj/datasets/ds/tables/otel_logs_trimmed_phys":
			tablesGetCalls.Add(1)
			tbl = &bigqueryapi.Table{
				NumRows:              100_000,
				NumBytes:             26_000_000,
				NumTotalLogicalBytes: 26_000_000,
			}
			if returnPhysicalBytes.Load() {
				tbl.NumActivePhysicalBytes = 3_100_000
				tbl.NumTotalPhysicalBytes = 3_100_000
			}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(tbl); encErr != nil {
			t.Errorf("encode table response: %v", encErr)
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("create bigqueryapi.Service: %v", err)
	}

	const wantRows = int64(100_000)
	uZero, trZero, err := pollTablesGetStorageStats(
		ctx, rawSvc, "test-proj", "ds", "otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
		wantRows, 40*time.Millisecond, 15*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("pollTablesGetStorageStats (active_physical_bytes=0): %v", err)
	}
	if jobsCalls.Load() != 0 {
		t.Fatalf("jobsCalls = %d, want 0", jobsCalls.Load())
	}
	if tablesGetCalls.Load() < 2 {
		t.Fatalf("tablesGetCalls = %d, want >= 2", tablesGetCalls.Load())
	}
	if uZero.TotalRows != wantRows || trZero.TotalRows != wantRows {
		t.Fatalf("rows = (%d, %d), want (%d, %d)", uZero.TotalRows, trZero.TotalRows, wantRows, wantRows)
	}
	if uZero.TotalLogicalBytes != 48_000_000 || trZero.TotalLogicalBytes != 26_000_000 {
		t.Fatalf("logical bytes = (%d, %d), want (48000000, 26000000)", uZero.TotalLogicalBytes, trZero.TotalLogicalBytes)
	}
	if uZero.ActivePhysicalBytes != 0 || trZero.ActivePhysicalBytes != 0 || uZero.TotalPhysicalBytes != 0 || trZero.TotalPhysicalBytes != 0 {
		t.Fatalf("expected zero physical bytes before async calculation, got u=%+v tr=%+v", uZero, trZero)
	}

	returnPhysicalBytes.Store(true)
	uPhys, trPhys, err := pollTablesGetStorageStats(
		ctx, rawSvc, "test-proj", "ds", "otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
		wantRows, 2*time.Second, 20*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("pollTablesGetStorageStats (active_physical_bytes>0): %v", err)
	}
	if jobsCalls.Load() != 0 {
		t.Fatalf("jobsCalls = %d, want 0", jobsCalls.Load())
	}
	if uPhys.ActivePhysicalBytes != 6_000_000 || trPhys.ActivePhysicalBytes != 3_100_000 {
		t.Fatalf("active physical bytes = (%d, %d), want (6000000, 3100000)", uPhys.ActivePhysicalBytes, trPhys.ActivePhysicalBytes)
	}
	if uPhys.TotalPhysicalBytes != 6_000_000 || trPhys.TotalPhysicalBytes != 3_100_000 {
		t.Fatalf("total physical bytes = (%d, %d), want (6000000, 3100000)", uPhys.TotalPhysicalBytes, trPhys.TotalPhysicalBytes)
	}
}

func TestNV15MinSoakDurationAndLostAckStreamRecovery(t *testing.T) {
	if err := validateNV15SoakDuration(time.Nanosecond); err == nil {
		t.Fatal("expected 1ns soak duration to be rejected")
	}
	if err := validateNV15SoakDuration(59 * time.Second); err == nil {
		t.Fatal("expected 59s soak duration to be rejected")
	}
	if err := validateNV15SoakDuration(60 * time.Second); err != nil {
		t.Fatalf("expected 60s soak duration to be accepted, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	fakeSrv := bqfake.NewServer(t)
	ic := &nv15LostAckInterceptor{}
	origNewMWClient := newManagedWriterClient
	t.Cleanup(func() { newManagedWriterClient = origNewMWClient })
	newManagedWriterClient = func(cCtx context.Context, projectID string, opts ...option.ClientOption) (*managedwriter.Client, error) {
		wrapped := append(append([]option.ClientOption(nil), opts...),
			option.WithGRPCDialOption(grpc.WithChainStreamInterceptor(ic.StreamClientInterceptor())),
		)
		return origNewMWClient(cCtx, projectID, wrapped...)
	}

	rawCfg := CreateDefaultConfig()
	cfg, ok := rawCfg.(*Config)
	if !ok {
		t.Fatalf("CreateDefaultConfig() returned %T, want *Config", rawCfg)
	}
	cfg.Project = "test-proj"
	cfg.Dataset = "otel"
	cfg.Location = "US"
	cfg.Logs.Table = "otel_logs"
	cfg.Logs.SynthesizeInsertID = true
	cfg.AutoCreate.Dataset = true
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = false
	cfg.AutoCreate.SearchIndexes = false
	cfg.Write.StreamPoolSize = 2
	cfg.Endpoint = EndpointConfig{
		URL:                   fakeSrv.Addr(),
		AdminURL:              fakeSrv.RESTURL(),
		Insecure:              true,
		WithoutAuthentication: true,
	}
	cfg.QueueSettings = configoptional.None[exporterhelper.QueueBatchConfig]()
	cfg.BackOffConfig.Enabled = true
	cfg.BackOffConfig.InitialInterval = 10 * time.Millisecond
	cfg.BackOffConfig.MaxInterval = 100 * time.Millisecond

	exp, err := CreateLogsExporter(ctx, exportertest.NewNopSettings(NewFactory().Type()), cfg)
	if err != nil {
		t.Fatalf("CreateLogsExporter: %v", err)
	}
	if startErr := exp.Start(ctx, componenttest.NewNopHost()); startErr != nil {
		t.Fatalf("Start exporter: %v", startErr)
	}
	var shutdownOnce sync.Once
	shutdown := func(sctx context.Context) error {
		var serr error
		shutdownOnce.Do(func() {
			serr = exp.Shutdown(sctx)
		})
		return serr
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if stopErr := shutdown(cleanCtx); stopErr != nil {
			t.Errorf("Shutdown exporter: %v", stopErr)
		}
	})

	const (
		warmupBatches = 4
		faultBatches  = 8
		batchSize     = 25
	)
	baseTS := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for seq := range warmupBatches {
		batch := buildNV15LogsBatch(seq, batchSize, baseTS)
		if consumeErr := exp.ConsumeLogs(ctx, batch); consumeErr != nil {
			t.Fatalf("warmup ConsumeLogs(%d): %v", seq, consumeErr)
		}
	}

	ic.Armed.Store(true)
	postFaultBatches := 0
	for i := range faultBatches {
		seq := warmupBatches + i
		batch := buildNV15LogsBatch(seq, batchSize, baseTS)
		if consumeErr := exp.ConsumeLogs(ctx, batch); consumeErr != nil {
			t.Fatalf("post-arm ConsumeLogs(%d): %v", seq, consumeErr)
		}
		if ic.Injected.Load() {
			postFaultBatches++
		}
	}
	if stopErr := shutdown(ctx); stopErr != nil {
		t.Fatalf("shutdown exporter: %v", stopErr)
	}

	if !ic.Injected.Load() {
		t.Fatal("expected nv15LostAckInterceptor to inject post-ack stream disconnect")
	}
	if ic.InjectedBatchRows.Load() <= 0 {
		t.Fatalf("injectedBatchRows = %d, want > 0", ic.InjectedBatchRows.Load())
	}
	if ic.StreamsOpened.Load() < 3 {
		t.Fatalf("streamsOpened = %d, want >= 3", ic.StreamsOpened.Load())
	}
	if postFaultBatches <= 0 {
		t.Fatalf("postFaultBatches = %d, want > 0", postFaultBatches)
	}

	uniqueSent := (warmupBatches + faultBatches) * batchSize
	rows := fakeSrv.Rows("otel_logs")
	wantMinRaw := uniqueSent + int(ic.InjectedBatchRows.Load())
	if len(rows) < wantMinRaw {
		t.Fatalf(
			"raw otel_logs row count = %d, want >= %d (uniqueSent=%d + injectedBatchRows=%d)",
			len(rows), wantMinRaw, uniqueSent, ic.InjectedBatchRows.Load(),
		)
	}

	type dedupKey struct {
		logName  string
		insertID string
	}
	seen := make(map[dedupKey]struct{}, uniqueSent)
	for idx, r := range rows {
		logName, _ := r["log_name"].(string)
		insertID, _ := r["insert_id"].(string)
		if insertID == "" {
			t.Fatalf("row %d missing synthesized insert_id: %v", idx, r)
		}
		seen[dedupKey{logName: logName, insertID: insertID}] = struct{}{}
	}
	if len(seen) != uniqueSent {
		t.Fatalf("unique (log_name, insert_id) count = %d, want %d (raw=%d)", len(seen), uniqueSent, len(rows))
	}
}
