// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

const (
	collectorStartupTimeout  = 20 * time.Second
	collectorShutdownTimeout = 30 * time.Second
	collectorMaxDiagBytes    = 64 * 1024
	linuxUserHZ              = 100.0
	prebuiltRingPerWorker    = 4
)

type collectorEndpointOverride struct {
	otlpAddr    string
	healthAddr  string
	useBQFake   bool
	fakeGRPCURL string
	fakeRESTURL string
}

type boundedDiagBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *boundedDiagBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := collectorMaxDiagBytes - b.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.buf.Write(p[:remaining])
		} else {
			_, _ = b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedDiagBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(b.buf.String())
}

type collectorPreparedBatch struct {
	tracesReq   ptraceotlp.ExportRequest
	logsReq     plogotlp.ExportRequest
	metricsReq  pmetricotlp.ExportRequest
	otlpBytes   int64
	recordCount int64
}

func reserveLoopbackAddr(ctx context.Context) (net.Listener, string, error) {
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, "", fmt.Errorf("reserving loopback TCP port: %w", err)
	}
	return lis, lis.Addr().String(), nil
}

func ensureYAMLSubmap(parent map[string]any, key string) map[string]any {
	if existing, ok := parent[key].(map[string]any); ok && existing != nil {
		return existing
	}
	created := make(map[string]any)
	parent[key] = created
	return created
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, bool, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, false, fmt.Errorf("parsing collector YAML config: %w", err)
	}
	if len(doc) == 0 {
		return nil, false, errors.New("collector YAML config is empty")
	}

	receivers := ensureYAMLSubmap(doc, "receivers")
	otlpRecv := ensureYAMLSubmap(receivers, "otlp")
	otlpRecv["protocols"] = map[string]any{
		"grpc": map[string]any{
			"endpoint": ep.otlpAddr,
		},
	}

	hasHealthCheck := false
	if extMap, ok := doc["extensions"].(map[string]any); ok {
		if _, exists := extMap["health_check"]; exists {
			hc := ensureYAMLSubmap(extMap, "health_check")
			hc["endpoint"] = ep.healthAddr
			hasHealthCheck = true
		}
	}

	exporters := ensureYAMLSubmap(doc, "exporters")
	bq := ensureYAMLSubmap(exporters, "bigquery")
	bq["project"] = cfg.ProjectID
	bq["dataset"] = cfg.DatasetID
	bq["location"] = cfg.Location

	writeCfg := ensureYAMLSubmap(bq, "write")
	writeCfg["stream_pool_size"] = cfg.StreamPoolSize
	writeCfg["connection_pool_size"] = cfg.ConnectionPoolSize
	writeCfg["max_inflight_requests"] = cfg.MaxInflightRequests
	writeCfg["max_request_bytes"] = cfg.MaxRequestBytes
	if cfg.Compression != "" {
		writeCfg["compression"] = cfg.Compression
	}
	if cfg.Backpressure {
		bp := ensureYAMLSubmap(writeCfg, "backpressure")
		bp["enabled"] = true
	}
	if cfg.Redaction {
		red := ensureYAMLSubmap(bq, "redaction")
		red["enabled"] = true
	}

	if ep.useBQFake {
		bq["endpoint"] = map[string]any{
			"url":                    ep.fakeGRPCURL,
			"admin_url":              ep.fakeRESTURL,
			"insecure":               true,
			"without_authentication": true,
		}
		bq["auto_create"] = map[string]any{
			"dataset":         false,
			"tables":          false,
			"companion_views": false,
			"search_indexes":  false,
		}
	} else {
		delete(bq, "endpoint")
		bq["auto_create"] = map[string]any{
			"dataset":         false,
			"tables":          true,
			"companion_views": false,
			"search_indexes":  false,
		}
	}

	if signal != "" {
		svc := ensureYAMLSubmap(doc, "service")
		pipelines := ensureYAMLSubmap(svc, "pipelines")
		if _, exists := pipelines[signal]; !exists {
			var procs []any
			if procMap, ok := doc["processors"].(map[string]any); ok {
				if _, hasMem := procMap["memory_limiter"]; hasMem {
					procs = append(procs, "memory_limiter")
				}
				if _, hasBatch := procMap["batch"]; hasBatch {
					procs = append(procs, "batch")
				}
			}
			pipelines[signal] = map[string]any{
				"receivers":  []any{"otlp"},
				"processors": procs,
				"exporters":  []any{"bigquery"},
			}
		}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return nil, false, fmt.Errorf("marshaling rewritten collector YAML: %w", err)
	}
	return out, hasHealthCheck, nil
}

func resolveCollectorConfigPath(cfgPath string) string {
	if filepath.IsAbs(cfgPath) {
		return cfgPath
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return cfgPath
	}
	wd, err := os.Getwd()
	if err != nil {
		return cfgPath
	}
	dir := wd
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			candidate := filepath.Join(dir, cfgPath)
			if _, cErr := os.Stat(candidate); cErr == nil {
				return candidate
			}
			return cfgPath
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cfgPath
		}
		dir = parent
	}
}

func readPIDCPUSeconds(pid int) float64 {
	if pid <= 0 {
		return 0
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+1 >= len(s) {
		return 0
	}
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) <= 12 {
		return 0
	}
	utimeTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0
	}
	stimeTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0
	}
	return float64(utimeTicks+stimeTicks) / linuxUserHZ
}

func readPIDMemoryMB(pid int) (vmRSSMB, vmHWMMB float64) {
	if pid <= 0 {
		return 0, 0
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		if pid == os.Getpid() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			sysMB := float64(ms.Sys) / (1024.0 * 1024.0)
			return sysMB, sysMB
		}
		return 0, 0
	}
	for line := range strings.SplitSeq(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "VmRSS:"):
			vmRSSMB = parseProcStatusKBToMB(strings.TrimPrefix(line, "VmRSS:"))
		case strings.HasPrefix(line, "VmHWM:"):
			vmHWMMB = parseProcStatusKBToMB(strings.TrimPrefix(line, "VmHWM:"))
		}
	}
	if vmHWMMB < vmRSSMB {
		vmHWMMB = vmRSSMB
	}
	return vmRSSMB, vmHWMMB
}

func parseProcStatusKBToMB(rawVal string) float64 {
	fields := strings.Fields(rawVal)
	if len(fields) == 0 {
		return 0
	}
	kb, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0
	}
	return float64(kb) / 1024.0
}

func newCollectorBatchBuilder(cfg RunnerConfig, signal string) (func(int) (collectorPreparedBatch, error), error) {
	fnVal := reflect.ValueOf(NewGenerator)
	cfgType := fnVal.Type().In(0)
	var argVal reflect.Value
	var structVal reflect.Value
	if cfgType.Kind() == reflect.Pointer {
		argVal = reflect.New(cfgType.Elem())
		structVal = argVal.Elem()
	} else {
		ptr := reflect.New(cfgType)
		structVal = ptr.Elem()
		argVal = structVal
	}
	setReflectFieldString(structVal, "WorkloadProfile", cfg.WorkloadProfile)
	setReflectFieldInt(structVal, "PayloadBytes", cfg.PayloadBytes)
	setReflectFieldBool(structVal, "UniquePayloads", cfg.UniquePayloads)
	setReflectFieldBool(structVal, "PlantSecrets", cfg.Redaction || cfg.PlantSecrets)
	setReflectFieldBool(structVal, "Redaction", cfg.Redaction)
	setReflectFieldInt(structVal, "ResourceAttrs", cfg.ResourceAttrs)
	setReflectFieldBool(structVal, "UpstreamInsertID", cfg.UpstreamInsertID)

	outs := fnVal.Call([]reflect.Value{argVal})
	if len(outs) == 2 && !outs[1].IsNil() {
		if err, ok := outs[1].Interface().(error); ok {
			return nil, err
		}
	}
	genAny := outs[0].Interface()
	return bindCollectorBatchBuilder(genAny, signal)
}

func setReflectFieldString(v reflect.Value, name, val string) {
	f := v.FieldByName(name)
	if f.IsValid() && f.CanSet() && f.Kind() == reflect.String {
		f.SetString(val)
	}
}

func setReflectFieldInt(v reflect.Value, name string, val int) {
	f := v.FieldByName(name)
	if f.IsValid() && f.CanSet() && f.Kind() == reflect.Int {
		f.SetInt(int64(val))
	}
}

func setReflectFieldBool(v reflect.Value, name string, val bool) {
	f := v.FieldByName(name)
	if f.IsValid() && f.CanSet() && f.Kind() == reflect.Bool {
		f.SetBool(val)
	}
}

func bindCollectorBatchBuilder(gen any, signal string) (func(int) (collectorPreparedBatch, error), error) {
	switch signal {
	case "logs":
		var makeLogs func(int) plog.Logs
		switch g := gen.(type) {
		case interface{ LogsBatch(int) plog.Logs }:
			makeLogs = g.LogsBatch
		case interface{ GenerateLogs(int) plog.Logs }:
			makeLogs = g.GenerateLogs
		case interface{ Logs(int) plog.Logs }:
			makeLogs = g.Logs
		case interface{ NextLogs(int) plog.Logs }:
			makeLogs = g.NextLogs
		default:
			return nil, errors.New("generator does not expose a logs batch method")
		}
		return func(n int) (collectorPreparedBatch, error) {
			ld := makeLogs(n)
			req := plogotlp.NewExportRequestFromLogs(ld)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				logsReq:     req,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(ld.LogRecordCount()),
			}, nil
		}, nil
	case "traces":
		var makeTraces func(int) ptrace.Traces
		switch g := gen.(type) {
		case interface{ TracesBatch(int) ptrace.Traces }:
			makeTraces = g.TracesBatch
		case interface{ GenerateTraces(int) ptrace.Traces }:
			makeTraces = g.GenerateTraces
		case interface{ Traces(int) ptrace.Traces }:
			makeTraces = g.Traces
		case interface{ NextTraces(int) ptrace.Traces }:
			makeTraces = g.NextTraces
		default:
			return nil, errors.New("generator does not expose a traces batch method")
		}
		return func(n int) (collectorPreparedBatch, error) {
			td := makeTraces(n)
			req := ptraceotlp.NewExportRequestFromTraces(td)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				tracesReq:   req,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(td.SpanCount()),
			}, nil
		}, nil
	case "metrics":
		var makeMetrics func(int) pmetric.Metrics
		switch g := gen.(type) {
		case interface{ MetricsBatch(int) pmetric.Metrics }:
			makeMetrics = g.MetricsBatch
		case interface{ GenerateMetrics(int) pmetric.Metrics }:
			makeMetrics = g.GenerateMetrics
		case interface{ Metrics(int) pmetric.Metrics }:
			makeMetrics = g.Metrics
		case interface{ NextMetrics(int) pmetric.Metrics }:
			makeMetrics = g.NextMetrics
		default:
			return nil, errors.New("generator does not expose a metrics batch method")
		}
		return func(n int) (collectorPreparedBatch, error) {
			md := makeMetrics(n)
			req := pmetricotlp.NewExportRequestFromMetrics(md)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				metricsReq:  req,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(md.DataPointCount()),
			}, nil
		}, nil
	default:
		return nil, fmt.Errorf("unsupported signal %q", signal)
	}
}

func buildCollectorEnv(maxProcs int) []string {
	base := os.Environ()
	if maxProcs <= 0 {
		return base
	}
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if !strings.HasPrefix(kv, "GOMAXPROCS=") {
			out = append(out, kv)
		}
	}
	out = append(out, "GOMAXPROCS="+strconv.Itoa(maxProcs))
	return out
}

func probeCollectorReady(ctx context.Context, httpClient *http.Client, healthAddr, otlpAddr string, hasHealthCheck bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if hasHealthCheck {
		req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+healthAddr, http.NoBody)
		if err != nil {
			return false
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return false
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false
		}
	}

	dialer := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := dialer.DialContext(probeCtx, "tcp", otlpAddr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func waitCollectorReady(ctx context.Context, doneCh <-chan struct{}, waitErr *error, diag *boundedDiagBuffer, healthAddr, otlpAddr string, hasHealthCheck bool) error {
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	defer httpClient.CloseIdleConnections()

	deadline := time.Now().Add(collectorStartupTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if probeCollectorReady(ctx, httpClient, healthAddr, otlpAddr, hasHealthCheck) {
			return nil
		}
		select {
		case <-doneCh:
			return fmt.Errorf("collector exited before becoming ready (%w): %s", *waitErr, diag.String())
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if time.Now().After(deadline) {
				return fmt.Errorf("timed out after %s waiting for collector readiness on %s: %s", collectorStartupTimeout, otlpAddr, diag.String())
			}
		}
	}
}

func exportCollectorBatch(
	ctx context.Context,
	signal string,
	batch collectorPreparedBatch,
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
) (rejected int64, err error) {
	switch signal {
	case "traces":
		resp, rpcErr := tracesClient.Export(ctx, batch.tracesReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedSpans(), nil
	case "logs":
		resp, rpcErr := logsClient.Export(ctx, batch.logsReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedLogRecords(), nil
	case "metrics":
		resp, rpcErr := metricsClient.Export(ctx, batch.metricsReq)
		if rpcErr != nil {
			return 0, rpcErr
		}
		return resp.PartialSuccess().RejectedDataPoints(), nil
	default:
		return 0, fmt.Errorf("unsupported signal %q", signal)
	}
}

type collectorPhaseStats struct {
	batchesAttempted    int64
	batchesSucceeded    int64
	batchesFailed       int64
	recordsAttempted    int64
	recordsSubmitted    int64
	rejectedRecords     int64
	dispatchedOTLPBytes int64
	dispatchedRecords   int64
	latenciesMs         []float64
	firstErr            error
}

func runCollectorWorkerPhase(
	ctx context.Context,
	cfg RunnerConfig,
	signal string,
	duration time.Duration,
	maxBatches int,
	prebuilt [][]collectorPreparedBatch,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
) collectorPhaseStats {
	var (
		batchesAttempted    atomic.Int64
		batchesSucceeded    atomic.Int64
		batchesFailed       atomic.Int64
		recordsAttempted    atomic.Int64
		recordsSubmitted    atomic.Int64
		rejectedRecords     atomic.Int64
		dispatchedOTLPBytes atomic.Int64
		dispatchedRecords   atomic.Int64
		globalSeq           atomic.Int64
		errOnce             sync.Once
		firstErr            error
	)

	callTimeout := cfg.CallTimeout
	if callTimeout <= 0 {
		callTimeout = 30 * time.Second
	}

	var workerInterval time.Duration
	if cfg.TargetRate > 0 {
		workerInterval = time.Duration(float64(time.Second) * float64(cfg.BatchSize*cfg.Workers) / float64(cfg.TargetRate))
	}

	deadline := time.Now().Add(duration)
	perWorkerLatencies := make([][]float64, cfg.Workers)

	var wg sync.WaitGroup
	for workerID := range cfg.Workers {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			nextTick := time.Now()
			localSeq := 0
			for ctx.Err() == nil && time.Now().Before(deadline) {
				gSeq := int(globalSeq.Add(1))
				if maxBatches > 0 && gSeq > maxBatches {
					return
				}
				if workerInterval > 0 {
					if waitDur := time.Until(nextTick); waitDur > 0 {
						timer := time.NewTimer(waitDur)
						select {
						case <-ctx.Done():
							timer.Stop()
							return
						case <-timer.C:
						}
					}
					nextTick = nextTick.Add(workerInterval)
				}

				if cfg.workerHook != nil {
					cfg.workerHook(wID, localSeq)
				}

				var (
					batch collectorPreparedBatch
					err   error
				)
				if len(prebuilt) > 0 {
					ring := prebuilt[wID]
					batch = ring[localSeq%len(ring)]
				} else {
					batch, err = makeBatch(cfg.BatchSize)
					if err != nil {
						batchesAttempted.Add(1)
						batchesFailed.Add(1)
						errOnce.Do(func() { firstErr = err })
						localSeq++
						continue
					}
				}
				localSeq++

				batchesAttempted.Add(1)
				recordsAttempted.Add(batch.recordCount)
				dispatchedOTLPBytes.Add(batch.otlpBytes)
				dispatchedRecords.Add(batch.recordCount)

				rpcCtx, cancel := context.WithTimeout(ctx, callTimeout)
				rpcStart := time.Now()
				rejected, rpcErr := exportCollectorBatch(rpcCtx, signal, batch, tracesClient, logsClient, metricsClient)
				rpcMs := float64(time.Since(rpcStart).Microseconds()) / 1000.0
				cancel()

				if rpcErr != nil {
					if ctx.Err() != nil {
						return
					}
					batchesFailed.Add(1)
					errOnce.Do(func() { firstErr = rpcErr })
					continue
				}

				perWorkerLatencies[wID] = append(perWorkerLatencies[wID], rpcMs)
				if rejected > 0 {
					rejectedRecords.Add(rejected)
				}
				accepted := max(int64(0), batch.recordCount-rejected)
				if accepted == 0 && batch.recordCount > 0 {
					batchesFailed.Add(1)
					errOnce.Do(func() {
						firstErr = fmt.Errorf("collector rejected all %d records in batch", batch.recordCount)
					})
					continue
				}
				batchesSucceeded.Add(1)
				recordsSubmitted.Add(accepted)
			}
		}(workerID)
	}
	wg.Wait()

	totalSamples := 0
	for _, s := range perWorkerLatencies {
		totalSamples += len(s)
	}
	allLatencies := make([]float64, 0, totalSamples)
	for _, s := range perWorkerLatencies {
		allLatencies = append(allLatencies, s...)
	}

	return collectorPhaseStats{
		batchesAttempted:    batchesAttempted.Load(),
		batchesSucceeded:    batchesSucceeded.Load(),
		batchesFailed:       batchesFailed.Load(),
		recordsAttempted:    recordsAttempted.Load(),
		recordsSubmitted:    recordsSubmitted.Load(),
		rejectedRecords:     rejectedRecords.Load(),
		dispatchedOTLPBytes: dispatchedOTLPBytes.Load(),
		dispatchedRecords:   dispatchedRecords.Load(),
		latenciesMs:         allLatencies,
		firstErr:            firstErr,
	}
}

func drainCollectorWarmup(ctx context.Context, fakeSrv *bqfake.Server, expectedRows int64, doneCh <-chan struct{}, waitErr *error, diag *boundedDiagBuffer) error {
	if fakeSrv == nil {
		timer := time.NewTimer(1500 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
			return fmt.Errorf("collector exited during warmup drain (%w): %s", *waitErr, diag.String())
		case <-timer.C:
			return nil
		}
	}

	deadline := time.Now().Add(3 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	lastAcked := -1
	stableTicks := 0
	for {
		_, _, acked := fakeSrv.Counts()
		if int64(acked) >= expectedRows && acked == lastAcked {
			stableTicks++
			if stableTicks >= 2 {
				return nil
			}
		} else {
			stableTicks = 0
		}
		lastAcked = acked
		if time.Now().After(deadline) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-doneCh:
			return fmt.Errorf("collector exited during warmup drain (%w): %s", *waitErr, diag.String())
		case <-ticker.C:
		}
	}
}

func collectorTargetTable(signal string) string {
	switch signal {
	case "traces":
		return "otel_spans"
	case "logs":
		return "otel_logs"
	case "metrics":
		return "otel_metrics"
	default:
		return "otel_logs"
	}
}

func runCollectorSingleSignal(ctx context.Context, cfg RunnerConfig, signal string) (SignalResult, error, error) {
	binInfo, err := os.Stat(cfg.CollectorBin)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("stat collector binary %q: %w", cfg.CollectorBin, err)
	}
	if binInfo.IsDir() {
		return SignalResult{}, nil, fmt.Errorf("collector binary %q is a directory", cfg.CollectorBin)
	}

	resolvedCfgPath := resolveCollectorConfigPath(cfg.CollectorConfig)
	rawYAML, err := os.ReadFile(resolvedCfgPath)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("reading collector config %q: %w", cfg.CollectorConfig, err)
	}

	useBQFake := cfg.ProjectID == "bench-project" && !cfg.EphemeralDataset
	var fakeSrv *bqfake.Server
	if useBQFake {
		fakeSrv, err = bqfake.New()
		if err != nil {
			return SignalResult{}, nil, fmt.Errorf("starting bqfake for collector mode: %w", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(true)
		fakeSrv.SeedDataset(cfg.ProjectID, cfg.DatasetID, cfg.Location)
	}

	otlpLis, otlpAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		return SignalResult{}, nil, err
	}
	healthLis, healthAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		_ = otlpLis.Close()
		return SignalResult{}, nil, err
	}

	override := collectorEndpointOverride{
		otlpAddr:   otlpAddr,
		healthAddr: healthAddr,
		useBQFake:  useBQFake,
	}
	if fakeSrv != nil {
		override.fakeGRPCURL = fakeSrv.Addr()
		override.fakeRESTURL = strings.TrimRight(fakeSrv.RESTURL(), "/") + "/bigquery/v2/"
	}

	rewrittenYAML, hasHealthCheck, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, override)
	if err != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, err
	}

	tempCfgFile, err := os.CreateTemp("", "bq-otel-collector-*.yaml")
	if err != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, fmt.Errorf("creating temporary collector config: %w", err)
	}
	tempCfgPath := tempCfgFile.Name()
	defer func() { _ = os.Remove(tempCfgPath) }()
	if _, writeErr := tempCfgFile.Write(rewrittenYAML); writeErr != nil {
		_ = tempCfgFile.Close()
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, fmt.Errorf("writing temporary collector config: %w", writeErr)
	}
	if closeErr := tempCfgFile.Close(); closeErr != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, fmt.Errorf("closing temporary collector config: %w", closeErr)
	}

	makeBatch, err := newCollectorBatchBuilder(cfg, signal)
	if err != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, err
	}

	var prebuilt [][]collectorPreparedBatch
	if !cfg.UniquePayloads {
		prebuilt = make([][]collectorPreparedBatch, cfg.Workers)
		for w := range cfg.Workers {
			ring := make([]collectorPreparedBatch, prebuiltRingPerWorker)
			for r := range prebuiltRingPerWorker {
				b, bErr := makeBatch(cfg.BatchSize)
				if bErr != nil {
					_ = otlpLis.Close()
					_ = healthLis.Close()
					return SignalResult{}, nil, bErr
				}
				ring[r] = b
			}
			prebuilt[w] = ring
		}
	}

	_ = otlpLis.Close()
	_ = healthLis.Close()

	diag := &boundedDiagBuffer{}
	cmd := exec.CommandContext(ctx, cfg.CollectorBin, "--config="+tempCfgPath)
	cmd.Env = buildCollectorEnv(cfg.MaxProcs)
	cmd.Stdout = diag
	cmd.Stderr = diag
	cmd.Cancel = func() error {
		return cmd.Process.Signal(syscall.SIGTERM)
	}
	cmd.WaitDelay = 10 * time.Second

	if startErr := cmd.Start(); startErr != nil {
		return SignalResult{}, nil, fmt.Errorf("starting collector %q: %w", cfg.CollectorBin, startErr)
	}

	doneCh := make(chan struct{})
	var cmdWaitErr error
	go func() {
		cmdWaitErr = cmd.Wait()
		close(doneCh)
	}()

	childDone := false
	defer func() {
		if !childDone && cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-doneCh:
			case <-timer.C:
				_ = cmd.Process.Kill()
				<-doneCh
			}
		}
	}()

	if readyErr := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, healthAddr, otlpAddr, hasHealthCheck); readyErr != nil {
		return SignalResult{}, nil, readyErr
	}

	conn, err := grpc.NewClient(
		otlpAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(bqfake.DefaultMaxServerMsgSize)),
	)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("dialing collector OTLP gRPC %s: %w", otlpAddr, err)
	}
	defer func() { _ = conn.Close() }()

	tracesClient := ptraceotlp.NewGRPCClient(conn)
	logsClient := plogotlp.NewGRPCClient(conn)
	metricsClient := pmetricotlp.NewGRPCClient(conn)

	pid := cmd.Process.Pid
	if cfg.WarmupDuration > 0 {
		warmupStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.WarmupDuration, 0, prebuilt, makeBatch, tracesClient, logsClient, metricsClient)
		if ctx.Err() != nil {
			return SignalResult{}, nil, ctx.Err()
		}
		if drainErr := drainCollectorWarmup(ctx, fakeSrv, warmupStats.recordsSubmitted, doneCh, &cmdWaitErr, diag); drainErr != nil {
			return SignalResult{}, nil, drainErr
		}
	}

	var (
		ackedRowsBefore  int
		ackedBytesBefore int64
	)
	if fakeSrv != nil {
		_, _, ackedRowsBefore = fakeSrv.Counts()
		ackedBytesBefore = fakeSrv.AckedBytes()
	}
	cpuBeforeSec := readPIDCPUSeconds(pid)

	var (
		memMu     sync.Mutex
		lastRSSMB float64
		peakRSSMB float64
		stopMemCh = make(chan struct{})
		memDoneWg sync.WaitGroup
	)
	sampleMem := func() {
		rss, hwm := readPIDMemoryMB(pid)
		memMu.Lock()
		if rss > 0 {
			lastRSSMB = rss
		}
		if hwm > peakRSSMB {
			peakRSSMB = hwm
		}
		if rss > peakRSSMB {
			peakRSSMB = rss
		}
		memMu.Unlock()
	}
	sampleMem()
	memDoneWg.Add(1)
	go func() {
		defer memDoneWg.Done()
		ticker := time.NewTicker(200 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopMemCh:
				return
			case <-ticker.C:
				sampleMem()
			}
		}
	}()

	startWall := time.Now()
	steadyStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.Duration, cfg.maxBatches, prebuilt, makeBatch, tracesClient, logsClient, metricsClient)
	close(stopMemCh)
	memDoneWg.Wait()
	sampleMem()

	cpuBeforeTermSec := readPIDCPUSeconds(pid)
	_ = conn.Close()

	_ = cmd.Process.Signal(syscall.SIGTERM)
	shutdownTimer := time.NewTimer(collectorShutdownTimeout)
	defer shutdownTimer.Stop()
	select {
	case <-doneCh:
		childDone = true
	case <-shutdownTimer.C:
		_ = cmd.Process.Kill()
		<-doneCh
		childDone = true
		return SignalResult{}, steadyStats.firstErr, fmt.Errorf("collector did not exit within %s after SIGTERM: %s", collectorShutdownTimeout, diag.String())
	}
	elapsed := time.Since(startWall)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}

	if cmdWaitErr != nil && ctx.Err() == nil {
		return SignalResult{}, steadyStats.firstErr, fmt.Errorf("collector exited with error (%w): %s", cmdWaitErr, diag.String())
	}

	var totalCPUSec float64
	if cmd.ProcessState != nil {
		totalCPUSec = cmd.ProcessState.UserTime().Seconds() + cmd.ProcessState.SystemTime().Seconds()
	}
	if totalCPUSec < cpuBeforeTermSec {
		totalCPUSec = cpuBeforeTermSec
	}
	cpuDeltaSec := max(0.0, totalCPUSec-cpuBeforeSec)

	var (
		ackedRows       int64
		protoBytesTotal int64
	)
	if fakeSrv != nil {
		_, _, ackedRowsAfter := fakeSrv.Counts()
		ackedRows = int64(max(0, ackedRowsAfter-ackedRowsBefore))
		protoBytesTotal = max(int64(0), fakeSrv.AckedBytes()-ackedBytesBefore)
	} else {
		ackedRows = steadyStats.recordsSubmitted
		if singleBPR, bprErr := measureSingleAttemptBytesPerRow(cfg, signal); bprErr == nil && singleBPR > 0 {
			protoBytesTotal = int64(math.Round(singleBPR * float64(ackedRows)))
		}
	}

	elapsedSec := elapsed.Seconds()
	rowsPerSec := float64(ackedRows) / elapsedSec
	wireMBPerSec := (float64(protoBytesTotal) / (1024.0 * 1024.0)) / elapsedSec
	var bytesPerRow float64
	if ackedRows > 0 {
		bytesPerRow = float64(protoBytesTotal) / float64(ackedRows)
	}

	var otlpBytesPerRow float64
	if steadyStats.dispatchedRecords > 0 {
		otlpBytesPerRow = float64(steadyStats.dispatchedOTLPBytes) / float64(steadyStats.dispatchedRecords)
	}

	var byteLayers *ByteLayersSummary
	if steadyStats.dispatchedRecords > 0 && bytesPerRow > 0 {
		var sourceTotal int64
		if baseLayers, _, baseErr := measureByteProfileWithDispatched(cfg, signal, bytesPerRow, nil); baseErr == nil && baseLayers != nil && baseLayers.SourceContentBytesPerRow > 0 {
			sourceTotal = int64(math.Round(baseLayers.SourceContentBytesPerRow * float64(steadyStats.dispatchedRecords)))
		}
		dispatched := &dispatchedByteTotals{
			sourceBytes: sourceTotal,
			otlpBytes:   steadyStats.dispatchedOTLPBytes,
			records:     steadyStats.dispatchedRecords,
		}
		if layers, _, lErr := measureByteProfileWithDispatched(cfg, signal, bytesPerRow, dispatched); lErr == nil && layers != nil {
			layers.OTLPBytesPerRow = round2(otlpBytesPerRow)
			layers.ProtoRowsBytesPerRow = round2(bytesPerRow)
			if otlpBytesPerRow > 0 {
				layers.OTLPToProtoRowsRatio = round2(bytesPerRow / otlpBytesPerRow)
			}
			byteLayers = layers
		} else {
			var expansion float64
			if otlpBytesPerRow > 0 {
				expansion = round2(bytesPerRow / otlpBytesPerRow)
			}
			byteLayers = &ByteLayersSummary{
				OTLPBytesPerRow:      round2(otlpBytesPerRow),
				ProtoRowsBytesPerRow: round2(bytesPerRow),
				OTLPToProtoRowsRatio: expansion,
			}
		}
		if !useBQFake && byteLayers != nil {
			populateLiveTableStorage(ctx, cfg, collectorTargetTable(signal), byteLayers)
		}
	}

	cpuCoresUsed := cpuDeltaSec / elapsedSec
	var cpuCoresPer10k float64
	if rowsPerSec > 0 {
		cpuCoresPer10k = cpuCoresUsed / (rowsPerSec / 10000.0)
	}

	telem := TelemetrySnapshot{
		AcknowledgedRows: ackedRows,
		RejectedRows:     steadyStats.rejectedRecords,
		AppendBytesTotal: protoBytesTotal,
	}

	return SignalResult{
		Signal:                    signal,
		Mode:                      cfg.Mode,
		WorkloadProfile:           cfg.WorkloadProfile,
		StreamPoolSize:            cfg.StreamPoolSize,
		ConnectionPoolSize:        cfg.ConnectionPoolSize,
		Workers:                   cfg.Workers,
		BatchSize:                 cfg.BatchSize,
		PayloadBytes:              cfg.PayloadBytes,
		Redaction:                 cfg.Redaction,
		Backpressure:              cfg.Backpressure,
		ElapsedSeconds:            round2(elapsedSec),
		BatchesAttempted:          steadyStats.batchesAttempted,
		BatchesSucceeded:          steadyStats.batchesSucceeded,
		BatchesFailed:             steadyStats.batchesFailed,
		RecordsAttempted:          steadyStats.recordsAttempted,
		RecordsSubmitted:          steadyStats.recordsSubmitted,
		AchievedRowsPerSec:        round2(rowsPerSec),
		WireMBPerSec:              round2(wireMBPerSec),
		BytesPerRow:               round2(bytesPerRow),
		AttemptedBytesPerAckedRow: round2(bytesPerRow),
		Latency:                   computeLatencySummary(steadyStats.latenciesMs),
		Memory: MemorySummary{
			SysMB:               round2(lastRSSMB),
			PeakRSSMB:           round2(peakRSSMB),
			CPUSeconds:          round2(cpuDeltaSec),
			CPUCoresUsed:        round2(cpuCoresUsed),
			CPUCoresPer10kRowsS: round2(cpuCoresPer10k),
		},
		Telemetry:  telem,
		ByteLayers: byteLayers,
	}, steadyStats.firstErr, nil
}
