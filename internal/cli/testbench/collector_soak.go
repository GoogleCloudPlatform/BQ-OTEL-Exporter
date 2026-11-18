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
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
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
	metricsHost string
	metricsPort int
	useBQFake   bool
	fakeGRPCURL string
	fakeRESTURL string
}

type collectorMetricsSample struct {
	Telemetry        TelemetrySnapshot
	QueueSize        int64
	InflightRequests int64
	SendFailed       int64
	HeapAllocBytes   uint64
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

func extractYAMLStringSlice(raw any) ([]string, error) {
	if raw == nil {
		return nil, nil
	}
	switch v := raw.(type) {
	case []string:
		out := make([]string, len(v))
		copy(out, v)
		return out, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected string item in YAML sequence, got %T", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected YAML sequence of strings, got %T", raw)
	}
}

func isBigQueryComponentID(id string) bool {
	return id == "bigquery" || strings.HasPrefix(id, "bigquery/")
}

func isOTLPComponentID(id string) bool {
	return id == "otlp" || strings.HasPrefix(id, "otlp/")
}

func rewriteBigQueryExporterMap(bq map[string]any, cfg RunnerConfig, ep collectorEndpointOverride) {
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
	if cfg.Redaction && cfg.OffloadDir == "" {
		red := ensureYAMLSubmap(bq, "redaction")
		red["enabled"] = true
		red["redact_log_body"] = true
		patterns := make([]any, len(blockedSecretPatterns))
		for i, p := range blockedSecretPatterns {
			patterns[i] = p
		}
		red["blocked_value_patterns"] = patterns
	}
	if cfg.OffloadGCSBucket != "" {
		off := ensureYAMLSubmap(bq, "offload")
		off["enabled"] = true
		off["bucket"] = cfg.OffloadGCSBucket
		off["min_bytes"] = cfg.OffloadThresholdBytes
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
			"tables":          cfg.EphemeralDataset,
			"companion_views": cfg.EphemeralDataset,
			"search_indexes":  false,
		}
		if cfg.EphemeralDataset {
			quarantine := ensureYAMLSubmap(bq, "quarantine")
			quarantine["enabled"] = true
		}
	}
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, bool, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, false, fmt.Errorf("parsing collector YAML config: %w", err)
	}
	if len(doc) == 0 {
		return nil, false, errors.New("collector YAML config is empty")
	}
	if signal == "" {
		signal = "logs"
	}

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
	for k := range pipelines {
		if k != signal {
			delete(pipelines, k)
		}
	}

	activePipe := ensureYAMLSubmap(pipelines, signal)
	exporterIDs, err := extractYAMLStringSlice(activePipe["exporters"])
	if err != nil {
		return nil, false, fmt.Errorf("reading exporters for collector pipeline %q: %w", signal, err)
	}
	if len(exporterIDs) == 0 {
		return nil, false, errors.New("active collector pipeline has no exporters configured")
	}
	activeExporters := make(map[string]struct{}, len(exporterIDs))
	for _, expID := range exporterIDs {
		if !isBigQueryComponentID(expID) {
			return nil, false, fmt.Errorf("collector pipeline %q references unsupported non-bigquery exporter %q", signal, expID)
		}
		activeExporters[expID] = struct{}{}
	}

	exportersMap := ensureYAMLSubmap(doc, "exporters")
	for _, expID := range exporterIDs {
		bq := ensureYAMLSubmap(exportersMap, expID)
		rewriteBigQueryExporterMap(bq, cfg, ep)
	}
	for k := range exportersMap {
		if _, used := activeExporters[k]; !used {
			delete(exportersMap, k)
		}
	}

	receiverIDs, err := extractYAMLStringSlice(activePipe["receivers"])
	if err != nil {
		return nil, false, fmt.Errorf("reading receivers for collector pipeline %q: %w", signal, err)
	}
	if len(receiverIDs) == 0 {
		receiverIDs = []string{"otlp"}
		activePipe["receivers"] = []any{"otlp"}
	}
	activeReceivers := make(map[string]struct{}, len(receiverIDs))
	for _, recvID := range receiverIDs {
		if !isOTLPComponentID(recvID) {
			return nil, false, fmt.Errorf("collector pipeline %q references unsupported non-otlp receiver %q", signal, recvID)
		}
		activeReceivers[recvID] = struct{}{}
	}

	receiversMap := ensureYAMLSubmap(doc, "receivers")
	for _, recvID := range receiverIDs {
		otlpRecv := ensureYAMLSubmap(receiversMap, recvID)
		protocols := ensureYAMLSubmap(otlpRecv, "protocols")
		delete(protocols, "http")
		grpcCfg := ensureYAMLSubmap(protocols, "grpc")
		grpcCfg["endpoint"] = ep.otlpAddr
	}
	for k := range receiversMap {
		if _, used := activeReceivers[k]; !used {
			delete(receiversMap, k)
		}
	}

	hasHealthCheck := false
	if extMap, ok := doc["extensions"].(map[string]any); ok {
		if _, exists := extMap["health_check"]; exists {
			hc := ensureYAMLSubmap(extMap, "health_check")
			hc["endpoint"] = ep.healthAddr
			hasHealthCheck = true
		}
	}

	if ep.metricsHost != "" && ep.metricsPort > 0 {
		telem := ensureYAMLSubmap(svc, "telemetry")
		metricsCfg := ensureYAMLSubmap(telem, "metrics")
		metricsCfg["level"] = "detailed"
		metricsCfg["readers"] = []any{
			map[string]any{
				"pull": map[string]any{
					"exporter": map[string]any{
						"prometheus": map[string]any{
							"host":                ep.metricsHost,
							"port":                ep.metricsPort,
							"without_scope_info":  true,
							"without_type_suffix": true,
							"without_units":       true,
						},
					},
				},
			},
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
	gen := NewGenerator(GeneratorConfig{
		WorkloadProfile:  cfg.WorkloadProfile,
		PayloadBytes:     cfg.PayloadBytes,
		UniquePayloads:   cfg.UniquePayloads,
		PlantSecrets:     cfg.Redaction || cfg.PlantSecrets,
		ResourceAttrs:    cfg.ResourceAttrs,
		UpstreamInsertID: cfg.UpstreamInsertID,
	})
	switch signal {
	case "logs":
		return func(n int) (collectorPreparedBatch, error) {
			ld := gen.LogsBatch(n)
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
		return func(n int) (collectorPreparedBatch, error) {
			td := gen.TracesBatch(n)
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
		return func(n int) (collectorPreparedBatch, error) {
			md := gen.MetricsBatch(n)
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

func probeHTTPOK(ctx context.Context, httpClient *http.Client, url string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return false
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func probeCollectorReady(ctx context.Context, httpClient *http.Client, healthAddr, metricsAddr, otlpAddr string, hasHealthCheck bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if hasHealthCheck {
		if !probeHTTPOK(probeCtx, httpClient, "http://"+healthAddr) {
			return false
		}
	}
	if metricsAddr != "" {
		if !probeHTTPOK(probeCtx, httpClient, "http://"+metricsAddr+"/metrics") {
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

func waitCollectorReady(ctx context.Context, doneCh <-chan struct{}, waitErr *error, diag *boundedDiagBuffer, healthAddr, metricsAddr, otlpAddr string, hasHealthCheck bool) error {
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	defer httpClient.CloseIdleConnections()

	deadline := time.Now().Add(collectorStartupTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if probeCollectorReady(ctx, httpClient, healthAddr, metricsAddr, otlpAddr, hasHealthCheck) {
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

func parsePromLabels(raw string) map[string]string {
	labels := make(map[string]string)
	i := 0
	n := len(raw)
	for i < n {
		for i < n && (raw[i] == ',' || raw[i] == ' ' || raw[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(raw[i:], '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(raw[i : i+eq])
		i += eq + 1
		if i >= n || raw[i] != '"' {
			break
		}
		i++
		var val strings.Builder
		for i < n {
			ch := raw[i]
			i++
			if ch == '\\' && i < n {
				esc := raw[i]
				i++
				switch esc {
				case 'n':
					val.WriteByte('\n')
				case 't':
					val.WriteByte('\t')
				default:
					val.WriteByte(esc)
				}
				continue
			}
			if ch == '"' {
				break
			}
			val.WriteByte(ch)
		}
		if key != "" {
			labels[key] = val.String()
		}
	}
	return labels
}

func parsePromExpositionLine(line string) (string, map[string]string, float64, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", nil, 0, false
	}
	var name string
	var labels map[string]string
	var rest string
	if openIdx := strings.IndexByte(line, '{'); openIdx >= 0 {
		name = strings.TrimSpace(line[:openIdx])
		closeIdx := -1
		inQuotes := false
		for i := openIdx + 1; i < len(line); i++ {
			ch := line[i]
			if ch == '\\' && inQuotes {
				i++
				continue
			}
			if ch == '"' {
				inQuotes = !inQuotes
				continue
			}
			if ch == '}' && !inQuotes {
				closeIdx = i
				break
			}
		}
		if closeIdx < 0 {
			return "", nil, 0, false
		}
		labels = parsePromLabels(line[openIdx+1 : closeIdx])
		rest = strings.TrimSpace(line[closeIdx+1:])
	} else {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return "", nil, 0, false
		}
		name = fields[0]
		rest = fields[1]
	}
	valFields := strings.Fields(rest)
	if len(valFields) == 0 || name == "" {
		return "", nil, 0, false
	}
	val, err := strconv.ParseFloat(valFields[0], 64)
	if err != nil || math.IsNaN(val) || math.IsInf(val, 0) {
		return "", nil, 0, false
	}
	return name, labels, val, true
}

func matchesSignalLabel(labels map[string]string, signal string) bool {
	if len(labels) == 0 {
		return true
	}
	sig := labels["signal"]
	return sig == "" || sig == signal
}

func matchesExporterLabel(labels map[string]string) bool {
	if len(labels) == 0 {
		return true
	}
	exp := labels["exporter"]
	return exp == "" || isBigQueryComponentID(exp)
}

func parseCollectorPrometheusMetrics(body, signal string) collectorMetricsSample {
	var s collectorMetricsSample
	for line := range strings.SplitSeq(body, "\n") {
		rawName, labels, val, ok := parsePromExpositionLine(line)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(rawName, "_total")
		switch name {
		case "otelcol_exporter_bigquery_acknowledged_rows":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.AcknowledgedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_rejected_rows":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.RejectedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_quarantined_rows":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.QuarantinedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_retries":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.Retries += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_append_bytes":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.AppendBytesTotal += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_append_result_wait_count":
			if matchesSignalLabel(labels, signal) {
				if val > 0 {
					s.Telemetry.AppendWaitCount += uint64(math.Round(val))
				}
			}
		case "otelcol_exporter_bigquery_append_result_wait_sum":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.AppendWaitSumSeconds += val
			}
		case "otelcol_exporter_bigquery_redacted_values":
			if matchesSignalLabel(labels, signal) {
				n := int64(math.Round(val))
				s.Telemetry.RedactedValuesTotal += n
				mt := labels["match_type"]
				if mt != "" {
					if s.Telemetry.RedactedByMatchType == nil {
						s.Telemetry.RedactedByMatchType = make(map[string]int64)
					}
					s.Telemetry.RedactedByMatchType[mt] += n
				}
			}
		case "otelcol_exporter_bigquery_offloaded_payloads":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.OffloadedPayloads += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offloaded_bytes":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.OffloadedBytes += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offload_dedup_hits":
			if matchesSignalLabel(labels, signal) {
				s.Telemetry.OffloadDedupHits += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_backpressure_level":
			if matchesSignalLabel(labels, signal) {
				lvl := round2(val)
				if lvl > s.Telemetry.BackpressureLevel {
					s.Telemetry.BackpressureLevel = lvl
				}
			}
		case "otelcol_exporter_bigquery_effective_request_bytes":
			if matchesSignalLabel(labels, signal) {
				eff := int64(math.Round(val))
				if eff > 0 {
					s.Telemetry.EffectiveRequestBytes = eff
				}
			}
		case "otelcol_exporter_bigquery_backpressure_events":
			if matchesSignalLabel(labels, signal) {
				trig := labels["trigger"]
				if trig == "" {
					trig = "unknown"
				}
				if s.Telemetry.BackpressureEvents == nil {
					s.Telemetry.BackpressureEvents = make(map[string]int64)
				}
				s.Telemetry.BackpressureEvents[trig] += int64(math.Round(val))
			}
		case "otelcol_exporter_queue_size":
			if matchesExporterLabel(labels) {
				s.QueueSize += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_inflight_requests":
			if matchesSignalLabel(labels, signal) {
				s.InflightRequests += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_spans":
			if signal == "traces" && matchesExporterLabel(labels) {
				s.SendFailed += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_log_records":
			if signal == "logs" && matchesExporterLabel(labels) {
				s.SendFailed += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_metric_points":
			if signal == "metrics" && matchesExporterLabel(labels) {
				s.SendFailed += int64(math.Round(val))
			}
		case "otelcol_process_runtime_heap_alloc_bytes":
			if val >= 0 {
				s.HeapAllocBytes = uint64(math.Round(val))
			}
		}
	}
	s.Telemetry.AppendWaitSumSeconds = round2(s.Telemetry.AppendWaitSumSeconds)
	if s.Telemetry.AppendWaitCount > 0 {
		s.Telemetry.AppendWaitMeanMs = round2((s.Telemetry.AppendWaitSumSeconds * 1000.0) / float64(s.Telemetry.AppendWaitCount))
	}
	return s
}

func diffCollectorTelemetry(before, after collectorMetricsSample) (TelemetrySnapshot, int64) {
	var waitCount uint64
	if after.Telemetry.AppendWaitCount > before.Telemetry.AppendWaitCount {
		waitCount = after.Telemetry.AppendWaitCount - before.Telemetry.AppendWaitCount
	}
	waitSumSec := max(0.0, after.Telemetry.AppendWaitSumSeconds-before.Telemetry.AppendWaitSumSeconds)
	var waitMeanMs float64
	if waitCount > 0 {
		waitMeanMs = round2((waitSumSec * 1000.0) / float64(waitCount))
	}

	var redactedByType map[string]int64
	for k, v := range after.Telemetry.RedactedByMatchType {
		d := v - before.Telemetry.RedactedByMatchType[k]
		if d > 0 {
			if redactedByType == nil {
				redactedByType = make(map[string]int64)
			}
			redactedByType[k] = d
		}
	}

	var bpEvents map[string]int64
	for k, v := range after.Telemetry.BackpressureEvents {
		d := v - before.Telemetry.BackpressureEvents[k]
		if d > 0 {
			if bpEvents == nil {
				bpEvents = make(map[string]int64)
			}
			bpEvents[k] = d
		}
	}

	deltaSendFailed := max(int64(0), after.SendFailed-before.SendFailed)
	return TelemetrySnapshot{
		AcknowledgedRows:      max(int64(0), after.Telemetry.AcknowledgedRows-before.Telemetry.AcknowledgedRows),
		RejectedRows:          max(int64(0), after.Telemetry.RejectedRows-before.Telemetry.RejectedRows),
		QuarantinedRows:       max(int64(0), after.Telemetry.QuarantinedRows-before.Telemetry.QuarantinedRows),
		Retries:               max(int64(0), after.Telemetry.Retries-before.Telemetry.Retries),
		AppendBytesTotal:      max(int64(0), after.Telemetry.AppendBytesTotal-before.Telemetry.AppendBytesTotal),
		AppendWaitCount:       waitCount,
		AppendWaitSumSeconds:  round2(waitSumSec),
		AppendWaitMeanMs:      waitMeanMs,
		RedactedValuesTotal:   max(int64(0), after.Telemetry.RedactedValuesTotal-before.Telemetry.RedactedValuesTotal),
		RedactedByMatchType:   redactedByType,
		OffloadedPayloads:     max(int64(0), after.Telemetry.OffloadedPayloads-before.Telemetry.OffloadedPayloads),
		OffloadedBytes:        max(int64(0), after.Telemetry.OffloadedBytes-before.Telemetry.OffloadedBytes),
		OffloadDedupHits:      max(int64(0), after.Telemetry.OffloadDedupHits-before.Telemetry.OffloadDedupHits),
		BackpressureLevel:     after.Telemetry.BackpressureLevel,
		EffectiveRequestBytes: after.Telemetry.EffectiveRequestBytes,
		BackpressureEvents:    bpEvents,
	}, deltaSendFailed
}

func scrapeCollectorMetrics(ctx context.Context, httpClient *http.Client, metricsAddr, signal string) (collectorMetricsSample, error) {
	scrapeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(scrapeCtx, http.MethodGet, "http://"+metricsAddr+"/metrics", http.NoBody)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("building collector metrics request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("scraping collector metrics from %s: %w", metricsAddr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return collectorMetricsSample{}, fmt.Errorf("scraping collector metrics from %s: unexpected status %d", metricsAddr, resp.StatusCode)
	}
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return collectorMetricsSample{}, fmt.Errorf("reading collector metrics body: %w", err)
	}
	return parseCollectorPrometheusMetrics(string(bodyBytes), signal), nil
}

func drainCollectorPipeline(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal string,
	baseline collectorMetricsSample,
	expectedSubmitted int64,
	timeout time.Duration,
	doneCh <-chan struct{},
	waitErr *error,
	diag *boundedDiagBuffer,
) (collectorMetricsSample, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastSample  collectorMetricsSample
		stableTicks int
		lastScrape  error
	)

	for {
		cur, scrapeErr := scrapeCollectorMetrics(ctx, httpClient, metricsAddr, signal)
		if scrapeErr == nil {
			lastSample = cur
			lastScrape = nil
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, cur)
			accounted := deltaTelem.AcknowledgedRows + deltaTelem.RejectedRows + deltaTelem.QuarantinedRows + deltaSendFailed
			if accounted >= expectedSubmitted && cur.QueueSize <= 0 && cur.InflightRequests <= 0 {
				stableTicks++
				if stableTicks >= 2 || (expectedSubmitted == 0 && stableTicks >= 1) {
					return cur, nil
				}
			} else {
				stableTicks = 0
			}
		} else {
			lastScrape = scrapeErr
			stableTicks = 0
		}

		if time.Now().After(deadline) {
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, lastSample)
			accounted := deltaTelem.AcknowledgedRows + deltaTelem.RejectedRows + deltaTelem.QuarantinedRows + deltaSendFailed
			if lastScrape != nil {
				return lastSample, fmt.Errorf(
					"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d, last_scrape_err=%w)",
					timeout, expectedSubmitted, accounted,
					deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
					deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests, lastScrape,
				)
			}
			return lastSample, fmt.Errorf(
				"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d)",
				timeout, expectedSubmitted, accounted,
				deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
				deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests,
			)
		}

		select {
		case <-ctx.Done():
			return lastSample, ctx.Err()
		case <-doneCh:
			var wErr error
			if waitErr != nil {
				wErr = *waitErr
			}
			var diagStr string
			if diag != nil {
				diagStr = diag.String()
			}
			return lastSample, fmt.Errorf("collector exited during pipeline drain (%w): %s", wErr, diagStr)
		case <-ticker.C:
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
	phaseCtx, phaseCancel := context.WithDeadline(ctx, deadline)
	defer phaseCancel()

	perWorkerLatencies := make([][]float64, cfg.Workers)

	var wg sync.WaitGroup
	for workerID := range cfg.Workers {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			nextTick := time.Now()
			localSeq := 0
			for phaseCtx.Err() == nil && time.Now().Before(deadline) {
				if workerInterval > 0 && !nextTick.Before(deadline) {
					return
				}
				gSeq := int(globalSeq.Add(1))
				if maxBatches > 0 && gSeq > maxBatches {
					return
				}
				if workerInterval > 0 {
					if waitDur := time.Until(nextTick); waitDur > 0 {
						timer := time.NewTimer(waitDur)
						select {
						case <-phaseCtx.Done():
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

	useBQFake := !cfg.CollectorAllowLive
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
	metricsLis, metricsAddr, err := reserveLoopbackAddr(ctx)
	if err != nil {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		return SignalResult{}, nil, err
	}
	closeReservedListeners := func() {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		_ = metricsLis.Close()
	}

	metricsHost, metricsPortStr, splitErr := net.SplitHostPort(metricsAddr)
	if splitErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("splitting metrics address %q: %w", metricsAddr, splitErr)
	}
	metricsPort, portErr := strconv.Atoi(metricsPortStr)
	if portErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("parsing metrics port %q: %w", metricsPortStr, portErr)
	}

	override := collectorEndpointOverride{
		otlpAddr:    otlpAddr,
		healthAddr:  healthAddr,
		metricsHost: metricsHost,
		metricsPort: metricsPort,
		useBQFake:   useBQFake,
	}
	if fakeSrv != nil {
		override.fakeGRPCURL = fakeSrv.Addr()
		override.fakeRESTURL = strings.TrimRight(fakeSrv.RESTURL(), "/") + "/bigquery/v2/"
	}

	rewrittenYAML, hasHealthCheck, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, override)
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, err
	}

	tempCfgFile, err := os.CreateTemp("", "bq-otel-collector-*.yaml")
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("creating temporary collector config: %w", err)
	}
	tempCfgPath := tempCfgFile.Name()
	defer func() { _ = os.Remove(tempCfgPath) }()
	if _, writeErr := tempCfgFile.Write(rewrittenYAML); writeErr != nil {
		_ = tempCfgFile.Close()
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("writing temporary collector config: %w", writeErr)
	}
	if closeErr := tempCfgFile.Close(); closeErr != nil {
		closeReservedListeners()
		return SignalResult{}, nil, fmt.Errorf("closing temporary collector config: %w", closeErr)
	}

	makeBatch, err := newCollectorBatchBuilder(cfg, signal)
	if err != nil {
		closeReservedListeners()
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
					closeReservedListeners()
					return SignalResult{}, nil, bErr
				}
				ring[r] = b
			}
			prebuilt[w] = ring
		}
	}

	closeReservedListeners()

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
	terminateCollector := func() {
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
			childDone = true
		}
	}
	defer terminateCollector()

	if readyErr := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, healthAddr, metricsAddr, otlpAddr, hasHealthCheck); readyErr != nil {
		return SignalResult{}, nil, readyErr
	}

	metricsClientHTTP := &http.Client{Timeout: 2 * time.Second}
	defer metricsClientHTTP.CloseIdleConnections()

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

	drainTimeout := max(15*time.Second, cfg.CallTimeout)
	baseMetrics, err := scrapeCollectorMetrics(ctx, metricsClientHTTP, metricsAddr, signal)
	if err != nil {
		return SignalResult{}, nil, err
	}

	pid := cmd.Process.Pid
	if cfg.WarmupDuration > 0 {
		warmupStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.WarmupDuration, 0, prebuilt, makeBatch, tracesClient, logsClient, metricsClient)
		if ctx.Err() != nil {
			return SignalResult{}, warmupStats.firstErr, ctx.Err()
		}
		if warmupStats.firstErr != nil && !cfg.AllowPartialFailures {
			return SignalResult{}, warmupStats.firstErr, warmupStats.firstErr
		}
		warmupAfter, drainErr := drainCollectorPipeline(ctx, metricsClientHTTP, metricsAddr, signal, baseMetrics, warmupStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag)
		if drainErr != nil {
			return SignalResult{}, warmupStats.firstErr, drainErr
		}
		_, warmupSendFailed := diffCollectorTelemetry(baseMetrics, warmupAfter)
		if warmupSendFailed > 0 && !cfg.AllowPartialFailures {
			sendErr := fmt.Errorf("collector exporter failed to send %d %s records during warmup", warmupSendFailed, signal)
			return SignalResult{}, errors.Join(warmupStats.firstErr, sendErr), sendErr
		}
		baseMetrics = warmupAfter
	}

	var ackedBytesBefore int64
	if fakeSrv != nil {
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
	afterMetrics, drainErr := drainCollectorPipeline(ctx, metricsClientHTTP, metricsAddr, signal, baseMetrics, steadyStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag)
	elapsed := time.Since(startWall)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}

	close(stopMemCh)
	memDoneWg.Wait()
	sampleMem()

	if drainErr != nil && !cfg.AllowPartialFailures {
		_ = conn.Close()
		terminateCollector()
		return SignalResult{}, errors.Join(steadyStats.firstErr, drainErr), drainErr
	}

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

	telem, deltaSendFailed := diffCollectorTelemetry(baseMetrics, afterMetrics)
	if steadyStats.rejectedRecords > telem.RejectedRows {
		telem.RejectedRows = steadyStats.rejectedRecords
	}
	if deltaSendFailed > 0 {
		if steadyStats.batchesFailed == 0 {
			steadyStats.batchesFailed = 1
		}
		if steadyStats.firstErr == nil {
			steadyStats.firstErr = fmt.Errorf("collector exporter failed to send %d %s records", deltaSendFailed, signal)
		}
	}
	if drainErr != nil && steadyStats.firstErr == nil {
		steadyStats.firstErr = drainErr
	}

	ackedRows := telem.AcknowledgedRows
	attemptedProtoBytes := telem.AppendBytesTotal
	uninflatedBytes := attemptedProtoBytes
	if fakeSrv != nil {
		fakeAckedBytes := max(int64(0), fakeSrv.AckedBytes()-ackedBytesBefore)
		uninflatedBytes = fakeAckedBytes
		if attemptedProtoBytes == 0 {
			attemptedProtoBytes = fakeAckedBytes
			telem.AppendBytesTotal = fakeAckedBytes
		}
	}

	elapsedSec := elapsed.Seconds()
	rowsPerSec := float64(ackedRows) / elapsedSec
	wireMBPerSec := (float64(uninflatedBytes) / (1024.0 * 1024.0)) / elapsedSec
	var (
		bytesPerRow               float64
		attemptedBytesPerAckedRow float64
	)
	if ackedRows > 0 {
		bytesPerRow = float64(uninflatedBytes) / float64(ackedRows)
		attemptedBytesPerAckedRow = float64(attemptedProtoBytes) / float64(ackedRows)
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
		AttemptedBytesPerAckedRow: round2(attemptedBytesPerAckedRow),
		Latency:                   computeLatencySummary(steadyStats.latenciesMs),
		Memory: MemorySummary{
			HeapAllocBytes:      afterMetrics.HeapAllocBytes,
			HeapAllocMB:         round2(float64(afterMetrics.HeapAllocBytes) / (1024.0 * 1024.0)),
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
