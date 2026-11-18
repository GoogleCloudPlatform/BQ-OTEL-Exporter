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
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
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
	otlpAddr       string
	extraOTLPAddrs []string
	healthAddr     string
	metricsHost    string
	metricsPort    int
	storageRoot    string
	useBQFake      bool
	fakeGRPCURL    string
	fakeRESTURL    string
}

type collectorRewriteMeta struct {
	hasHealthCheck        bool
	activePipelineKey     string
	activeExporterID      string
	effectiveTable        string
	effectiveRedaction    bool
	effectiveBackpressure bool
	extraOTLPAddrs        []string
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
	sourceBytes int64
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

func yamlBool(raw any) bool {
	switch v := raw.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
	}
	return false
}

func isBigQueryComponentID(id string) bool {
	return id == "bigquery" || strings.HasPrefix(id, "bigquery/")
}

func isOTLPComponentID(id string) bool {
	return id == "otlp" || strings.HasPrefix(id, "otlp/")
}

func isHealthCheckComponentID(id string) bool {
	return id == "health_check" || strings.HasPrefix(id, "health_check/")
}

func isFileStorageComponentID(id string) bool {
	return id == "file_storage" || strings.HasPrefix(id, "file_storage/")
}

func sanitizeExtensionDirName(id string) string {
	var b strings.Builder
	for _, r := range id {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	s := b.String()
	if s == "" || s == "." || s == ".." {
		return "file_storage"
	}
	return s
}

func signalTableSchema(signal string) *storagepb.TableSchema {
	switch signal {
	case "traces":
		return schema.SpansTableSchema()
	case "metrics":
		return schema.MetricsTableSchema()
	default:
		return schema.LogsTableSchema()
	}
}

func countActiveSignalOTLPReceivers(rawYAML []byte, signal string) int {
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil || len(doc) == 0 {
		return 1
	}
	if signal == "" {
		signal = "logs"
	}
	svc, _ := doc["service"].(map[string]any)
	pipelines, _ := svc["pipelines"].(map[string]any)
	var matched []string
	for k := range pipelines {
		if k == signal || strings.HasPrefix(k, signal+"/") {
			matched = append(matched, k)
		}
	}
	if len(matched) != 1 {
		return 1
	}
	pipe, _ := pipelines[matched[0]].(map[string]any)
	recvIDs, err := extractYAMLStringSlice(pipe["receivers"])
	if err != nil || len(recvIDs) == 0 {
		return 1
	}
	return len(recvIDs)
}

func formatCollectorExitErr(prefix string, waitErr error, diag *boundedDiagBuffer) error {
	var diagStr string
	if diag != nil {
		diagStr = diag.String()
	}
	if waitErr == nil {
		return fmt.Errorf("%s (exit status 0): %s", prefix, diagStr)
	}
	return fmt.Errorf("%s (%w): %s", prefix, waitErr, diagStr)
}

func rewriteBigQueryExporterMap(bq map[string]any, signal string, cfg RunnerConfig, ep collectorEndpointOverride) (effectiveTable string, effectiveRedaction bool, effectiveBackpressure bool, err error) {
	bq["project"] = cfg.ProjectID
	bq["dataset"] = cfg.DatasetID
	bq["location"] = cfg.Location

	if sigMap, ok := bq[signal].(map[string]any); ok && sigMap != nil {
		if tbl, ok := sigMap["table"].(string); ok {
			effectiveTable = strings.TrimSpace(tbl)
		}
	}
	if effectiveTable == "" {
		effectiveTable = collectorTargetTable(signal)
	}

	writeCfg := ensureYAMLSubmap(bq, "write")
	writeCfg["stream_pool_size"] = cfg.StreamPoolSize
	writeCfg["connection_pool_size"] = cfg.ConnectionPoolSize
	writeCfg["max_inflight_requests"] = cfg.MaxInflightRequests
	writeCfg["max_request_bytes"] = cfg.MaxRequestBytes
	if cfg.Compression != "" {
		writeCfg["compression"] = cfg.Compression
	}

	bpMap, _ := writeCfg["backpressure"].(map[string]any)
	yamlBackpressure := bpMap != nil && yamlBool(bpMap["enabled"])
	if cfg.Backpressure {
		bp := ensureYAMLSubmap(writeCfg, "backpressure")
		bp["enabled"] = true
		if cfg.SimulateAckDelay > 0 {
			lt := max(time.Millisecond, cfg.SimulateAckDelay/2)
			bp["latency_threshold"] = lt.String()
		}
	}
	effectiveBackpressure = cfg.Backpressure || yamlBackpressure

	if ep.useBQFake && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0) {
		retryCfg := ensureYAMLSubmap(bq, "retry_on_failure")
		retryCfg["enabled"] = true
		retryCfg["initial_interval"] = "10ms"
		retryCfg["max_interval"] = "50ms"
	}

	redMap, _ := bq["redaction"].(map[string]any)
	yamlRedaction := redMap != nil && yamlBool(redMap["enabled"])
	if cfg.Redaction {
		red := ensureYAMLSubmap(bq, "redaction")
		red["enabled"] = true
		red["redact_log_body"] = true
		patterns := make([]any, len(blockedSecretPatterns))
		for i, p := range blockedSecretPatterns {
			patterns[i] = p
		}
		red["blocked_value_patterns"] = patterns
	}
	effectiveRedaction = cfg.Redaction || yamlRedaction

	if cfg.OffloadGCSBucket != "" {
		off := ensureYAMLSubmap(bq, "offload")
		off["enabled"] = true
		off["bucket"] = cfg.OffloadGCSBucket
		off["min_bytes"] = cfg.OffloadThresholdBytes
	}
	if offMap, ok := bq["offload"].(map[string]any); ok && offMap != nil {
		if yamlBool(offMap["enabled"]) && ep.useBQFake {
			return "", false, false, errors.New("collector offload.enabled requires --collector-allow-live (payload offload writes to live Cloud Storage)")
		}
		if ep.useBQFake {
			delete(bq, "offload")
		}
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
	return effectiveTable, effectiveRedaction, effectiveBackpressure, nil
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, collectorRewriteMeta, error) {
	var meta collectorRewriteMeta
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, meta, fmt.Errorf("parsing collector YAML config: %w", err)
	}
	if len(doc) == 0 {
		return nil, meta, errors.New("collector YAML config is empty")
	}
	if signal == "" {
		signal = "logs"
	}

	svc := ensureYAMLSubmap(doc, "service")
	pipelines := ensureYAMLSubmap(svc, "pipelines")

	var matched []string
	for k := range pipelines {
		if k == signal || strings.HasPrefix(k, signal+"/") {
			matched = append(matched, k)
		}
	}
	slices.Sort(matched)

	switch len(matched) {
	case 0:
		if len(pipelines) > 0 {
			found := make([]string, 0, len(pipelines))
			for k := range pipelines {
				found = append(found, k)
			}
			slices.Sort(found)
			return nil, meta, fmt.Errorf("collector config defines no %q pipeline (found %v)", signal, found)
		}
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
		meta.activePipelineKey = signal
	case 1:
		meta.activePipelineKey = matched[0]
		for k := range pipelines {
			if k != meta.activePipelineKey {
				delete(pipelines, k)
			}
		}
	default:
		return nil, meta, fmt.Errorf("collector config defines multiple %q pipelines (%v); keep a single pipeline for the benchmarked signal", signal, matched)
	}

	activePipe := ensureYAMLSubmap(pipelines, meta.activePipelineKey)
	exporterIDs, err := extractYAMLStringSlice(activePipe["exporters"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading exporters for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	if len(exporterIDs) != 1 {
		return nil, meta, fmt.Errorf("collector pipeline %q must configure exactly 1 bigquery exporter for single-sink accounting, got %d (%v)", meta.activePipelineKey, len(exporterIDs), exporterIDs)
	}
	if !isBigQueryComponentID(exporterIDs[0]) {
		return nil, meta, fmt.Errorf("collector pipeline %q references unsupported non-bigquery exporter %q", meta.activePipelineKey, exporterIDs[0])
	}
	meta.activeExporterID = exporterIDs[0]

	exportersMap := ensureYAMLSubmap(doc, "exporters")
	bq := ensureYAMLSubmap(exportersMap, meta.activeExporterID)
	effTable, effRedact, effBP, err := rewriteBigQueryExporterMap(bq, signal, cfg, ep)
	if err != nil {
		return nil, meta, err
	}
	meta.effectiveTable = effTable
	meta.effectiveRedaction = effRedact
	meta.effectiveBackpressure = effBP

	for k := range exportersMap {
		if k != meta.activeExporterID {
			delete(exportersMap, k)
		}
	}

	activeExts, err := extractYAMLStringSlice(svc["extensions"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading collector service.extensions: %w", err)
	}
	activeExtSet := make(map[string]struct{}, len(activeExts))
	dedupExts := make([]string, 0, len(activeExts))
	for _, extID := range activeExts {
		if _, seen := activeExtSet[extID]; !seen {
			activeExtSet[extID] = struct{}{}
			dedupExts = append(dedupExts, extID)
		}
	}

	if sqMap, ok := bq["sending_queue"].(map[string]any); ok && sqMap != nil {
		if rawStorage, hasStorage := sqMap["storage"]; hasStorage && rawStorage != nil {
			stID, isStr := rawStorage.(string)
			if !isStr {
				return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage must be a string extension ID, got %T", meta.activeExporterID, rawStorage)
			}
			stID = strings.TrimSpace(stID)
			if stID != "" {
				if !isFileStorageComponentID(stID) {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is unsupported; only file_storage* extensions are supported", meta.activeExporterID, stID)
				}
				if _, isActive := activeExtSet[stID]; !isActive {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q is not enabled in service.extensions", meta.activeExporterID, stID)
				}
			}
		}
	}

	if len(dedupExts) > 0 {
		extMap := ensureYAMLSubmap(doc, "extensions")
		healthCheckCount := 0
		for _, extID := range dedupExts {
			switch {
			case isHealthCheckComponentID(extID):
				healthCheckCount++
				if healthCheckCount > 1 {
					return nil, meta, fmt.Errorf("collector service.extensions enables multiple health_check extensions (%v); at most one is supported", dedupExts)
				}
				hc := ensureYAMLSubmap(extMap, extID)
				hc["endpoint"] = ep.healthAddr
				meta.hasHealthCheck = true
			case isFileStorageComponentID(extID):
				if strings.TrimSpace(ep.storageRoot) == "" {
					return nil, meta, fmt.Errorf("collector extension %q requires an isolated storageRoot directory", extID)
				}
				safeExtName := sanitizeExtensionDirName(extID)
				queueDir := filepath.Join(ep.storageRoot, safeExtName, "queue")
				compactionDir := filepath.Join(ep.storageRoot, safeExtName, "compaction")
				if mkErr := os.MkdirAll(queueDir, 0o700); mkErr != nil {
					return nil, meta, fmt.Errorf("creating isolated file_storage queue directory for %q: %w", extID, mkErr)
				}
				if mkErr := os.MkdirAll(compactionDir, 0o700); mkErr != nil {
					return nil, meta, fmt.Errorf("creating isolated file_storage compaction directory for %q: %w", extID, mkErr)
				}
				fsCfg := ensureYAMLSubmap(extMap, extID)
				fsCfg["directory"] = queueDir
				ensureYAMLSubmap(fsCfg, "compaction")["directory"] = compactionDir
			default:
				return nil, meta, fmt.Errorf("collector service.extensions references unsupported active extension %q", extID)
			}
		}
		for k := range extMap {
			if _, used := activeExtSet[k]; !used {
				delete(extMap, k)
			}
		}
		if len(extMap) == 0 {
			delete(doc, "extensions")
		}
	} else {
		delete(doc, "extensions")
	}

	receiverIDs, err := extractYAMLStringSlice(activePipe["receivers"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading receivers for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	if len(receiverIDs) == 0 {
		receiverIDs = []string{"otlp"}
		activePipe["receivers"] = []any{"otlp"}
	}
	activeReceivers := make(map[string]struct{}, len(receiverIDs))
	dedupReceivers := make([]string, 0, len(receiverIDs))
	for _, recvID := range receiverIDs {
		if !isOTLPComponentID(recvID) {
			return nil, meta, fmt.Errorf("collector pipeline %q references unsupported non-otlp receiver %q", meta.activePipelineKey, recvID)
		}
		if _, seen := activeReceivers[recvID]; !seen {
			activeReceivers[recvID] = struct{}{}
			dedupReceivers = append(dedupReceivers, recvID)
		}
	}

	receiversMap := ensureYAMLSubmap(doc, "receivers")
	usedAddrs := make(map[string]struct{}, len(dedupReceivers))
	if ep.otlpAddr != "" {
		usedAddrs[ep.otlpAddr] = struct{}{}
	}
	for i, recvID := range dedupReceivers {
		otlpRecv := ensureYAMLSubmap(receiversMap, recvID)
		protocols := ensureYAMLSubmap(otlpRecv, "protocols")
		delete(protocols, "http")
		grpcCfg := ensureYAMLSubmap(protocols, "grpc")
		if i == 0 {
			grpcCfg["endpoint"] = ep.otlpAddr
			continue
		}
		addr := "127.0.0.1:0"
		if i-1 < len(ep.extraOTLPAddrs) && strings.TrimSpace(ep.extraOTLPAddrs[i-1]) != "" {
			candidate := strings.TrimSpace(ep.extraOTLPAddrs[i-1])
			if candidate != "127.0.0.1:0" {
				if _, dup := usedAddrs[candidate]; dup {
					return nil, meta, fmt.Errorf("duplicate OTLP receiver endpoint %q assigned to receiver %q", candidate, recvID)
				}
				usedAddrs[candidate] = struct{}{}
			}
			addr = candidate
		}
		grpcCfg["endpoint"] = addr
		meta.extraOTLPAddrs = append(meta.extraOTLPAddrs, addr)
	}
	for k := range receiversMap {
		if _, used := activeReceivers[k]; !used {
			delete(receiversMap, k)
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
		return nil, meta, fmt.Errorf("marshaling rewritten collector YAML: %w", err)
	}
	return out, meta, nil
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

func readPIDCPUSeconds(pid int) (float64, bool) {
	if pid <= 0 {
		return 0, false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, false
	}
	s := string(raw)
	closeParen := strings.LastIndexByte(s, ')')
	if closeParen < 0 || closeParen+1 >= len(s) {
		return 0, false
	}
	fields := strings.Fields(s[closeParen+1:])
	if len(fields) <= 12 {
		return 0, false
	}
	utimeTicks, err := strconv.ParseUint(fields[11], 10, 64)
	if err != nil {
		return 0, false
	}
	stimeTicks, err := strconv.ParseUint(fields[12], 10, 64)
	if err != nil {
		return 0, false
	}
	return float64(utimeTicks+stimeTicks) / linuxUserHZ, true
}

func readPIDMemoryMB(pid int) (vmRSSMB, vmHWMMB float64, ok bool) {
	if pid <= 0 {
		return 0, 0, false
	}
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		if pid == os.Getpid() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			sysMB := float64(ms.Sys) / (1024.0 * 1024.0)
			return sysMB, sysMB, sysMB > 0
		}
		return 0, 0, false
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
	if vmRSSMB <= 0 && vmHWMMB <= 0 {
		if pid == os.Getpid() {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			sysMB := float64(ms.Sys) / (1024.0 * 1024.0)
			return sysMB, sysMB, sysMB > 0
		}
		return 0, 0, false
	}
	return vmRSSMB, vmHWMMB, true
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
			srcBytes := logsSourceContentBytes(ld)
			req := plogotlp.NewExportRequestFromLogs(ld)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				logsReq:     req,
				sourceBytes: srcBytes,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(ld.LogRecordCount()),
			}, nil
		}, nil
	case "traces":
		return func(n int) (collectorPreparedBatch, error) {
			td := gen.TracesBatch(n)
			srcBytes := tracesSourceContentBytes(td)
			req := ptraceotlp.NewExportRequestFromTraces(td)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				tracesReq:   req,
				sourceBytes: srcBytes,
				otlpBytes:   int64(len(raw)),
				recordCount: int64(td.SpanCount()),
			}, nil
		}, nil
	case "metrics":
		return func(n int) (collectorPreparedBatch, error) {
			md := gen.MetricsBatch(n)
			srcBytes := metricsSourceContentBytes(md)
			req := pmetricotlp.NewExportRequestFromMetrics(md)
			raw, err := req.MarshalProto()
			if err != nil {
				return collectorPreparedBatch{}, err
			}
			return collectorPreparedBatch{
				metricsReq:  req,
				sourceBytes: srcBytes,
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
			var wErr error
			if waitErr != nil {
				wErr = *waitErr
			}
			return formatCollectorExitErr("collector exited before becoming ready", wErr, diag)
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

func matchesExporterLabel(labels map[string]string, activeExporterID string) bool {
	exp := labels["exporter"]
	return exp == "" || (activeExporterID != "" && exp == activeExporterID) || (activeExporterID == "" && isBigQueryComponentID(exp))
}

func parseCollectorPrometheusMetrics(body, signal, exporterID string) collectorMetricsSample {
	var s collectorMetricsSample
	for line := range strings.SplitSeq(body, "\n") {
		rawName, labels, val, ok := parsePromExpositionLine(line)
		if !ok {
			continue
		}
		name := strings.TrimSuffix(rawName, "_total")
		switch name {
		case "otelcol_exporter_bigquery_acknowledged_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AcknowledgedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_rejected_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.RejectedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_quarantined_rows":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.QuarantinedRows += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_retries":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.Retries += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_append_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AppendBytesTotal += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_append_result_wait_count":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				if val > 0 {
					s.Telemetry.AppendWaitCount += uint64(math.Round(val))
				}
			}
		case "otelcol_exporter_bigquery_append_result_wait_sum":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.AppendWaitSumSeconds += val
			}
		case "otelcol_exporter_bigquery_redacted_values":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
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
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadedPayloads += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offloaded_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadedBytes += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_offload_dedup_hits":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.Telemetry.OffloadDedupHits += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_backpressure_level":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				lvl := round2(val)
				if lvl > s.Telemetry.BackpressureLevel {
					s.Telemetry.BackpressureLevel = lvl
				}
			}
		case "otelcol_exporter_bigquery_effective_request_bytes":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				eff := int64(math.Round(val))
				if eff > 0 {
					s.Telemetry.EffectiveRequestBytes = eff
				}
			}
		case "otelcol_exporter_bigquery_backpressure_events":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
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
			if matchesExporterLabel(labels, exporterID) {
				s.QueueSize += int64(math.Round(val))
			}
		case "otelcol_exporter_bigquery_inflight_requests":
			if matchesSignalLabel(labels, signal) && matchesExporterLabel(labels, exporterID) {
				s.InflightRequests += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_spans":
			if signal == "traces" && matchesExporterLabel(labels, exporterID) {
				s.SendFailed += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_log_records":
			if signal == "logs" && matchesExporterLabel(labels, exporterID) {
				s.SendFailed += int64(math.Round(val))
			}
		case "otelcol_exporter_send_failed_metric_points":
			if signal == "metrics" && matchesExporterLabel(labels, exporterID) {
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

func scrapeCollectorMetrics(ctx context.Context, httpClient *http.Client, metricsAddr, signal, exporterID string) (collectorMetricsSample, error) {
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
	return parseCollectorPrometheusMetrics(string(bodyBytes), signal, exporterID), nil
}

func drainCollectorPipeline(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal, exporterID string,
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
		cur, scrapeErr := scrapeCollectorMetrics(ctx, httpClient, metricsAddr, signal, exporterID)
		if scrapeErr == nil {
			lastSample = cur
			lastScrape = nil
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, cur)
			accounted := deltaTelem.AcknowledgedRows + deltaTelem.RejectedRows + deltaSendFailed
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
			accounted := deltaTelem.AcknowledgedRows + deltaTelem.RejectedRows + deltaSendFailed
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
			return lastSample, formatCollectorExitErr("collector exited during pipeline drain", wErr, diag)
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
	batchesAttempted      int64
	batchesSucceeded      int64
	batchesFailed         int64
	recordsAttempted      int64
	recordsSubmitted      int64
	rejectedRecords       int64
	dispatchedSourceBytes int64
	dispatchedOTLPBytes   int64
	dispatchedRecords     int64
	latenciesMs           []float64
	firstErr              error
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
		batchesAttempted      atomic.Int64
		batchesSucceeded      atomic.Int64
		batchesFailed         atomic.Int64
		recordsAttempted      atomic.Int64
		recordsSubmitted      atomic.Int64
		rejectedRecords       atomic.Int64
		dispatchedSourceBytes atomic.Int64
		dispatchedOTLPBytes   atomic.Int64
		dispatchedRecords     atomic.Int64
		globalSeq             atomic.Int64
		errOnce               sync.Once
		firstErr              error
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
				dispatchedSourceBytes.Add(batch.sourceBytes)
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
		batchesAttempted:      batchesAttempted.Load(),
		batchesSucceeded:      batchesSucceeded.Load(),
		batchesFailed:         batchesFailed.Load(),
		recordsAttempted:      recordsAttempted.Load(),
		recordsSubmitted:      recordsSubmitted.Load(),
		rejectedRecords:       rejectedRecords.Load(),
		dispatchedSourceBytes: dispatchedSourceBytes.Load(),
		dispatchedOTLPBytes:   dispatchedOTLPBytes.Load(),
		dispatchedRecords:     dispatchedRecords.Load(),
		latenciesMs:           allLatencies,
		firstErr:              firstErr,
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

	storageRoot, err := os.MkdirTemp("", "bq-otel-collector-storage-*")
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("creating temporary collector storage directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(storageRoot) }()

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

	extraCount := max(0, countActiveSignalOTLPReceivers(rawYAML, signal)-1)
	extraListeners := make([]net.Listener, 0, extraCount)
	extraOTLPAddrs := make([]string, 0, extraCount)
	closeReservedListeners := func() {
		_ = otlpLis.Close()
		_ = healthLis.Close()
		_ = metricsLis.Close()
		for _, l := range extraListeners {
			_ = l.Close()
		}
	}
	for range extraCount {
		exLis, exAddr, exErr := reserveLoopbackAddr(ctx)
		if exErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, exErr
		}
		extraListeners = append(extraListeners, exLis)
		extraOTLPAddrs = append(extraOTLPAddrs, exAddr)
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
		otlpAddr:       otlpAddr,
		extraOTLPAddrs: extraOTLPAddrs,
		healthAddr:     healthAddr,
		metricsHost:    metricsHost,
		metricsPort:    metricsPort,
		storageRoot:    storageRoot,
		useBQFake:      useBQFake,
	}
	if fakeSrv != nil {
		override.fakeGRPCURL = fakeSrv.Addr()
		override.fakeRESTURL = strings.TrimRight(fakeSrv.RESTURL(), "/") + "/bigquery/v2/"
	}

	rewrittenYAML, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, override)
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, err
	}
	if fakeSrv != nil && meta.effectiveTable != collectorTargetTable(signal) {
		if seedErr := fakeSrv.SeedTable(cfg.ProjectID, cfg.DatasetID, meta.effectiveTable, signalTableSchema(signal)); seedErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, fmt.Errorf("seeding custom table %q in bqfake: %w", meta.effectiveTable, seedErr)
		}
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

	if readyErr := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, healthAddr, metricsAddr, otlpAddr, meta.hasHealthCheck); readyErr != nil {
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
	baseMetrics, err := scrapeCollectorMetrics(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID)
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
		warmupAfter, drainErr := drainCollectorPipeline(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID, baseMetrics, warmupStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag)
		if drainErr != nil {
			return SignalResult{}, warmupStats.firstErr, drainErr
		}
		warmupTelem, warmupSendFailed := diffCollectorTelemetry(baseMetrics, warmupAfter)
		if !cfg.AllowPartialFailures && (warmupSendFailed > 0 || warmupTelem.RejectedRows > 0 || warmupTelem.QuarantinedRows > 0 || warmupTelem.AcknowledgedRows < warmupStats.recordsSubmitted) {
			sendErr := fmt.Errorf(
				"collector warmup failed gate for %s (submitted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d)",
				signal, warmupStats.recordsSubmitted, warmupTelem.AcknowledgedRows,
				warmupTelem.RejectedRows, warmupTelem.QuarantinedRows, warmupSendFailed,
			)
			return SignalResult{}, errors.Join(warmupStats.firstErr, sendErr), sendErr
		}
		baseMetrics = warmupAfter
	}

	var ackedBytesBefore int64
	if fakeSrv != nil {
		ackedBytesBefore = fakeSrv.AckedBytes()
	}
	cpuBeforeSec, cpuBeforeOK := readPIDCPUSeconds(pid)

	var (
		memMu        sync.Mutex
		lastRSSMB    float64
		peakRSSMB    float64
		memSampledOK bool
		stopMemCh    = make(chan struct{})
		memDoneWg    sync.WaitGroup
	)
	sampleMem := func() {
		rss, hwm, ok := readPIDMemoryMB(pid)
		memMu.Lock()
		if ok {
			memSampledOK = true
		}
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

	if fakeSrv != nil && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0) {
		fakeSrv.SetPeriodicFaults(ctx, meta.effectiveTable, cfg.SimulateThrottleEvery, cfg.SimulateAckDelay)
	}

	startWall := time.Now()
	steadyStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.Duration, cfg.maxBatches, prebuilt, makeBatch, tracesClient, logsClient, metricsClient)
	afterMetrics, drainErr := drainCollectorPipeline(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID, baseMetrics, steadyStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag)
	elapsed := time.Since(startWall)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}
	cpuAfterDrainSec, cpuAfterOK := readPIDCPUSeconds(pid)

	close(stopMemCh)
	memDoneWg.Wait()
	sampleMem()

	if drainErr != nil && !cfg.AllowPartialFailures {
		_ = conn.Close()
		terminateCollector()
		return SignalResult{}, errors.Join(steadyStats.firstErr, drainErr), drainErr
	}

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

	var cpuDeltaSec float64
	if cpuBeforeOK && cpuAfterOK {
		cpuDeltaSec = max(0.0, cpuAfterDrainSec-cpuBeforeSec)
	} else if cmd.ProcessState != nil {
		totalCPUSec := cmd.ProcessState.UserTime().Seconds() + cmd.ProcessState.SystemTime().Seconds()
		cpuDeltaSec = max(0.0, totalCPUSec-cpuBeforeSec)
	}

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
		dispatched := &dispatchedByteTotals{
			sourceBytes: steadyStats.dispatchedSourceBytes,
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
			populateLiveTableStorage(ctx, cfg, meta.effectiveTable, byteLayers)
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
		Redaction:                 meta.effectiveRedaction,
		Backpressure:              meta.effectiveBackpressure,
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
			PeakRSSUnavailable:  !memSampledOK,
			CPUSeconds:          round2(cpuDeltaSec),
			CPUCoresUsed:        round2(cpuCoresUsed),
			CPUCoresPer10kRowsS: round2(cpuCoresPer10k),
		},
		Telemetry:  telem,
		ByteLayers: byteLayers,
	}, steadyStats.firstErr, nil
}
