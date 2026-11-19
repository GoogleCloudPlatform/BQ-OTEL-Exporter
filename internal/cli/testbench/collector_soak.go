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
	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
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

var collectorMinDrainTimeout = 15 * time.Second

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
	dryRun         bool
}

type collectorRewriteMeta struct {
	hasHealthCheck               bool
	healthCheckPath              string
	activePipelineKey            string
	activeExporterID             string
	effectiveTable               string
	effectiveRedaction           bool
	effectiveBackpressure        bool
	effectiveStreamPoolSize      int
	effectiveConnectionPoolSize  int
	effectiveMaxInflightRequests int
	effectiveMaxRequestBytes     int
	extraOTLPAddrs               []string
	batchProcessorTimeout        time.Duration
	batchProcessorSendSize       int
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

func ensureInlineYAMLSubmap(parent map[string]any, key, pathDesc string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		created := make(map[string]any)
		parent[key] = created
		return created, nil
	}
	if existing, ok := raw.(map[string]any); ok {
		if existing == nil {
			created := make(map[string]any)
			parent[key] = created
			return created, nil
		}
		return existing, nil
	}
	return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (%T: %v)", pathDesc, raw, raw)
}

func optionalInlineYAMLSubmap(parent map[string]any, key, pathDesc string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		return nil, nil
	}
	existing, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (%T: %v)", pathDesc, raw, raw)
	}
	return existing, nil
}

func parseYAMLNonNegativeInt(raw any) (int, error) {
	switch v := raw.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("must be >= 0, got %d", v)
		}
		return v, nil
	case int64:
		if v < 0 || v > int64(math.MaxInt) {
			return 0, fmt.Errorf("must be in [0, %d], got %d", math.MaxInt, v)
		}
		return int(v), nil
	case uint64:
		if v > uint64(math.MaxInt) {
			return 0, fmt.Errorf("exceeds max int: %d", v)
		}
		return int(v), nil
	default:
		return 0, fmt.Errorf("expected integer, got %T", raw)
	}
}

func isValidEnvVarName(name string) bool {
	if name == "" {
		return false
	}
	for i := range len(name) {
		c := name[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_'
		isDigit := c >= '0' && c <= '9'
		if i == 0 && !isAlpha {
			return false
		}
		if !isAlpha && !isDigit {
			return false
		}
	}
	return true
}

func resolveCollectorEnvString(raw string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '$' {
			out.WriteByte(raw[i])
			i++
			continue
		}
		if i+1 < len(raw) && raw[i+1] == '$' {
			out.WriteByte('$')
			i += 2
			continue
		}
		if i+1 >= len(raw) || raw[i+1] != '{' {
			out.WriteByte('$')
			i++
			continue
		}
		closeRel := strings.IndexByte(raw[i+2:], '}')
		if closeRel < 0 {
			return "", fmt.Errorf("unclosed ${...} reference in %q", raw)
		}
		expr := raw[i+2 : i+2+closeRel]
		token := "${" + expr + "}"
		if expr == "" {
			return "", fmt.Errorf("empty ${} reference in %q", raw)
		}
		if strings.Contains(expr, "${") {
			return "", fmt.Errorf("nested ${ reference in %q is not supported", raw)
		}
		beforeDefault, defaultVal, hasDefault := strings.Cut(expr, ":-")
		var (
			varName      string
			hasEnvScheme bool
		)
		if colonIdx := strings.IndexByte(beforeDefault, ':'); colonIdx >= 0 {
			scheme := beforeDefault[:colonIdx]
			rest := beforeDefault[colonIdx+1:]
			if scheme == "" {
				return "", fmt.Errorf("empty provider scheme in %q", token)
			}
			if scheme != "env" {
				return "", fmt.Errorf("unsupported collector config provider %q in %q (only env is supported)", scheme, token)
			}
			hasEnvScheme = true
			varName = rest
		} else {
			varName = beforeDefault
		}
		if hasDefault && !hasEnvScheme {
			return "", fmt.Errorf("default syntax :- requires explicit env: scheme in %q", token)
		}
		if varName == "" {
			return "", fmt.Errorf("empty environment variable name in %q", token)
		}
		if strings.ContainsRune(varName, ':') {
			return "", fmt.Errorf("invalid ':' in environment variable name %q in %q", varName, token)
		}
		if !isValidEnvVarName(varName) {
			return "", fmt.Errorf("invalid environment variable name %q in %q", varName, token)
		}
		val, ok := os.LookupEnv(varName)
		if hasDefault {
			if !ok {
				out.WriteString(strings.ReplaceAll(defaultVal, "$$", "$"))
			} else {
				out.WriteString(val)
			}
		} else if ok {
			out.WriteString(val)
		}
		i += 2 + closeRel + 1
	}
	return out.String(), nil
}

func resolveCollectorTableRef(raw string) (string, error) {
	return resolveCollectorEnvString(raw)
}

func resolveCollectorYAMLBool(raw any, fieldPath string) (bool, error) {
	if raw == nil {
		return false, nil
	}
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		resolved, err := resolveCollectorEnvString(v)
		if err != nil {
			return false, fmt.Errorf("resolving %s: %w", fieldPath, err)
		}
		trimmed := strings.TrimSpace(resolved)
		if trimmed == "" {
			return false, nil
		}
		parsed, err := strconv.ParseBool(trimmed)
		if err != nil {
			return false, fmt.Errorf("parsing %s boolean %q: %w", fieldPath, trimmed, err)
		}
		return parsed, nil
	default:
		return false, fmt.Errorf("%s must be a boolean, got %T", fieldPath, raw)
	}
}

func resolveCollectorEnvYAMLValue(raw any, pathDesc string) (any, error) {
	switch v := raw.(type) {
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		cloned := make(map[string]any, len(v))
		for k, val := range v {
			childPath := k
			if pathDesc != "" {
				childPath = pathDesc + "." + k
			}
			resolvedVal, err := resolveCollectorEnvYAMLValue(val, childPath)
			if err != nil {
				return nil, err
			}
			cloned[k] = resolvedVal
		}
		return cloned, nil
	case []any:
		if v == nil {
			return nil, nil
		}
		cloned := make([]any, len(v))
		for idx, val := range v {
			childPath := fmt.Sprintf("%s[%d]", pathDesc, idx)
			resolvedVal, err := resolveCollectorEnvYAMLValue(val, childPath)
			if err != nil {
				return nil, err
			}
			cloned[idx] = resolvedVal
		}
		return cloned, nil
	case string:
		if !strings.Contains(v, "$") {
			return v, nil
		}
		resolved, err := resolveCollectorEnvString(v)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", pathDesc, err)
		}
		trimmed := strings.TrimSpace(v)
		if strings.HasPrefix(trimmed, "${") && strings.HasSuffix(trimmed, "}") && strings.IndexByte(trimmed, '}') == len(trimmed)-1 {
			var parsed any
			if err := yaml.Unmarshal([]byte(resolved), &parsed); err == nil {
				return parsed, nil
			}
		}
		return resolved, nil
	default:
		return raw, nil
	}
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

func rewriteBigQueryExporterMap(bq map[string]any, exporterID, signal string, cfg RunnerConfig, ep collectorEndpointOverride, meta *collectorRewriteMeta) error {
	exporterPath := "exporters." + exporterID
	bq["project"] = cfg.ProjectID
	bq["dataset"] = cfg.DatasetID
	bq["location"] = cfg.Location

	sigMap, err := ensureInlineYAMLSubmap(bq, signal, exporterPath+"."+signal)
	if err != nil {
		return err
	}
	var effectiveTable string
	if rawTable, exists := sigMap["table"]; exists && rawTable != nil {
		rawStr, ok := rawTable.(string)
		if !ok {
			return fmt.Errorf("collector exporter %s.table must be a string, got %T", signal, rawTable)
		}
		resolvedTable, resErr := resolveCollectorTableRef(rawStr)
		if resErr != nil {
			return fmt.Errorf("resolving collector exporter %s.table: %w", signal, resErr)
		}
		effectiveTable = strings.TrimSpace(resolvedTable)
		if strings.TrimSpace(rawStr) != "" && effectiveTable == "" {
			return fmt.Errorf("collector exporter %s.table %q resolved to an empty table name", signal, rawStr)
		}
	}
	if effectiveTable == "" {
		effectiveTable = collectorTargetTable(signal)
	}
	sigMap["table"] = effectiveTable
	meta.effectiveTable = effectiveTable

	writeCfg, err := ensureInlineYAMLSubmap(bq, "write", exporterPath+".write")
	if err != nil {
		return err
	}
	if cfg.StreamPoolSize > 0 {
		writeCfg["stream_pool_size"] = cfg.StreamPoolSize
	}
	if cfg.ConnectionPoolSize > 0 {
		writeCfg["connection_pool_size"] = cfg.ConnectionPoolSize
	}
	if cfg.MaxInflightRequests > 0 {
		writeCfg["max_inflight_requests"] = cfg.MaxInflightRequests
	}
	if cfg.MaxRequestBytes > 0 {
		writeCfg["max_request_bytes"] = cfg.MaxRequestBytes
	}
	if cfg.Compression != "" {
		writeCfg["compression"] = cfg.Compression
	}

	bpMap, err := optionalInlineYAMLSubmap(writeCfg, "backpressure", exporterPath+".write.backpressure")
	if err != nil {
		return err
	}
	var yamlBackpressure bool
	if bpMap != nil {
		yamlBackpressure, err = resolveCollectorYAMLBool(bpMap["enabled"], exporterPath+".write.backpressure.enabled")
		if err != nil {
			return err
		}
	}
	if cfg.Backpressure {
		bp, bpErr := ensureInlineYAMLSubmap(writeCfg, "backpressure", exporterPath+".write.backpressure")
		if bpErr != nil {
			return bpErr
		}
		bp["enabled"] = true
		if cfg.SimulateAckDelay > 0 {
			lt := max(time.Millisecond, cfg.SimulateAckDelay/2)
			bp["latency_threshold"] = lt.String()
		}
	}
	meta.effectiveBackpressure = cfg.Backpressure || yamlBackpressure

	resolvedWriteAny, err := resolveCollectorEnvYAMLValue(writeCfg, exporterPath+".write")
	if err != nil {
		return err
	}
	resolvedWriteMap, _ := resolvedWriteAny.(map[string]any)
	defaultExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return errors.New("unexpected exporter config type")
	}
	if resolvedWriteMap != nil {
		if err := confmap.NewFromStringMap(resolvedWriteMap).Unmarshal(&defaultExpCfg.Write); err != nil {
			return fmt.Errorf("decoding collector exporter %q write config: %w", exporterID, err)
		}
	}
	meta.effectiveStreamPoolSize = defaultExpCfg.Write.StreamPoolSize
	meta.effectiveConnectionPoolSize = defaultExpCfg.Write.ConnectionPoolSize
	meta.effectiveMaxInflightRequests = defaultExpCfg.Write.MaxInflightRequests
	meta.effectiveMaxRequestBytes = defaultExpCfg.Write.MaxRequestBytes

	if _, err := optionalInlineYAMLSubmap(bq, "retry_on_failure", exporterPath+".retry_on_failure"); err != nil {
		return err
	}
	if ep.useBQFake && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0) {
		retryCfg, rErr := ensureInlineYAMLSubmap(bq, "retry_on_failure", exporterPath+".retry_on_failure")
		if rErr != nil {
			return rErr
		}
		retryCfg["enabled"] = true
		retryCfg["initial_interval"] = "10ms"
		retryCfg["max_interval"] = "50ms"
	}

	redMap, err := optionalInlineYAMLSubmap(bq, "redaction", exporterPath+".redaction")
	if err != nil {
		return err
	}
	var yamlRedaction bool
	if redMap != nil {
		yamlRedaction, err = resolveCollectorYAMLBool(redMap["enabled"], exporterPath+".redaction.enabled")
		if err != nil {
			return err
		}
	}
	if cfg.Redaction {
		red, redErr := ensureInlineYAMLSubmap(bq, "redaction", exporterPath+".redaction")
		if redErr != nil {
			return redErr
		}
		red["enabled"] = true
		red["redact_log_body"] = true
		var existingPatterns []string
		if rawPatterns, hasPatterns := red["blocked_value_patterns"]; hasPatterns && rawPatterns != nil {
			parsed, pErr := extractYAMLStringSlice(rawPatterns)
			if pErr != nil {
				return fmt.Errorf("reading redaction.blocked_value_patterns: %w", pErr)
			}
			existingPatterns = parsed
		}
		seen := make(map[string]struct{}, len(existingPatterns)+len(blockedSecretPatterns))
		merged := make([]any, 0, len(existingPatterns)+len(blockedSecretPatterns))
		for _, p := range existingPatterns {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				merged = append(merged, p)
			}
		}
		for _, p := range blockedSecretPatterns {
			if _, dup := seen[p]; !dup {
				seen[p] = struct{}{}
				merged = append(merged, p)
			}
		}
		red["blocked_value_patterns"] = merged
	}
	meta.effectiveRedaction = cfg.Redaction || yamlRedaction

	if cfg.OffloadGCSBucket != "" {
		off, offErr := ensureInlineYAMLSubmap(bq, "offload", exporterPath+".offload")
		if offErr != nil {
			return offErr
		}
		off["enabled"] = true
		off["bucket"] = cfg.OffloadGCSBucket
		off["min_bytes"] = cfg.OffloadThresholdBytes
	}
	offMap, err := optionalInlineYAMLSubmap(bq, "offload", exporterPath+".offload")
	if err != nil {
		return err
	}
	if offMap != nil {
		offEnabled, offBoolErr := resolveCollectorYAMLBool(offMap["enabled"], exporterPath+".offload.enabled")
		if offBoolErr != nil {
			return offBoolErr
		}
		if ep.useBQFake && offEnabled {
			return errors.New("collector offload.enabled requires --collector-allow-live (payload offload writes to live Cloud Storage)")
		}
	}
	if ep.useBQFake {
		bq["offload"] = map[string]any{"enabled": false}
	}

	quarantineMap, err := optionalInlineYAMLSubmap(bq, "quarantine", exporterPath+".quarantine")
	if err != nil {
		return err
	}
	if quarantineMap != nil {
		if _, err := resolveCollectorYAMLBool(quarantineMap["enabled"], exporterPath+".quarantine.enabled"); err != nil {
			return err
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
			quarantine, qErr := ensureInlineYAMLSubmap(bq, "quarantine", exporterPath+".quarantine")
			if qErr != nil {
				return qErr
			}
			quarantine["enabled"] = true
		}
	}
	return nil
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

	svc, err := ensureInlineYAMLSubmap(doc, "service", "service")
	if err != nil {
		return nil, meta, err
	}
	pipelines, err := ensureInlineYAMLSubmap(svc, "pipelines", "service.pipelines")
	if err != nil {
		return nil, meta, err
	}
	procMap, err := optionalInlineYAMLSubmap(doc, "processors", "processors")
	if err != nil {
		return nil, meta, err
	}

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
		if procMap != nil {
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

	activePipe, err := ensureInlineYAMLSubmap(pipelines, meta.activePipelineKey, "service.pipelines."+meta.activePipelineKey)
	if err != nil {
		return nil, meta, err
	}
	procIDs, err := extractYAMLStringSlice(activePipe["processors"])
	if err != nil {
		return nil, meta, fmt.Errorf("reading processors for collector pipeline %q: %w", meta.activePipelineKey, err)
	}
	sawBatch := false
	for _, id := range procIDs {
		if id != "batch" && !strings.HasPrefix(id, "batch/") {
			continue
		}
		procTimeout := 200 * time.Millisecond
		procSendSize := 8192
		if rawProcCfg, hasProcCfg := procMap[id]; hasProcCfg && rawProcCfg != nil {
			procCfg, ok := rawProcCfg.(map[string]any)
			if !ok {
				return nil, meta, fmt.Errorf("collector processor %q must be an inline YAML map, got %T", id, rawProcCfg)
			}
			if rawT, hasT := procCfg["timeout"]; hasT && rawT != nil {
				tStr, isStr := rawT.(string)
				if !isStr {
					return nil, meta, fmt.Errorf("collector processor %q timeout must be a duration string, got %T", id, rawT)
				}
				if strings.Contains(tStr, "$") {
					resolvedT, rErr := resolveCollectorEnvString(tStr)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q timeout: %w", id, rErr)
					}
					tStr = resolvedT
				}
				parsedT, pErr := time.ParseDuration(strings.TrimSpace(tStr))
				if pErr != nil {
					return nil, meta, fmt.Errorf("parsing collector processor %q timeout %q: %w", id, tStr, pErr)
				}
				if parsedT < 0 {
					return nil, meta, fmt.Errorf("collector processor %q timeout %q must be >= 0", id, tStr)
				}
				procTimeout = parsedT
			}
			if rawS, hasS := procCfg["send_batch_size"]; hasS && rawS != nil {
				if sStr, isStr := rawS.(string); isStr && strings.Contains(sStr, "$") {
					resolvedS, rErr := resolveCollectorEnvString(sStr)
					if rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector processor %q send_batch_size: %w", id, rErr)
					}
					n, sErr := strconv.Atoi(strings.TrimSpace(resolvedS))
					if sErr != nil || n < 0 {
						return nil, meta, fmt.Errorf("parsing collector processor %q send_batch_size %q: expected non-negative integer", id, resolvedS)
					}
					procSendSize = n
				} else {
					parsedS, sErr := parseYAMLNonNegativeInt(rawS)
					if sErr != nil {
						return nil, meta, fmt.Errorf("parsing collector processor %q send_batch_size: %w", id, sErr)
					}
					procSendSize = parsedS
				}
			}
		}
		meta.batchProcessorTimeout = max(meta.batchProcessorTimeout, procTimeout)
		if !sawBatch {
			meta.batchProcessorSendSize = procSendSize
			sawBatch = true
		} else if procSendSize > meta.batchProcessorSendSize {
			meta.batchProcessorSendSize = procSendSize
		}
	}

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

	exportersMap, err := ensureInlineYAMLSubmap(doc, "exporters", "exporters")
	if err != nil {
		return nil, meta, err
	}
	bq, err := ensureInlineYAMLSubmap(exportersMap, meta.activeExporterID, "exporters."+meta.activeExporterID)
	if err != nil {
		return nil, meta, err
	}
	if err := rewriteBigQueryExporterMap(bq, meta.activeExporterID, signal, cfg, ep, &meta); err != nil {
		return nil, meta, err
	}

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

	sqMap, err := optionalInlineYAMLSubmap(bq, "sending_queue", "exporters."+meta.activeExporterID+".sending_queue")
	if err != nil {
		return nil, meta, err
	}
	if sqMap != nil {
		if rawStorage, hasStorage := sqMap["storage"]; hasStorage && rawStorage != nil {
			origStID, isStr := rawStorage.(string)
			if !isStr {
				return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage must be a string extension ID, got %T", meta.activeExporterID, rawStorage)
			}
			stID := origStID
			if strings.Contains(stID, "$") {
				resolvedStID, rErr := resolveCollectorEnvString(stID)
				if rErr != nil {
					return nil, meta, fmt.Errorf("resolving collector exporter %q sending_queue.storage: %w", meta.activeExporterID, rErr)
				}
				stID = strings.TrimSpace(resolvedStID)
				if strings.TrimSpace(origStID) != "" && stID == "" {
					return nil, meta, fmt.Errorf("collector exporter %q sending_queue.storage %q resolved to an empty extension ID", meta.activeExporterID, origStID)
				}
				sqMap["storage"] = stID
			} else {
				stID = strings.TrimSpace(stID)
			}
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

	if _, err := optionalInlineYAMLSubmap(doc, "extensions", "extensions"); err != nil {
		return nil, meta, err
	}
	if len(dedupExts) > 0 {
		extMap, extErr := ensureInlineYAMLSubmap(doc, "extensions", "extensions")
		if extErr != nil {
			return nil, meta, extErr
		}
		healthCheckCount := 0
		for _, extID := range dedupExts {
			switch {
			case isHealthCheckComponentID(extID):
				healthCheckCount++
				if healthCheckCount > 1 {
					return nil, meta, fmt.Errorf("collector service.extensions enables multiple health_check extensions (%v); at most one is supported", dedupExts)
				}
				hc, hcErr := ensureInlineYAMLSubmap(extMap, extID, "extensions."+extID)
				if hcErr != nil {
					return nil, meta, hcErr
				}
				hc["endpoint"] = ep.healthAddr
				var rawPath string
				if rawVal, hasPath := hc["path"]; hasPath && rawVal != nil {
					pStr, ok := rawVal.(string)
					if !ok {
						return nil, meta, fmt.Errorf("collector config extensions.%s.path must be a string, got %T", extID, rawVal)
					}
					if strings.Contains(pStr, "$") {
						resolvedPath, rErr := resolveCollectorEnvString(pStr)
						if rErr != nil {
							return nil, meta, fmt.Errorf("resolving collector config extensions.%s.path: %w", extID, rErr)
						}
						pStr = resolvedPath
						hc["path"] = pStr
					}
					rawPath = pStr
				}
				meta.hasHealthCheck = true
				meta.healthCheckPath = normalizeHealthCheckPath(rawPath)
			case isFileStorageComponentID(extID):
				if strings.TrimSpace(ep.storageRoot) == "" {
					return nil, meta, fmt.Errorf("collector extension %q requires an isolated storageRoot directory", extID)
				}
				safeExtName := sanitizeExtensionDirName(extID)
				queueDir := filepath.Join(ep.storageRoot, safeExtName, "queue")
				compactionDir := filepath.Join(ep.storageRoot, safeExtName, "compaction")
				if !ep.dryRun {
					if mkErr := os.MkdirAll(queueDir, 0o700); mkErr != nil {
						return nil, meta, fmt.Errorf("creating isolated file_storage queue directory for %q: %w", extID, mkErr)
					}
					if mkErr := os.MkdirAll(compactionDir, 0o700); mkErr != nil {
						return nil, meta, fmt.Errorf("creating isolated file_storage compaction directory for %q: %w", extID, mkErr)
					}
				}
				fsCfg, fsErr := ensureInlineYAMLSubmap(extMap, extID, "extensions."+extID)
				if fsErr != nil {
					return nil, meta, fsErr
				}
				fsCfg["directory"] = queueDir
				compactionCfg, compErr := ensureInlineYAMLSubmap(fsCfg, "compaction", "extensions."+extID+".compaction")
				if compErr != nil {
					return nil, meta, compErr
				}
				compactionCfg["directory"] = compactionDir
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

	receiversMap, err := ensureInlineYAMLSubmap(doc, "receivers", "receivers")
	if err != nil {
		return nil, meta, err
	}
	usedAddrs := make(map[string]struct{}, len(dedupReceivers))
	if ep.otlpAddr != "" {
		usedAddrs[ep.otlpAddr] = struct{}{}
	}
	for i, recvID := range dedupReceivers {
		otlpRecv, rErr := ensureInlineYAMLSubmap(receiversMap, recvID, "receivers."+recvID)
		if rErr != nil {
			return nil, meta, rErr
		}
		protocols, pErr := ensureInlineYAMLSubmap(otlpRecv, "protocols", "receivers."+recvID+".protocols")
		if pErr != nil {
			return nil, meta, pErr
		}
		delete(protocols, "http")
		grpcCfg, gErr := ensureInlineYAMLSubmap(protocols, "grpc", "receivers."+recvID+".protocols.grpc")
		if gErr != nil {
			return nil, meta, gErr
		}
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

	existingTelem, err := optionalInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
	if err != nil {
		return nil, meta, err
	}
	if existingTelem != nil {
		if _, err := optionalInlineYAMLSubmap(existingTelem, "metrics", "service.telemetry.metrics"); err != nil {
			return nil, meta, err
		}
	}
	if ep.metricsHost != "" && ep.metricsPort > 0 {
		telem, tErr := ensureInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
		if tErr != nil {
			return nil, meta, tErr
		}
		metricsCfg, mErr := ensureInlineYAMLSubmap(telem, "metrics", "service.telemetry.metrics")
		if mErr != nil {
			return nil, meta, mErr
		}
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

func validateCollectorPreflightConfig(cfg RunnerConfig, signal string) error {
	resolvedCfgPath := resolveCollectorConfigPath(cfg.CollectorConfig)
	rawYAML, err := os.ReadFile(resolvedCfgPath)
	if err != nil {
		return fmt.Errorf("reading collector config %q: %w", cfg.CollectorConfig, err)
	}
	rewrittenYAML, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, signal, collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: "preflight",
		useBQFake:   !cfg.CollectorAllowLive,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
		dryRun:      true,
	})
	if err != nil {
		return err
	}

	var doc map[string]any
	if err := yaml.Unmarshal(rewrittenYAML, &doc); err != nil {
		return fmt.Errorf("parsing rewritten collector YAML config: %w", err)
	}
	exportersMap, ok := doc["exporters"].(map[string]any)
	if !ok {
		return errors.New("rewritten collector config missing exporters map")
	}
	bqMap, ok := exportersMap[meta.activeExporterID].(map[string]any)
	if !ok {
		return fmt.Errorf("rewritten collector exporter %q is not a map", meta.activeExporterID)
	}

	expCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return errors.New("unexpected exporter config type")
	}
	expCfg.QueueSettings = configoptional.None[exporterhelper.QueueBatchConfig]()
	expCfg.Project = cfg.ProjectID
	expCfg.Dataset = cfg.DatasetID
	expCfg.Location = cfg.Location
	switch signal {
	case "traces":
		expCfg.Traces.Table = meta.effectiveTable
	case "metrics":
		expCfg.Metrics.Table = meta.effectiveTable
	default:
		expCfg.Logs.Table = meta.effectiveTable
	}

	if writeMap, ok := bqMap["write"].(map[string]any); ok && writeMap != nil {
		resolvedWriteAny, resErr := resolveCollectorEnvYAMLValue(writeMap, "exporters."+meta.activeExporterID+".write")
		if resErr != nil {
			return resErr
		}
		resolvedWriteMap, _ := resolvedWriteAny.(map[string]any)
		if resolvedWriteMap != nil {
			if err := confmap.NewFromStringMap(resolvedWriteMap).Unmarshal(&expCfg.Write); err != nil {
				return fmt.Errorf("decoding collector exporter %q write config: %w", meta.activeExporterID, err)
			}
		}
	}

	useLocalOffload := cfg.OffloadDir != "" && (signal == "traces" || signal == "logs")
	expCfg.Redaction.Enabled = cfg.Redaction && !useLocalOffload
	if expCfg.Redaction.Enabled {
		expCfg.Redaction.RedactLogBody = true
		expCfg.Redaction.BlockedValuePatterns = blockedSecretPatterns
	}
	if cfg.OffloadGCSBucket != "" {
		expCfg.Offload.Enabled = true
		expCfg.Offload.Bucket = cfg.OffloadGCSBucket
		if cfg.OffloadThresholdBytes > 0 {
			expCfg.Offload.MinBytes = cfg.OffloadThresholdBytes
		}
	}
	if !cfg.CollectorAllowLive {
		expCfg.Endpoint.URL = "127.0.0.1:50051"
		expCfg.Endpoint.Insecure = true
		expCfg.Endpoint.WithoutAuthentication = true
		expCfg.TimeoutSettings.Timeout = 10 * time.Second
	} else {
		expCfg.TimeoutSettings.Timeout = 30 * time.Second
		if cfg.EphemeralDataset {
			expCfg.AutoCreate.Dataset = false
			expCfg.AutoCreate.Tables = true
			expCfg.Quarantine.Enabled = true
		}
	}
	if cfg.CallTimeout > 0 {
		expCfg.TimeoutSettings.Timeout = cfg.CallTimeout
	}
	if err := expCfg.Validate(); err != nil {
		return fmt.Errorf("validating exporter config: %w", err)
	}
	return nil
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

func normalizeHealthCheckPath(healthPath string) string {
	p := strings.TrimSpace(healthPath)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func stopCollectorProcess(p *os.Process) (killed bool) {
	if p == nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return p.Kill() == nil
	}
	err := p.Signal(syscall.SIGTERM)
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrProcessDone) || errors.Is(err, syscall.ESRCH) {
		return false
	}
	return p.Kill() == nil
}

func finalizeCollectorShutdown(
	proc *os.Process,
	doneCh <-chan struct{},
	cmdWaitErr *error,
	ctxErr error,
	diag *boundedDiagBuffer,
) (childDone bool, err error) {
	var killedByShutdown bool
	select {
	case <-doneCh:
		childDone = true
	default:
	}
	if !childDone {
		killedByShutdown = stopCollectorProcess(proc)
		shutdownTimer := time.NewTimer(collectorShutdownTimeout)
		defer shutdownTimer.Stop()
		select {
		case <-doneCh:
			childDone = true
		case <-shutdownTimer.C:
			if proc != nil {
				_ = proc.Kill()
			}
			<-doneCh
			var diagText string
			if diag != nil {
				diagText = diag.String()
			}
			return true, fmt.Errorf("collector did not exit within %s after SIGTERM: %s", collectorShutdownTimeout, diagText)
		}
	}

	var waitErr error
	if cmdWaitErr != nil {
		waitErr = *cmdWaitErr
	}
	if waitErr != nil && ctxErr == nil && !killedByShutdown {
		var diagText string
		if diag != nil {
			diagText = diag.String()
		}
		return true, fmt.Errorf("collector exited with error (%w): %s", waitErr, diagText)
	}
	return true, nil
}

func probeCollectorReady(ctx context.Context, httpClient *http.Client, healthAddr, healthPath, metricsAddr, otlpAddr string, hasHealthCheck bool) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if hasHealthCheck {
		hcPath := normalizeHealthCheckPath(healthPath)
		if !probeHTTPOK(probeCtx, httpClient, "http://"+healthAddr+hcPath) {
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

func waitCollectorReady(ctx context.Context, doneCh <-chan struct{}, waitErr *error, diag *boundedDiagBuffer, healthAddr, healthPath, metricsAddr, otlpAddr string, hasHealthCheck bool) error {
	httpClient := &http.Client{Timeout: 500 * time.Millisecond}
	defer httpClient.CloseIdleConnections()

	deadline := time.Now().Add(collectorStartupTimeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		if probeCollectorReady(ctx, httpClient, healthAddr, healthPath, metricsAddr, otlpAddr, hasHealthCheck) {
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
	rawWaitSum := s.Telemetry.AppendWaitSumSeconds
	s.Telemetry.appendWaitSumSecondsRaw = rawWaitSum
	s.Telemetry.hasRawAppendWaitSum = true
	if s.Telemetry.AppendWaitCount > 0 {
		s.Telemetry.AppendWaitMeanMs = round2((rawWaitSum * 1000.0) / float64(s.Telemetry.AppendWaitCount))
	}
	s.Telemetry.AppendWaitSumSeconds = round2(rawWaitSum)
	return s
}

func diffCollectorTelemetry(before, after collectorMetricsSample) (TelemetrySnapshot, int64) {
	var waitCount uint64
	if after.Telemetry.AppendWaitCount > before.Telemetry.AppendWaitCount {
		waitCount = after.Telemetry.AppendWaitCount - before.Telemetry.AppendWaitCount
	}
	waitSumSec := max(0.0, after.Telemetry.rawAppendWaitSumSeconds()-before.Telemetry.rawAppendWaitSumSeconds())
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
		AcknowledgedRows:        max(int64(0), after.Telemetry.AcknowledgedRows-before.Telemetry.AcknowledgedRows),
		RejectedRows:            max(int64(0), after.Telemetry.RejectedRows-before.Telemetry.RejectedRows),
		QuarantinedRows:         max(int64(0), after.Telemetry.QuarantinedRows-before.Telemetry.QuarantinedRows),
		Retries:                 max(int64(0), after.Telemetry.Retries-before.Telemetry.Retries),
		AppendBytesTotal:        max(int64(0), after.Telemetry.AppendBytesTotal-before.Telemetry.AppendBytesTotal),
		AppendWaitCount:         waitCount,
		AppendWaitSumSeconds:    round2(waitSumSec),
		AppendWaitMeanMs:        waitMeanMs,
		RedactedValuesTotal:     max(int64(0), after.Telemetry.RedactedValuesTotal-before.Telemetry.RedactedValuesTotal),
		RedactedByMatchType:     redactedByType,
		OffloadedPayloads:       max(int64(0), after.Telemetry.OffloadedPayloads-before.Telemetry.OffloadedPayloads),
		OffloadedBytes:          max(int64(0), after.Telemetry.OffloadedBytes-before.Telemetry.OffloadedBytes),
		OffloadDedupHits:        max(int64(0), after.Telemetry.OffloadDedupHits-before.Telemetry.OffloadDedupHits),
		BackpressureLevel:       after.Telemetry.BackpressureLevel,
		EffectiveRequestBytes:   after.Telemetry.EffectiveRequestBytes,
		BackpressureEvents:      bpEvents,
		appendWaitSumSecondsRaw: waitSumSec,
		hasRawAppendWaitSum:     true,
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
	sample, _, err := drainCollectorPipelineWithUnique(
		ctx, httpClient, metricsAddr, signal, exporterID,
		baseline, expectedSubmitted, timeout, doneCh, waitErr, diag,
		0, nil, 0, 0,
	)
	return sample, err
}

func drainCollectorPipelineWithUnique(
	ctx context.Context,
	httpClient *http.Client,
	metricsAddr, signal, exporterID string,
	baseline collectorMetricsSample,
	expectedSubmitted int64,
	timeout time.Duration,
	doneCh <-chan struct{},
	waitErr *error,
	diag *boundedDiagBuffer,
	uniqueAckedBefore int64,
	uniqueAckedFn func() int64,
	batchTimeout time.Duration,
	batchSendSize int,
) (collectorMetricsSample, time.Duration, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastSample    collectorMetricsSample
		stableTicks   int
		lastScrape    error
		hasPrevSample bool
		prevAccounted int64
		lastTickTime  = time.Now()
		idleBatchWait time.Duration
	)

	computeAccounted := func(deltaTelem TelemetrySnapshot, deltaSendFailed int64) int64 {
		exporterAccounted := deltaTelem.AcknowledgedRows + deltaTelem.RejectedRows + deltaSendFailed
		if uniqueAckedFn != nil {
			uniqueAccounted := max(int64(0), uniqueAckedFn()-uniqueAckedBefore) + deltaTelem.RejectedRows + deltaSendFailed
			return min(exporterAccounted, uniqueAccounted)
		}
		return exporterAccounted
	}

	for {
		cur, scrapeErr := scrapeCollectorMetrics(ctx, httpClient, metricsAddr, signal, exporterID)
		now := time.Now()
		tickDelta := now.Sub(lastTickTime)
		lastTickTime = now
		if scrapeErr == nil {
			lastSample = cur
			lastScrape = nil
			deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, cur)
			accounted := computeAccounted(deltaTelem, deltaSendFailed)
			if !hasPrevSample {
				hasPrevSample = true
				prevAccounted = accounted
			} else {
				if batchTimeout > 0 && tickDelta > 0 && cur.QueueSize <= 0 && cur.InflightRequests <= 0 && accounted == prevAccounted {
					pending := expectedSubmitted - accounted
					if pending > 0 && (batchSendSize <= 0 || pending < int64(batchSendSize)) {
						idleBatchWait = min(batchTimeout, idleBatchWait+tickDelta)
					}
				}
				prevAccounted = accounted
			}
			if accounted >= expectedSubmitted && cur.QueueSize <= 0 && cur.InflightRequests <= 0 {
				stableTicks++
				if stableTicks >= 2 || (expectedSubmitted == 0 && stableTicks >= 1) {
					return cur, idleBatchWait, nil
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
			accounted := computeAccounted(deltaTelem, deltaSendFailed)
			if lastScrape != nil {
				return lastSample, idleBatchWait, fmt.Errorf(
					"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d, last_scrape_err=%w)",
					timeout, expectedSubmitted, accounted,
					deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
					deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests, lastScrape,
				)
			}
			return lastSample, idleBatchWait, fmt.Errorf(
				"timed out after %s waiting for collector pipeline to drain (submitted=%d, accounted=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d, queue_size=%d, inflight=%d)",
				timeout, expectedSubmitted, accounted,
				deltaTelem.AcknowledgedRows, deltaTelem.RejectedRows, deltaTelem.QuarantinedRows,
				deltaSendFailed, lastSample.QueueSize, lastSample.InflightRequests,
			)
		}

		select {
		case <-ctx.Done():
			return lastSample, idleBatchWait, ctx.Err()
		case <-doneCh:
			var wErr error
			if waitErr != nil {
				wErr = *waitErr
			}
			return lastSample, idleBatchWait, formatCollectorExitErr("collector exited during pipeline drain", wErr, diag)
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
	prebuilt []collectorPreparedBatch,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
	childDoneCh <-chan struct{},
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

	startPhase := time.Now()
	deadline := startPhase.Add(duration)
	phaseCtx, phaseCancel := context.WithDeadline(ctx, deadline)
	defer phaseCancel()

	var (
		pacerMu         sync.Mutex
		nextScheduled   = startPhase
		remainingBudget int64
		pacedBatchCap   = cfg.BatchSize
	)
	budgetLimited := cfg.TargetRate > 0 && maxBatches == 0
	if budgetLimited {
		totalBudget := max(int64(1), int64(math.Round(float64(cfg.TargetRate)*duration.Seconds())))
		remainingBudget = totalBudget
		pacedBatchCap = min(cfg.BatchSize, max(1, cfg.TargetRate/max(4, cfg.Workers)))
	}

	rpcParentCtx, rpcParentCancel := context.WithCancel(ctx)
	defer rpcParentCancel()

	if childDoneCh != nil {
		go func() {
			select {
			case <-childDoneCh:
				phaseCancel()
				rpcParentCancel()
			case <-phaseCtx.Done():
			}
		}()
	}

	perWorkerLatencies := make([][]float64, cfg.Workers)

	var wg sync.WaitGroup
	for workerID := range cfg.Workers {
		wg.Add(1)
		go func(wID int) {
			defer wg.Done()
			localSeq := 0
			for phaseCtx.Err() == nil && time.Now().Before(deadline) {
				gSeq := int(globalSeq.Add(1))
				if maxBatches > 0 && gSeq > maxBatches {
					return
				}

				var batchRows int64
				if cfg.TargetRate > 0 {
					pacerMu.Lock()
					if !nextScheduled.Before(deadline) || (budgetLimited && remainingBudget <= 0) {
						pacerMu.Unlock()
						if maxBatches == 0 {
							<-phaseCtx.Done()
						}
						return
					}
					if budgetLimited {
						batchRows = min(remainingBudget, int64(pacedBatchCap))
						remainingBudget -= batchRows
					} else {
						batchRows = int64(cfg.BatchSize)
					}
					scheduledAt := nextScheduled
					nextScheduled = nextScheduled.Add(time.Duration(float64(time.Second) * float64(batchRows) / float64(cfg.TargetRate)))
					pacerMu.Unlock()

					if waitDur := time.Until(scheduledAt); waitDur > 0 {
						timer := time.NewTimer(waitDur)
						select {
						case <-phaseCtx.Done():
							timer.Stop()
							return
						case <-timer.C:
						}
					}
					if phaseCtx.Err() != nil {
						return
					}
				} else {
					batchRows = int64(cfg.BatchSize)
				}

				if cfg.workerHook != nil {
					cfg.workerHook(wID, localSeq)
				}

				var (
					batch collectorPreparedBatch
					err   error
				)
				if len(prebuilt) > 0 && int(batchRows) == cfg.BatchSize {
					batch = prebuilt[(wID+localSeq)%len(prebuilt)]
				} else {
					batch, err = makeBatch(int(batchRows))
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

				rpcCtx, cancel := context.WithTimeout(rpcParentCtx, callTimeout)
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
					if childDoneCh != nil {
						select {
						case <-childDoneCh:
							return
						default:
						}
					}
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
	return runCollectorSingleSignalWithFake(ctx, cfg, signal, nil)
}

func runCollectorSingleSignalWithFake(ctx context.Context, cfg RunnerConfig, signal string, injectedFake *bqfake.Server) (SignalResult, error, error) {
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
		if injectedFake != nil {
			fakeSrv = injectedFake
		} else {
			fakeSrv, err = bqfake.New()
			if err != nil {
				return SignalResult{}, nil, fmt.Errorf("starting bqfake for collector mode: %w", err)
			}
			defer func() { _ = fakeSrv.Close() }()
			fakeSrv.SetDiscardRows(true)
		}
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

	faultSimEnabled := fakeSrv != nil && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0)
	effectiveUniquePayloads := cfg.UniquePayloads || faultSimEnabled
	batchCfg := cfg
	batchCfg.UniquePayloads = effectiveUniquePayloads

	makeBatch, err := newCollectorBatchBuilder(batchCfg, signal)
	if err != nil {
		closeReservedListeners()
		return SignalResult{}, nil, err
	}

	var prebuilt []collectorPreparedBatch
	if !effectiveUniquePayloads {
		batchBudgetBytes := max(int64(1), int64(cfg.BatchSize)*int64(cfg.PayloadBytes))
		ringLen := int(min(int64(prebuiltRingPerWorker), max(int64(1), MaxBatchPayloadBudgetBytes/batchBudgetBytes)))
		prebuilt = make([]collectorPreparedBatch, ringLen)
		for r := range ringLen {
			b, bErr := makeBatch(cfg.BatchSize)
			if bErr != nil {
				closeReservedListeners()
				return SignalResult{}, nil, bErr
			}
			prebuilt[r] = b
		}
	}

	closeReservedListeners()

	diag := &boundedDiagBuffer{}
	cmd := exec.CommandContext(ctx, cfg.CollectorBin, "--config="+tempCfgPath)
	cmd.Env = buildCollectorEnv(cfg.MaxProcs)
	cmd.Stdout = diag
	cmd.Stderr = diag
	cmd.Cancel = func() error {
		stopCollectorProcess(cmd.Process)
		return nil
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
			stopCollectorProcess(cmd.Process)
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

	if readyErr := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, healthAddr, meta.healthCheckPath, metricsAddr, otlpAddr, meta.hasHealthCheck); readyErr != nil {
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

	drainTimeout := max(collectorMinDrainTimeout, cfg.CallTimeout)
	if meta.batchProcessorTimeout > 0 {
		drainTimeout = max(drainTimeout, 2*meta.batchProcessorTimeout+5*time.Second)
	}
	baseMetrics, err := scrapeCollectorMetrics(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID)
	if err != nil {
		return SignalResult{}, nil, err
	}

	pid := cmd.Process.Pid
	if cfg.WarmupDuration > 0 {
		warmupStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.WarmupDuration, 0, prebuilt, makeBatch, tracesClient, logsClient, metricsClient, doneCh)
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
		if !cfg.AllowPartialFailures && (warmupStats.batchesFailed > 0 || warmupStats.rejectedRecords > 0 || warmupSendFailed > 0 || warmupTelem.RejectedRows > 0 || warmupTelem.QuarantinedRows > 0 || warmupTelem.AcknowledgedRows < warmupStats.recordsSubmitted) {
			sendErr := fmt.Errorf(
				"collector warmup failed gate for %s (submitted=%d, otlp_rejected=%d, acked=%d, rejected=%d, quarantined=%d, send_failed=%d)",
				signal, warmupStats.recordsSubmitted, warmupStats.rejectedRecords, warmupTelem.AcknowledgedRows,
				warmupTelem.RejectedRows, warmupTelem.QuarantinedRows, warmupSendFailed,
			)
			return SignalResult{}, errors.Join(warmupStats.firstErr, sendErr), sendErr
		}
		baseMetrics = warmupAfter
	}

	var (
		fakeCommittedRowsBefore int64
		ackedBytesBefore        int64
		fakeThrottlesBefore     int64
		uniqueAckedBefore       int64
		uniqueAckedBytesBefore  int64
		uniqueAckedFn           func() int64
	)
	if fakeSrv != nil {
		fakeCommittedRowsBefore = fakeSrv.AckedRowsForTable(meta.effectiveTable)
		ackedBytesBefore = fakeSrv.AckedBytesForTable(meta.effectiveTable)
		fakeThrottlesBefore = fakeSrv.ThrottlesInjectedForTable(meta.effectiveTable)
		if faultSimEnabled {
			fakeSrv.SetTrackUniqueAcked(true)
			uniqueAckedBefore = fakeSrv.UniqueAckedRowsForTable(meta.effectiveTable)
			uniqueAckedBytesBefore = fakeSrv.UniqueAckedBytesForTable(meta.effectiveTable)
			uniqueAckedFn = func() int64 {
				return fakeSrv.UniqueAckedRowsForTable(meta.effectiveTable)
			}
		}
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

	if faultSimEnabled {
		fakeSrv.SetPeriodicFaults(ctx, meta.effectiveTable, cfg.SimulateThrottleEvery, cfg.SimulateAckDelay)
	}

	startWall := time.Now()
	steadyStats := runCollectorWorkerPhase(ctx, cfg, signal, cfg.Duration, cfg.maxBatches, prebuilt, makeBatch, tracesClient, logsClient, metricsClient, doneCh)
	phaseEnd := time.Now()
	afterMetrics, idleBatchWait, drainErr := drainCollectorPipelineWithUnique(
		ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID,
		baseMetrics, steadyStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag,
		uniqueAckedBefore, uniqueAckedFn, meta.batchProcessorTimeout, meta.batchProcessorSendSize,
	)
	phaseElapsed := phaseEnd.Sub(startWall)
	totalElapsed := time.Since(startWall)
	elapsed := max(phaseElapsed, totalElapsed-idleBatchWait)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}

	var (
		fakeCommittedRowsAtCutoff    int64
		fakeAckedBytesAtCutoff       int64
		fakeUniqueAckedAtCutoff      int64
		fakeUniqueAckedBytesAtCutoff int64
	)
	if fakeSrv != nil {
		fakeCommittedRowsAtCutoff = fakeSrv.AckedRowsForTable(meta.effectiveTable)
		fakeAckedBytesAtCutoff = fakeSrv.AckedBytesForTable(meta.effectiveTable)
		if faultSimEnabled {
			fakeUniqueAckedAtCutoff = fakeSrv.UniqueAckedRowsForTable(meta.effectiveTable)
			fakeUniqueAckedBytesAtCutoff = fakeSrv.UniqueAckedBytesForTable(meta.effectiveTable)
		}
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

	if faultSimEnabled && cfg.SimulateThrottleEvery > 0 && steadyStats.recordsSubmitted > 0 {
		if (fakeSrv.ThrottlesInjectedForTable(meta.effectiveTable) - fakeThrottlesBefore) == 0 {
			_ = conn.Close()
			terminateCollector()
			throttleErr := fmt.Errorf(
				"-simulate-throttle-every=%d never fired on destination table %q",
				cfg.SimulateThrottleEvery, meta.effectiveTable,
			)
			return SignalResult{}, errors.Join(steadyStats.firstErr, throttleErr), throttleErr
		}
	}

	var (
		incompleteDrain bool
		drainWarning    string
	)
	if drainErr != nil {
		incompleteDrain = true
		drainWarning = drainErr.Error()
		steadyStats.batchesFailed = max(int64(1), steadyStats.batchesFailed)
		if steadyStats.firstErr == nil {
			steadyStats.firstErr = drainErr
		}
	}

	_ = conn.Close()

	var shutdownErr error
	childDone, shutdownErr = finalizeCollectorShutdown(cmd.Process, doneCh, &cmdWaitErr, ctx.Err(), diag)
	if shutdownErr != nil {
		return SignalResult{}, steadyStats.firstErr, shutdownErr
	}

	cpuUnavailable := !cpuBeforeOK || !cpuAfterOK
	var cpuDeltaSec float64
	if !cpuUnavailable {
		cpuDeltaSec = max(0.0, cpuAfterDrainSec-cpuBeforeSec)
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

	ackedRows := telem.AcknowledgedRows
	attemptedProtoBytes := telem.AppendBytesTotal
	var committedRows int64
	if fakeSrv != nil {
		committedRows = max(int64(0), fakeCommittedRowsAtCutoff-fakeCommittedRowsBefore)
		fakeAckedBytes := max(int64(0), fakeAckedBytesAtCutoff-ackedBytesBefore)
		if attemptedProtoBytes == 0 {
			attemptedProtoBytes = fakeAckedBytes
			telem.AppendBytesTotal = fakeAckedBytes
		}
	}

	var (
		deliveredRows             int64
		replayedRows              int64
		uniqueDeliveryVerified    bool
		bytesPerRowUnavailable    bool
		bytesPerRow               float64
		attemptedBytesPerAckedRow float64
	)
	if ackedRows > 0 {
		attemptedBytesPerAckedRow = float64(attemptedProtoBytes) / float64(ackedRows)
	}

	if faultSimEnabled {
		deliveredRows = max(int64(0), fakeUniqueAckedAtCutoff-uniqueAckedBefore)
		replayedRows = max(int64(0), committedRows-deliveredRows)
		uniqueDeliveryVerified = true
		deliveredBytes := max(int64(0), fakeUniqueAckedBytesAtCutoff-uniqueAckedBytesBefore)
		if deliveredRows > 0 {
			bytesPerRow = float64(deliveredBytes) / float64(deliveredRows)
		}
	} else {
		deliveredRows = min(ackedRows, steadyStats.recordsSubmitted)
		switch {
		case fakeSrv != nil:
			replayedRows = max(int64(0), max(committedRows, ackedRows)-steadyStats.recordsSubmitted)
			fakeAckedBytes := max(int64(0), fakeAckedBytesAtCutoff-ackedBytesBefore)
			if committedRows > 0 {
				bytesPerRow = float64(fakeAckedBytes) / float64(committedRows)
			} else if ackedRows > 0 {
				bytesPerRow = float64(fakeAckedBytes) / float64(ackedRows)
			}
		default:
			replayedRows = max(int64(0), ackedRows-steadyStats.recordsSubmitted)
			if telem.Retries > 0 || deltaSendFailed > 0 || telem.RejectedRows > 0 || telem.QuarantinedRows > 0 ||
				incompleteDrain || replayedRows > 0 || (steadyStats.recordsSubmitted > 0 && ackedRows < steadyStats.recordsSubmitted) {
				bytesPerRowUnavailable = true
			} else if ackedRows > 0 {
				bytesPerRow = float64(attemptedProtoBytes) / float64(ackedRows)
			}
		}
	}
	telem.ReplayedRows = replayedRows

	elapsedSec := elapsed.Seconds()
	rowsPerSec := float64(deliveredRows) / elapsedSec
	var wireMBPerSec float64
	if !bytesPerRowUnavailable {
		wireMBPerSec = (bytesPerRow * float64(deliveredRows)) / (1024.0 * 1024.0) / elapsedSec
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

	var cpuCoresUsed, cpuCoresPer10k float64
	if !cpuUnavailable {
		cpuCoresUsed = cpuDeltaSec / elapsedSec
		if rowsPerSec > 0 {
			cpuCoresPer10k = cpuCoresUsed / (rowsPerSec / 10000.0)
		}
	}

	return SignalResult{
		Signal:                    signal,
		Mode:                      cfg.Mode,
		WorkloadProfile:           cfg.WorkloadProfile,
		StreamPoolSize:            meta.effectiveStreamPoolSize,
		ConnectionPoolSize:        meta.effectiveConnectionPoolSize,
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
		DeliveredRows:             deliveredRows,
		UniqueDeliveryVerified:    uniqueDeliveryVerified,
		AchievedRowsPerSec:        round2(rowsPerSec),
		WireMBPerSec:              round2(wireMBPerSec),
		BytesPerRow:               round2(bytesPerRow),
		BytesPerRowUnavailable:    bytesPerRowUnavailable,
		AttemptedBytesPerAckedRow: round2(attemptedBytesPerAckedRow),
		IncompleteDrain:           incompleteDrain,
		DrainWarning:              drainWarning,
		Latency:                   computeLatencySummary(steadyStats.latenciesMs),
		Memory: MemorySummary{
			HeapAllocBytes:      afterMetrics.HeapAllocBytes,
			HeapAllocMB:         round2(float64(afterMetrics.HeapAllocBytes) / (1024.0 * 1024.0)),
			SysMB:               round2(lastRSSMB),
			PeakRSSMB:           round2(peakRSSMB),
			PeakRSSUnavailable:  !memSampledOK,
			CPUUnavailable:      cpuUnavailable,
			CPUSeconds:          round2(cpuDeltaSec),
			CPUCoresUsed:        round2(cpuCoresUsed),
			CPUCoresPer10kRowsS: round2(cpuCoresPer10k),
		},
		Telemetry:  telem,
		ByteLayers: byteLayers,
	}, steadyStats.firstErr, nil
}
