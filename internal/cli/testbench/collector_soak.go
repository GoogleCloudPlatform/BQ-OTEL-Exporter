// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"bytes"
	"cmp"
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
	"regexp"
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
	"go.opentelemetry.io/collector/pdata/pcommon"
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
	collectorStartupTimeout       = 20 * time.Second
	collectorShutdownTimeout      = 30 * time.Second
	collectorMaxDiagBytes         = 64 * 1024
	linuxUserHZ                   = 100.0
	maxCollectorEnvExpansionDepth = 16
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
	hasHealthCheck                  bool
	healthCheckPath                 string
	activePipelineKey               string
	activeExporterID                string
	effectiveTable                  string
	effectiveEndpoint               bigqueryexporter.EndpointConfig
	effectiveCredentials            bigqueryexporter.CredentialsConfig
	effectiveRedaction              bool
	effectiveBackpressure           bool
	effectiveStreamPoolSize         int
	effectiveConnectionPoolSize     int
	effectiveMaxInflightRequests    int
	effectiveMaxRequestBytes        int
	extraOTLPAddrs                  []string
	batchProcessorTimeout           time.Duration
	batchProcessorSendSize          int
	queueBatchFlushTimeout          time.Duration
	queueBatchMinItems              int
	effectiveLogsLogNameAttr        string
	effectiveLogsInsertIDAttr       string
	effectiveLogsSynthesizeInsertID bool
	pipelineAltersIdentityKeys      bool
}

type collectorBatchWaitConfig struct {
	batchProcTimeout       time.Duration
	batchProcSendSize      int
	queueBatchFlushTimeout time.Duration
	queueBatchMinItems     int
}

type collectorMetricsSample struct {
	Telemetry                TelemetrySnapshot
	QueueSize                int64
	InflightRequests         int64
	Sent                     int64
	HasSentMetric            bool
	HasAppendBytesMetric     bool
	SendFailed               int64
	EnqueueFailed            int64
	RejectedRequestPermanent int64
	RejectedRowError         int64
	RejectedOffloadPermanent int64
	HeapAllocBytes           uint64
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
	return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (got %T)", pathDesc, raw)
}

func optionalInlineYAMLSubmap(parent map[string]any, key, pathDesc string) (map[string]any, error) {
	raw, exists := parent[key]
	if !exists || raw == nil {
		return nil, nil
	}
	existing, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("collector config %s must be an inline YAML map rather than a non-map or external reference (got %T)", pathDesc, raw)
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

func collectorEnvLookup(maxProcs int) func(string) (string, bool) {
	return func(key string) (string, bool) {
		if maxProcs > 0 && (key == "GOMAXPROCS" || (runtime.GOOS == "windows" && strings.EqualFold(key, "GOMAXPROCS"))) {
			return strconv.Itoa(maxProcs), true
		}
		return os.LookupEnv(key)
	}
}

func resolveCollectorEnvStringWithLookup(raw string, lookupEnv func(string) (string, bool)) (string, error) {
	return resolveCollectorEnvStringWithOptions(raw, lookupEnv, false)
}

func resolveCollectorEnvStringWithOptions(raw string, lookupEnv func(string) (string, bool), redactValues bool) (string, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	return expandCollectorEnvSegment(raw, lookupEnv, redactValues, 0, nil)
}

func expandCollectorEnvSegment(
	raw string,
	lookupEnv func(string) (string, bool),
	redactValues bool,
	depth int,
	activeVars []string,
) (string, error) {
	if depth > maxCollectorEnvExpansionDepth {
		if redactValues {
			return "", errors.New("too many recursive expansions")
		}
		return "", fmt.Errorf("too many recursive expansions in %q", raw)
	}
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
			if redactValues {
				return "", errors.New("unclosed ${...} reference")
			}
			return "", fmt.Errorf("unclosed ${...} reference in %q", raw)
		}
		expr := raw[i+2 : i+2+closeRel]
		token := "${" + expr + "}"
		if expr == "" {
			if redactValues {
				return "", errors.New("empty ${} reference")
			}
			return "", fmt.Errorf("empty ${} reference in %q", raw)
		}
		if strings.Contains(expr, "${") {
			if redactValues {
				return "", errors.New("nested ${ reference is not supported")
			}
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
				if redactValues {
					return "", errors.New("empty provider scheme in ${...} reference")
				}
				return "", fmt.Errorf("empty provider scheme in %q", token)
			}
			if scheme != "env" {
				if redactValues {
					return "", errors.New("unsupported collector config provider in ${...} reference (only env is supported)")
				}
				return "", fmt.Errorf("unsupported collector config provider %q in %q (only env is supported)", scheme, token)
			}
			hasEnvScheme = true
			varName = rest
		} else {
			varName = beforeDefault
		}
		if hasDefault && !hasEnvScheme {
			if redactValues {
				return "", errors.New("default syntax :- requires explicit env: scheme")
			}
			return "", fmt.Errorf("default syntax :- requires explicit env: scheme in %q", token)
		}
		if varName == "" {
			if redactValues {
				return "", errors.New("empty environment variable name")
			}
			return "", fmt.Errorf("empty environment variable name in %q", token)
		}
		if strings.ContainsRune(varName, ':') {
			if redactValues {
				return "", errors.New("invalid ':' in environment variable name")
			}
			return "", fmt.Errorf("invalid ':' in environment variable name %q in %q", varName, token)
		}
		if !isValidEnvVarName(varName) {
			if redactValues {
				return "", errors.New("invalid environment variable name")
			}
			return "", fmt.Errorf("invalid environment variable name %q in %q", varName, token)
		}
		if slices.Contains(activeVars, varName) {
			if redactValues {
				return "", errors.New("too many recursive expansions")
			}
			return "", fmt.Errorf("too many recursive expansions in %q (cycle at %q)", token, varName)
		}
		val, ok := lookupEnv(varName)
		if hasDefault && !ok {
			expandedDefault, err := expandCollectorEnvSegment(defaultVal, lookupEnv, redactValues, depth+1, activeVars)
			if err != nil {
				return "", err
			}
			out.WriteString(expandedDefault)
		} else if ok {
			nextActive := make([]string, len(activeVars)+1)
			copy(nextActive, activeVars)
			nextActive[len(activeVars)] = varName
			expandedVal, err := expandCollectorEnvSegment(val, lookupEnv, redactValues, depth+1, nextActive)
			if err != nil {
				return "", err
			}
			out.WriteString(expandedVal)
		}
		i += 2 + closeRel + 1
	}
	return out.String(), nil
}

func resolveCollectorTableRefWithLookup(raw string, lookupEnv func(string) (string, bool)) (string, error) {
	return resolveCollectorEnvStringWithLookup(raw, lookupEnv)
}

func resolveCollectorYAMLBoolWithLookup(raw any, fieldPath string, lookupEnv func(string) (string, bool)) (bool, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
	if raw == nil {
		return false, nil
	}
	switch v := raw.(type) {
	case bool:
		return v, nil
	case string:
		resolved, err := resolveCollectorEnvStringWithLookup(v, lookupEnv)
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

func preserveResolvedCollectorStringPath(pathDesc string) bool {
	for _, suffix := range []string{
		".credentials.file",
		".credentials.json",
		".credentials.impersonate_service_account",
		".credentials.quota_project",
		".credentials.universe_domain",
	} {
		if strings.HasSuffix(pathDesc, suffix) {
			return true
		}
	}
	if idx := strings.Index(pathDesc, ".credentials.impersonate_delegates["); idx >= 0 && strings.HasSuffix(pathDesc, "]") {
		return true
	}
	return false
}

func resolveCollectorEnvYAMLValueWithLookup(raw any, pathDesc string, lookupEnv func(string) (string, bool)) (any, error) {
	return resolveCollectorEnvYAMLValueWithOptions(raw, pathDesc, lookupEnv, false)
}

func resolveCollectorEnvYAMLValueWithOptions(raw any, pathDesc string, lookupEnv func(string) (string, bool), redactValues bool) (any, error) {
	if lookupEnv == nil {
		lookupEnv = os.LookupEnv
	}
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
			resolvedVal, err := resolveCollectorEnvYAMLValueWithOptions(val, childPath, lookupEnv, redactValues)
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
			resolvedVal, err := resolveCollectorEnvYAMLValueWithOptions(val, childPath, lookupEnv, redactValues)
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
		resolved, err := resolveCollectorEnvStringWithOptions(v, lookupEnv, redactValues)
		if err != nil {
			return nil, fmt.Errorf("resolving %s: %w", pathDesc, err)
		}
		if preserveResolvedCollectorStringPath(pathDesc) {
			return resolved, nil
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

func decodeCollectorCredentialsMap(
	exporterID, exporterPath string,
	resolvedCredMap map[string]any,
	dst *bigqueryexporter.CredentialsConfig,
) error {
	keys := make([]string, 0, len(resolvedCredMap))
	for k := range resolvedCredMap {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		val := resolvedCredMap[k]
		if val == nil {
			continue
		}
		switch k {
		case "file", "json", "impersonate_service_account", "quota_project", "universe_domain":
			if _, ok := val.(string); !ok {
				return fmt.Errorf("decoding collector exporter %q credentials config: %s.credentials.%s must be a string, got %T", exporterID, exporterPath, k, val)
			}
		case "impersonate_delegates":
			if _, err := extractYAMLStringSlice(val); err != nil {
				return fmt.Errorf("decoding collector exporter %q credentials config: %s.credentials.%s: %w", exporterID, exporterPath, k, err)
			}
		default:
			return fmt.Errorf("decoding collector exporter %q credentials config: unsupported key %q in %s.credentials", exporterID, k, exporterPath)
		}
	}
	if err := confmap.NewFromStringMap(resolvedCredMap).Unmarshal(dst); err != nil {
		return fmt.Errorf("decoding collector exporter %q credentials config: invalid %s.credentials configuration", exporterID, exporterPath)
	}
	return nil
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

func rewriteBigQueryExporterMapWithLookup(bq map[string]any, exporterID, signal string, cfg RunnerConfig, ep collectorEndpointOverride, meta *collectorRewriteMeta, lookupEnv func(string) (string, bool)) error {
	if lookupEnv == nil {
		lookupEnv = collectorEnvLookup(cfg.MaxProcs)
	}
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
		resolvedTable, resErr := resolveCollectorTableRefWithLookup(rawStr, lookupEnv)
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
		yamlBackpressure, err = resolveCollectorYAMLBoolWithLookup(bpMap["enabled"], exporterPath+".write.backpressure.enabled", lookupEnv)
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

	resolvedWriteAny, err := resolveCollectorEnvYAMLValueWithLookup(writeCfg, exporterPath+".write", lookupEnv)
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
	if err := validateCollectorWriteLimits(defaultExpCfg.Write); err != nil {
		return fmt.Errorf("validating collector exporter %q write config: %w", exporterID, err)
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
		yamlRedaction, err = resolveCollectorYAMLBoolWithLookup(redMap["enabled"], exporterPath+".redaction.enabled", lookupEnv)
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
		offEnabled, offBoolErr := resolveCollectorYAMLBoolWithLookup(offMap["enabled"], exporterPath+".offload.enabled", lookupEnv)
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
		if _, err := resolveCollectorYAMLBoolWithLookup(quarantineMap["enabled"], exporterPath+".quarantine.enabled", lookupEnv); err != nil {
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
		meta.effectiveEndpoint = bigqueryexporter.EndpointConfig{
			URL:                   ep.fakeGRPCURL,
			AdminURL:              ep.fakeRESTURL,
			Insecure:              true,
			WithoutAuthentication: true,
		}
		bq["auto_create"] = map[string]any{
			"dataset":         false,
			"tables":          false,
			"companion_views": false,
			"search_indexes":  false,
		}
	} else {
		epMap, epErr := optionalInlineYAMLSubmap(bq, "endpoint", exporterPath+".endpoint")
		if epErr != nil {
			return epErr
		}
		if epMap != nil {
			resolvedEPAny, resErr := resolveCollectorEnvYAMLValueWithLookup(epMap, exporterPath+".endpoint", lookupEnv)
			if resErr != nil {
				return resErr
			}
			resolvedEPMap, _ := resolvedEPAny.(map[string]any)
			if resolvedEPMap != nil {
				if err := confmap.NewFromStringMap(resolvedEPMap).Unmarshal(&defaultExpCfg.Endpoint); err != nil {
					return fmt.Errorf("decoding collector exporter %q endpoint config: %w", exporterID, err)
				}
			}
			meta.effectiveEndpoint = defaultExpCfg.Endpoint
		}
		credMap, credErr := optionalInlineYAMLSubmap(bq, "credentials", exporterPath+".credentials")
		if credErr != nil {
			return credErr
		}
		if credMap != nil {
			resolvedCredAny, resCredErr := resolveCollectorEnvYAMLValueWithOptions(credMap, exporterPath+".credentials", lookupEnv, true)
			if resCredErr != nil {
				return resCredErr
			}
			resolvedCredMap, _ := resolvedCredAny.(map[string]any)
			if resolvedCredMap != nil {
				if err := decodeCollectorCredentialsMap(exporterID, exporterPath, resolvedCredMap, &defaultExpCfg.Credentials); err != nil {
					return err
				}
			}
			meta.effectiveCredentials = defaultExpCfg.Credentials
		}
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

func validateCollectorWriteLimits(w bigqueryexporter.WriteConfig) error {
	if w.StreamPoolSize < 1 || w.StreamPoolSize > 16 {
		return fmt.Errorf("effective write.stream_pool_size %d must be between 1 and 16", w.StreamPoolSize)
	}
	if w.ConnectionPoolSize < 1 || w.ConnectionPoolSize > 16 {
		return fmt.Errorf("effective write.connection_pool_size %d must be between 1 and 16", w.ConnectionPoolSize)
	}
	if w.MaxInflightRequests < 1 || w.MaxInflightRequests > MaxBenchmarkInflightRequests {
		return fmt.Errorf("effective write.max_inflight_requests %d must be between 1 and %d", w.MaxInflightRequests, MaxBenchmarkInflightRequests)
	}
	if w.MaxRequestBytes <= 0 {
		return fmt.Errorf("effective write.max_request_bytes %d must be > 0", w.MaxRequestBytes)
	}
	return nil
}

func rejectConfmapDelimiterKeys(node any, path string) error {
	switch m := node.(type) {
	case map[string]any:
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			if strings.Contains(k, "::") {
				return fmt.Errorf("collector config key %q (at %s) contains unsupported confmap path delimiter \"::\"", k, childPath)
			}
			if err := rejectConfmapDelimiterKeys(m[k], childPath); err != nil {
				return err
			}
		}
	case map[any]any:
		type anyEntry struct {
			kStr string
			val  any
		}
		entries := make([]anyEntry, 0, len(m))
		for k, v := range m {
			entries = append(entries, anyEntry{kStr: fmt.Sprint(k), val: v})
		}
		slices.SortFunc(entries, func(a, b anyEntry) int {
			return strings.Compare(a.kStr, b.kStr)
		})
		for _, e := range entries {
			childPath := e.kStr
			if path != "" {
				childPath = path + "." + e.kStr
			}
			if strings.Contains(e.kStr, "::") {
				return fmt.Errorf("collector config key %q (at %s) contains unsupported confmap path delimiter \"::\"", e.kStr, childPath)
			}
			if err := rejectConfmapDelimiterKeys(e.val, childPath); err != nil {
				return err
			}
		}
	case []any:
		for i, elem := range m {
			elemPath := fmt.Sprintf("%s[%d]", path, i)
			if err := rejectConfmapDelimiterKeys(elem, elemPath); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteCollectorLoopbackConfig(rawYAML []byte, cfg RunnerConfig, signal string, ep collectorEndpointOverride) ([]byte, collectorRewriteMeta, error) {
	var meta collectorRewriteMeta
	lookupEnv := collectorEnvLookup(cfg.MaxProcs)
	var doc map[string]any
	if err := yaml.Unmarshal(rawYAML, &doc); err != nil {
		return nil, meta, fmt.Errorf("parsing collector YAML config: %w", err)
	}
	if len(doc) == 0 {
		return nil, meta, errors.New("collector YAML config is empty")
	}
	if err := rejectConfmapDelimiterKeys(doc, ""); err != nil {
		return nil, meta, err
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
		return nil, meta, fmt.Errorf("collector config defines no %q pipeline (service.pipelines is empty)", signal)
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
	if len(procIDs) > 0 {
		if procMap == nil {
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined processor %q (processors section is missing)", meta.activePipelineKey, procIDs[0])
		}
		for _, id := range procIDs {
			if _, exists := procMap[id]; !exists {
				defined := make([]string, 0, len(procMap))
				for k := range procMap {
					defined = append(defined, k)
				}
				slices.Sort(defined)
				return nil, meta, fmt.Errorf("collector pipeline %q references undefined processor %q (defined processors: %v)", meta.activePipelineKey, id, defined)
			}
		}
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
					resolvedT, rErr := resolveCollectorEnvStringWithLookup(tStr, lookupEnv)
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
					resolvedS, rErr := resolveCollectorEnvStringWithLookup(sStr, lookupEnv)
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

	exportersMap, err := optionalInlineYAMLSubmap(doc, "exporters", "exporters")
	if err != nil {
		return nil, meta, err
	}
	if exportersMap == nil {
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (exporters section is missing)", meta.activePipelineKey, meta.activeExporterID)
	}
	if _, exists := exportersMap[meta.activeExporterID]; !exists {
		defined := make([]string, 0, len(exportersMap))
		for k := range exportersMap {
			defined = append(defined, k)
		}
		slices.Sort(defined)
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined exporter %q (defined exporters: %v)", meta.activePipelineKey, meta.activeExporterID, defined)
	}
	bq, err := ensureInlineYAMLSubmap(exportersMap, meta.activeExporterID, "exporters."+meta.activeExporterID)
	if err != nil {
		return nil, meta, err
	}
	if err := rewriteBigQueryExporterMapWithLookup(bq, meta.activeExporterID, signal, cfg, ep, &meta, lookupEnv); err != nil {
		return nil, meta, err
	}
	meta.effectiveLogsSynthesizeInsertID = true
	if defaultCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config); ok {
		meta.effectiveLogsSynthesizeInsertID = defaultCfg.Logs.SynthesizeInsertID
		if rawLogs, hasLogs := bq["logs"]; hasLogs && rawLogs != nil {
			logsMap, isMap := rawLogs.(map[string]any)
			if !isMap {
				return nil, meta, fmt.Errorf("collector exporter %q logs must be an inline YAML map, got %T", meta.activeExporterID, rawLogs)
			}
			resolvedLogsAny, resLogsErr := resolveCollectorEnvYAMLValueWithLookup(logsMap, "exporters."+meta.activeExporterID+".logs", lookupEnv)
			if resLogsErr != nil {
				return nil, meta, resLogsErr
			}
			if resolvedLogsMap, ok := resolvedLogsAny.(map[string]any); ok && resolvedLogsMap != nil {
				if err := confmap.NewFromStringMap(resolvedLogsMap).Unmarshal(&defaultCfg.Logs); err != nil {
					return nil, meta, fmt.Errorf("decoding collector exporter %q logs config: %w", meta.activeExporterID, err)
				}
				meta.effectiveLogsLogNameAttr = strings.TrimSpace(defaultCfg.Logs.LogNameAttribute)
				meta.effectiveLogsInsertIDAttr = strings.TrimSpace(defaultCfg.Logs.InsertIDAttribute)
				meta.effectiveLogsSynthesizeInsertID = defaultCfg.Logs.SynthesizeInsertID
			}
		}
	}
	meta.pipelineAltersIdentityKeys = collectorPipelineMayAlterIdentityKeys(
		signal, procIDs, procMap, meta.effectiveLogsLogNameAttr, meta.effectiveLogsInsertIDAttr,
	)

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
				resolvedStID, rErr := resolveCollectorEnvStringWithLookup(stID, lookupEnv)
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
		if _, err := optionalInlineYAMLSubmap(sqMap, "batch", "exporters."+meta.activeExporterID+".sending_queue.batch"); err != nil {
			return nil, meta, err
		}
		resolvedSQAny, resSQErr := resolveCollectorEnvYAMLValueWithLookup(sqMap, "exporters."+meta.activeExporterID+".sending_queue", lookupEnv)
		if resSQErr != nil {
			return nil, meta, resSQErr
		}
		sqExpCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
		if !ok {
			return nil, meta, errors.New("unexpected exporter config type")
		}
		if err := confmap.NewFromStringMap(map[string]any{"sending_queue": resolvedSQAny}).Unmarshal(sqExpCfg); err != nil {
			return nil, meta, fmt.Errorf("decoding collector exporter %q sending_queue config: %w", meta.activeExporterID, err)
		}
		if sqExpCfg.QueueSettings.HasValue() {
			q := sqExpCfg.QueueSettings.Get()
			if q != nil && q.Batch.HasValue() {
				qb := q.Batch.Get()
				if qb != nil && qb.MinSize > 0 && qb.FlushTimeout > 0 {
					meta.queueBatchFlushTimeout = qb.FlushTimeout
					effectiveSizer := qb.Sizer
					if strings.TrimSpace(effectiveSizer.String()) == "" {
						effectiveSizer = q.Sizer
					}
					if s := strings.ToLower(strings.TrimSpace(effectiveSizer.String())); s == "" || s == "items" {
						meta.queueBatchMinItems = int(min(qb.MinSize, int64(math.MaxInt)))
					} else {
						meta.queueBatchMinItems = 0
					}
				}
			}
		}
	}

	extMap, extErr := optionalInlineYAMLSubmap(doc, "extensions", "extensions")
	if extErr != nil {
		return nil, meta, extErr
	}
	if len(dedupExts) > 0 {
		if extMap == nil {
			return nil, meta, fmt.Errorf("collector service.extensions references undefined extension %q (extensions section is missing)", dedupExts[0])
		}
		healthCheckCount := 0
		for _, extID := range dedupExts {
			if _, exists := extMap[extID]; !exists {
				defined := make([]string, 0, len(extMap))
				for k := range extMap {
					defined = append(defined, k)
				}
				slices.Sort(defined)
				return nil, meta, fmt.Errorf("collector service.extensions references undefined extension %q (defined extensions: %v)", extID, defined)
			}
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
						resolvedPath, rErr := resolveCollectorEnvStringWithLookup(pStr, lookupEnv)
						if rErr != nil {
							return nil, meta, fmt.Errorf("resolving collector config extensions.%s.path: %w", extID, rErr)
						}
						pStr = resolvedPath
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
		return nil, meta, fmt.Errorf("collector pipeline %q must configure at least 1 otlp receiver", meta.activePipelineKey)
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

	receiversMap, err := optionalInlineYAMLSubmap(doc, "receivers", "receivers")
	if err != nil {
		return nil, meta, err
	}
	if receiversMap == nil {
		return nil, meta, fmt.Errorf("collector pipeline %q references undefined receiver %q (receivers section is missing)", meta.activePipelineKey, dedupReceivers[0])
	}
	for _, recvID := range dedupReceivers {
		if _, exists := receiversMap[recvID]; !exists {
			defined := make([]string, 0, len(receiversMap))
			for k := range receiversMap {
				defined = append(defined, k)
			}
			slices.Sort(defined)
			return nil, meta, fmt.Errorf("collector pipeline %q references undefined receiver %q (defined receivers: %v)", meta.activePipelineKey, recvID, defined)
		}
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
		if rawTLS, hasTLS := grpcCfg["tls"]; hasTLS && rawTLS != nil {
			return nil, meta, fmt.Errorf("collector receiver %q configures protocols.grpc.tls, which is not supported by loopback plaintext mode", recvID)
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
	var (
		existingMetrics map[string]any
		existingLogs    map[string]any
	)
	if existingTelem != nil {
		if existingMetrics, err = optionalInlineYAMLSubmap(existingTelem, "metrics", "service.telemetry.metrics"); err != nil {
			return nil, meta, err
		}
		if existingLogs, err = optionalInlineYAMLSubmap(existingTelem, "logs", "service.telemetry.logs"); err != nil {
			return nil, meta, err
		}
		if _, err = optionalInlineYAMLSubmap(existingTelem, "traces", "service.telemetry.traces"); err != nil {
			return nil, meta, err
		}
	}
	if ep.useBQFake {
		telem, tErr := ensureInlineYAMLSubmap(svc, "telemetry", "service.telemetry")
		if tErr != nil {
			return nil, meta, tErr
		}
		delete(telem, "traces")
		sanitizedLogs := map[string]any{
			"output_paths":       []any{"stderr"},
			"error_output_paths": []any{"stderr"},
		}
		if existingLogs != nil {
			for _, scalarKey := range []string{"level", "encoding"} {
				if rawVal, ok := existingLogs[scalarKey]; ok && rawVal != nil {
					s, ok := rawVal.(string)
					if !ok {
						return nil, meta, fmt.Errorf("collector service.telemetry.logs.%s must be a string, got %T", scalarKey, rawVal)
					}
					if _, rErr := resolveCollectorEnvStringWithOptions(s, lookupEnv, true); rErr != nil {
						return nil, meta, fmt.Errorf("resolving collector service.telemetry.logs.%s: %w", scalarKey, rErr)
					}
					sanitizedLogs[scalarKey] = s
				}
			}
		}
		telem["logs"] = sanitizedLogs
		if existingMetrics != nil {
			delete(existingMetrics, "readers")
			delete(existingMetrics, "address")
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

var ottlDeleteMatchingKeysStmtPattern = regexp.MustCompile(`^\s*delete_matching_keys\(\s*attributes\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*$`)

// collectorPipelineMayAlterIdentityKeys reports whether any configured processor
// in the active pipeline can drop rows or mutate dedup-identity fields
// before the exporter receives them. Trimming processors that strictly delete
// non-identity attributes keep upstream SubmittedKeySet reconciliation enabled.
func collectorPipelineMayAlterIdentityKeys(
	signal string,
	procIDs []string,
	procMap map[string]any,
	logNameAttr, insertIDAttr string,
) bool {
	if len(procIDs) == 0 {
		return false
	}
	recordIdentityAttrs := make([]string, 0, 1+len(benchLogNameAttrs)+len(benchInsertIDAttrs)+2)
	recordIdentityAttrs = append(recordIdentityAttrs, "service.name")
	recordIdentityAttrs = append(recordIdentityAttrs, benchLogNameAttrs...)
	recordIdentityAttrs = append(recordIdentityAttrs, benchInsertIDAttrs...)
	if logNameAttr != "" {
		recordIdentityAttrs = append(recordIdentityAttrs, logNameAttr)
	}
	if insertIDAttr != "" {
		recordIdentityAttrs = append(recordIdentityAttrs, insertIDAttr)
	}

	actionTouchesIdentity := func(action map[string]any, identityAttrs []string) bool {
		actStr, _ := action["action"].(string)
		if !strings.EqualFold(strings.TrimSpace(actStr), "delete") {
			return true
		}
		if rawKey, hasKey := action["key"]; hasKey && rawKey != nil {
			keyStr, ok := rawKey.(string)
			if !ok {
				return true
			}
			for _, idKey := range identityAttrs {
				if keyStr == idKey {
					return true
				}
			}
		}
		if rawPat, hasPat := action["pattern"]; hasPat && rawPat != nil {
			patStr, ok := rawPat.(string)
			if !ok {
				return true
			}
			re, err := regexp.Compile(patStr)
			if err != nil {
				return true
			}
			for _, idKey := range identityAttrs {
				if re.MatchString(idKey) {
					return true
				}
			}
		}
		for k := range action {
			if k != "action" && k != "key" && k != "pattern" {
				return true
			}
		}
		return false
	}

	for _, id := range procIDs {
		switch {
		case id == "memory_limiter" || strings.HasPrefix(id, "memory_limiter/"):
			continue
		case id == "batch" || strings.HasPrefix(id, "batch/"):
			continue
		case id == "resource" || strings.HasPrefix(id, "resource/"):
			cfgMap, _ := procMap[id].(map[string]any)
			if cfgMap == nil {
				continue
			}
			for k := range cfgMap {
				if k != "attributes" {
					return true
				}
			}
			rawActions, _ := cfgMap["attributes"].([]any)
			for _, item := range rawActions {
				actMap, ok := item.(map[string]any)
				if !ok || actionTouchesIdentity(actMap, []string{"service.name"}) {
					return true
				}
			}
		case id == "attributes" || strings.HasPrefix(id, "attributes/"):
			cfgMap, _ := procMap[id].(map[string]any)
			if cfgMap == nil {
				continue
			}
			for k := range cfgMap {
				if k != "actions" {
					return true
				}
			}
			rawActions, _ := cfgMap["actions"].([]any)
			for _, item := range rawActions {
				actMap, ok := item.(map[string]any)
				if !ok || actionTouchesIdentity(actMap, recordIdentityAttrs) {
					return true
				}
			}
		case id == "transform" || strings.HasPrefix(id, "transform/"):
			if signal != "logs" {
				return true
			}
			cfgMap, _ := procMap[id].(map[string]any)
			if cfgMap == nil {
				continue
			}
			for k := range cfgMap {
				if k != "error_mode" && k != "log_statements" {
					return true
				}
			}
			rawGroups, _ := cfgMap["log_statements"].([]any)
			for _, g := range rawGroups {
				gMap, ok := g.(map[string]any)
				if !ok {
					return true
				}
				ctxStr, _ := gMap["context"].(string)
				var scopeIdentity []string
				switch strings.TrimSpace(ctxStr) {
				case "resource":
					scopeIdentity = []string{"service.name"}
				case "log":
					scopeIdentity = recordIdentityAttrs
				default:
					return true
				}
				for gk := range gMap {
					if gk != "context" && gk != "statements" && gk != "conditions" && gk != "error_mode" {
						return true
					}
				}
				if rawConds, hasConds := gMap["conditions"]; hasConds && rawConds != nil {
					if condSlice, ok := rawConds.([]any); !ok || len(condSlice) > 0 {
						return true
					}
				}
				rawStmts, _ := gMap["statements"].([]any)
				for _, s := range rawStmts {
					stmtStr, ok := s.(string)
					if !ok {
						return true
					}
					m := ottlDeleteMatchingKeysStmtPattern.FindStringSubmatch(stmtStr)
					if len(m) != 2 {
						return true
					}
					pat, err := strconv.Unquote(m[1])
					if err != nil {
						return true
					}
					re, err := regexp.Compile(pat)
					if err != nil {
						return true
					}
					for _, idKey := range scopeIdentity {
						if re.MatchString(idKey) {
							return true
						}
					}
				}
			}
		default:
			return true
		}
	}
	return false
}

func validateCollectorPreflightConfig(cfg RunnerConfig, signal string) error {
	_, err := validateCollectorPreflightConfigWithMeta(cfg, signal)
	return err
}

func validateCollectorPreflightConfigWithMeta(cfg RunnerConfig, signal string) (collectorRewriteMeta, error) {
	var emptyMeta collectorRewriteMeta
	if strings.TrimSpace(cfg.CollectorBin) != "" {
		if _, err := resolveCollectorBinaryPath(cfg.CollectorBin); err != nil {
			return emptyMeta, err
		}
	}
	resolvedCfgPath := resolveCollectorConfigPath(cfg.CollectorConfig)
	rawYAML, err := os.ReadFile(resolvedCfgPath)
	if err != nil {
		return emptyMeta, fmt.Errorf("reading collector config %q: %w", cfg.CollectorConfig, err)
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
		return emptyMeta, err
	}

	var doc map[string]any
	if err := yaml.Unmarshal(rewrittenYAML, &doc); err != nil {
		return emptyMeta, fmt.Errorf("parsing rewritten collector YAML config: %w", err)
	}
	exportersMap, ok := doc["exporters"].(map[string]any)
	if !ok {
		return emptyMeta, errors.New("rewritten collector config missing exporters map")
	}
	bqMap, ok := exportersMap[meta.activeExporterID].(map[string]any)
	if !ok {
		return emptyMeta, fmt.Errorf("rewritten collector exporter %q is not a map", meta.activeExporterID)
	}

	expCfg, ok := bigqueryexporter.NewFactory().CreateDefaultConfig().(*bigqueryexporter.Config)
	if !ok {
		return emptyMeta, errors.New("unexpected exporter config type")
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

	lookupEnv := collectorEnvLookup(cfg.MaxProcs)
	if writeMap, ok := bqMap["write"].(map[string]any); ok && writeMap != nil {
		resolvedWriteAny, resErr := resolveCollectorEnvYAMLValueWithLookup(writeMap, "exporters."+meta.activeExporterID+".write", lookupEnv)
		if resErr != nil {
			return emptyMeta, resErr
		}
		resolvedWriteMap, _ := resolvedWriteAny.(map[string]any)
		if resolvedWriteMap != nil {
			if err := confmap.NewFromStringMap(resolvedWriteMap).Unmarshal(&expCfg.Write); err != nil {
				return emptyMeta, fmt.Errorf("decoding collector exporter %q write config: %w", meta.activeExporterID, err)
			}
		}
	}
	if err := validateCollectorWriteLimits(expCfg.Write); err != nil {
		return emptyMeta, fmt.Errorf("validating collector exporter %q write config: %w", meta.activeExporterID, err)
	}
	if logsMap, ok := bqMap["logs"].(map[string]any); ok && logsMap != nil {
		resolvedLogsAny, resErr := resolveCollectorEnvYAMLValueWithLookup(logsMap, "exporters."+meta.activeExporterID+".logs", lookupEnv)
		if resErr != nil {
			return emptyMeta, resErr
		}
		if resolvedLogsMap, ok := resolvedLogsAny.(map[string]any); ok && resolvedLogsMap != nil {
			if err := confmap.NewFromStringMap(resolvedLogsMap).Unmarshal(&expCfg.Logs); err != nil {
				return emptyMeta, fmt.Errorf("decoding collector exporter %q logs config: %w", meta.activeExporterID, err)
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
		expCfg.Endpoint = meta.effectiveEndpoint
		expCfg.Credentials = meta.effectiveCredentials
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
		return emptyMeta, fmt.Errorf("validating exporter config: %w", err)
	}
	return meta, nil
}

func resolveCollectorBinaryPath(rawBin string) (string, error) {
	bin := strings.TrimSpace(rawBin)
	if bin == "" {
		return "", errors.New("collector binary path is empty")
	}
	hasSep := strings.ContainsRune(bin, os.PathSeparator) ||
		(os.PathSeparator != '/' && strings.ContainsRune(bin, '/')) ||
		filepath.VolumeName(bin) != ""
	var candidate string
	if hasSep {
		candidate = bin
	} else {
		lookedUp, err := exec.LookPath(bin)
		if err != nil {
			if errors.Is(err, exec.ErrDot) {
				return "", fmt.Errorf("collector binary %q resolved to current working directory; specify an explicit relative path (e.g. %q): %w", rawBin, "./"+bin, err)
			}
			return "", fmt.Errorf("looking up collector binary %q in PATH: %w", rawBin, err)
		}
		candidate = lookedUp
	}
	abs, err := filepath.Abs(candidate)
	if err != nil {
		return "", fmt.Errorf("resolving absolute path for collector binary %q: %w", rawBin, err)
	}
	binInfo, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("stat collector binary %q: %w", rawBin, err)
	}
	if binInfo.IsDir() {
		return "", fmt.Errorf("collector binary %q is a directory", rawBin)
	}
	return abs, nil
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

func cloneCollectorPreparedBatch(src collectorPreparedBatch) collectorPreparedBatch {
	out := collectorPreparedBatch{
		sourceBytes: src.sourceBytes,
		otlpBytes:   src.otlpBytes,
		recordCount: src.recordCount,
	}
	if src.logsReq != (plogotlp.ExportRequest{}) {
		dst := plog.NewLogs()
		src.logsReq.Logs().CopyTo(dst)
		out.logsReq = plogotlp.NewExportRequestFromLogs(dst)
	}
	if src.tracesReq != (ptraceotlp.ExportRequest{}) {
		dst := ptrace.NewTraces()
		src.tracesReq.Traces().CopyTo(dst)
		out.tracesReq = ptraceotlp.NewExportRequestFromTraces(dst)
	}
	if src.metricsReq != (pmetricotlp.ExportRequest{}) {
		dst := pmetric.NewMetrics()
		src.metricsReq.Metrics().CopyTo(dst)
		out.metricsReq = pmetricotlp.NewExportRequestFromMetrics(dst)
	}
	return out
}

func selectEarliestSliceKeepMask(tsNanos []int64, targetRows int) []bool {
	type slicePointRef struct {
		tsNano int64
		ord    int
	}
	refs := make([]slicePointRef, len(tsNanos))
	for i, ts := range tsNanos {
		refs[i] = slicePointRef{tsNano: ts, ord: i}
	}
	slices.SortFunc(refs, func(a, b slicePointRef) int {
		if c := cmp.Compare(a.tsNano, b.tsNano); c != 0 {
			return c
		}
		return cmp.Compare(a.ord, b.ord)
	})
	keep := make([]bool, len(tsNanos))
	for idx := 0; idx < len(refs) && idx < targetRows; idx++ {
		keep[refs[idx].ord] = true
	}
	return keep
}

func sliceCollectorPreparedBatch(src collectorPreparedBatch, signal string, targetRows int) (collectorPreparedBatch, error) {
	if targetRows <= 0 {
		return collectorPreparedBatch{}, fmt.Errorf("cannot slice collector %s batch to %d rows", signal, targetRows)
	}
	if int64(targetRows) >= src.recordCount {
		return cloneCollectorPreparedBatch(src), nil
	}
	out := cloneCollectorPreparedBatch(src)
	switch signal {
	case "traces":
		td := out.tracesReq.Traces()
		rss := td.ResourceSpans()
		var tsNanos []int64
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					tsNanos = append(tsNanos, spans.At(k).StartTimestamp().AsTime().UnixNano())
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				spans.RemoveIf(func(ptrace.Span) bool {
					keepThis := curOrd < len(keep) && keep[curOrd]
					curOrd++
					return !keepThis
				})
			}
			sss.RemoveIf(func(ss ptrace.ScopeSpans) bool {
				return ss.Spans().Len() == 0
			})
		}
		rss.RemoveIf(func(rs ptrace.ResourceSpans) bool {
			return rs.ScopeSpans().Len() == 0
		})
		out.sourceBytes = tracesSourceContentBytes(td)
		raw, err := out.tracesReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(td.SpanCount())
	case "logs":
		ld := out.logsReq.Logs()
		rls := ld.ResourceLogs()
		var tsNanos []int64
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					tsNanos = append(tsNanos, lrs.At(k).Timestamp().AsTime().UnixNano())
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				lrs.RemoveIf(func(plog.LogRecord) bool {
					keepThis := curOrd < len(keep) && keep[curOrd]
					curOrd++
					return !keepThis
				})
			}
			sls.RemoveIf(func(sl plog.ScopeLogs) bool {
				return sl.LogRecords().Len() == 0
			})
		}
		rls.RemoveIf(func(rl plog.ResourceLogs) bool {
			return rl.ScopeLogs().Len() == 0
		})
		out.sourceBytes = logsSourceContentBytes(ld)
		raw, err := out.logsReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(ld.LogRecordCount())
	case "metrics":
		md := out.metricsReq.Metrics()
		rms := md.ResourceMetrics()
		var tsNanos []int64
		collectPoint := func(ts pcommon.Timestamp) {
			tsNanos = append(tsNanos, ts.AsTime().UnixNano())
		}
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					m := ms.At(k)
					switch m.Type() {
					case pmetric.MetricTypeHistogram:
						dps := m.Histogram().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeGauge:
						dps := m.Gauge().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeSum:
						dps := m.Sum().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeSummary:
						dps := m.Summary().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					case pmetric.MetricTypeExponentialHistogram:
						dps := m.ExponentialHistogram().DataPoints()
						for l := 0; l < dps.Len(); l++ {
							collectPoint(dps.At(l).Timestamp())
						}
					}
				}
			}
		}
		keep := selectEarliestSliceKeepMask(tsNanos, targetRows)
		curOrd := 0
		nextKept := func() bool {
			keepThis := curOrd < len(keep) && keep[curOrd]
			curOrd++
			return keepThis
		}
		for i := 0; i < rms.Len(); i++ {
			sms := rms.At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				ms.RemoveIf(func(m pmetric.Metric) bool {
					var remaining int
					switch m.Type() {
					case pmetric.MetricTypeHistogram:
						dps := m.Histogram().DataPoints()
						dps.RemoveIf(func(pmetric.HistogramDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeGauge:
						dps := m.Gauge().DataPoints()
						dps.RemoveIf(func(pmetric.NumberDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeSum:
						dps := m.Sum().DataPoints()
						dps.RemoveIf(func(pmetric.NumberDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeSummary:
						dps := m.Summary().DataPoints()
						dps.RemoveIf(func(pmetric.SummaryDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					case pmetric.MetricTypeExponentialHistogram:
						dps := m.ExponentialHistogram().DataPoints()
						dps.RemoveIf(func(pmetric.ExponentialHistogramDataPoint) bool {
							return !nextKept()
						})
						remaining = dps.Len()
					}
					return remaining == 0
				})
			}
			sms.RemoveIf(func(sm pmetric.ScopeMetrics) bool {
				return sm.Metrics().Len() == 0
			})
		}
		rms.RemoveIf(func(rm pmetric.ResourceMetrics) bool {
			return rm.ScopeMetrics().Len() == 0
		})
		out.sourceBytes = metricsSourceContentBytes(md)
		raw, err := out.metricsReq.MarshalProto()
		if err != nil {
			return collectorPreparedBatch{}, err
		}
		out.otlpBytes = int64(len(raw))
		out.recordCount = int64(md.DataPointCount())
	default:
		return collectorPreparedBatch{}, fmt.Errorf("unsupported signal %q", signal)
	}
	return out, nil
}

func stampCollectorPreparedBatchIdentity(signal string, b collectorPreparedBatch, baseTime time.Time, startSeq uint64, upstreamInsertID bool) {
	switch signal {
	case "logs":
		if b.logsReq != (plogotlp.ExportRequest{}) {
			stampFreshLogsIdentity(b.logsReq.Logs(), baseTime, startSeq, upstreamInsertID)
		}
	case "traces":
		if b.tracesReq != (ptraceotlp.ExportRequest{}) {
			stampFreshTracesIdentity(b.tracesReq.Traces(), baseTime, startSeq)
		}
	case "metrics":
		if b.metricsReq != (pmetricotlp.ExportRequest{}) {
			stampFreshMetricsIdentity(b.metricsReq.Metrics(), baseTime, startSeq)
		}
	}
}

func stampCollectorPreparedBatchTreeEpoch(
	signal string,
	b collectorPreparedBatch,
	baseTime time.Time,
	treeStride, treeDelta uint64,
	fallbackSeq *atomic.Uint64,
	upstreamInsertID bool,
) {
	switch signal {
	case "logs":
		if b.logsReq != (plogotlp.ExportRequest{}) {
			stampLogsTreeEpoch(b.logsReq.Logs(), baseTime, treeStride, treeDelta, fallbackSeq, upstreamInsertID)
		}
	case "traces":
		if b.tracesReq != (ptraceotlp.ExportRequest{}) {
			stampTracesTreeEpoch(b.tracesReq.Traces(), baseTime, treeStride, treeDelta, fallbackSeq)
		}
	case "metrics":
		if b.metricsReq != (pmetricotlp.ExportRequest{}) {
			stampMetricsTreeEpoch(b.metricsReq.Metrics(), baseTime, treeStride, treeDelta, fallbackSeq)
		}
	}
}

func dialCollectorOTLPClient(otlpAddr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		otlpAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(math.MaxInt32)),
	)
}

func newCollectorBatchBuilder(cfg RunnerConfig, signal string) (func(int) (collectorPreparedBatch, error), error) {
	return newCollectorBatchBuilderWithSeed(cfg, signal, 0)
}

func newCollectorBatchBuilderWithSeed(cfg RunnerConfig, signal string, seed uint64) (func(int) (collectorPreparedBatch, error), error) {
	gen := NewGenerator(GeneratorConfig{
		Seed:             seed,
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
			if cfg.UpstreamInsertID && cfg.WorkloadProfile != WorkloadProfileAccessLogs {
				populateLogsUpstreamInsertIDPlaceholder(ld)
			}
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
		k, _, _ := strings.Cut(kv, "=")
		if runtime.GOOS == "windows" {
			if strings.EqualFold(k, "GOMAXPROCS") {
				continue
			}
		} else if k == "GOMAXPROCS" {
			continue
		}
		out = append(out, kv)
	}
	out = append(out, fmt.Sprintf("GOMAXPROCS=%d", maxProcs))
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

func exporterMetricSignalLabel(signal string) string {
	if signal == "traces" {
		return schema.SignalSpans
	}
	return signal
}

func exporterHelperSignalSuffix(signal string) string {
	switch signal {
	case "traces":
		return "spans"
	case "logs":
		return "log_records"
	case "metrics":
		return "metric_points"
	default:
		return ""
	}
}

func matchesSignalLabel(labels map[string]string, signal string) bool {
	if len(labels) == 0 {
		return true
	}
	sig := labels["signal"]
	return sig == "" || sig == exporterMetricSignalLabel(signal)
}

func matchesExporterLabel(labels map[string]string, activeExporterID string) bool {
	exp := labels["exporter"]
	return exp == "" || (activeExporterID != "" && exp == activeExporterID) || (activeExporterID == "" && isBigQueryComponentID(exp))
}

func parseCollectorPrometheusMetrics(body, signal, exporterID string) collectorMetricsSample {
	var s collectorMetricsSample
	helperSuffix := exporterHelperSignalSuffix(signal)
	var sentMetricName, sendFailedMetricName, enqueueFailedMetricName string
	if helperSuffix != "" {
		sentMetricName = "otelcol_exporter_sent_" + helperSuffix
		sendFailedMetricName = "otelcol_exporter_send_failed_" + helperSuffix
		enqueueFailedMetricName = "otelcol_exporter_enqueue_failed_" + helperSuffix
	}
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
				n := int64(math.Round(val))
				s.Telemetry.RejectedRows += n
				switch labels["reason"] {
				case "request_permanent":
					s.RejectedRequestPermanent += n
				case "row_error":
					s.RejectedRowError += n
				case "offload_permanent":
					s.RejectedOffloadPermanent += n
				}
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
				s.HasAppendBytesMetric = true
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
		case sentMetricName:
			if sentMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.Sent += int64(math.Round(val))
				s.HasSentMetric = true
			}
		case sendFailedMetricName:
			if sendFailedMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.SendFailed += int64(math.Round(val))
			}
		case enqueueFailedMetricName:
			if enqueueFailedMetricName != "" && matchesExporterLabel(labels, exporterID) {
				s.EnqueueFailed += int64(math.Round(val))
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

func computeCollectorDrainAccounted(
	baseline, cur collectorMetricsSample,
	deltaTelem TelemetrySnapshot,
	deltaSendFailed int64,
	uniqueAckedBefore int64,
	uniqueAckedFn func() int64,
) int64 {
	deltaReqPerm := max(int64(0), cur.RejectedRequestPermanent-baseline.RejectedRequestPermanent)
	deltaSent := max(int64(0), cur.Sent-baseline.Sent)
	deltaEnqueueFailed := max(int64(0), cur.EnqueueFailed-baseline.EnqueueFailed)

	nonPermRejected := max(int64(0), deltaTelem.RejectedRows-deltaReqPerm)
	exporterAccounted := deltaTelem.AcknowledgedRows + nonPermRejected + deltaSendFailed + deltaEnqueueFailed
	if cur.HasSentMetric {
		helperAccounted := deltaSent + deltaSendFailed + deltaEnqueueFailed
		exporterAccounted = min(exporterAccounted, helperAccounted)
	}
	if uniqueAckedFn != nil {
		rawUnique := uniqueAckedFn()
		if rawUnique == math.MaxInt64 {
			return exporterAccounted
		}
		uniqueAccounted := max(int64(0), rawUnique-uniqueAckedBefore) + nonPermRejected + deltaSendFailed + deltaEnqueueFailed
		return min(exporterAccounted, uniqueAccounted)
	}
	return exporterAccounted
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
	return drainCollectorPipelineWithBatchWait(
		ctx, httpClient, metricsAddr, signal, exporterID,
		baseline, expectedSubmitted, timeout, doneCh, waitErr, diag,
		uniqueAckedBefore, uniqueAckedFn,
		collectorBatchWaitConfig{
			batchProcTimeout:  batchTimeout,
			batchProcSendSize: batchSendSize,
		},
	)
}

func drainCollectorPipelineWithBatchWait(
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
	waitCfg collectorBatchWaitConfig,
) (collectorMetricsSample, time.Duration, error) {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var (
		lastSample     collectorMetricsSample
		stableTicks    int
		lastScrape     error
		hasPrevSample  bool
		prevAccounted  int64
		lastTickTime   = time.Now()
		batchProcWait  time.Duration
		queueBatchWait time.Duration
		idleBatchWait  time.Duration
	)

	computeAccounted := func(cur collectorMetricsSample, deltaTelem TelemetrySnapshot, deltaSendFailed int64) int64 {
		return computeCollectorDrainAccounted(baseline, cur, deltaTelem, deltaSendFailed, uniqueAckedBefore, uniqueAckedFn)
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
			accounted := computeAccounted(cur, deltaTelem, deltaSendFailed)
			if !hasPrevSample {
				hasPrevSample = true
				prevAccounted = accounted
			} else {
				if tickDelta > 0 && cur.InflightRequests <= 0 && accounted == prevAccounted {
					pending := expectedSubmitted - accounted
					if pending > 0 {
						if waitCfg.batchProcTimeout > 0 && cur.QueueSize <= 0 &&
							(waitCfg.batchProcSendSize <= 0 || pending < int64(waitCfg.batchProcSendSize)) &&
							batchProcWait < waitCfg.batchProcTimeout {
							batchProcWait = min(waitCfg.batchProcTimeout, batchProcWait+tickDelta)
						} else if waitCfg.queueBatchFlushTimeout > 0 &&
							(waitCfg.queueBatchMinItems <= 0 || pending < int64(waitCfg.queueBatchMinItems)) &&
							queueBatchWait < waitCfg.queueBatchFlushTimeout {
							queueBatchWait = min(waitCfg.queueBatchFlushTimeout, queueBatchWait+tickDelta)
						}
					}
					idleBatchWait = min(waitCfg.batchProcTimeout+waitCfg.queueBatchFlushTimeout, batchProcWait+queueBatchWait)
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
			accounted := computeAccounted(lastSample, deltaTelem, deltaSendFailed)
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
	hasPartialReject      bool
	latenciesMs           []float64
	firstErr              error
}

type collectorWorkerBatch struct {
	batch collectorPreparedBatch
}

func buildCollectorWorkerBatchesFromPrebuilt(workers int, prebuilt []collectorPreparedBatch, ownWorkerZero bool) [][]collectorWorkerBatch {
	if workers <= 0 || len(prebuilt) == 0 {
		return nil
	}
	workerBatches := make([][]collectorWorkerBatch, workers)
	// Build higher-indexed worker clones before moving ownership of prebuilt into worker 0
	// so worker 0 avoids a duplicate copy and peaks at `workers` copies total.
	for w := workers - 1; w >= 0; w-- {
		workerBatches[w] = make([]collectorWorkerBatch, len(prebuilt))
		for i := range prebuilt {
			if ownWorkerZero && w == 0 {
				workerBatches[w][i] = collectorWorkerBatch{
					batch: prebuilt[i],
				}
				prebuilt[i] = collectorPreparedBatch{}
			} else {
				workerBatches[w][i] = collectorWorkerBatch{
					batch: cloneCollectorPreparedBatch(prebuilt[i]),
				}
			}
		}
	}
	return workerBatches
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
	return runCollectorWorkerPhaseWithSeq(
		ctx, cfg, signal, duration, maxBatches, prebuilt, makeBatch,
		tracesClient, logsClient, metricsClient, childDoneCh, new(atomic.Uint64),
	)
}

func runCollectorWorkerPhaseWithSeq(
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
	dispatchSeq *atomic.Uint64,
) collectorPhaseStats {
	seedCount := max(1, len(prebuilt))
	workerBatches := buildCollectorWorkerBatchesFromPrebuilt(cfg.Workers, prebuilt, false)
	treeStride := computePrebuiltTreeStride(seedCount, cfg.BatchSize)
	if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
		treeStride = computePrebuiltAccessLogSeqStride(seedCount, cfg.BatchSize)
	}
	return runCollectorWorkerPhasePrepared(
		ctx, cfg, signal, duration, maxBatches,
		workerBatches, treeStride, 0,
		makeBatch, tracesClient, logsClient, metricsClient, childDoneCh, dispatchSeq,
		nil, logKeyRecordOptions{synthesizeInsertID: true},
	)
}

func runCollectorWorkerPhasePrepared(
	ctx context.Context,
	cfg RunnerConfig,
	signal string,
	duration time.Duration,
	maxBatches int,
	workerBatches [][]collectorWorkerBatch,
	treeStride uint64,
	epochOffset uint64,
	makeBatch func(int) (collectorPreparedBatch, error),
	tracesClient ptraceotlp.GRPCClient,
	logsClient plogotlp.GRPCClient,
	metricsClient pmetricotlp.GRPCClient,
	childDoneCh <-chan struct{},
	dispatchSeq *atomic.Uint64,
	phaseSubmitted *bqfake.SubmittedKeySet,
	logKeyOpts logKeyRecordOptions,
) collectorPhaseStats {
	if dispatchSeq == nil {
		dispatchSeq = new(atomic.Uint64)
	}
	if treeStride == 0 {
		if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
			treeStride = computePrebuiltAccessLogSeqStride(1, cfg.BatchSize)
		} else {
			treeStride = computePrebuiltTreeStride(1, cfg.BatchSize)
		}
	}
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
		hasPartialReject      atomic.Bool
		globalSeq             atomic.Int64
		prebuiltDispatchSeq   atomic.Uint64
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
			var workerSubmitted *bqfake.SubmittedKeySet
			if phaseSubmitted != nil {
				workerSubmitted = bqfake.NewSubmittedKeySet()
				defer func() {
					phaseSubmitted.Merge(workerSubmitted)
				}()
			}
			var (
				hasWorkerPrebuilt bool
				myBatches         []collectorWorkerBatch
			)
			if wID < len(workerBatches) && len(workerBatches[wID]) > 0 {
				hasWorkerPrebuilt = true
				myBatches = workerBatches[wID]
			}
			localSeq := 0
			for phaseCtx.Err() == nil && time.Now().Before(deadline) {
				gSeq := int(globalSeq.Add(1))
				if maxBatches > 0 && gSeq > maxBatches {
					return
				}

				var (
					batchRows       int64
					prebuiltOrdinal uint64
				)
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
					if hasWorkerPrebuilt {
						prebuiltOrdinal = prebuiltDispatchSeq.Add(1) - 1
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
					if hasWorkerPrebuilt {
						prebuiltOrdinal = prebuiltDispatchSeq.Add(1) - 1
					}
				}

				if cfg.workerHook != nil {
					cfg.workerHook(wID, localSeq)
				}

				var (
					batch collectorPreparedBatch
					err   error
				)
				if hasWorkerPrebuilt {
					d := prebuiltOrdinal
					slotIdx := int(d % uint64(len(myBatches)))
					epoch := d / uint64(len(myBatches))
					batch = myBatches[slotIdx].batch
					if int(batchRows) < cfg.BatchSize {
						batch, err = sliceCollectorPreparedBatch(batch, signal, int(batchRows))
						if err != nil {
							batchesAttempted.Add(1)
							batchesFailed.Add(1)
							errOnce.Do(func() { firstErr = err })
							localSeq++
							continue
						}
					}
					if batch.recordCount > 0 {
						treeDelta := (epochOffset + epoch) * treeStride
						stampCollectorPreparedBatchTreeEpoch(signal, batch, DefaultBaseTime, treeStride, treeDelta, dispatchSeq, cfg.UpstreamInsertID)
					}
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
				if rejected > 0 && accepted > 0 {
					hasPartialReject.Store(true)
				}
				if workerSubmitted != nil && rejected == 0 && accepted > 0 {
					switch signal {
					case "traces":
						recordDispatchedTracesKeys(workerSubmitted, batch.tracesReq.Traces())
					case "logs":
						recordDispatchedLogsKeys(workerSubmitted, batch.logsReq.Logs(), logKeyOpts)
					case "metrics":
						recordDispatchedMetricsKeys(workerSubmitted, batch.metricsReq.Metrics())
					}
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
		hasPartialReject:      hasPartialReject.Load(),
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
	resolvedBin, err := resolveCollectorBinaryPath(cfg.CollectorBin)
	if err != nil {
		return SignalResult{}, nil, err
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

	usesTaggedTracker := signal == "metrics" || (signal == "logs" && !cfg.UpstreamInsertID)
	faultSimEnabled := fakeSrv != nil && (cfg.SimulateThrottleEvery > 0 || cfg.SimulateAckDelay > 0)
	if faultSimEnabled && cfg.TargetRate > 0 {
		limit := int64(fakeSrv.MaxTrackedGeneratedRowsForTagged(usesTaggedTracker))
		estimatedRows := max(int64(1), int64(math.Round(float64(cfg.TargetRate)*cfg.Duration.Seconds())))
		if estimatedRows > limit {
			closeReservedListeners()
			return SignalResult{}, nil, fmt.Errorf(
				"estimated steady-state volume (%d rows at rate=%d for duration=%s) exceeds bqfake unique-acked row tracking limit (%d) on destination table %q; lower -rate or -duration so fault-simulated runs stay within %d unique rows, or omit -simulate-throttle-every / -simulate-ack-delay",
				estimatedRows, cfg.TargetRate, cfg.Duration, limit, meta.effectiveTable, limit,
			)
		}
	}
	effectiveUniquePayloads := cfg.UniquePayloads
	usePrebuilt := !effectiveUniquePayloads && !collectorUsesDynamicPacing(cfg)
	if usePrebuilt {
		if bErr := validatePrebuiltBatchBudget(cfg); bErr != nil {
			closeReservedListeners()
			return SignalResult{}, nil, bErr
		}
	}
	batchCfg := cfg
	batchCfg.UniquePayloads = effectiveUniquePayloads

	var (
		workerBatches          [][]collectorWorkerBatch
		treeStride             uint64 = 7
		makeBatch              func(int) (collectorPreparedBatch, error)
		warmupPartialMakeBatch func(int) (collectorPreparedBatch, error)
		steadyPartialMakeBatch func(int) (collectorPreparedBatch, error)
	)
	if usePrebuilt && cfg.Workers > 0 {
		geom := computeWorkerSlotGeometry(cfg, signal)
		if geom.seedBatchCount > 0 {
			seedMakeBatch, sErr := newCollectorBatchBuilder(batchCfg, signal)
			if sErr != nil {
				closeReservedListeners()
				return SignalResult{}, nil, sErr
			}
			seedBatches := make([]collectorPreparedBatch, geom.seedBatchCount)
			for i := range geom.seedBatchCount {
				sb, bErr := seedMakeBatch(cfg.BatchSize)
				if bErr != nil {
					closeReservedListeners()
					return SignalResult{}, nil, bErr
				}
				seedBatches[i] = sb
			}
			workerBatches = buildCollectorWorkerBatchesFromPrebuilt(cfg.Workers, seedBatches, true)
			seedBatches = nil
			if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
				treeStride = computePrebuiltAccessLogSeqStride(geom.seedBatchCount, cfg.BatchSize)
			} else {
				treeStride = computePrebuiltTreeStride(geom.seedBatchCount, cfg.BatchSize)
			}
		}
	}
	if len(workerBatches) == 0 {
		var makeBatchSeed uint64
		if cfg.WarmupDuration > 0 && !usePrebuilt {
			makeBatchSeed = uint64(warmupTreeBaseOffset)
		}
		makeBatch, err = newCollectorBatchBuilderWithSeed(batchCfg, signal, makeBatchSeed)
		if err != nil {
			closeReservedListeners()
			return SignalResult{}, nil, err
		}
		warmupPartialMakeBatch = makeBatch
		steadyPartialMakeBatch = makeBatch
		if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
			treeStride = computePrebuiltAccessLogSeqStride(1, cfg.BatchSize)
		} else {
			treeStride = computePrebuiltTreeStride(1, cfg.BatchSize)
		}
	}
	var warmupEpochOffset uint64
	if signal == "logs" && cfg.WorkloadProfile == WorkloadProfileAccessLogs {
		warmupEpochOffset = max(uint64(1), (uint64(warmupAccessLogSeqOffset)+treeStride-1)/treeStride)
	} else {
		warmupEpochOffset = max(uint64(1), (uint64(warmupTreeBaseOffset)+treeStride-1)/treeStride)
	}

	closeReservedListeners()

	diag := &boundedDiagBuffer{}
	cmd := exec.CommandContext(ctx, resolvedBin, "--config="+tempCfgPath)
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

	conn, err := dialCollectorOTLPClient(otlpAddr)
	if err != nil {
		return SignalResult{}, nil, fmt.Errorf("dialing collector OTLP gRPC %s: %w", otlpAddr, err)
	}
	defer func() { _ = conn.Close() }()

	tracesClient := ptraceotlp.NewGRPCClient(conn)
	logsClient := plogotlp.NewGRPCClient(conn)
	metricsClient := pmetricotlp.NewGRPCClient(conn)

	drainTimeout := max(collectorMinDrainTimeout, cfg.CallTimeout)
	totalBatchTimeout := meta.batchProcessorTimeout + meta.queueBatchFlushTimeout
	if totalBatchTimeout > 0 {
		drainTimeout = max(drainTimeout, 2*totalBatchTimeout+5*time.Second)
	}
	batchWaitCfg := collectorBatchWaitConfig{
		batchProcTimeout:       meta.batchProcessorTimeout,
		batchProcSendSize:      meta.batchProcessorSendSize,
		queueBatchFlushTimeout: meta.queueBatchFlushTimeout,
		queueBatchMinItems:     meta.queueBatchMinItems,
	}
	baseMetrics, err := scrapeCollectorMetrics(ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID)
	if err != nil {
		return SignalResult{}, nil, err
	}

	var dispatchSeq atomic.Uint64
	activeTrackingLimit := func() int {
		limit := fakeSrv.MaxTrackedGeneratedRowsForTagged(usesTaggedTracker)
		if _, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable(meta.effectiveTable); tier2Hashes > 0 {
			limit = fakeSrv.MaxUniqueAckedRows()
		}
		return limit
	}
	formatWarmupUniqueAckedSaturatedErr := func() error {
		limit := activeTrackingLimit()
		return fmt.Errorf(
			"bqfake warmup unique-acked row tracking saturated at %d unique rows on destination table %q; warmup distinct-row delivery cannot be verified (lower -rate, shorten warmup_duration, or omit -soak so warmup stays within %d unique rows)",
			limit, meta.effectiveTable, limit,
		)
	}
	formatUniqueAckedSaturatedErr := func() error {
		limit := activeTrackingLimit()
		if faultSimEnabled {
			return fmt.Errorf(
				"bqfake unique-acked row tracking saturated at %d unique rows on destination table %q; unique_delivery_verified cannot be asserted (lower -rate or -duration so fault-simulated runs stay within %d unique rows, or disable -simulate-throttle-every / -simulate-ack-delay)",
				limit, meta.effectiveTable, limit,
			)
		}
		return fmt.Errorf(
			"bqfake unique-acked row tracking saturated at %d unique rows on destination table %q; unique_delivery_verified cannot be asserted (lower -rate or -duration so runs stay within %d unique rows)",
			limit, meta.effectiveTable, limit,
		)
	}

	pid := cmd.Process.Pid
	logKeyOpts := logKeyRecordOptions{
		logNameAttr:        meta.effectiveLogsLogNameAttr,
		insertIDAttr:       meta.effectiveLogsInsertIDAttr,
		synthesizeInsertID: meta.effectiveLogsSynthesizeInsertID,
	}
	// Enable unique tracking once per signal before any warmup phase so steady-state
	// replays of warmup rows remain recognized and counted against delta tracking.
	if fakeSrv != nil {
		fakeSrv.SetTrackUniqueAcked(true)
	}
	if cfg.WarmupDuration > 0 {
		warmupRunCtx := ctx
		var (
			cancelWarmupRun       context.CancelFunc
			warmupBeforeSnap      bqfake.TableStatsSnapshot
			warmupSubmitted       *bqfake.SubmittedKeySet
			warmupSinkAckedBefore int64
			warmupSinkAckedFn     func() int64
		)
		if fakeSrv != nil {
			warmupRunCtx, cancelWarmupRun = context.WithCancel(ctx)
			fakeSrv.SetOnUniqueAckedSaturated(func(tbl string) {
				if tbl == "" || tbl == meta.effectiveTable {
					cancelWarmupRun()
				}
			})
			fakeSrv.BeginUniqueAckedPhase(meta.effectiveTable)
			warmupBeforeSnap = fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
			if !meta.pipelineAltersIdentityKeys {
				warmupSubmitted = bqfake.NewSubmittedKeySet()
			}
			warmupSinkAckedBefore = warmupBeforeSnap.UniqueAckedRows
			warmupSinkAckedFn = func() int64 {
				snap := fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
				if snap.UniqueSaturated {
					return math.MaxInt64
				}
				return snap.UniqueAckedRows
			}
		}
		dispatchSeq.Store(warmupAccessLogSeqOffset)
		warmupStats := runCollectorWorkerPhasePrepared(
			warmupRunCtx, cfg, signal, cfg.WarmupDuration, 0,
			workerBatches, treeStride, warmupEpochOffset,
			warmupPartialMakeBatch, tracesClient, logsClient, metricsClient, doneCh, &dispatchSeq,
			warmupSubmitted, logKeyOpts,
		)
		if cancelWarmupRun != nil {
			cancelWarmupRun()
		}
		if fakeSrv != nil {
			fakeSrv.SetOnUniqueAckedSaturated(nil)
		}
		if fakeSrv != nil && fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable).UniqueSaturated {
			_ = conn.Close()
			terminateCollector()
			satErr := formatWarmupUniqueAckedSaturatedErr()
			return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
		}
		if ctx.Err() != nil {
			return SignalResult{}, warmupStats.firstErr, ctx.Err()
		}
		if warmupStats.firstErr != nil && !cfg.AllowPartialFailures {
			return SignalResult{}, warmupStats.firstErr, warmupStats.firstErr
		}
		warmupAfter, _, drainErr := drainCollectorPipelineWithBatchWait(
			ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID,
			baseMetrics, warmupStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag,
			warmupSinkAckedBefore, warmupSinkAckedFn, batchWaitCfg,
		)
		if drainErr != nil {
			if fakeSrv != nil && fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable).UniqueSaturated {
				_ = conn.Close()
				terminateCollector()
				satErr := formatWarmupUniqueAckedSaturatedErr()
				return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
			}
			return SignalResult{}, warmupStats.firstErr, drainErr
		}
		var (
			warmupCommitted int64
			warmupUnique    int64
			warmupAfterSnap bqfake.TableStatsSnapshot
			warmupRec       bqfake.ReconciliationResult
			warmupHasRec    bool
		)
		if fakeSrv != nil {
			if warmupSubmitted != nil && !warmupStats.hasPartialReject {
				warmupAfterSnap, warmupRec = fakeSrv.ReconcileAndSnapshotForTable(meta.effectiveTable, warmupSubmitted)
				warmupHasRec = true
			} else {
				warmupAfterSnap = fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
			}
			if warmupAfterSnap.UniqueSaturated || warmupRec.Saturated {
				_ = conn.Close()
				terminateCollector()
				satErr := formatWarmupUniqueAckedSaturatedErr()
				return SignalResult{}, errors.Join(warmupStats.firstErr, satErr), satErr
			}
			warmupCommitted = max(int64(0), warmupAfterSnap.AckedRows-warmupBeforeSnap.AckedRows)
			warmupUnique = max(int64(0), warmupAfterSnap.UniqueAckedRows-warmupBeforeSnap.UniqueAckedRows)
		}
		warmupTelem, warmupSendFailed := diffCollectorTelemetry(baseMetrics, warmupAfter)
		warmupEnqueueFailed := max(int64(0), warmupAfter.EnqueueFailed-baseMetrics.EnqueueFailed)
		if !cfg.AllowPartialFailures && (warmupStats.batchesFailed > 0 || warmupStats.rejectedRecords > 0 || warmupSendFailed > 0 || warmupEnqueueFailed > 0 || warmupTelem.RejectedRows > 0 || warmupTelem.QuarantinedRows > 0 || warmupTelem.AcknowledgedRows != warmupStats.recordsSubmitted || (fakeSrv != nil && (warmupCommitted != warmupStats.recordsSubmitted || warmupUnique != warmupStats.recordsSubmitted || (warmupHasRec && (warmupRec.MissingRows > 0 || warmupRec.UnexpectedRows > 0))))) {
			sendErr := fmt.Errorf(
				"collector warmup failed gate for %s (submitted=%d, otlp_rejected=%d, acked=%d, committed=%d, unique_committed=%d, missing=%d, unexpected=%d, rejected=%d, quarantined=%d, send_failed=%d, enqueue_failed=%d)",
				signal, warmupStats.recordsSubmitted, warmupStats.rejectedRecords, warmupTelem.AcknowledgedRows, warmupCommitted, warmupUnique,
				warmupRec.MissingRows, warmupRec.UnexpectedRows,
				warmupTelem.RejectedRows, warmupTelem.QuarantinedRows, warmupSendFailed, warmupEnqueueFailed,
			)
			return SignalResult{}, errors.Join(warmupStats.firstErr, sendErr), sendErr
		}
		dispatchSeq.Store(0)
		if len(workerBatches) == 0 {
			makeBatch, err = newCollectorBatchBuilder(batchCfg, signal)
			if err != nil {
				return SignalResult{}, nil, err
			}
			steadyPartialMakeBatch = makeBatch
		}
		baseMetrics = warmupAfter
	}

	var (
		steadyBeforeSnap bqfake.TableStatsSnapshot
		steadySubmitted  *bqfake.SubmittedKeySet
		sinkAckedBefore  int64
		sinkAckedFn      func() int64
	)
	if fakeSrv != nil {
		fakeSrv.BeginUniqueAckedPhase(meta.effectiveTable)
		steadyBeforeSnap = fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
		if !meta.pipelineAltersIdentityKeys {
			steadySubmitted = bqfake.NewSubmittedKeySet()
		}
		sinkAckedBefore = steadyBeforeSnap.UniqueAckedRows
		sinkAckedFn = func() int64 {
			snap := fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
			if snap.UniqueSaturated {
				return math.MaxInt64
			}
			return snap.UniqueAckedRows
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
	stopMemSampler := sync.OnceFunc(func() {
		close(stopMemCh)
		memDoneWg.Wait()
	})
	defer stopMemSampler()

	phaseRunCtx := ctx
	if fakeSrv != nil {
		var cancelPhaseRun context.CancelFunc
		phaseRunCtx, cancelPhaseRun = context.WithCancel(ctx)
		defer cancelPhaseRun()
		fakeSrv.SetOnUniqueAckedSaturated(func(tbl string) {
			if tbl == "" || tbl == meta.effectiveTable {
				cancelPhaseRun()
			}
		})
		defer fakeSrv.SetOnUniqueAckedSaturated(nil)
		if faultSimEnabled {
			fakeSrv.SetPeriodicFaults(ctx, meta.effectiveTable, cfg.SimulateThrottleEvery, cfg.SimulateAckDelay)
		}
	}

	startWall := time.Now()
	steadyStats := runCollectorWorkerPhasePrepared(
		phaseRunCtx, cfg, signal, cfg.Duration, cfg.maxBatches,
		workerBatches, treeStride, 0,
		steadyPartialMakeBatch, tracesClient, logsClient, metricsClient, doneCh, &dispatchSeq,
		steadySubmitted, logKeyOpts,
	)
	phaseEnd := time.Now()
	preSaturated := fakeSrv != nil && fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable).UniqueSaturated
	var (
		afterMetrics  collectorMetricsSample
		idleBatchWait time.Duration
		drainErr      error
	)
	if preSaturated {
		mCtx, mCancel := context.WithTimeout(context.Background(), 2*time.Second)
		if mSample, mErr := scrapeCollectorMetrics(mCtx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID); mErr == nil {
			afterMetrics = mSample
		} else {
			afterMetrics = baseMetrics
		}
		mCancel()
	} else {
		afterMetrics, idleBatchWait, drainErr = drainCollectorPipelineWithBatchWait(
			ctx, metricsClientHTTP, metricsAddr, signal, meta.activeExporterID,
			baseMetrics, steadyStats.recordsSubmitted, drainTimeout, doneCh, &cmdWaitErr, diag,
			sinkAckedBefore, sinkAckedFn, batchWaitCfg,
		)
	}
	phaseElapsed := phaseEnd.Sub(startWall)
	totalElapsed := time.Since(startWall)
	elapsed := max(phaseElapsed, totalElapsed-idleBatchWait)
	if elapsed <= 0 {
		elapsed = time.Microsecond
	}

	var (
		cutoffSnap               bqfake.TableStatsSnapshot
		reconcileRes             bqfake.ReconciliationResult
		fakeUniqueAckedSaturated bool
	)
	if fakeSrv != nil {
		if steadySubmitted != nil && !steadyStats.hasPartialReject {
			cutoffSnap, reconcileRes = fakeSrv.ReconcileAndSnapshotForTable(meta.effectiveTable, steadySubmitted)
		} else {
			cutoffSnap = fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable)
		}
		fakeUniqueAckedSaturated = cutoffSnap.UniqueSaturated || reconcileRes.Saturated
	}
	cpuAfterDrainSec, cpuAfterOK := readPIDCPUSeconds(pid)

	stopMemSampler()
	sampleMem()

	var satErr error
	if fakeUniqueAckedSaturated {
		satErr = formatUniqueAckedSaturatedErr()
	}

	var throttleErr error
	if faultSimEnabled && cfg.SimulateThrottleEvery > 0 && steadyStats.recordsSubmitted > 0 {
		if (cutoffSnap.ThrottlesInjected - steadyBeforeSnap.ThrottlesInjected) == 0 {
			throttleErr = fmt.Errorf(
				"-simulate-throttle-every=%d never fired on destination table %q",
				cfg.SimulateThrottleEvery, meta.effectiveTable,
			)
		}
	}

	preDrainFirstErr := steadyStats.firstErr
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
	if shutdownErr != nil && drainErr == nil && throttleErr == nil && satErr == nil {
		return SignalResult{}, steadyStats.firstErr, shutdownErr
	}

	cpuUnavailable := !cpuBeforeOK || !cpuAfterOK
	var cpuDeltaSec float64
	if !cpuUnavailable {
		cpuDeltaSec = max(0.0, cpuAfterDrainSec-cpuBeforeSec)
	}

	telem, deltaSendFailed := diffCollectorTelemetry(baseMetrics, afterMetrics)
	deltaEnqueueFailed := max(int64(0), afterMetrics.EnqueueFailed-baseMetrics.EnqueueFailed)
	if steadyStats.rejectedRecords > telem.RejectedRows {
		telem.RejectedRows = steadyStats.rejectedRecords
	}
	if deltaSendFailed > 0 || deltaEnqueueFailed > 0 {
		if steadyStats.batchesFailed == 0 {
			steadyStats.batchesFailed = 1
		}
		if steadyStats.firstErr == nil {
			if deltaEnqueueFailed == 0 {
				steadyStats.firstErr = fmt.Errorf("collector exporter failed to send %d %s records", deltaSendFailed, signal)
			} else {
				steadyStats.firstErr = fmt.Errorf("collector exporter failed to send or enqueue %s records (send_failed=%d, enqueue_failed=%d)", signal, deltaSendFailed, deltaEnqueueFailed)
			}
		}
	}

	ackedRows := telem.AcknowledgedRows
	attemptedProtoBytes := telem.AppendBytesTotal
	var committedRows int64
	if fakeSrv != nil {
		committedRows = max(int64(0), cutoffSnap.AckedRows-steadyBeforeSnap.AckedRows)
		fakeAckedBytes := max(int64(0), cutoffSnap.AckedBytes-steadyBeforeSnap.AckedBytes)
		if attemptedProtoBytes == 0 {
			attemptedProtoBytes = fakeAckedBytes
			telem.AppendBytesTotal = fakeAckedBytes
		}
	}

	var (
		deliveredRows             int64
		replayedRows              int64
		missingRows               int64
		unexpectedRows            int64
		uniqueDeliveryVerified    bool
		bytesPerRowUnavailable    bool
		bytesPerRow               float64
		attemptedBytesPerAckedRow float64
	)
	if ackedRows > 0 {
		attemptedBytesPerAckedRow = float64(attemptedProtoBytes) / float64(ackedRows)
	}

	if fakeSrv != nil {
		deliveredRows = max(int64(0), cutoffSnap.UniqueAckedRows-steadyBeforeSnap.UniqueAckedRows)
		replayedRows = max(int64(0), committedRows-deliveredRows)
		missingRows = reconcileRes.MissingRows
		unexpectedRows = reconcileRes.UnexpectedRows
		uniqueDeliveryVerified = !fakeUniqueAckedSaturated
		deliveredBytes := max(int64(0), cutoffSnap.UniqueAckedBytes-steadyBeforeSnap.UniqueAckedBytes)
		if deliveredRows > 0 {
			bytesPerRow = float64(deliveredBytes) / float64(deliveredRows)
		}
	} else {
		deliveredRows = min(ackedRows, steadyStats.recordsSubmitted)
		replayedRows = max(int64(0), ackedRows-steadyStats.recordsSubmitted)
		if telem.Retries > 0 || deltaSendFailed > 0 || deltaEnqueueFailed > 0 || telem.RejectedRows > 0 || telem.QuarantinedRows > 0 ||
			incompleteDrain || replayedRows > 0 || (steadyStats.recordsSubmitted > 0 && ackedRows < steadyStats.recordsSubmitted) ||
			(ackedRows > 0 && (!afterMetrics.HasAppendBytesMetric || attemptedProtoBytes <= 0)) {
			bytesPerRowUnavailable = true
		} else if ackedRows > 0 {
			bytesPerRow = float64(attemptedProtoBytes) / float64(ackedRows)
		}
		if ackedRows > 0 && (!afterMetrics.HasAppendBytesMetric || attemptedProtoBytes <= 0) {
			attemptedBytesPerAckedRow = 0
		}
	}
	telem.ReplayedRows = replayedRows

	elapsedSec := elapsed.Seconds()
	rowsPerSec := float64(deliveredRows) / elapsedSec
	var wireMBPerSec float64
	if !bytesPerRowUnavailable {
		wireMBPerSec = (bytesPerRow * float64(deliveredRows)) / (1024.0 * 1024.0) / elapsedSec
	}

	var byteLayers *ByteLayersSummary
	if steadyStats.dispatchedRecords > 0 && bytesPerRow > 0 {
		dispatched := dispatchedByteTotals{
			sourceBytes: steadyStats.dispatchedSourceBytes,
			otlpBytes:   steadyStats.dispatchedOTLPBytes,
			records:     steadyStats.dispatchedRecords,
		}
		byteLayers = buildByteLayersSummaryFromMeasured(dispatched, bytesPerRow)
		if !useBQFake && byteLayers != nil {
			if hasUnroutedCustomCollectorEndpoint(meta.effectiveEndpoint) {
				byteLayers.BQStorageQueryNote = "INFORMATION_SCHEMA.TABLE_STORAGE lookup skipped: collector exporter uses custom endpoint.url or without_authentication without endpoint.admin_url"
			} else {
				populateLiveTableStorageWithCollectorOptions(ctx, cfg, meta.effectiveTable, &meta.effectiveEndpoint, &meta.effectiveCredentials, byteLayers)
			}
		}
	}

	var cpuCoresUsed, cpuCoresPer10k float64
	if !cpuUnavailable {
		cpuCoresUsed = cpuDeltaSec / elapsedSec
		if rowsPerSec > 0 {
			cpuCoresPer10k = cpuCoresUsed / (rowsPerSec / 10000.0)
		}
	}

	res := SignalResult{
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
		MissingRows:               missingRows,
		UnexpectedRows:            unexpectedRows,
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
	}
	var cutoffHardErrs []error
	if satErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, satErr)
	}
	if drainErr != nil && !cfg.AllowPartialFailures {
		cutoffHardErrs = append(cutoffHardErrs, drainErr)
	}
	if throttleErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, throttleErr)
	}
	if shutdownErr != nil {
		cutoffHardErrs = append(cutoffHardErrs, shutdownErr)
	}
	if len(cutoffHardErrs) > 0 {
		hardErr := errors.Join(cutoffHardErrs...)
		return res, errors.Join(preDrainFirstErr, hardErr), hardErr
	}
	return res, steadyStats.firstErr, nil
}
