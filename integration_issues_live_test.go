// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	stdhttp "net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	bqstorage "cloud.google.com/go/bigquery/storage/apiv1"
	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/apache/arrow/go/v15/arrow"
	"github.com/apache/arrow/go/v15/arrow/array"
	"github.com/apache/arrow/go/v15/arrow/ipc"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/backfill"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/quarantinereplay"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/validate"
)

// liveIssuesSecretPattern masks the planted bearer credential wherever it
// appears inside a string value or log body.
const liveIssuesSecretPattern = `Bearer\s+sk-secret-[A-Za-z0-9]+`

// liveIssuesMaxAttributes is the structural limit the configuration sets
// through a retired key. The golden spans carry at most 10 attributes and the
// quarantined records more than 12 extras each, so the limit decides which
// records are quarantined.
const liveIssuesMaxAttributes = 12

// liveIssuesRetiredLimitKey retires a key for this test only, so the
// deprecation path runs against the live exporter without touching the
// shipped registry.
var liveIssuesRetiredLimitKey = deprecatedConfigKey{
	OldPath:         "limits.legacy_max_attributes",
	NewPath:         "limits.max_attribute_count",
	DeprecatedIn:    "v0.0.4",
	RemovalEarliest: "v0.0.6",
	Anchor:          "live-test-legacy-max-attributes",
}

// liveIssuesRun is the state the subtests of TestLiveIssuesEndToEndBigQuery
// share: one owned ephemeral dataset and, when a bucket is configured, one
// object prefix in it. Both are deleted on cleanup.
type liveIssuesRun struct {
	project, location, dataset string
	// bucket is empty when no Cloud Storage bucket is configured.
	bucket, prefix string
	runID          string
	secret         string
	svcMain        string
	svcQuarantine  string
	svcBackfill    string
	base           time.Time
	admin          *bq.Client
	httpClient     *stdhttp.Client

	objMu sync.Mutex
	// objects holds every gs:// URI the run wrote, so cleanup can delete
	// each one directly where a prefix-scoped IAM condition denies listing.
	objects map[string]bool
}

func (r *liveIssuesRun) trackObject(uri string) {
	if uri == "" {
		return
	}
	r.objMu.Lock()
	defer r.objMu.Unlock()
	r.objects[uri] = true
}

func (r *liveIssuesRun) trackedObjects() []string {
	r.objMu.Lock()
	defer r.objMu.Unlock()
	out := make([]string, 0, len(r.objects))
	for uri := range r.objects {
		out = append(out, uri)
	}
	slices.Sort(out)
	return out
}

type liveIssuesExporters struct {
	traces  *tracesExporter
	logs    *logsExporter
	metrics *metricsExporter
}

// TestLiveIssuesEndToEndBigQuery verifies the exporter's alpha and beta exit
// work against real BigQuery and, when BQ_OFFLOAD_TEST_BUCKET names a bucket,
// real Cloud Storage. One configuration, resolved from YAML with ${env:...}
// expansion and a retired key the way a Collector resolves it, drives traces,
// logs, and metrics exporters with gzip AppendRows compression, adaptive
// backpressure, redaction, a structural limit, quarantine, companion views,
// and payload offload. The subtests then check, on the rows BigQuery holds:
//
//   - gzip-compressed appends round-trip every field, and the zstd decoder the
//     BigQuery client links through Apache Arrow decodes ZSTD-compressed
//     Storage Read API batches of those rows (GitHub issue 33);
//   - every self-telemetry instrument emitted during the traffic matches the
//     name, unit, type, and attribute set metadata.yaml declares (issue 38);
//   - the retired key warns once with its migration link, the planted secret
//     never reaches BigQuery or Cloud Storage, quarantined records replay from
//     BigQuery into the signal tables, bq-otel-validate passes and fails
//     closed, and bq-otel-backfill appends a Cloud Storage archive (issues 41
//     and 43);
//   - the dedup views collapse a deliberately replayed batch, the companion
//     views and the trajectory table function return the expected rows, and
//     the live tables match the compiled schema contract (issue 40).
//
// The multi-worker testbench check (issues 34 and 42) lives in
// internal/testbench, which this package cannot import.
//
// It is opt-in: it creates billable resources.
func TestLiveIssuesEndToEndBigQuery(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping the live issue verification against BigQuery")
	}
	bucket := os.Getenv("BQ_OFFLOAD_TEST_BUCKET")
	if bucket == "" {
		bucket = os.Getenv("BQ_OFFLOAD_BUCKET")
	}
	if bucket == "" && os.Getenv("REQUIRE_LIVE_GCS") == "1" {
		t.Fatal("REQUIRE_LIVE_GCS=1 is set but BQ_OFFLOAD_TEST_BUCKET is empty")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
	t.Cleanup(cancel)
	r := newLiveIssuesRun(ctx, t, project, location, bucket)

	var cfg *Config
	if !t.Run("ConfigResolvesEnvExpansionAndRetiredKey", func(t *testing.T) {
		cfg = r.resolveConfig(t)
	}) {
		t.FailNow()
	}

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	core, observed := observer.New(zapcore.InfoLevel)
	settings := component.TelemetrySettings{Logger: zap.New(core), MeterProvider: provider}
	exps := r.startExporters(ctx, t, settings, cfg)

	// Each golden batch goes out twice: the second push is a deliberate
	// replay that the dedup views must collapse. The quarantined records go
	// out once.
	for _, push := range []struct {
		name string
		run  func() error
	}{
		{"traces", func() error { return exps.traces.pushTraceData(ctx, r.mainTraces()) }},
		{"quarantined traces", func() error { return exps.traces.pushTraceData(ctx, r.quarantinedTraces()) }},
		{"logs", func() error { return exps.logs.pushLogData(ctx, r.mainLogs()) }},
		{"quarantined logs", func() error { return exps.logs.pushLogData(ctx, r.quarantinedLogs()) }},
		{"metrics", func() error { return exps.metrics.pushMetricsData(ctx, r.mainMetrics()) }},
		{"replayed traces", func() error { return exps.traces.pushTraceData(ctx, r.mainTraces()) }},
		{"replayed logs", func() error { return exps.logs.pushLogData(ctx, r.mainLogs()) }},
		{"replayed metrics", func() error { return exps.metrics.pushMetricsData(ctx, r.mainMetrics()) }},
	} {
		if err := push.run(); err != nil {
			t.Fatalf("push %s: %v", push.name, err)
		}
	}

	if !t.Run("DedupViewsCollapseDeliberateReplay", func(t *testing.T) {
		r.checkDedupCounts(ctx, t)
	}) {
		t.FailNow()
	}
	t.Run("GzipAppendRowsRoundTripEveryField", func(t *testing.T) {
		r.checkRoundTrip(ctx, t)
	})
	t.Run("ZstdArrowStorageReadDecodesLiveRows", func(t *testing.T) {
		r.checkZstdArrowRead(ctx, t)
	})
	t.Run("SelfTelemetryMatchesMetadataYAML", func(t *testing.T) {
		r.checkSelfTelemetry(ctx, t, reader)
	})
	t.Run("RetiredKeyWarnsOnceWithMigrationLink", func(t *testing.T) {
		checkRetiredKeyWarning(t, observed)
	})
	t.Run("CompanionViewsAndTrajectoryTVF", func(t *testing.T) {
		r.checkCompanionViews(ctx, t)
	})
	t.Run("LiveTablesMatchCompiledSchemaContract", func(t *testing.T) {
		r.checkSchemaContract(ctx, t)
	})
	t.Run("RollupAndMCPViewsPrunePartitions", func(t *testing.T) {
		r.checkRollupViewsPrunePartitions(ctx, t)
	})
	t.Run("QuarantineReplaysFromBigQueryIntoSignalTables", func(t *testing.T) {
		r.checkQuarantineReplay(ctx, t)
	})
	t.Run("RedactionMasksSecretBeforeBigQueryAndGCS", func(t *testing.T) {
		r.checkRedaction(ctx, t)
	})
	t.Run("ValidatePreflightConformsAndFailsClosed", func(t *testing.T) {
		r.checkValidate(ctx, t)
	})
	t.Run("BackfillAppendsRedactedGCSArchive", func(t *testing.T) {
		r.checkBackfill(ctx, t)
	})
}

func newLiveIssuesRun(ctx context.Context, t *testing.T, project, location, bucket string) *liveIssuesRun {
	t.Helper()
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("random run ID: %v", err)
	}
	var secret [12]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("random secret: %v", err)
	}
	runID := hex.EncodeToString(nonce[:])
	r := &liveIssuesRun{
		project:  project,
		location: location,
		dataset:  uniqueEphemeralDatasetID("otel_exporter_issues_it"),
		bucket:   bucket,
		// The it-offload- prefix is the one the CI service account's
		// conditional Cloud Storage role and the bucket's one-day lifecycle
		// rule cover (deploy/terraform/ci_wif.tf).
		prefix:        "it-offload-issues-" + runID,
		runID:         runID,
		secret:        "sk-secret-" + hex.EncodeToString(secret[:]),
		svcMain:       "it-issues-main-" + runID,
		svcQuarantine: "it-issues-quarantine-" + runID,
		svcBackfill:   "it-issues-backfill-" + runID,
		base:          time.Now().UTC().Truncate(time.Millisecond).Add(-5 * time.Second),
		objects:       map[string]bool{},
	}

	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, []string{
		bigqueryapi.BigqueryScope,
		"https://www.googleapis.com/auth/devstorage.read_write",
	})
	if err != nil {
		t.Fatalf("create BigQuery and Cloud Storage HTTP client: %v", err)
	}
	admin, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery client: %v", err)
	}
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close BigQuery client: %v", err)
		}
		closeHTTP()
	})
	r.admin = admin
	r.httpClient = httpClient
	if err := createOwnedEphemeralDataset(ctx, admin, r.dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, r.dataset, err)
	}
	if bucket != "" {
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
			defer cleanupCancel()
			for _, uri := range r.trackedObjects() {
				deleteGCSObject(cleanupCtx, t, httpClient, uri)
			}
			// Catches anything the boundary missed where listing is allowed.
			listAndDeleteGCSPrefix(cleanupCtx, t, httpClient, bucket, r.prefix+"/")
			listAndDeleteGCSPrefix(cleanupCtx, t, httpClient, bucket, r.prefix+"-backfill/")
		})
	}
	t.Logf("live run %s: dataset %s.%s, bucket %q, prefix %q", runID, project, r.dataset, bucket, r.prefix)
	return r
}

// resolveConfig resolves the exporter block the way a Collector does, from
// YAML whose values come from ${env:...} references, and decodes it through
// Config.Unmarshal with a retired key. It combines the staged Google Cloud
// setups: Application Default Credentials (no credentials block),
// auto_create, quarantine, Cloud Storage offload, and redaction.
func (r *liveIssuesRun) resolveConfig(t *testing.T) *Config {
	t.Helper()
	quarantineRawBytes := "8388608"
	if r.bucket != "" {
		// A small inline cap moves every quarantined payload to Cloud Storage.
		quarantineRawBytes = "256"
	}
	t.Setenv("BQ_OTEL_IT_DATASET", r.dataset)
	t.Setenv("BQ_OTEL_IT_LOCATION", r.location)
	t.Setenv("BQ_OTEL_IT_MAX_ATTRIBUTES", strconv.Itoa(liveIssuesMaxAttributes))
	t.Setenv("BQ_OTEL_IT_QUARANTINE_RAW_BYTES", quarantineRawBytes)
	lines := []string{
		"exporters:",
		"  bigquery:",
		"    project: ${env:BQ_PROJECT}",
		"    dataset: ${env:BQ_OTEL_IT_DATASET}",
		"    location: ${env:BQ_OTEL_IT_LOCATION}",
		"    auto_create:",
		"      dataset: true",
		"      tables: true",
		"      companion_views: true",
		"    quarantine:",
		"      enabled: true",
		"      table: otel_quarantine",
		"      partition_expiration_days: 30",
		"      max_raw_payload_bytes: ${env:BQ_OTEL_IT_QUARANTINE_RAW_BYTES}",
		"    redaction:",
		"      enabled: true",
		"      redact_log_body: true",
		"      blocked_value_patterns:",
		"        - '" + liveIssuesSecretPattern + "'",
		"    limits:",
		"      legacy_max_attributes: ${env:BQ_OTEL_IT_MAX_ATTRIBUTES}",
		"    write:",
		"      compression: gzip",
		"      backpressure:",
		"        enabled: true",
	}
	if r.bucket != "" {
		t.Setenv("BQ_OTEL_IT_BUCKET", r.bucket)
		t.Setenv("BQ_OTEL_IT_PREFIX", r.prefix)
		lines = append(lines,
			"    offload:",
			"      enabled: true",
			"      bucket: ${env:BQ_OTEL_IT_BUCKET}",
			"      prefix: ${env:BQ_OTEL_IT_PREFIX}",
			"      min_bytes: 256",
		)
	}
	conf := resolveLiveIssuesYAML(t, strings.Join(lines, "\n")+"\n")
	cfg := createDefaultConfig().(*Config)
	if err := cfg.unmarshalWithDeprecations(conf, []deprecatedConfigKey{liveIssuesRetiredLimitKey}); err != nil {
		t.Fatalf("unmarshal resolved configuration: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("resolved configuration does not validate: %v", err)
	}

	wantRawBytes, _ := strconv.Atoi(quarantineRawBytes)
	for _, c := range []struct {
		name      string
		got, want any
	}{
		{"project", cfg.Project, r.project},
		{"dataset", cfg.Dataset, r.dataset},
		{"location", cfg.Location, r.location},
		{"credentials (ADC: no block)", cfg.Credentials, CredentialsConfig{}},
		{"limits.max_attribute_count (from the retired key)", cfg.Limits.MaxAttributeCount, liveIssuesMaxAttributes},
		{"auto_create", cfg.AutoCreate, AutoCreateConfig{Dataset: true, Tables: true, CompanionViews: true}},
		{"quarantine.enabled", cfg.Quarantine.Enabled, true},
		{"quarantine.table", cfg.Quarantine.Table, "otel_quarantine"},
		{"quarantine.partition_expiration_days", cfg.Quarantine.PartitionExpirationDays, 30},
		{"quarantine.max_raw_payload_bytes", cfg.Quarantine.MaxRawPayloadBytes, wantRawBytes},
		{"redaction.enabled", cfg.Redaction.Enabled, true},
		{"redaction.redact_log_body", cfg.Redaction.RedactLogBody, true},
		{"redaction.blocked_value_patterns", cfg.Redaction.BlockedValuePatterns, []string{liveIssuesSecretPattern}},
		{"write.compression", cfg.Write.Compression, "gzip"},
		{"write.backpressure.enabled", cfg.Write.Backpressure.Enabled, true},
		{"offload.enabled", cfg.Offload.Enabled, r.bucket != ""},
	} {
		if fmt.Sprintf("%#v", c.got) != fmt.Sprintf("%#v", c.want) {
			t.Errorf("%s = %#v, want %#v", c.name, c.got, c.want)
		}
	}
	if r.bucket != "" && (cfg.Offload.Bucket != r.bucket || cfg.Offload.Prefix != r.prefix || cfg.Offload.MinBytes != 256) {
		t.Errorf("offload = %+v, want bucket %q prefix %q min_bytes 256", cfg.Offload, r.bucket, r.prefix)
	}
	if cfg.deprecations == nil || !slices.Equal(cfg.deprecations.applied, []deprecatedConfigKey{liveIssuesRetiredLimitKey}) {
		t.Errorf("recorded deprecations = %+v, want the retired limits key", cfg.deprecations)
	}
	return cfg
}

// resolveLiveIssuesYAML resolves text through a confmap.Resolver whose env
// provider reads the process environment, as the Collector's does.
func resolveLiveIssuesYAML(t *testing.T, text string) *confmap.Conf {
	t.Helper()
	input := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &staticYAMLProvider{scheme: "input", RetrieveFunc: func(context.Context, string, confmap.WatcherFunc) (*confmap.Retrieved, error) {
			return confmap.NewRetrievedFromYAML([]byte(text))
		}}
	})
	env := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &staticYAMLProvider{scheme: "env", RetrieveFunc: func(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
			name := strings.TrimPrefix(uri, "env:")
			value, ok := os.LookupEnv(name)
			if !ok {
				return nil, fmt.Errorf("environment variable %s is not set", name)
			}
			return confmap.NewRetrievedFromYAML([]byte(value))
		}}
	})
	resolver, err := confmap.NewResolver(confmap.ResolverSettings{
		URIs:              []string{"input:collector.yaml"},
		ProviderFactories: []confmap.ProviderFactory{input, env},
		DefaultScheme:     "env",
	})
	if err != nil {
		t.Fatalf("create resolver: %v", err)
	}
	t.Cleanup(func() { _ = resolver.Shutdown(context.Background()) })
	conf, err := resolver.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve configuration: %v", err)
	}
	sub, err := conf.Sub("exporters" + confmap.KeyDelimiter + "bigquery")
	if err != nil {
		t.Fatalf("select exporters.bigquery: %v", err)
	}
	return sub
}

func (r *liveIssuesRun) startExporters(ctx context.Context, t *testing.T, settings component.TelemetrySettings, cfg *Config) liveIssuesExporters {
	t.Helper()
	stop := func(name string, shutdown func(context.Context) error) {
		t.Cleanup(func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer shutdownCancel()
			if err := shutdown(shutdownCtx); err != nil {
				t.Errorf("shut down %s exporter: %v", name, err)
			}
		})
	}
	traces, err := newTracesExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newTracesExporter: %v", err)
	}
	if err := traces.start(ctx, nil); err != nil {
		t.Fatalf("start traces exporter: %v", err)
	}
	stop("traces", traces.shutdown)
	logs, err := newLogsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newLogsExporter: %v", err)
	}
	if err := logs.start(ctx, nil); err != nil {
		t.Fatalf("start logs exporter: %v", err)
	}
	stop("logs", logs.shutdown)
	metrics, err := newMetricsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newMetricsExporter: %v", err)
	}
	if err := metrics.start(ctx, nil); err != nil {
		t.Fatalf("start metrics exporter: %v", err)
	}
	stop("metrics", metrics.shutdown)
	if r.bucket != "" {
		for _, se := range []*signalExporter{traces.signalExporter, logs.signalExporter} {
			if se.offloader == nil {
				t.Fatalf("offload is enabled but the %s exporter has no offloader", se.table)
			}
			se.offloader.SetStore(&recordingBlobStore{inner: se.offloader.Store(), onWrite: r.trackObject})
		}
	}
	return liveIssuesExporters{traces: traces, logs: logs, metrics: metrics}
}

func liveTraceID(b byte) pcommon.TraceID {
	var id pcommon.TraceID
	for i := range id {
		id[i] = b
	}
	return id
}

func liveSpanID(b byte) pcommon.SpanID {
	var id pcommon.SpanID
	for i := range id {
		id[i] = b
	}
	return id
}

func liveHex(id []byte) string { return hex.EncodeToString(id) }

var (
	liveTraceMain       = liveTraceID(0x11)
	liveTraceAgent      = liveTraceID(0x22)
	liveTraceQuarantine = liveTraceID(0x33)
	liveTraceBackfill   = liveTraceID(0x44)
	liveSpanChat        = liveSpanID(0x1a)
	liveSpanAgent       = liveSpanID(0x2a)
	liveSpanAgentChat   = liveSpanID(0x2b)
	liveSpanQuarantine  = liveSpanID(0x3a)
	liveSpanBackfill    = liveSpanID(0x4a)
)

func (r *liveIssuesRun) ts(offset time.Duration) pcommon.Timestamp {
	return pcommon.NewTimestampFromTime(r.base.Add(offset))
}

// prompt is large enough to be offloaded and carries the planted secret on
// every line.
func (r *liveIssuesRun) prompt() string {
	return strings.Repeat("Context block with credentials: Authorization: Bearer "+r.secret+"\n", 8)
}

func (r *liveIssuesRun) redactedPrompt() string {
	return regexp.MustCompile(liveIssuesSecretPattern).ReplaceAllString(r.prompt(), "[REDACTED]")
}

// mainTraces holds an MCP tool chat span with an offloaded prompt and a
// blocked api_key attribute, and an agent invocation with one child chat
// span. Every attribute bag stays within the structural limit.
func (r *liveIssuesRun) mainTraces() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", r.svcMain)
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("it-issues-scope")

	chat := ss.Spans().AppendEmpty()
	chat.SetTraceID(liveTraceMain)
	chat.SetSpanID(liveSpanChat)
	chat.SetName("chat gemini-2.5-pro")
	chat.SetKind(ptrace.SpanKindClient)
	chat.SetStartTimestamp(r.ts(0))
	chat.SetEndTimestamp(r.ts(250 * time.Millisecond))
	chat.Status().SetCode(ptrace.StatusCodeOk)
	attrs := chat.Attributes()
	attrs.PutStr("gen_ai.operation.name", "chat")
	attrs.PutStr("gen_ai.system", "gcp.vertex.agent")
	attrs.PutStr("gen_ai.request.model", "gemini-2.5-pro")
	attrs.PutStr("gen_ai.conversation.id", "conv-"+r.runID+"-a")
	attrs.PutStr("gen_ai.tool.name", "search")
	attrs.PutStr("mcp.method.name", "tools/call")
	attrs.PutInt("gen_ai.usage.input_tokens", 10)
	attrs.PutInt("gen_ai.usage.output_tokens", 5)
	attrs.PutStr("gen_ai.prompt", r.prompt())
	attrs.PutStr("api_key", r.secret)

	agent := ss.Spans().AppendEmpty()
	agent.SetTraceID(liveTraceAgent)
	agent.SetSpanID(liveSpanAgent)
	agent.SetName("invoke_agent planner")
	agent.SetKind(ptrace.SpanKindInternal)
	agent.SetStartTimestamp(r.ts(10 * time.Millisecond))
	agent.SetEndTimestamp(r.ts(900 * time.Millisecond))
	agent.Status().SetCode(ptrace.StatusCodeOk)
	attrs = agent.Attributes()
	attrs.PutStr("gen_ai.operation.name", "invoke_agent")
	attrs.PutStr("gen_ai.system", "gcp.vertex.agent")
	attrs.PutStr("gen_ai.agent.name", "planner")
	attrs.PutStr("gen_ai.conversation.id", "conv-"+r.runID+"-b")
	attrs.PutInt("gen_ai.usage.input_tokens", 8)
	attrs.PutInt("gen_ai.usage.output_tokens", 4)

	child := ss.Spans().AppendEmpty()
	child.SetTraceID(liveTraceAgent)
	child.SetSpanID(liveSpanAgentChat)
	child.SetParentSpanID(liveSpanAgent)
	child.SetName("chat gemini-2.5-flash")
	child.SetKind(ptrace.SpanKindInternal)
	child.SetStartTimestamp(r.ts(20 * time.Millisecond))
	child.SetEndTimestamp(r.ts(800 * time.Millisecond))
	child.Status().SetCode(ptrace.StatusCodeOk)
	attrs = child.Attributes()
	attrs.PutStr("gen_ai.operation.name", "chat")
	attrs.PutStr("gen_ai.system", "gcp.vertex.agent")
	attrs.PutStr("gen_ai.request.model", "gemini-2.5-flash")
	attrs.PutStr("gen_ai.conversation.id", "conv-"+r.runID+"-b")
	attrs.PutInt("gen_ai.usage.input_tokens", 8)
	attrs.PutInt("gen_ai.usage.output_tokens", 4)
	return td
}

// liveOverLimitExtras is how many extra.N attributes liveOverLimitAttributes
// adds: on its own more than liveIssuesMaxAttributes.
const liveOverLimitExtras = liveIssuesMaxAttributes + 2

// liveOverLimitAttributes fills a bag past liveIssuesMaxAttributes.
func (r *liveIssuesRun) liveOverLimitAttributes(attrs pcommon.Map) {
	attrs.PutStr("api_key", r.secret)
	for i := 1; i <= liveOverLimitExtras; i++ {
		attrs.PutStr("extra."+strconv.Itoa(i), "v"+strconv.Itoa(i))
	}
}

func (r *liveIssuesRun) quarantinedTraces() ptrace.Traces {
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", r.svcQuarantine)
	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(liveTraceQuarantine)
	span.SetSpanID(liveSpanQuarantine)
	span.SetName("chat quarantined")
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(r.ts(30 * time.Millisecond))
	span.SetEndTimestamp(r.ts(60 * time.Millisecond))
	attrs := span.Attributes()
	attrs.PutStr("gen_ai.operation.name", "chat")
	attrs.PutStr("gen_ai.prompt", r.prompt())
	r.liveOverLimitAttributes(attrs)
	return td
}

func (r *liveIssuesRun) mainLogs() plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", r.svcMain)
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(r.ts(100 * time.Millisecond))
	rec.SetObservedTimestamp(r.ts(100 * time.Millisecond))
	rec.SetEventName("gen_ai.user.message")
	rec.SetSeverityNumber(plog.SeverityNumberInfo)
	rec.SetTraceID(liveTraceMain)
	rec.SetSpanID(liveSpanChat)
	rec.Body().SetStr(r.prompt())
	rec.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	rec.Attributes().PutStr("api_key", r.secret)
	return ld
}

func (r *liveIssuesRun) quarantinedLogs() plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", r.svcQuarantine)
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(r.ts(110 * time.Millisecond))
	rec.SetObservedTimestamp(r.ts(110 * time.Millisecond))
	rec.SetEventName("gen_ai.choice")
	rec.SetTraceID(liveTraceQuarantine)
	rec.SetSpanID(liveSpanQuarantine)
	rec.Body().SetStr(r.prompt())
	r.liveOverLimitAttributes(rec.Attributes())
	return ld
}

// mainMetrics holds a gauge, a monotonic delta sum with an exemplar on the
// chat span, and a histogram with an exemplar on the same span.
func (r *liveIssuesRun) mainMetrics() pmetric.Metrics {
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", r.svcMain)
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("it-issues-scope")
	start, now := r.ts(-time.Second), r.ts(200*time.Millisecond)

	gauge := sm.Metrics().AppendEmpty()
	gauge.SetName("gen_ai.client.active_requests")
	gauge.SetUnit("{request}")
	gp := gauge.SetEmptyGauge().DataPoints().AppendEmpty()
	gp.SetTimestamp(now)
	gp.SetDoubleValue(2.5)
	gp.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")

	usage := sm.Metrics().AppendEmpty()
	usage.SetName("gen_ai.client.token.usage")
	usage.SetUnit("{token}")
	sum := usage.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	sum.SetIsMonotonic(true)
	sp := sum.DataPoints().AppendEmpty()
	sp.SetStartTimestamp(start)
	sp.SetTimestamp(now)
	sp.SetIntValue(15)
	sp.Attributes().PutStr("gen_ai.system", "gcp.vertex.agent")
	sp.Attributes().PutStr("gen_ai.token.type", "input")
	sp.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	sex := sp.Exemplars().AppendEmpty()
	sex.SetTimestamp(now)
	sex.SetIntValue(15)
	sex.SetTraceID(liveTraceMain)
	sex.SetSpanID(liveSpanChat)

	duration := sm.Metrics().AppendEmpty()
	duration.SetName("gen_ai.client.operation.duration")
	duration.SetUnit("s")
	hist := duration.SetEmptyHistogram()
	hist.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	hp := hist.DataPoints().AppendEmpty()
	hp.SetStartTimestamp(start)
	hp.SetTimestamp(now)
	hp.SetCount(3)
	hp.SetSum(0.9)
	hp.SetMin(0.1)
	hp.SetMax(0.5)
	hp.ExplicitBounds().FromRaw([]float64{0.1, 0.25, 0.5})
	hp.BucketCounts().FromRaw([]uint64{1, 1, 1, 0})
	hp.Attributes().PutStr("gen_ai.operation.name", "chat")
	hp.Attributes().PutStr("gen_ai.request.model", "gemini-2.5-pro")
	histEx := hp.Exemplars().AppendEmpty()
	histEx.SetTimestamp(now)
	histEx.SetDoubleValue(0.5)
	histEx.SetTraceID(liveTraceMain)
	histEx.SetSpanID(liveSpanChat)
	return md
}

// liveQuery runs a parameterized query and returns every row.
func (r *liveIssuesRun) liveQuery(ctx context.Context, sql string, params ...bq.QueryParameter) ([][]bq.Value, error) {
	q := r.admin.Query(sql)
	q.Parameters = params
	it, err := q.Read(ctx)
	if err != nil {
		return nil, err
	}
	var out [][]bq.Value
	for {
		var row []bq.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		out = append(out, row)
	}
}

func (r *liveIssuesRun) mustQuery(ctx context.Context, t *testing.T, sql string, params ...bq.QueryParameter) [][]bq.Value {
	t.Helper()
	rows, err := r.liveQuery(ctx, sql, params...)
	if err != nil {
		t.Fatalf("query failed: %v\nSQL:\n%s", err, sql)
	}
	return rows
}

// table returns the backquoted path of a table or view in the run's dataset.
func (r *liveIssuesRun) table(name string) string {
	return "`" + r.project + "." + r.dataset + "." + name + "`"
}

// waitForCount polls a single-value COUNT query until it returns want, and
// fails at once if it overshoots.
func (r *liveIssuesRun) waitForCount(ctx context.Context, t *testing.T, label, sql string, want int64, params ...bq.QueryParameter) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var got int64
	for {
		rows, err := r.liveQuery(ctx, sql, params...)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if len(rows) == 1 && len(rows[0]) == 1 {
			got, _ = rows[0][0].(int64)
		}
		if got == want {
			return
		}
		if got > want {
			t.Fatalf("%s = %d, want %d", label, got, want)
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("%s = %d after waiting, want %d", label, got, want)
		}
		time.Sleep(time.Second)
	}
}

func liveParam(name string, value any) bq.QueryParameter {
	return bq.QueryParameter{Name: name, Value: value}
}

// liveRunQuery runs q to completion and returns its final status. A job that
// finished with an error returns that error.
func liveRunQuery(ctx context.Context, q *bq.Query) (*bq.Job, *bq.JobStatus, error) {
	job, err := q.Run(ctx)
	if err != nil {
		return nil, nil, err
	}
	status, err := job.Wait(ctx)
	if err != nil {
		return job, nil, err
	}
	if err := status.Err(); err != nil {
		return job, status, err
	}
	return job, status, nil
}

func (r *liveIssuesRun) checkDedupCounts(ctx context.Context, t *testing.T) {
	svc := liveParam("svc", r.svcMain)
	for _, c := range []struct {
		table      string
		base, uniq int64
	}{
		{"otel_spans", 6, 3},
		{"otel_logs", 2, 1},
		{"otel_metrics", 6, 3},
	} {
		r.waitForCount(ctx, t, c.table+" rows",
			"SELECT COUNT(*) FROM "+r.table(c.table)+" WHERE service_name = @svc", c.base, svc)
		r.waitForCount(ctx, t, c.table+"_dedup rows",
			"SELECT COUNT(*) FROM "+r.table(c.table+"_dedup")+" WHERE service_name = @svc", c.uniq, svc)
	}
	r.waitForCount(ctx, t, "otel_quarantine rows",
		"SELECT COUNT(*) FROM "+r.table("otel_quarantine")+" WHERE service_name = @svc", 2,
		liveParam("svc", r.svcQuarantine))
}

func liveRowsEqual(got [][]bq.Value, want [][]any) bool {
	return fmt.Sprint(got) == fmt.Sprint(want)
}

func (r *liveIssuesRun) checkRoundTrip(ctx context.Context, t *testing.T) {
	offloaded := int64(0)
	if r.bucket != "" {
		offloaded = 1
	}
	svc := liveParam("svc", r.svcMain)
	spans := r.mustQuery(ctx, t, `
		SELECT span_id, IFNULL(parent_span_id, ''), name, kind, status.code, duration_nano,
			JSON_VALUE(attributes, '$."gen_ai.request.model"'),
			LAX_INT64(attributes['gen_ai.usage.input_tokens']),
			LAX_INT64(attributes['gen_ai.usage.output_tokens']),
			JSON_VALUE(attributes, '$.api_key'),
			ARRAY_LENGTH(object_refs)
		FROM `+r.table("otel_spans_dedup")+`
		WHERE service_name = @svc
		ORDER BY span_id`, svc)
	wantSpans := [][]any{
		{liveHex(liveSpanChat[:]), "", "chat gemini-2.5-pro", int64(ptrace.SpanKindClient), int64(ptrace.StatusCodeOk), int64(250 * time.Millisecond),
			"gemini-2.5-pro", int64(10), int64(5), "[REDACTED]", offloaded},
		{liveHex(liveSpanAgent[:]), "", "invoke_agent planner", int64(ptrace.SpanKindInternal), int64(ptrace.StatusCodeOk), int64(890 * time.Millisecond),
			nil, int64(8), int64(4), nil, int64(0)},
		{liveHex(liveSpanAgentChat[:]), liveHex(liveSpanAgent[:]), "chat gemini-2.5-flash", int64(ptrace.SpanKindInternal), int64(ptrace.StatusCodeOk), int64(780 * time.Millisecond),
			"gemini-2.5-flash", int64(8), int64(4), nil, int64(0)},
	}
	if !liveRowsEqual(spans, wantSpans) {
		t.Errorf("otel_spans_dedup rows =\n%v\nwant\n%v", spans, wantSpans)
	}

	logs := r.mustQuery(ctx, t, `
		SELECT event_name, trace_id, span_id, severity_number, timestamp_source,
			JSON_VALUE(attributes, '$.api_key'), ARRAY_LENGTH(object_refs)
		FROM `+r.table("otel_logs_dedup")+`
		WHERE service_name = @svc`, svc)
	wantLogs := [][]any{{"gen_ai.user.message", liveHex(liveTraceMain[:]), liveHex(liveSpanChat[:]), int64(plog.SeverityNumberInfo),
		schema.TimestampSourceEvent, "[REDACTED]", offloaded}}
	if !liveRowsEqual(logs, wantLogs) {
		t.Errorf("otel_logs_dedup rows =\n%v\nwant\n%v", logs, wantLogs)
	}

	metrics := r.mustQuery(ctx, t, `
		SELECT metric_name, metric_type, IFNULL(value_type, ''), value_int64, value_double,
			count, sum, min, max, TO_JSON_STRING(explicit_bounds), TO_JSON_STRING(bucket_counts),
			IFNULL(aggregation_temporality, ''), ARRAY_LENGTH(exemplars),
			(SELECT ANY_VALUE(e.span_id) FROM UNNEST(exemplars) AS e),
			(SELECT ANY_VALUE(COALESCE(e.value_double, CAST(e.value_int64 AS FLOAT64))) FROM UNNEST(exemplars) AS e)
		FROM `+r.table("otel_metrics_dedup")+`
		WHERE service_name = @svc
		ORDER BY metric_name`, svc)
	chat := liveHex(liveSpanChat[:])
	wantMetrics := [][]any{
		{"gen_ai.client.active_requests", "GAUGE", "DOUBLE", nil, 2.5, nil, nil, nil, nil, "[]", "[]", "", int64(0), nil, nil},
		{"gen_ai.client.operation.duration", "HISTOGRAM", "", nil, nil, int64(3), 0.9, 0.1, 0.5, "[0.1,0.25,0.5]", "[1,1,1,0]", "DELTA", int64(1), chat, 0.5},
		{"gen_ai.client.token.usage", "SUM", "INT64", int64(15), nil, nil, nil, nil, nil, "[]", "[]", "DELTA", int64(1), chat, float64(15)},
	}
	if !liveRowsEqual(metrics, wantMetrics) {
		t.Errorf("otel_metrics_dedup rows =\n%v\nwant\n%v", metrics, wantMetrics)
	}

	if r.bucket == "" {
		inline := r.mustQuery(ctx, t, "SELECT JSON_VALUE(attributes, '$.\"gen_ai.prompt\"') FROM "+r.table("otel_spans_dedup")+
			" WHERE span_id = @span", liveParam("span", chat))
		if len(inline) != 1 || inline[0][0] != r.redactedPrompt() {
			t.Errorf("inline gen_ai.prompt = %v, want the redacted prompt", inline)
		}
		return
	}
	fetcher, closeFetcher, err := quarantinereplay.NewGCSObjectFetcher(ctx)
	if err != nil {
		t.Fatalf("NewGCSObjectFetcher: %v", err)
	}
	defer closeFetcher()
	for _, c := range []struct {
		table, where string
		params       []bq.QueryParameter
	}{
		{"otel_spans_dedup", "span_id = @id", []bq.QueryParameter{liveParam("id", chat)}},
		{"otel_logs_dedup", "service_name = @id", []bq.QueryParameter{liveParam("id", r.svcMain)}},
	} {
		refs := r.mustQuery(ctx, t, `
			SELECT o.uri, o.version, IF(o.details IS NULL, '', TO_JSON_STRING(o.details))
			FROM `+r.table(c.table)+`, UNNEST(object_refs) AS o
			WHERE `+c.where, c.params...)
		if len(refs) != 1 {
			t.Errorf("%s object_refs = %v, want one offloaded payload", c.table, refs)
			continue
		}
		ref := refs[0]
		want := r.redactedPrompt()
		sum := sha256.Sum256([]byte(want))
		wantHex := hex.EncodeToString(sum[:])
		uri, _ := ref[0].(string)
		version, _ := ref[1].(string)
		details, _ := ref[2].(string)
		if !strings.HasSuffix(uri, "/"+wantHex) || !strings.Contains(details, fmt.Sprintf(`"size":%d`, len(want))) {
			t.Errorf("%s object_refs[0] = (uri=%q, details=%q), want content-addressed uri suffix /%s and size %d",
				c.table, uri, details, wantHex, len(want))
		}
		blob, err := fetcher(ctx, uri+"?generation="+version)
		if err != nil {
			t.Errorf("fetch %s generation %s: %v", uri, version, err)
			continue
		}
		if string(blob) != want {
			t.Errorf("%s offloaded object %s = %q, want the exact redacted prompt", c.table, uri, blob)
		}
	}
}

// checkZstdArrowRead reads exporter-written rows back through the BigQuery
// Storage Read API with ZSTD buffer compression. The Arrow IPC reader the
// BigQuery client links decodes those buffers with klauspost/compress, the
// module the vulnerability fix upgraded, so this exercises the upgraded
// decoder on real service traffic rather than on a fixture.
func (r *liveIssuesRun) checkZstdArrowRead(ctx context.Context, t *testing.T) {
	assertLinkedModuleAtLeast(t, "github.com/klauspost/compress", 1, 20, 2)

	const replicas = 4000
	probe := "it_zstd_probe"
	// Replicating the three metric points gives the service enough
	// repetitive column data that ZSTD visibly shrinks the batches.
	ctas := fmt.Sprintf(`
		CREATE TABLE %s AS
		SELECT m.metric_name, m.point_fingerprint,
			COALESCE(m.value_int64, 0) AS value_int64,
			COALESCE(m.value_double, 0) + COALESCE(m.sum, 0) AS value_double,
			n AS replica
		FROM %s AS m, UNNEST(GENERATE_ARRAY(1, %d)) AS n
		WHERE m.service_name = '%s'`, r.table(probe), r.table("otel_metrics_dedup"), replicas, r.svcMain)
	if _, _, err := liveRunQuery(ctx, r.admin.Query(ctas)); err != nil {
		t.Fatalf("create %s: %v", probe, err)
	}
	want := r.mustQuery(ctx, t, "SELECT COUNT(*), SUM(value_int64), SUM(value_double), COUNT(DISTINCT metric_name) FROM "+r.table(probe))
	wantRows, _ := want[0][0].(int64)
	wantInt, _ := want[0][1].(int64)
	wantDouble, _ := want[0][2].(float64)
	if wantRows != 3*replicas || wantInt != 15*replicas || math.Abs(wantDouble-3.4*replicas) > 1e-6 {
		t.Fatalf("%s holds rows=%d sum_int=%d sum_double=%f, want %d, %d, %f", probe, wantRows, wantInt, wantDouble, 3*replicas, 15*replicas, 3.4*replicas)
	}

	rc, err := bqstorage.NewBigQueryReadClient(ctx)
	if err != nil {
		t.Fatalf("create Storage Read client: %v", err)
	}
	defer func() {
		if err := rc.Close(); err != nil {
			t.Errorf("close Storage Read client: %v", err)
		}
	}()
	got := map[storagepb.ArrowSerializationOptions_CompressionCodec]liveArrowTotals{}
	for _, codec := range []storagepb.ArrowSerializationOptions_CompressionCodec{
		storagepb.ArrowSerializationOptions_ZSTD,
		storagepb.ArrowSerializationOptions_COMPRESSION_UNSPECIFIED,
	} {
		totals, err := liveArrowReadTable(ctx, rc, r.project, r.dataset, probe, codec)
		if err != nil {
			t.Fatalf("Storage Read API %s read of %s: %v", codec, probe, err)
		}
		got[codec] = totals
		t.Logf("Storage Read API %s: %d rows in %d batches, %d serialized bytes", codec, totals.rows, totals.batches, totals.wireBytes)
		if totals.rows != wantRows || totals.sumInt != wantInt || math.Abs(totals.sumDouble-wantDouble) > 1e-6 || int64(len(totals.names)) != want[0][3] {
			t.Errorf("%s decode = rows %d, sum_int %d, sum_double %f, %d metric names; want %d, %d, %f, %v",
				codec, totals.rows, totals.sumInt, totals.sumDouble, len(totals.names), wantRows, wantInt, wantDouble, want[0][3])
		}
	}
	zstd, plain := got[storagepb.ArrowSerializationOptions_ZSTD], got[storagepb.ArrowSerializationOptions_COMPRESSION_UNSPECIFIED]
	if zstd.wireBytes <= 0 || zstd.wireBytes >= plain.wireBytes {
		t.Errorf("ZSTD batches = %d bytes, uncompressed = %d bytes; want ZSTD smaller, proving the service compressed what the decoder read",
			zstd.wireBytes, plain.wireBytes)
	}
}

// assertLinkedModuleAtLeast fails unless the test binary links module at
// version vMAJOR.MINOR.PATCH or later.
func assertLinkedModuleAtLeast(t *testing.T, module string, major, minor, patch int) {
	t.Helper()
	info, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatal("debug.ReadBuildInfo: no build information in the test binary")
	}
	for _, dep := range info.Deps {
		if dep.Path != module {
			continue
		}
		if dep.Replace != nil {
			dep = dep.Replace
		}
		var got [3]int
		if _, err := fmt.Sscanf(dep.Version, "v%d.%d.%d", &got[0], &got[1], &got[2]); err != nil {
			t.Fatalf("%s version %q: %v", module, dep.Version, err)
		}
		if slices.Compare(got[:], []int{major, minor, patch}) < 0 {
			t.Fatalf("test binary links %s %s, want v%d.%d.%d or later", module, dep.Version, major, minor, patch)
		}
		t.Logf("test binary links %s %s", module, dep.Version)
		return
	}
	t.Fatalf("test binary does not link %s", module)
}

type liveArrowTotals struct {
	rows, batches, wireBytes int64
	sumInt                   int64
	sumDouble                float64
	names                    map[string]bool
}

func liveArrowReadTable(ctx context.Context, rc *bqstorage.BigQueryReadClient, project, dataset, table string, codec storagepb.ArrowSerializationOptions_CompressionCodec) (liveArrowTotals, error) {
	totals := liveArrowTotals{names: map[string]bool{}}
	session, err := rc.CreateReadSession(ctx, &storagepb.CreateReadSessionRequest{
		Parent: "projects/" + project,
		ReadSession: &storagepb.ReadSession{
			Table:      fmt.Sprintf("projects/%s/datasets/%s/tables/%s", project, dataset, table),
			DataFormat: storagepb.DataFormat_ARROW,
			ReadOptions: &storagepb.ReadSession_TableReadOptions{
				SelectedFields: []string{"metric_name", "value_int64", "value_double"},
				OutputFormatSerializationOptions: &storagepb.ReadSession_TableReadOptions_ArrowSerializationOptions{
					ArrowSerializationOptions: &storagepb.ArrowSerializationOptions{BufferCompression: codec},
				},
			},
		},
		MaxStreamCount: 1,
	})
	if err != nil {
		return totals, fmt.Errorf("create read session: %w", err)
	}
	schemaBytes := session.GetArrowSchema().GetSerializedSchema()
	if len(schemaBytes) == 0 {
		return totals, errors.New("read session has no Arrow schema")
	}
	for _, stream := range session.GetStreams() {
		rows, err := rc.ReadRows(ctx, &storagepb.ReadRowsRequest{ReadStream: stream.GetName()})
		if err != nil {
			return totals, fmt.Errorf("read rows: %w", err)
		}
		for {
			resp, err := rows.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				return totals, fmt.Errorf("receive rows: %w", err)
			}
			batch := resp.GetArrowRecordBatch().GetSerializedRecordBatch()
			totals.wireBytes += int64(len(batch))
			totals.batches++
			decoded, err := liveDecodeArrowBatch(schemaBytes, batch, &totals)
			if err != nil {
				return totals, err
			}
			if decoded != resp.GetRowCount() {
				return totals, fmt.Errorf("decoded %d rows from a batch the service counted as %d", decoded, resp.GetRowCount())
			}
		}
	}
	return totals, nil
}

func liveDecodeArrowBatch(schemaBytes, batch []byte, totals *liveArrowTotals) (int64, error) {
	stream := make([]byte, 0, len(schemaBytes)+len(batch))
	stream = append(append(stream, schemaBytes...), batch...)
	reader, err := ipc.NewReader(bytes.NewReader(stream))
	if err != nil {
		return 0, fmt.Errorf("open Arrow IPC stream: %w", err)
	}
	defer reader.Release()
	var decoded int64
	for reader.Next() {
		rec := reader.Record()
		cols := map[string]arrow.Array{}
		for i, f := range rec.Schema().Fields() {
			cols[f.Name] = rec.Column(i)
		}
		names, okNames := cols["metric_name"].(*array.String)
		ints, okInts := cols["value_int64"].(*array.Int64)
		doubles, okDoubles := cols["value_double"].(*array.Float64)
		if !okNames || !okInts || !okDoubles {
			return decoded, fmt.Errorf("unexpected Arrow column types in %v", rec.Schema())
		}
		for i := 0; i < int(rec.NumRows()); i++ {
			if !names.IsNull(i) {
				totals.names[names.Value(i)] = true
			}
			if !ints.IsNull(i) {
				totals.sumInt += ints.Value(i)
			}
			if !doubles.IsNull(i) {
				totals.sumDouble += doubles.Value(i)
			}
		}
		decoded += rec.NumRows()
	}
	if err := reader.Err(); err != nil {
		return decoded, fmt.Errorf("decode Arrow record batch: %w", err)
	}
	totals.rows += decoded
	return decoded, nil
}

// liveTelemetryMetadata is the telemetry part of metadata.yaml.
type liveTelemetryMetadata struct {
	Telemetry struct {
		Metrics map[string]struct {
			Unit string `yaml:"unit"`
			Sum  *struct {
				ValueType string `yaml:"value_type"`
				Monotonic bool   `yaml:"monotonic"`
			} `yaml:"sum"`
			Gauge *struct {
				ValueType string `yaml:"value_type"`
			} `yaml:"gauge"`
			Histogram *struct {
				ValueType        string    `yaml:"value_type"`
				BucketBoundaries []float64 `yaml:"bucket_boundaries"`
			} `yaml:"histogram"`
			Attributes []string `yaml:"attributes"`
		} `yaml:"metrics"`
	} `yaml:"telemetry"`
	Attributes map[string]struct {
		Enum []string `yaml:"enum"`
	} `yaml:"attributes"`
}

// checkSelfTelemetry collects what the exporters recorded during the live
// traffic and checks every emitted instrument against metadata.yaml, then
// checks the values the traffic must have produced.
func (r *liveIssuesRun) checkSelfTelemetry(ctx context.Context, t *testing.T, reader *sdkmetric.ManualReader) {
	raw, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatalf("read metadata.yaml: %v", err)
	}
	var md liveTelemetryMetadata
	if err := yaml.Unmarshal(raw, &md); err != nil {
		t.Fatalf("parse metadata.yaml: %v", err)
	}
	if len(md.Telemetry.Metrics) == 0 {
		t.Fatal("metadata.yaml declares no telemetry metrics")
	}
	for _, gauge := range []string{"otelcol_exporter_bigquery_inflight_requests", "otelcol_exporter_bigquery_unresolved_results"} {
		if err := waitForZeroGauge(ctx, t, reader, gauge); err != nil {
			t.Error(err)
		}
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect self-telemetry: %v", err)
	}

	// sums maps instrument -> attribute set -> int value.
	sums := map[string]map[string]int64{}
	histCounts := map[string]uint64{}
	floatGauges := map[string][]float64{}
	intGauges := map[string][]int64{}
	emitted := map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		if sm.Scope.Name != metadata.ScopeName {
			t.Errorf("instrumentation scope %q, want %q", sm.Scope.Name, metadata.ScopeName)
		}
		for _, m := range sm.Metrics {
			emitted[m.Name] = true
			decl, ok := md.Telemetry.Metrics[m.Name]
			if !ok {
				t.Errorf("emitted %s, which metadata.yaml does not declare", m.Name)
				continue
			}
			if m.Unit != decl.Unit {
				t.Errorf("%s unit = %q, metadata.yaml declares %q", m.Name, m.Unit, decl.Unit)
			}
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				if decl.Sum == nil || decl.Sum.ValueType != "int" || decl.Sum.Monotonic != data.IsMonotonic {
					t.Errorf("%s is an int64 sum (monotonic=%t), metadata.yaml declares %+v", m.Name, data.IsMonotonic, decl)
				}
				sums[m.Name] = map[string]int64{}
				for _, dp := range data.DataPoints {
					key := liveCheckAttributes(t, m.Name, dp.Attributes.ToSlice(), decl.Attributes, md, r.secret)
					sums[m.Name][key] += dp.Value
				}
			case metricdata.Histogram[float64]:
				if decl.Histogram == nil || decl.Histogram.ValueType != "double" {
					t.Errorf("%s is a float64 histogram, metadata.yaml declares %+v", m.Name, decl)
				}
				for _, dp := range data.DataPoints {
					liveCheckAttributes(t, m.Name, dp.Attributes.ToSlice(), decl.Attributes, md, r.secret)
					if decl.Histogram != nil && !slices.Equal(dp.Bounds, decl.Histogram.BucketBoundaries) {
						t.Errorf("%s bounds = %v, metadata.yaml declares %v", m.Name, dp.Bounds, decl.Histogram.BucketBoundaries)
					}
					histCounts[m.Name] += dp.Count
				}
			case metricdata.Gauge[float64]:
				if decl.Gauge == nil || decl.Gauge.ValueType != "double" {
					t.Errorf("%s is a float64 gauge, metadata.yaml declares %+v", m.Name, decl)
				}
				for _, dp := range data.DataPoints {
					liveCheckAttributes(t, m.Name, dp.Attributes.ToSlice(), decl.Attributes, md, r.secret)
					floatGauges[m.Name] = append(floatGauges[m.Name], dp.Value)
				}
			case metricdata.Gauge[int64]:
				if decl.Gauge == nil || decl.Gauge.ValueType != "int" {
					t.Errorf("%s is an int64 gauge, metadata.yaml declares %+v", m.Name, decl)
				}
				for _, dp := range data.DataPoints {
					liveCheckAttributes(t, m.Name, dp.Attributes.ToSlice(), decl.Attributes, md, r.secret)
					intGauges[m.Name] = append(intGauges[m.Name], dp.Value)
				}
			default:
				t.Errorf("%s has unexpected data type %T", m.Name, m.Data)
			}
		}
	}

	total := func(name string) int64 {
		var n int64
		for _, v := range sums[name] {
			n += v
		}
		return n
	}
	const p = "otelcol_exporter_bigquery_"
	// 3 spans, 1 log, and 3 metric points, each sent twice.
	wantAcked := int64(14)
	if total(p+"retries") == 0 && total(p+"uncertain_ack_replays") == 0 {
		if got := total(p + "acknowledged_rows"); got != wantAcked {
			t.Errorf("acknowledged_rows = %d, want %d", got, wantAcked)
		}
	} else if got := total(p + "acknowledged_rows"); got < wantAcked {
		t.Errorf("acknowledged_rows = %d with retries, want at least %d", got, wantAcked)
	}
	for _, c := range []struct {
		name, attrs string
		want        int64
	}{
		{p + "rejected_rows", "reason=attribute_count", 2},
		{p + "quarantined_rows", "reason=attribute_count", 2},
	} {
		if got := sums[c.name][c.attrs]; got != c.want {
			t.Errorf("%s{%s} = %d, want %d (all points: %v)", c.name, c.attrs, got, c.want, sums[c.name])
		}
	}
	if got := total(p + "quarantine_failed_rows"); got != 0 {
		t.Errorf("quarantine_failed_rows = %d, want 0", got)
	}
	for _, name := range []string{p + "append_bytes"} {
		if got := total(name); got <= 0 {
			t.Errorf("%s = %d, want > 0", name, got)
		}
	}
	for _, matchType := range []string{"key", "value"} {
		var n int64
		for attrs, v := range sums[p+"redacted_values"] {
			if strings.Contains(attrs, "match_type="+matchType) {
				n += v
			}
		}
		if n <= 0 {
			t.Errorf("redacted_values{match_type=%s} = %d, want > 0 (all points: %v)", matchType, n, sums[p+"redacted_values"])
		}
	}
	if histCounts[p+"append_result_wait"] == 0 {
		t.Errorf("append_result_wait recorded no samples")
	}
	if !emitted[p+"inflight_requests"] {
		t.Errorf("inflight_requests was not emitted, although every append passes through it")
	}
	// unresolved_results moves only when an attempt ends before its result,
	// so with no timeouts it may never be recorded; either way every attribute
	// series must settle at 0.
	for _, name := range []string{p + "inflight_requests", p + "unresolved_results"} {
		for attrs, got := range sums[name] {
			if got != 0 {
				t.Errorf("%s{%s} = %d after the traffic settled, want 0", name, attrs, got)
			}
		}
	}
	if values := intGauges[p+"effective_request_bytes"]; len(values) != 3 || slices.Min(values) <= 0 {
		t.Errorf("effective_request_bytes = %v, want one positive value per signal writer", values)
	}
	if values := floatGauges[p+"backpressure_level"]; len(values) != 3 || slices.Min(values) < 0 || slices.Max(values) > 1 {
		t.Errorf("backpressure_level = %v, want one value in [0, 1] per signal writer", values)
	}
	if r.bucket != "" {
		for _, name := range []string{p + "offloaded_payloads", p + "offloaded_bytes"} {
			if got := total(name); got <= 0 {
				t.Errorf("%s = %d, want > 0", name, got)
			}
		}
		if got := total(p + "offload_errors"); got != 0 {
			t.Errorf("offload_errors = %d, want 0 (%v)", got, sums[p+"offload_errors"])
		}
	}
	var declared []string
	for name := range md.Telemetry.Metrics {
		if !emitted[name] {
			declared = append(declared, name)
		}
	}
	slices.Sort(declared)
	t.Logf("self-telemetry: %d of %d declared instruments emitted; not emitted by this traffic: %v", len(emitted), len(md.Telemetry.Metrics), declared)
}

// liveCheckAttributes checks one data point's attribute set against the
// declared attribute keys and their enumerations, and returns the set as a
// sorted key=value string.
func liveCheckAttributes(t *testing.T, name string, kvs []attribute.KeyValue, declared []string, md liveTelemetryMetadata, secret string) string {
	t.Helper()
	var keys, pairs []string
	for _, kv := range kvs {
		key, value := string(kv.Key), kv.Value.String()
		keys = append(keys, key)
		pairs = append(pairs, key+"="+value)
		if strings.Contains(value, secret) {
			t.Errorf("%s attribute %s carries telemetry content", name, key)
		}
		if enum := md.Attributes[key].Enum; len(enum) > 0 && !slices.Contains(enum, value) {
			t.Errorf("%s attribute %s=%q is outside the declared enumeration %v", name, key, value, enum)
		}
	}
	slices.Sort(keys)
	slices.Sort(pairs)
	want := slices.Clone(declared)
	slices.Sort(want)
	if !slices.Equal(keys, want) {
		t.Errorf("%s data point attributes %v, metadata.yaml declares %v", name, keys, want)
	}
	return strings.Join(pairs, ",")
}

func checkRetiredKeyWarning(t *testing.T, observed *observer.ObservedLogs) {
	entries := observed.FilterMessageSnippet(`"` + liveIssuesRetiredLimitKey.OldPath + `" is deprecated`).All()
	if len(entries) != 1 {
		t.Fatalf("deprecation warnings for %s = %d, want exactly 1 across the three exporters", liveIssuesRetiredLimitKey.OldPath, len(entries))
	}
	entry := entries[0]
	if entry.Level != zapcore.WarnLevel {
		t.Errorf("deprecation log level = %v, want WARN", entry.Level)
	}
	link := migrationGuideURL + "#" + liveIssuesRetiredLimitKey.Anchor
	if !strings.Contains(entry.Message, link) {
		t.Errorf("deprecation warning %q does not link %s", entry.Message, link)
	}
	fields := entry.ContextMap()
	if fields["replacement_key"] != liveIssuesRetiredLimitKey.NewPath || fields["migration_guide"] != link {
		t.Errorf("deprecation warning fields = %v, want replacement_key %s and migration_guide %s", fields, liveIssuesRetiredLimitKey.NewPath, link)
	}
}

func (r *liveIssuesRun) checkCompanionViews(ctx context.Context, t *testing.T) {
	svc := liveParam("svc", r.svcMain)
	chat, agent, child := liveHex(liveSpanChat[:]), liveHex(liveSpanAgent[:]), liveHex(liveSpanAgentChat[:])
	convA, convB := "conv-"+r.runID+"-a", "conv-"+r.runID+"-b"
	for _, c := range []struct {
		name string
		sql  string
		want [][]any
	}{
		{
			name: schema.GenAISpansViewName,
			sql: `SELECT span_name, gen_ai_operation_name, gen_ai_request_model, gen_ai_usage_input_tokens,
				gen_ai_usage_output_tokens, gen_ai_conversation_id, gen_ai_tool_name
				FROM ` + r.table(schema.GenAISpansViewName) + ` WHERE service_name = @svc ORDER BY span_id`,
			want: [][]any{
				{"chat gemini-2.5-pro", "chat", "gemini-2.5-pro", int64(10), int64(5), convA, "search"},
				{"invoke_agent planner", "invoke_agent", nil, int64(8), int64(4), convB, nil},
				{"chat gemini-2.5-flash", "chat", "gemini-2.5-flash", int64(8), int64(4), convB, nil},
			},
		},
		{
			// The agent span reports the sum of its child's tokens, so only
			// the two chat spans count as calls, each once despite the replay.
			name: schema.GenAIModelCostsViewName,
			sql: `SELECT model, SUM(call_count), SUM(total_input_tokens), SUM(total_output_tokens)
				FROM ` + r.table(schema.GenAIModelCostsViewName) + ` WHERE service_name = @svc GROUP BY model ORDER BY model`,
			want: [][]any{
				{"gemini-2.5-flash", int64(1), int64(8), int64(4)},
				{"gemini-2.5-pro", int64(1), int64(10), int64(5)},
			},
		},
		{
			name: schema.MCPSpansViewName,
			sql: `SELECT span_id, mcp_method_name, is_tool_call, also_in_gen_ai_view, gen_ai_tool_name
				FROM ` + r.table(schema.MCPSpansViewName) + ` WHERE service_name = @svc`,
			want: [][]any{{chat, "tools/call", true, true, "search"}},
		},
		{
			name: schema.MCPToolUsageViewName,
			sql: `SELECT SUM(call_count), SUM(gen_ai_tagged_call_count)
				FROM ` + r.table(schema.MCPToolUsageViewName) + ` WHERE service_name = @svc`,
			want: [][]any{{int64(1), int64(1)}},
		},
		{
			// The session id comes from the joined chat span: the log
			// record carries none of its own.
			name: schema.GenAILogsViewName,
			sql: `SELECT event_name, gen_ai_system, adk_session_id, trace_id, span_id
				FROM ` + r.table(schema.GenAILogsViewName) + ` WHERE service_name = @svc`,
			want: [][]any{{"gen_ai.user.message", "gcp.vertex.agent", convA, liveHex(liveTraceMain[:]), chat}},
		},
		{
			name: schema.GenAIMetricsViewName,
			sql: `SELECT metric_name FROM ` + r.table(schema.GenAIMetricsViewName) + `
				WHERE service_name = @svc ORDER BY metric_name`,
			want: [][]any{{"gen_ai.client.active_requests"}, {"gen_ai.client.operation.duration"}, {"gen_ai.client.token.usage"}},
		},
		{
			name: schema.GenAIMetricExemplarsViewName,
			sql: `SELECT metric_name, span_name, exemplar_value_int64, exemplar_value_double
				FROM ` + r.table(schema.GenAIMetricExemplarsViewName) + ` WHERE service_name = @svc ORDER BY metric_name`,
			want: [][]any{
				{"gen_ai.client.operation.duration", "chat gemini-2.5-pro", nil, 0.5},
				{"gen_ai.client.token.usage", "chat gemini-2.5-pro", int64(15), nil},
			},
		},
		{
			name: schema.GenAIAgentTrajectoryViewName,
			sql: `SELECT span_id, depth, root_span_id, IFNULL(nearest_agent_name, ''), is_orphan, is_leaf
				FROM ` + r.table(schema.GenAIAgentTrajectoryViewName) + ` WHERE service_name = @svc ORDER BY span_id`,
			want: [][]any{
				{chat, int64(0), chat, "", false, true},
				{agent, int64(0), agent, "planner", false, false},
				{child, int64(1), agent, "planner", false, true},
			},
		},
		{
			name: schema.GenAIAgentTrajectoryTVFName,
			sql: `SELECT span_id, depth, root_span_id, IFNULL(nearest_agent_name, ''), is_orphan, step_index, is_leaf, is_token_leaf
				FROM ` + r.table(schema.GenAIAgentTrajectoryTVFName) + `(
					TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 MINUTE), TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 30 MINUTE),
					TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 25 HOUR), TIMESTAMP_ADD(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR))
				WHERE service_name = @svc ORDER BY span_id`,
			want: [][]any{
				{chat, int64(0), chat, "", false, int64(1), true, true},
				{agent, int64(0), agent, "planner", false, int64(1), false, false},
				{child, int64(1), agent, "planner", false, int64(2), true, true},
			},
		},
	} {
		if c.name == schema.GenAIAgentTrajectoryTVFName {
			// The table functions are operator-run DDL, not auto-created.
			ddl, ok := schema.CompanionTVFDDLs(r.project, r.dataset, "otel_spans", "otel_logs")[c.name]
			if !ok {
				t.Fatalf("no DDL for %s", c.name)
			}
			if _, _, err := liveRunQuery(ctx, r.admin.Query(ddl)); err != nil {
				t.Fatalf("create %s: %v", c.name, err)
			}
		}
		start := time.Now()
		q := r.admin.Query(c.sql)
		q.Parameters = []bq.QueryParameter{svc}
		job, status, err := liveRunQuery(ctx, q)
		if err != nil {
			t.Errorf("%s query: %v", c.name, err)
			continue
		}
		var slotMillis int64
		if qs, ok := status.Statistics.Details.(*bq.QueryStatistics); ok && qs != nil {
			slotMillis = qs.SlotMillis
		}
		t.Logf("%s: %.1fs wall, %d slot-ms, %d bytes processed", c.name, time.Since(start).Seconds(), slotMillis, status.Statistics.TotalBytesProcessed)
		it, err := job.Read(ctx)
		if err != nil {
			t.Errorf("%s read: %v", c.name, err)
			continue
		}
		var got [][]bq.Value
		for {
			var row []bq.Value
			err := it.Next(&row)
			if errors.Is(err, iterator.Done) {
				break
			}
			if err != nil {
				t.Errorf("%s next: %v", c.name, err)
				break
			}
			got = append(got, row)
		}
		if !liveRowsEqual(got, c.want) {
			t.Errorf("%s rows =\n%v\nwant\n%v", c.name, got, c.want)
		}
	}
}

// checkSchemaContract compares each live table with the compiled contract
// the encoder writes against, field by field, and checks the version every
// row carries.
func (r *liveIssuesRun) checkSchemaContract(ctx context.Context, t *testing.T) {
	for _, c := range []struct {
		table    string
		contract func() *storagepb.TableSchema
	}{
		{"otel_spans", schema.SpansTableSchema},
		{"otel_logs", schema.LogsTableSchema},
		{"otel_metrics", schema.MetricsTableSchema},
		{"otel_quarantine", schema.QuarantineTableSchema},
	} {
		md, err := r.admin.Dataset(r.dataset).Table(c.table).Metadata(ctx)
		if err != nil {
			t.Errorf("%s metadata: %v", c.table, err)
			continue
		}
		want, err := schema.ToBigQuery(c.contract())
		if err != nil {
			t.Fatalf("%s contract: %v", c.table, err)
		}
		if diff := liveSchemaDiff("", md.Schema, want); diff != "" {
			t.Errorf("live %s schema differs from the compiled contract: %s", c.table, diff)
		}
		have, err := schema.FromBigQuery(md.Schema)
		if err != nil {
			t.Errorf("%s schema does not convert back to a contract: %v", c.table, err)
		} else if diffs := schema.CompatibilityDifferences(c.contract(), have); len(diffs) > 0 {
			t.Errorf("%s compatibility differences: %v", c.table, diffs)
		}
		for k, wantLabel := range schema.ContractLabels(schema.ContractV1Candidate) {
			if got := md.Labels[k]; got != wantLabel {
				t.Errorf("%s label %s = %q, want %q", c.table, k, got, wantLabel)
			}
		}
	}
}

// checkRollupViewsPrunePartitions builds the rollup and MCP views over a
// spans table that requires a partition filter, seeds two partitions three
// days apart, and dry-runs each view with a narrow and a wide filter on the
// column its partition pruning keys on. Both filters must compile, the narrow
// one must read some bytes but fewer than the wide one, and a query without a
// filter must be rejected.
func (r *liveIssuesRun) checkRollupViewsPrunePartitions(ctx context.Context, t *testing.T) {
	const spans = "otel_spans_rpf"
	md, dedupQuery, err := schema.DestinationMetadataWithOptions(
		schema.SpansTableSchema(), r.project, r.dataset, spans, schema.DestinationOptions{RequirePartitionFilter: true})
	if err != nil {
		t.Fatalf("derive %s metadata: %v", spans, err)
	}
	if err := r.admin.Dataset(r.dataset).Table(spans).Create(ctx, md); err != nil {
		t.Fatalf("create %s: %v", spans, err)
	}
	createView := func(name, query string) {
		t.Helper()
		if err := r.admin.Dataset(r.dataset).Table(name).Create(ctx, &bq.TableMetadata{ViewQuery: query}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	// over points a view at the RPF chain instead of the exporter's views,
	// and refuses a rewrite that missed, which would test the wrong table.
	over := func(query, from, to string) string {
		t.Helper()
		rewritten := strings.ReplaceAll(query, r.table(from), r.table(to))
		if strings.Contains(rewritten, r.table(from)) || !strings.Contains(rewritten, r.table(to)) {
			t.Fatalf("rewriting %s to %s left the query reading %s", from, to, from)
		}
		return rewritten
	}
	createView(spans+"_dedup", dedupQuery)
	createView("v_gen_ai_spans_rpf", fmt.Sprintf(schema.GenAISpansViewQuery, r.project, r.dataset, spans))
	createView("v_mcp_spans_rpf", fmt.Sprintf(schema.MCPSpansViewQuery, r.project, r.dataset, spans))
	views := []struct {
		name, column string
		date         bool
	}{
		{"v_gen_ai_model_costs_rpf", "usage_hour", false},
		{"v_gen_ai_sessions_rpf", "session_start_date", true},
		{"v_gen_ai_tool_usage_rpf", "usage_hour", false},
		{"v_mcp_spans_rpf", "start_time", false},
		{"v_mcp_tool_usage_rpf", "usage_hour", false},
	}
	createView(views[0].name, over(fmt.Sprintf(schema.GenAIModelCostsViewQuery, r.project, r.dataset), schema.GenAISpansViewName, "v_gen_ai_spans_rpf"))
	createView(views[1].name, over(fmt.Sprintf(schema.GenAISessionsViewQuery, r.project, r.dataset), schema.GenAISpansViewName, "v_gen_ai_spans_rpf"))
	createView(views[2].name, over(fmt.Sprintf(schema.GenAIToolUsageViewQuery, r.project, r.dataset), schema.GenAISpansViewName, "v_gen_ai_spans_rpf"))
	createView(views[4].name, over(fmt.Sprintf(schema.MCPToolUsageViewQuery, r.project, r.dataset), schema.MCPSpansViewName, "v_mcp_spans_rpf"))

	seed := `INSERT INTO ` + r.table(spans) + ` (
			start_time, start_time_unix_nano, end_time, end_time_unix_nano,
			receive_time, receive_time_unix_nano, duration_nano,
			trace_id, span_id, name, kind, service_name, attributes)
		SELECT
			TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL age_minutes MINUTE), 1000,
			TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL age_minutes MINUTE), 2000,
			CURRENT_TIMESTAMP(), 3000, 1000, trace_id, span_id, 'chat gemini-2.5-pro', 3, 'rpf-svc',
			JSON '{"gen_ai.operation.name":"chat","gen_ai.request.model":"gemini-2.5-pro","gen_ai.conversation.id":"conv-rpf","gen_ai.tool.name":"search","mcp.method.name":"tools/call","gen_ai.usage.input_tokens":10,"gen_ai.usage.output_tokens":5}'
		FROM UNNEST([
			STRUCT(72 * 60 AS age_minutes, '0102030405060708090a0b0c0d0e0f10' AS trace_id, '0102030405060708' AS span_id),
			STRUCT(30 AS age_minutes, '1112131415161718191a1b1c1d1e1f20' AS trace_id, '1112131415161718' AS span_id)
		])`
	q := r.admin.Query(seed)
	if _, _, err := liveRunQuery(ctx, q); err != nil {
		t.Fatalf("seed two partitions of %s: %v", spans, err)
	}

	dryRunBytes := func(sql string) (int64, error) {
		q := r.admin.Query(sql)
		q.DryRun = true
		job, err := q.Run(ctx)
		if err != nil {
			return 0, err
		}
		status := job.LastStatus()
		if status == nil || status.Statistics == nil {
			return 0, errors.New("dry run returned no statistics")
		}
		if err := status.Err(); err != nil {
			return 0, err
		}
		return status.Statistics.TotalBytesProcessed, nil
	}
	for _, v := range views {
		since := func(hours int) string {
			if v.date {
				return fmt.Sprintf("DATE_SUB(CURRENT_DATE(), INTERVAL %d DAY)", (hours+23)/24)
			}
			return fmt.Sprintf("TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL %d HOUR)", hours)
		}
		query := func(hours int) string {
			return fmt.Sprintf("SELECT * FROM %s WHERE %s >= %s", r.table(v.name), v.column, since(hours))
		}
		narrow, err := dryRunBytes(query(2))
		if err != nil {
			t.Errorf("%s narrow dry run: %v", v.name, err)
			continue
		}
		wide, err := dryRunBytes(query(96))
		if err != nil {
			t.Errorf("%s wide dry run: %v", v.name, err)
			continue
		}
		t.Logf("%s: narrow %d bytes, wide %d bytes", v.name, narrow, wide)
		if narrow <= 0 || narrow >= wide {
			t.Errorf("%s pruning on %s: narrow %d bytes, wide %d bytes; want 0 < narrow < wide", v.name, v.column, narrow, wide)
		}
		_, err = dryRunBytes("SELECT * FROM " + r.table(v.name))
		if err == nil {
			t.Errorf("%s without a filter compiled, want the partition filter requirement to reject it", v.name)
		} else if msg := strings.ToLower(err.Error()); !strings.Contains(msg, "partition") || !strings.Contains(msg, "filter") {
			t.Errorf("%s without a filter failed with %v, want a partition filter rejection", v.name, err)
		}
	}
}

func liveSchemaDiff(path string, got, want bq.Schema) string {
	if len(got) != len(want) {
		var gotNames, wantNames []string
		for _, f := range got {
			gotNames = append(gotNames, f.Name)
		}
		for _, f := range want {
			wantNames = append(wantNames, f.Name)
		}
		return fmt.Sprintf("%s has fields %v, want %v", path, gotNames, wantNames)
	}
	for i := range want {
		g, w := got[i], want[i]
		name := path + "." + w.Name
		if g.Name != w.Name || g.Type != w.Type || g.Required != w.Required || g.Repeated != w.Repeated {
			return fmt.Sprintf("%s = {%s %s required=%t repeated=%t}, want {%s %s required=%t repeated=%t}",
				name, g.Name, g.Type, g.Required, g.Repeated, w.Name, w.Type, w.Required, w.Repeated)
		}
		if diff := liveSchemaDiff(name, g.Schema, w.Schema); diff != "" {
			return diff
		}
	}
	return ""
}

// liveExporterSink replays reconstructed records through live exporters.
type liveExporterSink struct {
	traces *tracesExporter
	logs   *logsExporter
}

func (s liveExporterSink) ExportTraces(ctx context.Context, td ptrace.Traces) error {
	return s.traces.pushTraceData(ctx, td)
}

func (s liveExporterSink) ExportLogs(ctx context.Context, ld plog.Logs) error {
	return s.logs.pushLogData(ctx, ld)
}

func (s liveExporterSink) ExportMetrics(context.Context, pmetric.Metrics) error {
	return errors.New("no metric was quarantined, so none should replay")
}

// liveCrashingSink fails the failAt-th export once with a retryable error,
// before the record reaches the inner sink, the way a replay that crashes
// mid-run leaves its last record undelivered.
type liveCrashingSink struct {
	inner  quarantinereplay.Sink
	failAt int

	mu     sync.Mutex
	calls  int
	failed bool
}

func (s *liveCrashingSink) crash() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if !s.failed && s.calls == s.failAt {
		s.failed = true
		return errors.New("injected retryable export failure")
	}
	return nil
}

func (s *liveCrashingSink) ExportTraces(ctx context.Context, td ptrace.Traces) error {
	if err := s.crash(); err != nil {
		return err
	}
	return s.inner.ExportTraces(ctx, td)
}

func (s *liveCrashingSink) ExportLogs(ctx context.Context, ld plog.Logs) error {
	if err := s.crash(); err != nil {
		return err
	}
	return s.inner.ExportLogs(ctx, ld)
}

func (s *liveCrashingSink) ExportMetrics(ctx context.Context, md pmetric.Metrics) error {
	if err := s.crash(); err != nil {
		return err
	}
	return s.inner.ExportMetrics(ctx, md)
}

// checkQuarantineReplay reads the quarantined span and log straight from
// BigQuery with the quarantine replay library, through Cloud Storage when the
// payloads were offloaded, and replays them into the signal tables through
// exporters that keep the default structural limits. The first run crashes
// on its second record; the second run resumes from the checkpointed BigQuery
// cursor and must read only that record; a third run finds nothing left. The
// replay exporters do not redact, so the redaction check that follows also
// proves the quarantined payloads were stored already masked.
func (r *liveIssuesRun) checkQuarantineReplay(ctx context.Context, t *testing.T) {
	stored := r.mustQuery(ctx, t, `
		SELECT signal, error_code, IFNULL(raw_payload, '') = '', IFNULL(payload_ref.uri, '') != ''
		FROM `+r.table("otel_quarantine")+`
		WHERE service_name = @svc ORDER BY signal`, liveParam("svc", r.svcQuarantine))
	// error_code carries the published UPPER_SNAKE code; the self-telemetry
	// reason label for the same rejection is lowercase.
	offloaded := r.bucket != ""
	wantStored := [][]any{{"logs", "ATTRIBUTE_COUNT", offloaded, offloaded}, {"spans", "ATTRIBUTE_COUNT", offloaded, offloaded}}
	if !liveRowsEqual(stored, wantStored) {
		t.Errorf("otel_quarantine rows = %v, want %v", stored, wantStored)
	}

	var fetcher quarantinereplay.ObjectFetcher
	if offloaded {
		f, closeFetcher, err := quarantinereplay.NewGCSObjectFetcher(ctx)
		if err != nil {
			t.Fatalf("NewGCSObjectFetcher: %v", err)
		}
		defer closeFetcher()
		fetcher = f
	}
	cfg := validConfig()
	cfg.Project = r.project
	cfg.Dataset = r.dataset
	cfg.Location = r.location
	settings := component.TelemetrySettings{Logger: zap.NewNop(), MeterProvider: noop.NewMeterProvider()}
	shutDown := func(name string, fn func(context.Context) error) {
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := fn(shutCtx); err != nil {
			t.Errorf("shut down replay %s exporter: %v", name, err)
		}
	}
	traces, err := newTracesExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newTracesExporter: %v", err)
	}
	if err := traces.start(ctx, nil); err != nil {
		t.Fatalf("start replay traces exporter: %v", err)
	}
	defer shutDown("traces", traces.shutdown)
	logs, err := newLogsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newLogsExporter: %v", err)
	}
	if err := logs.start(ctx, nil); err != nil {
		t.Fatalf("start replay logs exporter: %v", err)
	}
	defer shutDown("logs", logs.shutdown)

	src := quarantinereplay.BigQuerySource{Project: r.project, Dataset: r.dataset}
	opts := quarantinereplay.Options{
		ObjectFetcher: fetcher,
		Checkpoint:    &quarantinereplay.CheckpointConfig{Path: filepath.Join(t.TempDir(), "quarantine-replay-checkpoint.json")},
	}
	sink := &liveCrashingSink{inner: liveExporterSink{traces: traces, logs: logs}, failAt: 2}
	first, err := quarantinereplay.ReplayBigQuery(ctx, src, sink, opts)
	if err == nil || !strings.Contains(err.Error(), "injected retryable export failure") {
		t.Fatalf("first replay run error = %v (summary %+v), want the injected export failure to stop it", err, first)
	}
	second, err := quarantinereplay.ReplayBigQuery(ctx, src, sink, opts)
	if err != nil {
		t.Fatalf("resumed replay run: %v (summary %+v)", err, second)
	}
	third, err := quarantinereplay.ReplayBigQuery(ctx, src, sink, opts)
	if err != nil {
		t.Fatalf("third replay run: %v (summary %+v)", err, third)
	}
	t.Logf("replay runs: first %+v, resumed %+v, third %+v", first, second, third)
	if first.ReplayedSpans+first.ReplayedLogs != 1 {
		t.Errorf("first run replayed %d records before the crash, want 1", first.ReplayedSpans+first.ReplayedLogs)
	}
	if second.TotalRead != 1 || second.ReplayedSpans+second.ReplayedLogs != 1 || second.FailedExport != 0 || second.FailedUnmarshal != 0 {
		t.Errorf("resumed run summary = %+v, want exactly the one record the first run did not deliver", second)
	}
	if first.ReplayedSpans+second.ReplayedSpans != 1 || first.ReplayedLogs+second.ReplayedLogs != 1 {
		t.Errorf("replayed spans %d+%d and logs %d+%d across the crash, want 1 of each", first.ReplayedSpans, second.ReplayedSpans, first.ReplayedLogs, second.ReplayedLogs)
	}
	if third != (quarantinereplay.Summary{}) {
		t.Errorf("third run summary = %+v, want nothing left to read", third)
	}

	svc := liveParam("svc", r.svcQuarantine)
	for _, table := range []string{"otel_spans", "otel_spans_dedup", "otel_logs", "otel_logs_dedup"} {
		r.waitForCount(ctx, t, "replayed rows in "+table, "SELECT COUNT(*) FROM "+r.table(table)+" WHERE service_name = @svc", 1, svc)
	}
	extra := fmt.Sprintf("extra.%d", liveOverLimitExtras)
	spans := r.mustQuery(ctx, t, `
		SELECT trace_id, span_id, name, JSON_VALUE(attributes, '$.api_key'), JSON_VALUE(attributes, '$."`+extra+`"'),
			JSON_VALUE(attributes, '$."gen_ai.prompt"')
		FROM `+r.table("otel_spans")+` WHERE service_name = @svc`, svc)
	wantSpans := [][]any{{liveHex(liveTraceQuarantine[:]), liveHex(liveSpanQuarantine[:]), "chat quarantined", "[REDACTED]",
		"v" + strconv.Itoa(liveOverLimitExtras), r.redactedPrompt()}}
	if !liveRowsEqual(spans, wantSpans) {
		t.Errorf("replayed span = %v, want %v", spans, wantSpans)
	}
	logRows := r.mustQuery(ctx, t, `
		SELECT trace_id, event_name, JSON_VALUE(attributes, '$.api_key'), JSON_VALUE(body)
		FROM `+r.table("otel_logs")+` WHERE service_name = @svc`, svc)
	wantLogs := [][]any{{liveHex(liveTraceQuarantine[:]), "gen_ai.choice", "[REDACTED]", r.redactedPrompt()}}
	if !liveRowsEqual(logRows, wantLogs) {
		t.Errorf("replayed log = %v, want %v", logRows, wantLogs)
	}
}

// checkRedaction scans every row of every table, and every object the
// exporters wrote, for the planted secret.
func (r *liveIssuesRun) checkRedaction(ctx context.Context, t *testing.T) {
	secret := liveParam("secret", r.secret)
	for _, table := range []string{"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"} {
		rows := r.mustQuery(ctx, t, `
			SELECT COUNT(*), COUNTIF(STRPOS(TO_JSON_STRING(t), @secret) > 0), COUNTIF(STRPOS(TO_JSON_STRING(t), '[REDACTED]') > 0)
			FROM `+r.table(table)+` AS t`, secret)
		if len(rows) != 1 || len(rows[0]) != 3 {
			t.Fatalf("%s scan returned %v", table, rows)
		}
		n, _ := rows[0][0].(int64)
		leaked, _ := rows[0][1].(int64)
		masked, _ := rows[0][2].(int64)
		t.Logf("%s: %d rows, %d with the secret, %d with the mask", table, n, leaked, masked)
		if n == 0 {
			t.Errorf("%s has no rows to scan", table)
		}
		if leaked != 0 {
			t.Errorf("%s: %d rows contain the planted secret", table, leaked)
		}
		if (table == "otel_spans" || table == "otel_logs") && masked == 0 {
			t.Errorf("%s: no row carries the [REDACTED] mask", table)
		}
	}
	if r.bucket == "" {
		return
	}
	// Every object the exporters wrote passed through the recording store at
	// the WriteObject boundary, quarantine payloads included, and every
	// payload reference BigQuery holds must name one of them.
	var written []string
	for _, uri := range r.trackedObjects() {
		if strings.HasPrefix(uri, "gs://"+r.bucket+"/"+r.prefix+"/") {
			written = append(written, uri)
		}
	}
	slices.Sort(written)
	written = slices.Compact(written)
	isWritten := map[string]bool{}
	for _, uri := range written {
		isWritten[uri] = true
	}
	refs := r.mustQuery(ctx, t, `
		SELECT o.uri FROM `+r.table("otel_spans")+`, UNNEST(object_refs) AS o
		UNION ALL SELECT o.uri FROM `+r.table("otel_logs")+`, UNNEST(object_refs) AS o
		UNION ALL SELECT payload_ref.uri FROM `+r.table("otel_quarantine")+` WHERE payload_ref.uri IS NOT NULL`)
	for _, row := range refs {
		if uri, _ := row[0].(string); !isWritten[uri] {
			t.Errorf("BigQuery references %s, which the exporters were not seen writing", uri)
		}
	}
	scan := written
	switch names, err := liveListGCSObjects(ctx, r.httpClient, r.bucket, r.prefix+"/"); {
	case errors.Is(err, errGCSListForbidden):
		// A prefix-scoped conditional role allows object reads but not a
		// bucket listing; the recorded set is then the complete inventory.
		t.Logf("listing gs://%s/%s/ is not permitted; scanning the %d objects recorded at the WriteObject boundary", r.bucket, r.prefix, len(written))
	case err != nil:
		t.Fatalf("list gs://%s/%s/: %v", r.bucket, r.prefix, err)
	default:
		listed := make([]string, 0, len(names))
		for _, name := range names {
			listed = append(listed, "gs://"+r.bucket+"/"+name)
		}
		slices.Sort(listed)
		if !slices.Equal(listed, written) {
			t.Errorf("objects under gs://%s/%s/ = %v, want exactly the %d the exporters wrote: %v", r.bucket, r.prefix, listed, len(written), written)
		}
		scan = listed
	}
	fetcher, closeFetcher, err := quarantinereplay.NewGCSObjectFetcher(ctx)
	if err != nil {
		t.Fatalf("NewGCSObjectFetcher: %v", err)
	}
	defer closeFetcher()
	var masked int
	kinds := map[string]bool{}
	for _, uri := range scan {
		blob, err := fetcher(ctx, uri)
		if err != nil {
			t.Errorf("fetch %s: %v", uri, err)
			continue
		}
		if bytes.Contains(blob, []byte(r.secret)) {
			t.Errorf("%s contains the planted secret", uri)
		}
		if bytes.Contains(blob, []byte("[REDACTED]")) {
			masked++
		}
		if kind, _, ok := strings.Cut(strings.TrimPrefix(uri, "gs://"+r.bucket+"/"+r.prefix+"/"), "/"); ok {
			kinds[kind] = true
		}
	}
	t.Logf("gs://%s/%s/: %d objects, %d carry the mask, kinds %v", r.bucket, r.prefix, len(scan), masked, kinds)
	for _, kind := range []string{"spans", "logs", "quarantine"} {
		if !kinds[kind] {
			t.Errorf("no %s object under gs://%s/%s/", kind, r.bucket, r.prefix)
		}
	}
	if masked == 0 || masked != len(scan) {
		t.Errorf("%d of %d offloaded objects carry the [REDACTED] mask, want all of them", masked, len(scan))
	}
}

// errGCSListForbidden reports a bucket listing that IAM refused.
var errGCSListForbidden = errors.New("listing the bucket is forbidden")

func liveListGCSObjects(ctx context.Context, httpClient *stdhttp.Client, bucket, prefix string) ([]string, error) {
	var names []string
	pageToken := ""
	for {
		listURL := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o?prefix=%s",
			url.PathEscape(bucket), url.QueryEscape(prefix))
		if pageToken != "" {
			listURL += "&pageToken=" + url.QueryEscape(pageToken)
		}
		req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, listURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		var page struct {
			NextPageToken string `json:"nextPageToken"`
			Items         []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		decodeErr := json.NewDecoder(resp.Body).Decode(&page)
		_ = resp.Body.Close()
		if resp.StatusCode == stdhttp.StatusForbidden {
			return nil, errGCSListForbidden
		}
		if resp.StatusCode != stdhttp.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if decodeErr != nil {
			return nil, decodeErr
		}
		for _, item := range page.Items {
			names = append(names, item.Name)
		}
		if page.NextPageToken == "" {
			return names, nil
		}
		pageToken = page.NextPageToken
	}
}

// checkValidate runs the bq-otel-validate preflight against the live dataset,
// then once more against a quarantine table that does not exist, which must
// fail closed.
func (r *liveIssuesRun) checkValidate(ctx context.Context, t *testing.T) {
	report, err := validate.Run(ctx, validate.Config{Project: r.project, Dataset: r.dataset})
	if err != nil {
		t.Fatalf("validate.Run: %v", err)
	}
	passed := map[validate.Category]int{}
	for _, c := range report.Checks {
		if c.Status == validate.StatusPass {
			passed[c.Category]++
		}
		if c.Status == validate.StatusFail || c.Status == validate.StatusWarn {
			t.Logf("validate %s %s %s: %s %s (%s)", c.Status, c.Category, c.Name, c.Resource, c.Detail, c.Remediation)
		}
	}
	t.Logf("validate: conforms=%t summary=%+v passed by category=%v", report.Conforms, report.Summary, passed)
	if !report.Conforms || report.Summary.Fail != 0 {
		t.Errorf("validate report conforms=%t with %d failed checks, want a conforming report", report.Conforms, report.Summary.Fail)
	}
	if report.SchemaVersion != schema.Version {
		t.Errorf("validate schema version = %q, want %q", report.SchemaVersion, schema.Version)
	}
	for _, cat := range []validate.Category{validate.CategorySchema, validate.CategoryViews, validate.CategoryIAM, validate.CategoryStorageWrite} {
		if passed[cat] == 0 {
			t.Errorf("validate passed no %s check", cat)
		}
	}

	missing := "otel_quarantine_absent_" + r.runID
	broken, err := validate.Run(ctx, validate.Config{
		Project:         r.project,
		Dataset:         r.dataset,
		QuarantineTable: missing,
		Checks:          []validate.Category{validate.CategorySchema},
	})
	if err != nil {
		t.Fatalf("validate.Run with a missing quarantine table: %v", err)
	}
	failedOnMissing := false
	for _, c := range broken.Checks {
		if c.Status == validate.StatusFail && strings.Contains(c.Resource, missing) {
			failedOnMissing = true
		}
	}
	if broken.Conforms || !failedOnMissing {
		t.Errorf("validate with a missing quarantine table: conforms=%t, failed check on %s=%t; want a failing report", broken.Conforms, missing, failedOnMissing)
	}
}

// backfillArchive is one OTLP JSON line of traces and one of logs, the
// format the Collector's file exporter writes. Both carry the planted secret
// in cleartext, as an unscreened archive would.
func (r *liveIssuesRun) backfillArchive(t *testing.T) []byte {
	t.Helper()
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", r.svcBackfill)
	span := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetTraceID(liveTraceBackfill)
	span.SetSpanID(liveSpanBackfill)
	span.SetName("chat backfilled")
	span.SetStartTimestamp(r.ts(-time.Hour))
	span.SetEndTimestamp(r.ts(-time.Hour + 100*time.Millisecond))
	span.Attributes().PutStr("gen_ai.operation.name", "chat")
	span.Attributes().PutStr("gen_ai.prompt", "Authorization: Bearer "+r.secret)
	span.Attributes().PutStr("api_key", r.secret)

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", r.svcBackfill)
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(r.ts(-time.Hour))
	rec.SetEventName("gen_ai.user.message")
	rec.SetTraceID(liveTraceBackfill)
	rec.SetSpanID(liveSpanBackfill)
	rec.Body().SetStr("user said: Authorization: Bearer " + r.secret)

	tracesJSON, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatalf("marshal archive traces: %v", err)
	}
	logsJSON, err := (&plog.JSONMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatalf("marshal archive logs: %v", err)
	}
	return []byte(string(tracesJSON) + "\n" + string(logsJSON) + "\n")
}

// checkBackfill appends a Cloud Storage archive twice with bq-otel-backfill.
// Redaction must mask the secret on the way in, and the dedup views must
// collapse the second run.
func (r *liveIssuesRun) checkBackfill(ctx context.Context, t *testing.T) {
	if r.bucket == "" {
		t.Skip("BQ_OFFLOAD_TEST_BUCKET is unset; the backfill source lives in Cloud Storage")
	}
	archivePrefix := r.prefix + "-backfill/"
	store, err := offload.NewGCSBlobStore(ctx)
	if err != nil {
		t.Fatalf("NewGCSBlobStore: %v", err)
	}
	defer func() { _ = store.Close() }()
	archive := archivePrefix + "archive.jsonl"
	r.trackObject("gs://" + r.bucket + "/" + archive)
	if _, err := store.WriteObject(ctx, r.bucket, archive, "application/x-ndjson", r.backfillArchive(t)); err != nil {
		t.Fatalf("upload backfill archive: %v", err)
	}
	cfg := backfill.Config{
		Source:               "gs://" + r.bucket + "/" + archivePrefix,
		Project:              r.project,
		Dataset:              r.dataset,
		Redact:               true,
		BlockedValuePatterns: []string{liveIssuesSecretPattern},
		RedactLogBody:        true,
	}
	for run := 1; run <= 2; run++ {
		report, err := backfill.Run(ctx, cfg)
		if run == 1 && err != nil && cfg.Store == nil && strings.Contains(err.Error(), "listing gs://") && strings.Contains(err.Error(), "HTTP 403") {
			// A prefix-scoped conditional CI role allows object reads under
			// it-offload-* but not bucket-wide storage.objects.list.
			t.Logf("listing gs://%s/%s is not permitted (%v); retrying backfill with recorded object %q", r.bucket, archivePrefix, err, archive)
			cfg.Store = &liveRecordedBackfillStore{
				httpClient: r.httpClient,
				objectName: archive,
			}
			report, err = backfill.Run(ctx, cfg)
		}
		if err != nil {
			t.Fatalf("backfill run %d: %v", run, err)
		}
		appended := map[string]int64{}
		for _, s := range report.Signals {
			appended[s.Signal] = s.Appended
			if s.Records != s.Appended || len(s.Rejected) > 0 || s.Unwritten != 0 {
				t.Errorf("backfill run %d %s: records=%d appended=%d rejected=%v unwritten=%d", run, s.Signal, s.Records, s.Appended, s.Rejected, s.Unwritten)
			}
		}
		if !report.Complete() || report.Objects != 1 || report.Lines != 2 || appended["traces"] != 1 || appended["logs"] != 1 || appended["metrics"] != 0 {
			t.Errorf("backfill run %d report = %+v, want 1 object, 2 lines, 1 span and 1 log appended", run, report)
		}
	}
	svc := liveParam("svc", r.svcBackfill)
	for _, table := range []string{"otel_spans", "otel_logs"} {
		r.waitForCount(ctx, t, table+" backfilled rows", "SELECT COUNT(*) FROM "+r.table(table)+" WHERE service_name = @svc", 2, svc)
		r.waitForCount(ctx, t, table+"_dedup backfilled rows", "SELECT COUNT(*) FROM "+r.table(table+"_dedup")+" WHERE service_name = @svc", 1, svc)
		rows := r.mustQuery(ctx, t, `
			SELECT COUNTIF(STRPOS(TO_JSON_STRING(t), @secret) > 0), COUNTIF(STRPOS(TO_JSON_STRING(t), '[REDACTED]') > 0)
			FROM `+r.table(table)+` AS t WHERE service_name = @svc`, svc, liveParam("secret", r.secret))
		if fmt.Sprint(rows) != "[[0 2]]" {
			t.Errorf("%s backfilled rows with the secret / with the mask = %v, want [[0 2]]", table, rows)
		}
	}
}

// liveRecordedBackfillStore implements backfill.ObjectStore for environments
// where conditional IAM permits reading objects written under a test prefix
// without granting bucket-wide storage.objects.list.
type liveRecordedBackfillStore struct {
	httpClient *stdhttp.Client
	objectName string
}

var _ backfill.ObjectStore = (*liveRecordedBackfillStore)(nil)

func (s *liveRecordedBackfillStore) List(_ context.Context, _ string, prefix string, fn func(backfill.Object) error) error {
	if !strings.HasPrefix(s.objectName, prefix) {
		return nil
	}
	return fn(backfill.Object{Name: s.objectName})
}

func (s *liveRecordedBackfillStore) Open(ctx context.Context, bucket string, obj backfill.Object) (io.ReadCloser, error) {
	endpoint := fmt.Sprintf("https://storage.googleapis.com/storage/v1/b/%s/o/%s?alt=media",
		url.PathEscape(bucket), url.PathEscape(obj.Name))
	if obj.Generation != "" {
		endpoint += "&generation=" + url.QueryEscape(obj.Generation)
	}
	req, err := stdhttp.NewRequestWithContext(ctx, stdhttp.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != stdhttp.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return nil, fmt.Errorf("GET %s: HTTP %d: %s", obj.Name, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return resp.Body, nil
}
