// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"gopkg.in/yaml.v3"
)

func TestModeCollectorNormalizeValidation(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector.yaml")
	if err := os.WriteFile(cfgPath, []byte("receivers: {}\nexporters: {}\nservice: {}\n"), 0o600); err != nil {
		t.Fatalf("write temp collector config: %v", err)
	}

	invalidMode := RunnerConfig{Mode: "invalid-mode"}
	if err := invalidMode.Normalize(); err == nil {
		t.Fatal("expected Normalize error for invalid mode")
	}

	missingBin := RunnerConfig{
		Mode:            ModeCollector,
		CollectorConfig: cfgPath,
	}
	if err := missingBin.Normalize(); err == nil {
		t.Fatal("expected Normalize error when CollectorBin is empty in collector mode")
	}

	valid := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: cfgPath,
	}
	if err := valid.Normalize(); err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}
	if valid.Mode != ModeCollector {
		t.Fatalf("Mode = %q, want %q", valid.Mode, ModeCollector)
	}
	if valid.ProjectID != "bench-project" || valid.DatasetID != "otel_bench" {
		t.Fatalf("default project/dataset = %q/%q, want bench-project/otel_bench", valid.ProjectID, valid.DatasetID)
	}
	if valid.StreamPoolSize <= 0 || valid.ConnectionPoolSize <= 0 {
		t.Fatalf("expected positive pool defaults, got stream=%d conn=%d", valid.StreamPoolSize, valid.ConnectionPoolSize)
	}

	rejectExplicitLive := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: cfgPath,
		ProjectID:       "my-prod-project",
		DatasetID:       "prod_ds",
	}
	if err := rejectExplicitLive.Normalize(); err == nil {
		t.Fatal("expected Normalize error for explicit live ProjectID/DatasetID when CollectorAllowLive is false")
	}

	rejectHermeticEphemeral := RunnerConfig{
		Mode:             ModeCollector,
		CollectorBin:     os.Args[0],
		CollectorConfig:  cfgPath,
		EphemeralDataset: true,
	}
	if err := rejectHermeticEphemeral.Normalize(); err == nil {
		t.Fatal("expected Normalize error for EphemeralDataset when CollectorAllowLive is false")
	}

	rejectLiveEmptyProject := RunnerConfig{
		Mode:               ModeCollector,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		CollectorAllowLive: true,
		DatasetID:          "my_ds",
	}
	if err := rejectLiveEmptyProject.Normalize(); err == nil {
		t.Fatal("expected Normalize error when CollectorAllowLive is true and ProjectID is empty")
	}

	rejectLiveBenchProject := RunnerConfig{
		Mode:               ModeCollector,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		CollectorAllowLive: true,
		ProjectID:          "bench-project",
		DatasetID:          "my_ds",
	}
	if err := rejectLiveBenchProject.Normalize(); err == nil {
		t.Fatal("expected Normalize error when CollectorAllowLive is true and ProjectID is bench-project")
	}

	validLive := RunnerConfig{
		Mode:               ModeCollector,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		CollectorAllowLive: true,
		ProjectID:          "my-live-proj",
		DatasetID:          "my_ds",
	}
	if err := validLive.Normalize(); err != nil {
		t.Fatalf("Normalize() unexpected error for valid live config: %v", err)
	}
	if validLive.ProjectID != "my-live-proj" || validLive.DatasetID != "my_ds" {
		t.Fatalf("live project/dataset = %q/%q, want my-live-proj/my_ds", validLive.ProjectID, validLive.DatasetID)
	}

	validLiveEphemeral := RunnerConfig{
		Mode:               ModeCollector,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		CollectorAllowLive: true,
		ProjectID:          "my-live-proj",
		EphemeralDataset:   true,
	}
	if err := validLiveEphemeral.Normalize(); err != nil {
		t.Fatalf("Normalize() unexpected error for live ephemeral config: %v", err)
	}
	if !strings.HasPrefix(validLiveEphemeral.DatasetID, "otel_bench_") {
		t.Fatalf("ephemeral DatasetID = %q, want otel_bench_* prefix", validLiveEphemeral.DatasetID)
	}

	rejectAllowLiveBQFake := RunnerConfig{
		Mode:               ModeBQFake,
		CollectorAllowLive: true,
	}
	if err := rejectAllowLiveBQFake.Normalize(); err == nil {
		t.Fatal("expected Normalize error when CollectorAllowLive is true with ModeBQFake")
	}
}

func TestRewriteCollectorLoopbackConfigPreservesTrimPipeline(t *testing.T) {
	const rawYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  memory_limiter: {check_interval: 1s}
  resource/trim_access_logs: {attributes: []}
  attributes/trim_access_logs: {actions: []}
  transform/trim_access_logs: {log_statements: []}
  batch: {send_batch_size: 500}
exporters:
  bigquery:
    project: orig-project
    dataset: orig_dataset
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [memory_limiter, resource/trim_access_logs, attributes/trim_access_logs, transform/trim_access_logs, batch]
      exporters: [bigquery]
`
	cfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		StreamPoolSize:      8,
		ConnectionPoolSize:  8,
		MaxInflightRequests: 32,
		MaxRequestBytes:     8 * 1024 * 1024,
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}

	out, hasHealth, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() error: %v", err)
	}
	if !hasHealth {
		t.Fatal("expected hasHealthCheck=true")
	}

	var got struct {
		Extensions struct {
			HealthCheck struct {
				Endpoint string `yaml:"endpoint"`
			} `yaml:"health_check"`
		} `yaml:"extensions"`
		Receivers struct {
			OTLP struct {
				Protocols struct {
					GRPC struct {
						Endpoint string `yaml:"endpoint"`
					} `yaml:"grpc"`
				} `yaml:"protocols"`
			} `yaml:"otlp"`
		} `yaml:"receivers"`
		Processors map[string]any `yaml:"processors"`
		Exporters  struct {
			BigQuery struct {
				Project  string `yaml:"project"`
				Dataset  string `yaml:"dataset"`
				Endpoint struct {
					URL                   string `yaml:"url"`
					AdminURL              string `yaml:"admin_url"`
					Insecure              bool   `yaml:"insecure"`
					WithoutAuthentication bool   `yaml:"without_authentication"`
				} `yaml:"endpoint"`
			} `yaml:"bigquery"`
		} `yaml:"exporters"`
		Service struct {
			Pipelines struct {
				Logs struct {
					Processors []string `yaml:"processors"`
				} `yaml:"logs"`
			} `yaml:"pipelines"`
		} `yaml:"service"`
	}
	if unmarshalErr := yaml.Unmarshal(out, &got); unmarshalErr != nil {
		t.Fatalf("unmarshal rewritten YAML: %v", unmarshalErr)
	}
	if got.Receivers.OTLP.Protocols.GRPC.Endpoint != ep.otlpAddr {
		t.Fatalf("otlp endpoint = %q, want %q", got.Receivers.OTLP.Protocols.GRPC.Endpoint, ep.otlpAddr)
	}
	if got.Extensions.HealthCheck.Endpoint != ep.healthAddr {
		t.Fatalf("health_check endpoint = %q, want %q", got.Extensions.HealthCheck.Endpoint, ep.healthAddr)
	}
	bqEP := got.Exporters.BigQuery.Endpoint
	if bqEP.URL != ep.fakeGRPCURL || bqEP.AdminURL != ep.fakeRESTURL || !bqEP.Insecure || !bqEP.WithoutAuthentication {
		t.Fatalf("unexpected bigquery fake endpoint rewrite: %+v", bqEP)
	}
	wantProcs := []string{
		"memory_limiter",
		"resource/trim_access_logs",
		"attributes/trim_access_logs",
		"transform/trim_access_logs",
		"batch",
	}
	if !slices.Equal(got.Service.Pipelines.Logs.Processors, wantProcs) {
		t.Fatalf("logs pipeline processors = %v, want %v", got.Service.Pipelines.Logs.Processors, wantProcs)
	}
	for _, proc := range wantProcs[1:4] {
		if _, ok := got.Processors[proc]; !ok {
			t.Fatalf("processor definition %q missing after rewrite", proc)
		}
	}
}

func TestRewriteCollectorLoopbackConfigSafetyAndFidelity(t *testing.T) {
	const customExporterYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        max_recv_msg_size_mib: 64
      http:
        endpoint: 0.0.0.0:4318
processors:
  batch:
    send_batch_size: 500
exporters:
  bigquery/custom:
    project: orig-project
    dataset: orig_dataset
    location: US
  bigquery/unused:
    project: untouched-prod-project
    dataset: untouched_prod_ds
  otlp/unused:
    endpoint: prod-traces.example.com:4317
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery/custom]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp/unused]
`
	cfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		Redaction:           true,
		StreamPoolSize:      4,
		ConnectionPoolSize:  4,
		MaxInflightRequests: 16,
		MaxRequestBytes:     8 * 1024 * 1024,
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		metricsHost: "127.0.0.1",
		metricsPort: 18889,
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}

	out, hasHealth, err := rewriteCollectorLoopbackConfig([]byte(customExporterYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() error: %v", err)
	}
	if !hasHealth {
		t.Fatal("expected hasHealthCheck=true")
	}

	var rewritten struct {
		Receivers struct {
			OTLP struct {
				Protocols map[string]any `yaml:"protocols"`
			} `yaml:"otlp"`
		} `yaml:"receivers"`
		Exporters map[string]struct {
			Project  string `yaml:"project"`
			Dataset  string `yaml:"dataset"`
			Endpoint struct {
				URL                   string `yaml:"url"`
				AdminURL              string `yaml:"admin_url"`
				Insecure              bool   `yaml:"insecure"`
				WithoutAuthentication bool   `yaml:"without_authentication"`
			} `yaml:"endpoint"`
			Redaction struct {
				Enabled              bool     `yaml:"enabled"`
				RedactLogBody        bool     `yaml:"redact_log_body"`
				BlockedValuePatterns []string `yaml:"blocked_value_patterns"`
			} `yaml:"redaction"`
		} `yaml:"exporters"`
		Service struct {
			Pipelines map[string]struct {
				Exporters []string `yaml:"exporters"`
			} `yaml:"pipelines"`
			Telemetry struct {
				Metrics struct {
					Readers []struct {
						Pull struct {
							Exporter struct {
								Prometheus struct {
									Host string `yaml:"host"`
									Port int    `yaml:"port"`
								} `yaml:"prometheus"`
							} `yaml:"exporter"`
						} `yaml:"pull"`
					} `yaml:"readers"`
				} `yaml:"metrics"`
			} `yaml:"telemetry"`
		} `yaml:"service"`
	}
	if unmarshalErr := yaml.Unmarshal(out, &rewritten); unmarshalErr != nil {
		t.Fatalf("unmarshal rewritten YAML: %v", unmarshalErr)
	}

	if _, hasHTTP := rewritten.Receivers.OTLP.Protocols["http"]; hasHTTP {
		t.Fatal("expected receivers.otlp.protocols.http to be deleted")
	}
	grpcProto, ok := rewritten.Receivers.OTLP.Protocols["grpc"].(map[string]any)
	if !ok {
		t.Fatalf("receivers.otlp.protocols.grpc missing or invalid: %#v", rewritten.Receivers.OTLP.Protocols["grpc"])
	}
	if grpcProto["endpoint"] != ep.otlpAddr {
		t.Fatalf("grpc.endpoint = %v, want %q", grpcProto["endpoint"], ep.otlpAddr)
	}
	if grpcProto["max_recv_msg_size_mib"] != 64 {
		t.Fatalf("grpc.max_recv_msg_size_mib = %v, want 64", grpcProto["max_recv_msg_size_mib"])
	}

	if _, hasUnused := rewritten.Exporters["bigquery/unused"]; hasUnused {
		t.Fatal("expected unreferenced bigquery/unused exporter to be deleted")
	}
	if _, hasUnusedOTLP := rewritten.Exporters["otlp/unused"]; hasUnusedOTLP {
		t.Fatal("expected unreferenced otlp/unused exporter to be deleted")
	}
	customBQ, hasCustom := rewritten.Exporters["bigquery/custom"]
	if !hasCustom {
		t.Fatal("expected bigquery/custom exporter to be preserved and rewritten")
	}
	if customBQ.Project != cfg.ProjectID || customBQ.Dataset != cfg.DatasetID {
		t.Fatalf("bigquery/custom project/dataset = %q/%q, want %q/%q", customBQ.Project, customBQ.Dataset, cfg.ProjectID, cfg.DatasetID)
	}
	if customBQ.Endpoint.URL != ep.fakeGRPCURL || customBQ.Endpoint.AdminURL != ep.fakeRESTURL || !customBQ.Endpoint.Insecure || !customBQ.Endpoint.WithoutAuthentication {
		t.Fatalf("unexpected bigquery/custom endpoint rewrite: %+v", customBQ.Endpoint)
	}
	if !customBQ.Redaction.Enabled || !customBQ.Redaction.RedactLogBody || len(customBQ.Redaction.BlockedValuePatterns) == 0 {
		t.Fatalf("unexpected redaction config when cfg.Redaction=true: %+v", customBQ.Redaction)
	}

	if _, hasTraces := rewritten.Service.Pipelines["traces"]; hasTraces {
		t.Fatal("expected inactive traces pipeline to be deleted")
	}
	if !slices.Equal(rewritten.Service.Pipelines["logs"].Exporters, []string{"bigquery/custom"}) {
		t.Fatalf("logs pipeline exporters = %v, want [bigquery/custom]", rewritten.Service.Pipelines["logs"].Exporters)
	}

	if len(rewritten.Service.Telemetry.Metrics.Readers) == 0 {
		t.Fatal("expected service.telemetry.metrics Prometheus pull reader to be injected")
	}
	promCfg := rewritten.Service.Telemetry.Metrics.Readers[0].Pull.Exporter.Prometheus
	if promCfg.Host != ep.metricsHost || promCfg.Port != ep.metricsPort {
		t.Fatalf("prometheus reader host:port = %q:%d, want %q:%d", promCfg.Host, promCfg.Port, ep.metricsHost, ep.metricsPort)
	}

	const mixedExportersYAML = `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig
    dataset: orig_ds
  debug: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery, debug]
`
	if _, _, mixedErr := rewriteCollectorLoopbackConfig([]byte(mixedExportersYAML), cfg, "logs", ep); mixedErr == nil {
		t.Fatal("expected error when active pipeline references non-bigquery exporter [bigquery, debug]")
	}

	const nonBQExporterYAML = `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  otlp/prod:
    endpoint: prod.example.com:4317
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [otlp/prod]
`
	if _, _, nonBQErr := rewriteCollectorLoopbackConfig([]byte(nonBQExporterYAML), cfg, "logs", ep); nonBQErr == nil {
		t.Fatal("expected error when active pipeline references non-bigquery exporter [otlp/prod]")
	}

	const liveAutoCreateYAML = `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig-project
    dataset: orig_dataset
    location: US
    auto_create:
      dataset: false
      tables: false
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	liveEP := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		metricsHost: "127.0.0.1",
		metricsPort: 18890,
		useBQFake:   false,
	}
	liveCfgExisting := RunnerConfig{
		ProjectID:           "my-live-proj",
		DatasetID:           "existing_ds",
		Location:            "US",
		EphemeralDataset:    false,
		StreamPoolSize:      4,
		ConnectionPoolSize:  4,
		MaxInflightRequests: 16,
		MaxRequestBytes:     8 * 1024 * 1024,
	}
	liveOutExisting, _, liveErr := rewriteCollectorLoopbackConfig([]byte(liveAutoCreateYAML), liveCfgExisting, "logs", liveEP)
	if liveErr != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() live existing error: %v", liveErr)
	}

	var liveParsedExisting struct {
		Exporters struct {
			BigQuery struct {
				AutoCreate struct {
					Tables bool `yaml:"tables"`
				} `yaml:"auto_create"`
			} `yaml:"bigquery"`
		} `yaml:"exporters"`
	}
	if unmarshalErr := yaml.Unmarshal(liveOutExisting, &liveParsedExisting); unmarshalErr != nil {
		t.Fatalf("unmarshal live existing YAML: %v", unmarshalErr)
	}
	if liveParsedExisting.Exporters.BigQuery.AutoCreate.Tables {
		t.Fatal("expected auto_create.tables=false when useBQFake=false and EphemeralDataset=false")
	}

	liveCfgEphemeral := liveCfgExisting
	liveCfgEphemeral.DatasetID = "otel_bench_ephemeral"
	liveCfgEphemeral.EphemeralDataset = true
	liveOutEphemeral, _, ephemErr := rewriteCollectorLoopbackConfig([]byte(liveAutoCreateYAML), liveCfgEphemeral, "logs", liveEP)
	if ephemErr != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() live ephemeral error: %v", ephemErr)
	}

	var liveParsedEphemeral struct {
		Exporters struct {
			BigQuery struct {
				AutoCreate struct {
					Tables bool `yaml:"tables"`
				} `yaml:"auto_create"`
			} `yaml:"bigquery"`
		} `yaml:"exporters"`
	}
	if unmarshalErr := yaml.Unmarshal(liveOutEphemeral, &liveParsedEphemeral); unmarshalErr != nil {
		t.Fatalf("unmarshal live ephemeral YAML: %v", unmarshalErr)
	}
	if !liveParsedEphemeral.Exporters.BigQuery.AutoCreate.Tables {
		t.Fatal("expected auto_create.tables=true when EphemeralDataset=true")
	}
}

func TestParseCollectorPrometheusMetricsAndDrainTimeout(t *testing.T) {
	const exposition = `
# HELP otelcol_exporter_bigquery_acknowledged_rows Rows acknowledged by BigQuery
# TYPE otelcol_exporter_bigquery_acknowledged_rows counter
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 500
otelcol_exporter_bigquery_acknowledged_rows{signal="traces"} 999
# HELP otelcol_exporter_bigquery_append_bytes Bytes appended to BigQuery
# TYPE otelcol_exporter_bigquery_append_bytes counter
otelcol_exporter_bigquery_append_bytes{signal="logs"} 387500
# HELP otelcol_exporter_bigquery_redacted_values Redacted field values
# TYPE otelcol_exporter_bigquery_redacted_values counter
otelcol_exporter_bigquery_redacted_values{match_type="value_pattern",signal="logs"} 12
# HELP otelcol_exporter_queue_size Exporter queue size
# TYPE otelcol_exporter_queue_size gauge
otelcol_exporter_queue_size 0
# HELP otelcol_exporter_bigquery_inflight_requests Inflight BigQuery append requests
# TYPE otelcol_exporter_bigquery_inflight_requests gauge
otelcol_exporter_bigquery_inflight_requests 0
# HELP otelcol_exporter_send_failed_log_records Failed log records
# TYPE otelcol_exporter_send_failed_log_records counter
otelcol_exporter_send_failed_log_records 3
`
	sample := parseCollectorPrometheusMetrics(exposition, "logs")
	if sample.Telemetry.AcknowledgedRows != 500 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want 500", sample.Telemetry.AcknowledgedRows)
	}
	if sample.Telemetry.AppendBytesTotal != 387500 {
		t.Fatalf("Telemetry.AppendBytesTotal = %d, want 387500", sample.Telemetry.AppendBytesTotal)
	}
	if sample.Telemetry.RedactedValuesTotal != 12 {
		t.Fatalf("Telemetry.RedactedValuesTotal = %d, want 12", sample.Telemetry.RedactedValuesTotal)
	}
	if sample.QueueSize != 0 {
		t.Fatalf("QueueSize = %d, want 0", sample.QueueSize)
	}
	if sample.InflightRequests != 0 {
		t.Fatalf("InflightRequests = %d, want 0", sample.InflightRequests)
	}
	if sample.SendFailed != 3 {
		t.Fatalf("SendFailed = %d, want 3", sample.SendFailed)
	}
	if sample.HeapAllocBytes != 0 {
		t.Fatalf("HeapAllocBytes = %d, want 0", sample.HeapAllocBytes)
	}

	var metricsPayload atomic.Pointer[string]
	incompleteMetrics := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 6
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests 0
`
	metricsPayload.Store(&incompleteMetrics)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		body := metricsPayload.Load()
		_, _ = w.Write([]byte(*body))
	}))
	defer srv.Close()

	ctx := context.Background()
	metricsAddr := srv.Listener.Addr().String()
	doneCh := make(chan struct{})
	var waitErr error
	diag := new(boundedDiagBuffer)

	_, timeoutErr := drainCollectorPipeline(
		ctx,
		srv.Client(),
		metricsAddr,
		"logs",
		collectorMetricsSample{},
		12,
		120*time.Millisecond,
		doneCh,
		&waitErr,
		diag,
	)
	if timeoutErr == nil {
		t.Fatal("expected non-nil timeout error when acknowledged_rows (6) < expectedSubmitted (12)")
	}

	completeMetrics := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 12
otelcol_exporter_bigquery_append_bytes{signal="logs"} 9600
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests 0
`
	metricsPayload.Store(&completeMetrics)

	scraped, scrapeErr := scrapeCollectorMetrics(ctx, srv.Client(), metricsAddr, "logs")
	if scrapeErr != nil {
		t.Fatalf("scrapeCollectorMetrics() unexpected error: %v", scrapeErr)
	}
	if scraped.Telemetry.AcknowledgedRows != 12 {
		t.Fatalf("scraped AcknowledgedRows = %d, want 12", scraped.Telemetry.AcknowledgedRows)
	}

	drained, drainErr := drainCollectorPipeline(
		ctx,
		srv.Client(),
		metricsAddr,
		"logs",
		collectorMetricsSample{},
		12,
		2*time.Second,
		doneCh,
		&waitErr,
		diag,
	)
	if drainErr != nil {
		t.Fatalf("drainCollectorPipeline() unexpected error after full ack: %v", drainErr)
	}
	if drained.Telemetry.AcknowledgedRows != 12 || drained.QueueSize != 0 || drained.InflightRequests != 0 {
		t.Fatalf("unexpected drained sample: %+v", drained)
	}
}

type loopbackLogsOTLPServer struct {
	plogotlp.UnimplementedGRPCServer
}

func (s *loopbackLogsOTLPServer) Export(context.Context, plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	return plogotlp.NewExportResponse(), nil
}

func TestRateLimitedCollectorWorkerPhaseRespectsDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback OTLP server: %v", err)
	}

	grpcSrv := grpc.NewServer()
	plogotlp.RegisterGRPCServer(grpcSrv, &loopbackLogsOTLPServer{})
	go func() {
		_ = grpcSrv.Serve(lis)
	}()
	t.Cleanup(grpcSrv.Stop)

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("create OTLP gRPC client: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})

	client := plogotlp.NewGRPCClient(conn)
	cfg := RunnerConfig{
		TargetRate: 1,
		BatchSize:  500,
		Workers:    2,
		Duration:   80 * time.Millisecond,
	}
	if err = cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize(): %v", err)
	}
	makeBatch, err := newCollectorBatchBuilder(cfg, "logs")
	if err != nil {
		t.Fatalf("newCollectorBatchBuilder() unexpected error: %v", err)
	}

	start := time.Now()
	if phaseStats := runCollectorWorkerPhase(ctx, cfg, "logs", cfg.Duration, 0, nil, makeBatch, nil, client, nil); phaseStats.firstErr != nil {
		t.Fatalf("runCollectorWorkerPhase() unexpected error: %v", phaseStats.firstErr)
	}
	if elapsed := time.Since(start); elapsed >= 3*time.Second {
		t.Fatalf("runCollectorWorkerPhase() wall time = %v, want < 3s", elapsed)
	}
}

func TestReadPIDCPUAndMemoryHelpers(t *testing.T) {
	if got := readPIDCPUSeconds(0); got != 0 {
		t.Fatalf("readPIDCPUSeconds(0) = %v, want 0", got)
	}
	if rss, hwm := readPIDMemoryMB(0); rss != 0 || hwm != 0 {
		t.Fatalf("readPIDMemoryMB(0) = (%v, %v), want (0, 0)", rss, hwm)
	}

	pid := os.Getpid()
	cpuBefore := readPIDCPUSeconds(pid)
	cpuAfter := readPIDCPUSeconds(pid)
	if cpuBefore < 0 || cpuAfter < cpuBefore {
		t.Fatalf("invalid CPU seconds for pid %d: before=%v after=%v", pid, cpuBefore, cpuAfter)
	}
	rssMB, hwmMB := readPIDMemoryMB(pid)
	if rssMB <= 0 || hwmMB < rssMB {
		t.Fatalf("invalid memory MB for pid %d: rss=%v hwm=%v", pid, rssMB, hwmMB)
	}
}
