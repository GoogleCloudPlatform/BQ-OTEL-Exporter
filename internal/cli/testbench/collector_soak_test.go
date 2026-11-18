// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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

	out, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() error: %v", err)
	}
	if !meta.hasHealthCheck {
		t.Fatal("expected meta.hasHealthCheck=true")
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

	out, meta, err := rewriteCollectorLoopbackConfig([]byte(customExporterYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() error: %v", err)
	}
	if !meta.hasHealthCheck {
		t.Fatal("expected meta.hasHealthCheck=true")
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
	sample := parseCollectorPrometheusMetrics(exposition, "logs", "bigquery")
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
		"bigquery",
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

	// Quarantine double-count check: acknowledged=8, rejected=2, quarantined=2 => accounted=10 < 12.
	quarantineMetrics := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 8
otelcol_exporter_bigquery_rejected_rows{signal="logs"} 2
otelcol_exporter_bigquery_quarantined_rows{signal="logs"} 2
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests 0
`
	metricsPayload.Store(&quarantineMetrics)
	_, qTimeoutErr := drainCollectorPipeline(
		ctx,
		srv.Client(),
		metricsAddr,
		"logs",
		"bigquery",
		collectorMetricsSample{},
		12,
		120*time.Millisecond,
		doneCh,
		&waitErr,
		diag,
	)
	if qTimeoutErr == nil {
		t.Fatal("expected drainCollectorPipeline timeout when acknowledged=8, rejected=2, quarantined=2 for expectedSubmitted=12")
	}

	completeMetrics := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 12
otelcol_exporter_bigquery_append_bytes{signal="logs"} 9600
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests 0
`
	metricsPayload.Store(&completeMetrics)

	scraped, scrapeErr := scrapeCollectorMetrics(ctx, srv.Client(), metricsAddr, "logs", "bigquery")
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
		"bigquery",
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
	if got, ok := readPIDCPUSeconds(0); got != 0 || ok {
		t.Fatalf("readPIDCPUSeconds(0) = (%v, %v), want (0, false)", got, ok)
	}
	if rss, hwm, ok := readPIDMemoryMB(0); rss != 0 || hwm != 0 || ok {
		t.Fatalf("readPIDMemoryMB(0) = (%v, %v, %v), want (0, 0, false)", rss, hwm, ok)
	}
	if rss, hwm, ok := readPIDMemoryMB(999999999); rss != 0 || hwm != 0 || ok {
		t.Fatalf("readPIDMemoryMB(non-existent) = (%v, %v, %v), want (0, 0, false)", rss, hwm, ok)
	}

	pid := os.Getpid()
	cpuBefore, okBefore := readPIDCPUSeconds(pid)
	cpuAfter, okAfter := readPIDCPUSeconds(pid)
	if okBefore && okAfter && (cpuBefore < 0 || cpuAfter < cpuBefore) {
		t.Fatalf("invalid CPU seconds for pid %d: before=%v after=%v", pid, cpuBefore, cpuAfter)
	}
	rssMB, hwmMB, memOK := readPIDMemoryMB(pid)
	if !memOK || rssMB <= 0 || hwmMB < rssMB {
		t.Fatalf("invalid memory MB for pid %d: rss=%v hwm=%v ok=%v", pid, rssMB, hwmMB, memOK)
	}
}

func TestRewriteExtensionsIsolationAndPruning(t *testing.T) {
	origQueueDir := t.TempDir()
	sentinelPath := filepath.Join(origQueueDir, "sentinel.txt")
	if err := os.WriteFile(sentinelPath, []byte("keep-untouched"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}
	storageRoot := t.TempDir()

	yamlWithStorageAndInactiveHC := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  file_storage/bq_logs:
    directory: ` + origQueueDir + `
    compaction:
      directory: ` + origQueueDir + `
receivers:
  otlp: {}
exporters:
  bigquery:
    sending_queue:
      enabled: true
      storage: file_storage/bq_logs
service:
  extensions: [file_storage/bq_logs]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		StreamPoolSize:      2,
		ConnectionPoolSize:  2,
		MaxInflightRequests: 8,
		MaxRequestBytes:     8 * 1024 * 1024,
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43170",
		healthAddr:  "127.0.0.1:13130",
		storageRoot: storageRoot,
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}

	out, meta, err := rewriteCollectorLoopbackConfig([]byte(yamlWithStorageAndInactiveHC), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig() error: %v", err)
	}
	if meta.hasHealthCheck {
		t.Fatal("expected meta.hasHealthCheck=false when health_check is omitted from service.extensions")
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	extMap, _ := doc["extensions"].(map[string]any)
	if _, hasHC := extMap["health_check"]; hasHC {
		t.Fatal("expected inactive extensions.health_check to be pruned")
	}
	fsMap, ok := extMap["file_storage/bq_logs"].(map[string]any)
	if !ok {
		t.Fatalf("expected file_storage/bq_logs in extensions, got %#v", extMap)
	}
	gotQueueDir, _ := fsMap["directory"].(string)
	compMap, _ := fsMap["compaction"].(map[string]any)
	gotCompDir, _ := compMap["directory"].(string)
	if !strings.HasPrefix(gotQueueDir, storageRoot) || gotQueueDir == origQueueDir {
		t.Fatalf("file_storage directory = %q, want under %q", gotQueueDir, storageRoot)
	}
	if !strings.HasPrefix(gotCompDir, storageRoot) || gotCompDir == origQueueDir {
		t.Fatalf("file_storage compaction.directory = %q, want under %q", gotCompDir, storageRoot)
	}
	entries, err := os.ReadDir(origQueueDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "sentinel.txt" {
		t.Fatalf("original queue dir modified: entries=%v err=%v", entries, err)
	}

	// Unenabled sending_queue.storage must fail.
	unenabledStorageYAML := `
extensions:
  file_storage:
    directory: /tmp/unused
receivers:
  otlp: {}
exporters:
  bigquery:
    sending_queue:
      storage: file_storage
service:
  extensions: []
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(unenabledStorageYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error when sending_queue.storage is not in service.extensions")
	}

	// Unsupported sending_queue.storage must fail.
	badStorageYAML := `
extensions:
  redis_storage: {}
receivers:
  otlp: {}
exporters:
  bigquery:
    sending_queue:
      storage: redis_storage
service:
  extensions: [redis_storage]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(badStorageYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error when sending_queue.storage references non-file_storage extension")
	}

	// Unsupported active extension must fail.
	badExtYAML := `
extensions:
  pprof:
    endpoint: 0.0.0.0:1777
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  extensions: [pprof]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(badExtYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error for unsupported active extension pprof")
	}
}

func TestRewriteOffloadRedactionPipelinesExportersReceiversAndMetadata(t *testing.T) {
	cfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		Redaction:           true,
		OffloadDir:          "/tmp/local-offload-ignored-in-collector",
		StreamPoolSize:      2,
		ConnectionPoolSize:  2,
		MaxInflightRequests: 8,
		MaxRequestBytes:     8 * 1024 * 1024,
	}
	ep := collectorEndpointOverride{
		otlpAddr:       "127.0.0.1:43171",
		extraOTLPAddrs: []string{"127.0.0.1:43172"},
		healthAddr:     "127.0.0.1:13131",
		storageRoot:    t.TempDir(),
		useBQFake:      true,
		fakeGRPCURL:    "127.0.0.1:50051",
		fakeRESTURL:    "http://127.0.0.1:8080",
	}

	// Offload enabled in fake mode must fail.
	offloadEnabledYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    offload:
      enabled: true
      bucket: prod-bucket
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnabledYAML), cfg, "logs", ep); err == nil || !strings.Contains(err.Error(), "--collector-allow-live") {
		t.Fatalf("expected --collector-allow-live error for offload.enabled in fake mode, got %v", err)
	}

	// Named pipeline logs/access + offload.enabled:false stripped + redaction honored even with OffloadDir set + multi-OTLP receivers + YAML backpressure + custom table.
	namedPipelineYAML := `
receivers:
  otlp: {}
  otlp/edge: {}
exporters:
  bigquery/access:
    logs:
      table: custom_access_logs
    write:
      backpressure:
        enabled: true
    offload:
      enabled: false
      bucket: unused-bucket
service:
  pipelines:
    logs/access:
      receivers: [otlp, otlp/edge]
      exporters: [bigquery/access]
    traces/main:
      receivers: [otlp]
      exporters: [bigquery/access]
`
	out, meta, err := rewriteCollectorLoopbackConfig([]byte(namedPipelineYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(namedPipeline) error: %v", err)
	}
	if meta.activePipelineKey != "logs/access" {
		t.Fatalf("activePipelineKey = %q, want logs/access", meta.activePipelineKey)
	}
	if meta.activeExporterID != "bigquery/access" {
		t.Fatalf("activeExporterID = %q, want bigquery/access", meta.activeExporterID)
	}
	if meta.effectiveTable != "custom_access_logs" {
		t.Fatalf("effectiveTable = %q, want custom_access_logs", meta.effectiveTable)
	}
	if !meta.effectiveRedaction {
		t.Fatal("expected effectiveRedaction=true when cfg.Redaction=true even with OffloadDir set")
	}
	if !meta.effectiveBackpressure {
		t.Fatal("expected effectiveBackpressure=true from YAML write.backpressure.enabled=true")
	}
	if !slices.Equal(meta.extraOTLPAddrs, []string{"127.0.0.1:43172"}) {
		t.Fatalf("extraOTLPAddrs = %v, want [127.0.0.1:43172]", meta.extraOTLPAddrs)
	}

	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal namedPipeline out: %v", err)
	}
	exporters, _ := doc["exporters"].(map[string]any)
	bqAccess, _ := exporters["bigquery/access"].(map[string]any)
	if _, hasOffload := bqAccess["offload"]; hasOffload {
		t.Fatal("expected offload block to be deleted in fake mode when enabled:false")
	}
	redMap, _ := bqAccess["redaction"].(map[string]any)
	if redMap == nil || redMap["enabled"] != true {
		t.Fatalf("expected redaction.enabled=true, got %#v", redMap)
	}
	recvs, _ := doc["receivers"].(map[string]any)
	r0 := recvs["otlp"].(map[string]any)["protocols"].(map[string]any)["grpc"].(map[string]any)["endpoint"]
	r1 := recvs["otlp/edge"].(map[string]any)["protocols"].(map[string]any)["grpc"].(map[string]any)["endpoint"]
	if r0 != "127.0.0.1:43171" || r1 != "127.0.0.1:43172" {
		t.Fatalf("receiver endpoints = (%v, %v), want (127.0.0.1:43171, 127.0.0.1:43172)", r0, r1)
	}

	// Fallback to 127.0.0.1:0 when extraOTLPAddrs is omitted.
	epNoExtra := ep
	epNoExtra.extraOTLPAddrs = nil
	_, metaFallback, err := rewriteCollectorLoopbackConfig([]byte(namedPipelineYAML), cfg, "logs", epNoExtra)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(no extraOTLPAddrs) error: %v", err)
	}
	if !slices.Equal(metaFallback.extraOTLPAddrs, []string{"127.0.0.1:0"}) {
		t.Fatalf("fallback extraOTLPAddrs = %v, want [127.0.0.1:0]", metaFallback.extraOTLPAddrs)
	}

	// Multiple pipelines for same signal must fail.
	multiPipeYAML := `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    logs/access:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(multiPipeYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error for multiple logs pipelines (logs and logs/access)")
	}

	// Multiple exporters in active pipeline must fail.
	multiExpYAML := `
receivers:
  otlp: {}
exporters:
  bigquery: {}
  bigquery/2: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery, bigquery/2]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(multiExpYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error for multiple bigquery exporters [bigquery, bigquery/2]")
	}

	// Metric exporter label filtering by activeExporterID.
	promBody := `
otelcol_exporter_bigquery_acknowledged_rows{exporter="bigquery/access",signal="logs"} 42
otelcol_exporter_bigquery_acknowledged_rows{exporter="bigquery/other",signal="logs"} 999
otelcol_exporter_queue_size{exporter="bigquery/access"} 3
otelcol_exporter_queue_size{exporter="bigquery/other"} 50
otelcol_exporter_send_failed_log_records{exporter="bigquery/access"} 1
otelcol_exporter_send_failed_log_records{exporter="bigquery/other"} 20
`
	filtered := parseCollectorPrometheusMetrics(promBody, "logs", "bigquery/access")
	if filtered.Telemetry.AcknowledgedRows != 42 || filtered.QueueSize != 3 || filtered.SendFailed != 1 {
		t.Fatalf("exporter label filtering mismatch: acked=%d queue=%d sendFailed=%d", filtered.Telemetry.AcknowledgedRows, filtered.QueueSize, filtered.SendFailed)
	}
}

func TestFormatCollectorExitErrAndZeroExitSubprocess(t *testing.T) {
	if os.Getenv("GO_WANT_COLLECTOR_HELPER") == "exit0" {
		_, _ = os.Stdout.WriteString("helper clean exit 0\n")
		os.Exit(0)
	}

	diag := &boundedDiagBuffer{}
	_, _ = diag.Write([]byte("clean shutdown"))
	errNil := formatCollectorExitErr("collector exited", nil, diag)
	if strings.Contains(errNil.Error(), "%!w") || !strings.Contains(errNil.Error(), "exit status 0") {
		t.Fatalf("unexpected nil exit err format: %q", errNil.Error())
	}

	sentinel := errors.New("exit status 2")
	errWrapped := formatCollectorExitErr("collector exited", sentinel, diag)
	if !errors.Is(errWrapped, sentinel) {
		t.Fatalf("expected wrapped sentinel error, got %v", errWrapped)
	}

	startExit0Helper := func(t *testing.T) (<-chan struct{}, *error, *boundedDiagBuffer) {
		t.Helper()
		d := &boundedDiagBuffer{}
		cmd := exec.Command(os.Args[0], "-test.run=^TestFormatCollectorExitErrAndZeroExitSubprocess$")
		cmd.Env = append(os.Environ(), "GO_WANT_COLLECTOR_HELPER=exit0")
		cmd.Stdout = d
		cmd.Stderr = d
		if err := cmd.Start(); err != nil {
			t.Fatalf("start exit0 helper: %v", err)
		}
		doneCh := make(chan struct{})
		var waitErr error
		go func() {
			waitErr = cmd.Wait()
			close(doneCh)
		}()
		<-doneCh
		return doneCh, &waitErr, d
	}

	ctx := context.Background()
	deadLis, deadAddrLis, err := reserveLoopbackAddr(ctx)
	if err != nil {
		t.Fatalf("reserveLoopbackAddr: %v", err)
	}
	_ = deadLis.Close()

	doneCh1, waitErr1, diag1 := startExit0Helper(t)
	readyErr := waitCollectorReady(ctx, doneCh1, waitErr1, diag1, deadAddrLis, "", deadAddrLis, false)
	if readyErr == nil || strings.Contains(readyErr.Error(), "%!w") || !strings.Contains(readyErr.Error(), "exit status 0") {
		t.Fatalf("waitCollectorReady zero-exit error = %v, want clean exit status 0 without %%!w", readyErr)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("otelcol_exporter_bigquery_acknowledged_rows{signal=\"logs\"} 0\n"))
	}))
	defer srv.Close()

	doneCh2, waitErr2, diag2 := startExit0Helper(t)
	_, drainErr := drainCollectorPipeline(ctx, srv.Client(), srv.Listener.Addr().String(), "logs", "bigquery", collectorMetricsSample{}, 10, 5*time.Second, doneCh2, waitErr2, diag2)
	if drainErr == nil || strings.Contains(drainErr.Error(), "%!w") || !strings.Contains(drainErr.Error(), "exit status 0") {
		t.Fatalf("drainCollectorPipeline zero-exit error = %v, want clean exit status 0 without %%!w", drainErr)
	}
}

func findCollectorDistBinary(t *testing.T) string {
	t.Helper()
	resolved := resolveCollectorConfigPath(filepath.Join("otelcol-bq-dist", "otelcol-bq"))
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		t.Skipf("otelcol-bq binary not found at %q; skipping end-to-end collector binary test", resolved)
	}
	return resolved
}

func TestCollectorIntegrationNamedPipelineStorageIsolationAndFaults(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	origQueueDir := t.TempDir()
	sentinel := filepath.Join(origQueueDir, "untouched.marker")
	if err := os.WriteFile(sentinel, []byte("original"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	cfgYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  file_storage/access:
    directory: ` + origQueueDir + `
    compaction:
      directory: ` + origQueueDir + `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 50
    timeout: 20ms
exporters:
  bigquery/access:
    project: orig-proj
    dataset: orig_ds
    location: US
    logs:
      table: custom_access_logs
    sending_queue:
      enabled: true
      storage: file_storage/access
service:
  extensions: [health_check, file_storage/access]
  pipelines:
    logs/access:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery/access]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-e2e.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write collector-e2e.yaml: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// (a) Named pipeline logs/access + isolated file_storage + custom table, leaving origQueueDir untouched.
	cfgA := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       25,
		Duration:        300 * time.Millisecond,
		WarmupDuration:  100 * time.Millisecond,
		maxBatches:      4,
	}
	if err := cfgA.Normalize(); err != nil {
		t.Fatalf("cfgA.Normalize(): %v", err)
	}
	resA, softErrA, hardErrA := runCollectorSingleSignal(ctx, cfgA, "logs")
	if hardErrA != nil || softErrA != nil {
		t.Fatalf("runCollectorSingleSignal(A) hardErr=%v softErr=%v", hardErrA, softErrA)
	}
	if resA.Telemetry.AcknowledgedRows <= 0 {
		t.Fatalf("expected AcknowledgedRows > 0, got %d", resA.Telemetry.AcknowledgedRows)
	}
	entries, err := os.ReadDir(origQueueDir)
	if err != nil || len(entries) != 1 || entries[0].Name() != "untouched.marker" {
		t.Fatalf("expected original file_storage directory untouched, got entries=%v err=%v", entries, err)
	}

	// (b) Periodic fault injection: -simulate-throttle-every=1 -simulate-ack-delay=50ms.
	cfgB := RunnerConfig{
		Mode:                  ModeCollector,
		CollectorBin:          collectorBin,
		CollectorConfig:       cfgPath,
		Signals:               []string{"logs"},
		Workers:               1,
		BatchSize:             20,
		Duration:              300 * time.Millisecond,
		WarmupDuration:        0,
		SimulateThrottleEvery: 1,
		SimulateAckDelay:      50 * time.Millisecond,
		Backpressure:          true,
		maxBatches:            2,
	}
	if err := cfgB.Normalize(); err != nil {
		t.Fatalf("cfgB.Normalize(): %v", err)
	}
	resB, softErrB, hardErrB := runCollectorSingleSignal(ctx, cfgB, "logs")
	if hardErrB != nil || softErrB != nil {
		t.Fatalf("runCollectorSingleSignal(B) hardErr=%v softErr=%v", hardErrB, softErrB)
	}
	if resB.Telemetry.Retries <= 0 {
		t.Fatalf("expected Telemetry.Retries > 0 under SimulateThrottleEvery=1, got %d", resB.Telemetry.Retries)
	}
	if resB.ElapsedSeconds < 0.04 {
		t.Fatalf("expected ElapsedSeconds >= 0.04 under SimulateAckDelay=50ms, got %v", resB.ElapsedSeconds)
	}
}
