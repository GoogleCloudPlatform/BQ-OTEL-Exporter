// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/descriptorpb"
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
	phaseStats := runCollectorWorkerPhase(ctx, cfg, "logs", cfg.Duration, 0, nil, makeBatch, nil, client, nil, nil)
	if phaseStats.firstErr != nil {
		t.Fatalf("runCollectorWorkerPhase() unexpected error: %v", phaseStats.firstErr)
	}
	if elapsed := time.Since(start); elapsed < 70*time.Millisecond || elapsed >= 3*time.Second {
		t.Fatalf("runCollectorWorkerPhase() wall time = %v, want in [70ms, 3s)", elapsed)
	}
	if phaseStats.recordsSubmitted != 1 {
		t.Fatalf("recordsSubmitted = %d, want 1 (capped to phase budget)", phaseStats.recordsSubmitted)
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

	// Non-map offload reference (e.g. ${file:...}) in fake mode must fail.
	offloadFileRefYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    offload: "${file:/etc/collector/offload.yaml}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadFileRefYAML), cfg, "logs", ep); err == nil || !strings.Contains(err.Error(), "--collector-allow-live") {
		t.Fatalf("expected --collector-allow-live error for non-map offload in fake mode, got %v", err)
	}

	// Non-boolean offload.enabled (e.g. ${env:...}) in fake mode must fail.
	offloadEnvEnabledYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    offload:
      enabled: "${env:OFFLOAD_ENABLED}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnvEnabledYAML), cfg, "logs", ep); err == nil || !strings.Contains(err.Error(), "--collector-allow-live") {
		t.Fatalf("expected --collector-allow-live error for unresolved offload.enabled in fake mode, got %v", err)
	}

	// Non-sequence redaction.blocked_value_patterns must fail.
	badRedactionPatternsYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    redaction:
      blocked_value_patterns: "not-a-sequence"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(badRedactionPatternsYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error when redaction.blocked_value_patterns is not a YAML sequence")
	}

	// Named pipeline logs/access + offload explicitly disabled + redaction patterns merged & deduplicated + custom health_check path + multi-OTLP receivers + YAML backpressure + custom table.
	namedPipelineYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    path: readyz
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
    redaction:
      blocked_value_patterns:
        - 'CUSTOM_TOKEN_[0-9]+'
        - '` + blockedSecretPatterns[0] + `'
    offload:
      enabled: false
      bucket: unused-bucket
service:
  extensions: [health_check]
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
	if !meta.hasHealthCheck || meta.healthCheckPath != "/readyz" {
		t.Fatalf("healthCheck meta = (has=%v, path=%q), want (true, /readyz)", meta.hasHealthCheck, meta.healthCheckPath)
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
	offOut, hasOffload := bqAccess["offload"].(map[string]any)
	if !hasOffload || offOut["enabled"] != false || len(offOut) != 1 {
		t.Fatalf("expected offload={enabled:false} in fake mode, got %#v", bqAccess["offload"])
	}
	redMap, _ := bqAccess["redaction"].(map[string]any)
	if redMap == nil || redMap["enabled"] != true {
		t.Fatalf("expected redaction.enabled=true, got %#v", redMap)
	}
	gotPatterns, pErr := extractYAMLStringSlice(redMap["blocked_value_patterns"])
	if pErr != nil {
		t.Fatalf("extract merged blocked_value_patterns: %v", pErr)
	}
	if len(gotPatterns) != 1+len(blockedSecretPatterns) || gotPatterns[0] != "CUSTOM_TOKEN_[0-9]+" {
		t.Fatalf("merged blocked_value_patterns = %v, want CUSTOM_TOKEN_[0-9]+ followed by deduplicated %v", gotPatterns, blockedSecretPatterns)
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
	readyErr := waitCollectorReady(ctx, doneCh1, waitErr1, diag1, deadAddrLis, "", "", deadAddrLis, false)
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

type fakeCollectorHelperServer struct {
	plogotlp.UnimplementedGRPCServer
	mode        string
	bqWriteCli  storagepb.BigQueryWriteClient
	streamName  string
	rowDesc     *descriptorpb.DescriptorProto
	enc         *protoenc.Encoder
	mu          sync.Mutex
	ackedRows   atomic.Int64
	appendBytes atomic.Int64
	retries     atomic.Int64
	batchSeq    atomic.Int64
}

func (s *fakeCollectorHelperServer) appendRowsToBQFake(ctx context.Context, ids []string) (int64, error) {
	if s.bqWriteCli == nil || len(ids) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	serialized := make([][]byte, 0, len(ids))
	var totalBytes int64
	for _, id := range ids {
		raw, err := s.enc.Encode(transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts.UnixMicro(),
			"receive_time_unix_nano":  ts.UnixNano(),
			"log_name":                "projects/test-project/logs/app",
			"insert_id":               id,
			"body":                    fmt.Sprintf("%q", "payload-"+id),
		})
		if err != nil {
			return 0, err
		}
		serialized = append(serialized, raw)
		totalBytes += int64(len(raw))
	}

	for attempt := range 6 {
		stream, err := s.bqWriteCli.AppendRows(ctx)
		if err != nil {
			return 0, err
		}
		req := &storagepb.AppendRowsRequest{
			WriteStream: s.streamName,
			Rows: &storagepb.AppendRowsRequest_ProtoRows{
				ProtoRows: &storagepb.AppendRowsRequest_ProtoData{
					WriterSchema: &storagepb.ProtoSchema{ProtoDescriptor: s.rowDesc},
					Rows:         &storagepb.ProtoRows{SerializedRows: serialized},
				},
			},
		}
		if sendErr := stream.Send(req); sendErr != nil {
			_ = stream.CloseSend()
			return 0, sendErr
		}
		_ = stream.CloseSend()
		resp, recvErr := stream.Recv()
		if recvErr == nil && resp.GetError() == nil {
			s.ackedRows.Add(int64(len(ids)))
			s.appendBytes.Add(totalBytes)
			return totalBytes, nil
		}
		if attempt < 5 {
			s.retries.Add(1)
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if recvErr != nil {
			return 0, recvErr
		}
		return 0, fmt.Errorf("bqfake status %d: %s", resp.GetError().GetCode(), resp.GetError().GetMessage())
	}
	return 0, nil
}

func (s *fakeCollectorHelperServer) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	n := req.Logs().LogRecordCount()
	seq := s.batchSeq.Add(1)
	resp := plogotlp.NewExportResponse()

	if s.mode == "warmup_partial_reject" && seq == 1 && n > 1 {
		resp.PartialSuccess().SetRejectedLogRecords(1)
		n--
	}

	ids := make([]string, 0, n)
	rlSlice := req.Logs().ResourceLogs()
	idx := 0
	for i := 0; i < rlSlice.Len() && len(ids) < n; i++ {
		slSlice := rlSlice.At(i).ScopeLogs()
		for j := 0; j < slSlice.Len() && len(ids) < n; j++ {
			lrs := slSlice.At(j).LogRecords()
			for k := 0; k < lrs.Len() && len(ids) < n; k++ {
				lr := lrs.At(k)
				id := fmt.Sprintf("b%d-r%d-%s", seq, idx, lr.Body().AsString())
				if v, ok := lr.Attributes().Get("insert_id"); ok && v.Str() != "" {
					id = v.Str()
				}
				ids = append(ids, id)
				idx++
			}
		}
	}

	switch s.mode {
	case "drain_stall":
		half := max(1, len(ids)/2)
		_, err := s.appendRowsToBQFake(ctx, ids[:half])
		return resp, err
	case "replay_with_drop":
		if len(ids) >= 2 {
			deliver := ids[:len(ids)-1]
			if _, err := s.appendRowsToBQFake(ctx, deliver); err != nil {
				return resp, err
			}
			// Replay first row twice so total ackedRows >= submitted while unique delivered < submitted.
			_, err := s.appendRowsToBQFake(ctx, []string{deliver[0], deliver[0]})
			return resp, err
		}
	case "replay_all_delivered":
		if _, err := s.appendRowsToBQFake(ctx, ids); err != nil {
			return resp, err
		}
		if len(ids) > 0 {
			_, err := s.appendRowsToBQFake(ctx, ids[:1])
			return resp, err
		}
		return resp, nil
	case "live_retry_inflation":
		s.ackedRows.Add(int64(len(ids)))
		s.appendBytes.Add(int64(len(ids)) * 2000)
		s.retries.Add(2)
		return resp, nil
	default:
		_, err := s.appendRowsToBQFake(ctx, ids)
		return resp, err
	}
	return resp, nil
}

func runFakeCollectorHelperMain(mode string) {
	var cfgPath string
	for _, arg := range os.Args[1:] {
		if after, ok := strings.CutPrefix(arg, "--config="); ok {
			cfgPath = after
		}
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(2)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "unmarshal config: %v\n", err)
		os.Exit(2)
	}

	recvs, _ := doc["receivers"].(map[string]any)
	otlpMap, _ := recvs["otlp"].(map[string]any)
	protos, _ := otlpMap["protocols"].(map[string]any)
	grpcMap, _ := protos["grpc"].(map[string]any)
	otlpEndpoint, _ := grpcMap["endpoint"].(string)

	var hcEndpoint, hcPath string
	if exts, ok := doc["extensions"].(map[string]any); ok {
		if hc, ok := exts["health_check"].(map[string]any); ok {
			hcEndpoint, _ = hc["endpoint"].(string)
			hcPath, _ = hc["path"].(string)
		}
	}
	if hcPath == "" {
		hcPath = "/"
	} else if !strings.HasPrefix(hcPath, "/") {
		hcPath = "/" + hcPath
	}

	svc, _ := doc["service"].(map[string]any)
	telem, _ := svc["telemetry"].(map[string]any)
	metricsCfg, _ := telem["metrics"].(map[string]any)
	readers, _ := metricsCfg["readers"].([]any)
	var metricsAddr string
	if len(readers) > 0 {
		r0, _ := readers[0].(map[string]any)
		pull, _ := r0["pull"].(map[string]any)
		exp, _ := pull["exporter"].(map[string]any)
		prom, _ := exp["prometheus"].(map[string]any)
		host, _ := prom["host"].(string)
		port, _ := prom["port"].(int)
		metricsAddr = net.JoinHostPort(host, strconv.Itoa(port))
	}

	exporters, _ := doc["exporters"].(map[string]any)
	var bqFakeURL, projectID, datasetID, tableID string
	var activeExpID string
	for k, v := range exporters {
		activeExpID = k
		bqMap, _ := v.(map[string]any)
		projectID, _ = bqMap["project"].(string)
		datasetID, _ = bqMap["dataset"].(string)
		if logsMap, ok := bqMap["logs"].(map[string]any); ok {
			tableID, _ = logsMap["table"].(string)
		}
		if epMap, ok := bqMap["endpoint"].(map[string]any); ok {
			bqFakeURL, _ = epMap["url"].(string)
		}
	}
	if tableID == "" {
		tableID = "otel_logs"
	}

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build logs encoder: %v\n", err)
		os.Exit(2)
	}
	helper := &fakeCollectorHelperServer{
		mode:       mode,
		streamName: fmt.Sprintf("projects/%s/datasets/%s/tables/%s/streams/_default", projectID, datasetID, tableID),
		rowDesc:    logEnc.Descriptor(),
		enc:        logEnc,
	}
	if bqFakeURL != "" {
		conn, dialErr := grpc.NewClient(bqFakeURL, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if dialErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "dial bqfake: %v\n", dialErr)
			os.Exit(2)
		}
		helper.bqWriteCli = storagepb.NewBigQueryWriteClient(conn)
	}

	otlpLis, err := net.Listen("tcp", otlpEndpoint)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "listen otlp: %v\n", err)
		os.Exit(2)
	}
	grpcSrv := grpc.NewServer()
	plogotlp.RegisterGRPCServer(grpcSrv, helper)
	go func() { _ = grpcSrv.Serve(otlpLis) }()

	if hcEndpoint != "" {
		hcLis, hcErr := net.Listen("tcp", hcEndpoint)
		if hcErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "listen health_check: %v\n", hcErr)
			os.Exit(2)
		}
		hcMux := http.NewServeMux()
		hcMux.HandleFunc(hcPath, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		hcSrv := &http.Server{Handler: hcMux, ReadHeaderTimeout: 2 * time.Second}
		go func() { _ = hcSrv.Serve(hcLis) }()
	}

	if metricsAddr != "" {
		mLis, mErr := net.Listen("tcp", metricsAddr)
		if mErr != nil {
			_, _ = fmt.Fprintf(os.Stderr, "listen metrics: %v\n", mErr)
			os.Exit(2)
		}
		mMux := http.NewServeMux()
		mMux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = fmt.Fprintf(w,
				"otelcol_exporter_bigquery_acknowledged_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_append_bytes{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_retries{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_queue_size{exporter=%q} 0\n"+
					"otelcol_exporter_bigquery_inflight_requests{exporter=%q,signal=\"logs\"} 0\n"+
					"otelcol_process_runtime_heap_alloc_bytes 1048576\n",
				activeExpID, helper.ackedRows.Load(),
				activeExpID, helper.appendBytes.Load(),
				activeExpID, helper.retries.Load(),
				activeExpID, activeExpID,
			)
		})
		mSrv := &http.Server{Handler: mMux, ReadHeaderTimeout: 2 * time.Second}
		go func() { _ = mSrv.Serve(mLis) }()
	}

	if mode == "crash_mid_phase" {
		time.Sleep(250 * time.Millisecond)
		_, _ = os.Stderr.WriteString("simulated mid-phase collector crash\n")
		os.Exit(2)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
	if mode == "drain_stall" {
		// Flush extra rows during shutdown AFTER drain cutoff to verify pre-shutdown byte snapshot.
		_, _ = helper.appendRowsToBQFake(context.Background(), []string{"post-cutoff-1", "post-cutoff-2", "post-cutoff-3", "post-cutoff-4"})
	}
	grpcSrv.Stop()
	os.Exit(0)
}

func findCollectorDistBinary(t *testing.T) string {
	t.Helper()
	resolved := resolveCollectorConfigPath(filepath.Join("otelcol-bq-dist", "otelcol-bq"))
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() {
		if os.Getenv("BQ_TEST_COLLECTOR_INTEGRATION") == "1" {
			t.Fatalf("BQ_TEST_COLLECTOR_INTEGRATION=1 requires built collector binary at %q, but stat failed: %v", resolved, err)
		}
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
	if !resB.UniqueDeliveryVerified {
		t.Fatal("expected UniqueDeliveryVerified=true under SimulateThrottleEvery/SimulateAckDelay")
	}
	if resB.DeliveredRows != resB.RecordsSubmitted {
		t.Fatalf("DeliveredRows = %d, want RecordsSubmitted = %d", resB.DeliveredRows, resB.RecordsSubmitted)
	}

	// (c) SimulateThrottleEvery=2 verifies unique delivery without throughput/row-size inflation.
	cfgC := RunnerConfig{
		Mode:                  ModeCollector,
		CollectorBin:          collectorBin,
		CollectorConfig:       cfgPath,
		Signals:               []string{"logs"},
		Workers:               2,
		BatchSize:             15,
		Duration:              300 * time.Millisecond,
		WarmupDuration:        0,
		SimulateThrottleEvery: 2,
		maxBatches:            4,
	}
	if err := cfgC.Normalize(); err != nil {
		t.Fatalf("cfgC.Normalize(): %v", err)
	}
	resC, softErrC, hardErrC := runCollectorSingleSignal(ctx, cfgC, "logs")
	if hardErrC != nil || softErrC != nil {
		t.Fatalf("runCollectorSingleSignal(C) hardErr=%v softErr=%v", hardErrC, softErrC)
	}
	if !resC.UniqueDeliveryVerified || resC.DeliveredRows != resC.RecordsSubmitted {
		t.Fatalf("unique delivery C mismatch: verified=%v delivered=%d submitted=%d", resC.UniqueDeliveryVerified, resC.DeliveredRows, resC.RecordsSubmitted)
	}
	if resC.BytesPerRow <= 0 {
		t.Fatalf("expected positive BytesPerRow, got %v", resC.BytesPerRow)
	}
}

func configureCollectorHelperEnv(t *testing.T, helperMode string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	t.Setenv("GO_WANT_FAKE_COLLECTOR", helperMode)
	return exe
}

func TestCollectorSubprocessHelper(t *testing.T) {
	baseYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    path: readyz
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "helper-collector.yaml")
	if err := os.WriteFile(cfgPath, []byte(baseYAML), 0o600); err != nil {
		t.Fatalf("write helper-collector.yaml: %v", err)
	}

	t.Run("ShortSoakPacingAndCustomHealthCheckPath", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "ok")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       100,
			TargetRate:      5,
			Duration:        600 * time.Millisecond,
			WarmupDuration:  0,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignal hardErr=%v softErr=%v", hardErr, softErr)
		}
		if res.RecordsSubmitted != 3 || res.DeliveredRows != 3 {
			t.Fatalf("submitted=%d delivered=%d, want 3/3", res.RecordsSubmitted, res.DeliveredRows)
		}
		if res.ElapsedSeconds < 0.55 {
			t.Fatalf("ElapsedSeconds = %v, want >= 0.55s (phase must stay open until deadline)", res.ElapsedSeconds)
		}
		if res.AchievedRowsPerSec > 10.0 {
			t.Fatalf("AchievedRowsPerSec = %v, want ~5 rows/s (<= 10)", res.AchievedRowsPerSec)
		}
	})

	t.Run("MidPhaseCrashCancelsPromptly", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "crash_mid_phase")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         2,
			BatchSize:       10,
			TargetRate:      5,
			Duration:        10 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		elapsed := time.Since(start)
		if hardErr == nil && softErr == nil {
			t.Fatal("expected error when collector crashes mid-phase")
		}
		if elapsed >= 5*time.Second {
			t.Fatalf("mid-phase crash took %v, want < 5s (workers should cancel immediately on child exit)", elapsed)
		}
	})

	t.Run("WarmupPartialOTLPRejectionFailsGate", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "warmup_partial_reject")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       10,
			TargetRate:      20,
			WarmupDuration:  200 * time.Millisecond,
			Duration:        200 * time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr == nil || !strings.Contains(hardErr.Error(), "otlp_rejected=1") {
			t.Fatalf("expected warmup gate error mentioning otlp_rejected=1, got %v", hardErr)
		}
	})

	t.Run("DrainTimeoutAllowPartialFailuresPreShutdownByteCutoff", func(t *testing.T) {
		prevMin := collectorMinDrainTimeout
		collectorMinDrainTimeout = 200 * time.Millisecond
		t.Cleanup(func() { collectorMinDrainTimeout = prevMin })

		bin := configureCollectorHelperEnv(t, "drain_stall")
		cfg := RunnerConfig{
			Mode:                 ModeCollector,
			CollectorBin:         bin,
			CollectorConfig:      cfgPath,
			Signals:              []string{"logs"},
			Workers:              1,
			BatchSize:            10,
			Duration:             150 * time.Millisecond,
			CallTimeout:          200 * time.Millisecond,
			AllowPartialFailures: true,
			maxBatches:           1,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, _, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr != nil {
			t.Fatalf("expected nil hardErr under AllowPartialFailures=true, got %v", hardErr)
		}
		if !res.IncompleteDrain || res.DrainWarning == "" {
			t.Fatalf("expected IncompleteDrain=true and non-empty DrainWarning, got incomplete=%v warn=%q", res.IncompleteDrain, res.DrainWarning)
		}
		if res.BatchesFailed < 1 {
			t.Fatalf("expected BatchesFailed >= 1 on incomplete drain, got %d", res.BatchesFailed)
		}
		// Helper wrote 5 rows before cutoff and 4 extra rows on SIGTERM after cutoff;
		// pre-shutdown snapshot ensures BytesPerRow equals AttemptedBytesPerAckedRow (~30B), not inflated by 9/5.
		if res.Telemetry.AcknowledgedRows != 5 {
			t.Fatalf("AcknowledgedRows = %d, want 5", res.Telemetry.AcknowledgedRows)
		}
		if res.BytesPerRow != res.AttemptedBytesPerAckedRow {
			t.Fatalf("BytesPerRow (%v) != AttemptedBytesPerAckedRow (%v); post-cutoff shutdown bytes leaked into snapshot", res.BytesPerRow, res.AttemptedBytesPerAckedRow)
		}
	})

	t.Run("ReplayedRowsAndUniqueDeliveryVerification", func(t *testing.T) {
		prevMin := collectorMinDrainTimeout
		collectorMinDrainTimeout = 250 * time.Millisecond
		t.Cleanup(func() { collectorMinDrainTimeout = prevMin })

		// 1) Replay masking a dropped row under fault simulation is caught by unique-ack drain!
		t.Run("replay_with_drop", func(t *testing.T) {
			binDrop := configureCollectorHelperEnv(t, "replay_with_drop")
			cfgDrop := RunnerConfig{
				Mode:                 ModeCollector,
				CollectorBin:         binDrop,
				CollectorConfig:      cfgPath,
				Signals:              []string{"logs"},
				Workers:              1,
				BatchSize:            4,
				Duration:             150 * time.Millisecond,
				CallTimeout:          200 * time.Millisecond,
				SimulateAckDelay:     5 * time.Millisecond,
				AllowPartialFailures: true,
				maxBatches:           1,
			}
			if err := cfgDrop.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resDrop, _, hardErr := runCollectorSingleSignal(ctx, cfgDrop, "logs")
			if hardErr != nil {
				t.Fatalf("unexpected hardErr: %v", hardErr)
			}
			if !resDrop.UniqueDeliveryVerified || resDrop.DeliveredRows != 3 || resDrop.Telemetry.AcknowledgedRows != 5 || resDrop.Telemetry.ReplayedRows != 2 || !resDrop.IncompleteDrain {
				t.Fatalf("expected unique delivery to catch masked drop (delivered=3, acked=5, replayed=2, incompleteDrain=true), got verified=%v delivered=%d acked=%d replayed=%d incomplete=%v",
					resDrop.UniqueDeliveryVerified, resDrop.DeliveredRows, resDrop.Telemetry.AcknowledgedRows, resDrop.Telemetry.ReplayedRows, resDrop.IncompleteDrain)
			}
		})

		// 2) Replay when all rows ARE uniquely delivered succeeds under fault simulation without inflating DeliveredRows or BytesPerRow.
		t.Run("replay_all_delivered", func(t *testing.T) {
			binAll := configureCollectorHelperEnv(t, "replay_all_delivered")
			cfgAll := RunnerConfig{
				Mode:             ModeCollector,
				CollectorBin:     binAll,
				CollectorConfig:  cfgPath,
				Signals:          []string{"logs"},
				Workers:          1,
				BatchSize:        4,
				Duration:         150 * time.Millisecond,
				SimulateAckDelay: 5 * time.Millisecond,
				maxBatches:       1,
			}
			if err := cfgAll.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			resAll, softErrAll, hardErrAll := runCollectorSingleSignal(ctx, cfgAll, "logs")
			if hardErrAll != nil || softErrAll != nil {
				t.Fatalf("unexpected err: hard=%v soft=%v", hardErrAll, softErrAll)
			}
			if !resAll.UniqueDeliveryVerified || resAll.DeliveredRows != 4 || resAll.Telemetry.ReplayedRows != 1 {
				t.Fatalf("unexpected replay_all_delivered stats: verified=%v delivered=%d replayed=%d", resAll.UniqueDeliveryVerified, resAll.DeliveredRows, resAll.Telemetry.ReplayedRows)
			}
		})
	})

	t.Run("LiveModeRetriesMarkBytesPerRowUnavailable", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "live_retry_inflation")
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorBin:       bin,
			CollectorConfig:    cfgPath,
			CollectorAllowLive: true,
			ProjectID:          "live-test-proj",
			DatasetID:          "live_test_ds",
			Signals:            []string{"logs"},
			Workers:            1,
			BatchSize:          5,
			Duration:           150 * time.Millisecond,
			maxBatches:         1,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr != nil || softErr != nil {
			t.Fatalf("unexpected err: hard=%v soft=%v", hardErr, softErr)
		}
		if !res.BytesPerRowUnavailable || res.BytesPerRow != 0 || res.WireMBPerSec != 0 {
			t.Fatalf("expected BytesPerRowUnavailable=true and zero BytesPerRow/WireMBPerSec when live retries > 0, got unavail=%v bpr=%v wire=%v", res.BytesPerRowUnavailable, res.BytesPerRow, res.WireMBPerSec)
		}
		if res.AttemptedBytesPerAckedRow != 2000 {
			t.Fatalf("AttemptedBytesPerAckedRow = %v, want 2000", res.AttemptedBytesPerAckedRow)
		}
		if res.ByteLayers != nil {
			t.Fatalf("expected ByteLayers == nil when BytesPerRowUnavailable, got %+v", res.ByteLayers)
		}
	})
}
