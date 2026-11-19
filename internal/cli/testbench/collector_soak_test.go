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
	"runtime"
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
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
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
	if valid.StreamPoolSize != 0 || valid.ConnectionPoolSize != 0 || valid.MaxInflightRequests != 0 || valid.MaxRequestBytes != 0 {
		t.Fatalf("expected zero write.* fields in collector mode to inherit YAML settings, got stream=%d conn=%d inflight=%d reqBytes=%d",
			valid.StreamPoolSize, valid.ConnectionPoolSize, valid.MaxInflightRequests, valid.MaxRequestBytes)
	}

	nonCollector := RunnerConfig{Mode: ModeBQFake}
	if err := nonCollector.Normalize(); err != nil {
		t.Fatalf("ModeBQFake Normalize() unexpected error: %v", err)
	}
	if nonCollector.StreamPoolSize != 4 || nonCollector.ConnectionPoolSize != 4 || nonCollector.MaxInflightRequests != 32 || nonCollector.MaxRequestBytes != 8*1024*1024 {
		t.Fatalf("ModeBQFake write.* defaults = (%d, %d, %d, %d), want (4, 4, 32, 8388608)",
			nonCollector.StreamPoolSize, nonCollector.ConnectionPoolSize, nonCollector.MaxInflightRequests, nonCollector.MaxRequestBytes)
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

	// Non-map offload reference (e.g. ${file:...}) must fail closed in both fake and live modes.
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
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadFileRefYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected fail-closed error for non-map offload in fake mode")
	}
	liveEP := ep
	liveEP.useBQFake = false
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadFileRefYAML), cfg, "logs", liveEP); err == nil {
		t.Fatal("expected fail-closed error for non-map offload in live mode")
	}

	// ${env:...} offload.enabled resolves booleans: true fails in fake mode, false/unset succeeds, invalid fails.
	offloadEnvEnabledYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    offload:
      enabled: "${env:TEST_OFFLOAD_ENABLED_BOOL}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnvEnabledYAML), cfg, "logs", ep); err != nil {
		t.Fatalf("expected unset ${env:TEST_OFFLOAD_ENABLED_BOOL} to resolve as false in fake mode, got %v", err)
	}
	t.Setenv("TEST_OFFLOAD_ENABLED_BOOL", "false")
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnvEnabledYAML), cfg, "logs", ep); err != nil {
		t.Fatalf("expected TEST_OFFLOAD_ENABLED_BOOL=false to succeed in fake mode, got %v", err)
	}
	t.Setenv("TEST_OFFLOAD_ENABLED_BOOL", "true")
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnvEnabledYAML), cfg, "logs", ep); err == nil || !strings.Contains(err.Error(), "--collector-allow-live") {
		t.Fatalf("expected --collector-allow-live error for TEST_OFFLOAD_ENABLED_BOOL=true in fake mode, got %v", err)
	}
	t.Setenv("TEST_OFFLOAD_ENABLED_BOOL", "yes")
	if _, _, err := rewriteCollectorLoopbackConfig([]byte(offloadEnvEnabledYAML), cfg, "logs", ep); err == nil {
		t.Fatal("expected error for invalid boolean TEST_OFFLOAD_ENABLED_BOOL=yes")
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
	mode                 string
	bqWriteCli           storagepb.BigQueryWriteClient
	streamName           string
	rowDesc              *descriptorpb.DescriptorProto
	enc                  *protoenc.Encoder
	quarantineStreamName string
	quarantineRowDesc    *descriptorpb.DescriptorProto
	quarantineEnc        *protoenc.Encoder
	mu                   sync.Mutex
	ackedRows            atomic.Int64
	rejectedRows         atomic.Int64
	quarantinedRows      atomic.Int64
	appendBytes          atomic.Int64
	retries              atomic.Int64
	batchSeq             atomic.Int64
}

func (s *fakeCollectorHelperServer) appendQuarantineRowToBQFake(ctx context.Context, rawPayload string) error {
	if s.bqWriteCli == nil || s.quarantineEnc == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	raw, err := s.quarantineEnc.Encode(transform.Row{
		"ingest_time":   ts.UnixMicro(),
		"signal":        schema.SignalLogs,
		"error_code":    "value_size",
		"error_message": "attribute exceeds max value size",
		"raw_payload":   rawPayload,
	})
	if err != nil {
		return err
	}
	for attempt := range 6 {
		stream, sErr := s.bqWriteCli.AppendRows(ctx)
		if sErr != nil {
			return sErr
		}
		req := &storagepb.AppendRowsRequest{
			WriteStream: s.quarantineStreamName,
			Rows: &storagepb.AppendRowsRequest_ProtoRows{
				ProtoRows: &storagepb.AppendRowsRequest_ProtoData{
					WriterSchema: &storagepb.ProtoSchema{ProtoDescriptor: s.quarantineRowDesc},
					Rows:         &storagepb.ProtoRows{SerializedRows: [][]byte{raw}},
				},
			},
		}
		if sendErr := stream.Send(req); sendErr != nil {
			_ = stream.CloseSend()
			return sendErr
		}
		_ = stream.CloseSend()
		resp, recvErr := stream.Recv()
		if recvErr == nil && resp.GetError() == nil {
			s.rejectedRows.Add(1)
			s.quarantinedRows.Add(1)
			return nil
		}
		if attempt < 5 {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		if recvErr != nil {
			return recvErr
		}
		return fmt.Errorf("bqfake quarantine status %d: %s", resp.GetError().GetCode(), resp.GetError().GetMessage())
	}
	return nil
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
	case "quarantine_one_of_four":
		deliverIDs := []string{"q-log-0", "q-log-1", "q-log-2"}
		if len(ids) < 3 {
			deliverIDs = ids
		}
		if _, err := s.appendRowsToBQFake(ctx, deliverIDs); err != nil {
			return resp, err
		}
		if err := s.appendQuarantineRowToBQFake(ctx, strings.Repeat("Q", 2048)); err != nil {
			return resp, err
		}
		return resp, nil
	case "live_retry_inflation":
		s.ackedRows.Add(int64(len(ids)))
		s.appendBytes.Add(int64(len(ids)) * 2000)
		s.retries.Add(2)
		return resp, nil
	case "live_partial_delivery":
		acked := max(0, len(ids)-4)
		rejected := len(ids) - acked
		s.ackedRows.Add(int64(acked))
		s.rejectedRows.Add(int64(rejected))
		s.appendBytes.Add(10000)
		return resp, nil
	default:
		_, err := s.appendRowsToBQFake(ctx, ids)
		return resp, err
	}
	return resp, nil
}

func runFakeCollectorHelperMain(mode string) {
	if mode == "exit_immediately_code3" {
		_, _ = os.Stderr.WriteString("child exited non-zero\n")
		os.Exit(3)
	}
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
	quarantineEnc, err := protoenc.New(schema.QuarantineTableSchema())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "build quarantine encoder: %v\n", err)
		os.Exit(2)
	}
	helper := &fakeCollectorHelperServer{
		mode:                 mode,
		streamName:           fmt.Sprintf("projects/%s/datasets/%s/tables/%s/streams/_default", projectID, datasetID, tableID),
		rowDesc:              logEnc.Descriptor(),
		enc:                  logEnc,
		quarantineStreamName: fmt.Sprintf("projects/%s/datasets/%s/tables/otel_quarantine/streams/_default", projectID, datasetID),
		quarantineRowDesc:    quarantineEnc.Descriptor(),
		quarantineEnc:        quarantineEnc,
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
			acked := helper.ackedRows.Load()
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = fmt.Fprintf(w,
				"otelcol_exporter_bigquery_acknowledged_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_rejected_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_quarantined_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_append_bytes{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_retries{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_queue_size{exporter=%q} 0\n"+
					"otelcol_exporter_bigquery_inflight_requests{exporter=%q,signal=\"logs\"} 0\n"+
					"otelcol_process_runtime_heap_alloc_bytes 1048576\n",
				activeExpID, acked,
				activeExpID, helper.rejectedRows.Load(),
				activeExpID, helper.quarantinedRows.Load(),
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
	if mode == "exit_error_on_sigterm" {
		_, _ = os.Stderr.WriteString("post-drain fatal exit\n")
		os.Exit(3)
	}
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
		BatchSize:             55,
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
	if resC.Telemetry.Retries <= 0 {
		t.Fatalf("expected Telemetry.Retries > 0 under SimulateThrottleEvery=2, got %d", resC.Telemetry.Retries)
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

	t.Run("SimulateThrottleNeverFiredFailsClosed", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "ok")
		cfg := RunnerConfig{
			Mode:                  ModeCollector,
			CollectorBin:          bin,
			CollectorConfig:       cfgPath,
			Signals:               []string{"logs"},
			Workers:               1,
			BatchSize:             4,
			Duration:              150 * time.Millisecond,
			SimulateThrottleEvery: 5, // 1 AppendRows request < 5 => 0 periodic throttles injected
			maxBatches:            1,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr == nil || softErr == nil {
			t.Fatalf("expected fail-closed error when SimulateThrottleEvery never fired, got hard=%v soft=%v", hardErr, softErr)
		}
		if !strings.Contains(hardErr.Error(), "-simulate-throttle-every=5") || !strings.Contains(hardErr.Error(), "otel_logs") {
			t.Fatalf("expected error naming -simulate-throttle-every=5 and destination table otel_logs, got %v", hardErr)
		}
	})

	t.Run("QuarantinedRowsExcludedFromDeliveredAndBytes", func(t *testing.T) {
		logEnc, encErr := protoenc.New(schema.LogsTableSchema())
		if encErr != nil {
			t.Fatalf("protoenc.New(LogsTableSchema): %v", encErr)
		}
		ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
		refLogBytes, encErr := logEnc.Encode(transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts.UnixMicro(),
			"receive_time_unix_nano":  ts.UnixNano(),
			"log_name":                "projects/test-project/logs/app",
			"insert_id":               "q-log-0",
			"body":                    fmt.Sprintf("%q", "payload-q-log-0"),
		})
		if encErr != nil {
			t.Fatalf("encode reference log row: %v", encErr)
		}
		wantLogsRowBytes := round2(float64(len(refLogBytes)))

		bin := configureCollectorHelperEnv(t, "quarantine_one_of_four")
		cfg := RunnerConfig{
			Mode:                 ModeCollector,
			CollectorBin:         bin,
			CollectorConfig:      cfgPath,
			Signals:              []string{"logs"},
			Workers:              1,
			BatchSize:            4,
			Duration:             150 * time.Millisecond,
			SimulateAckDelay:     5 * time.Millisecond,
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
			t.Fatalf("unexpected hardErr: %v", hardErr)
		}
		if res.IncompleteDrain {
			t.Fatalf("expected clean drain with 3 acked + 1 rejected == 4 submitted, got DrainWarning=%q", res.DrainWarning)
		}
		if res.DeliveredRows != 3 {
			t.Fatalf("DeliveredRows = %d, want 3 (quarantine row must be excluded)", res.DeliveredRows)
		}
		if res.Telemetry.AcknowledgedRows != 3 || res.Telemetry.RejectedRows != 1 || res.Telemetry.QuarantinedRows != 1 {
			t.Fatalf("unexpected telemetry: acked=%d rejected=%d quarantined=%d, want 3/1/1",
				res.Telemetry.AcknowledgedRows, res.Telemetry.RejectedRows, res.Telemetry.QuarantinedRows)
		}
		if res.BytesPerRow != wantLogsRowBytes {
			t.Fatalf("BytesPerRow = %v, want %v (must reflect only otel_logs rows and exclude 2 KiB otel_quarantine row)", res.BytesPerRow, wantLogsRowBytes)
		}
	})
}

func TestRewriteFailClosedNonMapSubmapsAndTableRefResolution(t *testing.T) {
	baseEP := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080/bigquery/v2/",
	}
	baseCfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		StreamPoolSize:      2,
		ConnectionPoolSize:  2,
		MaxInflightRequests: 16,
		MaxRequestBytes:     8 * 1024 * 1024,
	}

	t.Run("RedactionExternalRefFailsClosedRegardlessOfCLIFlag", func(t *testing.T) {
		rawYAML := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    redaction: "${file:policy.yaml}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		cfgEnabled := baseCfg
		cfgEnabled.Redaction = true
		if _, _, err := rewriteCollectorLoopbackConfig(rawYAML, cfgEnabled, "logs", baseEP); err == nil {
			t.Fatal("expected rewriteCollectorLoopbackConfig error when cfg.Redaction=true and bq.redaction is a non-map reference")
		}

		cfgDisabled := baseCfg
		cfgDisabled.Redaction = false
		if _, _, err := rewriteCollectorLoopbackConfig(rawYAML, cfgDisabled, "logs", baseEP); err == nil {
			t.Fatal("expected rewriteCollectorLoopbackConfig error when cfg.Redaction=false and bq.redaction is a non-map reference")
		}
	})

	t.Run("SiblingSubmapsFailClosedWhenNonMap", func(t *testing.T) {
		nonMapCases := []struct {
			name string
			yaml string
			cfg  func(RunnerConfig) RunnerConfig
			ep   func(collectorEndpointOverride) collectorEndpointOverride
		}{
			{
				name: "exporters",
				yaml: "receivers:\n  otlp: {}\nexporters: \"${file:exporters.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "exporters.bigquery",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: \"${file:bq.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "service",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice: \"${file:service.yaml}\"\n",
			},
			{
				name: "service.pipelines",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  pipelines: \"${file:pipelines.yaml}\"\n",
			},
			{
				name: "service.pipelines.logs",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs: \"${file:logs-pipe.yaml}\"\n",
			},
			{
				name: "processors_with_pipeline",
				yaml: "receivers:\n  otlp: {}\nprocessors: \"${file:procs.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "processors_with_empty_pipelines",
				yaml: "receivers:\n  otlp: {}\nprocessors: \"${file:procs.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines: {}\n",
			},
			{
				name: "receivers",
				yaml: "receivers: \"${file:receivers.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "receivers.otlp",
				yaml: "receivers:\n  otlp: \"${file:otlp.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "receivers.otlp.protocols",
				yaml: "receivers:\n  otlp:\n    protocols: \"${file:protos.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "receivers.otlp.protocols.grpc",
				yaml: "receivers:\n  otlp:\n    protocols:\n      grpc: \"${file:grpc.yaml}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "extensions_inactive",
				yaml: "extensions: \"${file:ext.yaml}\"\nreceivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "extensions.health_check",
				yaml: "extensions:\n  health_check: \"${file:hc.yaml}\"\nreceivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  extensions: [health_check]\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "extensions.file_storage.compaction",
				yaml: "extensions:\n  file_storage:\n    compaction: \"${file:comp.yaml}\"\nreceivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  extensions: [file_storage]\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "sending_queue",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    sending_queue: \"${file:sq.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "write",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    write: \"${file:write.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "write.backpressure_when_flag_true",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    write:\n      backpressure: \"${file:bp.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
				cfg:  func(c RunnerConfig) RunnerConfig { c.Backpressure = true; return c },
			},
			{
				name: "write.backpressure_when_flag_false",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    write:\n      backpressure: \"${file:bp.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
				cfg:  func(c RunnerConfig) RunnerConfig { c.Backpressure = false; return c },
			},
			{
				name: "redaction_when_flag_false",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    redaction: \"${file:red.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
				cfg:  func(c RunnerConfig) RunnerConfig { c.Redaction = false; return c },
			},
			{
				name: "offload_live_mode",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    offload: \"${file:offload.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
				ep:   func(e collectorEndpointOverride) collectorEndpointOverride { e.useBQFake = false; return e },
			},
			{
				name: "quarantine",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    quarantine: \"${file:q.yaml}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "service.telemetry",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  telemetry: \"${file:telem.yaml}\"\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
			{
				name: "service.telemetry.metrics",
				yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  telemetry:\n    metrics: \"${file:metrics.yaml}\"\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
			},
		}
		for _, tc := range nonMapCases {
			t.Run(tc.name, func(t *testing.T) {
				c := baseCfg
				if tc.cfg != nil {
					c = tc.cfg(c)
				}
				e := baseEP
				e.storageRoot = t.TempDir()
				if tc.ep != nil {
					e = tc.ep(e)
				}
				if _, _, err := rewriteCollectorLoopbackConfig([]byte(tc.yaml), c, "logs", e); err == nil {
					t.Fatalf("expected fail-closed error for non-map %s", tc.name)
				}
			})
		}
	})

	t.Run("EnvBooleanResolutionForRedactionAndBackpressure", func(t *testing.T) {
		envBoolYAML := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    write:
      backpressure:
        enabled: "${env:TEST_BP_ON:-true}"
    redaction:
      enabled: "${env:TEST_REDACT_ON}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		t.Setenv("TEST_REDACT_ON", "true")
		_, meta, err := rewriteCollectorLoopbackConfig(envBoolYAML, baseCfg, "logs", baseEP)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(env bools) error: %v", err)
		}
		if !meta.effectiveRedaction {
			t.Fatal("expected effectiveRedaction=true when TEST_REDACT_ON=true")
		}
		if !meta.effectiveBackpressure {
			t.Fatal("expected effectiveBackpressure=true when TEST_BP_ON is unset with :-true default")
		}

		// Set-but-empty TEST_BP_ON="" keeps empty string under OTel envprovider :- (not default), resolving to false.
		t.Setenv("TEST_BP_ON", "")
		t.Setenv("TEST_REDACT_ON", "")
		_, metaEmpty, err := rewriteCollectorLoopbackConfig(envBoolYAML, baseCfg, "logs", baseEP)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(empty env bools) error: %v", err)
		}
		if metaEmpty.effectiveRedaction || metaEmpty.effectiveBackpressure {
			t.Fatalf("expected false/false for empty env bools, got redact=%v bp=%v", metaEmpty.effectiveRedaction, metaEmpty.effectiveBackpressure)
		}

		// YAML 1.1 "yes" must be rejected by strconv.ParseBool.
		t.Setenv("TEST_BP_ON", "yes")
		if _, _, err := rewriteCollectorLoopbackConfig(envBoolYAML, baseCfg, "logs", baseEP); err == nil {
			t.Fatal("expected error when write.backpressure.enabled resolves to 'yes'")
		}
	})

	t.Run("EnvTableResolutionWrittenBackAndMalformedRefsFailClosed", func(t *testing.T) {
		t.Setenv("TEST_BQ_LOGS_TABLE", "env_resolved_logs")

		for _, tc := range []struct {
			name      string
			tableExpr string
			wantTable string
		}{
			{name: "env_scheme", tableExpr: "${env:TEST_BQ_LOGS_TABLE}", wantTable: "env_resolved_logs"},
			{name: "bare_var", tableExpr: "${TEST_BQ_LOGS_TABLE}", wantTable: "env_resolved_logs"},
			{name: "unset_with_default", tableExpr: "${env:TEST_UNSET_BQ_LOGS_TABLE_XYZ:-fallback_logs}", wantTable: "fallback_logs"},
			{name: "escaped_dollar", tableExpr: "$$literal_logs", wantTable: "$literal_logs"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rawYAML := []byte(fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs:
      table: %q
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, tc.tableExpr))
				rewritten, meta, err := rewriteCollectorLoopbackConfig(rawYAML, baseCfg, "logs", baseEP)
				if err != nil {
					t.Fatalf("rewriteCollectorLoopbackConfig(%q) unexpected error: %v", tc.tableExpr, err)
				}
				if meta.effectiveTable != tc.wantTable {
					t.Fatalf("meta.effectiveTable = %q, want %q", meta.effectiveTable, tc.wantTable)
				}
				var doc map[string]any
				if err := yaml.Unmarshal(rewritten, &doc); err != nil {
					t.Fatalf("yaml.Unmarshal: %v", err)
				}
				logsMap := doc["exporters"].(map[string]any)["bigquery"].(map[string]any)["logs"].(map[string]any)
				if gotTable, _ := logsMap["table"].(string); gotTable != tc.wantTable {
					t.Fatalf("rewritten logs.table = %q, want %q", gotTable, tc.wantTable)
				}
			})
		}

		// Under OTel Collector envprovider v1.71.0, :- uses default ONLY when unset (!ok),
		// so a set-but-empty env var stays "" and fails empty-table validation.
		t.Setenv("TEST_EMPTY_BQ_LOGS_TABLE", "")
		emptyWithDefault := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs:
      table: "${env:TEST_EMPTY_BQ_LOGS_TABLE:-fallback_from_empty}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		if _, _, err := rewriteCollectorLoopbackConfig(emptyWithDefault, baseCfg, "logs", baseEP); err == nil || !strings.Contains(err.Error(), "empty table name") {
			t.Fatalf("expected empty-table error for set-but-empty env var with :- default, got %v", err)
		}

		// Bare ${VAR:-default} without explicit env: scheme must fail closed.
		bareWithDefault := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs:
      table: "${TEST_MISSING_BQ_TABLE_999:-fallback}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		if _, _, err := rewriteCollectorLoopbackConfig(bareWithDefault, baseCfg, "logs", baseEP); err == nil || !strings.Contains(err.Error(), "requires explicit env: scheme") {
			t.Fatalf("expected explicit env: scheme error for bare ${VAR:-default}, got %v", err)
		}

		for _, badExpr := range []string{
			"${env:TEST_MISSING_BQ_TABLE_999}",
			"${env:TEST_EMPTY_BQ_LOGS_TABLE}",
			"${file:/etc/table}",
			"${http://example.com/table}",
			"${env:UNCLOSED",
			"${}",
			"${env:}",
			"${env:A:B}",
			"${env:${NESTED}}",
		} {
			rawBad := []byte(fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs:
      table: %q
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, badExpr))
			if _, _, badErr := rewriteCollectorLoopbackConfig(rawBad, baseCfg, "logs", baseEP); badErr == nil {
				t.Fatalf("expected fail-closed error for table=%q", badExpr)
			}
		}

		nonStringTable := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs:
      table: 123
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		if _, _, err := rewriteCollectorLoopbackConfig(nonStringTable, baseCfg, "logs", baseEP); err == nil {
			t.Fatal("expected fail-closed error for non-string logs.table")
		}

		nonMapLogs := []byte(`
receivers:
  otlp: {}
exporters:
  bigquery:
    logs: "${file:logs.yaml}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		if _, _, err := rewriteCollectorLoopbackConfig(nonMapLogs, baseCfg, "logs", baseEP); err == nil {
			t.Fatal("expected fail-closed error for non-map exporter logs section")
		}
	})
}

type recordingLoopbackLogsOTLPServer struct {
	plogotlp.UnimplementedGRPCServer
	mu       sync.Mutex
	arrivals []time.Time
	counts   []int
}

func (s *recordingLoopbackLogsOTLPServer) Export(_ context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	n := req.Logs().LogRecordCount()
	now := time.Now()
	s.mu.Lock()
	s.arrivals = append(s.arrivals, now)
	s.counts = append(s.counts, n)
	s.mu.Unlock()
	return plogotlp.NewExportResponse(), nil
}

func TestRateLimitedCollectorWorkerPhaseSpreadsAcrossWorkers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen loopback OTLP server: %v", err)
	}

	recSrv := &recordingLoopbackLogsOTLPServer{}
	grpcSrv := grpc.NewServer()
	plogotlp.RegisterGRPCServer(grpcSrv, recSrv)
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
		TargetRate: 20,
		Workers:    4,
		Duration:   1 * time.Second,
		BatchSize:  500,
	}
	if err = cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize(): %v", err)
	}
	makeBatch, err := newCollectorBatchBuilder(cfg, "logs")
	if err != nil {
		t.Fatalf("newCollectorBatchBuilder() unexpected error: %v", err)
	}

	phaseStats := runCollectorWorkerPhase(ctx, cfg, "logs", cfg.Duration, 0, nil, makeBatch, nil, client, nil, nil)
	if phaseStats.firstErr != nil {
		t.Fatalf("runCollectorWorkerPhase() unexpected error: %v", phaseStats.firstErr)
	}
	if phaseStats.recordsSubmitted != 20 {
		t.Fatalf("recordsSubmitted = %d, want 20", phaseStats.recordsSubmitted)
	}

	recSrv.mu.Lock()
	counts := slices.Clone(recSrv.counts)
	arrivals := slices.Clone(recSrv.arrivals)
	recSrv.mu.Unlock()

	var totalRows int
	for _, c := range counts {
		totalRows += c
	}
	if totalRows != 20 {
		t.Fatalf("total exported rows = %d, want 20 (counts=%v)", totalRows, counts)
	}
	if len(counts) == 0 || counts[0] > 5 {
		t.Fatalf("first batch rows = %v, want <= 5 (counts=%v)", counts, counts)
	}
	if len(arrivals) < 2 {
		t.Fatalf("expected multiple paced dispatches across 1s window, got %d (%v)", len(counts), counts)
	}
	span := arrivals[len(arrivals)-1].Sub(arrivals[0])
	if span < 500*time.Millisecond {
		t.Fatalf("dispatch arrival span = %v, want >= 500ms (counts=%v)", span, counts)
	}
}

func TestRewriteBatchProcessorMetadataAndDrainIdleWait(t *testing.T) {
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080/bigquery/v2/",
		dryRun:      true,
	}
	cfg := RunnerConfig{
		ProjectID:           "bench-project",
		DatasetID:           "otel_bench",
		Location:            "US",
		StreamPoolSize:      2,
		ConnectionPoolSize:  2,
		MaxInflightRequests: 16,
		MaxRequestBytes:     8 * 1024 * 1024,
	}

	yamlBatch20s := []byte(`
receivers:
  otlp: {}
processors:
  batch/logs:
    timeout: 20s
    send_batch_size: 4096
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch/logs]
      exporters: [bigquery]
`)
	_, meta, err := rewriteCollectorLoopbackConfig(yamlBatch20s, cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(batch 20s) unexpected error: %v", err)
	}
	if meta.batchProcessorTimeout != 20*time.Second {
		t.Fatalf("batchProcessorTimeout = %v, want 20s", meta.batchProcessorTimeout)
	}
	if meta.batchProcessorSendSize != 4096 {
		t.Fatalf("batchProcessorSendSize = %d, want 4096", meta.batchProcessorSendSize)
	}
	derivedDrain := max(collectorMinDrainTimeout, 2*meta.batchProcessorTimeout+5*time.Second)
	if derivedDrain != 45*time.Second {
		t.Fatalf("derived drainTimeout = %v, want 45s", derivedDrain)
	}

	for _, badBatch := range []string{
		"timeout: -1s",
		"timeout: 123",
		"timeout: not-a-duration",
		"send_batch_size: -5",
		`send_batch_size: "abc"`,
	} {
		rawBad := []byte(fmt.Sprintf(`
receivers:
  otlp: {}
processors:
  batch:
    %s
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`, badBatch))
		if _, _, badErr := rewriteCollectorLoopbackConfig(rawBad, cfg, "logs", ep); badErr == nil {
			t.Fatalf("expected fail-closed error for invalid batch setting %q", badBatch)
		}
	}

	// Exercise drainCollectorPipelineWithUnique against an httptest Prometheus server.
	var metricsPayload atomic.Pointer[string]
	initBody := ""
	metricsPayload.Store(&initBody)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = w.Write([]byte(*metricsPayload.Load()))
	}))
	defer func() {
		srv.Client().CloseIdleConnections()
		srv.Close()
	}()
	metricsAddr := srv.Listener.Addr().String()

	t.Run("IdleTailWaitAccumulatedAndCappedAtBatchTimeout", func(t *testing.T) {
		idleStalled := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 6
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`
		flushed := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 10
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`
		metricsPayload.Store(&idleStalled)

		stopCh := make(chan struct{})
		var bgWg sync.WaitGroup
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			timer := time.NewTimer(220 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-stopCh:
			case <-timer.C:
				metricsPayload.Store(&flushed)
			}
		}()
		defer func() {
			close(stopCh)
			bgWg.Wait()
		}()

		doneCh := make(chan struct{})
		var waitErr error
		diag := new(boundedDiagBuffer)
		batchTimeout := 150 * time.Millisecond
		_, idleWait, drainErr := drainCollectorPipelineWithUnique(
			context.Background(), srv.Client(), metricsAddr, "logs", "bigquery",
			collectorMetricsSample{}, 10, 2*time.Second, doneCh, &waitErr, diag,
			0, nil, batchTimeout, 100,
		)
		if drainErr != nil {
			t.Fatalf("drainCollectorPipelineWithUnique unexpected error: %v", drainErr)
		}
		if idleWait <= 0 || idleWait > batchTimeout {
			t.Fatalf("idleBatchWait = %v, want in (0, %v]", idleWait, batchTimeout)
		}
		if idleWait != batchTimeout {
			t.Fatalf("expected 220ms stall to cap idleBatchWait at batchTimeout=%v, got %v", batchTimeout, idleWait)
		}
	})

	t.Run("ActiveBacklogDoesNotCountAsIdleBatchWait", func(t *testing.T) {
		for _, tc := range []struct {
			name          string
			stalledMetric string
			batchSendSize int
		}{
			{
				name: "exporter_queue_non_empty",
				stalledMetric: `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 6
otelcol_exporter_queue_size 2
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`,
				batchSendSize: 100,
			},
			{
				name: "inflight_requests_positive",
				stalledMetric: `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 6
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 1
`,
				batchSendSize: 100,
			},
			{
				name: "pending_at_least_batch_send_size",
				stalledMetric: `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 0
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`,
				batchSendSize: 10,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				flushed := `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 10
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`
				stalled := tc.stalledMetric
				metricsPayload.Store(&stalled)

				stopCh := make(chan struct{})
				var bgWg sync.WaitGroup
				bgWg.Add(1)
				go func() {
					defer bgWg.Done()
					timer := time.NewTimer(140 * time.Millisecond)
					defer timer.Stop()
					select {
					case <-stopCh:
					case <-timer.C:
						metricsPayload.Store(&flushed)
					}
				}()
				defer func() {
					close(stopCh)
					bgWg.Wait()
				}()

				doneCh := make(chan struct{})
				var waitErr error
				diag := new(boundedDiagBuffer)
				_, idleWait, drainErr := drainCollectorPipelineWithUnique(
					context.Background(), srv.Client(), metricsAddr, "logs", "bigquery",
					collectorMetricsSample{}, 10, 2*time.Second, doneCh, &waitErr, diag,
					0, nil, 500*time.Millisecond, tc.batchSendSize,
				)
				if drainErr != nil {
					t.Fatalf("drainCollectorPipelineWithUnique unexpected error: %v", drainErr)
				}
				if idleWait != 0 {
					t.Fatalf("idleBatchWait = %v, want 0 during active backlog (%s)", idleWait, tc.name)
				}
			})
		}
	})
}

func TestCollectorLostAckCommitThenStreamClosedReplayAccounting(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector.yaml")
	const rawYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig
    dataset: orig_ds
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("FaultSimEnabledCountsRealReplayedRowsAndPassesLossless", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(true)
		fakeSrv.EnqueueFault(bqfake.Fault{
			Mode:  bqfake.FaultCommitThenStreamClosed,
			Table: "otel_logs",
		})

		bin := configureCollectorHelperEnv(t, "default")
		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     bin,
			CollectorConfig:  cfgPath,
			Signals:          []string{"logs"},
			Workers:          1,
			BatchSize:        2,
			Duration:         500 * time.Millisecond,
			SimulateAckDelay: time.Millisecond,
			maxBatches:       2,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("unexpected hardErr: %v", hardErr)
		}
		if gotCommitted := fakeSrv.AckedRowsForTable("otel_logs"); gotCommitted != 6 {
			t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 6 (4 unique + 2 replayed)", gotCommitted)
		}
		if gotUnique := fakeSrv.UniqueAckedRowsForTable("otel_logs"); gotUnique != 4 {
			t.Fatalf("fakeSrv.UniqueAckedRowsForTable(otel_logs) = %d, want 4", gotUnique)
		}
		if gotDelayed := fakeSrv.DelayedAcksInjectedForTable("otel_logs"); gotDelayed < 1 {
			t.Fatalf("fakeSrv.DelayedAcksInjectedForTable(otel_logs) = %d, want >= 1", gotDelayed)
		}
		if res.Telemetry.AcknowledgedRows != 4 {
			t.Fatalf("Telemetry.AcknowledgedRows = %d, want 4", res.Telemetry.AcknowledgedRows)
		}
		if res.Telemetry.Retries < 1 {
			t.Fatalf("Telemetry.Retries = %d, want >= 1", res.Telemetry.Retries)
		}
		if res.DeliveredRows != 4 || !res.UniqueDeliveryVerified {
			t.Fatalf("DeliveredRows=%d UniqueDeliveryVerified=%v, want 4/true", res.DeliveredRows, res.UniqueDeliveryVerified)
		}
		if res.Telemetry.ReplayedRows != 2 {
			t.Fatalf("Telemetry.ReplayedRows = %d, want 2", res.Telemetry.ReplayedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
	})

	t.Run("FaultSimDisabledCountsRealReplayedRowsAndFailsLossless", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(true)
		fakeSrv.EnqueueFault(bqfake.Fault{
			Mode:  bqfake.FaultCommitThenStreamClosed,
			Table: "otel_logs",
		})

		bin := configureCollectorHelperEnv(t, "default")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       2,
			Duration:        500 * time.Millisecond,
			maxBatches:      2,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("unexpected hardErr: %v", hardErr)
		}
		if gotCommitted := fakeSrv.AckedRowsForTable("otel_logs"); gotCommitted != 6 {
			t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 6", gotCommitted)
		}
		if res.UniqueDeliveryVerified {
			t.Fatal("expected UniqueDeliveryVerified=false when faultSimEnabled=false")
		}
		if res.Telemetry.ReplayedRows != 2 {
			t.Fatalf("Telemetry.ReplayedRows = %d, want 2", res.Telemetry.ReplayedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr == nil {
			t.Fatal("expected checkSignalResultLossless to fail closed when UniqueDeliveryVerified=false and ReplayedRows=2")
		}
	})
}

func TestCollectorRewritePreservesHighVolumeLogsYAMLWriteSettings(t *testing.T) {
	hvCfgPath := resolveCollectorConfigPath(filepath.Join("example", "otel-collector-high-volume-logs.yaml"))
	rawYAML, err := os.ReadFile(hvCfgPath)
	if err != nil {
		t.Fatalf("read %s: %v", hvCfgPath, err)
	}

	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}

	bareCfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: hvCfgPath,
		Signals:         []string{"logs"},
	}
	if err := bareCfg.Normalize(); err != nil {
		t.Fatalf("bareCfg.Normalize: %v", err)
	}
	rewrittenBare, metaBare, err := rewriteCollectorLoopbackConfig(rawYAML, bareCfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(bare): %v", err)
	}
	if metaBare.effectiveStreamPoolSize != 8 || metaBare.effectiveConnectionPoolSize != 8 || metaBare.effectiveMaxInflightRequests != 16 {
		t.Fatalf("bare effective write.* = (%d, %d, %d), want (8, 8, 16)",
			metaBare.effectiveStreamPoolSize, metaBare.effectiveConnectionPoolSize, metaBare.effectiveMaxInflightRequests)
	}
	var docBare map[string]any
	if err := yaml.Unmarshal(rewrittenBare, &docBare); err != nil {
		t.Fatalf("yaml.Unmarshal(bare): %v", err)
	}
	writeBare := docBare["exporters"].(map[string]any)["bigquery"].(map[string]any)["write"].(map[string]any)
	if writeBare["stream_pool_size"] != 8 || writeBare["connection_pool_size"] != 8 || writeBare["max_inflight_requests"] != 16 {
		t.Fatalf("rewritten bare write map = %#v, want stream=8 conn=8 inflight=16", writeBare)
	}

	// Selective CLI override (-stream-pool-size=4) overrides only stream_pool_size while keeping YAML connection_pool_size=8 and max_inflight_requests=16.
	overrideCfg := bareCfg
	overrideCfg.StreamPoolSize = 4
	rewrittenOverride, metaOverride, err := rewriteCollectorLoopbackConfig(rawYAML, overrideCfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(StreamPoolSize=4): %v", err)
	}
	if metaOverride.effectiveStreamPoolSize != 4 || metaOverride.effectiveConnectionPoolSize != 8 || metaOverride.effectiveMaxInflightRequests != 16 {
		t.Fatalf("override effective write.* = (%d, %d, %d), want (4, 8, 16)",
			metaOverride.effectiveStreamPoolSize, metaOverride.effectiveConnectionPoolSize, metaOverride.effectiveMaxInflightRequests)
	}
	var docOverride map[string]any
	if err := yaml.Unmarshal(rewrittenOverride, &docOverride); err != nil {
		t.Fatalf("yaml.Unmarshal(override): %v", err)
	}
	writeOverride := docOverride["exporters"].(map[string]any)["bigquery"].(map[string]any)["write"].(map[string]any)
	if writeOverride["stream_pool_size"] != 4 || writeOverride["connection_pool_size"] != 8 || writeOverride["max_inflight_requests"] != 16 {
		t.Fatalf("rewritten override write map = %#v, want stream=4 conn=8 inflight=16", writeOverride)
	}

	// Subprocess run with omitted CLI write.* flags reports effective YAML pool sizes (8/8) in SignalResult.
	bin := configureCollectorHelperEnv(t, "default")
	runCfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    bin,
		CollectorConfig: hvCfgPath,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       4,
		Duration:        150 * time.Millisecond,
		maxBatches:      1,
	}
	if err := runCfg.Normalize(); err != nil {
		t.Fatalf("runCfg.Normalize: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignal(ctx, runCfg, "logs")
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignal(hv logs): hard=%v soft=%v", hardErr, softErr)
	}
	if res.StreamPoolSize != 8 || res.ConnectionPoolSize != 8 {
		t.Fatalf("SignalResult pool sizes = (%d, %d), want (8, 8)", res.StreamPoolSize, res.ConnectionPoolSize)
	}
}

func TestCollectorEnvResolutionForHealthCheckStorageAndBatchProcessor(t *testing.T) {
	t.Setenv("TEST_SQ_EXT", "file_storage/access")
	t.Setenv("TEST_HC_PATH", "livez")
	t.Setenv("TEST_BATCH_TIMEOUT", "750ms")
	t.Setenv("TEST_BATCH_SIZE", "2048")

	rawYAML := []byte(`
extensions:
  health_check:
    path: "${env:TEST_HC_PATH}"
  file_storage/access: {}
receivers:
  otlp: {}
processors:
  batch:
    timeout: "${env:TEST_BATCH_TIMEOUT}"
    send_batch_size: "${env:TEST_BATCH_SIZE}"
exporters:
  bigquery:
    sending_queue:
      enabled: true
      storage: "${env:TEST_SQ_EXT}"
service:
  extensions: [health_check, file_storage/access]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`)
	cfg := RunnerConfig{
		ProjectID: "bench-project",
		DatasetID: "otel_bench",
		Location:  "US",
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}
	_, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(env refs) error: %v", err)
	}
	if meta.healthCheckPath != "/livez" {
		t.Fatalf("meta.healthCheckPath = %q, want /livez", meta.healthCheckPath)
	}
	if meta.batchProcessorTimeout != 750*time.Millisecond || meta.batchProcessorSendSize != 2048 {
		t.Fatalf("batch meta = (%v, %d), want (750ms, 2048)", meta.batchProcessorTimeout, meta.batchProcessorSendSize)
	}

	for _, badCase := range []struct {
		name string
		yaml string
	}{
		{
			name: "file_ref_health_check_path",
			yaml: "extensions:\n  health_check:\n    path: \"${file:hcpath}\"\nreceivers:\n  otlp: {}\nexporters:\n  bigquery: {}\nservice:\n  extensions: [health_check]\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
		},
		{
			name: "file_ref_sending_queue_storage",
			yaml: "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    sending_queue:\n      storage: \"${file:sq}\"\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n",
		},
		{
			name: "file_ref_batch_timeout",
			yaml: "receivers:\n  otlp: {}\nprocessors:\n  batch:\n    timeout: \"${file:to}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      processors: [batch]\n      exporters: [bigquery]\n",
		},
		{
			name: "file_ref_batch_send_batch_size",
			yaml: "receivers:\n  otlp: {}\nprocessors:\n  batch:\n    send_batch_size: \"${file:sbs}\"\nexporters:\n  bigquery: {}\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      processors: [batch]\n      exporters: [bigquery]\n",
		},
	} {
		t.Run(badCase.name, func(t *testing.T) {
			if _, _, badErr := rewriteCollectorLoopbackConfig([]byte(badCase.yaml), cfg, "logs", ep); badErr == nil {
				t.Fatalf("expected fail-closed error for %s", badCase.name)
			}
		})
	}
}

func TestDiffCollectorTelemetryPreservesSub10msWaitPrecision(t *testing.T) {
	beforeProm := `
otelcol_exporter_bigquery_append_result_wait_count{exporter="bigquery",signal="logs"} 2
otelcol_exporter_bigquery_append_result_wait_sum{exporter="bigquery",signal="logs"} 0.0042
`
	afterProm := `
otelcol_exporter_bigquery_append_result_wait_count{exporter="bigquery",signal="logs"} 4
otelcol_exporter_bigquery_append_result_wait_sum{exporter="bigquery",signal="logs"} 0.0086
`
	beforeSample := parseCollectorPrometheusMetrics(beforeProm, "logs", "bigquery")
	afterSample := parseCollectorPrometheusMetrics(afterProm, "logs", "bigquery")
	delta, _ := diffCollectorTelemetry(beforeSample, afterSample)
	if delta.AppendWaitCount != 2 {
		t.Fatalf("AppendWaitCount = %d, want 2", delta.AppendWaitCount)
	}
	if delta.AppendWaitMeanMs != 2.2 {
		t.Fatalf("AppendWaitMeanMs = %v, want 2.2 (unrounded 0.0044s / 2)", delta.AppendWaitMeanMs)
	}
}

func TestCollectorLivePartialDeliveryMarksBytesPerRowUnavailable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector.yaml")
	const rawYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig
    dataset: orig_ds
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "live_partial_delivery")
	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		CollectorAllowLive:   true,
		AllowPartialFailures: true,
		ProjectID:            "live-test-proj",
		DatasetID:            "live_test_ds",
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            10,
		Duration:             150 * time.Millisecond,
		maxBatches:           1,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, _, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
	if hardErr != nil {
		t.Fatalf("unexpected hardErr: %v", hardErr)
	}
	if res.Telemetry.AcknowledgedRows != 6 || res.Telemetry.RejectedRows != 4 || res.Telemetry.Retries != 0 {
		t.Fatalf("unexpected telemetry: acked=%d rejected=%d retries=%d, want 6/4/0",
			res.Telemetry.AcknowledgedRows, res.Telemetry.RejectedRows, res.Telemetry.Retries)
	}
	if !res.BytesPerRowUnavailable || res.BytesPerRow != 0 || res.WireMBPerSec != 0 {
		t.Fatalf("expected BytesPerRowUnavailable=true and zero BytesPerRow/WireMBPerSec on live partial delivery, got unavail=%v bpr=%v wire=%v",
			res.BytesPerRowUnavailable, res.BytesPerRow, res.WireMBPerSec)
	}
}

func TestStopCollectorProcessAndPostDrainChildErrorExit(t *testing.T) {
	t.Run("AlreadyExitedProcessReturnsKilledFalse", func(t *testing.T) {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		if err := cmd.Start(); err != nil {
			t.Fatalf("cmd.Start: %v", err)
		}
		if err := cmd.Wait(); err != nil {
			t.Fatalf("cmd.Wait: %v", err)
		}
		if killed := stopCollectorProcess(cmd.Process); killed {
			t.Fatal("stopCollectorProcess on already-exited child returned true, want false")
		}
	})

	t.Run("AlreadyExitedNonZeroChildSurfacesExitError", func(t *testing.T) {
		diag := &boundedDiagBuffer{}
		cmd := exec.Command(os.Args[0])
		cmd.Env = append(os.Environ(), "GO_WANT_FAKE_COLLECTOR=exit_immediately_code3")
		cmd.Stdout = diag
		cmd.Stderr = diag
		if err := cmd.Start(); err != nil {
			t.Fatalf("cmd.Start: %v", err)
		}
		doneCh := make(chan struct{})
		var waitErr error
		go func() {
			waitErr = cmd.Wait()
			close(doneCh)
		}()
		<-doneCh

		childDone, err := finalizeCollectorShutdown(cmd.Process, doneCh, &waitErr, nil, diag)
		if !childDone {
			t.Fatal("expected childDone=true")
		}
		if err == nil {
			t.Fatal("expected error when child already exited non-zero, got nil")
		}
		if !strings.Contains(err.Error(), "collector exited with error") {
			t.Fatalf("expected error containing %q, got %v", "collector exited with error", err)
		}
		if !strings.Contains(err.Error(), "child exited non-zero") {
			t.Fatalf("expected error containing %q, got %v", "child exited non-zero", err)
		}
	})

	t.Run("PostDrainChildNonZeroExitPreserved", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows has no SIGTERM graceful shutdown; already-exited non-zero preservation is covered by AlreadyExitedNonZeroChildSurfacesExitError")
		}
		cfgPath := filepath.Join(t.TempDir(), "collector.yaml")
		const rawYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: orig
    dataset: orig_ds
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		bin := configureCollectorHelperEnv(t, "exit_error_on_sigterm")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       4,
			Duration:        150 * time.Millisecond,
			maxBatches:      1,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		_, _, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
		if hardErr == nil || !strings.Contains(hardErr.Error(), "collector exited with error") {
			t.Fatalf("expected collector exited with error when child exits non-zero after drain, got %v", hardErr)
		}
	})
}
