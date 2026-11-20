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
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
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
otelcol_exporter_bigquery_acknowledged_rows{signal="spans"} 999
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

	t.Run("TracesSpansSignalLabelsAndExporterHelperSuffix", func(t *testing.T) {
		const tracesExposition = `
otelcol_exporter_bigquery_acknowledged_rows_total{exporter="bigquery",signal="spans"} 40
otelcol_exporter_bigquery_acknowledged_rows_total{exporter="bigquery",signal="logs"} 999
otelcol_exporter_bigquery_rejected_rows_total{exporter="bigquery",signal="spans",reason="request_permanent"} 3
otelcol_exporter_bigquery_rejected_rows_total{exporter="bigquery",signal="logs",reason="row_error"} 88
otelcol_exporter_bigquery_append_bytes_total{exporter="bigquery",signal="spans"} 32768
otelcol_exporter_bigquery_append_bytes_total{exporter="bigquery",signal="logs"} 111111
otelcol_exporter_bigquery_append_result_wait_count{exporter="bigquery",signal="spans"} 5
otelcol_exporter_bigquery_append_result_wait_count{exporter="bigquery",signal="logs"} 99
otelcol_exporter_bigquery_append_result_wait_sum{exporter="bigquery",signal="spans"} 0.05
otelcol_exporter_bigquery_append_result_wait_sum{exporter="bigquery",signal="logs"} 9.9
otelcol_exporter_bigquery_redacted_values_total{exporter="bigquery",signal="spans",match_type="key_glob"} 7
otelcol_exporter_bigquery_redacted_values_total{exporter="bigquery",signal="spans",match_type="value_pattern"} 5
otelcol_exporter_bigquery_redacted_values_total{exporter="bigquery",signal="logs",match_type="key_glob"} 50
otelcol_exporter_bigquery_backpressure_level{exporter="bigquery",signal="spans"} 0.75
otelcol_exporter_bigquery_backpressure_level{exporter="bigquery",signal="logs"} 0.99
otelcol_exporter_bigquery_effective_request_bytes{exporter="bigquery",signal="spans"} 4194304
otelcol_exporter_bigquery_effective_request_bytes{exporter="bigquery",signal="logs"} 1048576
otelcol_exporter_bigquery_backpressure_events_total{exporter="bigquery",signal="spans",trigger="throttle"} 2
otelcol_exporter_bigquery_backpressure_events_total{exporter="bigquery",signal="logs",trigger="throttle"} 77
otelcol_exporter_sent_spans_total{exporter="bigquery"} 40
otelcol_exporter_sent_log_records_total{exporter="bigquery"} 999
otelcol_exporter_send_failed_spans_total{exporter="bigquery"} 3
otelcol_exporter_send_failed_log_records_total{exporter="bigquery"} 88
otelcol_exporter_enqueue_failed_spans_total{exporter="bigquery"} 2
otelcol_exporter_enqueue_failed_log_records_total{exporter="bigquery"} 77
`
		trSample := parseCollectorPrometheusMetrics(tracesExposition, "traces", "bigquery")
		if trSample.Telemetry.AcknowledgedRows != 40 {
			t.Fatalf("Telemetry.AcknowledgedRows = %d, want 40", trSample.Telemetry.AcknowledgedRows)
		}
		if trSample.Telemetry.RejectedRows != 3 || trSample.RejectedRequestPermanent != 3 || trSample.RejectedRowError != 0 {
			t.Fatalf("unexpected rejected counts: total=%d reqPerm=%d rowErr=%d",
				trSample.Telemetry.RejectedRows, trSample.RejectedRequestPermanent, trSample.RejectedRowError)
		}
		if trSample.Telemetry.AppendBytesTotal != 32768 {
			t.Fatalf("Telemetry.AppendBytesTotal = %d, want 32768", trSample.Telemetry.AppendBytesTotal)
		}
		if trSample.Telemetry.AppendWaitCount != 5 {
			t.Fatalf("Telemetry.AppendWaitCount = %d, want 5", trSample.Telemetry.AppendWaitCount)
		}
		if trSample.Telemetry.RedactedValuesTotal != 12 {
			t.Fatalf("Telemetry.RedactedValuesTotal = %d, want 12", trSample.Telemetry.RedactedValuesTotal)
		}
		if len(trSample.Telemetry.RedactedByMatchType) != 2 ||
			trSample.Telemetry.RedactedByMatchType["key_glob"] != 7 ||
			trSample.Telemetry.RedactedByMatchType["value_pattern"] != 5 {
			t.Fatalf("Telemetry.RedactedByMatchType = %v, want key_glob=7 value_pattern=5", trSample.Telemetry.RedactedByMatchType)
		}
		if trSample.Telemetry.BackpressureLevel != 0.75 {
			t.Fatalf("Telemetry.BackpressureLevel = %v, want 0.75", trSample.Telemetry.BackpressureLevel)
		}
		if trSample.Telemetry.EffectiveRequestBytes != 4194304 {
			t.Fatalf("Telemetry.EffectiveRequestBytes = %d, want 4194304", trSample.Telemetry.EffectiveRequestBytes)
		}
		if len(trSample.Telemetry.BackpressureEvents) != 1 || trSample.Telemetry.BackpressureEvents["throttle"] != 2 {
			t.Fatalf("Telemetry.BackpressureEvents = %v, want throttle=2", trSample.Telemetry.BackpressureEvents)
		}
		if !trSample.HasSentMetric || trSample.Sent != 40 {
			t.Fatalf("HasSentMetric=%v Sent=%d, want true/40", trSample.HasSentMetric, trSample.Sent)
		}
		if trSample.SendFailed != 3 {
			t.Fatalf("SendFailed = %d, want 3", trSample.SendFailed)
		}
		if trSample.EnqueueFailed != 2 {
			t.Fatalf("EnqueueFailed = %d, want 2", trSample.EnqueueFailed)
		}
	})

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
	enqueueFailed        atomic.Int64
	batchSeq             atomic.Int64
	warmupMu             sync.Mutex
	warmupIDs            []string
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
	var firstTSNano int64
	hasFirstTS := false
	rlSlice := req.Logs().ResourceLogs()
	idx := 0
	for i := 0; i < rlSlice.Len() && len(ids) < n; i++ {
		slSlice := rlSlice.At(i).ScopeLogs()
		for j := 0; j < slSlice.Len() && len(ids) < n; j++ {
			lrs := slSlice.At(j).LogRecords()
			for k := 0; k < lrs.Len() && len(ids) < n; k++ {
				lr := lrs.At(k)
				if !hasFirstTS {
					firstTSNano = int64(lr.Timestamp())
					hasFirstTS = true
				}
				id := fmt.Sprintf("b%d-r%d-%s", seq, idx, lr.Body().AsString())
				if v, ok := lr.Attributes().Get("insert_id"); ok && v.Str() != "" {
					id = v.Str()
				} else if v, ok := lr.Attributes().Get("logging.googleapis.com/insertId"); ok && v.Str() != "" {
					id = v.Str()
				}
				ids = append(ids, id)
				idx++
			}
		}
	}

	switch s.mode {
	case "replay_warmup_rows":
		warmupCutoffNano := DefaultBaseTime.Add(time.Duration(uint64(warmupTreeBaseOffset)*4) * 100 * time.Microsecond).UnixNano()
		s.warmupMu.Lock()
		if hasFirstTS && firstTSNano >= warmupCutoffNano {
			s.warmupIDs = append(s.warmupIDs, ids...)
			s.warmupMu.Unlock()
			_, err := s.appendRowsToBQFake(ctx, ids)
			return resp, err
		}
		replayIDs := ids
		if len(s.warmupIDs) > 0 {
			replayIDs = make([]string, len(ids))
			for i := range replayIDs {
				replayIDs[i] = s.warmupIDs[i%len(s.warmupIDs)]
			}
		}
		s.warmupMu.Unlock()
		_, err := s.appendRowsToBQFake(ctx, replayIDs)
		return resp, err
	case "ack_without_commit":
		s.ackedRows.Add(int64(n))
		s.appendBytes.Add(int64(n) * 500)
		return resp, nil
	case "delayed_commit_200ms":
		idsCopy := slices.Clone(ids)
		go func() {
			time.Sleep(200 * time.Millisecond)
			_, _ = s.appendRowsToBQFake(context.Background(), idsCopy)
		}()
		return resp, nil
	case "drain_stall", "drain_stall_exit_error_on_sigterm":
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
	case "replay_one_with_drop":
		if len(ids) >= 2 {
			deliver := ids[:len(ids)-1]
			if _, err := s.appendRowsToBQFake(ctx, deliver); err != nil {
				return resp, err
			}
			// Replay first row once so committedRows == submitted (4) while unique delivered == 3 and replayed == 1.
			_, err := s.appendRowsToBQFake(ctx, []string{deliver[0]})
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
	case "extra_distinct_row":
		extra := append(slices.Clone(ids), fmt.Sprintf("extra-distinct-b%d", seq))
		_, err := s.appendRowsToBQFake(ctx, extra)
		return resp, err
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
	case "live_enqueue_failed":
		acked := max(0, len(ids)-2)
		enqFailed := len(ids) - acked
		s.ackedRows.Add(int64(acked))
		s.enqueueFailed.Add(int64(enqFailed))
		s.appendBytes.Add(int64(acked) * 500)
		return resp, nil
	case "live_missing_append_bytes":
		s.ackedRows.Add(int64(len(ids)))
		return resp, nil
	case "live_ok":
		s.ackedRows.Add(int64(len(ids)))
		s.appendBytes.Add(int64(len(ids)) * 640)
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
			appendBytesLine := fmt.Sprintf("otelcol_exporter_bigquery_append_bytes{exporter=%q,signal=\"logs\"} %d\n", activeExpID, helper.appendBytes.Load())
			if mode == "live_missing_append_bytes" {
				appendBytesLine = fmt.Sprintf("otelcol_exporter_sent_log_records{exporter=%q} %d\n", activeExpID, acked)
			}
			_, _ = fmt.Fprintf(w,
				"otelcol_exporter_bigquery_acknowledged_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_rejected_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_bigquery_quarantined_rows{exporter=%q,signal=\"logs\"} %d\n"+
					"%s"+
					"otelcol_exporter_bigquery_retries{exporter=%q,signal=\"logs\"} %d\n"+
					"otelcol_exporter_enqueue_failed_log_records{exporter=%q} %d\n"+
					"otelcol_exporter_queue_size{exporter=%q} 0\n"+
					"otelcol_exporter_bigquery_inflight_requests{exporter=%q,signal=\"logs\"} 0\n"+
					"otelcol_process_runtime_heap_alloc_bytes 1048576\n",
				activeExpID, acked,
				activeExpID, helper.rejectedRows.Load(),
				activeExpID, helper.quarantinedRows.Load(),
				appendBytesLine,
				activeExpID, helper.retries.Load(),
				activeExpID, helper.enqueueFailed.Load(),
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
	if mode == "drain_stall" || mode == "drain_stall_exit_error_on_sigterm" {
		// Flush extra rows during shutdown AFTER drain cutoff to verify pre-shutdown byte snapshot.
		_, _ = helper.appendRowsToBQFake(context.Background(), []string{"post-cutoff-1", "post-cutoff-2", "post-cutoff-3", "post-cutoff-4"})
	}
	grpcSrv.Stop()
	if mode == "exit_error_on_sigterm" || mode == "drain_stall_exit_error_on_sigterm" {
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
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 {
			t.Fatalf("UniqueDeliveryVerified=%v DeliveredRows=%d, want true/4", res.UniqueDeliveryVerified, res.DeliveredRows)
		}
		if res.Telemetry.ReplayedRows != 2 {
			t.Fatalf("Telemetry.ReplayedRows = %d, want 2", res.Telemetry.ReplayedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr == nil {
			t.Fatal("expected checkSignalResultLossless to fail closed when faultSimEnabled=false and ReplayedRows=2")
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

func TestDrainCollectorPipelineDoesNotDoubleCountPermanentRejections(t *testing.T) {
	const beforeBufferedFlush = `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 4
otelcol_exporter_bigquery_rejected_rows{signal="logs",reason="request_permanent"} 4
otelcol_exporter_sent_log_records 4
otelcol_exporter_send_failed_log_records 4
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`
	const afterBufferedFlush = `
otelcol_exporter_bigquery_acknowledged_rows{signal="logs"} 6
otelcol_exporter_bigquery_rejected_rows{signal="logs",reason="request_permanent"} 4
otelcol_exporter_sent_log_records 6
otelcol_exporter_send_failed_log_records 4
otelcol_exporter_queue_size 0
otelcol_exporter_bigquery_inflight_requests{signal="logs"} 0
`

	var scrapes atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		if scrapes.Add(1) <= 2 {
			_, _ = w.Write([]byte(beforeBufferedFlush))
			return
		}
		_, _ = w.Write([]byte(afterBufferedFlush))
	}))
	defer srv.Close()

	doneCh := make(chan struct{})
	var waitErr error
	diag := new(boundedDiagBuffer)
	sample, drainErr := drainCollectorPipeline(
		context.Background(),
		srv.Client(),
		srv.Listener.Addr().String(),
		"logs",
		"bigquery",
		collectorMetricsSample{},
		10,
		2*time.Second,
		doneCh,
		&waitErr,
		diag,
	)
	if drainErr != nil {
		t.Fatalf("drainCollectorPipeline unexpected error: %v", drainErr)
	}
	if gotScrapes := scrapes.Load(); gotScrapes < 3 {
		t.Fatalf("scrapes = %d, want >= 3 (must not complete on scrape 2 when disjoint accounted is 8 < 10)", gotScrapes)
	}
	if sample.Telemetry.AcknowledgedRows != 6 {
		t.Fatalf("AcknowledgedRows = %d, want 6", sample.Telemetry.AcknowledgedRows)
	}
	if sample.Telemetry.RejectedRows != 4 {
		t.Fatalf("RejectedRows = %d, want 4", sample.Telemetry.RejectedRows)
	}
	if sample.Sent != 6 {
		t.Fatalf("Sent = %d, want 6", sample.Sent)
	}
	if sample.SendFailed != 4 {
		t.Fatalf("SendFailed = %d, want 4", sample.SendFailed)
	}

	t.Run("BaselineOffsetSubtraction", func(t *testing.T) {
		baseline := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 10,
				RejectedRows:     5,
			},
			RejectedRequestPermanent: 5,
			Sent:                     10,
			HasSentMetric:            true,
			SendFailed:               5,
			EnqueueFailed:            2,
		}
		cur := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 16,
				RejectedRows:     9,
			},
			RejectedRequestPermanent: 9,
			Sent:                     16,
			HasSentMetric:            true,
			SendFailed:               9,
			EnqueueFailed:            3,
		}
		deltaTelem, deltaSendFailed := diffCollectorTelemetry(baseline, cur)
		got := computeCollectorDrainAccounted(baseline, cur, deltaTelem, deltaSendFailed, 0, nil)
		// Disjoint terminal outcomes since baseline: 6 acked + 0 non-perm rejected + 4 send_failed + 1 enqueue_failed = 11.
		if got != 11 {
			t.Fatalf("computeCollectorDrainAccounted(baseline offset) = %d, want 11", got)
		}
	})

	t.Run("RowErrorAndOffloadPermanentClampedByHelperAccounted", func(t *testing.T) {
		base := collectorMetricsSample{
			HasSentMetric: true,
		}

		// retry_on_failure disabled, batch 1 (4 rows): 2 row_error + send_failed=4, sent=0 -> accounted=4 (not 6).
		curRowErrZeroSent := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 0,
				RejectedRows:     2,
			},
			RejectedRowError: 2,
			Sent:             0,
			HasSentMetric:    true,
			SendFailed:       4,
		}
		dtRow0, dsfRow0 := diffCollectorTelemetry(base, curRowErrZeroSent)
		if got := computeCollectorDrainAccounted(base, curRowErrZeroSent, dtRow0, dsfRow0, 0, nil); got != 4 {
			t.Fatalf("computeCollectorDrainAccounted(row_error=2, send_failed=4, sent=0) = %d, want 4", got)
		}

		// After buffered batch 2 (2 rows) flushes: ack=2, rejected=2, send_failed=4, sent=2 -> accounted=6 (not 8).
		curRowErrAfterFlush := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 2,
				RejectedRows:     2,
			},
			RejectedRowError: 2,
			Sent:             2,
			HasSentMetric:    true,
			SendFailed:       4,
		}
		dtRow2, dsfRow2 := diffCollectorTelemetry(base, curRowErrAfterFlush)
		if got := computeCollectorDrainAccounted(base, curRowErrAfterFlush, dtRow2, dsfRow2, 0, nil); got != 6 {
			t.Fatalf("computeCollectorDrainAccounted(ack=2, row_error=2, send_failed=4, sent=2) = %d, want 6", got)
		}

		// offload_permanent=2 with sent=0, send_failed=4 -> accounted=4.
		curOffloadPerm := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 0,
				RejectedRows:     2,
			},
			RejectedOffloadPermanent: 2,
			Sent:                     0,
			HasSentMetric:            true,
			SendFailed:               4,
		}
		dtOff, dsfOff := diffCollectorTelemetry(base, curOffloadPerm)
		if got := computeCollectorDrainAccounted(base, curOffloadPerm, dtOff, dsfOff, 0, nil); got != 4 {
			t.Fatalf("computeCollectorDrainAccounted(offload_permanent=2, send_failed=4, sent=0) = %d, want 4", got)
		}

		// Retries-on control: 4-row batch where 1 row_error was stripped and 3 rows acked (sent=4, send_failed=0) -> accounted=4.
		curRetriesOn := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 3,
				RejectedRows:     1,
			},
			RejectedRowError: 1,
			Sent:             4,
			HasSentMetric:    true,
			SendFailed:       0,
		}
		dtRetryOn, dsfRetryOn := diffCollectorTelemetry(base, curRetriesOn)
		if got := computeCollectorDrainAccounted(base, curRetriesOn, dtRetryOn, dsfRetryOn, 0, nil); got != 4 {
			t.Fatalf("computeCollectorDrainAccounted(retries-on control) = %d, want 4", got)
		}
	})

	t.Run("EnqueueFailedCountsOnceInTerminalOutcomes", func(t *testing.T) {
		base := collectorMetricsSample{
			Sent:          5,
			HasSentMetric: true,
			EnqueueFailed: 2,
		}
		cur := collectorMetricsSample{
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 4,
			},
			Sent:          9, // deltaSent = 4
			HasSentMetric: true,
			EnqueueFailed: 5, // deltaEnqueueFailed = 3
		}
		dt, dsf := diffCollectorTelemetry(base, cur)
		if got := computeCollectorDrainAccounted(base, cur, dt, dsf, 0, nil); got != 7 {
			t.Fatalf("computeCollectorDrainAccounted(enqueue_failed without uniqueFn) = %d, want 7", got)
		}
		if gotUnique := computeCollectorDrainAccounted(base, cur, dt, dsf, 10, func() int64 { return 14 }); gotUnique != 7 {
			t.Fatalf("computeCollectorDrainAccounted(enqueue_failed with uniqueFn) = %d, want 7", gotUnique)
		}
	})
}

func TestRunCollectorLiveEnqueueFailedMarksBatchFailedAndUnreliableBytes(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "live-enqueue-failed.yaml")
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
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "live_enqueue_failed")
	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		CollectorAllowLive:   true,
		ProjectID:            "live-test-proj",
		DatasetID:            "live_test_ds",
		AllowPartialFailures: true,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            6,
		Duration:             200 * time.Millisecond,
		WarmupDuration:       0,
		maxBatches:           1,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "logs")
	if hardErr != nil {
		t.Fatalf("runCollectorSingleSignal hardErr = %v, want nil", hardErr)
	}
	if softErr == nil || !strings.Contains(softErr.Error(), "enqueue_failed=2") {
		t.Fatalf("softErr = %v, want non-nil mentioning enqueue_failed=2", softErr)
	}
	if res.BatchesFailed <= 0 {
		t.Fatalf("BatchesFailed = %d, want > 0", res.BatchesFailed)
	}
	if !res.BytesPerRowUnavailable {
		t.Fatal("expected BytesPerRowUnavailable=true when enqueue_failed > 0 in live collector mode")
	}
	if res.BytesPerRow != 0 || res.WireMBPerSec != 0 {
		t.Fatalf("BytesPerRow=%v WireMBPerSec=%v, want 0/0 when BytesPerRowUnavailable=true", res.BytesPerRow, res.WireMBPerSec)
	}

	cfgStrict := cfg
	cfgStrict.AllowPartialFailures = false
	if lossErr := checkSignalResultLossless(cfgStrict, "logs", res, softErr); lossErr == nil {
		t.Fatal("expected checkSignalResultLossless to fail when AllowPartialFailures=false and enqueue_failed > 0")
	}
	if _, runErr := Run(ctx, cfgStrict); runErr == nil || !strings.Contains(runErr.Error(), "failed lossless delivery check") {
		t.Fatalf("Run(AllowPartialFailures=false) err = %v, want lossless delivery failure", runErr)
	}
}

func TestCollectorIntegrationPermanentRejectionDrainsBufferedBatch(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	const cfgYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 4
    timeout: 400ms
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
    logs:
      table: otel_logs
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-perm-reject-drain.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	fakeSrv.EnqueueFault(
		bqfake.Fault{Mode: bqfake.FaultNone},
		bqfake.Fault{Mode: bqfake.FaultPermissionDenied},
		bqfake.Fault{Mode: bqfake.FaultNone},
	)

	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         collectorBin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            2,
		maxBatches:           5,
		Duration:             5 * time.Second,
		WarmupDuration:       0,
		StreamPoolSize:       1,
		ConnectionPoolSize:   1,
		MaxInflightRequests:  8,
		MaxRequestBytes:      8 * 1024 * 1024,
		AllowPartialFailures: true,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
	}
	if res.DeliveredRows != 6 {
		t.Fatalf("DeliveredRows = %d, want 6", res.DeliveredRows)
	}
	if res.Telemetry.AcknowledgedRows != 6 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want 6", res.Telemetry.AcknowledgedRows)
	}
	if res.Telemetry.RejectedRows != 4 {
		t.Fatalf("Telemetry.RejectedRows = %d, want 4", res.Telemetry.RejectedRows)
	}
	if res.IncompleteDrain {
		t.Fatalf("IncompleteDrain = true (warning=%q), want false", res.DrainWarning)
	}
	if gotAcked := fakeSrv.AckedRowsForTable("otel_logs"); gotAcked != 6 {
		t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 6", gotAcked)
	}
}

func TestCollectorIntegrationTracesRedactionAndBackpressureMetrics(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	const cfgYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 20
    timeout: 20ms
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-traces-redaction-bp.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	cfg := RunnerConfig{
		Mode:             ModeCollector,
		CollectorBin:     collectorBin,
		CollectorConfig:  cfgPath,
		Signals:          []string{"traces"},
		Workers:          1,
		BatchSize:        20,
		Duration:         300 * time.Millisecond,
		WarmupDuration:   0,
		maxBatches:       2,
		Redaction:        true,
		Backpressure:     true,
		SimulateAckDelay: 25 * time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, softErr, hardErr := runCollectorSingleSignal(ctx, cfg, "traces")
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignal(traces) hardErr=%v softErr=%v, want nil/nil", hardErr, softErr)
	}
	if !res.Redaction {
		t.Fatal("expected res.Redaction=true")
	}
	if !res.Backpressure {
		t.Fatal("expected res.Backpressure=true")
	}
	if res.Telemetry.AcknowledgedRows <= 0 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want > 0", res.Telemetry.AcknowledgedRows)
	}
	if res.Telemetry.RedactedValuesTotal <= 0 {
		t.Fatalf("Telemetry.RedactedValuesTotal = %d, want > 0", res.Telemetry.RedactedValuesTotal)
	}
	if res.Telemetry.EffectiveRequestBytes <= 0 {
		t.Fatalf("Telemetry.EffectiveRequestBytes = %d, want > 0", res.Telemetry.EffectiveRequestBytes)
	}
}

func TestCollectorPreflightWriteLimitsAndCLIOverride(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	writeTempCfg := func(t *testing.T, writeBlock string) string {
		t.Helper()
		raw := "receivers:\n  otlp: {}\nexporters:\n  bigquery:\n    project: orig-proj\n    dataset: orig_ds\n    write:\n" + writeBlock + "\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n"
		p := filepath.Join(t.TempDir(), "write-limits.yaml")
		if wErr := os.WriteFile(p, []byte(raw), 0o600); wErr != nil {
			t.Fatalf("write temp config: %v", wErr)
		}
		return p
	}

	cases := []struct {
		name       string
		writeBlock string
		envKey     string
		envVal     string
		wantSub    string
	}{
		{
			name:       "connection_pool_size_literal_17",
			writeBlock: "      connection_pool_size: 17",
			wantSub:    "effective write.connection_pool_size 17 must be between 1 and 16",
		},
		{
			name:       "connection_pool_size_env_17",
			writeBlock: `      connection_pool_size: "${env:TEST_WRITE_CONN_POOL}"`,
			envKey:     "TEST_WRITE_CONN_POOL",
			envVal:     "17",
			wantSub:    "effective write.connection_pool_size 17 must be between 1 and 16",
		},
		{
			name:       "stream_pool_size_literal_17",
			writeBlock: "      stream_pool_size: 17",
			wantSub:    "effective write.stream_pool_size 17 must be between 1 and 16",
		},
		{
			name:       "stream_pool_size_env_17",
			writeBlock: `      stream_pool_size: "${env:TEST_WRITE_STREAM_POOL}"`,
			envKey:     "TEST_WRITE_STREAM_POOL",
			envVal:     "17",
			wantSub:    "effective write.stream_pool_size 17 must be between 1 and 16",
		},
		{
			name:       "max_inflight_requests_literal_65537",
			writeBlock: "      max_inflight_requests: 65537",
			wantSub:    "effective write.max_inflight_requests 65537 must be between 1 and 65536",
		},
		{
			name:       "max_inflight_requests_env_65537",
			writeBlock: `      max_inflight_requests: "${env:TEST_WRITE_MAX_INFLIGHT}"`,
			envKey:     "TEST_WRITE_MAX_INFLIGHT",
			envVal:     "65537",
			wantSub:    "effective write.max_inflight_requests 65537 must be between 1 and 65536",
		},
		{
			name:       "max_request_bytes_literal_0",
			writeBlock: "      max_request_bytes: 0",
			wantSub:    "effective write.max_request_bytes 0 must be > 0",
		},
		{
			name:       "max_request_bytes_env_0",
			writeBlock: `      max_request_bytes: "${env:TEST_WRITE_MAX_REQ_BYTES}"`,
			envKey:     "TEST_WRITE_MAX_REQ_BYTES",
			envVal:     "0",
			wantSub:    "effective write.max_request_bytes 0 must be > 0",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envKey != "" {
				t.Setenv(tc.envKey, tc.envVal)
			}
			cfgPath := writeTempCfg(t, tc.writeBlock)
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    exe,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
			}
			err := validateRunConfig(t.Context(), &cfg, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("validateRunConfig(%s) err = %v, want substring %q", tc.name, err, tc.wantSub)
			}
			if preErr := validateCollectorPreflightConfig(cfg, "logs"); preErr == nil || !strings.Contains(preErr.Error(), tc.wantSub) {
				t.Fatalf("validateCollectorPreflightConfig(%s) err = %v, want substring %q", tc.name, preErr, tc.wantSub)
			}
		})
	}

	t.Run("explicit_cli_overrides_out_of_range_yaml_values", func(t *testing.T) {
		cfgPath := writeTempCfg(t, strings.Join([]string{
			"      stream_pool_size: 17",
			"      connection_pool_size: 17",
			"      max_inflight_requests: 65537",
			"      max_request_bytes: 0",
		}, "\n"))
		cfg := RunnerConfig{
			Mode:                ModeCollector,
			CollectorBin:        exe,
			CollectorConfig:     cfgPath,
			Signals:             []string{"logs"},
			StreamPoolSize:      4,
			ConnectionPoolSize:  8,
			MaxInflightRequests: 32,
			MaxRequestBytes:     8 * 1024 * 1024,
		}
		if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
			t.Fatalf("validateRunConfig(CLI overrides) unexpected error: %v", err)
		}
		if err := validateCollectorPreflightConfig(cfg, "logs"); err != nil {
			t.Fatalf("validateCollectorPreflightConfig(CLI overrides) unexpected error: %v", err)
		}
	})
}

func TestCollectorRejectsConfmapDelimiterKeys(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
	}

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "top_level_exporters_bigquery_dataset",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
exporters::bigquery::dataset: prod_ds
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "top_level_exporters_bigquery_logs_table",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
exporters::bigquery::logs::table: custom_logs
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "top_level_exporters_bigquery_offload_enabled",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
exporters::bigquery::offload::enabled: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "top_level_extensions_file_storage_directory",
			yaml: `
extensions:
  file_storage: {}
extensions::file_storage::directory: /var/lib/otelcol/shared
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  extensions: [file_storage]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "nested_logs_table_under_exporters_bigquery",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery:
    logs::table: bad
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "nested_write_max_inflight_under_exporters_bigquery",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery:
    write::max_inflight_requests: 64
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "delim.yaml")
			if wErr := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    exe,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
			}
			if _, _, rwErr := rewriteCollectorLoopbackConfig([]byte(tc.yaml), cfg, "logs", ep); rwErr == nil || !strings.Contains(rwErr.Error(), "::") {
				t.Fatalf("rewriteCollectorLoopbackConfig(%s) err = %v, want confmap \"::\" error", tc.name, rwErr)
			}
			if preErr := validateRunConfig(t.Context(), &cfg, nil); preErr == nil || !strings.Contains(preErr.Error(), "::") {
				t.Fatalf("validateRunConfig(%s) err = %v, want confmap \"::\" error", tc.name, preErr)
			}
		})
	}
}

func TestCollectorRejectsEmptyOrOmittedServicePipelines(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: t.TempDir(),
		useBQFake:   true,
	}

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "empty_service_pipelines_map",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  pipelines: {}
`,
		},
		{
			name: "omitted_service_pipelines_key",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  extensions: []
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "empty-pipelines.yaml")
			if wErr := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    exe,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
			}
			if _, _, rwErr := rewriteCollectorLoopbackConfig([]byte(tc.yaml), cfg, "logs", ep); rwErr == nil || !strings.Contains(rwErr.Error(), "service.pipelines is empty") {
				t.Fatalf("rewriteCollectorLoopbackConfig(%s) err = %v, want service.pipelines is empty error", tc.name, rwErr)
			}
			if preErr := validateRunConfig(t.Context(), &cfg, nil); preErr == nil || !strings.Contains(preErr.Error(), "service.pipelines is empty") {
				t.Fatalf("validateRunConfig(%s) err = %v, want service.pipelines is empty error", tc.name, preErr)
			}
		})
	}
}

func TestCollectorRejectsOTLPGRPCTLSReceiver(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: t.TempDir(),
		useBQFake:   true,
	}

	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "inline_grpc_tls_map",
			yaml: `
receivers:
  otlp:
    protocols:
      grpc:
        tls:
          cert_file: /etc/cert.pem
          key_file: /etc/key.pem
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "file_ref_grpc_tls",
			yaml: `
receivers:
  otlp:
    protocols:
      grpc:
        tls: "${file:tls.yaml}"
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "grpc-tls.yaml")
			if wErr := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    exe,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
			}
			if _, _, rwErr := rewriteCollectorLoopbackConfig([]byte(tc.yaml), cfg, "logs", ep); rwErr == nil || !strings.Contains(rwErr.Error(), "protocols.grpc.tls") {
				t.Fatalf("rewriteCollectorLoopbackConfig(%s) err = %v, want protocols.grpc.tls error", tc.name, rwErr)
			}
			if preErr := validateRunConfig(t.Context(), &cfg, nil); preErr == nil || !strings.Contains(preErr.Error(), "protocols.grpc.tls") {
				t.Fatalf("validateRunConfig(%s) err = %v, want protocols.grpc.tls error", tc.name, preErr)
			}
		})
	}
}

func TestResolveCollectorBinaryPath(t *testing.T) {
	pathDir := t.TempDir()
	cwdDir := t.TempDir()
	t.Chdir(cwdDir)
	t.Setenv("PATH", pathDir)

	assertSameFile := func(got, want string) os.FileInfo {
		t.Helper()
		fiGot, gErr := os.Stat(got)
		if gErr != nil {
			t.Fatalf("os.Stat(%q): %v", got, gErr)
		}
		fiWant, wErr := os.Stat(want)
		if wErr != nil {
			t.Fatalf("os.Stat(%q): %v", want, wErr)
		}
		if !os.SameFile(fiGot, fiWant) {
			t.Fatalf("path %q does not refer to the same file as %q", got, want)
		}
		return fiGot
	}

	binName := "otelcol-testbin"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}

	cwdBin := filepath.Join(cwdDir, binName)
	if wErr := os.WriteFile(cwdBin, []byte("fake-cwd-bin"), 0o700); wErr != nil {
		t.Fatalf("write cwdBin: %v", wErr)
	}
	cwdInfo, err := os.Stat(cwdBin)
	if err != nil {
		t.Fatalf("os.Stat(cwdBin): %v", err)
	}

	// (a) Bare binName present ONLY in cwdDir (not in PATH) must fail closed.
	if got, rErr := resolveCollectorBinaryPath(binName); rErr == nil {
		t.Fatalf("resolveCollectorBinaryPath(%q) in cwd only succeeded with %q, want error", binName, got)
	}

	// (b) Bare binName present in BOTH cwdDir and pathDir must resolve to pathDir, never cwdDir.
	pathBin := filepath.Join(pathDir, binName)
	if wErr := os.WriteFile(pathBin, []byte("fake-path-bin"), 0o700); wErr != nil {
		t.Fatalf("write pathBin: %v", wErr)
	}
	if runtime.GOOS == "windows" {
		if _, hasNoDefault := os.LookupEnv("NoDefaultCurrentDirectoryInExePath"); !hasNoDefault {
			gotDot, dotErr := resolveCollectorBinaryPath(binName)
			if !errors.Is(dotErr, exec.ErrDot) {
				t.Fatalf("resolveCollectorBinaryPath(%q) without NoDefaultCurrentDirectoryInExePath = (%q, %v), want exec.ErrDot", binName, gotDot, dotErr)
			}
		}
		t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")
	}
	gotPathBin, err := resolveCollectorBinaryPath(binName)
	if err != nil {
		t.Fatalf("resolveCollectorBinaryPath(%q) in PATH error: %v", binName, err)
	}
	gotInfo := assertSameFile(gotPathBin, pathBin)
	if os.SameFile(gotInfo, cwdInfo) {
		t.Fatalf("resolveCollectorBinaryPath(%q) = %q resolved to cwdBin %q", binName, gotPathBin, cwdBin)
	}

	// (c) Explicit relative "./<binName>" (or ".\<binName>") resolves to cwdDir.
	relDotBin := "." + string(filepath.Separator) + binName
	gotDotBin, err := resolveCollectorBinaryPath(relDotBin)
	if err != nil {
		t.Fatalf("resolveCollectorBinaryPath(%q) error: %v", relDotBin, err)
	}
	assertSameFile(gotDotBin, cwdBin)

	// (d) Directory path must return a directory error.
	dirCandidate := t.TempDir()
	if got, dirErr := resolveCollectorBinaryPath(dirCandidate); dirErr == nil || !strings.Contains(dirErr.Error(), "is a directory") {
		t.Fatalf("resolveCollectorBinaryPath(dir) = (%q, %v), want 'is a directory' error", got, dirErr)
	}
}

func TestCollectorUniqueAckedSaturationFailsClosed(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector-unique-sat.yaml")
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

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()
	fakeSrv.SetDiscardRows(true)
	fakeSrv.SetMaxUniqueAckedRows(2)

	bin := configureCollectorHelperEnv(t, "default")
	cfg := RunnerConfig{
		Mode:             ModeCollector,
		CollectorBin:     bin,
		CollectorConfig:  cfgPath,
		Signals:          []string{"logs"},
		Workers:          1,
		BatchSize:        2,
		maxBatches:       2,
		SimulateAckDelay: time.Millisecond,
		Duration:         500 * time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "saturated") || !strings.Contains(hardErr.Error(), "unique_delivery_verified") {
		t.Fatalf("runCollectorSingleSignalWithFake(MaxUniqueAckedRows=2) hardErr = %v, want error containing 'saturated' and 'unique_delivery_verified'", hardErr)
	}
}

func TestCollectorIntegrationRowErrorRetryOffDrainsBufferedBatch(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 4
    timeout: 400ms
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
    logs:
      table: otel_logs
    retry_on_failure:
      enabled: false
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-row-error-retry-off.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	fakeSrv.EnqueueFault(bqfake.Fault{
		Mode:  bqfake.FaultRowErrors,
		Table: "otel_logs",
		RowErrors: []*storagepb.RowError{
			{Index: 0, Code: storagepb.RowError_FIELDS_ERROR, Message: "bad0"},
			{Index: 1, Code: storagepb.RowError_FIELDS_ERROR, Message: "bad1"},
		},
	})
	fakeSrv.EnqueueFault(bqfake.Fault{
		Mode:  bqfake.FaultNone,
		Table: "otel_logs",
	})

	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         collectorBin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            2,
		maxBatches:           3,
		Duration:             5 * time.Second,
		WarmupDuration:       0,
		StreamPoolSize:       1,
		ConnectionPoolSize:   1,
		MaxInflightRequests:  8,
		MaxRequestBytes:      8 * 1024 * 1024,
		AllowPartialFailures: true,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake unexpected hardErr: %v", hardErr)
	}
	if res.IncompleteDrain {
		t.Fatalf("expected IncompleteDrain=false, got true (warning=%q)", res.DrainWarning)
	}
	if res.DeliveredRows != 2 {
		t.Fatalf("DeliveredRows = %d, want 2", res.DeliveredRows)
	}
	if res.Telemetry.AcknowledgedRows != 2 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want 2", res.Telemetry.AcknowledgedRows)
	}
	if res.Telemetry.RejectedRows != 2 {
		t.Fatalf("Telemetry.RejectedRows = %d, want 2", res.Telemetry.RejectedRows)
	}
	if got := fakeSrv.AckedRowsForTable("otel_logs"); got != 2 {
		t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 2", got)
	}
}

func TestCollectorLosslessRequiresDestinationCommitInFakeMode(t *testing.T) {
	origMinDrain := collectorMinDrainTimeout
	collectorMinDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() {
		collectorMinDrainTimeout = origMinDrain
	})

	cfgPath := filepath.Join(t.TempDir(), "collector-ack-no-commit.yaml")
	rawYAML := `
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
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "ack_without_commit")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// (a) AllowPartialFailures=false: drain times out against bqfake (0 committed rows), so both
	// runCollectorSingleSignalWithFake and Run fail closed.
	fakeSrvStrict, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrvStrict.Close() }()

	cfgStrict := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: false,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           150 * time.Millisecond,
		WarmupDuration:     0,
	}
	if err := cfgStrict.Normalize(); err != nil {
		t.Fatalf("cfgStrict.Normalize: %v", err)
	}
	if _, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfgStrict, "logs", fakeSrvStrict); hardErr == nil || !strings.Contains(hardErr.Error(), "timed out") {
		t.Fatalf("runCollectorSingleSignalWithFake(AllowPartialFailures=false) hardErr = %v, want drain timeout", hardErr)
	}
	if got := fakeSrvStrict.AckedRowsForTable("otel_logs"); got != 0 {
		t.Fatalf("fakeSrvStrict.AckedRowsForTable(otel_logs) = %d, want 0", got)
	}
	if _, runErr := Run(ctx, cfgStrict); runErr == nil {
		t.Fatal("Run(AllowPartialFailures=false, ack_without_commit) succeeded, want error")
	}

	// (b) AllowPartialFailures=true: runCollectorSingleSignalWithFake returns DeliveredRows=0 and
	// IncompleteDrain=true, and checkSignalResultLossless fails closed regardless of AllowPartialFailures.
	fakeSrvPartial, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrvPartial.Close() }()

	cfgPartial := cfgStrict
	cfgPartial.AllowPartialFailures = true
	resPartial, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfgPartial, "logs", fakeSrvPartial)
	if hardErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake(AllowPartialFailures=true) unexpected hardErr: %v", hardErr)
	}
	if got := fakeSrvPartial.AckedRowsForTable("otel_logs"); got != 0 {
		t.Fatalf("fakeSrvPartial.AckedRowsForTable(otel_logs) = %d, want 0", got)
	}
	if resPartial.DeliveredRows != 0 {
		t.Fatalf("resPartial.DeliveredRows = %d, want 0", resPartial.DeliveredRows)
	}
	if !resPartial.IncompleteDrain {
		t.Fatal("expected resPartial.IncompleteDrain = true")
	}
	if lossErr := checkSignalResultLossless(cfgPartial, "logs", resPartial, softErr); lossErr == nil {
		t.Fatal("checkSignalResultLossless(AllowPartialFailures=true, DeliveredRows=0) succeeded, want error")
	}
	if lossErr := checkSignalResultLossless(cfgStrict, "logs", resPartial, softErr); lossErr == nil {
		t.Fatal("checkSignalResultLossless(AllowPartialFailures=false, DeliveredRows=0) succeeded, want error")
	}

	// (c) Synthetic ModeCollector shortfall: DeliveredRows=2 < RecordsSubmitted=4 fails closed even when
	// Telemetry.AcknowledgedRows=4 and UniqueDeliveryVerified=false.
	synthRes := SignalResult{
		Signal:                 "logs",
		Mode:                   ModeCollector,
		BatchesAttempted:       1,
		BatchesSucceeded:       1,
		RecordsSubmitted:       4,
		DeliveredRows:          2,
		UniqueDeliveryVerified: false,
		Latency:                LatencySummary{Samples: 1},
		Telemetry:              TelemetrySnapshot{AcknowledgedRows: 4},
	}
	if lossErr := checkSignalResultLossless(cfgStrict, "logs", synthRes, nil); lossErr == nil || !strings.Contains(lossErr.Error(), "failed lossless delivery check") {
		t.Fatalf("checkSignalResultLossless(DeliveredRows=2 < Submitted=4) = %v, want lossless delivery error", lossErr)
	}
}

func TestCollectorRejectsUndefinedPipelineExporter(t *testing.T) {
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:50052",
	}

	typoYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery/access:
    redaction:
      enabled: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/acess]
`
	typoPath := filepath.Join(t.TempDir(), "typo-exporter.yaml")
	if err := os.WriteFile(typoPath, []byte(typoYAML), 0o600); err != nil {
		t.Fatalf("write typo YAML: %v", err)
	}
	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: typoPath,
		Signals:         []string{"logs"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	_, _, rwErr := rewriteCollectorLoopbackConfig([]byte(typoYAML), cfg, "logs", ep)
	if rwErr == nil || !strings.Contains(rwErr.Error(), `"logs"`) || !strings.Contains(rwErr.Error(), `"bigquery/acess"`) || !strings.Contains(rwErr.Error(), "bigquery/access") {
		t.Fatalf("rewriteCollectorLoopbackConfig(typo) err = %v, want error naming pipeline \"logs\", missing \"bigquery/acess\", and defined \"bigquery/access\"", rwErr)
	}
	pfErr := validateCollectorPreflightConfig(cfg, "logs")
	if pfErr == nil || !strings.Contains(pfErr.Error(), `"logs"`) || !strings.Contains(pfErr.Error(), `"bigquery/acess"`) || !strings.Contains(pfErr.Error(), "bigquery/access") {
		t.Fatalf("validateCollectorPreflightConfig(typo) err = %v, want error naming pipeline \"logs\", missing \"bigquery/acess\", and defined \"bigquery/access\"", pfErr)
	}

	missingSectionYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/acess]
`
	missingPath := filepath.Join(t.TempDir(), "missing-exporters.yaml")
	if err := os.WriteFile(missingPath, []byte(missingSectionYAML), 0o600); err != nil {
		t.Fatalf("write missing-exporters YAML: %v", err)
	}
	cfgMissing := cfg
	cfgMissing.CollectorConfig = missingPath

	_, _, rwMissingErr := rewriteCollectorLoopbackConfig([]byte(missingSectionYAML), cfgMissing, "logs", ep)
	if rwMissingErr == nil || !strings.Contains(rwMissingErr.Error(), `"logs"`) || !strings.Contains(rwMissingErr.Error(), `"bigquery/acess"`) {
		t.Fatalf("rewriteCollectorLoopbackConfig(missing exporters) err = %v, want error naming \"logs\" and \"bigquery/acess\"", rwMissingErr)
	}
	pfMissingErr := validateCollectorPreflightConfig(cfgMissing, "logs")
	if pfMissingErr == nil || !strings.Contains(pfMissingErr.Error(), `"logs"`) || !strings.Contains(pfMissingErr.Error(), `"bigquery/acess"`) {
		t.Fatalf("validateCollectorPreflightConfig(missing exporters) err = %v, want error naming \"logs\" and \"bigquery/acess\"", pfMissingErr)
	}
}

func TestCollectorLiveEndpointPreservationAndValidation(t *testing.T) {
	t.Setenv("TEST_LIVE_WRITE_ENDPOINT", "bigquery-write-psc.example.com:443")
	t.Setenv("TEST_LIVE_ADMIN_ENDPOINT", "https://bigquery-psc.example.com/bigquery/v2/")

	validLiveYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      url: "${env:TEST_LIVE_WRITE_ENDPOINT}"
      admin_url: "${env:TEST_LIVE_ADMIN_ENDPOINT}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "live-psc.yaml")
	if err := os.WriteFile(cfgPath, []byte(validLiveYAML), 0o600); err != nil {
		t.Fatalf("write live-psc.yaml: %v", err)
	}
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		ProjectID:          "live-proj",
		DatasetID:          "live_ds",
		Location:           "US",
		Signals:            []string{"logs"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   false,
	}
	rewritten, meta, err := rewriteCollectorLoopbackConfig([]byte(validLiveYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(useBQFake=false): %v", err)
	}
	if meta.effectiveEndpoint.URL != "bigquery-write-psc.example.com:443" {
		t.Fatalf("meta.effectiveEndpoint.URL = %q, want %q", meta.effectiveEndpoint.URL, "bigquery-write-psc.example.com:443")
	}
	if meta.effectiveEndpoint.AdminURL != "https://bigquery-psc.example.com/bigquery/v2/" {
		t.Fatalf("meta.effectiveEndpoint.AdminURL = %q, want %q", meta.effectiveEndpoint.AdminURL, "https://bigquery-psc.example.com/bigquery/v2/")
	}
	var parsed map[string]any
	if uErr := yaml.Unmarshal(rewritten, &parsed); uErr != nil {
		t.Fatalf("yaml.Unmarshal(rewritten): %v", uErr)
	}
	exps, _ := parsed["exporters"].(map[string]any)
	bqMap, _ := exps["bigquery"].(map[string]any)
	epMap, _ := bqMap["endpoint"].(map[string]any)
	if epMap["url"] == nil || epMap["admin_url"] == nil {
		t.Fatalf("expected endpoint.url and endpoint.admin_url preserved when useBQFake=false, got %v", epMap)
	}

	if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr != nil {
		t.Fatalf("validateCollectorPreflightConfig(valid PSC HTTPS) unexpected error: %v", pfErr)
	}

	// Non-loopback HTTP admin_url must fail preflight up front.
	httpAdminYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      url: bigquery-write-psc.example.com:443
      admin_url: http://bigquery-psc.example.com
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	httpAdminPath := filepath.Join(t.TempDir(), "live-http-admin.yaml")
	if wErr := os.WriteFile(httpAdminPath, []byte(httpAdminYAML), 0o600); wErr != nil {
		t.Fatalf("write live-http-admin.yaml: %v", wErr)
	}
	cfgHTTPAdmin := cfg
	cfgHTTPAdmin.CollectorConfig = httpAdminPath
	if pfErr := validateCollectorPreflightConfig(cfgHTTPAdmin, "logs"); pfErr == nil {
		t.Fatal("validateCollectorPreflightConfig(non-loopback http:// admin_url) succeeded, want error")
	}

	// Non-loopback insecure: true must fail preflight up front.
	insecureYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      url: bigquery-write-psc.example.com:443
      insecure: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	insecurePath := filepath.Join(t.TempDir(), "live-insecure.yaml")
	if wErr := os.WriteFile(insecurePath, []byte(insecureYAML), 0o600); wErr != nil {
		t.Fatalf("write live-insecure.yaml: %v", wErr)
	}
	cfgInsecure := cfg
	cfgInsecure.CollectorConfig = insecurePath
	if pfErr := validateCollectorPreflightConfig(cfgInsecure, "logs"); pfErr == nil {
		t.Fatal("validateCollectorPreflightConfig(non-loopback insecure=true) succeeded, want error")
	}
}

func TestCollectorUpstreamInsertIDGeneratesFreshEventIdentities(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector-upstream-insert-id.yaml")
	rawYAML := `
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
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	bin := configureCollectorHelperEnv(t, "default")
	cfg := RunnerConfig{
		Mode:             ModeCollector,
		CollectorBin:     bin,
		CollectorConfig:  cfgPath,
		WorkloadProfile:  WorkloadProfileAccessLogs,
		UpstreamInsertID: true,
		Signals:          []string{"logs"},
		Workers:          2,
		BatchSize:        2,
		maxBatches:       8,
		Duration:         5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hardErr=%v softErr=%v", hardErr, softErr)
	}
	if res.Telemetry.ReplayedRows != 0 {
		t.Fatalf("Telemetry.ReplayedRows = %d, want 0", res.Telemetry.ReplayedRows)
	}
	if got := fakeSrv.AckedRowsForTable("otel_logs"); got != 16 {
		t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 16", got)
	}

	rows := fakeSrv.Rows("otel_logs")
	if len(rows) != 16 {
		t.Fatalf("len(fakeSrv.Rows(otel_logs)) = %d, want 16", len(rows))
	}
	seenInsertIDs := make(map[string]struct{}, 16)
	seenTuples := make(map[string]struct{}, 16)
	for i, r := range rows {
		insertID, _ := r["insert_id"].(string)
		if !strings.HasPrefix(insertID, "edge-") {
			t.Fatalf("row[%d] insert_id = %q, want upstream 'edge-...' identity", i, insertID)
		}
		seenInsertIDs[insertID] = struct{}{}
		tuple := fmt.Sprintf("%v|%v|%s", r["log_name"], r["timestamp"], insertID)
		seenTuples[tuple] = struct{}{}
	}
	if len(seenInsertIDs) != 16 {
		t.Fatalf("distinct insert_id count = %d, want 16", len(seenInsertIDs))
	}
	if len(seenTuples) != 16 {
		t.Fatalf("distinct (log_name, timestamp, insert_id) tuple count = %d, want 16", len(seenTuples))
	}
}

func TestCollectorEnvResolutionUsesEffectiveChildGOMAXPROCS(t *testing.T) {
	t.Setenv("GOMAXPROCS", "1")

	rawYAML := `
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
    write:
      stream_pool_size: "${env:GOMAXPROCS}"
      connection_pool_size: "${env:GOMAXPROCS}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-gomaxprocs.yaml")
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:50052",
	}

	cfg2 := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		MaxProcs:        2,
	}
	if err := cfg2.Normalize(); err != nil {
		t.Fatalf("cfg2.Normalize: %v", err)
	}
	_, meta2, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg2, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(MaxProcs=2): %v", err)
	}
	if meta2.effectiveStreamPoolSize != 2 || meta2.effectiveConnectionPoolSize != 2 {
		t.Fatalf("effective pool sizes = (%d, %d), want (2, 2)", meta2.effectiveStreamPoolSize, meta2.effectiveConnectionPoolSize)
	}
	if pfErr := validateCollectorPreflightConfig(cfg2, "logs"); pfErr != nil {
		t.Fatalf("validateCollectorPreflightConfig(MaxProcs=2) unexpected error: %v", pfErr)
	}

	cfg17 := cfg2
	cfg17.MaxProcs = 17
	if pfErr := validateCollectorPreflightConfig(cfg17, "logs"); pfErr == nil || !strings.Contains(pfErr.Error(), "17") {
		t.Fatalf("validateCollectorPreflightConfig(MaxProcs=17) err = %v, want error rejecting effective stream_pool_size=17 (> 16)", pfErr)
	}
}

func TestCollectorUniqueAckedPreflightAndEarlyAbort(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector-unique-cap.yaml")
	rawYAML := `
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
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("PreflightRejectsBeforeStartingCollector", func(t *testing.T) {
		// Use exit_immediately_code3 so any child spawn produces "child exited non-zero"
		// rather than preflight rejection.
		failOnStartBin := configureCollectorHelperEnv(t, "exit_immediately_code3")

		t.Run("ThreeMillionGeneratedRowsPassPreflight", func(t *testing.T) {
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()

			cfg := RunnerConfig{
				Mode:                  ModeCollector,
				CollectorBin:          failOnStartBin,
				CollectorConfig:       cfgPath,
				Signals:               []string{"logs"},
				TargetRate:            100000,
				Duration:              30 * time.Second,
				SimulateThrottleEvery: 1,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr == nil || !strings.Contains(hardErr.Error(), "child exited non-zero") {
				t.Fatalf("expected 3M generated run to pass preflight and reach child process start ('child exited non-zero'), got %v", hardErr)
			}
		})

		t.Run("AboveBitmapLimitRejectsBeforeStartingCollector", func(t *testing.T) {
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()

			cfg := RunnerConfig{
				Mode:                  ModeCollector,
				CollectorBin:          failOnStartBin,
				CollectorConfig:       cfgPath,
				Signals:               []string{"logs"},
				TargetRate:            1000000,
				Duration:              70 * time.Second,
				SimulateThrottleEvery: 1,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr == nil {
				t.Fatal("expected preflight rejection when TargetRate*Duration exceeds MaxTrackedGeneratedRows")
			}
			msg := hardErr.Error()
			wantLimit := fmt.Sprintf("%d", bqfake.DefaultMaxSequenceBitmapChunks*65536)
			for _, wantSub := range []string{wantLimit, "-rate", "-duration", "-simulate-throttle-every", "-simulate-ack-delay"} {
				if !strings.Contains(msg, wantSub) {
					t.Fatalf("preflight error %q missing %q", msg, wantSub)
				}
			}
			if strings.Contains(msg, "child exited non-zero") {
				t.Fatalf("expected rejection before spawning collector, got %q", msg)
			}
		})

		t.Run("CustomMaxUniqueAckedRowsCapRejectsBeforeStartingCollector", func(t *testing.T) {
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()
			fakeSrv.SetMaxUniqueAckedRows(100)

			cfg := RunnerConfig{
				Mode:                  ModeCollector,
				CollectorBin:          failOnStartBin,
				CollectorConfig:       cfgPath,
				Signals:               []string{"logs"},
				TargetRate:            100,
				Duration:              3 * time.Second,
				SimulateThrottleEvery: 1,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr == nil {
				t.Fatal("expected preflight rejection when TargetRate*Duration exceeds custom MaxUniqueAckedRows=100")
			}
			msg := hardErr.Error()
			if !strings.Contains(msg, "100") {
				t.Fatalf("preflight error %q missing custom cap 100", msg)
			}
			if strings.Contains(msg, "child exited non-zero") {
				t.Fatalf("expected rejection before spawning collector, got %q", msg)
			}
		})
	})

	t.Run("EarlySaturationAbortCancelsPhasePromptly", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "default")
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(true)
		fakeSrv.SetMaxUniqueAckedRows(4)

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     bin,
			CollectorConfig:  cfgPath,
			Signals:          []string{"logs"},
			Workers:          1,
			BatchSize:        2,
			maxBatches:       0,
			TargetRate:       0,
			Duration:         10 * time.Second,
			WarmupDuration:   0,
			SimulateAckDelay: time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		start := time.Now()
		res, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		elapsed := time.Since(start)
		if hardErr == nil {
			t.Fatal("expected saturation hardErr, got nil")
		}
		if res.Signal != "logs" || res.RecordsAttempted <= 0 || res.RecordsSubmitted <= 0 || res.UniqueDeliveryVerified {
			t.Fatalf("expected populated cutoff SignalResult with UniqueDeliveryVerified=false on saturation, got %+v", res)
		}
		if !strings.Contains(hardErr.Error(), "saturated") || !strings.Contains(hardErr.Error(), "-rate") {
			t.Fatalf("hardErr = %v, want 'saturated' and '-rate' remedy", hardErr)
		}
		if elapsed >= 4*time.Second {
			t.Fatalf("early saturation abort took %s, want < 4s (duration was 10s)", elapsed)
		}
	})
}

func TestCollectorSendingQueueBatchParsingAndDrainWait(t *testing.T) {
	t.Setenv("TEST_SQ_FLUSH_TIMEOUT", "450ms")

	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:50052",
	}

	makeYAML := func(sqBlock string) []byte {
		return []byte(fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: orig-proj
    dataset: orig_ds
    location: US
%s
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, sqBlock))
	}

	baseCfg := RunnerConfig{
		Mode:         ModeCollector,
		CollectorBin: os.Args[0],
		Signals:      []string{"logs"},
	}

	tests := []struct {
		name      string
		sqBlock   string
		wantFlush time.Duration
		wantItems int
	}{
		{
			name: "items_default_active",
			sqBlock: `    sending_queue:
      batch:
        flush_timeout: 500ms
        min_size: 4`,
			wantFlush: 500 * time.Millisecond,
			wantItems: 4,
		},
		{
			name: "min_size_zero_inactive",
			sqBlock: `    sending_queue:
      batch:
        flush_timeout: 500ms
        min_size: 0`,
			wantFlush: 0,
			wantItems: 0,
		},
		{
			name: "queue_disabled",
			sqBlock: `    sending_queue:
      enabled: false
      batch:
        flush_timeout: 500ms
        min_size: 4`,
			wantFlush: 0,
			wantItems: 0,
		},
		{
			name: "batch_disabled",
			sqBlock: `    sending_queue:
      batch:
        enabled: false
        flush_timeout: 500ms
        min_size: 4`,
			wantFlush: 0,
			wantItems: 0,
		},
		{
			name: "inherits_parent_bytes_sizer",
			sqBlock: `    sending_queue:
      sizer: bytes
      batch:
        flush_timeout: 350ms
        min_size: 4096`,
			wantFlush: 350 * time.Millisecond,
			wantItems: 0,
		},
		{
			name: "env_resolved_flush_timeout",
			sqBlock: `    sending_queue:
      batch:
        flush_timeout: "${env:TEST_SQ_FLUSH_TIMEOUT}"
        min_size: 4`,
			wantFlush: 450 * time.Millisecond,
			wantItems: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw := makeYAML(tc.sqBlock)
			p := filepath.Join(t.TempDir(), "sq.yaml")
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg := baseCfg
			cfg.CollectorConfig = p
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			_, meta, err := rewriteCollectorLoopbackConfig(raw, cfg, "logs", ep)
			if err != nil {
				t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
			}
			if meta.queueBatchFlushTimeout != tc.wantFlush {
				t.Fatalf("queueBatchFlushTimeout = %s, want %s", meta.queueBatchFlushTimeout, tc.wantFlush)
			}
			if meta.queueBatchMinItems != tc.wantItems {
				t.Fatalf("queueBatchMinItems = %d, want %d", meta.queueBatchMinItems, tc.wantItems)
			}
		})
	}

	// Verify derived drainTimeout incorporates queueBatchFlushTimeout in runCollectorSingleSignalWithFake:
	// with collectorMinDrainTimeout=80ms and delayed_commit_200ms, min_size=4 + flush_timeout=500ms extends
	// drainTimeout (2*500ms + 5s = 6s > 200ms) so drain succeeds cleanly.
	t.Run("DerivedDrainTimeoutIncorporatesQueueBatchFlushTimeout", func(t *testing.T) {
		origMinDrain := collectorMinDrainTimeout
		collectorMinDrainTimeout = 80 * time.Millisecond
		t.Cleanup(func() {
			collectorMinDrainTimeout = origMinDrain
		})

		raw := makeYAML(`    sending_queue:
      batch:
        flush_timeout: 500ms
        min_size: 4`)
		p := filepath.Join(t.TempDir(), "sq-drain-timeout.yaml")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    configureCollectorHelperEnv(t, "delayed_commit_200ms"),
			CollectorConfig: p,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       2,
			maxBatches:      1,
			Duration:        100 * time.Millisecond,
			WarmupDuration:  0,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()

		res, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(flush_timeout=500ms) hardErr = %v, want nil", hardErr)
		}
		if res.DeliveredRows != 2 {
			t.Fatalf("DeliveredRows = %d, want 2", res.DeliveredRows)
		}
	})

	// Verify drainCollectorPipelineWithBatchWait accumulates idleBatchWait while QueueSize > 0 and
	// InflightRequests == 0, capping idleBatchWait at queueBatchFlushTimeout.
	t.Run("DrainWaitAccumulatesAndCapsQueueBatchFlushTimeout", func(t *testing.T) {
		const holdingMetrics = `# TYPE otelcol_exporter_bigquery_acknowledged_rows counter
otelcol_exporter_bigquery_acknowledged_rows{exporter="bigquery",signal="logs"} 4
otelcol_exporter_sent_log_records{exporter="bigquery"} 4
otelcol_exporter_queue_size{exporter="bigquery"} 2
otelcol_exporter_bigquery_inflight_requests{exporter="bigquery",signal="logs"} 0
`
		const flushedMetrics = `# TYPE otelcol_exporter_bigquery_acknowledged_rows counter
otelcol_exporter_bigquery_acknowledged_rows{exporter="bigquery",signal="logs"} 6
otelcol_exporter_sent_log_records{exporter="bigquery"} 6
otelcol_exporter_queue_size{exporter="bigquery"} 0
otelcol_exporter_bigquery_inflight_requests{exporter="bigquery",signal="logs"} 0
`
		var (
			mu          sync.Mutex
			firstScrape time.Time
			scrapes     int
		)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			mu.Lock()
			scrapes++
			if firstScrape.IsZero() {
				firstScrape = time.Now()
			}
			stillHolding := scrapes < 4 || time.Since(firstScrape) < 160*time.Millisecond
			mu.Unlock()
			if stillHolding {
				_, _ = w.Write([]byte(holdingMetrics))
				return
			}
			_, _ = w.Write([]byte(flushedMetrics))
		}))
		defer srv.Close()

		const flushCap = 100 * time.Millisecond
		doneCh := make(chan struct{})
		var waitErr error
		diag := new(boundedDiagBuffer)
		sample, idleBatchWait, drainErr := drainCollectorPipelineWithBatchWait(
			context.Background(),
			srv.Client(),
			srv.Listener.Addr().String(),
			"logs",
			"bigquery",
			collectorMetricsSample{},
			6,
			3*time.Second,
			doneCh,
			&waitErr,
			diag,
			0,
			nil,
			collectorBatchWaitConfig{
				queueBatchFlushTimeout: flushCap,
				queueBatchMinItems:     4,
			},
		)
		if drainErr != nil {
			t.Fatalf("drainCollectorPipelineWithBatchWait unexpected error: %v", drainErr)
		}
		if sample.Telemetry.AcknowledgedRows != 6 {
			t.Fatalf("AcknowledgedRows = %d, want 6", sample.Telemetry.AcknowledgedRows)
		}
		if idleBatchWait <= 0 {
			t.Fatalf("idleBatchWait = %s, want > 0", idleBatchWait)
		}
		if idleBatchWait > flushCap {
			t.Fatalf("idleBatchWait = %s, want capped at <= %s", idleBatchWait, flushCap)
		}
		if idleBatchWait != flushCap {
			t.Fatalf("idleBatchWait = %s, want exact cap %s after >=160ms idle hold", idleBatchWait, flushCap)
		}
	})
}

func TestCollectorIntegrationDefaultWorkloadProducesDistinctDedupKeys(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	cfgPath := resolveCollectorConfigPath(filepath.Join("example", "otel-collector-high-volume-logs.yaml"))

	t.Setenv("BQ_PROJECT", "orig-proj")
	t.Setenv("BQ_DATASET", "orig_ds")
	t.Setenv("BQ_LOCATION", "US")

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		Workers:         2,
		BatchSize:       1,
		maxBatches:      12,
		Duration:        5 * time.Second,
		WarmupDuration:  0,
	}
	if normErr := cfg.Normalize(); normErr != nil {
		t.Fatalf("Normalize: %v", normErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hardErr=%v softErr=%v", hardErr, softErr)
	}
	if res.RecordsSubmitted != 12 {
		t.Fatalf("RecordsSubmitted = %d, want 12", res.RecordsSubmitted)
	}
	if res.DeliveredRows != 12 {
		t.Fatalf("DeliveredRows = %d, want 12", res.DeliveredRows)
	}
	if res.Telemetry.ReplayedRows != 0 {
		t.Fatalf("Telemetry.ReplayedRows = %d, want 0", res.Telemetry.ReplayedRows)
	}
	if gotAcked := fakeSrv.AckedRowsForTable("otel_logs"); gotAcked != 12 {
		t.Fatalf("AckedRowsForTable(otel_logs) = %d, want 12", gotAcked)
	}

	rows := fakeSrv.Rows("otel_logs")
	if len(rows) != 12 {
		t.Fatalf("len(rows) = %d, want 12", len(rows))
	}
	seenInsertIDs := make(map[string]struct{}, 12)
	seenUnixNano := make(map[any]struct{}, 12)
	seenTuples := make(map[string]struct{}, 12)
	for i, r := range rows {
		insertID, _ := r["insert_id"].(string)
		if insertID == "" {
			t.Fatalf("row[%d] insert_id is empty: %#v", i, r["insert_id"])
		}
		unixNano := r["time_unix_nano"]
		if unixNano == nil {
			t.Fatalf("row[%d] time_unix_nano is nil", i)
		}
		seenInsertIDs[insertID] = struct{}{}
		seenUnixNano[unixNano] = struct{}{}
		seenTuples[fmt.Sprintf("%v|%v|%s", r["log_name"], r["timestamp"], insertID)] = struct{}{}
	}
	if len(seenInsertIDs) != 12 {
		t.Fatalf("distinct insert_id count = %d, want 12", len(seenInsertIDs))
	}
	if len(seenUnixNano) != 12 {
		t.Fatalf("distinct time_unix_nano count = %d, want 12", len(seenUnixNano))
	}
	if len(seenTuples) != 12 {
		t.Fatalf("distinct (log_name, timestamp, insert_id) tuple count = %d, want 12", len(seenTuples))
	}
}

type testTimestampCaptureOTLPServer struct {
	plogotlp.UnimplementedGRPCServer
	mu         sync.Mutex
	timestamps []pcommon.Timestamp
	insertIDs  []string
}

func (s *testTimestampCaptureOTLPServer) Export(_ context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	rls := req.Logs().ResourceLogs()
	s.mu.Lock()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			lrs := sls.At(j).LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				lr := lrs.At(k)
				s.timestamps = append(s.timestamps, lr.Timestamp())
				id := ""
				if v, ok := lr.Attributes().Get("logging.googleapis.com/insertId"); ok {
					id = v.Str()
				}
				s.insertIDs = append(s.insertIDs, id)
			}
		}
	}
	s.mu.Unlock()
	return plogotlp.NewExportResponse(), nil
}

func collectLogIdentities(ld plog.Logs) (timestamps []pcommon.Timestamp, insertIDs []string) {
	rls := ld.ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			lrs := sls.At(j).LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				lr := lrs.At(k)
				timestamps = append(timestamps, lr.Timestamp())
				id := ""
				if v, ok := lr.Attributes().Get("logging.googleapis.com/insertId"); ok {
					id = v.Str()
				}
				insertIDs = append(insertIDs, id)
			}
		}
	}
	return timestamps, insertIDs
}

type spanIdentitySnapshot struct {
	spanID       pcommon.SpanID
	parentSpanID pcommon.SpanID
	startTS      pcommon.Timestamp
}

func collectSpanIdentities(td ptrace.Traces) []spanIdentitySnapshot {
	var out []spanIdentitySnapshot
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		sss := rss.At(i).ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				sp := spans.At(k)
				out = append(out, spanIdentitySnapshot{
					spanID:       sp.SpanID(),
					parentSpanID: sp.ParentSpanID(),
					startTS:      sp.StartTimestamp(),
				})
			}
		}
	}
	return out
}

func collectMetricTimestamps(md pmetric.Metrics) []pcommon.Timestamp {
	var out []pcommon.Timestamp
	rms := md.ResourceMetrics()
	for i := 0; i < rms.Len(); i++ {
		sms := rms.At(i).ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			ms := sms.At(j).Metrics()
			for k := 0; k < ms.Len(); k++ {
				m := ms.At(k)
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					dps := m.Gauge().DataPoints()
					for p := 0; p < dps.Len(); p++ {
						out = append(out, dps.At(p).Timestamp())
					}
				case pmetric.MetricTypeSum:
					dps := m.Sum().DataPoints()
					for p := 0; p < dps.Len(); p++ {
						out = append(out, dps.At(p).Timestamp())
					}
				case pmetric.MetricTypeHistogram:
					dps := m.Histogram().DataPoints()
					for p := 0; p < dps.Len(); p++ {
						out = append(out, dps.At(p).Timestamp())
					}
				case pmetric.MetricTypeExponentialHistogram:
					dps := m.ExponentialHistogram().DataPoints()
					for p := 0; p < dps.Len(); p++ {
						out = append(out, dps.At(p).Timestamp())
					}
				case pmetric.MetricTypeSummary:
					dps := m.Summary().DataPoints()
					for p := 0; p < dps.Len(); p++ {
						out = append(out, dps.At(p).Timestamp())
					}
				case pmetric.MetricTypeEmpty:
				}
			}
		}
	}
	return out
}

func TestCollectorDefaultWorkloadStampsDistinctSignalIdentities(t *testing.T) {
	t.Run("LogsDefaultAndUpstreamInsertID", func(t *testing.T) {
		for _, upstreamInsertID := range []bool{false, true} {
			name := "upstream_insert_id_false"
			if upstreamInsertID {
				name = "upstream_insert_id_true"
			}
			t.Run(name, func(t *testing.T) {
				ld := NewGenerator(GeneratorConfig{UpstreamInsertID: upstreamInsertID}).LogsBatch(2)
				if upstreamInsertID {
					stampFreshLogsIdentity(ld, DefaultBaseTime, 1, true)
				}
				src := []collectorPreparedBatch{{
					logsReq:     plogotlp.NewExportRequestFromLogs(ld),
					recordCount: int64(ld.LogRecordCount()),
				}}
				origTS, origIDs := collectLogIdentities(src[0].logsReq.Logs())

				cloned := cloneCollectorPreparedBatch(src[0])
				seenTS := make(map[pcommon.Timestamp]struct{})
				seenIDs := make(map[string]struct{})

				for dispatchIdx, startSeq := range []uint64{100, 200} {
					stampCollectorPreparedBatchIdentity("logs", cloned, DefaultBaseTime, startSeq, upstreamInsertID)
					gotTS, gotIDs := collectLogIdentities(cloned.logsReq.Logs())
					if len(gotTS) != 2 {
						t.Fatalf("dispatch %d log count = %d, want 2", dispatchIdx, len(gotTS))
					}
					for idx, ts := range gotTS {
						seenTS[ts] = struct{}{}
						if upstreamInsertID {
							if gotIDs[idx] == "" {
								t.Fatalf("dispatch %d record %d missing upstream insertId", dispatchIdx, idx)
							}
							seenIDs[gotIDs[idx]] = struct{}{}
						} else if gotIDs[idx] != "" {
							t.Fatalf("dispatch %d record %d unexpected insertId %q when upstreamInsertID=false", dispatchIdx, idx, gotIDs[idx])
						}
					}
				}
				if len(seenTS) != 4 {
					t.Fatalf("distinct log timestamps across 2 dispatches = %d, want 4", len(seenTS))
				}
				if upstreamInsertID && len(seenIDs) != 4 {
					t.Fatalf("distinct upstream insertIds across 2 dispatches = %d, want 4", len(seenIDs))
				}

				afterSrcTS, afterSrcIDs := collectLogIdentities(src[0].logsReq.Logs())
				if !slices.Equal(origTS, afterSrcTS) || !slices.Equal(origIDs, afterSrcIDs) {
					t.Fatalf("shared src log batch was mutated: orig=(%v, %v), after=(%v, %v)", origTS, origIDs, afterSrcTS, afterSrcIDs)
				}
			})
		}
	})

	t.Run("TracesParentChildPreservedAndTemplateUnmutated", func(t *testing.T) {
		td := NewGenerator(GeneratorConfig{}).TracesBatch(3)
		src := []collectorPreparedBatch{{
			tracesReq:   ptraceotlp.NewExportRequestFromTraces(td),
			recordCount: int64(td.SpanCount()),
		}}
		origSpans := collectSpanIdentities(src[0].tracesReq.Traces())
		if len(origSpans) != 3 {
			t.Fatalf("len(origSpans) = %d, want 3", len(origSpans))
		}
		if !origSpans[0].parentSpanID.IsEmpty() {
			t.Fatalf("expected span[0] to be root, got parent %x", origSpans[0].parentSpanID)
		}
		if origSpans[1].parentSpanID != origSpans[0].spanID || origSpans[2].parentSpanID != origSpans[0].spanID {
			t.Fatalf("expected child spans to reference root %x, got %x and %x",
				origSpans[0].spanID, origSpans[1].parentSpanID, origSpans[2].parentSpanID)
		}

		cloned := cloneCollectorPreparedBatch(src[0])
		seenSpanIDs := make(map[pcommon.SpanID]struct{})
		seenStartTS := make(map[pcommon.Timestamp]struct{})

		for dispatchIdx, startSeq := range []uint64{10, 20} {
			stampCollectorPreparedBatchIdentity("traces", cloned, DefaultBaseTime, startSeq, false)
			snaps := collectSpanIdentities(cloned.tracesReq.Traces())
			if len(snaps) != 3 {
				t.Fatalf("dispatch %d span count = %d, want 3", dispatchIdx, len(snaps))
			}
			if !snaps[0].parentSpanID.IsEmpty() {
				t.Fatalf("dispatch %d root span unexpectedly has parent %x", dispatchIdx, snaps[0].parentSpanID)
			}
			if snaps[1].parentSpanID != snaps[0].spanID || snaps[2].parentSpanID != snaps[0].spanID {
				t.Fatalf("dispatch %d parent/child broken: root=%x child1_parent=%x child2_parent=%x",
					dispatchIdx, snaps[0].spanID, snaps[1].parentSpanID, snaps[2].parentSpanID)
			}
			for _, s := range snaps {
				if s.spanID.IsEmpty() {
					t.Fatalf("dispatch %d produced empty spanID", dispatchIdx)
				}
				seenSpanIDs[s.spanID] = struct{}{}
				seenStartTS[s.startTS] = struct{}{}
			}
		}
		if len(seenSpanIDs) != 6 {
			t.Fatalf("distinct span IDs across 2 dispatches = %d, want 6", len(seenSpanIDs))
		}
		if len(seenStartTS) != 6 {
			t.Fatalf("distinct span timestamps across 2 dispatches = %d, want 6", len(seenStartTS))
		}

		afterOrig := collectSpanIdentities(src[0].tracesReq.Traces())
		if !slices.Equal(origSpans, afterOrig) {
			t.Fatalf("shared src trace batch was mutated: orig=%+v after=%+v", origSpans, afterOrig)
		}
	})

	t.Run("MetricsDatapointTimestampsAdvanceAndTemplateUnmutated", func(t *testing.T) {
		md := NewGenerator(GeneratorConfig{}).MetricsBatch(4)
		src := []collectorPreparedBatch{{
			metricsReq:  pmetricotlp.NewExportRequestFromMetrics(md),
			recordCount: int64(md.DataPointCount()),
		}}
		origTS := collectMetricTimestamps(src[0].metricsReq.Metrics())
		if len(origTS) != 4 {
			t.Fatalf("len(origTS) = %d, want 4", len(origTS))
		}

		cloned := cloneCollectorPreparedBatch(src[0])
		seenTS := make(map[pcommon.Timestamp]struct{})
		for dispatchIdx, startSeq := range []uint64{50, 150} {
			stampCollectorPreparedBatchIdentity("metrics", cloned, DefaultBaseTime, startSeq, false)
			gotTS := collectMetricTimestamps(cloned.metricsReq.Metrics())
			if len(gotTS) != 4 {
				t.Fatalf("dispatch %d datapoint count = %d, want 4", dispatchIdx, len(gotTS))
			}
			for _, ts := range gotTS {
				seenTS[ts] = struct{}{}
			}
		}
		if len(seenTS) != 8 {
			t.Fatalf("distinct metric timestamps across 2 dispatches = %d, want 8", len(seenTS))
		}

		afterOrig := collectMetricTimestamps(src[0].metricsReq.Metrics())
		if !slices.Equal(origTS, afterOrig) {
			t.Fatalf("shared src metrics batch was mutated: orig=%v after=%v", origTS, afterOrig)
		}
	})

	t.Run("WorkerPhaseStampsDistinctTimestampsAcrossConcurrentRingReuses", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		captureSrv := &testTimestampCaptureOTLPServer{}
		grpcSrv := grpc.NewServer()
		plogotlp.RegisterGRPCServer(grpcSrv, captureSrv)
		go func() { _ = grpcSrv.Serve(lis) }()
		defer grpcSrv.Stop()

		conn, err := dialCollectorOTLPClient(lis.Addr().String())
		if err != nil {
			t.Fatalf("dialCollectorOTLPClient: %v", err)
		}
		defer func() { _ = conn.Close() }()

		cfg := RunnerConfig{
			Mode:      ModeCollector,
			Signals:   []string{"logs"},
			Workers:   2,
			BatchSize: 1,
		}
		makeBatch, err := newCollectorBatchBuilder(cfg, "logs")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder: %v", err)
		}
		const ringLen = 2
		prebuilt := make([]collectorPreparedBatch, ringLen)
		origTemplateTS := make([][]pcommon.Timestamp, ringLen)
		for i := range ringLen {
			b, bErr := makeBatch(cfg.BatchSize)
			if bErr != nil {
				t.Fatalf("makeBatch[%d]: %v", i, bErr)
			}
			prebuilt[i] = b
			origTemplateTS[i], _ = collectLogIdentities(b.logsReq.Logs())
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var seq atomic.Uint64
		stats := runCollectorWorkerPhaseWithSeq(
			ctx,
			cfg,
			"logs",
			5*time.Second,
			10,
			prebuilt,
			makeBatch,
			ptraceotlp.GRPCClient(nil),
			plogotlp.NewGRPCClient(conn),
			pmetricotlp.GRPCClient(nil),
			nil,
			&seq,
		)
		if stats.firstErr != nil {
			t.Fatalf("runCollectorWorkerPhaseWithSeq unexpected error: %v", stats.firstErr)
		}
		if stats.recordsSubmitted != 10 {
			t.Fatalf("recordsSubmitted = %d, want 10", stats.recordsSubmitted)
		}

		captureSrv.mu.Lock()
		gotTS := slices.Clone(captureSrv.timestamps)
		captureSrv.mu.Unlock()
		if len(gotTS) != 10 {
			t.Fatalf("captured log records = %d, want 10", len(gotTS))
		}
		uniqueTS := make(map[pcommon.Timestamp]struct{}, len(gotTS))
		for _, ts := range gotTS {
			uniqueTS[ts] = struct{}{}
		}
		if len(uniqueTS) != 10 {
			t.Fatalf("distinct log timestamps = %d, want 10 (got %v)", len(uniqueTS), gotTS)
		}
		for i := range ringLen {
			afterTS, _ := collectLogIdentities(prebuilt[i].logsReq.Logs())
			if !slices.Equal(origTemplateTS[i], afterTS) {
				t.Fatalf("prebuilt[%d] template mutated: orig=%v after=%v", i, origTemplateTS[i], afterTS)
			}
		}
	})

	t.Run("PacedPartialBatchStampsDistinctSequentialIdentities", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		captureSrv := &testTimestampCaptureOTLPServer{}
		grpcSrv := grpc.NewServer()
		plogotlp.RegisterGRPCServer(grpcSrv, captureSrv)
		go func() { _ = grpcSrv.Serve(lis) }()
		defer grpcSrv.Stop()

		conn, err := dialCollectorOTLPClient(lis.Addr().String())
		if err != nil {
			t.Fatalf("dialCollectorOTLPClient: %v", err)
		}
		defer func() { _ = conn.Close() }()

		// TargetRate=18 for Duration=400ms yields totalBudget=round(7.2)=7 rows
		// with pacedBatchCap=min(4, max(1, 18/4))=4:
		//   - dispatch 1: full batch of 4 rows (uses prebuilt worker slot)
		//   - dispatch 2: partial final batch of 3 rows (uses makeBatch(3) + partial-batch stamp)
		// Without partial-batch stamping, makeBatch(3) starts at gen.logSeq == 4 (seq 4,5,6),
		// colliding on seq 4 with dispatch 1 (seq 1,2,3,4).
		cfg := RunnerConfig{
			Mode:             ModeCollector,
			WorkloadProfile:  WorkloadProfileAccessLogs,
			UpstreamInsertID: true,
			Signals:          []string{"logs"},
			Workers:          1,
			BatchSize:        4,
			TargetRate:       18,
			Duration:         400 * time.Millisecond,
			PayloadBytes:     128,
			ResourceAttrs:    DefaultAccessLogsResourceAttrs,
		}
		makeBatch, err := newCollectorBatchBuilder(cfg, "logs")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder: %v", err)
		}
		b0, err := makeBatch(cfg.BatchSize)
		if err != nil {
			t.Fatalf("makeBatch(4): %v", err)
		}
		prebuilt := []collectorPreparedBatch{b0}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var seq atomic.Uint64
		stats := runCollectorWorkerPhaseWithSeq(
			ctx,
			cfg,
			"logs",
			cfg.Duration,
			0,
			prebuilt,
			makeBatch,
			ptraceotlp.GRPCClient(nil),
			plogotlp.NewGRPCClient(conn),
			pmetricotlp.GRPCClient(nil),
			nil,
			&seq,
		)
		if stats.firstErr != nil {
			t.Fatalf("runCollectorWorkerPhaseWithSeq unexpected error: %v", stats.firstErr)
		}
		if stats.batchesSucceeded != 2 || stats.recordsSubmitted != 7 {
			t.Fatalf("paced stats = (batches=%d, records=%d), want (2, 7)",
				stats.batchesSucceeded, stats.recordsSubmitted)
		}

		captureSrv.mu.Lock()
		gotTS := slices.Clone(captureSrv.timestamps)
		gotIDs := slices.Clone(captureSrv.insertIDs)
		captureSrv.mu.Unlock()
		if len(gotTS) != 7 || len(gotIDs) != 7 {
			t.Fatalf("captured = (ts=%d, ids=%d), want (7, 7)", len(gotTS), len(gotIDs))
		}
		for i := range 7 {
			wantSeq := uint64(i + 1)
			wantTS := pcommon.NewTimestampFromTime(DefaultBaseTime.Add(time.Duration(wantSeq) * 100 * time.Microsecond))
			wantID := fmt.Sprintf("edge-%016x", wantSeq)
			if gotTS[i] != wantTS {
				t.Fatalf("record[%d] timestamp = %v, want %v (seq=%d)", i, gotTS[i], wantTS, wantSeq)
			}
			if gotIDs[i] != wantID {
				t.Fatalf("record[%d] insertId = %q, want %q", i, gotIDs[i], wantID)
			}
		}
	})
}

func TestRunStrictDrainTimeoutWithFailedShutdownStillEmitsCutoffSignalResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no SIGTERM graceful shutdown")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	origMinDrain := collectorMinDrainTimeout
	collectorMinDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() {
		collectorMinDrainTimeout = origMinDrain
	})

	collectorYAML := `extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-drain-stall-sigterm-err.yaml")
	if err := os.WriteFile(cfgPath, []byte(collectorYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "drain_stall_exit_error_on_sigterm")
	cfgStrict := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            10,
		Duration:             150 * time.Millisecond,
		CallTimeout:          200 * time.Millisecond,
		AllowPartialFailures: false,
		maxBatches:           1,
	}
	if err := cfgStrict.Normalize(); err != nil {
		t.Fatalf("cfgStrict.Normalize: %v", err)
	}

	report, runErr := Run(ctx, cfgStrict)
	if runErr == nil || !strings.Contains(runErr.Error(), "timed out") || !strings.Contains(runErr.Error(), "collector exited with error") || !strings.Contains(runErr.Error(), "post-drain fatal exit") {
		t.Fatalf("Run(cfgStrict) error = %v, want joined drain timeout + collector shutdown error", runErr)
	}
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("report = %+v, want non-nil report with 1 cutoff SignalResult despite failed shutdown", report)
	}

	res := report.Results[0]
	if res.Signal != "logs" {
		t.Fatalf("res.Signal = %q, want %q", res.Signal, "logs")
	}
	if !res.IncompleteDrain {
		t.Fatal("res.IncompleteDrain = false, want true")
	}
	if res.DrainWarning == "" || !strings.Contains(res.DrainWarning, "timed out") {
		t.Fatalf("res.DrainWarning = %q, want non-empty drain timeout warning", res.DrainWarning)
	}
	if res.BatchesFailed < 1 {
		t.Fatalf("res.BatchesFailed = %d, want >= 1", res.BatchesFailed)
	}
	if res.Telemetry.AcknowledgedRows != 5 || res.DeliveredRows != 5 {
		t.Fatalf("cutoff delivery = (acked=%d, delivered=%d), want (5, 5)",
			res.Telemetry.AcknowledgedRows, res.DeliveredRows)
	}
	if res.BytesPerRow != res.AttemptedBytesPerAckedRow {
		t.Fatalf("BytesPerRow (%v) != AttemptedBytesPerAckedRow (%v); post-cutoff shutdown bytes leaked into snapshot",
			res.BytesPerRow, res.AttemptedBytesPerAckedRow)
	}
}

func TestCollectorWarmupReplayCannotHideMissingRecord(t *testing.T) {
	const cfgYAML = `
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
	cfgPath := filepath.Join(t.TempDir(), "warmup-replay-gate.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("WarmupReplayFailsStrictWarmupGate", func(t *testing.T) {
		prevMin := collectorMinDrainTimeout
		collectorMinDrainTimeout = 250 * time.Millisecond
		t.Cleanup(func() { collectorMinDrainTimeout = prevMin })

		bin := configureCollectorHelperEnv(t, "replay_with_drop")
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()

		cfg := RunnerConfig{
			Mode:                 ModeCollector,
			CollectorBin:         bin,
			CollectorConfig:      cfgPath,
			Signals:              []string{"logs"},
			Workers:              1,
			BatchSize:            4,
			WarmupDuration:       250 * time.Millisecond,
			Duration:             200 * time.Millisecond,
			AllowPartialFailures: false,
			SimulateAckDelay:     0,
		}
		if normErr := cfg.Normalize(); normErr != nil {
			t.Fatalf("Normalize: %v", normErr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr == nil {
			t.Fatal("expected warmup error when replay masks dropped warmup record")
		}
		rawCommitted := fakeSrv.AckedRowsForTable("otel_logs")
		uniqueCommitted := fakeSrv.UniqueAckedRowsForTable("otel_logs")
		if uniqueCommitted <= 0 || rawCommitted <= uniqueCommitted {
			t.Fatalf("expected replay to inflate rawCommitted (%d) > uniqueCommitted (%d) > 0", rawCommitted, uniqueCommitted)
		}
		errMsg := hardErr.Error()
		hasUniqueDrainTimeout := strings.Contains(errMsg, "timed out") && strings.Contains(errMsg, "accounted=")
		hasWarmupGateErr := strings.Contains(errMsg, "collector warmup failed gate") && strings.Contains(errMsg, "unique_committed=")
		if !hasUniqueDrainTimeout && !hasWarmupGateErr {
			t.Fatalf("hardErr = %v, want unique-tracked drain timeout ('accounted=') or 'collector warmup failed gate' ('unique_committed=')", hardErr)
		}
	})

	t.Run("WarmupUniqueTrackingPersistsAcrossPhasesWithBoundaryDelta", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			ackDelay time.Duration
		}{
			{name: "faultSimEnabled=false", ackDelay: 0},
			{name: "faultSimEnabled=true", ackDelay: time.Millisecond},
		} {
			t.Run(tc.name, func(t *testing.T) {
				bin := configureCollectorHelperEnv(t, "default")
				fakeSrv, err := bqfake.New()
				if err != nil {
					t.Fatalf("bqfake.New: %v", err)
				}
				defer func() { _ = fakeSrv.Close() }()
				fakeSrv.SetDiscardRows(false)

				cfg := RunnerConfig{
					Mode:             ModeCollector,
					CollectorBin:     bin,
					CollectorConfig:  cfgPath,
					Signals:          []string{"logs"},
					Workers:          1,
					BatchSize:        2,
					maxBatches:       4,
					WarmupDuration:   150 * time.Millisecond,
					Duration:         150 * time.Millisecond,
					SimulateAckDelay: tc.ackDelay,
				}
				if normErr := cfg.Normalize(); normErr != nil {
					t.Fatalf("Normalize: %v", normErr)
				}

				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
				if hardErr != nil || softErr != nil {
					t.Fatalf("unexpected error: hardErr=%v softErr=%v", hardErr, softErr)
				}
				if res.RecordsSubmitted != 8 || res.DeliveredRows != 8 || res.Telemetry.ReplayedRows != 0 {
					t.Fatalf("submitted=%d delivered=%d replayed=%d, want 8/8/0", res.RecordsSubmitted, res.DeliveredRows, res.Telemetry.ReplayedRows)
				}
				if !res.UniqueDeliveryVerified {
					t.Fatal("expected UniqueDeliveryVerified=true")
				}
				totalStored := int64(len(fakeSrv.Rows("otel_logs")))
				if gotUnique := fakeSrv.UniqueAckedRowsForTable("otel_logs"); gotUnique != totalStored || gotUnique <= 8 {
					t.Fatalf("UniqueAckedRowsForTable(otel_logs) = %d (stored=%d), want persisted warmup+steady total > 8", gotUnique, totalStored)
				}
			})
		}

		t.Run("WarmupReplayInSteadyStateFailsStrictDelivery", func(t *testing.T) {
			bin := configureCollectorHelperEnv(t, "replay_warmup_rows")
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()

			cfg := RunnerConfig{
				Mode:             ModeCollector,
				CollectorBin:     bin,
				CollectorConfig:  cfgPath,
				Signals:          []string{"logs"},
				Workers:          1,
				BatchSize:        2,
				maxBatches:       1,
				WarmupDuration:   150 * time.Millisecond,
				Duration:         150 * time.Millisecond,
				CallTimeout:      500 * time.Millisecond,
				SimulateAckDelay: 0,
			}
			if normErr := cfg.Normalize(); normErr != nil {
				t.Fatalf("Normalize: %v", normErr)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
			if hardErr == nil && lossErr == nil {
				t.Fatalf("expected steady-state replay of warmup rows to fail strict delivery (got delivered=%d submitted=%d replayed=%d)",
					res.DeliveredRows, res.RecordsSubmitted, res.Telemetry.ReplayedRows)
			}
			if res.DeliveredRows >= res.RecordsSubmitted && res.RecordsSubmitted > 0 {
				t.Fatalf("DeliveredRows=%d must be < RecordsSubmitted=%d when warmup rows are replayed in steady state",
					res.DeliveredRows, res.RecordsSubmitted)
			}
		})
	})

	t.Run("WarmupEarlySaturationFailsClosed", func(t *testing.T) {
		bin := configureCollectorHelperEnv(t, "default")
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(true)
		fakeSrv.SetMaxUniqueAckedRows(2)

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Workers:         1,
			BatchSize:       4,
			TargetRate:      0,
			WarmupDuration:  5 * time.Second,
			Duration:        1 * time.Second,
		}
		if normErr := cfg.Normalize(); normErr != nil {
			t.Fatalf("Normalize: %v", normErr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		start := time.Now()
		_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		elapsed := time.Since(start)
		if hardErr == nil || !strings.Contains(hardErr.Error(), "saturated") || !strings.Contains(hardErr.Error(), "warmup") || strings.Contains(hardErr.Error(), "simulate-throttle-every") {
			t.Fatalf("hardErr = %v, want warmup saturation error without fault-simulation advice", hardErr)
		}
		if elapsed >= 4*time.Second {
			t.Fatalf("elapsed = %s, want < 4s (early saturation should cancel warmup promptly)", elapsed)
		}
	})
}

func TestCollectorLiveCredentialsPreservationAndValidation(t *testing.T) {
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   false,
	}

	makeLiveCfg := func(t *testing.T, yamlBody string) RunnerConfig {
		t.Helper()
		p := filepath.Join(t.TempDir(), "live-creds.yaml")
		if err := os.WriteFile(p, []byte(yamlBody), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       os.Args[0],
			CollectorConfig:    p,
			ProjectID:          "live-proj",
			DatasetID:          "live_ds",
			Location:           "US",
			Signals:            []string{"logs"},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		return cfg
	}

	t.Run("FileAndQuotaProjectEnvExpanded", func(t *testing.T) {
		credsFile := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(credsFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write creds.json: %v", err)
		}
		t.Setenv("TEST_LIVE_CREDS_FILE", credsFile)
		t.Setenv("TEST_LIVE_QUOTA_PROJECT", "quota-proj-expanded")
		t.Setenv("TEST_LIVE_UNIVERSE_DOMAIN", "apis-tpclp.goog")

		const rawYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      admin_url: https://localhost:443
    credentials:
      file: "${env:TEST_LIVE_CREDS_FILE}"
      quota_project: "${env:TEST_LIVE_QUOTA_PROJECT}"
      universe_domain: "${env:TEST_LIVE_UNIVERSE_DOMAIN}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := makeLiveCfg(t, rawYAML)
		_, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
		}
		if meta.effectiveCredentials.File != credsFile {
			t.Fatalf("effectiveCredentials.File = %q, want %q", meta.effectiveCredentials.File, credsFile)
		}
		if meta.effectiveCredentials.QuotaProject != "quota-proj-expanded" {
			t.Fatalf("effectiveCredentials.QuotaProject = %q, want %q", meta.effectiveCredentials.QuotaProject, "quota-proj-expanded")
		}
		if meta.effectiveCredentials.UniverseDomain != "apis-tpclp.goog" {
			t.Fatalf("effectiveCredentials.UniverseDomain = %q, want %q", meta.effectiveCredentials.UniverseDomain, "apis-tpclp.goog")
		}
		if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr != nil {
			t.Fatalf("validateCollectorPreflightConfig unexpected error: %v", pfErr)
		}
	})

	t.Run("JSONStringWithEnvPreservedNotObjectUnmarshaled", func(t *testing.T) {
		const inlineJSON = `{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com"}`
		t.Setenv("TEST_LIVE_CREDS_JSON", inlineJSON)

		const rawYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    credentials:
      json: "${env:TEST_LIVE_CREDS_JSON}"
      quota_project: qp-json
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := makeLiveCfg(t, rawYAML)
		_, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
		}
		if string(meta.effectiveCredentials.JSON) != os.Getenv("TEST_LIVE_CREDS_JSON") {
			t.Fatalf("effectiveCredentials.JSON = %q, want %q", string(meta.effectiveCredentials.JSON), inlineJSON)
		}
		if meta.effectiveCredentials.QuotaProject != "qp-json" {
			t.Fatalf("effectiveCredentials.QuotaProject = %q, want %q", meta.effectiveCredentials.QuotaProject, "qp-json")
		}
		if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr != nil {
			t.Fatalf("validateCollectorPreflightConfig unexpected error: %v", pfErr)
		}
	})

	t.Run("NumericAndScalarCredentialEnvStringsPreserved", func(t *testing.T) {
		credsFile := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(credsFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write creds.json: %v", err)
		}
		t.Setenv("TEST_LIVE_NUM_QUOTA_PROJ", "123456")
		t.Setenv("TEST_LIVE_CREDS_FILE_NUM_ENV", credsFile)
		t.Setenv("TEST_LIVE_BOOL_QUOTA_FILE", "true")
		t.Setenv("TEST_LIVE_BOOL_SA", "false")
		t.Setenv("TEST_LIVE_NUM_DELEGATE", "7890")
		t.Setenv("TEST_LIVE_NUM_UNIVERSE", "42")

		const rawYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      admin_url: https://localhost:443
    credentials:
      file: "${env:TEST_LIVE_BOOL_QUOTA_FILE}"
      quota_project: "${env:TEST_LIVE_NUM_QUOTA_PROJ}"
      impersonate_service_account: "${env:TEST_LIVE_BOOL_SA}"
      impersonate_delegates:
        - "${env:TEST_LIVE_NUM_DELEGATE}"
      universe_domain: "${env:TEST_LIVE_NUM_UNIVERSE}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := makeLiveCfg(t, rawYAML)
		_, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(numeric quota_project env) unexpected error: %v", err)
		}
		if meta.effectiveCredentials.QuotaProject != "123456" {
			t.Fatalf("effectiveCredentials.QuotaProject = %q, want %q", meta.effectiveCredentials.QuotaProject, "123456")
		}
		if meta.effectiveCredentials.File != "true" {
			t.Fatalf("effectiveCredentials.File = %q, want %q", meta.effectiveCredentials.File, "true")
		}
		if meta.effectiveCredentials.ImpersonateServiceAccount != "false" {
			t.Fatalf("effectiveCredentials.ImpersonateServiceAccount = %q, want %q", meta.effectiveCredentials.ImpersonateServiceAccount, "false")
		}
		if meta.effectiveCredentials.UniverseDomain != "42" {
			t.Fatalf("effectiveCredentials.UniverseDomain = %q, want %q", meta.effectiveCredentials.UniverseDomain, "42")
		}
		if len(meta.effectiveCredentials.ImpersonateDelegates) != 1 || meta.effectiveCredentials.ImpersonateDelegates[0] != "7890" {
			t.Fatalf("effectiveCredentials.ImpersonateDelegates = %v, want [7890]", meta.effectiveCredentials.ImpersonateDelegates)
		}

		// Also verify end-to-end validateCollectorPreflightConfig passes with numeric quota_project.
		const livePreflightYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    endpoint:
      admin_url: https://localhost:443
    credentials:
      file: "${env:TEST_LIVE_CREDS_FILE_NUM_ENV}"
      quota_project: "${env:TEST_LIVE_NUM_QUOTA_PROJ}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		liveCfg := makeLiveCfg(t, livePreflightYAML)
		if pfErr := validateCollectorPreflightConfig(liveCfg, "logs"); pfErr != nil {
			t.Fatalf("validateCollectorPreflightConfig(numeric quota_project) unexpected error: %v", pfErr)
		}
	})

	t.Run("ImpersonateServiceAccountAndDelegatesPreserved", func(t *testing.T) {
		const targetSA = "target-writer@live-proj.iam.gserviceaccount.com"
		const delegateSA = "hop-one@live-proj.iam.gserviceaccount.com"
		t.Setenv("TEST_LIVE_IMPERSONATE_SA", targetSA)
		t.Setenv("TEST_LIVE_IMPERSONATE_DELEGATE", delegateSA)

		const rawYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    credentials:
      impersonate_service_account: "${env:TEST_LIVE_IMPERSONATE_SA}"
      impersonate_delegates:
        - "${env:TEST_LIVE_IMPERSONATE_DELEGATE}"
      quota_project: qp-imp
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := makeLiveCfg(t, rawYAML)
		_, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
		}
		if meta.effectiveCredentials.ImpersonateServiceAccount != targetSA {
			t.Fatalf("ImpersonateServiceAccount = %q, want %q", meta.effectiveCredentials.ImpersonateServiceAccount, targetSA)
		}
		if !slices.Equal(meta.effectiveCredentials.ImpersonateDelegates, []string{delegateSA}) {
			t.Fatalf("ImpersonateDelegates = %v, want [%q]", meta.effectiveCredentials.ImpersonateDelegates, delegateSA)
		}
		if meta.effectiveCredentials.QuotaProject != "qp-imp" {
			t.Fatalf("QuotaProject = %q, want %q", meta.effectiveCredentials.QuotaProject, "qp-imp")
		}
		if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr != nil {
			t.Fatalf("validateCollectorPreflightConfig unexpected error: %v", pfErr)
		}
	})

	t.Run("MutuallyExclusiveFileAndJSONFailsClosed", func(t *testing.T) {
		credsFile := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(credsFile, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write creds.json: %v", err)
		}
		rawYAML := fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    credentials:
      file: %q
      json: '{"type":"service_account"}'
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, credsFile)
		cfg := makeLiveCfg(t, rawYAML)
		if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr == nil || !strings.Contains(pfErr.Error(), "credentials.file and credentials.json are mutually exclusive") {
			t.Fatalf("validateCollectorPreflightConfig err = %v, want mutually exclusive credentials error", pfErr)
		}
	})

	t.Run("DelegatesWithoutImpersonationFailsClosed", func(t *testing.T) {
		const rawYAML = `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: live_ds
    location: US
    credentials:
      impersonate_delegates:
        - hop@live-proj.iam.gserviceaccount.com
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := makeLiveCfg(t, rawYAML)
		if pfErr := validateCollectorPreflightConfig(cfg, "logs"); pfErr == nil || !strings.Contains(pfErr.Error(), "credentials.impersonate_delegates requires credentials.impersonate_service_account") {
			t.Fatalf("validateCollectorPreflightConfig err = %v, want delegates-without-impersonation error", pfErr)
		}
	})
}

func TestCollectorRejectsUndefinedReceiverExtensionAndProcessorIDs(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantSubstrs []string
	}{
		{
			name: "undefined_processor_missing_section",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch/missing]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"processors section is missing", "batch/missing"},
		},
		{
			name: "undefined_processor_existing_section",
			yaml: `
receivers:
  otlp: {}
processors:
  batch: {}
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/missing]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"undefined processor", "attributes/missing", "batch"},
		},
		{
			name: "undefined_extension_missing_section",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  extensions: [health_check/missing]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"extensions section is missing", "health_check/missing"},
		},
		{
			name: "undefined_extension_existing_section",
			yaml: `
extensions:
  health_check: {}
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  extensions: [file_storage/missing]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"undefined extension", "file_storage/missing", "health_check"},
		},
		{
			name: "empty_receivers_on_active_pipeline",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: []
      exporters: [bigquery]
`,
			wantSubstrs: []string{"must configure at least 1 otlp receiver"},
		},
		{
			name: "undefined_receiver_missing_section",
			yaml: `
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp/missing]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"receivers section is missing", "otlp/missing"},
		},
		{
			name: "undefined_receiver_existing_section",
			yaml: `
receivers:
  otlp: {}
exporters:
  bigquery: {}
service:
  pipelines:
    logs:
      receivers: [otlp/missing]
      exporters: [bigquery]
`,
			wantSubstrs: []string{"undefined receiver", "otlp/missing", "otlp"},
		},
		{
			name: "positive_empty_yaml_bodies_succeed",
			yaml: `
extensions:
  health_check:
receivers:
  otlp:
processors:
  batch:
exporters:
  bigquery:
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`,
			wantSubstrs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "preflight.yaml")
			if err := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: false,
				CollectorBin:       os.Args[0],
				CollectorConfig:    cfgPath,
				Signals:            []string{"logs"},
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			gotErr := validateCollectorPreflightConfig(cfg, "logs")
			if len(tc.wantSubstrs) == 0 {
				if gotErr != nil {
					t.Fatalf("validateCollectorPreflightConfig unexpected error: %v", gotErr)
				}
				return
			}
			if gotErr == nil {
				t.Fatalf("validateCollectorPreflightConfig = nil, want error containing %v", tc.wantSubstrs)
			}
			for _, sub := range tc.wantSubstrs {
				if !strings.Contains(gotErr.Error(), sub) {
					t.Fatalf("validateCollectorPreflightConfig error = %q, missing substring %q", gotErr.Error(), sub)
				}
			}
		})
	}
}

type testLargeOTLPServer struct {
	plogotlp.UnimplementedGRPCServer
	gotRecords   atomic.Int64
	gotBodyBytes atomic.Int64
}

func (s *testLargeOTLPServer) Export(_ context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	rls := req.Logs().ResourceLogs()
	for i := 0; i < rls.Len(); i++ {
		sls := rls.At(i).ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			lrs := sls.At(j).LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				s.gotRecords.Add(1)
				s.gotBodyBytes.Add(int64(len(lrs.At(k).Body().AsString())))
			}
		}
	}
	return plogotlp.NewExportResponse(), nil
}

func TestCollectorOTLPClientNotCappedAt32MiB(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	srv := &testLargeOTLPServer{}
	grpcSrv := grpc.NewServer(grpc.MaxRecvMsgSize(64 * 1024 * 1024))
	plogotlp.RegisterGRPCServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(lis) }()
	defer grpcSrv.Stop()

	conn, err := dialCollectorOTLPClient(lis.Addr().String())
	if err != nil {
		t.Fatalf("dialCollectorOTLPClient: %v", err)
	}
	defer func() { _ = conn.Close() }()

	const bodyBytes = 34 * 1024 * 1024
	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr(strings.Repeat("x", bodyBytes))

	req := plogotlp.NewExportRequestFromLogs(ld)
	raw, err := req.MarshalProto()
	if err != nil {
		t.Fatalf("req.MarshalProto: %v", err)
	}
	if len(raw) <= 32*1024*1024 {
		t.Fatalf("marshaled OTLP request bytes = %d, want > 33554432", len(raw))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := plogotlp.NewGRPCClient(conn).Export(ctx, req); err != nil {
		t.Fatalf("Export(>32MiB OTLP payload) unexpected error: %v", err)
	}
	if got := srv.gotRecords.Load(); got != 1 {
		t.Fatalf("srv.gotRecords = %d, want 1", got)
	}
	if got := srv.gotBodyBytes.Load(); got != bodyBytes {
		t.Fatalf("srv.gotBodyBytes = %d, want %d", got, bodyBytes)
	}
}

func TestCollectorCredentialsValidationRedactsSecretsAndRecursiveEnv(t *testing.T) {
	t.Setenv("TEST_CRED_CYCLE_A", "${env:TEST_CRED_CYCLE_B}_SECRET_CYCLE_MARKER_995")
	t.Setenv("TEST_CRED_CYCLE_B", "${env:TEST_CRED_CYCLE_A}")
	t.Setenv("TEST_CRED_BAD_MAP", "{tok: SECRET_MAP_MARKER_997}")

	redactedCases := []struct {
		name             string
		credentialsBlock string
		secretMarkers    []string
		wantSubstrs      []string
	}{
		{
			name:             "scalar_credentials_value_redacted",
			credentialsBlock: `    credentials: "SECRET_SCALAR_CRED_MARKER_991"`,
			secretMarkers:    []string{"SECRET_SCALAR_CRED_MARKER_991"},
			wantSubstrs:      []string{"exporters.bigquery.credentials", "got string"},
		},
		{
			name: "nested_env_in_credentials_json_redacted",
			credentialsBlock: `    credentials:
      json: '{"private_key":"SECRET_JSON_KEY_MARKER_992","tok":"${env:A${env:B}}"}'`,
			secretMarkers: []string{"SECRET_JSON_KEY_MARKER_992"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.json", "nested ${ reference"},
		},
		{
			name: "unclosed_env_with_json_brace_in_credentials_json_redacted",
			credentialsBlock: `    credentials:
      json: '{"private_key":"SECRET_UNCLOSED_KEY_MARKER_992B","tok":"${env:UNCLOSED"}'`,
			secretMarkers: []string{"SECRET_UNCLOSED_KEY_MARKER_992B", "UNCLOSED"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.json", "invalid environment variable name"},
		},
		{
			name: "true_unclosed_env_in_credentials_redacted",
			credentialsBlock: `    credentials:
      json: "SECRET_UNCLOSED_RAW_MARKER_992C_${env:UNCLOSED_TOKEN"`,
			secretMarkers: []string{"SECRET_UNCLOSED_RAW_MARKER_992C", "UNCLOSED_TOKEN"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.json", "unclosed ${...} reference"},
		},
		{
			name: "missing_env_scheme_default_in_credentials_redacted",
			credentialsBlock: `    credentials:
      file: "${FOO:-SECRET_DEFAULT_MARKER_993}"`,
			secretMarkers: []string{"SECRET_DEFAULT_MARKER_993"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.file", "default syntax :- requires explicit env: scheme"},
		},
		{
			name: "unsupported_provider_in_credentials_redacted",
			credentialsBlock: `    credentials:
      quota_project: "${SECRET_SCHEME_MARKER_994:SECRET_REST_994}"`,
			secretMarkers: []string{"SECRET_SCHEME_MARKER_994", "SECRET_REST_994"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.quota_project", "unsupported collector config provider"},
		},
		{
			name: "recursive_cycle_in_credentials_redacted",
			credentialsBlock: `    credentials:
      quota_project: "${env:TEST_CRED_CYCLE_A}"`,
			secretMarkers: []string{"SECRET_CYCLE_MARKER_995", "TEST_CRED_CYCLE_A", "TEST_CRED_CYCLE_B"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.quota_project", "too many recursive expansions"},
		},
		{
			name: "non_string_yaml_decode_in_credentials_redacted",
			credentialsBlock: `    credentials:
      file:
        - "SECRET_SLICE_MARKER_996"`,
			secretMarkers: []string{"SECRET_SLICE_MARKER_996"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.file", "must be a string"},
		},
		{
			name: "non_slice_yaml_decode_in_delegates_redacted",
			credentialsBlock: `    credentials:
      impersonate_delegates: "${env:TEST_CRED_BAD_MAP}"`,
			secretMarkers: []string{"SECRET_MAP_MARKER_997"},
			wantSubstrs:   []string{"exporters.bigquery.credentials.impersonate_delegates", "expected YAML sequence"},
		},
	}

	for _, tc := range redactedCases {
		t.Run(tc.name, func(t *testing.T) {
			yamlDoc := "receivers:\n  otlp:\n    protocols:\n      grpc:\n        endpoint: 127.0.0.1:4317\nexporters:\n  bigquery:\n    project: live-proj\n    dataset: live_ds\n" +
				tc.credentialsBlock + "\nservice:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: [bigquery]\n"
			cfgPath := filepath.Join(t.TempDir(), "cred-redact.yaml")
			if err := os.WriteFile(cfgPath, []byte(yamlDoc), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				CollectorBin:       os.Args[0],
				CollectorConfig:    cfgPath,
				ProjectID:          "live-proj",
				DatasetID:          "live_ds",
				Signals:            []string{"logs"},
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			gotErr := validateCollectorPreflightConfig(cfg, "logs")
			if gotErr == nil {
				t.Fatalf("expected non-nil error for %s", tc.name)
			}
			msg := gotErr.Error()
			for _, secret := range tc.secretMarkers {
				if strings.Contains(msg, secret) {
					t.Fatalf("error leaked secret marker %q: %s", secret, msg)
				}
			}
			for _, want := range tc.wantSubstrs {
				if !strings.Contains(msg, want) {
					t.Fatalf("error %q missing expected diagnostic %q", msg, want)
				}
			}
		})
	}

	t.Run("RecursiveEnvExpansionAndDollarEscaping", func(t *testing.T) {
		envMap := map[string]string{
			"OUTER":   "${env:MID}",
			"MID":     "${env:LEAF}",
			"LEAF":    "otel_logs_chained",
			"CYCLE_A": "${env:CYCLE_B}",
			"CYCLE_B": "${env:CYCLE_A}",
			"ESC_VAL": "$$literal",
		}
		for i := range 18 {
			envMap[fmt.Sprintf("DEPTH_%d", i)] = fmt.Sprintf("${env:DEPTH_%d}", i+1)
		}
		envMap["DEPTH_18"] = "too_deep"
		lookup := func(k string) (string, bool) {
			v, ok := envMap[k]
			return v, ok
		}

		got, err := resolveCollectorEnvStringWithLookup("${env:OUTER}", lookup)
		if err != nil || got != "otel_logs_chained" {
			t.Fatalf("chained expansion = (%q, %v), want (\"otel_logs_chained\", nil)", got, err)
		}

		gotDefault, err := resolveCollectorEnvStringWithLookup("${env:UNSET_VAR:-fallback_$$_val}", lookup)
		if err != nil || gotDefault != "fallback_$_val" {
			t.Fatalf("default escaped = (%q, %v), want (\"fallback_$_val\", nil)", gotDefault, err)
		}

		// Direct cycle fails with "too many recursive expansions".
		if _, err := resolveCollectorEnvStringWithLookup("${env:CYCLE_A}", lookup); err == nil || !strings.Contains(err.Error(), "too many recursive expansions") {
			t.Fatalf("cycle error = %v, want 'too many recursive expansions'", err)
		}
		// Depth > 16 chain also fails with "too many recursive expansions".
		if _, err := resolveCollectorEnvStringWithLookup("${env:DEPTH_0}", lookup); err == nil || !strings.Contains(err.Error(), "too many recursive expansions") {
			t.Fatalf("deep chain error = %v, want 'too many recursive expansions'", err)
		}

		// Escaped $$ emits literal $ and is NOT re-expanded in a subsequent pass.
		gotEsc, err := resolveCollectorEnvStringWithLookup("$${env:LEAF}", lookup)
		if err != nil || gotEsc != "${env:LEAF}" {
			t.Fatalf("escaped $$ = (%q, %v), want (\"${env:LEAF}\", nil)", gotEsc, err)
		}
		gotEscConcat, err := resolveCollectorEnvStringWithLookup("${env:ESC_VAL}{env:LEAF}", lookup)
		if err != nil || gotEscConcat != "$literal{env:LEAF}" {
			t.Fatalf("escaped env concat = (%q, %v), want (\"$literal{env:LEAF}\", nil)", gotEscConcat, err)
		}
	})
}

func TestCollectorStrictModeDropPlusReplayFailsLossless(t *testing.T) {
	prevDrain := collectorMinDrainTimeout
	collectorMinDrainTimeout = 250 * time.Millisecond
	defer func() { collectorMinDrainTimeout = prevDrain }()

	cfgPath := filepath.Join(t.TempDir(), "collector-b2.yaml")
	rawYAML := `
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
    project: bench-project
    dataset: otel_bench
    location: US
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

	bin := configureCollectorHelperEnv(t, "replay_one_with_drop")
	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            4,
		maxBatches:           1,
		Duration:             500 * time.Millisecond,
		CallTimeout:          250 * time.Millisecond,
		UpstreamInsertID:     true,
		AllowPartialFailures: false,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, runErr := Run(ctx, cfg)
	if runErr == nil {
		t.Fatal("Run(strict drop+replay with faultSim=false) = nil, want failure")
	}
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("expected 1 cutoff SignalResult in report, got %+v", report)
	}
	res := report.Results[0]
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 3 || res.Telemetry.ReplayedRows != 1 {
		t.Fatalf("verified=%v delivered=%d replayed=%d, want true/3/1",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.Telemetry.ReplayedRows)
	}
}

func TestCollectorMultiSignalPrebuiltCrossJoinParity(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-multisig.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 16
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	const (
		workers    = 2
		batchSize  = 4
		maxBatches = 2
		wantSteady = batchSize * maxBatches
	)
	for _, sig := range []string{"traces", "logs", "metrics"} {
		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  cfgPath,
			Signals:          []string{sig},
			Workers:          workers,
			BatchSize:        batchSize,
			maxBatches:       maxBatches,
			Duration:         2 * time.Second,
			WarmupDuration:   80 * time.Millisecond,
			UniquePayloads:   false,
			UpstreamInsertID: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize(%s): %v", sig, err)
		}
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, sig, fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(%s) hard=%v soft=%v", sig, hardErr, softErr)
		}
		if res.DeliveredRows != wantSteady || !res.UniqueDeliveryVerified {
			t.Fatalf("%s DeliveredRows=%d UniqueDeliveryVerified=%v, want %d/true",
				sig, res.DeliveredRows, res.UniqueDeliveryVerified, wantSteady)
		}
	}

	warmupCutoffNano := DefaultBaseTime.Add(time.Duration(uint64(warmupTreeBaseOffset)*4) * 100 * time.Microsecond).UnixNano()
	type joinKey struct {
		traceID     string
		spanID      string
		serviceName string
	}
	spans := make(map[joinKey]struct{}, wantSteady)
	for _, r := range fakeSrv.Rows("otel_spans") {
		if stNano, _ := r["start_time_unix_nano"].(int64); stNano >= warmupCutoffNano {
			continue
		}
		tid, _ := r["trace_id"].(string)
		sid, _ := r["span_id"].(string)
		svc, _ := r["service_name"].(string)
		spans[joinKey{traceID: tid, spanID: sid, serviceName: svc}] = struct{}{}
	}
	if len(spans) != wantSteady {
		t.Fatalf("distinct steady-state collector spans = %d, want %d", len(spans), wantSteady)
	}

	joinedLogs := 0
	for _, r := range fakeSrv.Rows("otel_logs") {
		if tNano, _ := r["time_unix_nano"].(int64); tNano >= warmupCutoffNano {
			continue
		}
		tid, _ := r["trace_id"].(string)
		sid, _ := r["span_id"].(string)
		svc, _ := r["service_name"].(string)
		if _, ok := spans[joinKey{traceID: tid, spanID: sid, serviceName: svc}]; !ok {
			t.Fatalf("collector log (%s, %s, %s) failed to join steady-state spans", tid, sid, svc)
		}
		joinedLogs++
	}
	if joinedLogs != wantSteady {
		t.Fatalf("joined collector logs = %d/%d, want 100%%", joinedLogs, wantSteady)
	}

	joinedExemplars := 0
	for _, r := range fakeSrv.Rows("otel_metrics") {
		if tNano, _ := r["time_unix_nano"].(int64); tNano >= warmupCutoffNano {
			continue
		}
		svc, _ := r["service_name"].(string)
		exs, _ := r["exemplars"].([]map[string]any)
		if len(exs) != 1 {
			t.Fatalf("collector metric exemplars len = %d, want 1", len(exs))
		}
		tid, _ := exs[0]["trace_id"].(string)
		sid, _ := exs[0]["span_id"].(string)
		if _, ok := spans[joinKey{traceID: tid, spanID: sid, serviceName: svc}]; !ok {
			t.Fatalf("collector metric exemplar (%s, %s, %s) failed to join steady-state spans", tid, sid, svc)
		}
		joinedExemplars++
	}
	if joinedExemplars != wantSteady {
		t.Fatalf("joined collector metric exemplars = %d/%d, want 100%%", joinedExemplars, wantSteady)
	}
}

func TestCollectorPartialFailuresStillFailWhenThrottleNeverFired(t *testing.T) {
	prevDrain := collectorMinDrainTimeout
	collectorMinDrainTimeout = 250 * time.Millisecond
	defer func() { collectorMinDrainTimeout = prevDrain }()

	cfgPath := filepath.Join(t.TempDir(), "collector-b4.yaml")
	rawYAML := `
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
    project: bench-project
    dataset: otel_bench
    location: US
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

	bin := configureCollectorHelperEnv(t, "drain_stall")
	cfg := RunnerConfig{
		Mode:                  ModeCollector,
		CollectorBin:          bin,
		CollectorConfig:       cfgPath,
		Signals:               []string{"logs"},
		Workers:               1,
		BatchSize:             4,
		maxBatches:            1,
		Duration:              500 * time.Millisecond,
		CallTimeout:           250 * time.Millisecond,
		SimulateThrottleEvery: 100,
		AllowPartialFailures:  true,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, runErr := Run(ctx, cfg)
	if runErr == nil || !strings.Contains(runErr.Error(), "-simulate-throttle-every=100 never fired") {
		t.Fatalf("Run(AllowPartialFailures=true, 0 throttles) = %v, want '-simulate-throttle-every=100 never fired'", runErr)
	}
}

func TestCollectorCustomLoopbackEndpointWithoutAdminURLSkipsPublicREST(t *testing.T) {
	var restCalls atomic.Int64
	prevHook := newBigQueryClientHook
	newBigQueryClientHook = func(projectID string) error {
		restCalls.Add(1)
		return fmt.Errorf("unexpected public BigQuery REST client dial for project %q", projectID)
	}
	defer func() { newBigQueryClientHook = prevHook }()

	cfgPath := filepath.Join(t.TempDir(), "collector-custom-ep.yaml")
	rawYAML := `
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
    project: live-emulator-proj
    dataset: live_emulator_ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      insecure: true
      without_authentication: true
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

	bin := configureCollectorHelperEnv(t, "live_ok")
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		ProjectID:          "live-emulator-proj",
		DatasetID:          "live_emulator_ds",
		Location:           "US",
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           400 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run(custom loopback endpoint without admin_url) unexpected error: %v", err)
	}
	if got := restCalls.Load(); got != 0 {
		t.Fatalf("public REST client calls = %d, want 0", got)
	}
	if len(report.Results) != 1 || report.Results[0].ByteLayers == nil || !strings.Contains(report.Results[0].ByteLayers.BQStorageQueryNote, "without endpoint.admin_url") {
		t.Fatalf("expected BQStorageQueryNote explaining skipped lookup, got %+v", report.Results)
	}

	// EphemeralDataset=true with without_authentication=true fails closed upfront before dialing REST.
	ephNoAuthCfg := cfg
	ephNoAuthCfg.DatasetID = ""
	ephNoAuthCfg.EphemeralDataset = true
	if _, ephErr := Run(ctx, ephNoAuthCfg); ephErr == nil {
		t.Fatal("Run(EphemeralDataset with without_authentication=true) = nil, want error")
	}
	if got := restCalls.Load(); got != 0 {
		t.Fatalf("public REST client calls after no-auth ephemeral rejection = %d, want 0", got)
	}

	// EphemeralDataset=true with custom writer endpoint.url (without_authentication=false) and empty
	// endpoint.admin_url must fail closed requiring endpoint.admin_url before dialing public REST.
	customAuthYAML := strings.ReplaceAll(rawYAML, "without_authentication: true", "without_authentication: false")
	customAuthPath := filepath.Join(t.TempDir(), "collector-custom-ep-auth.yaml")
	if err := os.WriteFile(customAuthPath, []byte(customAuthYAML), 0o600); err != nil {
		t.Fatalf("write auth config: %v", err)
	}
	ephCustomURLCfg := cfg
	ephCustomURLCfg.CollectorConfig = customAuthPath
	ephCustomURLCfg.DatasetID = ""
	ephCustomURLCfg.EphemeralDataset = true
	if _, ephErr := Run(ctx, ephCustomURLCfg); ephErr == nil || !strings.Contains(ephErr.Error(), "endpoint.admin_url") {
		t.Fatalf("Run(EphemeralDataset with custom endpoint.url and empty admin_url) = %v, want error requiring endpoint.admin_url", ephErr)
	}
	if got := restCalls.Load(); got != 0 {
		t.Fatalf("public REST client calls after custom-url ephemeral rejection = %d, want 0", got)
	}
}

func TestCollectorLiveMissingAppendBytesReportsUnavailable(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector-missing-bytes.yaml")
	rawYAML := `
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
    project: live-emulator-proj
    dataset: live_emulator_ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      insecure: true
      without_authentication: true
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

	bin := configureCollectorHelperEnv(t, "live_missing_append_bytes")
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		ProjectID:          "live-emulator-proj",
		DatasetID:          "live_emulator_ds",
		Location:           "US",
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           400 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run(live_missing_append_bytes) unexpected error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("len(report.Results) = %d, want 1", len(report.Results))
	}
	res := report.Results[0]
	if !res.BytesPerRowUnavailable || res.BytesPerRow != 0 || res.AttemptedBytesPerAckedRow != 0 || res.WireMBPerSec != 0 {
		t.Fatalf("expected BytesPerRowUnavailable=true and zero byte rates, got unavail=%v bpr=%v attemptedBpr=%v wire=%v",
			res.BytesPerRowUnavailable, res.BytesPerRow, res.AttemptedBytesPerAckedRow, res.WireMBPerSec)
	}
	md := FormatMarkdown(report)
	if strings.Count(md, "| unavailable | unavailable |") < 1 {
		t.Fatalf("FormatMarkdown did not render unavailable for Encoded-Row MiB/s and Bytes/Row:\n%s", md)
	}
}

func TestCollectorUniquePayloadsWarmupDisjointFromSteadyStateAndZeroTier2Hashes(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-tier1-unique-warmup.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 16
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	warmupCutoffNano := DefaultBaseTime.Add(time.Duration(uint64(warmupTreeBaseOffset)*4) * 100 * time.Microsecond).UnixNano()

	type sigSpec struct {
		name             string
		signal           string
		table            string
		profile          string
		upstreamInsertID bool
	}
	for _, sp := range []sigSpec{
		{name: "traces", signal: "traces", table: "otel_spans"},
		{name: "logs", signal: "logs", table: "otel_logs"},
		{name: "logs_tracestep_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileGenAIMixed, upstreamInsertID: true},
		{name: "logs_access_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileAccessLogs, upstreamInsertID: true},
		{name: "metrics", signal: "metrics", table: "otel_metrics"},
	} {
		t.Run(sp.name, func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(false)

			const (
				batchSize  = 4
				maxBatches = 2
				wantSteady = batchSize * maxBatches
			)
			cfg := RunnerConfig{
				Mode:             ModeCollector,
				CollectorBin:     collectorBin,
				CollectorConfig:  cfgPath,
				Signals:          []string{sp.signal},
				WorkloadProfile:  sp.profile,
				Workers:          2,
				BatchSize:        batchSize,
				maxBatches:       maxBatches,
				Duration:         2 * time.Second,
				WarmupDuration:   80 * time.Millisecond,
				UniquePayloads:   true,
				UpstreamInsertID: sp.upstreamInsertID,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize(%s): %v", sp.signal, err)
			}

			res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, sp.signal, fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runCollectorSingleSignalWithFake(%s) hard=%v soft=%v", sp.signal, hardErr, softErr)
			}
			if !res.UniqueDeliveryVerified || res.DeliveredRows != wantSteady {
				t.Fatalf("%s UniqueDeliveryVerified=%v DeliveredRows=%d, want true/%d",
					sp.signal, res.UniqueDeliveryVerified, res.DeliveredRows, wantSteady)
			}

			tier1Chunks, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable(sp.table)
			if tier1Chunks < 1 || tier2Hashes != 0 {
				t.Fatalf("%s Tier counts = (tier1Chunks=%d, tier2Hashes=%d), want (>0, 0)",
					sp.signal, tier1Chunks, tier2Hashes)
			}

			var warmupCount, steadyCount int
			for _, r := range fakeSrv.Rows(sp.table) {
				var tsNano int64
				if sp.signal == "traces" {
					tsNano, _ = r["start_time_unix_nano"].(int64)
				} else {
					tsNano, _ = r["time_unix_nano"].(int64)
				}
				if tsNano >= warmupCutoffNano {
					warmupCount++
				} else {
					steadyCount++
				}
			}
			if warmupCount == 0 {
				t.Fatalf("%s expected warmup rows >= %d, got 0", sp.signal, warmupCutoffNano)
			}
			if steadyCount != wantSteady {
				t.Fatalf("%s steady rows (< warmupCutoffNano) = %d, want %d (warmup collided with steady range)",
					sp.signal, steadyCount, wantSteady)
			}
		})
	}
}

func TestCollectorWarmupRejectsExtraDistinctRow(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "collector-warmup-extra.yaml")
	rawYAML := `
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
    project: bench-project
    dataset: otel_bench
    location: US
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

	bin := configureCollectorHelperEnv(t, "extra_distinct_row")
	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            4,
		WarmupDuration:       250 * time.Millisecond,
		Duration:             200 * time.Millisecond,
		AllowPartialFailures: false,
	}
	if normErr := cfg.Normalize(); normErr != nil {
		t.Fatalf("Normalize: %v", normErr)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "collector warmup failed gate") {
		t.Fatalf("runCollectorSingleSignalWithFake(extra_distinct_row in warmup) hardErr = %v, want collector warmup failed gate error", hardErr)
	}
}

func TestCollectorStrictDrainTimeoutAndMissedThrottlePreservesCutoffReport(t *testing.T) {
	prevMin := collectorMinDrainTimeout
	collectorMinDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { collectorMinDrainTimeout = prevMin })

	cfgPath := filepath.Join(t.TempDir(), "collector-cutoff-throttle.yaml")
	rawYAML := `
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
    project: bench-project
    dataset: otel_bench
    location: US
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

	bin := configureCollectorHelperEnv(t, "drain_stall")
	cfg := RunnerConfig{
		Mode:                  ModeCollector,
		CollectorBin:          bin,
		CollectorConfig:       cfgPath,
		Signals:               []string{"logs"},
		Workers:               1,
		BatchSize:             4,
		maxBatches:            1,
		Duration:              500 * time.Millisecond,
		CallTimeout:           250 * time.Millisecond,
		SimulateThrottleEvery: 100,
		AllowPartialFailures:  false,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, runErr := Run(ctx, cfg)
	if runErr == nil {
		t.Fatal("Run(drain_stall + missed throttle) unexpected nil error")
	}
	errMsg := runErr.Error()
	if !strings.Contains(errMsg, "timed out") {
		t.Fatalf("Run error = %v, want drain timeout cause preserved", runErr)
	}
	if !strings.Contains(errMsg, "-simulate-throttle-every=100 never fired") {
		t.Fatalf("Run error = %v, want missed-throttle cause preserved", runErr)
	}
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("expected cutoff report with 1 SignalResult, got report=%+v", report)
	}
	res := report.Results[0]
	if !res.IncompleteDrain {
		t.Fatalf("expected cutoff res.IncompleteDrain=true, got false (%+v)", res)
	}
	if res.DeliveredRows <= 0 {
		t.Fatalf("expected partial DeliveredRows > 0 in cutoff result, got %d", res.DeliveredRows)
	}
}

func TestCollectorRewritePreservesEscapedHealthCheckPathAndRealBinaryStarts(t *testing.T) {
	const rawYAML = `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    path: /health/$$$$/ready
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfg := RunnerConfig{
		Mode:      ModeCollector,
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
	rewritten, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", ep)
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
	}
	if meta.healthCheckPath != "/health/$$/ready" {
		t.Fatalf("meta.healthCheckPath = %q, want %q", meta.healthCheckPath, "/health/$$/ready")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rewritten, &doc); err != nil {
		t.Fatalf("yaml.Unmarshal(rewritten): %v", err)
	}
	exts, _ := doc["extensions"].(map[string]any)
	hc, _ := exts["health_check"].(map[string]any)
	if gotPath, _ := hc["path"].(string); gotPath != "/health/$$$$/ready" {
		t.Fatalf("rewritten extensions.health_check.path = %q, want unexpanded %q so child Collector expands $$ once", gotPath, "/health/$$$$/ready")
	}

	collectorBin := findCollectorDistBinary(t)
	cfgPath := filepath.Join(t.TempDir(), "collector-escaped-health.yaml")
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	runCfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        2 * time.Second,
	}
	if err := runCfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fakeSrv := bqfake.NewServer(t)
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, runCfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake(escaped health_check) hard=%v soft=%v", hardErr, softErr)
	}
	if res.DeliveredRows != 4 {
		t.Fatalf("DeliveredRows = %d, want 4", res.DeliveredRows)
	}
}

func TestCollectorPacedTracesPreserveParentLinksAndBatchSizeOneCoversAllFrameworks(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-traces.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 16
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	assertTraceGraph := func(t *testing.T, rows []map[string]any, wantCount int, wantFrameworks int) {
		t.Helper()
		if len(rows) != wantCount {
			t.Fatalf("len(otel_spans) = %d, want %d", len(rows), wantCount)
		}
		services := make(map[string]struct{})
		spansByTrace := make(map[string]map[string]struct{})
		type spanRef struct {
			traceID string
			spanID  string
			parent  string
		}
		var refs []spanRef
		for _, r := range rows {
			svc, _ := r["service_name"].(string)
			services[svc] = struct{}{}
			tid, _ := r["trace_id"].(string)
			sid, _ := r["span_id"].(string)
			pid, _ := r["parent_span_id"].(string)
			if spansByTrace[tid] == nil {
				spansByTrace[tid] = make(map[string]struct{})
			}
			spansByTrace[tid][sid] = struct{}{}
			refs = append(refs, spanRef{traceID: tid, spanID: sid, parent: pid})
		}
		if wantFrameworks > 0 && len(services) != wantFrameworks {
			t.Fatalf("distinct frameworks = %d (%v), want %d", len(services), services, wantFrameworks)
		}
		var missingParents int
		for _, ref := range refs {
			if ref.parent == "" {
				continue
			}
			if _, ok := spansByTrace[ref.traceID][ref.parent]; !ok {
				missingParents++
			}
		}
		if missingParents > 0 {
			t.Fatalf("found %d spans pointing to absent parent_span_id across %d traces", missingParents, len(spansByTrace))
		}
	}

	t.Run("PacedTracesSingleWorkerBatchFourRateFour", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"traces"},
			Workers:         1,
			BatchSize:       4,
			TargetRate:      4,
			Duration:        1 * time.Second,
			WarmupDuration:  250 * time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(paced traces) hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 4 || res.RecordsSubmitted != 4 {
			t.Fatalf("DeliveredRows=%d RecordsSubmitted=%d, want 4/4", res.DeliveredRows, res.RecordsSubmitted)
		}
		warmupCutoffNano := DefaultBaseTime.Add(time.Duration(uint64(warmupTreeBaseOffset)*4) * 100 * time.Microsecond).UnixNano()
		var warmupRows, steadyRows []map[string]any
		for _, r := range fakeSrv.Rows("otel_spans") {
			tsNano, _ := r["start_time_unix_nano"].(int64)
			if tsNano >= warmupCutoffNano {
				warmupRows = append(warmupRows, r)
			} else {
				steadyRows = append(steadyRows, r)
			}
		}
		if len(warmupRows) == 0 {
			t.Fatalf("expected warmup spans >= %d when WarmupDuration=250ms, got 0 (steady=%d)", warmupCutoffNano, len(steadyRows))
		}
		assertTraceGraph(t, steadyRows, 4, 0)
		_, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable("otel_spans")
		if tier2Hashes != 0 {
			t.Fatalf("Tier 2 hash count = %d, want 0", tier2Hashes)
		}
	})

	t.Run("PacedTracesShortFinalDispatchContinuesPreviousTrace", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		// TargetRate=24 with BatchSize=6 keeps pacedBatchCap=6 so prebuilt mode runs;
		// Duration=334ms yields totalBudget=8 -> dispatches 6 then short final 2.
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"traces"},
			Workers:         1,
			BatchSize:       6,
			TargetRate:      24,
			Duration:        334 * time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(paced short final) hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 8 || res.RecordsSubmitted != 8 {
			t.Fatalf("DeliveredRows=%d RecordsSubmitted=%d, want 8/8", res.DeliveredRows, res.RecordsSubmitted)
		}
		rows := fakeSrv.Rows("otel_spans")
		assertTraceGraph(t, rows, 8, 0)

		traceSizes := make(map[string]int)
		for _, r := range rows {
			tid, _ := r["trace_id"].(string)
			traceSizes[tid]++
		}
		if len(traceSizes) != 2 {
			t.Fatalf("trace count = %d (%v), want 2 traces of size 4 each (short final dispatch must continue tree 1, not start trace 3)", len(traceSizes), traceSizes)
		}
		for tid, sz := range traceSizes {
			if sz != 4 {
				t.Fatalf("trace %s span count = %d (%v), want 4", tid, sz, traceSizes)
			}
		}
	})

	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("BatchSizeOneWorkers=%dCoversAllFrameworks", workers), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(false)

			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    collectorBin,
				CollectorConfig: cfgPath,
				Signals:         []string{"traces"},
				Workers:         workers,
				BatchSize:       1,
				maxBatches:      28,
				Duration:        5 * time.Second,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runCollectorSingleSignalWithFake(workers=%d) hard=%v soft=%v", workers, hardErr, softErr)
			}
			if res.DeliveredRows != 28 {
				t.Fatalf("DeliveredRows = %d, want 28", res.DeliveredRows)
			}
			assertTraceGraph(t, fakeSrv.Rows("otel_spans"), 28, len(DefaultFrameworks()))
		})
	}
}

func TestCollectorIntegrationAttributesProcessorEdgeInsertIDDoesNotCollapse(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-attributes-edge-id.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  attributes/edge_insert_id:
    actions:
      - key: logging.googleapis.com/insertId
        value: edge-0000000000000001
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/edge_insert_id, batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:             ModeCollector,
		CollectorBin:     collectorBin,
		CollectorConfig:  cfgPath,
		Signals:          []string{"logs"},
		WorkloadProfile:  WorkloadProfileAccessLogs,
		Workers:          1,
		BatchSize:        4,
		maxBatches:       1,
		Duration:         5 * time.Second,
		UpstreamInsertID: false,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if res.DeliveredRows != 4 || res.RecordsSubmitted != 4 || res.Telemetry.ReplayedRows != 0 {
		t.Fatalf("delivered=%d submitted=%d replayed=%d, want 4/4/0 (processor-overwritten edge- insertId must not collapse distinct logs)",
			res.DeliveredRows, res.RecordsSubmitted, res.Telemetry.ReplayedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
}

func TestCollectorBuildWorkerBatchesAndPacedSliceContinuity(t *testing.T) {
	cfg := RunnerConfig{
		Mode:      ModeCollector,
		Signals:   []string{"traces"},
		Workers:   2,
		BatchSize: 6,
	}
	t.Run("OwnWorkerZeroMovesSeedsWithoutCloningAndPreservesWorkerIndependence", func(t *testing.T) {
		logCfg := cfg
		logCfg.Signals = []string{"logs"}
		mkLog, err := newCollectorBatchBuilder(logCfg, "logs")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(logs): %v", err)
		}
		seed1, err := mkLog(4)
		if err != nil {
			t.Fatalf("mkLog: %v", err)
		}
		origLog := seed1.logsReq.Logs()
		seeds1 := []collectorPreparedBatch{seed1}
		wb1 := buildCollectorWorkerBatchesFromPrebuilt(1, seeds1, true)
		if len(wb1) != 1 || len(wb1[0]) != 1 {
			t.Fatalf("wb1 dims = (%d), want (1x1)", len(wb1))
		}
		if seeds1[0].recordCount != 0 || seeds1[0].logsReq != (plogotlp.ExportRequest{}) {
			t.Fatalf("expected owned seeds1[0] to be cleared after handoff, got %+v", seeds1[0])
		}
		// Mutating worker 0's record updates origLog in-place (confirming zero extra clone allocation).
		wb1[0][0].batch.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("shared-owner-sentinel")
		if got := origLog.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString(); got != "shared-owner-sentinel" {
			t.Fatalf("expected worker 0 to take direct ownership of seed batch without cloning, orig body=%q", got)
		}

		seed2A, _ := mkLog(4)
		seed2B, _ := mkLog(4)
		orig2A := seed2A.logsReq.Logs()
		seeds2 := []collectorPreparedBatch{seed2A, seed2B}
		wb2 := buildCollectorWorkerBatchesFromPrebuilt(2, seeds2, true)
		if len(wb2) != 2 || len(wb2[0]) != 2 || len(wb2[1]) != 2 {
			t.Fatalf("wb2 dims unexpected: %d workers", len(wb2))
		}
		wb2[1][0].batch.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("worker1-clone-only")
		if got := orig2A.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString(); got == "worker1-clone-only" {
			t.Fatal("worker 1 clone aliased worker 0 owned storage")
		}

		seed3, _ := mkLog(4)
		origBody3 := seed3.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString()
		seeds3 := []collectorPreparedBatch{seed3}
		wb3 := buildCollectorWorkerBatchesFromPrebuilt(2, seeds3, false)
		wb3[0][0].batch.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().SetStr("caller-isolated")
		if got := seed3.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().AsString(); got != origBody3 {
			t.Fatalf("ownWorkerZero=false mutated caller seed: got %q, want %q", got, origBody3)
		}
	})

	t.Run("SliceCollectorPreparedBatchPreservesTraceTreeAndCountsAcrossSignals", func(t *testing.T) {
		for _, sig := range []string{"traces", "logs", "metrics"} {
			mk, err := newCollectorBatchBuilder(cfg, sig)
			if err != nil {
				t.Fatalf("newCollectorBatchBuilder(%s): %v", sig, err)
			}
			b0, err := mk(6)
			if err != nil {
				t.Fatalf("mk[0](%s): %v", sig, err)
			}
			b1, err := mk(6)
			if err != nil {
				t.Fatalf("mk[1](%s): %v", sig, err)
			}
			sliced, err := sliceCollectorPreparedBatch(b1, sig, 2)
			if err != nil {
				t.Fatalf("sliceCollectorPreparedBatch(%s, 2): %v", sig, err)
			}
			if sliced.recordCount != 2 || sliced.otlpBytes <= 0 || sliced.sourceBytes <= 0 {
				t.Fatalf("%s sliced counts unexpected: %+v", sig, sliced)
			}
			if b1.recordCount != 6 {
				t.Fatalf("%s source batch mutated to recordCount=%d, want 6", sig, b1.recordCount)
			}
			if sig == "traces" {
				// b0 has spans 0..5 (tree 0 full + tree 1 root/child); sliced b1 takes spans 6..7 (tree 1 steps 2..3).
				// Combined trace sizes must be 4, 4 with zero orphan parent links.
				if sliced.tracesReq.Traces().SpanCount() != 2 {
					t.Fatalf("sliced SpanCount = %d, want 2", sliced.tracesReq.Traces().SpanCount())
				}
				counts := make(map[string]int)
				byID := make(map[string]bool)
				var parents []string
				collectSpans := func(td ptrace.Traces) {
					for i := 0; i < td.ResourceSpans().Len(); i++ {
						ss := td.ResourceSpans().At(i).ScopeSpans()
						for j := 0; j < ss.Len(); j++ {
							sp := ss.At(j).Spans()
							for k := 0; k < sp.Len(); k++ {
								s := sp.At(k)
								counts[s.TraceID().String()]++
								byID[s.TraceID().String()+"/"+s.SpanID().String()] = true
								if !s.ParentSpanID().IsEmpty() {
									parents = append(parents, s.TraceID().String()+"/"+s.ParentSpanID().String())
								}
							}
						}
					}
				}
				collectSpans(b0.tracesReq.Traces())
				collectSpans(sliced.tracesReq.Traces())
				if len(counts) != 2 {
					t.Fatalf("combined sliced trace count = %d (%v), want 2", len(counts), counts)
				}
				for tid, c := range counts {
					if c != 4 {
						t.Fatalf("trace %s size = %d (%v), want 4", tid, c, counts)
					}
				}
				for _, pKey := range parents {
					if !byID[pKey] {
						t.Fatalf("orphan parent %s after slice", pKey)
					}
				}
			}
		}

		mkTrace, err := newCollectorBatchBuilder(cfg, "traces")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(traces): %v", err)
		}
		mkMetric, err := newCollectorBatchBuilder(cfg, "metrics")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(metrics): %v", err)
		}
		traceFull, err := mkTrace(4)
		if err != nil {
			t.Fatalf("mkTrace(4): %v", err)
		}
		metricFull, err := mkMetric(4)
		if err != nil {
			t.Fatalf("mkMetric(4): %v", err)
		}
		traceSlice, err := sliceCollectorPreparedBatch(traceFull, "traces", 2)
		if err != nil {
			t.Fatalf("sliceCollectorPreparedBatch(traces, 2): %v", err)
		}
		metricSlice, err := sliceCollectorPreparedBatch(metricFull, "metrics", 2)
		if err != nil {
			t.Fatalf("sliceCollectorPreparedBatch(metrics, 2): %v", err)
		}
		spanKeys := make(map[string]struct{})
		td := traceSlice.tracesReq.Traces()
		for i := 0; i < td.ResourceSpans().Len(); i++ {
			sss := td.ResourceSpans().At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					sp := spans.At(k)
					spanKeys[sp.TraceID().String()+"/"+sp.SpanID().String()] = struct{}{}
				}
			}
		}
		if len(spanKeys) != 2 {
			t.Fatalf("sliced spanKeys count = %d, want 2", len(spanKeys))
		}
		md := metricSlice.metricsReq.Metrics()
		exemplarCount := 0
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			sms := md.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					dps := ms.At(k).Histogram().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						exs := dps.At(l).Exemplars()
						for e := 0; e < exs.Len(); e++ {
							ex := exs.At(e)
							exemplarCount++
							key := ex.TraceID().String() + "/" + ex.SpanID().String()
							if _, ok := spanKeys[key]; !ok {
								t.Fatalf("dangling metric exemplar %s after slice (not in sliced spans %v)", key, spanKeys)
							}
						}
					}
				}
			}
		}
		if exemplarCount != 2 {
			t.Fatalf("exemplarCount = %d, want 2", exemplarCount)
		}
	})

	t.Run("SliceBatchSizeAboveFrameworkCycleAlignsTracesLogsMetrics", func(t *testing.T) {
		wrapCfg := cfg
		wrapCfg.BatchSize = 32
		mkT, err := newCollectorBatchBuilder(wrapCfg, "traces")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(traces): %v", err)
		}
		mkL, err := newCollectorBatchBuilder(wrapCfg, "logs")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(logs): %v", err)
		}
		mkM, err := newCollectorBatchBuilder(wrapCfg, "metrics")
		if err != nil {
			t.Fatalf("newCollectorBatchBuilder(metrics): %v", err)
		}
		fullT, _ := mkT(32)
		fullL, _ := mkL(32)
		fullM, _ := mkM(32)

		slT, err := sliceCollectorPreparedBatch(fullT, "traces", 18)
		if err != nil {
			t.Fatalf("slice(traces, 18): %v", err)
		}
		slL, err := sliceCollectorPreparedBatch(fullL, "logs", 18)
		if err != nil {
			t.Fatalf("slice(logs, 18): %v", err)
		}
		slM, err := sliceCollectorPreparedBatch(fullM, "metrics", 18)
		if err != nil {
			t.Fatalf("slice(metrics, 18): %v", err)
		}

		var spanIDs, logIDs, metricIDs []string
		td := slT.tracesReq.Traces()
		for i := 0; i < td.ResourceSpans().Len(); i++ {
			sss := td.ResourceSpans().At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					sp := spans.At(k)
					spanIDs = append(spanIDs, sp.TraceID().String()+"/"+sp.SpanID().String())
				}
			}
		}
		ld := slL.logsReq.Logs()
		for i := 0; i < ld.ResourceLogs().Len(); i++ {
			sls := ld.ResourceLogs().At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					lr := lrs.At(k)
					logIDs = append(logIDs, lr.TraceID().String()+"/"+lr.SpanID().String())
				}
			}
		}
		md := slM.metricsReq.Metrics()
		for i := 0; i < md.ResourceMetrics().Len(); i++ {
			sms := md.ResourceMetrics().At(i).ScopeMetrics()
			for j := 0; j < sms.Len(); j++ {
				ms := sms.At(j).Metrics()
				for k := 0; k < ms.Len(); k++ {
					dps := ms.At(k).Histogram().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						exs := dps.At(l).Exemplars()
						for e := 0; e < exs.Len(); e++ {
							ex := exs.At(e)
							metricIDs = append(metricIDs, ex.TraceID().String()+"/"+ex.SpanID().String())
						}
					}
				}
			}
		}
		slices.Sort(spanIDs)
		slices.Sort(logIDs)
		slices.Sort(metricIDs)
		if len(spanIDs) != 18 || !slices.Equal(spanIDs, logIDs) || !slices.Equal(spanIDs, metricIDs) {
			t.Fatalf("sliced (trace_id, span_id) mismatch across signals (lens %d/%d/%d):\nspans=%v\nlogs=%v\nmetrics=%v",
				len(spanIDs), len(logIDs), len(metricIDs), spanIDs, logIDs, metricIDs)
		}
	})
}

func TestCollectorIntegrationPacedTracesAndMetricsJoinWithoutDanglingExemplar(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-traces-metrics.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 16
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"traces", "metrics"},
		Workers:         1,
		BatchSize:       4,
		TargetRate:      20,
		Duration:        300 * time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, sig := range []string{"traces", "metrics"} {
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, sig, fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(%s) hard=%v soft=%v", sig, hardErr, softErr)
		}
		if res.DeliveredRows != 6 || res.RecordsSubmitted != 6 {
			t.Fatalf("%s DeliveredRows=%d RecordsSubmitted=%d, want 6/6", sig, res.DeliveredRows, res.RecordsSubmitted)
		}
	}

	spanKeys := make(map[string]struct{})
	for _, r := range fakeSrv.Rows("otel_spans") {
		tid, _ := r["trace_id"].(string)
		sid, _ := r["span_id"].(string)
		spanKeys[tid+"/"+sid] = struct{}{}
	}
	if len(spanKeys) != 6 {
		t.Fatalf("spanKeys count = %d, want 6", len(spanKeys))
	}

	joinedExemplars := 0
	for _, r := range fakeSrv.Rows("otel_metrics") {
		exs, _ := r["exemplars"].([]map[string]any)
		for _, em := range exs {
			tid, _ := em["trace_id"].(string)
			sid, _ := em["span_id"].(string)
			joinedExemplars++
			if _, ok := spanKeys[tid+"/"+sid]; !ok {
				t.Fatalf("dangling metric exemplar %s/%s not present in otel_spans %v", tid, sid, spanKeys)
			}
		}
	}
	if joinedExemplars != 6 {
		t.Fatalf("joinedExemplars = %d, want 6", joinedExemplars)
	}
}

func TestCollectorIntegrationFaultSimPreservesPayloadBodiesWhenUniquePayloadsFalse(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-faultsim-bodies.yaml")
	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  batch:
    send_batch_size: 8
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	runBodies := func(ackDelay time.Duration) []string {
		t.Helper()
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  cfgPath,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileGenAIMixed,
			Workers:          1,
			BatchSize:        4,
			maxBatches:       2,
			Duration:         5 * time.Second,
			UniquePayloads:   false,
			SimulateAckDelay: ackDelay,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize(ackDelay=%s): %v", ackDelay, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(ackDelay=%s) hard=%v soft=%v", ackDelay, hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 8 || res.RecordsSubmitted != 8 {
			t.Fatalf("ackDelay=%s got delivered=%d submitted=%d verified=%v", ackDelay, res.DeliveredRows, res.RecordsSubmitted, res.UniqueDeliveryVerified)
		}
		_, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable("otel_logs")
		if tier2Hashes != 0 {
			t.Fatalf("ackDelay=%s tier2Hashes=%d, want 0", ackDelay, tier2Hashes)
		}
		rows := fakeSrv.Rows("otel_logs")
		type rowItem struct {
			ts   int64
			body string
		}
		items := make([]rowItem, 0, len(rows))
		for _, r := range rows {
			tsNano, _ := r["time_unix_nano"].(int64)
			body, _ := r["body"].(string)
			items = append(items, rowItem{ts: tsNano, body: body})
		}
		slices.SortFunc(items, func(a, b rowItem) int {
			if a.ts < b.ts {
				return -1
			}
			if a.ts > b.ts {
				return 1
			}
			return 0
		})
		out := make([]string, len(items))
		for i, it := range items {
			out[i] = it.body
		}
		return out
	}

	baselineBodies := runBodies(0)
	delayedBodies := runBodies(time.Millisecond)
	if !slices.Equal(baselineBodies, delayedBodies) {
		t.Fatalf("SimulateAckDelay changed generated log bodies when UniquePayloads=false:\nbaseline=%v\ndelayed=%v", baselineBodies, delayedBodies)
	}
}
