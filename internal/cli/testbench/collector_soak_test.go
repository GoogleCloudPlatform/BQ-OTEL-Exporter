// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
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
	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
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
	logNameAttr          string
	insertIDAttr         string
	synthesizeInsertID   bool
	warmupMu             sync.Mutex
	warmupRows           []transform.Row
	steadyWarmupReplayed bool
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

func (s *fakeCollectorHelperServer) appendEncodedRowsToBQFake(ctx context.Context, rows []transform.Row) (int64, error) {
	if s.bqWriteCli == nil || len(rows) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	serialized := make([][]byte, 0, len(rows))
	var totalBytes int64
	for _, r := range rows {
		raw, err := s.enc.Encode(r)
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
			s.ackedRows.Add(int64(len(rows)))
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

func (s *fakeCollectorHelperServer) appendRowsToBQFake(ctx context.Context, ids []string) (int64, error) {
	if s.bqWriteCli == nil || len(ids) == 0 {
		return 0, nil
	}
	ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	rows := make([]transform.Row, 0, len(ids))
	for _, id := range ids {
		rows = append(rows, transform.Row{
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
	}
	return s.appendEncodedRowsToBQFake(ctx, rows)
}

func (s *fakeCollectorHelperServer) Export(ctx context.Context, req plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	n := req.Logs().LogRecordCount()
	seq := s.batchSeq.Add(1)
	resp := plogotlp.NewExportResponse()

	if s.mode == "warmup_partial_reject" && seq == 1 && n > 1 {
		resp.PartialSuccess().SetRejectedLogRecords(1)
		n--
	}

	var firstTSNano int64
	hasFirstTS := false
	rlSlice := req.Logs().ResourceLogs()
	for i := 0; i < rlSlice.Len() && !hasFirstTS; i++ {
		slSlice := rlSlice.At(i).ScopeLogs()
		for j := 0; j < slSlice.Len() && !hasFirstTS; j++ {
			lrs := slSlice.At(j).LogRecords()
			if lrs.Len() > 0 {
				firstTSNano = int64(lrs.At(0).Timestamp())
				hasFirstTS = true
			}
		}
	}

	rows, _ := transform.LogRows(req.Logs(), transform.Options{
		Contract:           schema.ContractV1Candidate,
		Limits:             transform.DefaultLimits(),
		SynthesizeInsertID: s.synthesizeInsertID,
		LogNameAttribute:   s.logNameAttr,
		InsertIDAttribute:  s.insertIDAttr,
	})
	if n < len(rows) {
		rows = rows[:n]
	}

	switch s.mode {
	case "replay_warmup_rows":
		s.warmupMu.Lock()
		if hasFirstTS && isWarmupEventTime(DefaultBaseTime, firstTSNano) {
			s.warmupRows = append(s.warmupRows, rows...)
			s.warmupMu.Unlock()
			_, err := s.appendEncodedRowsToBQFake(ctx, rows)
			return resp, err
		}
		replayRows := rows
		if len(s.warmupRows) > 0 {
			replayRows = make([]transform.Row, len(rows))
			for i := range replayRows {
				replayRows[i] = s.warmupRows[i%len(s.warmupRows)]
			}
		}
		s.warmupMu.Unlock()
		_, err := s.appendEncodedRowsToBQFake(ctx, replayRows)
		return resp, err
	case "replay_warmup_alongside_steady":
		s.warmupMu.Lock()
		if hasFirstTS && isWarmupEventTime(DefaultBaseTime, firstTSNano) {
			if len(s.warmupRows) == 0 && len(rows) > 0 {
				s.warmupRows = append(s.warmupRows, rows[0])
			}
			s.warmupMu.Unlock()
			_, err := s.appendEncodedRowsToBQFake(ctx, rows)
			return resp, err
		}
		deliver := rows
		if len(s.warmupRows) > 0 && !s.steadyWarmupReplayed {
			s.steadyWarmupReplayed = true
			deliver = append(slices.Clone(rows), s.warmupRows[0])
		}
		s.warmupMu.Unlock()
		_, err := s.appendEncodedRowsToBQFake(ctx, deliver)
		return resp, err
	case "ack_without_commit":
		s.ackedRows.Add(int64(n))
		s.appendBytes.Add(int64(n) * 500)
		return resp, nil
	case "delayed_commit_200ms":
		rowsCopy := slices.Clone(rows)
		go func() {
			time.Sleep(200 * time.Millisecond)
			_, _ = s.appendEncodedRowsToBQFake(context.Background(), rowsCopy)
		}()
		return resp, nil
	case "drain_stall", "drain_stall_exit_error_on_sigterm":
		half := max(1, len(rows)/2)
		_, err := s.appendEncodedRowsToBQFake(ctx, rows[:half])
		return resp, err
	case "replay_with_drop":
		if len(rows) >= 2 {
			deliver := rows[:len(rows)-1]
			if _, err := s.appendEncodedRowsToBQFake(ctx, deliver); err != nil {
				return resp, err
			}
			// Replay first row twice so total ackedRows >= submitted while unique delivered < submitted.
			_, err := s.appendEncodedRowsToBQFake(ctx, []transform.Row{deliver[0], deliver[0]})
			return resp, err
		}
	case "replay_one_with_drop":
		if len(rows) >= 2 {
			deliver := rows[:len(rows)-1]
			if _, err := s.appendEncodedRowsToBQFake(ctx, deliver); err != nil {
				return resp, err
			}
			// Replay first row once so committedRows == submitted (4) while unique delivered == 3 and replayed == 1.
			_, err := s.appendEncodedRowsToBQFake(ctx, []transform.Row{deliver[0]})
			return resp, err
		}
	case "replay_all_delivered":
		if _, err := s.appendEncodedRowsToBQFake(ctx, rows); err != nil {
			return resp, err
		}
		if len(rows) > 0 {
			_, err := s.appendEncodedRowsToBQFake(ctx, rows[:1])
			return resp, err
		}
		return resp, nil
	case "extra_ack_no_replay":
		if _, err := s.appendEncodedRowsToBQFake(ctx, rows); err != nil {
			return resp, err
		}
		if seq == 1 {
			s.ackedRows.Add(1)
		}
		return resp, nil
	case "extra_distinct_row":
		ts := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
		extraRow := transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts.UnixMicro(),
			"receive_time_unix_nano":  ts.UnixNano(),
			"log_name":                "projects/test-project/logs/app",
			"insert_id":               fmt.Sprintf("extra-distinct-b%d", seq),
			"body":                    fmt.Sprintf("%q", fmt.Sprintf("payload-extra-distinct-b%d", seq)),
		}
		extra := append(slices.Clone(rows), extraRow)
		_, err := s.appendEncodedRowsToBQFake(ctx, extra)
		return resp, err
	case "quarantine_one_of_four":
		deliverIDs := []string{"q-log-0", "q-log-1", "q-log-2"}
		if n < 3 {
			deliverIDs = deliverIDs[:n]
		}
		if _, err := s.appendRowsToBQFake(ctx, deliverIDs); err != nil {
			return resp, err
		}
		if err := s.appendQuarantineRowToBQFake(ctx, strings.Repeat("Q", 2048)); err != nil {
			return resp, err
		}
		return resp, nil
	case "live_retry_inflation":
		s.ackedRows.Add(int64(n))
		s.appendBytes.Add(int64(n) * 2000)
		s.retries.Add(2)
		return resp, nil
	case "live_partial_delivery":
		acked := max(0, n-4)
		rejected := n - acked
		s.ackedRows.Add(int64(acked))
		s.rejectedRows.Add(int64(rejected))
		s.appendBytes.Add(10000)
		return resp, nil
	case "live_enqueue_failed":
		acked := max(0, n-2)
		enqFailed := n - acked
		s.ackedRows.Add(int64(acked))
		s.enqueueFailed.Add(int64(enqFailed))
		s.appendBytes.Add(int64(acked) * 500)
		return resp, nil
	case "live_missing_append_bytes":
		s.ackedRows.Add(int64(n))
		return resp, nil
	case "live_ok":
		s.ackedRows.Add(int64(n))
		s.appendBytes.Add(int64(n) * 640)
		return resp, nil
	default:
		_, err := s.appendEncodedRowsToBQFake(ctx, rows)
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
	var logNameAttr, insertIDAttr string
	synthesizeInsertID := true
	var activeExpID string
	for k, v := range exporters {
		activeExpID = k
		bqMap, _ := v.(map[string]any)
		projectID, _ = bqMap["project"].(string)
		datasetID, _ = bqMap["dataset"].(string)
		if logsMap, ok := bqMap["logs"].(map[string]any); ok {
			tableID, _ = logsMap["table"].(string)
			logNameAttr, _ = logsMap["log_name_attribute"].(string)
			insertIDAttr, _ = logsMap["insert_id_attribute"].(string)
			if rawSynth, hasSynth := logsMap["synthesize_insert_id"]; hasSynth {
				if synthBool, ok := rawSynth.(bool); ok {
					synthesizeInsertID = synthBool
				}
			}
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
	helperStreamName := fmt.Sprintf("projects/%s/datasets/%s/tables/%s/streams/_default", projectID, datasetID, tableID)
	if mode == "wrong_dataset" {
		helperStreamName = fmt.Sprintf("projects/%s/datasets/wrong_ds/tables/%s/streams/_default", projectID, tableID)
	}
	helper := &fakeCollectorHelperServer{
		mode:                 mode,
		streamName:           helperStreamName,
		rowDesc:              logEnc.Descriptor(),
		enc:                  logEnc,
		quarantineStreamName: fmt.Sprintf("projects/%s/datasets/%s/tables/otel_quarantine/streams/_default", projectID, datasetID),
		quarantineRowDesc:    quarantineEnc.Descriptor(),
		quarantineEnc:        quarantineEnc,
		logNameAttr:          logNameAttr,
		insertIDAttr:         insertIDAttr,
		synthesizeInsertID:   synthesizeInsertID,
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
			if resAll.ObservedDelayedAckFaults < 1 || resAll.ObservedUncertainCommitFaults != 0 || resAll.Telemetry.Retries != 0 || resAll.UnexplainedReplayRows != 1 {
				t.Fatalf("unexpected replay_all_delivered fault accounting: delayed=%d uncertain=%d retries=%d unexplained=%d",
					resAll.ObservedDelayedAckFaults, resAll.ObservedUncertainCommitFaults, resAll.Telemetry.Retries, resAll.UnexplainedReplayRows)
			}
			if lossErr := checkSignalResultLossless(cfgAll, "logs", resAll, softErrAll); lossErr == nil || !strings.Contains(lossErr.Error(), "unexplained_replays=1") {
				t.Fatalf("checkSignalResultLossless(SimulateAckDelay>0, Retries=0, UnexplainedReplayRows=1) = %v, want failure citing unexplained_replays=1", lossErr)
			}
		})

		t.Run("ExtraAckWithoutReplayFailsStrictRun", func(t *testing.T) {
			binExtraAck := configureCollectorHelperEnv(t, "extra_ack_no_replay")
			cfgExtraAck := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    binExtraAck,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
				Workers:         1,
				BatchSize:       4,
				Duration:        150 * time.Millisecond,
				maxBatches:      1,
			}
			if err := cfgExtraAck.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			report, runErr := Run(ctx, cfgExtraAck)
			if runErr == nil || !strings.Contains(runErr.Error(), "failed lossless delivery check") || !strings.Contains(runErr.Error(), "acked=5") {
				t.Fatalf("Run = %v, want strict lossless failure citing acked=5", runErr)
			}
			if len(report.Results) != 1 {
				t.Fatalf("len(report.Results) = %d, want 1", len(report.Results))
			}
			got := report.Results[0]
			if got.RecordsSubmitted != 4 || got.DeliveredRows != 4 || got.Telemetry.AcknowledgedRows != 5 || got.Telemetry.ReplayedRows != 0 {
				t.Fatalf("unexpected stats: submitted=%d delivered=%d acked=%d replayed=%d, want 4/4/5/0",
					got.RecordsSubmitted, got.DeliveredRows, got.Telemetry.AcknowledgedRows, got.Telemetry.ReplayedRows)
			}
		})

		t.Run("ExtraAckWithoutReplayWithFaultSimulationFailsStrictRun", func(t *testing.T) {
			binExtraAck := configureCollectorHelperEnv(t, "extra_ack_no_replay")
			cfgExtraAck := RunnerConfig{
				Mode:                  ModeCollector,
				CollectorBin:          binExtraAck,
				CollectorConfig:       cfgPath,
				Signals:               []string{"logs"},
				Workers:               1,
				BatchSize:             4,
				Duration:              150 * time.Millisecond,
				SimulateThrottleEvery: 1,
				maxBatches:            1,
			}
			if err := cfgExtraAck.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			report, runErr := Run(ctx, cfgExtraAck)
			if runErr == nil || !strings.Contains(runErr.Error(), "failed lossless delivery check") || !strings.Contains(runErr.Error(), "acked=5") {
				t.Fatalf("Run = %v, want strict lossless failure citing acked=5 even with faultSimEnabled", runErr)
			}
			if len(report.Results) != 1 {
				t.Fatalf("len(report.Results) = %d, want 1", len(report.Results))
			}
			got := report.Results[0]
			if !got.UniqueDeliveryVerified || got.RecordsSubmitted != 4 || got.DeliveredRows != 4 || got.Telemetry.AcknowledgedRows != 5 || got.Telemetry.ReplayedRows != 0 {
				t.Fatalf("unexpected stats: verified=%v submitted=%d delivered=%d acked=%d replayed=%d, want true/4/4/5/0",
					got.UniqueDeliveryVerified, got.RecordsSubmitted, got.DeliveredRows, got.Telemetry.AcknowledgedRows, got.Telemetry.ReplayedRows)
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

	t.Run("EnvTableRawExprPreservedAndEscapedRefsNotDoubleExpanded", func(t *testing.T) {
		t.Setenv("TEST_BQ_LOGS_TABLE", "env_resolved_logs")
		t.Setenv("SCRATCH_TABLE_TARGET", "otel_logs")

		for _, tc := range []struct {
			name      string
			tableExpr string
			wantTable string
		}{
			{name: "env_scheme", tableExpr: "${env:TEST_BQ_LOGS_TABLE}", wantTable: "env_resolved_logs"},
			{name: "bare_var", tableExpr: "${TEST_BQ_LOGS_TABLE}", wantTable: "env_resolved_logs"},
			{name: "unset_with_default", tableExpr: "${env:TEST_UNSET_BQ_LOGS_TABLE_XYZ:-fallback_logs}", wantTable: "fallback_logs"},
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
				if gotTable, _ := logsMap["table"].(string); gotTable != tc.tableExpr {
					t.Fatalf("rewritten logs.table = %q, want raw preserved expression %q", gotTable, tc.tableExpr)
				}
			})
		}

		// Escaped table expressions ($${...} or $$...) expand only once and must fail table-ID validation
		// in both loopback rewrite and live preflight without double-expanding SCRATCH_TABLE_TARGET.
		for _, escapedExpr := range []string{"$$literal_logs", "$${env:SCRATCH_TABLE_TARGET}"} {
			rawEscaped := []byte(fmt.Sprintf(`
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
`, escapedExpr))
			if _, _, err := rewriteCollectorLoopbackConfig(rawEscaped, baseCfg, "logs", baseEP); err == nil || !strings.Contains(err.Error(), "must contain only letters, numbers and underscores") {
				t.Fatalf("loopback rewrite(%q) = %v, want invalid table ID error", escapedExpr, err)
			}
			liveEP := baseEP
			liveEP.useBQFake = false
			if _, _, err := rewriteCollectorLoopbackConfig(rawEscaped, baseCfg, "logs", liveEP); err == nil || !strings.Contains(err.Error(), "must contain only letters, numbers and underscores") {
				t.Fatalf("live rewrite(%q) = %v, want invalid table ID error", escapedExpr, err)
			}

			cfgPath := filepath.Join(t.TempDir(), "escaped-table.yaml")
			if err := os.WriteFile(cfgPath, rawEscaped, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			liveCfg := baseCfg
			liveCfg.CollectorAllowLive = true
			liveCfg.CollectorConfig = cfgPath
			if _, err := validateCollectorPreflightConfigWithMeta(liveCfg, "logs"); err == nil || !strings.Contains(err.Error(), "must contain only letters, numbers and underscores") {
				t.Fatalf("live preflight(%q) = %v, want invalid table ID error", escapedExpr, err)
			}
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

	t.Run("LoopbackDropsCredentialsPrunesUnusedProcessorsAndPreservesAttrWhitespace", func(t *testing.T) {
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/ambient-creds-must-be-ignored-in-loopback.json")
		rawYAML := []byte(`
receivers:
  otlp: {}
processors:
  batch: {}
  attributes/unused_trace:
    actions:
      - key: unused
        value: ${file:/nonexistent/unused.txt}
        action: upsert
exporters:
  bigquery:
    credentials:
      json: "${file:/nonexistent/missing-creds.json}"
    logs:
      table: otel_logs
      log_name_attribute: " event.name "
      insert_id_attribute: " custom.id "
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      processors: [attributes/unused_trace]
      exporters: [bigquery]
`)
		rewritten, meta, err := rewriteCollectorLoopbackConfig(rawYAML, baseCfg, "logs", baseEP)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig unexpected error: %v", err)
		}
		if meta.effectiveLogsLogNameAttr != " event.name " || meta.effectiveLogsInsertIDAttr != " custom.id " {
			t.Fatalf("whitespace lost in meta attrs: log_name=%q insert_id=%q",
				meta.effectiveLogsLogNameAttr, meta.effectiveLogsInsertIDAttr)
		}
		if len(meta.rawCredentialSecrets) != 0 {
			t.Fatalf("loopback discovered ambient/exporter credentials: %v", meta.rawCredentialSecrets)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(rewritten, &doc); err != nil {
			t.Fatalf("yaml.Unmarshal: %v", err)
		}
		bqCfg := doc["exporters"].(map[string]any)["bigquery"].(map[string]any)
		if _, hasCreds := bqCfg["credentials"]; hasCreds {
			t.Fatalf("expected credentials dropped in loopback rewrite, got %v", bqCfg["credentials"])
		}
		procs := doc["processors"].(map[string]any)
		if _, hasUnused := procs["attributes/unused_trace"]; hasUnused {
			t.Fatalf("expected unused processor pruned, got processors=%v", procs)
		}
		if _, hasBatch := procs["batch"]; !hasBatch {
			t.Fatalf("expected active batch processor preserved, got processors=%v", procs)
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

		// S1: Run must preserve the populated cutoff SignalResult even when
		// finalizeCollectorShutdown fails after clean pipeline drain.
		report, runErr := Run(ctx, cfg)
		if runErr == nil || !strings.Contains(runErr.Error(), "collector exited with error") {
			t.Fatalf("Run error = %v, want collector exited with error", runErr)
		}
		if report == nil || len(report.Results) != 1 {
			t.Fatalf("expected 1 preserved SignalResult in report, got %+v", report)
		}
		gotRes := report.Results[0]
		if gotRes.Signal != "logs" || gotRes.RecordsSubmitted <= 0 || gotRes.Telemetry.AcknowledgedRows <= 0 || gotRes.Latency.Samples <= 0 || gotRes.BytesPerRow <= 0 {
			t.Fatalf("expected populated cutoff SignalResult fields, got %+v", gotRes)
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

func TestCollectorRejectsActiveHealthCheckTLS(t *testing.T) {
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

	const sentinelSecret = "super-secret-hc-key-token-12345"
	t.Setenv("TEST_HC_TLS_SET", sentinelSecret)
	t.Setenv("TEST_HC_TLS_MAP", "cert_file: /etc/hc.pem")

	rejectCases := []struct {
		name string
		yaml string
	}{
		{
			name: "inline_tls_map",
			yaml: `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls:
      cert_file: /etc/hc-cert.pem
      key_file: /etc/` + sentinelSecret + `.pem
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "empty_tls_map",
			yaml: `
extensions:
  health_check/ready:
    endpoint: 0.0.0.0:13133
    tls: {}
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check/ready]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "file_ref_tls",
			yaml: `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls: "${file:hc-tls-secret.yaml}"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "env_ref_tls_scalar",
			yaml: `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls: "${env:TEST_HC_TLS_SET}"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
		{
			name: "env_ref_tls_map",
			yaml: `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls: "${env:TEST_HC_TLS_MAP}"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
		},
	}

	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "hc-tls.yaml")
			if wErr := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    exe,
				CollectorConfig: cfgPath,
				Signals:         []string{"logs"},
			}
			_, _, rwErr := rewriteCollectorLoopbackConfig([]byte(tc.yaml), cfg, "logs", ep)
			if rwErr == nil || !strings.Contains(rwErr.Error(), "tls") {
				t.Fatalf("rewriteCollectorLoopbackConfig(%s) err = %v, want tls error", tc.name, rwErr)
			}
			for _, forbidden := range []string{sentinelSecret, "hc-tls-secret.yaml", "/etc/hc.pem"} {
				if strings.Contains(rwErr.Error(), forbidden) {
					t.Fatalf("rewriteCollectorLoopbackConfig(%s) leaked %q in err %v", tc.name, forbidden, rwErr)
				}
			}
			preErr := validateRunConfig(t.Context(), &cfg, nil)
			if preErr == nil || !strings.Contains(preErr.Error(), "tls") {
				t.Fatalf("validateRunConfig(%s) err = %v, want tls error", tc.name, preErr)
			}
		})
	}

	t.Run("RunPreflightRejectsBeforeEphemeralDatasetCreation", func(t *testing.T) {
		var adminCalls atomic.Int32
		adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			adminCalls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer adminSrv.Close()

		yamlCfg := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls:
      cert_file: /etc/cert.pem
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: hc-tls-proj
    dataset: ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, adminSrv.URL)
		cfgPath := filepath.Join(t.TempDir(), "hc-tls-eph.yaml")
		if wErr := os.WriteFile(cfgPath, []byte(yamlCfg), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		_, runErr := Run(t.Context(), RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       exe,
			CollectorConfig:    cfgPath,
			ProjectID:          "hc-tls-proj",
			Location:           "US",
			EphemeralDataset:   true,
			Signals:            []string{"logs"},
			Workers:            1,
			BatchSize:          2,
			maxBatches:         1,
			Duration:           100 * time.Millisecond,
		})
		if runErr == nil || !strings.Contains(runErr.Error(), "tls") {
			t.Fatalf("Run(health_check tls) err = %v, want tls error", runErr)
		}
		if got := adminCalls.Load(); got != 0 {
			t.Fatalf("expected preflight to reject health_check tls before any admin REST calls, got %d calls", got)
		}
	})

	t.Run("PrunesInactiveHealthCheckWithTLSAndAllowsEmptyEnvTLS", func(t *testing.T) {
		yamlCfg := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
    tls: "${env:TEST_HC_TLS_UNSET:-}"
  health_check/unused:
    endpoint: 0.0.0.0:13134
    tls:
      cert_file: /etc/unused-cert.pem
      key_file: /etc/unused-key.pem
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery: {}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfgPath := filepath.Join(t.TempDir(), "hc-inactive-tls.yaml")
		if wErr := os.WriteFile(cfgPath, []byte(yamlCfg), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    exe,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
		}
		rewritten, _, rwErr := rewriteCollectorLoopbackConfig([]byte(yamlCfg), cfg, "logs", ep)
		if rwErr != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig unexpected error: %v", rwErr)
		}
		if strings.Contains(string(rewritten), "health_check/unused") {
			t.Fatalf("expected inactive health_check/unused to be pruned, got:\n%s", rewritten)
		}
		if preErr := validateRunConfig(t.Context(), &cfg, nil); preErr != nil {
			t.Fatalf("validateRunConfig unexpected error: %v", preErr)
		}
	})
}

func TestCollectorPreflightRejectsIncompatibleSharedTables(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	writeCfg := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "shared-table.yaml")
		if wErr := os.WriteFile(p, []byte(body), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		return p
	}

	t.Run("LogsAndTracesShareTableRejectedBeforeEphemeralCreate", func(t *testing.T) {
		var adminCalls atomic.Int32
		adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			adminCalls.Add(1)
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer adminSrv.Close()

		cfgPath := writeCfg(t, fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery/logs:
    project: shared-tbl-proj
    dataset: placeholder_ds
    location: US
    logs:
      table: shared_events
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
  bigquery/traces:
    project: shared-tbl-proj
    dataset: placeholder_ds
    location: US
    traces:
      table: shared_events
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, adminSrv.URL, adminSrv.URL))

		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       exe,
			CollectorConfig:    cfgPath,
			ProjectID:          "shared-tbl-proj",
			Location:           "US",
			EphemeralDataset:   true,
			Signals:            []string{"logs", "traces"},
			Workers:            1,
			BatchSize:          2,
			maxBatches:         1,
			Duration:           100 * time.Millisecond,
		}
		_, runErr := Run(t.Context(), cfg)
		if runErr == nil || !strings.Contains(runErr.Error(), "logs") || !strings.Contains(runErr.Error(), "traces") || !strings.Contains(runErr.Error(), "shared_events") {
			t.Fatalf("Run error = %v, want conflict citing logs, traces, and shared_events", runErr)
		}
		if got := adminCalls.Load(); got != 0 {
			t.Fatalf("expected preflight to fail before dataset creation, got %d admin calls", got)
		}
	})

	t.Run("SingleSignalAndQuarantineShareTableRejected", func(t *testing.T) {
		cfgPath := writeCfg(t, `
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
    project: shared-tbl-proj
    dataset: placeholder_ds
    location: US
    logs:
      table: otel_quarantine
    quarantine:
      table: otel_quarantine
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       exe,
			CollectorConfig:    cfgPath,
			ProjectID:          "shared-tbl-proj",
			Location:           "US",
			EphemeralDataset:   true,
			Signals:            []string{"logs"},
		}
		preErr := validateRunConfig(t.Context(), &cfg, nil)
		if preErr == nil || !strings.Contains(preErr.Error(), "logs") || !strings.Contains(preErr.Error(), "quarantine") || !strings.Contains(preErr.Error(), "otel_quarantine") {
			t.Fatalf("validateRunConfig error = %v, want conflict citing logs, quarantine, and otel_quarantine", preErr)
		}
	})

	t.Run("TracesQuarantineAndLogsPrimaryCollisionRejected", func(t *testing.T) {
		cfgPath := writeCfg(t, `
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
    project: shared-tbl-proj
    dataset: placeholder_ds
    location: US
    traces:
      table: custom_spans
    logs:
      table: shared_q_and_logs
    quarantine:
      table: shared_q_and_logs
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [bigquery]
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       exe,
			CollectorConfig:    cfgPath,
			ProjectID:          "shared-tbl-proj",
			Location:           "US",
			EphemeralDataset:   true,
			Signals:            []string{"traces", "logs"},
		}
		preErr := validateRunConfig(t.Context(), &cfg, nil)
		if preErr == nil || !strings.Contains(preErr.Error(), "traces") || !strings.Contains(preErr.Error(), "logs") || !strings.Contains(preErr.Error(), "quarantine") || !strings.Contains(preErr.Error(), "shared_q_and_logs") {
			t.Fatalf("validateRunConfig error = %v, want conflict citing traces, logs, quarantine, and shared_q_and_logs", preErr)
		}
	})

	t.Run("MultipleSignalsSharingQuarantineAllowed", func(t *testing.T) {
		cfgPath := writeCfg(t, `
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
    project: shared-tbl-proj
    dataset: placeholder_ds
    location: US
    traces:
      table: custom_spans
    logs:
      table: custom_logs
    metrics:
      table: custom_metrics
    quarantine:
      table: common_quarantine
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [bigquery]
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      exporters: [bigquery]
`)
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       exe,
			CollectorConfig:    cfgPath,
			ProjectID:          "shared-tbl-proj",
			Location:           "US",
			EphemeralDataset:   true,
			Signals:            []string{"traces", "logs", "metrics"},
		}
		if preErr := validateRunConfig(t.Context(), &cfg, nil); preErr != nil {
			t.Fatalf("validateRunConfig(shared quarantine) unexpected error: %v", preErr)
		}
		var got []string
		for _, sp := range cfg.collectorEphemeralTables {
			got = append(got, sp.signal+":"+sp.table)
		}
		want := []string{"traces:custom_spans", "quarantine:common_quarantine", "logs:custom_logs", "metrics:custom_metrics"}
		if !slices.Equal(got, want) {
			t.Fatalf("collectorEphemeralTables = %v, want %v", got, want)
		}
	})
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

	// (e) Non-executable file must fail closed on Unix before starting any run or admin call.
	if runtime.GOOS != "windows" {
		nonExecBin := filepath.Join(t.TempDir(), "non-exec-otelcol")
		if wErr := os.WriteFile(nonExecBin, []byte("not executable"), 0o600); wErr != nil {
			t.Fatalf("write nonExecBin: %v", wErr)
		}
		if got, execErr := resolveCollectorBinaryPath(nonExecBin); execErr == nil || !strings.Contains(execErr.Error(), "not executable") {
			t.Fatalf("resolveCollectorBinaryPath(0o600) = (%q, %v), want 'not executable' error", got, execErr)
		}

		// (f) Non-regular file (Unix socket) must fail closed even with 0755 mode bits.
		sockDir, mkErr := os.MkdirTemp("", "bqcol-")
		if mkErr != nil {
			t.Fatalf("MkdirTemp: %v", mkErr)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		sockBin := filepath.Join(sockDir, "s")
		sockLis, sockErr := net.Listen("unix", sockBin)
		if sockErr != nil {
			t.Fatalf("net.Listen(unix, %s): %v", sockBin, sockErr)
		}
		defer func() { _ = sockLis.Close() }()
		if chErr := os.Chmod(sockBin, 0o755); chErr != nil {
			t.Fatalf("Chmod(%s): %v", sockBin, chErr)
		}
		if got, regErr := resolveCollectorBinaryPath(sockBin); regErr == nil || !strings.Contains(regErr.Error(), "not a regular file") {
			t.Fatalf("resolveCollectorBinaryPath(socket) = (%q, %v), want 'not a regular file' error", got, regErr)
		}
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
			multiSignalYAML := `
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
    metrics:
      receivers: [otlp]
      exporters: [bigquery]
`
			multiCfgPath := filepath.Join(t.TempDir(), "collector-unique-cap-multi.yaml")
			if err := os.WriteFile(multiCfgPath, []byte(multiSignalYAML), 0o600); err != nil {
				t.Fatalf("write multi config: %v", err)
			}
			for _, tc := range []struct {
				name             string
				signal           string
				upstreamInsertID bool
				duration         time.Duration
			}{
				{
					name:             "UntaggedEdgeInsertIDLogs70MExceeds67M",
					signal:           "logs",
					upstreamInsertID: true,
					duration:         70 * time.Second,
				},
				{
					name:             "TaggedSynthesizedLogs8MExceeds6MByteBudget",
					signal:           "logs",
					upstreamInsertID: false,
					duration:         8 * time.Second,
				},
				{
					name:             "TaggedMetrics4MExceeds3MByteBudget",
					signal:           "metrics",
					upstreamInsertID: false,
					duration:         4 * time.Second,
				},
			} {
				t.Run(tc.name, func(t *testing.T) {
					fakeSrv, err := bqfake.New()
					if err != nil {
						t.Fatalf("bqfake.New: %v", err)
					}
					defer func() { _ = fakeSrv.Close() }()

					cfg := RunnerConfig{
						Mode:                  ModeCollector,
						CollectorBin:          failOnStartBin,
						CollectorConfig:       multiCfgPath,
						Signals:               []string{tc.signal},
						UpstreamInsertID:      tc.upstreamInsertID,
						TargetRate:            1000000,
						Duration:              tc.duration,
						SimulateThrottleEvery: 1,
					}
					if err := cfg.Normalize(); err != nil {
						t.Fatalf("Normalize: %v", err)
					}

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, tc.signal, fakeSrv)
					if hardErr == nil {
						t.Fatal("expected preflight rejection when TargetRate*Duration exceeds tracking limit")
					}
					msg := hardErr.Error()
					usesTagged := tc.signal == "metrics" || (tc.signal == "logs" && !tc.upstreamInsertID)
					wantLimit := fmt.Sprintf("%d", fakeSrv.MaxTrackedGeneratedRowsForSignal(tc.signal, usesTagged))
					for _, wantSub := range []string{wantLimit, "-rate", "-duration", "-simulate-throttle-every", "-simulate-ack-delay"} {
						if !strings.Contains(msg, wantSub) {
							t.Fatalf("preflight error %q missing %q", msg, wantSub)
						}
					}
					if strings.Contains(msg, "child exited non-zero") {
						t.Fatalf("expected rejection before spawning collector, got %q", msg)
					}
				})
			}

			t.Run("NullIDLogs3MExceeds2MCapRejectsBeforeStartingCollector", func(t *testing.T) {
				nullCfgPath := filepath.Join(t.TempDir(), "collector-null-id-cap.yaml")
				nullYAML := `
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
    logs:
      synthesize_insert_id: false
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
				if err := os.WriteFile(nullCfgPath, []byte(nullYAML), 0o600); err != nil {
					t.Fatalf("write null-id config: %v", err)
				}
				fakeSrv, err := bqfake.New()
				if err != nil {
					t.Fatalf("bqfake.New: %v", err)
				}
				defer func() { _ = fakeSrv.Close() }()

				cfgOver := RunnerConfig{
					Mode:                  ModeCollector,
					CollectorBin:          failOnStartBin,
					CollectorConfig:       nullCfgPath,
					Signals:               []string{"logs"},
					UpstreamInsertID:      false,
					TargetRate:            1000000,
					Duration:              3 * time.Second,
					SimulateThrottleEvery: 1,
				}
				if err := cfgOver.Normalize(); err != nil {
					t.Fatalf("Normalize(over): %v", err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfgOver, "logs", fakeSrv)
				if hardErr == nil {
					t.Fatal("expected preflight rejection for 3M NULL-ID logs > 2M cap")
				}
				wantNullCap := fmt.Sprintf("%d", fakeSrv.MaxTrackedNullIDLogRows())
				if !strings.Contains(hardErr.Error(), wantNullCap) || strings.Contains(hardErr.Error(), "child exited non-zero") {
					t.Fatalf("preflight error = %q, want NULL-ID cap %s before spawning collector", hardErr.Error(), wantNullCap)
				}

				cfgAtCap := cfgOver
				cfgAtCap.Duration = 2 * time.Second
				if err := cfgAtCap.Normalize(); err != nil {
					t.Fatalf("Normalize(atCap): %v", err)
				}
				_, _, atCapErr := runCollectorSingleSignalWithFake(ctx, cfgAtCap, "logs", fakeSrv)
				if atCapErr == nil || !strings.Contains(atCapErr.Error(), "child exited non-zero") {
					t.Fatalf("expected 2M NULL-ID logs run to pass preflight and reach child process start, got %v", atCapErr)
				}
			})
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
		//   - dispatch 0 (epoch 0): full batch of 4 rows -> canonical seq 0,1,2,3
		//   - dispatch 1 (epoch 1, accessStride=12): sliced 3 rows -> canonical seq 12,13,14
		// Preserving (origSeq % 12) keeps pod service_name and severity aligned
		// with sequence numbers across reused templates without chunk fanout.
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
		wantSeqs := []uint64{0, 1, 2, 3, 12, 13, 14}
		if len(gotTS) != len(wantSeqs) || len(gotIDs) != len(wantSeqs) {
			t.Fatalf("captured = (ts=%d, ids=%d), want (%d, %d)", len(gotTS), len(gotIDs), len(wantSeqs), len(wantSeqs))
		}
		for i, wantSeq := range wantSeqs {
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

	t.Run("WarmupReplayAlongsideSteadyWithFaultSimFailsStrictDelivery", func(t *testing.T) {
		cfgPathLocal := filepath.Join(t.TempDir(), "collector-replay-warmup-faultsim.yaml")
		if wErr := os.WriteFile(cfgPathLocal, []byte(`
extensions:
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
    logs:
      table: otel_logs
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		bin := configureCollectorHelperEnv(t, "replay_warmup_alongside_steady")
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()

		cfg := RunnerConfig{
			Mode:                  ModeCollector,
			CollectorBin:          bin,
			CollectorConfig:       cfgPathLocal,
			Signals:               []string{"logs"},
			Workers:               1,
			BatchSize:             2,
			maxBatches:            1,
			WarmupDuration:        150 * time.Millisecond,
			Duration:              250 * time.Millisecond,
			CallTimeout:           500 * time.Millisecond,
			SimulateThrottleEvery: 1,
			SimulateAckDelay:      time.Millisecond,
		}
		if normErr := cfg.Normalize(); normErr != nil {
			t.Fatalf("Normalize: %v", normErr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("unexpected hardErr: %v", hardErr)
		}
		if res.UnexpectedRows != 1 || res.MissingRows != 0 {
			t.Fatalf("missing=%d unexpected=%d, want 0/1 (warmup row replayed alongside steady rows)", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless(faultSim=true) = %v, want strict failure citing unexpected=1", lossErr)
		}
	})

	t.Run("WarmupDuplicateFailsWarmupGateEvenWithSteadyFaultSim", func(t *testing.T) {
		cfgPathLocal := filepath.Join(t.TempDir(), "collector-warmup-dup-faultsim.yaml")
		if wErr := os.WriteFile(cfgPathLocal, []byte(`
extensions:
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
    logs:
      table: otel_logs
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		bin := configureCollectorHelperEnv(t, "replay_all_delivered")
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()

		cfg := RunnerConfig{
			Mode:                  ModeCollector,
			CollectorBin:          bin,
			CollectorConfig:       cfgPathLocal,
			Signals:               []string{"logs"},
			Workers:               1,
			BatchSize:             2,
			WarmupDuration:        150 * time.Millisecond,
			Duration:              150 * time.Millisecond,
			SimulateThrottleEvery: 2,
			SimulateAckDelay:      time.Millisecond,
		}
		if normErr := cfg.Normalize(); normErr != nil {
			t.Fatalf("Normalize: %v", normErr)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr == nil || !strings.Contains(hardErr.Error(), "collector warmup failed gate") {
			t.Fatalf("expected warmup gate failure when warmup duplicates occur without active warmup faults, got hardErr=%v", hardErr)
		}
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

		// Verify standalone numeric/boolean env values on logs string fields stay strings in preflight.
		t.Setenv("TEST_LIVE_NUMERIC_TABLE", "20261120")
		t.Setenv("TEST_LIVE_NUMERIC_ATTR", "9001")
		const numericLogsYAML = `
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
    logs:
      table: "${env:TEST_LIVE_NUMERIC_TABLE}"
      log_name_attribute: "${env:TEST_LIVE_NUMERIC_ATTR}"
      labels:
        build: "${env:TEST_LIVE_NUMERIC_TABLE}"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		numLogsCfg := makeLiveCfg(t, numericLogsYAML)
		metaLogs, numLogsErr := validateCollectorPreflightConfigWithMeta(numLogsCfg, "logs")
		if numLogsErr != nil {
			t.Fatalf("validateCollectorPreflightConfigWithMeta(numeric logs.table) unexpected error: %v", numLogsErr)
		}
		if metaLogs.effectiveTable != "20261120" || metaLogs.effectiveLogsLogNameAttr != "9001" {
			t.Fatalf("meta = (table=%q, log_name_attr=%q), want (20261120, 9001)", metaLogs.effectiveTable, metaLogs.effectiveLogsLogNameAttr)
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

		// Bare ${VAR} and nested ${env:A:-${env:B}} fallbacks match Collector confmap rules in both helpers.
		for _, tc := range []struct {
			expr string
			want string
		}{
			{expr: "${LEAF}", want: "otel_logs_chained"},
			{expr: "${env:UNSET_A:-${env:LEAF}}", want: "otel_logs_chained"},
			{expr: "${env:UNSET_A:-${LEAF}}", want: "otel_logs_chained"},
			{expr: "${env:UNSET_A:-${env:UNSET_B:-nested_fallback}}", want: "nested_fallback"},
			{expr: "${env:LEAF:-${env:UNSET_B}}", want: "otel_logs_chained"},
		} {
			gotEnv, errEnv := resolveCollectorEnvStringWithLookup(tc.expr, lookup)
			if errEnv != nil || gotEnv != tc.want {
				t.Fatalf("resolveCollectorEnvStringWithLookup(%q) = (%q, %v), want (%q, nil)", tc.expr, gotEnv, errEnv, tc.want)
			}
			gotConf, okConf := resolveCollectorConfmapString(tc.expr, lookup)
			if !okConf || gotConf != tc.want {
				t.Fatalf("resolveCollectorConfmapString(%q) = (%q, %v), want (%q, true)", tc.expr, gotConf, okConf, tc.want)
			}
		}
		if _, err := resolveCollectorEnvStringWithLookup("${env:LEAF:-${file:/etc/passwd}}", lookup); err == nil || !strings.Contains(err.Error(), "unsupported collector config provider") {
			t.Fatalf("nested unsupported scheme in default error = %v, want unsupported collector config provider", err)
		}
		if _, err := resolveCollectorEnvStringWithLookup("${env:UNSET_A:-${env:UNCLOSED}", lookup); err == nil || !strings.Contains(err.Error(), "unclosed") {
			t.Fatalf("unclosed nested fallback error = %v, want unclosed error", err)
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

	maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()
	type joinKey struct {
		traceID     string
		spanID      string
		serviceName string
	}
	spans := make(map[joinKey]struct{}, wantSteady)
	for _, r := range fakeSrv.Rows("otel_spans") {
		if stNano, _ := r["start_time_unix_nano"].(int64); isWarmupEventTime(DefaultBaseTime, stNano) {
			if stNano >= maxWarmupNano {
				t.Fatalf("warmup span timestamp %d jumped outside phase-local window (>= %d)", stNano, maxWarmupNano)
			}
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
		if tNano, _ := r["time_unix_nano"].(int64); isWarmupEventTime(DefaultBaseTime, tNano) {
			if tNano >= maxWarmupNano {
				t.Fatalf("warmup log timestamp %d jumped outside phase-local window (>= %d)", tNano, maxWarmupNano)
			}
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
		if tNano, _ := r["time_unix_nano"].(int64); isWarmupEventTime(DefaultBaseTime, tNano) {
			if tNano >= maxWarmupNano {
				t.Fatalf("warmup metric timestamp %d jumped outside phase-local window (>= %d)", tNano, maxWarmupNano)
			}
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

	maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()

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
				if isWarmupEventTime(DefaultBaseTime, tsNano) {
					if tsNano >= maxWarmupNano {
						t.Fatalf("%s warmup row timestamp %d jumped outside phase-local window (>= %d)", sp.signal, tsNano, maxWarmupNano)
					}
					warmupCount++
				} else {
					steadyCount++
				}
			}
			if warmupCount == 0 {
				t.Fatalf("%s expected warmup rows with phase-local +%dus substep, got 0", sp.signal, warmupTimeSubstepNano/1000)
			}
			if steadyCount != wantSteady {
				t.Fatalf("%s steady rows = %d, want %d (warmup collided with steady range)",
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
		maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()
		var warmupRows, steadyRows []map[string]any
		for _, r := range fakeSrv.Rows("otel_spans") {
			tsNano, _ := r["start_time_unix_nano"].(int64)
			if isWarmupEventTime(DefaultBaseTime, tsNano) {
				if tsNano >= maxWarmupNano {
					t.Fatalf("warmup span timestamp %d jumped outside phase-local window (>= %d)", tsNano, maxWarmupNano)
				}
				warmupRows = append(warmupRows, r)
			} else {
				steadyRows = append(steadyRows, r)
			}
		}
		if len(warmupRows) == 0 {
			t.Fatalf("expected phase-local warmup spans when WarmupDuration=250ms, got 0 (steady=%d)", len(steadyRows))
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

	t.Run("PacedMultiWorkerPausedFirstReservationPreservesOrdinalAndParentLinks", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		var firstReserved atomic.Bool
		secondReached := make(chan struct{})
		var secondOnce sync.Once

		// Workers=2, TargetRate=20, BatchSize=5, Duration=400ms reserves totalBudget=8:
		// reservation 0 has batchRows=5 (slot 0 spans 0..4), reservation 1 has batchRows=3
		// (slot 1 spans 5..9 sliced to 5..7). Pausing reservation 0 after pacer lock release
		// must keep ordinal 0 paired with batchRows=5 so span 5's parent span 4 is not dropped.
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"traces"},
			Workers:         2,
			BatchSize:       5,
			TargetRate:      20,
			Duration:        400 * time.Millisecond,
			workerHook: func(_, _ int) {
				if firstReserved.CompareAndSwap(false, true) {
					select {
					case <-secondReached:
					case <-time.After(5 * time.Second):
					}
					time.Sleep(25 * time.Millisecond)
					return
				}
				secondOnce.Do(func() { close(secondReached) })
			},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake(paused reservation) hard=%v soft=%v", hardErr, softErr)
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
			t.Fatalf("trace count = %d (%v), want 2 complete traces", len(traceSizes), traceSizes)
		}
		for tid, sz := range traceSizes {
			if sz != 4 {
				t.Fatalf("trace %s span count = %d (%v), want 4", tid, sz, traceSizes)
			}
		}
	})
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
	if res.UniqueDeliveryVerified {
		t.Fatal("expected UniqueDeliveryVerified=false when identity-altering processor skips upstream SubmittedKeySet reconciliation")
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

func TestCollectorLiveWithoutAuthenticationSkipsAmbientADC(t *testing.T) {
	badADC := filepath.Join(t.TempDir(), "poisoned-adc-must-not-be-read.json")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", badADC)
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

	var (
		mu              sync.Mutex
		authHeadersSeen []string
		existingDS      = map[string]bool{"live_ds": true}
		datasetCreated  bool
		datasetDeleted  bool
		tableQueried    bool
	)
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeadersSeen = append(authHeadersSeen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
			mu.Lock()
			datasetCreated = true
			existingDS["ephemeral_ds_temp"] = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(&bigqueryapi.Dataset{
				DatasetReference: &bigqueryapi.DatasetReference{ProjectId: "live-noauth-proj", DatasetId: "ephemeral_ds_temp"},
				Location:         "US",
			})
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/"):
			dsName := filepath.Base(r.URL.Path)
			mu.Lock()
			exists := existingDS[dsName]
			mu.Unlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(&bigqueryapi.Dataset{
				DatasetReference: &bigqueryapi.DatasetReference{ProjectId: "live-noauth-proj", DatasetId: dsName},
				Location:         "US",
			})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries"):
			mu.Lock()
			tableQueried = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(&bigqueryapi.QueryResponse{
				JobComplete: true,
				Schema: &bigqueryapi.TableSchema{
					Fields: []*bigqueryapi.TableFieldSchema{
						{Name: "total_rows", Type: "INTEGER"},
						{Name: "total_logical_bytes", Type: "INTEGER"},
						{Name: "active_physical_bytes", Type: "INTEGER"},
						{Name: "long_term_physical_bytes", Type: "INTEGER"},
						{Name: "time_travel_physical_bytes", Type: "INTEGER"},
						{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
					},
				},
				Rows: []*bigqueryapi.TableRow{{F: []*bigqueryapi.TableCell{
					{V: "4"}, {V: "4096"}, {V: "2048"}, {V: "0"}, {V: "512"}, {V: "256"},
				}}},
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
			mu.Lock()
			datasetDeleted = true
			delete(existingDS, filepath.Base(r.URL.Path))
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer adminSrv.Close()

	cfgPath := filepath.Join(t.TempDir(), "collector-noauth.yaml")
	rawYAML := fmt.Sprintf(`
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
    project: live-noauth-proj
    dataset: placeholder_ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, adminSrv.URL)
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "live_ok")
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		ProjectID:          "live-noauth-proj",
		DatasetID:          "live_ds",
		Location:           "US",
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           400 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rep, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run(without_authentication=true with admin_url): %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].ByteLayers == nil || rep.Results[0].ByteLayers.BQTotalRows != 4 || rep.Results[0].ByteLayers.BQStorageQueryNote != "" {
		t.Fatalf("unexpected TABLE_STORAGE ByteLayers: %+v", rep.Results)
	}
	// Verify validateRunConfig propagates endpoint.without_authentication into RunnerConfig
	// and ephemeral dataset helpers honor it without ambient ADC.
	ephCfg := cfg
	ephCfg.DatasetID = "ephemeral_ds_temp"
	if vErr := validateRunConfig(ctx, &ephCfg, nil); vErr != nil {
		t.Fatalf("validateRunConfig(without_authentication=true): %v", vErr)
	}
	if !ephCfg.collectorWithoutAuth || ephCfg.collectorAdminURL != adminSrv.URL+"/bigquery/v2/" {
		t.Fatalf("validateRunConfig propagated (withoutAuth=%v, adminURL=%q), want (true, %q)",
			ephCfg.collectorWithoutAuth, ephCfg.collectorAdminURL, adminSrv.URL+"/bigquery/v2/")
	}
	ephOpts, closeEphOpts, optErr := buildLiveRESTClientOptions(ctx, ephCfg, "", nil)
	if optErr != nil {
		t.Fatalf("buildLiveRESTClientOptions(collectorWithoutAuth): %v", optErr)
	}
	defer closeEphOpts()
	if cErr := createEphemeralDataset(ctx, ephCfg.ProjectID, ephCfg.DatasetID, ephCfg.Location, ephOpts...); cErr != nil {
		t.Fatalf("createEphemeralDataset(without_authentication=true): %v", cErr)
	}
	if dErr := DeleteDatasetWithContents(ctx, ephCfg.ProjectID, ephCfg.DatasetID, ephOpts...); dErr != nil {
		t.Fatalf("DeleteDatasetWithContents(without_authentication=true): %v", dErr)
	}
	mu.Lock()
	defer mu.Unlock()
	if !datasetCreated || !datasetDeleted || !tableQueried {
		t.Fatalf("missing REST calls: created=%v deleted=%v queried=%v", datasetCreated, datasetDeleted, tableQueried)
	}
	for i, authHdr := range authHeadersSeen {
		if authHdr != "" {
			t.Fatalf("REST call %d unexpectedly included Authorization header %q", i, authHdr)
		}
	}

	t.Run("ConflictingWithoutAuthenticationAcrossSignalsFails", func(t *testing.T) {
		noAuthLogsPath := filepath.Join(t.TempDir(), "collector-conflict.yaml")
		conflictYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery/logs:
    project: live-noauth-proj
    dataset: ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      insecure: true
      admin_url: %[1]s/bigquery/v2/
      without_authentication: true
  bigquery/traces:
    project: live-noauth-proj
    dataset: ds
    location: US
    endpoint:
      admin_url: %[1]s/bigquery/v2/
      without_authentication: false
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, adminSrv.URL)
		if wErr := os.WriteFile(noAuthLogsPath, []byte(conflictYAML), 0o600); wErr != nil {
			t.Fatalf("write conflict config: %v", wErr)
		}
		conflictCfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       bin,
			CollectorConfig:    noAuthLogsPath,
			ProjectID:          "live-noauth-proj",
			DatasetID:          "ds",
			Location:           "US",
			Signals:            []string{"logs", "traces"},
			Workers:            1,
			BatchSize:          4,
			Duration:           time.Second,
		}
		if vErr := validateRunConfig(ctx, &conflictCfg, nil); vErr == nil || !strings.Contains(vErr.Error(), "conflicting collector endpoint.without_authentication") {
			t.Fatalf("validateRunConfig error = %v, want conflicting collector endpoint.without_authentication", vErr)
		}
	})
}

func TestRewriteCollectorLoopbackConfigIsolatesFakeModeTelemetry(t *testing.T) {
	baseYAML := []byte(`
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
    project: p
    dataset: d
    location: US
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: warn
      encoding: json
      output_paths: ["/tmp/operator-telemetry.log"]
      error_output_paths: ["/tmp/operator-telemetry-err.log"]
      processors:
        - simple:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: http://127.0.0.1:4318/v1/logs
    traces:
      level: normal
      processors:
        - simple:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: http://127.0.0.1:4318/v1/traces
    metrics:
      level: detailed
      address: 0.0.0.0:8888
      readers:
        - periodic:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: http://127.0.0.1:4318/v1/metrics
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`)
	cfg := RunnerConfig{Mode: ModeCollector}
	rewrittenFake, _, err := rewriteCollectorLoopbackConfig(baseYAML, cfg, "logs", collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		metricsHost: "127.0.0.1",
		metricsPort: 8889,
		storageRoot: "preflight",
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
		dryRun:      true,
	})
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig(useBQFake=true): %v", err)
	}
	var fakeDoc map[string]any
	if uErr := yaml.Unmarshal(rewrittenFake, &fakeDoc); uErr != nil {
		t.Fatalf("unmarshal fake rewritten YAML: %v", uErr)
	}
	svc := fakeDoc["service"].(map[string]any)
	telem := svc["telemetry"].(map[string]any)
	if _, hasTraces := telem["traces"]; hasTraces {
		t.Fatalf("expected service.telemetry.traces deleted in fake mode, got %v", telem["traces"])
	}
	logsCfg := telem["logs"].(map[string]any)
	if _, hasProcs := logsCfg["processors"]; hasProcs {
		t.Fatalf("expected service.telemetry.logs.processors deleted in fake mode, got %v", logsCfg["processors"])
	}
	if logsCfg["level"] != "warn" || logsCfg["encoding"] != "json" {
		t.Fatalf("expected scalar level/encoding preserved, got %v", logsCfg)
	}
	for _, pathKey := range []string{"output_paths", "error_output_paths"} {
		gotPaths, _ := extractYAMLStringSlice(logsCfg[pathKey])
		if !slices.Equal(gotPaths, []string{"stderr"}) {
			t.Fatalf("%s = %v, want [stderr]", pathKey, gotPaths)
		}
	}
	metricsCfg := telem["metrics"].(map[string]any)
	if _, hasAddr := metricsCfg["address"]; hasAddr {
		t.Fatalf("expected deprecated service.telemetry.metrics.address stripped, got %v", metricsCfg["address"])
	}
	readers, _ := metricsCfg["readers"].([]any)
	if len(readers) != 1 {
		t.Fatalf("len(metrics.readers) = %d, want 1 loopback prometheus pull reader", len(readers))
	}

	// Non-inline external provider reference inside service.telemetry.logs/traces must fail closed.
	for _, badKey := range []string{"logs: ${file:/tmp/logs.yaml}", "traces: ${file:/tmp/traces.yaml}"} {
		var badYAML string
		if badKey == "logs: ${file:/tmp/logs.yaml}" {
			badYAML = strings.Replace(string(baseYAML), "    logs:\n      level: warn\n      encoding: json\n      output_paths: [\"/tmp/operator-telemetry.log\"]\n      error_output_paths: [\"/tmp/operator-telemetry-err.log\"]\n      processors:\n        - simple:\n            exporter:\n              otlp:\n                protocol: http/protobuf\n                endpoint: http://127.0.0.1:4318/v1/logs", "    logs: ${file:/tmp/logs.yaml}", 1)
		} else {
			badYAML = strings.Replace(string(baseYAML), "    traces:\n      level: normal\n      processors:\n        - simple:\n            exporter:\n              otlp:\n                protocol: http/protobuf\n                endpoint: http://127.0.0.1:4318/v1/traces", "    traces: ${file:/tmp/traces.yaml}", 1)
		}
		if _, _, badErr := rewriteCollectorLoopbackConfig([]byte(badYAML), cfg, "logs", collectorEndpointOverride{
			otlpAddr: "127.0.0.1:4317", storageRoot: "preflight", useBQFake: true, fakeGRPCURL: "127.0.0.1:50051", fakeRESTURL: "http://127.0.0.1:8080", dryRun: true,
		}); badErr == nil {
			t.Fatalf("expected error for non-map %s, got nil", badKey)
		}
	}
}

func TestCollectorIntegrationFakeModeIsolatesCollectorDiagnostics(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	var (
		mu           sync.Mutex
		externalHits int
		hitPaths     []string
	)
	telemetrySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		externalHits++
		hitPaths = append(hitPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer telemetrySrv.Close()

	tmpDir := t.TempDir()
	logOutPath := filepath.Join(tmpDir, "operator_internal.log")
	errOutPath := filepath.Join(tmpDir, "operator_internal_err.log")
	cfgPath := filepath.Join(tmpDir, "collector-telemetry-isolation.yaml")
	rawYAML := fmt.Sprintf(`
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
    timeout: 20ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
service:
  extensions: [health_check]
  telemetry:
    logs:
      level: info
      output_paths: [%[2]q]
      error_output_paths: [%[3]q]
      processors:
        - simple:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: %[1]s/v1/logs
    traces:
      level: normal
      processors:
        - simple:
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: %[1]s/v1/traces
    metrics:
      level: detailed
      readers:
        - periodic:
            interval: 50
            exporter:
              otlp:
                protocol: http/protobuf
                endpoint: %[1]s/v1/metrics
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`, telemetrySrv.URL, logOutPath, errOutPath)
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: false,
		CollectorBin:       collectorBin,
		CollectorConfig:    cfgPath,
		Signals:            []string{"logs"},
		WorkloadProfile:    WorkloadProfileAccessLogs,
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           5 * time.Second,
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
	if res.DeliveredRows != 4 || res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 {
		t.Fatalf("unexpected delivery/telemetry: delivered=%d submitted=%d acked=%d, want 4/4/4",
			res.DeliveredRows, res.RecordsSubmitted, res.Telemetry.AcknowledgedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
	mu.Lock()
	gotHits := externalHits
	gotPaths := slices.Clone(hitPaths)
	mu.Unlock()
	if gotHits != 0 {
		t.Fatalf("fake mode leaked %d internal collector telemetry requests to external server (paths=%v)", gotHits, gotPaths)
	}
	for _, p := range []string{logOutPath, errOutPath} {
		if _, statErr := os.Stat(p); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("expected operator telemetry log file %q not to be written in fake mode, stat err=%v", p, statErr)
		}
	}
}

func TestCollectorIntegrationMissingLogReplayObservedTimeAndSubstitutionFailsLossless(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	obsFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "observed_time_unix_nano")

	cfgPath := filepath.Join(t.TempDir(), "collector-reconcile.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
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

	t.Run("ObservedTimeReplay", func(t *testing.T) {
		prevMin := collectorMinDrainTimeout
		collectorMinDrainTimeout = 300 * time.Millisecond
		t.Cleanup(func() { collectorMinDrainTimeout = prevMin })

		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		var (
			hookMu    sync.Mutex
			seenFirst []byte
			seenCount int
			replaced  bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			if seenFirst == nil {
				seenFirst = slices.Clone(serialized[0])
			}
			nextCount := seenCount + len(serialized)
			if !replaced && nextCount >= 4 {
				idx := 4 - seenCount - 1
				mut := slices.Clone(serialized)
				mut[idx] = bumpProtoVarintField(t, seenFirst, obsFieldNum, 1_000_000)
				replaced = true
				seenCount = nextCount
				return mut
			}
			seenCount = nextCount
			return serialized
		})

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			WorkloadProfile: WorkloadProfileAccessLogs,
			Workers:         1,
			BatchSize:       4,
			maxBatches:      1,
			Duration:        5 * time.Second,
			CallTimeout:     300 * time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr == nil {
			t.Fatal("runCollectorSingleSignalWithFake(ObservedTimeReplay) hardErr = nil, want drain/lossless failure")
		}
		if res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 {
			t.Fatalf("submitted=%d acked=%d, want 4/4", res.RecordsSubmitted, res.Telemetry.AcknowledgedRows)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 3 || res.Telemetry.ReplayedRows != 1 {
			t.Fatalf("verified=%v delivered=%d replayed=%d, want true/3/1",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.Telemetry.ReplayedRows)
		}
		if res.MissingRows != 1 || res.UnexpectedRows != 0 {
			t.Fatalf("missing=%d unexpected=%d, want 1/0", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "delivered=3") || !strings.Contains(lossErr.Error(), "replayed=1") || !strings.Contains(lossErr.Error(), "missing=1") {
			t.Fatalf("checkSignalResultLossless = %v, want delivered=3, replayed=1, missing=1", lossErr)
		}
	})

	t.Run("RowSubstitution", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		rogueRow := encodeRogueSubstitutionLogRow(t, logEnc, "id1:0000000000000000")
		var (
			hookMu    sync.Mutex
			seenCount int
			replaced  bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			nextCount := seenCount + len(serialized)
			if !replaced && nextCount >= 4 {
				idx := 4 - seenCount - 1
				mut := slices.Clone(serialized)
				mut[idx] = rogueRow
				replaced = true
				seenCount = nextCount
				return mut
			}
			seenCount = nextCount
			return serialized
		})

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			WorkloadProfile: WorkloadProfileAccessLogs,
			Workers:         1,
			BatchSize:       4,
			maxBatches:      1,
			Duration:        5 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 || res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("submitted=%d acked=%d delivered=%d replayed=%d, want 4/4/4/0",
				res.RecordsSubmitted, res.Telemetry.AcknowledgedRows, res.DeliveredRows, res.Telemetry.ReplayedRows)
		}
		if res.MissingRows != 1 || res.UnexpectedRows != 1 {
			t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
		}
	})
}

func TestCollectorIntegrationNonIdentityAttributeUpsertKeepsReconciliationActive(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "collector-non-identity-upsert.yaml")
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
  attributes/bench_label:
    actions:
      - key: benchmark.label
        value: bench-tag
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/bench_label, batch]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	t.Run("CleanDelivery", func(t *testing.T) {
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
			UpstreamInsertID: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.RecordsSubmitted != 4 {
			t.Fatalf("verified=%v delivered=%d submitted=%d, want true/4/4",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.RecordsSubmitted)
		}
		if res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("missing=%d unexpected=%d, want 0/0", res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
	})

	t.Run("DropPlusRogueSubstitutionFailsLossless", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		rogueRow := encodeRogueSubstitutionLogRow(t, logEnc, "rogue-subst-99")
		var (
			hookMu    sync.Mutex
			seenCount int
			replaced  bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			nextCount := seenCount + len(serialized)
			if !replaced && nextCount >= 4 {
				idx := 4 - seenCount - 1
				mut := slices.Clone(serialized)
				mut[idx] = rogueRow
				replaced = true
				seenCount = nextCount
				return mut
			}
			seenCount = nextCount
			return serialized
		})

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
			UpstreamInsertID: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.RecordsSubmitted != 4 {
			t.Fatalf("verified=%v delivered=%d submitted=%d, want true/4/4",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.RecordsSubmitted)
		}
		if res.MissingRows != 1 || res.UnexpectedRows != 1 {
			t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
		}
	})
}

func TestCollectorPipelineIdentityEffectAndSanitizeDiagnostics(t *testing.T) {
	t.Run("PipelineIdentityEffectClassification", func(t *testing.T) {
		for _, tc := range []struct {
			name         string
			signal       string
			yamlBody     string
			logNameAttr  string
			insertIDAttr string
			wantAlters   bool
			wantModifies bool
		}{
			{
				name: "non_identity_upsert_insert_update_delete_hash_convert_with_include_exclude",
				yamlBody: `
processors:
  resource/tag:
    include:
      match_type: strict
      attributes:
        - key: deployment.environment
          value: prod
    attributes:
      - key: service.namespace
        value: checkout
        action: upsert
      - key: legacy.tag
        action: delete
  attributes/bench:
    exclude:
      match_type: regexp
      services: ["ignored.*"]
    actions:
      - key: benchmark.label
        value: bench-tag
        action: upsert
      - key: http.route
        action: insert
        value: /v1/health
      - key: request.id
        action: update
        from_attribute: corr.id
      - key: user.email
        action: hash
      - pattern: ^custom\.num\..*
        action: convert
        converted_type: string
  transform/non_id:
    log_statements:
      - context: log
        statements:
          - set(attributes["bench.tag"], "enabled")
          - delete_key(attributes, "tmp.scratch")
          - delete_matching_keys(attributes, "^debug\\.")
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [resource/tag, attributes/bench, transform/non_id, batch]
      exporters: [bigquery]
`,
				wantAlters:   false,
				wantModifies: true,
			},
			{
				name: "extract_action_fails_closed",
				yamlBody: `
processors:
  attributes/extract:
    actions:
      - key: body.raw
        pattern: ^(?P<extracted_field>.+)$
        action: extract
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/extract, batch]
      exporters: [bigquery]
`,
				wantAlters:   true,
				wantModifies: true,
			},
			{
				name: "missing_key_and_pattern_fails_closed",
				yamlBody: `
processors:
  attributes/no_target:
    actions:
      - action: delete
        value: stray
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/no_target, batch]
      exporters: [bigquery]
`,
				wantAlters:   true,
				wantModifies: true,
			},
			{
				name:         "custom_log_name_attribute_mutation_detected",
				logNameAttr:  "custom.log_name",
				insertIDAttr: "custom.insert_id",
				yamlBody: `
processors:
  attributes/custom_log:
    actions:
      - key: custom.log_name
        value: override
        action: upsert
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/custom_log, batch]
      exporters: [bigquery]
`,
				wantAlters:   true,
				wantModifies: true,
			},
			{
				name: "transform_touching_service_name_fails_closed",
				yamlBody: `
processors:
  transform/res:
    log_statements:
      - context: resource
        statements:
          - set(attributes["service.name"], "spoofed")
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [transform/res, batch]
      exporters: [bigquery]
`,
				wantAlters:   true,
				wantModifies: true,
			},
			{
				name: "transform_nested_set_fails_closed",
				yamlBody: `
processors:
  transform/nested:
    log_statements:
      - context: log
        statements:
          - set(attributes["safe"], set(attributes["log.iostream"], "stderr"))
`,
				wantAlters:   true,
				wantModifies: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(tc.yamlBody), &doc); err != nil {
					t.Fatalf("yaml.Unmarshal: %v", err)
				}
				procMap, _ := doc["processors"].(map[string]any)
				var procIDs []string
				for id := range procMap {
					procIDs = append(procIDs, id)
				}
				sig := tc.signal
				if sig == "" {
					sig = "logs"
				}
				got := collectorPipelineIdentityEffect(sig, procIDs, procMap, tc.logNameAttr, tc.insertIDAttr)
				if got.altersIdentityKeys != tc.wantAlters || got.modifiesNonIdentityAttrs != tc.wantModifies {
					t.Fatalf("collectorPipelineIdentityEffect = %+v, want alters=%v modifies=%v",
						got, tc.wantAlters, tc.wantModifies)
				}
			})
		}
	})

	t.Run("PipelineIdentityEffectSimulation", func(t *testing.T) {
		hvYAML, err := os.ReadFile(resolveCollectorConfigPath(filepath.Join("example", "otel-collector-high-volume-logs.yaml")))
		if err != nil {
			t.Fatalf("read high-volume logs example: %v", err)
		}
		var hvDoc map[string]any
		if err := yaml.Unmarshal(hvYAML, &hvDoc); err != nil {
			t.Fatalf("yaml.Unmarshal(hv): %v", err)
		}
		hvProcMap, _ := hvDoc["processors"].(map[string]any)
		hvPipe := hvDoc["service"].(map[string]any)["pipelines"].(map[string]any)["logs"].(map[string]any)
		hvProcIDs, err := extractYAMLStringSlice(hvPipe["processors"])
		if err != nil {
			t.Fatalf("extractYAMLStringSlice(hv): %v", err)
		}
		hvImpact := collectorPipelineIdentityEffect("logs", hvProcIDs, hvProcMap, "", "")
		if hvImpact.altersIdentityKeys || !hvImpact.modifiesNonIdentityAttrs || !hvImpact.canSimulate || len(hvImpact.ops) != 9 {
			t.Fatalf("high-volume logs impact = %+v (len(ops)=%d), want alters=false modifies=true canSimulate=true ops=9",
				hvImpact, len(hvImpact.ops))
		}

		for _, tc := range []struct {
			name        string
			yamlBody    string
			wantSim     bool
			wantOpCount int
		}{
			{
				name: "deterministic_scalar_ops_simulatable",
				yamlBody: `
processors:
  resource/add:
    attributes:
      - key: deploy.env
        value: staging
        action: insert
  attributes/tag:
    actions:
      - key: bench.label
        value: smoke
        action: upsert
      - key: bench.existing
        value: updated
        action: update
  transform/set:
    log_statements:
      - context: log
        statements:
          - set(attributes["ottl.tag"], "v1")
  batch: {}
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [resource/add, attributes/tag, transform/set, batch]
      exporters: [bigquery]
`,
				wantSim:     true,
				wantOpCount: 4,
			},
			{
				name: "hash_action_unsimulatable",
				yamlBody: `
processors:
  attributes/hash:
    actions:
      - key: user.email
        action: hash
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/hash]
      exporters: [bigquery]
`,
				wantSim:     false,
				wantOpCount: 0,
			},
			{
				name: "include_filter_unsimulatable",
				yamlBody: `
processors:
  attributes/filtered:
    include:
      match_type: strict
      attributes:
        - key: deployment.environment
          value: prod
    actions:
      - key: bench.label
        value: prod
        action: upsert
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/filtered]
      exporters: [bigquery]
`,
				wantSim:     false,
				wantOpCount: 0,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(tc.yamlBody), &doc); err != nil {
					t.Fatalf("yaml.Unmarshal: %v", err)
				}
				procMap, _ := doc["processors"].(map[string]any)
				pipe := doc["service"].(map[string]any)["pipelines"].(map[string]any)["logs"].(map[string]any)
				procIDs, _ := extractYAMLStringSlice(pipe["processors"])
				got := collectorPipelineIdentityEffect("logs", procIDs, procMap, "", "")
				if got.altersIdentityKeys || !got.modifiesNonIdentityAttrs || got.canSimulate != tc.wantSim || len(got.ops) != tc.wantOpCount {
					t.Fatalf("impact = %+v (len(ops)=%d), want alters=false modifies=true canSimulate=%v ops=%d",
						got, len(got.ops), tc.wantSim, tc.wantOpCount)
				}
			})
		}

		envMap := map[string]string{
			"BENCH_REVIEW_REGION": "west",
			"BENCH_SHARDS":        "42",
			"BENCH_ID_KEY":        "service.name",
			"BENCH_EMPTY":         "",
		}
		lookupEnv := func(k string) (string, bool) {
			v, ok := envMap[k]
			return v, ok
		}

		t.Run("env_expanded_values_and_escaped_dollar_simulate_accurately", func(t *testing.T) {
			const yamlBody = `
processors:
  attributes/env:
    actions:
      - key: benchmark.region
        value: ${env:BENCH_REVIEW_REGION}
        action: upsert
      - key: benchmark.shards
        value: ${env:BENCH_SHARDS}
        action: upsert
      - key: benchmark.fallback
        value: ${env:BENCH_UNSET:-east}
        action: insert
      - key: benchmark.cost
        value: $$10
        action: upsert
      - key: benchmark.bare_region
        value: ${BENCH_REVIEW_REGION}
        action: upsert
      - key: benchmark.nested_fallback
        value: ${env:BENCH_UNSET:-${env:BENCH_REVIEW_REGION}}
        action: upsert
      - key: benchmark.nested_shards
        value: ${env:BENCH_UNSET:-${BENCH_SHARDS}}
        action: upsert
  transform/env:
    log_statements:
      - context: log
        statements:
          - set(attributes["ottl.region"], "${env:BENCH_REVIEW_REGION}")
          - set(attributes["ottl.bare_region"], "${BENCH_REVIEW_REGION}")
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/env, transform/env]
      exporters: [bigquery]
`
			var doc map[string]any
			if err := yaml.Unmarshal([]byte(yamlBody), &doc); err != nil {
				t.Fatalf("yaml.Unmarshal: %v", err)
			}
			procMap, _ := doc["processors"].(map[string]any)
			pipe := doc["service"].(map[string]any)["pipelines"].(map[string]any)["logs"].(map[string]any)
			procIDs, _ := extractYAMLStringSlice(pipe["processors"])
			got := collectorPipelineIdentityEffectWithLookup("logs", procIDs, procMap, "", "", lookupEnv)
			if got.altersIdentityKeys || !got.modifiesNonIdentityAttrs || !got.canSimulate || len(got.ops) != 9 {
				t.Fatalf("impact = %+v (len(ops)=%d), want alters=false modifies=true canSimulate=true ops=9",
					got, len(got.ops))
			}
			if got.ops[0].value != "west" || got.ops[1].value != int(42) || got.ops[2].value != "east" ||
				got.ops[3].value != "$10" || got.ops[4].value != "west" || got.ops[5].value != "west" ||
				got.ops[6].value != int(42) || got.ops[7].value != "west" || got.ops[8].value != "west" {
				t.Fatalf("unexpected resolved op values: %#v", got.ops)
			}
		})

		for _, tc := range []struct {
			name         string
			yamlBody     string
			wantAltersID bool
		}{
			{
				name: "env_expanded_key_resolving_to_service_name_alters_identity",
				yamlBody: `
processors:
  resource/env_id:
    attributes:
      - key: ${env:BENCH_ID_KEY}
        value: spoofed
        action: upsert
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [resource/env_id]
      exporters: [bigquery]
`,
				wantAltersID: true,
			},
			{
				name: "file_scheme_fails_closed",
				yamlBody: `
processors:
  attributes/file:
    actions:
      - key: benchmark.region
        value: ${file:/tmp/region.txt}
        action: upsert
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/file]
      exporters: [bigquery]
`,
			},
			{
				name: "bare_var_default_without_env_scheme_fails_closed",
				yamlBody: `
processors:
  attributes/bare_default:
    actions:
      - key: benchmark.region
        value: ${BENCH_UNSET:-fallback}
        action: upsert
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/bare_default]
      exporters: [bigquery]
`,
			},
			{
				name: "empty_standalone_env_var_fails_closed",
				yamlBody: `
processors:
  attributes/empty:
    actions:
      - key: benchmark.region
        value: ${env:BENCH_EMPTY}
        action: upsert
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/empty]
      exporters: [bigquery]
`,
			},
			{
				name: "ottl_file_scheme_fails_closed",
				yamlBody: `
processors:
  transform/file:
    log_statements:
      - context: log
        statements:
          - set(attributes["ottl.region"], "${file:/tmp/region.txt}")
service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [transform/file]
      exporters: [bigquery]
`,
				wantAltersID: true,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(tc.yamlBody), &doc); err != nil {
					t.Fatalf("yaml.Unmarshal: %v", err)
				}
				procMap, _ := doc["processors"].(map[string]any)
				pipe := doc["service"].(map[string]any)["pipelines"].(map[string]any)["logs"].(map[string]any)
				procIDs, _ := extractYAMLStringSlice(pipe["processors"])
				got := collectorPipelineIdentityEffectWithLookup("logs", procIDs, procMap, "", "", lookupEnv)
				if got.altersIdentityKeys != tc.wantAltersID || !got.modifiesNonIdentityAttrs || got.canSimulate || len(got.ops) != 0 {
					t.Fatalf("impact = %+v (len(ops)=%d), want alters=%v modifies=true canSimulate=false ops=0",
						got, len(got.ops), tc.wantAltersID)
				}
			})
		}

		for _, badVal := range []any{"${env:UNCLOSED", "${env:${BENCH_REVIEW_REGION}}", "${yaml:x}", "${env:BENCH_EMPTY}", "${BENCH_UNSET:-fallback}", "${env:UNSET:-${env:UNCLOSED}"} {
			if gotVal, ok := resolveCollectorConfmapActionValue(badVal, lookupEnv); ok {
				t.Fatalf("resolveCollectorConfmapActionValue(%#v) = (%#v, true), want ok=false", badVal, gotVal)
			}
		}
	})

	t.Run("SanitizeCollectorDiagnosticsUnitAndErrorPaths", func(t *testing.T) {
		pastedCreds := `{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nSECRET_PEM_BODY\n-----END PRIVATE KEY-----\n","client_email":"sa-secret@proj.iam.gserviceaccount.com"}`
		unsupportedJSON := `{"type":"SECRET_CUSTOM_CRED_TYPE","client_secret":"SECRET_CLIENT_VAL","refresh_token":"SECRET_REFRESH_VAL"}`
		creds := bigqueryexporter.CredentialsConfig{
			File:                      pastedCreds,
			JSON:                      configopaque.String(unsupportedJSON),
			ImpersonateServiceAccount: "impersonated-secret@proj.iam.gserviceaccount.com",
		}

		var diag boundedDiagBuffer
		diag.SetCredentialRedactions(creds, "/var/run/secrets/extra-adc-creds.json")
		rawLog := strings.Join([]string{
			`{"level":"error","msg":"start failed","error":"reading credentials file: open ` + strings.ReplaceAll(strings.ReplaceAll(pastedCreds, `"`, `\"`), "\n", `\\n`) + `: no such file or directory"}`,
			`Error: loading credentials file "/tmp/secret-sa-file.json": credentials file "/tmp/secret-sa-file.json" has unsupported type "SECRET_FALLBACK_TYPE"`,
			`CreateFile ` + pastedCreds + `: The filename, directory name, or volume label syntax is incorrect.`,
			`Authorization: Bearer tok_test_bearer_marker_123456`,
			`impersonate=impersonated-secret@proj.iam.gserviceaccount.com client_secret=SECRET_CLIENT_VAL`,
			`benign: listen tcp 127.0.0.1:4317: bind: address already in use (otel_logs)`,
		}, "\n")
		_, _ = diag.Write([]byte(rawLog))

		clean := diag.String()
		for _, forbidden := range []string{
			"SECRET_PEM_BODY",
			"PRIVATE KEY",
			"sa-secret@proj.iam.gserviceaccount.com",
			"SECRET_CUSTOM_CRED_TYPE",
			"SECRET_CLIENT_VAL",
			"SECRET_REFRESH_VAL",
			"impersonated-secret@proj.iam.gserviceaccount.com",
			"SECRET_FALLBACK_TYPE",
			"/tmp/secret-sa-file.json",
			"tok_test_bearer_marker_123456",
		} {
			if strings.Contains(clean, forbidden) {
				t.Fatalf("sanitized diag leaked %q:\n%s", forbidden, clean)
			}
		}
		for _, wantKept := range []string{
			"[REDACTED]",
			"no such file or directory",
			"The filename, directory name, or volume label syntax is incorrect.",
			"listen tcp 127.0.0.1:4317: bind: address already in use (otel_logs)",
		} {
			if !strings.Contains(clean, wantKept) {
				t.Fatalf("sanitized diag dropped expected diagnostic substring %q:\n%s", wantKept, clean)
			}
		}

		// Verify all error wrappers (startup, readiness exit, drain, shutdown) propagate sanitized diag only.
		exitErr := formatCollectorExitErr("collector exited before becoming ready", errors.New("exit status 1"), &diag)
		drainErr := formatCollectorExitErr("collector exited during pipeline drain", errors.New("exit status 1"), &diag)
		doneCh := make(chan struct{})
		close(doneCh)
		fakeWaitErr := errors.New("exit status 2")
		readyExitErr := waitCollectorReady(t.Context(), doneCh, &fakeWaitErr, &diag, "127.0.0.1:1", "/ready", "", "127.0.0.1:1", false)
		_, shutdownErr := finalizeCollectorShutdown(nil, doneCh, &fakeWaitErr, nil, &diag)
		for name, gotErr := range map[string]error{
			"formatCollectorExitErr_ready": exitErr,
			"formatCollectorExitErr_drain": drainErr,
			"waitCollectorReady":           readyExitErr,
			"finalizeCollectorShutdown":    shutdownErr,
		} {
			if gotErr == nil {
				t.Fatalf("%s returned nil error", name)
			}
			msg := gotErr.Error()
			for _, forbidden := range []string{"SECRET_PEM_BODY", "SECRET_CUSTOM_CRED_TYPE", "tok_test_bearer_marker_123456"} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("%s leaked %q in error:\n%s", name, forbidden, msg)
				}
			}
		}
	})

	t.Run("EndpointURLAndAdminURLRedaction", func(t *testing.T) {
		ep := bigqueryexporter.EndpointConfig{
			URL:      "https://epuser:secret_ep_pass@write-private.example.test:443/v2?k=ab&token=secret_ep_tok",
			AdminURL: "https://aduser:secret_admin_pass@admin-private.example.test:8443/bigquery/v2?x=12&sig=secret_admin_sig",
		}
		extracted := collectEndpointURLSecrets(ep)
		for _, want := range []string{
			ep.URL,
			ep.AdminURL,
			"epuser",
			"secret_ep_pass",
			"secret_ep_tok",
			"aduser",
			"secret_admin_pass",
			"secret_admin_sig",
		} {
			if !slices.Contains(extracted, want) {
				t.Fatalf("collectEndpointURLSecrets missing %q in %v", want, extracted)
			}
		}
		for _, trivial := range []string{"ab", "12"} {
			if slices.Contains(extracted, trivial) {
				t.Fatalf("collectEndpointURLSecrets should skip <4-char query value %q: %v", trivial, extracted)
			}
		}

		var diag boundedDiagBuffer
		diag.SetCredentialRedactions(bigqueryexporter.CredentialsConfig{}, extracted...)
		rawLines := strings.Join([]string{
			fmt.Sprintf(`{"level":"error","msg":"metadata request failed","admin_url":%q}`, ep.AdminURL),
			fmt.Sprintf(`dial tcp failed url=%s pass=secret_admin_pass sig=secret_admin_sig ep_pass=secret_ep_pass ep_tok=secret_ep_tok`, ep.URL),
			`benign line keeps ab and 12 intact`,
		}, "\n")
		_, _ = diag.Write([]byte(rawLines))
		clean := diag.String()
		for _, forbidden := range []string{
			ep.AdminURL,
			ep.URL,
			"admin-private.example.test",
			"write-private.example.test",
			"aduser",
			"secret_admin_pass",
			"secret_admin_sig",
			"epuser",
			"secret_ep_pass",
			"secret_ep_tok",
		} {
			if strings.Contains(clean, forbidden) {
				t.Fatalf("sanitized diag leaked %q:\n%s", forbidden, clean)
			}
		}
		if !strings.Contains(clean, "benign line keeps ab and 12 intact") {
			t.Fatalf("sanitized diag corrupted short benign text:\n%s", clean)
		}
	})

	t.Run("BoundedDiagBufferBoundaryTruncationAndOverlongLines", func(t *testing.T) {
		const secret25 = "MYSECRET_VAL_BOUNDARY_25"
		// Verify zero substrings (>=8 chars) of secret25 leak at 64 KiB boundaries.
		assertNoSecretFragments := func(t *testing.T, label, text, secret string) {
			t.Helper()
			if strings.Contains(text, secret[:8]) || strings.Contains(text, secret[len(secret)-8:]) || strings.Contains(text, secret) {
				t.Fatalf("%s leaked secret fragment from %q:\n%s", label, secret, text)
			}
		}

		// 1 & 2. Straddle the 64 KiB collectorMaxDiagBytes boundary right through the middle of secret25,
		// both single-write and chunked writes.
		fillLine := strings.Repeat("b", 127) + "\n" // 128 bytes/line
		// 511*128 + 83 = 65,491 bytes; prefix `{"level":"error","client_secret":"` (34B) reaches 65,525,
		// so secret25 (24B) spans bytes 65,525..65,549 and sanitized line overflows 65,536 cleanly.
		fillBlock := strings.Repeat(fillLine, 511) + strings.Repeat("c", 82) + "\n"
		secretLine := fmt.Sprintf(`{"level":"error","client_secret":"%s","msg":"fail"}`+"\n", secret25)

		for _, chunkSize := range []int{0, 13, 1} {
			var buf boundedDiagBuffer
			payload := fillBlock + secretLine
			if chunkSize == 0 {
				_, _ = buf.Write([]byte(payload))
			} else {
				for off := 0; off < len(payload); off += chunkSize {
					end := min(len(payload), off+chunkSize)
					_, _ = buf.Write([]byte(payload[off:end]))
				}
			}
			got := buf.String()
			assertNoSecretFragments(t, fmt.Sprintf("chunkSize=%d", chunkSize), got, secret25)
			if !strings.Contains(got, "[diagnostics truncated]") {
				t.Fatalf("chunkSize=%d expected [diagnostics truncated], tail=%q", chunkSize, got[max(0, len(got)-80):])
			}
			exitMsg := formatCollectorExitErr("collector exited", errors.New("exit status 1"), &buf).Error()
			assertNoSecretFragments(t, fmt.Sprintf("formatExit chunkSize=%d", chunkSize), exitMsg, secret25)
		}

		// 3. Overlong line (>256 KiB) with secret near 64 KiB boundary drops cleanly and preserves following short lines.
		var overBuf boundedDiagBuffer
		overlongPrefix := strings.Repeat("x", 65500)
		overlongSecret := "OVERLONG_LINE_SECRET_64K_MARKER"
		overlongRest := strings.Repeat("y", collectorMaxPendingDiagLineBytes) + "\n"
		afterLine := fmt.Sprintf(`{"level":"info","client_secret":"%s","msg":"after_overlong"}`+"\n", "AFTER_OVERLONG_SECRET_999")
		_, _ = overBuf.Write([]byte(overlongPrefix + `"client_secret":"` + overlongSecret + `"` + overlongRest + afterLine))
		overClean := overBuf.String()
		assertNoSecretFragments(t, "overlong_line", overClean, overlongSecret)
		if strings.Contains(overClean, "AFTER_OVERLONG_SECRET_999") {
			t.Fatalf("subsequent line leaked AFTER_OVERLONG_SECRET_999:\n%s", overClean)
		}
		if !strings.Contains(overClean, "[overlong diagnostic line omitted]") || !strings.Contains(overClean, "after_overlong") {
			t.Fatalf("expected omitted marker and retained subsequent sanitized line, got:\n%s", overClean)
		}

		// 4. Unfinished JSON secret line without closing quote at EOF is still redacted.
		var unclosedBuf boundedDiagBuffer
		unclosedSecret := "UNCLOSED_SECRET_EOF_25"
		_, _ = unclosedBuf.Write([]byte(`{"level":"error","client_secret":"` + unclosedSecret))
		unclosedClean := unclosedBuf.String()
		assertNoSecretFragments(t, "unclosed_eof", unclosedClean, unclosedSecret)
		if !strings.Contains(unclosedClean, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] on unclosed EOF secret line, got %q", unclosedClean)
		}
	})

	t.Run("BoundedDiagBufferMultilinePEMPrivateKeyRedaction", func(t *testing.T) {
		const pemSentinel = "SENTINEL_PEM_KEY_BODY_987654321"
		makePEMBlock := func(label, sep string) string {
			return strings.Join([]string{
				"-----BEGIN " + label + "-----",
				"MIIEowIBAAKCAQEA000000000000000000000000000000",
				pemSentinel + "_LINE2",
				"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
				"-----END " + label + "-----",
			}, sep)
		}

		for _, tc := range []struct {
			name        string
			payload     string
			chunkSize   int
			wantPresent []string
		}{
			{
				name:        "single_write_lf_private_key",
				payload:     "error: failed loading key:\n" + makePEMBlock("PRIVATE KEY", "\n") + "\npost_end_diagnostic_ok\n",
				wantPresent: []string{"error: failed loading key:", "[REDACTED_PRIVATE_KEY]", "post_end_diagnostic_ok"},
			},
			{
				name:        "single_write_crlf_rsa_private_key",
				payload:     "startup err:\r\n" + makePEMBlock("RSA PRIVATE KEY", "\r\n") + "\r\npost_end_crlf_ok\r\n",
				wantPresent: []string{"startup err:", "[REDACTED_PRIVATE_KEY]", "post_end_crlf_ok"},
			},
			{
				name:        "chunk_1byte_ec_private_key",
				payload:     "before_ec\n" + makePEMBlock("EC PRIVATE KEY", "\n") + " trailing_same_line_ok\nafter_ec_ok\n",
				chunkSize:   1,
				wantPresent: []string{"before_ec", "[REDACTED_PRIVATE_KEY]", "trailing_same_line_ok", "after_ec_ok"},
			},
			{
				name:        "chunk_7byte_multiple_keys",
				payload:     "k1\n" + makePEMBlock("PRIVATE KEY", "\n") + "\nmid_ok\n" + makePEMBlock("RSA PRIVATE KEY", "\n") + "\ntail_ok\n",
				chunkSize:   7,
				wantPresent: []string{"k1", "[REDACTED_PRIVATE_KEY]", "mid_ok", "tail_ok"},
			},
			{
				name:        "truncated_eof_no_end_delimiter",
				payload:     "eof_err\n-----BEGIN PRIVATE KEY-----\nMIIE_HEADER\n" + pemSentinel + "_UNCLOSED\nno_end_on_final_line",
				chunkSize:   5,
				wantPresent: []string{"eof_err", "[REDACTED_PRIVATE_KEY]"},
			},
			{
				name: "straddling_64kib_cap",
				payload: strings.Repeat(strings.Repeat("p", 127)+"\n", 511) +
					strings.Repeat("q", 90) + "\n" +
					makePEMBlock("PRIVATE KEY", "\n") + "\npost_trunc_should_drop\n",
				chunkSize:   13,
				wantPresent: []string{"[diagnostics truncated]"},
			},
			{
				name: "overlong_line_256kib_with_pem_block",
				payload: "before_overlong\n" +
					"-----BEGIN RSA PRIVATE KEY-----" +
					strings.Repeat("a", 65500) + pemSentinel + strings.Repeat("z", collectorMaxPendingDiagLineBytes) +
					"-----END RSA PRIVATE KEY-----\n" +
					"after_overlong_pem_ok\n",
				chunkSize:   4096,
				wantPresent: []string{"before_overlong", "[REDACTED_PRIVATE_KEY]", "[overlong diagnostic line omitted]", "after_overlong_pem_ok"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var buf boundedDiagBuffer
				if tc.chunkSize <= 0 {
					_, _ = buf.Write([]byte(tc.payload))
				} else {
					for off := 0; off < len(tc.payload); off += tc.chunkSize {
						end := min(len(tc.payload), off+tc.chunkSize)
						_, _ = buf.Write([]byte(tc.payload[off:end]))
					}
				}
				got1 := buf.String()
				got2 := buf.String()
				if got1 != got2 {
					t.Fatalf("String() is not idempotent:\ngot1=%q\ngot2=%q", got1, got2)
				}
				for _, forbidden := range []string{pemSentinel, "MIIEowIBAAKCAQEA", "MIIE_HEADER", "no_end_on_final_line", "PRIVATE KEY", "zzzzzzzz"} {
					if strings.Contains(got1, forbidden) {
						t.Fatalf("diagnostic output leaked %q:\n%s", forbidden, got1)
					}
				}
				for _, want := range tc.wantPresent {
					if !strings.Contains(got1, want) {
						t.Fatalf("diagnostic output missing %q:\n%s", want, got1)
					}
				}
				exitErr := formatCollectorExitErr("collector exited", errors.New("exit status 1"), &buf).Error()
				if strings.Contains(exitErr, pemSentinel) || strings.Contains(exitErr, "PRIVATE KEY") {
					t.Fatalf("formatCollectorExitErr leaked sentinel or header:\n%s", exitErr)
				}
			})
		}

		t.Run("SetCredentialRedactionsCachesFileAndTruncatedWriteShortCircuits", func(t *testing.T) {
			credPath := filepath.Join(t.TempDir(), "cached-sa.json")
			const (
				cachedKeyID = "cached-key-id-4411"
				cachedEmail = "cached-sa@proj.iam.gserviceaccount.com"
				cachedPEM   = "-----BEGIN PRIVATE KEY-----\nCACHED_SA_KEY_BODY_7788\n-----END PRIVATE KEY-----\n"
			)
			credPayload, err := json.Marshal(map[string]string{
				"type":           "service_account",
				"project_id":     "proj",
				"private_key_id": cachedKeyID,
				"private_key":    cachedPEM,
				"client_email":   cachedEmail,
			})
			if err != nil {
				t.Fatalf("json.Marshal: %v", err)
			}
			if err := os.WriteFile(credPath, credPayload, 0o600); err != nil {
				t.Fatalf("write creds: %v", err)
			}

			var cachedBuf boundedDiagBuffer
			cachedBuf.SetCredentialRedactions(bigqueryexporter.CredentialsConfig{File: credPath})
			// Remove the credentials file before any diagnostic line is written;
			// per-child cached secrets must still redact every field.
			if err := os.Remove(credPath); err != nil {
				t.Fatalf("remove creds: %v", err)
			}
			if len(cachedBuf.preparedSecrets) == 0 {
				t.Fatal("preparedSecrets empty after SetCredentialRedactions")
			}

			_, _ = cachedBuf.Write([]byte("auth failed for " + cachedEmail + " key_id=" + cachedKeyID + "\n"))
			gotCached := cachedBuf.String()
			for _, forbidden := range []string{credPath, cachedEmail, cachedKeyID, "CACHED_SA_KEY_BODY_7788"} {
				if strings.Contains(gotCached, forbidden) {
					t.Fatalf("cached sanitizer leaked %q after file removal:\n%s", forbidden, gotCached)
				}
			}

			// Truncated buffer short-circuits subsequent writes cleanly without parsing/updating state.
			var truncBuf boundedDiagBuffer
			truncBuf.SetCredentialRedactions(bigqueryexporter.CredentialsConfig{
				ImpersonateServiceAccount: "post-trunc@proj.iam.gserviceaccount.com",
			})
			fill := strings.Repeat(strings.Repeat("x", 127)+"\n", 513) // 65,664 B > collectorMaxDiagBytes
			if n, wErr := truncBuf.Write([]byte(fill)); wErr != nil || n != len(fill) {
				t.Fatalf("fill Write = (%d, %v), want (%d, nil)", n, wErr, len(fill))
			}
			if !truncBuf.truncated {
				t.Fatal("expected truncBuf.truncated = true after exceeding collectorMaxDiagBytes")
			}
			if truncBuf.pending.Len() != 0 {
				t.Fatalf("expected empty pending buffer after truncation, got %d", truncBuf.pending.Len())
			}

			postTruncPayload := []byte("-----BEGIN PRIVATE KEY-----\nPOST_TRUNC_SECRET_PEM\npost-trunc@proj.iam.gserviceaccount.com")
			if n, wErr := truncBuf.Write(postTruncPayload); wErr != nil || n != len(postTruncPayload) {
				t.Fatalf("post-trunc Write = (%d, %v), want (%d, nil)", n, wErr, len(postTruncPayload))
			}
			if truncBuf.inPEMKeyBlock {
				t.Fatal("post-trunc Write mutated inPEMKeyBlock; expected immediate short-circuit")
			}
			if truncBuf.pending.Len() != 0 {
				t.Fatalf("post-trunc Write wrote %d bytes into pending; expected immediate short-circuit", truncBuf.pending.Len())
			}
			gotTrunc := truncBuf.String()
			if !strings.HasSuffix(gotTrunc, "[diagnostics truncated]") || strings.Contains(gotTrunc, "POST_TRUNC_SECRET_PEM") || strings.Contains(gotTrunc, "post-trunc@proj.iam.gserviceaccount.com") {
				t.Fatalf("unexpected truncated diag output: %q", gotTrunc[max(0, len(gotTrunc)-120):])
			}
		})
	})

	t.Run("RealCollectorStartupFailuresNeverLeakCredentialInputs", func(t *testing.T) {
		collectorBin := findCollectorDistBinary(t)

		t.Run("PastedJSONInCredentialsFile", func(t *testing.T) {
			pastedJSON := `{"type":"service_account","private_key":"SECRET_LIVE_KEY_MARKER"}`
			cfgPath := filepath.Join(t.TempDir(), "collector-pasted-creds-file.yaml")
			rawYAML := fmt.Sprintf(`
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
    project: live-sanitize-test-proj
    dataset: otel_bench
    location: US
    endpoint:
      url: 127.0.0.1:19999
      admin_url: http://127.0.0.1:19999/bigquery/v2/
      insecure: true
    credentials:
      file: %q
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, pastedJSON)
			if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				CollectorBin:       collectorBin,
				CollectorConfig:    cfgPath,
				ProjectID:          "live-sanitize-test-proj",
				DatasetID:          "otel_bench",
				Location:           "US",
				Signals:            []string{"logs"},
				Workers:            1,
				BatchSize:          2,
				Duration:           2 * time.Second,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", nil)
			if hardErr == nil {
				t.Fatal("expected collector startup failure for pasted JSON in credentials.file, got nil")
			}
			msg := hardErr.Error()
			for _, forbidden := range []string{"SECRET_LIVE_KEY_MARKER", "private_key", pastedJSON} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("collector startup error leaked %q:\n%s", forbidden, msg)
				}
			}
		})

		t.Run("UnsupportedCredentialsJSONType", func(t *testing.T) {
			badCredJSON := `{"type":"SECRET_UNSUPPORTED_TYPE_MARKER","client_secret":"SECRET_CLIENT_MARKER"}`
			cfgPath := filepath.Join(t.TempDir(), "collector-unsupported-creds-json.yaml")
			rawYAML := fmt.Sprintf(`
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
    project: live-sanitize-test-proj
    dataset: otel_bench
    location: US
    endpoint:
      url: 127.0.0.1:19999
      admin_url: http://127.0.0.1:19999/bigquery/v2/
      insecure: true
    credentials:
      json: %q
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, badCredJSON)
			if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				CollectorBin:       collectorBin,
				CollectorConfig:    cfgPath,
				ProjectID:          "live-sanitize-test-proj",
				DatasetID:          "otel_bench",
				Location:           "US",
				Signals:            []string{"logs"},
				Workers:            1,
				BatchSize:          2,
				Duration:           2 * time.Second,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", nil)
			if hardErr == nil {
				t.Fatal("expected collector startup failure for unsupported credentials.json type, got nil")
			}
			msg := hardErr.Error()
			for _, forbidden := range []string{"SECRET_UNSUPPORTED_TYPE_MARKER", "SECRET_CLIENT_MARKER", badCredJSON} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("collector startup error leaked %q:\n%s", forbidden, msg)
				}
			}
		})
	})
}

func TestCollectorIntegrationNullInsertIDOccurrenceCounting(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-null-insert-id.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: false
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

	t.Run("CleanDelivery", func(t *testing.T) {
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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("verified=%v delivered=%d replayed=%d, want true/4/0",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.Telemetry.ReplayedRows)
		}
		if res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("missing=%d unexpected=%d, want 0/0", res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
	})

	t.Run("ExtraReplayNotCollapsed", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		var (
			hookMu    sync.Mutex
			seenFirst []byte
			seenCount int
			appended  bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			if seenFirst == nil {
				seenFirst = slices.Clone(serialized[0])
			}
			nextCount := seenCount + len(serialized)
			if !appended && nextCount >= 4 {
				appended = true
				seenCount = nextCount
				return append(slices.Clone(serialized), slices.Clone(seenFirst))
			}
			seenCount = nextCount
			return serialized
		})

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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if res.DeliveredRows != 5 || res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("delivered=%d replayed=%d, want 5/0", res.DeliveredRows, res.Telemetry.ReplayedRows)
		}
		if res.MissingRows != 0 || res.UnexpectedRows != 1 {
			t.Fatalf("missing=%d unexpected=%d, want 0/1", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "delivered=5") || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want delivered=5 and unexpected=1", lossErr)
		}
	})

	t.Run("ReplacedByReplayFailsLossless", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		var (
			hookMu    sync.Mutex
			seenFirst []byte
			seenCount int
			replaced  bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			if seenFirst == nil {
				seenFirst = slices.Clone(serialized[0])
			}
			nextCount := seenCount + len(serialized)
			if !replaced && nextCount >= 4 {
				idx := 4 - seenCount - 1
				mut := slices.Clone(serialized)
				mut[idx] = slices.Clone(seenFirst)
				replaced = true
				seenCount = nextCount
				return mut
			}
			seenCount = nextCount
			return serialized
		})

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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("delivered=%d replayed=%d, want 4/0", res.DeliveredRows, res.Telemetry.ReplayedRows)
		}
		if res.MissingRows != 1 || res.UnexpectedRows != 1 {
			t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
		}
	})
}

func TestCollectorIntegrationMutatedInsertIDOrFingerprintFailsLossless(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	insertIDFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "insert_id")

	metricEnc, err := protoenc.New(schema.MetricsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(MetricsTableSchema): %v", err)
	}
	fpFieldNum := findProtoFieldNumber(t, metricEnc.Descriptor(), "point_fingerprint")

	cfgPath := filepath.Join(t.TempDir(), "collector-mutated-tags.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
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

	for _, redaction := range []bool{false, true} {
		t.Run(fmt.Sprintf("MutatedSynthesizedInsertID_redaction=%t", redaction), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			var (
				hookMu    sync.Mutex
				seenCount int
				mutated   bool
			)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table != "otel_logs" || len(serialized) == 0 {
					return serialized
				}
				hookMu.Lock()
				defer hookMu.Unlock()
				nextCount := seenCount + len(serialized)
				if !mutated && nextCount >= 4 {
					idx := 4 - seenCount - 1
					mut := slices.Clone(serialized)
					mut[idx] = mutateProtoStringField(t, serialized[idx], insertIDFieldNum, flipLastTagChar)
					mutated = true
					seenCount = nextCount
					return mut
				}
				seenCount = nextCount
				return serialized
			})

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
				Redaction:        redaction,
				UpstreamInsertID: false,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 {
				t.Fatalf("verified=%v delivered=%d, want true/4", res.UniqueDeliveryVerified, res.DeliveredRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 1 {
				t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
			}
		})

		t.Run(fmt.Sprintf("MutatedMetricPointFingerprint_redaction=%t", redaction), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			var (
				hookMu    sync.Mutex
				seenCount int
				mutated   bool
			)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table != "otel_metrics" || len(serialized) == 0 {
					return serialized
				}
				hookMu.Lock()
				defer hookMu.Unlock()
				nextCount := seenCount + len(serialized)
				if !mutated && nextCount >= 4 {
					idx := 4 - seenCount - 1
					mut := slices.Clone(serialized)
					mut[idx] = mutateProtoStringField(t, serialized[idx], fpFieldNum, flipLastTagChar)
					mutated = true
					seenCount = nextCount
					return mut
				}
				seenCount = nextCount
				return serialized
			})

			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    collectorBin,
				CollectorConfig: cfgPath,
				Signals:         []string{"metrics"},
				Workers:         1,
				BatchSize:       4,
				maxBatches:      1,
				Duration:        5 * time.Second,
				Redaction:       redaction,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "metrics", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 {
				t.Fatalf("verified=%v delivered=%d, want true/4", res.UniqueDeliveryVerified, res.DeliveredRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 1 {
				t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "metrics", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
			}
		})
	}
}

func TestCollectorIntegrationCustomLogNameAttributeSucceedsWithoutSaturation(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	logNameFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "log_name")

	cfgPath := filepath.Join(t.TempDir(), "collector-custom-log-name.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      log_name_attribute: event.name
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

	t.Run("CleanDelivery", func(t *testing.T) {
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
			maxBatches:       1,
			Duration:         5 * time.Second,
			UpstreamInsertID: false,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 {
			t.Fatalf("verified=%v delivered=%d, want true/4", res.UniqueDeliveryVerified, res.DeliveredRows)
		}
		if res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("missing=%d unexpected=%d, want 0/0", res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
	})

	t.Run("MutatedLogNameFailsLossless", func(t *testing.T) {
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		var (
			hookMu    sync.Mutex
			seenCount int
			mutated   bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			hookMu.Lock()
			defer hookMu.Unlock()
			nextCount := seenCount + len(serialized)
			if !mutated && nextCount >= 4 {
				idx := 4 - seenCount - 1
				mut := slices.Clone(serialized)
				mut[idx] = mutateProtoStringField(t, serialized[idx], logNameFieldNum, func(s string) string {
					return s + "-mutated"
				})
				mutated = true
				seenCount = nextCount
				return mut
			}
			seenCount = nextCount
			return serialized
		})

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  cfgPath,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileGenAIMixed,
			Workers:          1,
			BatchSize:        4,
			maxBatches:       1,
			Duration:         5 * time.Second,
			UpstreamInsertID: false,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if res.MissingRows != 1 || res.UnexpectedRows != 1 {
			t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
		}
	})
}

func TestCollectorIntegrationTrimmingPipelineVerifiesSynthesizedInsertIDs(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	hvCfgPath := resolveCollectorConfigPath(filepath.Join("example", "otel-collector-high-volume-logs.yaml"))

	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	insertIDFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "insert_id")

	t.Run("CleanDelivery", func(t *testing.T) {
		t.Setenv("BQ_PROJECT", "orig-proj")
		t.Setenv("BQ_DATASET", "orig_ds")
		t.Setenv("BQ_LOCATION", "US")

		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  hvCfgPath,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileAccessLogs,
			Workers:          1,
			BatchSize:        4,
			maxBatches:       1,
			Duration:         10 * time.Second,
			UpstreamInsertID: false,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
	})

	t.Run("SubstitutedSameWellFormedInsertIDFailsLossless", func(t *testing.T) {
		t.Setenv("BQ_PROJECT", "orig-proj")
		t.Setenv("BQ_DATASET", "orig_ds")
		t.Setenv("BQ_LOCATION", "US")

		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			mut := make([][]byte, len(serialized))
			for i, raw := range serialized {
				mut[i] = mutateProtoStringField(t, raw, insertIDFieldNum, func(string) string {
					return "id1:0000000000000000"
				})
			}
			return mut
		})

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  hvCfgPath,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileAccessLogs,
			Workers:          1,
			BatchSize:        4,
			maxBatches:       1,
			Duration:         10 * time.Second,
			UpstreamInsertID: false,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if res.MissingRows != 4 || res.UnexpectedRows != 4 {
			t.Fatalf("missing=%d unexpected=%d, want 4/4", res.MissingRows, res.UnexpectedRows)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=4") || !strings.Contains(lossErr.Error(), "unexpected=4") {
			t.Fatalf("checkSignalResultLossless = %v, want missing=4 and unexpected=4", lossErr)
		}
	})

	t.Run("UnsimulatableProcessorReportsVerificationUnavailable", func(t *testing.T) {
		cfgPath := filepath.Join(t.TempDir(), "collector-hash-unsimulatable.yaml")
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
  attributes/hash_non_id:
    actions:
      - key: benchmark.label
        action: hash
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/hash_non_id, batch]
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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 4 || res.UniqueDeliveryVerified {
			t.Fatalf("delivered=%d uniqueDeliveryVerified=%v, want 4/false when derived insert_id cannot be predicted",
				res.DeliveredRows, res.UniqueDeliveryVerified)
		}
	})
}

func TestCollectorIntegrationRedactingServiceNamePreservesSpanReconciliation(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-redact-service-name-traces.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    redaction:
      enabled: true
      blocked_keys: ["service.name"]
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

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"traces"},
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
		t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "traces", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
	rows := fakeSrv.Rows("otel_spans")
	if len(rows) != 4 {
		t.Fatalf("len(otel_spans rows) = %d, want 4", len(rows))
	}
	for i, r := range rows {
		if svc, _ := r["service_name"].(string); svc != "[REDACTED]" {
			t.Fatalf("span row[%d] service_name = %q, want [REDACTED]", i, svc)
		}
	}
}

func TestCollectorIntegrationEnvExpandedProcessorValueReconciles(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	t.Run("EnvExpandedAttributeUpsertPassesLossless", func(t *testing.T) {
		t.Setenv("BENCH_REVIEW_REGION", "west")
		t.Setenv("BENCH_REVIEW_COUNT", "7")

		cfgPath := filepath.Join(t.TempDir(), "collector-env-upsert.yaml")
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
  attributes/env_tag:
    actions:
      - key: benchmark.region
        value: ${env:BENCH_REVIEW_REGION}
        action: upsert
      - key: benchmark.count
        value: ${env:BENCH_REVIEW_COUNT}
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/env_tag, batch]
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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
		rows := fakeSrv.Rows("otel_logs")
		if len(rows) != 4 {
			t.Fatalf("len(otel_logs rows) = %d, want 4", len(rows))
		}
		for i, r := range rows {
			attrsJSON, _ := r["attributes"].(string)
			var attrs map[string]any
			if err := json.Unmarshal([]byte(attrsJSON), &attrs); err != nil {
				t.Fatalf("row[%d] invalid attributes JSON %q: %v", i, attrsJSON, err)
			}
			if attrs["benchmark.region"] != "west" || attrs["benchmark.count"] != "7" {
				t.Fatalf("row[%d] attributes = %v (%T), want benchmark.region=west benchmark.count=\"7\"", i, attrs, attrs["benchmark.count"])
			}
		}
	})

	t.Run("UnmodelableConfmapValueReportsVerificationUnavailable", func(t *testing.T) {
		tmpDir := t.TempDir()
		regionFile := filepath.Join(tmpDir, "region.txt")
		if err := os.WriteFile(regionFile, []byte("west"), 0o600); err != nil {
			t.Fatalf("write region file: %v", err)
		}

		cfgPath := filepath.Join(tmpDir, "collector-file-upsert.yaml")
		rawYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
processors:
  attributes/file_tag:
    actions:
      - key: benchmark.region
        value: %q
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/file_tag, batch]
      exporters: [bigquery]
`, "${file:"+filepath.ToSlash(regionFile)+"}")
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

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 4 || res.UniqueDeliveryVerified {
			t.Fatalf("delivered=%d uniqueDeliveryVerified=%v, want 4/false for unmodeled file provider",
				res.DeliveredRows, res.UniqueDeliveryVerified)
		}
	})

	t.Run("BareEnvVarAttributeUpsertVerifiesInsertIDs", func(t *testing.T) {
		t.Setenv("BENCH_REVIEW_BARE_REGION", "east-bare")
		t.Setenv("BENCH_REVIEW_BARE_COUNT", "11")

		cfgPath := filepath.Join(t.TempDir(), "collector-bare-env-upsert.yaml")
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
  attributes/bare_tag:
    actions:
      - key: benchmark.region
        value: ${BENCH_REVIEW_BARE_REGION}
        action: upsert
      - key: benchmark.count
        value: ${BENCH_REVIEW_BARE_COUNT}
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/bare_tag, batch]
      exporters: [bigquery]
`
		if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}

		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		// Corrupt one committed insert_id at bqfake on the positive pass vs clean pass:
		// First run cleanly and assert UniqueDeliveryVerified=true + strict pass.
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
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}

		// Mutate one insert_id in-flight at bqfake to prove bare ${VAR} reconciles
		// and detects mismatched insert_id strictly rather than skipping verification.
		logEnc, encErr := protoenc.New(schema.LogsTableSchema())
		if encErr != nil {
			t.Fatalf("protoenc.New: %v", encErr)
		}
		rogueRow := encodeRogueSubstitutionLogRow(t, logEnc, "corrupted-bare-id")
		tamperSrv := bqfake.NewServer(t)
		tamperSrv.SetDiscardRows(true)
		var tampered atomic.Bool
		tamperSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 || !tampered.CompareAndSwap(false, true) {
				return serialized
			}
			out := slices.Clone(serialized)
			out[0] = rogueRow
			return out
		})
		resTamper, softTamper, hardTamper := runCollectorSingleSignalWithFake(ctx, cfg, "logs", tamperSrv)
		if hardTamper != nil || softTamper != nil {
			t.Fatalf("tamper run unexpected error hard=%v soft=%v", hardTamper, softTamper)
		}
		if !resTamper.UniqueDeliveryVerified || resTamper.MissingRows != 1 || resTamper.UnexpectedRows != 1 {
			t.Fatalf("tamper verified=%v missing=%d unexpected=%d, want true/1/1",
				resTamper.UniqueDeliveryVerified, resTamper.MissingRows, resTamper.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", resTamper, softTamper); lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") {
			t.Fatalf("expected lossless gate failure on tampered insert_id with bare ${VAR}, got %v", lossErr)
		}
	})

	t.Run("NestedEnvFallbackLogsTablePassesPreflightAndCollector", func(t *testing.T) {
		t.Setenv("BENCH_NESTED_FALLBACK_TBL", "nested_fallback_logs")

		cfgPath := filepath.Join(t.TempDir(), "collector-nested-env-table.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: "${env:BENCH_NESTED_UNSET_TBL:-${env:BENCH_NESTED_FALLBACK_TBL}}"
      synthesize_insert_id: true
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

		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			WorkloadProfile: WorkloadProfileAccessLogs,
			Workers:         1,
			BatchSize:       4,
			maxBatches:      1,
			Duration:        5 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		meta, pfErr := validateCollectorPreflightConfigWithMeta(cfg, "logs")
		if pfErr != nil {
			t.Fatalf("validateCollectorPreflightConfigWithMeta: %v", pfErr)
		}
		if meta.effectiveTable != "nested_fallback_logs" {
			t.Fatalf("meta.effectiveTable = %q, want nested_fallback_logs", meta.effectiveTable)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
				res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
		if got := fakeSrv.UniqueAckedRowsForTable("nested_fallback_logs"); got != 4 {
			t.Fatalf("UniqueAckedRowsForTable(nested_fallback_logs) = %d, want 4", got)
		}
	})
}

func TestCollectorIntegrationLoopbackIgnoresCredentialsBlock(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "nonexistent-adc.json"))

	cfgPath := filepath.Join(t.TempDir(), "collector-loopback-credentials.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    credentials:
      json: "${file:/nonexistent/missing-creds.json}"
    logs:
      table: otel_logs
      synthesize_insert_id: true
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

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		WorkloadProfile: WorkloadProfileAccessLogs,
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
		t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
}

func TestCollectorIntegrationPrunesUnusedProcessorsFromUnselectedPipelines(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	cfgPath := filepath.Join(t.TempDir(), "collector-unused-trace-proc.yaml")
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
  attributes/unused_trace:
    actions:
      - key: unused.attr
        value: "${file:/nonexistent/unused-proc.yaml}"
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
    traces:
      table: otel_spans
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      processors: [attributes/unused_trace, batch]
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
		Signals:         []string{"logs"},
		WorkloadProfile: WorkloadProfileAccessLogs,
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
		t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
}

func TestCollectorIntegrationQuotedWhitespaceLogNameAttributeReconciles(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	rawYAML := []byte(`
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
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      log_name_attribute: " event.name "
      synthesize_insert_id: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [bigquery]
`)

	otlpLis, otlpAddr, err := reserveLoopbackAddr(t.Context())
	if err != nil {
		t.Fatalf("reserve OTLP addr: %v", err)
	}
	hcLis, hcAddr, err := reserveLoopbackAddr(t.Context())
	if err != nil {
		_ = otlpLis.Close()
		t.Fatalf("reserve health addr: %v", err)
	}
	metricsLis, metricsAddr, err := reserveLoopbackAddr(t.Context())
	if err != nil {
		_ = otlpLis.Close()
		_ = hcLis.Close()
		t.Fatalf("reserve metrics addr: %v", err)
	}
	mHost, mPortStr, _ := net.SplitHostPort(metricsAddr)
	mPort, _ := strconv.Atoi(mPortStr)

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:         ModeCollector,
		CollectorBin: collectorBin,
		ProjectID:    "bench-project",
		DatasetID:    "otel_bench",
		Location:     "US",
		Signals:      []string{"logs"},
		Workers:      1,
		BatchSize:    4,
		Duration:     5 * time.Second,
		CallTimeout:  5 * time.Second,
	}
	rewrittenYAML, meta, err := rewriteCollectorLoopbackConfig(rawYAML, cfg, "logs", collectorEndpointOverride{
		otlpAddr:    otlpAddr,
		healthAddr:  hcAddr,
		metricsHost: mHost,
		metricsPort: mPort,
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: fakeSrv.Addr(),
		fakeRESTURL: strings.TrimRight(fakeSrv.RESTURL(), "/") + "/bigquery/v2/",
	})
	if err != nil {
		_ = otlpLis.Close()
		_ = hcLis.Close()
		_ = metricsLis.Close()
		t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
	}
	if meta.effectiveLogsLogNameAttr != " event.name " {
		t.Fatalf("meta.effectiveLogsLogNameAttr = %q, want %q", meta.effectiveLogsLogNameAttr, " event.name ")
	}

	tmpCfg := filepath.Join(t.TempDir(), "collector-spaced-log-name.yaml")
	if err := os.WriteFile(tmpCfg, rewrittenYAML, 0o600); err != nil {
		_ = otlpLis.Close()
		_ = hcLis.Close()
		_ = metricsLis.Close()
		t.Fatalf("write rewritten config: %v", err)
	}
	_ = otlpLis.Close()
	_ = hcLis.Close()
	_ = metricsLis.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	diag := &boundedDiagBuffer{}
	cmd := exec.CommandContext(ctx, collectorBin, "--config="+tmpCfg)
	cmd.Stdout = diag
	cmd.Stderr = diag
	cmd.Cancel = func() error {
		stopCollectorProcess(cmd.Process)
		return nil
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start collector: %v", err)
	}
	doneCh := make(chan struct{})
	var cmdWaitErr error
	go func() {
		cmdWaitErr = cmd.Wait()
		close(doneCh)
	}()
	defer func() {
		stopCollectorProcess(cmd.Process)
		<-doneCh
	}()

	if err := waitCollectorReady(ctx, doneCh, &cmdWaitErr, diag, hcAddr, meta.healthCheckPath, metricsAddr, otlpAddr, meta.hasHealthCheck); err != nil {
		t.Fatalf("waitCollectorReady: %v", err)
	}

	fakeSrv.SetTrackUniqueAcked(true)
	fakeSrv.BeginUniqueAckedPhase(meta.effectiveTable)
	submitted := bqfake.NewSubmittedKeySet()

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "spaced-attr-svc")
	sl := rl.ScopeLogs().AppendEmpty()
	baseNano := DefaultBaseTime.UnixNano()
	for i := range 4 {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(baseNano + int64(i)*1000))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.Body().SetStr(fmt.Sprintf("spaced-log-body-%d", i))
		// Both "event.name" and " event.name " present: only exact-match preserves "spaced-log".
		lr.Attributes().PutStr("event.name", "unspaced-fallback")
		lr.Attributes().PutStr(" event.name ", "spaced-log")
	}

	recordDispatchedLogsKeys(submitted, ld, logKeyRecordOptions{
		logNameAttr:        meta.effectiveLogsLogNameAttr,
		insertIDAttr:       meta.effectiveLogsInsertIDAttr,
		synthesizeInsertID: meta.effectiveLogsSynthesizeInsertID,
		predictDerivedTag:  true,
	})

	conn, err := grpc.NewClient(otlpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial collector OTLP: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := plogotlp.NewGRPCClient(conn).Export(ctx, plogotlp.NewExportRequestFromLogs(ld)); err != nil {
		t.Fatalf("OTLP ExportLogs: %v", err)
	}

	metricsClientHTTP := &http.Client{Timeout: 2 * time.Second}
	baseM := collectorMetricsSample{}
	snapFn := func() int64 { return fakeSrv.TableStatsSnapshotForTable(meta.effectiveTable).UniqueAckedRows }
	if _, _, dErr := drainCollectorPipelineWithBatchWait(ctx, metricsClientHTTP, metricsAddr, "logs", meta.activeExporterID, baseM, 4, 5*time.Second, doneCh, &cmdWaitErr, diag, 0, snapFn, collectorBatchWaitConfig{}); dErr != nil {
		t.Fatalf("drainCollectorPipelineWithBatchWait: %v", dErr)
	}

	snap, rec := fakeSrv.ReconcileAndSnapshotForTable(meta.effectiveTable, submitted)
	if rec.MissingRows != 0 || rec.UnexpectedRows != 0 || rec.MatchedRows != 4 || snap.UniqueAckedRows != 4 {
		t.Fatalf("reconcile matched=%d missing=%d unexpected=%d unique=%d, want 4/0/0/4",
			rec.MatchedRows, rec.MissingRows, rec.UnexpectedRows, snap.UniqueAckedRows)
	}
	rows := fakeSrv.Rows("otel_logs")
	if len(rows) != 4 {
		t.Fatalf("len(otel_logs rows) = %d, want 4", len(rows))
	}
	for i, r := range rows {
		if ln, _ := r["log_name"].(string); ln != "spaced-log" {
			t.Fatalf("row[%d] log_name = %q, want %q", i, ln, "spaced-log")
		}
	}
}

func TestCollectorIntegrationNumericEnvTablePreservedAsString(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	t.Setenv("BENCH_NUMERIC_TABLE", "20261120")

	cfgPath := filepath.Join(t.TempDir(), "collector-numeric-env-table.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: ${env:BENCH_NUMERIC_TABLE}
      synthesize_insert_id: true
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

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)

	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    collectorBin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		WorkloadProfile: WorkloadProfileAccessLogs,
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	meta, pfErr := validateCollectorPreflightConfigWithMeta(cfg, "logs")
	if pfErr != nil {
		t.Fatalf("validateCollectorPreflightConfigWithMeta: %v", pfErr)
	}
	if meta.effectiveTable != "20261120" {
		t.Fatalf("meta.effectiveTable = %q, want 20261120", meta.effectiveTable)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 4 || res.MissingRows != 0 || res.UnexpectedRows != 0 {
		t.Fatalf("verified=%v delivered=%d missing=%d unexpected=%d, want true/4/0/0",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
	}
	if got := fakeSrv.UniqueAckedRowsForTable("20261120"); got != 4 {
		t.Fatalf("UniqueAckedRowsForTable(20261120) = %d, want 4", got)
	}
}

func TestCollectorIntegrationNullInsertIDFaultRetryPassesStrictGate(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)

	writeNullIDCfg := func(t *testing.T) string {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "collector-null-id-fault.yaml")
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
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    retry_on_failure:
      enabled: true
      initial_interval: 20ms
      max_interval: 100ms
      max_elapsed_time: 10s
    logs:
      table: otel_logs
      synthesize_insert_id: false
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
		return cfgPath
	}

	t.Run("SteadyStateFaultRetryPassesStrictGateWithExactBytesPerRow", func(t *testing.T) {
		cfgPath := writeNullIDCfg(t)
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		fakeSrv.EnqueueFault(bqfake.Fault{
			Mode:  bqfake.FaultCommitThenStreamClosed,
			Table: "otel_logs",
		})

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
			SimulateAckDelay: time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.RecordsSubmitted != 4 || res.DeliveredRows != 4 ||
			res.MissingRows != 0 || res.UnexpectedRows != 0 || res.Telemetry.ReplayedRows != 4 {
			t.Fatalf("result verified=%v submitted=%d delivered=%d missing=%d unexpected=%d replayed=%d, want true/4/4/0/0/4",
				res.UniqueDeliveryVerified, res.RecordsSubmitted, res.DeliveredRows,
				res.MissingRows, res.UnexpectedRows, res.Telemetry.ReplayedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}

		snap := fakeSrv.TableStatsSnapshotForTable("otel_logs")
		if snap.AckedRows != 8 || snap.UniqueAckedRows != 8 || snap.NullIDRepeatRows != 4 || snap.NullIDRepeatBytes <= 0 {
			t.Fatalf("snap = %+v, want AckedRows=8 UniqueAckedRows=8 NullIDRepeatRows=4 NullIDRepeatBytes>0", snap)
		}
		wantSingleAttemptBPR := float64(snap.UniqueAckedBytes-snap.NullIDRepeatBytes) / 4.0
		if math.Abs(res.BytesPerRow-wantSingleAttemptBPR) > 1e-6 {
			t.Fatalf("res.BytesPerRow = %f, want single-attempt %f (UniqueAckedBytes=%d NullIDRepeatBytes=%d)",
				res.BytesPerRow, wantSingleAttemptBPR, snap.UniqueAckedBytes, snap.NullIDRepeatBytes)
		}
	})

	t.Run("WarmupFaultRetryPassesWarmupAndSteadyStrictGate", func(t *testing.T) {
		cfgPath := writeNullIDCfg(t)
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		fakeSrv.EnqueueFault(bqfake.Fault{
			Mode:  bqfake.FaultCommitThenStreamClosed,
			Table: "otel_logs",
		})

		cfg := RunnerConfig{
			Mode:             ModeCollector,
			CollectorBin:     collectorBin,
			CollectorConfig:  cfgPath,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileAccessLogs,
			Workers:          1,
			BatchSize:        4,
			TargetRate:       4,
			WarmupDuration:   1500 * time.Millisecond,
			Duration:         1500 * time.Millisecond,
			SimulateAckDelay: time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if !res.UniqueDeliveryVerified || res.DeliveredRows != res.RecordsSubmitted || res.MissingRows != 0 || res.UnexpectedRows != 0 {
			t.Fatalf("verified=%v submitted=%d delivered=%d missing=%d unexpected=%d, want verified=true submitted==delivered and 0/0",
				res.UniqueDeliveryVerified, res.RecordsSubmitted, res.DeliveredRows, res.MissingRows, res.UnexpectedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
			t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
		}
		snap := fakeSrv.TableStatsSnapshotForTable("otel_logs")
		if snap.NullIDRepeatRows < 1 {
			t.Fatalf("expected warmup CommitThenStreamClosed replay (NullIDRepeatRows >= 1), got %+v", snap)
		}
		if res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("expected steady-state ReplayedRows=0 after warmup consumed fault (confirming replay happened in warmup), got %d", res.Telemetry.ReplayedRows)
		}
	})

	t.Run("NonFaultNullIDDuplicateStillFailsStrictGate", func(t *testing.T) {
		cfgPath := writeNullIDCfg(t)
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)
		fakeSrv.EnqueueFault(bqfake.Fault{
			Mode:  bqfake.FaultCommitThenStreamClosed,
			Table: "otel_logs",
		})

		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    collectorBin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			WorkloadProfile: WorkloadProfileAccessLogs,
			Workers:         1,
			BatchSize:       4,
			maxBatches:      1,
			Duration:        5 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("unexpected hardErr: %v", hardErr)
		}
		if res.DeliveredRows != 8 || res.UnexpectedRows != 4 || res.Telemetry.ReplayedRows != 0 {
			t.Fatalf("delivered=%d unexpected=%d replayed=%d, want 8/4/0",
				res.DeliveredRows, res.UnexpectedRows, res.Telemetry.ReplayedRows)
		}
		if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr == nil || !strings.Contains(lossErr.Error(), "delivered=8") || !strings.Contains(lossErr.Error(), "unexpected=4") {
			t.Fatalf("expected strict gate failure with delivered=8 unexpected=4, got %v", lossErr)
		}
	})
}

func TestCollectorPreflightRejectsFullExporterConfigBeforeEphemeralDataset(t *testing.T) {
	storageDir := t.TempDir()
	var nonExecBin, nonRegularBin string
	if runtime.GOOS != "windows" {
		nonExecBin = filepath.Join(t.TempDir(), "non-exec-otelcol")
		if err := os.WriteFile(nonExecBin, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
			t.Fatalf("write non-exec binary: %v", err)
		}
		sockDir, mkErr := os.MkdirTemp("", "bqcol-")
		if mkErr != nil {
			t.Fatalf("MkdirTemp: %v", mkErr)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
		nonRegularBin = filepath.Join(sockDir, "s")
		sockLis, sockErr := net.Listen("unix", nonRegularBin)
		if sockErr != nil {
			t.Fatalf("net.Listen(unix, %s): %v", nonRegularBin, sockErr)
		}
		defer func() { _ = sockLis.Close() }()
		if chErr := os.Chmod(nonRegularBin, 0o755); chErr != nil {
			t.Fatalf("Chmod(%s): %v", nonRegularBin, chErr)
		}
	}
	type preflightCase struct {
		name              string
		signals           []string
		redaction         bool
		collectorBin      string
		endpointURL       string
		endpointAdminURL  string
		endpointBlock     string
		extensionsBody    string
		serviceExtensions string
		exporterBody      string
		pipelinesBody     string
		wantSubstr        string
		forbidden         []string
	}
	tests := []preflightCase{
		{
			name:    "TracesNegativePartitionExpiration",
			signals: []string{"traces"},
			exporterBody: `
    traces:
      table: otel_spans
      partition_expiration_days: -1`,
			pipelinesBody: `
    traces:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "traces.partition_expiration_days (-1) must not be negative",
		},
		{
			name:    "MetricsNegativePartitionExpiration",
			signals: []string{"metrics"},
			exporterBody: `
    metrics:
      table: otel_metrics
      partition_expiration_days: -1`,
			pipelinesBody: `
    metrics:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "metrics.partition_expiration_days (-1) must not be negative",
		},
		{
			name:    "QuarantineNegativePartitionExpiration",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    quarantine:
      partition_expiration_days: -1`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "quarantine.partition_expiration_days (-1) must not be negative",
		},
		{
			name:    "InvalidTracesClusteringColumn",
			signals: []string{"traces"},
			exporterBody: `
    traces:
      table: otel_spans
      clustering:
        - nonexistent_column`,
			pipelinesBody: `
    traces:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "traces.",
		},
		{
			name:    "UnknownExporterField",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    unknown_exporter_flag: true`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "unknown_exporter_flag",
		},
		{
			name:    "RedactsCredentialsAndAdminURLOnDecodeError",
			signals: []string{"logs"},
			exporterBody: `
    credentials:
      json: '{"type":"service_account","private_key":"SECRET_PRIV_KEY_DO_NOT_LEAK"}'
    logs:
      table: otel_logs
    bogus_preflight_key: 1`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "bogus_preflight_key",
			forbidden:  []string{"SECRET_PRIV_KEY_DO_NOT_LEAK", "secret_admin_pw"},
		},
		{
			name:    "SendingQueueNegativeNumConsumers",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    sending_queue:
      num_consumers: -1`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "num_consumers",
		},
		{
			name:    "SendingQueueZeroQueueSize",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    sending_queue:
      queue_size: 0`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "queue_size",
		},
		{
			name:    "SendingQueueBatchZeroFlushTimeout",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    sending_queue:
      batch:
        flush_timeout: 0s`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "flush_timeout",
		},
		{
			name:    "SendingQueueBatchMinExceedsMaxSize",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    sending_queue:
      batch:
        min_size: 100
        max_size: 10`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "max_size",
		},
		{
			name:              "SendingQueueWaitForResultWithPersistentStorage",
			signals:           []string{"logs"},
			extensionsBody:    fmt.Sprintf("\n  file_storage/bq_queue:\n    directory: %s", storageDir),
			serviceExtensions: "[health_check, file_storage/bq_queue]",
			exporterBody: `
    logs:
      table: otel_logs
    sending_queue:
      enabled: true
      wait_for_result: true
      storage: file_storage/bq_queue`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "wait_for_result",
		},
		{
			name:    "RetryOnFailureNegativeInitialInterval",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    retry_on_failure:
      initial_interval: -1s`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "initial_interval",
		},
		{
			name:    "RetryOnFailureInvalidRandomizationFactor",
			signals: []string{"logs"},
			exporterBody: `
    logs:
      table: otel_logs
    retry_on_failure:
      randomization_factor: 1.5`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "randomization_factor",
		},
		{
			name:      "InvalidYAMLRedactionPatternPreservedWithRedactionFlag",
			signals:   []string{"logs"},
			redaction: true,
			exporterBody: `
    logs:
      table: otel_logs
    redaction:
      blocked_value_patterns:
        - "("`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "redaction.",
		},
		{
			name:             "MalformedAdminURLRedactsCredentials",
			signals:          []string{"logs"},
			endpointAdminURL: "ftp://alice:secret_ftp_pw@private.example.test/bigquery/v2/?token=secret_ftp_tok",
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.admin_url must be an absolute http(s):// URL",
			forbidden:  []string{"secret_ftp_pw", "secret_ftp_tok", "alice", "private.example.test"},
		},
		{
			name:             "NonLoopbackHTTPAdminURLRedactsCredentials",
			signals:          []string{"logs"},
			endpointAdminURL: "http://bob:secret_http_pw@private.example.test:9050/bigquery/v2/?key=secret_http_tok",
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.admin_url must use https:// unless it is a loopback address",
			forbidden:  []string{"secret_http_pw", "secret_http_tok", "bob", "private.example.test"},
		},
		{
			name:        "NonLoopbackEndpointInsecureRedactsCredentials",
			signals:     []string{"logs"},
			endpointURL: "https://carol:secret_url_pw@private.example.test:443?sig=secret_url_sig",
			exporterBody: `
      insecure: true
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.insecure is only allowed for a loopback endpoint",
			forbidden:  []string{"secret_url_pw", "secret_url_sig", "carol", "private.example.test"},
		},
		{
			name:        "NonLoopbackEndpointWithoutAuthRedactsCredentials",
			signals:     []string{"logs"},
			endpointURL: "https://dave:secret_noauth_pw@private.example.test:443?sig=secret_noauth_sig",
			exporterBody: `
      without_authentication: true
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.without_authentication is only allowed for a loopback endpoint",
			forbidden:  []string{"secret_noauth_pw", "secret_noauth_sig", "dave", "private.example.test"},
		},
		{
			name:        "EmptyNormalizedEndpointURLRedactsRawValue",
			signals:     []string{"logs"},
			endpointURL: "https://   /",
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.url must specify a non-empty target",
			forbidden:  []string{"https://   /", "secret_admin_pw"},
		},
		{
			name:             "MalformedEndpointAdminURLRefRedactsCredentials",
			signals:          []string{"logs"},
			endpointAdminURL: "https://alice:secret_admin_pw@admin.example.test/bq?sig=secret_admin_sig#${bad:secret_ref}",
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "unsupported collector config provider",
			forbidden:  []string{"alice", "secret_admin_pw", "secret_admin_sig", "secret_ref", "admin.example.test"},
		},
		{
			name:        "MalformedEndpointURLRefRedactsCredentials",
			signals:     []string{"logs"},
			endpointURL: "https://bob:secret_ep_pw@write.example.test:443?sig=secret_ep_sig#${env:}",
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "empty environment variable name",
			forbidden:  []string{"bob", "secret_ep_pw", "secret_ep_sig", "write.example.test"},
		},
		{
			name:    "EndpointAdminURLSequenceTypeRedactsCredentials",
			signals: []string{"logs"},
			endpointBlock: `      url: 127.0.0.1:4317
      admin_url:
        - "https://carol:secret_seq_admin@admin.example.test?token=secret_seq_tok"`,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.admin_url must be a string",
			forbidden:  []string{"carol", "secret_seq_admin", "secret_seq_tok", "admin.example.test"},
		},
		{
			name:    "EndpointURLMapTypeRedactsCredentials",
			signals: []string{"logs"},
			endpointBlock: `      url:
        nested: "https://dave:secret_map_url@write.example.test?token=secret_map_tok"
      admin_url: "https://admin.example.test/bigquery/v2/"`,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.url must be a string",
			forbidden:  []string{"dave", "secret_map_url", "secret_map_tok", "write.example.test"},
		},
		{
			name:    "EndpointUnsupportedKeyRedactsValue",
			signals: []string{"logs"},
			endpointBlock: `      url: 127.0.0.1:4317
      bogus_endpoint_key: "https://eve:secret_bogus_pw@admin.example.test?token=secret_bogus_tok"`,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "unsupported key",
			forbidden:  []string{"eve", "secret_bogus_pw", "secret_bogus_tok", "admin.example.test"},
		},
		{
			name:    "EndpointInsecureStringTypeRedactsValue",
			signals: []string{"logs"},
			endpointBlock: `      url: 127.0.0.1:4317
      insecure: "secret_insecure_val"`,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "endpoint.insecure must be a boolean",
			forbidden:  []string{"secret_insecure_val"},
		},
	}
	if nonExecBin != "" {
		tests = append(tests, preflightCase{
			name:         "NonExecutableCollectorBinaryRejectedBeforeEphemeralDataset",
			signals:      []string{"logs"},
			collectorBin: nonExecBin,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "not executable",
		})
	}
	if nonRegularBin != "" {
		tests = append(tests, preflightCase{
			name:         "SocketNonRegularCollectorBinaryRejectedBeforeEphemeralDataset",
			signals:      []string{"logs"},
			collectorBin: nonRegularBin,
			exporterBody: `
    logs:
      table: otel_logs`,
			pipelinesBody: `
    logs:
      receivers: [otlp]
      exporters: [bigquery]`,
			wantSubstr: "not a regular file",
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var adminHits atomic.Int64
			adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				adminHits.Add(1)
				http.Error(w, "unexpected admin request", http.StatusInternalServerError)
			}))
			defer adminSrv.Close()

			endpointURL := "127.0.0.1:4317"
			if tc.endpointURL != "" {
				endpointURL = tc.endpointURL
			}
			adminURL := adminSrv.URL + "/bigquery/v2/"
			if tc.endpointAdminURL != "" {
				adminURL = tc.endpointAdminURL
			} else if len(tc.forbidden) > 0 {
				adminURL = strings.Replace(adminURL, "http://", "http://alice:secret_admin_pw@", 1)
			}
			epBlock := tc.endpointBlock
			if epBlock == "" {
				epBlock = fmt.Sprintf("      url: %q\n      admin_url: %q", endpointURL, adminURL)
			}
			svcExts := tc.serviceExtensions
			if svcExts == "" {
				svcExts = "[health_check]"
			}
			colBin := os.Args[0]
			if tc.collectorBin != "" {
				colBin = tc.collectorBin
			}

			cfgPath := filepath.Join(t.TempDir(), "invalid-live-preflight.yaml")
			rawYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133%s
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: my-live-proj
    dataset: otel_bench
    location: US
    endpoint:
%s%s
service:
  extensions: %s
  pipelines:%s
`, tc.extensionsBody, epBlock, tc.exporterBody, svcExts, tc.pipelinesBody)
			if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}

			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				EphemeralDataset:   true,
				Redaction:          tc.redaction,
				CollectorBin:       colBin,
				CollectorConfig:    cfgPath,
				ProjectID:          "my-live-proj",
				Location:           "US",
				Signals:            tc.signals,
				Workers:            1,
				BatchSize:          2,
				Duration:           time.Second,
			}
			_, runErr := Run(t.Context(), cfg)
			if runErr == nil {
				t.Fatalf("Run succeeded, want preflight error containing %q", tc.wantSubstr)
			}
			if !strings.Contains(runErr.Error(), tc.wantSubstr) {
				t.Fatalf("Run error = %q, want substring %q", runErr.Error(), tc.wantSubstr)
			}
			if hits := adminHits.Load(); hits != 0 {
				t.Fatalf("ephemeral dataset admin endpoint received %d HTTP requests, want 0 (preflight must fail before dataset creation)", hits)
			}
			for _, secret := range tc.forbidden {
				if strings.Contains(runErr.Error(), secret) {
					t.Fatalf("Run error leaked secret %q: %s", secret, runErr.Error())
				}
			}
		})
	}

	// Direct preflight check: invalid YAML redaction pattern is also rejected when
	// OffloadDir is populated alongside Redaction=true.
	t.Run("InvalidYAMLRedactionPatternPreservedWithLocalOffload", func(t *testing.T) {
		cfgPath := filepath.Join(t.TempDir(), "invalid-redaction-offload.yaml")
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
    logs:
      table: otel_logs
    redaction:
      blocked_value_patterns:
        - "("
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
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			Redaction:       true,
			OffloadDir:      t.TempDir(),
			CollectorBin:    os.Args[0],
			CollectorConfig: cfgPath,
			ProjectID:       "bench-project",
			DatasetID:       "otel_bench",
			Location:        "US",
			Signals:         []string{"logs"},
		}
		pfErr := validateCollectorPreflightConfig(cfg, "logs")
		if pfErr == nil || !strings.Contains(pfErr.Error(), "redaction.") {
			t.Fatalf("validateCollectorPreflightConfig = %v, want redaction pattern compilation error", pfErr)
		}
	})

	// Numeric env value in labels stays string and passes full confmap Unmarshal + Validate.
	t.Run("EnvResolvedNumericLabelPreservedAsString", func(t *testing.T) {
		t.Setenv("BENCH_NUMERIC_COHORT", "42")
		cfgPath := filepath.Join(t.TempDir(), "valid-label-env.yaml")
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
    labels:
      cohort: "${env:BENCH_NUMERIC_COHORT}"
    traces:
      table: otel_spans
      partition_expiration_days: 7
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [bigquery]
`
		if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: cfgPath,
			Signals:         []string{"traces"},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		if err := validateCollectorPreflightConfig(cfg, "traces"); err != nil {
			t.Fatalf("validateCollectorPreflightConfig unexpected error: %v", err)
		}
	})
}

func TestCollectorWrongDatasetRowsDoNotSatisfyReconciliation(t *testing.T) {
	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SeedDataset("bench-project", "otel_bench", "US")
	fakeSrv.SeedDataset("bench-project", "wrong_ds", "US")
	bin := configureCollectorHelperEnv(t, "wrong_dataset")

	cfgPath := filepath.Join(t.TempDir(), "wrong-ds-collector.yaml")
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
	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    bin,
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        400 * time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "accounted=0") || !strings.Contains(hardErr.Error(), "acked=4") {
		t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want drain failure with accounted=0 and acked=4 when commits land in wrong_ds", hardErr)
	}
	expectedKey := bqfake.CanonicalTableKey("bench-project", "otel_bench", "otel_logs")
	if gotExpected := fakeSrv.AckedRowsForTable(expectedKey); gotExpected != 0 {
		t.Fatalf("AckedRowsForTable(%q) = %d, want 0", expectedKey, gotExpected)
	}
	wrongKey := bqfake.CanonicalTableKey("bench-project", "wrong_ds", "otel_logs")
	if gotWrong := fakeSrv.AckedRowsForTable(wrongKey); gotWrong != 4 {
		t.Fatalf("AckedRowsForTable(%q) = %d, want 4", wrongKey, gotWrong)
	}
}

func TestCollectorExtensionStorageDirInjectiveAndDistinct(t *testing.T) {
	t.Parallel()
	samples := []string{
		"file_storage",
		"file_storage/A",
		"file_storage/a",
		"file_storage/Ab",
		"file_storage/ab",
		"file_storage/AB",
		"file_storage/a_b",
		"file_storage/a/b",
		"file_storage/a_2fb",
		"file_storage/a.b",
		"file_storage/a_2eb",
		"",
		".",
		"..",
	}
	seen := make(map[string]string, len(samples))
	seenLower := make(map[string]string, len(samples))
	for _, id := range samples {
		san := sanitizeExtensionDirName(id)
		if san == "" || san == "." || san == ".." || strings.ContainsAny(san, `/\.`) {
			t.Fatalf("sanitizeExtensionDirName(%q) = %q contains unsafe path characters", id, san)
		}
		if san != strings.ToLower(san) {
			t.Fatalf("sanitizeExtensionDirName(%q) = %q contains uppercase characters unsafe for case-insensitive volumes", id, san)
		}
		if prev, dup := seen[san]; dup {
			t.Fatalf("sanitizeExtensionDirName collision: %q and %q both mapped to %q", prev, id, san)
		}
		lowerSan := strings.ToLower(san)
		if prev, dup := seenLower[lowerSan]; dup {
			t.Fatalf("case-folded sanitizeExtensionDirName collision: %q and %q both folded to %q", prev, id, lowerSan)
		}
		seen[san] = id
		seenLower[lowerSan] = id
	}

	rawYAML := `
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
  file_storage/A: {}
  file_storage/a: {}
  file_storage/a_b: {}
  file_storage/a/b: {}
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: p
    dataset: d
    location: US
    sending_queue:
      enabled: true
      storage: file_storage/a_b
service:
  extensions: [health_check, file_storage/A, file_storage/a, file_storage/a_b, file_storage/a/b]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	rewritten, _, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), RunnerConfig{
		Mode:      ModeCollector,
		ProjectID: "p",
		DatasetID: "d",
		Location:  "US",
	}, "logs", collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: "/tmp/test-root",
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080/bigquery/v2/",
		dryRun:      true,
	})
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(rewritten, &doc); err != nil {
		t.Fatalf("yaml.Unmarshal rewritten: %v", err)
	}
	exts, _ := doc["extensions"].(map[string]any)
	dirA, _ := exts["file_storage/a_b"].(map[string]any)["directory"].(string)
	dirB, _ := exts["file_storage/a/b"].(map[string]any)["directory"].(string)
	if dirA == "" || dirB == "" || dirA == dirB {
		t.Fatalf("expected distinct queue directories for file_storage/a_b (%q) and file_storage/a/b (%q)", dirA, dirB)
	}
	dirUpperA, _ := exts["file_storage/A"].(map[string]any)["directory"].(string)
	dirLowerA, _ := exts["file_storage/a"].(map[string]any)["directory"].(string)
	if dirUpperA == "" || dirLowerA == "" || strings.EqualFold(dirUpperA, dirLowerA) {
		t.Fatalf("expected case-insensitively distinct queue directories for file_storage/A (%q) and file_storage/a (%q)", dirUpperA, dirLowerA)
	}
}

func TestCollectorEphemeralDatasetWithWithoutAuthProvisionsTablesViaParent(t *testing.T) {
	var (
		mu                sync.Mutex
		createdDS         = make(map[string]bool)
		createdTables     = make(map[string]map[string]any)
		updatedTables     = make(map[string]map[string]any)
		conflictOnceViews = make(map[string]map[string]any)
		deletedDS         bool
		tableQueried      bool
		authHeadersSeen   []string
	)
	var failTableCreateStatus atomic.Int32
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authHeadersSeen = append(authHeadersSeen, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/") && !strings.Contains(r.URL.Path, "/tables"):
			dsID := filepath.Base(r.URL.Path)
			mu.Lock()
			exists := createdDS[dsID]
			mu.Unlock()
			if !exists {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":{"code":404,"message":"not found"}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"datasetReference":{"projectId":"live-noauth-eph","datasetId":%q},"location":"US"}`, dsID)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/tables/"):
			tid := filepath.Base(r.URL.Path)
			mu.Lock()
			existing := conflictOnceViews[tid]
			mu.Unlock()
			if existing == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":{"code":404,"message":"not found"}}`)
				return
			}
			_ = json.NewEncoder(w).Encode(existing)
		case (r.Method == http.MethodPatch || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/tables/"):
			tid := filepath.Base(r.URL.Path)
			var patch map[string]any
			_ = json.NewDecoder(r.Body).Decode(&patch)
			mu.Lock()
			updatedTables[tid] = patch
			mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"tableReference":{"projectId":"live-noauth-eph","datasetId":"ds","tableId":%q}}`, tid)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
			var body struct {
				DatasetReference struct {
					DatasetID string `json:"datasetId"`
				} `json:"datasetReference"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			createdDS[body.DatasetReference.DatasetID] = true
			mu.Unlock()
			_, _ = fmt.Fprintf(w, `{"datasetReference":{"projectId":"live-noauth-eph","datasetId":%q},"location":"US"}`, body.DatasetReference.DatasetID)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tables"):
			if code := int(failTableCreateStatus.Load()); code != 0 {
				w.WriteHeader(code)
				_, _ = io.WriteString(w, `{"error":{"code":403,"message":"table create denied"}}`)
				return
			}
			var tbl map[string]any
			_ = json.NewDecoder(r.Body).Decode(&tbl)
			ref, _ := tbl["tableReference"].(map[string]any)
			tid, _ := ref["tableId"].(string)
			mu.Lock()
			_, hasConflict := conflictOnceViews[tid]
			if !hasConflict {
				createdTables[tid] = tbl
			}
			mu.Unlock()
			if hasConflict {
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"error":{"code":409,"message":"already exists"}}`)
				return
			}
			_, _ = fmt.Fprintf(w, `{"tableReference":{"projectId":"live-noauth-eph","datasetId":"ds","tableId":%q}}`, tid)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries"):
			mu.Lock()
			tableQueried = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(&bigqueryapi.QueryResponse{
				JobComplete: true,
				Schema: &bigqueryapi.TableSchema{
					Fields: []*bigqueryapi.TableFieldSchema{
						{Name: "total_rows", Type: "INTEGER"},
						{Name: "total_logical_bytes", Type: "INTEGER"},
						{Name: "active_physical_bytes", Type: "INTEGER"},
						{Name: "long_term_physical_bytes", Type: "INTEGER"},
						{Name: "time_travel_physical_bytes", Type: "INTEGER"},
						{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
					},
				},
				Rows: []*bigqueryapi.TableRow{{F: []*bigqueryapi.TableCell{
					{V: "4"}, {V: "4096"}, {V: "2048"}, {V: "0"}, {V: "512"}, {V: "256"},
				}}},
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
			dsID := filepath.Base(r.URL.Path)
			mu.Lock()
			deletedDS = true
			delete(createdDS, dsID)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer adminSrv.Close()

	cfgPath := filepath.Join(t.TempDir(), "collector-noauth-ephemeral.yaml")
	rawYAML := fmt.Sprintf(`
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
    project: live-noauth-eph
    dataset: placeholder_ds
    location: US
    labels:
      env: soak
    logs:
      table: custom_ephemeral_logs
      labels:
        sig: logs
    traces:
      table: custom_ephemeral_spans
      labels:
        sig: traces
    metrics:
      table: custom_ephemeral_metrics
      labels:
        sig: metrics
    quarantine:
      table: custom_ephemeral_quarantine
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      exporters: [bigquery]
`, adminSrv.URL)
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "live_ok")
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		ProjectID:          "live-noauth-eph",
		Location:           "US",
		EphemeralDataset:   true,
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           400 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Verify child YAML keeps auto_create.tables=false & companion_views=false so
	// exporter Config.Validate accepts endpoint.without_authentication=true.
	rewritten, meta, err := rewriteCollectorLoopbackConfig([]byte(rawYAML), cfg, "logs", collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:4317",
		healthAddr:  "127.0.0.1:13133",
		storageRoot: "dry",
		useBQFake:   false,
		dryRun:      true,
	})
	if err != nil {
		t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
	}
	if !meta.effectiveEndpoint.WithoutAuthentication {
		t.Fatal("expected effectiveEndpoint.WithoutAuthentication=true")
	}
	var rewrittenDoc map[string]any
	if err := yaml.Unmarshal(rewritten, &rewrittenDoc); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	exps, _ := rewrittenDoc["exporters"].(map[string]any)
	bqMap, _ := exps[meta.activeExporterID].(map[string]any)
	acMap, _ := bqMap["auto_create"].(map[string]any)
	if acMap["tables"] != false || acMap["companion_views"] != false {
		t.Fatalf("auto_create = %+v, want tables=false and companion_views=false with without_authentication=true", acMap)
	}

	rep, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run(ephemeral + without_authentication + admin_url): %v", err)
	}
	if !rep.EphemeralDatasetDeleted {
		t.Fatal("expected EphemeralDatasetDeleted = true")
	}
	mu.Lock()
	gotRunTables := make([]string, 0, len(createdTables))
	for k := range createdTables {
		gotRunTables = append(gotRunTables, k)
	}
	slices.Sort(gotRunTables)
	gotDeleted := deletedDS
	gotQueried := tableQueried
	gotAuths := slices.Clone(authHeadersSeen)
	logsViewFromRun := createdTables["custom_ephemeral_logs_dedup"]
	createdTables = make(map[string]map[string]any)
	mu.Unlock()
	if !slices.Equal(gotRunTables, []string{"custom_ephemeral_logs", "custom_ephemeral_logs_dedup", "custom_ephemeral_quarantine"}) {
		t.Fatalf("Run parent-provisioned tables & views = %v, want [custom_ephemeral_logs custom_ephemeral_logs_dedup custom_ephemeral_quarantine]", gotRunTables)
	}
	if logsViewObj, _ := logsViewFromRun["view"].(map[string]any); logsViewObj == nil || logsViewObj["useLegacySql"] != false {
		t.Fatalf("Run custom_ephemeral_logs_dedup missing StandardSQL view definition: %+v", logsViewFromRun)
	}
	if !gotDeleted || !gotQueried {
		t.Fatalf("deleted=%v queried=%v, want true, true", gotDeleted, gotQueried)
	}
	for i, authHdr := range gotAuths {
		if authHdr != "" {
			t.Fatalf("REST call %d unexpectedly carried Authorization %q", i, authHdr)
		}
	}

	// Verify multi-signal (logs, traces, metrics) preflight + ensureEphemeralDatasetTables creates
	// all 3 base tables, 1 shared quarantine table (no quarantine_dedup), and all 3 _dedup views
	// with UseLegacySQL=false, canonical view SQL, and merged per-signal labels.
	multiCfg := cfg
	multiCfg.Signals = []string{"logs", "traces", "metrics"}
	if vErr := validateRunConfig(ctx, &multiCfg, nil); vErr != nil {
		t.Fatalf("validateRunConfig(logs, traces, metrics): %v", vErr)
	}
	if err := ensureEphemeralDatasetTables(
		ctx,
		"live-noauth-eph",
		"multi_ds",
		multiCfg.collectorEphemeralTables,
		option.WithEndpoint(adminSrv.URL+"/bigquery/v2/"),
		option.WithoutAuthentication(),
	); err != nil {
		t.Fatalf("ensureEphemeralDatasetTables(logs, traces, metrics): %v", err)
	}
	mu.Lock()
	gotTables := make([]string, 0, len(createdTables))
	for k := range createdTables {
		gotTables = append(gotTables, k)
	}
	slices.Sort(gotTables)
	logsView := createdTables["custom_ephemeral_logs_dedup"]
	tracesView := createdTables["custom_ephemeral_spans_dedup"]
	metricsView := createdTables["custom_ephemeral_metrics_dedup"]
	mu.Unlock()
	wantTables := []string{
		"custom_ephemeral_logs",
		"custom_ephemeral_logs_dedup",
		"custom_ephemeral_metrics",
		"custom_ephemeral_metrics_dedup",
		"custom_ephemeral_quarantine",
		"custom_ephemeral_spans",
		"custom_ephemeral_spans_dedup",
	}
	if !slices.Equal(gotTables, wantTables) {
		t.Fatalf("multi-signal parent-provisioned tables & views = %v, want %v", gotTables, wantTables)
	}
	for _, viewCheck := range []struct {
		name    string
		tbl     map[string]any
		baseTbl string
		sigLbl  string
	}{
		{name: "custom_ephemeral_logs_dedup", tbl: logsView, baseTbl: "custom_ephemeral_logs", sigLbl: "logs"},
		{name: "custom_ephemeral_spans_dedup", tbl: tracesView, baseTbl: "custom_ephemeral_spans", sigLbl: "traces"},
		{name: "custom_ephemeral_metrics_dedup", tbl: metricsView, baseTbl: "custom_ephemeral_metrics", sigLbl: "metrics"},
	} {
		viewObj, ok := viewCheck.tbl["view"].(map[string]any)
		if !ok || viewObj == nil {
			t.Fatalf("%s missing view definition: %+v", viewCheck.name, viewCheck.tbl)
		}
		if useLegacy, _ := viewObj["useLegacySql"].(bool); useLegacy {
			t.Fatalf("%s useLegacySql = true, want false", viewCheck.name)
		}
		queryStr, _ := viewObj["query"].(string)
		if !strings.Contains(queryStr, "`live-noauth-eph.multi_ds."+viewCheck.baseTbl+"`") {
			t.Fatalf("%s view query = %q, want reference to `live-noauth-eph.multi_ds.%s`", viewCheck.name, queryStr, viewCheck.baseTbl)
		}
		lbls, _ := viewCheck.tbl["labels"].(map[string]any)
		if lbls["env"] != "soak" || lbls["sig"] != viewCheck.sigLbl {
			t.Fatalf("%s labels = %+v, want env=soak sig=%s", viewCheck.name, lbls, viewCheck.sigLbl)
		}
	}

	// Verify 409 conflict on existing base table + stale _dedup view reconciles ViewQuery via Update.
	mu.Lock()
	createdTables = make(map[string]map[string]any)
	updatedTables = make(map[string]map[string]any)
	conflictOnceViews = map[string]map[string]any{
		"custom_ephemeral_logs": {
			"tableReference": map[string]any{"projectId": "live-noauth-eph", "datasetId": "conflict_ds", "tableId": "custom_ephemeral_logs"},
			"type":           "TABLE",
			"etag":           "etag-base",
		},
		"custom_ephemeral_logs_dedup": {
			"tableReference": map[string]any{"projectId": "live-noauth-eph", "datasetId": "conflict_ds", "tableId": "custom_ephemeral_logs_dedup"},
			"type":           "VIEW",
			"etag":           "etag-view-1",
			"view": map[string]any{
				"query":        "SELECT 1",
				"useLegacySql": true,
			},
		},
	}
	mu.Unlock()
	reconcileSpecs := []ephemeralTableSpec{{
		signal:   "logs",
		table:    "custom_ephemeral_logs",
		destOpts: schema.DestinationOptions{Labels: map[string]string{"env": "soak"}},
	}}
	if recErr := ensureEphemeralDatasetTables(
		ctx,
		"live-noauth-eph",
		"conflict_ds",
		reconcileSpecs,
		option.WithEndpoint(adminSrv.URL+"/bigquery/v2/"),
		option.WithoutAuthentication(),
	); recErr != nil {
		t.Fatalf("ensureEphemeralDatasetTables(409 stale view reconcile): %v", recErr)
	}
	mu.Lock()
	patchedView := updatedTables["custom_ephemeral_logs_dedup"]
	conflictOnceViews = make(map[string]map[string]any)
	mu.Unlock()
	patchViewMap, _ := patchedView["view"].(map[string]any)
	if patchViewMap == nil || patchViewMap["useLegacySql"] != false || !strings.Contains(fmt.Sprint(patchViewMap["query"]), "custom_ephemeral_logs") {
		t.Fatalf("stale 409 _dedup view update payload = %+v, want StandardSQL query referencing custom_ephemeral_logs", patchedView)
	}

	// Verify table creation failure cleans up the already-created ephemeral dataset.
	mu.Lock()
	deletedDS = false
	createdDS = make(map[string]bool)
	mu.Unlock()
	failTableCreateStatus.Store(http.StatusForbidden)
	_, failErr := Run(ctx, cfg)
	if failErr == nil || !strings.Contains(failErr.Error(), "creating ephemeral table") || !strings.Contains(failErr.Error(), "HTTP 403") {
		t.Fatalf("Run(table create 403) = %v, want sanitized creating ephemeral table HTTP 403", failErr)
	}
	mu.Lock()
	cleanupRan := deletedDS
	mu.Unlock()
	if !cleanupRan {
		t.Fatal("expected deferred dataset cleanup to delete owned ephemeral dataset when parent table provisioning fails")
	}
}

func TestCollectorWarmupFaultFreeDuplicateRejectedWithSimulateThrottleFlag(t *testing.T) {
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
    timeout: 20ms
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
      processors: [batch]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-warmup-fault-free-dup.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(true)

	var injected atomic.Bool
	fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
		if table != "otel_logs" || len(serialized) == 0 {
			return serialized
		}
		if !injected.Swap(true) {
			return append(slices.Clone(serialized), slices.Clone(serialized[0]))
		}
		return serialized
	})

	cfg := RunnerConfig{
		Mode:                  ModeCollector,
		CollectorBin:          collectorBin,
		CollectorConfig:       cfgPath,
		Signals:               []string{"logs"},
		Workers:               1,
		BatchSize:             4,
		TargetRate:            8,
		WarmupDuration:        300 * time.Millisecond,
		Duration:              300 * time.Millisecond,
		SimulateThrottleEvery: 2,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	_, _, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "collector warmup failed gate") {
		t.Fatalf("runCollectorSingleSignalWithFake error = %v, want collector warmup failed gate when fault-free warmup commits duplicate", hardErr)
	}
	if !injected.Load() {
		t.Fatal("expected warmup duplicate hook to fire")
	}
}

func TestCollectorEphemeralDatasetPropagatesKMSKeyAndLabelsAndRunRelativeClock(t *testing.T) {
	const wantKMSKey = "projects/live-noauth-eph/locations/us/keyRings/ring-1/cryptoKeys/key-1"

	var (
		mu              sync.Mutex
		activeDatasets  = make(map[string]*bigqueryapi.Dataset)
		capturedDSPosts []bigqueryapi.Dataset
		deletedCount    int
	)
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/") && !strings.Contains(r.URL.Path, "/tables"):
			dsID := filepath.Base(r.URL.Path)
			mu.Lock()
			found := activeDatasets[dsID]
			mu.Unlock()
			if found == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = io.WriteString(w, `{"error":{"code":404,"message":"not found"}}`)
				return
			}
			_ = json.NewEncoder(w).Encode(found)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
			var ds bigqueryapi.Dataset
			if decErr := json.NewDecoder(r.Body).Decode(&ds); decErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			mu.Lock()
			capturedDSPosts = append(capturedDSPosts, ds)
			if ds.DatasetReference != nil {
				copied := ds
				activeDatasets[ds.DatasetReference.DatasetId] = &copied
			}
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(&ds)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tables"):
			_, _ = io.WriteString(w, `{}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries"):
			_ = json.NewEncoder(w).Encode(&bigqueryapi.QueryResponse{
				JobComplete: true,
				Schema: &bigqueryapi.TableSchema{
					Fields: []*bigqueryapi.TableFieldSchema{
						{Name: "total_rows", Type: "INTEGER"},
						{Name: "total_logical_bytes", Type: "INTEGER"},
						{Name: "active_physical_bytes", Type: "INTEGER"},
						{Name: "long_term_physical_bytes", Type: "INTEGER"},
						{Name: "time_travel_physical_bytes", Type: "INTEGER"},
						{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
					},
				},
				Rows: []*bigqueryapi.TableRow{{F: []*bigqueryapi.TableCell{
					{V: "4"}, {V: "4096"}, {V: "2048"}, {V: "0"}, {V: "512"}, {V: "256"},
				}}},
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
			dsID := filepath.Base(r.URL.Path)
			mu.Lock()
			deletedCount++
			delete(activeDatasets, dsID)
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer adminSrv.Close()

	cfgPath := filepath.Join(t.TempDir(), "collector-kms-labels.yaml")
	rawYAML := fmt.Sprintf(`
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
    project: live-noauth-eph
    dataset: placeholder_ds
    location: US
    kms_key_name: %q
    labels:
      cost_center: cc-42
      env: soak
      bq_otel_testbench_owner: spoofed-token
    logs:
      table: custom_kms_logs
    quarantine:
      table: custom_kms_quarantine
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, wantKMSKey, adminSrv.URL)
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "live_ok")
	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       bin,
		CollectorConfig:    cfgPath,
		ProjectID:          "live-noauth-eph",
		Location:           "US",
		EphemeralDataset:   true,
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           400 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	rep, err := Run(ctx, cfg)
	if err != nil || !rep.EphemeralDatasetDeleted {
		t.Fatalf("Run failed or did not delete dataset: rep=%+v err=%v", rep, err)
	}
	if _, err := RunStreamPoolSweep(ctx, cfg, []int{1}); err != nil {
		t.Fatalf("RunStreamPoolSweep failed: %v", err)
	}

	mu.Lock()
	gotDatasets := slices.Clone(capturedDSPosts)
	gotDeleted := deletedCount
	mu.Unlock()
	if gotDeleted != 2 || len(gotDatasets) != 2 {
		t.Fatalf("captured datasets=%d deletedCount=%d, want 2, 2 (Run + RunStreamPoolSweep)", len(gotDatasets), gotDeleted)
	}
	for idx, ds := range gotDatasets {
		if ds.DefaultEncryptionConfiguration == nil || ds.DefaultEncryptionConfiguration.KmsKeyName != wantKMSKey {
			t.Fatalf("POST /datasets[%d] DefaultEncryptionConfiguration = %+v, want KmsKeyName=%q", idx, ds.DefaultEncryptionConfiguration, wantKMSKey)
		}
		if ds.Labels["cost_center"] != "cc-42" || ds.Labels["env"] != "soak" {
			t.Fatalf("POST /datasets[%d] Labels = %+v, want cost_center=cc-42 env=soak", idx, ds.Labels)
		}
		if owner := ds.Labels[ephemeralOwnerLabelKey]; owner == "" || owner == "spoofed-token" {
			t.Fatalf("POST /datasets[%d] owner label = %q, want generated ownership token", idx, owner)
		}
	}

	checkCfg := cfg
	if vErr := validateRunConfig(ctx, &checkCfg, nil); vErr != nil {
		t.Fatalf("validateRunConfig: %v", vErr)
	}
	if checkCfg.collectorDatasetKMSKey != wantKMSKey || checkCfg.collectorDatasetLabels["cost_center"] != "cc-42" || checkCfg.collectorDatasetLabels["env"] != "soak" {
		t.Fatalf("validateRunConfig propagated kms=%q labels=%+v, want kms=%q labels={cc-42, soak}", checkCfg.collectorDatasetKMSKey, checkCfg.collectorDatasetLabels, wantKMSKey)
	}
	if checkCfg.liveRunBaseTime.IsZero() || time.Since(checkCfg.liveRunBaseTime) > time.Minute || checkCfg.liveRunBaseTime.Equal(DefaultBaseTime) {
		t.Fatalf("liveRunBaseTime = %v, want recent UTC run-relative timestamp", checkCfg.liveRunBaseTime)
	}

	// Cross-signal kms_key_name / labels conflict rejection.
	conflictYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery/logs:
    project: live-noauth-eph
    dataset: placeholder_ds
    location: US
    kms_key_name: %q
    labels:
      cost_center: cc-1
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
  bigquery/traces:
    project: live-noauth-eph
    dataset: placeholder_ds
    location: US
    kms_key_name: projects/live-noauth-eph/locations/us/keyRings/ring-2/cryptoKeys/key-2
    labels:
      cost_center: cc-1
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %s/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, wantKMSKey, adminSrv.URL, adminSrv.URL)
	conflictPath := filepath.Join(t.TempDir(), "conflict-kms.yaml")
	if wErr := os.WriteFile(conflictPath, []byte(conflictYAML), 0o600); wErr != nil {
		t.Fatalf("write conflictYAML: %v", wErr)
	}
	conflictCfg := cfg
	conflictCfg.CollectorConfig = conflictPath
	conflictCfg.Signals = []string{"logs", "traces"}
	if cErr := validateRunConfig(ctx, &conflictCfg, nil); cErr == nil || !strings.Contains(cErr.Error(), "conflicting collector kms_key_name") {
		t.Fatalf("validateRunConfig(kms conflict) = %v, want conflicting collector kms_key_name", cErr)
	}
	labelConflictYAML := strings.ReplaceAll(conflictYAML,
		"kms_key_name: projects/live-noauth-eph/locations/us/keyRings/ring-2/cryptoKeys/key-2\n    labels:\n      cost_center: cc-1",
		"kms_key_name: "+wantKMSKey+"\n    labels:\n      cost_center: cc-2",
	)
	labelConflictPath := filepath.Join(t.TempDir(), "conflict-labels.yaml")
	if wErr := os.WriteFile(labelConflictPath, []byte(labelConflictYAML), 0o600); wErr != nil {
		t.Fatalf("write labelConflictYAML: %v", wErr)
	}
	labelConflictCfg := conflictCfg
	labelConflictCfg.CollectorConfig = labelConflictPath
	if lErr := validateRunConfig(ctx, &labelConflictCfg, nil); lErr == nil || !strings.Contains(lErr.Error(), "conflicting collector labels") {
		t.Fatalf("validateRunConfig(labels conflict) = %v, want conflicting collector labels", lErr)
	}

	// Live generator timestamps use recent run-relative clock; bqfake keeps DefaultBaseTime (2026-01-01).
	before := time.Now().UTC().Truncate(time.Second)
	liveCfg := RunnerConfig{Mode: ModeCollector, CollectorAllowLive: true}
	liveBase := benchmarkGeneratorBaseTime(liveCfg)
	if liveBase.Before(before) || liveBase.After(time.Now().UTC().Add(2*time.Second)) {
		t.Fatalf("benchmarkGeneratorBaseTime(live) = %v, want around %v", liveBase, before)
	}
	mkLive, bErr := newCollectorBatchBuilder(liveCfg, "logs")
	if bErr != nil {
		t.Fatalf("newCollectorBatchBuilder(live): %v", bErr)
	}
	liveBatch, bErr := mkLive(1)
	if bErr != nil {
		t.Fatalf("mkLive(1): %v", bErr)
	}
	tsNano := liveBatch.logsReq.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Timestamp().AsTime()
	if tsNano.Before(before) {
		t.Fatalf("live collector generated log timestamp = %v, want >= %v (not expired DefaultBaseTime)", tsNano, before)
	}
	fakeCfg := RunnerConfig{Mode: ModeCollector, CollectorAllowLive: false}
	if gotFake := benchmarkGeneratorBaseTime(fakeCfg); !gotFake.Equal(DefaultBaseTime) {
		t.Fatalf("benchmarkGeneratorBaseTime(fake) = %v, want DefaultBaseTime %v", gotFake, DefaultBaseTime)
	}
}

func TestCollectorRedactionEnvBlockedValuePatterns(t *testing.T) {
	ep := collectorEndpointOverride{
		otlpAddr:    "127.0.0.1:43179",
		healthAddr:  "127.0.0.1:13139",
		storageRoot: t.TempDir(),
		useBQFake:   true,
		fakeGRPCURL: "127.0.0.1:50051",
		fakeRESTURL: "http://127.0.0.1:8080",
		dryRun:      true,
	}
	baseYAML := func(patternsLine string) string {
		return fmt.Sprintf(`
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
    redaction:
      enabled: true
      blocked_value_patterns: %s
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, patternsLine)
	}

	t.Run("JSONEnvListWithDollarAnchorsAndDeduplication", func(t *testing.T) {
		t.Setenv("BQ_TEST_BLOCKED_PATTERNS", fmt.Sprintf(
			`["^SEC_[0-9]+$", "COST_$$[0-9]+", "$${env:RAW_LITERAL}", %q]`,
			blockedSecretPatterns[0],
		))
		cfgPath := filepath.Join(t.TempDir(), "collector-env-json.yaml")
		raw := baseYAML("${env:BQ_TEST_BLOCKED_PATTERNS}")
		if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Redaction:       true,
			ProjectID:       "bench-project",
			DatasetID:       "otel_bench",
			Location:        "US",
		}
		if _, err := validateCollectorPreflightConfigWithMeta(cfg, "logs"); err != nil {
			t.Fatalf("validateCollectorPreflightConfigWithMeta: %v", err)
		}
		out, meta, err := rewriteCollectorLoopbackConfig([]byte(raw), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig: %v", err)
		}
		wantResolved := append([]string{"^SEC_[0-9]+$", "COST_$[0-9]+", "${env:RAW_LITERAL}"}, blockedSecretPatterns...)
		if !slices.Equal(meta.effectiveRedactionConfig.BlockedValuePatterns, wantResolved) {
			t.Fatalf("effective BlockedValuePatterns = %q, want %q", meta.effectiveRedactionConfig.BlockedValuePatterns, wantResolved)
		}

		var doc map[string]any
		if err := yaml.Unmarshal(out, &doc); err != nil {
			t.Fatalf("yaml.Unmarshal rewritten: %v", err)
		}
		exps, _ := doc["exporters"].(map[string]any)
		bqMap, _ := exps["bigquery"].(map[string]any)
		redMap, _ := bqMap["redaction"].(map[string]any)
		gotChildYAML, err := extractYAMLStringSlice(redMap["blocked_value_patterns"])
		if err != nil {
			t.Fatalf("extract child blocked_value_patterns: %v", err)
		}
		wantChildYAML := append([]string{"^SEC_[0-9]+$$", "COST_$$[0-9]+", "$${env:RAW_LITERAL}"}, blockedSecretPatterns...)
		if !slices.Equal(gotChildYAML, wantChildYAML) {
			t.Fatalf("child YAML blocked_value_patterns = %q, want %q", gotChildYAML, wantChildYAML)
		}
	})

	t.Run("MultilineYAMLEnvListAndPerElementEnvRefs", func(t *testing.T) {
		t.Setenv("BQ_TEST_YAML_LIST", "- '^ML_A_[0-9]+$'\n- 'PREFIX_$$10'\n")
		cfg := RunnerConfig{
			Mode:      ModeCollector,
			Redaction: true,
			ProjectID: "bench-project",
			DatasetID: "otel_bench",
			Location:  "US",
		}
		_, meta, err := rewriteCollectorLoopbackConfig([]byte(baseYAML("${env:BQ_TEST_YAML_LIST}")), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(multiline env): %v", err)
		}
		wantPrefix := []string{"^ML_A_[0-9]+$", "PREFIX_$10"}
		if len(meta.effectiveRedactionConfig.BlockedValuePatterns) < 2 || !slices.Equal(meta.effectiveRedactionConfig.BlockedValuePatterns[:2], wantPrefix) {
			t.Fatalf("effective BlockedValuePatterns = %q, want prefix %q", meta.effectiveRedactionConfig.BlockedValuePatterns, wantPrefix)
		}

		t.Setenv("BQ_TEST_ITEM_REGEX", "^ELEM_TOKEN_[0-9]+$")
		itemRaw := baseYAML("\n      - ${env:BQ_TEST_ITEM_REGEX}\n      - 'ANCHOR_$${env:KEEP}$'")
		_, itemMeta, err := rewriteCollectorLoopbackConfig([]byte(itemRaw), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(item env): %v", err)
		}
		wantItemPrefix := []string{"^ELEM_TOKEN_[0-9]+$", "ANCHOR_${env:KEEP}$"}
		if len(itemMeta.effectiveRedactionConfig.BlockedValuePatterns) < 2 || !slices.Equal(itemMeta.effectiveRedactionConfig.BlockedValuePatterns[:2], wantItemPrefix) {
			t.Fatalf("effective item BlockedValuePatterns = %q, want prefix %q", itemMeta.effectiveRedactionConfig.BlockedValuePatterns, wantItemPrefix)
		}
	})

	t.Run("NestedWordBoundaryEscapeAndExplicitEmptySequence", func(t *testing.T) {
		t.Setenv("BQ_TEST_NESTED_RX", `\bID-[0-9]+\b`)
		t.Setenv("BQ_TEST_OUTER_LIST", "${env:BQ_TEST_INNER_LIST}")
		t.Setenv("BQ_TEST_INNER_LIST", `["${env:BQ_TEST_NESTED_RX}"]`)
		for _, redactionFlag := range []bool{true, false} {
			t.Run(fmt.Sprintf("redaction=%t", redactionFlag), func(t *testing.T) {
				raw := baseYAML("${env:BQ_TEST_OUTER_LIST}")
				cfgPath := filepath.Join(t.TempDir(), "collector-nested-rx.yaml")
				if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
					t.Fatalf("write config: %v", err)
				}
				cfg := RunnerConfig{
					Mode:            ModeCollector,
					CollectorBin:    os.Args[0],
					CollectorConfig: cfgPath,
					Signals:         []string{"logs"},
					Redaction:       redactionFlag,
					ProjectID:       "bench-project",
					DatasetID:       "otel_bench",
					Location:        "US",
				}
				meta, err := validateCollectorPreflightConfigWithMeta(cfg, "logs")
				if err != nil {
					t.Fatalf("validateCollectorPreflightConfigWithMeta: %v", err)
				}
				wantPrefix := []string{`\bID-[0-9]+\b`}
				if len(meta.effectiveRedactionConfig.BlockedValuePatterns) == 0 || !slices.Equal(meta.effectiveRedactionConfig.BlockedValuePatterns[:1], wantPrefix) {
					t.Fatalf("BlockedValuePatterns = %q, want %q prefix (literal \\b preserved, not 0x08)", meta.effectiveRedactionConfig.BlockedValuePatterns, wantPrefix)
				}
				if strings.Contains(meta.effectiveRedactionConfig.BlockedValuePatterns[0], "\b") {
					t.Fatalf("pattern contains literal ASCII 0x08 backspace: %q", meta.effectiveRedactionConfig.BlockedValuePatterns[0])
				}

				// Explicit inline [], env '[]', and absent optional nil remain valid.
				t.Setenv("BQ_TEST_EXPLICIT_EMPTY", "[]")
				for _, emptyExpr := range []string{"[]", "${env:BQ_TEST_EXPLICIT_EMPTY}", "null"} {
					emptyPath := filepath.Join(t.TempDir(), "collector-empty.yaml")
					emptyRaw := baseYAML(emptyExpr)
					if err := os.WriteFile(emptyPath, []byte(emptyRaw), 0o600); err != nil {
						t.Fatalf("write config: %v", err)
					}
					emptyCfg := cfg
					emptyCfg.CollectorConfig = emptyPath
					if _, err := validateCollectorPreflightConfigWithMeta(emptyCfg, "logs"); err != nil {
						t.Fatalf("expr=%q redaction=%t: unexpected preflight error: %v", emptyExpr, redactionFlag, err)
					}
				}
			})
		}
	})

	t.Run("InvalidAndSecretValuesFailClosedWithoutLeak", func(t *testing.T) {
		for _, redactionFlag := range []bool{true, false} {
			modeLabel := fmt.Sprintf("redaction=%t", redactionFlag)
			t.Run(modeLabel, func(t *testing.T) {
				for _, tc := range []struct {
					name     string
					expr     string
					envVar   string
					envVal   string
					setEnv   bool
					secrets  []string
					wantSubs []string
				}{
					{
						name:     "UnsetEnvVarRejected",
						expr:     "${env:BQ_TEST_DEFINITELY_UNSET_PATTERNS}",
						wantSubs: []string{"redaction.blocked_value_patterns", "null"},
					},
					{
						name:     "EmptyEnvVarRejected",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "",
						setEnv:   true,
						wantSubs: []string{"redaction.blocked_value_patterns", "null"},
					},
					{
						name:     "WhitespaceEnvVarRejected",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "   \n",
						setEnv:   true,
						wantSubs: []string{"redaction.blocked_value_patterns", "null"},
					},
					{
						name:     "NullEnvVarRejected",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "null",
						setEnv:   true,
						wantSubs: []string{"redaction.blocked_value_patterns", "null"},
					},
					{
						name:     "TildeNullEnvVarRejected",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "~",
						setEnv:   true,
						wantSubs: []string{"redaction.blocked_value_patterns", "null"},
					},
					{
						name:     "InlineMapElementNeverLeaksMapKey",
						expr:     `[{SECRET_MAP_KEY: "SECRET_MAP_VALUE"}]`,
						secrets:  []string{"SECRET_MAP_KEY", "SECRET_MAP_VALUE"},
						wantSubs: []string{"blocked_value_patterns[0]", "expected string, got map"},
					},
					{
						name:     "EnvMapElementNeverLeaksMapKey",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   `[{"SECRET_MAP_KEY":"SECRET_MAP_VALUE"}]`,
						setEnv:   true,
						secrets:  []string{"SECRET_MAP_KEY", "SECRET_MAP_VALUE"},
						wantSubs: []string{"blocked_value_patterns[0]", "expected string, got map"},
					},
					{
						name:     "NonSequenceString",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "SECRET_INLINE_SCALAR_NEVER_LEAK",
						setEnv:   true,
						secrets:  []string{"SECRET_INLINE_SCALAR_NEVER_LEAK"},
						wantSubs: []string{"redaction.blocked_value_patterns"},
					},
					{
						name:     "CommaScalarNotCoercedIntoSlice",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "SECRET_A,SECRET_B",
						secrets:  []string{"SECRET_A", "SECRET_B"},
						wantSubs: []string{"redaction.blocked_value_patterns", "expected YAML sequence of strings"},
					},
					{
						name:     "NonStringSequenceItem",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   `[42, "SECRET_ELEM_NEVER_LEAK"]`,
						secrets:  []string{"SECRET_ELEM_NEVER_LEAK"},
						wantSubs: []string{"redaction.blocked_value_patterns"},
					},
					{
						name:     "InvalidYAMLSequence",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   `[unclosed_SECRET_YAML_LEAK`,
						secrets:  []string{"SECRET_YAML_LEAK"},
						wantSubs: []string{"redaction.blocked_value_patterns"},
					},
					{
						name:     "UnsupportedProviderScheme",
						expr:     "${file:/etc/shadow_secret_path}",
						secrets:  []string{"shadow_secret_path"},
						wantSubs: []string{"redaction.blocked_value_patterns"},
					},
					{
						name:     "InvalidRE2InEnvElementRedactsPattern",
						expr:     `["${env:BQ_SECRET_ENV}"]`,
						envVar:   "BQ_SECRET_ENV",
						envVal:   "sk-secret-[unclosed",
						secrets:  []string{"sk-secret", "[unclosed"},
						wantSubs: []string{"blocked_value_patterns[0]", "invalid regular expression"},
					},
					{
						name:     "EmptyMatchingRegexInEnvElementRedactsPattern",
						expr:     `["${env:BQ_SECRET_ENV}"]`,
						envVar:   "BQ_SECRET_ENV",
						envVal:   "secret-token|",
						secrets:  []string{"secret-token"},
						wantSubs: []string{"blocked_value_patterns[0]", "empty"},
					},
					{
						name:     "InvalidRE2ScalarEnvNeverCoercedOrLeaked",
						expr:     "${env:BQ_TEST_BAD_PATTERNS}",
						envVar:   "BQ_TEST_BAD_PATTERNS",
						envVal:   "SECRET_[unclosed",
						secrets:  []string{"SECRET_", "[unclosed"},
						wantSubs: []string{"redaction.blocked_value_patterns"},
					},
				} {
					t.Run(tc.name, func(t *testing.T) {
						if tc.setEnv || tc.envVar != "" {
							t.Setenv(tc.envVar, tc.envVal)
						}
						raw := baseYAML(tc.expr)
						cfgPath := filepath.Join(t.TempDir(), "collector-bad-patterns.yaml")
						if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
							t.Fatalf("write config: %v", err)
						}
						cfg := RunnerConfig{
							Mode:            ModeCollector,
							CollectorBin:    os.Args[0],
							CollectorConfig: cfgPath,
							Signals:         []string{"logs"},
							Redaction:       redactionFlag,
							ProjectID:       "bench-project",
							DatasetID:       "otel_bench",
							Location:        "US",
						}
						if _, _, err := rewriteCollectorLoopbackConfig([]byte(raw), cfg, "logs", ep); err == nil {
							t.Fatalf("rewriteCollectorLoopbackConfig expected error for %s (%s)", tc.name, modeLabel)
						} else {
							for _, want := range tc.wantSubs {
								if !strings.Contains(err.Error(), want) {
									t.Fatalf("rewrite error = %q, want %q", err.Error(), want)
								}
							}
							for _, secret := range tc.secrets {
								if strings.Contains(err.Error(), secret) {
									t.Fatalf("rewrite error leaked secret %q: %q", secret, err.Error())
								}
							}
						}
						if _, err := validateCollectorPreflightConfigWithMeta(cfg, "logs"); err == nil {
							t.Fatalf("validateCollectorPreflightConfigWithMeta expected error for %s (%s)", tc.name, modeLabel)
						} else {
							for _, want := range tc.wantSubs {
								if !strings.Contains(err.Error(), want) {
									t.Fatalf("preflight error = %q, want %q", err.Error(), want)
								}
							}
							for _, secret := range tc.secrets {
								if strings.Contains(err.Error(), secret) {
									t.Fatalf("preflight error leaked secret %q: %q", secret, err.Error())
								}
							}
						}
					})
				}
			})
		}
	})

	t.Run("WithoutRedactionFlagEnvSuppliedListStillValidatesAndPreservesDollars", func(t *testing.T) {
		t.Setenv("BQ_TEST_ENV_ONLY_PATTERNS", `["^YAML_SEC_[0-9]+$", "COST_$$[0-9]+"]`)
		raw := baseYAML("${env:BQ_TEST_ENV_ONLY_PATTERNS}")
		cfgPath := filepath.Join(t.TempDir(), "collector-env-yaml-redaction-only.yaml")
		if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: cfgPath,
			Signals:         []string{"logs"},
			Redaction:       false,
			ProjectID:       "bench-project",
			DatasetID:       "otel_bench",
			Location:        "US",
		}
		meta, err := validateCollectorPreflightConfigWithMeta(cfg, "logs")
		if err != nil {
			t.Fatalf("validateCollectorPreflightConfigWithMeta(Redaction=false): %v", err)
		}
		if !meta.effectiveRedaction {
			t.Fatal("expected effectiveRedaction=true from YAML redaction.enabled=true")
		}
		want := []string{"^YAML_SEC_[0-9]+$", "COST_$[0-9]+"}
		if !slices.Equal(meta.effectiveRedactionConfig.BlockedValuePatterns, want) {
			t.Fatalf("effective BlockedValuePatterns = %q, want %q", meta.effectiveRedactionConfig.BlockedValuePatterns, want)
		}
		out, _, err := rewriteCollectorLoopbackConfig([]byte(raw), cfg, "logs", ep)
		if err != nil {
			t.Fatalf("rewriteCollectorLoopbackConfig(Redaction=false): %v", err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(out, &doc); err != nil {
			t.Fatalf("yaml.Unmarshal rewritten: %v", err)
		}
		exps, _ := doc["exporters"].(map[string]any)
		bqMap, _ := exps["bigquery"].(map[string]any)
		redMap, _ := bqMap["redaction"].(map[string]any)
		gotChildYAML, err := extractYAMLStringSlice(redMap["blocked_value_patterns"])
		if err != nil {
			t.Fatalf("extract child blocked_value_patterns: %v", err)
		}
		wantChildYAML := []string{"^YAML_SEC_[0-9]+$$", "COST_$$[0-9]+"}
		if !slices.Equal(gotChildYAML, wantChildYAML) {
			t.Fatalf("child YAML blocked_value_patterns = %q, want %q", gotChildYAML, wantChildYAML)
		}
	})
}

func TestCollectorIntegrationRedactionEnvBlockedValuePatterns(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	t.Setenv("BQ_TEST_ENV_WORD_BOUNDARY_RX", `\bID-[0-9]+\b`)
	t.Setenv("BQ_TEST_ENV_REDACT_PATTERNS", `["CUSTOM_END_DOLLAR_[0-9]+$", "COST_\\$$[0-9]+", "${env:BQ_TEST_ENV_WORD_BOUNDARY_RX}"]`)

	cfgPath := filepath.Join(t.TempDir(), "collector-env-redact-integration.yaml")
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
  attributes/redact_samples:
    actions:
      - key: sample.anchor_match
        value: CUSTOM_END_DOLLAR_1234
        action: upsert
      - key: sample.anchor_nonmatch
        value: CUSTOM_END_DOLLAR_1234_suffix
        action: upsert
      - key: sample.cost_literal
        value: COST_$$99
        action: upsert
      - key: sample.word_boundary_match
        value: prefix ID-12345 suffix
        action: upsert
      - key: sample.word_boundary_nonmatch
        value: XID-12345
        action: upsert
      - key: sample.default_bearer
        value: Bearer sk-secret0123456789abcdef
        action: upsert
  batch:
    send_batch_size: 4
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
    redaction:
      enabled: true
      blocked_value_patterns: ${env:BQ_TEST_ENV_REDACT_PATTERNS}
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      processors: [attributes/redact_samples, batch]
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
		Signals:         []string{"logs"},
		WorkloadProfile: WorkloadProfileAccessLogs,
		Redaction:       true,
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil || softErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
	}
	if lossErr := checkSignalResultLossless(cfg, "logs", res, softErr); lossErr != nil {
		t.Fatalf("checkSignalResultLossless: %v", lossErr)
	}
	if res.MatchedRows != 4 || res.DeliveredRows != 4 || res.Telemetry.RedactedValuesTotal <= 0 {
		t.Fatalf("matched=%d delivered=%d redacted=%d, want 4/4/>0",
			res.MatchedRows, res.DeliveredRows, res.Telemetry.RedactedValuesTotal)
	}
	rows := fakeSrv.Rows("otel_logs")
	if len(rows) != 4 {
		t.Fatalf("len(otel_logs) = %d, want 4", len(rows))
	}
	rawAttrs, ok := rows[0]["attributes"].(string)
	if !ok || rawAttrs == "" {
		t.Fatalf("row[0] missing attributes JSON string: %+v", rows[0])
	}
	var attrs map[string]any
	if err := json.Unmarshal([]byte(rawAttrs), &attrs); err != nil {
		t.Fatalf("unmarshal row[0] attributes: %v (%s)", err, rawAttrs)
	}
	if got := attrs["sample.anchor_match"]; got != "[REDACTED]" {
		t.Fatalf("sample.anchor_match = %v, want [REDACTED] (regex $ end anchor preserved)", got)
	}
	if got := attrs["sample.anchor_nonmatch"]; got != "CUSTOM_END_DOLLAR_1234_suffix" {
		t.Fatalf("sample.anchor_nonmatch = %v, want unredacted CUSTOM_END_DOLLAR_1234_suffix (regex $ anchor must not over-match)", got)
	}
	if got := attrs["sample.cost_literal"]; got != "[REDACTED]" {
		t.Fatalf("sample.cost_literal = %v, want [REDACTED] (literal $ escaped properly)", got)
	}
	if got := attrs["sample.word_boundary_match"]; got != "prefix [REDACTED] suffix" {
		t.Fatalf("sample.word_boundary_match = %v, want %q (nested \\b preserved, not decoded as backspace)", got, "prefix [REDACTED] suffix")
	}
	if got := attrs["sample.word_boundary_nonmatch"]; got != "XID-12345" {
		t.Fatalf("sample.word_boundary_nonmatch = %v, want unredacted XID-12345 (\\b word boundary enforced)", got)
	}
	if got := attrs["sample.default_bearer"]; got != "[REDACTED]" {
		t.Fatalf("sample.default_bearer = %v, want [REDACTED] (benchmark default secret pattern merged)", got)
	}
}

func TestCollectorIntegrationAllowPartialFailuresZeroMatchedRowsFails(t *testing.T) {
	collectorBin := findCollectorDistBinary(t)
	enc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}

	cfgPath := filepath.Join(t.TempDir(), "collector-zero-match-partial.yaml")
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
  batch:
    send_batch_size: 2
    timeout: 50ms
exporters:
  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
    logs:
      table: otel_logs
      synthesize_insert_id: true
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

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(true)

	unrelatedTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
	var (
		nextID   atomic.Int64
		replaced atomic.Bool
	)
	fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
		if table != "otel_logs" || len(serialized) == 0 {
			return serialized
		}
		replaced.Store(true)
		out := make([][]byte, 0, len(serialized))
		for range serialized {
			id := nextID.Add(1)
			raw, eErr := enc.Encode(transform.Row{
				"timestamp":               unrelatedTS.UnixMicro(),
				"timestamp_source":        "observed",
				"time_unix_nano":          unrelatedTS.UnixNano(),
				"observed_time_unix_nano": unrelatedTS.UnixNano(),
				"receive_time":            unrelatedTS.UnixMicro(),
				"receive_time_unix_nano":  unrelatedTS.UnixNano(),
				"log_name":                "projects/test-project/logs/unrelated",
				"insert_id":               fmt.Sprintf("unrelated-col-%d", id),
				"body":                    `"unrelated"`,
			})
			if eErr != nil {
				t.Errorf("Encode(unrelated-col-%d): %v", id, eErr)
				return serialized
			}
			out = append(out, raw)
		}
		return out
	})

	cfg := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         collectorBin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		WorkloadProfile:      WorkloadProfileAccessLogs,
		Workers:              1,
		BatchSize:            2,
		maxBatches:           1,
		Duration:             5 * time.Second,
		WarmupDuration:       0,
		AllowPartialFailures: true,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	res, softErr, hardErr := runCollectorSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runCollectorSingleSignalWithFake hardErr = %v, want nil", hardErr)
	}
	if !replaced.Load() {
		t.Fatal("before-commit replacement hook never fired")
	}
	if !res.Reconciled || res.DeliveredRows != res.RecordsSubmitted || res.MatchedRows != 0 || res.UnexpectedRows != res.RecordsSubmitted || res.MissingRows != res.RecordsSubmitted {
		t.Fatalf("got (reconciled=%v, delivered=%d, matched=%d, unexpected=%d, missing=%d, submitted=%d), want (true, %d, 0, %d, %d, %d)",
			res.Reconciled, res.DeliveredRows, res.MatchedRows, res.UnexpectedRows, res.MissingRows, res.RecordsSubmitted,
			res.RecordsSubmitted, res.RecordsSubmitted, res.RecordsSubmitted, res.RecordsSubmitted)
	}
	lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
	if lossErr == nil || !strings.Contains(lossErr.Error(), "matched 0 submitted rows") {
		t.Fatalf("checkSignalResultLossless(AllowPartialFailures=true, MatchedRows=0) = %v, want matched 0 submitted rows error", lossErr)
	}
}
