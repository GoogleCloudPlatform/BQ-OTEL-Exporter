// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

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
	if valid.StreamPoolSize <= 0 || valid.ConnectionPoolSize <= 0 {
		t.Fatalf("expected positive pool defaults, got stream=%d conn=%d", valid.StreamPoolSize, valid.ConnectionPoolSize)
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
