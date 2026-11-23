// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/cli/testbench"
)

func TestCLIRunBQFakeAndJSONOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	jsonPath := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer

	err := run(ctx, []string{
		"-mode=bqfake",
		"-signals=traces,logs",
		"-duration=200ms",
		"-batch-size=40",
		"-workers=2",
		"-stream-pool-size=2",
		"-redaction=true",
		"-format=markdown",
		"-json-out=" + jsonPath,
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run() unexpected error: %v (stderr: %s)", err, stderr.String())
	}

	outStr := stdout.String()
	if !strings.Contains(outStr, "| `traces` |") || !strings.Contains(outStr, "| `logs` |") || !strings.Contains(outStr, "Encoded-Row MiB/s") {
		t.Fatalf("stdout missing expected markdown table headers/rows:\n%s", outStr)
	}

	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading json-out file: %v", err)
	}
	var report testbench.BenchmarkReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshaling json-out: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("len(report.Results) = %d, want 2", len(report.Results))
	}

	// Regression check for small -payload-bytes values (e.g. 64 bytes in [11, 105])
	// with -unique-payloads and -redaction enabled.
	stdout.Reset()
	stderr.Reset()
	if err := run(ctx, []string{
		"-mode=bqfake",
		"-signals=traces,logs",
		"-duration=100ms",
		"-batch-size=20",
		"-workers=1",
		"-stream-pool-size=1",
		"-payload-bytes=64",
		"-unique-payloads=true",
		"-redaction=true",
		"-format=json",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run(-payload-bytes=64) unexpected error: %v (stderr: %s)", err, stderr.String())
	}
}

func TestCLISweepAndFlagValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	err := run(ctx, []string{
		"-mode=bqfake",
		"-signals=traces",
		"-duration=150ms",
		"-batch-size=32",
		"-workers=2",
		"-stream-pool-sweep=1,2",
		"-format=json",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run(-stream-pool-sweep=1,2) error: %v", err)
	}

	var report testbench.BenchmarkReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("unmarshaling json stdout: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("len(report.Results) = %d, want 2", len(report.Results))
	}
	if report.Config.ConnectionPoolSize != 4 || report.Config.MaxInflightRequests != 32 || report.Config.MaxRequestBytes != 8*1024*1024 {
		t.Fatalf("default bqfake write config = (%d, %d, %d), want (4, 32, 8388608)",
			report.Config.ConnectionPoolSize, report.Config.MaxInflightRequests, report.Config.MaxRequestBytes)
	}

	badFlagCases := [][]string{
		{"-format=xml"},
		{"-workload-profile=invalid"},
		{"-workload-profile=access-logs", "-signals=traces"},
		{"-soak", "-duration=10s"},
		{"-resource-attrs=-1"},
		{"-resource-attrs=257"},
		{"-max-procs=-1"},
		{"-stream-pool-sweep=0,abc"},
		{"-stream-pool-size=-1"},
		{"-stream-pool-size=17"},
		{"-connection-pool-size=-1"},
		{"-connection-pool-size=17"},
		{"-max-inflight-requests=-1"},
		{"-max-inflight-requests=65537"},
		{"-max-inflight-requests=9223372036854775807"},
		{"-max-request-bytes=-1"},
		{"unexpected-positional-arg"},
	}
	for _, args := range badFlagCases {
		stdout.Reset()
		stderr.Reset()
		if err := run(ctx, args, &stdout, &stderr); err == nil {
			t.Errorf("run(%v) succeeded, want error", args)
		}
		if code := runArgs(ctx, args, &stdout, &stderr); code != 2 {
			t.Errorf("runArgs(%v) = %d, want exit 2 (stderr=%q)", args, code, stderr.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	if err := run(ctx, []string{
		"-mode=bqfake",
		"-signals=traces",
		"-duration=100ms",
		"-batch-size=20",
		"-workers=1",
		"-stream-pool-size=0",
		"-connection-pool-size=0",
		"-max-inflight-requests=0",
		"-max-request-bytes=0",
		"-format=json",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run(explicit =0 write flags) error: %v (stderr: %s)", err, stderr.String())
	}
	var zeroReport testbench.BenchmarkReport
	if err := json.Unmarshal(stdout.Bytes(), &zeroReport); err != nil {
		t.Fatalf("unmarshaling explicit =0 json stdout: %v", err)
	}
	if zeroReport.Config.StreamPoolSize != 4 ||
		zeroReport.Config.ConnectionPoolSize != 4 ||
		zeroReport.Config.MaxInflightRequests != 32 ||
		zeroReport.Config.MaxRequestBytes != 8*1024*1024 {
		t.Fatalf("explicit =0 bqfake write config = (%d, %d, %d, %d), want (4, 4, 32, 8388608)",
			zeroReport.Config.StreamPoolSize,
			zeroReport.Config.ConnectionPoolSize,
			zeroReport.Config.MaxInflightRequests,
			zeroReport.Config.MaxRequestBytes)
	}
}

func TestRunArgsExitCodes(t *testing.T) {
	ctx := context.Background()

	for _, flagName := range []string{"-h", "-help"} {
		t.Run("help_"+flagName, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runArgs(ctx, []string{flagName}, &stdout, &stderr)
			if code != 0 {
				t.Fatalf("%s exit code = %d, want 0; stderr=%q", flagName, code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("%s wrote unexpected stdout %q", flagName, stdout.String())
			}
			if strings.Contains(stderr.String(), "bq-otel-testbench: ") || strings.Contains(stderr.String(), "flag: help requested") {
				t.Errorf("%s stderr should not contain error prefix: %q", flagName, stderr.String())
			}
			if !strings.Contains(stderr.String(), "Usage of bq-otel-testbench:") {
				t.Errorf("%s stderr missing usage header: %q", flagName, stderr.String())
			}
		})
	}

	usageCases := [][]string{
		{"-bogus"},
		{"-mode=invalid"},
		{"-mode=live"},
		{"-signals=profiles"},
		{"-stream-pool-sweep=17"},
	}
	for _, args := range usageCases {
		var stdout, stderr bytes.Buffer
		if code := runArgs(ctx, args, &stdout, &stderr); code != 2 {
			t.Errorf("runArgs(%v) = %d, want exit 2 (stderr=%q)", args, code, stderr.String())
		}
	}

	t.Run("runtime failure exits 1", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		badOut := filepath.Join(t.TempDir(), "missing", "report.json")
		code := runArgs(ctx, []string{"-mode=bqfake", "-duration=10ms", "-batch-size=1", "-workers=1", "-json-out=" + badOut}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runtime failure exit code = %d, want 1; stderr=%q", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "bq-otel-testbench: ") {
			t.Errorf("runtime failure stderr missing prefix: %q", stderr.String())
		}
	})
}

func TestCLIAccessLogsAndProfiles(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	cpuPath := filepath.Join(tmpDir, "cpu.pprof")
	memPath := filepath.Join(tmpDir, "mem.pprof")
	var stdout, stderr bytes.Buffer

	err := run(ctx, []string{
		"-mode=bqfake",
		"-workload-profile=access-logs",
		"-resource-attrs=10",
		"-upstream-insert-id=true",
		"-max-procs=2",
		"-duration=150ms",
		"-batch-size=25",
		"-workers=1",
		"-stream-pool-size=1",
		"-cpuprofile=" + cpuPath,
		"-memprofile=" + memPath,
		"-format=markdown",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run(access-logs) error: %v (stderr: %s)", err, stderr.String())
	}

	outStr := stdout.String()
	for _, want := range []string{"profile=access-logs", "5-Layer Byte Accounting", "Field-Family Wire Byte Breakdown"} {
		if !strings.Contains(outStr, want) {
			t.Errorf("stdout missing %q:\n%s", want, outStr)
		}
	}

	for _, p := range []string{cpuPath, memPath} {
		info, statErr := os.Stat(p)
		if statErr != nil {
			t.Fatalf("stat(%s): %v", p, statErr)
		}
		if info.Size() == 0 {
			t.Errorf("profile %s is empty", p)
		}
		if runtime.GOOS != "windows" {
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Errorf("profile %s mode = %o, want 0600", p, perm)
			}
		}
	}
}

func TestCLIModeCollectorPreservesYAMLWriteConfig(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	cfgPath := filepath.Join(t.TempDir(), "collector.yaml")
	const yamlBody = `receivers:
  otlp: {}
exporters:
  bigquery:
    write:
      stream_pool_size: 17
      max_request_bytes: 262144
      max_row_bytes: 524288
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("writing collector config: %v", err)
	}

	t.Run("omitted_flags_preserve_yaml", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(ctx, []string{
			"-mode=collector",
			"-collector-bin=" + os.Args[0],
			"-collector-config=" + cfgPath,
			"-signals=logs",
			"-duration=10ms",
		}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "stream_pool_size") {
			t.Fatalf("run() error = %v, want stream_pool_size validation error", err)
		}
	})

	t.Run("selective_override_preserves_other_yaml_fields", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(ctx, []string{
			"-mode=collector",
			"-collector-bin=" + os.Args[0],
			"-collector-config=" + cfgPath,
			"-signals=logs",
			"-duration=10ms",
			"-stream-pool-size=4",
		}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "max_row_bytes") {
			t.Fatalf("run() error = %v, want max_row_bytes validation error", err)
		}
		if strings.Contains(err.Error(), "stream_pool_size") {
			t.Fatalf("run() error = %v, did not expect stream_pool_size error after -stream-pool-size=4 override", err)
		}
	})

	t.Run("explicit_zero_flags_preserve_yaml", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run(ctx, []string{
			"-mode=collector",
			"-collector-bin=" + os.Args[0],
			"-collector-config=" + cfgPath,
			"-signals=logs",
			"-duration=10ms",
			"-stream-pool-size=0",
			"-connection-pool-size=0",
			"-max-inflight-requests=0",
			"-max-request-bytes=0",
		}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "stream_pool_size") {
			t.Fatalf("run() error = %v, want YAML stream_pool_size validation error", err)
		}
		var uerr usageError
		if errors.As(err, &uerr) {
			t.Fatalf("run() returned flag usageError %v, want Collector YAML validation error", err)
		}
	})
}

func TestCLIEmitReportAndJSONOutOnLosslessGateFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	tmpDir := t.TempDir()
	memPath := filepath.Join(tmpDir, "mem.pprof")
	jsonPath := filepath.Join(tmpDir, "report.json")
	var stdout, stderr bytes.Buffer

	code := runArgs(ctx, []string{
		"-mode=bqfake",
		"-signals=traces",
		"-simulate-ack-delay=200ms",
		"-call-timeout=40ms",
		"-duration=350ms",
		"-batch-size=10",
		"-workers=1",
		"-stream-pool-size=1",
		"-memprofile=" + memPath,
		"-json-out=" + jsonPath,
		"-format=both",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("runArgs() = %d, want 1 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "bq-otel-testbench: ") {
		t.Errorf("stderr missing error prefix: %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "Encoded-Row MiB/s") {
		t.Errorf("stdout missing Markdown report header:\n%s", stdout.String())
	}

	memInfo, err := os.Stat(memPath)
	if err != nil {
		t.Fatalf("stat(%s): %v", memPath, err)
	}
	if memInfo.Size() == 0 {
		t.Errorf("memprofile %s is empty", memPath)
	}
	if runtime.GOOS != "windows" {
		if perm := memInfo.Mode().Perm(); perm != 0o600 {
			t.Errorf("memprofile %s mode = %o, want 0600", memPath, perm)
		}
	}

	jsonInfo, err := os.Stat(jsonPath)
	if err != nil {
		t.Fatalf("stat(%s): %v", jsonPath, err)
	}
	if runtime.GOOS != "windows" {
		if perm := jsonInfo.Mode().Perm(); perm != 0o600 {
			t.Errorf("json-out %s mode = %o, want 0600", jsonPath, perm)
		}
	}
	raw, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatalf("reading json-out %s: %v", jsonPath, err)
	}
	var report testbench.BenchmarkReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("unmarshaling json-out: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("len(report.Results) = %d, want 1", len(report.Results))
	}
	if report.Results[0].BatchesFailed <= 0 {
		t.Errorf("Results[0].BatchesFailed = %d, want > 0", report.Results[0].BatchesFailed)
	}
}

func TestCLIWorkloadProfileHelpMentionsSignalsUnset(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := runArgs(ctx, []string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runArgs(-h) = %d, want 0", code)
	}
	help := stderr.String()
	idx := strings.Index(help, "-workload-profile")
	if idx < 0 {
		t.Fatalf("help output missing -workload-profile:\n%s", help)
	}
	section := help[idx:min(len(help), idx+240)]
	if !strings.Contains(section, "when --signals is unset") {
		t.Fatalf("-workload-profile help %q missing 'when --signals is unset'", section)
	}
}

func TestCLIAllowPartialFailuresHelpDocumentsMatchedRowsRequirement(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var stdout, stderr bytes.Buffer
	code := runArgs(ctx, []string{"-h"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runArgs(-h) = %d, want 0", code)
	}
	help := stderr.String()
	idx := strings.Index(help, "-allow-partial-failures")
	if idx < 0 {
		t.Fatalf("help output missing -allow-partial-failures:\n%s", help)
	}
	section := help[idx:min(len(help), idx+400)]
	for _, want := range []string{
		"at least one batch succeeds",
		"at least one row is delivered/acknowledged",
		"matched_rows > 0",
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("-allow-partial-failures help %q missing %q", section, want)
		}
	}
}
