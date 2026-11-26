// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/cli/testbench"
	"go.yaml.in/yaml/v3"
)

func init() {
	if os.Getenv("GO_WANT_CLI_STARTUP_HELPER") != "1" {
		return
	}
	var cfgPath string
	for _, arg := range os.Args[1:] {
		if p, ok := strings.CutPrefix(arg, "--config="); ok {
			cfgPath = p
		}
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "helper read config: %v\n", err)
		os.Exit(2)
	}
	var doc struct {
		Exporters map[string]any `yaml:"exporters"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "helper parse config: %v\n", err)
		os.Exit(2)
	}
	var expID string
	for k := range doc.Exporters {
		expID = k
	}
	_, _ = fmt.Fprintf(
		os.Stderr,
		"2026-11-23T00:00:00.000Z\tinfo\tbuilders/builders.go:28\tDevelopment component.\t{\"otelcol.component.id\": %q, \"otelcol.component.kind\": \"exporter\", \"otelcol.signal\": \"logs\"}\n"+
			"Error: cannot start pipelines: failed to start \"otlp\" receiver: simulated missing authenticator (storage=bigquerystorage.mtls.googleapis.com:443)\n",
		expID,
	)
	os.Exit(1)
}

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

func TestCLIYAMLParseErrorRedactsMultilinePolicyText(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	for _, tc := range []struct {
		name    string
		yaml    string
		wantSub string
		secrets []string
	}{
		{
			name: "mistagged_int_multiline_quoted_key_and_already_defined",
			yaml: `receivers:
  otlp: {}
exporters:
  bigquery:
    redaction:
      enabled: true
      blocked_value_patterns:
        - !!int "SAMPLE_SECRET_KEY_LINE1\n  already defined"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSub: "invalid YAML scalar value",
			secrets: []string{"SAMPLE_SECRET_KEY_LINE1", "already defined"},
		},
		{
			name: "mistagged_timestamp_and_unknown_anchor_secret_redacted",
			yaml: `receivers:
  otlp: {}
exporters:
  bigquery:
    redaction:
      enabled: true
      blocked_value_patterns:
        - !!timestamp "SAMPLE_TS_SECRET\n  line 2 already defined"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSub: "invalid YAML scalar value",
			secrets: []string{"SAMPLE_TS_SECRET", "already defined"},
		},
		{
			name: "invalid_binary_base64_preserves_reason_without_secret",
			yaml: `receivers:
  otlp: {}
exporters:
  bigquery:
    redaction:
      enabled: true
      blocked_value_patterns:
        - !!binary "SECRET_BAD_BASE64!"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSub: "!!binary value contains invalid base64 data",
			secrets: []string{"SECRET_BAD_BASE64"},
		},
		{
			name: "unknown_anchor_secret_redacted",
			yaml: `receivers:
  otlp: {}
exporters:
  bigquery:
    redaction:
      enabled: true
      blocked_value_patterns:
        - *SAMPLE_ANCHOR_SECRET
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`,
			wantSub: "unknown YAML anchor",
			secrets: []string{"SAMPLE_ANCHOR_SECRET"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), tc.name+".yaml")
			if wErr := os.WriteFile(cfgPath, []byte(tc.yaml), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}
			var stdout, stderr bytes.Buffer
			code := runArgs(ctx, []string{
				"-mode=collector",
				"-collector-bin=" + exe,
				"-collector-config=" + cfgPath,
				"-signals=logs",
			}, &stdout, &stderr)
			if code != 1 {
				t.Fatalf("runArgs exit code = %d, want 1 (stderr=%q)", code, stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("unexpected stdout: %q", stdout.String())
			}
			outErr := stderr.String()
			if !strings.Contains(outErr, tc.wantSub) {
				t.Fatalf("stderr = %q, want %q", outErr, tc.wantSub)
			}
			for _, secret := range tc.secrets {
				if strings.Contains(outErr, secret) {
					t.Fatalf("stderr leaked policy text %q: %q", secret, outErr)
				}
			}
		})
	}
}

func TestCLIInterpolatedExporterRedactsSelectedRouteInFieldErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	for _, pipeForm := range []struct {
		name     string
		pipeLine string
		setEnv   func(t *testing.T, route string)
	}{
		{
			name:     "element_env",
			pipeLine: `["bigquery/${env:ROUTE}"]`,
			setEnv: func(t *testing.T, route string) {
				t.Helper()
				t.Setenv("ROUTE", route)
			},
		},
		{
			name:     "whole_list_env",
			pipeLine: `'${env:PIPE_EXPORTERS}'`,
			setEnv: func(t *testing.T, route string) {
				t.Helper()
				t.Setenv("PIPE_EXPORTERS", "[bigquery/"+route+"]")
			},
		},
	} {
		t.Run(pipeForm.name, func(t *testing.T) {
			twoRouteYAML := `receivers:
  otlp: {}
exporters:
  bigquery/blue:
    project: bench-project
    dataset: otel_bench
    location: US
    redaction:
      enabled: true
      blocked_value_patterns:
        - "[unclosed"
  bigquery/green:
    project: bench-project
    dataset: otel_bench
    location: US
    redaction:
      enabled: true
      blocked_value_patterns:
        - "[unclosed"
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: ` + pipeForm.pipeLine + "\n"
			cfgPath := filepath.Join(t.TempDir(), "two-routes.yaml")
			if wErr := os.WriteFile(cfgPath, []byte(twoRouteYAML), 0o600); wErr != nil {
				t.Fatalf("write config: %v", wErr)
			}

			runWithRoute := func(route string) string {
				t.Helper()
				pipeForm.setEnv(t, route)
				var stdout, stderr bytes.Buffer
				code := runArgs(ctx, []string{
					"-mode=collector",
					"-collector-bin=" + exe,
					"-collector-config=" + cfgPath,
					"-signals=logs",
				}, &stdout, &stderr)
				if code != 1 {
					t.Fatalf("runArgs(route=%s) exit code = %d, want 1 (stderr=%q)", route, code, stderr.String())
				}
				if stdout.Len() != 0 {
					t.Fatalf("runArgs(route=%s) unexpected stdout: %q", route, stdout.String())
				}
				return stderr.String()
			}

			blueErr := runWithRoute("blue")
			greenErr := runWithRoute("green")
			if blueErr != greenErr {
				t.Fatalf("stderr differed across env routes:\nblue:  %q\ngreen: %q", blueErr, greenErr)
			}
			if !strings.Contains(blueErr, "exporters.<interpolated-exporter>.redaction.blocked_value_patterns") {
				t.Fatalf("stderr = %q, want exporters.<interpolated-exporter>.redaction.blocked_value_patterns", blueErr)
			}
			for _, routeSecret := range []string{"blue", "green"} {
				if strings.Contains(blueErr, routeSecret) {
					t.Fatalf("stderr leaked selected route %q: %q", routeSecret, blueErr)
				}
			}
		})
	}
}

func TestCLIInterpolatedExporterRedactsSelectedRouteInStartupLogs(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	t.Setenv("GO_WANT_CLI_STARTUP_HELPER", "1")

	const exportersBlock = `  bigquery:
    project: bench-project
    dataset: otel_bench
    location: US
  bigquery/bqroutealpha:
    project: bench-project
    dataset: otel_bench
    location: US
  bigquery/bqroutebeta:
    project: bench-project
    dataset: otel_bench
    location: US
  'bigquery/bqroutealpha"q':
    project: bench-project
    dataset: otel_bench
    location: US
  'bigquery/bqroutealpha\b':
    project: bench-project
    dataset: otel_bench
    location: US
`
	leakedMarkers := []string{
		"bigquery/bqroutealpha",
		"bigquery/bqroutebeta",
		"bqroutealpha",
		"bqroutebeta",
	}
	runStartupCLI := func(t *testing.T, pipeExpr string) string {
		t.Helper()
		runCtx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()

		tmpDir := t.TempDir()
		cfgPath := filepath.Join(tmpDir, "startup.yaml")
		jsonPath := filepath.Join(tmpDir, "report.json")
		yml := "receivers:\n  otlp: {}\nexporters:\n" + exportersBlock + "service:\n  pipelines:\n    logs:\n      receivers: [otlp]\n      exporters: " + pipeExpr + "\n"
		if wErr := os.WriteFile(cfgPath, []byte(yml), 0o600); wErr != nil {
			t.Fatalf("write config: %v", wErr)
		}
		var stdout, stderr bytes.Buffer
		code := runArgs(runCtx, []string{
			"-mode=collector",
			"-collector-bin=" + exe,
			"-collector-config=" + cfgPath,
			"-signals=logs",
			"-duration=200ms",
			"-json-out=" + jsonPath,
		}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("runArgs exit code = %d, want 1 (stderr=%q)", code, stderr.String())
		}
		rawJSON, readErr := os.ReadFile(jsonPath)
		if readErr != nil {
			t.Fatalf("reading JSON report %s: %v", jsonPath, readErr)
		}
		var report testbench.BenchmarkReport
		if uErr := json.Unmarshal(rawJSON, &report); uErr != nil {
			t.Fatalf("unmarshaling JSON report: %v\n%s", uErr, string(rawJSON))
		}
		// Assert recorded config/binary paths separately so temp directory paths
		// cannot collide with diagnostic redaction assertions.
		if report.Config.CollectorConfig != cfgPath {
			t.Fatalf("report.Config.CollectorConfig = %q, want %q", report.Config.CollectorConfig, cfgPath)
		}
		if report.Config.CollectorBin != exe {
			t.Fatalf("report.Config.CollectorBin = %q, want %q", report.Config.CollectorBin, exe)
		}
		report.Config.CollectorConfig = ""
		report.Config.CollectorBin = ""
		diagJSON, mErr := json.Marshal(report)
		if mErr != nil {
			t.Fatalf("re-marshaling sanitized report fields: %v", mErr)
		}
		for _, leaked := range leakedMarkers {
			if strings.Contains(string(diagJSON), leaked) {
				t.Fatalf("JSON diagnostic fields leaked %q: %s", leaked, string(diagJSON))
			}
		}
		return stderr.String()
	}

	t.Setenv("ROUTE", "bqroutealpha")
	elemAlpha := runStartupCLI(t, `["bigquery/${env:ROUTE}"]`)
	t.Setenv("ROUTE", "bqroutebeta")
	elemBeta := runStartupCLI(t, `["bigquery/${env:ROUTE}"]`)
	t.Setenv("ROUTE", `bqroutealpha"q`)
	elemQuote := runStartupCLI(t, `["bigquery/${env:ROUTE}"]`)
	t.Setenv("ROUTE", `bqroutealpha\b`)
	elemBS := runStartupCLI(t, `["bigquery/${env:ROUTE}"]`)
	t.Setenv("PIPE_EXPORTERS", "[bigquery/bqroutealpha]")
	listAlpha := runStartupCLI(t, `'${env:PIPE_EXPORTERS}'`)
	t.Setenv("PIPE_EXPORTERS", "[bigquery/bqroutebeta]")
	listBeta := runStartupCLI(t, `'${env:PIPE_EXPORTERS}'`)
	t.Setenv("PIPE_EXPORTERS", `["bigquery/bqroutealpha\"q"]`)
	listQuote := runStartupCLI(t, `'${env:PIPE_EXPORTERS}'`)
	t.Setenv("PIPE_EXPORTERS", `["bigquery/bqroutealpha\\b"]`)
	listBS := runStartupCLI(t, `'${env:PIPE_EXPORTERS}'`)
	t.Setenv("PIPE_EXPORTERS", "[bigquery]")
	listBare := runStartupCLI(t, `'${env:PIPE_EXPORTERS}'`)

	if elemAlpha != elemBeta || elemAlpha != elemQuote || elemAlpha != elemBS ||
		elemAlpha != listAlpha || listAlpha != listBeta || listAlpha != listQuote || listAlpha != listBS || listAlpha != listBare {
		t.Fatalf("startup stderr differed across interpolated routes/forms:\nelemAlpha=%q\nelemBeta=%q\nelemQuote=%q\nelemBS=%q\nlistAlpha=%q\nlistBeta=%q\nlistQuote=%q\nlistBS=%q\nlistBare=%q",
			elemAlpha, elemBeta, elemQuote, elemBS, listAlpha, listBeta, listQuote, listBS, listBare)
	}
	for _, want := range []string{
		`"otelcol.component.id": "<interpolated-exporter>"`,
		`bigquerystorage.mtls.googleapis.com:443`,
	} {
		if !strings.Contains(listAlpha, want) {
			t.Fatalf("stderr = %q, want %q", listAlpha, want)
		}
	}
	for _, leaked := range leakedMarkers {
		if strings.Contains(listAlpha, leaked) {
			t.Fatalf("stderr leaked %q in %q", leaked, listAlpha)
		}
	}

	literalErr := runStartupCLI(t, `[bigquery/bqroutebeta]`)
	if !strings.Contains(literalErr, `"otelcol.component.id": "bigquery/bqroutebeta"`) || strings.Contains(literalErr, "<interpolated-exporter>") {
		t.Fatalf("literal startup stderr = %q, want unredacted bigquery/bqroutebeta", literalErr)
	}
}
