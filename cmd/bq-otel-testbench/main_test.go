// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testbench"
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

	badFlagCases := [][]string{
		{"-format=xml"},
		{"-stream-pool-sweep=0,abc"},
		{"-max-inflight-requests=0"},
		{"-max-inflight-requests=-1"},
		{"-max-inflight-requests=65537"},
		{"-max-inflight-requests=9223372036854775807"},
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
