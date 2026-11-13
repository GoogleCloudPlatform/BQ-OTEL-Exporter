// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Command bq-otel-testbench runs synthetic OpenTelemetry GenAI and MCP load
// benchmarks against bigqueryexporter using either the in-process bqfake
// Storage Write API server or a live BigQuery dataset.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testbench"
)

type usageError struct {
	err error
}

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

func main() {
	os.Exit(runMain())
}

func runMain() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runArgs(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func runArgs(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if err := run(ctx, args, stdout, stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "bq-otel-testbench: %v\n", err)
		var uerr usageError
		if errors.As(err, &uerr) {
			return 2
		}
		return 1
	}
	return 0
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) (retErr error) {
	fs := flag.NewFlagSet("bq-otel-testbench", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var (
		cfg            testbench.RunnerConfig
		signalsCSV     string
		sweepCSV       string
		format         string
		jsonOut        string
		cpuProfilePath string
		memProfilePath string
	)

	fs.StringVar(&cfg.Mode, "mode", testbench.ModeBQFake, "Sink mode: bqfake or live")
	fs.StringVar(&signalsCSV, "signals", "", "Comma-separated OTLP signals to benchmark (default traces for genai-mixed, logs for access-logs)")
	fs.StringVar(&cfg.WorkloadProfile, "workload-profile", testbench.WorkloadProfileGenAIMixed, "Synthetic workload profile: genai-mixed or access-logs")
	fs.IntVar(&cfg.ResourceAttrs, "resource-attrs", 0, "Number of resource attributes per ResourceLogs in access-logs profile (0 = default 12)")
	fs.BoolVar(&cfg.UpstreamInsertID, "upstream-insert-id", false, "Attach logging.googleapis.com/insertId to synthetic access-logs records")
	fs.IntVar(&cfg.TargetRate, "rate", 0, "Target records/sec per signal (0 = unthrottled max throughput)")
	fs.DurationVar(&cfg.Duration, "duration", 0, "Steady-state benchmark duration per signal (default 2s, or >= 60s when -soak is set; default 60s)")
	fs.BoolVar(&cfg.Soak, "soak", false, "Enable >= 60s steady-state soak preset with warmup discard (duration must be >= 60s if explicitly set)")
	fs.IntVar(&cfg.MaxProcs, "max-procs", 0, "Optional runtime.GOMAXPROCS cap for CPU-bounded benchmarks (0 = unchanged)")
	fs.StringVar(&cpuProfilePath, "cpuprofile", "", "Optional file path to write Go pprof CPU profile")
	fs.StringVar(&memProfilePath, "memprofile", "", "Optional file path to write Go pprof heap memory profile")
	fs.IntVar(&cfg.BatchSize, "batch-size", 500, "Records per batch")
	fs.IntVar(&cfg.Workers, "workers", 4, "Concurrent producer workers")
	fs.IntVar(&cfg.StreamPoolSize, "stream-pool-size", 4, "BigQuery Write API stream_pool_size (1..16)")
	fs.StringVar(&sweepCSV, "stream-pool-sweep", "", "Optional comma-separated stream_pool_size sweep (e.g. 1,2,4,8,16)")
	fs.IntVar(&cfg.ConnectionPoolSize, "connection-pool-size", 4, "BigQuery Write API gRPC connection_pool_size (1..16)")
	fs.IntVar(&cfg.MaxInflightRequests, "max-inflight-requests", 32, "Maximum in-flight AppendRows requests per stream (1..65536)")
	fs.IntVar(&cfg.MaxRequestBytes, "max-request-bytes", 8*1024*1024, "Maximum serialized ProtoRows payload bytes per request")
	fs.StringVar(&cfg.Compression, "compression", "", "Optional gRPC compressor (empty or gzip)")
	fs.BoolVar(&cfg.Redaction, "redaction", false, "Enable Step-0 sensitive-data redaction and plant synthetic secrets")
	fs.BoolVar(&cfg.PlantSecrets, "plant-secrets", false, "Plant synthetic secret attributes even when redaction is disabled")
	fs.BoolVar(&cfg.Backpressure, "backpressure", false, "Enable AIMD adaptive write backpressure")
	fs.IntVar(&cfg.PayloadBytes, "payload-bytes", 0, "Synthetic payload byte length (default 1024 for genai-mixed, 128 for access-logs)")
	fs.BoolVar(&cfg.UniquePayloads, "unique-payloads", false, "Generate unique sequence prefixes per payload (disables dedup hits)")
	fs.StringVar(&cfg.OffloadDir, "offload-dir", "", "Optional local directory sink to benchmark SHA-256 content-addressed offload")
	fs.StringVar(&cfg.OffloadGCSBucket, "offload-gcs-bucket", "", "Optional GCS bucket name for native exporter payload offloading (live mode)")
	fs.IntVar(&cfg.OffloadThresholdBytes, "offload-threshold-bytes", 4096, "Byte threshold when --offload-dir or --offload-gcs-bucket is enabled")
	fs.DurationVar(&cfg.SimulateAckDelay, "simulate-ack-delay", 0, "Inject FaultDelayedAck into bqfake on batch 1 and every 3rd batch")
	fs.IntVar(&cfg.SimulateThrottleEvery, "simulate-throttle-every", 0, "Inject FaultResourceExhausted into bqfake every N batches")
	fs.DurationVar(&cfg.CallTimeout, "call-timeout", 0, "Optional per-batch Consume* timeout override")
	fs.BoolVar(&cfg.AllowPartialFailures, "allow-partial-failures", false, "Permit non-zero failed batches when at least one batch succeeds")
	fs.StringVar(&cfg.ProjectID, "project", "", "GCP project ID (required when --mode=live)")
	fs.StringVar(&cfg.DatasetID, "dataset", "", "BigQuery dataset ID (required when --mode=live and --ephemeral-dataset=false; must be empty when --ephemeral-dataset=true)")
	fs.StringVar(&cfg.Location, "location", "US", "BigQuery dataset location")
	fs.BoolVar(&cfg.EphemeralDataset, "ephemeral-dataset", false, "Auto-create a unique otel_bench_<timestamp>_<random_hex> dataset in live mode and delete it on teardown")
	fs.StringVar(&format, "format", "both", "Output format: markdown, json, or both")
	fs.StringVar(&jsonOut, "json-out", "", "Optional file path to write JSON benchmark report")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return usageError{err: err}
	}
	if fs.NArg() > 0 {
		return usageError{err: fmt.Errorf("unexpected positional arguments: %v", fs.Args())}
	}
	if cfg.MaxInflightRequests <= 0 || cfg.MaxInflightRequests > testbench.MaxBenchmarkInflightRequests {
		return usageError{err: fmt.Errorf("--max-inflight-requests must be in 1..%d, got %d", testbench.MaxBenchmarkInflightRequests, cfg.MaxInflightRequests)}
	}

	cfg.Signals = splitNonEmptyCSV(signalsCSV)
	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "markdown", "json", "both":
	default:
		return usageError{err: fmt.Errorf("unsupported --format %q: must be markdown, json, or both", format)}
	}

	checkCfg := cfg
	if err := checkCfg.Normalize(); err != nil {
		return usageError{err: err}
	}

	if cpuProfilePath != "" {
		cpuFile, openErr := os.OpenFile(cpuProfilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if openErr != nil {
			return fmt.Errorf("creating -cpuprofile %q: %w", cpuProfilePath, openErr)
		}
		if startErr := pprof.StartCPUProfile(cpuFile); startErr != nil {
			return errors.Join(fmt.Errorf("starting CPU profile: %w", startErr), cpuFile.Close())
		}
		defer func() {
			pprof.StopCPUProfile()
			if closeErr := cpuFile.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("closing -cpuprofile %q: %w", cpuProfilePath, closeErr))
			}
		}()
	}

	var (
		report *testbench.BenchmarkReport
		err    error
	)
	if strings.TrimSpace(sweepCSV) != "" {
		poolSizes, parseErr := parseIntCSV(sweepCSV)
		if parseErr != nil {
			return usageError{err: fmt.Errorf("parsing --stream-pool-sweep: %w", parseErr)}
		}
		for _, ps := range poolSizes {
			if ps < 1 || ps > 16 {
				return usageError{err: fmt.Errorf("stream_pool_size %d must be between 1 and 16", ps)}
			}
		}
		report, err = testbench.RunStreamPoolSweep(ctx, cfg, poolSizes)
	} else {
		report, err = testbench.Run(ctx, cfg)
	}
	if err != nil {
		return err
	}

	if memProfilePath != "" {
		memFile, openErr := os.OpenFile(memProfilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if openErr != nil {
			return fmt.Errorf("creating -memprofile %q: %w", memProfilePath, openErr)
		}
		runtime.GC()
		writeErr := pprof.WriteHeapProfile(memFile)
		closeErr := memFile.Close()
		if writeErr != nil {
			return fmt.Errorf("writing -memprofile %q: %w", memProfilePath, writeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("closing -memprofile %q: %w", memProfilePath, closeErr)
		}
	}

	jsonStr, err := testbench.FormatJSON(report)
	if err != nil {
		return err
	}

	if jsonOut != "" {
		if err := os.WriteFile(jsonOut, []byte(jsonStr), 0o600); err != nil {
			return fmt.Errorf("writing --json-out %q: %w", jsonOut, err)
		}
	}

	switch format {
	case "markdown":
		_, err = io.WriteString(stdout, testbench.FormatMarkdown(report))
	case "json":
		_, err = io.WriteString(stdout, jsonStr)
	case "both":
		if _, err = io.WriteString(stdout, testbench.FormatMarkdown(report)+"\n"); err == nil {
			_, err = io.WriteString(stdout, jsonStr)
		}
	}
	return err
}

func splitNonEmptyCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func parseIntCSV(raw string) ([]int, error) {
	parts := splitNonEmptyCSV(raw)
	if len(parts) == 0 {
		return nil, errors.New("empty integer list")
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("invalid positive integer %q", p)
		}
		out = append(out, v)
	}
	return out, nil
}
