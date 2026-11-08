// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package testbench

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
)

// liveParityBatchSize is a whole number of generator cycles: the framework
// rotation repeats every 28 records and the payload corpus every 16, so every
// prebuilt batch carries the same mix of records and the mean row size does
// not depend on which batches a worker happens to send.
const liveParityBatchSize = 112

// liveParityMaxBatches bounds each signal of each run to the same workload,
// so the two runs append the same number of rows instead of whatever fits in
// a time window.
const liveParityMaxBatches = 8

// TestLiveRunMultiWorkerBytesPerRowParity runs the load testbench in live
// mode against a real BigQuery dataset, once with one worker and once with
// two, for traces, logs, and metrics. Both runs are bounded to the same
// number of batches. Each run must have every batch acknowledged with no
// rejected rows, BigQuery must hold exactly the acknowledged rows, and the
// retry-uninflated BytesPerRow of the two runs must agree, which is the
// property the bounded hermetic check protects.
//
// It creates billable resources: one ephemeral dataset, deleted on cleanup.
func TestLiveRunMultiWorkerBytesPerRowParity(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping the live testbench parity run")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	base := RunnerConfig{
		Mode:               ModeLive,
		ProjectID:          project,
		Location:           location,
		EphemeralDataset:   true,
		Signals:            []string{"traces", "logs", "metrics"},
		BatchSize:          liveParityBatchSize,
		StreamPoolSize:     2,
		ConnectionPoolSize: 2,
		Duration:           3 * time.Minute,
		maxBatches:         liveParityMaxBatches,
	}
	if err := base.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// The test owns the dataset across both runs, the way
	// RunStreamPoolSweep owns one across its steps, so it can count the rows
	// after each run.
	if err := createEphemeralDataset(ctx, project, base.DatasetID, location); err != nil {
		t.Fatalf("create ephemeral dataset: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cleanupCancel()
		if err := DeleteDatasetWithContents(cleanupCtx, project, base.DatasetID); err != nil {
			t.Errorf("delete ephemeral dataset %s: %v", base.DatasetID, err)
		}
	})
	base.KeepEphemeralDataset = true

	client, closeClient, err := newBigQueryClient(ctx, project)
	if err != nil {
		t.Fatalf("create BigQuery client: %v", err)
	}
	t.Cleanup(closeClient)
	client.Location = location

	tables := map[string]string{"traces": "otel_spans", "logs": "otel_logs", "metrics": "otel_metrics"}
	wantRows := int64(liveParityBatchSize * liveParityMaxBatches)
	stored := map[string]int64{}
	hadRetries := map[string]bool{}
	bytesPerRow := map[int]map[string]float64{}
	for _, workers := range []int{1, 2} {
		cfg := base
		cfg.Workers = workers
		report, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("live Run with %d worker(s): %v", workers, err)
		}
		if len(report.Results) != len(base.Signals) {
			t.Fatalf("live Run with %d worker(s) returned %d results, want %d", workers, len(report.Results), len(base.Signals))
		}
		bytesPerRow[workers] = map[string]float64{}
		for _, res := range report.Results {
			tel := res.Telemetry
			t.Logf("workers=%d signal=%s acked=%d rejected=%d retries=%d batches=%d/%d rows/s=%.0f wire_MB/s=%.2f bytes/row=%.2f attempted_bytes/acked_row=%.2f latency_ms p50=%.1f p95=%.1f max=%.1f",
				workers, res.Signal, tel.AcknowledgedRows, tel.RejectedRows, tel.Retries,
				res.BatchesSucceeded, res.BatchesAttempted, res.AchievedRowsPerSec, res.WireMBPerSec,
				res.BytesPerRow, res.AttemptedBytesPerAckedRow, res.Latency.P50Ms, res.Latency.P95Ms, res.Latency.MaxMs)
			if res.BatchesSucceeded != liveParityMaxBatches || res.BatchesFailed != 0 {
				t.Errorf("workers=%d %s: batches succeeded=%d failed=%d, want %d and 0", workers, res.Signal, res.BatchesSucceeded, res.BatchesFailed, liveParityMaxBatches)
			}
			if tel.RejectedRows != 0 {
				t.Errorf("workers=%d %s: rejected rows = %d, want 0", workers, res.Signal, tel.RejectedRows)
			}
			if tel.AcknowledgedRows != wantRows {
				t.Errorf("workers=%d %s: acknowledged rows = %d, want %d", workers, res.Signal, tel.AcknowledgedRows, wantRows)
			}
			if res.BytesPerRow <= 0 {
				t.Errorf("workers=%d %s: BytesPerRow = %.2f, want > 0", workers, res.Signal, res.BytesPerRow)
			}
			bytesPerRow[workers][res.Signal] = res.BytesPerRow

			table := tables[res.Signal]
			wantTotal := stored[table] + tel.AcknowledgedRows
			hadRetries[table] = hadRetries[table] || tel.Retries > 0
			got, err := liveCountRows(ctx, client, project, base.DatasetID, table, wantTotal, !hadRetries[table])
			if err != nil {
				t.Errorf("workers=%d %s: %v", workers, res.Signal, err)
				stored[table] = wantTotal
				continue
			}
			stored[table] = got
			t.Logf("workers=%d %s: SELECT COUNT(*) FROM %s = %d after this run", workers, res.Signal, table, got)
		}
	}
	for _, signal := range base.Signals {
		one, two := bytesPerRow[1][signal], bytesPerRow[2][signal]
		if math.Abs(one-two) > 1.0 {
			t.Errorf("%s BytesPerRow with 1 worker = %.2f, with 2 workers = %.2f; want the same bounded workload to agree within 1 B", signal, one, two)
		}
	}
}

// liveCountRows waits until the table holds want rows. When exact is false a
// retry may have stored an extra copy, so any count at or above want passes.
func liveCountRows(ctx context.Context, client *bigquery.Client, project, dataset, table string, want int64, exact bool) (int64, error) {
	query := client.Query(fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.%s`", project, dataset, table))
	deadline := time.Now().Add(2 * time.Minute)
	var got int64
	for {
		it, err := query.Read(ctx)
		if err != nil {
			return got, fmt.Errorf("count %s: %w", table, err)
		}
		var row []bigquery.Value
		if err := it.Next(&row); err != nil && !errors.Is(err, iterator.Done) {
			return got, fmt.Errorf("read count of %s: %w", table, err)
		}
		if len(row) == 1 {
			got, _ = row[0].(int64)
		}
		switch {
		case got == want, !exact && got > want:
			return got, nil
		case exact && got > want:
			return got, fmt.Errorf("SELECT COUNT(*) FROM %s = %d, want exactly the %d acknowledged rows", table, got, want)
		case time.Now().After(deadline) || ctx.Err() != nil:
			return got, fmt.Errorf("SELECT COUNT(*) FROM %s = %d, want %d acknowledged rows", table, got, want)
		}
		time.Sleep(time.Second)
	}
}
