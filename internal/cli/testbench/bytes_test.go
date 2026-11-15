// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
)

func TestTableStorageRegionSQLFiltersDeleted(t *testing.T) {
	sqlText, err := tableStorageRegionSQL("my-project", "US")
	if err != nil {
		t.Fatalf("tableStorageRegionSQL: %v", err)
	}
	if !strings.Contains(sqlText, "WHERE table_schema = @dataset AND table_name = @table AND deleted = FALSE") {
		t.Fatalf("tableStorageRegionSQL missing active-table filter (AND deleted = FALSE): %s", sqlText)
	}

	var capturedSQL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		schema := &bigqueryapi.TableSchema{
			Fields: []*bigqueryapi.TableFieldSchema{
				{Name: "total_rows", Type: "INTEGER"},
				{Name: "total_logical_bytes", Type: "INTEGER"},
				{Name: "active_physical_bytes", Type: "INTEGER"},
				{Name: "long_term_physical_bytes", Type: "INTEGER"},
				{Name: "time_travel_physical_bytes", Type: "INTEGER"},
				{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
			},
		}
		rows := []*bigqueryapi.TableRow{
			{
				F: []*bigqueryapi.TableCell{
					{V: "100"},
					{V: "10000"},
					{V: "4000"},
					{V: "0"},
					{V: "0"},
					{V: "0"},
				},
			},
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries") {
			var req bigqueryapi.QueryRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				capturedSQL = req.Query
			}
			_ = json.NewEncoder(w).Encode(bigqueryapi.QueryResponse{
				JobReference: &bigqueryapi.JobReference{ProjectId: "my-project", JobId: "j1", Location: "US"},
				JobComplete:  true,
				TotalRows:    1,
				Schema:       schema,
				Rows:         rows,
			})
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs") {
			var job bigqueryapi.Job
			if err := json.NewDecoder(r.Body).Decode(&job); err == nil &&
				job.Configuration != nil && job.Configuration.Query != nil {
				capturedSQL = job.Configuration.Query.Query
			}
			_ = json.NewEncoder(w).Encode(bigqueryapi.Job{
				JobReference: &bigqueryapi.JobReference{ProjectId: "my-project", JobId: "j1", Location: "US"},
				Status:       &bigqueryapi.JobStatus{State: "DONE"},
				Configuration: &bigqueryapi.JobConfiguration{
					Query: &bigqueryapi.JobConfigurationQuery{Query: capturedSQL},
				},
				Statistics: &bigqueryapi.JobStatistics{
					Query: &bigqueryapi.JobStatistics2{},
				},
			})
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/queries/") {
			_ = json.NewEncoder(w).Encode(bigqueryapi.GetQueryResultsResponse{
				JobComplete: true,
				TotalRows:   1,
				Schema:      schema,
				Rows:        rows,
			})
			return
		}
		http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}))
	defer srv.Close()

	layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
	cfg := RunnerConfig{
		Mode:      ModeLive,
		ProjectID: "my-project",
		DatasetID: "my_dataset",
		Location:  "US",
		ClientOptions: []option.ClientOption{
			option.WithEndpoint(srv.URL + "/bigquery/v2/"),
			option.WithoutAuthentication(),
		},
	}
	populateLiveTableStorage(context.Background(), cfg, "otel_spans", layers)
	if layers.BQStorageQueryNote != "" {
		t.Fatalf("unexpected BQStorageQueryNote: %s", layers.BQStorageQueryNote)
	}
	if !strings.Contains(capturedSQL, "AND deleted = FALSE") {
		t.Fatalf("submitted TABLE_STORAGE SQL missing AND deleted = FALSE: %q", capturedSQL)
	}
}

func TestRunByteLayersMatchDispatchedPool(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	measurePool := func(cfg RunnerConfig, signal string) (source [8]int64, otlp [8]int64) {
		gen := NewGenerator(GeneratorConfig{
			PayloadBytes:     cfg.PayloadBytes,
			PlantSecrets:     cfg.Redaction || cfg.PlantSecrets,
			UniquePayloads:   cfg.UniquePayloads,
			WorkloadProfile:  cfg.WorkloadProfile,
			ResourceAttrs:    cfg.ResourceAttrs,
			UpstreamInsertID: cfg.UpstreamInsertID,
		})
		tm := &ptrace.ProtoMarshaler{}
		lm := &plog.ProtoMarshaler{}
		mm := &pmetric.ProtoMarshaler{}
		for i := 0; i < 8; i++ {
			switch signal {
			case "traces":
				td := gen.TracesBatch(cfg.BatchSize)
				source[i] = tracesSourceContentBytes(td)
				otlp[i] = int64(tm.TracesSize(td))
			case "logs":
				ld := gen.LogsBatch(cfg.BatchSize)
				source[i] = logsSourceContentBytes(ld)
				otlp[i] = int64(lm.LogsSize(ld))
			case "metrics":
				md := gen.MetricsBatch(cfg.BatchSize)
				source[i] = metricsSourceContentBytes(md)
				otlp[i] = int64(mm.MetricsSize(md))
			}
		}
		return source, otlp
	}

	t.Run("traces 1-record-per-batch cycles 8-batch pool", func(t *testing.T) {
		cfg := RunnerConfig{
			Mode:           ModeBQFake,
			Signals:        []string{"traces"},
			Duration:       10 * time.Second,
			BatchSize:      1,
			Workers:        1,
			StreamPoolSize: 1,
			PayloadBytes:   1024,
			maxBatches:     8,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		poolSrc, poolOTLP := measurePool(cfg, "traces")
		var sumSrc, sumOTLP int64
		for i := 0; i < 8; i++ {
			sumSrc += poolSrc[i]
			sumOTLP += poolOTLP[i]
		}
		wantSrcBPR := round2(float64(sumSrc) / 8.0)
		wantOTLPBPR := round2(float64(sumOTLP) / 8.0)

		singleLayers, _, err := measureByteProfile(cfg, "traces", 0)
		if err != nil {
			t.Fatalf("measureByteProfile: %v", err)
		}
		if singleLayers.OTLPBytesPerRow == wantOTLPBPR && singleLayers.SourceContentBytesPerRow == wantSrcBPR {
			t.Fatalf("expected single-batch reference (src=%.2f, otlp=%.2f) to differ from 8-batch pool mean (src=%.2f, otlp=%.2f)",
				singleLayers.SourceContentBytesPerRow, singleLayers.OTLPBytesPerRow, wantSrcBPR, wantOTLPBPR)
		}

		rep, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(rep.Results) != 1 || rep.Results[0].ByteLayers == nil {
			t.Fatalf("unexpected report results: %+v", rep.Results)
		}
		got := rep.Results[0].ByteLayers
		t.Logf("traces batch=1 (8-batch pool): single=(src=%.2f, otlp=%.2f) dispatched=(src=%.2f, otlp=%.2f, protorows=%.2f, otlp_amp=%.2fx)",
			singleLayers.SourceContentBytesPerRow, singleLayers.OTLPBytesPerRow,
			got.SourceContentBytesPerRow, got.OTLPBytesPerRow, got.ProtoRowsBytesPerRow, got.OTLPToProtoRowsRatio)
		if got.SourceContentBytesPerRow != wantSrcBPR {
			t.Errorf("SourceContentBytesPerRow = %.2f, want 8-batch pool mean %.2f (single-batch was %.2f)",
				got.SourceContentBytesPerRow, wantSrcBPR, singleLayers.SourceContentBytesPerRow)
		}
		if got.OTLPBytesPerRow != wantOTLPBPR {
			t.Errorf("OTLPBytesPerRow = %.2f, want 8-batch pool mean %.2f (single-batch was %.2f)",
				got.OTLPBytesPerRow, wantOTLPBPR, singleLayers.OTLPBytesPerRow)
		}
		wantOTLPRatio := round2(got.ProtoRowsBytesPerRow / (float64(sumOTLP) / 8.0))
		if got.OTLPToProtoRowsRatio != wantOTLPRatio {
			t.Errorf("OTLPToProtoRowsRatio = %.2f, want %.2f", got.OTLPToProtoRowsRatio, wantOTLPRatio)
		}
		wantSrcRatio := round2(got.ProtoRowsBytesPerRow / (float64(sumSrc) / 8.0))
		if got.SourceToProtoRowsRatio != wantSrcRatio {
			t.Errorf("SourceToProtoRowsRatio = %.2f, want %.2f", got.SourceToProtoRowsRatio, wantSrcRatio)
		}
	})

	t.Run("non-uniform 11-batch dispatch computes exact weighted mix", func(t *testing.T) {
		var dispatchedIdxs []int
		cfg := RunnerConfig{
			Mode:           ModeBQFake,
			Signals:        []string{"traces"},
			Duration:       10 * time.Second,
			BatchSize:      1,
			Workers:        1,
			StreamPoolSize: 1,
			PayloadBytes:   1024,
			maxBatches:     11,
			workerHook: func(workerID, seq int) {
				dispatchedIdxs = append(dispatchedIdxs, (workerID+seq)%8)
			},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		poolSrc, poolOTLP := measurePool(cfg, "traces")
		rep, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		if len(dispatchedIdxs) != 11 {
			t.Fatalf("len(dispatchedIdxs) = %d, want 11", len(dispatchedIdxs))
		}
		var weightedSrc, weightedOTLP int64
		for _, idx := range dispatchedIdxs {
			weightedSrc += poolSrc[idx]
			weightedOTLP += poolOTLP[idx]
		}
		wantSrcBPR := round2(float64(weightedSrc) / 11.0)
		wantOTLPBPR := round2(float64(weightedOTLP) / 11.0)

		got := rep.Results[0].ByteLayers
		t.Logf("traces batch=1 (11-batch non-uniform): expected=(src=%.2f, otlp=%.2f) dispatched=(src=%.2f, otlp=%.2f, protorows=%.2f)",
			wantSrcBPR, wantOTLPBPR, got.SourceContentBytesPerRow, got.OTLPBytesPerRow, got.ProtoRowsBytesPerRow)
		if got.SourceContentBytesPerRow != wantSrcBPR {
			t.Errorf("SourceContentBytesPerRow = %.2f, want exact 11-batch weighted %.2f", got.SourceContentBytesPerRow, wantSrcBPR)
		}
		if got.OTLPBytesPerRow != wantOTLPBPR {
			t.Errorf("OTLPBytesPerRow = %.2f, want exact 11-batch weighted %.2f", got.OTLPBytesPerRow, wantOTLPBPR)
		}
	})

	t.Run("logs and unique-payloads 1-record-per-batch match dispatched batches", func(t *testing.T) {
		cfg := RunnerConfig{
			Mode:           ModeBQFake,
			Signals:        []string{"logs"},
			Duration:       10 * time.Second,
			BatchSize:      1,
			Workers:        1,
			StreamPoolSize: 1,
			PayloadBytes:   512,
			UniquePayloads: true,
			maxBatches:     8,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		poolSrc, poolOTLP := measurePool(cfg, "logs")
		var sumSrc, sumOTLP int64
		for i := 0; i < 8; i++ {
			sumSrc += poolSrc[i]
			sumOTLP += poolOTLP[i]
		}
		wantSrcBPR := round2(float64(sumSrc) / 8.0)
		wantOTLPBPR := round2(float64(sumOTLP) / 8.0)

		rep, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
		got := rep.Results[0].ByteLayers
		t.Logf("logs unique_payloads batch=1 (8-batch): expected=(src=%.2f, otlp=%.2f) dispatched=(src=%.2f, otlp=%.2f, protorows=%.2f)",
			wantSrcBPR, wantOTLPBPR, got.SourceContentBytesPerRow, got.OTLPBytesPerRow, got.ProtoRowsBytesPerRow)
		if got.SourceContentBytesPerRow != wantSrcBPR {
			t.Errorf("SourceContentBytesPerRow = %.2f, want %.2f", got.SourceContentBytesPerRow, wantSrcBPR)
		}
		if got.OTLPBytesPerRow != wantOTLPBPR {
			t.Errorf("OTLPBytesPerRow = %.2f, want %.2f", got.OTLPBytesPerRow, wantOTLPBPR)
		}
	})
}
