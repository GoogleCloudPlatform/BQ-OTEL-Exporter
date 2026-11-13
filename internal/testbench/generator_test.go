// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
)

func TestAccessLogsGeneratorShapeAndToggles(t *testing.T) {
	t.Run("default access-logs is trace-less with 12 resource attrs and no insertId", func(t *testing.T) {
		g1 := NewGenerator(GeneratorConfig{
			WorkloadProfile: WorkloadProfileAccessLogs,
			UniquePayloads:  true,
		})
		g2 := NewGenerator(GeneratorConfig{
			WorkloadProfile: WorkloadProfileAccessLogs,
			UniquePayloads:  true,
		})

		ld1 := g1.LogsBatch(20)
		ld2 := g2.LogsBatch(20)
		if ld1.LogRecordCount() != 20 {
			t.Fatalf("LogRecordCount = %d, want 20", ld1.LogRecordCount())
		}

		b1, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld1)
		if err != nil {
			t.Fatalf("MarshalLogs(ld1): %v", err)
		}
		b2, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld2)
		if err != nil {
			t.Fatalf("MarshalLogs(ld2): %v", err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatal("access-logs LogsBatch is not deterministic across identical generators")
		}

		rls := ld1.ResourceLogs()
		if rls.Len() == 0 {
			t.Fatal("expected non-empty ResourceLogs")
		}
		for i := 0; i < rls.Len(); i++ {
			resAttrs := rls.At(i).Resource().Attributes()
			if resAttrs.Len() != DefaultAccessLogsResourceAttrs {
				t.Fatalf("ResourceLogs[%d] attribute count = %d, want %d", i, resAttrs.Len(), DefaultAccessLogsResourceAttrs)
			}
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					lr := lrs.At(k)
					if !lr.TraceID().IsEmpty() {
						t.Fatalf("access-logs TraceID = %s, want unset", lr.TraceID())
					}
					if !lr.SpanID().IsEmpty() {
						t.Fatalf("access-logs SpanID = %s, want unset", lr.SpanID())
					}
					for _, key := range []string{
						"http.request.method",
						"url.path",
						"http.response.status_code",
						"network.peer.address",
						"user_agent.original",
					} {
						if _, ok := lr.Attributes().Get(key); !ok {
							t.Errorf("access-logs record missing attribute %q", key)
						}
					}
					if _, ok := lr.Attributes().Get("logging.googleapis.com/insertId"); ok {
						t.Error("unexpected logging.googleapis.com/insertId when UpstreamInsertID=false")
					}
				}
			}
		}
	})

	t.Run("configurable ResourceAttrs and UpstreamInsertID", func(t *testing.T) {
		g := NewGenerator(GeneratorConfig{
			WorkloadProfile:  WorkloadProfileAccessLogs,
			ResourceAttrs:    18,
			UpstreamInsertID: true,
			PlantSecrets:     true,
		})
		ld := g.LogsBatch(8)
		rls := ld.ResourceLogs()
		if got := rls.At(0).Resource().Attributes().Len(); got != 18 {
			t.Fatalf("Resource attribute count = %d, want 18", got)
		}
		var secretCount int
		for i := 0; i < rls.Len(); i++ {
			sls := rls.At(i).ScopeLogs()
			for j := 0; j < sls.Len(); j++ {
				lrs := sls.At(j).LogRecords()
				for k := 0; k < lrs.Len(); k++ {
					lr := lrs.At(k)
					idVal, ok := lr.Attributes().Get("logging.googleapis.com/insertId")
					if !ok || !strings.HasPrefix(idVal.Str(), "edge-") {
						t.Errorf("missing or invalid logging.googleapis.com/insertId: %q (ok=%t)", idVal.Str(), ok)
					}
					if _, ok := lr.Attributes().Get("client.api_key"); ok {
						secretCount++
					}
				}
			}
		}
		if secretCount == 0 {
			t.Error("expected planted secrets when PlantSecrets=true in access-logs profile")
		}
	})
}

func TestNormalizeSoakAndProfileValidation(t *testing.T) {
	soakCfg := RunnerConfig{
		WorkloadProfile: WorkloadProfileAccessLogs,
		Soak:            true,
	}
	if err := soakCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(soak access-logs): %v", err)
	}
	if soakCfg.Duration < 60*time.Second {
		t.Errorf("Soak Duration = %s, want >= 60s", soakCfg.Duration)
	}
	if soakCfg.WarmupDuration <= 0 {
		t.Errorf("Soak WarmupDuration = %s, want > 0", soakCfg.WarmupDuration)
	}
	if len(soakCfg.Signals) != 1 || soakCfg.Signals[0] != "logs" {
		t.Errorf("Soak access-logs Signals = %v, want [logs]", soakCfg.Signals)
	}
	if soakCfg.ResourceAttrs != DefaultAccessLogsResourceAttrs {
		t.Errorf("ResourceAttrs = %d, want %d", soakCfg.ResourceAttrs, DefaultAccessLogsResourceAttrs)
	}
	if soakCfg.PayloadBytes != 128 {
		t.Errorf("PayloadBytes = %d, want 128", soakCfg.PayloadBytes)
	}

	invalid := []RunnerConfig{
		{WorkloadProfile: "unknown"},
		{WorkloadProfile: WorkloadProfileAccessLogs, Signals: []string{"traces"}},
		{WorkloadProfile: WorkloadProfileAccessLogs, ResourceAttrs: -1},
		{Soak: true, Duration: 10 * time.Second},
		{MaxProcs: -1},
		{WarmupDuration: -time.Second},
	}
	for _, tc := range invalid {
		if err := tc.Normalize(); err == nil {
			t.Errorf("Normalize(%+v) succeeded, want error", tc)
		}
	}
}

func TestByteAccountingAndWarmupDiscard(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Verify access-logs byte profile: field-family buckets sum to TotalBytesPerRow,
	// resource + sidecars are non-trivial, and trimming ResourceAttrs reduces resource wire bytes.
	fullCfg := RunnerConfig{
		Mode:            ModeBQFake,
		WorkloadProfile: WorkloadProfileAccessLogs,
		Signals:         []string{"logs"},
		BatchSize:       100,
		ResourceAttrs:   12,
	}
	if err := fullCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(fullCfg): %v", err)
	}
	fullLayers, fullBreakdown, err := measureByteProfile(fullCfg, "logs", 0)
	if err != nil {
		t.Fatalf("measureByteProfile(fullCfg): %v", err)
	}
	if fullLayers == nil || fullBreakdown == nil {
		t.Fatal("expected non-nil byte layers and field breakdown")
	}
	sumBuckets := fullBreakdown.ResourceBytes +
		fullBreakdown.ScopeBytes +
		fullBreakdown.BodyBytes +
		fullBreakdown.AttributesBytes +
		fullBreakdown.SchemaSidecarBytes +
		fullBreakdown.IdentityBytes +
		fullBreakdown.UnixNanoBytes +
		fullBreakdown.OtherBytes
	if math.Abs(sumBuckets-fullBreakdown.TotalBytesPerRow) > 0.25 {
		t.Fatalf("field family sum %.2f != TotalBytesPerRow %.2f", sumBuckets, fullBreakdown.TotalBytesPerRow)
	}
	if fullBreakdown.ResourcePct <= 20.0 {
		t.Errorf("access-logs ResourcePct = %.2f%%, expected > 20%% for 12 GKE resource attrs", fullBreakdown.ResourcePct)
	}
	if fullBreakdown.SchemaSidecarPct <= 10.0 {
		t.Errorf("access-logs SchemaSidecarPct = %.2f%%, expected > 10%% with *_schema sidecars", fullBreakdown.SchemaSidecarPct)
	}
	if fullLayers.OTLPToProtoRowsRatio <= 1.0 {
		t.Errorf("OTLPToProtoRowsRatio = %.2f, expected > 1.0 wire amplification on batched access logs", fullLayers.OTLPToProtoRowsRatio)
	}

	trimmedCfg := fullCfg
	trimmedCfg.ResourceAttrs = 2
	_, trimmedBreakdown, err := measureByteProfile(trimmedCfg, "logs", 0)
	if err != nil {
		t.Fatalf("measureByteProfile(trimmedCfg): %v", err)
	}
	if trimmedBreakdown.ResourceBytes >= fullBreakdown.ResourceBytes {
		t.Errorf("trimmed ResourceBytes (%.2f) >= full ResourceBytes (%.2f)", trimmedBreakdown.ResourceBytes, fullBreakdown.ResourceBytes)
	}

	// Verify WarmupDuration discards warmup batches and MaxProcs restores runtime.GOMAXPROCS.
	rep, err := Run(ctx, RunnerConfig{
		Mode:            ModeBQFake,
		WorkloadProfile: WorkloadProfileAccessLogs,
		Signals:         []string{"logs"},
		Duration:        200 * time.Millisecond,
		WarmupDuration:  120 * time.Millisecond,
		BatchSize:       25,
		Workers:         2,
		StreamPoolSize:  2,
		MaxProcs:        2,
	})
	if err != nil {
		t.Fatalf("Run(access-logs with warmup): %v", err)
	}
	if rep.GOMAXPROCS != 2 {
		t.Errorf("report.GOMAXPROCS = %d, want 2", rep.GOMAXPROCS)
	}
	if len(rep.Results) != 1 {
		t.Fatalf("len(rep.Results) = %d, want 1", len(rep.Results))
	}
	res := rep.Results[0]
	if res.Telemetry.AcknowledgedRows != res.RecordsSubmitted {
		t.Errorf("steady-state AcknowledgedRows (%d) != RecordsSubmitted (%d); warmup discard leaked",
			res.Telemetry.AcknowledgedRows, res.RecordsSubmitted)
	}
	if res.ByteLayers == nil || res.FieldFamilyBytes == nil {
		t.Fatal("SignalResult missing ByteLayers or FieldFamilyBytes")
	}

	md := FormatMarkdown(rep)
	for _, want := range []string{"5-Layer Byte Accounting", "Field-Family Wire Byte Breakdown", "profile=access-logs"} {
		if !strings.Contains(md, want) {
			t.Errorf("FormatMarkdown missing %q:\n%s", want, md)
		}
	}
}

func TestPopulateLiveTableStorage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		schema := &bigqueryapi.TableSchema{
			Fields: []*bigqueryapi.TableFieldSchema{
				{Name: "total_rows", Type: "INTEGER"},
				{Name: "total_logical_bytes", Type: "INTEGER"},
				{Name: "active_physical_bytes", Type: "INTEGER"},
				{Name: "long_term_physical_bytes", Type: "INTEGER"},
			},
		}
		rows := []*bigqueryapi.TableRow{
			{
				F: []*bigqueryapi.TableCell{
					{V: "1000"},
					{V: "1200000"},
					{V: "300000"},
					{V: "0"},
				},
			},
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries") {
			resp := bigqueryapi.QueryResponse{
				JobReference: &bigqueryapi.JobReference{ProjectId: "p", JobId: "j1", Location: "US"},
				JobComplete:  true,
				TotalRows:    1,
				Schema:       schema,
				Rows:         rows,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs") {
			resp := bigqueryapi.Job{
				JobReference: &bigqueryapi.JobReference{ProjectId: "p", JobId: "j1", Location: "US"},
				Status:       &bigqueryapi.JobStatus{State: "DONE"},
				Configuration: &bigqueryapi.JobConfiguration{
					Query: &bigqueryapi.JobConfigurationQuery{Query: "SELECT 1"},
				},
				Statistics: &bigqueryapi.JobStatistics{
					Query: &bigqueryapi.JobStatistics2{},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/queries/") {
			resp := bigqueryapi.GetQueryResultsResponse{
				JobComplete: true,
				TotalRows:   1,
				Schema:      schema,
				Rows:        rows,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}))
	defer srv.Close()

	layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 1000}
	cfg := RunnerConfig{
		Mode:      ModeLive,
		ProjectID: "p",
		DatasetID: "d",
		Location:  "US",
		ClientOptions: []option.ClientOption{
			option.WithEndpoint(srv.URL + "/bigquery/v2/"),
			option.WithoutAuthentication(),
		},
	}
	populateLiveTableStorage(context.Background(), cfg, "otel_logs", layers)
	if layers.BQStorageQueryNote != "" {
		t.Fatalf("unexpected BQStorageQueryNote: %s", layers.BQStorageQueryNote)
	}
	if layers.BQTotalRows != 1000 || layers.BQLogicalBytes != 1200000 || layers.BQActivePhysicalBytes != 300000 {
		t.Fatalf("unexpected live storage values: %+v", layers)
	}
	if layers.BQLogicalBytesPerRow != 1200 || layers.BQPhysicalBytesPerRow != 300 || layers.BQCompressionRatio != 4.0 {
		t.Fatalf("unexpected per-row/compression values: %+v", layers)
	}

	// Empty location without dataset metadata must return an explicit note rather than defaulting to "us".
	noLocLayers := &ByteLayersSummary{ProtoRowsBytesPerRow: 1000}
	noLocCfg := cfg
	noLocCfg.Location = ""
	populateLiveTableStorage(context.Background(), noLocCfg, "otel_logs", noLocLayers)
	if !strings.Contains(noLocLayers.BQStorageQueryNote, "dataset metadata lookup failed") {
		t.Fatalf("expected dataset metadata failure note for empty location, got %q", noLocLayers.BQStorageQueryNote)
	}
}
