// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	bqi "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/bigquery"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
)

func TestWriterObserverRecordsThroughTelemetry(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	tel, err := metadata.NewTelemetry(provider)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var obs bqi.Observer = newWriterObserver(tel)
	obs.RecordInflightRequests(ctx, 2)
	obs.RecordUnresolvedResults(ctx, 3)
	obs.RecordAppendResultWait(ctx, 2*time.Second)
	obs.RecordTimeoutAfterDispatch(ctx)
	obs.RecordStreamRetirement(ctx)
	obs.RecordBackpressureLevel(ctx, "traces", "otel_spans", 0.5)
	obs.RecordEffectiveRequestBytes(ctx, "traces", "otel_spans", 1024)
	obs.RecordBackpressureEvent(ctx, "traces", "otel_spans", "step_down")

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]float64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					got[m.Name] += float64(dp.Value)
				}
			case metricdata.Gauge[int64]:
				for _, dp := range data.DataPoints {
					got[m.Name] = float64(dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range data.DataPoints {
					got[m.Name] = dp.Value
				}
			case metricdata.Histogram[float64]:
				for _, dp := range data.DataPoints {
					got[m.Name] += dp.Sum
				}
			}
		}
	}
	for name, want := range map[string]float64{
		"otelcol_exporter_bigquery_inflight_requests":       2,
		"otelcol_exporter_bigquery_unresolved_results":      3,
		"otelcol_exporter_bigquery_append_result_wait":      2,
		"otelcol_exporter_bigquery_timeouts_after_dispatch": 1,
		"otelcol_exporter_bigquery_stream_retirements":      1,
		"otelcol_exporter_bigquery_backpressure_level":      0.5,
		"otelcol_exporter_bigquery_effective_request_bytes": 1024,
		"otelcol_exporter_bigquery_backpressure_events":     1,
	} {
		if v, ok := got[name]; !ok || v != want {
			t.Errorf("%s = %v (recorded %v), want %v", name, v, ok, want)
		}
	}

	// A nil Telemetry records nothing, and its observer must not panic.
	nilObs := newWriterObserver(nil)
	nilObs.RecordInflightRequests(ctx, 1)
	nilObs.RecordUnresolvedResults(ctx, 1)
	nilObs.RecordAppendResultWait(ctx, time.Second)
	nilObs.RecordTimeoutAfterDispatch(ctx)
	nilObs.RecordStreamRetirement(ctx)
	nilObs.RecordBackpressureLevel(ctx, "traces", "otel_spans", 1)
	nilObs.RecordEffectiveRequestBytes(ctx, "traces", "otel_spans", 1)
	nilObs.RecordBackpressureEvent(ctx, "traces", "otel_spans", "recovery")
}
