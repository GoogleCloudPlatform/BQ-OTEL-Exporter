// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"time"

	bqi "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/bigquery"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
)

// writerObserver hands internal/bigquery the Telemetry recording methods it
// needs as method values. internal/bigquery never holds the
// *metadata.Telemetry itself, so it cannot reflect on it to reach the
// instrument fields and record around the methods that the README
// self-telemetry check reads.
type writerObserver struct {
	inflightRequests      func(context.Context, int64)
	unresolvedResults     func(context.Context, int64)
	appendResultWait      func(context.Context, time.Duration)
	timeoutAfterDispatch  func(context.Context)
	streamRetirement      func(context.Context)
	backpressureLevel     func(ctx context.Context, signal, table string, level float64)
	effectiveRequestBytes func(ctx context.Context, signal, table string, bytes int64)
	backpressureEvent     func(ctx context.Context, signal, table, trigger string)
}

var _ bqi.Observer = writerObserver{}

// newWriterObserver returns the writer observer of t. The Telemetry methods
// accept a nil receiver, so a nil t gives an observer that records nothing.
func newWriterObserver(t *metadata.Telemetry) writerObserver {
	return writerObserver{
		inflightRequests:      t.RecordInflightRequests,
		unresolvedResults:     t.RecordUnresolvedResults,
		appendResultWait:      t.RecordAppendResultWait,
		timeoutAfterDispatch:  t.RecordTimeoutAfterDispatch,
		streamRetirement:      t.RecordStreamRetirement,
		backpressureLevel:     t.RecordBackpressureLevel,
		effectiveRequestBytes: t.RecordEffectiveRequestBytes,
		backpressureEvent:     t.RecordBackpressureEvent,
	}
}

func (o writerObserver) RecordInflightRequests(ctx context.Context, delta int64) {
	o.inflightRequests(ctx, delta)
}

func (o writerObserver) RecordUnresolvedResults(ctx context.Context, delta int64) {
	o.unresolvedResults(ctx, delta)
}

func (o writerObserver) RecordAppendResultWait(ctx context.Context, elapsed time.Duration) {
	o.appendResultWait(ctx, elapsed)
}

func (o writerObserver) RecordTimeoutAfterDispatch(ctx context.Context) {
	o.timeoutAfterDispatch(ctx)
}

func (o writerObserver) RecordStreamRetirement(ctx context.Context) {
	o.streamRetirement(ctx)
}

func (o writerObserver) RecordBackpressureLevel(ctx context.Context, signal, table string, level float64) {
	o.backpressureLevel(ctx, signal, table, level)
}

func (o writerObserver) RecordEffectiveRequestBytes(ctx context.Context, signal, table string, bytes int64) {
	o.effectiveRequestBytes(ctx, signal, table, bytes)
}

func (o writerObserver) RecordBackpressureEvent(ctx context.Context, signal, table, trigger string) {
	o.backpressureEvent(ctx, signal, table, trigger)
}
