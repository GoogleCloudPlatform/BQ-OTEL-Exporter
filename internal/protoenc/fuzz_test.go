// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package protoenc

import (
	"context"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

// fuzzMaxValueBytes is the value limit FuzzWireEncoderMatchesDynamicPB runs
// under. It is far below the 256 KiB default so that a seed of a few hundred
// bytes reaches the value_size rejection path and the fuzzer never has to
// mutate or minimize a 256 KiB input; it is still above 127, so an accepted
// string value can need a two-byte length prefix.
// TestWireEncoderMatchesDynamicPBAtDefaultValueLimit covers the default limit.
const fuzzMaxValueBytes = 256

type fuzzOffloader struct {
	enable bool
}

func (f fuzzOffloader) OffloadSpan(_ context.Context, _ ptrace.Span, _ pcommon.Resource, _ pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	if !f.enable {
		return nil, nil
	}
	return []transform.PayloadRef{{
		AttributePath: "attributes.payload",
		ObjectRef: transform.ObjectRef{
			URI:        "gs://fuzz-bucket/spans/obj-1",
			Version:    "42",
			Authorizer: "projects/p/locations/us/connections/c",
			Details:    `{"gcs_metadata":{"content_type":"text/plain","size":128}}`,
		},
	}}, nil
}

func (f fuzzOffloader) OffloadLog(_ context.Context, _ plog.LogRecord, _ pcommon.Resource, _ pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	if !f.enable {
		return nil, nil
	}
	return []transform.PayloadRef{{
		AttributePath: "body",
		ObjectRef: transform.ObjectRef{
			URI:     "gs://fuzz-bucket/logs/obj-1",
			Version: "",
			Details: "",
		},
	}}, nil
}

func assertWireParity(t *testing.T, label string, md protoreflect.MessageDescriptor, wantWire, gotPlanWire, gotStreamWire []byte) {
	t.Helper()
	wantMsg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(wantWire, wantMsg); err != nil {
		t.Fatalf("%s: unmarshal dynamicpb wire: %v", label, err)
	}
	gotPlanMsg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(gotPlanWire, gotPlanMsg); err != nil {
		t.Fatalf("%s: unmarshal plan wire: %v", label, err)
	}
	if !proto.Equal(wantMsg, gotPlanMsg) {
		t.Fatalf("%s: plan wire decoded mismatch:\nwant: %v\ngot:  %v", label, wantMsg, gotPlanMsg)
	}
	if gotStreamWire != nil {
		gotStreamMsg := dynamicpb.NewMessage(md)
		if err := proto.Unmarshal(gotStreamWire, gotStreamMsg); err != nil {
			t.Fatalf("%s: unmarshal stream wire: %v", label, err)
		}
		if !proto.Equal(wantMsg, gotStreamMsg) {
			t.Fatalf("%s: stream wire decoded mismatch:\nwant: %v\ngot:  %v", label, wantMsg, gotStreamMsg)
		}
	}
}

func FuzzWireEncoderMatchesDynamicPB(f *testing.F) {
	f.Add("checkout", "GET /cart", "disk full", int64(1700000000000000000), int64(25000000), uint8(0x0f), float64(12.5))
	f.Add("", "", "", int64(0), int64(-500), uint8(0x00), math.NaN())
	f.Add("svc\xff", "span\x00name", "body\xff", int64(1700000005000000000), int64(0), uint8(0xff), math.Inf(1))
	f.Add("edge", "call", "hello", int64(1700000001000000000), int64(1000000), uint8(0x55), math.Inf(-1))
	// One byte over the harness's lowered value limit, so a seed of a few
	// hundred bytes exercises value_size rejection parity.
	f.Add("oversized", "call", strings.Repeat("x", fuzzMaxValueBytes+1), int64(1700000001000000000), int64(1000000), uint8(0x00), float64(1.0))

	limits := transform.DefaultLimits()
	limits.MaxValueBytes = fuzzMaxValueBytes
	check := newWireParityCheck(f, limits)
	f.Fuzz(func(t *testing.T, svc, name, text string, baseNano, deltaNano int64, flags uint8, val float64) {
		check(t, svc, name, text, baseNano, deltaNano, flags, val)
	})
}

// wireParityRejections are the records the row-map builders rejected in one
// check, which the streaming builders were verified to reject identically.
type wireParityRejections struct {
	spans, logs, metrics []transform.Rejection
}

// newWireParityCheck returns the differential check of
// FuzzWireEncoderMatchesDynamicPB under limits: for all four tables, the plan
// and streaming wire encoders must agree with dynamicpb, and the streaming row
// builders must reject exactly the records the row-map builders reject.
func newWireParityCheck(tb testing.TB, limits transform.Limits) func(t *testing.T, svc, name, text string, baseNano, deltaNano int64, flags uint8, val float64) wireParityRejections {
	tb.Helper()
	spanEnc, err := New(schema.SpansTableSchema())
	if err != nil {
		tb.Fatalf("New(SpansTableSchema): %v", err)
	}
	logEnc, err := New(schema.LogsTableSchema())
	if err != nil {
		tb.Fatalf("New(LogsTableSchema): %v", err)
	}
	metEnc, err := New(schema.MetricsTableSchema())
	if err != nil {
		tb.Fatalf("New(MetricsTableSchema): %v", err)
	}
	qEnc, err := New(schema.QuarantineTableSchema())
	if err != nil {
		tb.Fatalf("New(QuarantineTableSchema): %v", err)
	}

	spanMD := buildDynamicDescriptor(tb, spanEnc.Descriptor())
	logMD := buildDynamicDescriptor(tb, logEnc.Descriptor())
	metMD := buildDynamicDescriptor(tb, metEnc.Descriptor())
	qMD := buildDynamicDescriptor(tb, qEnc.Descriptor())
	fixed := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)

	return func(t *testing.T, svc, name, text string, baseNano, deltaNano int64, flags uint8, val float64) wireParityRejections {
		startTS := pcommon.Timestamp(1_700_000_000_000_000_000)
		if baseNano > 0 {
			startTS = pcommon.Timestamp(uint64(baseNano))
		}
		endTS := startTS
		if deltaNano >= 0 && uint64(startTS)+uint64(deltaNano) <= math.MaxInt64 {
			endTS = startTS + pcommon.Timestamp(uint64(deltaNano))
		} else if deltaNano < 0 && int64(startTS)+deltaNano > 0 {
			endTS = pcommon.Timestamp(int64(startTS) + deltaNano)
		}

		// 1. otel_spans
		td := ptrace.NewTraces()
		rs := td.ResourceSpans().AppendEmpty()
		if svc != "" {
			rs.Resource().Attributes().PutStr("service.name", svc)
		}
		rs.Resource().Attributes().PutInt("int_val", deltaNano)
		if flags&1 != 0 {
			rs.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
		}
		ss := rs.ScopeSpans().AppendEmpty()
		ss.Scope().SetName(name)
		if flags&2 != 0 {
			ss.Scope().SetVersion("1.0.0")
			ss.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
		}
		sp := ss.Spans().AppendEmpty()
		sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
		if flags&4 != 0 {
			sp.SetParentSpanID(pcommon.SpanID{8, 7, 6, 5, 4, 3, 2, 1})
			sp.TraceState().FromRaw("rojo=00f067aa0ba902b7")
		}
		sp.SetName(name)
		sp.SetKind(ptrace.SpanKind(flags % 7))
		sp.SetStartTimestamp(startTS)
		sp.SetEndTimestamp(endTS)
		sp.SetFlags(uint32(flags))
		sp.Status().SetCode(ptrace.StatusCode(flags % 3))
		if flags&8 != 0 {
			sp.Status().SetMessage(text)
		}
		sp.Attributes().PutStr("msg", text)
		sp.Attributes().PutDouble("score", val)
		sp.Attributes().PutBool("ok", flags&16 != 0)
		ev := sp.Events().AppendEmpty()
		ev.SetName("") // explicitly exercise empty-string event name presence
		if flags&32 != 0 {
			ev.SetTimestamp(startTS)
		}
		lk := sp.Links().AppendEmpty()
		if flags&64 != 0 {
			lk.SetTraceID(pcommon.TraceID{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
			lk.SetSpanID(pcommon.SpanID{9, 8, 7, 6, 5, 4, 3, 2})
		}

		sOpts := transform.Options{
			Limits:           limits,
			Now:              func() time.Time { return fixed },
			Contract:         schema.ContractV1Candidate,
			PayloadOffloader: fuzzOffloader{enable: flags&128 != 0},
		}
		sRows, sRej := transform.SpanRows(td, sOpts)
		streamSpans, sKept, streamSRej, streamSDrops := transform.StreamSpanRows(td, sOpts, 0, spanEnc)
		if !slices.Equal(streamSRej, sRej) || len(streamSDrops) != 0 || len(streamSpans) != len(sRows) || len(sKept) != len(sRows) {
			t.Fatalf("span parity mismatch: SpanRows=(%d, %+v) StreamSpanRows=(%d, kept=%d, rej=%+v, drops=%+v)",
				len(sRows), sRej, len(streamSpans), len(sKept), streamSRej, streamSDrops)
		}
		if len(sRej) == 0 {
			if len(sRows) != 1 {
				t.Fatalf("SpanRows = (%d, %+v)", len(sRows), sRej)
			}
			wantSpanWire, err := spanEnc.encodeDynamicPB(sRows[0])
			if err != nil {
				t.Fatalf("span dynamicpb: %v", err)
			}
			gotSpanPlanWire, err := spanEnc.Encode(sRows[0])
			if err != nil {
				t.Fatalf("span plan Encode: %v", err)
			}
			assertWireParity(t, "otel_spans", spanMD, wantSpanWire, gotSpanPlanWire, streamSpans[0])
		}

		// 2. otel_logs
		ld := plog.NewLogs()
		lrl := ld.ResourceLogs().AppendEmpty()
		if svc != "" {
			lrl.Resource().Attributes().PutStr("service.name", svc)
		}
		lsl := lrl.ScopeLogs().AppendEmpty()
		lsl.Scope().SetName(name)
		lr := lsl.LogRecords().AppendEmpty()
		if flags&1 != 0 {
			lr.SetTimestamp(startTS)
		}
		if flags&2 != 0 {
			lr.SetObservedTimestamp(endTS)
		}
		if flags&4 != 0 {
			lr.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
			lr.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
		}
		lr.SetFlags(plog.LogRecordFlags(flags))
		lr.SetSeverityNumber(plog.SeverityNumber(int32(flags % 25)))
		lr.SetSeverityText(text)
		lr.SetEventName(name)
		if flags&8 != 0 {
			lr.Body().SetStr(text)
		} else if flags&16 != 0 {
			lr.Body().SetEmptyBytes().FromRaw([]byte(text))
		}
		lr.Attributes().PutStr("k", text)
		lr.Attributes().PutInt("n", deltaNano)

		lOpts := transform.Options{
			Limits:             limits,
			Now:                func() time.Time { return fixed },
			Contract:           schema.ContractV1Candidate,
			SynthesizeInsertID: flags&32 != 0,
			PayloadOffloader:   fuzzOffloader{enable: flags&64 != 0},
		}
		lRows, lRej := transform.LogRows(ld, lOpts)
		streamLogs, lKept, streamLRej, streamLDrops := transform.StreamLogRows(ld, lOpts, 0, logEnc)
		if !slices.Equal(streamLRej, lRej) || len(streamLDrops) != 0 || len(streamLogs) != len(lRows) || len(lKept) != len(lRows) {
			t.Fatalf("log parity mismatch: LogRows=(%d, %+v) StreamLogRows=(%d, kept=%d, rej=%+v, drops=%+v)",
				len(lRows), lRej, len(streamLogs), len(lKept), streamLRej, streamLDrops)
		}
		if len(lRej) == 0 {
			if len(lRows) != 1 {
				t.Fatalf("LogRows = (%d, %+v)", len(lRows), lRej)
			}
			wantLogWire, err := logEnc.encodeDynamicPB(lRows[0])
			if err != nil {
				t.Fatalf("log dynamicpb: %v", err)
			}
			gotLogPlanWire, err := logEnc.Encode(lRows[0])
			if err != nil {
				t.Fatalf("log plan Encode: %v", err)
			}
			assertWireParity(t, "otel_logs", logMD, wantLogWire, gotLogPlanWire, streamLogs[0])
		}

		// 3. otel_metrics (covering Gauge, Sum, Histogram, ExponentialHistogram, Summary)
		md := pmetric.NewMetrics()
		mrm := md.ResourceMetrics().AppendEmpty()
		if svc != "" {
			mrm.Resource().Attributes().PutStr("service.name", svc)
		}
		msm := mrm.ScopeMetrics().AppendEmpty()
		msm.Scope().SetName(name)
		// Gauge
		mg := msm.Metrics().AppendEmpty()
		mg.SetName("fuzz.gauge")
		mg.Metadata().PutStr("k", text)
		gdp := mg.SetEmptyGauge().DataPoints().AppendEmpty()
		gdp.SetTimestamp(startTS)
		gdp.SetDoubleValue(val)
		ex := gdp.Exemplars().AppendEmpty()
		if flags&1 != 0 {
			ex.SetTimestamp(startTS)
		}
		ex.SetDoubleValue(val)
		ex.FilteredAttributes().PutStr("f", text)
		// Sum
		ms := msm.Metrics().AppendEmpty()
		ms.SetName("fuzz.sum")
		s := ms.SetEmptySum()
		s.SetIsMonotonic(flags&2 != 0)
		s.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
		sdp := s.DataPoints().AppendEmpty()
		sdp.SetTimestamp(startTS)
		sdp.SetStartTimestamp(endTS)
		sdp.SetIntValue(deltaNano)
		// Histogram
		mh := msm.Metrics().AppendEmpty()
		mh.SetName("fuzz.hist")
		h := mh.SetEmptyHistogram()
		h.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		hdp := h.DataPoints().AppendEmpty()
		hdp.SetTimestamp(startTS)
		hdp.SetCount(5)
		if flags&4 != 0 {
			hdp.SetSum(val)
			hdp.SetMin(0)
			hdp.SetMax(val)
		}
		hdp.ExplicitBounds().FromRaw([]float64{1.0, 5.0})
		hdp.BucketCounts().FromRaw([]uint64{2, 2, 1})
		// ExponentialHistogram
		meh := msm.Metrics().AppendEmpty()
		meh.SetName("fuzz.exphist")
		eh := meh.SetEmptyExponentialHistogram()
		ehdp := eh.DataPoints().AppendEmpty()
		ehdp.SetTimestamp(startTS)
		ehdp.SetCount(3)
		ehdp.SetScale(-1)
		ehdp.SetZeroCount(1)
		ehdp.Positive().SetOffset(-2)
		ehdp.Positive().BucketCounts().FromRaw([]uint64{1, 2})
		// Summary
		msum := msm.Metrics().AppendEmpty()
		msum.SetName("fuzz.summary")
		sumdp := msum.SetEmptySummary().DataPoints().AppendEmpty()
		sumdp.SetTimestamp(startTS)
		sumdp.SetCount(2)
		sumdp.SetSum(val)
		qv := sumdp.QuantileValues().AppendEmpty()
		qv.SetQuantile(0.99)
		qv.SetValue(val)

		mOpts := transform.Options{
			Limits:   limits,
			Now:      func() time.Time { return fixed },
			Contract: schema.ContractV1Candidate,
		}
		mRows, mRej := transform.MetricRows(md, mOpts)
		streamMetrics, mKept, streamMRej, streamMDrops := transform.StreamMetricRows(md, mOpts, 0, metEnc)
		if !slices.Equal(streamMRej, mRej) || len(streamMDrops) != 0 || len(streamMetrics) != len(mRows) || len(mKept) != len(mRows) {
			t.Fatalf("metric parity mismatch: MetricRows=(%d, %+v) StreamMetricRows=(%d, kept=%d, rej=%+v, drops=%+v)",
				len(mRows), mRej, len(streamMetrics), len(mKept), streamMRej, streamMDrops)
		}
		if len(mRej) == 0 && len(mRows) != 5 {
			t.Fatalf("MetricRows = (%d, %+v)", len(mRows), mRej)
		}
		for i := range mRows {
			wantMWire, err := metEnc.encodeDynamicPB(mRows[i])
			if err != nil {
				t.Fatalf("metric[%d] dynamicpb: %v", i, err)
			}
			gotMPlanWire, err := metEnc.Encode(mRows[i])
			if err != nil {
				t.Fatalf("metric[%d] plan Encode: %v", i, err)
			}
			assertWireParity(t, "otel_metrics", metMD, wantMWire, gotMPlanWire, streamMetrics[i])
		}

		// 4. otel_quarantine
		qSvc := sanitizeFast(svc)
		qName := sanitizeFast(name)
		qRow := transform.Row{
			"ingest_time":   fixed.UnixMicro(),
			"signal":        schema.SignalLogs,
			"error_code":    "ROW_ERROR",
			"error_message": sanitizeFast(text),
			"trace_id":      "0102030405060708090a0b0c0d0e0f10",
			"span_id":       "0102030405060708",
		}
		if qSvc != "" {
			qRow["service_name"] = qSvc
			qRow["exporter_instance"] = qSvc
		}
		if qName != "" {
			qRow["raw_payload"] = qName
		}
		if flags&1 != 0 {
			qRow["raw_attributes"] = "{}"
		}
		if flags&2 != 0 {
			qRow["payload_ref"] = transform.ObjectRef{
				URI:     "gs://fuzz-bucket/q/0",
				Version: "7",
				Details: `{"gcs_metadata":{"size":10}}`,
			}.ToRow()
		}
		wantQWire, err := qEnc.encodeDynamicPB(qRow)
		if err != nil {
			t.Fatalf("quarantine dynamicpb: %v", err)
		}
		gotQPlanWire, err := qEnc.Encode(qRow)
		if err != nil {
			t.Fatalf("quarantine plan Encode: %v", err)
		}
		assertWireParity(t, "otel_quarantine", qMD, wantQWire, gotQPlanWire, nil)
		return wireParityRejections{spans: sRej, logs: lRej, metrics: mRej}
	}
}

// TestWireEncoderMatchesDynamicPBAtDefaultValueLimit runs the fuzz target's
// check at the default 256 KiB value limit, which is too large for a fuzz
// seed: a value exactly at the limit is accepted and encoded, with a
// three-byte length prefix, and one byte more is rejected as value_size by the
// row-map and the streaming builders alike.
func TestWireEncoderMatchesDynamicPBAtDefaultValueLimit(t *testing.T) {
	limits := transform.DefaultLimits()
	check := newWireParityCheck(t, limits)
	run := func(t *testing.T, text string) wireParityRejections {
		return check(t, "oversized", "call", text, int64(1700000001000000000), int64(1000000), uint8(0x00), float64(1.0))
	}

	t.Run("at the limit", func(t *testing.T) {
		got := run(t, strings.Repeat("x", limits.MaxValueBytes))
		if len(got.spans) != 0 || len(got.logs) != 0 || len(got.metrics) != 0 {
			t.Fatalf("a %d-byte value was rejected: %+v, want every record encoded", limits.MaxValueBytes, got)
		}
	})

	t.Run("one byte over the limit", func(t *testing.T) {
		got := run(t, strings.Repeat("x", limits.MaxValueBytes+1))
		for signal, rej := range map[string][]transform.Rejection{
			"span":   got.spans,
			"log":    got.logs,
			"metric": got.metrics,
		} {
			if len(rej) == 0 {
				t.Errorf("%s record with a %d-byte value was not rejected", signal, limits.MaxValueBytes+1)
			}
			for _, r := range rej {
				if r.Reason != transform.ReasonValueSize {
					t.Errorf("%s rejection = %+v, want reason %s", signal, r, transform.ReasonValueSize)
				}
			}
		}
	})
}
