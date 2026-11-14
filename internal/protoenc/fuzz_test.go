// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package protoenc

import (
	"context"
	"math"
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

	spanEnc, err := New(schema.SpansTableSchema())
	if err != nil {
		f.Fatalf("New(SpansTableSchema): %v", err)
	}
	logEnc, err := New(schema.LogsTableSchema())
	if err != nil {
		f.Fatalf("New(LogsTableSchema): %v", err)
	}
	metEnc, err := New(schema.MetricsTableSchema())
	if err != nil {
		f.Fatalf("New(MetricsTableSchema): %v", err)
	}
	qEnc, err := New(schema.QuarantineTableSchema())
	if err != nil {
		f.Fatalf("New(QuarantineTableSchema): %v", err)
	}

	spanMD := buildDynamicDescriptor(f, spanEnc.Descriptor())
	logMD := buildDynamicDescriptor(f, logEnc.Descriptor())
	metMD := buildDynamicDescriptor(f, metEnc.Descriptor())
	qMD := buildDynamicDescriptor(f, qEnc.Descriptor())
	fixed := time.Date(2026, 11, 13, 8, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, svc, name, text string, baseNano, deltaNano int64, flags uint8, val float64) {
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
			Limits:           transform.DefaultLimits(),
			Now:              func() time.Time { return fixed },
			Contract:         schema.ContractV1Candidate,
			PayloadOffloader: fuzzOffloader{enable: flags&128 != 0},
		}
		sRows, sRej := transform.SpanRows(td, sOpts)
		if len(sRej) != 0 || len(sRows) != 1 {
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
		streamSpans, _, streamSRej, streamSDrops := transform.StreamSpanRows(td, sOpts, 0, spanEnc)
		if len(streamSRej) != 0 || len(streamSDrops) != 0 || len(streamSpans) != 1 {
			t.Fatalf("StreamSpanRows = (%d, %+v, %+v)", len(streamSpans), streamSRej, streamSDrops)
		}
		assertWireParity(t, "otel_spans", spanMD, wantSpanWire, gotSpanPlanWire, streamSpans[0])

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
			Limits:             transform.DefaultLimits(),
			Now:                func() time.Time { return fixed },
			Contract:           schema.ContractV1Candidate,
			SynthesizeInsertID: flags&32 != 0,
			PayloadOffloader:   fuzzOffloader{enable: flags&64 != 0},
		}
		lRows, lRej := transform.LogRows(ld, lOpts)
		if len(lRej) != 0 || len(lRows) != 1 {
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
		streamLogs, _, streamLRej, streamLDrops := transform.StreamLogRows(ld, lOpts, 0, logEnc)
		if len(streamLRej) != 0 || len(streamLDrops) != 0 || len(streamLogs) != 1 {
			t.Fatalf("StreamLogRows = (%d, %+v, %+v)", len(streamLogs), streamLRej, streamLDrops)
		}
		assertWireParity(t, "otel_logs", logMD, wantLogWire, gotLogPlanWire, streamLogs[0])

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
			Limits:   transform.DefaultLimits(),
			Now:      func() time.Time { return fixed },
			Contract: schema.ContractV1Candidate,
		}
		mRows, mRej := transform.MetricRows(md, mOpts)
		if len(mRej) != 0 || len(mRows) != 5 {
			t.Fatalf("MetricRows = (%d, %+v)", len(mRows), mRej)
		}
		streamMetrics, _, streamMRej, streamMDrops := transform.StreamMetricRows(md, mOpts, 0, metEnc)
		if len(streamMRej) != 0 || len(streamMDrops) != 0 || len(streamMetrics) != 5 {
			t.Fatalf("StreamMetricRows = (%d, %+v, %+v)", len(streamMetrics), streamMRej, streamMDrops)
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
		qIn := QuarantineWireInput{
			IngestTimeMicros: fixed.UnixMicro(),
			Signal:           schema.SignalLogs,
			ErrorCode:        "ROW_ERROR",
			ErrorMessage:     sanitizeFast(text),
			ServiceName:      sanitizeFast(svc),
			TraceID:          "0102030405060708090a0b0c0d0e0f10",
			SpanID:           "0102030405060708",
			RawPayload:       sanitizeFast(name),
			HasRawAttributes: flags&1 != 0,
			RawAttributes:    "{}",
			HasPayloadRef:    flags&2 != 0,
			PayloadRef: transform.ObjectRef{
				URI:        "gs://fuzz-bucket/q/0",
				Version:    "7",
				Authorizer: "",
				Details:    `{"gcs_metadata":{"size":10}}`,
			},
			ExporterInstance: sanitizeFast(svc),
		}
		qRow := transform.Row{
			"ingest_time":   qIn.IngestTimeMicros,
			"signal":        qIn.Signal,
			"error_code":    qIn.ErrorCode,
			"error_message": qIn.ErrorMessage,
		}
		if qIn.ServiceName != "" {
			qRow["service_name"] = qIn.ServiceName
		}
		if qIn.TraceID != "" {
			qRow["trace_id"] = qIn.TraceID
		}
		if qIn.SpanID != "" {
			qRow["span_id"] = qIn.SpanID
		}
		if qIn.RawPayload != "" {
			qRow["raw_payload"] = qIn.RawPayload
		}
		if qIn.HasRawAttributes {
			qRow["raw_attributes"] = qIn.RawAttributes
		}
		if qIn.HasPayloadRef {
			qRow["payload_ref"] = qIn.PayloadRef.ToRow()
		}
		if qIn.ExporterInstance != "" {
			qRow["exporter_instance"] = qIn.ExporterInstance
		}
		wantQWire, err := qEnc.encodeDynamicPB(qRow)
		if err != nil {
			t.Fatalf("quarantine dynamicpb: %v", err)
		}
		gotQPlanWire, err := qEnc.Encode(qRow)
		if err != nil {
			t.Fatalf("quarantine plan Encode: %v", err)
		}
		gotQStreamWire, _, _, err := EncodeQuarantineWire(&qIn, 0)
		if err != nil {
			t.Fatalf("quarantine stream Encode: %v", err)
		}
		assertWireParity(t, "otel_quarantine", qMD, wantQWire, gotQPlanWire, gotQStreamWire)
	})
}
