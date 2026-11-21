// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package transform

import (
	"math"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

func extractLogRowInsertIDs(rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		if id, ok := r["insert_id"].(string); ok {
			out[i] = id
		}
	}
	return out
}

func extractMetricRowFingerprints(rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i], _ = r["point_fingerprint"].(string)
	}
	return out
}

func buildParityLogsBatch() plog.Logs {
	ld := plog.NewLogs()

	// Resource 0: explicit insert_ids, configured override, non-string/empty fallback,
	// duplicate peer ordinals, invalid UTF-8, and rich ValueTypes.
	rl0 := ld.ResourceLogs().AppendEmpty()
	rl0.SetSchemaUrl("https://example.test/res/\xff")
	rl0.Resource().Attributes().PutStr("service.name", "edge-\xffproxy")
	rl0.Resource().SetDroppedAttributesCount(2)

	// Empty ScopeLogs should not shift indices or ordinals.
	rl0.ScopeLogs().AppendEmpty()

	sl0 := rl0.ScopeLogs().AppendEmpty()
	sl0.SetSchemaUrl("https://example.test/scope/\xff")
	sl0.Scope().SetName("scope-\xffname")
	sl0.Scope().SetVersion("1.2.3")
	sl0.Scope().Attributes().PutInt("scope.gen", 7)
	sl0.Scope().SetDroppedAttributesCount(1)

	addBase := func(ts int64, body string) plog.LogRecord {
		lr := sl0.LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(ts))
		lr.SetObservedTimestamp(pcommon.Timestamp(ts + 500))
		lr.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		lr.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
		lr.SetFlags(plog.LogRecordFlags(1))
		lr.SetEventName("ev.\xffname")
		lr.SetSeverityNumber(plog.SeverityNumberWarn)
		lr.SetSeverityText("WARN\xff")
		lr.Body().SetStr(body)
		lr.SetDroppedAttributesCount(3)
		return lr
	}

	// 0: configured InsertIDAttribute takes precedence over well-known attrs (sanitized UTF-8).
	lr0 := addBase(1_700_000_000_000_000_000, "configured")
	lr0.Attributes().PutStr("custom.id", "cfg-\xffid")
	lr0.Attributes().PutStr("logging.googleapis.com/insertId", "well-known-id")

	// 1: non-string & empty configured/well-known attrs fall back to gcp.insert.id.
	lr1 := addBase(1_700_000_000_000_001_000, "fallback")
	lr1.Attributes().PutInt("custom.id", 42)
	lr1.Attributes().PutStr("logging.googleapis.com/insertId", "")
	lr1.Attributes().PutStr("gcp.insert.id", "gcp-id-1")

	// 2, 3, 5: identical ID-less records exercising intra-batch ordinal [0, 1, 2].
	addDup := func() {
		lr := addBase(1_700_000_000_000_002_000, "dup-\xffbody")
		lr.Attributes().PutStr("k.str", "val-\xff")
		lr.Attributes().PutInt("k.int", 42)
		lr.Attributes().PutDouble("k.nan", math.NaN())
		lr.Attributes().PutBool("k.bool", true)
		lr.Attributes().PutEmptyBytes("k.bytes").FromRaw([]byte{1, 2, 3, 4})
		sl := lr.Attributes().PutEmptySlice("k.slice")
		sl.AppendEmpty().SetStr("a")
		sl.AppendEmpty().SetInt(9)
		mp := lr.Attributes().PutEmptyMap("k.map")
		mp.PutStr("nested", "v")
	}
	addDup() // 2
	addDup() // 3

	// 4: distinct ID-less record interleaved between duplicates.
	lr4 := addBase(1_700_000_000_000_002_000, "distinct")
	lr4.Attributes().PutStr("k.str", "other")

	addDup() // 5

	// 6: log.record.uid well-known attr.
	lr6 := addBase(1_700_000_000_000_003_000, "uid")
	lr6.Attributes().PutStr("log.record.uid", "uid-6")

	// Resource 1: second resource/scope origin with duplicate of record shape.
	rl1 := ld.ResourceLogs().AppendEmpty()
	rl1.Resource().Attributes().PutStr("service.name", "other-svc")
	sl1 := rl1.ScopeLogs().AppendEmpty()
	lr7 := sl1.LogRecords().AppendEmpty()
	lr7.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_004_000))
	lr7.Body().SetStr("resource-1")

	return ld
}

func TestResolveLogInsertIDsParityWithLogRows(t *testing.T) {
	t.Run("empty_logs", func(t *testing.T) {
		got := ResolveLogInsertIDs(plog.NewLogs(), Options{SynthesizeInsertID: true})
		if len(got) != 0 {
			t.Fatalf("ResolveLogInsertIDs(empty) = %v, want len 0", got)
		}
	})

	t.Run("synthesize_true_mixed_explicit_and_ordinals", func(t *testing.T) {
		ld := buildParityLogsBatch()
		opts := testOpts()
		opts.Contract = schema.ContractV1Candidate
		opts.InsertIDAttribute = "custom.id"
		opts.SynthesizeInsertID = true

		rows, rejects := LogRows(ld, opts)
		if len(rejects) != 0 || len(rows) != ld.LogRecordCount() {
			t.Fatalf("LogRows = (%d rows, %+v rejects), want (%d, nil)", len(rows), rejects, ld.LogRecordCount())
		}
		want := extractLogRowInsertIDs(rows)

		got := ResolveLogInsertIDs(ld, opts)
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveLogInsertIDs = %v, want %v", got, want)
		}
		if got[0] != "cfg-\uFFFDid" {
			t.Errorf("got[0] = %q, want sanitized custom.id", got[0])
		}
		if got[1] != "gcp-id-1" {
			t.Errorf("got[1] = %q, want gcp-id-1", got[1])
		}
		if got[2] == got[3] || got[3] == got[5] || got[2] == got[5] {
			t.Errorf("duplicate records collided: got[2]=%q got[3]=%q got[5]=%q", got[2], got[3], got[5])
		}
		if got[6] != "uid-6" {
			t.Errorf("got[6] = %q, want uid-6", got[6])
		}

		// Zero-valued Options{InsertIDAttribute, SynthesizeInsertID} without Limits/Now
		// must produce the exact same IDs.
		zeroOptsGot := ResolveLogInsertIDs(ld, Options{
			InsertIDAttribute:  "custom.id",
			SynthesizeInsertID: true,
		})
		if !slices.Equal(zeroOptsGot, want) {
			t.Fatalf("ResolveLogInsertIDs(zero Limits) = %v, want %v", zeroOptsGot, want)
		}
	})

	t.Run("synthesize_false_emits_empty_for_idless_and_zero_sha256", func(t *testing.T) {
		ld := buildParityLogsBatch()
		var shaCalls atomic.Int64
		opts := testOpts()
		opts.InsertIDAttribute = "custom.id"
		opts.SynthesizeInsertID = false
		opts.onSHA256 = func() { shaCalls.Add(1) }

		rows, rejects := LogRows(ld, opts)
		if len(rejects) != 0 {
			t.Fatalf("unexpected rejections: %+v", rejects)
		}
		want := extractLogRowInsertIDs(rows)

		shaCalls.Store(0)
		got := ResolveLogInsertIDs(ld, opts)
		if shaCalls.Load() != 0 {
			t.Fatalf("sha256 calls = %d, want 0 when SynthesizeInsertID=false", shaCalls.Load())
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveLogInsertIDs(SynthesizeInsertID=false) = %v, want %v", got, want)
		}
		for _, idx := range []int{2, 3, 4, 5, 7} {
			if got[idx] != "" {
				t.Errorf("got[%d] = %q, want empty string for SQL NULL", idx, got[idx])
			}
		}
	})

	t.Run("all_explicit_insert_id_zero_sha256", func(t *testing.T) {
		ld := plog.NewLogs()
		sl := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
		for _, id := range []string{"e1", "e2"} {
			lr := sl.LogRecords().AppendEmpty()
			lr.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_000_000))
			lr.Attributes().PutStr("logging.googleapis.com/insertId", id)
		}
		var shaCalls atomic.Int64
		opts := Options{
			SynthesizeInsertID: true,
			onSHA256:           func() { shaCalls.Add(1) },
		}
		got := ResolveLogInsertIDs(ld, opts)
		if shaCalls.Load() != 0 {
			t.Fatalf("sha256 calls = %d, want 0 when all records have explicit insert_id", shaCalls.Load())
		}
		if !slices.Equal(got, []string{"e1", "e2"}) {
			t.Fatalf("got = %v, want [e1 e2]", got)
		}
	})

	t.Run("redactor_parity_and_non_mutation", func(t *testing.T) {
		ld := plog.NewLogs()
		rl := ld.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", "checkout")
		rl.Resource().Attributes().PutStr("password", "res-pw")
		sl := rl.ScopeLogs().AppendEmpty()
		sl.Scope().Attributes().PutStr("note", leakedSecret)

		// 0: explicit insert_id carrying secret pattern
		lr0 := sl.LogRecords().AppendEmpty()
		lr0.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_000_000))
		lr0.Attributes().PutStr("custom.id", "id-"+leakedSecret)

		// 1: synthesized record carrying blocked key and redacted body
		lr1 := sl.LogRecords().AppendEmpty()
		lr1.SetTimestamp(pcommon.Timestamp(1_700_000_000_001_000_000))
		lr1.Attributes().PutStr("session_token", "tok-abc")
		lr1.Body().SetStr("secret " + leakedSecret)

		before := marshalLogsJSON(t, ld)

		opts := testOpts()
		opts.InsertIDAttribute = "custom.id"
		opts.SynthesizeInsertID = true
		opts.Redactor = testRedactor(t, true)

		rows, rejects := LogRows(ld, opts)
		if len(rejects) != 0 || len(rows) != 2 {
			t.Fatalf("LogRows = (%d, %+v)", len(rows), rejects)
		}
		want := extractLogRowInsertIDs(rows)

		got := ResolveLogInsertIDs(ld, opts)
		if marshalLogsJSON(t, ld) != before {
			t.Fatal("ResolveLogInsertIDs mutated caller's plog.Logs")
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveLogInsertIDs with Redactor = %v, want %v", got, want)
		}
		if got[0] != "id-"+redactedMark {
			t.Errorf("got[0] = %q, want redacted explicit insert_id", got[0])
		}
	})

	t.Run("offloader_preserves_pre_offload_identity", func(t *testing.T) {
		ld := plog.NewLogs()
		lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
		lr.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_000_000))
		lr.Body().SetStr(strings.Repeat("x", 128))

		opts := testOpts()
		opts.PayloadOffloader = thresholdOffloader{}
		rows, rejects := LogRows(ld, opts)
		if len(rejects) != 0 || len(rows) != 1 {
			t.Fatalf("LogRows = (%d, %+v)", len(rows), rejects)
		}
		got := ResolveLogInsertIDs(ld, opts)
		want := extractLogRowInsertIDs(rows)
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveLogInsertIDs with offloader = %v, want %v", got, want)
		}
	})
}

func buildParityMetricsBatch() pmetric.Metrics {
	md := pmetric.NewMetrics()

	rm0 := md.ResourceMetrics().AppendEmpty()
	rm0.SetSchemaUrl("https://example.test/mres/\xff")
	rm0.Resource().Attributes().PutStr("service.name", "metrics-\xffsvc")
	rm0.Resource().SetDroppedAttributesCount(1)

	// Empty ScopeMetrics should not disturb indexing.
	rm0.ScopeMetrics().AppendEmpty()

	sm0 := rm0.ScopeMetrics().AppendEmpty()
	sm0.SetSchemaUrl("https://example.test/mscope/\xff")
	sm0.Scope().SetName("meter-\xffname")
	sm0.Scope().SetVersion("2.0")
	sm0.Scope().Attributes().PutStr("scope.tag", "s0")

	addExemplar := func(exs pmetric.ExemplarSlice, intVal int64, dblVal float64, useInt bool) {
		ex := exs.AppendEmpty()
		ex.SetTimestamp(pcommon.Timestamp(1_700_000_001_000_000_000))
		if useInt {
			ex.SetIntValue(intVal)
		} else {
			ex.SetDoubleValue(dblVal)
		}
		ex.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
		ex.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
		ex.FilteredAttributes().PutStr("region", "us-\xffcentral1")
	}

	// 1. Gauge: int, NaN double, NoRecordedValue, plus identical duplicate peers [P, P].
	mGauge := sm0.Metrics().AppendEmpty()
	mGauge.SetName("gauge.\xffname")
	mGauge.SetUnit("1\xff")
	mGauge.Metadata().PutInt("meta.k", 42)
	gDPs := mGauge.SetEmptyGauge().DataPoints()

	gdp0 := gDPs.AppendEmpty()
	gdp0.SetTimestamp(1_700_000_001_000_000_000)
	gdp0.SetIntValue(99)
	gdp0.Attributes().PutStr("host", "h1")
	addExemplar(gdp0.Exemplars(), 99, 0, true)

	gdp1 := gDPs.AppendEmpty()
	gdp1.SetTimestamp(1_700_000_001_000_000_000)
	gdp1.SetDoubleValue(math.NaN())
	addExemplar(gdp1.Exemplars(), 0, math.NaN(), false)

	gdp2 := gDPs.AppendEmpty()
	gdp2.SetTimestamp(1_700_000_001_000_000_000)
	gdp2.SetFlags(pmetric.DefaultDataPointFlags.WithNoRecordedValue(true))
	gdp2.SetDoubleValue(12.34)

	// Duplicate gauge points sharing exact payload -> distinct intra-batch ordinals.
	gdp3 := gDPs.AppendEmpty()
	gdp0.CopyTo(gdp3)

	// 2. Sum: monotonic cumulative & non-monotonic delta & unspecified.
	for _, tc := range []struct {
		name string
		temp pmetric.AggregationTemporality
		mono bool
	}{
		{"sum.cum.mono", pmetric.AggregationTemporalityCumulative, true},
		{"sum.delta.nonmono", pmetric.AggregationTemporalityDelta, false},
		{"sum.unspec", pmetric.AggregationTemporalityUnspecified, false},
	} {
		mSum := sm0.Metrics().AppendEmpty()
		mSum.SetName(tc.name)
		sum := mSum.SetEmptySum()
		sum.SetAggregationTemporality(tc.temp)
		sum.SetIsMonotonic(tc.mono)
		sdp := sum.DataPoints().AppendEmpty()
		sdp.SetStartTimestamp(1_700_000_000_000_000_000)
		sdp.SetTimestamp(1_700_000_002_000_000_000)
		sdp.SetDoubleValue(math.Inf(1))
	}

	// 3. Histogram: with sum/min/max and without sum/min/max + duplicate point.
	mHist := sm0.Metrics().AppendEmpty()
	mHist.SetName("hist.lat")
	mHist.SetUnit("ms")
	hist := mHist.SetEmptyHistogram()
	hist.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	hdp0 := hist.DataPoints().AppendEmpty()
	hdp0.SetStartTimestamp(1_700_000_000_000_000_000)
	hdp0.SetTimestamp(1_700_000_003_000_000_000)
	hdp0.SetCount(10)
	hdp0.SetSum(4.5)
	hdp0.SetMin(0.1)
	hdp0.SetMax(1.2)
	hdp0.ExplicitBounds().FromRaw([]float64{0.25, 0.5, 1.0})
	hdp0.BucketCounts().FromRaw([]uint64{3, 4, 2, 1})
	addExemplar(hdp0.Exemplars(), 0, 0.75, false)

	hdp1 := hist.DataPoints().AppendEmpty()
	hdp0.CopyTo(hdp1)

	hdp2 := hist.DataPoints().AppendEmpty()
	hdp2.SetTimestamp(1_700_000_003_500_000_000)
	hdp2.SetFlags(pmetric.DefaultDataPointFlags.WithNoRecordedValue(true))

	// 4. ExponentialHistogram.
	mExp := sm0.Metrics().AppendEmpty()
	mExp.SetName("exp.lat")
	exp := mExp.SetEmptyExponentialHistogram()
	exp.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	edp := exp.DataPoints().AppendEmpty()
	edp.SetTimestamp(1_700_000_004_000_000_000)
	edp.SetCount(5)
	edp.SetSum(1.8)
	edp.SetMin(0.1)
	edp.SetMax(0.9)
	edp.SetScale(3)
	edp.SetZeroCount(1)
	edp.SetZeroThreshold(0.001)
	edp.Positive().SetOffset(2)
	edp.Positive().BucketCounts().FromRaw([]uint64{2, 2})
	edp.Negative().SetOffset(-1)
	edp.Negative().BucketCounts().FromRaw([]uint64{1})

	// 5. Summary.
	mSumy := sm0.Metrics().AppendEmpty()
	mSumy.SetName("sumy.dur")
	qdp := mSumy.SetEmptySummary().DataPoints().AppendEmpty()
	qdp.SetTimestamp(1_700_000_005_000_000_000)
	qdp.SetCount(100)
	qdp.SetSum(55.0)
	qv := qdp.QuantileValues().AppendEmpty()
	qv.SetQuantile(0.95)
	qv.SetValue(1.1)

	// Second ResourceMetrics/ScopeMetrics.
	rm1 := md.ResourceMetrics().AppendEmpty()
	rm1.Resource().Attributes().PutStr("service.name", "metrics-svc-2")
	sm1 := rm1.ScopeMetrics().AppendEmpty()
	m2 := sm1.Metrics().AppendEmpty()
	m2.SetName("gauge.second")
	dp2 := m2.SetEmptyGauge().DataPoints().AppendEmpty()
	dp2.SetTimestamp(1_700_000_006_000_000_000)
	dp2.SetIntValue(1)

	return md
}

func TestResolveMetricPointFingerprintsParityWithMetricRows(t *testing.T) {
	t.Run("empty_metrics", func(t *testing.T) {
		got := ResolveMetricPointFingerprints(pmetric.NewMetrics(), Options{})
		if len(got) != 0 {
			t.Fatalf("ResolveMetricPointFingerprints(empty) = %v, want len 0", got)
		}
	})

	t.Run("all_five_types_and_duplicate_ordinals", func(t *testing.T) {
		md := buildParityMetricsBatch()
		opts := testOpts()
		opts.Contract = schema.ContractV1Candidate

		rows, rejects := MetricRows(md, opts)
		if len(rejects) != 0 || len(rows) != md.DataPointCount() {
			t.Fatalf("MetricRows = (%d rows, %+v rejects), want (%d, nil)", len(rows), rejects, md.DataPointCount())
		}
		want := extractMetricRowFingerprints(rows)

		got := ResolveMetricPointFingerprints(md, opts)
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveMetricPointFingerprints mismatch:\n got=%v\nwant=%v", got, want)
		}
		// Duplicate gauge points at 0 & 3 must have distinct fingerprints.
		if got[0] == got[3] {
			t.Errorf("duplicate gauge points shared fingerprint %q", got[0])
		}
		// Duplicate histogram points at 7 & 8 must have distinct fingerprints.
		if got[7] == got[8] {
			t.Errorf("duplicate histogram points shared fingerprint %q", got[7])
		}

		// Zero-valued Options{} without Limits/Now must match MetricRows.
		zeroOptsGot := ResolveMetricPointFingerprints(md, Options{})
		if !slices.Equal(zeroOptsGot, want) {
			t.Fatalf("ResolveMetricPointFingerprints(zero Limits) mismatch:\n got=%v\nwant=%v", zeroOptsGot, want)
		}
	})

	t.Run("redactor_parity_and_non_mutation", func(t *testing.T) {
		md := pmetric.NewMetrics()
		rm := md.ResourceMetrics().AppendEmpty()
		rm.Resource().Attributes().PutStr("service.name", "checkout")
		rm.Resource().Attributes().PutStr("api_key", "res-secret")
		sm := rm.ScopeMetrics().AppendEmpty()
		sm.Scope().Attributes().PutStr("scope.note", leakedSecret)
		m := sm.Metrics().AppendEmpty()
		m.SetName("gen_ai.client.token.usage")
		m.Metadata().PutStr("client_secret", "cs")
		dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetTimestamp(1_700_000_000_000_000_000)
		dp.SetIntValue(7)
		dp.Attributes().PutStr("access_token", "at")
		dp.Attributes().PutStr("note", leakedSecret)
		dp.Exemplars().AppendEmpty().FilteredAttributes().PutStr("password", "pw")

		before := marshalMetricsJSON(t, md)

		opts := testOpts()
		opts.Redactor = testRedactor(t, false)
		rows, rejects := MetricRows(md, opts)
		if len(rejects) != 0 || len(rows) != 1 {
			t.Fatalf("MetricRows = (%d, %+v)", len(rows), rejects)
		}
		want := extractMetricRowFingerprints(rows)

		got := ResolveMetricPointFingerprints(md, opts)
		if marshalMetricsJSON(t, md) != before {
			t.Fatal("ResolveMetricPointFingerprints mutated caller's pmetric.Metrics")
		}
		if !slices.Equal(got, want) {
			t.Fatalf("ResolveMetricPointFingerprints with Redactor = %v, want %v", got, want)
		}
	})
}
