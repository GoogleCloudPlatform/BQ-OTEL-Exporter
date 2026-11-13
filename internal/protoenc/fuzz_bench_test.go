// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package protoenc

import (
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

func buildDynamicDescriptor(t testing.TB, dp *descriptorpb.DescriptorProto) protoreflect.MessageDescriptor {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Syntax:      proto.String("proto2"),
		Name:        proto.String("fuzz_row.proto"),
		MessageType: []*descriptorpb.DescriptorProto{dp},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	return fd.Messages().Get(0)
}

func FuzzProtoEncRoundTrip(f *testing.F) {
	f.Add("0102030405060708090a0b0c0d0e0f10", "0102030405060708", "invoke_agent", int64(42000), int64(1700000000123456), `{"gen_ai.system":"gcp.vertex.agent"}`)
	f.Add("ffffffffffffffffffffffffffffffff", "0000000000000000", "", int64(0), int64(0), `{}`)
	f.Add("abcdef0123456789abcdef0123456789", "1234567890abcdef", "call_llm", int64(999999999), int64(1800000000000000), `{"k":"v","num":123}`)

	enc, err := New(schema.SpansTableSchema())
	if err != nil {
		f.Fatalf("New(SpansTableSchema): %v", err)
	}
	md := buildDynamicDescriptor(f, enc.Descriptor())

	f.Fuzz(func(t *testing.T, traceID, spanID, name string, durationNano, startMicros int64, attrsJSON string) {
		endMicros := startMicros + durationNano/1000
		startNano := startMicros * 1000
		endNano := startNano + durationNano

		row := transform.Row{
			"start_time":               startMicros,
			"start_time_unix_nano":     startNano,
			"end_time":                 endMicros,
			"end_time_unix_nano":       endNano,
			"receive_time":             startMicros,
			"receive_time_unix_nano":   startNano,
			"duration_nano":            durationNano,
			"trace_id":                 traceID,
			"span_id":                  spanID,
			"parent_span_id":           "",
			"trace_state":              "",
			"flags":                    int64(1),
			"name":                     name,
			"kind":                     int64(3),
			"kind_name":                "SPAN_KIND_CLIENT",
			"status":                   transform.Row{"code": int64(1), "code_name": "STATUS_CODE_OK", "message": ""},
			"attributes":               attrsJSON,
			"dropped_attributes_count": int64(0),
			"service_name":             "fuzz-agent",
			"resource":                 transform.Row{"attributes": `{}`, "dropped_attributes_count": int64(0)},
			"resource_schema_url":      "",
			"instrumentation_scope":    transform.Row{"name": "fuzz", "version": "1.0", "attributes": `{}`, "dropped_attributes_count": int64(0)},
			"scope_schema_url":         "",
			"events":                   []transform.Row{},
			"dropped_events_count":     int64(0),
			"links":                    []transform.Row{},
			"dropped_links_count":      int64(0),
			"object_refs":              []transform.Row{},
		}

		wire, err := enc.Encode(row)
		if err != nil {
			t.Fatalf("enc.Encode failed: %v", err)
		}

		msg := dynamicpb.NewMessage(md)
		if err := proto.Unmarshal(wire, msg); err != nil {
			t.Fatalf("dynamicpb Unmarshal failed: %v", err)
		}

		gotTraceID := msg.Get(md.Fields().ByName("trace_id")).String()
		if gotTraceID != traceID {
			t.Fatalf("round-trip trace_id mismatch: got %q, want %q", gotTraceID, traceID)
		}
		gotName := msg.Get(md.Fields().ByName("name")).String()
		if gotName != name {
			t.Fatalf("round-trip name mismatch: got %q, want %q", gotName, name)
		}
		gotDuration := msg.Get(md.Fields().ByName("duration_nano")).Int()
		if gotDuration != durationNano {
			t.Fatalf("round-trip duration_nano mismatch: got %d, want %d", gotDuration, durationNano)
		}
		gotStartMicros := msg.Get(md.Fields().ByName("start_time")).Int()
		if gotStartMicros != startMicros {
			t.Fatalf("round-trip start_time mismatch: got %d, want %d", gotStartMicros, startMicros)
		}
	})
}

func BenchmarkProtoEncEncode(b *testing.B) {
	enc, err := New(schema.SpansTableSchema())
	if err != nil {
		b.Fatalf("New(SpansTableSchema): %v", err)
	}
	now := time.Unix(1700000000, 0).UTC()
	nowMicros := now.UnixMicro()
	endMicros := now.Add(250 * time.Millisecond).UnixMicro()
	row := transform.Row{
		"start_time":               nowMicros,
		"start_time_unix_nano":     now.UnixNano(),
		"end_time":                 endMicros,
		"end_time_unix_nano":       now.Add(250 * time.Millisecond).UnixNano(),
		"receive_time":             nowMicros,
		"receive_time_unix_nano":   now.UnixNano(),
		"duration_nano":            int64(250_000_000),
		"trace_id":                 "0102030405060708090a0b0c0d0e0f10",
		"span_id":                  "0102030405060708",
		"parent_span_id":           "0000000000000001",
		"trace_state":              "",
		"flags":                    int64(1),
		"name":                     "invoke_agent",
		"kind":                     int64(3),
		"kind_name":                "SPAN_KIND_CLIENT",
		"status":                   transform.Row{"code": int64(1), "code_name": "STATUS_CODE_OK", "message": ""},
		"attributes":               `{"gen_ai.system":"gcp.vertex.agent","gen_ai.request.model":"gemini-2.5-pro"}`,
		"dropped_attributes_count": int64(0),
		"service_name":             "agent",
		"resource":                 transform.Row{"attributes": `{"service.name":"agent"}`, "dropped_attributes_count": int64(0)},
		"resource_schema_url":      "",
		"instrumentation_scope":    transform.Row{"name": "genai", "version": "0.1.0", "attributes": `{}`, "dropped_attributes_count": int64(0)},
		"scope_schema_url":         "",
		"events": []transform.Row{
			{
				"time":                     nowMicros,
				"time_unix_nano":           now.UnixNano(),
				"name":                     "gen_ai.content.prompt",
				"attributes":               `{"gen_ai.prompt":"hello"}`,
				"dropped_attributes_count": int64(0),
			},
		},
		"dropped_events_count": int64(0),
		"links":                []transform.Row{},
		"dropped_links_count":  int64(0),
		"object_refs": []transform.Row{
			{
				"uri":        "gs://bucket/obj",
				"version":    "1",
				"authorizer": "projects/p/locations/us/connections/c",
				"details":    `{}`,
			},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wire, err := enc.Encode(row)
		if err != nil || len(wire) == 0 {
			b.Fatalf("Encode failed: %v", err)
		}
	}
}

func BenchmarkDynamicPBvsWireEncoder(b *testing.B) {
	now := time.Unix(1700000000, 0).UTC()
	ts := pcommon.Timestamp(now.UnixNano())

	// Build a 100-record access-log batch sharing 1 ResourceLogs & 1 ScopeLogs.
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "edge-nginx")
	rl.Resource().Attributes().PutStr("k8s.cluster.name", "prod-us-central1")
	rl.Resource().Attributes().PutStr("k8s.namespace.name", "ingress")
	rl.Resource().Attributes().PutStr("k8s.pod.name", "edge-nginx-7c9f8b6d5-x2p9q")
	rl.Resource().Attributes().PutStr("host.name", "gke-prod-node-1234")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("access-log")
	sl.Scope().SetVersion("1.0.0")
	for i := range 100 {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(ts + pcommon.Timestamp(i*1000))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")
		lr.Body().SetStr("GET /api/v1/items/42 HTTP/1.1 200 1432")
		lr.Attributes().PutStr("http.request.method", "GET")
		lr.Attributes().PutStr("url.path", "/api/v1/items/42")
		lr.Attributes().PutInt("http.response.status_code", 200)
		lr.Attributes().PutStr("network.peer.address", "10.128.0.14")
		lr.Attributes().PutStr("logging.googleapis.com/insertId", "up-req-123456")
	}

	logEnc, err := New(schema.LogsTableSchema())
	if err != nil {
		b.Fatal(err)
	}
	opts := transform.Options{
		Limits:   transform.DefaultLimits(),
		Now:      func() time.Time { return now },
		Contract: schema.ContractV1Candidate,
	}
	rows, _ := transform.LogRows(ld, opts)
	sampleWire, _ := logEnc.encodeDynamicPB(rows[0])
	batchBytes := int64(len(sampleWire) * len(rows))

	b.Run("logs_100_rows/dynamicpb_encode_only", func(b *testing.B) {
		b.SetBytes(batchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := range rows {
				w, err := logEnc.encodeDynamicPB(rows[j])
				if err != nil || len(w) == 0 {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("logs_100_rows/protowire_plan_encode_only", func(b *testing.B) {
		b.SetBytes(batchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := range rows {
				w, err := logEnc.Encode(rows[j])
				if err != nil || len(w) == 0 {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("logs_100_rows/transform_plus_dynamicpb", func(b *testing.B) {
		b.SetBytes(batchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, _ := transform.LogRows(ld, opts)
			for j := range r {
				w, err := logEnc.encodeDynamicPB(r[j])
				if err != nil || len(w) == 0 {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("logs_100_rows/streaming_protowire_resource_reuse", func(b *testing.B) {
		b.SetBytes(batchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc, _, _, _ := transform.StreamLogRows(ld, opts, 0, logEnc)
			if len(enc) != 100 {
				b.Fatalf("got %d rows, want 100", len(enc))
			}
		}
	})

	// Build a 100-span batch sharing 1 ResourceSpans & 1 ScopeSpans.
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "checkout-api")
	rs.Resource().Attributes().PutStr("k8s.cluster.name", "prod-us-central1")
	rs.Resource().Attributes().PutStr("k8s.pod.name", "checkout-api-5d6f")
	ss := rs.ScopeSpans().AppendEmpty()
	ss.Scope().SetName("checkout-tracer")
	ss.Scope().SetVersion("1.2.0")
	for i := range 100 {
		sp := ss.Spans().AppendEmpty()
		sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, byte(i + 1)})
		sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, byte(i + 1)})
		sp.SetName("POST /v1/checkout")
		sp.SetKind(ptrace.SpanKindServer)
		sp.SetStartTimestamp(ts + pcommon.Timestamp(i*1000))
		sp.SetEndTimestamp(ts + pcommon.Timestamp(i*1000+500_000))
		sp.Attributes().PutStr("http.request.method", "POST")
		sp.Attributes().PutInt("http.response.status_code", 200)
	}
	spanEnc, err := New(schema.SpansTableSchema())
	if err != nil {
		b.Fatal(err)
	}
	spanRows, _ := transform.SpanRows(td, opts)
	sampleSpanWire, _ := spanEnc.encodeDynamicPB(spanRows[0])
	spanBatchBytes := int64(len(sampleSpanWire) * len(spanRows))

	b.Run("spans_100_rows/transform_plus_dynamicpb", func(b *testing.B) {
		b.SetBytes(spanBatchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, _ := transform.SpanRows(td, opts)
			for j := range r {
				w, err := spanEnc.encodeDynamicPB(r[j])
				if err != nil || len(w) == 0 {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("spans_100_rows/streaming_protowire_resource_reuse", func(b *testing.B) {
		b.SetBytes(spanBatchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc, _, _, _ := transform.StreamSpanRows(td, opts, 0, spanEnc)
			if len(enc) != 100 {
				b.Fatalf("got %d rows, want 100", len(enc))
			}
		}
	})

	// Build a 100-datapoint metric batch sharing 1 ResourceMetrics & 1 ScopeMetrics.
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "checkout-api")
	rm.Resource().Attributes().PutStr("k8s.cluster.name", "prod-us-central1")
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName("checkout-meter")
	m := sm.Metrics().AppendEmpty()
	m.SetName("http.server.request.count")
	m.SetUnit("{request}")
	sum := m.SetEmptySum()
	sum.SetIsMonotonic(true)
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
	for i := range 100 {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetStartTimestamp(ts)
		dp.SetTimestamp(ts + pcommon.Timestamp(i*1000))
		dp.SetIntValue(int64(100 + i))
		dp.Attributes().PutStr("http.route", "/v1/checkout")
		dp.Attributes().PutInt("http.response.status_code", int64(200+i%5))
	}
	metricEnc, err := New(schema.MetricsTableSchema())
	if err != nil {
		b.Fatal(err)
	}
	metricRows, _ := transform.MetricRows(md, opts)
	sampleMetricWire, _ := metricEnc.encodeDynamicPB(metricRows[0])
	metricBatchBytes := int64(len(sampleMetricWire) * len(metricRows))

	b.Run("metrics_100_rows/transform_plus_dynamicpb", func(b *testing.B) {
		b.SetBytes(metricBatchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			r, _ := transform.MetricRows(md, opts)
			for j := range r {
				w, err := metricEnc.encodeDynamicPB(r[j])
				if err != nil || len(w) == 0 {
					b.Fatal(err)
				}
			}
		}
	})

	b.Run("metrics_100_rows/streaming_protowire_resource_reuse", func(b *testing.B) {
		b.SetBytes(metricBatchBytes)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			enc, _, _, _ := transform.StreamMetricRows(md, opts, 0, metricEnc)
			if len(enc) != 100 {
				b.Fatalf("got %d rows, want 100", len(enc))
			}
		}
	})
}
