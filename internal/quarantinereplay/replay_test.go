// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package quarantinereplay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
)

func sampleSpanJSON(t *testing.T, name string) string {
	t.Helper()
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "checkout")
	sp := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	sp.SetName(name)
	sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func sampleLogJSON(t *testing.T, body string) string {
	t.Helper()
	ld := plog.NewLogs()
	lr := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.Body().SetStr(body)
	raw, err := (&plog.JSONMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestReplayJSONLAndFilters(t *testing.T) {
	spanPayload := sampleSpanJSON(t, "GET /orders")
	logPayload := sampleLogJSON(t, "replayed log body")
	offloadedSpanPayload := sampleSpanJSON(t, "offloaded-span")

	records := []Record{
		{
			IngestTime: "2026-10-11T10:00:00Z",
			Signal:     "spans",
			ErrorCode:  "OVERSIZE_ROW",
			RawPayload: spanPayload,
		},
		{
			IngestTime: "2026-10-11T11:00:00Z",
			Signal:     "logs",
			ErrorCode:  "ROW_ERROR",
			RawPayload: logPayload,
		},
		{
			IngestTime: "2026-10-11T12:00:00Z",
			Signal:     "spans",
			ErrorCode:  "OVERSIZE_ROW",
			PayloadRef: &ObjectRef{URI: "gs://q-bucket/quarantine/spans/obj1.json"},
		},
		{
			// metadata_only row: neither raw_payload nor payload_ref
			IngestTime: "2026-10-11T12:30:00Z",
			Signal:     "spans",
			ErrorCode:  "OVERSIZE_ROW",
		},
	}

	var buf bytes.Buffer
	for _, r := range records {
		line, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}

	sink := NewMemorySink()
	fetcher := func(_ context.Context, uri string) ([]byte, error) {
		if uri == "gs://q-bucket/quarantine/spans/obj1.json" {
			return []byte(offloadedSpanPayload), nil
		}
		t.Fatalf("unexpected URI %q", uri)
		return nil, nil
	}

	sum, err := Replay(context.Background(), bytes.NewReader(buf.Bytes()), sink, Options{
		Filter: Filter{
			Signal:     "spans",
			ErrorCodes: []string{"OVERSIZE_ROW"},
			Since:      time.Date(2026, 10, 11, 9, 0, 0, 0, time.UTC),
			Until:      time.Date(2026, 10, 11, 13, 0, 0, 0, time.UTC),
		},
		ObjectFetcher: fetcher,
	})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if sum.TotalRead != 4 || sum.Matched != 3 || sum.SkippedFiltered != 1 || sum.SkippedNoPayload != 1 || sum.ReplayedSpans != 2 {
		t.Fatalf("Summary = %+v, want TotalRead=4 Matched=3 SkippedFiltered=1 SkippedNoPayload=1 ReplayedSpans=2", sum)
	}
	if len(sink.Traces) != 2 || len(sink.Logs) != 0 {
		t.Fatalf("sink Traces=%d Logs=%d, want 2 and 0", len(sink.Traces), len(sink.Logs))
	}
}

func TestReplayJSONArrayAndJSONWriterSink(t *testing.T) {
	records := []Record{
		{
			IngestTime: int64(1_760_000_000_000_000),
			Signal:     "logs",
			ErrorCode:  "ROW_ERROR",
			RawPayload: sampleLogJSON(t, "array-log"),
		},
	}
	arrBytes, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	sink := NewJSONWriterSink(&out)
	sum, err := Replay(context.Background(), bytes.NewReader(arrBytes), sink, Options{})
	if err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	if sum.ReplayedLogs != 1 {
		t.Fatalf("ReplayedLogs = %d, want 1", sum.ReplayedLogs)
	}
	if !strings.Contains(out.String(), `"signal":"logs"`) || !strings.Contains(out.String(), "array-log") {
		t.Errorf("JSONWriterSink output = %q", out.String())
	}
}

func TestGCSObjectFetcher(t *testing.T) {
	livePayload := sampleSpanJSON(t, "gcs-live-span")
	genPayload := sampleSpanJSON(t, "gcs-gen-42-span")
	var lastQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastQuery = r.URL.RawQuery
		if r.URL.Path != "/storage/v1/b/my-q-bucket/o/path/to/span.json" {
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Query().Get("generation") {
		case "":
			_, _ = w.Write([]byte(livePayload))
		case "42":
			_, _ = w.Write([]byte(genPayload))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	fetcher, cleanup, err := NewGCSObjectFetcher(
		context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("NewGCSObjectFetcher() error = %v", err)
	}
	defer cleanup()

	got, err := fetcher(context.Background(), "gs://my-q-bucket/path/to/span.json")
	if err != nil {
		t.Fatalf("fetcher() error = %v", err)
	}
	if string(got) != livePayload {
		t.Errorf("fetched payload = %q, want %q", string(got), livePayload)
	}

	gotGen, err := fetcher(context.Background(), "gs://my-q-bucket/path/to/span.json?generation=42")
	if err != nil {
		t.Fatalf("fetcher(generation=42) error = %v", err)
	}
	if string(gotGen) != genPayload || !strings.Contains(lastQuery, "generation=42") {
		t.Errorf("fetched generation payload = %q (query=%q), want %q with generation=42", string(gotGen), lastQuery, genPayload)
	}

	// Missing generation must fail rather than reading the live object.
	if _, err := fetcher(context.Background(), "gs://my-q-bucket/path/to/span.json?generation=999"); err == nil {
		t.Error("expected error when requested generation returns HTTP 404")
	}

	if _, err := fetcher(context.Background(), "https://not-gs/bucket/obj"); err == nil {
		t.Error("expected error for non-gs:// URI")
	}
	if _, err := fetcher(context.Background(), "gs://bucket-only/"); err == nil {
		t.Error("expected error for gs:// URI without object key")
	}
}

func TestReplayForwardsPayloadRefGeneration(t *testing.T) {
	genPayload := sampleSpanJSON(t, "pinned-generation-span")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/storage/v1/b/q-bucket/o/quarantine/spans/item.json" && r.URL.Query().Get("generation") == "777" {
			_, _ = w.Write([]byte(genPayload))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	fetcher, cleanup, err := NewGCSObjectFetcher(
		context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	records := []Record{
		{
			IngestTime: "2026-10-11T12:00:00Z",
			Signal:     "spans",
			ErrorCode:  "OVERSIZE_ROW",
			PayloadRef: &ObjectRef{
				URI:     "gs://q-bucket/quarantine/spans/item.json",
				Version: "777",
			},
		},
		{
			IngestTime: "2026-10-11T12:01:00Z",
			Signal:     "spans",
			ErrorCode:  "OVERSIZE_ROW",
			PayloadRef: &ObjectRef{
				URI:     "gs://q-bucket/quarantine/spans/item.json",
				Version: "888-deleted",
			},
		},
	}
	rawInput, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}

	sink := NewMemorySink()
	sum, err := Replay(context.Background(), bytes.NewReader(rawInput), sink, Options{
		ObjectFetcher: fetcher,
	})
	if err == nil {
		t.Fatal("expected error for unavailable generation 888-deleted")
	}
	if sum.ReplayedSpans != 1 || sum.FailedUnmarshal != 1 || len(sink.Traces) != 1 {
		t.Fatalf("Summary = %+v, sink.Traces = %d, want ReplayedSpans=1 FailedUnmarshal=1", sum, len(sink.Traces))
	}
	gotName := sink.Traces[0].ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Name()
	if gotName != "pinned-generation-span" {
		t.Errorf("replayed span name = %q, want pinned-generation-span", gotName)
	}
}

func TestParsedIngestTimeAndEdgeCases(t *testing.T) {
	cases := []any{
		"2026-10-11 12:00:00.123456 UTC",
		"1760184000123456",
		"1760184000.5",
		json.Number("1760184000123456"),
		json.Number("1760184000.5"),
		float64(1760184000123456),
		float64(1760184000.5),
		int64(1760184000),
	}
	for _, in := range cases {
		rec := Record{IngestTime: in}
		if ts, ok := rec.ParsedIngestTime(); !ok || ts.IsZero() {
			t.Errorf("ParsedIngestTime(%#v) = (%v, %v), want valid time", in, ts, ok)
		}
	}
	for _, invalid := range []any{nil, "", "not-a-timestamp", struct{}{}} {
		rec := Record{IngestTime: invalid}
		if _, ok := rec.ParsedIngestTime(); ok {
			t.Errorf("ParsedIngestTime(%#v) succeeded unexpectedly", invalid)
		}
	}

	// Empty input returns empty summary without error.
	if sum, err := Replay(context.Background(), strings.NewReader("   \n"), NewNopSink(), Options{}); err != nil || sum.TotalRead != 0 {
		t.Errorf("empty Replay() = (%+v, %v), want (0, nil)", sum, err)
	}

	// Nil sink returns error.
	if _, err := Replay(context.Background(), strings.NewReader(""), nil, Options{}); err == nil {
		t.Error("expected error when sink is nil")
	}

	// Malformed JSONL, missing ObjectFetcher, bad OTLP JSON, and unsupported signal.
	badRecords := strings.Join([]string{
		`{"signal":"spans","error_code":"ROW_ERROR","raw_payload":"{not-valid-otlp"}`,
		`{"signal":"logs","error_code":"ROW_ERROR","raw_payload":"{not-valid-otlp"}`,
		`{"signal":"metrics","error_code":"ROW_ERROR","raw_payload":"{not-valid-otlp"}`,
		`{"signal":"unknown","error_code":"ROW_ERROR","raw_payload":"{}"}`,
		`{"signal":"spans","error_code":"ROW_ERROR","payload_ref":{"uri":"gs://b/k"}}`,
	}, "\n")
	sum, err := Replay(context.Background(), strings.NewReader(badRecords), NewNopSink(), Options{})
	if err == nil || sum.FailedUnmarshal != 5 {
		t.Errorf("Replay(badRecords) = (%+v, %v), want FailedUnmarshal=5 and joined error", sum, err)
	}
}

func sampleMetricJSON(t *testing.T, name string) string {
	t.Helper()
	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", "billing")
	m := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName(name)
	dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
	dp.SetTimestamp(pcommon.Timestamp(1760184000000000000))
	dp.SetDoubleValue(42.5)
	raw, err := (&pmetric.JSONMarshaler{}).MarshalMetrics(md)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestReplayMetricsAndSignalFilterAndBadTimestamp(t *testing.T) {
	inlineMetric := sampleMetricJSON(t, "inline.gauge")
	offloadedMetric := sampleMetricJSON(t, "offloaded.gauge")
	inlineSpan := sampleSpanJSON(t, "trace-span")
	inlineLog := sampleLogJSON(t, "skip-log")

	records := []Record{
		{
			IngestTime: "2026-10-11T10:00:00Z",
			Signal:     "metrics",
			ErrorCode:  "ROW_ERROR",
			RawPayload: inlineMetric,
		},
		{
			IngestTime: "2026-10-11T10:01:00Z",
			Signal:     "otel_metrics",
			ErrorCode:  "OVERSIZE_ROW",
			PayloadRef: &ObjectRef{URI: "gs://q-bucket/metrics/m1.json", Version: "101"},
		},
		{
			IngestTime: "2026-10-11T10:02:00Z",
			Signal:     "spans",
			ErrorCode:  "ROW_ERROR",
			RawPayload: inlineSpan,
		},
		{
			IngestTime: "2026-10-11T10:03:00Z",
			Signal:     "logs",
			ErrorCode:  "ROW_ERROR",
			RawPayload: inlineLog,
		},
		{
			IngestTime: "corrupt-timestamp",
			Signal:     "metrics",
			ErrorCode:  "ROW_ERROR",
			RawPayload: inlineMetric,
		},
	}

	var jsonl bytes.Buffer
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		jsonl.Write(b)
		jsonl.WriteByte('\n')
	}

	sink := NewMemorySink()
	since, _ := time.Parse(time.RFC3339, "2026-10-11T09:00:00Z")
	sum, err := Replay(context.Background(), &jsonl, sink, Options{
		Filter: Filter{
			Signal: "traces,metrics",
			Since:  since,
		},
		ObjectFetcher: func(_ context.Context, uri string) ([]byte, error) {
			if strings.Contains(uri, "metrics/m1.json") {
				return []byte(offloadedMetric), nil
			}
			return nil, context.DeadlineExceeded
		},
	})
	if err == nil {
		t.Fatal("expected error for corrupt ingest_time when Since is set")
	}
	if sum.TotalRead != 5 || sum.ReplayedMetrics != 2 || sum.ReplayedSpans != 1 || sum.SkippedFiltered != 1 || sum.FailedUnmarshal != 1 {
		t.Fatalf("Summary = %+v, want TotalRead=5 ReplayedMetrics=2 ReplayedSpans=1 SkippedFiltered=1 FailedUnmarshal=1", sum)
	}
	if len(sink.Metrics) != 2 {
		t.Fatalf("len(sink.Metrics) = %d, want 2", len(sink.Metrics))
	}

	var outBuf bytes.Buffer
	jw := NewJSONWriterSink(&outBuf)
	if err := jw.ExportMetrics(context.Background(), sink.Metrics[0]); err != nil {
		t.Fatalf("JSONWriterSink.ExportMetrics() error = %v", err)
	}
	if !strings.Contains(outBuf.String(), `"signal":"metrics"`) || !strings.Contains(outBuf.String(), "inline.gauge") {
		t.Errorf("JSONWriterSink output = %s", outBuf.String())
	}
}

// spanNames lists the names of the spans in td.
func spanNames(td ptrace.Traces) []string {
	var names []string
	rss := td.ResourceSpans()
	for i := range rss.Len() {
		sss := rss.At(i).ScopeSpans()
		for j := range sss.Len() {
			spans := sss.At(j).Spans()
			for k := range spans.Len() {
				names = append(names, spans.At(k).Name())
			}
		}
	}
	return names
}

// recordingSink records the names of the spans it takes. fail, when set,
// is asked first, with the 1-based number of the export call, whether the
// call fails.
type recordingSink struct {
	calls int
	names []string
	fail  func(call int) error
}

func (s *recordingSink) take(names ...string) error {
	s.calls++
	if s.fail != nil {
		if err := s.fail(s.calls); err != nil {
			return err
		}
	}
	s.names = append(s.names, names...)
	return nil
}

func (s *recordingSink) ExportTraces(_ context.Context, td ptrace.Traces) error {
	return s.take(spanNames(td)...)
}

func (s *recordingSink) ExportLogs(context.Context, plog.Logs) error { return s.take("log") }

func (s *recordingSink) ExportMetrics(context.Context, pmetric.Metrics) error {
	return s.take("metric")
}

// spanRecordsJSONL returns JSONL quarantine records, one per error code,
// whose spans are named span-0, span-1, and so on.
func spanRecordsJSONL(t *testing.T, codes ...string) string {
	t.Helper()
	var b strings.Builder
	for i, code := range codes {
		line, err := json.Marshal(Record{
			IngestTime: "2026-10-11T10:00:00Z",
			Signal:     "spans",
			ErrorCode:  code,
			RawPayload: sampleSpanJSON(t, fmt.Sprintf("span-%d", i)),
		})
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func oversizeCodes(n int) []string {
	return slices.Repeat([]string{"OVERSIZE_ROW"}, n)
}

func readCheckpointFile(t *testing.T, path string) checkpointState {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st checkpointState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("checkpoint %s: %v", data, err)
	}
	return st
}

// assertDirHolds fails unless dir holds exactly the named files, so that no
// temporary checkpoint file was left behind.
func assertDirHolds(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s holds %v, want %v", dir, got, want)
	}
}

// assertCursor checks that the checkpoint's BigQuery cursor matches the
// expected (ingest_time, row_fp, row_ord, canonical_row_key) and that it was
// written with the canonical row-ordering version.
func assertCursor(t *testing.T, st checkpointState, wantIngestMicros, wantFP, wantOrd int64, wantKey string, wantHandled int64) {
	t.Helper()
	if st.Cursor == nil {
		t.Fatalf("cursor is nil, want ingest=%d fp=%d ord=%d", wantIngestMicros, wantFP, wantOrd)
	}
	if st.Cursor.IngestTimeMicros != wantIngestMicros || st.Cursor.RowFingerprint != wantFP || st.Cursor.DuplicateOrdinal != wantOrd {
		t.Errorf("cursor = {ingest=%d fp=%d ord=%d}, want {ingest=%d fp=%d ord=%d}",
			st.Cursor.IngestTimeMicros, st.Cursor.RowFingerprint, st.Cursor.DuplicateOrdinal,
			wantIngestMicros, wantFP, wantOrd)
	}
	if st.Cursor.CursorOrderVersion != cursorOrderVersionCanonical {
		t.Errorf("cursor order version = %d, want %d", st.Cursor.CursorOrderVersion, cursorOrderVersionCanonical)
	}
	if st.Cursor.CanonicalRowKey != wantKey {
		t.Errorf("cursor canonical_row_key = %q, want %q", st.Cursor.CanonicalRowKey, wantKey)
	}
	if wantKey != "" {
		if int64(st.Cursor.GroupCount) <= wantOrd {
			t.Errorf("cursor group_count = %d, want > %d", st.Cursor.GroupCount, wantOrd)
		}
		if err := validateHexSHA256(st.Cursor.PrefixSHA256); err != nil {
			t.Errorf("cursor prefix_sha256 = %q: %v", st.Cursor.PrefixSHA256, err)
		}
		if err := validateHexSHA256(st.Cursor.GroupSHA256); err != nil {
			t.Errorf("cursor group_sha256 = %q: %v", st.Cursor.GroupSHA256, err)
		}
		if wantOrd == 0 && st.Cursor.GroupCount == 1 {
			wantSHA := evalSQLWindowDigest([]string{wantKey}, "BYTE_LENGTH", ":")
			if st.Cursor.PrefixSHA256 != wantSHA {
				t.Errorf("cursor prefix_sha256 = %q, want %q", st.Cursor.PrefixSHA256, wantSHA)
			}
			if st.Cursor.GroupSHA256 != wantSHA {
				t.Errorf("cursor group_sha256 = %q, want %q", st.Cursor.GroupSHA256, wantSHA)
			}
		}
	}
	if st.Handled != wantHandled {
		t.Errorf("handled = %d, want %d", st.Handled, wantHandled)
	}
}

func TestReplayCheckpointResumesAfterCrash(t *testing.T) {
	dir := t.TempDir()
	cfg := &CheckpointConfig{Path: filepath.Join(dir, "replay.ckpt"), Source: "file:/data/quarantine.jsonl"}
	input := spanRecordsJSONL(t, oversizeCodes(5)...)

	// The first run dies while the third record is being exported.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	crashing := &recordingSink{fail: func(call int) error {
		if call == 3 {
			cancel()
			return ctx.Err()
		}
		return nil
	}}
	if _, err := Replay(ctx, strings.NewReader(input), crashing, Options{Checkpoint: cfg}); !errors.Is(err, context.Canceled) {
		t.Fatalf("crashed run returned %v, want context.Canceled", err)
	}
	st := readCheckpointFile(t, cfg.Path)
	if st.Version != checkpointVersion || st.Kind != checkpointKindFile || st.Source != cfg.Source || st.Next != 2 || st.Handled != 2 {
		t.Fatalf("checkpoint after the crash = %+v, want next=2 handled=2", st)
	}
	assertDirHolds(t, dir, "replay.ckpt")

	// The rerun replays the remaining records exactly once.
	resumed := &recordingSink{}
	sum, err := Replay(context.Background(), strings.NewReader(input), resumed, Options{Checkpoint: cfg})
	if err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3, SkippedCheckpointed: 2}); sum != want {
		t.Errorf("resumed summary = %+v, want %+v", sum, want)
	}
	if want := []string{"span-2", "span-3", "span-4"}; !slices.Equal(resumed.names, want) {
		t.Errorf("resumed run replayed %v, want %v", resumed.names, want)
	}
	if st := readCheckpointFile(t, cfg.Path); st.Next != 5 || st.Handled != 5 {
		t.Errorf("final checkpoint = %+v, want next=5 handled=5", st)
	}

	// A finished checkpoint leaves nothing to replay.
	again := &recordingSink{}
	sum, err = Replay(context.Background(), strings.NewReader(input), again, Options{Checkpoint: cfg})
	if err != nil || sum != (Summary{SkippedCheckpointed: 5}) || again.calls != 0 {
		t.Errorf("third run = %+v, %v, %d exports; want every record skipped", sum, err, again.calls)
	}
	assertDirHolds(t, dir, "replay.ckpt")
}

func TestReplayCheckpointPermanentAndTransientFailures(t *testing.T) {
	dir := t.TempDir()
	input := spanRecordsJSONL(t, oversizeCodes(3)...)

	// A permanent failure counts the record as handled, and the run goes on.
	permanentCfg := &CheckpointConfig{Path: filepath.Join(dir, "permanent.ckpt"), Source: "stdin"}
	rejecting := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return &PermanentError{Err: errors.New("receiver rejected the batch")}
		}
		return nil
	}}
	sum, err := Replay(context.Background(), strings.NewReader(input), rejecting, Options{Checkpoint: permanentCfg})
	if err == nil || !strings.Contains(err.Error(), "receiver rejected the batch") {
		t.Errorf("run with a permanent failure returned %v, want the failure reported", err)
	}
	if sum.ReplayedSpans != 2 || sum.FailedExport != 1 {
		t.Errorf("summary = %+v, want 2 replayed and 1 failed export", sum)
	}
	if st := readCheckpointFile(t, permanentCfg.Path); st.Next != 3 || st.Handled != 3 {
		t.Errorf("checkpoint = %+v, want every record handled", st)
	}

	// A transient failure stops the run at the record, which the next run
	// retries.
	transientCfg := &CheckpointConfig{Path: filepath.Join(dir, "transient.ckpt"), Source: "stdin"}
	flaky := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return errors.New("connection reset by peer")
		}
		return nil
	}}
	sum, err = Replay(context.Background(), strings.NewReader(input), flaky, Options{Checkpoint: transientCfg})
	if err == nil || !strings.Contains(err.Error(), "connection reset by peer") || !strings.Contains(err.Error(), "rerun with checkpoint") {
		t.Errorf("run with a transient failure returned %v, want a stop at the record", err)
	}
	if sum.ReplayedSpans != 1 || sum.FailedExport != 1 || flaky.calls != 2 {
		t.Errorf("summary = %+v after %d exports, want a stop at the second record", sum, flaky.calls)
	}
	if st := readCheckpointFile(t, transientCfg.Path); st.Next != 1 || st.Handled != 1 {
		t.Errorf("checkpoint = %+v, want next=1", st)
	}
	retried := &recordingSink{}
	sum, err = Replay(context.Background(), strings.NewReader(input), retried, Options{Checkpoint: transientCfg})
	if err != nil || sum.ReplayedSpans != 2 || sum.SkippedCheckpointed != 1 {
		t.Errorf("retry run = %+v, %v; want 2 replayed and 1 skipped", sum, err)
	}
	if want := []string{"span-1", "span-2"}; !slices.Equal(retried.names, want) {
		t.Errorf("retry run replayed %v, want %v", retried.names, want)
	}
	assertDirHolds(t, dir, "permanent.ckpt", "transient.ckpt")
}

func TestReplayCheckpointRefusesMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.ckpt")
	input := spanRecordsJSONL(t, oversizeCodes(2)...)
	cfg := &CheckpointConfig{Path: path, Source: "file:/data/a.jsonl"}
	ctx := context.Background()
	if _, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{Filter: Filter{Signal: "traces,logs"}, Checkpoint: cfg}); err != nil {
		t.Fatal(err)
	}
	// An equivalent spelling of the filter shares the checkpoint.
	sum, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{Filter: Filter{Signal: "logs, spans"}, Checkpoint: cfg})
	if err != nil || sum.SkippedCheckpointed != 2 {
		t.Errorf("equivalent filter = %+v, %v; want both records skipped", sum, err)
	}
	for name, opts := range map[string]Options{
		"other filter": {Filter: Filter{Signal: "logs"}, Checkpoint: cfg},
		"other window": {Filter: Filter{Signal: "spans,logs", Since: time.Unix(1, 0)}, Checkpoint: cfg},
		"other source": {Filter: Filter{Signal: "spans,logs"}, Checkpoint: &CheckpointConfig{Path: path, Source: "file:/data/b.jsonl"}},
	} {
		if _, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), opts); err == nil || !strings.Contains(err.Error(), "was written for") {
			t.Errorf("%s: Replay returned %v, want the checkpoint refused", name, err)
		}
	}
	validBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Trailing whitespace after the single JSON object is accepted.
	if err := os.WriteFile(path, append(slices.Clone(validBytes), []byte(" \t\r\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if sum, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{Filter: Filter{Signal: "spans,logs"}, Checkpoint: cfg}); err != nil || sum.SkippedCheckpointed != 2 {
		t.Errorf("trailing whitespace checkpoint: Replay returned (%+v, %v), want both records skipped", sum, err)
	}
	// Trailing second JSON object or trailing HTML after the first JSON object is rejected before any export.
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{name: "trailing JSON object", suffix: "{}"},
		{name: "trailing HTML", suffix: "<html><body>error</body></html>"},
	} {
		if err := os.WriteFile(path, append(slices.Clone(validBytes), []byte(tc.suffix)...), 0o600); err != nil {
			t.Fatal(err)
		}
		sink := &recordingSink{}
		if _, err := Replay(ctx, strings.NewReader(input), sink, Options{Filter: Filter{Signal: "spans,logs"}, Checkpoint: cfg}); err == nil || !strings.Contains(err.Error(), "unexpected trailing data after JSON object") {
			t.Errorf("%s: Replay returned %v, want unexpected trailing data error", tc.name, err)
		}
		if len(sink.names) != 0 {
			t.Errorf("%s: Replay exported %v before rejecting checkpoint", tc.name, sink.names)
		}
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{Checkpoint: cfg}); err == nil || !strings.Contains(err.Error(), "parsing checkpoint") {
		t.Errorf("corrupt checkpoint: Replay returned %v, want a parse error", err)
	}
	if _, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{Checkpoint: &CheckpointConfig{Path: " "}}); err == nil {
		t.Error("a blank checkpoint path was accepted")
	}
}

func TestJSONWriterSinkSync(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "out.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	sink := NewJSONWriterSink(f)
	if err := sink.ExportTraces(context.Background(), ptrace.NewTraces()); err != nil {
		t.Fatal(err)
	}
	if err := sink.Sync(); err != nil {
		t.Errorf("syncing a file: %v", err)
	}
	if err := NewJSONWriterSink(&bytes.Buffer{}).Sync(); err != nil {
		t.Errorf("syncing a buffer: %v", err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if err := NewJSONWriterSink(w).Sync(); err != nil {
		t.Errorf("syncing a pipe, which cannot be synced at all: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := sink.Sync(); err == nil {
		t.Error("syncing a closed file succeeded")
	}

	// On Darwin/BSD, calling Sync on a pipe returns syscall.EBADF rather than
	// syscall.EINVAL. JSONWriterSink checks Stat().Mode().IsRegular() first so
	// pipes and character devices never reach Sync().
	pipeWriter := &fakeModeWriter{mode: fs.ModeNamedPipe, syncErr: syscall.EBADF}
	if err := NewJSONWriterSink(pipeWriter).Sync(); err != nil || pipeWriter.synced {
		t.Errorf("syncing a named pipe writer = %v (synced=%v), want nil without calling Sync", err, pipeWriter.synced)
	}
	closedWriter := &fakeModeWriter{statErr: fs.ErrClosed, syncErr: nil}
	if err := NewJSONWriterSink(closedWriter).Sync(); !errors.Is(err, fs.ErrClosed) {
		t.Errorf("syncing a writer whose Stat fails = %v, want fs.ErrClosed", err)
	}
}

type fakeModeWriter struct {
	bytes.Buffer
	mode    fs.FileMode
	statErr error
	syncErr error
	synced  bool
}

type fakeFileInfo struct {
	fs.FileInfo
	mode fs.FileMode
}

func (fi fakeFileInfo) Mode() fs.FileMode { return fi.mode }

func (w *fakeModeWriter) Stat() (fs.FileInfo, error) {
	if w.statErr != nil {
		return nil, w.statErr
	}
	return fakeFileInfo{mode: w.mode}, nil
}

func (w *fakeModeWriter) Sync() error {
	w.synced = true
	return w.syncErr
}

type hookedTempFile struct {
	checkpointTempFile
	record   func(op string)
	writeErr error
	syncErr  error
	closeErr error
}

func (f *hookedTempFile) Write(p []byte) (int, error) {
	if f.record != nil {
		f.record("tmp.Write")
	}
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.checkpointTempFile.Write(p)
}

func (f *hookedTempFile) Sync() error {
	if f.record != nil {
		f.record("tmp.Sync")
	}
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.checkpointTempFile.Sync()
}

func (f *hookedTempFile) Close() error {
	if f.record != nil {
		f.record("tmp.Close")
	}
	cerr := f.checkpointTempFile.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return cerr
}

type recordingSyncSink struct {
	recordingSink
	onSync func() error
}

func (s *recordingSyncSink) Sync() error {
	if s.onSync != nil {
		return s.onSync()
	}
	return nil
}

func TestCheckpointDurabilityAndAtomicity(t *testing.T) {
	prevHooks := checkpointHooks
	t.Cleanup(func() { checkpointHooks = prevHooks })

	dir := t.TempDir()
	ckptPath := filepath.Join(dir, "durable.ckpt")
	opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath, Source: "file:quarantine.jsonl"}}
	input := spanRecordsJSONL(t, "OVERSIZE_ROW", "OVERSIZE_ROW")

	var ops []string
	var preRenameDiskNext int64 = -1
	checkpointHooks = checkpointFS{
		createTemp: func(d, pattern string) (checkpointTempFile, error) {
			ops = append(ops, "createTemp")
			tf, err := defaultCheckpointFS.createTemp(d, pattern)
			if err != nil {
				return nil, err
			}
			return &hookedTempFile{
				checkpointTempFile: tf,
				record:             func(op string) { ops = append(ops, op) },
			}, nil
		},
		rename: func(oldpath, newpath string) error {
			ops = append(ops, "rename")
			// Before rename replaces newpath, newpath on disk must still hold the
			// previous record's checkpoint (or not exist on the very first save),
			// proving save() never overwrites newpath in place.
			if raw, err := os.ReadFile(newpath); err == nil {
				var st checkpointState
				if jerr := json.Unmarshal(raw, &st); jerr != nil {
					t.Errorf("checkpoint on disk before rename is corrupt: %v", jerr)
				}
				preRenameDiskNext = st.Next
			}
			return defaultCheckpointFS.rename(oldpath, newpath)
		},
		remove: func(name string) error {
			ops = append(ops, "remove")
			return defaultCheckpointFS.remove(name)
		},
		syncDir: func(d string) error {
			ops = append(ops, "syncDir")
			return defaultCheckpointFS.syncDir(d)
		},
	}

	sink := &recordingSyncSink{
		onSync: func() error {
			ops = append(ops, "sink.Sync")
			return nil
		},
	}
	if _, err := Replay(context.Background(), strings.NewReader(input), sink, opts); err != nil {
		t.Fatalf("Replay() error = %v", err)
	}
	wantOps := []string{
		"sink.Sync", "createTemp", "tmp.Write", "tmp.Sync", "tmp.Close", "rename", "syncDir",
		"sink.Sync", "createTemp", "tmp.Write", "tmp.Sync", "tmp.Close", "rename", "syncDir",
	}
	if !slices.Equal(ops, wantOps) {
		t.Fatalf("checkpoint durability operations = %v, want %v", ops, wantOps)
	}
	if preRenameDiskNext != 1 {
		t.Errorf("before the second rename, checkpoint on disk had Next=%d, want 1 (atomic temp+rename)", preRenameDiskNext)
	}

	// Fault injection on the 2nd record across every durability step must leave
	// the 1st record's checkpoint intact on disk and clean up temporary files.
	for _, faultStep := range []string{"sink.Sync", "tmp.Write", "tmp.Sync", "tmp.Close", "rename", "syncDir"} {
		t.Run("fault at "+faultStep, func(t *testing.T) {
			subDir := t.TempDir()
			subCkpt := filepath.Join(subDir, "replay.ckpt")
			subOpts := Options{Checkpoint: &CheckpointConfig{Path: subCkpt, Source: "file:quarantine.jsonl"}}
			saveCall := 0
			boom := errors.New("injected " + faultStep + " failure")

			checkpointHooks = checkpointFS{
				createTemp: func(d, pattern string) (checkpointTempFile, error) {
					saveCall++
					tf, err := defaultCheckpointFS.createTemp(d, pattern)
					if err != nil {
						return nil, err
					}
					ht := &hookedTempFile{checkpointTempFile: tf}
					if saveCall == 2 {
						switch faultStep {
						case "tmp.Write":
							ht.writeErr = boom
						case "tmp.Sync":
							ht.syncErr = boom
						case "tmp.Close":
							ht.closeErr = boom
						}
					}
					return ht, nil
				},
				rename: func(oldpath, newpath string) error {
					if saveCall == 2 && faultStep == "rename" {
						return boom
					}
					return defaultCheckpointFS.rename(oldpath, newpath)
				},
				remove: defaultCheckpointFS.remove,
				syncDir: func(d string) error {
					if saveCall == 2 && faultStep == "syncDir" {
						return boom
					}
					return defaultCheckpointFS.syncDir(d)
				},
			}
			syncCalls := 0
			flakySink := &recordingSyncSink{
				onSync: func() error {
					syncCalls++
					if syncCalls == 2 && faultStep == "sink.Sync" {
						return boom
					}
					return nil
				},
			}
			_, err := Replay(context.Background(), strings.NewReader(input), flakySink, subOpts)
			if !errors.Is(err, boom) {
				t.Fatalf("Replay() error = %v, want %v", err, boom)
			}
			assertDirHolds(t, subDir, "replay.ckpt")
			st := readCheckpointFile(t, subCkpt)
			wantNext := int64(1)
			if faultStep == "syncDir" {
				// syncDir fails after rename has already atomically replaced the file.
				wantNext = 2
			}
			if st.Next != wantNext {
				t.Fatalf("after %s failure, checkpoint Next = %d, want %d", faultStep, st.Next, wantNext)
			}

			// Restore normal hooks and verify a resumed run completes cleanly.
			checkpointHooks = defaultCheckpointFS
			resumed := &recordingSink{}
			sum, err := Replay(context.Background(), strings.NewReader(input), resumed, subOpts)
			if err != nil {
				t.Fatalf("resumed Replay() error = %v", err)
			}
			if faultStep == "syncDir" {
				if sum.SkippedCheckpointed != 2 || len(resumed.names) != 0 {
					t.Errorf("resumed after syncDir failure: sum=%+v names=%v", sum, resumed.names)
				}
			} else {
				if sum.SkippedCheckpointed != 1 || !slices.Equal(resumed.names, []string{"span-1"}) {
					t.Errorf("resumed after %s failure: sum=%+v names=%v, want span-1", faultStep, sum, resumed.names)
				}
			}
		})
	}
}

// fakeClock drives a RateLimiter without real sleeps.
type fakeClock struct {
	now   time.Time
	slept time.Duration
}

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.now = c.now.Add(d)
	c.slept += d
	return nil
}

func TestRateLimiter(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		rate  float64
		waits int
		want  time.Duration
	}{
		{rate: 10, waits: 21, want: 2 * time.Second},
		{rate: 0.5, waits: 3, want: 4 * time.Second},
		{rate: 1000, waits: 1, want: 0},
	} {
		clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
		l := newRateLimiter(tc.rate, clk.Now, clk.Sleep)
		for range tc.waits {
			if err := l.Wait(ctx); err != nil {
				t.Fatal(err)
			}
		}
		if d := clk.slept - tc.want; d < 0 || d > time.Millisecond {
			t.Errorf("rate %v: %d waits slept %v, want %v", tc.rate, tc.waits, clk.slept, tc.want)
		}
	}

	// After an idle spell the bucket holds one second's worth of tokens and
	// no more.
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	l := newRateLimiter(10, clk.Now, clk.Sleep)
	for range 1 {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	clk.now = clk.now.Add(time.Hour)
	for range 10 {
		if err := l.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if clk.slept != 0 {
		t.Errorf("a full bucket slept %v", clk.slept)
	}
	if err := l.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if clk.slept != 100*time.Millisecond {
		t.Errorf("the first wait past the burst slept %v, want 100ms", clk.slept)
	}

	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := l.Wait(canceled); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait on a canceled context returned %v", err)
	}
	for _, bad := range []float64{0, -1, math.NaN(), math.Inf(1)} {
		if _, err := NewRateLimiter(bad); err == nil {
			t.Errorf("NewRateLimiter(%v) succeeded", bad)
		}
	}

	// An extremely small positive rate must clamp wait to math.MaxInt64 rather
	// than overflowing int64 to a negative time.Duration and busy-looping.
	sleepCalls := 0
	var gotWait time.Duration
	tinyCtx, tinyCancel := context.WithCancel(ctx)
	tiny := newRateLimiter(1e-300, clk.Now, func(c context.Context, d time.Duration) error {
		sleepCalls++
		gotWait = d
		if d <= 0 {
			t.Fatalf("Wait computed non-positive duration %v (int64 overflow)", d)
		}
		tinyCancel()
		return c.Err()
	})
	if err := tiny.Wait(tinyCtx); err != nil {
		t.Fatalf("first Wait on 1e-300 rate failed: %v", err)
	}
	if err := tiny.Wait(tinyCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("second Wait on 1e-300 rate = %v, want context.Canceled", err)
	}
	if sleepCalls != 1 || gotWait != time.Duration(math.MaxInt64) {
		t.Errorf("sleepCalls = %d, gotWait = %v; want 1 call with math.MaxInt64", sleepCalls, gotWait)
	}
}

func TestReplayRateLimit(t *testing.T) {
	ctx := context.Background()
	// Only records handed to the sink wait for a token.
	clk := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	input := spanRecordsJSONL(t, "OVERSIZE_ROW", "ROW_ERROR", "OVERSIZE_ROW", "ROW_ERROR", "OVERSIZE_ROW")
	sum, err := Replay(ctx, strings.NewReader(input), NewMemorySink(), Options{
		Filter:      Filter{ErrorCodes: []string{"OVERSIZE_ROW"}},
		RateLimiter: newRateLimiter(2, clk.Now, clk.Sleep),
	})
	if err != nil || sum.ReplayedSpans != 3 || sum.SkippedFiltered != 2 {
		t.Fatalf("rate-limited run = %+v, %v", sum, err)
	}
	if clk.slept != time.Second {
		t.Errorf("3 records at 2/s slept %v, want 1s", clk.slept)
	}

	// On the real clock a run cannot outpace its limit.
	limiter, err := NewRateLimiter(40)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	sum, err = Replay(ctx, strings.NewReader(spanRecordsJSONL(t, oversizeCodes(5)...)), NewMemorySink(), Options{RateLimiter: limiter})
	if elapsed := time.Since(start); err != nil || sum.ReplayedSpans != 5 || elapsed < 100*time.Millisecond {
		t.Errorf("5 records at 40/s = %+v, %v in %v; want at least 100ms", sum, err, elapsed)
	}

	// A run canceled while it waits leaves the waiting record uncounted.
	canceled, cancel := context.WithCancel(ctx)
	defer cancel()
	stalling := newRateLimiter(1, time.Now, func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	})
	sum, err = Replay(canceled, strings.NewReader(spanRecordsJSONL(t, oversizeCodes(2)...)), NewMemorySink(), Options{RateLimiter: stalling})
	if !errors.Is(err, context.Canceled) || sum != (Summary{TotalRead: 1, Matched: 1, ReplayedSpans: 1}) {
		t.Errorf("canceled run = %+v, %v; want one record replayed and context.Canceled", sum, err)
	}
}

// otlpReceiver is an OTLP/HTTP receiver that answers each signal path with
// a scripted series of responses, the last of which repeats.
type otlpReceiver struct {
	mu     sync.Mutex
	script map[string][]scriptedResponse
	calls  map[string]int
	items  []string
}

type scriptedResponse struct {
	status int
	header map[string]string
	body   []byte
}

func newOTLPReceiver(script map[string][]scriptedResponse) *otlpReceiver {
	return &otlpReceiver{script: script, calls: map[string]int{}}
}

func (rc *otlpReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-protobuf" {
		http.Error(w, "want a protobuf POST", http.StatusUnsupportedMediaType)
		return
	}
	var items []string
	switch r.URL.Path {
	case "/otlp/v1/traces":
		req := ptraceotlp.NewExportRequest()
		err = req.UnmarshalProto(body)
		items = spanNames(req.Traces())
	case "/otlp/v1/logs":
		req := plogotlp.NewExportRequest()
		err = req.UnmarshalProto(body)
		rls := req.Logs().ResourceLogs()
		for i := range rls.Len() {
			sls := rls.At(i).ScopeLogs()
			for j := range sls.Len() {
				lrs := sls.At(j).LogRecords()
				for k := range lrs.Len() {
					items = append(items, lrs.At(k).Body().AsString())
				}
			}
		}
	case "/otlp/v1/metrics":
		req := pmetricotlp.NewExportRequest()
		err = req.UnmarshalProto(body)
		rms := req.Metrics().ResourceMetrics()
		for i := range rms.Len() {
			sms := rms.At(i).ScopeMetrics()
			for j := range sms.Len() {
				ms := sms.At(j).Metrics()
				for k := range ms.Len() {
					items = append(items, ms.At(k).Name())
				}
			}
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	n := rc.calls[r.URL.Path]
	rc.calls[r.URL.Path] = n + 1
	rc.items = append(rc.items, items...)
	resp := scriptedResponse{status: http.StatusOK}
	if s := rc.script[r.URL.Path]; len(s) > 0 {
		resp = s[min(n, len(s)-1)]
	}
	rc.mu.Unlock()
	for k, v := range resp.header {
		w.Header().Set(k, v)
	}
	w.WriteHeader(resp.status)
	_, _ = w.Write(resp.body)
}

func mustMarshal(t *testing.T, marshal func() ([]byte, error)) []byte {
	t.Helper()
	b, err := marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOTLPHTTPSink(t *testing.T) {
	td := ptrace.NewTraces()
	td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty().SetName("otlp-span")
	ld := plog.NewLogs()
	ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetStr("otlp-log")
	md := pmetric.NewMetrics()
	m := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName("otlp-metric")
	m.SetEmptyGauge().DataPoints().AppendEmpty().SetIntValue(1)
	item := map[string]string{"traces": "otlp-span", "logs": "otlp-log", "metrics": "otlp-metric"}

	protoHeader := map[string]string{"Content-Type": "application/x-protobuf"}
	statusBody := mustMarshal(t, func() ([]byte, error) {
		return proto.Marshal(&statuspb.Status{Code: 3, Message: "log body too large"})
	})
	rejectedPoints := pmetricotlp.NewExportResponse()
	rejectedPoints.PartialSuccess().SetRejectedDataPoints(2)
	rejectedPoints.PartialSuccess().SetErrorMessage("stale points")
	rejectedSpans := ptraceotlp.NewExportResponse()
	rejectedSpans.PartialSuccess().SetRejectedSpans(1)
	rejectedSpans.PartialSuccess().SetErrorMessage("bad span")
	warning := plogotlp.NewExportResponse()
	warning.PartialSuccess().SetErrorMessage("attributes truncated")

	tests := []struct {
		name          string
		signal        string
		script        []scriptedResponse
		maxAttempts   int
		wantErr       []string
		wantPermanent bool
		wantCalls     int
		wantDelays    []time.Duration
	}{
		{
			name:       "503 then success honors Retry-After",
			signal:     "traces",
			script:     []scriptedResponse{{status: 503, header: map[string]string{"Retry-After": "2"}}, {status: 200}},
			wantCalls:  2,
			wantDelays: []time.Duration{2 * time.Second},
		},
		{
			name:       "429 then success backs off",
			signal:     "metrics",
			script:     []scriptedResponse{{status: 429}, {status: 200}},
			wantCalls:  2,
			wantDelays: []time.Duration{500 * time.Millisecond},
		},
		{
			name:        "502 until the attempts run out",
			signal:      "logs",
			script:      []scriptedResponse{{status: 502}},
			maxAttempts: 3,
			wantErr:     []string{"502 Bad Gateway", "gave up after 3 attempts"},
			wantCalls:   3,
			wantDelays:  []time.Duration{500 * time.Millisecond, time.Second},
		},
		{
			name:          "400 is permanent",
			signal:        "logs",
			script:        []scriptedResponse{{status: 400, header: protoHeader, body: statusBody}},
			wantErr:       []string{"400 Bad Request", "log body too large"},
			wantPermanent: true,
			wantCalls:     1,
		},
		{
			name:          "413 is permanent",
			signal:        "traces",
			script:        []scriptedResponse{{status: 413}},
			wantErr:       []string{"413"},
			wantPermanent: true,
			wantCalls:     1,
		},
		{
			name:      "401 stops without a retry",
			signal:    "metrics",
			script:    []scriptedResponse{{status: 401, body: []byte("missing credentials")}},
			wantErr:   []string{"401 Unauthorized", "missing credentials"},
			wantCalls: 1,
		},
		{
			name:      "a redirect is not followed",
			signal:    "traces",
			script:    []scriptedResponse{{status: 307, header: map[string]string{"Location": "http://elsewhere.invalid/v1/traces"}}},
			wantErr:   []string{"307"},
			wantCalls: 1,
		},
		{
			name:          "partial success rejecting points",
			signal:        "metrics",
			script:        []scriptedResponse{{status: 200, header: protoHeader, body: mustMarshal(t, rejectedPoints.MarshalProto)}},
			wantErr:       []string{"rejected 2 data points", "stale points"},
			wantPermanent: true,
			wantCalls:     1,
		},
		{
			name:          "JSON partial success rejecting spans",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: mustMarshal(t, rejectedSpans.MarshalJSON)}},
			wantErr:       []string{"rejected 1 spans", "bad span"},
			wantPermanent: true,
			wantCalls:     1,
		},
		{
			name:      "a partial success warning is a success",
			signal:    "logs",
			script:    []scriptedResponse{{status: 200, header: protoHeader, body: mustMarshal(t, warning.MarshalProto)}},
			wantCalls: 1,
		},
		{
			name:          "200 HTML proxy page is not treated as delivered",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "text/html; charset=utf-8"}, body: []byte("<html>Sign in</html>")}},
			wantErr:       []string{`unexpected Content-Type "text/html; charset=utf-8"`, "Sign in"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 truncated JSON body is not treated as delivered",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{"partialSuccess":`)}},
			wantErr:       []string{"decoding 200 OK response"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 malformed protobuf body is not treated as delivered",
			signal:        "logs",
			script:        []scriptedResponse{{status: 200, header: protoHeader, body: []byte{0x0a, 0xff, 0x01}}},
			wantErr:       []string{"decoding 200 OK response"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 oversized body is rejected as ambiguous delivery",
			signal:        "metrics",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: bytes.Repeat([]byte(" "), otlpMaxResponseBytes+1)}},
			wantErr:       []string{"response body exceeds 1048576 bytes"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "202 Accepted is rejected as unexpected status",
			signal:        "traces",
			script:        []scriptedResponse{{status: 202, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{}`)}},
			wantErr:       []string{"unexpected status 202 Accepted"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 JSON with trailing HTML after object is rejected",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{}<html>Sign in</html>`)}},
			wantErr:       []string{"decoding 200 OK response"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 JSON with trailing truncated JSON is rejected",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{} {"partialSuccess":`)}},
			wantErr:       []string{"decoding 200 OK response"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 JSON null is rejected",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`null`)}},
			wantErr:       []string{"decoding 200 OK response"},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:          "200 empty body with malformed Content-Type is rejected",
			signal:        "traces",
			script:        []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": ";"}}},
			wantErr:       []string{`unexpected Content-Type ";"`},
			wantPermanent: false,
			wantCalls:     1,
		},
		{
			name:      "200 empty body with absent Content-Type succeeds",
			signal:    "traces",
			script:    []scriptedResponse{{status: 200}},
			wantCalls: 1,
		},
		{
			name:      "200 empty body with JSON Content-Type succeeds",
			signal:    "traces",
			script:    []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}}},
			wantCalls: 1,
		},
		{
			name:      "200 empty body with protobuf Content-Type succeeds",
			signal:    "traces",
			script:    []scriptedResponse{{status: 200, header: protoHeader}},
			wantCalls: 1,
		},
		{
			name:      "200 empty JSON object succeeds",
			signal:    "traces",
			script:    []scriptedResponse{{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{}`)}},
			wantCalls: 1,
		},
		{
			name:      "204 No Content with empty body succeeds",
			signal:    "traces",
			script:    []scriptedResponse{{status: 204}},
			wantCalls: 1,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rc := newOTLPReceiver(map[string][]scriptedResponse{"/otlp/v1/" + tc.signal: tc.script})
			srv := httptest.NewServer(rc)
			defer srv.Close()
			sink, err := NewOTLPHTTPSink(srv.URL+"/otlp/", OTLPHTTPSinkOptions{MaxAttempts: tc.maxAttempts})
			if err != nil {
				t.Fatal(err)
			}
			defer sink.Close()
			var delays []time.Duration
			sink.backoff = otlpBackoffBase
			sink.sleep = func(_ context.Context, d time.Duration) error {
				delays = append(delays, d)
				return nil
			}
			ctx := context.Background()
			switch tc.signal {
			case "traces":
				err = sink.ExportTraces(ctx, td)
			case "logs":
				err = sink.ExportLogs(ctx, ld)
			case "metrics":
				err = sink.ExportMetrics(ctx, md)
			}
			if len(tc.wantErr) == 0 && err != nil {
				t.Errorf("export: %v", err)
			}
			if len(tc.wantErr) > 0 {
				if err == nil {
					t.Fatalf("export succeeded, want an error with %q", tc.wantErr)
				}
				for _, want := range tc.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("error %q lacks %q", err, want)
					}
				}
				if got := isPermanent(err); got != tc.wantPermanent {
					t.Errorf("isPermanent(%v) = %v, want %v", err, got, tc.wantPermanent)
				}
			}
			if got := rc.calls["/otlp/v1/"+tc.signal]; got != tc.wantCalls {
				t.Errorf("receiver got %d requests, want %d", got, tc.wantCalls)
			}
			if want := slices.Repeat([]string{item[tc.signal]}, tc.wantCalls); !slices.Equal(rc.items, want) {
				t.Errorf("receiver decoded %v, want %v", rc.items, want)
			}
			if !slices.Equal(delays, tc.wantDelays) {
				t.Errorf("delays = %v, want %v", delays, tc.wantDelays)
			}
		})
	}
}

func TestReplayIntoOTLPHTTPSink(t *testing.T) {
	rc := newOTLPReceiver(nil)
	srv := httptest.NewServer(rc)
	defer srv.Close()
	sink, err := NewOTLPHTTPSink(srv.URL+"/otlp", OTLPHTTPSinkOptions{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	var input strings.Builder
	for _, rec := range []Record{
		{IngestTime: "2026-10-11T10:00:00Z", Signal: "spans", ErrorCode: "OVERSIZE_ROW", RawPayload: sampleSpanJSON(t, "replayed-span")},
		{IngestTime: "2026-10-11T10:00:00Z", Signal: "logs", ErrorCode: "ROW_ERROR", RawPayload: sampleLogJSON(t, "replayed-log")},
		{IngestTime: "2026-10-11T10:00:00Z", Signal: "metrics", ErrorCode: "ROW_ERROR", RawPayload: sampleMetricJSON(t, "replayed-metric")},
	} {
		line, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		input.Write(line)
		input.WriteByte('\n')
	}
	sum, err := Replay(context.Background(), strings.NewReader(input.String()), sink, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 1, ReplayedLogs: 1, ReplayedMetrics: 1}); sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
	if want := map[string]int{"/otlp/v1/traces": 1, "/otlp/v1/logs": 1, "/otlp/v1/metrics": 1}; !maps.Equal(rc.calls, want) {
		t.Errorf("receiver calls = %v, want %v", rc.calls, want)
	}
	for _, want := range []string{"replayed-span", "replayed-log", "replayed-metric"} {
		if !slices.Contains(rc.items, want) {
			t.Errorf("receiver never decoded %q (got %v)", want, rc.items)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.ExportTraces(canceled, ptrace.NewTraces()); !errors.Is(err, context.Canceled) {
		t.Errorf("export on a canceled context returned %v", err)
	}

	for _, bad := range []string{
		"", "localhost:4318", "ftp://collector:4318", "http://", "http://collector:4318/?token=x",
		"http://collector:4318/#part", "http://[::1",
	} {
		if _, err := NewOTLPHTTPSink(bad, OTLPHTTPSinkOptions{}); err == nil {
			t.Errorf("NewOTLPHTTPSink(%q) succeeded", bad)
		}
	}
	for _, opts := range []OTLPHTTPSinkOptions{{Timeout: -time.Second}, {MaxAttempts: -1}} {
		if _, err := NewOTLPHTTPSink("http://collector:4318", opts); err == nil {
			t.Errorf("NewOTLPHTTPSink with %+v succeeded", opts)
		}
	}

	// Ambiguous 2xx responses (trailing HTML/JSON after {}, JSON null, or a
	// malformed Content-Type on an empty 200) must never advance a checkpoint,
	// while valid empty/JSON/protobuf/204 responses must advance it.
	input1 := spanRecordsJSONL(t, "OVERSIZE_ROW")
	for _, tc := range []struct {
		name string
		resp scriptedResponse
	}{
		{
			name: "trailing HTML after JSON object",
			resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{}<html>Sign in</html>`)},
		},
		{
			name: "trailing truncated JSON after JSON object",
			resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{} {"partialSuccess":`)},
		},
		{
			name: "JSON null body",
			resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`null`)},
		},
		{
			name: "malformed Content-Type on empty 200",
			resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": ";"}},
		},
	} {
		t.Run("checkpoint rejected on "+tc.name, func(t *testing.T) {
			badRC := newOTLPReceiver(map[string][]scriptedResponse{"/otlp/v1/traces": {tc.resp}})
			badSrv := httptest.NewServer(badRC)
			defer badSrv.Close()
			badSink, err := NewOTLPHTTPSink(badSrv.URL+"/otlp", OTLPHTTPSinkOptions{MaxAttempts: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer badSink.Close()
			ckptPath := filepath.Join(t.TempDir(), "ambiguous.ckpt")
			sum, err := Replay(context.Background(), strings.NewReader(input1), badSink, Options{
				Checkpoint: &CheckpointConfig{Path: ckptPath, Source: "file:q.jsonl"},
			})
			if err == nil {
				t.Fatalf("Replay(%s) succeeded unexpectedly", tc.name)
			}
			if sum.ReplayedSpans != 0 || sum.FailedExport != 1 {
				t.Errorf("Replay(%s) summary = %+v, want ReplayedSpans=0 FailedExport=1", tc.name, sum)
			}
			if _, statErr := os.Stat(ckptPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("Replay(%s) wrote checkpoint %s (statErr=%v), want no checkpoint created", tc.name, ckptPath, statErr)
			}
		})
	}

	okProto := ptraceotlp.NewExportResponse()
	okProtoBytes := mustMarshal(t, okProto.MarshalProto)
	for _, tc := range []struct {
		name string
		resp scriptedResponse
	}{
		{name: "empty 200 without Content-Type", resp: scriptedResponse{status: 200}},
		{name: "empty 200 with application/json", resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/json"}}},
		{name: "empty 200 with application/x-protobuf", resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/x-protobuf"}}},
		{name: "200 with {}", resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: []byte(`{}`)}},
		{name: "200 with nonempty protobuf response", resp: scriptedResponse{status: 200, header: map[string]string{"Content-Type": "application/x-protobuf"}, body: okProtoBytes}},
		{name: "empty 204 No Content", resp: scriptedResponse{status: 204}},
	} {
		t.Run("checkpoint advances on "+tc.name, func(t *testing.T) {
			okRC := newOTLPReceiver(map[string][]scriptedResponse{"/otlp/v1/traces": {tc.resp}})
			okSrv := httptest.NewServer(okRC)
			defer okSrv.Close()
			okSink, err := NewOTLPHTTPSink(okSrv.URL+"/otlp", OTLPHTTPSinkOptions{MaxAttempts: 1})
			if err != nil {
				t.Fatal(err)
			}
			defer okSink.Close()
			ckptPath := filepath.Join(t.TempDir(), "valid.ckpt")
			sum, err := Replay(context.Background(), strings.NewReader(input1), okSink, Options{
				Checkpoint: &CheckpointConfig{Path: ckptPath, Source: "file:q.jsonl"},
			})
			if err != nil || sum.ReplayedSpans != 1 {
				t.Fatalf("Replay(%s) = (%+v, %v), want ReplayedSpans=1 and nil error", tc.name, sum, err)
			}
			if st := readCheckpointFile(t, ckptPath); st.Next != 1 || st.Handled != 1 {
				t.Errorf("Replay(%s) checkpoint = %+v, want Next=1 Handled=1", tc.name, st)
			}
		})
	}
}

func TestOTLPRetryDelays(t *testing.T) {
	now := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"", 0},
		{"soon", 0},
		{"0", 0},
		{"-3", 0},
		{"7", 7 * time.Second},
		{"86400", otlpMaxRetryDelay},
		{now.Add(10 * time.Second).Format(http.TimeFormat), 10 * time.Second},
		{now.Add(time.Hour).Format(http.TimeFormat), otlpMaxRetryDelay},
		{now.Add(-time.Minute).Format(http.TimeFormat), 0},
	} {
		if got := parseRetryAfter(tc.header, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.header, got, tc.want)
		}
	}
	for attempt, want := range map[int]time.Duration{
		1: 500 * time.Millisecond, 2: time.Second, 3: 2 * time.Second, 7: 32 * time.Second, 8: otlpMaxRetryDelay, 50: otlpMaxRetryDelay,
	} {
		if got := otlpBackoffBase(attempt); got != want {
			t.Errorf("otlpBackoffBase(%d) = %v, want %v", attempt, got, want)
		}
		lo := time.Duration(float64(want) * 0.8)
		hi := min(time.Duration(float64(want)*1.2), otlpMaxRetryDelay)
		minSeen := hi + time.Second
		var maxSeen time.Duration
		for range 64 {
			got := otlpBackoff(attempt)
			if got < lo || got > hi {
				t.Fatalf("otlpBackoff(%d) = %v, want within [%v, %v]", attempt, got, lo, hi)
			}
			if got < minSeen {
				minSeen = got
			}
			if got > maxSeen {
				maxSeen = got
			}
		}
		if minSeen == maxSeen {
			t.Fatalf("otlpBackoff(%d) produced constant %v across 64 calls, want jitter", attempt, minSeen)
		}
	}
}

func TestOTLPHTTPSinkAppliesBoundedJitterByDefault(t *testing.T) {
	rc := newOTLPReceiver(map[string][]scriptedResponse{
		"/otlp/v1/logs": {{status: 429}, {status: 200}},
	})
	srv := httptest.NewServer(rc)
	defer srv.Close()
	sink, err := NewOTLPHTTPSink(srv.URL+"/otlp/", OTLPHTTPSinkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()

	var delays []time.Duration
	sink.sleep = func(_ context.Context, d time.Duration) error {
		delays = append(delays, d)
		return nil
	}
	ld := plog.NewLogs()
	ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetStr("hi")
	if err := sink.ExportLogs(context.Background(), ld); err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	if len(delays) != 1 {
		t.Fatalf("delays = %v, want 1", delays)
	}
	lo := time.Duration(float64(otlpInitialBackoff) * 0.8)
	hi := time.Duration(float64(otlpInitialBackoff) * 1.2)
	if delays[0] < lo || delays[0] > hi {
		t.Fatalf("default sink retry delay = %v, want within [%v, %v]", delays[0], lo, hi)
	}
}

// quarantineResultColumns are the columns the replay query selects.
var quarantineResultColumns = []string{
	"ingest_time_us", "signal", "error_code", "error_message", "service_name",
	"trace_id", "span_id", "raw_payload", "payload_ref_uri", "payload_ref_version",
	"row_fp", "row_ord", "row_key", "group_size", "prefix_sha256", "group_sha256",
}

// sqlWindowDigestPattern extracts the length function, delimiter literal,
// window frame upper bound, and column alias from the SQL SHA-256 window
// expressions in quarantineQueryTemplate.
var sqlWindowDigestPattern = regexp.MustCompile(
	`TO_HEX\(SHA256\(STRING_AGG\(CONCAT\(CAST\((BYTE_LENGTH|CHAR_LENGTH)\(row_key\) AS STRING\), '([^']*)', row_key\), ''\) OVER \(PARTITION BY ingest_time, row_fp ORDER BY row_key ROWS BETWEEN UNBOUNDED PRECEDING AND (CURRENT ROW|UNBOUNDED FOLLOWING)\)\)\)\s+AS\s+(prefix_sha256|group_sha256)`,
)

type sqlDigestSpec struct {
	lenFn string
	delim string
	frame string
}

func parseSQLWindowDigestSpecs(query string) map[string]sqlDigestSpec {
	out := map[string]sqlDigestSpec{}
	for _, m := range sqlWindowDigestPattern.FindAllStringSubmatch(query, -1) {
		out[m[4]] = sqlDigestSpec{
			lenFn: m[1],
			delim: m[2],
			frame: m[3],
		}
	}
	return out
}

func evalSQLWindowDigest(keys []string, lenFn, delim string) string {
	h := sha256.New()
	for _, k := range keys {
		n := len(k)
		if lenFn == "CHAR_LENGTH" {
			n = utf8.RuneCountInString(k)
		}
		h.Write([]byte(strconv.Itoa(n)))
		h.Write([]byte(delim))
		h.Write([]byte(k))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fakeQuarantineRow is one row the fake BigQuery returns.
type fakeQuarantineRow struct {
	ingest       time.Time
	fp           int64
	ord          int64
	groupSize    int
	prefixSHA256 string
	groupSHA256  string
	signal       string
	code         string
	payload      string
}

func (r fakeQuarantineRow) after(c bigQueryCursor) bool {
	us := r.ingest.UnixMicro()
	if us != c.IngestTimeMicros {
		return us > c.IngestTimeMicros
	}
	if r.fp != c.RowFingerprint {
		return r.fp > c.RowFingerprint
	}
	return r.ord > c.DuplicateOrdinal
}

func (r fakeQuarantineRow) canonicalKey() string {
	b, _ := json.Marshal(struct {
		Signal  string `json:"signal"`
		Code    string `json:"error_code"`
		Message string `json:"error_message"`
		Payload string `json:"raw_payload"`
	}{
		Signal:  r.signal,
		Code:    r.code,
		Message: "rejected",
		Payload: r.payload,
	})
	return string(b)
}

func (r fakeQuarantineRow) jsonForCols(cols []string) map[string]any {
	cell := func(v string) map[string]any {
		if v == "" {
			return map[string]any{"v": nil}
		}
		return map[string]any{"v": v}
	}
	byCol := map[string]map[string]any{
		"ingest_time_us":      cell(strconv.FormatInt(r.ingest.UnixMicro(), 10)),
		"signal":              cell(r.signal),
		"error_code":          cell(r.code),
		"error_message":       cell("rejected"),
		"service_name":        cell("checkout"),
		"trace_id":            cell(""),
		"span_id":             cell(""),
		"raw_payload":         cell(r.payload),
		"payload_ref_uri":     cell(""),
		"payload_ref_version": cell(""),
		"row_fp":              cell(strconv.FormatInt(r.fp, 10)),
		"row_ord":             cell(strconv.FormatInt(r.ord, 10)),
		"row_key":             cell(r.canonicalKey()),
		"group_size":          cell(strconv.Itoa(r.groupSize)),
		"prefix_sha256":       cell(r.prefixSHA256),
		"group_sha256":        cell(r.groupSHA256),
	}
	f := make([]any, len(cols))
	for i, c := range cols {
		f[i] = byCol[c]
	}
	return map[string]any{"f": f}
}

// selectedQuarantineColumns extracts the column names projected by the outer
// `SELECT ... FROM quarantined` clause of query so fakeQuarantineBigQuery only
// returns columns the query actually selected.
func selectedQuarantineColumns(query string) []string {
	fromIdx := strings.Index(query, "FROM quarantined")
	if fromIdx < 0 {
		return slices.Clone(quarantineResultColumns)
	}
	selectIdx := strings.LastIndex(query[:fromIdx], "SELECT")
	if selectIdx < 0 {
		return slices.Clone(quarantineResultColumns)
	}
	proj := query[selectIdx+len("SELECT") : fromIdx]
	var cols []string
	for _, part := range strings.Split(proj, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}
		if idx := strings.LastIndex(strings.ToUpper(item), " AS "); idx >= 0 {
			item = strings.TrimSpace(item[idx+len(" AS "):])
		}
		if slices.Contains(quarantineResultColumns, item) {
			cols = append(cols, item)
		}
	}
	return cols
}

// fakeQuarantineBigQuery serves the BigQuery REST calls ReplayBigQuery
// makes, jobs.query and jobs.getQueryResults, for project "proj". It
// applies a resume cursor as the real query does and pages by maxResults.
type fakeQuarantineBigQuery struct {
	mu   sync.Mutex
	rows []fakeQuarantineRow // in (ingest_time, row_fp) order
	// pending is how many getQueryResults calls report an unfinished job.
	pending int
	// status, when set, fails jobs.query with that HTTP status.
	status int

	selected     []fakeQuarantineRow
	selectedCols []string
	requests     []*bigqueryapi.QueryRequest
	resultsCalls []url.Values
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeQuarantineBigQuery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job := map[string]any{"projectId": "proj", "jobId": "job-1", "location": "EU"}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/bigquery/v2/projects/proj/queries":
		req := new(bigqueryapi.QueryRequest)
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.requests = append(f.requests, req)
		if f.status != 0 {
			writeTestJSON(w, f.status, map[string]any{"error": map[string]any{"code": f.status, "message": "Access Denied: Project proj"}})
			return
		}
		cursor, resume := cursorParams(req)
		f.selected = nil
		f.selectedCols = selectedQuarantineColumns(req.Query)
		ordered := slices.Clone(f.rows)
		if strings.Contains(req.Query, "ROW_NUMBER() OVER (PARTITION BY ingest_time, row_fp ORDER BY row_key)") &&
			strings.Contains(req.Query, "ORDER BY ingest_time, row_fp, row_ord, row_key") {
			slices.SortStableFunc(ordered, func(a, b fakeQuarantineRow) int {
				if a.ingest.UnixMicro() != b.ingest.UnixMicro() {
					return strings.Compare(
						fmt.Sprintf("%020d", a.ingest.UnixMicro()),
						fmt.Sprintf("%020d", b.ingest.UnixMicro()),
					)
				}
				if a.fp != b.fp {
					if a.fp < b.fp {
						return -1
					}
					return 1
				}
				return strings.Compare(a.canonicalKey(), b.canonicalKey())
			})
		}
		type rowKey struct {
			us int64
			fp int64
		}
		hasWindowCount := strings.Contains(req.Query, "COUNT(*) OVER (PARTITION BY ingest_time, row_fp) AS group_size")
		digestSpecs := parseSQLWindowDigestSpecs(req.Query)
		groupCounts := map[rowKey]int{}
		fullGroupKeys := map[rowKey][]string{}
		for i := range ordered {
			k := rowKey{us: ordered[i].ingest.UnixMicro(), fp: ordered[i].fp}
			groupCounts[k]++
			fullGroupKeys[k] = append(fullGroupKeys[k], ordered[i].canonicalKey())
		}
		ords := map[rowKey]int64{}
		prefixKeys := map[rowKey][]string{}
		for i := range ordered {
			k := rowKey{us: ordered[i].ingest.UnixMicro(), fp: ordered[i].fp}
			ordered[i].ord = ords[k]
			ords[k]++
			if hasWindowCount {
				ordered[i].groupSize = groupCounts[k]
			} else if strings.Contains(req.Query, "1 AS group_size") {
				ordered[i].groupSize = 1
			}
			prefixKeys[k] = append(prefixKeys[k], ordered[i].canonicalKey())
			if spec, ok := digestSpecs["prefix_sha256"]; ok {
				keys := prefixKeys[k]
				if spec.frame == "UNBOUNDED FOLLOWING" {
					keys = fullGroupKeys[k]
				}
				ordered[i].prefixSHA256 = evalSQLWindowDigest(keys, spec.lenFn, spec.delim)
			}
			if spec, ok := digestSpecs["group_sha256"]; ok {
				keys := fullGroupKeys[k]
				if spec.frame == "CURRENT ROW" {
					keys = prefixKeys[k]
				}
				ordered[i].groupSHA256 = evalSQLWindowDigest(keys, spec.lenFn, spec.delim)
			}
		}
		if resume && strings.Contains(req.Query, "@cursor_key") &&
			strings.Contains(req.Query, "@cursor_group_count") &&
			strings.Contains(req.Query, "@cursor_prefix_sha256") {
			hasGroupSHACheck := strings.Contains(req.Query, "group_sha256 = @cursor_group_sha256")
			matched := false
			for _, row := range ordered {
				if row.ingest.UnixMicro() == cursor.IngestTimeMicros &&
					row.fp == cursor.RowFingerprint &&
					row.ord == cursor.DuplicateOrdinal &&
					row.canonicalKey() == cursor.CanonicalRowKey &&
					row.groupSize == cursor.GroupCount &&
					row.prefixSHA256 == cursor.PrefixSHA256 &&
					(!hasGroupSHACheck || row.groupSHA256 == cursor.GroupSHA256) {
					matched = true
					break
				}
			}
			if !matched {
				if strings.Contains(req.Query, "(row_fp = @cursor_fp AND row_ord > @cursor_ord) OR NOT EXISTS (") {
					cursor.RowFingerprint = math.MinInt64
				}
				cursor.DuplicateOrdinal = -1
				cursor.CanonicalRowKey = ""
				cursor.GroupCount = 0
				cursor.PrefixSHA256 = ""
				cursor.GroupSHA256 = ""
			}
		}
		for _, row := range ordered {
			if !resume || row.after(cursor) {
				f.selected = append(f.selected, row)
			}
		}
		writeTestJSON(w, http.StatusOK, map[string]any{"jobReference": job, "jobComplete": false})
	case r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/queries/job-1":
		q := r.URL.Query()
		f.resultsCalls = append(f.resultsCalls, q)
		if f.pending > 0 {
			f.pending--
			writeTestJSON(w, http.StatusOK, map[string]any{"jobReference": job, "jobComplete": false})
			return
		}
		start, _ := strconv.Atoi(q.Get("pageToken"))
		pageSize, _ := strconv.Atoi(q.Get("maxResults"))
		if pageSize <= 0 {
			pageSize = len(f.selected)
		}
		start = min(start, len(f.selected))
		end := min(start+pageSize, len(f.selected))
		cols := f.selectedCols
		if len(cols) == 0 {
			cols = quarantineResultColumns
		}
		rows := []any{}
		for _, row := range f.selected[start:end] {
			rows = append(rows, row.jsonForCols(cols))
		}
		fields := make([]any, len(cols))
		for i, name := range cols {
			typ := "STRING"
			if name == "ingest_time_us" || name == "row_fp" || name == "row_ord" || name == "group_size" {
				typ = "INTEGER"
			}
			fields[i] = map[string]any{"name": name, "type": typ}
		}
		resp := map[string]any{
			"jobReference": job,
			"jobComplete":  true,
			"schema":       map[string]any{"fields": fields},
			"rows":         rows,
			"totalRows":    strconv.Itoa(len(f.selected)),
		}
		if end < len(f.selected) {
			resp["pageToken"] = strconv.Itoa(end)
		}
		writeTestJSON(w, http.StatusOK, resp)
	default:
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

// cursorParams reads the resume cursor from a query's parameters.
func cursorParams(req *bigqueryapi.QueryRequest) (bigQueryCursor, bool) {
	var (
		c                bigQueryCursor
		haveTime, haveFP bool
	)
	for _, p := range req.QueryParameters {
		if p.ParameterValue == nil {
			continue
		}
		switch p.Name {
		case "cursor_time":
			if ts, err := time.Parse(bigQueryTimestampLayout, p.ParameterValue.Value); err == nil {
				c.IngestTimeMicros, haveTime = ts.UnixMicro(), true
			}
		case "cursor_fp":
			if fp, err := strconv.ParseInt(p.ParameterValue.Value, 10, 64); err == nil {
				c.RowFingerprint, haveFP = fp, true
			}
		case "cursor_ord":
			if ord, err := strconv.ParseInt(p.ParameterValue.Value, 10, 64); err == nil {
				c.DuplicateOrdinal = ord
			}
		case "cursor_key":
			c.CanonicalRowKey = p.ParameterValue.Value
		case "cursor_group_count":
			if cnt, err := strconv.Atoi(p.ParameterValue.Value); err == nil {
				c.GroupCount = cnt
			}
		case "cursor_prefix_sha256":
			c.PrefixSHA256 = p.ParameterValue.Value
		case "cursor_group_sha256":
			c.GroupSHA256 = p.ParameterValue.Value
		}
	}
	return c, haveTime && haveFP
}

// queryParamValues maps each query parameter to its type and value, with
// array values joined by commas.
func queryParamValues(req *bigqueryapi.QueryRequest) map[string]string {
	out := map[string]string{}
	for _, p := range req.QueryParameters {
		if p.ParameterValue == nil || p.ParameterType == nil {
			continue
		}
		if p.ParameterType.Type == "ARRAY" && p.ParameterType.ArrayType != nil {
			var vals []string
			for _, v := range p.ParameterValue.ArrayValues {
				vals = append(vals, v.Value)
			}
			out[p.Name] = p.ParameterType.ArrayType.Type + "[" + strings.Join(vals, ",") + "]"
			continue
		}
		out[p.Name] = p.ParameterType.Type + " " + p.ParameterValue.Value
	}
	return out
}

func bigQueryTestOptions(srv *httptest.Server) []option.ClientOption {
	return []option.ClientOption{option.WithEndpoint(srv.URL + "/bigquery/v2/"), option.WithoutAuthentication()}
}

func TestReplayBigQuery(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	fake := &fakeQuarantineBigQuery{
		pending: 1,
		rows: []fakeQuarantineRow{
			{ingest: base, fp: -5, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "bq-span-1")},
			{ingest: base, fp: 7, signal: "logs", code: "ROW_ERROR", payload: sampleLogJSON(t, "bq-log")},
			{ingest: base.Add(time.Minute), fp: 1, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "bq-span-2")},
			// The real query never returns a row outside the window; the
			// filter still drops one.
			{ingest: base.Add(3 * time.Hour), fp: 2, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "late")},
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	sink := NewMemorySink()
	opts := Options{Filter: Filter{
		Signal:     "traces,logs",
		ErrorCodes: []string{"oversize_row", "ROW_ERROR"},
		Since:      base.Add(-time.Hour),
		Until:      base.Add(time.Hour),
	}}
	sum, err := ReplayBigQuery(context.Background(), BigQuerySource{Project: "proj", Dataset: "ds", PageSize: 2}, sink, opts, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("ReplayBigQuery: %v", err)
	}
	if want := (Summary{TotalRead: 4, Matched: 3, ReplayedSpans: 2, ReplayedLogs: 1, SkippedFiltered: 1}); sum != want {
		t.Errorf("summary = %+v, want %+v", sum, want)
	}
	var names []string
	for _, td := range sink.Traces {
		names = append(names, spanNames(td)...)
	}
	if want := []string{"bq-span-1", "bq-span-2"}; !slices.Equal(names, want) || len(sink.Logs) != 1 {
		t.Errorf("replayed spans %v and %d log batches, want %v and 1", names, len(sink.Logs), want)
	}

	if len(fake.requests) != 1 {
		t.Fatalf("got %d jobs.query calls, want 1", len(fake.requests))
	}
	req := fake.requests[0]
	for _, want := range []string{
		"FROM `proj.ds.otel_quarantine`",
		"WHERE ingest_time >= @since\n    AND ingest_time <= @until\n    AND signal IN UNNEST(@signals)\n    AND error_code IN UNNEST(@error_codes)\n",
		"ORDER BY ingest_time, row_fp",
	} {
		if !strings.Contains(req.Query, want) {
			t.Errorf("query lacks %q:\n%s", want, req.Query)
		}
	}
	if strings.Contains(req.Query, "@cursor") {
		t.Errorf("a fresh run resumes:\n%s", req.Query)
	}
	if req.UseLegacySql == nil || *req.UseLegacySql || req.ParameterMode != "NAMED" || req.MaxResults != 2 {
		t.Errorf("request has useLegacySql=%v parameterMode=%q maxResults=%d", req.UseLegacySql, req.ParameterMode, req.MaxResults)
	}
	wantParams := map[string]string{
		"since":       "TIMESTAMP 2026-10-11 09:00:00+00:00",
		"until":       "TIMESTAMP 2026-10-11 11:00:00+00:00",
		"signals":     "STRING[traces,spans,otel_spans,logs,otel_logs]",
		"error_codes": "STRING[oversize_row,OVERSIZE_ROW,ROW_ERROR,row_error]",
	}
	if got := queryParamValues(req); !maps.Equal(got, wantParams) {
		t.Errorf("query parameters = %v, want %v", got, wantParams)
	}
	if len(fake.resultsCalls) != 3 {
		t.Fatalf("got %d jobs.getQueryResults calls, want 3 (one unfinished, two pages)", len(fake.resultsCalls))
	}
	for i, q := range fake.resultsCalls {
		wantToken := ""
		if i == 2 {
			wantToken = "2"
		}
		if q.Get("location") != "EU" || q.Get("maxResults") != "2" || q.Get("pageToken") != wantToken {
			t.Errorf("getQueryResults call %d = %v, want location=EU maxResults=2 pageToken=%q", i, q, wantToken)
		}
	}
}

func TestReplayBigQueryCheckpointResume(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: -9, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "first")},
		{ingest: base, fp: 4, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "second")},
		{ingest: base.Add(time.Second), fp: -1, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "third")},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}
	dir := t.TempDir()
	opts := Options{Checkpoint: &CheckpointConfig{Path: filepath.Join(dir, "bq.ckpt")}}

	// The first run stops where the sink fails in a way a retry may fix.
	flaky := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return errors.New("receiver unavailable")
		}
		return nil
	}}
	_, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...)
	if err == nil || !strings.Contains(err.Error(), "receiver unavailable") || !strings.Contains(err.Error(), "rerun with checkpoint") {
		t.Fatalf("first run returned %v, want a stop at the transient failure", err)
	}
	st := readCheckpointFile(t, opts.Checkpoint.Path)
	if st.Kind != checkpointKindBigQuery || st.Source != "bigquery:proj.ds.dead_letters" {
		t.Fatalf("checkpoint = %+v, want kind=%s source=%q", st, checkpointKindBigQuery, "bigquery:proj.ds.dead_letters")
	}
	assertCursor(t, st, base.UnixMicro(), -9, 0, fake.rows[0].canonicalKey(), 1)

	// The rerun asks BigQuery only for the rows after the cursor.
	resumed := &recordingSink{}
	sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
		t.Errorf("resumed summary = %+v, want %+v", sum, want)
	}
	if want := []string{"second", "third"}; !slices.Equal(resumed.names, want) {
		t.Errorf("resumed run replayed %v, want %v", resumed.names, want)
	}
	req := fake.requests[len(fake.requests)-1]
	for _, want := range []string{
		"FROM `proj.ds.dead_letters`",
		"WHERE ingest_time > @cursor_time OR (ingest_time = @cursor_time AND (row_fp > @cursor_fp OR (row_fp = @cursor_fp AND row_ord > @cursor_ord) OR NOT EXISTS (SELECT 1 FROM quarantined WHERE ingest_time = @cursor_time AND row_fp = @cursor_fp AND row_ord = @cursor_ord AND row_key = @cursor_key AND group_size = @cursor_group_count AND prefix_sha256 = @cursor_prefix_sha256 AND group_sha256 = @cursor_group_sha256)))\nORDER BY ingest_time, row_fp, row_ord",
	} {
		if !strings.Contains(req.Query, want) {
			t.Errorf("resume query lacks %q:\n%s", want, req.Query)
		}
	}
	params := queryParamValues(req)
	wantFirstPfx := evalSQLWindowDigest([]string{fake.rows[0].canonicalKey()}, "BYTE_LENGTH", ":")
	if params["since"] != "TIMESTAMP 2026-10-11 10:00:00+00:00" ||
		params["cursor_time"] != "TIMESTAMP 2026-10-11 10:00:00+00:00" ||
		params["cursor_fp"] != "INT64 -9" ||
		params["cursor_ord"] != "INT64 0" ||
		params["cursor_key"] != "STRING "+fake.rows[0].canonicalKey() ||
		params["cursor_group_count"] != "INT64 1" ||
		params["cursor_prefix_sha256"] != "STRING "+wantFirstPfx ||
		params["cursor_group_sha256"] != "STRING "+wantFirstPfx {
		t.Errorf("resume parameters = %v, want the partition bound raised to the cursor with cursor_key, cursor_group_count, cursor_prefix_sha256, and cursor_group_sha256", params)
	}
	st = readCheckpointFile(t, opts.Checkpoint.Path)
	assertCursor(t, st, base.Add(time.Second).UnixMicro(), -1, 0, fake.rows[2].canonicalKey(), 3)
	assertDirHolds(t, dir, "bq.ckpt")
}

func TestReplayBigQueryDuplicateRowsWithCheckpoint(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	dupPayload := sampleSpanJSON(t, "dup-span")
	fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: dupPayload},
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: dupPayload},
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: dupPayload},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}

	// 1. Uninterrupted checkpointed run over three identical rows must replay all three.
	dir1 := t.TempDir()
	opts1 := Options{Checkpoint: &CheckpointConfig{Path: filepath.Join(dir1, "uninterrupted.ckpt")}}
	sink1 := &recordingSink{}
	sum1, err := ReplayBigQuery(context.Background(), src, sink1, opts1, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("uninterrupted ReplayBigQuery: %v", err)
	}
	if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum1 != want {
		t.Errorf("uninterrupted summary = %+v, want %+v", sum1, want)
	}
	if len(sink1.names) != 3 {
		t.Errorf("uninterrupted replayed %d spans, want 3", len(sink1.names))
	}
	st1 := readCheckpointFile(t, opts1.Checkpoint.Path)
	assertCursor(t, st1, base.UnixMicro(), 77, 2, fake.rows[2].canonicalKey(), 3)

	// 2. Interrupted run failing transiently on the 2nd duplicate, followed by a resume,
	// must deliver all three duplicate rows across the two runs without dropping any.
	dir2 := t.TempDir()
	opts2 := Options{Checkpoint: &CheckpointConfig{Path: filepath.Join(dir2, "interrupted.ckpt")}}
	flaky := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return errors.New("transient OTLP timeout")
		}
		return nil
	}}
	_, err = ReplayBigQuery(context.Background(), src, flaky, opts2, bigQueryTestOptions(srv)...)
	if err == nil || !strings.Contains(err.Error(), "transient OTLP timeout") {
		t.Fatalf("first interrupted run = %v, want transient OTLP timeout", err)
	}
	st2 := readCheckpointFile(t, opts2.Checkpoint.Path)
	assertCursor(t, st2, base.UnixMicro(), 77, 0, fake.rows[0].canonicalKey(), 1)

	resumed := &recordingSink{}
	sum2, err := ReplayBigQuery(context.Background(), src, resumed, opts2, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("resumed duplicate run: %v", err)
	}
	if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum2 != want {
		t.Errorf("resumed duplicate summary = %+v, want %+v", sum2, want)
	}
	if total := len(flaky.names) + len(resumed.names); total != 3 {
		t.Errorf("total replayed duplicates across both runs = %d, want 3", total)
	}
	st2 = readCheckpointFile(t, opts2.Checkpoint.Path)
	assertCursor(t, st2, base.UnixMicro(), 77, 2, fake.rows[2].canonicalKey(), 3)

	// 3. Two distinct rows sharing (ingest_time, row_fp) must receive a
	// deterministic row_ord across restarts even when the underlying table scan
	// order reverses between the initial query and the resumed query.
	spanA := sampleSpanJSON(t, "collision-span-A")
	spanB := sampleSpanJSON(t, "collision-span-B")
	fakeCollision := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanA},
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanB},
	}}
	srvCollision := httptest.NewServer(fakeCollision)
	defer srvCollision.Close()

	dir3 := t.TempDir()
	opts3 := Options{Checkpoint: &CheckpointConfig{Path: filepath.Join(dir3, "collision.ckpt")}}
	flakyCollision := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return errors.New("transient collision timeout")
		}
		return nil
	}}
	_, err = ReplayBigQuery(context.Background(), src, flakyCollision, opts3, bigQueryTestOptions(srvCollision)...)
	if err == nil || !strings.Contains(err.Error(), "transient collision timeout") {
		t.Fatalf("first collision run = %v, want transient collision timeout", err)
	}
	if !slices.Equal(flakyCollision.names, []string{"collision-span-A"}) {
		t.Fatalf("first collision run exported %v, want [collision-span-A]", flakyCollision.names)
	}

	// Reverse the physical table scan order before resuming.
	fakeCollision.mu.Lock()
	fakeCollision.rows[0], fakeCollision.rows[1] = fakeCollision.rows[1], fakeCollision.rows[0]
	fakeCollision.mu.Unlock()

	resumedCollision := &recordingSink{}
	sum3, err := ReplayBigQuery(context.Background(), src, resumedCollision, opts3, bigQueryTestOptions(srvCollision)...)
	if err != nil {
		t.Fatalf("resumed collision run: %v", err)
	}
	if want := (Summary{TotalRead: 1, Matched: 1, ReplayedSpans: 1}); sum3 != want {
		t.Errorf("resumed collision summary = %+v, want %+v", sum3, want)
	}
	if !slices.Equal(resumedCollision.names, []string{"collision-span-B"}) {
		t.Errorf("resumed collision run exported %v, want [collision-span-B] (must not re-export collision-span-A or drop collision-span-B)", resumedCollision.names)
	}
}

// TestReplayBigQueryLegacyCursorRewind tests that a legacy v1 BigQuery
// checkpoint (written before canonical row_key ordering, with
// CursorOrderVersion 0 and no CanonicalRowKey) is detected and rewound so the
// whole (ingest_time, row_fp) group is replayed at-least-once, instead of
// skipping rows whose row_ord changed under the new ordering.
//
// Scenario: two distinct rows A and B share (ingest_time, row_fp). Under the
// old unordered ROW_NUMBER(), B got ordinal 0 and A got ordinal 1. The first
// run delivered B (ordinal 0) and failed on A, saving duplicate_ordinal=0.
// Under the new canonical ordering A gets ordinal 0 and B gets ordinal 1, so
// the old cursor's duplicate_ordinal=0 would mean "skip A, re-export B" —
// silent data loss of A. The rewind sets duplicate_ordinal=-1 so both rows
// are replayed.
func TestReplayBigQueryLegacyCursorRewind(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	spanA := sampleSpanJSON(t, "legacy-span-A")
	spanB := sampleSpanJSON(t, "legacy-span-B")
	fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanA},
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanB},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}
	dir := t.TempDir()
	ckptPath := filepath.Join(dir, "legacy.ckpt")

	// Write a legacy v1 checkpoint: the old writer delivered row B
	// (ordinal 0 under the old unordered ROW_NUMBER()) and failed on A,
	// saving duplicate_ordinal=0 with no cursor_order_version or
	// canonical_row_key fields.
	legacy := checkpointState{
		Version: checkpointVersion,
		Kind:    checkpointKindBigQuery,
		Source:  "bigquery:proj.ds.dead_letters",
		Filter:  (Filter{}).fingerprint(),
		Cursor: &bigQueryCursor{
			IngestTimeMicros: base.UnixMicro(),
			RowFingerprint:   77,
			DuplicateOrdinal: 0,
			// CursorOrderVersion is 0 (zero value), CanonicalRowKey is "".
		},
		Handled: 1,
	}
	data, err := json.MarshalIndent(legacy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(ckptPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	// Resuming under the new code must rewind the legacy cursor and
	// replay both rows (A and B) at-least-once, not skip A.
	opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath, Source: "bigquery:proj.ds.dead_letters"}}
	sink := &recordingSink{}
	sum, err := ReplayBigQuery(context.Background(), src, sink, opts, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("resumed legacy run: %v", err)
	}
	// Both rows should be replayed (at-least-once), not just B.
	if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
		t.Errorf("legacy resume summary = %+v, want %+v (rewind must replay the whole group)", sum, want)
	}
	if len(sink.names) != 2 {
		t.Errorf("legacy resume replayed %d spans, want 2 (both A and B)", len(sink.names))
	}
	// The resumed checkpoint must now be a v2 cursor at the last row.
	st := readCheckpointFile(t, ckptPath)
	assertCursor(t, st, base.UnixMicro(), 77, 1, fake.rows[1].canonicalKey(), 3) // 1 legacy + 2 replayed
}

// TestReplayBigQueryV2CursorResume tests that a v2 BigQuery cursor written by
// ReplayBigQuery (with CursorOrderVersion=2 and the returned row's exact
// CanonicalRowKey) resumes after the last handled row without rewinding.
func TestReplayBigQueryV2CursorResume(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	spanA := sampleSpanJSON(t, "v2-span-A-é")
	spanB := sampleSpanJSON(t, "v2-span-B")
	spanC := sampleSpanJSON(t, "v2-span-C")
	fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanA},
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanB},
		{ingest: base.Add(time.Second), fp: 88, signal: "spans", code: "OVERSIZE_ROW", payload: spanC},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}
	dir := t.TempDir()
	ckptPath := filepath.Join(dir, "v2.ckpt")
	opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath, Source: "bigquery:proj.ds.dead_letters"}}

	// Run 1: real ReplayBigQuery writer delivers A (ordinal 0) and fails
	// transiently on B (ordinal 1), writing a v2 checkpoint at A.
	flaky := &recordingSink{fail: func(call int) error {
		if call == 2 {
			return errors.New("transient v2 sink error")
		}
		return nil
	}}
	if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil || !strings.Contains(err.Error(), "transient v2 sink error") {
		t.Fatalf("first v2 run = %v, want transient v2 sink error", err)
	}
	if !slices.Equal(flaky.names, []string{"v2-span-A-é"}) {
		t.Fatalf("first v2 run exported %v, want [v2-span-A-é]", flaky.names)
	}
	st1 := readCheckpointFile(t, ckptPath)
	assertCursor(t, st1, base.UnixMicro(), 77, 0, fake.rows[0].canonicalKey(), 1)

	// Resuming must skip A (already handled) and replay B and C.
	sink := &recordingSink{}
	sum, err := ReplayBigQuery(context.Background(), src, sink, opts, bigQueryTestOptions(srv)...)
	if err != nil {
		t.Fatalf("resumed v2 run: %v", err)
	}
	if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
		t.Errorf("v2 resume summary = %+v, want %+v (only B and C, not A)", sum, want)
	}
	if !slices.Equal(sink.names, []string{"v2-span-B", "v2-span-C"}) {
		t.Errorf("v2 resume replayed %v, want [v2-span-B, v2-span-C] (A must be skipped)", sink.names)
	}
	st := readCheckpointFile(t, ckptPath)
	assertCursor(t, st, base.Add(time.Second).UnixMicro(), 88, 0, fake.rows[2].canonicalKey(), 3) // 1 prior + 2 replayed
}

// TestReplayBigQueryV2ChangedCollisionGroup verifies that when a collision or
// duplicate group's membership changes between runs (for example, an already
// acknowledged row is deleted from the quarantine table) or a checkpoint carries
// a canonical_row_key that does not match the row at duplicate_ordinal, both
// the server query and the client-side reconciliation rewind that group so no
// undelivered row is skipped.
func TestReplayBigQueryV2ChangedCollisionGroup(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}

	t.Run("deleted acknowledged row in collision group delivers remaining row", func(t *testing.T) {
		spanEarly := sampleSpanJSON(t, "early-span")
		spanA := sampleSpanJSON(t, "collision-span-A")
		spanB := sampleSpanJSON(t, "collision-span-B")
		spanLater := sampleSpanJSON(t, "later-span")
		rowEarly := fakeQuarantineRow{ingest: base.Add(-time.Second), fp: 10, signal: "spans", code: "OVERSIZE_ROW", payload: spanEarly}
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanA}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: spanB}
		rowLater := fakeQuarantineRow{ingest: base.Add(time.Second), fp: 88, signal: "spans", code: "OVERSIZE_ROW", payload: spanLater}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowEarly, rowA, rowB, rowLater}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "deleted_a.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}

		// Run 1 delivers rowEarly and rowA (ord=0 in (base, 77)) and fails transiently on rowB (ord=1).
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on B")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil || !strings.Contains(err.Error(), "transient failure on B") {
			t.Fatalf("first run = %v, want transient failure on B", err)
		}
		if !slices.Equal(flaky.names, []string{"early-span", "collision-span-A"}) {
			t.Fatalf("first run exported %v, want [early-span collision-span-A]", flaky.names)
		}
		st1 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st1, base.UnixMicro(), 77, 0, rowA.canonicalKey(), 2)

		// Delete already-handled rowA from the quarantine table before resuming.
		// rowB now shifts from ord=1 to ord=0 inside (base, 77).
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowEarly, rowB, rowLater}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after deleting A: %v", err)
		}
		if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-B", "later-span"}) {
			t.Errorf("resumed run exported %v, want [collision-span-B later-span] (B must not be skipped and early-span must stay excluded)", resumed.names)
		}
		st2 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st2, base.Add(time.Second).UnixMicro(), 88, 0, rowLater.canonicalKey(), 4)
	})

	t.Run("deleted two acknowledged rows in 3-way collision group delivers third row", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB, rowC}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "deleted_ab.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on C")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on C")
		}
		assertCursor(t, readCheckpointFile(t, ckptPath), base.UnixMicro(), 77, 1, rowB.canonicalKey(), 2)

		// Delete both A and B so C shifts from ord=2 to ord=0.
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowC}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after deleting A and B: %v", err)
		}
		if want := (Summary{TotalRead: 1, Matched: 1, ReplayedSpans: 1}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-C"}) {
			t.Errorf("resumed run exported %v, want [collision-span-C]", resumed.names)
		}
	})

	t.Run("deleted copy in 3-way duplicate group rewinds and delivers remaining duplicate", func(t *testing.T) {
		dupPayload := sampleSpanJSON(t, "dup-span-X")
		rowX := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: dupPayload}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowX, rowX, rowX}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "dup_deleted.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		flaky := &recordingSink{fail: func(call int) error {
			if call == 2 {
				return errors.New("transient failure on 2nd duplicate")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on 2nd duplicate")
		}
		st1 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st1, base.UnixMicro(), 77, 0, rowX.canonicalKey(), 1)
		if st1.Cursor.GroupCount != 3 {
			t.Fatalf("first run cursor group_count = %d, want 3", st1.Cursor.GroupCount)
		}

		// Delete one of the 3 identical copies so 2 copies remain ([X, X]).
		// Even though ord=0 still has key(X) and prefix_sha256 H(X), group_size
		// dropped from 3 to 2, so the boundary group must rewind and replay [X, X].
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowX, rowX}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after deleting one duplicate copy: %v", err)
		}
		if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"dup-span-X", "dup-span-X"}) {
			t.Errorf("resumed run exported %v, want [dup-span-X dup-span-X]", resumed.names)
		}
		st2 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st2, base.UnixMicro(), 77, 1, rowX.canonicalKey(), 3)
		if st2.Cursor.GroupCount != 2 {
			t.Errorf("resumed cursor group_count = %d, want 2", st2.Cursor.GroupCount)
		}

		// A second resume against the unchanged [X, X] group must be quiet.
		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), src, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet second resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("deleted A and inserted D between A and B in 3-way collision group rewinds and delivers D B C", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowD := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-D")}
		if rowA.canonicalKey() >= rowD.canonicalKey() || rowD.canonicalKey() >= rowB.canonicalKey() || rowB.canonicalKey() >= rowC.canonicalKey() {
			t.Fatalf("canonical keys not ordered A < D < B < C")
		}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB, rowC}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "replaced_ad.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on C")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on C")
		}
		assertCursor(t, readCheckpointFile(t, ckptPath), base.UnixMicro(), 77, 1, rowB.canonicalKey(), 2)

		// Delete A and insert D (A < D < B) so the group is [D, B, C].
		// Even though B still sits at ord=1 and group_size is still 3, the
		// prefix_sha256 for 0..1 changed from H(A, B) to H(D, B), so the group
		// must rewind and deliver [D, B, C] without losing D.
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowD, rowB, rowC}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after replacing A with D: %v", err)
		}
		if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-B", "collision-span-C", "collision-span-D"}) {
			t.Errorf("resumed run exported %v, want [collision-span-B collision-span-C collision-span-D]", resumed.names)
		}

		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), src, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet second resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("deleted A and inserted X before A in 3-way collision group rewinds and delivers X B C", func(t *testing.T) {
		rowX := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-0")}
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		if rowX.canonicalKey() >= rowA.canonicalKey() || rowA.canonicalKey() >= rowB.canonicalKey() || rowB.canonicalKey() >= rowC.canonicalKey() {
			t.Fatalf("canonical keys not ordered X < A < B < C")
		}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB, rowC}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "replaced_ax.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on C")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), src, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on C")
		}
		assertCursor(t, readCheckpointFile(t, ckptPath), base.UnixMicro(), 77, 1, rowB.canonicalKey(), 2)

		// Delete A and insert X (X < A < B) so the group is [X, B, C].
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowX, rowB, rowC}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after replacing A with X: %v", err)
		}
		if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-0", "collision-span-B", "collision-span-C"}) {
			t.Errorf("resumed run exported %v, want [collision-span-0 collision-span-B collision-span-C]", resumed.names)
		}

		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), src, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet second resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("paginated insertion before A after checkpointing B rewinds group across pages", func(t *testing.T) {
		rowX := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-0")}
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		rowLater := fakeQuarantineRow{ingest: base.Add(time.Second), fp: 88, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "later-span")}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB, rowC, rowLater}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		pagedSrc := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters", PageSize: 1}
		ckptPath := filepath.Join(t.TempDir(), "paged_insert.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on C")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on C")
		}
		assertCursor(t, readCheckpointFile(t, ckptPath), base.UnixMicro(), 77, 1, rowB.canonicalKey(), 2)

		// Insert X < A so the boundary group becomes [X, A, B, C] (4 rows).
		// Without rp.cp.rewindCursorGroup(), X (at ord=0 < 1 with key(X) < key(B))
		// would be treated as handled by pos.after(cursorAtB) and silently dropped!
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowX, rowA, rowB, rowC, rowLater}
		fake.mu.Unlock()

		// Mid-rewind failure after delivering X (call 1) and failing on A (call 2)
		// must save the new 4-row group's cursor at X (ord=0, GroupCount=4).
		midFlaky := &recordingSink{fail: func(call int) error {
			if call == 2 {
				return errors.New("transient failure during rewind on A")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, midFlaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("mid-rewind run succeeded, want transient failure on A")
		}
		if !slices.Equal(midFlaky.names, []string{"collision-span-0"}) {
			t.Fatalf("mid-rewind run exported %v, want [collision-span-0] (X must not be skipped)", midFlaky.names)
		}
		stMid := readCheckpointFile(t, ckptPath)
		assertCursor(t, stMid, base.UnixMicro(), 77, 0, rowX.canonicalKey(), 3)
		if stMid.Cursor.GroupCount != 4 {
			t.Fatalf("mid-rewind cursor group_count = %d, want 4", stMid.Cursor.GroupCount)
		}

		// Resuming after the mid-rewind failure must skip X (already delivered in
		// the 4-row group) and deliver [A, B, C, later-span].
		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), pagedSrc, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after mid-rewind failure: %v", err)
		}
		if want := (Summary{TotalRead: 4, Matched: 4, ReplayedSpans: 4}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-A", "collision-span-B", "collision-span-C", "later-span"}) {
			t.Errorf("resumed run exported %v, want [collision-span-A collision-span-B collision-span-C later-span]", resumed.names)
		}

		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), pagedSrc, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet final resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("deleted duplicate A0 and inserted C after B in [A0, A1, B] rewinds and delivers A1 B C across pages", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		if rowA.canonicalKey() >= rowB.canonicalKey() || rowB.canonicalKey() >= rowC.canonicalKey() {
			t.Fatalf("canonical keys not ordered A < B < C")
		}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowA, rowB}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		pagedSrc := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters", PageSize: 1}
		ckptPath := filepath.Join(t.TempDir(), "repro_a0_a1_b.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		// Run 1 delivers A0 (ord=0) and fails transiently on A1 (ord=1).
		flaky := &recordingSink{fail: func(call int) error {
			if call == 2 {
				return errors.New("transient failure on A1")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on A1")
		}
		if !slices.Equal(flaky.names, []string{"collision-span-A"}) {
			t.Fatalf("first run exported %v, want [collision-span-A]", flaky.names)
		}
		st1 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st1, base.UnixMicro(), 77, 0, rowA.canonicalKey(), 1)
		if st1.Cursor.GroupCount != 3 {
			t.Fatalf("first run cursor group_count = %d, want 3", st1.Cursor.GroupCount)
		}

		// Delete already-delivered A0 and insert C > B so the group is [A1, B, C].
		// At ord=0, A1 still has key(A), group_size=3, and prefix_sha256=H(A);
		// only group_sha256 changes from H(A, A, B) to H(A, B, C).
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowA, rowB, rowC}
		fake.mu.Unlock()

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), pagedSrc, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after [A0, A1, B] -> [A1, B, C]: %v", err)
		}
		if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-A", "collision-span-B", "collision-span-C"}) {
			t.Errorf("resumed run exported %v, want [collision-span-A collision-span-B collision-span-C] (A1 must not be skipped)", resumed.names)
		}

		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), pagedSrc, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet final resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("deleted duplicate B0 and inserted D after C in [A, B0, B1, C] rewinds across pages and survives mid-rewind failure", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		rowD := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-D")}
		if rowA.canonicalKey() >= rowB.canonicalKey() || rowB.canonicalKey() >= rowC.canonicalKey() || rowC.canonicalKey() >= rowD.canonicalKey() {
			t.Fatalf("canonical keys not ordered A < B < C < D")
		}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB, rowB, rowC}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		pagedSrc := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters", PageSize: 1}
		ckptPath := filepath.Join(t.TempDir(), "repro_a_b0_b1_c.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		// Run 1 delivers A (ord=0) and B0 (ord=1) and fails transiently on B1 (ord=2).
		flaky := &recordingSink{fail: func(call int) error {
			if call == 3 {
				return errors.New("transient failure on B1")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on B1")
		}
		if !slices.Equal(flaky.names, []string{"collision-span-A", "collision-span-B"}) {
			t.Fatalf("first run exported %v, want [collision-span-A collision-span-B]", flaky.names)
		}
		st1 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st1, base.UnixMicro(), 77, 1, rowB.canonicalKey(), 2)
		if st1.Cursor.GroupCount != 4 {
			t.Fatalf("first run cursor group_count = %d, want 4", st1.Cursor.GroupCount)
		}

		// Delete already-delivered B0 and insert D > C so the group is [A, B1, C, D].
		// At ord=1, B1 still has key(B), group_size=4, and prefix_sha256=H(A, B);
		// only group_sha256 changes from H(A, B, B, C) to H(A, B, C, D).
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowA, rowB, rowC, rowD}
		fake.mu.Unlock()

		// Mid-rewind failure after delivering A (call 1) and failing on B1 (call 2)
		// must save the new 4-row group's cursor at A (ord=0, GroupCount=4, GroupSHA256=H(A,B,C,D)).
		midFlaky := &recordingSink{fail: func(call int) error {
			if call == 2 {
				return errors.New("transient failure during rewind on B1")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, midFlaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("mid-rewind run succeeded, want transient failure on B1")
		}
		if !slices.Equal(midFlaky.names, []string{"collision-span-A"}) {
			t.Fatalf("mid-rewind run exported %v, want [collision-span-A]", midFlaky.names)
		}
		stMid := readCheckpointFile(t, ckptPath)
		assertCursor(t, stMid, base.UnixMicro(), 77, 0, rowA.canonicalKey(), 3)
		if stMid.Cursor.GroupCount != 4 {
			t.Fatalf("mid-rewind cursor group_count = %d, want 4", stMid.Cursor.GroupCount)
		}

		// Resuming after the mid-rewind failure skips A and delivers [B1, C, D].
		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), pagedSrc, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after mid-rewind failure: %v", err)
		}
		if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-B", "collision-span-C", "collision-span-D"}) {
			t.Errorf("resumed run exported %v, want [collision-span-B collision-span-C collision-span-D] (B1 must not be skipped)", resumed.names)
		}

		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), pagedSrc, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet final resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("pending row B in [A, B] moving to earlier fingerprint fp=76 across pages rewinds bucket and delivers B A later", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB77 := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowLater := fakeQuarantineRow{ingest: base.Add(time.Second), fp: 88, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "later-span")}
		if rowA.canonicalKey() >= rowB77.canonicalKey() {
			t.Fatalf("canonical keys not ordered A < B")
		}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB77, rowLater}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		pagedSrc := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters", PageSize: 1}
		ckptPath := filepath.Join(t.TempDir(), "repro_cross_fp_76.ckpt")
		opts := Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}
		// 1. Same-timestamp group [A(fp=77), B(fp=77)] plus a later row.
		// Deliver A (ord=0), fail transiently on B (ord=1), leaving a valid v2
		// checkpoint at A with full count/prefix/group digest.
		flaky := &recordingSink{fail: func(call int) error {
			if call == 2 {
				return errors.New("transient failure on B")
			}
			return nil
		}}
		if _, err := ReplayBigQuery(context.Background(), pagedSrc, flaky, opts, bigQueryTestOptions(srv)...); err == nil {
			t.Fatal("first run succeeded, want transient failure on B")
		}
		if !slices.Equal(flaky.names, []string{"collision-span-A"}) {
			t.Fatalf("first run exported %v, want [collision-span-A]", flaky.names)
		}
		st1 := readCheckpointFile(t, ckptPath)
		assertCursor(t, st1, base.UnixMicro(), 77, 0, rowA.canonicalKey(), 1)
		if st1.Cursor.GroupCount != 2 {
			t.Fatalf("first run cursor group_count = %d, want 2", st1.Cursor.GroupCount)
		}

		// 2. Before resume, change B so it is still a pending quarantine row at the
		// same timestamp but now has row_fp=76 (earlier than cursor row_fp=77).
		rowB76 := rowB77
		rowB76.fp = 76
		fake.mu.Lock()
		fake.rows = []fakeQuarantineRow{rowA, rowB76, rowLater}
		fake.mu.Unlock()

		// 3. Resume: the fp=77 group's count/digest mismatch rewinds the entire
		// cursor ingest_time bucket so B(fp=76), A(fp=77), and later-span are all
		// delivered (in canonical (ingest_time, row_fp, row_ord) order: B, A, later).
		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), pagedSrc, resumed, opts, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed run after B moved from fp=77 to fp=76: %v", err)
		}
		if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
			t.Errorf("resumed summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-B", "collision-span-A", "later-span"}) {
			t.Errorf("resumed run exported %v, want [collision-span-B collision-span-A later-span] (mutated B at fp=76 must not be skipped)", resumed.names)
		}

		// 4. Resume again: TotalRead=0, zero exports, error=nil.
		quiet := &recordingSink{}
		sumQuiet, err := ReplayBigQuery(context.Background(), pagedSrc, quiet, opts, bigQueryTestOptions(srv)...)
		if err != nil || sumQuiet != (Summary{}) || len(quiet.names) != 0 {
			t.Errorf("quiet final resume = (%+v, %v, %v), want TotalRead=0 and 0 exports", sumQuiet, err, quiet.names)
		}
	})

	t.Run("stamped legacy cursor with v2 and B key at ord 0 rewinds group and delivers A and B", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowA, rowB}}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		ckptPath := filepath.Join(t.TempDir(), "stamped_v2.ckpt")
		// Under unordered legacy ROW_NUMBER(), B got ord=0 and A got ord=1.
		// Even if that checkpoint is stamped with cursor_order_version=2 and
		// B's canonical_row_key at duplicate_ordinal=0, row_ord=0 in canonical
		// order holds A's key != B's key, so the group must rewind and deliver both.
		stamped := checkpointState{
			Version: checkpointVersion,
			Kind:    checkpointKindBigQuery,
			Source:  "bigquery:proj.ds.dead_letters",
			Filter:  (Filter{}).fingerprint(),
			Cursor: &bigQueryCursor{
				IngestTimeMicros:   base.UnixMicro(),
				RowFingerprint:     77,
				DuplicateOrdinal:   0,
				CursorOrderVersion: cursorOrderVersionCanonical,
				CanonicalRowKey:    rowB.canonicalKey(),
			},
			Handled: 1,
		}
		raw, err := json.MarshalIndent(stamped, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ckptPath, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}

		resumed := &recordingSink{}
		sum, err := ReplayBigQuery(context.Background(), src, resumed, Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}, bigQueryTestOptions(srv)...)
		if err != nil {
			t.Fatalf("resumed stamped v2 run: %v", err)
		}
		if want := (Summary{TotalRead: 2, Matched: 2, ReplayedSpans: 2}); sum != want {
			t.Errorf("stamped v2 summary = %+v, want %+v", sum, want)
		}
		if !slices.Equal(resumed.names, []string{"collision-span-A", "collision-span-B"}) {
			t.Errorf("stamped v2 run exported %v, want [collision-span-A collision-span-B] (A must not be lost)", resumed.names)
		}
	})

	t.Run("client-side position comparison and boundary reconciliation reject mismatched key at ordinal", func(t *testing.T) {
		rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-A")}
		rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-B")}
		rowC := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "collision-span-C")}
		cursorAtA := bigQueryCursor{
			IngestTimeMicros:   base.UnixMicro(),
			RowFingerprint:     77,
			DuplicateOrdinal:   0,
			CursorOrderVersion: cursorOrderVersionCanonical,
			CanonicalRowKey:    rowA.canonicalKey(),
			GroupCount:         2,
			PrefixSHA256:       evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"),
			GroupSHA256:        evalSQLWindowDigest([]string{rowA.canonicalKey(), rowB.canonicalKey()}, "BYTE_LENGTH", ":"),
		}
		// If A is deleted and B shifts to ordinal 0, B's position at ordinal 0
		// must still sort after cursorAtA on the client side.
		posBAtZero := recordPosition{
			ingestMicros: base.UnixMicro(),
			fingerprint:  77,
			ordinal:      0,
			canonicalKey: rowB.canonicalKey(),
		}
		if !posBAtZero.after(cursorAtA) {
			t.Errorf("posBAtZero.after(cursorAtA) = false, want true when B shifted to ordinal 0 after A was deleted")
		}
		// Conversely, A itself at ordinal 0 was already handled.
		posAAtZero := recordPosition{
			ingestMicros: base.UnixMicro(),
			fingerprint:  77,
			ordinal:      0,
			canonicalKey: rowA.canonicalKey(),
		}
		if posAAtZero.after(cursorAtA) {
			t.Errorf("posAAtZero.after(cursorAtA) = true, want false for already-handled row A")
		}

		// Directly exercise queryRows.reconcileBoundaryGroup on both a matching
		// 2-row group [A, B] and mutated groups [B], [A], and [A, C].
		qRowA := quarantineRow{pos: posAAtZero}
		fields := []*bigqueryapi.TableFieldSchema{
			{Name: "ingest_time_us", Type: "INTEGER"},
			{Name: "row_fp", Type: "INTEGER"},
			{Name: "row_ord", Type: "INTEGER"},
			{Name: "row_key", Type: "STRING"},
		}
		pageRowBAtOne := &bigqueryapi.TableRow{
			F: []*bigqueryapi.TableCell{
				{V: strconv.FormatInt(base.UnixMicro(), 10)},
				{V: "77"},
				{V: "1"},
				{V: rowB.canonicalKey()},
			},
		}
		qrMatch := &queryRows{started: true, fields: fields, page: []*bigqueryapi.TableRow{pageRowBAtOne}}
		matched, err := qrMatch.reconcileBoundaryGroup(context.Background(), qRowA, cursorAtA)
		if err != nil || !matched {
			t.Errorf("reconcileBoundaryGroup([A, B], cursorAtA) = (%v, %v), want (true, nil)", matched, err)
		}

		pageRowCAtOne := &bigqueryapi.TableRow{
			F: []*bigqueryapi.TableCell{
				{V: strconv.FormatInt(base.UnixMicro(), 10)},
				{V: "77"},
				{V: "1"},
				{V: rowC.canonicalKey()},
			},
		}
		qrGroupSHAMismatch := &queryRows{started: true, fields: fields, page: []*bigqueryapi.TableRow{pageRowCAtOne}}
		matched, err = qrGroupSHAMismatch.reconcileBoundaryGroup(context.Background(), qRowA, cursorAtA)
		if err != nil || matched {
			t.Errorf("reconcileBoundaryGroup([A, C] with GroupSHA256=H(A,C) != H(A,B), cursorAtA) = (%v, %v), want (false, nil)", matched, err)
		}

		qrKeyMismatch := &queryRows{started: true}
		matched, err = qrKeyMismatch.reconcileBoundaryGroup(context.Background(), quarantineRow{pos: posBAtZero}, cursorAtA)
		if err != nil || matched {
			t.Errorf("reconcileBoundaryGroup([B], cursorAtA) = (%v, %v), want (false, nil)", matched, err)
		}

		qrCountMismatch := &queryRows{started: true}
		matched, err = qrCountMismatch.reconcileBoundaryGroup(context.Background(), qRowA, cursorAtA)
		if err != nil || matched {
			t.Errorf("reconcileBoundaryGroup([A] with len=1 != GroupCount=2, cursorAtA) = (%v, %v), want (false, nil)", matched, err)
		}
	})
}

// TestReplayBigQueryCursorVersionAndKeyValidation tests all branches of
// cursor_order_version (<0, 0, 1, 2 with empty key, 2 with malformed key, >2).
func TestReplayBigQueryCursorVersionAndKeyValidation(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	rowEarly := fakeQuarantineRow{ingest: base.Add(-time.Second), fp: 10, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "early-span")}
	rowA := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "group-span-A")}
	rowB := fakeQuarantineRow{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "group-span-B")}
	rowLater := fakeQuarantineRow{ingest: base.Add(time.Second), fp: 88, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "later-span")}
	src := BigQuerySource{Project: "proj", Dataset: "ds", Table: "dead_letters"}

	writeCkpt := func(t *testing.T, c bigQueryCursor) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "cursor.ckpt")
		st := checkpointState{
			Version: checkpointVersion,
			Kind:    checkpointKindBigQuery,
			Source:  "bigquery:proj.ds.dead_letters",
			Filter:  (Filter{}).fingerprint(),
			Cursor:  &c,
			Handled: 1,
		}
		raw, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// 1. Invalid versions (<0, >2) and malformed v2 keys must be rejected before querying.
	for _, tc := range []struct {
		name string
		cur  bigQueryCursor
		want string
	}{
		{
			name: "negative cursor_order_version -1",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: -1, CanonicalRowKey: rowA.canonicalKey()},
			want: "unsupported cursor_order_version -1",
		},
		{
			name: "unknown cursor_order_version 99 with bogus key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 99, CanonicalRowKey: "not-a-row"},
			want: "unsupported cursor_order_version 99",
		},
		{
			name: "unknown cursor_order_version 99 with valid key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 99, CanonicalRowKey: rowA.canonicalKey()},
			want: "unsupported cursor_order_version 99",
		},
		{
			name: "v2 cursor with non-JSON canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: "not-a-row"},
			want: "invalid canonical_row_key",
		},
		{
			name: "v2 cursor with incomplete JSON object canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":"spans"}`},
			want: "invalid canonical_row_key",
		},
		{
			name: "v2 cursor with unexpected field in canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":"spans","error_code":"OVERSIZE_ROW","error_message":"rejected","raw_payload":"{}","extra":"x"}`},
			want: "invalid canonical_row_key",
		},
		{
			name: "v2 cursor with null signal in canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":null,"error_code":"OVERSIZE_ROW","error_message":"rejected","raw_payload":"{}"}`},
			want: `non-nullable field "signal" must not be null`,
		},
		{
			name: "v2 cursor with null error_code in canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":"spans","error_code":null,"error_message":"rejected","raw_payload":"{}"}`},
			want: `non-nullable field "error_code" must not be null`,
		},
		{
			name: "v2 cursor with null error_message in canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":"spans","error_code":"OVERSIZE_ROW","error_message":null,"raw_payload":"{}"}`},
			want: `non-nullable field "error_message" must not be null`,
		},
		{
			name: "v2 cursor with missing error_message in canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: `{"signal":"spans","error_code":"OVERSIZE_ROW","raw_payload":"{}"}`},
			want: `missing required field "error_message"`,
		},
		{
			name: "v2 cursor with empty canonical_row_key and non-zero group_count",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: "", GroupCount: 3},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with empty canonical_row_key and non-empty prefix_sha256",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: "", PrefixSHA256: "not-hex"},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with empty canonical_row_key and non-empty group_sha256",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: "", GroupSHA256: "not-hex"},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with empty canonical_row_key and all three group metadata fields set",
			cur: bigQueryCursor{
				IngestTimeMicros:   base.UnixMicro(),
				RowFingerprint:     77,
				DuplicateOrdinal:   0,
				CursorOrderVersion: 2,
				CanonicalRowKey:    "",
				GroupCount:         1,
				PrefixSHA256:       evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"),
				GroupSHA256:        evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"),
			},
			want: "group metadata with an empty canonical_row_key",
		},
		{
			name: "v2 cursor with only group_count set",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), GroupCount: 2},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with only prefix_sha256 set",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), PrefixSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":")},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with only group_sha256 set",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), GroupSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":")},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with group_count and prefix_sha256 without group_sha256",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), GroupCount: 2, PrefixSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":")},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with group_count and group_sha256 without prefix_sha256",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), GroupCount: 2, GroupSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":")},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with prefix_sha256 and group_sha256 without group_count",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: rowA.canonicalKey(), PrefixSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"), GroupSHA256: evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":")},
			want: "mismatched group_count",
		},
		{
			name: "v2 cursor with group_count <= duplicate_ordinal",
			cur: bigQueryCursor{
				IngestTimeMicros:   base.UnixMicro(),
				RowFingerprint:     77,
				DuplicateOrdinal:   2,
				CursorOrderVersion: 2,
				CanonicalRowKey:    rowA.canonicalKey(),
				GroupCount:         2,
				PrefixSHA256:       evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"),
				GroupSHA256:        evalSQLWindowDigest([]string{rowA.canonicalKey(), rowB.canonicalKey()}, "BYTE_LENGTH", ":"),
			},
			want: "group_count 2 <= duplicate_ordinal 2",
		},
		{
			name: "v2 cursor with invalid prefix_sha256",
			cur: bigQueryCursor{
				IngestTimeMicros:   base.UnixMicro(),
				RowFingerprint:     77,
				DuplicateOrdinal:   0,
				CursorOrderVersion: 2,
				CanonicalRowKey:    rowA.canonicalKey(),
				GroupCount:         2,
				PrefixSHA256:       "not-a-sha256",
				GroupSHA256:        evalSQLWindowDigest([]string{rowA.canonicalKey(), rowB.canonicalKey()}, "BYTE_LENGTH", ":"),
			},
			want: "invalid prefix_sha256",
		},
		{
			name: "v2 cursor with invalid group_sha256",
			cur: bigQueryCursor{
				IngestTimeMicros:   base.UnixMicro(),
				RowFingerprint:     77,
				DuplicateOrdinal:   0,
				CursorOrderVersion: 2,
				CanonicalRowKey:    rowA.canonicalKey(),
				GroupCount:         2,
				PrefixSHA256:       evalSQLWindowDigest([]string{rowA.canonicalKey()}, "BYTE_LENGTH", ":"),
				GroupSHA256:        "not-a-sha256",
			},
			want: "invalid group_sha256",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowEarly, rowA, rowB, rowLater}}
			srv := httptest.NewServer(fake)
			defer srv.Close()

			ckptPath := writeCkpt(t, tc.cur)
			sink := &recordingSink{}
			_, err := ReplayBigQuery(context.Background(), src, sink, Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}, bigQueryTestOptions(srv)...)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ReplayBigQuery() error = %v, want substring %q", err, tc.want)
			}
			if len(fake.requests) != 0 || len(sink.names) != 0 {
				t.Errorf("queries=%d exported=%v, want 0 queries and 0 exports before rejecting checkpoint", len(fake.requests), sink.names)
			}
		})
	}

	// 2. Legacy versions (0 and 1) and v2 with empty key must rewind only the
	// cursor's (ingest_time, row_fp) group, excluding earlier groups and
	// replaying the cursor's group + later groups once.
	for _, tc := range []struct {
		name string
		cur  bigQueryCursor
	}{
		{
			name: "legacy version 0",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 0},
		},
		{
			name: "legacy version 1",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 1},
		},
		{
			name: "v2 with empty canonical_row_key",
			cur:  bigQueryCursor{IngestTimeMicros: base.UnixMicro(), RowFingerprint: 77, DuplicateOrdinal: 0, CursorOrderVersion: 2, CanonicalRowKey: ""},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{rowEarly, rowA, rowB, rowLater}}
			srv := httptest.NewServer(fake)
			defer srv.Close()

			ckptPath := writeCkpt(t, tc.cur)
			sink := &recordingSink{}
			sum, err := ReplayBigQuery(context.Background(), src, sink, Options{Checkpoint: &CheckpointConfig{Path: ckptPath}}, bigQueryTestOptions(srv)...)
			if err != nil {
				t.Fatalf("ReplayBigQuery() = %v", err)
			}
			if want := (Summary{TotalRead: 3, Matched: 3, ReplayedSpans: 3}); sum != want {
				t.Errorf("summary = %+v, want %+v", sum, want)
			}
			if want := []string{"group-span-A", "group-span-B", "later-span"}; !slices.Equal(sink.names, want) {
				t.Errorf("exported %v, want %v (early-span excluded, group A+B rewound, later-span replayed once)", sink.names, want)
			}
		})
	}
}

// TestFakeQuarantineBigQueryHonorsSelectedProjection verifies that
// fakeQuarantineBigQuery's HTTP POST/GET handlers only serve columns present in
// the outer `SELECT ... FROM quarantined` projection, so omitting `row_key`,
// `group_size`, and `prefix_sha256` from the outer SELECT omits them from the
// returned TableSchema/TableRow and leaves CanonicalRowKey empty.
func TestFakeQuarantineBigQueryHonorsSelectedProjection(t *testing.T) {
	base := time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC)
	fake := &fakeQuarantineBigQuery{rows: []fakeQuarantineRow{
		{ingest: base, fp: 77, signal: "spans", code: "OVERSIZE_ROW", payload: sampleSpanJSON(t, "proj-span")},
	}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	defer srv.Client().CloseIdleConnections()

	opts := append(slices.Clone(bigQueryTestOptions(srv)), option.WithHTTPClient(srv.Client()))
	svc, err := bigqueryapi.NewService(context.Background(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	runProjectionQuery := func(t *testing.T, sqlText string) (*bigqueryapi.GetQueryResultsResponse, quarantineRow) {
		t.Helper()
		useLegacy := false
		qResp, err := svc.Jobs.Query("proj", &bigqueryapi.QueryRequest{
			Query:         sqlText,
			UseLegacySql:  &useLegacy,
			ParameterMode: "NAMED",
		}).Do()
		if err != nil {
			t.Fatalf("Jobs.Query: %v", err)
		}
		res, err := svc.Jobs.GetQueryResults("proj", qResp.JobReference.JobId).Location(qResp.JobReference.Location).Do()
		if err != nil {
			t.Fatalf("Jobs.GetQueryResults: %v", err)
		}
		if res.Schema == nil || len(res.Rows) != 1 {
			t.Fatalf("GetQueryResults rows=%d schema=%v, want 1 row", len(res.Rows), res.Schema)
		}
		decoded, haveOrd, err := decodeQuarantineRow(res.Schema.Fields, res.Rows[0])
		if err != nil || !haveOrd {
			t.Fatalf("decodeQuarantineRow = (%+v, %v, %v), want haveOrd=true and nil error", decoded, haveOrd, err)
		}
		return res, decoded
	}

	fullQuery := fmt.Sprintf(quarantineQueryTemplate, "proj.ds.dead_letters", "TRUE", "")
	fullRes, fullRow := runProjectionQuery(t, fullQuery)
	var fullFieldNames []string
	for _, f := range fullRes.Schema.Fields {
		fullFieldNames = append(fullFieldNames, f.Name)
	}
	if !slices.Contains(fullFieldNames, "row_key") || fullRow.pos.canonicalKey == "" || fullRow.pos.groupSize != 1 || fullRow.pos.prefixSHA256 == "" || fullRow.pos.groupSHA256 == "" {
		t.Fatalf("full projection fields=%v row.pos=%+v, want row_key, group_size=1, prefix_sha256, and group_sha256 populated", fullFieldNames, fullRow.pos)
	}

	withoutRowKeyQuery := strings.Replace(
		fullQuery,
		"payload_ref_uri, payload_ref_version, row_fp, row_ord, row_key, group_size, prefix_sha256, group_sha256\nFROM quarantined",
		"payload_ref_uri, payload_ref_version, row_fp, row_ord\nFROM quarantined",
		1,
	)
	if withoutRowKeyQuery == fullQuery {
		t.Fatal("strings.Replace did not modify outer SELECT list in quarantineQueryTemplate")
	}
	reducedRes, reducedRow := runProjectionQuery(t, withoutRowKeyQuery)
	var reducedFieldNames []string
	for _, f := range reducedRes.Schema.Fields {
		reducedFieldNames = append(reducedFieldNames, f.Name)
	}
	if slices.Contains(reducedFieldNames, "row_key") || slices.Contains(reducedFieldNames, "group_size") || slices.Contains(reducedFieldNames, "prefix_sha256") || slices.Contains(reducedFieldNames, "group_sha256") {
		t.Fatalf("reduced projection HTTP response schema = %v, want row_key/group_size/prefix_sha256/group_sha256 omitted", reducedFieldNames)
	}
	if reducedRow.pos.canonicalKey != "" || reducedRow.pos.groupSize != 0 || reducedRow.pos.prefixSHA256 != "" || reducedRow.pos.groupSHA256 != "" {
		t.Fatalf("reduced projection decoded row.pos = %+v, want empty canonicalKey, groupSize=0, empty prefixSHA256, and empty groupSHA256", reducedRow.pos)
	}
}

func TestPrefixDigestVectors(t *testing.T) {
	// Independent precomputed SHA-256 hex digests over `<byte_len>:<row_key>`.
	// Notably, "é" is 2 UTF-8 bytes (`\xc3\xa9`) vs 1 Unicode code point, so
	// SHA256("1:a2:é3:1:x") != SHA256("1:a1:é3:1:x") and != SHA256("1|a2|é3|1:x").
	for _, tc := range []struct {
		name string
		keys []string
		want string
	}{
		{
			name: "empty slice",
			keys: nil,
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "single empty string",
			keys: []string{""},
			want: "ba768b331fd86cec803be04e56ab2b3d4c0e98ef4ee4fcd4e72ad7cce61a1d1f",
		},
		{
			name: "two empty strings",
			keys: []string{"", ""},
			want: "390feabc786e369e55b904251d643b52b52b691c60eb74a498ef7c6df993bf12",
		},
		{
			name: "ascii multibyte utf8 and colon literal",
			keys: []string{"a", "é", "1:x"},
			want: "87f5a59f97013c6edb0f71955bd765bfd69385788296ae8b1fc3e8e351c7ab96",
		},
		{
			name: "colon delimiter pair 1",
			keys: []string{"a:b", "c"},
			want: "1c2de18a3ef3c0cdcce3495f7903aff96f0fa91c6a862095865919b9be96554b",
		},
		{
			name: "colon delimiter pair 2",
			keys: []string{"a", "b:c"},
			want: "804536b63b049b4dcd2bcfedd2982e9b28736d83fdfeda47d3f05ddfad7b3532",
		},
		{
			name: "pipe delimiter pair 1",
			keys: []string{"a|b", "c"},
			want: "f0aa1c055d0c6b57e68a861f8c4e7bc7ef675f543a99c66a90d598bea71a3f0e",
		},
		{
			name: "pipe delimiter pair 2",
			keys: []string{"a", "b|c"},
			want: "03caa3c875c96075e58e247d83f4126849f367803dfa5dc0e8159108602661a3",
		},
		{
			name: "single duplicate key",
			keys: []string{"dup"},
			want: "7b4f8270ef1779b47c291c6aaf25bb9c29cd46d177ce0fa2fd0680178a4ddd01",
		},
		{
			name: "two duplicate keys",
			keys: []string{"dup", "dup"},
			want: "95e4b397cc60d8e676112330344e8169d28b2ed73b6c8331bb15f55fcbbbe0c2",
		},
	} {
		if got := prefixDigest(tc.keys); got != tc.want {
			t.Errorf("prefixDigest(%q [%s]) = %s, want %s", tc.keys, tc.name, got, tc.want)
		}
	}
	if prefixDigest([]string{"a:b", "c"}) == prefixDigest([]string{"a", "b:c"}) {
		t.Error("prefixDigest collided on [\"a:b\", \"c\"] vs [\"a\", \"b:c\"]")
	}
	if prefixDigest([]string{"a|b", "c"}) == prefixDigest([]string{"a", "b|c"}) {
		t.Error("prefixDigest collided on [\"a|b\", \"c\"] vs [\"a\", \"b|c\"]")
	}
	if prefixDigest([]string{"dup"}) == prefixDigest([]string{"dup", "dup"}) {
		t.Error("prefixDigest collided on [\"dup\"] vs [\"dup\", \"dup\"]")
	}
}

func TestReplayBigQueryErrors(t *testing.T) {
	fake := &fakeQuarantineBigQuery{status: http.StatusForbidden}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx := context.Background()
	_, err := ReplayBigQuery(ctx, BigQuerySource{Project: "proj", Dataset: "ds"}, NewMemorySink(), Options{}, bigQueryTestOptions(srv)...)
	var gerr *googleapi.Error
	if !errors.As(err, &gerr) || gerr.Code != http.StatusForbidden || !strings.Contains(err.Error(), "roles/bigquery.jobUser") {
		t.Errorf("a forbidden query returned %v, want the 403 with the IAM hint", err)
	}
	for _, src := range []BigQuerySource{
		{Project: "Bad Project", Dataset: "ds"},
		{Project: "proj", Dataset: "ds-1"},
		{Project: "proj", Dataset: "ds", Table: "t`; DROP TABLE x; --"},
		{Project: "proj", Dataset: "ds", PageSize: -1},
	} {
		if _, err := ReplayBigQuery(ctx, src, NewMemorySink(), Options{}, bigQueryTestOptions(srv)...); err == nil {
			t.Errorf("source %+v was accepted", src)
		}
	}
	if _, err := ReplayBigQuery(ctx, BigQuerySource{Project: "proj", Dataset: "ds"}, nil, Options{}); err == nil {
		t.Error("a nil sink was accepted")
	}
	if n := len(fake.requests); n != 1 {
		t.Errorf("BigQuery got %d queries, want only the forbidden one", n)
	}
}

func TestCheckpointerAdvanceRollbackOnError(t *testing.T) {
	t.Run("file checkpoint restores Next, Handled, and UpdatedAt on syncSink and save errors", func(t *testing.T) {
		var syncErr error
		var renameErr error
		fsHooks := defaultCheckpointFS
		fsHooks.rename = func(oldpath, newpath string) error {
			if renameErr != nil {
				return renameErr
			}
			return defaultCheckpointFS.rename(oldpath, newpath)
		}

		sink := &recordingSyncSink{onSync: func() error { return syncErr }}
		cp, err := openCheckpoint(CheckpointConfig{
			Path:   filepath.Join(t.TempDir(), "file.ckpt"),
			Source: "file:quarantine.jsonl",
		}, checkpointKindFile, Filter{}, sink)
		if err != nil {
			t.Fatalf("openCheckpoint: %v", err)
		}
		cp.fs = fsHooks
		if err := cp.advance(recordPosition{index: 0}); err != nil {
			t.Fatalf("initial advance(0): %v", err)
		}
		savedUpdatedAt := cp.state.UpdatedAt

		syncErr = errors.New("disk sync failed")
		if err := cp.advance(recordPosition{index: 1}); err == nil {
			t.Fatal("advance(1) with failing syncSink succeeded, want error")
		}
		if cp.handled(recordPosition{index: 1}) {
			t.Fatal("cp.handled(1) = true after syncSink failure, want false")
		}
		if cp.state.Next != 1 || cp.state.Handled != 1 {
			t.Fatalf("after syncSink failure: Next=%d Handled=%d, want 1, 1", cp.state.Next, cp.state.Handled)
		}

		syncErr = nil
		renameErr = errors.New("rename failed")
		if err := cp.advance(recordPosition{index: 1}); err == nil {
			t.Fatal("advance(1) with failing save/rename succeeded, want error")
		}
		if cp.handled(recordPosition{index: 1}) {
			t.Fatal("cp.handled(1) = true after save failure, want false")
		}
		if cp.state.Next != 1 || cp.state.Handled != 1 || !cp.state.UpdatedAt.Equal(savedUpdatedAt) {
			t.Fatalf("after save failure: Next=%d Handled=%d UpdatedAt=%v, want 1, 1, %v",
				cp.state.Next, cp.state.Handled, cp.state.UpdatedAt, savedUpdatedAt)
		}

		renameErr = nil
		if err := cp.advance(recordPosition{index: 1}); err != nil {
			t.Fatalf("retry advance(1) after clearing fault: %v", err)
		}
		if !cp.handled(recordPosition{index: 1}) || cp.state.Next != 2 || cp.state.Handled != 2 {
			t.Fatalf("after retry: handled(1)=%v Next=%d Handled=%d, want true, 2, 2",
				cp.handled(recordPosition{index: 1}), cp.state.Next, cp.state.Handled)
		}
	})

	t.Run("BigQuery checkpoint restores cursor and groupKeys on syncSink and save errors", func(t *testing.T) {
		var syncErr error
		var renameErr error
		fsHooks := defaultCheckpointFS
		fsHooks.rename = func(oldpath, newpath string) error {
			if renameErr != nil {
				return renameErr
			}
			return defaultCheckpointFS.rename(oldpath, newpath)
		}

		sink := &recordingSyncSink{onSync: func() error { return syncErr }}
		cp, err := openCheckpoint(CheckpointConfig{
			Path:   filepath.Join(t.TempDir(), "bq.ckpt"),
			Source: "bigquery:proj.ds.otel_quarantine",
		}, checkpointKindBigQuery, Filter{}, sink)
		if err != nil {
			t.Fatalf("openCheckpoint: %v", err)
		}
		cp.fs = fsHooks

		pos0 := recordPosition{
			ingestMicros: 100,
			fingerprint:  7,
			ordinal:      0,
			canonicalKey: "key-0",
			groupSize:    2,
		}
		pos1 := recordPosition{
			ingestMicros: 100,
			fingerprint:  7,
			ordinal:      1,
			canonicalKey: "key-1",
			groupSize:    2,
		}
		posNextGroup := recordPosition{
			ingestMicros: 100,
			fingerprint:  8,
			ordinal:      0,
			canonicalKey: "key-other",
			groupSize:    1,
		}

		if err := cp.advance(pos0); err != nil {
			t.Fatalf("advance(pos0): %v", err)
		}

		// Fault mid-group on syncSink failure.
		syncErr = errors.New("sync boom")
		if err := cp.advance(pos1); err == nil {
			t.Fatal("advance(pos1) succeeded under sync error")
		}
		if cp.handled(pos1) {
			t.Fatal("handled(pos1) = true after sync failure, want false")
		}
		if cp.state.Handled != 1 || cp.state.Cursor == nil || cp.state.Cursor.DuplicateOrdinal != 0 ||
			cp.state.Cursor.CanonicalRowKey != "key-0" || !slices.Equal(cp.groupKeys, []string{"key-0"}) {
			t.Fatalf("mid-group sync rollback left Handled=%d Cursor=%+v groupKeys=%v",
				cp.state.Handled, cp.state.Cursor, cp.groupKeys)
		}

		// Fault on save/rename when crossing into a new fingerprint group.
		syncErr = nil
		renameErr = errors.New("save boom")
		if err := cp.advance(posNextGroup); err == nil {
			t.Fatal("advance(posNextGroup) succeeded under save error")
		}
		if cp.handled(posNextGroup) {
			t.Fatal("handled(posNextGroup) = true after save failure, want false")
		}
		if cp.state.Handled != 1 || cp.groupIngest != 100 || cp.groupFP != 7 ||
			!slices.Equal(cp.groupKeys, []string{"key-0"}) || cp.state.Cursor.RowFingerprint != 7 {
			t.Fatalf("cross-group save rollback left Handled=%d group=(%d,%d,%v) Cursor=%+v",
				cp.state.Handled, cp.groupIngest, cp.groupFP, cp.groupKeys, cp.state.Cursor)
		}

		// Clear fault and verify retry computes exact clean PrefixSHA256 for [key-0, key-1].
		renameErr = nil
		if err := cp.advance(pos1); err != nil {
			t.Fatalf("retry advance(pos1): %v", err)
		}
		wantPrefix := prefixDigest([]string{"key-0", "key-1"})
		if cp.state.Handled != 2 || cp.state.Cursor.DuplicateOrdinal != 1 ||
			cp.state.Cursor.PrefixSHA256 != wantPrefix || !slices.Equal(cp.groupKeys, []string{"key-0", "key-1"}) {
			t.Fatalf("after retry: Handled=%d Cursor=%+v groupKeys=%v, want PrefixSHA256=%q",
				cp.state.Handled, cp.state.Cursor, cp.groupKeys, wantPrefix)
		}
	})

	t.Run("restores OutputBytes, OutputDigest, and OutputNeedsNewline on save failure", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		seed := `{"signal":"traces","otlp":{"seed":1}}`
		if err := os.WriteFile(outPath, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()

		var renameErr error
		fsHooks := defaultCheckpointFS
		fsHooks.rename = func(oldpath, newpath string) error {
			if renameErr != nil {
				return renameErr
			}
			return defaultCheckpointFS.rename(oldpath, newpath)
		}
		sink := NewJSONWriterSink(f)
		cp, err := openCheckpoint(CheckpointConfig{
			Path:   filepath.Join(dir, "out.ckpt"),
			Source: "file:out.jsonl",
		}, checkpointKindFile, Filter{}, sink)
		if err != nil {
			t.Fatalf("openCheckpoint: %v", err)
		}
		cp.fs = fsHooks

		if err := cp.advance(recordPosition{index: 0}); err != nil {
			t.Fatalf("initial advance(0): %v", err)
		}
		wantBytes := int64(len(seed))
		wantDigest := cp.state.OutputDigest
		if cp.state.OutputBytes == nil || *cp.state.OutputBytes != wantBytes ||
			wantDigest == "" || cp.state.OutputNeedsNewline == nil || !*cp.state.OutputNeedsNewline {
			t.Fatalf("initial state unexpected: OutputBytes=%v OutputDigest=%q OutputNeedsNewline=%v",
				cp.state.OutputBytes, wantDigest, cp.state.OutputNeedsNewline)
		}

		// Write a new line to sink and inject a save/rename error on advance(1).
		if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "rollback-span")); err != nil {
			t.Fatal(err)
		}
		renameErr = errors.New("injected rename failure")
		if err := cp.advance(recordPosition{index: 1}); err == nil {
			t.Fatal("advance(1) succeeded under rename failure")
		}
		if cp.state.OutputBytes == nil || *cp.state.OutputBytes != wantBytes ||
			cp.state.OutputDigest != wantDigest ||
			cp.state.OutputNeedsNewline == nil || !*cp.state.OutputNeedsNewline {
			t.Fatalf("rollback failed to restore output metadata: bytes=%v digest=%q needsNL=%v",
				cp.state.OutputBytes, cp.state.OutputDigest, cp.state.OutputNeedsNewline)
		}
	})

	t.Run("defers rollback on createTemp error and panicking sync", func(t *testing.T) {
		var syncPanic any
		var createTempErr error
		fsHooks := defaultCheckpointFS
		fsHooks.createTemp = func(dir, pattern string) (checkpointTempFile, error) {
			if createTempErr != nil {
				return nil, createTempErr
			}
			return defaultCheckpointFS.createTemp(dir, pattern)
		}

		sink := &recordingSyncSink{onSync: func() error {
			if syncPanic != nil {
				panic(syncPanic)
			}
			return nil
		}}
		cp, err := openCheckpoint(CheckpointConfig{
			Path:   filepath.Join(t.TempDir(), "defer.ckpt"),
			Source: "bigquery:proj.ds.otel_quarantine",
		}, checkpointKindBigQuery, Filter{}, sink)
		if err != nil {
			t.Fatalf("openCheckpoint: %v", err)
		}
		cp.fs = fsHooks

		pos0 := recordPosition{
			ingestMicros: 200,
			fingerprint:  11,
			ordinal:      0,
			canonicalKey: "key-a",
			groupSize:    2,
		}
		pos1 := recordPosition{
			ingestMicros: 200,
			fingerprint:  11,
			ordinal:      1,
			canonicalKey: "key-b",
			groupSize:    2,
		}
		if err := cp.advance(pos0); err != nil {
			t.Fatalf("initial advance(pos0): %v", err)
		}
		savedUpdatedAt := cp.state.UpdatedAt

		// 1. Early save failure (createTemp) rolls back state and cursor.
		createTempErr = errors.New("tmp dir full")
		if err := cp.advance(pos1); err == nil {
			t.Fatal("advance(pos1) with failing createTemp succeeded, want error")
		}
		if cp.handled(pos1) || cp.state.Handled != 1 || !cp.state.UpdatedAt.Equal(savedUpdatedAt) ||
			cp.state.Cursor == nil || cp.state.Cursor.DuplicateOrdinal != 0 ||
			!slices.Equal(cp.groupKeys, []string{"key-a"}) {
			t.Fatalf("createTemp failure left Handled=%d UpdatedAt=%v Cursor=%+v groupKeys=%v",
				cp.state.Handled, cp.state.UpdatedAt, cp.state.Cursor, cp.groupKeys)
		}

		// 2. Panic inside syncSink still triggers deferred rollback.
		createTempErr = nil
		syncPanic = "boom"
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_ = cp.advance(pos1)
		}()
		if recovered != "boom" {
			t.Fatalf("recovered panic = %v, want %q", recovered, "boom")
		}
		if cp.handled(pos1) || cp.state.Handled != 1 ||
			cp.state.Cursor == nil || cp.state.Cursor.DuplicateOrdinal != 0 ||
			!slices.Equal(cp.groupKeys, []string{"key-a"}) {
			t.Fatalf("panic rollback left Handled=%d Cursor=%+v groupKeys=%v",
				cp.state.Handled, cp.state.Cursor, cp.groupKeys)
		}

		// 3. Clearing the fault lets retry advance cleanly.
		syncPanic = nil
		if err := cp.advance(pos1); err != nil {
			t.Fatalf("retry advance(pos1): %v", err)
		}
		wantPrefix := prefixDigest([]string{"key-a", "key-b"})
		if !cp.handled(pos1) || cp.state.Handled != 2 || cp.state.Cursor.PrefixSHA256 != wantPrefix {
			t.Fatalf("after retry: handled=%v Handled=%d PrefixSHA256=%q, want %q",
				cp.handled(pos1), cp.state.Handled, cp.state.Cursor.PrefixSHA256, wantPrefix)
		}
	})
}

type failingFileWriter struct {
	*os.File
	partialBytes int
	err          error
}

func (w *failingFileWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		n := min(w.partialBytes, len(p))
		if n > 0 {
			wn, _ := w.File.Write(p[:n])
			return wn, w.err
		}
		return 0, w.err
	}
	return w.File.Write(p)
}

type seekTruncWriter struct {
	buf       []byte
	pos       int64
	shortNext int
	errNext   error
	truncErr  error
	truncLog  []int64
}

func (w *seekTruncWriter) Write(p []byte) (int, error) {
	if w.shortNext > 0 {
		n := min(w.shortNext, len(p))
		w.shortNext = 0
		w.writeAtPos(p[:n])
		err := w.errNext
		w.errNext = nil
		return n, err
	}
	if w.errNext != nil {
		err := w.errNext
		w.errNext = nil
		return 0, err
	}
	w.writeAtPos(p)
	return len(p), nil
}

func (w *seekTruncWriter) writeAtPos(p []byte) {
	end := int(w.pos) + len(p)
	if end > len(w.buf) {
		grown := make([]byte, end)
		copy(grown, w.buf)
		w.buf = grown
	}
	copy(w.buf[int(w.pos):end], p)
	w.pos = int64(end)
}

func (w *seekTruncWriter) Seek(offset int64, whence int) (int64, error) {
	var target int64
	switch whence {
	case io.SeekStart:
		target = offset
	case io.SeekCurrent:
		target = w.pos + offset
	case io.SeekEnd:
		target = int64(len(w.buf)) + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if target < 0 {
		return 0, errors.New("negative seek")
	}
	w.pos = target
	return w.pos, nil
}

func (w *seekTruncWriter) Truncate(size int64) error {
	w.truncLog = append(w.truncLog, size)
	if w.truncErr != nil {
		return w.truncErr
	}
	w.buf = w.buf[:size]
	return nil
}

type pipeModeRejectWriter struct {
	mode      fs.FileMode
	truncSeen bool
}

func (w *pipeModeRejectWriter) Write(p []byte) (int, error) {
	return min(5, len(p)), syscall.EPIPE
}

func (w *pipeModeRejectWriter) Stat() (fs.FileInfo, error) {
	return fakeFileInfo{mode: w.mode}, nil
}

func (w *pipeModeRejectWriter) Truncate(int64) error {
	w.truncSeen = true
	return nil
}

func sampleTracesData(t *testing.T, name string) ptrace.Traces {
	t.Helper()
	td, err := (&ptrace.JSONUnmarshaler{}).UnmarshalTraces([]byte(sampleSpanJSON(t, name)))
	if err != nil {
		t.Fatal(err)
	}
	return td
}

func sampleLogsData(t *testing.T, body string) plog.Logs {
	t.Helper()
	ld, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs([]byte(sampleLogJSON(t, body)))
	if err != nil {
		t.Fatal(err)
	}
	return ld
}

func TestJSONWriterSinkRollbackOnWriteError(t *testing.T) {
	t.Run("os.File partial short write on O_APPEND preserves prior records", func(t *testing.T) {
		outPath := filepath.Join(t.TempDir(), "out.ndjson")
		sinkFirst := NewJSONWriterSink(func() *os.File {
			f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = f.Close() })
			return f
		}())
		if err := sinkFirst.ExportTraces(context.Background(), sampleTracesData(t, "span-0")); err != nil {
			t.Fatal(err)
		}
		firstBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}

		fAppend, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fAppend.Close() }()
		// Confirm OS leaves initial offset at 0 on O_APPEND before writing, so
		// rollback must rely on Stat().Size() rather than Seek(0, io.SeekCurrent).
		if cur, err := fAppend.Seek(0, io.SeekCurrent); err != nil || cur != 0 {
			t.Fatalf("O_APPEND initial offset = %d (err=%v), want 0", cur, err)
		}

		fw := &failingFileWriter{File: fAppend, partialBytes: 17, err: syscall.EFBIG}
		sink := NewJSONWriterSink(fw)
		err = sink.ExportTraces(context.Background(), sampleTracesData(t, "span-1"))
		if !errors.Is(err, syscall.EFBIG) {
			t.Fatalf("ExportTraces error = %v, want EFBIG", err)
		}
		afterFail, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterFail, firstBytes) {
			t.Fatalf("output after failed partial write mutated: got %q, want %q", afterFail, firstBytes)
		}

		fw.err = nil
		if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "span-1")); err != nil {
			t.Fatalf("retry ExportTraces failed: %v", err)
		}
		afterRetry, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(afterRetry), "\n"), "\n")
		if len(lines) != 2 {
			t.Fatalf("got %d lines after retry (%q), want 2", len(lines), string(afterRetry))
		}
		for i, line := range lines {
			if !json.Valid([]byte(line)) {
				t.Fatalf("line %d is invalid JSON: %q", i, line)
			}
		}
	})

	t.Run("Seeker+Truncate short write without Stat rolls back", func(t *testing.T) {
		w := &seekTruncWriter{}
		sink := NewJSONWriterSink(w)
		if err := sink.ExportLogs(context.Background(), sampleLogsData(t, "log-0")); err != nil {
			t.Fatal(err)
		}
		goodLen := int64(len(w.buf))

		// Simulate a short write with nil error: writeEnvelope must treat it as
		// io.ErrShortWrite and truncate back to goodLen.
		w.shortNext = 9
		w.errNext = nil
		if err := sink.ExportLogs(context.Background(), sampleLogsData(t, "log-1")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write err = %v, want io.ErrShortWrite", err)
		}
		if int64(len(w.buf)) != goodLen || w.pos != goodLen || !slices.Equal(w.truncLog, []int64{goodLen}) {
			t.Fatalf("rollback state: len=%d pos=%d truncLog=%v, want len/pos=%d", len(w.buf), w.pos, w.truncLog, goodLen)
		}

		if err := sink.ExportLogs(context.Background(), sampleLogsData(t, "log-1")); err != nil {
			t.Fatalf("retry after rollback failed: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(string(w.buf), "\n"), "\n")
		if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
			t.Fatalf("corrupt lines after retry: %q", string(w.buf))
		}
	})

	t.Run("non-regular pipe skips Truncate on error", func(t *testing.T) {
		w := &pipeModeRejectWriter{mode: fs.ModeNamedPipe}
		sink := NewJSONWriterSink(w)
		err := sink.ExportTraces(context.Background(), sampleTracesData(t, "pipe-span"))
		if !errors.Is(err, syscall.EPIPE) {
			t.Fatalf("err = %v, want EPIPE", err)
		}
		if w.truncSeen {
			t.Fatal("Truncate called on non-regular pipe writer")
		}
	})

	t.Run("non-EOF Seeker without Stat skips Truncate and preserves trailing data", func(t *testing.T) {
		first := "{\"signal\":\"traces\",\"otlp\":{\"id\":1}}\n"
		second := "{\"signal\":\"traces\",\"otlp\":{\"id\":2}}\n"
		initial := first + second
		w := &seekTruncWriter{
			buf: []byte(initial),
			pos: int64(len(first)),
		}
		sink := NewJSONWriterSink(w)

		w.errNext = syscall.EIO
		err := sink.ExportLogs(context.Background(), sampleLogsData(t, "mid-err"))
		if !errors.Is(err, syscall.EIO) {
			t.Fatalf("err = %v, want EIO", err)
		}
		if len(w.truncLog) != 0 {
			t.Fatalf("Truncate called on non-EOF stream: %v", w.truncLog)
		}
		if string(w.buf) != initial || w.pos != int64(len(first)) {
			t.Fatalf("non-EOF failed write mutated stream: buf=%q pos=%d, want buf=%q pos=%d",
				string(w.buf), w.pos, initial, len(first))
		}

		// Even on a partial short write at a non-EOF offset, Truncate must not run.
		w2 := &seekTruncWriter{
			buf:       []byte(initial),
			pos:       int64(len(first)),
			shortNext: 5,
		}
		sink2 := NewJSONWriterSink(w2)
		if err := sink2.ExportLogs(context.Background(), sampleLogsData(t, "mid-short")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write err = %v, want io.ErrShortWrite", err)
		}
		if len(w2.truncLog) != 0 {
			t.Fatalf("Truncate called on non-EOF short write: %v", w2.truncLog)
		}
		if len(w2.buf) != len(initial) {
			t.Fatalf("trailing bytes after non-EOF short write were lost: len=%d, want %d", len(w2.buf), len(initial))
		}
	})
}

func TestJSONWriterSinkTruncateIncompleteTrailingLine(t *testing.T) {
	t.Run("empty and newline-terminated files untouched", func(t *testing.T) {
		for _, initial := range []string{"", "{\"signal\":\"traces\"}\n"} {
			path := filepath.Join(t.TempDir(), "out.ndjson")
			if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			sink := NewJSONWriterSink(f)
			if err := sink.TruncateIncompleteTrailingLine(); err != nil {
				_ = f.Close()
				t.Fatalf("TruncateIncompleteTrailingLine(%q) failed: %v", initial, err)
			}
			_ = f.Close()
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != initial {
				t.Fatalf("got %q, want %q", string(got), initial)
			}
		}
	})

	t.Run("truncates partial fragment back to preceding newline", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ndjson")
		validLine := "{\"signal\":\"traces\",\"otlp\":{\"ok\":1}}\n"
		if err := os.WriteFile(path, []byte(validLine+`{"signal":"traces","otlp":{"trunc`), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := NewJSONWriterSink(f).TruncateIncompleteTrailingLine(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != validLine {
			t.Fatalf("got %q, want %q", string(got), validLine)
		}
	})

	t.Run("truncates single incomplete fragment without newline to zero", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ndjson")
		if err := os.WriteFile(path, []byte(`{"signal":"traces","otlp":{"partial"`), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := NewJSONWriterSink(f).TruncateIncompleteTrailingLine(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %q (%d bytes), want 0 bytes", string(got), len(got))
		}
	})

	t.Run("truncates partial fragment exceeding 64KiB chunk", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ndjson")
		validLine := "{\"signal\":\"traces\",\"otlp\":{\"ok\":1}}\n"
		hugePartial := validLine + `{"signal":"traces","otlp":"` + strings.Repeat("a", 75*1024)
		if err := os.WriteFile(path, []byte(hugePartial), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		if err := NewJSONWriterSink(f).TruncateIncompleteTrailingLine(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != validLine {
			t.Fatalf("got %d bytes, want %d bytes (%q)", len(got), len(validLine), validLine)
		}
	})

	t.Run("repairs write-only os.File via same-file reopen fallback", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ndjson")
		validLine := "{\"signal\":\"traces\",\"otlp\":{\"ok\":1}}\n"
		if err := os.WriteFile(path, []byte(validLine+`{"partial":`), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		sink := NewJSONWriterSink(f)
		if err := sink.TruncateIncompleteTrailingLine(); err != nil {
			t.Fatalf("write-only tail repair failed: %v", err)
		}
		if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "after-wronly")); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
		if len(lines) != 2 || lines[0]+"\n" != validLine || !json.Valid([]byte(lines[1])) {
			t.Fatalf("unexpected lines after O_WRONLY repair+append: %q", string(got))
		}
	})

	t.Run("preserves valid unterminated JSONL tail and inserts newline before next record", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			initial string
		}{
			{name: "compact valid JSON object", initial: `{"signal":"traces","otlp":{"ok":1}}`},
			{name: "valid JSON object with trailing spaces", initial: `{"signal":"traces","otlp":{"ok":1}}   `},
			{name: "valid JSON object exceeding 64KiB", initial: `{"signal":"traces","otlp":"` + strings.Repeat("b", 75*1024) + `"}`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "out.ndjson")
				if err := os.WriteFile(path, []byte(tc.initial), 0o600); err != nil {
					t.Fatal(err)
				}
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }()

				fw := &failingFileWriter{File: f}
				sink := NewJSONWriterSink(fw)
				if err := sink.TruncateIncompleteTrailingLine(); err != nil {
					t.Fatalf("TruncateIncompleteTrailingLine failed: %v", err)
				}
				kept, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(kept) != tc.initial {
					t.Fatalf("valid unterminated tail mutated: got %d bytes, want %d bytes", len(kept), len(tc.initial))
				}

				// If the very next write fails and rolls back, needsNewline must stay armed.
				fw.partialBytes = 5
				fw.err = syscall.EFBIG
				if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "rollback-needs-nl")); !errors.Is(err, syscall.EFBIG) {
					t.Fatalf("ExportTraces err = %v, want EFBIG", err)
				}
				afterRollback, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if string(afterRollback) != tc.initial {
					t.Fatalf("after rollback: got %q, want intact initial", string(afterRollback))
				}

				fw.err = nil
				if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "after-unterminated")); err != nil {
					t.Fatalf("ExportTraces after preserving tail failed: %v", err)
				}
				finalBytes, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
				if len(lines) != 2 {
					t.Fatalf("got %d lines (%q), want 2", len(lines), string(finalBytes))
				}
				if lines[0] != tc.initial {
					t.Fatalf("line 0 = %q, want %q", lines[0], tc.initial)
				}
				if !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "after-unterminated") {
					t.Fatalf("line 1 invalid or missing trace: %q", lines[1])
				}
			})
		}
	})
}

type permissionDeniedFile struct {
	*os.File
	partialBytes int
	writeErr     error
}

func (w *permissionDeniedFile) ReadAt([]byte, int64) (int, error) {
	return 0, fs.ErrPermission
}

func (w *permissionDeniedFile) Truncate(int64) error {
	return fs.ErrPermission
}

func (w *permissionDeniedFile) Write(p []byte) (int, error) {
	if w.writeErr != nil {
		n := min(w.partialBytes, len(p))
		if n > 0 {
			wn, _ := w.File.Write(p[:n])
			return wn, w.writeErr
		}
		return 0, w.writeErr
	}
	return w.File.Write(p)
}

type statErrorSeekTruncWriter struct {
	seekTruncWriter
}

func (w *statErrorSeekTruncWriter) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat unavailable")
}

type statErrorAppendFile struct {
	*os.File
	err error
}

func (w *statErrorAppendFile) Stat() (fs.FileInfo, error) {
	return nil, errors.New("stat failed")
}

func (w *statErrorAppendFile) Write([]byte) (int, error) {
	return 0, w.err
}

func TestTruncateIncompleteTrailingLinePermissionFallback(t *testing.T) {
	t.Run("repairs tail and rolls back failed write via SameFile O_RDWR reopen when ReadAt and Truncate return permission denied", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "out.ndjson")
		validLine := "{\"signal\":\"traces\",\"otlp\":{\"ok\":1}}\n"
		if err := os.WriteFile(path, []byte(validLine+`{"partial":`), 0o600); err != nil {
			t.Fatal(err)
		}

		f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()

		pf := &permissionDeniedFile{File: f}
		sink := NewJSONWriterSink(pf)
		if err := sink.TruncateIncompleteTrailingLine(); err != nil {
			t.Fatalf("TruncateIncompleteTrailingLine with permission-denied direct handle failed: %v", err)
		}
		afterRepair, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(afterRepair) != validLine {
			t.Fatalf("after tail repair got %q, want %q", string(afterRepair), validLine)
		}

		pf.partialBytes = 14
		pf.writeErr = syscall.EIO
		err = sink.ExportTraces(context.Background(), sampleTracesData(t, "rollback-denied"))
		if !errors.Is(err, syscall.EIO) {
			t.Fatalf("ExportTraces err = %v, want EIO", err)
		}
		afterRollback, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(afterRollback) != validLine {
			t.Fatalf("after rollback got %q, want %q", string(afterRollback), validLine)
		}

		pf.writeErr = nil
		if err := sink.ExportTraces(context.Background(), sampleTracesData(t, "after-fallback")); err != nil {
			t.Fatalf("retry ExportTraces failed: %v", err)
		}
		finalBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 2 || lines[0]+"\n" != validLine || !json.Valid([]byte(lines[1])) {
			t.Fatalf("unexpected lines after permission-fallback recovery: %q", string(finalBytes))
		}
	})

	t.Run("writeEnvelope does not fall back to Seek when Stat returns an error", func(t *testing.T) {
		w := &statErrorSeekTruncWriter{}
		sink := NewJSONWriterSink(w)
		if err := sink.ExportLogs(context.Background(), sampleLogsData(t, "log-0")); err != nil {
			t.Fatal(err)
		}
		firstRecord := slices.Clone(w.buf)

		w.shortNext = 7
		w.errNext = nil
		if err := sink.ExportLogs(context.Background(), sampleLogsData(t, "log-1")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write err = %v, want io.ErrShortWrite", err)
		}
		if len(w.truncLog) != 0 {
			t.Fatalf("Truncate must not be called when Stat errors: truncLog=%v", w.truncLog)
		}
		if !bytes.HasPrefix(w.buf, firstRecord) {
			t.Fatalf("prior committed bytes destroyed after Stat error: got %q", string(w.buf))
		}

		// Verify O_APPEND file whose Seek(0, SeekCurrent) returns 0 is NOT
		// truncated back to 0 bytes when Stat fails on a write error.
		outPath := filepath.Join(t.TempDir(), "append-stat-err.ndjson")
		initial := `{"signal":"traces","otlp":{"ok":1}}` + "\n"
		if err := os.WriteFile(outPath, []byte(initial), 0o600); err != nil {
			t.Fatal(err)
		}
		fAppend, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = fAppend.Close() }()

		sw := &statErrorAppendFile{File: fAppend, err: syscall.EFBIG}
		fileSink := NewJSONWriterSink(sw)
		if err := fileSink.ExportTraces(context.Background(), sampleTracesData(t, "span-fail")); !errors.Is(err, syscall.EFBIG) {
			t.Fatalf("ExportTraces err = %v, want EFBIG", err)
		}
		after, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(after) != initial {
			t.Fatalf("O_APPEND file truncated after Stat error: got %q, want %q", string(after), initial)
		}
	})
}

func TestCheckpointResumeTruncatesIncompleteTrailingLine(t *testing.T) {
	marshalRecords := func(t *testing.T, recs ...Record) []byte {
		t.Helper()
		var buf bytes.Buffer
		for _, r := range recs {
			line, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes()
	}
	rec0 := Record{IngestTime: 1_760_000_001_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "rec-0")}
	rec1 := Record{IngestTime: 1_760_000_002_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "rec-1")}

	t.Run("resume after checkpoint truncates trailing garbage and finishes remaining records", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")

		f1, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Append partial trailing fragment simulating crash mid-write on rec-1.
		fCorrupt, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fCorrupt.WriteString(`{"signal":"traces","otlp":{"half":`); err != nil {
			_ = fCorrupt.Close()
			t.Fatal(err)
		}
		_ = fCorrupt.Close()

		f2, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f2.Close()
		if err != nil {
			t.Fatalf("resume Replay failed: %v", err)
		}
		if sum.ReplayedSpans != 1 || sum.SkippedCheckpointed != 1 {
			t.Fatalf("Summary = %+v, want ReplayedSpans=1 SkippedCheckpointed=1", sum)
		}
		raw, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
			t.Fatalf("corrupt output after resume: %q", string(raw))
		}
		if !strings.Contains(lines[0], "rec-0") || !strings.Contains(lines[1], "rec-1") {
			t.Fatalf("unexpected records after resume: %q", string(raw))
		}
	})

	t.Run("resume before first checkpoint exists truncates partial first record", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")
		input := marshalRecords(t, rec0, rec1)

		if err := os.WriteFile(outPath, []byte(`{"signal":"traces","otlp":{"partial":`), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Replay(context.Background(), bytes.NewReader(input), NewJSONWriterSink(f), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f.Close()
		if err != nil {
			t.Fatalf("Replay failed: %v", err)
		}
		if sum.ReplayedSpans != 2 {
			t.Fatalf("ReplayedSpans = %d, want 2", sum.ReplayedSpans)
		}
		raw, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
			t.Fatalf("corrupt output after record-0 crash repair: %q", string(raw))
		}
	})

	t.Run("mismatched checkpoint rejects before mutating output", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")
		input := marshalRecords(t, rec0, rec1)

		f1, err := os.OpenFile(filepath.Join(dir, "other.ndjson"), os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(input), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:other"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		sentinel := "keep-this-untouched"
		if err := os.WriteFile(outPath, []byte(sentinel), 0o600); err != nil {
			t.Fatal(err)
		}
		f2, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(input), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f2.Close()
		if err == nil {
			t.Fatal("expected source-mismatch checkpoint error, got nil")
		}
		got, readErr := os.ReadFile(outPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != sentinel {
			t.Fatalf("mismatched checkpoint mutated output: got %q, want %q", string(got), sentinel)
		}
	})

	t.Run("fresh run with empty input preserves pre-existing valid unterminated JSONL tail", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")
		validUnterminated := `{"signal":"traces","otlp":{"preexisting":1}}`
		if err := os.WriteFile(outPath, []byte(validUnterminated), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), strings.NewReader(""), NewJSONWriterSink(f), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:empty"},
		})
		_ = f.Close()
		if err != nil {
			t.Fatalf("Replay on empty input failed: %v", err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != validUnterminated {
			t.Fatalf("empty checkpointed run deleted valid unterminated tail: got %q, want %q", string(got), validUnterminated)
		}
	})
}

func TestCheckpointOutputBytesRecovery(t *testing.T) {
	marshalRecords := func(t *testing.T, recs ...Record) []byte {
		t.Helper()
		var buf bytes.Buffer
		for _, r := range recs {
			line, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			buf.Write(line)
			buf.WriteByte('\n')
		}
		return buf.Bytes()
	}
	rec0 := Record{IngestTime: 1_760_000_001_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "bytes-rec-0")}
	rec1 := Record{IngestTime: 1_760_000_002_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "bytes-rec-1")}
	recOther := Record{IngestTime: 1_760_000_003_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "bytes-rec-other")}

	t.Run("truncates incomplete trailing fragment beyond checkpoint output_bytes", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")

		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		st := readCheckpointFile(t, cpPath)
		rec0Bytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if st.OutputBytes == nil || *st.OutputBytes != int64(len(rec0Bytes)) {
			t.Fatalf("checkpoint output_bytes = %v, want %d", st.OutputBytes, len(rec0Bytes))
		}
		if st.OutputTarget == "" || !strings.HasPrefix(st.OutputTarget, "file:") {
			t.Fatalf("checkpoint output_target = %q, want file: prefix", st.OutputTarget)
		}
		if err := validateHexSHA256(st.OutputDigest); err != nil {
			t.Fatalf("checkpoint output_digest = %q: %v", st.OutputDigest, err)
		}
		if st.OutputNeedsNewline == nil || *st.OutputNeedsNewline {
			t.Fatalf("checkpoint output_needs_newline = %v, want false", st.OutputNeedsNewline)
		}

		// Simulate crash mid-write after checkpoint update leaving an incomplete JSON fragment.
		fCrash, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fCrash.WriteString(`{"signal":"traces","otlp":{"uncommitted":`); err != nil {
			_ = fCrash.Close()
			t.Fatal(err)
		}
		_ = fCrash.Close()

		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f2.Close()
		if err != nil {
			t.Fatalf("resume Replay failed: %v", err)
		}
		if sum.SkippedCheckpointed != 1 || sum.ReplayedSpans != 1 {
			t.Fatalf("Summary = %+v, want SkippedCheckpointed=1 ReplayedSpans=1", sum)
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 2 || !strings.Contains(lines[0], "bytes-rec-0") || !strings.Contains(lines[1], "bytes-rec-1") {
			t.Fatalf("unexpected resumed output (incomplete fragment not trimmed): %q", string(finalBytes))
		}
	})

	t.Run("preserves complete valid JSONL records from another source beyond output_bytes while trimming trailing fragment", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "shared.ndjson")
		cp1Path := filepath.Join(dir, "cp1.json")
		cp2Path := filepath.Join(dir, "cp2.json")

		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cp1Path, Source: "ndjson:source-1"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Second independent source appends a completed record to the shared output.
		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, recOther)), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cp2Path, Source: "ndjson:source-2"},
		})
		_ = f2.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Append an incomplete crash fragment after source 2's completed line.
		fCrash, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fCrash.WriteString(`{"signal":"traces","otlp":{"partial":`); err != nil {
			_ = fCrash.Close()
			t.Fatal(err)
		}
		_ = fCrash.Close()

		// Resuming source 1 with cp1 must keep source 2's completed record,
		// trim only the incomplete fragment, and append rec1.
		f3, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(f3), Options{
			Checkpoint: &CheckpointConfig{Path: cp1Path, Source: "ndjson:source-1"},
		})
		_ = f3.Close()
		if err != nil {
			t.Fatalf("resume source-1 failed: %v", err)
		}
		if sum.SkippedCheckpointed != 1 || sum.ReplayedSpans != 1 {
			t.Fatalf("Summary = %+v, want SkippedCheckpointed=1 ReplayedSpans=1", sum)
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 3 || !strings.Contains(lines[0], "bytes-rec-0") || !strings.Contains(lines[1], "bytes-rec-other") || !strings.Contains(lines[2], "bytes-rec-1") {
			t.Fatalf("shared output lost or corrupted records: %q", string(finalBytes))
		}
	})

	t.Run("handles shared append after unterminated committed prefix and trims corrupt same-line suffix", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "shared-unterminated.ndjson")
		cpPath := filepath.Join(dir, "cp.json")

		seed := `{"signal":"traces","otlp":{"seed":1}}`
		if err := os.WriteFile(outPath, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
		skippedRec := Record{IngestTime: 1_760_000_000_000_000, Signal: "logs", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "ignored")}
		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec)), NewJSONWriterSink(f1), Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:filter"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Case A: another run appends a newline separator + incomplete fragment;
		// resume must trim back to seed and keep needsNewline=true.
		if err := os.WriteFile(outPath, []byte(seed+"\n{\"signal\":\"traces\",\"otlp\":{\"half\":"), 0o600); err != nil {
			t.Fatal(err)
		}
		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec, rec0)), NewJSONWriterSink(f2), Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:filter"},
		})
		_ = f2.Close()
		if err != nil {
			t.Fatalf("resume after separator+partial failed: %v", err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
		if len(lines) != 2 || lines[0] != seed || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "bytes-rec-0") {
			t.Fatalf("unexpected output after separator+partial recovery: %q", string(got))
		}

		// Case B: corrupt same-line suffix without leading newline must be truncated back to seed.
		cp2Path := filepath.Join(dir, "cp2.json")
		if err := os.WriteFile(outPath, []byte(seed), 0o600); err != nil {
			t.Fatal(err)
		}
		f3, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec)), NewJSONWriterSink(f3), Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cp2Path, Source: "ndjson:filter2"},
		})
		_ = f3.Close()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outPath, []byte(seed+`{"concatenated":true}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		f4, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec, rec0)), NewJSONWriterSink(f4), Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cp2Path, Source: "ndjson:filter2"},
		})
		_ = f4.Close()
		if err != nil {
			t.Fatalf("resume after same-line suffix failed: %v", err)
		}
		got2, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines2 := strings.Split(strings.TrimSuffix(string(got2), "\n"), "\n")
		if len(lines2) != 2 || lines2[0] != seed || !json.Valid([]byte(lines2[1])) || !strings.Contains(lines2[1], "bytes-rec-0") {
			t.Fatalf("unexpected output after same-line suffix recovery: %q", string(got2))
		}
	})

	t.Run("rejects checkpoint resume against different output path or OTLP target without modifying destination", func(t *testing.T) {
		dir := t.TempDir()
		outA := filepath.Join(dir, "outA.ndjson")
		outB := filepath.Join(dir, "outB.ndjson")
		cpA := filepath.Join(dir, "cpA.json")

		fA, err := os.OpenFile(outA, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(fA), Options{
			Checkpoint: &CheckpointConfig{Path: cpA, Source: "ndjson:same-source"},
		})
		_ = fA.Close()
		if err != nil {
			t.Fatal(err)
		}

		preexistingB := strings.Repeat(`{"signal":"traces","otlp":{"keep":"B"}}`+"\n", 5)
		if err := os.WriteFile(outB, []byte(preexistingB), 0o600); err != nil {
			t.Fatal(err)
		}
		fB, err := os.OpenFile(outB, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(fB), Options{
			Checkpoint: &CheckpointConfig{Path: cpA, Source: "ndjson:same-source"},
		})
		_ = fB.Close()
		if err == nil || !strings.Contains(err.Error(), "was written for output") {
			t.Fatalf("resume against outB err = %v, want output mismatch error", err)
		}
		gotB, err := os.ReadFile(outB)
		if err != nil {
			t.Fatal(err)
		}
		if string(gotB) != preexistingB {
			t.Fatalf("mismatched resume modified outB: got %d bytes, want %d bytes", len(gotB), len(preexistingB))
		}

		// Resuming a file checkpoint against an OTLPHTTPSink or MemorySink must also fail closed.
		otlpSink, err := NewOTLPHTTPSink("http://127.0.0.1:4318", OTLPHTTPSinkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer otlpSink.Close()
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), otlpSink, Options{
			Checkpoint: &CheckpointConfig{Path: cpA, Source: "ndjson:same-source"},
		}); err == nil || !strings.Contains(err.Error(), "was written for output") {
			t.Fatalf("resume file checkpoint against OTLPHTTPSink err = %v, want output mismatch error", err)
		}
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewMemorySink(), Options{
			Checkpoint: &CheckpointConfig{Path: cpA, Source: "ndjson:same-source"},
		}); err == nil || !strings.Contains(err.Error(), "was written for output") {
			t.Fatalf("resume file checkpoint against MemorySink err = %v, want output mismatch error", err)
		}

		// OTLPHTTPSink checkpoint binds to its endpoint.
		cpOTLP := filepath.Join(dir, "cpOTLP.json")
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/x-protobuf")
			respBytes, merr := ptraceotlp.NewExportResponse().MarshalProto()
			if merr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
		}))
		defer srv.Close()
		sink1, err := NewOTLPHTTPSink(srv.URL, OTLPHTTPSinkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer sink1.Close()
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), sink1, Options{
			Checkpoint: &CheckpointConfig{Path: cpOTLP, Source: "ndjson:otlp"},
		}); err != nil {
			t.Fatal(err)
		}
		sink2, err := NewOTLPHTTPSink("http://127.0.0.1:54318", OTLPHTTPSinkOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer sink2.Close()
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), sink2, Options{
			Checkpoint: &CheckpointConfig{Path: cpOTLP, Source: "ndjson:otlp"},
		}); err == nil || !strings.Contains(err.Error(), "was written for output") {
			t.Fatalf("resume OTLP checkpoint against different endpoint err = %v, want output mismatch error", err)
		}
	})

	t.Run("fails closed without modifying file when output prefix digest mismatches at same path", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")

		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		// Overwrite outPath at the same path with unrelated larger valid content.
		unrelated := strings.Repeat(`{"signal":"traces","otlp":{"unrelated":true}}`+"\n", 10)
		if err := os.WriteFile(outPath, []byte(unrelated), 0o600); err != nil {
			t.Fatal(err)
		}
		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f2.Close()
		if err == nil || !strings.Contains(err.Error(), "does not match checkpoint digest") {
			t.Fatalf("resume on overwritten output err = %v, want digest mismatch error", err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != unrelated {
			t.Fatalf("digest mismatch modified output file: got %d bytes, want %d bytes", len(got), len(unrelated))
		}

		// Multi-window (>64 KiB) digest mismatch in the final window must also fail closed,
		// and malformed or zero-byte output_digest must be rejected cleanly.
		largePath := filepath.Join(dir, "large.ndjson")
		largeCp := filepath.Join(dir, "large-cp.json")
		largeRec := Record{IngestTime: 1_760_000_004_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, strings.Repeat("Z", 75*1024))}
		fLarge, err := os.OpenFile(largePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, largeRec)), NewJSONWriterSink(fLarge), Options{
			Checkpoint: &CheckpointConfig{Path: largeCp, Source: "ndjson:large"},
		})
		_ = fLarge.Close()
		if err != nil {
			t.Fatal(err)
		}
		largeBytes, err := os.ReadFile(largePath)
		if err != nil {
			t.Fatal(err)
		}
		if len(largeBytes) <= int(outputDigestWindowBytes) {
			t.Fatalf("largeBytes len = %d, want > %d", len(largeBytes), outputDigestWindowBytes)
		}
		tampered := slices.Clone(largeBytes)
		tampered[len(tampered)-5] ^= 0x01
		if err := os.WriteFile(largePath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		fLarge2, err := os.OpenFile(largePath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, largeRec)), NewJSONWriterSink(fLarge2), Options{
			Checkpoint: &CheckpointConfig{Path: largeCp, Source: "ndjson:large"},
		})
		_ = fLarge2.Close()
		if err == nil || !strings.Contains(err.Error(), "does not match checkpoint digest") {
			t.Fatalf("resume on tampered >64KiB output err = %v, want digest mismatch error", err)
		}

		// Reject output_digest set with output_bytes=0 and invalid output_digest hex.
		zero := int64(0)
		for _, badDigest := range []struct {
			name   string
			bytes  *int64
			digest string
		}{
			{name: "digest with zero bytes", bytes: &zero, digest: strings.Repeat("a", 64)},
			{name: "malformed digest hex", bytes: &[]int64{10}[0], digest: "not-hex"},
		} {
			badCp := filepath.Join(dir, strings.ReplaceAll(badDigest.name, " ", "_")+".json")
			raw, merr := json.Marshal(checkpointState{
				Version:      checkpointVersion,
				Kind:         checkpointKindFile,
				Source:       "ndjson:bad",
				Filter:       (Filter{}).fingerprint(),
				Next:         1,
				Handled:      1,
				OutputBytes:  badDigest.bytes,
				OutputDigest: badDigest.digest,
			})
			if merr != nil {
				t.Fatal(merr)
			}
			if err := os.WriteFile(badCp, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := openCheckpoint(CheckpointConfig{Path: badCp, Source: "ndjson:bad"}, checkpointKindFile, Filter{}, NewNopSink()); err == nil {
				t.Fatalf("%s: expected error from openCheckpoint, got nil", badDigest.name)
			}
		}
	})

	t.Run("fails closed without modifying file when output is shorter than checkpoint output_bytes", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")

		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0)), NewJSONWriterSink(f1), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatal(err)
		}

		truncatedContent := `{"partial`
		if err := os.WriteFile(outPath, []byte(truncatedContent), 0o600); err != nil {
			t.Fatal(err)
		}
		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(f2), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:test"},
		})
		_ = f2.Close()
		if err == nil {
			t.Fatal("expected error when output file is shorter than output_bytes, got nil")
		}
		got, readErr := os.ReadFile(outPath)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if string(got) != truncatedContent {
			t.Fatalf("fail-closed error modified output file: got %q, want %q", string(got), truncatedContent)
		}
	})

	t.Run("rejects negative output_bytes and supports legacy checkpoints without output_bytes", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")
		srcName := "ndjson:legacy"
		filterFP := (Filter{}).fingerprint()

		neg := int64(-1)
		negBytes, err := json.Marshal(checkpointState{
			Version:     checkpointVersion,
			Kind:        checkpointKindFile,
			Source:      srcName,
			Filter:      filterFP,
			Next:        1,
			Handled:     1,
			OutputBytes: &neg,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cpPath, negBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outPath, []byte{}, 0o600); err != nil {
			t.Fatal(err)
		}
		fNeg, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(fNeg), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: srcName},
		})
		_ = fNeg.Close()
		if err == nil {
			t.Fatal("expected error for negative output_bytes, got nil")
		}

		// Legacy checkpoint omitting output_bytes must stay compatible and keep
		// an existing valid unterminated JSON line on disk intact.
		legacyValidTail := `{"signal":"traces","otlp":{"legacy_no_newline":true}}`
		if err := os.WriteFile(outPath, []byte(legacyValidTail), 0o600); err != nil {
			t.Fatal(err)
		}
		legacyBytes, err := json.Marshal(checkpointState{
			Version: checkpointVersion,
			Kind:    checkpointKindFile,
			Source:  srcName,
			Filter:  filterFP,
			Next:    1,
			Handled: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cpPath, legacyBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		fLegacy, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(fLegacy), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: srcName},
		})
		_ = fLegacy.Close()
		if err != nil {
			t.Fatalf("legacy checkpoint resume failed: %v", err)
		}
		if sum.SkippedCheckpointed != 1 || sum.ReplayedSpans != 1 {
			t.Fatalf("Summary = %+v, want SkippedCheckpointed=1 ReplayedSpans=1", sum)
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 2 || lines[0] != legacyValidTail || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "bytes-rec-1") {
			t.Fatalf("unexpected legacy resume output: %q", string(finalBytes))
		}
		updated := readCheckpointFile(t, cpPath)
		if updated.OutputBytes == nil || *updated.OutputBytes != int64(len(finalBytes)) {
			t.Fatalf("updated checkpoint output_bytes = %v, want %d", updated.OutputBytes, len(finalBytes))
		}
	})

	t.Run("preserves output_needs_newline across unreadable resume after filtered checkpoint", func(t *testing.T) {
		seed := `{"signal":"traces","otlp":{"seed":1}}`
		skippedRec := Record{IngestTime: 1_760_000_000_000_000, Signal: "logs", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "ignored")}

		// Cross-platform unreadable writer check (covers Windows and root too).
		w := &unreadableSeekTruncWriter{seekTruncWriter: seekTruncWriter{buf: []byte(seed), pos: int64(len(seed))}}
		cpMem := filepath.Join(t.TempDir(), "cp-mem.json")
		sink1 := NewJSONWriterSink(w)
		sink1.needsNewline = true // initial state as if seed was recovered before becoming write-only
		w.readOnly = false
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec)), sink1, Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cpMem, Source: "ndjson:unreadable"},
		}); err != nil {
			t.Fatalf("initial filtered run failed: %v", err)
		}
		st := readCheckpointFile(t, cpMem)
		if st.OutputNeedsNewline == nil || !*st.OutputNeedsNewline {
			t.Fatalf("OutputNeedsNewline = %v, want true", st.OutputNeedsNewline)
		}

		// Flip writer to unreadable (permission denied) and resume with a matching record.
		w.readOnly = true
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec, rec0)), NewJSONWriterSink(w), Options{
			Filter:     Filter{Signal: "traces"},
			Checkpoint: &CheckpointConfig{Path: cpMem, Source: "ndjson:unreadable"},
		}); err != nil {
			t.Fatalf("unreadable resume failed: %v", err)
		}
		lines := strings.Split(strings.TrimSuffix(string(w.buf), "\n"), "\n")
		if len(lines) != 2 || lines[0] != seed || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "bytes-rec-0") {
			t.Fatalf("unreadable resume concatenated or corrupted lines: %q", string(w.buf))
		}

		if runtime.GOOS != "windows" && os.Geteuid() != 0 {
			dir := t.TempDir()
			outPath := filepath.Join(dir, "out.ndjson")
			cpPath := filepath.Join(dir, "cp.json")
			t.Cleanup(func() { _ = os.Chmod(outPath, 0o600) })

			if err := os.WriteFile(outPath, []byte(seed), 0o600); err != nil {
				t.Fatal(err)
			}
			f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec)), NewJSONWriterSink(f1), Options{
				Filter:     Filter{Signal: "traces"},
				Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:mode0200"},
			})
			_ = f1.Close()
			if err != nil {
				t.Fatalf("initial filtered run failed: %v", err)
			}
			if err := os.Chmod(outPath, 0o200); err != nil {
				t.Fatal(err)
			}
			f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, skippedRec, rec0)), NewJSONWriterSink(f2), Options{
				Filter:     Filter{Signal: "traces"},
				Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:mode0200"},
			})
			_ = f2.Close()
			if err != nil {
				t.Fatalf("mode 0200 resume failed: %v", err)
			}
			if err := os.Chmod(outPath, 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(outPath)
			if err != nil {
				t.Fatal(err)
			}
			diskLines := strings.Split(strings.TrimSuffix(string(got), "\n"), "\n")
			if len(diskLines) != 2 || diskLines[0] != seed || !json.Valid([]byte(diskLines[1])) || !strings.Contains(diskLines[1], "bytes-rec-0") {
				t.Fatalf("mode 0200 resume concatenated or corrupted lines: %q", string(got))
			}
		}
	})

	t.Run("handles write-only handle with synthetic Name without failing digest capture and refuses unverified truncation", func(t *testing.T) {
		dir := t.TempDir()
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "cp.json")
		label := "virtual-writeonly-sink-label"
		rec2 := Record{IngestTime: 1_760_000_005_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "bytes-rec-2")}
		rec3 := Record{IngestTime: 1_760_000_006_000_000, Signal: "traces", ErrorCode: "ROW_ERROR", RawPayload: sampleSpanJSON(t, "bytes-rec-3")}

		f1, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum1, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(&syntheticNamedFile{file: f1, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = f1.Close()
		if err != nil {
			t.Fatalf("2-record checkpointed Replay on write-only handle with synthetic Name failed: %v", err)
		}
		if sum1.ReplayedSpans != 2 {
			t.Fatalf("sum1.ReplayedSpans = %d, want 2", sum1.ReplayedSpans)
		}
		disk1, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines1 := strings.Split(strings.TrimSuffix(string(disk1), "\n"), "\n")
		if len(lines1) != 2 || !strings.Contains(lines1[0], "bytes-rec-0") || !strings.Contains(lines1[1], "bytes-rec-1") {
			t.Fatalf("unexpected initial output: %q", string(disk1))
		}
		st1 := readCheckpointFile(t, cpPath)
		if st1.OutputTarget != "handle:"+label {
			t.Fatalf("st1.OutputTarget = %q, want %q", st1.OutputTarget, "handle:"+label)
		}
		if st1.OutputBytes == nil || *st1.OutputBytes != int64(len(disk1)) || *st1.OutputBytes <= 0 {
			t.Fatalf("st1.OutputBytes = %v, want %d", st1.OutputBytes, len(disk1))
		}
		if st1.OutputDigest != "" {
			t.Fatalf("st1.OutputDigest = %q, want empty", st1.OutputDigest)
		}
		if st1.OutputNeedsNewline == nil || *st1.OutputNeedsNewline {
			t.Fatalf("st1.OutputNeedsNewline = %v, want false", st1.OutputNeedsNewline)
		}

		// Clean resume (size == want) with 3rd record using write-only wrapper succeeds.
		f2, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum2, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1, rec2)), NewJSONWriterSink(&syntheticNamedFile{file: f2, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = f2.Close()
		if err != nil {
			t.Fatalf("clean resume on write-only handle failed: %v", err)
		}
		if sum2.SkippedCheckpointed != 2 || sum2.ReplayedSpans != 1 {
			t.Fatalf("sum2 = %+v, want SkippedCheckpointed=2 ReplayedSpans=1", sum2)
		}
		disk2, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines2 := strings.Split(strings.TrimSuffix(string(disk2), "\n"), "\n")
		if len(lines2) != 3 || !json.Valid([]byte(lines2[2])) || !strings.Contains(lines2[2], "bytes-rec-2") {
			t.Fatalf("unexpected output after clean write-only resume: %q", string(disk2))
		}
		st2 := readCheckpointFile(t, cpPath)
		if st2.OutputBytes == nil || *st2.OutputBytes != int64(len(disk2)) || st2.OutputDigest != "" {
			t.Fatalf("st2 unexpected: OutputBytes=%v want=%d OutputDigest=%q", st2.OutputBytes, len(disk2), st2.OutputDigest)
		}

		// Append incomplete trailing fragment beyond checkpoint output_bytes.
		fCrash, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fCrash.WriteString(`{"signal":"traces","otlp":{"partial":`); err != nil {
			_ = fCrash.Close()
			t.Fatal(err)
		}
		_ = fCrash.Close()
		beforePartial, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}

		// (a) Unreadable handle with size > want must fail closed without modifying file.
		f3a, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1, rec2, rec3)), NewJSONWriterSink(&syntheticNamedFile{file: f3a, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = f3a.Close()
		if err == nil {
			t.Fatal("expected error resuming unreadable handle when size > want, got nil")
		}
		after3a, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after3a, beforePartial) {
			t.Fatalf("unreadable size > want resume mutated file: got %q, want %q", string(after3a), string(beforePartial))
		}

		// (b) Readable handle with incomplete fragment and empty OutputDigest must also fail closed without truncating.
		f3b, err := os.OpenFile(outPath, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1, rec2, rec3)), NewJSONWriterSink(&syntheticNamedFile{file: f3b, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = f3b.Close()
		if err == nil || !strings.Contains(err.Error(), "cannot be truncated without a checkpoint output_digest") {
			t.Fatalf("expected unverified-prefix truncation refusal error, got: %v", err)
		}
		after3b, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after3b, beforePartial) {
			t.Fatalf("readable size > want without output_digest mutated file: got %q, want %q", string(after3b), string(beforePartial))
		}

		// Restore exact committed bytes, append one complete valid JSONL record from another writer (keepEnd == size),
		// and verify readable resume without OutputDigest preserves it and appends rec3 cleanly.
		if err := os.WriteFile(outPath, disk2, 0o600); err != nil {
			t.Fatal(err)
		}
		fOther, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, recOther)), NewJSONWriterSink(fOther), Options{}); err != nil {
			_ = fOther.Close()
			t.Fatal(err)
		}
		_ = fOther.Close()

		f4, err := os.OpenFile(outPath, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sum4, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1, rec2, rec3)), NewJSONWriterSink(&syntheticNamedFile{file: f4, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = f4.Close()
		if err != nil {
			t.Fatalf("readable resume without OutputDigest when all trailing records are complete failed: %v", err)
		}
		if sum4.SkippedCheckpointed != 3 || sum4.ReplayedSpans != 1 {
			t.Fatalf("sum4 = %+v, want SkippedCheckpointed=3 ReplayedSpans=1", sum4)
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		finalLines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(finalLines) != 5 || !strings.Contains(finalLines[3], "bytes-rec-other") || !strings.Contains(finalLines[4], "bytes-rec-3") {
			t.Fatalf("unexpected final lines after preserving complete trailing record without output_digest: %q", string(finalBytes))
		}

		// Boundary newline mismatch when resuming without OutputDigest must fail closed
		// without modifying the output file.
		corruptedPrefix := append(bytes.Clone(disk2[:len(disk2)-1]), ' ')
		if err := os.WriteFile(outPath, corruptedPrefix, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cpPath, mustMarshalCheckpoint(t, st2), 0o600); err != nil {
			t.Fatal(err)
		}
		fMismatch, err := os.OpenFile(outPath, os.O_RDWR|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1, rec2, rec3)), NewJSONWriterSink(&syntheticNamedFile{file: fMismatch, name: label}), Options{
			Checkpoint: &CheckpointConfig{Path: cpPath, Source: "ndjson:synthetic"},
		})
		_ = fMismatch.Close()
		if err == nil || !strings.Contains(err.Error(), "boundary newline state does not match checkpoint") {
			t.Fatalf("expected boundary newline mismatch error, got: %v", err)
		}
		afterMismatch, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterMismatch, corruptedPrefix) {
			t.Fatalf("boundary newline mismatch modified file: got %q, want %q", string(afterMismatch), string(corruptedPrefix))
		}

		// When Name() resolves to a different existing file on disk (!os.SameFile),
		// outputTarget must still use "handle:" and snapshotOutputState must not fail
		// or hash the wrong file.
		otherPath := filepath.Join(dir, "other-on-disk.ndjson")
		otherContent := strings.Repeat(`{"signal":"traces","otlp":{"other":1}}`+"\n", 4)
		if err := os.WriteFile(otherPath, []byte(otherContent), 0o600); err != nil {
			t.Fatal(err)
		}
		sameNameOut := filepath.Join(dir, "actual-out.ndjson")
		sameNameCP := filepath.Join(dir, "same-name-cp.json")
		fDiff, err := os.OpenFile(sameNameOut, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		sumDiff, err := Replay(context.Background(), bytes.NewReader(marshalRecords(t, rec0, rec1)), NewJSONWriterSink(&syntheticNamedFile{file: fDiff, name: otherPath}), Options{
			Checkpoint: &CheckpointConfig{Path: sameNameCP, Source: "ndjson:diff-file"},
		})
		_ = fDiff.Close()
		if err != nil {
			t.Fatalf("Replay with non-SameFile Name() failed: %v", err)
		}
		if sumDiff.ReplayedSpans != 2 {
			t.Fatalf("sumDiff.ReplayedSpans = %d, want 2", sumDiff.ReplayedSpans)
		}
		stDiff := readCheckpointFile(t, sameNameCP)
		if stDiff.OutputTarget != "handle:"+otherPath || stDiff.OutputDigest != "" {
			t.Fatalf("unexpected checkpoint state for non-SameFile handle: target=%q digest=%q", stDiff.OutputTarget, stDiff.OutputDigest)
		}
	})
}

func mustMarshalCheckpoint(t *testing.T, st checkpointState) []byte {
	t.Helper()
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

type syntheticNamedFile struct {
	file *os.File
	name string
}

func (w *syntheticNamedFile) Name() string                            { return w.name }
func (w *syntheticNamedFile) Write(p []byte) (int, error)             { return w.file.Write(p) }
func (w *syntheticNamedFile) Sync() error                             { return w.file.Sync() }
func (w *syntheticNamedFile) Stat() (fs.FileInfo, error)              { return w.file.Stat() }
func (w *syntheticNamedFile) Truncate(size int64) error               { return w.file.Truncate(size) }
func (w *syntheticNamedFile) ReadAt(p []byte, off int64) (int, error) { return w.file.ReadAt(p, off) }
func (w *syntheticNamedFile) Seek(off int64, whence int) (int64, error) {
	return w.file.Seek(off, whence)
}

type unreadableSeekTruncWriter struct {
	seekTruncWriter
	readOnly bool
}

func (w *unreadableSeekTruncWriter) ReadAt(p []byte, off int64) (int, error) {
	if w.readOnly {
		return 0, fs.ErrPermission
	}
	if off >= int64(len(w.buf)) {
		return 0, io.EOF
	}
	n := copy(p, w.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
