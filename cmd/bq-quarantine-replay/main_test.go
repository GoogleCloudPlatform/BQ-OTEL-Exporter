// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"google.golang.org/api/option"
)

func TestCLIRun(t *testing.T) {
	td := ptrace.NewTraces()
	sp := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	sp.SetName("cli-span")
	sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatal(err)
	}

	tmpDir := t.TempDir()
	inPath := filepath.Join(tmpDir, "quarantine.jsonl")
	outPath := filepath.Join(tmpDir, "replayed.jsonl")
	line := `{"ingest_time":"2026-10-11T10:00:00Z","signal":"spans","error_code":"OVERSIZE_ROW","raw_payload":` +
		strconvQuote(string(raw)) + "}\n"
	if err := os.WriteFile(inPath, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{
		"-input", inPath,
		"-output", outPath,
		"-signal", "spans",
		"-error-code", "OVERSIZE_ROW,ROW_ERROR",
		"-since", "2026-10-11T09:00:00Z",
		"-until", "2026-10-11T11:00:00Z",
	}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run() = %d, stderr=%s", code, stderr.String())
	}
	outBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(outBytes), `"signal":"spans"`) || !strings.Contains(string(outBytes), "cli-span") {
		t.Errorf("replayed output = %s", string(outBytes))
	}

	// Dry-run from stdin
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-dry-run", "-signal", "traces,metrics"}, strings.NewReader(line), &stdout, &stderr)
	if code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "replayed_spans=1") || !strings.Contains(stderr.String(), "replayed_metrics=0") {
		t.Errorf("dry-run code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	// Invalid -signal flag returns 2
	if got := run([]string{"-signal", "unknown"}, strings.NewReader(""), &stdout, &stderr); got != 2 {
		t.Errorf("bad -signal flag returned %d, want 2", got)
	}

	// Invalid timestamp flag returns 2
	if got := run([]string{"-since", "bad-time"}, strings.NewReader(""), &stdout, &stderr); got != 2 {
		t.Errorf("bad -since flag returned %d, want 2", got)
	}
}

func strconvQuote(s string) string {
	var b bytes.Buffer
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(s[i])
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// spanPayload returns OTLP JSON traces holding one span named name.
func spanPayload(t *testing.T, name string) string {
	t.Helper()
	td := ptrace.NewTraces()
	sp := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	sp.SetName(name)
	sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func quarantineLine(t *testing.T, spanName string) string {
	t.Helper()
	return `{"ingest_time":"2026-10-11T10:00:00Z","signal":"spans","error_code":"OVERSIZE_ROW","raw_payload":` +
		strconvQuote(spanPayload(t, spanName)) + "}\n"
}

func TestCLIFlagErrors(t *testing.T) {
	for _, args := range [][]string{
		{"-bq-project", "proj"},
		{"-bq-dataset", "ds"},
		{"-bq-project", "proj", "-bq-dataset", "ds", "-input", "rows.jsonl"},
		{"-bq-table", "dead_letters"},
		{"-bq-project", "Bad Project", "-bq-dataset", "ds"},
		{"-bq-project", "proj", "-bq-dataset", "ds", "-bq-table", "t`x"},
		{"-otlp-endpoint", "http://localhost:4318", "-output", "out.jsonl"},
		{"-otlp-endpoint", "http://localhost:4318", "-dry-run"},
		{"-otlp-endpoint", "ftp://localhost:4318"},
		{"-dry-run", "-checkpoint-file", "replay.ckpt"},
		{"-rate-limit", "-1"},
		{"-rate-limit", "NaN"},
		{"-rate-limit", "fast"},
	} {
		var stdout, stderr bytes.Buffer
		if got := run(args, strings.NewReader(""), &stdout, &stderr); got != 2 {
			t.Errorf("run(%q) = %d, want 2 (stderr=%q)", args, got, stderr.String())
		}
	}
}

func TestCLICheckpointResumeAppendsOutput(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "quarantine.jsonl")
	outPath := filepath.Join(dir, "replayed.jsonl")
	ckptPath := filepath.Join(dir, "replay.ckpt")
	if err := os.WriteFile(inPath, []byte(quarantineLine(t, "first")+quarantineLine(t, "second")), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-input", inPath, "-output", outPath, "-checkpoint-file", ckptPath}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("first run = %d, stderr=%s", code, stderr.String())
	}

	// More rows land in the same export. The rerun replays only those and
	// keeps what the first run wrote.
	f, err := os.OpenFile(inPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(quarantineLine(t, "third")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("resumed run = %d, stderr=%s", code, stderr.String())
	}
	if got := stderr.String(); !strings.Contains(got, "total_read=1 ") || !strings.Contains(got, "replayed_spans=1 ") || !strings.Contains(got, "skipped_checkpointed=2\n") {
		t.Errorf("resumed run summary = %q, want one record replayed and two skipped", got)
	}
	out, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], "first") || !strings.Contains(lines[1], "second") || !strings.Contains(lines[2], "third") {
		t.Errorf("output after the resumed run = %q, want first, second, third", lines)
	}
	ckpt, err := os.ReadFile(ckptPath)
	if err != nil {
		t.Fatal(err)
	}
	var ckptData struct {
		Source string `json:"source"`
	}
	if err := json.Unmarshal(ckpt, &ckptData); err != nil {
		t.Fatalf("unmarshal checkpoint JSON: %v", err)
	}
	if want := "file:" + inPath; ckptData.Source != want {
		t.Errorf("checkpoint source = %q, want %q", ckptData.Source, want)
	}

	// Without a checkpoint the output is replaced, as before.
	if code := run([]string{"-input", inPath, "-output", outPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("run without a checkpoint = %d, stderr=%s", code, stderr.String())
	}
	if out, err := os.ReadFile(outPath); err != nil || strings.Count(string(out), "\n") != 3 {
		t.Errorf("output without a checkpoint = %q, %v; want the three records once", out, err)
	}
}

// fakeBigQuery answers jobs.query for project "proj" with every row at once.
// It ignores the resume cursor, so a resumed run has to skip the rows it
// handled before.
type fakeBigQuery struct {
	mu              sync.Mutex
	datasetLocation string
	rows            [][]any
	queries         []string
	locations       []string
}

func (f *fakeBigQuery) snapshot() (queries, locations []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]string(nil), f.locations...)
}

func (f *fakeBigQuery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/datasets/ds" {
		f.mu.Lock()
		loc := f.datasetLocation
		f.mu.Unlock()
		if loc == "" {
			http.Error(w, "not configured", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"datasetReference": map[string]string{"projectId": "proj", "datasetId": "ds"},
			"location":         loc,
		})
		return
	}
	var req struct {
		Query    string `json:"query"`
		Location string `json:"location"`
	}
	if r.Method != http.MethodPost || r.URL.Path != "/bigquery/v2/projects/proj/queries" || json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, req.Query)
	f.locations = append(f.locations, req.Location)
	var fields []map[string]string
	for _, name := range []string{"ingest_time_us", "signal", "error_code", "raw_payload", "row_fp", "row_ord", "row_key"} {
		typ := "STRING"
		if name == "ingest_time_us" || name == "row_fp" || name == "row_ord" {
			typ = "INTEGER"
		}
		fields = append(fields, map[string]string{"name": name, "type": typ})
	}
	var rows []map[string]any
	for _, row := range f.rows {
		var cells []map[string]any
		for _, v := range row {
			cells = append(cells, map[string]any{"v": v})
		}
		rows = append(rows, map[string]any{"f": cells})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jobReference": map[string]string{"projectId": "proj", "jobId": "job-1", "location": "US"},
		"jobComplete":  true,
		"schema":       map[string]any{"fields": fields},
		"rows":         rows,
	})
}

// traceReceiver is an OTLP/HTTP receiver for traces that records span names.
type traceReceiver struct {
	mu    sync.Mutex
	names []string
}

func (rc *traceReceiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	req := ptraceotlp.NewExportRequest()
	if err != nil || r.URL.Path != "/v1/traces" || req.UnmarshalProto(body) != nil {
		http.Error(w, "unexpected request", http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rss := req.Traces().ResourceSpans()
	for i := range rss.Len() {
		sss := rss.At(i).ScopeSpans()
		for j := range sss.Len() {
			spans := sss.At(j).Spans()
			for k := range spans.Len() {
				rc.names = append(rc.names, spans.At(k).Name())
			}
		}
	}
}

func TestCLIBigQueryToOTLP(t *testing.T) {
	micros := strconv.FormatInt(time.Date(2026, 10, 11, 10, 0, 0, 0, time.UTC).UnixMicro(), 10)
	spanKeyBytes, err := json.Marshal(map[string]string{
		"signal":        "spans",
		"error_code":    "OVERSIZE_ROW",
		"error_message": "rejected",
		"raw_payload":   spanPayload(t, "from-bigquery"),
	})
	if err != nil {
		t.Fatal(err)
	}
	spanKey := string(spanKeyBytes)
	logKey := `{"signal":"logs","error_code":"ROW_ERROR","error_message":"rejected","raw_payload":""}`
	bq := &fakeBigQuery{rows: [][]any{
		{micros, "spans", "OVERSIZE_ROW", spanPayload(t, "from-bigquery"), "42", "0", spanKey},
		{micros, "logs", "ROW_ERROR", "", "43", "0", logKey},
	}}
	bqSrv := httptest.NewServer(bq)
	defer bqSrv.Close()
	prev := bigQueryClientOptions
	bigQueryClientOptions = func() []option.ClientOption {
		return []option.ClientOption{option.WithEndpoint(bqSrv.URL + "/bigquery/v2/"), option.WithoutAuthentication()}
	}
	defer func() { bigQueryClientOptions = prev }()
	rc := &traceReceiver{}
	otlpSrv := httptest.NewServer(rc)
	defer otlpSrv.Close()

	args := []string{
		"-bq-project", "proj", "-bq-dataset", "ds", "-bq-table", "dead_letters", "-signal", "spans",
		"-otlp-endpoint", otlpSrv.URL, "-rate-limit", "1000", "-checkpoint-file", filepath.Join(t.TempDir(), "bq.ckpt"),
	}
	var stdout, stderr bytes.Buffer
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, stderr=%s", code, stderr.String())
	}
	if want := "total_read=2 matched=1 replayed_spans=1 replayed_logs=0 replayed_metrics=0 skipped_filtered=1 "; !strings.Contains(stderr.String(), want) {
		t.Errorf("summary = %q, want %q", stderr.String(), want)
	}
	if stdout.Len() != 0 {
		t.Errorf("an OTLP replay wrote %q to stdout", stdout.String())
	}
	if gotQueries, _ := bq.snapshot(); len(gotQueries) != 1 || !strings.Contains(gotQueries[0], "FROM `proj.ds.dead_letters`") || !strings.Contains(gotQueries[0], "signal IN UNNEST(@signals)") {
		t.Errorf("queries = %q", gotQueries)
	}

	// The rerun resumes after both rows, so nothing is sent twice.
	stderr.Reset()
	if code := run(args, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("rerun = %d, stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "total_read=0 ") || !strings.Contains(stderr.String(), "skipped_checkpointed=2\n") {
		t.Errorf("rerun summary = %q, want both rows skipped", stderr.String())
	}
	if gotQueries, _ := bq.snapshot(); len(gotQueries) != 2 || !strings.Contains(gotQueries[1], "@cursor_time") {
		t.Errorf("the rerun did not resume from the cursor: %q", gotQueries)
	}
	if want := []string{"from-bigquery"}; len(rc.names) != 1 || rc.names[0] != want[0] {
		t.Errorf("receiver got spans %v, want %v", rc.names, want)
	}
}

func TestCLIFlagErrorsAndFileSafety(t *testing.T) {
	t.Run("trailing positional arguments return exit 2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"-bq-project=proj", "-bq-dataset=otel", "-dry-run", "stray-arg"}, strings.NewReader(""), &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "unexpected arguments") {
			t.Fatalf("code=%d stderr=%q, want exit 2 mentioning unexpected arguments", code, stderr.String())
		}
	})

	t.Run("same input and output file is rejected without truncation", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "same.jsonl")
		original := []byte(`{"signal":"traces","raw_payload":"{}"}` + "\n")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-input=" + path, "-output=" + path}, strings.NewReader(""), &stdout, &stderr)
		if code != 2 {
			t.Fatalf("code=%d stderr=%q, want exit 2 rejecting same input and output", code, stderr.String())
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, original) {
			t.Fatalf("input/output file modified: got %q, want %q", got, original)
		}
	})

	t.Run("redirected stdin and output pointing to same regular file is rejected without truncation", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "same_stdin.jsonl")
		original := []byte(`{"signal":"traces","raw_payload":"{}"}` + "\n")
		if err := os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		var stdout, stderr bytes.Buffer
		code := run([]string{"-output=" + path}, f, &stdout, &stderr)
		if code != 2 {
			t.Fatalf("code=%d stderr=%q, want exit 2 rejecting same stdin and output", code, stderr.String())
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, original) {
			t.Fatalf("stdin/output file modified: got %q, want %q", got, original)
		}
	})

	t.Run("non-regular character device /dev/null allowed for input and output", func(t *testing.T) {
		if _, err := os.Stat(os.DevNull); err != nil {
			t.Skipf("os.DevNull unavailable: %v", err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-input=" + os.DevNull, "-output=" + os.DevNull}, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("code=%d stderr=%q, want 0 for /dev/null", code, stderr.String())
		}
	})

	t.Run("output file uses 0600 permissions", func(t *testing.T) {
		dir := t.TempDir()
		inPath := filepath.Join(dir, "in.jsonl")
		outPath := filepath.Join(dir, "out.jsonl")
		if err := os.WriteFile(inPath, []byte(`{"signal":"traces","error_code":"TEST","raw_payload":"{}"}`+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-input=" + inPath, "-output=" + outPath}, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatalf("code=%d stderr=%q, want 0", code, stderr.String())
		}
		info, err := os.Stat(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			if perm := info.Mode().Perm(); perm != 0o600 {
				t.Fatalf("output permissions = %04o, want 0600", perm)
			}
		}
	})

	t.Run("canceled context exits non-zero cleanly", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "unexpected request", http.StatusServiceUnavailable)
		}))
		defer srv.Close()

		origOpts := bigQueryClientOptions
		bigQueryClientOptions = func() []option.ClientOption {
			return []option.ClientOption{option.WithEndpoint(srv.URL), option.WithoutAuthentication()}
		}
		defer func() { bigQueryClientOptions = origOpts }()

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var stdout, stderr bytes.Buffer
		code := runContext(ctx, []string{"-bq-project=proj", "-bq-dataset=otel", "-dry-run"}, strings.NewReader(""), &stdout, &stderr)
		if code != 1 {
			t.Fatalf("code=%d stderr=%q, want 1 on canceled context", code, stderr.String())
		}
	})

	t.Run("-bq-location without -bq-project and -bq-dataset exits 2", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		code := run([]string{"-bq-location=EU"}, strings.NewReader(""), &stdout, &stderr)
		if code != 2 || !strings.Contains(stderr.String(), "-bq-location needs -bq-project and -bq-dataset") {
			t.Fatalf("code=%d stderr=%q, want exit 2", code, stderr.String())
		}
	})

	t.Run("-h and -help return exit 0 and unknown flag returns exit 2", func(t *testing.T) {
		for _, arg := range []string{"-h", "-help"} {
			var stdout, stderr bytes.Buffer
			code := run([]string{arg}, strings.NewReader(""), &stdout, &stderr)
			if code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "-bq-location") {
				t.Fatalf("%s: code=%d stdout=%q stderr=%q, want exit 0 with usage mentioning -bq-location",
					arg, code, stdout.String(), stderr.String())
			}
		}
		var stdout, stderr bytes.Buffer
		code := run([]string{"-bogus"}, strings.NewReader(""), &stdout, &stderr)
		if code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "flag provided but not defined: -bogus") {
			t.Fatalf("unknown flag: code=%d stdout=%q stderr=%q, want exit 2", code, stdout.String(), stderr.String())
		}
	})
}

func TestCLIBigQueryLocationFlag(t *testing.T) {
	bq := &fakeBigQuery{datasetLocation: "EU"}
	bqSrv := httptest.NewServer(bq)
	defer bqSrv.Close()

	prev := bigQueryClientOptions
	bigQueryClientOptions = func() []option.ClientOption {
		return []option.ClientOption{option.WithEndpoint(bqSrv.URL + "/bigquery/v2/"), option.WithoutAuthentication()}
	}
	defer func() { bigQueryClientOptions = prev }()

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-bq-project=proj", "-bq-dataset=ds", "-dry-run"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("auto-detect run = %d, stderr=%s", code, stderr.String())
	}
	stderr.Reset()
	if code := run([]string{"-bq-project=proj", "-bq-dataset=ds", "-bq-location=europe-west1", "-dry-run"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("explicit -bq-location run = %d, stderr=%s", code, stderr.String())
	}
	want := []string{"EU", "europe-west1"}
	_, gotLocations := bq.snapshot()
	if len(gotLocations) != len(want) || gotLocations[0] != want[0] || gotLocations[1] != want[1] {
		t.Fatalf("locations = %v, want %v", gotLocations, want)
	}
}

func TestCLICheckpointResumeTruncatesPartialTrailingLine(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.ndjson")
	outPath := filepath.Join(dir, "out.ndjson")
	cpPath := filepath.Join(dir, "replay.checkpoint.json")

	rec0 := quarantineLine(t, "span-zero")
	rec1 := quarantineLine(t, "span-one")
	if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
		t.Fatal(err)
	}

	var firstStdout, firstStderr bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &firstStdout, &firstStderr); code != 0 {
		t.Fatalf("initial run failed: code=%d stderr=%s", code, firstStderr.String())
	}

	// Simulate rec1 arriving in input and a subsequent run crashing mid-write
	// while appending rec1, leaving an unterminated JSON fragment at EOF.
	if err := os.WriteFile(inPath, []byte(rec0+rec1), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"signal":"spans","otlp":{"partial":`); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("resume failed: code=%d stderr=%s", code, stderr.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(raw, []byte("\n")) {
		t.Fatalf("resumed output does not end with newline: %q", raw)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines (%q), want 2", len(lines), string(raw))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is invalid JSON: %q", i, line)
		}
	}
	if !strings.Contains(lines[0], "span-zero") || !strings.Contains(lines[1], "span-one") {
		t.Fatalf("unexpected replayed lines: %q", lines)
	}
}

func TestCLICheckpointPreservesValidUnterminatedTail(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.ndjson")
	outPath := filepath.Join(dir, "out.ndjson")
	cpPath := filepath.Join(dir, "replay.checkpoint.json")

	validUnterminated := `{"signal":"spans","otlp":{"preexisting":true}}`
	if err := os.WriteFile(outPath, []byte(validUnterminated), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var outEmpty, errEmpty bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &outEmpty, &errEmpty); code != 0 {
		t.Fatalf("empty checkpointed run failed: code=%d stderr=%s", code, errEmpty.String())
	}
	afterEmpty, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterEmpty) != validUnterminated {
		t.Fatalf("valid unterminated tail lost on empty run: got %q, want %q", string(afterEmpty), validUnterminated)
	}

	// Next checkpointed replay must keep line 0 intact and insert '\n' before line 1.
	cpPath2 := filepath.Join(dir, "replay2.checkpoint.json")
	rec0 := quarantineLine(t, "span-after-unterminated")
	if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
		t.Fatal(err)
	}
	var outNext, errNext bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath2}, strings.NewReader(""), &outNext, &errNext); code != 0 {
		t.Fatalf("checkpointed replay after unterminated tail failed: code=%d stderr=%s", code, errNext.String())
	}
	finalBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(finalBytes, []byte("\n")) {
		t.Fatalf("final output missing trailing newline: %q", string(finalBytes))
	}
	lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
	if len(lines) != 2 || lines[0] != validUnterminated || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "span-after-unterminated") {
		t.Fatalf("unexpected CLI output after unterminated tail: %q", string(finalBytes))
	}
}

func TestCLICheckpointRejectsDifferentOutputFileWithoutModification(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.ndjson")
	outA := filepath.Join(dir, "outA.ndjson")
	outB := filepath.Join(dir, "outB.ndjson")
	cpPath := filepath.Join(dir, "replay.checkpoint.json")

	rec0 := quarantineLine(t, "span-output-a")
	if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
		t.Fatal(err)
	}
	var out1, err1 bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outA, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out1, &err1); code != 0 {
		t.Fatalf("initial run to outA failed: code=%d stderr=%s", code, err1.String())
	}

	preexistingB := strings.Repeat(`{"signal":"spans","otlp":{"existing":"B"}}`+"\n", 10)
	if err := os.WriteFile(outB, []byte(preexistingB), 0o600); err != nil {
		t.Fatal(err)
	}
	var out2, err2 bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outB, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out2, &err2); code == 0 {
		t.Fatalf("expected non-zero exit resuming cpA against outB, got 0 (stderr=%s)", err2.String())
	}
	gotB, err := os.ReadFile(outB)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotB) != preexistingB {
		t.Fatalf("mismatched checkpoint resume modified outB: got %d bytes, want %d bytes", len(gotB), len(preexistingB))
	}

	// Even when outC shares the exact prefix of outA (e.g. copied before appending),
	// OutputTarget must still reject resuming cpA against a different file path.
	outAVal, err := os.ReadFile(outA)
	if err != nil {
		t.Fatal(err)
	}
	outC := filepath.Join(dir, "outC.ndjson")
	preexistingC := string(outAVal) + `{"signal":"spans","otlp":{"existing":"C"}}` + "\n"
	if err := os.WriteFile(outC, []byte(preexistingC), 0o600); err != nil {
		t.Fatal(err)
	}
	var out3, err3 bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outC, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out3, &err3); code == 0 {
		t.Fatalf("expected non-zero exit resuming cpA against same-prefix outC, got 0 (stderr=%s)", err3.String())
	}
	gotC, err := os.ReadFile(outC)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotC) != preexistingC {
		t.Fatalf("mismatched checkpoint resume modified outC: got %d bytes, want %d bytes", len(gotC), len(preexistingC))
	}
}

func TestCLICheckpointSharedOutputPreservesSecondSourceRecords(t *testing.T) {
	dir := t.TempDir()
	in1 := filepath.Join(dir, "in1.ndjson")
	in2 := filepath.Join(dir, "in2.ndjson")
	sharedOut := filepath.Join(dir, "shared.ndjson")
	cp1 := filepath.Join(dir, "cp1.json")
	cp2 := filepath.Join(dir, "cp2.json")

	rec1 := quarantineLine(t, "shared-src-1")
	rec2 := quarantineLine(t, "shared-src-2")
	if err := os.WriteFile(in1, []byte(rec1), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(in2, []byte(rec2), 0o600); err != nil {
		t.Fatal(err)
	}

	var out1, err1 bytes.Buffer
	if code := run([]string{"-input=" + in1, "-output=" + sharedOut, "-checkpoint-file=" + cp1}, strings.NewReader(""), &out1, &err1); code != 0 {
		t.Fatalf("source 1 run failed: code=%d stderr=%s", code, err1.String())
	}
	var out2, err2 bytes.Buffer
	if code := run([]string{"-input=" + in2, "-output=" + sharedOut, "-checkpoint-file=" + cp2}, strings.NewReader(""), &out2, &err2); code != 0 {
		t.Fatalf("source 2 run failed: code=%d stderr=%s", code, err2.String())
	}

	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		t.Cleanup(func() { _ = os.Chmod(sharedOut, 0o600) })
		beforeUnreadable, err := os.ReadFile(sharedOut)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(sharedOut, 0o200); err != nil {
			t.Fatal(err)
		}
		var outUnreadable, errUnreadable bytes.Buffer
		if code := run([]string{"-input=" + in1, "-output=" + sharedOut, "-checkpoint-file=" + cp1}, strings.NewReader(""), &outUnreadable, &errUnreadable); code == 0 {
			t.Fatalf("expected non-zero exit resuming source 1 on unreadable shared output with extra bytes, got 0 (stderr=%s)", errUnreadable.String())
		}
		if err := os.Chmod(sharedOut, 0o600); err != nil {
			t.Fatal(err)
		}
		afterUnreadable, err := os.ReadFile(sharedOut)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterUnreadable, beforeUnreadable) {
			t.Fatalf("unreadable shared output resume modified file: got %q, want %q", string(afterUnreadable), string(beforeUnreadable))
		}
	}

	// Resuming source 1 with cp1 against sharedOut must keep source 2's completed record intact.
	var out3, err3 bytes.Buffer
	if code := run([]string{"-input=" + in1, "-output=" + sharedOut, "-checkpoint-file=" + cp1}, strings.NewReader(""), &out3, &err3); code != 0 {
		t.Fatalf("resuming source 1 failed: code=%d stderr=%s", code, err3.String())
	}
	finalBytes, err := os.ReadFile(sharedOut)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "shared-src-1") || !strings.Contains(lines[1], "shared-src-2") {
		t.Fatalf("shared output lost source 2 record after resuming source 1: %q", string(finalBytes))
	}
}

func TestCLICheckpointMode0200PreservesPendingNewlineAfterFilteredRun(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("0200 read restrictions are not enforced on Windows or for root")
	}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.ndjson")
	outPath := filepath.Join(dir, "out.ndjson")
	cpPath := filepath.Join(dir, "replay.checkpoint.json")
	t.Cleanup(func() { _ = os.Chmod(outPath, 0o600) })

	seed := `{"signal":"spans","otlp":{"seed":1}}`
	if err := os.WriteFile(outPath, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	filteredRec := strings.Replace(quarantineLine(t, "filtered-span"), `"error_code":"OVERSIZE_ROW"`, `"error_code":"SKIP_ME"`, 1)
	matchingRec := quarantineLine(t, "matching-span")
	if err := os.WriteFile(inPath, []byte(filteredRec), 0o600); err != nil {
		t.Fatal(err)
	}

	var out1, err1 bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-error-code=OVERSIZE_ROW", "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out1, &err1); code != 0 {
		t.Fatalf("filtered checkpoint run failed: code=%d stderr=%s", code, err1.String())
	}

	if err := os.Chmod(outPath, 0o200); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inPath, []byte(filteredRec+matchingRec), 0o600); err != nil {
		t.Fatal(err)
	}
	var out2, err2 bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-error-code=OVERSIZE_ROW", "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out2, &err2); code != 0 {
		t.Fatalf("mode 0200 resume failed: code=%d stderr=%s", code, err2.String())
	}

	if err := os.Chmod(outPath, 0o600); err != nil {
		t.Fatal(err)
	}
	finalBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
	if len(lines) != 2 || lines[0] != seed || !json.Valid([]byte(lines[1])) || !strings.Contains(lines[1], "matching-span") {
		t.Fatalf("mode 0200 resume dropped pending newline: %q", string(finalBytes))
	}
}
