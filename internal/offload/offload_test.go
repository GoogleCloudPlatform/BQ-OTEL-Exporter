// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package offload

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

var fixedOffloadTime = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func TestNewValidation(t *testing.T) {
	store := NewMemoryBlobStore()
	if _, err := New(store, Options{MinBytes: 10, MaxObjectBytes: 20}); err == nil {
		t.Fatal("expected error for empty bucket")
	}
	if _, err := New(store, Options{Bucket: "b", MinBytes: 0, MaxObjectBytes: 20}); err == nil {
		t.Fatal("expected error for non-positive min_bytes")
	}
	if _, err := New(store, Options{Bucket: "b", MinBytes: 30, MaxObjectBytes: 20}); err == nil {
		t.Fatal("expected error when max_object_bytes < min_bytes")
	}
}

func TestOffloadSpanAndLog(t *testing.T) {
	store := NewMemoryBlobStore()
	off, err := New(store, Options{
		Bucket:         "my-telemetry-bucket",
		Prefix:         "custom-prefix",
		Authorizer:     "projects/p/locations/us/connections/bq-gcs",
		MinBytes:       32,
		MaxObjectBytes: 1024,
		Timeout:        time.Second,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	largePrompt := strings.Repeat("A", 64)
	sum := sha256.Sum256([]byte(largePrompt))
	wantSHA := hex.EncodeToString(sum[:])
	wantObj := "custom-prefix/spans/2026-10-11/" + wantSHA
	wantURI := "gs://my-telemetry-bucket/" + wantObj

	span := ptrace.NewSpan()
	span.Attributes().PutStr("gen_ai.prompt", largePrompt)
	span.Attributes().PutStr("small", "keep-inline")
	span.Attributes().PutStr("too_huge", strings.Repeat("Z", 2048))
	ev := span.Events().AppendEmpty()
	ev.Attributes().PutEmptyBytes("raw_chunk").FromRaw([]byte(strings.Repeat("B", 48)))

	res := pcommon.NewResource()
	scope := pcommon.NewInstrumentationScope()

	refs, err := off.OffloadSpan(context.Background(), span, res, scope)
	if err != nil {
		t.Fatalf("OffloadSpan() error = %v", err)
	}
	if len(refs) != 2 {
		t.Fatalf("OffloadSpan returned %d refs, want 2: %+v", len(refs), refs)
	}
	if refs[0].AttributePath != "attributes.gen_ai.prompt" || refs[0].ObjectRef.URI != wantURI {
		t.Errorf("refs[0] = %+v, want path attributes.gen_ai.prompt and URI %s", refs[0], wantURI)
	}
	if refs[0].ObjectRef.Authorizer != "projects/p/locations/us/connections/bq-gcs" {
		t.Errorf("refs[0].ObjectRef.Authorizer = %q", refs[0].ObjectRef.Authorizer)
	}
	if refs[0].StorageMode != "gcs_object_ref" || refs[0].ByteSize != 64 || refs[0].SHA256 != wantSHA {
		t.Errorf("refs[0] metadata mismatch: %+v", refs[0])
	}
	if got, _ := span.Attributes().Get("gen_ai.prompt"); got.Str() != "<offloaded:"+wantURI+">" {
		t.Errorf("span attribute gen_ai.prompt = %q, want offloaded placeholder", got.Str())
	}
	if got, _ := span.Attributes().Get("small"); got.Str() != "keep-inline" {
		t.Errorf("small attribute mutated to %q", got.Str())
	}
	if got, _ := span.Attributes().Get("too_huge"); len(got.Str()) != 2048 {
		t.Errorf("value exceeding MaxObjectBytes should remain untouched, got len %d", len(got.Str()))
	}
	if obj, ok := store.Get("my-telemetry-bucket", wantObj); !ok || string(obj.Data) != largePrompt {
		t.Errorf("stored object = %+v (ok=%v), want %q", obj, ok, largePrompt)
	}

	// Test OffloadLog with nested map/slice and body
	lr := plog.NewLogRecord()
	largeBody := strings.Repeat("L", 80)
	lr.Body().SetStr(largeBody)
	nested := lr.Attributes().PutEmptyMap("ctx")
	sl := nested.PutEmptySlice("items")
	sl.AppendEmpty().SetStr(strings.Repeat("I", 40))

	logRefs, err := off.OffloadLog(context.Background(), lr, res, scope)
	if err != nil {
		t.Fatalf("OffloadLog() error = %v", err)
	}
	if len(logRefs) != 2 {
		t.Fatalf("OffloadLog returned %d refs, want 2: %+v", len(logRefs), logRefs)
	}
	if logRefs[0].AttributePath != "body" || logRefs[1].AttributePath != "attributes.ctx.items[0]" {
		t.Errorf("logRefs paths = [%q, %q], want [body, attributes.ctx.items[0]]",
			logRefs[0].AttributePath, logRefs[1].AttributePath)
	}
	if !strings.HasPrefix(lr.Body().Str(), "<offloaded:gs://my-telemetry-bucket/custom-prefix/logs/2026-10-11/") {
		t.Errorf("offloaded log body = %q", lr.Body().Str())
	}
}

func TestOffloadQuarantineAndUploadErrors(t *testing.T) {
	store := NewMemoryBlobStore()
	off, err := New(store, Options{
		Bucket:         "quarantine-bucket",
		MinBytes:       16,
		MaxObjectBytes: 512,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	if got := off.OffloadQuarantine(context.Background(), "spans", []byte("short")); got.URI != "" {
		t.Errorf("below MinBytes should return empty ObjectRef, got %+v", got)
	}

	payload := []byte(strings.Repeat("Q", 64))
	ref := off.OffloadQuarantine(context.Background(), "spans", payload)
	if !strings.HasPrefix(ref.URI, "gs://quarantine-bucket/otel-offload/quarantine/spans/2026-10-11/") || !strings.HasSuffix(ref.URI, ".json") {
		t.Errorf("OffloadQuarantine URI = %q", ref.URI)
	}

	// Quarantine upload failure stays best-effort (returns empty ObjectRef),
	// whereas signal OffloadSpan/OffloadLog propagate the upload error so the
	// caller can return the record as retryable.
	outage := errors.New("simulated GCS outage")
	store.SetError(outage)
	if got := off.OffloadQuarantine(context.Background(), "spans", payload); got.URI != "" {
		t.Errorf("expected empty ObjectRef on quarantine upload failure, got %+v", got)
	}
	span := ptrace.NewSpan()
	span.Attributes().PutStr("prompt", strings.Repeat("P", 64))
	if refs, sErr := off.OffloadSpan(context.Background(), span, pcommon.NewResource(), pcommon.NewInstrumentationScope()); !errors.Is(sErr, outage) || len(refs) != 0 {
		t.Errorf("OffloadSpan() = (%+v, %v), want (nil, %v)", refs, sErr, outage)
	}
	if got, _ := span.Attributes().Get("prompt"); got.Str() != strings.Repeat("P", 64) {
		t.Errorf("failed upload should leave attribute untouched, got %q", got.Str())
	}

	lr := plog.NewLogRecord()
	lr.Body().SetStr(strings.Repeat("B", 64))
	if refs, lErr := off.OffloadLog(context.Background(), lr, pcommon.NewResource(), pcommon.NewInstrumentationScope()); !errors.Is(lErr, outage) || len(refs) != 0 {
		t.Errorf("OffloadLog() = (%+v, %v), want (nil, %v)", refs, lErr, outage)
	}
}

func TestRepeatedContentAddressedUploadsPreserveGeneration(t *testing.T) {
	store := NewMemoryBlobStore()
	off, err := New(store, Options{
		Bucket:         "dedup-bucket",
		MinBytes:       16,
		MaxObjectBytes: 512,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	payload := strings.Repeat("D", 64)
	sp1 := ptrace.NewSpan()
	sp1.Attributes().PutStr("prompt", payload)
	refs1, err := off.OffloadSpan(context.Background(), sp1, pcommon.NewResource(), pcommon.NewInstrumentationScope())
	if err != nil || len(refs1) != 1 {
		t.Fatalf("first OffloadSpan() = (%+v, %v)", refs1, err)
	}

	sp2 := ptrace.NewSpan()
	sp2.Attributes().PutStr("prompt", payload)
	refs2, err := off.OffloadSpan(context.Background(), sp2, pcommon.NewResource(), pcommon.NewInstrumentationScope())
	if err != nil || len(refs2) != 1 {
		t.Fatalf("second OffloadSpan() = (%+v, %v)", refs2, err)
	}

	if refs1[0].ObjectRef.Version == "" || refs1[0].ObjectRef.Version != refs2[0].ObjectRef.Version {
		t.Errorf("generations = (%q, %q), want identical non-empty generation", refs1[0].ObjectRef.Version, refs2[0].ObjectRef.Version)
	}
	if store.Count() != 1 {
		t.Errorf("store.Count() = %d, want 1", store.Count())
	}
}

func TestOffloadRespectsCallerContextDeadline(t *testing.T) {
	store := NewMemoryBlobStore()
	off, err := New(store, Options{
		Bucket:         "ctx-bucket",
		MinBytes:       16,
		MaxObjectBytes: 512,
		Timeout:        10 * time.Second,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if ref := off.OffloadQuarantine(cancelledCtx, "spans", []byte(strings.Repeat("Q", 64))); ref.URI != "" {
		t.Errorf("OffloadQuarantine with cancelled ctx returned %+v, want empty ObjectRef", ref)
	}
	sp := ptrace.NewSpan()
	sp.Attributes().PutStr("prompt", strings.Repeat("P", 64))
	if _, err := off.OffloadSpan(cancelledCtx, sp, pcommon.NewResource(), pcommon.NewInstrumentationScope()); !errors.Is(err, context.Canceled) {
		t.Errorf("OffloadSpan with cancelled ctx error = %v, want context.Canceled", err)
	}
}

func TestGCSBlobStoreUploadAndPreconditionPreservesGeneration(t *testing.T) {
	var uploadCalls, metaCalls int
	var gotPath, gotQuery, gotContentType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/test-bucket/o":
			uploadCalls++
			gotPath = r.URL.Path
			gotQuery = r.URL.RawQuery
			gotContentType = r.Header.Get("Content-Type")
			gotBody, _ = io.ReadAll(r.Body)
			if uploadCalls > 1 {
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"generation":"987654321"}`))

		case r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/test-bucket/o/otel-offload/spans/2026-10-11/abc":
			metaCalls++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"generation":"987654321","size":"9"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store, err := NewGCSBlobStore(
		context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("NewGCSBlobStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	ver, err := store.WriteObject(context.Background(), "test-bucket", "otel-offload/spans/2026-10-11/abc", "text/plain", []byte("hello-gcs"))
	if err != nil {
		t.Fatalf("first WriteObject() error = %v", err)
	}
	if ver != "987654321" {
		t.Errorf("first version = %q, want 987654321", ver)
	}
	if gotPath != "/upload/storage/v1/b/test-bucket/o" {
		t.Errorf("request path = %q, want /upload/storage/v1/b/test-bucket/o", gotPath)
	}
	if !strings.Contains(gotQuery, "uploadType=media") || !strings.Contains(gotQuery, "ifGenerationMatch=0") || !strings.Contains(gotQuery, "name=otel-offload%2Fspans%2F2026-10-11%2Fabc") {
		t.Errorf("request query = %q, want uploadType=media, ifGenerationMatch=0, and escaped name", gotQuery)
	}
	if gotContentType != "text/plain" || string(gotBody) != "hello-gcs" {
		t.Errorf("content-type=%q body=%q", gotContentType, string(gotBody))
	}

	// Second upload of identical object receives 412 and fetches existing generation.
	ver2, err := store.WriteObject(context.Background(), "test-bucket", "otel-offload/spans/2026-10-11/abc", "text/plain", []byte("hello-gcs"))
	if err != nil {
		t.Fatalf("second WriteObject() error = %v", err)
	}
	if ver2 != "987654321" || metaCalls != 1 {
		t.Errorf("second version = %q (metaCalls=%d), want 987654321 and metaCalls=1", ver2, metaCalls)
	}

	// Size mismatch on existing object returns error.
	if _, err := store.WriteObject(context.Background(), "test-bucket", "otel-offload/spans/2026-10-11/abc", "text/plain", []byte("different-length")); err == nil {
		t.Error("expected error when existing object size does not match upload size")
	}
}

type countingStore struct {
	mu      sync.Mutex
	calls   int
	objects map[string]string
	seq     int
	writeFn func(ctx context.Context, bucket, object, contentType string, data []byte) (string, error)
}

func (s *countingStore) WriteObject(ctx context.Context, bucket, object, contentType string, data []byte) (string, error) {
	if s.writeFn != nil {
		return s.writeFn(ctx, bucket, object, contentType, data)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.objects == nil {
		s.objects = make(map[string]string)
	}
	key := bucket + "/" + object
	if ver, ok := s.objects[key]; ok {
		return ver, nil
	}
	s.seq++
	ver := "gen-" + string(rune('0'+s.seq))
	s.objects[key] = ver
	return ver, nil
}

func TestOffloadIntraBatchAndCrossBatchDedupMetricsAndLRU(t *testing.T) {
	store := &countingStore{}
	var offloadPayloads atomic.Int64
	var offloadBytes atomic.Int64
	var dedupHits atomic.Int64

	off, err := New(store, Options{
		Bucket:         "dedup-bucket",
		MinBytes:       16,
		MaxObjectBytes: 8192,
		CacheSize:      2,
		Now:            func() time.Time { return fixedOffloadTime },
		OnOffload: func(payloads int, bytes int64, errClass string) {
			if errClass == "" {
				offloadPayloads.Add(int64(payloads))
				offloadBytes.Add(bytes)
			}
		},
		OnDedupHit: func() {
			dedupHits.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	payloadA := strings.Repeat("A", 1024)
	batchCtx := transform.WithBatchUploadCache(context.Background())
	for range 3 {
		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payloadA)
		refs, err := off.OffloadSpan(batchCtx, sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil || len(refs) != 1 {
			t.Fatalf("OffloadSpan() = (%d, %v), want 1 ref", len(refs), err)
		}
	}

	if store.calls != 1 {
		t.Fatalf("intra-batch WriteObject calls = %d, want 1", store.calls)
	}
	if got := offloadPayloads.Load(); got != 1 {
		t.Fatalf("intra-batch OnOffload payloads = %d, want 1", got)
	}
	if got := offloadBytes.Load(); got != 1024 {
		t.Fatalf("intra-batch OnOffload bytes = %d, want 1024", got)
	}
	if got := dedupHits.Load(); got != 2 {
		t.Fatalf("intra-batch OnDedupHit = %d, want 2", got)
	}

	// Cross-batch cache hit with a fresh context.
	sp2 := ptrace.NewSpan()
	sp2.Attributes().PutStr("prompt", payloadA)
	if _, err := off.OffloadSpan(context.Background(), sp2, pcommon.NewResource(), pcommon.NewInstrumentationScope()); err != nil {
		t.Fatalf("cross-batch OffloadSpan() error = %v", err)
	}
	if store.calls != 1 {
		t.Fatalf("cross-batch WriteObject calls = %d, want 1 (served from LRU cache)", store.calls)
	}
	if got := offloadPayloads.Load(); got != 1 {
		t.Fatalf("cross-batch OnOffload payloads = %d, want 1", got)
	}
	if got := dedupHits.Load(); got != 3 {
		t.Fatalf("cross-batch OnDedupHit = %d, want 3", got)
	}

	// LRU eviction when CacheSize (2) is exceeded: insert B and C, evicting A.
	for _, ch := range []string{"B", "C"} {
		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", strings.Repeat(ch, 1024))
		if _, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope()); err != nil {
			t.Fatalf("OffloadSpan(%s) error = %v", ch, err)
		}
	}
	if store.calls != 3 {
		t.Fatalf("after inserting B and C, WriteObject calls = %d, want 3", store.calls)
	}

	// B is still cached; A was evicted and must re-upload.
	spB := ptrace.NewSpan()
	spB.Attributes().PutStr("prompt", strings.Repeat("B", 1024))
	if _, err := off.OffloadSpan(context.Background(), spB, pcommon.NewResource(), pcommon.NewInstrumentationScope()); err != nil {
		t.Fatalf("OffloadSpan(B again) error = %v", err)
	}
	if store.calls != 3 {
		t.Fatalf("WriteObject calls after cached B = %d, want 3", store.calls)
	}

	spA := ptrace.NewSpan()
	spA.Attributes().PutStr("prompt", payloadA)
	if _, err := off.OffloadSpan(context.Background(), spA, pcommon.NewResource(), pcommon.NewInstrumentationScope()); err != nil {
		t.Fatalf("OffloadSpan(evicted A) error = %v", err)
	}
	if store.calls != 4 {
		t.Fatalf("WriteObject calls after evicted A = %d, want 4", store.calls)
	}
}

func TestBatchUploadCacheWaiterCancellationDoesNotFailFollowers(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	store := &countingStore{
		writeFn: func(ctx context.Context, _, _, _ string, _ []byte) (string, error) {
			close(started)
			select {
			case <-release:
				return "gen-shared", nil
			case <-ctx.Done():
				return "", ctx.Err()
			}
		},
	}

	off, err := New(store, Options{
		Bucket:         "shared-bucket",
		MinBytes:       16,
		MaxObjectBytes: 8192,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	sharedCtx := transform.WithBatchUploadCache(context.Background())
	waiter1Ctx, cancel1 := context.WithCancel(sharedCtx)
	defer cancel1()
	waiter2Ctx := sharedCtx

	payload := strings.Repeat("Z", 128)
	errCh1 := make(chan error, 1)
	go func() {
		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("k", payload)
		_, err := off.OffloadSpan(waiter1Ctx, sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		errCh1 <- err
	}()

	<-started

	errCh2 := make(chan error, 1)
	go func() {
		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("k", payload)
		_, err := off.OffloadSpan(waiter2Ctx, sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		errCh2 <- err
	}()

	// Give waiter2 a moment to register on the shared BatchUploadCache entry,
	// then cancel waiter1 while the upload is still in flight.
	time.Sleep(10 * time.Millisecond)
	cancel1()

	if err1 := <-errCh1; !errors.Is(err1, context.Canceled) {
		t.Fatalf("waiter1 error = %v, want context.Canceled", err1)
	}

	close(release)
	if err2 := <-errCh2; err2 != nil {
		t.Fatalf("waiter2 error = %v, want nil (detached leader context must finish)", err2)
	}
}

func TestGCSHTTPErrorAndClassifyOffloadError(t *testing.T) {
	cases := []struct {
		err      error
		wantCode string
		wantPerm bool
	}{
		{&GCSHTTPError{StatusCode: http.StatusBadRequest, Status: "400 Bad Request"}, "http_400", true},
		{&GCSHTTPError{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized"}, "http_401", true},
		{&GCSHTTPError{StatusCode: http.StatusForbidden, Status: "403 Forbidden", Body: "access denied"}, "http_403", true},
		{&GCSHTTPError{StatusCode: http.StatusNotFound, Status: "404 Not Found"}, "http_404", true},
		{&GCSHTTPError{StatusCode: http.StatusRequestTimeout, Status: "408 Request Timeout"}, "http_408", false},
		{&GCSHTTPError{StatusCode: http.StatusTooManyRequests, Status: "429 Too Many Requests"}, "http_429", false},
		{&GCSHTTPError{StatusCode: http.StatusUnprocessableEntity, Status: "422 Unprocessable"}, "http_4xx", true},
		{&GCSHTTPError{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable"}, "http_5xx", false},
		{errObjectContentTypeMismatch, "content_type_mismatch", true},
		{fmt.Errorf("wrapped: %w", errObjectContentTypeMismatch), "content_type_mismatch", true},
		{&ObjectMD5MismatchError{Object: "otel-offload/spans/2026-10-11/abc", StoreMD5: "1111", LocalMD5: "2222"}, "md5_mismatch", true},
		{fmt.Errorf("wrapped: %w", &ObjectMD5MismatchError{Object: "otel-offload/spans/2026-10-11/abc", StoreMD5: "1111", LocalMD5: "2222"}), "md5_mismatch", true},
		{(*ObjectMD5MismatchError)(nil), "unknown", false},
		{errObjectMD5Mismatch, "md5_mismatch", true},
		{&ObjectSizeMismatchError{Object: "otel-offload/spans/2026-10-11/abc", StoreSize: 128, LocalSize: 64}, "size_mismatch", true},
		{fmt.Errorf("wrapped: %w", &ObjectSizeMismatchError{Object: "otel-offload/spans/2026-10-11/abc", StoreSize: 128, LocalSize: 64}), "size_mismatch", true},
		{(*ObjectSizeMismatchError)(nil), "unknown", false},
		{errObjectSizeMismatch, "size_mismatch", true},
		{context.Canceled, "request_canceled", false},
		{context.DeadlineExceeded, "request_canceled", false},
		{errors.New("socket reset"), "unknown", false},
	}

	for _, tc := range cases {
		gotCode, gotPerm := ClassifyOffloadError(tc.err)
		if gotCode != tc.wantCode || gotPerm != tc.wantPerm {
			t.Errorf("ClassifyOffloadError(%v) = (%q, %v), want (%q, %v)",
				tc.err, gotCode, gotPerm, tc.wantCode, tc.wantPerm)
		}
		if IsPermanentOffloadError(tc.err) != tc.wantPerm {
			t.Errorf("IsPermanentOffloadError(%v) = %v, want %v", tc.err, !tc.wantPerm, tc.wantPerm)
		}
	}
}

func TestSequentialOffloadDoesNotMutateRecordOnSubsequentFailure(t *testing.T) {
	var calls int
	store := &countingStore{
		writeFn: func(_ context.Context, _, _, _ string, _ []byte) (string, error) {
			calls++
			if calls == 2 {
				return "", &GCSHTTPError{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable"}
			}
			return "gen-1", nil
		},
	}

	off, err := New(store, Options{
		Bucket:         "seq-bucket",
		MinBytes:       16,
		MaxObjectBytes: 8192,
		MaxConcurrency: 1,
		Now:            func() time.Time { return fixedOffloadTime },
	})
	if err != nil {
		t.Fatal(err)
	}

	sp := ptrace.NewSpan()
	sp.Attributes().PutStr("a.first", strings.Repeat("A", 64))
	sp.Attributes().PutStr("b.second", strings.Repeat("B", 64))

	if _, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope()); err == nil {
		t.Fatal("expected OffloadSpan error when second sequential upload fails")
	}
	v0, ok0 := sp.Attributes().Get("a.first")
	if !ok0 || v0.Str() != strings.Repeat("A", 64) {
		t.Fatalf("first candidate mutated despite second upload failing: got %q", v0.Str())
	}
	v1, ok1 := sp.Attributes().Get("b.second")
	if !ok1 || v1.Str() != strings.Repeat("B", 64) {
		t.Fatalf("second candidate mutated on failed upload: got %q", v1.Str())
	}
}

func TestOffloadStringAndBytesWithIdenticalPayloadPreserveDistinctContentTypes(t *testing.T) {
	const bucket = "ct-bucket"
	payloadStr := strings.Repeat("A", 64)
	payloadBytes := []byte(payloadStr)

	assertRefsMatchStore := func(t *testing.T, store *MemoryBlobStore, refs []transform.PayloadRef) {
		t.Helper()
		const prefix = "gs://" + bucket + "/"
		for _, ref := range refs {
			key, ok := strings.CutPrefix(ref.ObjectRef.URI, prefix)
			if !ok {
				t.Fatalf("ref URI %q missing prefix %q", ref.ObjectRef.URI, prefix)
			}
			obj, found := store.Get(bucket, key)
			if !found {
				t.Fatalf("store missing object %q for %s", key, ref.AttributePath)
			}
			if obj.ContentType != ref.MIMEType {
				t.Errorf("%s: stored ContentType = %q, want ref.MIMEType %q", ref.AttributePath, obj.ContentType, ref.MIMEType)
			}
			var details struct {
				GCSMetadata struct {
					ContentType string `json:"content_type"`
				} `json:"gcs_metadata"`
			}
			if err := json.Unmarshal([]byte(ref.ObjectRef.Details), &details); err != nil {
				t.Fatalf("%s: unmarshal Details %q: %v", ref.AttributePath, ref.ObjectRef.Details, err)
			}
			if details.GCSMetadata.ContentType != ref.MIMEType || details.GCSMetadata.ContentType != obj.ContentType {
				t.Errorf("%s: gcs_metadata.content_type = %q, ref.MIMEType = %q, stored = %q",
					ref.AttributePath, details.GCSMetadata.ContentType, ref.MIMEType, obj.ContentType)
			}
		}
	}

	for _, tc := range []struct {
		name           string
		firstBytes     bool
		maxConcurrency int
	}{
		{name: "sequential string then bytes", firstBytes: false, maxConcurrency: 1},
		{name: "sequential bytes then string", firstBytes: true, maxConcurrency: 1},
		{name: "concurrent string and bytes", firstBytes: false, maxConcurrency: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := NewMemoryBlobStore()
			off, err := New(store, Options{
				Bucket:         bucket,
				MinBytes:       16,
				MaxObjectBytes: 512,
				MaxConcurrency: tc.maxConcurrency,
				CacheSize:      16,
				Now:            func() time.Time { return fixedOffloadTime },
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			sp := ptrace.NewSpan()
			if tc.firstBytes {
				sp.Attributes().PutEmptyBytes("a_bytes").FromRaw(payloadBytes)
				sp.Attributes().PutStr("z_str", payloadStr)
			} else {
				sp.Attributes().PutStr("a_str", payloadStr)
				sp.Attributes().PutEmptyBytes("z_bytes").FromRaw(payloadBytes)
			}
			refs, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
			if err != nil {
				t.Fatalf("OffloadSpan() error = %v", err)
			}
			if len(refs) != 2 {
				t.Fatalf("OffloadSpan() returned %d refs, want 2: %+v", len(refs), refs)
			}
			if refs[0].ObjectRef.URI == refs[1].ObjectRef.URI {
				t.Fatalf("string and bytes attributes collided on URI %q", refs[0].ObjectRef.URI)
			}
			if store.Count() != 2 {
				t.Fatalf("store.Count() = %d, want 2 distinct objects", store.Count())
			}
			assertRefsMatchStore(t, store, refs)

			// Verify across separate spans too (exercising LRU cache hits in reverse order).
			spFirst := ptrace.NewSpan()
			spSecond := ptrace.NewSpan()
			if tc.firstBytes {
				spFirst.Attributes().PutEmptyBytes("bytes_attr").FromRaw(payloadBytes)
				spSecond.Attributes().PutStr("str_attr", payloadStr)
			} else {
				spFirst.Attributes().PutStr("str_attr", payloadStr)
				spSecond.Attributes().PutEmptyBytes("bytes_attr").FromRaw(payloadBytes)
			}
			refs1, err := off.OffloadSpan(context.Background(), spFirst, pcommon.NewResource(), pcommon.NewInstrumentationScope())
			if err != nil {
				t.Fatalf("spFirst OffloadSpan() error = %v", err)
			}
			refs2, err := off.OffloadSpan(context.Background(), spSecond, pcommon.NewResource(), pcommon.NewInstrumentationScope())
			if err != nil {
				t.Fatalf("spSecond OffloadSpan() error = %v", err)
			}
			assertRefsMatchStore(t, store, refs1)
			assertRefsMatchStore(t, store, refs2)

			// Verify log body string vs bytes attribute with identical payload.
			lr := plog.NewLogRecord()
			lr.Body().SetStr(payloadStr)
			lr.Attributes().PutEmptyBytes("bytes_attr").FromRaw(payloadBytes)
			logRefs, err := off.OffloadLog(context.Background(), lr, pcommon.NewResource(), pcommon.NewInstrumentationScope())
			if err != nil {
				t.Fatalf("OffloadLog() error = %v", err)
			}
			if len(logRefs) != 2 || logRefs[0].ObjectRef.URI == logRefs[1].ObjectRef.URI {
				t.Fatalf("OffloadLog() refs = %+v, want 2 distinct URIs", logRefs)
			}
			assertRefsMatchStore(t, store, logRefs)
		})
	}
}

func TestContentTypesCompatible(t *testing.T) {
	for _, tc := range []struct {
		name      string
		existing  string
		requested string
		want      bool
	}{
		{name: "empty existing", existing: "", requested: "text/plain; charset=utf-8", want: true},
		{name: "whitespace existing", existing: "   ", requested: "text/plain; charset=utf-8", want: true},
		{name: "empty requested", existing: "application/octet-stream", requested: "", want: true},
		{name: "exact match", existing: "text/plain; charset=utf-8", requested: "text/plain; charset=utf-8", want: true},
		{name: "case insensitive media and charset", existing: "TEXT/PLAIN; charset=UTF-8", requested: "text/plain; charset=utf-8", want: true},
		{name: "missing charset on existing", existing: "text/plain", requested: "text/plain; charset=utf-8", want: true},
		{name: "missing charset on requested", existing: "text/plain; charset=utf-8", requested: "text/plain", want: true},
		{name: "charset mismatch", existing: "text/plain; charset=iso-8859-1", requested: "text/plain; charset=utf-8", want: false},
		{name: "media type mismatch", existing: "application/octet-stream", requested: "text/plain; charset=utf-8", want: false},
		{name: "json vs plain", existing: "application/json", requested: "text/plain; charset=utf-8", want: false},
		{name: "malformed equal", existing: "not/valid/type", requested: "NOT/VALID/TYPE", want: true},
		{name: "malformed distinct", existing: "not/valid/a", requested: "not/valid/b", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := contentTypesCompatible(tc.existing, tc.requested); got != tc.want {
				t.Errorf("contentTypesCompatible(%q, %q) = %v, want %v", tc.existing, tc.requested, got, tc.want)
			}
		})
	}
}

func TestMemoryBlobStoreContentTypeCompatibility(t *testing.T) {
	ctx := context.Background()
	payload := []byte("hello-payload")

	t.Run("mismatch returns errObjectContentTypeMismatch", func(t *testing.T) {
		store := NewMemoryBlobStore()
		if _, err := store.WriteObject(ctx, "b", "obj", "application/octet-stream", payload); err != nil {
			t.Fatalf("first WriteObject: %v", err)
		}
		if _, err := store.WriteObject(ctx, "b", "obj", "text/plain; charset=utf-8", payload); !errors.Is(err, errObjectContentTypeMismatch) {
			t.Fatalf("second WriteObject err = %v, want errObjectContentTypeMismatch", err)
		}
	})

	t.Run("empty stored content type stays compatible", func(t *testing.T) {
		store := NewMemoryBlobStore()
		ver1, err := store.WriteObject(ctx, "b", "obj", "", payload)
		if err != nil {
			t.Fatalf("first WriteObject: %v", err)
		}
		ver2, err := store.WriteObject(ctx, "b", "obj", "text/plain; charset=utf-8", payload)
		if err != nil {
			t.Fatalf("second WriteObject: %v", err)
		}
		if ver2 != ver1 {
			t.Errorf("version = %q, want %q", ver2, ver1)
		}
	})

	t.Run("case and charset compatible reuse generation", func(t *testing.T) {
		store := NewMemoryBlobStore()
		ver1, err := store.WriteObject(ctx, "b", "obj", "TEXT/PLAIN; charset=UTF-8", payload)
		if err != nil {
			t.Fatalf("first WriteObject: %v", err)
		}
		ver2, err := store.WriteObject(ctx, "b", "obj", "text/plain; charset=utf-8", payload)
		if err != nil {
			t.Fatalf("second WriteObject: %v", err)
		}
		if ver2 != ver1 {
			t.Errorf("version = %q, want %q", ver2, ver1)
		}
	})
}

func TestGCSBlobStorePreconditionContentTypeCheck(t *testing.T) {
	const objectPath = "otel-offload/spans/2026-10-11/abc"
	var existingContentType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/test-bucket/o":
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
		case r.Method == http.MethodGet && r.URL.Path == "/storage/v1/b/test-bucket/o/"+objectPath:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"generation":  "424242",
				"size":        "9",
				"contentType": existingContentType,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	store, err := NewGCSBlobStore(
		context.Background(),
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	)
	if err != nil {
		t.Fatalf("NewGCSBlobStore() error = %v", err)
	}
	defer func() { _ = store.Close() }()

	existingContentType = "application/octet-stream"
	if _, err := store.WriteObject(context.Background(), "test-bucket", objectPath, "text/plain; charset=utf-8", []byte("hello-gcs")); !errors.Is(err, errObjectContentTypeMismatch) {
		t.Fatalf("412 with mismatched contentType: err = %v, want errObjectContentTypeMismatch", err)
	}

	existingContentType = "TEXT/PLAIN; charset=UTF-8"
	ver, err := store.WriteObject(context.Background(), "test-bucket", objectPath, "text/plain; charset=utf-8", []byte("hello-gcs"))
	if err != nil {
		t.Fatalf("412 with compatible contentType: err = %v", err)
	}
	if ver != "424242" {
		t.Errorf("generation = %q, want 424242", ver)
	}
}

func TestOffloadUnsuffixedCollisionFallsBackToTxtWithoutRecordingError(t *testing.T) {
	const bucket = "fallback-bucket"
	payloadStr := strings.Repeat("S", 64)
	sum := sha256.Sum256([]byte(payloadStr))
	wantSHA := hex.EncodeToString(sum[:])
	unsuffixedSpanObj := "otel-offload/spans/2026-10-11/" + wantSHA
	txtSpanObj := unsuffixedSpanObj + ".txt"
	unsuffixedLogObj := "otel-offload/logs/2026-10-11/" + wantSHA
	txtLogObj := unsuffixedLogObj + ".txt"

	t.Run("memory store string fallback and clean metrics", func(t *testing.T) {
		store := NewMemoryBlobStore()
		legacyVer, err := store.WriteObject(context.Background(), bucket, unsuffixedSpanObj, "application/octet-stream", []byte(payloadStr))
		if err != nil {
			t.Fatalf("seed legacy span object: %v", err)
		}
		if _, err := store.WriteObject(context.Background(), bucket, unsuffixedLogObj, "application/octet-stream", []byte(payloadStr)); err != nil {
			t.Fatalf("seed legacy log object: %v", err)
		}

		var errorClasses []string
		var successPayloads atomic.Int64
		var successBytes atomic.Int64
		var dedupHits atomic.Int64
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(payloads int, bytes int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
					return
				}
				successPayloads.Add(int64(payloads))
				successBytes.Add(bytes)
			},
			OnDedupHit: func() {
				dedupHits.Add(1)
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payloadStr)
		refs, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil {
			t.Fatalf("OffloadSpan() error = %v", err)
		}
		if len(refs) != 1 {
			t.Fatalf("OffloadSpan returned %d refs, want 1", len(refs))
		}
		wantTxtURI := "gs://" + bucket + "/" + txtSpanObj
		if refs[0].ObjectRef.URI != wantTxtURI {
			t.Errorf("URI = %q, want %q", refs[0].ObjectRef.URI, wantTxtURI)
		}
		if refs[0].ObjectRef.Version == "" || refs[0].ObjectRef.Version == legacyVer {
			t.Errorf("fallback Version = %q, want distinct version from legacy %q", refs[0].ObjectRef.Version, legacyVer)
		}
		if refs[0].MIMEType != "text/plain; charset=utf-8" {
			t.Errorf("MIMEType = %q, want text/plain; charset=utf-8", refs[0].MIMEType)
		}
		if got, _ := sp.Attributes().Get("prompt"); got.Str() != "<offloaded:"+wantTxtURI+">" {
			t.Errorf("span attribute = %q, want <offloaded:%s>", got.Str(), wantTxtURI)
		}
		legacyObj, ok := store.Get(bucket, unsuffixedSpanObj)
		if !ok || legacyObj.ContentType != "application/octet-stream" {
			t.Errorf("legacy object = %+v (ok=%v), want preserved application/octet-stream", legacyObj, ok)
		}
		txtObj, ok := store.Get(bucket, txtSpanObj)
		if !ok || txtObj.ContentType != "text/plain; charset=utf-8" || string(txtObj.Data) != payloadStr {
			t.Errorf("txt object = %+v (ok=%v), want text/plain; charset=utf-8", txtObj, ok)
		}

		// Repeat span upload hits LRU cache on .txt fallback with zero recorded errors.
		sp2 := ptrace.NewSpan()
		sp2.Attributes().PutStr("prompt", payloadStr)
		refs2, err := off.OffloadSpan(context.Background(), sp2, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil {
			t.Fatalf("second OffloadSpan() error = %v", err)
		}
		if refs2[0].ObjectRef.URI != wantTxtURI || refs2[0].ObjectRef.Version != refs[0].ObjectRef.Version {
			t.Errorf("second OffloadSpan ref = %+v, want %+v", refs2[0], refs[0])
		}
		if dedupHits.Load() != 1 {
			t.Errorf("dedupHits = %d, want 1", dedupHits.Load())
		}

		// OffloadLog also falls back from unsuffixed collision to .txt.
		lr := plog.NewLogRecord()
		lr.Body().SetStr(payloadStr)
		logRefs, err := off.OffloadLog(context.Background(), lr, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil {
			t.Fatalf("OffloadLog() error = %v", err)
		}
		wantLogTxtURI := "gs://" + bucket + "/" + txtLogObj
		if len(logRefs) != 1 || logRefs[0].ObjectRef.URI != wantLogTxtURI {
			t.Errorf("logRefs = %+v, want URI %q", logRefs, wantLogTxtURI)
		}

		if len(errorClasses) != 0 {
			t.Errorf("recorded internal collision errors %v, want 0", errorClasses)
		}
		if successPayloads.Load() != 2 || successBytes.Load() != int64(2*len(payloadStr)) {
			t.Errorf("success metrics = (%d, %d), want (2, %d)", successPayloads.Load(), successBytes.Load(), 2*len(payloadStr))
		}
	})

	t.Run("gcs 412 fallback end to end", func(t *testing.T) {
		var mu sync.Mutex
		objects := map[string]struct {
			gen         string
			size        string
			contentType string
			data        []byte
		}{
			unsuffixedSpanObj: {
				gen:         "100",
				size:        "64",
				contentType: "application/octet-stream",
				data:        []byte(payloadStr),
			},
		}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			defer mu.Unlock()
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o":
				name := r.URL.Query().Get("name")
				if _, exists := objects[name]; exists {
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
					return
				}
				body, _ := io.ReadAll(r.Body)
				objects[name] = struct {
					gen         string
					size        string
					contentType string
					data        []byte
				}{
					gen:         "200",
					size:        "64",
					contentType: r.Header.Get("Content-Type"),
					data:        body,
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"generation":"200"}`))

			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/"):
				name := strings.TrimPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/")
				obj, ok := objects[name]
				if !ok {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"generation":  obj.gen,
					"size":        obj.size,
					"contentType": obj.contentType,
				})

			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		store, err := NewGCSBlobStore(
			context.Background(),
			option.WithEndpoint(srv.URL),
			option.WithoutAuthentication(),
		)
		if err != nil {
			t.Fatalf("NewGCSBlobStore() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payloadStr)
		refs, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil {
			t.Fatalf("OffloadSpan() error = %v", err)
		}
		wantTxtURI := "gs://" + bucket + "/" + txtSpanObj
		if len(refs) != 1 || refs[0].ObjectRef.URI != wantTxtURI || refs[0].ObjectRef.Version != "200" {
			t.Fatalf("refs = %+v, want URI %q and version 200", refs, wantTxtURI)
		}
		if len(errorClasses) != 0 {
			t.Errorf("recorded internal collision errors %v, want 0", errorClasses)
		}
	})

	t.Run("txt retry mismatch still fails and records error", func(t *testing.T) {
		store := NewMemoryBlobStore()
		if _, err := store.WriteObject(context.Background(), bucket, unsuffixedSpanObj, "application/octet-stream", []byte(payloadStr)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.WriteObject(context.Background(), bucket, txtSpanObj, "image/png", []byte(payloadStr)); err != nil {
			t.Fatal(err)
		}

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payloadStr)
		_, err = off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if !errors.Is(err, errObjectContentTypeMismatch) {
			t.Fatalf("OffloadSpan() err = %v, want errObjectContentTypeMismatch", err)
		}
		if code, perm := ClassifyOffloadError(err); code != "content_type_mismatch" || !perm || !IsPermanentOffloadError(err) {
			t.Fatalf("ClassifyOffloadError(%v) = (%q, %v), IsPermanent=%v; want (\"content_type_mismatch\", true, true)",
				err, code, perm, IsPermanentOffloadError(err))
		}
		if len(errorClasses) != 1 || errorClasses[0] != "content_type_mismatch" {
			t.Errorf("errorClasses = %v, want [content_type_mismatch]", errorClasses)
		}
		if got, _ := sp.Attributes().Get("prompt"); got.Str() != payloadStr {
			t.Errorf("failed upload mutated attribute to %q", got.Str())
		}
	})

	t.Run("suffixed uploads do not fall back to txt", func(t *testing.T) {
		store := NewMemoryBlobStore()
		binObj := unsuffixedSpanObj + ".bin"
		if _, err := store.WriteObject(context.Background(), bucket, binObj, "text/plain", []byte(payloadStr)); err != nil {
			t.Fatal(err)
		}
		quarantineObj := "otel-offload/quarantine/spans/2026-10-11/" + wantSHA + ".json"
		if _, err := store.WriteObject(context.Background(), bucket, quarantineObj, "text/plain", []byte(payloadStr)); err != nil {
			t.Fatal(err)
		}

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutEmptyBytes("raw").FromRaw([]byte(payloadStr))
		_, err = off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if !errors.Is(err, errObjectContentTypeMismatch) {
			t.Fatalf("OffloadSpan(bytes) err = %v, want errObjectContentTypeMismatch", err)
		}
		if code, perm := ClassifyOffloadError(err); code != "content_type_mismatch" || !perm || !IsPermanentOffloadError(err) {
			t.Fatalf("ClassifyOffloadError(%v) = (%q, %v), IsPermanent=%v; want (\"content_type_mismatch\", true, true)",
				err, code, perm, IsPermanentOffloadError(err))
		}
		if ref := off.OffloadQuarantine(context.Background(), "spans", []byte(payloadStr)); ref.URI != "" {
			t.Errorf("OffloadQuarantine on .json mismatch returned %+v, want empty ObjectRef", ref)
		}
		if len(errorClasses) != 2 || errorClasses[0] != "content_type_mismatch" || errorClasses[1] != "content_type_mismatch" {
			t.Errorf("errorClasses = %v, want [content_type_mismatch content_type_mismatch]", errorClasses)
		}
	})
}

func TestOffloadHonestObjectRefDetailsAndUpdatedPreservation(t *testing.T) {
	payload := strings.Repeat("O", 48)
	md5Sum := md5.Sum([]byte(payload))
	wantMD5Hex := hex.EncodeToString(md5Sum[:])
	wantMD5B64 := base64.StdEncoding.EncodeToString(md5Sum[:])
	const wantUpdatedRFC3339 = "2026-11-13T05:00:00.123456Z"
	wantUpdatedTS, err := time.Parse(time.RFC3339Nano, wantUpdatedRFC3339)
	if err != nil {
		t.Fatal(err)
	}
	wantUpdatedMicros := wantUpdatedTS.UnixMicro()

	t.Run("plain BlobStore omits updated and emits real md5_hash and size", func(t *testing.T) {
		store := NewMemoryBlobStore()
		off, err := New(store, Options{
			Bucket:         "plain-bucket",
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
		})
		if err != nil {
			t.Fatal(err)
		}
		lr := plog.NewLogRecord()
		lr.Body().SetStr(payload)
		refs, err := off.OffloadLog(context.Background(), lr, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil || len(refs) != 1 {
			t.Fatalf("OffloadLog = (%d refs, %v), want 1 ref", len(refs), err)
		}
		var top map[string]any
		if err := json.Unmarshal([]byte(refs[0].ObjectRef.Details), &top); err != nil {
			t.Fatalf("unmarshal details: %v", err)
		}
		if len(top) != 1 {
			t.Fatalf("details top-level keys = %v, want only gcs_metadata", top)
		}
		gm, ok := top["gcs_metadata"].(map[string]any)
		if !ok {
			t.Fatalf("details missing gcs_metadata: %#v", top)
		}
		if _, hasSHA := gm["sha256"]; hasSHA {
			t.Errorf("details.gcs_metadata unexpectedly contains sha256: %#v", gm)
		}
		if _, hasUpdated := gm["updated"]; hasUpdated {
			t.Errorf("plain BlobStore must omit updated rather than inventing time.Now(): %#v", gm)
		}
		if gm["md5_hash"] != wantMD5Hex {
			t.Errorf("md5_hash = %v, want %q", gm["md5_hash"], wantMD5Hex)
		}
		if gm["size"] != float64(len(payload)) {
			t.Errorf("size = %v, want %d", gm["size"], len(payload))
		}
		if gm["content_type"] != "text/plain; charset=utf-8" {
			t.Errorf("content_type = %v, want text/plain; charset=utf-8", gm["content_type"])
		}
	})

	t.Run("GCSBlobStore preserves real updated across upload and LRU cache hit", func(t *testing.T) {
		var postCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/gcs-bucket/o" {
				postCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"generation": "777",
					"updated":    wantUpdatedRFC3339,
					"md5Hash":    wantMD5B64,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		store, err := NewGCSBlobStore(
			context.Background(),
			option.WithEndpoint(srv.URL),
			option.WithoutAuthentication(),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()

		off, err := New(store, Options{
			Bucket:         "gcs-bucket",
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
		})
		if err != nil {
			t.Fatal(err)
		}

		// First upload hits GCS and receives real updated timestamp.
		lr1 := plog.NewLogRecord()
		lr1.Body().SetStr(payload)
		refs1, err := off.OffloadLog(context.Background(), lr1, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil || len(refs1) != 1 {
			t.Fatalf("first OffloadLog = (%d, %v)", len(refs1), err)
		}

		// Second upload hits LRU cache: must make 0 HTTP calls and return the exact cached updated.
		lr2 := plog.NewLogRecord()
		lr2.Body().SetStr(payload)
		refs2, err := off.OffloadLog(context.Background(), lr2, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err != nil || len(refs2) != 1 {
			t.Fatalf("second OffloadLog = (%d, %v)", len(refs2), err)
		}
		if got := postCalls.Load(); got != 1 {
			t.Fatalf("HTTP upload count = %d, want 1 (LRU hit on second)", got)
		}
		if refs1[0].ObjectRef.Details != refs2[0].ObjectRef.Details {
			t.Errorf("LRU hit changed details:\n  first:  %s\n  second: %s", refs1[0].ObjectRef.Details, refs2[0].ObjectRef.Details)
		}

		var parsed struct {
			GCSMetadata struct {
				ContentType string `json:"content_type"`
				Size        int64  `json:"size"`
				MD5Hash     string `json:"md5_hash"`
				Updated     int64  `json:"updated"`
			} `json:"gcs_metadata"`
		}
		if err := json.Unmarshal([]byte(refs2[0].ObjectRef.Details), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed.GCSMetadata.MD5Hash != wantMD5Hex || parsed.GCSMetadata.Size != int64(len(payload)) || parsed.GCSMetadata.Updated != wantUpdatedMicros {
			t.Errorf("parsed gcs_metadata = %+v, want md5=%s size=%d updated=%d",
				parsed.GCSMetadata, wantMD5Hex, len(payload), wantUpdatedMicros)
		}
	})
}

func TestExistingObjectMD5MismatchIsPermanent(t *testing.T) {
	const bucket = "md5-mismatch-bucket"
	payload := strings.Repeat("M", 64)
	localMD5 := md5.Sum([]byte(payload))
	wantLocalMD5Hex := hex.EncodeToString(localMD5[:])

	corruptMD5 := md5.Sum([]byte(strings.Repeat("X", 64)))
	wantStoreMD5Hex := hex.EncodeToString(corruptMD5[:])
	corruptMD5B64 := base64.StdEncoding.EncodeToString(corruptMD5[:])

	t.Run("412 existing object MD5 mismatch returns typed permanent error", func(t *testing.T) {
		var uploadCalls, metaCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o":
				uploadCalls.Add(1)
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/"):
				metaCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"generation":  "909",
					"size":        fmt.Sprintf("%d", len(payload)),
					"contentType": "text/plain; charset=utf-8",
					"md5Hash":     corruptMD5B64,
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		store, err := NewGCSBlobStore(
			context.Background(),
			option.WithEndpoint(srv.URL),
			option.WithoutAuthentication(),
		)
		if err != nil {
			t.Fatalf("NewGCSBlobStore() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payload)
		refs, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err == nil || len(refs) != 0 {
			t.Fatalf("OffloadSpan() = (%+v, %v), want (nil, permanent MD5 mismatch error)", refs, err)
		}

		var md5Err *ObjectMD5MismatchError
		if !errors.As(err, &md5Err) {
			t.Fatalf("OffloadSpan() error = %T (%v), want *ObjectMD5MismatchError", err, err)
		}
		if !errors.Is(err, errObjectMD5Mismatch) {
			t.Errorf("errors.Is(err, errObjectMD5Mismatch) = false, want true")
		}
		if md5Err.Object == "" || md5Err.StoreMD5 != wantStoreMD5Hex || md5Err.LocalMD5 != wantLocalMD5Hex {
			t.Errorf("ObjectMD5MismatchError = %+v, want non-empty Object and StoreMD5=%s LocalMD5=%s", md5Err, wantStoreMD5Hex, wantLocalMD5Hex)
		}
		payloadSum := sha256.Sum256([]byte(payload))
		payloadSHA := hex.EncodeToString(payloadSum[:])
		if err.Error() != errObjectMD5Mismatch.Error() {
			t.Errorf("ObjectMD5MismatchError.Error() = %q, want content-free %q", err.Error(), errObjectMD5Mismatch.Error())
		}
		for _, forbidden := range []string{md5Err.Object, payloadSHA, wantStoreMD5Hex, wantLocalMD5Hex} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("ObjectMD5MismatchError.Error() = %q leaked %q", err.Error(), forbidden)
			}
		}
		if code, perm := ClassifyOffloadError(err); code != "md5_mismatch" || !perm || !IsPermanentOffloadError(err) {
			t.Fatalf("ClassifyOffloadError(%v) = (%q, %v), IsPermanent=%v; want (\"md5_mismatch\", true, true)",
				err, code, perm, IsPermanentOffloadError(err))
		}
		if uploadCalls.Load() != 1 || metaCalls.Load() != 1 {
			t.Errorf("HTTP calls = (upload=%d, meta=%d), want (1, 1) without .txt fallback", uploadCalls.Load(), metaCalls.Load())
		}
		if len(errorClasses) != 1 || errorClasses[0] != "md5_mismatch" {
			t.Errorf("recorded errorClasses = %v, want [md5_mismatch]", errorClasses)
		}
		if got, _ := sp.Attributes().Get("prompt"); got.Str() != payload {
			t.Errorf("failed upload mutated span attribute to %q", got.Str())
		}

		// Direct GCSBlobStore.WriteObject on 412 also surfaces the typed MD5 mismatch error.
		if _, werr := store.WriteObject(context.Background(), bucket, "direct-key", "text/plain; charset=utf-8", []byte(payload)); werr == nil {
			t.Fatal("WriteObject() on 412 MD5 mismatch succeeded, want *ObjectMD5MismatchError")
		} else if code, perm := ClassifyOffloadError(werr); code != "md5_mismatch" || !perm {
			t.Errorf("ClassifyOffloadError(WriteObject err %v) = (%q, %v), want (\"md5_mismatch\", true)", werr, code, perm)
		}
	})

	t.Run("200 upload response MD5 mismatch also returns typed permanent error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"generation": "910",
					"md5Hash":    corruptMD5B64,
				})
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		store, err := NewGCSBlobStore(
			context.Background(),
			option.WithEndpoint(srv.URL),
			option.WithoutAuthentication(),
		)
		if err != nil {
			t.Fatalf("NewGCSBlobStore() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		lr := plog.NewLogRecord()
		lr.Body().SetStr(payload)
		refs, err := off.OffloadLog(context.Background(), lr, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err == nil || len(refs) != 0 {
			t.Fatalf("OffloadLog() = (%+v, %v), want (nil, permanent MD5 mismatch error)", refs, err)
		}
		var md5Err *ObjectMD5MismatchError
		if !errors.As(err, &md5Err) {
			t.Fatalf("OffloadLog() error = %T (%v), want *ObjectMD5MismatchError", err, err)
		}
		if code, perm := ClassifyOffloadError(err); code != "md5_mismatch" || !perm || !IsPermanentOffloadError(err) {
			t.Fatalf("ClassifyOffloadError(%v) = (%q, %v), IsPermanent=%v; want (\"md5_mismatch\", true, true)",
				err, code, perm, IsPermanentOffloadError(err))
		}
		if len(errorClasses) != 1 || errorClasses[0] != "md5_mismatch" {
			t.Errorf("recorded errorClasses = %v, want [md5_mismatch]", errorClasses)
		}
	})
}

func TestExistingObjectSizeMismatchIsPermanent(t *testing.T) {
	const bucket = "size-mismatch-bucket"
	payload := strings.Repeat("S", 64)
	payloadSum := sha256.Sum256([]byte(payload))
	payloadSHA := hex.EncodeToString(payloadSum[:])
	const wrongStoreSize = int64(128)

	t.Run("412 existing object size mismatch returns typed content-free permanent error", func(t *testing.T) {
		var uploadCalls, metaCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o":
				uploadCalls.Add(1)
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
			case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/"):
				metaCalls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{
					"generation":  "911",
					"size":        fmt.Sprintf("%d", wrongStoreSize),
					"contentType": "text/plain; charset=utf-8",
				})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer srv.Close()

		store, err := NewGCSBlobStore(
			context.Background(),
			option.WithEndpoint(srv.URL),
			option.WithoutAuthentication(),
		)
		if err != nil {
			t.Fatalf("NewGCSBlobStore() error = %v", err)
		}
		defer func() { _ = store.Close() }()

		var errorClasses []string
		off, err := New(store, Options{
			Bucket:         bucket,
			MinBytes:       16,
			MaxObjectBytes: 512,
			CacheSize:      8,
			Now:            func() time.Time { return fixedOffloadTime },
			OnOffload: func(_ int, _ int64, errClass string) {
				if errClass != "" {
					errorClasses = append(errorClasses, errClass)
				}
			},
		})
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		sp := ptrace.NewSpan()
		sp.Attributes().PutStr("prompt", payload)
		refs, err := off.OffloadSpan(context.Background(), sp, pcommon.NewResource(), pcommon.NewInstrumentationScope())
		if err == nil || len(refs) != 0 {
			t.Fatalf("OffloadSpan() = (%+v, %v), want (nil, permanent size mismatch error)", refs, err)
		}

		var sizeErr *ObjectSizeMismatchError
		if !errors.As(err, &sizeErr) {
			t.Fatalf("OffloadSpan() error = %T (%v), want *ObjectSizeMismatchError", err, err)
		}
		if !errors.Is(err, errObjectSizeMismatch) {
			t.Errorf("errors.Is(err, errObjectSizeMismatch) = false, want true")
		}
		if sizeErr.Object == "" || sizeErr.StoreSize != wrongStoreSize || sizeErr.LocalSize != int64(len(payload)) {
			t.Errorf("ObjectSizeMismatchError = %+v, want non-empty Object, StoreSize=%d, LocalSize=%d",
				sizeErr, wrongStoreSize, len(payload))
		}
		if err.Error() != errObjectSizeMismatch.Error() {
			t.Errorf("ObjectSizeMismatchError.Error() = %q, want content-free %q", err.Error(), errObjectSizeMismatch.Error())
		}
		for _, forbidden := range []string{sizeErr.Object, payloadSHA, fmt.Sprintf("%d", wrongStoreSize), fmt.Sprintf("%d", len(payload))} {
			if strings.Contains(err.Error(), forbidden) {
				t.Errorf("ObjectSizeMismatchError.Error() = %q leaked %q", err.Error(), forbidden)
			}
		}
		if code, perm := ClassifyOffloadError(err); code != "size_mismatch" || !perm || !IsPermanentOffloadError(err) {
			t.Fatalf("ClassifyOffloadError(%v) = (%q, %v), IsPermanent=%v; want (\"size_mismatch\", true, true)",
				err, code, perm, IsPermanentOffloadError(err))
		}
		if uploadCalls.Load() != 1 || metaCalls.Load() != 1 {
			t.Errorf("HTTP calls = (upload=%d, meta=%d), want (1, 1) without .txt fallback", uploadCalls.Load(), metaCalls.Load())
		}
		if len(errorClasses) != 1 || errorClasses[0] != "size_mismatch" {
			t.Errorf("recorded errorClasses = %v, want [size_mismatch]", errorClasses)
		}
		if got, _ := sp.Attributes().Get("prompt"); got.Str() != payload {
			t.Errorf("failed upload mutated span attribute to %q", got.Str())
		}

		// Direct GCSBlobStore.WriteObject on 412 also surfaces the typed size mismatch error.
		if _, werr := store.WriteObject(context.Background(), bucket, "direct-key", "text/plain; charset=utf-8", []byte(payload)); werr == nil {
			t.Fatal("WriteObject() on 412 size mismatch succeeded, want *ObjectSizeMismatchError")
		} else if code, perm := ClassifyOffloadError(werr); code != "size_mismatch" || !perm {
			t.Errorf("ClassifyOffloadError(WriteObject err %v) = (%q, %v), want (\"size_mismatch\", true)", werr, code, perm)
		}
	})
}
