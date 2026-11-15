// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package transform_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/redact"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

func buildTestMessageDescriptor(t *testing.T, name string, dp *descriptorpb.DescriptorProto) protoreflect.MessageDescriptor {
	t.Helper()
	fd, err := protodesc.NewFile(&descriptorpb.FileDescriptorProto{
		Syntax:      proto.String("proto2"),
		Name:        proto.String(name + ".proto"),
		MessageType: []*descriptorpb.DescriptorProto{dp},
	}, nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile(%s): %v", name, err)
	}
	return fd.Messages().Get(0)
}

func assertStreamMatchesLegacyWire(
	t *testing.T,
	label string,
	md protoreflect.MessageDescriptor,
	gotWire, wantWire []byte,
) {
	t.Helper()
	wantMsg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(wantWire, wantMsg); err != nil {
		t.Fatalf("%s: unmarshal legacy wire: %v", label, err)
	}
	gotMsg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(gotWire, gotMsg); err != nil {
		t.Fatalf("%s: unmarshal stream wire: %v", label, err)
	}
	if !proto.Equal(gotMsg, wantMsg) {
		t.Fatalf("%s: decoded protobuf mismatch:\ngot:  %v\nwant: %v", label, gotMsg, wantMsg)
	}
}

func mergeSortedTestIndices(a, b []int) []int {
	if len(b) == 0 {
		return slices.Clone(a)
	}
	if len(a) == 0 {
		return slices.Clone(b)
	}
	out := make([]int, 0, len(a)+len(b))
	out = append(out, a...)
	out = append(out, b...)
	sort.Ints(out)
	return slices.Compact(out)
}

type countingBlobStore struct {
	inner   *offload.MemoryBlobStore
	puts    atomic.Int64
	onWrite func()
}

func (c *countingBlobStore) WriteObject(ctx context.Context, bucket, object, contentType string, data []byte) (string, error) {
	c.puts.Add(1)
	if c.onWrite != nil {
		c.onWrite()
	}
	return c.inner.WriteObject(ctx, bucket, object, contentType, data)
}

type spyEligOffloader struct {
	inner     *offload.Offloader
	eligSpans atomic.Int64
	eligLogs  atomic.Int64
}

var (
	_ transform.ConcurrentPayloadOffloader = (*spyEligOffloader)(nil)
	_ transform.ConcurrentPayloadOffloader = (*flakyOffloadRecord)(nil)
)

func (s *spyEligOffloader) MaxConcurrency() int {
	return s.inner.MaxConcurrency()
}

func (s *spyEligOffloader) HasEligibleSpan(span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) bool {
	s.eligSpans.Add(1)
	return s.inner.HasEligibleSpan(span, res, scope)
}

func (s *spyEligOffloader) HasEligibleLog(lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) bool {
	s.eligLogs.Add(1)
	return s.inner.HasEligibleLog(lr, res, scope)
}

func (s *spyEligOffloader) OffloadSpan(ctx context.Context, span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	return s.inner.OffloadSpan(ctx, span, res, scope)
}

func (s *spyEligOffloader) OffloadLog(ctx context.Context, lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	return s.inner.OffloadLog(ctx, lr, res, scope)
}

func (s *spyEligOffloader) OffloadSpanTracked(ctx context.Context, span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) (transform.OffloadReport, error) {
	return s.inner.OffloadSpanTracked(ctx, span, res, scope)
}

func (s *spyEligOffloader) OffloadLogTracked(ctx context.Context, lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) (transform.OffloadReport, error) {
	return s.inner.OffloadLogTracked(ctx, lr, res, scope)
}

type flakyOffloadRecord struct {
	spanErrByName map[string]error
	logErrByAttr  map[string]error
	inner         *offload.Offloader
	conc          int
}

func (f *flakyOffloadRecord) MaxConcurrency() int { return f.conc }

func (f *flakyOffloadRecord) HasEligibleSpan(span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) bool {
	if _, hasErr := f.spanErrByName[span.Name()]; hasErr {
		return true
	}
	return f.inner.HasEligibleSpan(span, res, scope)
}

func (f *flakyOffloadRecord) HasEligibleLog(lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) bool {
	if v, ok := lr.Attributes().Get("flaky_key"); ok {
		if _, hasErr := f.logErrByAttr[v.Str()]; hasErr {
			return true
		}
	}
	return f.inner.HasEligibleLog(lr, res, scope)
}

func (f *flakyOffloadRecord) OffloadSpan(ctx context.Context, span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	if err := f.spanErrByName[span.Name()]; err != nil {
		return nil, err
	}
	return f.inner.OffloadSpan(ctx, span, res, scope)
}

func (f *flakyOffloadRecord) OffloadLog(ctx context.Context, lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	if v, ok := lr.Attributes().Get("flaky_key"); ok {
		if err := f.logErrByAttr[v.Str()]; err != nil {
			return nil, err
		}
	}
	return f.inner.OffloadLog(ctx, lr, res, scope)
}

func (f *flakyOffloadRecord) OffloadSpanTracked(ctx context.Context, span ptrace.Span, res pcommon.Resource, scope pcommon.InstrumentationScope) (transform.OffloadReport, error) {
	if err := f.spanErrByName[span.Name()]; err != nil {
		return transform.OffloadReport{}, err
	}
	return f.inner.OffloadSpanTracked(ctx, span, res, scope)
}

func (f *flakyOffloadRecord) OffloadLogTracked(ctx context.Context, lr plog.LogRecord, res pcommon.Resource, scope pcommon.InstrumentationScope) (transform.OffloadReport, error) {
	if v, ok := lr.Attributes().Get("flaky_key"); ok {
		if err := f.logErrByAttr[v.Str()]; err != nil {
			return transform.OffloadReport{}, err
		}
	}
	return f.inner.OffloadLogTracked(ctx, lr, res, scope)
}

func putNestedMapDepth(dst pcommon.Map, key string, depth int) {
	cur := dst.PutEmptyMap(key)
	for i := 2; i < depth; i++ {
		cur = cur.PutEmptyMap("n")
	}
	cur.PutStr("leaf", "deep")
}

func setNestedBodyDepth(body pcommon.Value, depth int) {
	cur := body.SetEmptyMap()
	for i := 2; i < depth; i++ {
		cur = cur.PutEmptyMap("n")
	}
	cur.PutStr("leaf", "deep")
}

// Verifies that structural pre-offload checks (including nesting depth > 16)
// run BEFORE HasEligibleSpan / HasEligibleLog on both sequential and parallel
// paths, both for Row maps and Stream*Rows, so rejected records never walk
// nested structures for offload eligibility, never upload to the blob store,
// and keep their structural rejection reason instead of shifting to value_size.
func TestPreOffloadStructuralRejectsBeforeEligibilityScan(t *testing.T) {
	limits := transform.DefaultLimits()
	limits.MaxNestingDepth = 16
	limits.MaxValueBytes = 180

	for _, tc := range []struct {
		name string
		conc int
	}{
		{name: "sequential_pre_offload", conc: 1},
		{name: "parallel_pre_offload", conc: 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &countingBlobStore{inner: offload.NewMemoryBlobStore()}
			off, err := offload.New(store, offload.Options{
				Bucket:         "test-bucket",
				Prefix:         "otel",
				Authorizer:     "projects/p/locations/us/connections/c",
				MinBytes:       180,
				MaxObjectBytes: 4096,
				MaxConcurrency: tc.conc,
				Timeout:        5 * time.Second,
			})
			if err != nil {
				t.Fatalf("offload.New: %v", err)
			}
			spy := &spyEligOffloader{inner: off}
			opts := transform.Options{
				Limits:           limits,
				Now:              func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
				Contract:         schema.ContractV1Candidate,
				PayloadOffloader: spy,
			}

			// Spans: record 0 has depth 18 > 16 AND an oversized (>64B) attribute;
			// record 1 (for parallel path) is valid and eligible for offload.
			spanEnc, err := protoenc.New(schema.SpansTableSchema())
			if err != nil {
				t.Fatalf("protoenc.New(spans): %v", err)
			}
			buildTraces := func() ptrace.Traces {
				td := ptrace.NewTraces()
				rs := td.ResourceSpans().AppendEmpty()
				rs.Resource().Attributes().PutStr("service.name", "svc-a")
				ss := rs.ScopeSpans().AppendEmpty()

				sp0 := ss.Spans().AppendEmpty()
				sp0.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 1})
				sp0.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 1})
				sp0.SetName("deep-span")
				sp0.SetStartTimestamp(1_700_000_000_000_000_000)
				sp0.SetEndTimestamp(1_700_000_000_001_000_000)
				// Insert oversized value before the deep attribute so any premature
				// checkSpan(..., checkValueBytes=true) would shift the reject to value_size.
				sp0.Attributes().PutStr("aaa_large", strings.Repeat("X", 256))
				putNestedMapDepth(sp0.Attributes(), "zzz_deep", 18)

				if tc.conc > 1 {
					sp1 := ss.Spans().AppendEmpty()
					sp1.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 2})
					sp1.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 2})
					sp1.SetName("valid-span-1")
					sp1.SetStartTimestamp(1_700_000_000_000_000_000)
					sp1.SetEndTimestamp(1_700_000_000_001_000_000)
					sp1.Attributes().PutStr("payload", strings.Repeat("Y", 256))

					sp2 := ss.Spans().AppendEmpty()
					sp2.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 3})
					sp2.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 3})
					sp2.SetName("valid-span-2")
					sp2.SetStartTimestamp(1_700_000_000_000_000_000)
					sp2.SetEndTimestamp(1_700_000_000_001_000_000)
					sp2.Attributes().PutStr("payload", strings.Repeat("U", 256))
				}
				return td
			}

			wantEligCalls := int64(0)
			wantPuts := int64(0)
			var (
				barrierMu sync.Mutex
				arrived   int
				bothReady chan struct{}
			)
			resetBarrier := func() {
				if tc.conc <= 1 {
					return
				}
				barrierMu.Lock()
				arrived = 0
				bothReady = make(chan struct{})
				barrierMu.Unlock()
			}
			if tc.conc > 1 {
				wantEligCalls = 2
				wantPuts = 2
				// Two-party rendezvous proves preOffloadSpans/preOffloadLogs executes
				// uploads concurrently (if sequential, the first upload would time out).
				store.onWrite = func() {
					barrierMu.Lock()
					arrived++
					n := arrived
					ch := bothReady
					if n == 2 {
						close(ch)
					}
					barrierMu.Unlock()
					if n != 2 {
						select {
						case <-ch:
						case <-time.After(2 * time.Second):
							t.Errorf("expected parallel pre-offload concurrency=%d, timed out waiting for peer upload", tc.conc)
						}
					}
				}
			}

			spy.eligSpans.Store(0)
			store.puts.Store(0)
			resetBarrier()
			sRows, sRej := transform.SpanRows(buildTraces(), opts)
			if len(sRej) != 1 || sRej[0].Index != 0 || sRej[0].Reason != transform.ReasonNestingDepth {
				t.Fatalf("SpanRows rejects = %+v, want [index=0 reason=nesting_depth]", sRej)
			}
			if spy.eligSpans.Load() != wantEligCalls {
				t.Errorf("SpanRows HasEligibleSpan calls = %d, want %d (rejected span must not be walked)", spy.eligSpans.Load(), wantEligCalls)
			}
			if store.puts.Load() != wantPuts {
				t.Errorf("SpanRows blob puts = %d, want %d", store.puts.Load(), wantPuts)
			}

			spy.eligSpans.Store(0)
			store.puts.Store(0)
			resetBarrier()
			encSpans, sKept, ssRej, ssDrops := transform.StreamSpanRows(buildTraces(), opts, 0, spanEnc)
			if !slices.Equal(ssRej, sRej) || len(ssDrops) != 0 || len(encSpans) != len(sRows) || len(sKept) != len(sRows) {
				t.Fatalf("StreamSpanRows mismatch: enc=%d kept=%v rej=%+v drops=%+v wantRej=%+v",
					len(encSpans), sKept, ssRej, ssDrops, sRej)
			}
			if spy.eligSpans.Load() != wantEligCalls {
				t.Errorf("StreamSpanRows HasEligibleSpan calls = %d, want %d", spy.eligSpans.Load(), wantEligCalls)
			}
			if store.puts.Load() != wantPuts {
				t.Errorf("StreamSpanRows blob puts = %d, want %d", store.puts.Load(), wantPuts)
			}

			// Logs: record 0 has oversized (>64B) attribute AND deeply nested (>16) body.
			logEnc, err := protoenc.New(schema.LogsTableSchema())
			if err != nil {
				t.Fatalf("protoenc.New(logs): %v", err)
			}
			buildLogs := func() plog.Logs {
				ld := plog.NewLogs()
				rl := ld.ResourceLogs().AppendEmpty()
				rl.Resource().Attributes().PutStr("service.name", "svc-a")
				sl := rl.ScopeLogs().AppendEmpty()

				lr0 := sl.LogRecords().AppendEmpty()
				lr0.SetTimestamp(1_700_000_000_000_000_000)
				lr0.Attributes().PutStr("large_attr", strings.Repeat("Z", 256))
				setNestedBodyDepth(lr0.Body(), 18)

				if tc.conc > 1 {
					lr1 := sl.LogRecords().AppendEmpty()
					lr1.SetTimestamp(1_700_000_000_001_000_000)
					lr1.Body().SetStr(strings.Repeat("W", 256))

					lr2 := sl.LogRecords().AppendEmpty()
					lr2.SetTimestamp(1_700_000_000_002_000_000)
					lr2.Body().SetStr(strings.Repeat("V", 256))
				}
				return ld
			}

			spy.eligLogs.Store(0)
			store.puts.Store(0)
			resetBarrier()
			lRows, lRej := transform.LogRows(buildLogs(), opts)
			if len(lRej) != 1 || lRej[0].Index != 0 || lRej[0].Reason != transform.ReasonNestingDepth || lRej[0].FieldPath != "body" {
				t.Fatalf("LogRows rejects = %+v, want [index=0 reason=nesting_depth field=body]", lRej)
			}
			if spy.eligLogs.Load() != wantEligCalls {
				t.Errorf("LogRows HasEligibleLog calls = %d, want %d", spy.eligLogs.Load(), wantEligCalls)
			}
			if store.puts.Load() != wantPuts {
				t.Errorf("LogRows blob puts = %d, want %d", store.puts.Load(), wantPuts)
			}

			spy.eligLogs.Store(0)
			store.puts.Store(0)
			resetBarrier()
			encLogs, lKept, slRej, slDrops := transform.StreamLogRows(buildLogs(), opts, 0, logEnc)
			if !slices.Equal(slRej, lRej) || len(slDrops) != 0 || len(encLogs) != len(lRows) || len(lKept) != len(lRows) {
				t.Fatalf("StreamLogRows mismatch: enc=%d kept=%v rej=%+v drops=%+v wantRej=%+v",
					len(encLogs), lKept, slRej, slDrops, lRej)
			}
			if spy.eligLogs.Load() != wantEligCalls {
				t.Errorf("StreamLogRows HasEligibleLog calls = %d, want %d", spy.eligLogs.Load(), wantEligCalls)
			}
			if store.puts.Load() != wantPuts {
				t.Errorf("StreamLogRows blob puts = %d, want %d", store.puts.Load(), wantPuts)
			}
		})
	}
}

// Runs seeded multi-record differential checks comparing StreamSpanRows and
// StreamLogRows against SpanRows / LogRows + protobuf serialization across:
//   - small maxRowBytes triggering real ReasonRowBytes drops,
//   - redaction, multi-resource/scope grouping, and synthesized insert_ids,
//   - structural rejects alongside flaky transient/permanent offload errors,
//   - quarantine row parity and log drop-candidate ordinal preservation.
func TestStreamSpanAndLogRowsDifferential(t *testing.T) {
	spanEnc, err := protoenc.New(schema.SpansTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(spans): %v", err)
	}
	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(logs): %v", err)
	}
	spanMD := buildTestMessageDescriptor(t, "otel_spans_diff", spanEnc.Descriptor())
	logMD := buildTestMessageDescriptor(t, "otel_logs_diff", logEnc.Descriptor())

	redactor, err := redact.New(redact.Config{
		BlockedKeys:          []string{"authorization", "x-api-key"},
		BlockedValuePatterns: []string{`secret-[a-z0-9]+`},
		RedactLogBody:        true,
	})
	if err != nil {
		t.Fatalf("redact.New: %v", err)
	}

	rng := rand.New(rand.NewPCG(20261115, 98))
	fixedNow := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

	for _, conc := range []int{1, 3} {
		for seedIdx := 0; seedIdx < 6; seedIdx++ {
			t.Run(fmt.Sprintf("conc_%d/seed_%d", conc, seedIdx), func(t *testing.T) {
				store := offload.NewMemoryBlobStore()
				baseOff, err := offload.New(store, offload.Options{
					Bucket:         "diff-bucket",
					Prefix:         "otel",
					Authorizer:     "projects/p/locations/us/connections/c",
					MinBytes:       96,
					MaxObjectBytes: 4096,
					MaxConcurrency: conc,
					Timeout:        5 * time.Second,
				})
				if err != nil {
					t.Fatalf("offload.New: %v", err)
				}
				flakyOff := &flakyOffloadRecord{
					inner: baseOff,
					conc:  conc,
					spanErrByName: map[string]error{
						"offload-transient": errors.New("transient 503"),
						"offload-permanent": context.DeadlineExceeded,
					},
					logErrByAttr: map[string]error{
						"transient": errors.New("transient blob timeout"),
						"permanent": errors.New("permission denied"),
					},
				}

				limits := transform.DefaultLimits()
				limits.MaxNestingDepth = 6
				limits.MaxValueBytes = 256

				// --- Spans ---
				traceBatch := func() ptrace.Traces {
					td := ptrace.NewTraces()
					for r := 0; r < 2; r++ {
						rs := td.ResourceSpans().AppendEmpty()
						rs.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
						rs.Resource().Attributes().PutStr("service.name", fmt.Sprintf("svc-%d", r))
						rs.Resource().Attributes().PutStr("authorization", "Bearer secret-tok")
						for s := 0; s < 2; s++ {
							ss := rs.ScopeSpans().AppendEmpty()
							ss.Scope().SetName(fmt.Sprintf("scope-%d", s))
							ss.Scope().SetVersion("1.0.0")
							for i := 0; i < 4; i++ {
								sp := ss.Spans().AppendEmpty()
								id := byte(r*8 + s*4 + i + 1)
								sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, id})
								sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, id})
								start := pcommon.Timestamp(1_700_000_000_000_000_000 + int64(id)*1_000_000)
								sp.SetStartTimestamp(start)
								sp.SetEndTimestamp(start + 500_000)
								sp.Attributes().PutStr("token", "value-secret-abc123")
								switch {
								case r == 0 && s == 0 && i == 1:
									// Structural reject (nesting depth > 6)
									sp.SetName("deep-reject")
									putNestedMapDepth(sp.Attributes(), "nested", 8)
								case r == 0 && s == 1 && i == 0:
									sp.SetName("offload-transient")
									sp.Attributes().PutStr("blob", strings.Repeat("T", 140))
								case r == 1 && s == 0 && i == 2:
									sp.SetName("offload-permanent")
									sp.Attributes().PutStr("blob", strings.Repeat("P", 140))
								case rng.IntN(2) == 0:
									// Large attribute offloaded and small enough to survive maxRowBytes,
									// or large non-offloaded padding to trigger ReasonRowBytes.
									sp.SetName(fmt.Sprintf("op-big-%d", id))
									sp.Attributes().PutStr("pad", strings.Repeat("B", 220))
								default:
									sp.SetName(fmt.Sprintf("op-small-%d", id))
									sp.Attributes().PutInt("seq", int64(id))
								}
							}
						}
					}
					return td
				}()
				buildTraces := func() ptrace.Traces {
					cp := ptrace.NewTraces()
					traceBatch.CopyTo(cp)
					return cp
				}

				var legacySpanOffloadErrs, streamSpanOffloadErrs []int
				legacySpanOpts := transform.Options{
					Limits:           limits,
					Now:              func() time.Time { return fixedNow },
					Contract:         schema.ContractV1Candidate,
					Redactor:         redactor,
					PayloadOffloader: flakyOff,
					OnOffloadError: func(idx int, _ error) {
						legacySpanOffloadErrs = append(legacySpanOffloadErrs, idx)
					},
				}
				streamSpanOpts := legacySpanOpts
				streamSpanOpts.OnOffloadError = func(idx int, _ error) {
					streamSpanOffloadErrs = append(streamSpanOffloadErrs, idx)
				}

				sRows, sRej := transform.SpanRows(buildTraces(), legacySpanOpts)
				// Encode legacy rows first to pick a tight maxRowBytes that drops some
				// rows while keeping others.
				maxSpanRowBytes := 0
				var spanLens []int
				for _, r := range sRows {
					b, err := spanEnc.Encode(r)
					if err != nil {
						t.Fatalf("spanEnc.Encode: %v", err)
					}
					spanLens = append(spanLens, len(b))
				}
				sortedSpanLens := slices.Clone(spanLens)
				sort.Ints(sortedSpanLens)
				if len(sortedSpanLens) >= 3 {
					maxSpanRowBytes = sortedSpanLens[len(sortedSpanLens)/2]
				}

				encSpans, sKept, ssRej, ssDrops := transform.StreamSpanRows(buildTraces(), streamSpanOpts, maxSpanRowBytes, spanEnc)
				if !slices.Equal(ssRej, sRej) {
					t.Fatalf("span rejects mismatch: stream=%+v legacy=%+v", ssRej, sRej)
				}
				if !slices.Equal(streamSpanOffloadErrs, legacySpanOffloadErrs) {
					t.Fatalf("span offload error indices mismatch: stream=%v legacy=%v", streamSpanOffloadErrs, legacySpanOffloadErrs)
				}
				// Build expected kept & dropped rows from legacy path.
				rejOrErr := map[int]bool{}
				for _, rj := range sRej {
					rejOrErr[rj.Index] = true
				}
				for _, oi := range legacySpanOffloadErrs {
					rejOrErr[oi] = true
				}
				var wantSpanKeptIdx []int
				var wantSpanDrops []transform.QuarantineEntry
				var wantSpanWires [][]byte
				rowCursor := 0
				for idx := 0; idx < 16; idx++ {
					if rejOrErr[idx] {
						continue
					}
					b, err := spanEnc.Encode(sRows[rowCursor])
					if err != nil {
						t.Fatalf("spanEnc.Encode(%d): %v", rowCursor, err)
					}
					rowCursor++
					if maxSpanRowBytes > 0 && len(b) > maxSpanRowBytes {
						wantSpanDrops = append(wantSpanDrops, transform.QuarantineEntry{
							Rejection: transform.Rejection{Index: idx, Reason: transform.ReasonRowBytes, Limit: maxSpanRowBytes, Actual: len(b)},
						})
						continue
					}
					wantSpanKeptIdx = append(wantSpanKeptIdx, idx)
					wantSpanWires = append(wantSpanWires, b)
				}
				if len(wantSpanDrops) == 0 {
					t.Fatalf("expected >= 1 max_row_bytes span drop with maxSpanRowBytes=%d (lens=%v)", maxSpanRowBytes, sortedSpanLens)
				}
				if !slices.Equal(sKept, wantSpanKeptIdx) {
					t.Fatalf("span keptIndex = %v, want %v", sKept, wantSpanKeptIdx)
				}
				if !slices.Equal(ssDrops, wantSpanDrops) {
					t.Fatalf("span drops = %+v, want %+v", ssDrops, wantSpanDrops)
				}
				if len(encSpans) != len(wantSpanWires) {
					t.Fatalf("len(encSpans) = %d, want %d", len(encSpans), len(wantSpanWires))
				}
				for i := range encSpans {
					assertStreamMatchesLegacyWire(t, fmt.Sprintf("span[%d]", i), spanMD, encSpans[i], wantSpanWires[i])
				}
				// Verify offload retry selection & quarantine rows on rejected+dropped entries.
				allSpanQ := make([]transform.QuarantineEntry, 0, len(ssRej)+len(ssDrops))
				for _, rj := range ssRej {
					allSpanQ = append(allSpanQ, transform.QuarantineEntry{Rejection: rj})
				}
				allSpanQ = append(allSpanQ, ssDrops...)
				if qRows := transform.SpanQuarantineRows(buildTraces(), allSpanQ, streamSpanOpts); len(qRows) != len(allSpanQ) {
					t.Fatalf("SpanQuarantineRows = %d, want %d", len(qRows), len(allSpanQ))
				}
				if retryTD := transform.SelectSpans(buildTraces(), streamSpanOffloadErrs); retryTD.SpanCount() != len(streamSpanOffloadErrs) {
					t.Fatalf("SelectSpans count = %d, want %d", retryTD.SpanCount(), len(streamSpanOffloadErrs))
				}

				// --- Logs ---
				logBatch := func() plog.Logs {
					ld := plog.NewLogs()
					for r := 0; r < 2; r++ {
						rl := ld.ResourceLogs().AppendEmpty()
						rl.SetSchemaUrl("https://opentelemetry.io/schemas/1.26.0")
						rl.Resource().Attributes().PutStr("service.name", fmt.Sprintf("log-svc-%d", r))
						rl.Resource().Attributes().PutStr("x-api-key", "secret-key")
						sl := rl.ScopeLogs().AppendEmpty()
						sl.Scope().SetName("logger")
						for i := 0; i < 6; i++ {
							lr := sl.LogRecords().AppendEmpty()
							idx := r*6 + i
							lr.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_000_000 + int64(idx)*1_000_000))
							switch {
							case r == 0 && i == 0:
								lr.Body().SetStr("dup-entry secret-001")
								lr.Attributes().PutStr("k", "dup")
							case r == 0 && i == 1:
								// Exact duplicate of record 0 to exercise ordinal increment.
								lr.SetTimestamp(pcommon.Timestamp(1_700_000_000_000_000_000))
								lr.Body().SetStr("dup-entry secret-001")
								lr.Attributes().PutStr("k", "dup")
							case r == 0 && i == 2:
								setNestedBodyDepth(lr.Body(), 8)
							case r == 0 && i == 3:
								lr.Body().SetStr("flaky transient")
								lr.Attributes().PutStr("flaky_key", "transient")
							case r == 1 && i == 0:
								lr.Body().SetStr("flaky permanent")
								lr.Attributes().PutStr("flaky_key", "permanent")
							case r == 1 && i == 1:
								lr.Body().SetStr("oversized-for-drop " + strings.Repeat("M", 220))
								lr.Attributes().PutStr("log.record.uid", "explicit-uid-1")
							default:
								lr.Body().SetStr(fmt.Sprintf("msg-%d-%d", idx, rng.IntN(100)))
								lr.Attributes().PutStr("extra", strings.Repeat("E", 40+rng.IntN(180)))
							}
						}
					}
					return ld
				}()
				buildLogs := func() plog.Logs {
					cp := plog.NewLogs()
					logBatch.CopyTo(cp)
					return cp
				}

				var legacyLogOffloadErrs, streamLogOffloadErrs []int
				legacyLogOpts := transform.Options{
					Limits:             limits,
					Now:                func() time.Time { return fixedNow },
					Contract:           schema.ContractV1Candidate,
					SynthesizeInsertID: seedIdx%2 == 0,
					Redactor:           redactor,
					PayloadOffloader:   flakyOff,
					OnOffloadError: func(idx int, _ error) {
						legacyLogOffloadErrs = append(legacyLogOffloadErrs, idx)
					},
				}
				streamLogOpts := legacyLogOpts
				streamLogOpts.OnOffloadError = func(idx int, _ error) {
					streamLogOffloadErrs = append(streamLogOffloadErrs, idx)
				}

				lRows, lRej := transform.LogRows(buildLogs(), legacyLogOpts)
				var logLens []int
				for _, r := range lRows {
					b, err := logEnc.Encode(r)
					if err != nil {
						t.Fatalf("logEnc.Encode: %v", err)
					}
					logLens = append(logLens, len(b))
				}
				sortedLogLens := slices.Clone(logLens)
				sort.Ints(sortedLogLens)
				maxLogRowBytes := sortedLogLens[len(sortedLogLens)-2]

				encLogs, lKept, slRej, slDrops := transform.StreamLogRows(buildLogs(), streamLogOpts, maxLogRowBytes, logEnc)
				if !slices.Equal(slRej, lRej) {
					t.Fatalf("log rejects mismatch: stream=%+v legacy=%+v", slRej, lRej)
				}
				if !slices.Equal(streamLogOffloadErrs, legacyLogOffloadErrs) {
					t.Fatalf("log offload error indices mismatch: stream=%v legacy=%v", streamLogOffloadErrs, legacyLogOffloadErrs)
				}

				lRejOrErr := map[int]bool{}
				for _, rj := range lRej {
					lRejOrErr[rj.Index] = true
				}
				for _, oi := range legacyLogOffloadErrs {
					lRejOrErr[oi] = true
				}
				var wantLogKeptIdx []int
				var wantLogDrops []transform.QuarantineEntry
				var wantLogWires [][]byte
				lCursor := 0
				for idx := 0; idx < 12; idx++ {
					if lRejOrErr[idx] {
						continue
					}
					b, err := logEnc.Encode(lRows[lCursor])
					if err != nil {
						t.Fatalf("logEnc.Encode(%d): %v", lCursor, err)
					}
					lCursor++
					if maxLogRowBytes > 0 && len(b) > maxLogRowBytes {
						wantLogDrops = append(wantLogDrops, transform.QuarantineEntry{
							Rejection: transform.Rejection{Index: idx, Reason: transform.ReasonRowBytes, Limit: maxLogRowBytes, Actual: len(b)},
						})
						continue
					}
					wantLogKeptIdx = append(wantLogKeptIdx, idx)
					wantLogWires = append(wantLogWires, b)
				}
				if len(wantLogDrops) == 0 {
					t.Fatalf("expected >= 1 max_row_bytes log drop with maxLogRowBytes=%d (lens=%v)", maxLogRowBytes, sortedLogLens)
				}
				if !slices.Equal(lKept, wantLogKeptIdx) {
					t.Fatalf("log keptIndex = %v, want %v", lKept, wantLogKeptIdx)
				}
				if !slices.Equal(slDrops, wantLogDrops) {
					t.Fatalf("log drops = %+v, want %+v", slDrops, wantLogDrops)
				}
				if len(encLogs) != len(wantLogWires) {
					t.Fatalf("len(encLogs) = %d, want %d", len(encLogs), len(wantLogWires))
				}
				for i := range encLogs {
					assertStreamMatchesLegacyWire(t, fmt.Sprintf("log[%d]", i), logMD, encLogs[i], wantLogWires[i])
				}
			})
		}
	}
}

type perCallURILogOffloader struct {
	calls atomic.Int64
}

func (p *perCallURILogOffloader) OffloadSpan(_ context.Context, _ ptrace.Span, _ pcommon.Resource, _ pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	return nil, nil
}

func (p *perCallURILogOffloader) OffloadLog(_ context.Context, lr plog.LogRecord, _ pcommon.Resource, _ pcommon.InstrumentationScope) ([]transform.PayloadRef, error) {
	n := p.calls.Add(1)
	uri := "gs://b/short"
	if n == 1 {
		// Force the first identical record to exceed maxRowBytes via a long URI.
		uri = "gs://b/" + strings.Repeat("long-segment/", 16) + "obj"
	}
	lr.Body().SetStr("<offloaded>")
	return []transform.PayloadRef{{
		AttributePath: "body",
		ObjectRef:     transform.ObjectRef{URI: uri},
	}}, nil
}

// Verifies that when an earlier identical log record is dropped via
// ReasonRowBytes in StreamLogRows, the surviving peer still keeps its _1
// ordinal insert_id and merging keptIndex + dropIdx recovers both peers on retry.
func TestStreamLogRowsDropCandidateMergingPreservesOrdinal(t *testing.T) {
	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(logs): %v", err)
	}
	logMD := buildTestMessageDescriptor(t, "otel_logs_drop_merge", logEnc.Descriptor())

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "dup-svc")
	sl := rl.ScopeLogs().AppendEmpty()
	for i := 0; i < 2; i++ {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(1_700_000_000_000_000_000)
		lr.Body().SetStr("identical-body")
	}

	opts := transform.Options{
		Limits:             transform.DefaultLimits(),
		Now:                func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Contract:           schema.ContractV1Candidate,
		SynthesizeInsertID: true,
		PayloadOffloader:   &perCallURILogOffloader{},
	}

	// Measure the smaller record (index 1) vs larger record (index 0) via legacy LogRows.
	lRows, lRej := transform.LogRows(ld, opts)
	if len(lRej) != 0 || len(lRows) != 2 {
		t.Fatalf("LogRows = (%d, %+v)", len(lRows), lRej)
	}
	b0, err := logEnc.Encode(lRows[0])
	if err != nil {
		t.Fatal(err)
	}
	b1, err := logEnc.Encode(lRows[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(b0) <= len(b1) {
		t.Fatalf("expected row 0 (%d B) > row 1 (%d B)", len(b0), len(b1))
	}
	maxRowBytes := len(b1) + 10

	// Fresh offloader so call 1 (record 0) gets the long URI and drops, call 2 keeps.
	opts.PayloadOffloader = &perCallURILogOffloader{}
	encLogs, keptIndex, rejects, drops := transform.StreamLogRows(ld, opts, maxRowBytes, logEnc)
	if len(rejects) != 0 {
		t.Fatalf("unexpected rejects: %+v", rejects)
	}
	if !slices.Equal(keptIndex, []int{1}) {
		t.Fatalf("keptIndex = %v, want [1]", keptIndex)
	}
	if len(drops) != 1 || drops[0].Index != 0 || drops[0].Reason != transform.ReasonRowBytes {
		t.Fatalf("drops = %+v, want [{Index:0 Reason:row_bytes}]", drops)
	}
	if len(encLogs) != 1 {
		t.Fatalf("len(encLogs) = %d, want 1", len(encLogs))
	}

	gotMsg := dynamicpb.NewMessage(logMD)
	if err := proto.Unmarshal(encLogs[0], gotMsg); err != nil {
		t.Fatalf("proto.Unmarshal: %v", err)
	}
	insertID := gotMsg.Get(logMD.Fields().ByName("insert_id")).String()
	if insertID == lRows[0]["insert_id"] {
		t.Fatalf("kept peer insert_id = %q matched ordinal 0; record 0 did not consume ordinal 0", insertID)
	}
	if insertID != lRows[1]["insert_id"] {
		t.Fatalf("stream insert_id = %q, want legacy %q", insertID, lRows[1]["insert_id"])
	}

	dropIdx := make([]int, len(drops))
	for i, d := range drops {
		dropIdx[i] = d.Index
	}
	mergedCandidates := mergeSortedTestIndices(keptIndex, dropIdx)
	retryWithDrops := transform.PreserveLogOrdinalPeersForContract(ld, mergedCandidates, []int{1}, opts)
	if !slices.Equal(retryWithDrops, []int{0, 1}) {
		t.Fatalf("PreserveLogOrdinalPeersForContract(merged=%v) = %v, want [0 1]", mergedCandidates, retryWithDrops)
	}
	retryWithoutDrops := transform.PreserveLogOrdinalPeersForContract(ld, keptIndex, []int{1}, opts)
	if slices.Equal(retryWithoutDrops, []int{0, 1}) {
		t.Fatalf("PreserveLogOrdinalPeersForContract without drops unexpectedly included index 0: %v", retryWithoutDrops)
	}
}
