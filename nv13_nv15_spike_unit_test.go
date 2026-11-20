// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
)

const spikeAccessLogBody128B = "2026-11-17T12:00:00Z GET /api/v1/agents/sessions/turn HTTP/2.0 200 1428B 18.4ms envoy-ingress upstream=10.24.18.9:8443 status=ok"

type spikeTableStorageStats struct {
	TotalRows            int64
	TotalLogicalBytes    int64
	CurrentPhysicalBytes int64
	ActivePhysicalBytes  int64
	TotalPhysicalBytes   int64
}

func readSingleTableGetStorageStats(
	ctx context.Context, rawSvc *bigqueryapi.Service, project, dataset, table string,
) (spikeTableStorageStats, error) {
	tbl, err := rawSvc.Tables.Get(project, dataset, table).Context(ctx).Do()
	if err != nil {
		return spikeTableStorageStats{}, fmt.Errorf("tables.get %s.%s.%s: %w", project, dataset, table, err)
	}
	var totalRows int64
	if tbl.NumRows <= math.MaxInt64 {
		totalRows = int64(tbl.NumRows)
	} else {
		totalRows = math.MaxInt64
	}
	logicalBytes := tbl.NumTotalLogicalBytes
	if logicalBytes <= 0 {
		logicalBytes = tbl.NumBytes
	}
	// Measure current Capacitor storage strictly from NumCurrentPhysicalBytes
	// (which already covers active + long-term live physical storage while
	// excluding time-travel) without double-counting NumLongTermPhysicalBytes
	// or falling back to time-travel-inclusive NumActivePhysicalBytes/NumPhysicalBytes.
	var currentPhysicalBytes int64
	if tbl.NumCurrentPhysicalBytes > 0 {
		currentPhysicalBytes = tbl.NumCurrentPhysicalBytes
	}
	return spikeTableStorageStats{
		TotalRows:            totalRows,
		TotalLogicalBytes:    logicalBytes,
		CurrentPhysicalBytes: currentPhysicalBytes,
		ActivePhysicalBytes:  tbl.NumActivePhysicalBytes,
		TotalPhysicalBytes:   tbl.NumTotalPhysicalBytes,
	}, nil
}

func checkNV13PhysicalCompression(
	u, tr spikeTableStorageStats, requirePhysical bool,
) (untrimmedRatio, trimmedRatio, physicalSavingsPct float64, measured bool, err error) {
	if u.CurrentPhysicalBytes <= 0 || tr.CurrentPhysicalBytes <= 0 {
		if requirePhysical {
			return 0, 0, 0, false, fmt.Errorf(
				"positive current physical bytes required from tables.get (numCurrentPhysicalBytes > 0), got untrimmed=%d (active=%d) trimmed=%d (active=%d)",
				u.CurrentPhysicalBytes, u.ActivePhysicalBytes, tr.CurrentPhysicalBytes, tr.ActivePhysicalBytes,
			)
		}
		return 0, 0, 0, false, nil
	}
	if u.TotalLogicalBytes <= 0 || tr.TotalLogicalBytes <= 0 {
		return 0, 0, 0, false, fmt.Errorf(
			"positive logical bytes required from tables.get, got untrimmed=%d trimmed=%d",
			u.TotalLogicalBytes, tr.TotalLogicalBytes,
		)
	}
	untrimmedRatio = float64(u.TotalLogicalBytes) / float64(u.CurrentPhysicalBytes)
	trimmedRatio = float64(tr.TotalLogicalBytes) / float64(tr.CurrentPhysicalBytes)
	physicalSavingsPct = (1.0 - float64(tr.CurrentPhysicalBytes)/float64(u.CurrentPhysicalBytes)) * 100.0
	if untrimmedRatio <= 1.0 {
		return untrimmedRatio, trimmedRatio, physicalSavingsPct, true, fmt.Errorf(
			"untrimmed Capacitor compression ratio = %.2f:1, want > 1.0 (logical=%d current_physical=%d)",
			untrimmedRatio, u.TotalLogicalBytes, u.CurrentPhysicalBytes,
		)
	}
	if trimmedRatio <= 1.0 {
		return untrimmedRatio, trimmedRatio, physicalSavingsPct, true, fmt.Errorf(
			"trimmed Capacitor compression ratio = %.2f:1, want > 1.0 (logical=%d current_physical=%d)",
			trimmedRatio, tr.TotalLogicalBytes, tr.CurrentPhysicalBytes,
		)
	}
	if tr.CurrentPhysicalBytes >= u.CurrentPhysicalBytes {
		return untrimmedRatio, trimmedRatio, physicalSavingsPct, true, fmt.Errorf(
			"expected trimmed current physical bytes (%d) < untrimmed current physical bytes (%d)",
			tr.CurrentPhysicalBytes, u.CurrentPhysicalBytes,
		)
	}
	return untrimmedRatio, trimmedRatio, physicalSavingsPct, true, nil
}

func pollTablesGetStorageStats(
	ctx context.Context,
	rawSvc *bigqueryapi.Service,
	project, dataset, untrimmedPhys, trimmedPhys string,
	wantRows int64,
	timeout, interval time.Duration,
) (spikeTableStorageStats, spikeTableStorageStats, error) {
	pollCtx := ctx
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
		var cancel context.CancelFunc
		pollCtx, cancel = context.WithDeadline(ctx, deadline)
		defer cancel()
	}
	var (
		lastU, lastTr spikeTableStorageStats
		haveSample    bool
	)
	for {
		u, err := readSingleTableGetStorageStats(pollCtx, rawSvc, project, dataset, untrimmedPhys)
		if err != nil {
			if haveSample && timeout > 0 && errors.Is(err, context.DeadlineExceeded) && pollCtx.Err() != nil && ctx.Err() == nil {
				return lastU, lastTr, nil
			}
			return spikeTableStorageStats{}, spikeTableStorageStats{}, err
		}
		tr, err := readSingleTableGetStorageStats(pollCtx, rawSvc, project, dataset, trimmedPhys)
		if err != nil {
			if haveSample && timeout > 0 && errors.Is(err, context.DeadlineExceeded) && pollCtx.Err() != nil && ctx.Err() == nil {
				return lastU, lastTr, nil
			}
			return spikeTableStorageStats{}, spikeTableStorageStats{}, err
		}
		lastU, lastTr, haveSample = u, tr, true
		if u.TotalRows == wantRows && tr.TotalRows == wantRows &&
			u.TotalLogicalBytes > 0 && tr.TotalLogicalBytes > 0 &&
			u.CurrentPhysicalBytes > 0 && tr.CurrentPhysicalBytes > 0 {
			return u, tr, nil
		}
		if timeout <= 0 || interval <= 0 || time.Until(deadline) < interval {
			return u, tr, nil
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return spikeTableStorageStats{}, spikeTableStorageStats{}, ctx.Err()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			return spikeTableStorageStats{}, spikeTableStorageStats{}, ctx.Err()
		}
		if pollCtx.Err() != nil || time.Until(deadline) <= 0 {
			return lastU, lastTr, nil
		}
	}
}

func TestNV13PollTablesGetStorageStatsBoundsSlowMetadataReads(t *testing.T) {
	var serverSleepCompleted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
			serverSleepCompleted.Store(true)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bigqueryapi.Table{
			NumRows:                 100_000,
			NumTotalLogicalBytes:    48_000_000,
			NumCurrentPhysicalBytes: 6_000_000,
		})
	}))
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("bigqueryapi.NewService: %v", err)
	}

	_, _, err = pollTablesGetStorageStats(
		ctx, rawSvc, "test-proj", "ds",
		"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
		100_000, 150*time.Millisecond, 25*time.Millisecond,
	)
	if err == nil {
		t.Fatal("expected deadline error from slow tables.get metadata read, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected errors.Is(err, context.DeadlineExceeded), got: %v", err)
	}
	if serverSleepCompleted.Load() {
		t.Fatal("expected slow server handler to abort on request context cancellation before 5s timer completed")
	}

	t.Run("trimmed_table_blocks_past_deadline", func(t *testing.T) {
		var serverSleepCompleted atomic.Bool
		subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/otel_logs_untrimmed_phys") {
				w.Header().Set("Content-Type", "application/json")
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                 100_000,
					NumTotalLogicalBytes:    48_000_000,
					NumCurrentPhysicalBytes: 0,
				}); encErr != nil {
					t.Errorf("encode untrimmed table response: %v", encErr)
				}
				return
			}
			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return
			case <-timer.C:
				serverSleepCompleted.Store(true)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(bigqueryapi.Table{
				NumRows:                 100_000,
				NumTotalLogicalBytes:    26_000_000,
				NumCurrentPhysicalBytes: 0,
			})
		}))
		t.Cleanup(func() {
			subSrv.CloseClientConnections()
			subSrv.Close()
		})

		subCtx, subCancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(subCancel)
		subSvc, subErr := bigqueryapi.NewService(subCtx, option.WithEndpoint(subSrv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if subErr != nil {
			t.Fatalf("bigqueryapi.NewService: %v", subErr)
		}

		_, _, subErr = pollTablesGetStorageStats(
			subCtx, subSvc, "test-proj", "ds",
			"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
			100_000, 150*time.Millisecond, 25*time.Millisecond,
		)
		if subErr == nil {
			t.Fatal("expected deadline error when trimmed table blocks on initial poll, got nil")
		}
		if !errors.Is(subErr, context.DeadlineExceeded) {
			t.Fatalf("expected errors.Is(err, context.DeadlineExceeded), got: %v", subErr)
		}
		if serverSleepCompleted.Load() {
			t.Fatal("expected slow trimmed-table handler to abort on request context cancellation before 5s timer completed")
		}
	})

	t.Run("repoll_deadline_preserves_complete_sample", func(t *testing.T) {
		var trimmedCalls atomic.Int64
		var repollSleepCompleted atomic.Bool
		subSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/otel_logs_untrimmed_phys") {
				w.Header().Set("Content-Type", "application/json")
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                 100_000,
					NumTotalLogicalBytes:    48_000_000,
					NumCurrentPhysicalBytes: 0,
				}); encErr != nil {
					t.Errorf("encode untrimmed table response: %v", encErr)
				}
				return
			}
			if trimmedCalls.Add(1) >= 2 {
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-r.Context().Done():
					return
				case <-timer.C:
					repollSleepCompleted.Store(true)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
				NumRows:                 100_000,
				NumTotalLogicalBytes:    26_000_000,
				NumCurrentPhysicalBytes: 0,
			}); encErr != nil {
				t.Errorf("encode trimmed table response: %v", encErr)
			}
		}))
		t.Cleanup(func() {
			subSrv.CloseClientConnections()
			subSrv.Close()
		})

		subCtx, subCancel := context.WithTimeout(context.Background(), 15*time.Second)
		t.Cleanup(subCancel)
		subSvc, subErr := bigqueryapi.NewService(subCtx, option.WithEndpoint(subSrv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if subErr != nil {
			t.Fatalf("bigqueryapi.NewService: %v", subErr)
		}

		u, tr, subErr := pollTablesGetStorageStats(
			subCtx, subSvc, "test-proj", "ds",
			"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
			100_000, 300*time.Millisecond, 25*time.Millisecond,
		)
		if subErr != nil {
			t.Fatalf("expected preserved pre-deadline sample on re-poll deadline expiration, got: %v", subErr)
		}
		if repollSleepCompleted.Load() {
			t.Fatal("expected slow re-poll handler to abort on request context cancellation before 5s timer completed")
		}
		if u.TotalRows != 100_000 || tr.TotalRows != 100_000 {
			t.Fatalf("rows = (%d, %d), want (100000, 100000)", u.TotalRows, tr.TotalRows)
		}
		if u.TotalLogicalBytes != 48_000_000 || tr.TotalLogicalBytes != 26_000_000 {
			t.Fatalf("logical bytes = (%d, %d), want (48000000, 26000000)", u.TotalLogicalBytes, tr.TotalLogicalBytes)
		}
		if u.CurrentPhysicalBytes != 0 || tr.CurrentPhysicalBytes != 0 {
			t.Fatalf("current physical bytes = (%d, %d), want (0, 0)", u.CurrentPhysicalBytes, tr.CurrentPhysicalBytes)
		}
	})
}

func readExistingNV13PhysicalStorageStats(
	ctx context.Context,
	rawSvc *bigqueryapi.Service,
	project, dataset, untrimmedPhys, trimmedPhys string,
	wantRows int64,
	timeout, interval time.Duration,
) (spikeTableStorageStats, spikeTableStorageStats, error) {
	u, tr, err := pollTablesGetStorageStats(
		ctx, rawSvc, project, dataset, untrimmedPhys, trimmedPhys, wantRows, timeout, interval,
	)
	if err != nil {
		return spikeTableStorageStats{}, spikeTableStorageStats{}, fmt.Errorf(
			"read-only BQ_NV13_DATASET=%s.%s verification failed (tables %s, %s; want %d rows each): %w",
			project, dataset, untrimmedPhys, trimmedPhys, wantRows, err,
		)
	}
	if u.TotalRows != wantRows || tr.TotalRows != wantRows {
		return u, tr, fmt.Errorf(
			"read-only BQ_NV13_DATASET=%s.%s row count mismatch: want %d rows each, observed %s=%d (logical=%d current_physical=%d) %s=%d (logical=%d current_physical=%d)",
			project, dataset, wantRows,
			untrimmedPhys, u.TotalRows, u.TotalLogicalBytes, u.CurrentPhysicalBytes,
			trimmedPhys, tr.TotalRows, tr.TotalLogicalBytes, tr.CurrentPhysicalBytes,
		)
	}
	if u.TotalLogicalBytes <= 0 || tr.TotalLogicalBytes <= 0 {
		return u, tr, fmt.Errorf(
			"read-only BQ_NV13_DATASET=%s.%s logical bytes not populated: observed %s=%d %s=%d",
			project, dataset, untrimmedPhys, u.TotalLogicalBytes, trimmedPhys, tr.TotalLogicalBytes,
		)
	}
	return u, tr, nil
}

func validateNV15SoakDuration(d time.Duration) error {
	if d < 60*time.Second {
		return fmt.Errorf("must be >= 60s, got %s", d)
	}
	return nil
}

type nv15LostAckInterceptor struct {
	Armed             atomic.Bool
	Injected          atomic.Bool
	StreamsOpened     atomic.Int64
	InjectedBatchRows atomic.Int64

	mu                 sync.Mutex
	injectedRecordSeqs []int64
	parseErr           error
}

func (ic *nv15LostAckInterceptor) InjectedRecordSeqsSlice() ([]int64, error) {
	ic.mu.Lock()
	defer ic.mu.Unlock()
	if ic.parseErr != nil {
		return nil, ic.parseErr
	}
	return slices.Clone(ic.injectedRecordSeqs), nil
}

func (ic *nv15LostAckInterceptor) StreamClientInterceptor() grpc.StreamClientInterceptor {
	return func(
		ctx context.Context,
		desc *grpc.StreamDesc,
		cc *grpc.ClientConn,
		method string,
		streamer grpc.Streamer,
		opts ...grpc.CallOption,
	) (grpc.ClientStream, error) {
		cs, err := streamer(ctx, desc, cc, method, opts...)
		if err != nil || !strings.HasSuffix(method, "/AppendRows") {
			return cs, err
		}
		ic.StreamsOpened.Add(1)
		return &nv15LostAckStream{
			ClientStream: cs,
			parent:       ic,
		}, nil
	}
}

type nv15LostAckStream struct {
	grpc.ClientStream
	parent          *nv15LostAckInterceptor
	poisoned        atomic.Bool
	mu              sync.Mutex
	writerDesc      protoreflect.MessageDescriptor
	attrsFD         protoreflect.FieldDescriptor
	pendingRows     []int
	pendingSeqs     [][]int64
	pendingParseErr error
}

func parseNV15RecordSeqFromJSONValue(raw any) (int64, error) {
	switch v := raw.(type) {
	case string:
		dec := json.NewDecoder(strings.NewReader(v))
		dec.UseNumber()
		var attrs map[string]any
		if err := dec.Decode(&attrs); err != nil {
			return 0, fmt.Errorf("decode attributes JSON %q: %w", v, err)
		}
		return parseNV15RecordSeqFromMap(attrs)
	case map[string]any:
		return parseNV15RecordSeqFromMap(v)
	default:
		return 0, fmt.Errorf("unexpected attributes value type %T", raw)
	}
}

func parseNV15RecordSeqFromMap(attrs map[string]any) (int64, error) {
	rawSeq, ok := attrs["soak.record_seq"]
	if !ok {
		return 0, errors.New("missing attributes['soak.record_seq']")
	}
	switch v := rawSeq.(type) {
	case string:
		return strconv.ParseInt(v, 10, 64)
	case json.Number:
		return v.Int64()
	case float64:
		return int64(v), nil
	case int64:
		return v, nil
	case int:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("unexpected soak.record_seq type %T", rawSeq)
	}
}

func verifyNV15RecordSeqMultiplicities(rawCounts map[int64]int64, injectedSeqs, retainedSeqs []int64) error {
	if len(injectedSeqs) == 0 {
		return errors.New("injectedSeqs is empty; expected interrupted batch soak.record_seq list")
	}
	wantMin := make(map[int64]int64, len(injectedSeqs)+len(retainedSeqs))
	for _, seq := range injectedSeqs {
		if wantMin[seq] == 0 {
			wantMin[seq] = 1
		}
		wantMin[seq]++
	}
	for _, seq := range retainedSeqs {
		if wantMin[seq] == 0 {
			wantMin[seq] = 1
		}
		wantMin[seq]++
	}
	seqs := make([]int64, 0, len(wantMin))
	for seq := range wantMin {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	for _, seq := range seqs {
		if got := rawCounts[seq]; got < wantMin[seq] {
			return fmt.Errorf("raw table soak.record_seq=%d multiplicity=%d, want >= %d", seq, got, wantMin[seq])
		}
	}
	return nil
}

func (s *nv15LostAckStream) SendMsg(m any) error {
	if s.poisoned.Load() {
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	var (
		rowCount int
		seqs     []int64
	)
	s.mu.Lock()
	if req, ok := m.(*storagepb.AppendRowsRequest); ok {
		protoRows := req.GetProtoRows()
		if ws := protoRows.GetWriterSchema().GetProtoDescriptor(); ws != nil && s.writerDesc == nil {
			fdp := &descriptorpb.FileDescriptorProto{
				Name:        proto.String("nv15_writer.proto"),
				Syntax:      proto.String("proto2"),
				MessageType: []*descriptorpb.DescriptorProto{ws},
			}
			fileDesc, fdErr := protodesc.NewFile(fdp, nil)
			if fdErr != nil {
				if s.pendingParseErr == nil {
					s.pendingParseErr = fmt.Errorf("protodesc.NewFile: %w", fdErr)
				}
			} else if fileDesc.Messages().Len() > 0 {
				s.writerDesc = fileDesc.Messages().Get(0)
				s.attrsFD = s.writerDesc.Fields().ByName("attributes")
			}
		}
		serialized := protoRows.GetRows().GetSerializedRows()
		rowCount = len(serialized)
		if rowCount > 0 {
			if s.writerDesc == nil || s.attrsFD == nil {
				if s.pendingParseErr == nil {
					s.pendingParseErr = errors.New("nv15 interceptor missing writer schema or attributes field")
				}
			} else {
				seqs = make([]int64, 0, rowCount)
				for _, raw := range serialized {
					msg := dynamicpb.NewMessage(s.writerDesc)
					if uErr := proto.Unmarshal(raw, msg); uErr != nil {
						if s.pendingParseErr == nil {
							s.pendingParseErr = fmt.Errorf("unmarshal serialized row: %w", uErr)
						}
						break
					}
					seq, pErr := parseNV15RecordSeqFromJSONValue(msg.Get(s.attrsFD).String())
					if pErr != nil {
						if s.pendingParseErr == nil {
							s.pendingParseErr = pErr
						}
						break
					}
					seqs = append(seqs, seq)
				}
			}
		}
	}
	s.pendingRows = append(s.pendingRows, rowCount)
	s.pendingSeqs = append(s.pendingSeqs, seqs)
	s.mu.Unlock()

	if err := s.ClientStream.SendMsg(m); err != nil {
		s.mu.Lock()
		if n := len(s.pendingRows); n > 0 {
			s.pendingRows = s.pendingRows[:n-1]
		}
		if n := len(s.pendingSeqs); n > 0 {
			s.pendingSeqs = s.pendingSeqs[:n-1]
		}
		s.mu.Unlock()
		return err
	}
	return nil
}

func (s *nv15LostAckStream) RecvMsg(m any) error {
	if s.poisoned.Load() {
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	err := s.ClientStream.RecvMsg(m)
	var (
		rowCount int
		seqs     []int64
		parseErr error
	)
	s.mu.Lock()
	if len(s.pendingRows) > 0 {
		rowCount = s.pendingRows[0]
		s.pendingRows = s.pendingRows[1:]
	}
	if len(s.pendingSeqs) > 0 {
		seqs = s.pendingSeqs[0]
		s.pendingSeqs = s.pendingSeqs[1:]
	}
	parseErr = s.pendingParseErr
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if resp, ok := m.(*storagepb.AppendRowsResponse); ok && resp.GetError() != nil {
		return nil
	}
	if s.parent.Armed.Load() && rowCount > 0 && s.parent.Injected.CompareAndSwap(false, true) {
		s.parent.InjectedBatchRows.Store(int64(rowCount))
		s.parent.mu.Lock()
		s.parent.injectedRecordSeqs = slices.Clone(seqs)
		s.parent.parseErr = parseErr
		s.parent.mu.Unlock()
		s.poisoned.Store(true)
		return status.Error(codes.Unavailable, "nv15 injected post-ack stream disconnect")
	}
	return nil
}

func buildNV15LogsBatch(batchSeq, batchSize int, baseTS time.Time) plog.Logs {
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	resAttrs := rl.Resource().Attributes()
	resAttrs.PutStr("service.name", "nv15-default-stream-soak")
	resAttrs.PutStr("cloud.region", "us-central1")

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("nv15.soak.logger")
	sl.Scope().SetVersion("1.0.0")
	records := sl.LogRecords()
	records.EnsureCapacity(batchSize)

	for i := range batchSize {
		seq := batchSeq*batchSize + i
		recTS := baseTS.Add(time.Duration(seq) * time.Microsecond)
		lr := records.AppendEmpty()
		lr.SetTimestamp(pcommon.NewTimestampFromTime(recTS))
		lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(recTS.Add(500 * time.Nanosecond)))
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")
		lr.Body().SetStr(spikeAccessLogBody128B)

		attrs := lr.Attributes()
		attrs.PutInt("soak.batch_seq", int64(batchSeq))
		attrs.PutInt("soak.record_seq", int64(seq))
		attrs.PutStr("http.request.method", "GET")
		attrs.PutInt("http.response.status_code", 200)
	}
	return ld
}

func TestNV13TablesGetWithoutProjectTableStoragePermission(t *testing.T) {
	var (
		returnCurrentPhysical atomic.Bool
		tablesGetCalls        atomic.Int64
		jobsCalls             atomic.Int64
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/jobs") {
			jobsCalls.Add(1)
			t.Errorf("unexpected BigQuery jobs request %s %s: INFORMATION_SCHEMA.TABLE_STORAGE must never be queried", r.Method, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			if encErr := json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{"code": http.StatusForbidden, "message": "Access Denied: BigQuery jobs.create"},
			}); encErr != nil {
				t.Errorf("encode 403 response: %v", encErr)
			}
			return
		}
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		var tbl *bigqueryapi.Table
		switch r.URL.Path {
		case "/bigquery/v2/projects/test-proj/datasets/ds/tables/otel_logs_untrimmed_phys":
			tablesGetCalls.Add(1)
			// Phase 0: NumActivePhysicalBytes and NumPhysicalBytes are non-zero (time-travel / legacy)
			// while NumCurrentPhysicalBytes is 0; CurrentPhysicalBytes must stay 0.
			tbl = &bigqueryapi.Table{
				NumRows:                100_000,
				NumBytes:               48_000_000,
				NumTotalLogicalBytes:   48_000_000,
				NumActivePhysicalBytes: 6_000_000,
				NumPhysicalBytes:       6_000_000,
				NumTotalPhysicalBytes:  6_000_000,
			}
			if returnCurrentPhysical.Load() {
				tbl.NumCurrentPhysicalBytes = 5_500_000
				tbl.NumLongTermPhysicalBytes = 500_000
				tbl.NumActivePhysicalBytes = 7_200_000
				tbl.NumTotalPhysicalBytes = 7_800_000
			}
		case "/bigquery/v2/projects/test-proj/datasets/ds/tables/otel_logs_trimmed_phys":
			tablesGetCalls.Add(1)
			tbl = &bigqueryapi.Table{
				NumRows:                100_000,
				NumBytes:               26_000_000,
				NumTotalLogicalBytes:   26_000_000,
				NumActivePhysicalBytes: 3_100_000,
				NumPhysicalBytes:       3_100_000,
				NumTotalPhysicalBytes:  3_100_000,
			}
			if returnCurrentPhysical.Load() {
				tbl.NumCurrentPhysicalBytes = 2_900_000
				tbl.NumLongTermPhysicalBytes = 200_000
				tbl.NumActivePhysicalBytes = 4_400_000
				tbl.NumTotalPhysicalBytes = 4_900_000
			}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if encErr := json.NewEncoder(w).Encode(tbl); encErr != nil {
			t.Errorf("encode table response: %v", encErr)
		}
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
	if err != nil {
		t.Fatalf("create bigqueryapi.Service: %v", err)
	}

	const wantRows = int64(100_000)
	uZero, trZero, err := pollTablesGetStorageStats(
		ctx, rawSvc, "test-proj", "ds", "otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
		wantRows, 0, 0,
	)
	if err != nil {
		t.Fatalf("pollTablesGetStorageStats (numCurrentPhysicalBytes=0): %v", err)
	}
	if jobsCalls.Load() != 0 {
		t.Fatalf("jobsCalls = %d, want 0", jobsCalls.Load())
	}
	if tablesGetCalls.Load() < 2 {
		t.Fatalf("tablesGetCalls = %d, want >= 2", tablesGetCalls.Load())
	}
	if uZero.TotalRows != wantRows || trZero.TotalRows != wantRows {
		t.Fatalf("rows = (%d, %d), want (%d, %d)", uZero.TotalRows, trZero.TotalRows, wantRows, wantRows)
	}
	if uZero.TotalLogicalBytes != 48_000_000 || trZero.TotalLogicalBytes != 26_000_000 {
		t.Fatalf("logical bytes = (%d, %d), want (48000000, 26000000)", uZero.TotalLogicalBytes, trZero.TotalLogicalBytes)
	}
	if uZero.CurrentPhysicalBytes != 0 || trZero.CurrentPhysicalBytes != 0 {
		t.Fatalf("expected CurrentPhysicalBytes=0 when NumCurrentPhysicalBytes=0 (must not fall back to ActivePhysicalBytes/NumPhysicalBytes), got u=%+v tr=%+v", uZero, trZero)
	}
	if uZero.ActivePhysicalBytes != 6_000_000 || trZero.ActivePhysicalBytes != 3_100_000 {
		t.Fatalf("expected raw ActivePhysicalBytes preserved for diagnostics, got u=%+v tr=%+v", uZero, trZero)
	}

	returnCurrentPhysical.Store(true)
	uPhys, trPhys, err := pollTablesGetStorageStats(
		ctx, rawSvc, "test-proj", "ds", "otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
		wantRows, 2*time.Second, 20*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("pollTablesGetStorageStats (numCurrentPhysicalBytes>0): %v", err)
	}
	if jobsCalls.Load() != 0 {
		t.Fatalf("jobsCalls = %d, want 0", jobsCalls.Load())
	}
	if uPhys.CurrentPhysicalBytes != 5_500_000 || trPhys.CurrentPhysicalBytes != 2_900_000 {
		t.Fatalf("current physical bytes = (%d, %d), want (5500000, 2900000)", uPhys.CurrentPhysicalBytes, trPhys.CurrentPhysicalBytes)
	}
	if uPhys.TotalPhysicalBytes != 7_800_000 || trPhys.TotalPhysicalBytes != 4_900_000 {
		t.Fatalf("total physical bytes = (%d, %d), want (7800000, 4900000)", uPhys.TotalPhysicalBytes, trPhys.TotalPhysicalBytes)
	}

	if _, _, _, measured, err := checkNV13PhysicalCompression(uZero, trZero, true); err == nil || measured {
		t.Fatalf("checkNV13PhysicalCompression(zero current physical, requirePhysical=true) = (measured=%v, err=%v), want (false, non-nil error)", measured, err)
	}
	if _, _, _, measured, err := checkNV13PhysicalCompression(uZero, trZero, false); err != nil || measured {
		t.Fatalf("checkNV13PhysicalCompression(zero current physical, requirePhysical=false) = (measured=%v, err=%v), want (false, nil)", measured, err)
	}
	uRatio, trRatio, physSavingsPct, measured, err := checkNV13PhysicalCompression(uPhys, trPhys, true)
	if err != nil || !measured {
		t.Fatalf("checkNV13PhysicalCompression(phys, requirePhysical=true) = (measured=%v, err=%v), want (true, nil)", measured, err)
	}
	if uRatio <= 1.0 || trRatio <= 1.0 || physSavingsPct <= 0 {
		t.Fatalf("unexpected compression stats: untrimmedRatio=%.2f trimmedRatio=%.2f physicalSavingsPct=%.2f", uRatio, trRatio, physSavingsPct)
	}
	if _, _, _, _, err := checkNV13PhysicalCompression(trPhys, uPhys, true); err == nil {
		t.Fatal("expected error when trimmed current physical bytes >= untrimmed current physical bytes")
	}

	t.Run("long_term_physical_bytes_not_double_counted", func(t *testing.T) {
		longTermSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/bigquery/v2/projects/test-proj/datasets/ds/tables/otel_logs_long_term" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
				NumRows:                  100_000,
				NumTotalLogicalBytes:     80_000_000,
				NumCurrentPhysicalBytes:  10_000_000,
				NumLongTermPhysicalBytes: 4_000_000,
				NumActivePhysicalBytes:   8_000_000,
				NumTotalPhysicalBytes:    12_000_000,
			}); encErr != nil {
				t.Errorf("encode table response: %v", encErr)
			}
		}))
		t.Cleanup(longTermSrv.Close)

		ltSvc, ltErr := bigqueryapi.NewService(ctx, option.WithEndpoint(longTermSrv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if ltErr != nil {
			t.Fatalf("create bigqueryapi.Service: %v", ltErr)
		}
		stats, ltErr := readSingleTableGetStorageStats(ctx, ltSvc, "test-proj", "ds", "otel_logs_long_term")
		if ltErr != nil {
			t.Fatalf("readSingleTableGetStorageStats: %v", ltErr)
		}
		if stats.CurrentPhysicalBytes != 10_000_000 {
			t.Fatalf("CurrentPhysicalBytes = %d, want 10000000 (must not add NumLongTermPhysicalBytes=4000000 to yield 14000000)", stats.CurrentPhysicalBytes)
		}
	})
}

func TestNV13ExistingDatasetStrictReadOnly(t *testing.T) {
	t.Run("missing_table_404_fails_without_mutation", func(t *testing.T) {
		var nonGetCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				nonGetCalls.Add(1)
				t.Errorf("unexpected mutating HTTP request in BQ_NV13_DATASET read-only mode: %s %s", r.Method, r.URL.Path)
				http.Error(w, "mutations forbidden in read-only mode", http.StatusMethodNotAllowed)
				return
			}
			const prefix = "/bigquery/v2/projects/test-proj/datasets/persisted_nv13/tables/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			tableName := strings.TrimPrefix(r.URL.Path, prefix)
			if tableName == "otel_logs_untrimmed_phys" {
				w.Header().Set("Content-Type", "application/json")
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                 100_000,
					NumTotalLogicalBytes:    48_000_000,
					NumCurrentPhysicalBytes: 6_000_000,
				}); encErr != nil {
					t.Errorf("encode table response: %v", encErr)
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			if encErr := json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    http.StatusNotFound,
					"message": "Not found: Table test-proj:persisted_nv13." + tableName,
				},
			}); encErr != nil {
				t.Errorf("encode 404 response: %v", encErr)
			}
		}))
		t.Cleanup(srv.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("bigqueryapi.NewService: %v", err)
		}

		_, _, err = readExistingNV13PhysicalStorageStats(
			ctx, rawSvc, "test-proj", "persisted_nv13",
			"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
			100_000, 5*time.Second, 25*time.Millisecond,
		)
		if err == nil {
			t.Fatal("expected error when persisted table returns 404")
		}
		if !strings.Contains(err.Error(), "404") || !strings.Contains(err.Error(), "otel_logs_trimmed_phys") {
			t.Fatalf("expected error to cite 404 and missing table name, got: %v", err)
		}
		if got := nonGetCalls.Load(); got != 0 {
			t.Fatalf("non-GET HTTP calls = %d, want 0", got)
		}
	})

	t.Run("insufficient_rows_fails_with_observed_counts_without_mutation", func(t *testing.T) {
		var nonGetCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				nonGetCalls.Add(1)
				t.Errorf("unexpected mutating HTTP request in BQ_NV13_DATASET read-only mode: %s %s", r.Method, r.URL.Path)
				http.Error(w, "mutations forbidden in read-only mode", http.StatusMethodNotAllowed)
				return
			}
			const prefix = "/bigquery/v2/projects/test-proj/datasets/persisted_nv13/tables/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch strings.TrimPrefix(r.URL.Path, prefix) {
			case "otel_logs_untrimmed_phys":
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                 100_000,
					NumTotalLogicalBytes:    48_000_000,
					NumCurrentPhysicalBytes: 6_000_000,
				}); encErr != nil {
					t.Errorf("encode table response: %v", encErr)
				}
			case "otel_logs_trimmed_phys":
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                 42_000,
					NumTotalLogicalBytes:    11_000_000,
					NumCurrentPhysicalBytes: 1_300_000,
				}); encErr != nil {
					t.Errorf("encode table response: %v", encErr)
				}
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("bigqueryapi.NewService: %v", err)
		}

		_, _, err = readExistingNV13PhysicalStorageStats(
			ctx, rawSvc, "test-proj", "persisted_nv13",
			"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
			100_000, 0, 0,
		)
		if err == nil {
			t.Fatal("expected error when persisted table has fewer than 100000 rows")
		}
		if !strings.Contains(err.Error(), "otel_logs_untrimmed_phys=100000") ||
			!strings.Contains(err.Error(), "otel_logs_trimmed_phys=42000") {
			t.Fatalf("expected error to cite observed row counts, got: %v", err)
		}
		if got := nonGetCalls.Load(); got != 0 {
			t.Fatalf("non-GET HTTP calls = %d, want 0", got)
		}
	})

	t.Run("valid_persisted_tables_succeed_strictly_read_only", func(t *testing.T) {
		var nonGetCalls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				nonGetCalls.Add(1)
				t.Errorf("unexpected mutating HTTP request in BQ_NV13_DATASET read-only mode: %s %s", r.Method, r.URL.Path)
				http.Error(w, "mutations forbidden in read-only mode", http.StatusMethodNotAllowed)
				return
			}
			const prefix = "/bigquery/v2/projects/test-proj/datasets/persisted_nv13/tables/"
			if !strings.HasPrefix(r.URL.Path, prefix) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch strings.TrimPrefix(r.URL.Path, prefix) {
			case "otel_logs_untrimmed_phys":
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                  100_000,
					NumTotalLogicalBytes:     48_000_000,
					NumCurrentPhysicalBytes:  5_600_000,
					NumLongTermPhysicalBytes: 400_000,
				}); encErr != nil {
					t.Errorf("encode table response: %v", encErr)
				}
			case "otel_logs_trimmed_phys":
				if encErr := json.NewEncoder(w).Encode(bigqueryapi.Table{
					NumRows:                  100_000,
					NumTotalLogicalBytes:     26_000_000,
					NumCurrentPhysicalBytes:  2_900_000,
					NumLongTermPhysicalBytes: 200_000,
				}); encErr != nil {
					t.Errorf("encode table response: %v", encErr)
				}
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		rawSvc, err := bigqueryapi.NewService(ctx, option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication())
		if err != nil {
			t.Fatalf("bigqueryapi.NewService: %v", err)
		}

		u, tr, err := readExistingNV13PhysicalStorageStats(
			ctx, rawSvc, "test-proj", "persisted_nv13",
			"otel_logs_untrimmed_phys", "otel_logs_trimmed_phys",
			100_000, 5*time.Second, 25*time.Millisecond,
		)
		if err != nil {
			t.Fatalf("readExistingNV13PhysicalStorageStats: %v", err)
		}
		if u.CurrentPhysicalBytes != 5_600_000 || tr.CurrentPhysicalBytes != 2_900_000 {
			t.Fatalf("CurrentPhysicalBytes = (%d, %d), want (5600000, 2900000)", u.CurrentPhysicalBytes, tr.CurrentPhysicalBytes)
		}
		if got := nonGetCalls.Load(); got != 0 {
			t.Fatalf("non-GET HTTP calls = %d, want 0", got)
		}
	})
}

func TestNV15MinSoakDurationAndLostAckStreamRecovery(t *testing.T) {
	if err := validateNV15SoakDuration(time.Nanosecond); err == nil {
		t.Fatal("expected 1ns soak duration to be rejected")
	}
	if err := validateNV15SoakDuration(59 * time.Second); err == nil {
		t.Fatal("expected 59s soak duration to be rejected")
	}
	if err := validateNV15SoakDuration(60 * time.Second); err != nil {
		t.Fatalf("expected 60s soak duration to be accepted, got %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	fakeSrv := bqfake.NewServer(t)
	ic := &nv15LostAckInterceptor{}
	origNewMWClient := newManagedWriterClient
	t.Cleanup(func() { newManagedWriterClient = origNewMWClient })
	newManagedWriterClient = func(cCtx context.Context, projectID string, opts ...option.ClientOption) (*managedwriter.Client, error) {
		wrapped := append(append([]option.ClientOption(nil), opts...),
			option.WithGRPCDialOption(grpc.WithChainStreamInterceptor(ic.StreamClientInterceptor())),
		)
		return origNewMWClient(cCtx, projectID, wrapped...)
	}

	rawCfg := CreateDefaultConfig()
	cfg, ok := rawCfg.(*Config)
	if !ok {
		t.Fatalf("CreateDefaultConfig() returned %T, want *Config", rawCfg)
	}
	cfg.Project = "test-proj"
	cfg.Dataset = "otel"
	cfg.Location = "US"
	cfg.Logs.Table = "otel_logs"
	cfg.Logs.SynthesizeInsertID = true
	cfg.AutoCreate.Dataset = true
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = false
	cfg.AutoCreate.SearchIndexes = false
	cfg.Write.StreamPoolSize = 2
	cfg.Endpoint = EndpointConfig{
		URL:                   fakeSrv.Addr(),
		AdminURL:              fakeSrv.RESTURL(),
		Insecure:              true,
		WithoutAuthentication: true,
	}
	cfg.QueueSettings = configoptional.None[exporterhelper.QueueBatchConfig]()
	cfg.BackOffConfig.Enabled = true
	cfg.BackOffConfig.InitialInterval = 10 * time.Millisecond
	cfg.BackOffConfig.MaxInterval = 100 * time.Millisecond

	exp, err := CreateLogsExporter(ctx, exportertest.NewNopSettings(NewFactory().Type()), cfg)
	if err != nil {
		t.Fatalf("CreateLogsExporter: %v", err)
	}
	if startErr := exp.Start(ctx, componenttest.NewNopHost()); startErr != nil {
		t.Fatalf("Start exporter: %v", startErr)
	}
	var shutdownOnce sync.Once
	shutdown := func(sctx context.Context) error {
		var serr error
		shutdownOnce.Do(func() {
			serr = exp.Shutdown(sctx)
		})
		return serr
	}
	t.Cleanup(func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanCancel()
		if stopErr := shutdown(cleanCtx); stopErr != nil {
			t.Errorf("Shutdown exporter: %v", stopErr)
		}
	})

	const (
		warmupBatches = 4
		faultBatches  = 8
		batchSize     = 25
	)
	baseTS := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for seq := range warmupBatches {
		batch := buildNV15LogsBatch(seq, batchSize, baseTS)
		if consumeErr := exp.ConsumeLogs(ctx, batch); consumeErr != nil {
			t.Fatalf("warmup ConsumeLogs(%d): %v", seq, consumeErr)
		}
	}

	ic.Armed.Store(true)
	postFaultBatches := 0
	for i := range faultBatches {
		seq := warmupBatches + i
		batch := buildNV15LogsBatch(seq, batchSize, baseTS)
		if consumeErr := exp.ConsumeLogs(ctx, batch); consumeErr != nil {
			t.Fatalf("post-arm ConsumeLogs(%d): %v", seq, consumeErr)
		}
		if ic.Injected.Load() {
			postFaultBatches++
		}
	}
	if stopErr := shutdown(ctx); stopErr != nil {
		t.Fatalf("shutdown exporter: %v", stopErr)
	}

	if !ic.Injected.Load() {
		t.Fatal("expected nv15LostAckInterceptor to inject post-ack stream disconnect")
	}
	if ic.InjectedBatchRows.Load() <= 0 {
		t.Fatalf("injectedBatchRows = %d, want > 0", ic.InjectedBatchRows.Load())
	}
	if ic.StreamsOpened.Load() < 3 {
		t.Fatalf("streamsOpened = %d, want >= 3", ic.StreamsOpened.Load())
	}
	if postFaultBatches <= 0 {
		t.Fatalf("postFaultBatches = %d, want > 0", postFaultBatches)
	}

	uniqueSent := (warmupBatches + faultBatches) * batchSize
	rows := fakeSrv.Rows("otel_logs")
	wantMinRaw := uniqueSent + int(ic.InjectedBatchRows.Load())
	if len(rows) < wantMinRaw {
		t.Fatalf(
			"raw otel_logs row count = %d, want >= %d (uniqueSent=%d + injectedBatchRows=%d)",
			len(rows), wantMinRaw, uniqueSent, ic.InjectedBatchRows.Load(),
		)
	}

	type dedupKey struct {
		logName  string
		insertID string
	}
	dedupSeqByKey := make(map[dedupKey]int64, uniqueSent)
	rawCounts := make(map[int64]int64, uniqueSent)
	for idx, r := range rows {
		logName, _ := r["log_name"].(string)
		insertID, _ := r["insert_id"].(string)
		if insertID == "" {
			t.Fatalf("row %d missing synthesized insert_id: %v", idx, r)
		}
		seqVal, sErr := parseNV15RecordSeqFromJSONValue(r["attributes"])
		if sErr != nil {
			t.Fatalf("row %d parse soak.record_seq: %v", idx, sErr)
		}
		rawCounts[seqVal]++
		key := dedupKey{logName: logName, insertID: insertID}
		if prevSeq, exists := dedupSeqByKey[key]; exists && prevSeq != seqVal {
			t.Fatalf("dedup key (%q, %q) collided across soak.record_seq %d and %d", logName, insertID, prevSeq, seqVal)
		}
		dedupSeqByKey[key] = seqVal
	}
	if len(dedupSeqByKey) != uniqueSent {
		t.Fatalf("unique (log_name, insert_id) count = %d, want %d (raw=%d)", len(dedupSeqByKey), uniqueSent, len(rows))
	}

	dedupStats := nv15DedupStats{RowCount: int64(len(dedupSeqByKey))}
	distinctDedupSeqs := make(map[int64]struct{}, len(dedupSeqByKey))
	for _, seqVal := range dedupSeqByKey {
		distinctDedupSeqs[seqVal] = struct{}{}
		if seqVal < 0 || seqVal >= int64(uniqueSent) {
			dedupStats.OutOfRangeSeqRows++
		}
		if !dedupStats.HasMinMax {
			dedupStats.MinSeq = seqVal
			dedupStats.MaxSeq = seqVal
			dedupStats.HasMinMax = true
		} else {
			if seqVal < dedupStats.MinSeq {
				dedupStats.MinSeq = seqVal
			}
			if seqVal > dedupStats.MaxSeq {
				dedupStats.MaxSeq = seqVal
			}
		}
	}
	dedupStats.DistinctSeqs = int64(len(distinctDedupSeqs))
	if err := verifyNV15DedupSeqRange(dedupStats, int64(uniqueSent)); err != nil {
		t.Fatalf("deduplicated sequence range verification failed: %v", err)
	}

	injectedSeqs, parseErr := ic.InjectedRecordSeqsSlice()
	if parseErr != nil {
		t.Fatalf("InjectedRecordSeqsSlice: %v", parseErr)
	}
	if int64(len(injectedSeqs)) != ic.InjectedBatchRows.Load() {
		t.Fatalf("len(injectedRecordSeqs)=%d != InjectedBatchRows=%d", len(injectedSeqs), ic.InjectedBatchRows.Load())
	}
	if err := verifyNV15RecordSeqMultiplicities(rawCounts, injectedSeqs, nil); err != nil {
		t.Fatalf("interrupted batch multiplicity verification failed: %v", err)
	}
}

type nv15DedupStats struct {
	RowCount          int64
	DistinctSeqs      int64
	NullSeqRows       int64
	OutOfRangeSeqRows int64
	HasMinMax         bool
	MinSeq            int64
	MaxSeq            int64
}

func verifyNV15DedupSeqRange(stats nv15DedupStats, sent int64) error {
	if sent < 0 {
		return fmt.Errorf("invalid sent count %d: must be >= 0", sent)
	}
	if sent == 0 {
		if stats.RowCount != 0 || stats.DistinctSeqs != 0 || stats.NullSeqRows != 0 || stats.OutOfRangeSeqRows != 0 || stats.HasMinMax {
			return fmt.Errorf("expected empty dedup stats for sent=0, got %+v", stats)
		}
		return nil
	}
	if stats.RowCount != sent {
		return fmt.Errorf("dedup row_count=%d, want %d", stats.RowCount, sent)
	}
	if stats.DistinctSeqs != sent {
		return fmt.Errorf("dedup distinct_seqs=%d, want %d", stats.DistinctSeqs, sent)
	}
	if stats.NullSeqRows != 0 {
		return fmt.Errorf("dedup null_seq_rows=%d, want 0", stats.NullSeqRows)
	}
	if stats.OutOfRangeSeqRows != 0 {
		return fmt.Errorf("dedup out_of_range_seq_rows=%d (outside [0, %d)), want 0", stats.OutOfRangeSeqRows, sent)
	}
	if !stats.HasMinMax {
		return fmt.Errorf("dedup min_seq/max_seq missing for sent=%d", sent)
	}
	if stats.MinSeq != 0 || stats.MaxSeq != sent-1 {
		return fmt.Errorf("dedup seq range=[%d, %d], want [0, %d]", stats.MinSeq, stats.MaxSeq, sent-1)
	}
	return nil
}

func TestVerifyNV15DedupSeqRangeRejectsOutOfRangeSwap(t *testing.T) {
	clean := nv15DedupStats{
		RowCount:     300,
		DistinctSeqs: 300,
		HasMinMax:    true,
		MinSeq:       0,
		MaxSeq:       299,
	}
	if err := verifyNV15DedupSeqRange(clean, 300); err != nil {
		t.Fatalf("clean [0, 300) failed: %v", err)
	}

	// Swapping 299 -> 300 keeps row_count=300 and distinct_seqs=300,
	// so only the [0, sent) range check catches the out-of-range swap.
	swap300 := nv15DedupStats{
		RowCount:          300,
		DistinctSeqs:      300,
		OutOfRangeSeqRows: 1,
		HasMinMax:         true,
		MinSeq:            0,
		MaxSeq:            300,
	}
	if err := verifyNV15DedupSeqRange(swap300, 300); err == nil {
		t.Fatal("expected failure when 299 is swapped with out-of-range 300")
	}

	// Negative sequence -1 must also fail.
	swapNeg := nv15DedupStats{
		RowCount:          300,
		DistinctSeqs:      300,
		OutOfRangeSeqRows: 1,
		HasMinMax:         true,
		MinSeq:            -1,
		MaxSeq:            298,
	}
	if err := verifyNV15DedupSeqRange(swapNeg, 300); err == nil {
		t.Fatal("expected failure when sequence contains -1")
	}

	// Missing/NULL soak.record_seq must fail even when distinct count differs or matches.
	nullSeq := nv15DedupStats{
		RowCount:     300,
		DistinctSeqs: 300,
		NullSeqRows:  1,
		HasMinMax:    true,
		MinSeq:       0,
		MaxSeq:       298,
	}
	if err := verifyNV15DedupSeqRange(nullSeq, 300); err == nil {
		t.Fatal("expected failure when null_seq_rows > 0")
	}
}

func TestVerifyNV15RecordSeqMultiplicitiesRejectsWrongBatchReplay(t *testing.T) {
	// 300 distinct records (0..299); interrupted batch was 100..124,
	// while a broken reconnect wrongly replayed earlier batch 0..24.
	wrongCounts := make(map[int64]int64, 300)
	for seq := int64(0); seq < 300; seq++ {
		wrongCounts[seq] = 1
	}
	for seq := int64(0); seq < 25; seq++ {
		wrongCounts[seq] = 2 // wrong batch duplicated instead of 100..124
	}
	injected := make([]int64, 25)
	for i := range injected {
		injected[i] = int64(100 + i)
	}
	retained := make([]int64, 25)
	for i := range retained {
		retained[i] = int64(i)
	}

	if err := verifyNV15RecordSeqMultiplicities(wrongCounts, injected, retained); err == nil || !strings.Contains(err.Error(), "soak.record_seq=100 multiplicity=1") {
		t.Fatalf("expected failure when interrupted batch 100..124 lacks reconnect duplicate, got: %v", err)
	}

	// Overlapping explicit retained (0..24) + interrupted (0..24) requires multiplicity >= 3.
	wrongCounts[0] = 2
	if err := verifyNV15RecordSeqMultiplicities(wrongCounts, retained, retained); err == nil || !strings.Contains(err.Error(), "want >= 3") {
		t.Fatalf("expected >= 3 requirement when retained and interrupted overlap, got: %v", err)
	}

	// Fix multiplicity for interrupted 100..124 AND retained 0..24 -> passes.
	goodCounts := make(map[int64]int64, 300)
	for seq := int64(0); seq < 300; seq++ {
		goodCounts[seq] = 1
	}
	for seq := int64(0); seq < 25; seq++ {
		goodCounts[seq] = 2
	}
	for seq := int64(100); seq < 125; seq++ {
		goodCounts[seq] = 2
	}
	if err := verifyNV15RecordSeqMultiplicities(goodCounts, injected, retained); err != nil {
		t.Fatalf("expected valid replay multiplicity to pass, got: %v", err)
	}
}
