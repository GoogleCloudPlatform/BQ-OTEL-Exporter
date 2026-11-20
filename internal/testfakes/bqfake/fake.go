// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package bqfake provides an in-process BigQuery Storage Write API gRPC server
// and a BigQuery REST v2 metadata HTTP server for hermetic end-to-end tests.
//
// Incoming ProtoRows are decoded with dynamicpb against the stream's
// WriterSchema descriptor, checked against the destination table's
// storagepb.TableSchema, and stored as plain Go maps so tests can assert exact
// column values offline without live Google Cloud credentials.
package bqfake // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"cloud.google.com/go/bigquery/storage/managedwriter/adapt"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// FaultMode selects a simulated Storage Write API failure or delay.
type FaultMode int

const (
	// FaultNone acknowledges the request normally and records decoded rows.
	FaultNone FaultMode = iota
	// FaultRowErrors rejects the request with per-row errors and appends no rows.
	FaultRowErrors
	// FaultStreamClosed aborts the bidirectional AppendRows stream to exercise
	// stream retirement and reconnection.
	FaultStreamClosed
	// FaultUnavailable returns an in-band Unavailable response status.
	FaultUnavailable
	// FaultResourceExhausted returns an in-band ResourceExhausted response status.
	FaultResourceExhausted
	// FaultDelayedAck sleeps for Delay before acknowledging the request.
	FaultDelayedAck
	// FaultPermissionDenied returns an in-band PermissionDenied response status.
	FaultPermissionDenied
	// FaultInvalidArgument returns an in-band InvalidArgument response status.
	FaultInvalidArgument
	// FaultCommitThenStreamClosed commits the validated rows to the server
	// (updating ackedRows, ackedBytes, per-table counters, unique-acked
	// counters, and stored rows) and then aborts the bidirectional AppendRows
	// stream with codes.Aborted without sending an AppendRowsResponse,
	// simulating a response lost after commit.
	FaultCommitThenStreamClosed
)

// Fault describes a single programmed fault response on AppendRows.
type Fault struct {
	Mode      FaultMode
	Table     string
	RowErrors []*storagepb.RowError
	Delay     time.Duration
	Message   string
	// Ctx scopes the fault to a caller lifetime; once Ctx is done, AppendRows
	// discards the unconsumed fault instead of applying it to a later request,
	// and aborts an in-flight FaultDelayedAck delay early by returning a
	// stream-level gRPC status from AppendRows (tearing down that bidirectional
	// AppendRows stream).
	Ctx context.Context
}

type pendingRetryKey struct {
	table     string
	batchHash [32]byte
}

type periodicFaultState struct {
	ctx            context.Context
	throttleEvery  int
	ackDelay       time.Duration
	logicalSeq     int
	pendingRetries map[pendingRetryKey]time.Duration
}

// Server hosts both an in-process gRPC BigQueryWriteServer and an httptest
// BigQuery REST v2 metadata server.
type Server struct {
	storagepb.UnimplementedBigQueryWriteServer

	lis      net.Listener
	grpcSrv  *grpc.Server
	restSrv  *httptest.Server
	servedCh chan struct{}

	hasPeriodicFaults atomic.Bool

	mu                          sync.Mutex
	schemas                     map[string]*storagepb.TableSchema
	descriptors                 map[string]protoreflect.MessageDescriptor
	rows                        map[string][]map[string]any
	faults                      []Fault
	periodicFaults              map[string]*periodicFaultState
	discardRows                 bool
	trackUniqueAcked            bool
	maxUniqueAckedRows          int
	customMaxUniqueAcked        bool
	uniqueAckedSaturated        bool
	uniqueAckedSaturatedByTable map[string]bool
	seenAckedRows               map[[16]byte]struct{}
	seenSeqChunks               map[sequenceChunkKey]*sequenceBitmapChunk
	uniqueAckedRows             int64
	uniqueAckedBytes            int64
	ackedRowsByTable            map[string]int64
	ackedBytesByTable           map[string]int64
	seenAckedRowsByTable        map[string]map[[16]byte]struct{}
	seenSeqChunksByTable        map[string]map[sequenceChunkKey]*sequenceBitmapChunk
	uniqueAckedRowsByTable      map[string]int64
	uniqueAckedBytesByTable     map[string]int64
	onUniqueAckedSaturated      func(table string)
	beforeCommitHook            func(table string, serialized [][]byte) [][]byte
	periodicThrottlesInjected   map[string]int64
	throttlesInjectedByTable    map[string]int64
	delayedAcksInjectedByTable  map[string]int64

	connections int
	requests    int
	ackedRows   int
	ackedBytes  int64
	etagSeq     int

	datasets map[string]*bigqueryapi.Dataset
	tables   map[string]map[string]*bigqueryapi.Table
}

// NewServer starts a new in-process Server and registers cleanup on t.
func NewServer(t testing.TB) *Server {
	t.Helper()
	srv, err := New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.Close()
	})
	return srv
}

// DefaultMaxServerMsgSize sets the in-process gRPC server receive/send limit
// (32 MiB) well above BigQuery Storage Write API's 10 MiB request ceiling and
// the exporter's default 8 MiB write.max_request_bytes chunk threshold.
const DefaultMaxServerMsgSize = 32 * 1024 * 1024

// DefaultMaxUniqueAckedRows bounds the Tier 2 seen-row hash maps used when
// SetTrackUniqueAcked(true) is active on arbitrary/custom rows so sustained
// soak runs cannot grow server memory without bound.
const DefaultMaxUniqueAckedRows = 2_000_000

// DefaultMaxSequenceBitmapChunks bounds the Tier 1 sparse sequence bitmap
// chunks (65,536 sequence IDs = 8 KiB per chunk, 1,024 chunks = 67,108,864
// sequence IDs = 8 MiB maximum per table) used for generated benchmark rows.
const DefaultMaxSequenceBitmapChunks = 1024

// DefaultMaxTaggedSequenceBitmapChunks bounds the Tier 1 sequence bitmap chunks
// that also carry per-sequence 32-bit identity tags (264 KiB per chunk, 256
// chunks = 16,777,216 sequence IDs <= 66 MiB maximum per table) for generated
// logs with synthesized id1: insert IDs and generated metrics.
const DefaultMaxTaggedSequenceBitmapChunks = 256

// New starts a new in-process gRPC and REST fake server.
func New() (*Server, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listening on loopback: %w", err)
	}
	s := &Server{
		lis: lis,
		grpcSrv: grpc.NewServer(
			grpc.MaxRecvMsgSize(DefaultMaxServerMsgSize),
			grpc.MaxSendMsgSize(DefaultMaxServerMsgSize),
		),
		servedCh:                    make(chan struct{}),
		schemas:                     make(map[string]*storagepb.TableSchema),
		descriptors:                 make(map[string]protoreflect.MessageDescriptor),
		rows:                        make(map[string][]map[string]any),
		periodicFaults:              make(map[string]*periodicFaultState),
		maxUniqueAckedRows:          DefaultMaxUniqueAckedRows,
		uniqueAckedSaturatedByTable: make(map[string]bool),
		ackedRowsByTable:            make(map[string]int64),
		ackedBytesByTable:           make(map[string]int64),
		seenAckedRowsByTable:        make(map[string]map[[16]byte]struct{}),
		seenSeqChunksByTable:        make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk),
		uniqueAckedRowsByTable:      make(map[string]int64),
		uniqueAckedBytesByTable:     make(map[string]int64),
		periodicThrottlesInjected:   make(map[string]int64),
		throttlesInjectedByTable:    make(map[string]int64),
		delayedAcksInjectedByTable:  make(map[string]int64),
		datasets:                    make(map[string]*bigqueryapi.Dataset),
		tables:                      make(map[string]map[string]*bigqueryapi.Table),
	}

	if err := s.RegisterTableSchema("otel_spans", schema.SpansTableSchema()); err != nil {
		_ = lis.Close()
		return nil, err
	}
	if err := s.RegisterTableSchema("otel_logs", schema.LogsTableSchema()); err != nil {
		_ = lis.Close()
		return nil, err
	}
	if err := s.RegisterTableSchema("otel_metrics", schema.MetricsTableSchema()); err != nil {
		_ = lis.Close()
		return nil, err
	}
	if err := s.RegisterTableSchema("otel_quarantine", schema.QuarantineTableSchema()); err != nil {
		_ = lis.Close()
		return nil, err
	}

	storagepb.RegisterBigQueryWriteServer(s.grpcSrv, s)
	go func() {
		defer close(s.servedCh)
		_ = s.grpcSrv.Serve(lis)
	}()

	s.restSrv = httptest.NewServer(http.HandlerFunc(s.handleREST))
	return s, nil
}

// Close shuts down the REST and gRPC servers.
func (s *Server) Close() error {
	if s.restSrv != nil {
		s.restSrv.Close()
	}
	if s.grpcSrv != nil {
		s.grpcSrv.GracefulStop()
		<-s.servedCh
	}
	return nil
}

// Addr returns the loopback host:port of the gRPC Storage Write server.
func (s *Server) Addr() string {
	return s.lis.Addr().String()
}

// RESTURL returns the base URL of the REST v2 metadata server.
func (s *Server) RESTURL() string {
	return s.restSrv.URL
}

// WriteClientOptions returns client options that connect managedwriter to the
// fake gRPC server without TLS or ambient credentials.
func (s *Server) WriteClientOptions() []option.ClientOption {
	return []option.ClientOption{
		option.WithEndpoint(s.Addr()),
		option.WithGRPCDialOption(grpc.WithTransportCredentials(insecure.NewCredentials())),
		option.WithoutAuthentication(),
	}
}

// rewriteTransport redirects outgoing BigQuery REST requests to the local
// httptest.Server while preserving path and query parameters.
type rewriteTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (rt *rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.URL.Scheme = rt.target.Scheme
	cloned.URL.Host = rt.target.Host
	cloned.Host = rt.target.Host
	return rt.base.RoundTrip(cloned)
}

// NewHTTPClient returns an HTTP client and underlying transport that route all
// BigQuery REST v2 requests to this Server's httptest.Server without network
// access or credentials.
func (s *Server) NewHTTPClient() (*http.Client, *http.Transport) {
	target, _ := url.Parse(s.restSrv.URL)
	base := &http.Transport{}
	client := &http.Client{
		Transport: &rewriteTransport{
			base:   base,
			target: target,
		},
	}
	return client, base
}

// RegisterTableSchema registers a storagepb.TableSchema for validating and
// decoding ProtoRows sent to the named table.
func (s *Server) RegisterTableSchema(table string, ts *storagepb.TableSchema) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.registerTableSchemaLocked(table, ts)
}

func (s *Server) registerTableSchemaLocked(table string, ts *storagepb.TableSchema) error {
	md, err := descriptorFromTableSchema(ts)
	if err != nil {
		return err
	}
	s.schemas[table] = ts
	s.descriptors[table] = md
	return nil
}

// EnqueueFault appends one or more faults to the server's fault queue.
func (s *Server) EnqueueFault(faults ...Fault) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = append(s.faults, faults...)
}

// SetPeriodicFaults configures or clears periodic ResourceExhausted throttling
// and delayed acknowledgements for table (or all tables when table is "").
func (s *Server) SetPeriodicFaults(ctx context.Context, table string, throttleEvery int, ackDelay time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.periodicFaults == nil {
		s.periodicFaults = make(map[string]*periodicFaultState)
	}
	if s.periodicThrottlesInjected == nil {
		s.periodicThrottlesInjected = make(map[string]int64)
	}
	if table == "" {
		clear(s.periodicThrottlesInjected)
	} else {
		delete(s.periodicThrottlesInjected, table)
	}
	if throttleEvery <= 0 && ackDelay <= 0 {
		delete(s.periodicFaults, table)
		s.hasPeriodicFaults.Store(len(s.periodicFaults) > 0)
		return
	}
	s.periodicFaults[table] = &periodicFaultState{
		ctx:            ctx,
		throttleEvery:  throttleEvery,
		ackDelay:       ackDelay,
		pendingRetries: make(map[pendingRetryKey]time.Duration),
	}
	s.hasPeriodicFaults.Store(len(s.periodicFaults) > 0)
}

// Counts returns connection, request, and acknowledged-row totals.
func (s *Server) Counts() (connections, requests, ackedRows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections, s.requests, s.ackedRows
}

// AckedBytes returns the total serialized ProtoRows byte length across all
// acknowledged AppendRows requests.
func (s *Server) AckedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedBytes
}

// AckedRowsForTable returns the total number of rows acknowledged by
// AppendRows for table.
func (s *Server) AckedRowsForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedRowsByTable[table]
}

// AckedBytesForTable returns the total serialized ProtoRows byte length
// acknowledged by AppendRows for table.
func (s *Server) AckedBytesForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedBytesByTable[table]
}

// UniqueAckedRowsForTable returns the number of distinct canonical ProtoRows
// acknowledged for table while SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedRowsForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uniqueAckedRowsByTable[table]
}

// UniqueAckedBytesForTable returns the total serialized byte length of
// distinct canonical ProtoRows acknowledged for table while
// SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedBytesForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uniqueAckedBytesByTable[table]
}

// UniqueAckedTierCountsForTable returns the number of Tier 1 sparse sequence
// bitmap chunks and Tier 2 content hashes retained for table while
// SetTrackUniqueAcked(true) is active. When table is "", it returns the global
// Tier 1 chunk and Tier 2 hash counts.
func (s *Server) UniqueAckedTierCountsForTable(table string) (tier1Chunks, tier2Hashes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		return len(s.seenSeqChunks), len(s.seenAckedRows)
	}
	return len(s.seenSeqChunksByTable[table]), len(s.seenAckedRowsByTable[table])
}

// PeriodicThrottlesInjected returns the number of periodic
// FaultResourceExhausted responses injected for table. When table is "", it
// returns the sum of periodic throttles injected across all tables.
func (s *Server) PeriodicThrottlesInjected(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		var total int64
		for _, v := range s.periodicThrottlesInjected {
			total += v
		}
		return total
	}
	return s.periodicThrottlesInjected[table]
}

// ThrottlesInjectedForTable returns the number of FaultResourceExhausted
// responses (both queued one-shot faults and periodic throttles) injected for
// table. When table is "", it returns the total across all tables.
func (s *Server) ThrottlesInjectedForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		var total int64
		for _, v := range s.throttlesInjectedByTable {
			total += v
		}
		return total
	}
	return s.throttlesInjectedByTable[table]
}

// DelayedAcksInjectedForTable returns the number of FaultDelayedAck delays
// (Delay > 0) injected for table. When table is "", it returns the total
// across all tables.
func (s *Server) DelayedAcksInjectedForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		var total int64
		for _, v := range s.delayedAcksInjectedByTable {
			total += v
		}
		return total
	}
	return s.delayedAcksInjectedByTable[table]
}

// SetTrackUniqueAcked enables or disables tracking of distinct acknowledged
// ProtoRows (via Tier 1 sparse sequence bitmaps for canonical generated rows
// and Tier 2 content hashes for custom rows) and resets the global and
// per-table unique acknowledged row, byte, and saturation state.
func (s *Server) SetTrackUniqueAcked(track bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trackUniqueAcked = track
	s.uniqueAckedSaturated = false
	s.uniqueAckedSaturatedByTable = make(map[string]bool)
	s.uniqueAckedRows = 0
	s.uniqueAckedBytes = 0
	s.uniqueAckedRowsByTable = make(map[string]int64)
	s.uniqueAckedBytesByTable = make(map[string]int64)
	if track {
		s.seenAckedRows = make(map[[16]byte]struct{})
		s.seenSeqChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenAckedRowsByTable = make(map[string]map[[16]byte]struct{})
		s.seenSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
	} else {
		s.seenAckedRows = nil
		s.seenSeqChunks = nil
		s.seenAckedRowsByTable = nil
		s.seenSeqChunksByTable = nil
	}
}

// SetMaxUniqueAckedRows sets the maximum number of distinct canonical row
// hashes retained globally and per table while SetTrackUniqueAcked(true) is
// active. Passing limit <= 0 restores DefaultMaxUniqueAckedRows.
func (s *Server) SetMaxUniqueAckedRows(limit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = DefaultMaxUniqueAckedRows
	}
	s.maxUniqueAckedRows = limit
	s.customMaxUniqueAcked = limit < DefaultMaxUniqueAckedRows
}

// MaxUniqueAckedRows returns the effective maximum number of distinct canonical
// row hashes retained globally and per table while SetTrackUniqueAcked(true) is
// active.
func (s *Server) MaxUniqueAckedRows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.maxUniqueAckedRows > 0 {
		return s.maxUniqueAckedRows
	}
	return DefaultMaxUniqueAckedRows
}

// MaxTrackedGeneratedRows returns the effective row cap for untagged Tier-1
// sequence bitmap tracking: custom SetMaxUniqueAckedRows caps apply uniformly
// to both Tier 1 and Tier 2, whereas uncapped generated workloads track up to
// DefaultMaxSequenceBitmapChunks * 65536 rows per sequence domain.
func (s *Server) MaxTrackedGeneratedRows() int {
	return s.MaxTrackedGeneratedRowsForTagged(false)
}

// MaxTrackedSynthesizedLogRows returns the effective row cap for tagged Tier-1
// sequence bitmap tracking (synthesized id1: logs and generated metrics).
func (s *Server) MaxTrackedSynthesizedLogRows() int {
	return s.MaxTrackedGeneratedRowsForTagged(true)
}

// MaxTrackedGeneratedRowsForTagged returns the effective Tier-1 bitmap row cap
// for either untagged (false -> 67,108,864) or 32-bit identity-tagged
// (true -> 16,777,216) sequences when no smaller custom SetMaxUniqueAckedRows
// cap is configured.
func (s *Server) MaxTrackedGeneratedRowsForTagged(tagged bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.customMaxUniqueAcked && s.maxUniqueAckedRows > 0 {
		return s.maxUniqueAckedRows
	}
	if tagged {
		return DefaultMaxTaggedSequenceBitmapChunks * 65536
	}
	return DefaultMaxSequenceBitmapChunks * 65536
}

// SetOnUniqueAckedSaturated registers a callback invoked outside s.mu when a
// per-table seen-row hash map first reaches MaxUniqueAckedRows while
// SetTrackUniqueAcked(true) is active.
func (s *Server) SetOnUniqueAckedSaturated(fn func(table string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onUniqueAckedSaturated = fn
}

// SetBeforeCommitHook registers an optional test hook that can rewrite the
// serialized ProtoRows slice immediately before row validation and commit.
func (s *Server) SetBeforeCommitHook(fn func(table string, serialized [][]byte) [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeCommitHook = fn
}

// UniqueAckedSaturated reports whether the global seen-row hash map reached
// the configured SetMaxUniqueAckedRows cap while SetTrackUniqueAcked(true) was
// active.
func (s *Server) UniqueAckedSaturated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uniqueAckedSaturated
}

// UniqueAckedSaturatedForTable reports whether the per-table seen-row hash map
// for table reached the configured SetMaxUniqueAckedRows cap while
// SetTrackUniqueAcked(true) was active. When table is "", it reports global
// saturation.
func (s *Server) UniqueAckedSaturatedForTable(table string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		return s.uniqueAckedSaturated
	}
	return s.uniqueAckedSaturatedByTable[table]
}

// UniqueAckedRows returns the number of distinct serialized ProtoRows
// acknowledged while SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedRows() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uniqueAckedRows
}

// UniqueAckedBytes returns the total byte length of distinct serialized
// ProtoRows acknowledged while SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedBytes() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uniqueAckedBytes
}

// Rows returns a deep copy of all decoded rows appended to table.
func (s *Server) Rows(table string) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	src := s.rows[table]
	out := make([]map[string]any, len(src))
	for i, r := range src {
		out[i] = cloneMap(r)
	}
	return out
}

// RowCount returns the number of rows appended to table.
func (s *Server) RowCount(table string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.rows[table])
}

// ResetRows clears all stored rows and resets request, acknowledged, throttle,
// and delayed-ack counters.
func (s *Server) ResetRows() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = make(map[string][]map[string]any)
	s.requests = 0
	s.ackedRows = 0
	s.ackedBytes = 0
	s.uniqueAckedSaturated = false
	s.uniqueAckedSaturatedByTable = make(map[string]bool)
	s.uniqueAckedRows = 0
	s.uniqueAckedBytes = 0
	s.ackedRowsByTable = make(map[string]int64)
	s.ackedBytesByTable = make(map[string]int64)
	s.uniqueAckedRowsByTable = make(map[string]int64)
	s.uniqueAckedBytesByTable = make(map[string]int64)
	s.periodicThrottlesInjected = make(map[string]int64)
	s.throttlesInjectedByTable = make(map[string]int64)
	s.delayedAcksInjectedByTable = make(map[string]int64)
	if s.trackUniqueAcked {
		s.seenAckedRows = make(map[[16]byte]struct{})
		s.seenSeqChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenAckedRowsByTable = make(map[string]map[[16]byte]struct{})
		s.seenSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
	} else {
		s.seenAckedRows = nil
		s.seenSeqChunks = nil
		s.seenAckedRowsByTable = nil
		s.seenSeqChunksByTable = nil
	}
}

// SetDiscardRows configures whether AppendRows discards decoded rows after
// schema and required-field validation instead of retaining them in memory.
// When enabled, Rows and RowCount stay empty while request, acknowledged-row,
// and acknowledged-byte counters continue updating normally.
func (s *Server) SetDiscardRows(discard bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.discardRows = discard
}

// Dataset returns a snapshot of the REST v2 Dataset metadata if created.
func (s *Server) Dataset(project, dataset string) (*bigqueryapi.Dataset, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ds, ok := s.datasets[project+"."+dataset]
	if !ok || ds == nil {
		return nil, false
	}
	return cloneJSON(ds), true
}

// Table returns a snapshot of the REST v2 Table metadata if created.
func (s *Server) Table(project, dataset, table string) (*bigqueryapi.Table, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byTable, ok := s.tables[project+"."+dataset]
	if !ok {
		return nil, false
	}
	tbl, ok := byTable[table]
	if !ok || tbl == nil {
		return nil, false
	}
	return cloneJSON(tbl), true
}

// SeedDataset pre-populates a dataset in the REST v2 server.
func (s *Server) SeedDataset(project, dataset, location string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := project + "." + dataset
	s.datasets[key] = &bigqueryapi.Dataset{
		DatasetReference: &bigqueryapi.DatasetReference{
			ProjectId: project,
			DatasetId: dataset,
		},
		Location: location,
		Etag:     "etag-" + key,
	}
}

// SeedTable pre-populates a table in the REST v2 server and registers its
// storagepb.TableSchema for ProtoRows decoding.
func (s *Server) SeedTable(project, dataset, table string, ts *storagepb.TableSchema) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.registerTableSchemaLocked(table, ts); err != nil {
		return err
	}
	key := project + "." + dataset
	if _, ok := s.datasets[key]; !ok {
		s.datasets[key] = &bigqueryapi.Dataset{
			DatasetReference: &bigqueryapi.DatasetReference{
				ProjectId: project,
				DatasetId: dataset,
			},
			Location: "US",
			Etag:     "etag-" + key,
		}
	}
	if s.tables[key] == nil {
		s.tables[key] = make(map[string]*bigqueryapi.Table)
	}
	s.tables[key][table] = &bigqueryapi.Table{
		TableReference: &bigqueryapi.TableReference{
			ProjectId: project,
			DatasetId: dataset,
			TableId:   table,
		},
		Type:   "TABLE",
		Schema: toRESTTableSchema(ts),
		Etag:   "etag-" + table,
	}
	return nil
}

// GetWriteStream implements storagepb.BigQueryWriteServer.
func (s *Server) GetWriteStream(
	_ context.Context, req *storagepb.GetWriteStreamRequest,
) (*storagepb.WriteStream, error) {
	return &storagepb.WriteStream{
		Name:     req.GetName(),
		Type:     storagepb.WriteStream_COMMITTED,
		Location: "US",
	}, nil
}

// CreateWriteStream implements storagepb.BigQueryWriteServer.
func (s *Server) CreateWriteStream(
	_ context.Context, req *storagepb.CreateWriteStreamRequest,
) (*storagepb.WriteStream, error) {
	stream := req.GetWriteStream()
	name := req.GetParent() + "/streams/_default"
	if stream != nil && stream.GetName() != "" {
		name = stream.GetName()
	}
	return &storagepb.WriteStream{
		Name:     name,
		Type:     storagepb.WriteStream_COMMITTED,
		Location: "US",
	}, nil
}

// AppendRows implements storagepb.BigQueryWriteServer.
func (s *Server) AppendRows(srv storagepb.BigQueryWrite_AppendRowsServer) error {
	s.mu.Lock()
	s.connections++
	s.mu.Unlock()

	var streamTable string
	var streamDesc protoreflect.MessageDescriptor
	var ignoreFields [3]protowire.Number
	var seqFDs sequenceKeyFieldDescriptors

	for {
		req, err := srv.Recv()
		if err != nil {
			return nil
		}
		if ws := req.GetWriteStream(); ws != "" {
			if tbl := parseTableFromStream(ws); tbl != "" {
				streamTable = tbl
			}
		}

		var protoDescErr error
		if protoDesc := req.GetProtoRows().GetWriterSchema().GetProtoDescriptor(); protoDesc != nil {
			if protoDesc.GetName() == "" || len(protoDesc.GetField()) == 0 {
				protoDescErr = fmt.Errorf("writer proto descriptor must have a name and at least one field")
			} else if md, derr := descriptorFromProto(protoDesc); derr != nil {
				protoDescErr = fmt.Errorf("invalid writer proto descriptor: %w", derr)
			} else {
				streamDesc = md
				ignoreFields = ingestionTimestampFieldNumbers(md)
				seqFDs = lookupSequenceKeyFields(md)
			}
		}

		serialized := req.GetProtoRows().GetRows().GetSerializedRows()
		var batchKey [32]byte
		batchKeyComputed := false
		if s.hasPeriodicFaults.Load() {
			batchKey = hashSerializedRowsWithDesc(streamDesc, serialized, ignoreFields)
			batchKeyComputed = true
		}

		s.mu.Lock()
		s.requests++
		tableDesc := s.descriptors[streamTable]
		discardRows := s.discardRows
		trackUnique := s.trackUniqueAcked
		beforeCommit := s.beforeCommitHook
		fault := s.popMatchingFaultWithDescLocked(streamTable, streamDesc, batchKey, batchKeyComputed, serialized, ignoreFields)
		s.mu.Unlock()

		if protoDescErr != nil {
			if err := srv.Send(errorResponse(codes.InvalidArgument, protoDescErr.Error(), nil)); err != nil {
				return nil
			}
			continue
		}
		if streamDesc == nil {
			if err := srv.Send(errorResponse(codes.InvalidArgument, "missing writer schema proto descriptor", nil)); err != nil {
				return nil
			}
			continue
		}
		if tableDesc != nil {
			if verr := validateWriterDescriptor(streamDesc, tableDesc); verr != nil {
				if err := srv.Send(errorResponse(codes.InvalidArgument, verr.Error(), nil)); err != nil {
					return nil
				}
				continue
			}
		}

		switch fault.Mode {
		case FaultStreamClosed:
			msg := fault.Message
			if msg == "" {
				msg = "stream closed by fake fault injection"
			}
			return status.Error(codes.Aborted, msg)

		case FaultUnavailable:
			msg := fault.Message
			if msg == "" {
				msg = "service unavailable"
			}
			if err := srv.Send(errorResponse(codes.Unavailable, msg, nil)); err != nil {
				return nil
			}
			continue

		case FaultResourceExhausted:
			s.mu.Lock()
			if s.throttlesInjectedByTable == nil {
				s.throttlesInjectedByTable = make(map[string]int64)
			}
			s.throttlesInjectedByTable[streamTable]++
			s.mu.Unlock()
			msg := fault.Message
			if msg == "" {
				msg = "rate limit exceeded: Quota exceeded"
			}
			if err := srv.Send(errorResponse(codes.ResourceExhausted, msg, nil)); err != nil {
				return nil
			}
			continue

		case FaultPermissionDenied:
			msg := fault.Message
			if msg == "" {
				msg = "permission denied on destination table"
			}
			if err := srv.Send(errorResponse(codes.PermissionDenied, msg, nil)); err != nil {
				return nil
			}
			continue

		case FaultInvalidArgument:
			msg := fault.Message
			if msg == "" {
				msg = "invalid argument"
			}
			if err := srv.Send(errorResponse(codes.InvalidArgument, msg, nil)); err != nil {
				return nil
			}
			continue

		case FaultRowErrors:
			msg := fault.Message
			if msg == "" {
				msg = "row errors in append request"
			}
			if err := srv.Send(errorResponse(codes.InvalidArgument, msg, fault.RowErrors)); err != nil {
				return nil
			}
			continue

		case FaultDelayedAck:
			if fault.Ctx != nil && fault.Ctx.Err() != nil {
				return status.FromContextError(fault.Ctx.Err()).Err()
			}
			if fault.Delay > 0 {
				var faultDone <-chan struct{}
				if fault.Ctx != nil {
					faultDone = fault.Ctx.Done()
				}
				s.mu.Lock()
				if s.delayedAcksInjectedByTable == nil {
					s.delayedAcksInjectedByTable = make(map[string]int64)
				}
				s.delayedAcksInjectedByTable[streamTable]++
				s.mu.Unlock()
				timer := time.NewTimer(fault.Delay)
				select {
				case <-srv.Context().Done():
					timer.Stop()
					return nil
				case <-faultDone:
					timer.Stop()
					return status.FromContextError(fault.Ctx.Err()).Err()
				case <-timer.C:
				}
			}
		}

		if beforeCommit != nil && len(serialized) > 0 {
			serialized = beforeCommit(streamTable, serialized)
		}

		var decodedBatch []map[string]any
		if !discardRows {
			decodedBatch = make([]map[string]any, 0, len(serialized))
		}
		var (
			rowSeqKeys []extractedSequenceKey
			rowHashes  [][16]byte
		)
		if trackUnique && len(serialized) > 0 {
			rowSeqKeys = make([]extractedSequenceKey, len(serialized))
			rowHashes = make([][16]byte, len(serialized))
		}
		var rowErrs []*storagepb.RowError
		for i, raw := range serialized {
			msg, derr := unmarshalRow(streamDesc, raw)
			if derr == nil && tableDesc != nil {
				// The writer descriptor may declare a REQUIRED destination
				// column OPTIONAL, so decoding alone does not enforce it.
				derr = validateRequiredValues(msg, tableDesc, "")
			}
			if derr != nil {
				rowErrs = append(rowErrs, &storagepb.RowError{
					Index:   int64(i),
					Code:    storagepb.RowError_FIELDS_ERROR,
					Message: derr.Error(),
				})
				continue
			}
			if trackUnique {
				sk := extractGeneratedSequenceKey(msg, seqFDs)
				rowSeqKeys[i] = sk
				if !sk.ok {
					sum := hashCanonicalMessageWithFallback(msg, raw, ignoreFields)
					copy(rowHashes[i][:], sum[:16])
				}
			}
			if !discardRows {
				decodedBatch = append(decodedBatch, messageToMap(msg))
			}
		}
		if len(rowErrs) > 0 {
			// Appends are atomic: one bad row rejects every row of the request.
			if err := srv.Send(errorResponse(codes.InvalidArgument, "row errors in append request", rowErrs)); err != nil {
				return nil
			}
			continue
		}

		var chunkBytes int64
		for _, raw := range serialized {
			chunkBytes += int64(len(raw))
		}
		var (
			saturatedTable string
			saturatedCB    func(string)
		)
		s.mu.Lock()
		s.ackedRows += len(serialized)
		s.ackedBytes += chunkBytes
		if streamTable != "" {
			if s.ackedRowsByTable == nil {
				s.ackedRowsByTable = make(map[string]int64)
			}
			if s.ackedBytesByTable == nil {
				s.ackedBytesByTable = make(map[string]int64)
			}
			s.ackedRowsByTable[streamTable] += int64(len(serialized))
			s.ackedBytesByTable[streamTable] += chunkBytes
		}
		if s.trackUniqueAcked {
			limit := s.maxUniqueAckedRows
			if limit <= 0 {
				limit = DefaultMaxUniqueAckedRows
			}
			customCap := s.customMaxUniqueAcked
			if s.seenAckedRows == nil {
				s.seenAckedRows = make(map[[16]byte]struct{})
			}
			if s.seenSeqChunks == nil {
				s.seenSeqChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
			}
			var (
				tableSeen   map[[16]byte]struct{}
				tableChunks map[sequenceChunkKey]*sequenceBitmapChunk
			)
			if streamTable != "" {
				if s.uniqueAckedSaturatedByTable == nil {
					s.uniqueAckedSaturatedByTable = make(map[string]bool)
				}
				if s.seenAckedRowsByTable == nil {
					s.seenAckedRowsByTable = make(map[string]map[[16]byte]struct{})
				}
				tableSeen = s.seenAckedRowsByTable[streamTable]
				if tableSeen == nil {
					tableSeen = make(map[[16]byte]struct{})
					s.seenAckedRowsByTable[streamTable] = tableSeen
				}
				if s.seenSeqChunksByTable == nil {
					s.seenSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
				}
				tableChunks = s.seenSeqChunksByTable[streamTable]
				if tableChunks == nil {
					tableChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
					s.seenSeqChunksByTable[streamTable] = tableChunks
				}
				if s.uniqueAckedRowsByTable == nil {
					s.uniqueAckedRowsByTable = make(map[string]int64)
				}
				if s.uniqueAckedBytesByTable == nil {
					s.uniqueAckedBytesByTable = make(map[string]int64)
				}
			}
			for i, raw := range serialized {
				var sk extractedSequenceKey
				if len(rowSeqKeys) == len(serialized) {
					sk = rowSeqKeys[i]
				} else if msg, uerr := unmarshalRow(streamDesc, raw); uerr == nil {
					sk = extractGeneratedSequenceKey(msg, seqFDs)
				}
				var (
					cachedHash    [16]byte
					hasCachedHash bool
				)
				computeHash := func() [16]byte {
					if hasCachedHash {
						return cachedHash
					}
					if !sk.ok && len(rowHashes) == len(serialized) {
						cachedHash = rowHashes[i]
						hasCachedHash = true
						return cachedHash
					}
					var sum [32]byte
					if msg, uerr := unmarshalRow(streamDesc, raw); uerr == nil {
						sum = hashCanonicalMessageWithFallback(msg, raw, ignoreFields)
					} else {
						sum = hashCanonicalRow(raw, ignoreFields)
					}
					copy(cachedHash[:], sum[:16])
					hasCachedHash = true
					return cachedHash
				}
				isNewGlobal, satGlobal := recordUniqueAckedRow(
					s.seenSeqChunks,
					s.seenAckedRows,
					sk,
					computeHash,
					customCap,
					limit,
					s.uniqueAckedRows,
				)
				if satGlobal {
					s.uniqueAckedSaturated = true
				} else if isNewGlobal {
					s.uniqueAckedRows++
					s.uniqueAckedBytes += int64(len(raw))
				}
				if tableChunks != nil {
					isNewTbl, satTbl := recordUniqueAckedRow(
						tableChunks,
						tableSeen,
						sk,
						computeHash,
						customCap,
						limit,
						s.uniqueAckedRowsByTable[streamTable],
					)
					if satTbl {
						if !s.uniqueAckedSaturatedByTable[streamTable] {
							s.uniqueAckedSaturatedByTable[streamTable] = true
							saturatedTable = streamTable
							saturatedCB = s.onUniqueAckedSaturated
						}
					} else if isNewTbl {
						s.uniqueAckedRowsByTable[streamTable]++
						s.uniqueAckedBytesByTable[streamTable] += int64(len(raw))
					}
				}
			}
		}
		if !s.discardRows && streamTable != "" && len(decodedBatch) > 0 {
			s.rows[streamTable] = append(s.rows[streamTable], decodedBatch...)
		}
		s.mu.Unlock()
		if saturatedCB != nil {
			saturatedCB(saturatedTable)
		}

		if fault.Mode == FaultCommitThenStreamClosed {
			msg := fault.Message
			if msg == "" {
				msg = "stream closed after commit by fake fault injection"
			}
			return status.Error(codes.Aborted, msg)
		}

		resp := &storagepb.AppendRowsResponse{
			Response: &storagepb.AppendRowsResponse_AppendResult_{
				AppendResult: &storagepb.AppendRowsResponse_AppendResult{},
			},
		}
		if err := srv.Send(resp); err != nil {
			return nil
		}
	}
}

func validateWriterDescriptor(writerDesc, tableDesc protoreflect.MessageDescriptor) error {
	for i := 0; i < writerDesc.Fields().Len(); i++ {
		wf := writerDesc.Fields().Get(i)
		tf := tableDesc.Fields().ByName(wf.Name())
		if tf == nil {
			return fmt.Errorf("writer field %q does not exist in destination table schema", wf.Name())
		}
		if wf.IsList() != tf.IsList() {
			return fmt.Errorf("writer field %q repeated=%v does not match destination table repeated=%v", wf.Name(), wf.IsList(), tf.IsList())
		}
		if wf.Kind() != tf.Kind() {
			return fmt.Errorf("writer field %q kind %v does not match destination table kind %v", wf.Name(), wf.Kind(), tf.Kind())
		}
		if wf.Kind() == protoreflect.MessageKind {
			if err := validateWriterDescriptor(wf.Message(), tf.Message()); err != nil {
				return fmt.Errorf("writer field %q: %w", wf.Name(), err)
			}
		}
	}
	for i := 0; i < tableDesc.Fields().Len(); i++ {
		tf := tableDesc.Fields().Get(i)
		if tf.Cardinality() == protoreflect.Required && writerDesc.Fields().ByName(tf.Name()) == nil {
			return fmt.Errorf("required destination column %q is missing from writer schema", tf.Name())
		}
	}
	return nil
}

// validateRequiredValues reports the first REQUIRED destination column that a
// row decoded with the writer's descriptor leaves without a value. Records are
// checked only where present: a NULL parent STRUCT carries no values to
// require. prefix is the column path of msg within the row.
func validateRequiredValues(msg protoreflect.Message, tableDesc protoreflect.MessageDescriptor, prefix string) error {
	writerFields := msg.Descriptor().Fields()
	for i := 0; i < tableDesc.Fields().Len(); i++ {
		tf := tableDesc.Fields().Get(i)
		path := prefix + string(tf.Name())
		wf := writerFields.ByName(tf.Name())
		if wf == nil || !msg.Has(wf) {
			if tf.Cardinality() == protoreflect.Required {
				return fmt.Errorf("required destination column %q has no value", path)
			}
			continue
		}
		if tf.Kind() != protoreflect.MessageKind {
			continue
		}
		if tf.IsList() {
			list := msg.Get(wf).List()
			for j := 0; j < list.Len(); j++ {
				if err := validateRequiredValues(list.Get(j).Message(), tf.Message(), fmt.Sprintf("%s[%d].", path, j)); err != nil {
					return err
				}
			}
			continue
		}
		if err := validateRequiredValues(msg.Get(wf).Message(), tf.Message(), path+"."); err != nil {
			return err
		}
	}
	return nil
}

var generatedBaseUnixNano = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()

const (
	seqDomainSpan uint8 = iota + 1
	seqDomainLogEdgeInsertID
	seqDomainLogEdgeTraceStep
	seqDomainLogTraceStep
	seqDomainLogAccess
	seqDomainMetric
)

type sequenceChunkKey struct {
	domain       uint8
	identityHash uint64
	chunk        uint64
}

type sequenceBitmapChunk struct {
	bits [1024]uint64
	tags *[65536]uint32
}

type extractedSequenceKey struct {
	domain       uint8
	identityHash uint64
	seq          uint64
	hasTag       bool
	tag          uint32
	ok           bool
}

type sequenceKeyFieldDescriptors struct {
	timestamp        protoreflect.FieldDescriptor
	obsTimestamp     protoreflect.FieldDescriptor
	startTime        protoreflect.FieldDescriptor
	serviceName      protoreflect.FieldDescriptor
	severityNumber   protoreflect.FieldDescriptor
	logName          protoreflect.FieldDescriptor
	spanName         protoreflect.FieldDescriptor
	metricName       protoreflect.FieldDescriptor
	metricType       protoreflect.FieldDescriptor
	pointFingerprint protoreflect.FieldDescriptor
	startTimeNano    protoreflect.FieldDescriptor
	timeNano         protoreflect.FieldDescriptor
	obsTimeNano      protoreflect.FieldDescriptor
	traceID          protoreflect.FieldDescriptor
	spanID           protoreflect.FieldDescriptor
	insertID         protoreflect.FieldDescriptor
	eventName        protoreflect.FieldDescriptor
	exemplars        protoreflect.FieldDescriptor
	exTraceID        protoreflect.FieldDescriptor
	exSpanID         protoreflect.FieldDescriptor
}

func lookupSequenceKeyFields(desc protoreflect.MessageDescriptor) sequenceKeyFieldDescriptors {
	if desc == nil {
		return sequenceKeyFieldDescriptors{}
	}
	f := desc.Fields()
	out := sequenceKeyFieldDescriptors{
		timestamp:        f.ByName("timestamp"),
		obsTimestamp:     f.ByName("observed_timestamp"),
		startTime:        f.ByName("start_time"),
		serviceName:      f.ByName("service_name"),
		severityNumber:   f.ByName("severity_number"),
		logName:          f.ByName("log_name"),
		spanName:         f.ByName("name"),
		metricName:       f.ByName("metric_name"),
		metricType:       f.ByName("metric_type"),
		pointFingerprint: f.ByName("point_fingerprint"),
		startTimeNano:    f.ByName("start_time_unix_nano"),
		timeNano:         f.ByName("time_unix_nano"),
		obsTimeNano:      f.ByName("observed_time_unix_nano"),
		traceID:          f.ByName("trace_id"),
		spanID:           f.ByName("span_id"),
		insertID:         f.ByName("insert_id"),
		eventName:        f.ByName("event_name"),
		exemplars:        f.ByName("exemplars"),
	}
	if out.exemplars != nil && out.exemplars.Kind() == protoreflect.MessageKind {
		ef := out.exemplars.Message().Fields()
		out.exTraceID = ef.ByName("trace_id")
		out.exSpanID = ef.ByName("span_id")
	}
	return out
}

func msgString(msg protoreflect.Message, fd protoreflect.FieldDescriptor) string {
	if fd == nil || fd.Kind() != protoreflect.StringKind || !msg.Has(fd) {
		return ""
	}
	return msg.Get(fd).String()
}

func msgInt64(msg protoreflect.Message, fd protoreflect.FieldDescriptor) (int64, bool) {
	if fd == nil || !msg.Has(fd) {
		return 0, false
	}
	switch fd.Kind() {
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return msg.Get(fd).Int(), true
	default:
		return 0, false
	}
}

func parseLowerHexUint64(s string) (uint64, bool) {
	if len(s) != 16 {
		return 0, false
	}
	var out uint64
	for i := range 16 {
		c := s[i]
		var nib uint64
		switch {
		case c >= '0' && c <= '9':
			nib = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			nib = uint64(c-'a') + 10
		default:
			return 0, false
		}
		out = (out << 4) | nib
	}
	return out, true
}

func parseGeneratedTraceIDHex(s string) (uint64, bool) {
	if len(s) != 32 {
		return 0, false
	}
	hi, okHi := parseLowerHexUint64(s[0:16])
	lo, okLo := parseLowerHexUint64(s[16:32])
	if !okHi || !okLo || lo == 0 || hi != (0x0102030405060708^lo) {
		return 0, false
	}
	return lo - 1, true
}

func parseGeneratedSpanIDHex(s string) (treeID, step uint64, ok bool) {
	v, okHex := parseLowerHexUint64(s)
	if !okHex {
		return 0, 0, false
	}
	rawTree := v >> 4
	step = v & 0x0f
	if rawTree == 0 || step >= 4 {
		return 0, 0, false
	}
	return rawTree - 1, step, true
}

func parseGeneratedTreeAndStepHex(traceID, spanID string) (treeID, step uint64, ok bool) {
	tTree, tOK := parseGeneratedTraceIDHex(traceID)
	sTree, sStep, sOK := parseGeneratedSpanIDHex(spanID)
	if !tOK || !sOK || tTree != sTree {
		return 0, 0, false
	}
	return tTree, sStep, true
}

func parseEdgeInsertID(s string) (uint64, bool) {
	if len(s) != 21 || !strings.HasPrefix(s, "edge-") {
		return 0, false
	}
	return parseLowerHexUint64(s[5:21])
}

func isSynthesizedInsertIDV1(s string) bool {
	if len(s) != 26 || !strings.HasPrefix(s, schema.InsertIDPrefixV1) {
		return false
	}
	for i := 4; i < 26; i++ {
		c := s[i]
		isAlpha := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		isDigit := c >= '0' && c <= '9'
		if !isAlpha && !isDigit && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

var (
	generatedFrameworkServiceNames = [7]string{
		"adk-weather-agent",
		"langgraph-research-graph",
		"openai-triage-agent",
		"anthropic-agent-cli",
		"crewai-analyst-crew",
		"bedrock-converse-worker",
		"maf-orchestrator",
	}
	generatedGenAILogEventNames = [4]string{
		"gen_ai.user.message",
		"gen_ai.choice",
		"gen_ai.tool.message",
		"gen_ai.system.instructions",
	}
	generatedFrameworkSpanSpecs = [7]struct {
		crewai    bool
		agentName string
		model     string
		toolName  string
	}{
		{agentName: "weather_coordinator", model: "gemini-2.5-pro", toolName: "get_forecast"},
		{agentName: "research_supervisor", model: "gpt-4o", toolName: "vector_store_lookup"},
		{agentName: "billing_triage", model: "gpt-4o", toolName: "fetch_customer_ledger"},
		{agentName: "code-assistant", model: "anthropic-v4-default", toolName: "sandbox_bash_exec"},
		{crewai: true, model: "gpt-4o-mini", toolName: "sec_filing_extractor"},
		{agentName: "bedrock_router", model: "amazon.nova-pro-v1:0", toolName: "retrieve_and_generate"},
		{agentName: "support_orchestrator", model: "gpt-4o", toolName: "graph_calendar_query"},
	}
	generatedMCPSpanNames = [3]string{
		"mcp tools/call run_sql_query",
		"mcp resources/read gs://agent-context/schemas/orders.json",
		"mcp prompts/get incident_root_cause_triage",
	}
)

func generatedSpanName(treeID, step uint64) string {
	spec := generatedFrameworkSpanSpecs[treeID%uint64(len(generatedFrameworkSpanSpecs))]
	switch step {
	case 0:
		if spec.crewai {
			return "Crew.kickoff"
		}
		return "invoke_agent " + spec.agentName
	case 1:
		if spec.crewai {
			return "ChatCompletion " + spec.model
		}
		return "chat " + spec.model
	case 2:
		if spec.crewai {
			return "ToolUsage " + spec.toolName
		}
		return "execute_tool " + spec.toolName
	case 3:
		return generatedMCPSpanNames[treeID%uint64(len(generatedMCPSpanNames))]
	default:
		return ""
	}
}

func hashStringNonZero64(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.LittleEndian.Uint64(sum[:8]) | 1
}

func spanIdentityHash(spanName string, treeID, step uint64) (uint64, bool) {
	if spanName == generatedSpanName(treeID, step) {
		return 0, true
	}
	// Prebuilt Collector templates may rotate treeID across treeStrides divisible
	// by 7 (framework count) rather than 21 (lcm(7, 3)); hash the MCP name into
	// identityHash so legitimate MCP spans stay in Tier 1 without merging
	// distinct span names at identical (start_time, trace_id, span_id).
	if step == 3 && slices.Contains(generatedMCPSpanNames[:], spanName) {
		return hashStringNonZero64(spanName), true
	}
	return 0, false
}

func generatedMetricName(step uint64) string {
	if step%2 == 0 {
		return "gen_ai.client.token.usage"
	}
	return "gen_ai.client.operation.duration"
}

func hashString32(s string) uint32 {
	sum := sha256.Sum256([]byte(s))
	return binary.LittleEndian.Uint32(sum[:4])
}

func hasValidGeneratedGenAILogIdentity(msg protoreflect.Message, fds sequenceKeyFieldDescriptors, treeID, step uint64) bool {
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	if !hasSev || sev != 9 {
		return false
	}
	wantSvc := generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))]
	svc := msgString(msg, fds.serviceName)
	if svc != wantSvc || msgString(msg, fds.logName) != svc {
		return false
	}
	return msgString(msg, fds.eventName) == generatedGenAILogEventNames[step%uint64(len(generatedGenAILogEventNames))]
}

func generatedAccessLogServiceName(seq uint64) string {
	switch seq % 4 {
	case 0, 1:
		return "edge-ingress-gateway"
	case 2:
		return "vpc-flow-proxy"
	default:
		return "api-edge-envoy"
	}
}

func generatedAccessLogSeverity(seq uint64) int64 {
	switch seq % 6 {
	case 0, 1, 2:
		return 9
	case 3, 4:
		return 13
	default:
		return 17
	}
}

func hashLogStreamIdentity(svc, logName string, hasSev bool, sev int64) uint64 {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(len(svc)))
	h.Write(buf[:])
	h.Write([]byte(svc))
	binary.LittleEndian.PutUint64(buf[:], uint64(len(logName)))
	h.Write(buf[:])
	h.Write([]byte(logName))
	var flag [1]byte
	if hasSev {
		flag[0] = 1
	}
	h.Write(flag[:])
	binary.LittleEndian.PutUint64(buf[:], uint64(sev))
	h.Write(buf[:])
	sum := h.Sum(nil)
	// Reserve 0 for canonical generator-matched access-log streams so genuine
	// AccessLogsBatch runs use one chunk per 65,536 rows without extra buckets.
	return binary.LittleEndian.Uint64(sum[:8]) | 1
}

func accessLogStreamIdentityHash(msg protoreflect.Message, fds sequenceKeyFieldDescriptors, seq uint64) uint64 {
	svc := msgString(msg, fds.serviceName)
	logName := msgString(msg, fds.logName)
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	if hasSev &&
		svc == generatedAccessLogServiceName(seq) &&
		logName == svc &&
		sev == generatedAccessLogSeverity(seq) {
		return 0
	}
	return hashLogStreamIdentity(svc, logName, hasSev, sev)
}

func hasValidGeneratedAccessLogIdentity(msg protoreflect.Message, fds sequenceKeyFieldDescriptors) bool {
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	if !hasSev || (sev != 9 && sev != 13 && sev != 17) {
		return false
	}
	svc := msgString(msg, fds.serviceName)
	switch svc {
	case "edge-ingress-gateway", "vpc-flow-proxy", "api-edge-envoy":
	default:
		return false
	}
	return msgString(msg, fds.logName) == svc
}

func extractGeneratedSequenceKey(msg protoreflect.Message, fds sequenceKeyFieldDescriptors) extractedSequenceKey {
	if fds.logName != nil && fds.timeNano != nil {
		insertID := msgString(msg, fds.insertID)
		edgeSeq, isEdge := parseEdgeInsertID(insertID)
		isSynthV1 := !isEdge && isSynthesizedInsertIDV1(insertID)
		if !isEdge && !isSynthV1 {
			return extractedSequenceKey{}
		}
		var tag32 uint32
		if isSynthV1 {
			tag32 = hashString32(insertID)
		}
		tNano, hasTNano := msgInt64(msg, fds.timeNano)
		if !hasTNano {
			return extractedSequenceKey{}
		}
		if fds.timestamp != nil {
			tsMicro, hasTS := msgInt64(msg, fds.timestamp)
			if !hasTS || tsMicro != tNano/1000 {
				return extractedSequenceKey{}
			}
		}
		obsNano, hasObs := msgInt64(msg, fds.obsTimeNano)
		if !hasObs || obsNano != tNano+1_000_000 {
			return extractedSequenceKey{}
		}
		if fds.obsTimestamp != nil && msg.Has(fds.obsTimestamp) {
			obsMicro, hasObsMicro := msgInt64(msg, fds.obsTimestamp)
			if !hasObsMicro || obsMicro != obsNano/1000 {
				return extractedSequenceKey{}
			}
		}
		if isEdge {
			if edgeSeq > math.MaxInt64/100_000 || tNano != generatedBaseUnixNano+int64(edgeSeq)*100_000 {
				return extractedSequenceKey{}
			}
		}

		traceID := msgString(msg, fds.traceID)
		spanID := msgString(msg, fds.spanID)
		if traceID != "" || spanID != "" {
			treeID, step, ok := parseGeneratedTreeAndStepHex(traceID, spanID)
			if !ok {
				return extractedSequenceKey{}
			}
			seq := treeID*4 + step
			if seq > math.MaxInt64/100_000 || tNano != generatedBaseUnixNano+int64(seq)*100_000 {
				return extractedSequenceKey{}
			}
			if !hasValidGeneratedGenAILogIdentity(msg, fds, treeID, step) {
				return extractedSequenceKey{}
			}
			if isEdge {
				if edgeSeq != seq {
					return extractedSequenceKey{}
				}
				return extractedSequenceKey{domain: seqDomainLogEdgeTraceStep, seq: seq, ok: true}
			}
			return extractedSequenceKey{domain: seqDomainLogTraceStep, seq: seq, hasTag: true, tag: tag32, ok: true}
		}
		if msgString(msg, fds.eventName) != "http.server.request" {
			return extractedSequenceKey{}
		}
		if tNano < generatedBaseUnixNano || (tNano-generatedBaseUnixNano)%100_000 != 0 {
			return extractedSequenceKey{}
		}
		seq := uint64((tNano - generatedBaseUnixNano) / 100_000)
		if isEdge {
			if edgeSeq != seq || !hasValidGeneratedAccessLogIdentity(msg, fds) {
				return extractedSequenceKey{}
			}
			return extractedSequenceKey{
				domain:       seqDomainLogEdgeInsertID,
				identityHash: accessLogStreamIdentityHash(msg, fds, seq),
				seq:          seq,
				ok:           true,
			}
		}
		return extractedSequenceKey{
			domain:       seqDomainLogAccess,
			identityHash: accessLogStreamIdentityHash(msg, fds, seq),
			seq:          seq,
			hasTag:       true,
			tag:          tag32,
			ok:           true,
		}
	}

	if fds.metricName != nil && fds.timeNano != nil && fds.exemplars != nil {
		if !msg.Has(fds.exemplars) {
			return extractedSequenceKey{}
		}
		exList := msg.Get(fds.exemplars).List()
		if exList.Len() != 1 {
			return extractedSequenceKey{}
		}
		exMsg := exList.Get(0).Message()
		treeID, step, ok := parseGeneratedTreeAndStepHex(msgString(exMsg, fds.exTraceID), msgString(exMsg, fds.exSpanID))
		if !ok {
			return extractedSequenceKey{}
		}
		seq := treeID*4 + step
		tNano, hasTNano := msgInt64(msg, fds.timeNano)
		if !hasTNano || seq > math.MaxInt64/100_000 || tNano != generatedBaseUnixNano+int64(seq)*100_000 {
			return extractedSequenceKey{}
		}
		if fds.timestamp != nil {
			tsMicro, hasTS := msgInt64(msg, fds.timestamp)
			if !hasTS || tsMicro != tNano/1000 {
				return extractedSequenceKey{}
			}
		}
		wantSvc := generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))]
		if msgString(msg, fds.serviceName) != wantSvc {
			return extractedSequenceKey{}
		}
		if msgString(msg, fds.metricName) != generatedMetricName(step) {
			return extractedSequenceKey{}
		}
		if msgString(msg, fds.metricType) != "HISTOGRAM" {
			return extractedSequenceKey{}
		}
		pointFP := msgString(msg, fds.pointFingerprint)
		if pointFP == "" {
			return extractedSequenceKey{}
		}
		return extractedSequenceKey{
			domain: seqDomainMetric,
			seq:    seq,
			hasTag: true,
			tag:    hashString32(pointFP),
			ok:     true,
		}
	}

	if fds.logName == nil && fds.metricName == nil && fds.startTimeNano != nil && fds.traceID != nil && fds.spanID != nil {
		treeID, step, ok := parseGeneratedTreeAndStepHex(msgString(msg, fds.traceID), msgString(msg, fds.spanID))
		if !ok {
			return extractedSequenceKey{}
		}
		seq := treeID*4 + step
		stNano, hasST := msgInt64(msg, fds.startTimeNano)
		if !hasST || seq > math.MaxInt64/100_000 || stNano != generatedBaseUnixNano+int64(seq)*100_000 {
			return extractedSequenceKey{}
		}
		if fds.startTime != nil {
			stMicro, hasSTMicro := msgInt64(msg, fds.startTime)
			if !hasSTMicro || stMicro != stNano/1000 {
				return extractedSequenceKey{}
			}
		}
		wantSvc := generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))]
		if msgString(msg, fds.serviceName) != wantSvc {
			return extractedSequenceKey{}
		}
		idHash, nameOK := spanIdentityHash(msgString(msg, fds.spanName), treeID, step)
		if !nameOK {
			return extractedSequenceKey{}
		}
		return extractedSequenceKey{
			domain:       seqDomainSpan,
			identityHash: idHash,
			seq:          seq,
			ok:           true,
		}
	}

	return extractedSequenceKey{}
}

func recordUniqueAckedRow(
	chunks map[sequenceChunkKey]*sequenceBitmapChunk,
	seen map[[16]byte]struct{},
	sk extractedSequenceKey,
	computeHash func() [16]byte,
	customCap bool,
	limit int,
	currentUnique int64,
) (isNew, saturated bool) {
	if sk.ok {
		newBit, fallbackTier2, sat := recordSequenceBit(chunks, sk, customCap, currentUnique, limit)
		if !fallbackTier2 {
			return newBit, sat
		}
	}
	h := computeHash()
	if _, ok := seen[h]; !ok {
		if (customCap && currentUnique >= int64(limit)) || len(seen) >= limit {
			return false, true
		}
		seen[h] = struct{}{}
		return true, false
	}
	return false, false
}

func recordSequenceBit(
	chunks map[sequenceChunkKey]*sequenceBitmapChunk,
	sk extractedSequenceKey,
	customCap bool,
	currentUnique int64,
	limit int,
) (isNew, fallbackTier2, saturated bool) {
	key := sequenceChunkKey{domain: sk.domain, identityHash: sk.identityHash, chunk: sk.seq >> 16}
	wordIdx := (sk.seq >> 6) & 1023
	mask := uint64(1) << (sk.seq & 63)
	if chunk := chunks[key]; chunk != nil && (chunk.bits[wordIdx]&mask) != 0 {
		if sk.hasTag && (chunk.tags == nil || chunk.tags[sk.seq&65535] != sk.tag) {
			return false, true, false
		}
		return false, false, false
	}
	if customCap && currentUnique >= int64(limit) {
		return false, false, true
	}
	chunk := chunks[key]
	if chunk == nil {
		if len(chunks) >= DefaultMaxSequenceBitmapChunks {
			return false, false, true
		}
		if sk.hasTag {
			taggedCount := 0
			for _, existing := range chunks {
				if existing.tags != nil {
					taggedCount++
				}
			}
			if taggedCount >= DefaultMaxTaggedSequenceBitmapChunks {
				return false, false, true
			}
		}
		chunk = &sequenceBitmapChunk{}
		if sk.hasTag {
			chunk.tags = new([65536]uint32)
		}
		chunks[key] = chunk
	} else if sk.hasTag && chunk.tags == nil {
		// Defensive fallback if an untagged chunk unexpectedly exists under key.
		return false, true, false
	}
	chunk.bits[wordIdx] |= mask
	if sk.hasTag {
		chunk.tags[sk.seq&65535] = sk.tag
	}
	return true, false, false
}

func ingestionTimestampFieldNumbers(desc protoreflect.MessageDescriptor) [3]protowire.Number {
	if desc == nil {
		return [3]protowire.Number{}
	}
	fields := desc.Fields()
	var out [3]protowire.Number
	for i, name := range [3]protoreflect.Name{"receive_time", "receive_time_unix_nano", "ingest_time"} {
		if fd := fields.ByName(name); fd != nil {
			out[i] = fd.Number()
		}
	}
	return out
}

func isIgnoredFieldNumber(num protowire.Number, ignore [3]protowire.Number) bool {
	return num != 0 && (num == ignore[0] || num == ignore[1] || num == ignore[2])
}

type wireField struct {
	num protowire.Number
	raw []byte
}

func canonicalizeWireFields(raw []byte, ignore [3]protowire.Number) ([]byte, []byte, byte) {
	var fields []wireField
	b := raw
	var (
		malformedKind byte
		tail          []byte
	)
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			malformedKind = 1
			tail = b
			break
		}
		valLen := protowire.ConsumeFieldValue(num, typ, b[tagLen:])
		if valLen < 0 {
			malformedKind = 2
			tail = b
			break
		}
		fieldLen := tagLen + valLen
		if !isIgnoredFieldNumber(num, ignore) {
			fields = append(fields, wireField{num: num, raw: b[:fieldLen]})
		}
		b = b[fieldLen:]
	}
	slices.SortStableFunc(fields, func(a, b wireField) int {
		return cmp.Compare(a.num, b.num)
	})
	canonicalLen := 0
	for _, f := range fields {
		canonicalLen += len(f.raw)
	}
	out := make([]byte, 0, canonicalLen)
	for _, f := range fields {
		out = append(out, f.raw...)
	}
	return out, tail, malformedKind
}

func hashCanonicalRow(raw []byte, ignore [3]protowire.Number) [32]byte {
	canonical, tail, malformedKind := canonicalizeWireFields(raw, ignore)
	h := sha256.New()
	_, _ = h.Write(canonical)
	if malformedKind != 0 || len(tail) > 0 {
		_, _ = h.Write([]byte{0xff, malformedKind})
		_, _ = h.Write(tail)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func hashCanonicalMessage(msg protoreflect.Message, ignore [3]protowire.Number) ([32]byte, bool) {
	if msg == nil || !msg.IsValid() {
		return [32]byte{}, false
	}
	cloned := proto.Clone(msg.Interface()).ProtoReflect()
	fields := cloned.Descriptor().Fields()
	for _, num := range ignore {
		if num == 0 {
			continue
		}
		if fd := fields.ByNumber(num); fd != nil {
			cloned.Clear(fd)
		}
	}
	if unk := cloned.GetUnknown(); len(unk) > 0 {
		canonUnk, tail, kind := canonicalizeWireFields(unk, ignore)
		if kind == 0 && len(tail) == 0 {
			cloned.SetUnknown(canonUnk)
		}
	}
	canonical, err := proto.MarshalOptions{Deterministic: true, AllowPartial: true}.Marshal(cloned.Interface())
	if err != nil {
		return [32]byte{}, false
	}
	return sha256.Sum256(canonical), true
}

func hashCanonicalMessageWithFallback(msg protoreflect.Message, raw []byte, ignore [3]protowire.Number) [32]byte {
	if sum, ok := hashCanonicalMessage(msg, ignore); ok {
		return sum
	}
	return hashCanonicalRow(raw, ignore)
}

func hashSerializedRows(rows [][]byte, ignore [3]protowire.Number) [32]byte {
	return hashSerializedRowsWithDesc(nil, rows, ignore)
}

func hashSerializedRowsWithDesc(desc protoreflect.MessageDescriptor, rows [][]byte, ignore [3]protowire.Number) [32]byte {
	h := sha256.New()
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(rows)))
	_, _ = h.Write(lenBuf[:])
	for _, row := range rows {
		var rowSum [32]byte
		if desc != nil {
			if msg, err := unmarshalRow(desc, row); err == nil {
				rowSum = hashCanonicalMessageWithFallback(msg, row, ignore)
			} else {
				rowSum = hashCanonicalRow(row, ignore)
			}
		} else {
			rowSum = hashCanonicalRow(row, ignore)
		}
		_, _ = h.Write(rowSum[:])
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func (s *Server) popMatchingFaultLocked(
	table string,
	batchKey [32]byte,
	batchKeyComputed bool,
	serialized [][]byte,
	ignoreFields [3]protowire.Number,
) Fault {
	return s.popMatchingFaultWithDescLocked(table, nil, batchKey, batchKeyComputed, serialized, ignoreFields)
}

func (s *Server) popMatchingFaultWithDescLocked(
	table string,
	streamDesc protoreflect.MessageDescriptor,
	batchKey [32]byte,
	batchKeyComputed bool,
	serialized [][]byte,
	ignoreFields [3]protowire.Number,
) Fault {
	kept := s.faults[:0]
	matched := Fault{Mode: FaultNone}
	found := false
	for _, f := range s.faults {
		if f.Ctx != nil && f.Ctx.Err() != nil {
			continue
		}
		if !found && (f.Table == "" || f.Table == table) {
			matched = f
			found = true
			continue
		}
		kept = append(kept, f)
	}
	clear(s.faults[len(kept):])
	s.faults = kept
	if found || s.periodicFaults == nil {
		return matched
	}

	matchedKey := table
	pf := s.periodicFaults[table]
	if pf == nil && table != "" {
		matchedKey = ""
		pf = s.periodicFaults[""]
	}
	if pf == nil {
		return Fault{Mode: FaultNone}
	}
	if pf.ctx != nil && pf.ctx.Err() != nil {
		delete(s.periodicFaults, matchedKey)
		s.hasPeriodicFaults.Store(len(s.periodicFaults) > 0)
		return Fault{Mode: FaultNone}
	}
	if !batchKeyComputed {
		batchKey = hashSerializedRowsWithDesc(streamDesc, serialized, ignoreFields)
	}
	retryKey := pendingRetryKey{table: table, batchHash: batchKey}
	if delay, isRetry := pf.pendingRetries[retryKey]; isRetry {
		delete(pf.pendingRetries, retryKey)
		if delay > 0 {
			return Fault{Mode: FaultDelayedAck, Table: table, Delay: delay, Ctx: pf.ctx}
		}
		return Fault{Mode: FaultNone}
	}

	pf.logicalSeq++
	var wantDelay time.Duration
	if pf.ackDelay > 0 && (pf.logicalSeq == 1 || pf.logicalSeq%3 == 0) {
		wantDelay = pf.ackDelay
	}
	if pf.throttleEvery > 0 && pf.logicalSeq%pf.throttleEvery == 0 {
		if pf.pendingRetries == nil {
			pf.pendingRetries = make(map[pendingRetryKey]time.Duration)
		} else if len(pf.pendingRetries) > 65536 {
			clear(pf.pendingRetries)
		}
		pf.pendingRetries[retryKey] = wantDelay
		if s.periodicThrottlesInjected == nil {
			s.periodicThrottlesInjected = make(map[string]int64)
		}
		s.periodicThrottlesInjected[table]++
		return Fault{Mode: FaultResourceExhausted, Table: table, Ctx: pf.ctx}
	}
	if wantDelay > 0 {
		return Fault{Mode: FaultDelayedAck, Table: table, Delay: wantDelay, Ctx: pf.ctx}
	}
	return Fault{Mode: FaultNone}
}

func errorResponse(code codes.Code, msg string, rowErrs []*storagepb.RowError) *storagepb.AppendRowsResponse {
	return &storagepb.AppendRowsResponse{
		Response: &storagepb.AppendRowsResponse_Error{
			Error: status.New(code, msg).Proto(),
		},
		RowErrors: rowErrs,
	}
}

// parseTableFromStream extracts "{table}" from
// "projects/{p}/datasets/{d}/tables/{table}/streams/{s}".
func parseTableFromStream(streamName string) string {
	parts := strings.Split(streamName, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "tables" {
			return parts[i+1]
		}
	}
	return ""
}

func descriptorFromTableSchema(ts *storagepb.TableSchema) (protoreflect.MessageDescriptor, error) {
	desc, err := adapt.StorageSchemaToProto2Descriptor(ts, "root")
	if err != nil {
		return nil, fmt.Errorf("deriving proto2 descriptor: %w", err)
	}
	md, ok := desc.(protoreflect.MessageDescriptor)
	if !ok {
		return nil, fmt.Errorf("unexpected descriptor type %T", desc)
	}
	return md, nil
}

func descriptorFromProto(dp *descriptorpb.DescriptorProto) (protoreflect.MessageDescriptor, error) {
	name := dp.GetName()
	if name == "" {
		return nil, fmt.Errorf("descriptor name is empty")
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("stream_row.proto"),
		Syntax:      proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{dp},
	}
	fileDesc, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		return nil, err
	}
	md := fileDesc.Messages().ByName(protoreflect.Name(name))
	if md == nil {
		return nil, fmt.Errorf("message %q not found in descriptor", name)
	}
	return md, nil
}

// DecodeRowWithSchema unmarshals a serialized ProtoRows row against ts into a
// nested map[string]any keyed by column name.
func DecodeRowWithSchema(ts *storagepb.TableSchema, raw []byte) (map[string]any, error) {
	md, err := descriptorFromTableSchema(ts)
	if err != nil {
		return nil, err
	}
	return DecodeProtoRow(md, raw)
}

// DecodeProtoRow unmarshals a serialized protobuf message against md into a
// nested map[string]any keyed by field name.
func DecodeProtoRow(md protoreflect.MessageDescriptor, raw []byte) (map[string]any, error) {
	msg, err := unmarshalRow(md, raw)
	if err != nil {
		return nil, err
	}
	return messageToMap(msg), nil
}

func unmarshalRow(md protoreflect.MessageDescriptor, raw []byte) (protoreflect.Message, error) {
	msg := dynamicpb.NewMessage(md)
	if err := proto.Unmarshal(raw, msg); err != nil {
		return nil, fmt.Errorf("unmarshaling proto row: %w", err)
	}
	return msg, nil
}

func messageToMap(msg protoreflect.Message) map[string]any {
	out := make(map[string]any)
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		name := string(fd.Name())
		if fd.IsList() {
			list := v.List()
			if fd.Kind() == protoreflect.MessageKind {
				items := make([]map[string]any, list.Len())
				for i := 0; i < list.Len(); i++ {
					items[i] = messageToMap(list.Get(i).Message())
				}
				out[name] = items
			} else {
				items := make([]any, list.Len())
				for i := 0; i < list.Len(); i++ {
					items[i] = scalarToGo(fd, list.Get(i))
				}
				out[name] = items
			}
			return true
		}
		if fd.Kind() == protoreflect.MessageKind {
			out[name] = messageToMap(v.Message())
			return true
		}
		out[name] = scalarToGo(fd, v)
		return true
	})
	return out
}

func scalarToGo(fd protoreflect.FieldDescriptor, v protoreflect.Value) any {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return v.String()
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return v.Int()
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return int64(v.Uint())
	case protoreflect.DoubleKind, protoreflect.FloatKind:
		return v.Float()
	case protoreflect.BoolKind:
		return v.Bool()
	case protoreflect.BytesKind:
		return append([]byte(nil), v.Bytes()...)
	default:
		return v.Interface()
	}
}

// StartTimeHour extracts the microsecond start_time column from a decoded span
// row and returns its UTC hour truncation (`TIMESTAMP_TRUNC(start_time, HOUR)`).
func StartTimeHour(row map[string]any) (time.Time, bool) {
	us, ok := row["start_time"].(int64)
	if !ok {
		return time.Time{}, false
	}
	return time.UnixMicro(us).UTC().Truncate(time.Hour), true
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		switch tv := v.(type) {
		case map[string]any:
			out[k] = cloneMap(tv)
		case []map[string]any:
			cp := make([]map[string]any, len(tv))
			for i, elem := range tv {
				cp[i] = cloneMap(elem)
			}
			out[k] = cp
		case []byte:
			out[k] = append([]byte(nil), tv...)
		default:
			out[k] = v
		}
	}
	return out
}

func cloneJSON[T any](in *T) *T {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return &out
}

// handleREST implements the subset of the BigQuery REST v2 API used by
// cloud.google.com/go/bigquery for dataset/table/view metadata and creation.
func (s *Server) handleREST(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/bigquery/v2/")
	parts := strings.Split(strings.Trim(path, "/"), "/")

	// Routes:
	// 1. projects/{p}/datasets
	// 2. projects/{p}/datasets/{d}
	// 3. projects/{p}/datasets/{d}/tables
	// 4. projects/{p}/datasets/{d}/tables/{t}
	if len(parts) < 3 || parts[0] != "projects" || parts[2] != "datasets" {
		writeRESTError(w, http.StatusNotFound, "unsupported path: "+r.URL.Path)
		return
	}
	project := parts[1]

	if len(parts) == 3 {
		if r.Method != http.MethodPost {
			writeRESTError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var ds bigqueryapi.Dataset
		if err := decodeJSONBody(r.Body, &ds); err != nil {
			writeRESTError(w, http.StatusBadRequest, err.Error())
			return
		}
		datasetID := ""
		if ds.DatasetReference != nil {
			datasetID = ds.DatasetReference.DatasetId
		}
		if datasetID == "" {
			writeRESTError(w, http.StatusBadRequest, "missing datasetId")
			return
		}
		key := project + "." + datasetID
		s.mu.Lock()
		if _, exists := s.datasets[key]; exists {
			s.mu.Unlock()
			writeRESTError(w, http.StatusConflict, "Already Exists: Dataset "+key)
			return
		}
		ds.DatasetReference = &bigqueryapi.DatasetReference{
			ProjectId: project,
			DatasetId: datasetID,
		}
		if ds.Etag == "" {
			ds.Etag = "etag-" + key
		}
		s.datasets[key] = cloneJSON(&ds)
		payload, err := json.Marshal(&ds)
		s.mu.Unlock()
		if err != nil {
			writeRESTError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRESTBytes(w, http.StatusOK, payload)
		return
	}

	datasetID := parts[3]
	dsKey := project + "." + datasetID

	if len(parts) == 4 {
		if r.Method != http.MethodGet {
			writeRESTError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.mu.Lock()
		ds, ok := s.datasets[dsKey]
		var payload []byte
		var err error
		if ok && ds != nil {
			payload, err = json.Marshal(ds)
		}
		s.mu.Unlock()
		if !ok || ds == nil {
			writeRESTError(w, http.StatusNotFound, "Not found: Dataset "+dsKey)
			return
		}
		if err != nil {
			writeRESTError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRESTBytes(w, http.StatusOK, payload)
		return
	}

	if parts[4] != "tables" {
		writeRESTError(w, http.StatusNotFound, "unsupported resource under dataset: "+parts[4])
		return
	}

	if len(parts) == 5 {
		if r.Method != http.MethodPost {
			writeRESTError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var tbl bigqueryapi.Table
		if err := decodeJSONBody(r.Body, &tbl); err != nil {
			writeRESTError(w, http.StatusBadRequest, err.Error())
			return
		}
		tableID := ""
		if tbl.TableReference != nil {
			tableID = tbl.TableReference.TableId
		}
		if tableID == "" {
			writeRESTError(w, http.StatusBadRequest, "missing tableId")
			return
		}
		s.mu.Lock()
		if _, ok := s.datasets[dsKey]; !ok {
			s.mu.Unlock()
			writeRESTError(w, http.StatusNotFound, "Not found: Dataset "+dsKey)
			return
		}
		if s.tables[dsKey] == nil {
			s.tables[dsKey] = make(map[string]*bigqueryapi.Table)
		}
		if _, exists := s.tables[dsKey][tableID]; exists {
			s.mu.Unlock()
			writeRESTError(w, http.StatusConflict, "Already Exists: Table "+dsKey+"."+tableID)
			return
		}
		tbl.TableReference = &bigqueryapi.TableReference{
			ProjectId: project,
			DatasetId: datasetID,
			TableId:   tableID,
		}
		if tbl.View != nil {
			tbl.Type = "VIEW"
		} else if tbl.Type == "" {
			tbl.Type = "TABLE"
		}
		if tbl.Etag == "" {
			tbl.Etag = "etag-" + tableID
		}
		s.tables[dsKey][tableID] = cloneJSON(&tbl)
		if tbl.Schema != nil && len(tbl.Schema.Fields) > 0 {
			_ = s.registerTableSchemaLocked(tableID, fromRESTTableSchema(tbl.Schema))
		}
		payload, err := json.Marshal(&tbl)
		s.mu.Unlock()
		if err != nil {
			writeRESTError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeRESTBytes(w, http.StatusOK, payload)
		return
	}

	if len(parts) == 6 {
		tableID := parts[5]
		switch r.Method {
		case http.MethodGet:
			s.mu.Lock()
			byTable := s.tables[dsKey]
			var tbl *bigqueryapi.Table
			if byTable != nil {
				tbl = byTable[tableID]
			}
			var payload []byte
			var err error
			if tbl != nil {
				payload, err = json.Marshal(tbl)
			}
			s.mu.Unlock()
			if tbl == nil {
				writeRESTError(w, http.StatusNotFound, "Not found: Table "+dsKey+"."+tableID)
				return
			}
			if err != nil {
				writeRESTError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeRESTBytes(w, http.StatusOK, payload)
			return

		case http.MethodPatch, http.MethodPut:
			var patch bigqueryapi.Table
			if err := decodeJSONBody(r.Body, &patch); err != nil {
				writeRESTError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.mu.Lock()
			byTable := s.tables[dsKey]
			var existing *bigqueryapi.Table
			if byTable != nil {
				existing = byTable[tableID]
			}
			if existing == nil {
				s.mu.Unlock()
				writeRESTError(w, http.StatusNotFound, "Not found: Table "+dsKey+"."+tableID)
				return
			}
			if ifMatch := r.Header.Get("If-Match"); ifMatch != "" && ifMatch != existing.Etag {
				s.mu.Unlock()
				writeRESTError(w, http.StatusPreconditionFailed, "Precondition Failed: etag mismatch")
				return
			}
			if patch.Schema != nil {
				if existing.Schema != nil {
					if err := validateRESTSchemaUpdate(existing.Schema.Fields, patch.Schema.Fields); err != nil {
						s.mu.Unlock()
						writeRESTError(w, http.StatusBadRequest, err.Error())
						return
					}
				}
				// The schema is stored exactly as sent, policy tags included.
				// The fake keeps no tag that a request leaves out, so a test
				// sees exactly which tags an update carried.
				existing.Schema = cloneJSON(patch.Schema)
			}
			if patch.View != nil {
				existing.View = cloneJSON(patch.View)
				existing.Type = "VIEW"
			}
			if patch.TimePartitioning != nil {
				existing.TimePartitioning = cloneJSON(patch.TimePartitioning)
			}
			if patch.Clustering != nil {
				existing.Clustering = cloneJSON(patch.Clustering)
			}
			s.etagSeq++
			existing.Etag = fmt.Sprintf("etag-%s-%d", tableID, s.etagSeq)
			if existing.Schema != nil && len(existing.Schema.Fields) > 0 {
				_ = s.registerTableSchemaLocked(tableID, fromRESTTableSchema(existing.Schema))
			}
			payload, err := json.Marshal(existing)
			s.mu.Unlock()
			if err != nil {
				writeRESTError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeRESTBytes(w, http.StatusOK, payload)
			return

		default:
			writeRESTError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}

	writeRESTError(w, http.StatusNotFound, "unsupported endpoint: "+r.URL.Path)
}

func validateRESTSchemaUpdate(existing, next []*bigqueryapi.TableFieldSchema) error {
	nextByName := make(map[string]*bigqueryapi.TableFieldSchema, len(next))
	for _, f := range next {
		if f != nil {
			nextByName[f.Name] = f
		}
	}
	existingNames := make(map[string]bool, len(existing))
	for _, oldF := range existing {
		if oldF == nil {
			continue
		}
		existingNames[oldF.Name] = true
		newF, ok := nextByName[oldF.Name]
		if !ok {
			return fmt.Errorf("cannot remove existing column %q", oldF.Name)
		}
		if err := validateRESTSchemaUpdate(oldF.Fields, newF.Fields); err != nil {
			return fmt.Errorf("column %q: %w", oldF.Name, err)
		}
	}
	for _, newF := range next {
		if newF == nil || existingNames[newF.Name] {
			continue
		}
		if err := rejectNewRequiredFields(newF); err != nil {
			return err
		}
	}
	return nil
}

func rejectNewRequiredFields(f *bigqueryapi.TableFieldSchema) error {
	if strings.EqualFold(f.Mode, "REQUIRED") {
		return fmt.Errorf("cannot add REQUIRED column %q to an existing table", f.Name)
	}
	for _, child := range f.Fields {
		if child == nil {
			continue
		}
		if err := rejectNewRequiredFields(child); err != nil {
			return fmt.Errorf("column %q: %w", f.Name, err)
		}
	}
	return nil
}

func decodeJSONBody(r io.Reader, dst any) error {
	defer func() { _, _ = io.Copy(io.Discard, r) }()
	return json.NewDecoder(r).Decode(dst)
}

func writeRESTBytes(w http.ResponseWriter, code int, payload []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(payload)
	_, _ = w.Write([]byte("\n"))
}

func writeRESTJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeRESTError(w http.ResponseWriter, code int, msg string) {
	type errBody struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	var body errBody
	body.Error.Code = code
	body.Error.Message = msg
	writeRESTJSON(w, code, &body)
}

var restToStorageType = map[string]storagepb.TableFieldSchema_Type{
	"STRING":     storagepb.TableFieldSchema_STRING,
	"INTEGER":    storagepb.TableFieldSchema_INT64,
	"INT64":      storagepb.TableFieldSchema_INT64,
	"FLOAT":      storagepb.TableFieldSchema_DOUBLE,
	"FLOAT64":    storagepb.TableFieldSchema_DOUBLE,
	"NUMERIC":    storagepb.TableFieldSchema_NUMERIC,
	"BIGNUMERIC": storagepb.TableFieldSchema_BIGNUMERIC,
	"BOOLEAN":    storagepb.TableFieldSchema_BOOL,
	"BOOL":       storagepb.TableFieldSchema_BOOL,
	"TIMESTAMP":  storagepb.TableFieldSchema_TIMESTAMP,
	"DATE":       storagepb.TableFieldSchema_DATE,
	"TIME":       storagepb.TableFieldSchema_TIME,
	"DATETIME":   storagepb.TableFieldSchema_DATETIME,
	"GEOGRAPHY":  storagepb.TableFieldSchema_GEOGRAPHY,
	"BYTES":      storagepb.TableFieldSchema_BYTES,
	"INTERVAL":   storagepb.TableFieldSchema_INTERVAL,
	"JSON":       storagepb.TableFieldSchema_JSON,
	"RECORD":     storagepb.TableFieldSchema_STRUCT,
	"STRUCT":     storagepb.TableFieldSchema_STRUCT,
	"RANGE":      storagepb.TableFieldSchema_RANGE,
}

var storageToRESTType = func() map[storagepb.TableFieldSchema_Type]string {
	m := make(map[storagepb.TableFieldSchema_Type]string, len(restToStorageType))
	for k, v := range maps.All(restToStorageType) {
		if _, exists := m[v]; !exists {
			m[v] = k
		}
	}
	m[storagepb.TableFieldSchema_INT64] = "INTEGER"
	m[storagepb.TableFieldSchema_DOUBLE] = "FLOAT"
	m[storagepb.TableFieldSchema_BOOL] = "BOOLEAN"
	m[storagepb.TableFieldSchema_STRUCT] = "RECORD"
	return m
}()

func fromRESTTableSchema(ts *bigqueryapi.TableSchema) *storagepb.TableSchema {
	if ts == nil {
		return nil
	}
	return &storagepb.TableSchema{
		Fields: fromRESTFields(ts.Fields),
	}
}

func fromRESTFields(fields []*bigqueryapi.TableFieldSchema) []*storagepb.TableFieldSchema {
	out := make([]*storagepb.TableFieldSchema, 0, len(fields))
	for _, f := range fields {
		if f == nil {
			continue
		}
		typ, ok := restToStorageType[strings.ToUpper(f.Type)]
		if !ok {
			typ = storagepb.TableFieldSchema_STRING
		}
		mode := storagepb.TableFieldSchema_NULLABLE
		switch strings.ToUpper(f.Mode) {
		case "REQUIRED":
			mode = storagepb.TableFieldSchema_REQUIRED
		case "REPEATED":
			mode = storagepb.TableFieldSchema_REPEATED
		}
		out = append(out, &storagepb.TableFieldSchema{
			Name:        f.Name,
			Description: f.Description,
			Type:        typ,
			Mode:        mode,
			Fields:      fromRESTFields(f.Fields),
		})
	}
	return out
}

func toRESTTableSchema(ts *storagepb.TableSchema) *bigqueryapi.TableSchema {
	if ts == nil {
		return nil
	}
	return &bigqueryapi.TableSchema{
		Fields: toRESTFields(ts.GetFields()),
	}
}

func toRESTFields(fields []*storagepb.TableFieldSchema) []*bigqueryapi.TableFieldSchema {
	out := make([]*bigqueryapi.TableFieldSchema, 0, len(fields))
	for _, f := range fields {
		if f == nil {
			continue
		}
		mode := "NULLABLE"
		switch f.GetMode() {
		case storagepb.TableFieldSchema_REQUIRED:
			mode = "REQUIRED"
		case storagepb.TableFieldSchema_REPEATED:
			mode = "REPEATED"
		}
		out = append(out, &bigqueryapi.TableFieldSchema{
			Name:        f.GetName(),
			Description: f.GetDescription(),
			Type:        storageToRESTType[f.GetType()],
			Mode:        mode,
			Fields:      toRESTFields(f.GetFields()),
		})
	}
	return out
}
