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
	"math/bits"
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

	mu                                    sync.Mutex
	schemas                               map[string]*storagepb.TableSchema
	descriptors                           map[string]protoreflect.MessageDescriptor
	rows                                  map[string][]map[string]any
	faults                                []Fault
	periodicFaults                        map[string]*periodicFaultState
	discardRows                           bool
	trackUniqueAcked                      bool
	maxUniqueAckedRows                    int
	customMaxUniqueAcked                  bool
	uniqueAckedSaturated                  bool
	uniqueAckedSaturatedLimit             int
	uniqueAckedSaturatedUnit              string
	uniqueAckedSaturatedByTable           map[string]bool
	uniqueAckedSaturatedLimitByTable      map[string]int
	uniqueAckedSaturatedUnitByTable       map[string]string
	seenAckedRows                         map[[16]byte]struct{}
	seenSeqChunks                         map[sequenceChunkKey]*sequenceBitmapChunk
	seenSeqMultiTags                      map[seqSlotKey]map[string]struct{}
	seenSeqMultiTagExtraCount             int
	seenSeqTagBytes                       int64
	uniqueAckedRows                       int64
	uniqueAckedBytes                      int64
	nullIDRepeatRows                      int64
	nullIDRepeatBytes                     int64
	ackedRowsByTable                      map[string]int64
	ackedBytesByTable                     map[string]int64
	seenAckedRowsByTable                  map[string]map[[16]byte]struct{}
	seenSeqChunksByTable                  map[string]map[sequenceChunkKey]*sequenceBitmapChunk
	seenSeqMultiTagsByTable               map[string]map[seqSlotKey]map[string]struct{}
	seenSeqMultiTagExtraCountByTable      map[string]int
	seenSeqTagBytesByTable                map[string]int64
	seenNullIDLogCounts                   map[[16]byte]int64
	seenNullIDLogCountsByTable            map[string]map[[16]byte]int64
	uniqueAckedRowsByTable                map[string]int64
	uniqueAckedBytesByTable               map[string]int64
	nullIDRepeatRowsByTable               map[string]int64
	nullIDRepeatBytesByTable              map[string]int64
	phaseSeqChunksByTable                 map[string]map[sequenceChunkKey]*sequenceBitmapChunk
	phaseSeqMultiTagsByTable              map[string]map[seqSlotKey]map[string]struct{}
	phaseSeqMultiTagExtraCountByTable     map[string]int
	phaseSeqTagBytesByTable               map[string]int64
	phaseTier2ByTable                     map[string]map[[16]byte]struct{}
	phaseNullIDLogCountsByTable           map[string]map[[16]byte]int64
	phaseSaturatedByTable                 map[string]bool
	phaseSaturatedLimitByTable            map[string]int
	phaseSaturatedUnitByTable             map[string]string
	maxExactTagBytes                      int64
	maxPhaseNullIDLogKeys                 int
	onUniqueAckedSaturated                func(table string)
	beforeCommitHook                      func(table string, serialized [][]byte) [][]byte
	periodicThrottlesInjected             map[string]int64
	throttlesInjectedByTable              map[string]int64
	delayedAcksInjectedByTable            map[string]int64
	triggeredRetryableFaultsByTable       map[string]int64
	triggeredRetryableFaultRowsByTable    map[string]int64
	triggeredUncertainCommitFaultsByTable map[string]int64
	triggeredUncertainCommitRowsByTable   map[string]int64
	phaseUncertainCreditsByTable          map[string]map[phaseRowIdentityKey]int64
	phaseReplaysByTable                   map[string]map[phaseRowIdentityKey]int64

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
// that carry exact per-sequence identity strings (up to 256 chunks =
// 16,777,216 sequence IDs, ~1 MiB per dense [65536]string header array on
// 64-bit, paired with DefaultMaxExactTagBytes = 256 MiB for exact tag string
// storage) for generated logs with synthesized id1: insert IDs and generated
// metrics.
const DefaultMaxTaggedSequenceBitmapChunks = 256

// DefaultMaxExactTagBytes bounds exact full identity-tag string memory retained
// per tracker (256 MiB across single-slot and multi-tag entries for synthesized
// insert_id and point_fingerprint strings).
const DefaultMaxExactTagBytes = 256 << 20

const (
	// SaturationUnitRows is the saturation unit reported when unique-acked or
	// phase reconciliation reaches a row, chunk-slot, or key-map entry limit.
	SaturationUnitRows = "unique rows"
	// SaturationUnitTagBytes is the saturation unit reported when exact identity
	// tag storage reaches DefaultMaxExactTagBytes (or a configured tag-byte cap).
	SaturationUnitTagBytes = "tag bytes"
)

const exactTagPerEntryOverhead = 16

func exactTagEntryBytes(tag string) int64 {
	return int64(len(tag)) + exactTagPerEntryOverhead
}

func exactTagEntryBytesForSignal(signal string) int64 {
	switch signal {
	case "logs":
		return int64(len(schema.InsertIDPrefixV1)+22) + exactTagPerEntryOverhead
	case "metrics":
		return int64(len(schema.FingerprintPrefix)+64) + exactTagPerEntryOverhead
	default:
		// Conservative fallback matching metric point_fingerprint tag size.
		return int64(len(schema.FingerprintPrefix)+64) + exactTagPerEntryOverhead
	}
}

func preferSaturationCap(curLimit int, curUnit string, nextLimit int, nextUnit string) (int, string) {
	if nextLimit <= 0 {
		return curLimit, curUnit
	}
	if nextUnit == "" {
		nextUnit = SaturationUnitRows
	}
	if curLimit <= 0 || curUnit == "" {
		return nextLimit, nextUnit
	}
	if curUnit == nextUnit {
		if nextLimit < curLimit {
			return nextLimit, curUnit
		}
		return curLimit, curUnit
	}
	// Preserve matching (limit, unit) pairs: prefer row/map limits when both trip.
	if curUnit == SaturationUnitRows {
		return curLimit, curUnit
	}
	if nextUnit == SaturationUnitRows {
		return nextLimit, nextUnit
	}
	return curLimit, curUnit
}

func clampLimitToInt(limit int64) int {
	if limit <= 0 {
		return 0
	}
	if limit > int64(math.MaxInt) {
		return math.MaxInt
	}
	return int(limit)
}

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
		servedCh:                              make(chan struct{}),
		schemas:                               make(map[string]*storagepb.TableSchema),
		descriptors:                           make(map[string]protoreflect.MessageDescriptor),
		rows:                                  make(map[string][]map[string]any),
		periodicFaults:                        make(map[string]*periodicFaultState),
		maxUniqueAckedRows:                    DefaultMaxUniqueAckedRows,
		uniqueAckedSaturatedByTable:           make(map[string]bool),
		uniqueAckedSaturatedLimitByTable:      make(map[string]int),
		uniqueAckedSaturatedUnitByTable:       make(map[string]string),
		ackedRowsByTable:                      make(map[string]int64),
		ackedBytesByTable:                     make(map[string]int64),
		seenAckedRowsByTable:                  make(map[string]map[[16]byte]struct{}),
		seenSeqChunksByTable:                  make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk),
		seenSeqMultiTagsByTable:               make(map[string]map[seqSlotKey]map[string]struct{}),
		seenSeqMultiTagExtraCountByTable:      make(map[string]int),
		seenSeqTagBytesByTable:                make(map[string]int64),
		seenNullIDLogCountsByTable:            make(map[string]map[[16]byte]int64),
		uniqueAckedRowsByTable:                make(map[string]int64),
		uniqueAckedBytesByTable:               make(map[string]int64),
		nullIDRepeatRowsByTable:               make(map[string]int64),
		nullIDRepeatBytesByTable:              make(map[string]int64),
		periodicThrottlesInjected:             make(map[string]int64),
		throttlesInjectedByTable:              make(map[string]int64),
		delayedAcksInjectedByTable:            make(map[string]int64),
		triggeredRetryableFaultsByTable:       make(map[string]int64),
		triggeredRetryableFaultRowsByTable:    make(map[string]int64),
		triggeredUncertainCommitFaultsByTable: make(map[string]int64),
		triggeredUncertainCommitRowsByTable:   make(map[string]int64),
		phaseUncertainCreditsByTable:          make(map[string]map[phaseRowIdentityKey]int64),
		phaseReplaysByTable:                   make(map[string]map[phaseRowIdentityKey]int64),
		datasets:                              make(map[string]*bigqueryapi.Dataset),
		tables:                                make(map[string]map[string]*bigqueryapi.Table),
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
	switch {
	case table == "":
		clear(s.periodicThrottlesInjected)
	case isQualifiedTableKey(table):
		delete(s.periodicThrottlesInjected, table)
	default:
		for k := range s.periodicThrottlesInjected {
			if tableKeyMatches(table, k) {
				delete(s.periodicThrottlesInjected, k)
			}
		}
	}
	if throttleEvery <= 0 && ackDelay <= 0 {
		if table != "" && !isQualifiedTableKey(table) {
			for k := range s.periodicFaults {
				if k != "" && tableKeyMatches(table, k) {
					delete(s.periodicFaults, k)
				}
			}
		} else {
			delete(s.periodicFaults, table)
		}
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

func sumMatchingInt64(m map[string]int64, query string) int64 {
	if len(m) == 0 {
		return 0
	}
	if isQualifiedTableKey(query) {
		return m[query]
	}
	var total int64
	for k, v := range m {
		if tableKeyMatches(query, k) {
			total += v
		}
	}
	return total
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
	if table == "" {
		return int64(s.ackedRows)
	}
	return sumMatchingInt64(s.ackedRowsByTable, table)
}

// AckedBytesForTable returns the total serialized ProtoRows byte length
// acknowledged by AppendRows for table.
func (s *Server) AckedBytesForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		return s.ackedBytes
	}
	return sumMatchingInt64(s.ackedBytesByTable, table)
}

// UniqueAckedRowsForTable returns the number of distinct canonical ProtoRows
// acknowledged for table while SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedRowsForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		return s.uniqueAckedRows
	}
	return sumMatchingInt64(s.uniqueAckedRowsByTable, table)
}

// UniqueAckedBytesForTable returns the total serialized byte length of
// distinct canonical ProtoRows acknowledged for table while
// SetTrackUniqueAcked(true) is active.
func (s *Server) UniqueAckedBytesForTable(table string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if table == "" {
		return s.uniqueAckedBytes
	}
	return sumMatchingInt64(s.uniqueAckedBytesByTable, table)
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
	if isQualifiedTableKey(table) {
		return len(s.seenSeqChunksByTable[table]), len(s.seenAckedRowsByTable[table])
	}
	for k, ch := range s.seenSeqChunksByTable {
		if tableKeyMatches(table, k) {
			tier1Chunks += len(ch)
		}
	}
	for k, seen := range s.seenAckedRowsByTable {
		if tableKeyMatches(table, k) {
			tier2Hashes += len(seen)
		}
	}
	return tier1Chunks, tier2Hashes
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
	return sumMatchingInt64(s.periodicThrottlesInjected, table)
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
	return sumMatchingInt64(s.throttlesInjectedByTable, table)
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
	return sumMatchingInt64(s.delayedAcksInjectedByTable, table)
}

// PendingFaultsForTable returns the number of queued faults on the server that
// match table (empty table matches all tables) and may trigger delays or retries.
func (s *Server) PendingFaultsForTable(table string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, f := range s.faults {
		if f.Ctx != nil && f.Ctx.Err() != nil {
			continue
		}
		if !faultMatchesTable(f.Table, table) {
			continue
		}
		switch f.Mode {
		case FaultResourceExhausted, FaultDelayedAck, FaultCommitThenStreamClosed:
			count++
		}
	}
	return count
}

// TableStatsSnapshot captures per-table commit, byte, unique-delivery, and
// throttle counters atomically under a single server lock. When
// UniqueSaturated is true, UniqueSaturatedLimit holds the breached cap and
// UniqueSaturatedUnit names its unit (SaturationUnitRows or
// SaturationUnitTagBytes); both are zero/empty when !UniqueSaturated.
type TableStatsSnapshot struct {
	AckedRows        int64
	AckedBytes       int64
	UniqueAckedRows  int64
	UniqueAckedBytes int64
	// NullIDRepeatRows and NullIDRepeatBytes count committed NULL-insert_id
	// log occurrences whose logical dedup hash was already seen on the table
	// (or globally on "" snapshots). Subtracting them from UniqueAckedRows and
	// UniqueAckedBytes yields strictly first-seen totals while preserving
	// occurrence-preserving UniqueAckedRows accounting.
	NullIDRepeatRows               int64
	NullIDRepeatBytes              int64
	UniqueSaturated                bool
	UniqueSaturatedLimit           int
	UniqueSaturatedUnit            string
	ThrottlesInjected              int64
	TriggeredRetryableFaults       int64
	TriggeredRetryableFaultRows    int64
	TriggeredDelayedAckFaults      int64
	TriggeredUncertainCommitFaults int64
	TriggeredUncertainCommitRows   int64
}

// ReconciliationResult compares unique logical identities committed to a table
// during the active phase against the set of logical identities submitted. When
// Saturated is true, SaturatedLimit holds the breached cap and SaturatedUnit
// names its unit (SaturationUnitRows or SaturationUnitTagBytes); both are
// zero/empty when !Saturated.
type ReconciliationResult struct {
	SubmittedRows  int64
	MatchedRows    int64
	MissingRows    int64
	UnexpectedRows int64
	// ReplayedNullIDRows counts extra committed occurrences (commCnt - subCnt
	// for submitted hashes) of NULL-insert_id logs during the phase, keeping
	// transport retries of submitted NULL-insert_id logs separate from
	// unsubmitted UnexpectedRows.
	ReplayedNullIDRows int64
	// UnexplainedReplayRows counts phase row replays (Tier-1/Tier-2 already-seen
	// commits and excess NULL-insert_id occurrences beyond submitted count) that
	// lack a matching per-row ambiguous-commit credit from an observed
	// FaultCommitThenStreamClosed or failed post-commit response send.
	UnexplainedReplayRows int64
	Saturated             bool
	SaturatedLimit        int
	SaturatedUnit         string
}

// SubmittedKeySet tracks logical record identities submitted during a phase
// using the same Tier-1 sequence bitmaps, Tier-2 logical identity hashes, and
// NULL-insert_id occurrence counts as Server. It is safe for concurrent use or
// per-worker Merge.
type SubmittedKeySet struct {
	mu                 sync.Mutex
	chunks             map[sequenceChunkKey]*sequenceBitmapChunk
	multiTags          map[seqSlotKey]map[string]struct{}
	multiTagExtraCount int
	tagBytes           int64
	maxExactTagBytes   int64
	maxNullIDLogKeys   int
	tier2              map[[16]byte]struct{}
	nullIDLogCounts    map[[16]byte]int64
	count              int64
	saturated          bool
	saturatedLimit     int
	saturatedUnit      string
}

// NewSubmittedKeySet returns an empty phase key tracker matching Server's
// destination dedup-view logical identity rules.
func NewSubmittedKeySet() *SubmittedKeySet {
	return &SubmittedKeySet{
		chunks:          make(map[sequenceChunkKey]*sequenceBitmapChunk),
		tier2:           make(map[[16]byte]struct{}),
		nullIDLogCounts: make(map[[16]byte]int64),
	}
}

func (k *SubmittedKeySet) effectiveMaxExactTagBytes() int64 {
	if k.maxExactTagBytes > 0 {
		return k.maxExactTagBytes
	}
	return DefaultMaxExactTagBytes
}

func (k *SubmittedKeySet) effectiveMaxNullIDLogKeys() int {
	if k.maxNullIDLogKeys > 0 && k.maxNullIDLogKeys < DefaultMaxUniqueAckedRows {
		return k.maxNullIDLogKeys
	}
	return DefaultMaxUniqueAckedRows
}

func (k *SubmittedKeySet) markSaturatedLocked(limit int, unit string) {
	k.saturated = true
	k.saturatedLimit, k.saturatedUnit = preferSaturationCap(k.saturatedLimit, k.saturatedUnit, limit, unit)
}

func countTaggedChunks(chunks map[sequenceChunkKey]*sequenceBitmapChunk) int {
	tagged := 0
	for _, ch := range chunks {
		if ch != nil && ch.isTagged() {
			tagged++
		}
	}
	return tagged
}

func (k *SubmittedKeySet) recordTier1KeyLocked(sk extractedSequenceKey, fallbackSum func() [32]byte) {
	if k.chunks == nil {
		k.chunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
	}
	isNew, fallbackTier2, sat, satLimit, satUnit := recordTier1SlotWithMultiTags(
		k.chunks,
		&k.multiTags,
		&k.multiTagExtraCount,
		sk,
		false,
		k.count,
		DefaultMaxUniqueAckedRows,
		&k.tagBytes,
		k.effectiveMaxExactTagBytes(),
	)
	if sat {
		k.markSaturatedLocked(satLimit, satUnit)
		return
	}
	if fallbackTier2 {
		if fallbackSum != nil {
			k.recordTier2DigestLocked(fallbackSum())
		} else {
			k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
		}
		return
	}
	if isNew {
		k.count++
	}
}

func (k *SubmittedKeySet) recordNullIDLogLocked(sum [32]byte) {
	if k.nullIDLogCounts == nil {
		k.nullIDLogCounts = make(map[[16]byte]int64)
	}
	var h [16]byte
	copy(h[:], sum[:16])
	maxNullKeys := k.effectiveMaxNullIDLogKeys()
	if _, exists := k.nullIDLogCounts[h]; !exists && len(k.nullIDLogCounts) >= maxNullKeys {
		k.markSaturatedLocked(maxNullKeys, SaturationUnitRows)
		return
	}
	k.nullIDLogCounts[h]++
	k.count++
}

func (k *SubmittedKeySet) recordTier2DigestLocked(sum [32]byte) {
	if k.tier2 == nil {
		k.tier2 = make(map[[16]byte]struct{})
	}
	var h [16]byte
	copy(h[:], sum[:16])
	if _, seen := k.tier2[h]; seen {
		return
	}
	if len(k.tier2) >= DefaultMaxUniqueAckedRows {
		k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
		return
	}
	k.tier2[h] = struct{}{}
	k.count++
}

// RecordSpan records the logical identity of an exported span matching
// SpansDedupViewQuery (start_time, start_time_unix_nano, service_name,
// trace_id, span_id, name).
func (k *SubmittedKeySet) RecordSpan(startTimeNano int64, serviceName, traceIDHex, spanIDHex, spanName string) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	spanFallback := func() [32]byte {
		return hashSpanDedupKey(
			startTimeNano/1000, true,
			startTimeNano, true,
			serviceName, serviceName != "",
			traceIDHex, traceIDHex != "",
			spanIDHex, spanIDHex != "",
			spanName, true,
		)
	}
	if treeID, step, ok := parseGeneratedTreeAndStepHex(traceIDHex, spanIDHex); ok {
		seq := treeID*4 + step
		if seq <= math.MaxInt64/100_000 &&
			startTimeNano == generatedBaseUnixNano+int64(seq)*100_000 &&
			serviceName == generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))] {
			if idHash, nameOK := spanIdentityHash(spanName, treeID, step); nameOK {
				k.recordTier1KeyLocked(
					extractedSequenceKey{
						domain:       seqDomainSpan,
						identityHash: idHash,
						seq:          seq,
						ok:           true,
					},
					spanFallback,
				)
				return
			}
		}
	}
	k.recordTier2DigestLocked(spanFallback())
}

// RecordLog records the logical identity of an exported log matching
// LogsDedupViewQuery (timestamp, time_unix_nano, service_name, trace_id,
// span_id, severity_number, log_name, insert_id). When logName is empty, it
// applies transform.LogRows's fallback (serviceName, else "default").
func (k *SubmittedKeySet) RecordLog(
	timeNano int64,
	serviceName, logName, traceIDHex, spanIDHex string,
	severityNumber int64,
	insertID string,
	expectSynthesizedInsertID bool,
) {
	if k == nil {
		return
	}
	if logName == "" {
		if serviceName != "" {
			logName = serviceName
		} else {
			logName = "default"
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()

	if !expectSynthesizedInsertID && insertID == "" {
		sum := hashLogDedupKey(
			timeNano/1000, true,
			timeNano, true,
			serviceName, serviceName != "",
			traceIDHex, traceIDHex != "",
			spanIDHex, spanIDHex != "",
			severityNumber, true,
			logName, true,
			"", false,
		)
		k.recordNullIDLogLocked(sum)
		return
	}

	logFallback := func() [32]byte {
		return hashLogDedupKey(
			timeNano/1000, true,
			timeNano, true,
			serviceName, serviceName != "",
			traceIDHex, traceIDHex != "",
			spanIDHex, spanIDHex != "",
			severityNumber, true,
			logName, true,
			insertID, insertID != "",
		)
	}

	edgeSeq, isEdge := parseEdgeInsertID(insertID)
	isSynthV1 := !isEdge && isSynthesizedInsertIDV1(insertID)
	isSynthEligible := !isEdge && ((expectSynthesizedInsertID && insertID == "") || isSynthV1)
	if isEdge || isSynthEligible {
		if timeNano >= generatedBaseUnixNano && (timeNano-generatedBaseUnixNano)%100_000 == 0 {
			seq := uint64((timeNano - generatedBaseUnixNano) / 100_000)
			if !isEdge || (edgeSeq <= math.MaxInt64/100_000 && edgeSeq == seq) {
				var tag string
				if isSynthV1 {
					tag = insertID
				}
				if traceIDHex != "" || spanIDHex != "" {
					if treeID, step, ok := parseGeneratedTreeAndStepHex(traceIDHex, spanIDHex); ok && treeID*4+step == seq {
						if idHash, genOK := genAILogStreamIdentityHashValues(serviceName, logName, true, severityNumber, treeID); genOK {
							domain := seqDomainLogTraceStep
							if isEdge {
								domain = seqDomainLogEdgeTraceStep
							}
							k.recordTier1KeyLocked(
								extractedSequenceKey{
									domain:       domain,
									identityHash: idHash,
									seq:          seq,
									hasTag:       isSynthV1,
									tag:          tag,
									ok:           true,
								},
								logFallback,
							)
							return
						}
					}
				} else {
					if isEdge {
						if hasValidGeneratedAccessLogIdentityValues(serviceName, logName, true, severityNumber) {
							k.recordTier1KeyLocked(
								extractedSequenceKey{
									domain:       seqDomainLogEdgeInsertID,
									identityHash: accessLogStreamIdentityHashValues(serviceName, logName, true, severityNumber, seq),
									seq:          seq,
									ok:           true,
								},
								logFallback,
							)
							return
						}
					} else {
						k.recordTier1KeyLocked(
							extractedSequenceKey{
								domain:       seqDomainLogAccess,
								identityHash: accessLogStreamIdentityHashValues(serviceName, logName, true, severityNumber, seq),
								seq:          seq,
								hasTag:       isSynthV1,
								tag:          tag,
								ok:           true,
							},
							logFallback,
						)
						return
					}
				}
			}
		}
	}

	if expectSynthesizedInsertID && insertID == "" {
		k.markSaturatedLocked(DefaultMaxTaggedSequenceBitmapChunks*65536, SaturationUnitRows)
	}
	k.recordTier2DigestLocked(logFallback())
}

// RecordMetric records the logical identity of an exported metric data point
// without a point_fingerprint (untagged Tier-1 slot on generated metrics).
// Prefer RecordMetricWithFingerprint so per-point fingerprint mutations are caught.
func (k *SubmittedKeySet) RecordMetric(timeNano int64, serviceName, metricName, metricType string) {
	k.RecordMetricWithFingerprint(timeNano, serviceName, metricName, metricType, "")
}

// RecordMetricWithFingerprint records the logical identity of an exported
// metric data point matching MetricsDedupViewQuery (timestamp, time_unix_nano,
// service_name, metric_name, metric_type, point_fingerprint).
func (k *SubmittedKeySet) RecordMetricWithFingerprint(timeNano int64, serviceName, metricName, metricType, pointFingerprint string) {
	if k == nil {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	metricFallback := func() [32]byte {
		return hashMetricDedupKey(
			timeNano/1000, true,
			timeNano, true,
			serviceName, serviceName != "",
			metricName, metricName != "",
			metricType, metricType != "",
			pointFingerprint, pointFingerprint != "",
		)
	}
	if timeNano >= generatedBaseUnixNano && (timeNano-generatedBaseUnixNano)%100_000 == 0 {
		seq := uint64((timeNano - generatedBaseUnixNano) / 100_000)
		treeID, step := seq/4, seq%4
		if serviceName == generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))] &&
			metricName == generatedMetricName(step) &&
			metricType == "HISTOGRAM" {
			sk := extractedSequenceKey{
				domain: seqDomainMetric,
				seq:    seq,
				ok:     true,
			}
			if pointFingerprint != "" {
				sk.hasTag = true
				sk.tag = pointFingerprint
			}
			k.recordTier1KeyLocked(sk, metricFallback)
			return
		}
	}
	k.recordTier2DigestLocked(metricFallback())
}

// Merge merges all logical identities and saturation state from other into k.
func (k *SubmittedKeySet) Merge(other *SubmittedKeySet) {
	if k == nil || other == nil || k == other {
		return
	}
	type chunkCopy struct {
		key   sequenceChunkKey
		chunk *sequenceBitmapChunk
	}
	other.mu.Lock()
	otherSat := other.saturated
	otherSatLimit := other.saturatedLimit
	otherSatUnit := other.saturatedUnit
	chunksCopy := make([]chunkCopy, 0, len(other.chunks))
	for ck, ch := range other.chunks {
		if ch != nil && ch.hasAny() {
			chunksCopy = append(chunksCopy, chunkCopy{key: ck, chunk: ch.cloneChunk()})
		}
	}
	var otherMultiByChunk map[sequenceChunkKey]map[uint16]map[string]struct{}
	if len(other.multiTags) > 0 {
		otherMultiByChunk = make(map[sequenceChunkKey]map[uint16]map[string]struct{})
		for sk, m := range other.multiTags {
			if len(m) == 0 {
				continue
			}
			bySlot := otherMultiByChunk[sk.ck]
			if bySlot == nil {
				bySlot = make(map[uint16]map[string]struct{})
				otherMultiByChunk[sk.ck] = bySlot
			}
			cloned := make(map[string]struct{}, len(m))
			maps.Copy(cloned, m)
			bySlot[sk.slot] = cloned
		}
	}
	tier2Copy := make([][16]byte, 0, len(other.tier2))
	for h := range other.tier2 {
		tier2Copy = append(tier2Copy, h)
	}
	nullCountsCopy := make(map[[16]byte]int64, len(other.nullIDLogCounts))
	maps.Copy(nullCountsCopy, other.nullIDLogCounts)
	other.mu.Unlock()

	k.mu.Lock()
	defer k.mu.Unlock()
	if k.chunks == nil {
		k.chunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
	}
	if k.tier2 == nil {
		k.tier2 = make(map[[16]byte]struct{})
	}
	if k.nullIDLogCounts == nil {
		k.nullIDLogCounts = make(map[[16]byte]int64)
	}
	if otherSat {
		k.markSaturatedLocked(otherSatLimit, otherSatUnit)
	}

	maxTagBytes := k.effectiveMaxExactTagBytes()
	maxNullKeys := k.effectiveMaxNullIDLogKeys()
	taggedChunks := countTaggedChunks(k.chunks)
	tagBytesOK := func(add int64) bool {
		if add <= 0 || maxTagBytes <= 0 {
			return true
		}
		if k.tagBytes+add > maxTagBytes {
			k.markSaturatedLocked(clampLimitToInt(maxTagBytes), SaturationUnitTagBytes)
			return false
		}
		return true
	}

	for i := range chunksCopy {
		c := chunksCopy[i].chunk
		ck := chunksCopy[i].key
		inMultiBySlot := otherMultiByChunk[ck]
		dst := k.chunks[ck]
		if dst == nil {
			if len(k.chunks) >= DefaultMaxSequenceBitmapChunks {
				k.markSaturatedLocked(DefaultMaxSequenceBitmapChunks*65536, SaturationUnitRows)
				continue
			}
			if c.isTagged() && taggedChunks >= DefaultMaxTaggedSequenceBitmapChunks {
				k.markSaturatedLocked(DefaultMaxTaggedSequenceBitmapChunks*65536, SaturationUnitRows)
				continue
			}
			chunkBytes := c.exactTagBytes()
			if !tagBytesOK(chunkBytes) {
				continue
			}
			k.chunks[ck] = c
			if c.isTagged() {
				taggedChunks++
			}
			k.tagBytes += chunkBytes
			k.count += c.countBits()
			if len(inMultiBySlot) > 0 {
				if k.multiTags == nil {
					k.multiTags = make(map[seqSlotKey]map[string]struct{})
				}
				for slot, m := range inMultiBySlot {
					extra := len(m) - 1
					if extra <= 0 {
						continue
					}
					if len(k.multiTags)+k.multiTagExtraCount+len(m) > DefaultMaxUniqueAckedRows {
						k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
						break
					}
					cSlotTag, _ := c.hasSlot(slot)
					var extraBytes int64
					for t := range m {
						if t != "" && t != cSlotTag {
							extraBytes += exactTagEntryBytes(t)
						}
					}
					if !tagBytesOK(extraBytes) {
						break
					}
					k.multiTags[seqSlotKey{ck: ck, slot: slot}] = m
					k.multiTagExtraCount += extra
					k.tagBytes += extraBytes
					k.count += int64(extra)
				}
			}
			continue
		}
		if c.isTagged() && !dst.isTagged() {
			k.markSaturatedLocked(DefaultMaxTaggedSequenceBitmapChunks*65536, SaturationUnitRows)
			continue
		}
		c.forEachSlot(func(slot uint16, cTag string) {
			inMulti := inMultiBySlot[slot]
			dstTag, dstHas := dst.hasSlot(slot)
			if !dstHas {
				var cTagBytes int64
				if c.isTagged() && cTag != "" {
					cTagBytes = exactTagEntryBytes(cTag)
					if !tagBytesOK(cTagBytes) {
						return
					}
				}
				dst.setSlot(slot, c.isTagged(), cTag)
				k.tagBytes += cTagBytes
				k.count++
				if len(inMulti) > 1 {
					if len(k.multiTags)+k.multiTagExtraCount+len(inMulti) > DefaultMaxUniqueAckedRows {
						k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
						return
					}
					var extraBytes int64
					for t := range inMulti {
						if t != "" && t != cTag {
							extraBytes += exactTagEntryBytes(t)
						}
					}
					if !tagBytesOK(extraBytes) {
						return
					}
					if k.multiTags == nil {
						k.multiTags = make(map[seqSlotKey]map[string]struct{})
					}
					k.multiTags[seqSlotKey{ck: ck, slot: slot}] = inMulti
					k.multiTagExtraCount += len(inMulti) - 1
					k.tagBytes += extraBytes
					k.count += int64(len(inMulti) - 1)
				}
				return
			}
			sk := seqSlotKey{ck: ck, slot: slot}
			dstMulti := k.multiTags[sk]
			if dstMulti == nil && len(inMulti) == 0 && dstTag == cTag {
				return
			}
			if !dst.isTagged() || dstTag == "" || !c.isTagged() || (cTag == "" && len(inMulti) == 0) {
				k.markSaturatedLocked(DefaultMaxTaggedSequenceBitmapChunks*65536, SaturationUnitRows)
				return
			}
			addCandidate := func(t string) bool {
				if t == "" {
					return true
				}
				if dstMulti == nil {
					if t == dstTag {
						return true
					}
					if len(k.multiTags)+k.multiTagExtraCount+2 > DefaultMaxUniqueAckedRows {
						k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
						return false
					}
					addBytes := exactTagEntryBytes(t)
					if !tagBytesOK(addBytes) {
						return false
					}
					dstMulti = map[string]struct{}{dstTag: {}, t: {}}
					if k.multiTags == nil {
						k.multiTags = make(map[seqSlotKey]map[string]struct{})
					}
					k.multiTags[sk] = dstMulti
					k.multiTagExtraCount++
					k.tagBytes += addBytes
					k.count++
					return true
				}
				if _, exists := dstMulti[t]; exists {
					return true
				}
				if len(k.multiTags)+k.multiTagExtraCount >= DefaultMaxUniqueAckedRows {
					k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
					return false
				}
				addBytes := exactTagEntryBytes(t)
				if !tagBytesOK(addBytes) {
					return false
				}
				dstMulti[t] = struct{}{}
				k.multiTagExtraCount++
				k.tagBytes += addBytes
				k.count++
				return true
			}
			if len(inMulti) > 0 {
				for t := range inMulti {
					if !addCandidate(t) {
						return
					}
				}
				return
			}
			addCandidate(cTag)
		})
	}
	for _, h := range tier2Copy {
		if _, seen := k.tier2[h]; seen {
			continue
		}
		if len(k.tier2) >= DefaultMaxUniqueAckedRows {
			k.markSaturatedLocked(DefaultMaxUniqueAckedRows, SaturationUnitRows)
			break
		}
		k.tier2[h] = struct{}{}
		k.count++
	}
	for h, cnt := range nullCountsCopy {
		if cnt <= 0 {
			continue
		}
		if _, exists := k.nullIDLogCounts[h]; !exists && len(k.nullIDLogCounts) >= maxNullKeys {
			k.markSaturatedLocked(maxNullKeys, SaturationUnitRows)
			break
		}
		k.nullIDLogCounts[h] += cnt
		k.count += cnt
	}
}

// Count returns the number of distinct logical identities recorded in k.
func (k *SubmittedKeySet) Count() int64 {
	if k == nil {
		return 0
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.count
}

// Saturated reports whether Tier-1 chunk or Tier-2 hash capacity was exceeded.
func (k *SubmittedKeySet) Saturated() bool {
	if k == nil {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.saturated
}

func (s *Server) exactTagByteBudgetLocked() int64 {
	if s.maxExactTagBytes > 0 {
		return s.maxExactTagBytes
	}
	return DefaultMaxExactTagBytes
}

func (s *Server) effectivePhaseNullIDLogLimit(limit int) int {
	if s.maxPhaseNullIDLogKeys > 0 && s.maxPhaseNullIDLogKeys < limit {
		return s.maxPhaseNullIDLogKeys
	}
	return limit
}

func (s *Server) markPhaseSaturatedLocked(table string, satLimit int, satUnit string) {
	if table == "" {
		return
	}
	if s.phaseSaturatedByTable == nil {
		s.phaseSaturatedByTable = make(map[string]bool)
	}
	if s.phaseSaturatedLimitByTable == nil {
		s.phaseSaturatedLimitByTable = make(map[string]int)
	}
	if s.phaseSaturatedUnitByTable == nil {
		s.phaseSaturatedUnitByTable = make(map[string]string)
	}
	s.phaseSaturatedByTable[table] = true
	s.phaseSaturatedLimitByTable[table], s.phaseSaturatedUnitByTable[table] = preferSaturationCap(
		s.phaseSaturatedLimitByTable[table],
		s.phaseSaturatedUnitByTable[table],
		satLimit,
		satUnit,
	)
}

func (s *Server) markTableSaturatedLocked(
	table string,
	satLimit int,
	satUnit string,
	saturatedTable *string,
	saturatedCB *func(string),
) {
	s.uniqueAckedSaturated = true
	s.uniqueAckedSaturatedLimit, s.uniqueAckedSaturatedUnit = preferSaturationCap(
		s.uniqueAckedSaturatedLimit,
		s.uniqueAckedSaturatedUnit,
		satLimit,
		satUnit,
	)
	if table == "" {
		return
	}
	if s.uniqueAckedSaturatedByTable == nil {
		s.uniqueAckedSaturatedByTable = make(map[string]bool)
	}
	if s.uniqueAckedSaturatedLimitByTable == nil {
		s.uniqueAckedSaturatedLimitByTable = make(map[string]int)
	}
	if s.uniqueAckedSaturatedUnitByTable == nil {
		s.uniqueAckedSaturatedUnitByTable = make(map[string]string)
	}
	if !s.uniqueAckedSaturatedByTable[table] {
		s.uniqueAckedSaturatedByTable[table] = true
		if saturatedTable != nil {
			*saturatedTable = table
		}
		if saturatedCB != nil {
			*saturatedCB = s.onUniqueAckedSaturated
		}
	}
	s.uniqueAckedSaturatedLimitByTable[table], s.uniqueAckedSaturatedUnitByTable[table] = preferSaturationCap(
		s.uniqueAckedSaturatedLimitByTable[table],
		s.uniqueAckedSaturatedUnitByTable[table],
		satLimit,
		satUnit,
	)
	s.markPhaseSaturatedLocked(table, satLimit, satUnit)
}

func addMatchingTableKeys[V any](seen map[string]struct{}, query string, m map[string]V) {
	for k := range m {
		if tableKeyMatches(query, k) {
			seen[k] = struct{}{}
		}
	}
}

func sumAllInt64(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total += v
	}
	return total
}

func (s *Server) collectMatchingStatKeysLocked(table string) []string {
	if table == "" {
		return nil
	}
	if isQualifiedTableKey(table) {
		return []string{table}
	}
	seen := make(map[string]struct{})
	addMatchingTableKeys(seen, table, s.ackedRowsByTable)
	addMatchingTableKeys(seen, table, s.ackedBytesByTable)
	addMatchingTableKeys(seen, table, s.uniqueAckedRowsByTable)
	addMatchingTableKeys(seen, table, s.uniqueAckedBytesByTable)
	addMatchingTableKeys(seen, table, s.nullIDRepeatRowsByTable)
	addMatchingTableKeys(seen, table, s.nullIDRepeatBytesByTable)
	addMatchingTableKeys(seen, table, s.throttlesInjectedByTable)
	addMatchingTableKeys(seen, table, s.delayedAcksInjectedByTable)
	addMatchingTableKeys(seen, table, s.triggeredRetryableFaultsByTable)
	addMatchingTableKeys(seen, table, s.triggeredRetryableFaultRowsByTable)
	addMatchingTableKeys(seen, table, s.triggeredUncertainCommitFaultsByTable)
	addMatchingTableKeys(seen, table, s.triggeredUncertainCommitRowsByTable)
	addMatchingTableKeys(seen, table, s.uniqueAckedSaturatedByTable)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (s *Server) tableStatsSnapshotLocked(table string) TableStatsSnapshot {
	if table == "" {
		var (
			satLimit int
			satUnit  string
		)
		if s.uniqueAckedSaturated {
			satLimit = s.uniqueAckedSaturatedLimit
			satUnit = s.uniqueAckedSaturatedUnit
		}
		return TableStatsSnapshot{
			AckedRows:                      int64(s.ackedRows),
			AckedBytes:                     s.ackedBytes,
			UniqueAckedRows:                s.uniqueAckedRows,
			UniqueAckedBytes:               s.uniqueAckedBytes,
			NullIDRepeatRows:               s.nullIDRepeatRows,
			NullIDRepeatBytes:              s.nullIDRepeatBytes,
			UniqueSaturated:                s.uniqueAckedSaturated,
			UniqueSaturatedLimit:           satLimit,
			UniqueSaturatedUnit:            satUnit,
			ThrottlesInjected:              sumAllInt64(s.throttlesInjectedByTable),
			TriggeredRetryableFaults:       sumAllInt64(s.triggeredRetryableFaultsByTable),
			TriggeredRetryableFaultRows:    sumAllInt64(s.triggeredRetryableFaultRowsByTable),
			TriggeredDelayedAckFaults:      sumAllInt64(s.delayedAcksInjectedByTable),
			TriggeredUncertainCommitFaults: sumAllInt64(s.triggeredUncertainCommitFaultsByTable),
			TriggeredUncertainCommitRows:   sumAllInt64(s.triggeredUncertainCommitRowsByTable),
		}
	}
	keys := s.collectMatchingStatKeysLocked(table)
	if len(keys) == 0 {
		return TableStatsSnapshot{}
	}
	var (
		snap     TableStatsSnapshot
		satLimit int
		satUnit  string
	)
	for _, k := range keys {
		snap.AckedRows += s.ackedRowsByTable[k]
		snap.AckedBytes += s.ackedBytesByTable[k]
		snap.UniqueAckedRows += s.uniqueAckedRowsByTable[k]
		snap.UniqueAckedBytes += s.uniqueAckedBytesByTable[k]
		snap.NullIDRepeatRows += s.nullIDRepeatRowsByTable[k]
		snap.NullIDRepeatBytes += s.nullIDRepeatBytesByTable[k]
		snap.ThrottlesInjected += s.throttlesInjectedByTable[k]
		snap.TriggeredRetryableFaults += s.triggeredRetryableFaultsByTable[k]
		snap.TriggeredRetryableFaultRows += s.triggeredRetryableFaultRowsByTable[k]
		snap.TriggeredDelayedAckFaults += s.delayedAcksInjectedByTable[k]
		snap.TriggeredUncertainCommitFaults += s.triggeredUncertainCommitFaultsByTable[k]
		snap.TriggeredUncertainCommitRows += s.triggeredUncertainCommitRowsByTable[k]
		if s.uniqueAckedSaturatedByTable[k] {
			snap.UniqueSaturated = true
			satLimit, satUnit = preferSaturationCap(
				satLimit,
				satUnit,
				s.uniqueAckedSaturatedLimitByTable[k],
				s.uniqueAckedSaturatedUnitByTable[k],
			)
		}
	}
	if snap.UniqueSaturated {
		snap.UniqueSaturatedLimit = satLimit
		snap.UniqueSaturatedUnit = satUnit
	}
	return snap
}

// TableStatsSnapshotForTable atomically captures commit, byte, unique-delivery,
// and throttle counters for table (or global totals when table is "") under a
// single server lock.
func (s *Server) TableStatsSnapshotForTable(table string) TableStatsSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tableStatsSnapshotLocked(table)
}

func deleteMatchingKeys[V any](m map[string]V, query string) {
	if len(m) == 0 {
		return
	}
	if isQualifiedTableKey(query) {
		delete(m, query)
		return
	}
	for k := range m {
		if tableKeyMatches(query, k) {
			delete(m, k)
		}
	}
}

// BeginUniqueAckedPhase clears per-table phase reconciliation state (Tier-1
// bits, Tier-2 digests, and NULL-insert_id occurrence counts committed during the
// phase) while preserving cumulative seen-row state so replays from earlier
// phases remain excluded from incremental unique totals and still surface as
// unexpected phase commits when not submitted in the active phase.
func (s *Server) BeginUniqueAckedPhase(table string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.trackUniqueAcked {
		return
	}
	if table == "" {
		s.phaseSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		s.phaseSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
		s.phaseSeqMultiTagExtraCountByTable = make(map[string]int)
		s.phaseSeqTagBytesByTable = make(map[string]int64)
		s.phaseTier2ByTable = make(map[string]map[[16]byte]struct{})
		s.phaseNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
		s.phaseSaturatedByTable = make(map[string]bool)
		s.phaseSaturatedLimitByTable = make(map[string]int)
		s.phaseSaturatedUnitByTable = make(map[string]string)
		s.phaseUncertainCreditsByTable = make(map[string]map[phaseRowIdentityKey]int64)
		s.phaseReplaysByTable = make(map[string]map[phaseRowIdentityKey]int64)
		return
	}
	deleteMatchingKeys(s.phaseSeqChunksByTable, table)
	deleteMatchingKeys(s.phaseSeqMultiTagsByTable, table)
	deleteMatchingKeys(s.phaseSeqMultiTagExtraCountByTable, table)
	deleteMatchingKeys(s.phaseSeqTagBytesByTable, table)
	deleteMatchingKeys(s.phaseTier2ByTable, table)
	deleteMatchingKeys(s.phaseNullIDLogCountsByTable, table)
	deleteMatchingKeys(s.phaseSaturatedByTable, table)
	deleteMatchingKeys(s.phaseSaturatedLimitByTable, table)
	deleteMatchingKeys(s.phaseSaturatedUnitByTable, table)
	deleteMatchingKeys(s.phaseUncertainCreditsByTable, table)
	deleteMatchingKeys(s.phaseReplaysByTable, table)
}

func groupMultiTagsByChunk(multi map[seqSlotKey]map[string]struct{}) map[sequenceChunkKey]map[uint16]map[string]struct{} {
	if len(multi) == 0 {
		return nil
	}
	out := make(map[sequenceChunkKey]map[uint16]map[string]struct{})
	for sk, m := range multi {
		if len(m) == 0 {
			continue
		}
		bySlot := out[sk.ck]
		if bySlot == nil {
			bySlot = make(map[uint16]map[string]struct{})
			out[sk.ck] = bySlot
		}
		bySlot[sk.slot] = m
	}
	return out
}

func slotEntryCount(multi map[string]struct{}) int64 {
	if len(multi) > 1 {
		return int64(len(multi))
	}
	return 1
}

func reconcileSlot(
	subHas bool, subTag string, subMulti map[string]struct{},
	commHas bool, commTag string, commMulti map[string]struct{},
) (matched, missing, unexpected int64) {
	if !subHas && !commHas {
		return 0, 0, 0
	}
	if !subHas {
		return 0, 0, slotEntryCount(commMulti)
	}
	if !commHas {
		return 0, slotEntryCount(subMulti), 0
	}
	if len(subMulti) == 0 && subTag == "" {
		return 1, 0, slotEntryCount(commMulti) - 1
	}
	if len(subMulti) == 0 && len(commMulti) == 0 {
		if commTag == subTag {
			return 1, 0, 0
		}
		return 0, 1, 1
	}
	if len(subMulti) == 0 {
		if _, ok := commMulti[subTag]; ok {
			return 1, 0, int64(len(commMulti) - 1)
		}
		return 0, 1, int64(len(commMulti))
	}
	if len(commMulti) == 0 {
		if commTag != "" {
			if _, ok := subMulti[commTag]; ok {
				return 1, int64(len(subMulti) - 1), 0
			}
		}
		return 0, int64(len(subMulti)), 1
	}
	for t := range subMulti {
		if _, ok := commMulti[t]; ok {
			matched++
		} else {
			missing++
		}
	}
	unexpected = int64(len(commMulti)) - matched
	return matched, missing, unexpected
}

func reconcileChunk(
	subCh, commCh *sequenceBitmapChunk,
	subSlotMulti, commSlotMulti map[uint16]map[string]struct{},
) (matched, missing, unexpected int64) {
	if subCh == nil && commCh == nil {
		return 0, 0, 0
	}
	if subCh != nil && commCh != nil &&
		subCh.bits != nil && commCh.bits != nil &&
		len(subSlotMulti) == 0 && len(commSlotMulti) == 0 {
		for w := range 1024 {
			subW := subCh.bits[w]
			commW := commCh.bits[w]
			if subW == 0 && commW == 0 {
				continue
			}
			both := subW & commW
			if both != 0 {
				if subCh.tags == nil {
					matched += int64(bits.OnesCount64(both))
				} else {
					for m := both; m != 0; m &= m - 1 {
						slot := w*64 + bits.TrailingZeros64(m)
						subTag := subCh.tags[slot]
						if subTag == "" || (commCh.tags != nil && commCh.tags[slot] == subTag) {
							matched++
						} else {
							missing++
							unexpected++
						}
					}
				}
			}
			missing += int64(bits.OnesCount64(subW &^ commW))
			unexpected += int64(bits.OnesCount64(commW &^ subW))
		}
		return matched, missing, unexpected
	}
	if commCh == nil {
		subCh.forEachSlot(func(slot uint16, _ string) {
			missing += slotEntryCount(subSlotMulti[slot])
		})
		return matched, missing, unexpected
	}
	if subCh == nil {
		commCh.forEachSlot(func(slot uint16, _ string) {
			unexpected += slotEntryCount(commSlotMulti[slot])
		})
		return matched, missing, unexpected
	}
	subCh.forEachSlot(func(slot uint16, subTag string) {
		commTag, commHas := commCh.hasSlot(slot)
		m, miss, unexp := reconcileSlot(true, subTag, subSlotMulti[slot], commHas, commTag, commSlotMulti[slot])
		matched += m
		missing += miss
		unexpected += unexp
	})
	commCh.forEachSlot(func(slot uint16, _ string) {
		if _, subHas := subCh.hasSlot(slot); !subHas {
			unexpected += slotEntryCount(commSlotMulti[slot])
		}
	})
	return matched, missing, unexpected
}

func (s *Server) collectMatchingPhaseKeysLocked(table string) []string {
	if table == "" {
		return nil
	}
	if isQualifiedTableKey(table) {
		return []string{table}
	}
	seen := make(map[string]struct{})
	addMatchingTableKeys(seen, table, s.phaseSeqChunksByTable)
	addMatchingTableKeys(seen, table, s.phaseSeqMultiTagsByTable)
	addMatchingTableKeys(seen, table, s.phaseTier2ByTable)
	addMatchingTableKeys(seen, table, s.phaseNullIDLogCountsByTable)
	addMatchingTableKeys(seen, table, s.phaseUncertainCreditsByTable)
	addMatchingTableKeys(seen, table, s.phaseReplaysByTable)
	addMatchingTableKeys(seen, table, s.phaseSaturatedByTable)
	addMatchingTableKeys(seen, table, s.uniqueAckedSaturatedByTable)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (s *Server) reconcileTablePhaseLocked(table string, submitted *SubmittedKeySet) ReconciliationResult {
	if submitted == nil {
		return ReconciliationResult{}
	}
	submitted.mu.Lock()
	defer submitted.mu.Unlock()

	matchedKeys := s.collectMatchingPhaseKeysLocked(table)

	sat := submitted.saturated
	var (
		satLimit int
		satUnit  string
	)
	if submitted.saturated {
		satLimit, satUnit = preferSaturationCap(satLimit, satUnit, submitted.saturatedLimit, submitted.saturatedUnit)
	}
	for _, k := range matchedKeys {
		if s.phaseSaturatedByTable[k] {
			sat = true
			satLimit, satUnit = preferSaturationCap(satLimit, satUnit, s.phaseSaturatedLimitByTable[k], s.phaseSaturatedUnitByTable[k])
		}
		if s.uniqueAckedSaturatedByTable[k] {
			sat = true
			satLimit, satUnit = preferSaturationCap(satLimit, satUnit, s.uniqueAckedSaturatedLimitByTable[k], s.uniqueAckedSaturatedUnitByTable[k])
		}
	}
	res := ReconciliationResult{
		SubmittedRows:  submitted.count,
		Saturated:      sat,
		SaturatedLimit: satLimit,
		SaturatedUnit:  satUnit,
	}

	var (
		commChunks   map[sequenceChunkKey]*sequenceBitmapChunk
		commMulti    map[seqSlotKey]map[string]struct{}
		commTier2    map[[16]byte]struct{}
		commNullLogs map[[16]byte]int64
		commReplays  map[phaseRowIdentityKey]int64
		commCredits  map[phaseRowIdentityKey]int64
	)
	switch len(matchedKeys) {
	case 0:
	case 1:
		k := matchedKeys[0]
		commChunks = s.phaseSeqChunksByTable[k]
		commMulti = s.phaseSeqMultiTagsByTable[k]
		commTier2 = s.phaseTier2ByTable[k]
		commNullLogs = s.phaseNullIDLogCountsByTable[k]
		commReplays = s.phaseReplaysByTable[k]
		commCredits = s.phaseUncertainCreditsByTable[k]
	default:
		commChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
		commMulti = make(map[seqSlotKey]map[string]struct{})
		commTier2 = make(map[[16]byte]struct{})
		commNullLogs = make(map[[16]byte]int64)
		commReplays = make(map[phaseRowIdentityKey]int64)
		commCredits = make(map[phaseRowIdentityKey]int64)
		for _, k := range matchedKeys {
			for ck, ch := range s.phaseSeqChunksByTable[k] {
				if ch == nil {
					continue
				}
				dst := commChunks[ck]
				if dst == nil {
					commChunks[ck] = ch.cloneChunk()
					continue
				}
				if ch.isTagged() && !dst.hasTags {
					dst.hasTags = true
					if dst.bits != nil && dst.tags == nil {
						dst.tags = new([65536]string)
					}
				}
				ch.forEachSlot(func(slot uint16, tag string) {
					if existingTag, has := dst.hasSlot(slot); has {
						if tag != existingTag {
							sk := seqSlotKey{ck: ck, slot: slot}
							tags := commMulti[sk]
							if tags == nil {
								tags = map[string]struct{}{existingTag: {}, tag: {}}
								commMulti[sk] = tags
							} else {
								tags[tag] = struct{}{}
							}
						}
						return
					}
					hasTag := tag != "" || dst.hasTags
					if hasTag && dst.bits != nil && dst.tags == nil {
						dst.tags = new([65536]string)
					}
					dst.setSlot(slot, hasTag, tag)
				})
			}
			for slot, tags := range s.phaseSeqMultiTagsByTable[k] {
				dstTags := commMulti[slot]
				if dstTags == nil {
					dstTags = make(map[string]struct{}, len(tags))
					commMulti[slot] = dstTags
				}
				for tag := range tags {
					dstTags[tag] = struct{}{}
				}
			}
			for h := range s.phaseTier2ByTable[k] {
				commTier2[h] = struct{}{}
			}
			for h, cnt := range s.phaseNullIDLogCountsByTable[k] {
				commNullLogs[h] += cnt
			}
			for rk, cnt := range s.phaseReplaysByTable[k] {
				commReplays[rk] += cnt
			}
			for rk, cnt := range s.phaseUncertainCreditsByTable[k] {
				commCredits[rk] += cnt
			}
		}
	}

	subMultiByChunk := groupMultiTagsByChunk(submitted.multiTags)
	commMultiByChunk := groupMultiTagsByChunk(commMulti)
	for ck, subCh := range submitted.chunks {
		if subCh == nil {
			continue
		}
		m, miss, unexp := reconcileChunk(subCh, commChunks[ck], subMultiByChunk[ck], commMultiByChunk[ck])
		res.MatchedRows += m
		res.MissingRows += miss
		res.UnexpectedRows += unexp
	}
	for ck, commCh := range commChunks {
		if commCh == nil || submitted.chunks[ck] != nil {
			continue
		}
		_, _, unexp := reconcileChunk(nil, commCh, nil, commMultiByChunk[ck])
		res.UnexpectedRows += unexp
	}

	for h := range submitted.tier2 {
		if _, ok := commTier2[h]; ok {
			res.MatchedRows++
		} else {
			res.MissingRows++
		}
	}
	for h := range commTier2 {
		if _, ok := submitted.tier2[h]; !ok {
			res.UnexpectedRows++
		}
	}

	for h, subCnt := range submitted.nullIDLogCounts {
		commCnt := commNullLogs[h]
		if subCnt <= commCnt {
			res.MatchedRows += subCnt
			excess := commCnt - subCnt
			res.ReplayedNullIDRows += excess
			if excess > 0 {
				credit := commCredits[phaseRowIdentityKey{kind: phaseIdentityKindNullID, hash: h}]
				if excess > credit {
					res.UnexplainedReplayRows += excess - credit
				}
			}
		} else {
			res.MatchedRows += commCnt
			res.MissingRows += subCnt - commCnt
		}
	}
	for h, commCnt := range commNullLogs {
		if submitted.nullIDLogCounts[h] == 0 {
			res.UnexpectedRows += commCnt
		}
	}
	for rk, replayCnt := range commReplays {
		if credit := commCredits[rk]; replayCnt > credit {
			res.UnexplainedReplayRows += replayCnt - credit
		}
	}
	return res
}

// ReconcileTablePhase compares the logical identities newly committed during
// the active phase for table against submitted.
func (s *Server) ReconcileTablePhase(table string, submitted *SubmittedKeySet) ReconciliationResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileTablePhaseLocked(table, submitted)
}

func (s *Server) recordRetryableFaultLocked(table string, rows int) {
	if s.triggeredRetryableFaultsByTable == nil {
		s.triggeredRetryableFaultsByTable = make(map[string]int64)
	}
	if s.triggeredRetryableFaultRowsByTable == nil {
		s.triggeredRetryableFaultRowsByTable = make(map[string]int64)
	}
	s.triggeredRetryableFaultsByTable[table]++
	s.triggeredRetryableFaultRowsByTable[table] += int64(rows)
}

func (s *Server) recordUncertainCommitFaultLocked(table string, rows int) {
	if s.triggeredUncertainCommitFaultsByTable == nil {
		s.triggeredUncertainCommitFaultsByTable = make(map[string]int64)
	}
	if s.triggeredUncertainCommitRowsByTable == nil {
		s.triggeredUncertainCommitRowsByTable = make(map[string]int64)
	}
	s.triggeredUncertainCommitFaultsByTable[table]++
	s.triggeredUncertainCommitRowsByTable[table] += int64(rows)
}

func (s *Server) recordPhaseIdentityCountLocked(
	byTable *map[string]map[phaseRowIdentityKey]int64,
	table string,
	rk phaseRowIdentityKey,
	capRows int,
) bool {
	if table == "" || rk.kind == 0 {
		return false
	}
	if *byTable == nil {
		*byTable = make(map[string]map[phaseRowIdentityKey]int64)
	}
	counts := (*byTable)[table]
	if counts == nil {
		counts = make(map[phaseRowIdentityKey]int64)
		(*byTable)[table] = counts
	}
	if _, exists := counts[rk]; !exists && capRows > 0 && len(counts) >= capRows {
		s.markPhaseSaturatedLocked(table, capRows, SaturationUnitRows)
		return true
	}
	counts[rk]++
	return false
}

// ReconcileAndSnapshotForTable atomically captures TableStatsSnapshotForTable
// and ReconcileTablePhase under a single server lock.
func (s *Server) ReconcileAndSnapshotForTable(table string, submitted *SubmittedKeySet) (TableStatsSnapshot, ReconciliationResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tableStatsSnapshotLocked(table), s.reconcileTablePhaseLocked(table, submitted)
}

func (s *Server) recordPhaseAckedRowLocked(
	table string,
	sk extractedSequenceKey,
	usedTier2 bool,
	computeHash func() [16]byte,
	limit int,
) (saturated bool, satLimit int, satUnit string) {
	if table == "" {
		return false, 0, ""
	}
	if !usedTier2 && sk.ok {
		if s.phaseSeqChunksByTable == nil {
			s.phaseSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		}
		chunks := s.phaseSeqChunksByTable[table]
		if chunks == nil {
			chunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
			s.phaseSeqChunksByTable[table] = chunks
		}
		phaseSK := extractedSequenceKey{
			domain:       sk.domain,
			identityHash: sk.identityHash,
			seq:          sk.seq,
			hasTag:       sk.hasTag,
			tag:          sk.tag,
			ok:           true,
		}
		phaseMulti := s.phaseSeqMultiTagsByTable[table]
		phaseExtra := s.phaseSeqMultiTagExtraCountByTable[table]
		phaseTagBytes := s.phaseSeqTagBytesByTable[table]
		_, fallbackTier2, sat, tier1SatLimit, tier1SatUnit := recordTier1SlotWithMultiTags(
			chunks,
			&phaseMulti,
			&phaseExtra,
			phaseSK,
			false,
			0,
			limit,
			&phaseTagBytes,
			s.exactTagByteBudgetLocked(),
		)
		if phaseMulti != nil {
			if s.phaseSeqMultiTagsByTable == nil {
				s.phaseSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
			}
			s.phaseSeqMultiTagsByTable[table] = phaseMulti
		}
		if phaseExtra > 0 {
			if s.phaseSeqMultiTagExtraCountByTable == nil {
				s.phaseSeqMultiTagExtraCountByTable = make(map[string]int)
			}
			s.phaseSeqMultiTagExtraCountByTable[table] = phaseExtra
		}
		if phaseTagBytes > 0 {
			if s.phaseSeqTagBytesByTable == nil {
				s.phaseSeqTagBytesByTable = make(map[string]int64)
			}
			s.phaseSeqTagBytesByTable[table] = phaseTagBytes
		}
		if sat {
			s.markPhaseSaturatedLocked(table, tier1SatLimit, tier1SatUnit)
			return true, tier1SatLimit, tier1SatUnit
		}
		if !fallbackTier2 {
			return false, 0, ""
		}
	}
	if s.phaseTier2ByTable == nil {
		s.phaseTier2ByTable = make(map[string]map[[16]byte]struct{})
	}
	tier2 := s.phaseTier2ByTable[table]
	if tier2 == nil {
		tier2 = make(map[[16]byte]struct{})
		s.phaseTier2ByTable[table] = tier2
	}
	h := computeHash()
	if _, exists := tier2[h]; exists {
		return false, 0, ""
	}
	if len(tier2) >= limit {
		s.markPhaseSaturatedLocked(table, limit, SaturationUnitRows)
		return true, limit, SaturationUnitRows
	}
	tier2[h] = struct{}{}
	return false, 0, ""
}

func (s *Server) recordNullIDLogLocked(table string, computeHash func() [16]byte, phaseLimit, seenLimit int) (isRepeat, saturated bool, satLimit int, satUnit string) {
	if table == "" {
		return false, false, 0, ""
	}
	h := computeHash()
	if s.phaseNullIDLogCountsByTable == nil {
		s.phaseNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
	}
	phaseCounts := s.phaseNullIDLogCountsByTable[table]
	if phaseCounts == nil {
		phaseCounts = make(map[[16]byte]int64)
		s.phaseNullIDLogCountsByTable[table] = phaseCounts
	}
	if _, exists := phaseCounts[h]; !exists && len(phaseCounts) >= phaseLimit {
		s.markPhaseSaturatedLocked(table, phaseLimit, SaturationUnitRows)
		return false, true, phaseLimit, SaturationUnitRows
	}
	if s.seenNullIDLogCountsByTable == nil {
		s.seenNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
	}
	seenCounts := s.seenNullIDLogCountsByTable[table]
	if seenCounts == nil {
		seenCounts = make(map[[16]byte]int64)
		s.seenNullIDLogCountsByTable[table] = seenCounts
	}
	if _, exists := seenCounts[h]; !exists && len(seenCounts) >= seenLimit {
		s.markPhaseSaturatedLocked(table, seenLimit, SaturationUnitRows)
		return false, true, seenLimit, SaturationUnitRows
	}
	phaseCounts[h]++
	isRepeat = seenCounts[h] > 0
	seenCounts[h]++
	return isRepeat, false, 0, ""
}

func (s *Server) recordGlobalSeenNullIDLogLocked(computeHash func() [16]byte, limit int) (isRepeat, saturated bool) {
	h := computeHash()
	if s.seenNullIDLogCounts == nil {
		s.seenNullIDLogCounts = make(map[[16]byte]int64)
	}
	if _, exists := s.seenNullIDLogCounts[h]; !exists && len(s.seenNullIDLogCounts) >= limit {
		return false, true
	}
	isRepeat = s.seenNullIDLogCounts[h] > 0
	s.seenNullIDLogCounts[h]++
	return isRepeat, false
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
	s.uniqueAckedSaturatedLimit = 0
	s.uniqueAckedSaturatedUnit = ""
	s.uniqueAckedSaturatedByTable = make(map[string]bool)
	s.uniqueAckedSaturatedLimitByTable = make(map[string]int)
	s.uniqueAckedSaturatedUnitByTable = make(map[string]string)
	s.seenSeqMultiTagExtraCount = 0
	s.seenSeqTagBytes = 0
	s.uniqueAckedRows = 0
	s.uniqueAckedBytes = 0
	s.nullIDRepeatRows = 0
	s.nullIDRepeatBytes = 0
	s.uniqueAckedRowsByTable = make(map[string]int64)
	s.uniqueAckedBytesByTable = make(map[string]int64)
	s.nullIDRepeatRowsByTable = make(map[string]int64)
	s.nullIDRepeatBytesByTable = make(map[string]int64)
	if track {
		s.seenAckedRows = make(map[[16]byte]struct{})
		s.seenSeqChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenSeqMultiTags = make(map[seqSlotKey]map[string]struct{})
		s.seenNullIDLogCounts = make(map[[16]byte]int64)
		s.seenAckedRowsByTable = make(map[string]map[[16]byte]struct{})
		s.seenSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
		s.seenSeqMultiTagExtraCountByTable = make(map[string]int)
		s.seenSeqTagBytesByTable = make(map[string]int64)
		s.seenNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
		s.phaseSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		s.phaseSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
		s.phaseSeqMultiTagExtraCountByTable = make(map[string]int)
		s.phaseSeqTagBytesByTable = make(map[string]int64)
		s.phaseTier2ByTable = make(map[string]map[[16]byte]struct{})
		s.phaseNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
		s.phaseSaturatedByTable = make(map[string]bool)
		s.phaseSaturatedLimitByTable = make(map[string]int)
		s.phaseSaturatedUnitByTable = make(map[string]string)
		s.phaseUncertainCreditsByTable = make(map[string]map[phaseRowIdentityKey]int64)
		s.phaseReplaysByTable = make(map[string]map[phaseRowIdentityKey]int64)
	} else {
		s.seenAckedRows = nil
		s.seenSeqChunks = nil
		s.seenSeqMultiTags = nil
		s.seenNullIDLogCounts = nil
		s.seenAckedRowsByTable = nil
		s.seenSeqChunksByTable = nil
		s.seenSeqMultiTagsByTable = nil
		s.seenSeqMultiTagExtraCountByTable = nil
		s.seenSeqTagBytesByTable = nil
		s.seenNullIDLogCountsByTable = nil
		s.phaseSeqChunksByTable = nil
		s.phaseSeqMultiTagsByTable = nil
		s.phaseSeqMultiTagExtraCountByTable = nil
		s.phaseSeqTagBytesByTable = nil
		s.phaseTier2ByTable = nil
		s.phaseNullIDLogCountsByTable = nil
		s.phaseSaturatedByTable = nil
		s.phaseSaturatedLimitByTable = nil
		s.phaseSaturatedUnitByTable = nil
		s.phaseUncertainCreditsByTable = nil
		s.phaseReplaysByTable = nil
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
	return s.MaxTrackedGeneratedRowsForSignal("", false)
}

// MaxTrackedSynthesizedLogRows returns the effective row cap for tagged Tier-1
// sequence bitmap tracking of synthesized id1: logs (min of chunk capacity
// and exact-tag byte budget: 6,391,320 under DefaultMaxExactTagBytes).
func (s *Server) MaxTrackedSynthesizedLogRows() int {
	return s.MaxTrackedGeneratedRowsForSignal("logs", true)
}

// MaxTrackedNullIDLogRows returns the effective distinct logical-identity key
// cap tracked for NULL-insert_id log rows: custom SetMaxUniqueAckedRows limits
// apply when smaller than DefaultMaxUniqueAckedRows, otherwise up to
// DefaultMaxUniqueAckedRows (2,000,000).
func (s *Server) MaxTrackedNullIDLogRows() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.customMaxUniqueAcked && s.maxUniqueAckedRows > 0 {
		return s.maxUniqueAckedRows
	}
	return DefaultMaxUniqueAckedRows
}

// MaxTrackedGeneratedRowsForSignal returns the effective Tier-1 generated-row
// capacity for signal ("spans", "logs", or "metrics"): untagged tracking holds
// up to DefaultMaxSequenceBitmapChunks * 65536 (67,108,864) rows, whereas
// tagged tracking is bounded by both DefaultMaxTaggedSequenceBitmapChunks
// (16,777,216) and DefaultMaxExactTagBytes / per-tag bytes (6,391,320 for logs
// with id1: IDs, 3,195,660 for metrics with fp1: fingerprints), further clamped
// by any custom SetMaxUniqueAckedRows limit.
func (s *Server) MaxTrackedGeneratedRowsForSignal(signal string, tagged bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !tagged {
		if s.customMaxUniqueAcked && s.maxUniqueAckedRows > 0 {
			return s.maxUniqueAckedRows
		}
		return DefaultMaxSequenceBitmapChunks * 65536
	}
	bitmapCap := DefaultMaxTaggedSequenceBitmapChunks * 65536
	byteCap := clampLimitToInt(s.exactTagByteBudgetLocked() / exactTagEntryBytesForSignal(signal))
	capRows := min(bitmapCap, byteCap)
	if s.customMaxUniqueAcked && s.maxUniqueAckedRows > 0 {
		return min(s.maxUniqueAckedRows, capRows)
	}
	return capRows
}

// MaxTrackedGeneratedRowsForTagged returns the effective Tier-1 bitmap row cap
// for either untagged (false -> 67,108,864) or exact identity-tagged
// sequences (true -> min(16,777,216, DefaultMaxExactTagBytes / 42) = 6,391,320)
// when no smaller custom SetMaxUniqueAckedRows or tag-byte cap is configured.
// Prefer MaxTrackedGeneratedRowsForSignal when the target signal is known.
func (s *Server) MaxTrackedGeneratedRowsForTagged(tagged bool) int {
	if tagged {
		return s.MaxTrackedGeneratedRowsForSignal("logs", true)
	}
	return s.MaxTrackedGeneratedRowsForSignal("", false)
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
	if isQualifiedTableKey(table) {
		return s.uniqueAckedSaturatedByTable[table]
	}
	for k, sat := range s.uniqueAckedSaturatedByTable {
		if sat && tableKeyMatches(table, k) {
			return true
		}
	}
	return false
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
	if isQualifiedTableKey(table) {
		src := s.rows[table]
		out := make([]map[string]any, len(src))
		for i, r := range src {
			out[i] = cloneMap(r)
		}
		return out
	}
	var keys []string
	for k := range s.rows {
		if tableKeyMatches(table, k) {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	var out []map[string]any
	for _, k := range keys {
		for _, r := range s.rows[k] {
			out = append(out, cloneMap(r))
		}
	}
	return out
}

// RowCount returns the number of rows appended to table.
func (s *Server) RowCount(table string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if isQualifiedTableKey(table) {
		return len(s.rows[table])
	}
	total := 0
	for k, rows := range s.rows {
		if tableKeyMatches(table, k) {
			total += len(rows)
		}
	}
	return total
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
	s.uniqueAckedSaturatedLimit = 0
	s.uniqueAckedSaturatedUnit = ""
	s.uniqueAckedSaturatedByTable = make(map[string]bool)
	s.uniqueAckedSaturatedLimitByTable = make(map[string]int)
	s.uniqueAckedSaturatedUnitByTable = make(map[string]string)
	s.seenSeqMultiTagExtraCount = 0
	s.seenSeqTagBytes = 0
	s.uniqueAckedRows = 0
	s.uniqueAckedBytes = 0
	s.nullIDRepeatRows = 0
	s.nullIDRepeatBytes = 0
	s.ackedRowsByTable = make(map[string]int64)
	s.ackedBytesByTable = make(map[string]int64)
	s.uniqueAckedRowsByTable = make(map[string]int64)
	s.uniqueAckedBytesByTable = make(map[string]int64)
	s.nullIDRepeatRowsByTable = make(map[string]int64)
	s.nullIDRepeatBytesByTable = make(map[string]int64)
	s.periodicThrottlesInjected = make(map[string]int64)
	s.throttlesInjectedByTable = make(map[string]int64)
	s.delayedAcksInjectedByTable = make(map[string]int64)
	s.triggeredRetryableFaultsByTable = make(map[string]int64)
	s.triggeredRetryableFaultRowsByTable = make(map[string]int64)
	s.triggeredUncertainCommitFaultsByTable = make(map[string]int64)
	s.triggeredUncertainCommitRowsByTable = make(map[string]int64)
	if s.trackUniqueAcked {
		s.seenAckedRows = make(map[[16]byte]struct{})
		s.seenSeqChunks = make(map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenSeqMultiTags = make(map[seqSlotKey]map[string]struct{})
		s.seenNullIDLogCounts = make(map[[16]byte]int64)
		s.seenAckedRowsByTable = make(map[string]map[[16]byte]struct{})
		s.seenSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		s.seenSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
		s.seenSeqMultiTagExtraCountByTable = make(map[string]int)
		s.seenSeqTagBytesByTable = make(map[string]int64)
		s.seenNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
		s.phaseSeqChunksByTable = make(map[string]map[sequenceChunkKey]*sequenceBitmapChunk)
		s.phaseSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
		s.phaseSeqMultiTagExtraCountByTable = make(map[string]int)
		s.phaseSeqTagBytesByTable = make(map[string]int64)
		s.phaseTier2ByTable = make(map[string]map[[16]byte]struct{})
		s.phaseNullIDLogCountsByTable = make(map[string]map[[16]byte]int64)
		s.phaseSaturatedByTable = make(map[string]bool)
		s.phaseSaturatedLimitByTable = make(map[string]int)
		s.phaseSaturatedUnitByTable = make(map[string]string)
		s.phaseUncertainCreditsByTable = make(map[string]map[phaseRowIdentityKey]int64)
		s.phaseReplaysByTable = make(map[string]map[phaseRowIdentityKey]int64)
	} else {
		s.seenAckedRows = nil
		s.seenSeqChunks = nil
		s.seenSeqMultiTags = nil
		s.seenNullIDLogCounts = nil
		s.seenAckedRowsByTable = nil
		s.seenSeqChunksByTable = nil
		s.seenSeqMultiTagsByTable = nil
		s.seenSeqMultiTagExtraCountByTable = nil
		s.seenSeqTagBytesByTable = nil
		s.seenNullIDLogCountsByTable = nil
		s.phaseSeqChunksByTable = nil
		s.phaseSeqMultiTagsByTable = nil
		s.phaseSeqMultiTagExtraCountByTable = nil
		s.phaseSeqTagBytesByTable = nil
		s.phaseTier2ByTable = nil
		s.phaseNullIDLogCountsByTable = nil
		s.phaseSaturatedByTable = nil
		s.phaseSaturatedLimitByTable = nil
		s.phaseSaturatedUnitByTable = nil
		s.phaseUncertainCreditsByTable = nil
		s.phaseReplaysByTable = nil
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
	if err := s.registerTableSchemaLocked(CanonicalTableKey(project, dataset, table), ts); err != nil {
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
	var streamBareTable string
	var streamDesc protoreflect.MessageDescriptor
	var ignoreFields [3]protowire.Number
	var seqFDs sequenceKeyFieldDescriptors

	for {
		req, err := srv.Recv()
		if err != nil {
			return nil
		}
		if ws := req.GetWriteStream(); ws != "" {
			if qual, bare := parseQualifiedTableFromStream(ws); qual != "" {
				streamTable = qual
				streamBareTable = bare
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
		if tableDesc == nil && streamBareTable != "" {
			tableDesc = s.descriptors[streamBareTable]
		}
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
			s.mu.Lock()
			s.recordRetryableFaultLocked(streamTable, len(serialized))
			s.mu.Unlock()
			msg := fault.Message
			if msg == "" {
				msg = "stream closed by fake fault injection"
			}
			return status.Error(codes.Aborted, msg)

		case FaultUnavailable:
			s.mu.Lock()
			s.recordRetryableFaultLocked(streamTable, len(serialized))
			s.mu.Unlock()
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
			s.recordRetryableFaultLocked(streamTable, len(serialized))
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
			hookTable := streamBareTable
			if hookTable == "" {
				hookTable = streamTable
			}
			serialized = beforeCommit(hookTable, serialized)
		}

		var decodedBatch []map[string]any
		if !discardRows {
			decodedBatch = make([]map[string]any, 0, len(serialized))
		}
		var (
			rowSeqKeys   []extractedSequenceKey
			rowHashes    [][16]byte
			rowIsNullIDs []bool
		)
		if trackUnique && len(serialized) > 0 {
			rowSeqKeys = make([]extractedSequenceKey, len(serialized))
			rowHashes = make([][16]byte, len(serialized))
			rowIsNullIDs = make([]bool, len(serialized))
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
					rowIsNullIDs[i] = isNullInsertIDLog(msg, seqFDs)
					sum := hashDedupIdentityWithFallback(msg, seqFDs, raw, ignoreFields)
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
			rowIdentities  []phaseRowIdentityKey
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
			uncertainCapRows := limit
			if !customCap && uncertainCapRows > DefaultMaxUniqueAckedRows {
				uncertainCapRows = DefaultMaxUniqueAckedRows
			}
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
				rowIdentities = make([]phaseRowIdentityKey, len(serialized))
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
				var (
					sk       extractedSequenceKey
					isNullID bool
				)
				if len(rowSeqKeys) == len(serialized) {
					sk = rowSeqKeys[i]
					isNullID = rowIsNullIDs[i]
				} else if msg, uerr := unmarshalRow(streamDesc, raw); uerr == nil {
					sk = extractGeneratedSequenceKey(msg, seqFDs)
					if !sk.ok {
						isNullID = isNullInsertIDLog(msg, seqFDs)
					}
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
						sum = hashDedupIdentityWithFallback(msg, seqFDs, raw, ignoreFields)
					} else {
						sum = hashCanonicalRow(raw, ignoreFields)
					}
					copy(cachedHash[:], sum[:16])
					hasCachedHash = true
					return cachedHash
				}
				if isNullID {
					nullRowCap := limit
					if !customCap && nullRowCap > DefaultMaxUniqueAckedRows {
						nullRowCap = DefaultMaxUniqueAckedRows
					}
					nullSatOnTable := false
					if streamTable != "" {
						if customCap && s.uniqueAckedRowsByTable[streamTable] >= int64(limit) {
							s.markTableSaturatedLocked(streamTable, limit, SaturationUnitRows, &saturatedTable, &saturatedCB)
							nullSatOnTable = true
						} else {
							phaseNullLimit := s.effectivePhaseNullIDLogLimit(nullRowCap)
							isRepeatTable, nullSat, nullLimit, nullUnit := s.recordNullIDLogLocked(streamTable, computeHash, phaseNullLimit, nullRowCap)
							if nullSat {
								s.markTableSaturatedLocked(streamTable, nullLimit, nullUnit, &saturatedTable, &saturatedCB)
								nullSatOnTable = true
							} else {
								s.uniqueAckedRowsByTable[streamTable]++
								s.uniqueAckedBytesByTable[streamTable] += int64(len(raw))
								rk := phaseRowIdentityKey{kind: phaseIdentityKindNullID, hash: computeHash()}
								if len(rowIdentities) == len(serialized) {
									rowIdentities[i] = rk
								}
								if fault.Mode == FaultCommitThenStreamClosed {
									s.recordPhaseIdentityCountLocked(&s.phaseUncertainCreditsByTable, streamTable, rk, uncertainCapRows)
								}
								if isRepeatTable {
									if s.nullIDRepeatRowsByTable == nil {
										s.nullIDRepeatRowsByTable = make(map[string]int64)
									}
									if s.nullIDRepeatBytesByTable == nil {
										s.nullIDRepeatBytesByTable = make(map[string]int64)
									}
									s.nullIDRepeatRowsByTable[streamTable]++
									s.nullIDRepeatBytesByTable[streamTable] += int64(len(raw))
								}
							}
						}
					}
					if customCap && s.uniqueAckedRows >= int64(limit) {
						s.uniqueAckedSaturated = true
						s.uniqueAckedSaturatedLimit, s.uniqueAckedSaturatedUnit = preferSaturationCap(
							s.uniqueAckedSaturatedLimit,
							s.uniqueAckedSaturatedUnit,
							limit,
							SaturationUnitRows,
						)
					} else if !nullSatOnTable {
						isRepeatGlobal, globalSat := s.recordGlobalSeenNullIDLogLocked(computeHash, nullRowCap)
						if globalSat {
							s.uniqueAckedSaturated = true
							s.uniqueAckedSaturatedLimit, s.uniqueAckedSaturatedUnit = preferSaturationCap(
								s.uniqueAckedSaturatedLimit,
								s.uniqueAckedSaturatedUnit,
								nullRowCap,
								SaturationUnitRows,
							)
						} else {
							s.uniqueAckedRows++
							s.uniqueAckedBytes += int64(len(raw))
							if isRepeatGlobal {
								s.nullIDRepeatRows++
								s.nullIDRepeatBytes += int64(len(raw))
							}
						}
					}
					continue
				}
				maxTagBytes := s.exactTagByteBudgetLocked()
				isNewGlobal, _, satGlobal, globalSatLimit, globalSatUnit := recordUniqueAckedRowWithMultiTags(
					s.seenSeqChunks,
					&s.seenSeqMultiTags,
					&s.seenSeqMultiTagExtraCount,
					s.seenAckedRows,
					sk,
					computeHash,
					customCap,
					limit,
					s.uniqueAckedRows,
					&s.seenSeqTagBytes,
					maxTagBytes,
				)
				if satGlobal {
					s.uniqueAckedSaturated = true
					s.uniqueAckedSaturatedLimit, s.uniqueAckedSaturatedUnit = preferSaturationCap(
						s.uniqueAckedSaturatedLimit,
						s.uniqueAckedSaturatedUnit,
						globalSatLimit,
						globalSatUnit,
					)
				} else if isNewGlobal {
					s.uniqueAckedRows++
					s.uniqueAckedBytes += int64(len(raw))
				}
				if tableChunks != nil {
					tableMulti := s.seenSeqMultiTagsByTable[streamTable]
					tableExtra := s.seenSeqMultiTagExtraCountByTable[streamTable]
					tableTagBytes := s.seenSeqTagBytesByTable[streamTable]
					isNewTbl, usedTier2Tbl, satTbl, tblSatLimit, tblSatUnit := recordUniqueAckedRowWithMultiTags(
						tableChunks,
						&tableMulti,
						&tableExtra,
						tableSeen,
						sk,
						computeHash,
						customCap,
						limit,
						s.uniqueAckedRowsByTable[streamTable],
						&tableTagBytes,
						maxTagBytes,
					)
					if tableMulti != nil {
						if s.seenSeqMultiTagsByTable == nil {
							s.seenSeqMultiTagsByTable = make(map[string]map[seqSlotKey]map[string]struct{})
						}
						s.seenSeqMultiTagsByTable[streamTable] = tableMulti
					}
					if tableExtra > 0 {
						if s.seenSeqMultiTagExtraCountByTable == nil {
							s.seenSeqMultiTagExtraCountByTable = make(map[string]int)
						}
						s.seenSeqMultiTagExtraCountByTable[streamTable] = tableExtra
					}
					if tableTagBytes > 0 {
						if s.seenSeqTagBytesByTable == nil {
							s.seenSeqTagBytesByTable = make(map[string]int64)
						}
						s.seenSeqTagBytesByTable[streamTable] = tableTagBytes
					}
					if satTbl {
						s.markTableSaturatedLocked(streamTable, tblSatLimit, tblSatUnit, &saturatedTable, &saturatedCB)
					} else {
						var rk phaseRowIdentityKey
						if !usedTier2Tbl && sk.ok {
							rk = phaseRowIdentityKey{
								kind:         phaseIdentityKindTier1,
								domain:       sk.domain,
								identityHash: sk.identityHash,
								seq:          sk.seq,
								tag:          sk.tag,
							}
						} else {
							rk = phaseRowIdentityKey{
								kind: phaseIdentityKindTier2,
								hash: computeHash(),
							}
						}
						if len(rowIdentities) == len(serialized) {
							rowIdentities[i] = rk
						}
						if isNewTbl {
							s.uniqueAckedRowsByTable[streamTable]++
							s.uniqueAckedBytesByTable[streamTable] += int64(len(raw))
						} else {
							s.recordPhaseIdentityCountLocked(&s.phaseReplaysByTable, streamTable, rk, uncertainCapRows)
						}
						if fault.Mode == FaultCommitThenStreamClosed {
							s.recordPhaseIdentityCountLocked(&s.phaseUncertainCreditsByTable, streamTable, rk, uncertainCapRows)
						}
						if phaseSat, phaseSatLimit, phaseSatUnit := s.recordPhaseAckedRowLocked(streamTable, sk, usedTier2Tbl, computeHash, limit); phaseSat {
							s.markTableSaturatedLocked(streamTable, phaseSatLimit, phaseSatUnit, &saturatedTable, &saturatedCB)
						}
					}
				}
			}
		}
		if !s.discardRows && streamTable != "" && len(decodedBatch) > 0 {
			s.rows[streamTable] = append(s.rows[streamTable], decodedBatch...)
		}
		if fault.Mode == FaultCommitThenStreamClosed {
			s.recordUncertainCommitFaultLocked(streamTable, len(serialized))
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
			s.mu.Lock()
			s.recordUncertainCommitFaultLocked(streamTable, len(serialized))
			if trackUnique && streamTable != "" && len(rowIdentities) == len(serialized) {
				capRows := s.maxUniqueAckedRows
				if capRows <= 0 || (!s.customMaxUniqueAcked && capRows > DefaultMaxUniqueAckedRows) {
					capRows = DefaultMaxUniqueAckedRows
				}
				for _, rk := range rowIdentities {
					s.recordPhaseIdentityCountLocked(&s.phaseUncertainCreditsByTable, streamTable, rk, capRows)
				}
			}
			s.mu.Unlock()
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

type seqSlotKey struct {
	ck   sequenceChunkKey
	slot uint16
}

const (
	phaseIdentityKindTier1 uint8 = iota + 1
	phaseIdentityKindTier2
	phaseIdentityKindNullID
)

type phaseRowIdentityKey struct {
	kind         uint8
	domain       uint8
	identityHash uint64
	seq          uint64
	tag          string
	hash         [16]byte
}

const (
	sparseUntaggedPromoteThreshold = 512
	sparseTaggedPromoteThreshold   = 8192
)

type sequenceBitmapChunk struct {
	hasTags     bool
	sparseSlots map[uint16]string
	bits        *[1024]uint64
	tags        *[65536]string
}

func (c *sequenceBitmapChunk) isTagged() bool {
	return c != nil && (c.hasTags || c.tags != nil)
}

func (c *sequenceBitmapChunk) hasSlot(slot uint16) (string, bool) {
	if c == nil {
		return "", false
	}
	if c.bits != nil {
		w := slot >> 6
		mask := uint64(1) << (slot & 63)
		if (c.bits[w] & mask) == 0 {
			return "", false
		}
		if c.tags != nil {
			return c.tags[slot], true
		}
		return "", true
	}
	tag, ok := c.sparseSlots[slot]
	return tag, ok
}

func (c *sequenceBitmapChunk) hasAny() bool {
	if c == nil {
		return false
	}
	if c.bits != nil {
		for w := range 1024 {
			if c.bits[w] != 0 {
				return true
			}
		}
		return false
	}
	return len(c.sparseSlots) > 0
}

func (c *sequenceBitmapChunk) countBits() int64 {
	if c == nil {
		return 0
	}
	if c.bits != nil {
		var total int64
		for w := range 1024 {
			total += int64(bits.OnesCount64(c.bits[w]))
		}
		return total
	}
	return int64(len(c.sparseSlots))
}

func (c *sequenceBitmapChunk) exactTagBytes() int64 {
	if !c.isTagged() {
		return 0
	}
	var total int64
	c.forEachSlot(func(_ uint16, tag string) {
		if tag != "" {
			total += exactTagEntryBytes(tag)
		}
	})
	return total
}

func (c *sequenceBitmapChunk) setSlot(slot uint16, hasTag bool, tag string) {
	if c.bits != nil {
		w := slot >> 6
		c.bits[w] |= uint64(1) << (slot & 63)
		if hasTag && c.tags != nil {
			c.tags[slot] = tag
		}
		return
	}
	if c.sparseSlots == nil {
		c.sparseSlots = make(map[uint16]string)
	}
	var val string
	if hasTag {
		val = tag
	}
	c.sparseSlots[slot] = val
	thresh := sparseUntaggedPromoteThreshold
	if c.hasTags {
		thresh = sparseTaggedPromoteThreshold
	}
	if len(c.sparseSlots) >= thresh {
		c.promoteToDense()
	}
}

func (c *sequenceBitmapChunk) promoteToDense() {
	if c.bits != nil {
		return
	}
	c.bits = new([1024]uint64)
	if c.hasTags && c.tags == nil {
		c.tags = new([65536]string)
	}
	for slot, tag := range c.sparseSlots {
		w := slot >> 6
		c.bits[w] |= uint64(1) << (slot & 63)
		if c.tags != nil && tag != "" {
			c.tags[slot] = tag
		}
	}
	c.sparseSlots = nil
}

func (c *sequenceBitmapChunk) cloneChunk() *sequenceBitmapChunk {
	if c == nil {
		return nil
	}
	if c.bits != nil {
		bitsCopy := *c.bits
		var tagsCopy *[65536]string
		if c.tags != nil {
			tc := *c.tags
			tagsCopy = &tc
		}
		return &sequenceBitmapChunk{
			hasTags: c.hasTags,
			bits:    &bitsCopy,
			tags:    tagsCopy,
		}
	}
	sp := make(map[uint16]string, len(c.sparseSlots))
	maps.Copy(sp, c.sparseSlots)
	return &sequenceBitmapChunk{
		hasTags:     c.hasTags,
		sparseSlots: sp,
	}
}

func (c *sequenceBitmapChunk) forEachSlot(fn func(slot uint16, tag string)) {
	if c == nil {
		return
	}
	if c.bits != nil {
		for w := range 1024 {
			word := c.bits[w]
			for m := word; m != 0; m &= m - 1 {
				slot := uint16(w*64 + bits.TrailingZeros64(m))
				var tag string
				if c.tags != nil {
					tag = c.tags[slot]
				}
				fn(slot, tag)
			}
		}
		return
	}
	for slot, tag := range c.sparseSlots {
		fn(slot, tag)
	}
}

type extractedSequenceKey struct {
	domain       uint8
	identityHash uint64
	seq          uint64
	hasTag       bool
	tag          string
	ok           bool
}

type sequenceKeyFieldDescriptors struct {
	timestamp        protoreflect.FieldDescriptor
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
	traceID          protoreflect.FieldDescriptor
	spanID           protoreflect.FieldDescriptor
	insertID         protoreflect.FieldDescriptor
}

func lookupSequenceKeyFields(desc protoreflect.MessageDescriptor) sequenceKeyFieldDescriptors {
	if desc == nil {
		return sequenceKeyFieldDescriptors{}
	}
	f := desc.Fields()
	return sequenceKeyFieldDescriptors{
		timestamp:        f.ByName("timestamp"),
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
		traceID:          f.ByName("trace_id"),
		spanID:           f.ByName("span_id"),
		insertID:         f.ByName("insert_id"),
	}
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

func isLogRowDescriptor(fds sequenceKeyFieldDescriptors) bool {
	return fds.metricName == nil &&
		fds.pointFingerprint == nil &&
		fds.startTimeNano == nil &&
		fds.timeNano != nil &&
		(fds.logName != nil || fds.severityNumber != nil || fds.insertID != nil)
}

func isNullInsertIDLog(msg protoreflect.Message, fds sequenceKeyFieldDescriptors) bool {
	return msg != nil && msg.IsValid() && isLogRowDescriptor(fds) && (fds.insertID == nil || !msg.Has(fds.insertID))
}

func genAILogStreamIdentityHashValues(svc, logName string, hasSev bool, sev int64, treeID uint64) (uint64, bool) {
	if !hasSev || sev != 9 {
		return 0, false
	}
	wantSvc := generatedFrameworkServiceNames[treeID%uint64(len(generatedFrameworkServiceNames))]
	if svc != wantSvc || logName == "" {
		return 0, false
	}
	if logName == svc {
		return 0, true
	}
	return hashLogStreamIdentity(svc, logName, hasSev, sev), true
}

func genAILogStreamIdentityHash(msg protoreflect.Message, fds sequenceKeyFieldDescriptors, treeID uint64) (uint64, bool) {
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	svc, hasSvc := msgStringPresence(msg, fds.serviceName)
	if hasSvc && svc == "" {
		return 0, false
	}
	logName, hasLogName := msgStringPresence(msg, fds.logName)
	if !hasLogName || logName == "" {
		return 0, false
	}
	return genAILogStreamIdentityHashValues(svc, logName, hasSev, sev, treeID)
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

func accessLogStreamIdentityHashValues(svc, logName string, hasSev bool, sev int64, seq uint64) uint64 {
	if hasSev &&
		svc == generatedAccessLogServiceName(seq) &&
		logName == svc &&
		sev == generatedAccessLogSeverity(seq) {
		return 0
	}
	return hashLogStreamIdentity(svc, logName, hasSev, sev)
}

func accessLogStreamIdentityHash(msg protoreflect.Message, fds sequenceKeyFieldDescriptors, seq uint64) uint64 {
	svc := msgString(msg, fds.serviceName)
	logName := msgString(msg, fds.logName)
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	return accessLogStreamIdentityHashValues(svc, logName, hasSev, sev, seq)
}

func hasValidGeneratedAccessLogIdentityValues(svc, logName string, hasSev bool, sev int64) bool {
	if !hasSev || (sev != 9 && sev != 13 && sev != 17) || logName == "" {
		return false
	}
	switch svc {
	case "edge-ingress-gateway", "vpc-flow-proxy", "api-edge-envoy":
		return true
	default:
		return false
	}
}

func hasValidGeneratedAccessLogIdentity(msg protoreflect.Message, fds sequenceKeyFieldDescriptors) bool {
	sev, hasSev := msgInt64(msg, fds.severityNumber)
	svc := msgString(msg, fds.serviceName)
	logName := msgString(msg, fds.logName)
	return hasValidGeneratedAccessLogIdentityValues(svc, logName, hasSev, sev)
}

func extractGeneratedSequenceKey(msg protoreflect.Message, fds sequenceKeyFieldDescriptors) extractedSequenceKey {
	if isLogRowDescriptor(fds) && fds.insertID != nil {
		insertID := msgString(msg, fds.insertID)
		edgeSeq, isEdge := parseEdgeInsertID(insertID)
		isSynthV1 := !isEdge && isSynthesizedInsertIDV1(insertID)
		if !isEdge && !isSynthV1 {
			return extractedSequenceKey{}
		}
		var tag string
		if isSynthV1 {
			tag = insertID
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
		if isEdge {
			if edgeSeq > math.MaxInt64/100_000 || tNano != generatedBaseUnixNano+int64(edgeSeq)*100_000 {
				return extractedSequenceKey{}
			}
		}

		svc, hasSvc := msgStringPresence(msg, fds.serviceName)
		logName, hasLogName := msgStringPresence(msg, fds.logName)
		if (hasSvc && svc == "") || !hasLogName || logName == "" {
			return extractedSequenceKey{}
		}

		traceID, hasTraceID := msgStringPresence(msg, fds.traceID)
		spanID, hasSpanID := msgStringPresence(msg, fds.spanID)
		if hasTraceID || hasSpanID {
			treeID, step, ok := parseGeneratedTreeAndStepHex(traceID, spanID)
			if !ok {
				return extractedSequenceKey{}
			}
			seq := treeID*4 + step
			if seq > math.MaxInt64/100_000 || tNano != generatedBaseUnixNano+int64(seq)*100_000 {
				return extractedSequenceKey{}
			}
			idHash, genOK := genAILogStreamIdentityHash(msg, fds, treeID)
			if !genOK {
				return extractedSequenceKey{}
			}
			if isEdge {
				if edgeSeq != seq {
					return extractedSequenceKey{}
				}
				return extractedSequenceKey{domain: seqDomainLogEdgeTraceStep, identityHash: idHash, seq: seq, ok: true}
			}
			return extractedSequenceKey{domain: seqDomainLogTraceStep, identityHash: idHash, seq: seq, hasTag: true, tag: tag, ok: true}
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
			tag:          tag,
			ok:           true,
		}
	}

	if fds.metricName != nil && fds.timeNano != nil && fds.pointFingerprint != nil {
		tNano, hasTNano := msgInt64(msg, fds.timeNano)
		if !hasTNano || tNano < generatedBaseUnixNano || (tNano-generatedBaseUnixNano)%100_000 != 0 {
			return extractedSequenceKey{}
		}
		seq := uint64((tNano - generatedBaseUnixNano) / 100_000)
		treeID, step := seq/4, seq%4
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
			tag:    pointFP,
			ok:     true,
		}
	}

	if !isLogRowDescriptor(fds) && fds.metricName == nil && fds.startTimeNano != nil && fds.traceID != nil && fds.spanID != nil {
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

func recordUniqueAckedRowWithMultiTags(
	chunks map[sequenceChunkKey]*sequenceBitmapChunk,
	multiTags *map[seqSlotKey]map[string]struct{},
	extraCount *int,
	seen map[[16]byte]struct{},
	sk extractedSequenceKey,
	computeHash func() [16]byte,
	customCap bool,
	limit int,
	currentUnique int64,
	tagBytes *int64,
	maxTagBytes int64,
) (isNew, usedTier2, saturated bool, satLimit int, satUnit string) {
	if sk.ok {
		newBit, fallbackTier2, sat, tier1Limit, tier1Unit := recordTier1SlotWithMultiTags(
			chunks, multiTags, extraCount, sk, customCap, currentUnique, limit, tagBytes, maxTagBytes,
		)
		if !fallbackTier2 {
			return newBit, false, sat, tier1Limit, tier1Unit
		}
	}
	h := computeHash()
	if _, ok := seen[h]; !ok {
		if (customCap && currentUnique >= int64(limit)) || len(seen) >= limit {
			return false, true, true, limit, SaturationUnitRows
		}
		seen[h] = struct{}{}
		return true, true, false, 0, ""
	}
	return false, true, false, 0, ""
}

func recordTier1SlotWithMultiTags(
	chunks map[sequenceChunkKey]*sequenceBitmapChunk,
	multiTags *map[seqSlotKey]map[string]struct{},
	extraCount *int,
	sk extractedSequenceKey,
	customCap bool,
	currentUnique int64,
	limit int,
	tagBytes *int64,
	maxTagBytes int64,
) (isNew, fallbackTier2, saturated bool, satLimit int, satUnit string) {
	key := sequenceChunkKey{domain: sk.domain, identityHash: sk.identityHash, chunk: sk.seq >> 16}
	slot := uint16(sk.seq & 65535)
	extra := 0
	if extraCount != nil {
		extra = *extraCount
	}
	if multiTags != nil && *multiTags != nil {
		if m := (*multiTags)[seqSlotKey{ck: key, slot: slot}]; len(m) > 0 {
			if !sk.hasTag {
				return false, false, false, 0, ""
			}
			if _, exists := m[sk.tag]; exists {
				return false, false, false, 0, ""
			}
			if (customCap && currentUnique >= int64(limit)) || len(*multiTags)+extra >= limit {
				return false, false, true, limit, SaturationUnitRows
			}
			var addBytes int64
			if sk.tag != "" {
				addBytes = exactTagEntryBytes(sk.tag)
				if maxTagBytes > 0 && tagBytes != nil && *tagBytes+addBytes > maxTagBytes {
					return false, false, true, clampLimitToInt(maxTagBytes), SaturationUnitTagBytes
				}
			}
			m[sk.tag] = struct{}{}
			if extraCount != nil {
				*extraCount++
			}
			if tagBytes != nil {
				*tagBytes += addBytes
			}
			return true, false, false, 0, ""
		}
	}
	newBit, collisionOrUntagged, sat, bitSatLimit, bitSatUnit := recordSequenceBit(chunks, sk, customCap, currentUnique, limit, tagBytes, maxTagBytes)
	if !collisionOrUntagged || sat {
		return newBit, false, sat, bitSatLimit, bitSatUnit
	}
	chunk := chunks[key]
	if chunk == nil || !chunk.isTagged() {
		return false, true, false, 0, ""
	}
	existingTag, hasBit := chunk.hasSlot(slot)
	if !hasBit || existingTag == "" {
		return false, true, false, 0, ""
	}
	if customCap && currentUnique >= int64(limit) {
		return false, false, true, limit, SaturationUnitRows
	}
	if multiTags == nil {
		return false, true, false, 0, ""
	}
	curSlots := 0
	if *multiTags != nil {
		curSlots = len(*multiTags)
	}
	if curSlots+extra+2 > limit {
		return false, false, true, limit, SaturationUnitRows
	}
	var addBytes int64
	if sk.tag != "" {
		addBytes = exactTagEntryBytes(sk.tag)
		if maxTagBytes > 0 && tagBytes != nil && *tagBytes+addBytes > maxTagBytes {
			return false, false, true, clampLimitToInt(maxTagBytes), SaturationUnitTagBytes
		}
	}
	if *multiTags == nil {
		*multiTags = make(map[seqSlotKey]map[string]struct{})
	}
	(*multiTags)[seqSlotKey{ck: key, slot: slot}] = map[string]struct{}{
		existingTag: {},
		sk.tag:      {},
	}
	if extraCount != nil {
		*extraCount++
	}
	if tagBytes != nil {
		*tagBytes += addBytes
	}
	return true, false, false, 0, ""
}

func recordSequenceBit(
	chunks map[sequenceChunkKey]*sequenceBitmapChunk,
	sk extractedSequenceKey,
	customCap bool,
	currentUnique int64,
	limit int,
	tagBytes *int64,
	maxTagBytes int64,
) (isNew, fallbackTier2, saturated bool, satLimit int, satUnit string) {
	key := sequenceChunkKey{domain: sk.domain, identityHash: sk.identityHash, chunk: sk.seq >> 16}
	slot := uint16(sk.seq & 65535)
	if chunk := chunks[key]; chunk != nil {
		if existingTag, hasBit := chunk.hasSlot(slot); hasBit {
			if sk.hasTag && (!chunk.isTagged() || existingTag != sk.tag) {
				return false, true, false, 0, ""
			}
			return false, false, false, 0, ""
		}
	}
	if customCap && currentUnique >= int64(limit) {
		return false, false, true, limit, SaturationUnitRows
	}
	chunk := chunks[key]
	if chunk == nil {
		if len(chunks) >= DefaultMaxSequenceBitmapChunks {
			return false, false, true, DefaultMaxSequenceBitmapChunks * 65536, SaturationUnitRows
		}
		if sk.hasTag && countTaggedChunks(chunks) >= DefaultMaxTaggedSequenceBitmapChunks {
			return false, false, true, DefaultMaxTaggedSequenceBitmapChunks * 65536, SaturationUnitRows
		}
	} else if sk.hasTag && !chunk.isTagged() {
		// Defensive fallback if an untagged chunk unexpectedly exists under key.
		return false, true, false, 0, ""
	}
	var addBytes int64
	if sk.hasTag && sk.tag != "" {
		addBytes = exactTagEntryBytes(sk.tag)
		if maxTagBytes > 0 && tagBytes != nil && *tagBytes+addBytes > maxTagBytes {
			return false, false, true, clampLimitToInt(maxTagBytes), SaturationUnitTagBytes
		}
	}
	if chunk == nil {
		chunk = &sequenceBitmapChunk{hasTags: sk.hasTag}
		chunks[key] = chunk
	}
	chunk.setSlot(slot, sk.hasTag, sk.tag)
	if tagBytes != nil {
		*tagBytes += addBytes
	}
	return true, false, false, 0, ""
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

func msgStringPresence(msg protoreflect.Message, fd protoreflect.FieldDescriptor) (string, bool) {
	if fd == nil || fd.Kind() != protoreflect.StringKind || !msg.Has(fd) {
		return "", false
	}
	return msg.Get(fd).String(), true
}

func writeHashPresenceInt64(h io.Writer, has bool, v int64) {
	var buf [9]byte
	if has {
		buf[0] = 1
		binary.LittleEndian.PutUint64(buf[1:], uint64(v))
	}
	_, _ = h.Write(buf[:])
}

func writeHashPresenceStr(h io.Writer, has bool, s string) {
	if !has {
		_, _ = h.Write([]byte{0})
		return
	}
	var hdr [9]byte
	hdr[0] = 1
	binary.LittleEndian.PutUint64(hdr[1:], uint64(len(s)))
	_, _ = h.Write(hdr[:])
	_, _ = io.WriteString(h, s)
}

// hashSpanDedupKey computes the SHA-256 identity matching SpansDedupViewQuery:
// PARTITION BY start_time, start_time_unix_nano, service_name, trace_id, span_id, name.
func hashSpanDedupKey(
	startTime int64, hasStartTime bool,
	startTimeNano int64, hasStartTimeNano bool,
	serviceName string, hasServiceName bool,
	traceID string, hasTraceID bool,
	spanID string, hasSpanID bool,
	spanName string, hasSpanName bool,
) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("span-dedup-v1\x00"))
	writeHashPresenceInt64(h, hasStartTime, startTime)
	writeHashPresenceInt64(h, hasStartTimeNano, startTimeNano)
	writeHashPresenceStr(h, hasServiceName, serviceName)
	writeHashPresenceStr(h, hasTraceID, traceID)
	writeHashPresenceStr(h, hasSpanID, spanID)
	writeHashPresenceStr(h, hasSpanName, spanName)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// hashLogDedupKey computes the SHA-256 identity matching LogsDedupViewQuery:
// PARTITION BY timestamp, time_unix_nano, service_name, trace_id, span_id,
// severity_number, log_name, insert_id.
func hashLogDedupKey(
	ts int64, hasTS bool,
	timeNano int64, hasTimeNano bool,
	serviceName string, hasServiceName bool,
	traceID string, hasTraceID bool,
	spanID string, hasSpanID bool,
	severityNumber int64, hasSeverityNumber bool,
	logName string, hasLogName bool,
	insertID string, hasInsertID bool,
) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("log-dedup-v1\x00"))
	writeHashPresenceInt64(h, hasTS, ts)
	writeHashPresenceInt64(h, hasTimeNano, timeNano)
	writeHashPresenceStr(h, hasServiceName, serviceName)
	writeHashPresenceStr(h, hasTraceID, traceID)
	writeHashPresenceStr(h, hasSpanID, spanID)
	writeHashPresenceInt64(h, hasSeverityNumber, severityNumber)
	writeHashPresenceStr(h, hasLogName, logName)
	writeHashPresenceStr(h, hasInsertID, insertID)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// hashMetricDedupKey computes the SHA-256 identity matching MetricsDedupViewQuery:
// PARTITION BY timestamp, time_unix_nano, service_name, metric_name,
// metric_type, point_fingerprint.
func hashMetricDedupKey(
	ts int64, hasTS bool,
	timeNano int64, hasTimeNano bool,
	serviceName string, hasServiceName bool,
	metricName string, hasMetricName bool,
	metricType string, hasMetricType bool,
	pointFingerprint string, hasPointFingerprint bool,
) [32]byte {
	h := sha256.New()
	_, _ = h.Write([]byte("metric-dedup-v1\x00"))
	writeHashPresenceInt64(h, hasTS, ts)
	writeHashPresenceInt64(h, hasTimeNano, timeNano)
	writeHashPresenceStr(h, hasServiceName, serviceName)
	writeHashPresenceStr(h, hasMetricName, metricName)
	writeHashPresenceStr(h, hasMetricType, metricType)
	writeHashPresenceStr(h, hasPointFingerprint, pointFingerprint)
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// hashDedupIdentityWithFallback hashes only the destination _dedup view
// PARTITION BY columns for OTel logs, metrics, and spans, falling back to full
// canonical message hashing for arbitrary non-OTel schemas.
func hashDedupIdentityWithFallback(
	msg protoreflect.Message,
	fds sequenceKeyFieldDescriptors,
	raw []byte,
	ignore [3]protowire.Number,
) [32]byte {
	if msg != nil && msg.IsValid() {
		if isLogRowDescriptor(fds) {
			ts, hasTS := msgInt64(msg, fds.timestamp)
			tNano, hasTNano := msgInt64(msg, fds.timeNano)
			svc, hasSvc := msgStringPresence(msg, fds.serviceName)
			traceID, hasTraceID := msgStringPresence(msg, fds.traceID)
			spanID, hasSpanID := msgStringPresence(msg, fds.spanID)
			sev, hasSev := msgInt64(msg, fds.severityNumber)
			logName, hasLogName := msgStringPresence(msg, fds.logName)
			insertID, hasInsertID := msgStringPresence(msg, fds.insertID)
			return hashLogDedupKey(
				ts, hasTS,
				tNano, hasTNano,
				svc, hasSvc,
				traceID, hasTraceID,
				spanID, hasSpanID,
				sev, hasSev,
				logName, hasLogName,
				insertID, hasInsertID,
			)
		}
		if fds.metricName != nil && fds.timeNano != nil && (fds.pointFingerprint != nil || fds.metricType != nil) {
			ts, hasTS := msgInt64(msg, fds.timestamp)
			tNano, hasTNano := msgInt64(msg, fds.timeNano)
			svc, hasSvc := msgStringPresence(msg, fds.serviceName)
			metricName, hasMetricName := msgStringPresence(msg, fds.metricName)
			metricType, hasMetricType := msgStringPresence(msg, fds.metricType)
			fp, hasFP := msgStringPresence(msg, fds.pointFingerprint)
			return hashMetricDedupKey(
				ts, hasTS,
				tNano, hasTNano,
				svc, hasSvc,
				metricName, hasMetricName,
				metricType, hasMetricType,
				fp, hasFP,
			)
		}
		if !isLogRowDescriptor(fds) && fds.metricName == nil && fds.startTimeNano != nil && fds.traceID != nil && fds.spanID != nil {
			st, hasST := msgInt64(msg, fds.startTime)
			stNano, hasSTNano := msgInt64(msg, fds.startTimeNano)
			svc, hasSvc := msgStringPresence(msg, fds.serviceName)
			traceID, hasTraceID := msgStringPresence(msg, fds.traceID)
			spanID, hasSpanID := msgStringPresence(msg, fds.spanID)
			spanName, hasSpanName := msgStringPresence(msg, fds.spanName)
			return hashSpanDedupKey(
				st, hasST,
				stNano, hasSTNano,
				svc, hasSvc,
				traceID, hasTraceID,
				spanID, hasSpanID,
				spanName, hasSpanName,
			)
		}
	}
	return hashCanonicalMessageWithFallback(msg, raw, ignore)
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
		if !found && faultMatchesTable(f.Table, table) {
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
		if bare := bareTableName(table); bare != "" && bare != table {
			matchedKey = bare
			pf = s.periodicFaults[bare]
		}
	}
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

// CanonicalTableKey returns the canonical qualified Storage Write table
// identifier "projects/<project>/datasets/<dataset>/tables/<table>" when
// project and dataset are non-empty, or the trimmed bare table name otherwise.
func CanonicalTableKey(project, dataset, table string) string {
	project = strings.TrimSpace(project)
	dataset = strings.TrimSpace(dataset)
	table = strings.TrimSpace(table)
	if project == "" || dataset == "" || table == "" {
		return table
	}
	return "projects/" + project + "/datasets/" + dataset + "/tables/" + table
}

func isQualifiedTableKey(table string) bool {
	return strings.HasPrefix(table, "projects/")
}

func bareTableName(table string) string {
	if table == "" {
		return ""
	}
	if _, _, tbl, ok := parseQualifiedTableName(table); ok {
		return tbl
	}
	if idx := strings.LastIndex(table, "/tables/"); idx >= 0 {
		rest := table[idx+len("/tables/"):]
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			return rest[:slash]
		}
		return rest
	}
	return table
}

func tableKeyMatches(query, candidate string) bool {
	if query == "" {
		return true
	}
	if candidate == "" {
		return false
	}
	if isQualifiedTableKey(query) {
		return candidate == query
	}
	return candidate == query || bareTableName(candidate) == query
}

func faultMatchesTable(faultTable, targetTable string) bool {
	if faultTable == "" || targetTable == "" {
		return true
	}
	if isQualifiedTableKey(faultTable) && isQualifiedTableKey(targetTable) {
		return faultTable == targetTable
	}
	return bareTableName(faultTable) == bareTableName(targetTable)
}

func parseQualifiedTableName(resource string) (project, dataset, table string, ok bool) {
	parts := strings.Split(resource, "/")
	for i := 0; i+5 < len(parts); i++ {
		if parts[i] == "projects" && parts[i+2] == "datasets" && parts[i+4] == "tables" {
			p, d, t := parts[i+1], parts[i+3], parts[i+5]
			if p != "" && d != "" && t != "" {
				return p, d, t, true
			}
		}
	}
	return "", "", "", false
}

func parseQualifiedTableFromStream(streamName string) (qualified, bare string) {
	if p, d, t, ok := parseQualifiedTableName(streamName); ok {
		return CanonicalTableKey(p, d, t), t
	}
	t := parseTableFromStream(streamName)
	return t, t
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
			_ = s.registerTableSchemaLocked(CanonicalTableKey(project, datasetID, tableID), fromRESTTableSchema(tbl.Schema))
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
				_ = s.registerTableSchemaLocked(CanonicalTableKey(project, datasetID, tableID), fromRESTTableSchema(existing.Schema))
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
