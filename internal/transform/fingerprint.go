// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package transform // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"math"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// PreserveLogOrdinalPeers widens the log records to retry with
// SynthesizeInsertID=true so retrying them reproduces their synthesized
// insert_ids from the original batch.
func PreserveLogOrdinalPeers(ld plog.Logs, candidateIndices, retryableIndices []int) []int {
	return PreserveLogOrdinalPeersForContract(ld, candidateIndices, retryableIndices, Options{
		SynthesizeInsertID: true,
	})
}

// traceIDString renders a trace ID as lowercase hex, or empty when unset.
// Empty is distinct from a zero ID: OTLP uses an all-zero ID to mean absent.
func traceIDString(id pcommon.TraceID) string {
	if id.IsEmpty() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

func spanIDString(id pcommon.SpanID) string {
	if id.IsEmpty() {
		return ""
	}
	return hex.EncodeToString(id[:])
}

// Type tags for incremental streaming SHA-256 over OTLP AnyValue / Map without
// building intermediate JSON strings or *_schema sidecars.
const (
	hashTagString = 'S'
	hashTagInt    = 'I'
	hashTagDouble = 'D'
	hashTagBool   = 'B'
	hashTagBytes  = 'Y'
	hashTagSlice  = 'A'
	hashTagMap    = 'M'
	hashTagEmpty  = 'E'
)

type hashMapEntry struct {
	key string
	val pcommon.Value
}

var hashEntriesPool = sync.Pool{
	New: func() any {
		s := make([]hashMapEntry, 0, 16)
		return &s
	},
}

func acquireHashEntries(n int) *[]hashMapEntry {
	p := hashEntriesPool.Get().(*[]hashMapEntry)
	s := (*p)[:0]
	if cap(s) < n {
		s = make([]hashMapEntry, 0, n)
	}
	*p = s
	return p
}

func releaseHashEntries(p *[]hashMapEntry) {
	s := *p
	clear(s)
	if cap(s) <= 256 {
		*p = s[:0]
		hashEntriesPool.Put(p)
	}
}

func writeHashByte(h hash.Hash, b byte) {
	var one [1]byte
	one[0] = b
	_, _ = h.Write(one[:])
}

func writeHashUint64(h hash.Hash, v uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	_, _ = h.Write(buf[:])
}

func writeHashLenStr(h hash.Hash, s string) {
	writeHashUint64(h, uint64(len(s)))
	var buf [256]byte
	for len(s) > 0 {
		n := copy(buf[:], s)
		_, _ = h.Write(buf[:n])
		s = s[n:]
	}
}

func writeHashLenBytes(h hash.Hash, b []byte) {
	writeHashUint64(h, uint64(len(b)))
	if len(b) > 0 {
		_, _ = h.Write(b)
	}
}

func writeHashFieldStr(h hash.Hash, name, val string) {
	writeHashLenStr(h, name)
	writeHashLenStr(h, val)
}

func writeHashFieldBytes(h hash.Hash, name string, val []byte) {
	writeHashLenStr(h, name)
	writeHashLenBytes(h, val)
}

func writeHashFieldUint64(h hash.Hash, name string, val uint64) {
	writeHashLenStr(h, name)
	writeHashUint64(h, val)
}

func writeHashFieldInt64(h hash.Hash, name string, val int64) {
	writeHashLenStr(h, name)
	writeHashUint64(h, uint64(val))
}

var canonicalNaNBits = math.Float64bits(math.NaN())

func writeHashFieldFloat64(h hash.Hash, name string, val float64) {
	writeHashLenStr(h, name)
	if math.IsNaN(val) {
		writeHashUint64(h, canonicalNaNBits)
		return
	}
	writeHashUint64(h, math.Float64bits(val))
}

func writeHashFieldTaggedValue(h hash.Hash, name string, v pcommon.Value) {
	writeHashLenStr(h, name)
	writeHashTaggedValue(h, v)
}

func writeHashFieldTaggedMap(h hash.Hash, name string, m pcommon.Map) {
	writeHashLenStr(h, name)
	writeHashTaggedMap(h, m)
}

func writeHashTaggedValue(h hash.Hash, v pcommon.Value) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		writeHashByte(h, hashTagString)
		writeHashLenStr(h, sanitizeFast(v.Str()))

	case pcommon.ValueTypeInt:
		writeHashByte(h, hashTagInt)
		writeHashUint64(h, uint64(v.Int()))

	case pcommon.ValueTypeDouble:
		writeHashByte(h, hashTagDouble)
		f := v.Double()
		if math.IsNaN(f) {
			writeHashUint64(h, canonicalNaNBits)
		} else {
			writeHashUint64(h, math.Float64bits(f))
		}

	case pcommon.ValueTypeBool:
		writeHashByte(h, hashTagBool)
		if v.Bool() {
			writeHashByte(h, 1)
		} else {
			writeHashByte(h, 0)
		}

	case pcommon.ValueTypeBytes:
		writeHashByte(h, hashTagBytes)
		writeHashLenBytes(h, v.Bytes().AsRaw())

	case pcommon.ValueTypeSlice:
		writeHashByte(h, hashTagSlice)
		s := v.Slice()
		writeHashUint64(h, uint64(s.Len()))
		for i := 0; i < s.Len(); i++ {
			writeHashTaggedValue(h, s.At(i))
		}

	case pcommon.ValueTypeMap:
		writeHashTaggedMap(h, v.Map())

	default:
		writeHashByte(h, hashTagEmpty)
	}
}

func writeHashTaggedMap(h hash.Hash, m pcommon.Map) {
	writeHashByte(h, hashTagMap)
	if m.Len() == 0 {
		writeHashUint64(h, 0)
		return
	}
	ep := acquireHashEntries(m.Len())
	defer releaseHashEntries(ep)
	entries := (*ep)[:0]
	for k, v := range m.All() {
		entries = append(entries, hashMapEntry{key: sanitizeFast(k), val: v})
	}
	slices.SortStableFunc(entries, func(a, b hashMapEntry) int {
		return strings.Compare(a.key, b.key)
	})
	entries = slices.CompactFunc(entries, func(a, b hashMapEntry) bool {
		return a.key == b.key
	})
	*ep = entries

	writeHashUint64(h, uint64(len(entries)))
	for _, e := range entries {
		writeHashLenStr(h, e.key)
		writeHashTaggedValue(h, e.val)
	}
}

func sanitizeFast(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			if utf8.ValidString(s[i:]) {
				return s
			}
			return strings.ToValidUTF8(s, "\uFFFD")
		}
	}
	return s
}

func finalizeSHA256(h hash.Hash, onSHA256 func()) [32]byte {
	var sum [32]byte
	h.Sum(sum[:0])
	if onSHA256 != nil {
		onSHA256()
	}
	return sum
}

func hashOriginV1(
	h hash.Hash,
	res pcommon.Resource,
	resSchemaURL string,
	scope pcommon.InstrumentationScope,
	scopeSchemaURL string,
	onSHA256 func(),
) [32]byte {
	h.Reset()
	writeHashFieldTaggedMap(h, "resource.attributes", res.Attributes())
	writeHashFieldInt64(h, "resource.dropped_attributes_count", int64(res.DroppedAttributesCount()))
	writeHashFieldStr(h, "resource_schema_url", sanitizeFast(resSchemaURL))

	writeHashFieldStr(h, "instrumentation_scope.name", sanitizeFast(scope.Name()))
	writeHashFieldStr(h, "instrumentation_scope.version", sanitizeFast(scope.Version()))
	writeHashFieldTaggedMap(h, "instrumentation_scope.attributes", scope.Attributes())
	writeHashFieldInt64(h, "instrumentation_scope.dropped_attributes_count", int64(scope.DroppedAttributesCount()))
	writeHashFieldStr(h, "scope_schema_url", sanitizeFast(scopeSchemaURL))
	return finalizeSHA256(h, onSHA256)
}

func hashLogRecordDigestV1(
	h hash.Hash,
	lr plog.LogRecord,
	originDigest [32]byte,
	ordinal int,
	onSHA256 func(),
) [32]byte {
	h.Reset()
	writeHashFieldStr(h, "version", schema.InsertIDPrefixV1)
	writeHashFieldUint64(h, "time_unix_nano", uint64(lr.Timestamp()))
	writeHashFieldUint64(h, "observed_time_unix_nano", uint64(lr.ObservedTimestamp()))
	writeHashFieldStr(h, "trace_id", traceIDString(lr.TraceID()))
	writeHashFieldStr(h, "span_id", spanIDString(lr.SpanID()))
	writeHashFieldUint64(h, "flags", uint64(lr.Flags()))
	writeHashFieldStr(h, "event_name", sanitizeFast(lr.EventName()))
	writeHashFieldInt64(h, "severity_number", int64(lr.SeverityNumber()))
	writeHashFieldStr(h, "severity_text", sanitizeFast(lr.SeverityText()))
	writeHashFieldTaggedValue(h, "body", lr.Body())
	writeHashFieldTaggedMap(h, "attributes", lr.Attributes())
	writeHashFieldInt64(h, "dropped_attributes_count", int64(lr.DroppedAttributesCount()))
	writeHashFieldBytes(h, "origin_digest", originDigest[:])
	writeHashFieldInt64(h, "intra_batch_ordinal", int64(ordinal))
	return finalizeSHA256(h, onSHA256)
}

func formatInsertIDV1(sum [32]byte) string {
	var buf [26]byte
	copy(buf[:4], schema.InsertIDPrefixV1)
	base64.RawURLEncoding.Encode(buf[4:], sum[:16])
	return string(buf[:])
}

type fingerprinterV1 map[[32]byte]int

func (f fingerprinterV1) nextLogInsertID(
	h hash.Hash,
	lr plog.LogRecord,
	originDigest [32]byte,
	onSHA256 func(),
) string {
	first := hashLogRecordDigestV1(h, lr, originDigest, 0, onSHA256)
	ordinal := f[first]
	f[first] = ordinal + 1
	if ordinal == 0 {
		return formatInsertIDV1(first)
	}
	return formatInsertIDV1(hashLogRecordDigestV1(h, lr, originDigest, ordinal, onSHA256))
}

func (f fingerprinterV1) nextMetricFingerprint(hashOrdinal func(int) [32]byte) string {
	first := hashOrdinal(0)
	ordinal := f[first]
	f[first] = ordinal + 1
	var sum [32]byte
	if ordinal == 0 {
		sum = first
	} else {
		sum = hashOrdinal(ordinal)
	}
	return schema.FingerprintPrefix + hex.EncodeToString(sum[:])
}

// AllLogsHaveExplicitInsertID reports whether every log record at indices in ld
// carries a non-empty upstream insert_id attribute (configured insertIDAttr or
// well-known insertIDAttrs).
func AllLogsHaveExplicitInsertID(ld plog.Logs, indices []int, insertIDAttr string) bool {
	if len(indices) == 0 {
		return true
	}
	need := indexSet(indices)
	matched := 0
	idx := -1
	for _, rl := range ld.ResourceLogs().All() {
		for _, sl := range rl.ScopeLogs().All() {
			for _, lr := range sl.LogRecords().All() {
				idx++
				if !need[idx] {
					continue
				}
				if firstStringAttr(lr.Attributes(), insertIDAttr, insertIDAttrs) == "" {
					return false
				}
				matched++
				if matched == len(need) {
					return true
				}
			}
		}
	}
	return matched == len(need)
}

// PreserveLogOrdinalPeersForContract is the contract-aware counterpart of
// PreserveLogOrdinalPeers. Under ContractV1Candidate, records with an explicit
// upstream insert_id or when !opts.SynthesizeInsertID never depend on
// intra-batch ordinal hashing, so they neither pull in nor require peer records.
func PreserveLogOrdinalPeersForContract(
	ld plog.Logs,
	candidateIndices, retryableIndices []int,
	opts Options,
) []int {
	if len(retryableIndices) == 0 {
		return nil
	}
	if !opts.SynthesizeInsertID || len(candidateIndices) == 0 {
		return retryableIndices
	}
	if AllLogsHaveExplicitInsertID(ld, retryableIndices, opts.InsertIDAttribute) {
		return retryableIndices
	}
	candidate := indexSet(candidateIndices)
	retryable := indexSet(retryableIndices)

	allCandidatesRetried := true
	for _, c := range candidateIndices {
		if !retryable[c] {
			allCandidatesRetried = false
			break
		}
	}
	if allCandidatesRetried {
		return retryableIndices
	}

	type member struct {
		idx      int
		explicit bool
		group    [32]byte
	}
	members := make([]member, 0, len(candidateIndices))
	retried := make(map[[32]byte]bool)
	h := sha256.New()

	idx := -1
	for _, rl := range ld.ResourceLogs().All() {
		res := rl.Resource()
		for _, sl := range rl.ScopeLogs().All() {
			scope := sl.Scope()
			var originDigest [32]byte
			hasOrigin := false
			for _, lr := range sl.LogRecords().All() {
				idx++
				if !candidate[idx] && !retryable[idx] {
					continue
				}
				if firstStringAttr(lr.Attributes(), opts.InsertIDAttribute, insertIDAttrs) != "" {
					members = append(members, member{idx: idx, explicit: true})
					continue
				}
				if !hasOrigin {
					originDigest = hashOriginV1(h, res, rl.SchemaUrl(), scope, sl.SchemaUrl(), opts.onSHA256)
					hasOrigin = true
				}
				group := hashLogRecordDigestV1(h, lr, originDigest, 0, opts.onSHA256)
				members = append(members, member{idx: idx, group: group})
				if retryable[idx] {
					retried[group] = true
				}
			}
		}
	}

	out := make([]int, 0, len(members))
	for _, m := range members {
		if retryable[m.idx] || (!m.explicit && retried[m.group]) {
			out = append(out, m.idx)
		}
	}
	return out
}
