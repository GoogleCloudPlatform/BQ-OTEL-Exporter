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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/otlpjson"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// sha256OpCount counts SHA-256 finalizations performed by transform helpers so
// tests can prove zero-hash fast paths (e.g. trusted upstream insert_id and
// SynthesizeInsertID=false).
var sha256OpCount atomic.Int64

// LogFingerprint computes the record_fingerprint of a log record:
//
//	"fp1:" + lowercase_hex(SHA-256(canonical_log_record))
//
// canonical is the record's canonical form from canonicalLogRecord, and
// ordinal is its intra_batch_ordinal: the 0-based count of records with the
// same canonical form before it in the same export batch. The canonical log
// record that is hashed is canonical followed by the ordinal. The ordinal is
// what keeps identical records within one batch apart, while a retry of the
// batch, which repeats its records in the same order, reproduces every
// fingerprint.
func LogFingerprint(canonical string, ordinal int) string {
	var b strings.Builder
	b.WriteString(canonical)
	writeField(&b, "intra_batch_ordinal", strconv.Itoa(ordinal))
	sha256OpCount.Add(1)
	sum := sha256.Sum256([]byte(b.String()))
	return schema.FingerprintPrefix + hex.EncodeToString(sum[:])
}

// fingerprinter assigns fingerprints across one export batch, counting the
// records seen so far per canonical form to derive each intra_batch_ordinal.
// It is keyed by the ordinal-0 fingerprint rather than the canonical form, so
// memory stays bounded by the record count, not the payload size, and a
// record seen for the first time costs a single hash.
type fingerprinter map[string]int

// next returns the fingerprint of the next record with the given canonical
// form.
func (f fingerprinter) next(canonical string) string {
	first := LogFingerprint(canonical, 0)
	ordinal := f[first]
	f[first] = ordinal + 1
	if ordinal == 0 {
		return first
	}
	return LogFingerprint(canonical, ordinal)
}

// PreserveLogOrdinalPeers widens the log records to retry so that retrying
// them reproduces the fingerprints they had in the original batch.
//
// A record's fingerprint, and the insert_id that defaults to it, encodes its
// intra_batch_ordinal: how many records of the same canonical form precede it
// in the batch. LogRows fingerprints a retry payload from scratch, so leaving
// out an acknowledged record that is identical to a retried one shifts the
// retried record's ordinal down onto the acknowledged copy's. The retried
// record would then be written under the acknowledged copy's insert_id, and
// the dedup view would collapse two distinct records into one.
//
// candidateIndices lists every record of the batch that was sent and not
// permanently rejected, and retryableIndices the ones among them that still
// need delivering. Both are flattened positions in ld, the numbering SelectLogs
// and the rejections of LogRows use. Candidates must be records LogRows kept,
// since only those take part in the ordinal count.
//
// The result is, in ascending order, the retried records plus every other
// candidate that shares a canonical form with one of them, so the identical
// records ahead of a retried record travel with it. An acknowledged record
// sent again this way keeps its ordinal, and with it its insert_id, so the
// dedup view absorbs the extra copy. Candidates that share no canonical form
// with a retried record are left out: they are not owed, and no retried
// record's ordinal depends on them. A retried record that is missing from the
// candidates is returned all the same, so a caller's mistake cannot lose it.
// When there is nothing to widen, because no record is retried or every
// candidate is, retryableIndices comes back as given.
//
// The walk and the canonical form mirror LogRows, and must change with it.
func PreserveLogOrdinalPeers(ld plog.Logs, candidateIndices, retryableIndices []int) []int {
	if len(retryableIndices) == 0 {
		return nil
	}
	if len(candidateIndices) == 0 {
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
		idx int
		// group is the ordinal-0 fingerprint, the key the fingerprinter counts
		// ordinals under.
		group string
	}
	members := make([]member, 0, len(candidateIndices))
	retried := make(map[string]bool)

	idx := -1
	for _, rl := range ld.ResourceLogs().All() {
		resource := rl.Resource()
		res := encodeBag(resource.Attributes(), resource.DroppedAttributesCount())

		for _, sl := range rl.ScopeLogs().All() {
			scope := sl.Scope()
			scopeBag := encodeBag(scope.Attributes(), scope.DroppedAttributesCount())
			origin := canonicalOrigin(res, rl.SchemaUrl(), scope, scopeBag, sl.SchemaUrl())

			for _, lr := range sl.LogRecords().All() {
				idx++
				if !candidate[idx] && !retryable[idx] {
					continue
				}
				attrs := encodeBag(lr.Attributes(), lr.DroppedAttributesCount())
				body, bodySchema := otlpjson.EncodePlainValueWithSchema(lr.Body())
				group := LogFingerprint(canonicalLogRecord(lr, attrs, body, bodySchema, origin), 0)
				members = append(members, member{idx: idx, group: group})
				if retryable[idx] {
					retried[group] = true
				}
			}
		}
	}

	out := make([]int, 0, len(members))
	for _, m := range members {
		if retryable[m.idx] || retried[m.group] {
			out = append(out, m.idx)
		}
	}
	return out
}

// canonicalLogRecord renders the part of a log record's canonical form that
// is specific to the record, followed by origin, the part its resource and
// scope contribute, from canonicalOrigin.
//
// It covers every non-derived OTLP field. Values are the plain JSON the row
// stores together with their type schemas, since plain JSON alone would give
// an int 42 and a string "42" the same fingerprint. Times are the raw OTLP
// nanoseconds rather than the truncated microsecond timestamps.
//
// The receive time is deliberately excluded. It is ingestion-local and
// derived: including it would give every retry of the same record a different
// fingerprint, which would defeat the entire mechanism.
func canonicalLogRecord(lr plog.LogRecord, attrs encodedBag, body, bodySchema, origin string) string {
	var b strings.Builder

	// A field-tagged, length-free encoding would be ambiguous across field
	// boundaries, so every component is written with an explicit name and a
	// separator that cannot appear unescaped in the JSON-encoded parts.
	writeField(&b, "version", schema.FingerprintPrefix)
	writeField(&b, "time_unix_nano", strconv.FormatUint(uint64(lr.Timestamp()), 10))
	writeField(&b, "observed_time_unix_nano", strconv.FormatUint(uint64(lr.ObservedTimestamp()), 10))

	writeField(&b, "trace_id", traceIDString(lr.TraceID()))
	writeField(&b, "span_id", spanIDString(lr.SpanID()))
	writeField(&b, "flags", strconv.FormatUint(uint64(lr.Flags()), 10))

	writeField(&b, "event_name", sanitize(lr.EventName()))
	writeField(&b, "severity_number", strconv.FormatInt(int64(lr.SeverityNumber()), 10))
	writeField(&b, "severity_text", sanitize(lr.SeverityText()))
	writeField(&b, "body", body)
	writeField(&b, "body_schema", bodySchema)

	writeField(&b, "attributes", attrs.attributes)
	writeField(&b, "attributes_schema", attrs.schema)
	writeField(&b, "dropped_attributes_count", strconv.FormatInt(attrs.dropped, 10))

	b.WriteString(origin)
	return b.String()
}

// canonicalOrigin renders the part of the canonical form that a resource and
// scope contribute, once for all the log records under them.
func canonicalOrigin(
	res encodedBag,
	resSchemaURL string,
	scope pcommon.InstrumentationScope,
	scopeBag encodedBag,
	scopeSchemaURL string,
) string {
	var b strings.Builder
	writeField(&b, "resource.attributes", res.attributes)
	writeField(&b, "resource.attributes_schema", res.schema)
	writeField(&b, "resource.dropped_attributes_count", strconv.FormatInt(res.dropped, 10))
	writeField(&b, "resource_schema_url", sanitize(resSchemaURL))

	writeField(&b, "instrumentation_scope.name", sanitize(scope.Name()))
	writeField(&b, "instrumentation_scope.version", sanitize(scope.Version()))
	writeField(&b, "instrumentation_scope.attributes", scopeBag.attributes)
	writeField(&b, "instrumentation_scope.attributes_schema", scopeBag.schema)
	writeField(&b, "instrumentation_scope.dropped_attributes_count", strconv.FormatInt(scopeBag.dropped, 10))
	writeField(&b, "scope_schema_url", sanitize(scopeSchemaURL))
	return b.String()
}

// writeField appends one length-prefixed component. The length prefix is what
// makes the encoding unambiguous: without it, moving a character from the end
// of one field to the start of the next would produce the same byte stream.
func writeField(b *strings.Builder, name, value string) {
	b.WriteString(name)
	b.WriteByte('=')
	b.WriteString(strconv.Itoa(len(value)))
	b.WriteByte(':')
	b.WriteString(value)
	b.WriteByte('\n')
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

func finalizeSHA256(h hash.Hash) [32]byte {
	var sum [32]byte
	h.Sum(sum[:0])
	sha256OpCount.Add(1)
	return sum
}

func hashOriginV1(
	h hash.Hash,
	res pcommon.Resource,
	resSchemaURL string,
	scope pcommon.InstrumentationScope,
	scopeSchemaURL string,
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
	return finalizeSHA256(h)
}

func hashLogRecordDigestV1(h hash.Hash, lr plog.LogRecord, originDigest [32]byte, ordinal int) [32]byte {
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
	return finalizeSHA256(h)
}

func formatInsertIDV1(sum [32]byte) string {
	var buf [26]byte
	copy(buf[:4], schema.InsertIDPrefixV1)
	base64.RawURLEncoding.Encode(buf[4:], sum[:16])
	return string(buf[:])
}

type fingerprinterV1 map[[32]byte]int

func (f fingerprinterV1) nextLogInsertID(h hash.Hash, lr plog.LogRecord, originDigest [32]byte) string {
	first := hashLogRecordDigestV1(h, lr, originDigest, 0)
	ordinal := f[first]
	f[first] = ordinal + 1
	if ordinal == 0 {
		return formatInsertIDV1(first)
	}
	return formatInsertIDV1(hashLogRecordDigestV1(h, lr, originDigest, ordinal))
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
	if opts.Contract != schema.ContractV1Candidate {
		return PreserveLogOrdinalPeers(ld, candidateIndices, retryableIndices)
	}
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
					originDigest = hashOriginV1(h, res, rl.SchemaUrl(), scope, sl.SchemaUrl())
					hasOrigin = true
				}
				group := hashLogRecordDigestV1(h, lr, originDigest, 0)
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
