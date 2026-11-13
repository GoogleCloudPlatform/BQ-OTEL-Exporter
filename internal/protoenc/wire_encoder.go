// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package protoenc // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"

import (
	"encoding/hex"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/otlpjson"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

type canonicalTableKind uint8

const (
	tableCustom canonicalTableKind = iota
	tableSpans
	tableLogs
	tableMetrics
	tableQuarantine
)

const maxPooledBufCap = 256 << 10

type encScratch struct {
	row []byte
	sub []byte
}

var scratchPool = sync.Pool{
	New: func() any {
		return &encScratch{
			row: make([]byte, 0, 4096),
			sub: make([]byte, 0, 1024),
		}
	},
}

func acquireScratch() *encScratch {
	s := scratchPool.Get().(*encScratch)
	s.row = s.row[:0]
	s.sub = s.sub[:0]
	return s
}

func releaseScratch(s *encScratch) {
	if cap(s.row) <= maxPooledBufCap && cap(s.sub) <= maxPooledBufCap {
		s.row = s.row[:0]
		s.sub = s.sub[:0]
		scratchPool.Put(s)
	}
}

func detectCanonicalTableKind(ts *storagepb.TableSchema) canonicalTableKind {
	switch {
	case proto.Equal(ts, schema.SpansTableSchema()):
		return tableSpans
	case proto.Equal(ts, schema.LogsTableSchema()):
		return tableLogs
	case proto.Equal(ts, schema.MetricsTableSchema()):
		return tableMetrics
	case proto.Equal(ts, schema.QuarantineTableSchema()):
		return tableQuarantine
	default:
		return tableCustom
	}
}

// SupportsStreaming reports whether e is bound to the canonical table schema
// for signal and can stream pdata inputs directly via protowire without
// intermediate Row maps.
func (e *Encoder) SupportsStreaming(signal string) bool {
	if e == nil {
		return false
	}
	switch signal {
	case schema.SignalSpans:
		return e.kind == tableSpans
	case schema.SignalLogs:
		return e.kind == tableLogs
	case schema.SignalMetrics:
		return e.kind == tableMetrics
	default:
		return false
	}
}

// QuarantineWireInput carries pre-validated fields for one otel_quarantine row.
type QuarantineWireInput struct {
	IngestTimeMicros int64
	Signal           string
	ErrorCode        string
	ErrorMessage     string
	ServiceName      string
	TraceID          string
	SpanID           string
	RawPayload       string
	HasRawAttributes bool
	RawAttributes    string
	HasPayloadRef    bool
	PayloadRef       transform.ObjectRef
	ExporterInstance string
}

// wireFieldPlan stores pre-compiled protoreflect metadata for one message field
// so Encoder.Encode(transform.Row) runs with zero dynamicpb allocations.
type wireFieldPlan struct {
	name     string
	num      protowire.Number
	kind     protoreflect.Kind
	isList   bool
	isPacked bool
	required bool
	nested   *wireMsgPlan
}

type wireMsgPlan struct {
	fields []wireFieldPlan
	byName map[string]struct{}
}

func compileWirePlan(md protoreflect.MessageDescriptor) *wireMsgPlan {
	fds := md.Fields()
	n := fds.Len()
	plan := &wireMsgPlan{
		fields: make([]wireFieldPlan, 0, n),
		byName: make(map[string]struct{}, n),
	}
	for i := 0; i < n; i++ {
		fd := fds.Get(i)
		name := string(fd.Name())
		fp := wireFieldPlan{
			name:     name,
			num:      fd.Number(),
			kind:     fd.Kind(),
			isList:   fd.IsList(),
			isPacked: fd.IsList() && fd.IsPacked(),
			required: fd.Cardinality() == protoreflect.Required,
		}
		if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() {
			fp.nested = compileWirePlan(fd.Message())
		}
		plan.fields = append(plan.fields, fp)
		plan.byName[name] = struct{}{}
	}
	slices.SortFunc(plan.fields, func(a, b wireFieldPlan) int {
		return int(a.num - b.num)
	})
	return plan
}

func encodeRowWithPlan(plan *wireMsgPlan, row transform.Row) ([]byte, error) {
	s := acquireScratch()
	defer releaseScratch(s)
	buf, err := appendWireRow(s.row[:0], plan, row)
	s.row = buf
	if err != nil {
		return nil, err
	}
	if len(buf) == 0 {
		return nil, nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

func appendWireRow(dst []byte, plan *wireMsgPlan, row transform.Row) ([]byte, error) {
	matched := 0
	var missingReq string
	for i := range plan.fields {
		f := &plan.fields[i]
		val, ok := row[f.name]
		if !ok {
			if f.required && missingReq == "" {
				missingReq = f.name
			}
			continue
		}
		matched++
		if f.isList {
			if f.kind != protoreflect.MessageKind {
				var err error
				dst, err = appendRepeatedScalars(dst, f, val)
				if err != nil {
					return dst, err
				}
				continue
			}
			var nested []transform.Row
			switch v := val.(type) {
			case nil:
				continue
			case []transform.Row:
				nested = v
			case []map[string]any:
				nested = make([]transform.Row, len(v))
				for j, item := range v {
					nested[j] = item
				}
			default:
				return dst, fmt.Errorf("column %q: expected a list of rows, got %T", f.name, val)
			}
			for j, item := range nested {
				var err error
				dst, err = appendEmbeddedMessage(dst, f.num, func(b []byte) ([]byte, error) {
					return appendWireRow(b, f.nested, item)
				})
				if err != nil {
					return dst, fmt.Errorf("column %q[%d]: %w", f.name, j, err)
				}
			}
			continue
		}
		if f.kind == protoreflect.MessageKind {
			var nested transform.Row
			switch v := val.(type) {
			case nil:
			case transform.Row:
				nested = v
			case map[string]any:
				nested = v
			default:
				return dst, fmt.Errorf("column %q: expected a row, got %T", f.name, val)
			}
			if nested == nil {
				if f.required && missingReq == "" {
					missingReq = f.name
				}
				continue
			}
			var err error
			dst, err = appendEmbeddedMessage(dst, f.num, func(b []byte) ([]byte, error) {
				return appendWireRow(b, f.nested, nested)
			})
			if err != nil {
				return dst, fmt.Errorf("column %q: %w", f.name, err)
			}
			continue
		}
		if val == nil {
			if f.required {
				return dst, fmt.Errorf("column %q: required scalar cannot be nil", f.name)
			}
			continue
		}
		var err error
		dst, err = appendScalarField(dst, f.num, f.kind, val)
		if err != nil {
			return dst, fmt.Errorf("column %q: %w", f.name, err)
		}
	}
	if matched != len(row) {
		for name := range row {
			if _, ok := plan.byName[name]; !ok {
				return dst, fmt.Errorf("column %q is not present in the destination table schema", name)
			}
		}
	}
	if missingReq != "" {
		return dst, fmt.Errorf("required field %q not set", missingReq)
	}
	return dst, nil
}

func appendEmbeddedMessage(dst []byte, num protowire.Number, fn func([]byte) ([]byte, error)) ([]byte, error) {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	start := len(dst)
	var err error
	dst, err = fn(dst)
	if err != nil {
		return dst, err
	}
	return finalizeLengthPrefix(dst, start), nil
}

func finalizeLengthPrefix(dst []byte, start int) []byte {
	payloadLen := len(dst) - start
	vlen := protowire.SizeVarint(uint64(payloadLen))
	if cap(dst)-len(dst) < vlen {
		dst = slices.Grow(dst, vlen)
	}
	dst = dst[:len(dst)+vlen]
	copy(dst[start+vlen:], dst[start:start+payloadLen])
	protowire.AppendVarint(dst[:start], uint64(payloadLen))
	return dst
}

func appendRepeatedScalars(dst []byte, f *wireFieldPlan, val any) ([]byte, error) {
	if val == nil {
		return dst, nil
	}
	writePacked := func(n int, writeFn func([]byte, int) ([]byte, error)) ([]byte, error) {
		if n == 0 {
			return dst, nil
		}
		if f.isPacked {
			return appendEmbeddedMessage(dst, f.num, func(b []byte) ([]byte, error) {
				var err error
				for i := 0; i < n; i++ {
					b, err = writeFn(b, i)
					if err != nil {
						return b, fmt.Errorf("column %q[%d]: %w", f.name, i, err)
					}
				}
				return b, nil
			})
		}
		var err error
		for i := 0; i < n; i++ {
			dst = protowire.AppendTag(dst, f.num, wireTypeForKind(f.kind))
			dst, err = writeFn(dst, i)
			if err != nil {
				return dst, fmt.Errorf("column %q[%d]: %w", f.name, i, err)
			}
		}
		return dst, nil
	}

	switch s := val.(type) {
	case []any:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []string:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []int64:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []int:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []int32:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []float64:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case []bool:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	case [][]byte:
		return writePacked(len(s), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, s[i])
		})
	default:
		rv := reflect.ValueOf(val)
		if rv.Kind() != reflect.Slice {
			return dst, fmt.Errorf("column %q: expected a slice of %s, got %T", f.name, f.kind, val)
		}
		return writePacked(rv.Len(), func(b []byte, i int) ([]byte, error) {
			return appendScalarValue(b, f.kind, rv.Index(i).Interface())
		})
	}
}

func wireTypeForKind(kind protoreflect.Kind) protowire.Type {
	switch kind {
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType
	case protoreflect.DoubleKind, protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind:
		return protowire.Fixed64Type
	case protoreflect.FloatKind, protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind:
		return protowire.Fixed32Type
	default:
		return protowire.VarintType
	}
}

func appendScalarField(dst []byte, num protowire.Number, kind protoreflect.Kind, val any) ([]byte, error) {
	dst = protowire.AppendTag(dst, num, wireTypeForKind(kind))
	return appendScalarValue(dst, kind, val)
}

func appendScalarValue(dst []byte, kind protoreflect.Kind, val any) ([]byte, error) {
	switch kind {
	case protoreflect.StringKind:
		s, ok := val.(string)
		if !ok {
			return dst, fmt.Errorf("expected string, got %T", val)
		}
		return protowire.AppendString(dst, s), nil

	case protoreflect.Int64Kind:
		switch v := val.(type) {
		case int64:
			return protowire.AppendVarint(dst, uint64(v)), nil
		case int:
			return protowire.AppendVarint(dst, uint64(v)), nil
		default:
			return dst, fmt.Errorf("expected int64, got %T", val)
		}

	case protoreflect.Sint64Kind:
		switch v := val.(type) {
		case int64:
			return protowire.AppendVarint(dst, protowire.EncodeZigZag(v)), nil
		case int:
			return protowire.AppendVarint(dst, protowire.EncodeZigZag(int64(v))), nil
		default:
			return dst, fmt.Errorf("expected int64, got %T", val)
		}

	case protoreflect.Sfixed64Kind:
		switch v := val.(type) {
		case int64:
			return protowire.AppendFixed64(dst, uint64(v)), nil
		case int:
			return protowire.AppendFixed64(dst, uint64(v)), nil
		default:
			return dst, fmt.Errorf("expected int64, got %T", val)
		}

	case protoreflect.Int32Kind:
		v, err := toInt32(val)
		if err != nil {
			return dst, err
		}
		return protowire.AppendVarint(dst, uint64(int64(v))), nil

	case protoreflect.Sint32Kind:
		v, err := toInt32(val)
		if err != nil {
			return dst, err
		}
		return protowire.AppendVarint(dst, protowire.EncodeZigZag(int64(v))), nil

	case protoreflect.Sfixed32Kind:
		v, err := toInt32(val)
		if err != nil {
			return dst, err
		}
		return protowire.AppendFixed32(dst, uint32(v)), nil

	case protoreflect.DoubleKind:
		f, ok := val.(float64)
		if !ok {
			return dst, fmt.Errorf("expected float64, got %T", val)
		}
		return protowire.AppendFixed64(dst, math.Float64bits(f)), nil

	case protoreflect.BoolKind:
		b, ok := val.(bool)
		if !ok {
			return dst, fmt.Errorf("expected bool, got %T", val)
		}
		return protowire.AppendVarint(dst, protowire.EncodeBool(b)), nil

	case protoreflect.BytesKind:
		b, ok := val.([]byte)
		if !ok {
			return dst, fmt.Errorf("expected []byte, got %T", val)
		}
		return protowire.AppendBytes(dst, b), nil

	default:
		return dst, fmt.Errorf("unsupported field kind %s", kind)
	}
}

func toInt32(val any) (int32, error) {
	switch v := val.(type) {
	case int32:
		return v, nil
	case int64:
		if v < math.MinInt32 || v > math.MaxInt32 {
			return 0, fmt.Errorf("int32 overflow: %d out of range [%d, %d]", v, math.MinInt32, math.MaxInt32)
		}
		return int32(v), nil
	case int:
		if int64(v) < math.MinInt32 || int64(v) > math.MaxInt32 {
			return 0, fmt.Errorf("int32 overflow: %d out of range [%d, %d]", v, math.MinInt32, math.MaxInt32)
		}
		return int32(v), nil
	default:
		return 0, fmt.Errorf("expected int32, got %T", val)
	}
}

// --- Direct Zero-Reflection Streaming Encoders for Canonical Tables ---

const (
	spansResourceFieldNum   protowire.Number = 20
	spansScopeFieldNum      protowire.Number = 22
	logsResourceFieldNum    protowire.Number = 18
	logsScopeFieldNum       protowire.Number = 20
	metricsResourceFieldNum protowire.Number = 33
	metricsScopeFieldNum    protowire.Number = 35
)

// EncodeSpanResource encodes the outer `resource` field (field 20) once per ResourceSpans.
func (e *Encoder) EncodeSpanResource(attrs pcommon.Map, dropped uint32) []byte {
	return encodeResourceField(spansResourceFieldNum, attrs, dropped)
}

// EncodeSpanScope encodes the outer `instrumentation_scope` field (field 22) once per ScopeSpans.
func (e *Encoder) EncodeSpanScope(name, version string, attrs pcommon.Map, dropped uint32) []byte {
	return encodeScopeField(spansScopeFieldNum, name, version, attrs, dropped)
}

// EncodeLogResource encodes the outer `resource` field (field 18) once per ResourceLogs.
func (e *Encoder) EncodeLogResource(attrs pcommon.Map, dropped uint32) []byte {
	return encodeResourceField(logsResourceFieldNum, attrs, dropped)
}

// EncodeLogScope encodes the outer `instrumentation_scope` field (field 20) once per ScopeLogs.
func (e *Encoder) EncodeLogScope(name, version string, attrs pcommon.Map, dropped uint32) []byte {
	return encodeScopeField(logsScopeFieldNum, name, version, attrs, dropped)
}

// EncodeMetricResource encodes the outer `resource` field (field 33) once per ResourceMetrics.
func (e *Encoder) EncodeMetricResource(attrs pcommon.Map, dropped uint32) []byte {
	return encodeResourceField(metricsResourceFieldNum, attrs, dropped)
}

// EncodeMetricScope encodes the outer `instrumentation_scope` field (field 35) once per ScopeMetrics.
func (e *Encoder) EncodeMetricScope(name, version string, attrs pcommon.Map, dropped uint32) []byte {
	return encodeScopeField(metricsScopeFieldNum, name, version, attrs, dropped)
}

func encodeResourceField(fieldNum protowire.Number, attrs pcommon.Map, dropped uint32) []byte {
	s := acquireScratch()
	defer releaseScratch(s)
	buf := protowire.AppendTag(s.row[:0], fieldNum, protowire.BytesType)
	start := len(buf)
	buf = appendMapJSONField(&s.sub, buf, 1, attrs)
	buf = appendVarintField(buf, 2, uint64(dropped))
	buf = finalizeLengthPrefix(buf, start)
	s.row = buf
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}

func encodeScopeField(fieldNum protowire.Number, name, version string, attrs pcommon.Map, dropped uint32) []byte {
	s := acquireScratch()
	defer releaseScratch(s)
	buf := protowire.AppendTag(s.row[:0], fieldNum, protowire.BytesType)
	start := len(buf)
	if name != "" {
		buf = appendStringField(buf, 1, name)
	}
	if version != "" {
		buf = appendStringField(buf, 2, version)
	}
	buf = appendMapJSONField(&s.sub, buf, 3, attrs)
	buf = appendVarintField(buf, 4, uint64(dropped))
	buf = finalizeLengthPrefix(buf, start)
	s.row = buf
	out := make([]byte, len(buf))
	copy(out, buf)
	return out
}

// EncodeSpanWire serializes one otel_spans row directly to protobuf wire bytes.
func (e *Encoder) EncodeSpanWire(in *transform.SpanWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	return EncodeSpanWire(in, maxRowBytes)
}

// EncodeSpanWire serializes one otel_spans row directly to protobuf wire bytes
// using pooled buffers and pre-encoded Resource/InstrumentationScope bytes.
func EncodeSpanWire(in *transform.SpanWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	s := acquireScratch()
	defer releaseScratch(s)
	span := in.Span
	start := span.StartTimestamp()
	end := span.EndTimestamp()

	buf := s.row[:0]
	buf = appendVarintField(buf, 1, uint64(micros(start)))
	buf = appendVarintField(buf, 2, uint64(start))
	buf = appendVarintField(buf, 3, uint64(micros(end)))
	buf = appendVarintField(buf, 4, uint64(end))
	buf = appendVarintField(buf, 5, uint64(in.ReceiveTimeMicros))
	buf = appendVarintField(buf, 6, uint64(in.ReceiveTimeUnixNano))
	buf = appendVarintField(buf, 7, uint64(max(0, int64(end)-int64(start))))

	var hexBuf [32]byte
	if tid := span.TraceID(); !tid.IsEmpty() {
		hex.Encode(hexBuf[:32], tid[:])
		buf = appendBytesField(buf, 8, hexBuf[:32])
	} else {
		buf = appendStringField(buf, 8, "")
	}
	if sid := span.SpanID(); !sid.IsEmpty() {
		hex.Encode(hexBuf[:16], sid[:])
		buf = appendBytesField(buf, 9, hexBuf[:16])
	} else {
		buf = appendStringField(buf, 9, "")
	}
	if pid := span.ParentSpanID(); !pid.IsEmpty() {
		hex.Encode(hexBuf[:16], pid[:])
		buf = appendBytesField(buf, 10, hexBuf[:16])
	}
	if ts := sanitizeFast(span.TraceState().AsRaw()); ts != "" {
		buf = appendStringField(buf, 11, ts)
	}
	buf = appendVarintField(buf, 12, uint64(span.Flags()))
	buf = appendStringField(buf, 13, sanitizeFast(span.Name()))
	buf = appendVarintField(buf, 14, uint64(span.Kind()))
	if kn := spanKindName(span.Kind()); kn != "" {
		buf = appendStringField(buf, 15, kn)
	}

	// Field 16: status STRUCT (always present).
	st := span.Status()
	buf = protowire.AppendTag(buf, 16, protowire.BytesType)
	stStart := len(buf)
	buf = appendVarintField(buf, 1, uint64(st.Code()))
	if cn := statusCodeName(st.Code()); cn != "" {
		buf = appendStringField(buf, 2, cn)
	}
	if msg := sanitizeFast(st.Message()); msg != "" {
		buf = appendStringField(buf, 3, msg)
	}
	buf = finalizeLengthPrefix(buf, stStart)

	buf = appendMapJSONField(&s.sub, buf, 17, span.Attributes())
	buf = appendVarintField(buf, 18, uint64(span.DroppedAttributesCount()))
	if in.ServiceName != "" {
		buf = appendStringField(buf, 19, in.ServiceName)
	}
	if len(in.ResourceWire) > 0 {
		buf = append(buf, in.ResourceWire...)
	}
	if in.ResourceSchemaURL != "" {
		buf = appendStringField(buf, 21, in.ResourceSchemaURL)
	}
	if len(in.ScopeWire) > 0 {
		buf = append(buf, in.ScopeWire...)
	}
	if in.ScopeSchemaURL != "" {
		buf = appendStringField(buf, 23, in.ScopeSchemaURL)
	}

	// Field 24: events REPEATED STRUCT.
	events := span.Events()
	for i := 0; i < events.Len(); i++ {
		ev := events.At(i)
		buf = protowire.AppendTag(buf, 24, protowire.BytesType)
		evStart := len(buf)
		if ev.Timestamp() != 0 {
			buf = appendVarintField(buf, 1, uint64(micros(ev.Timestamp())))
		}
		buf = appendVarintField(buf, 2, uint64(ev.Timestamp()))
		buf = appendStringField(buf, 3, sanitizeFast(ev.Name()))
		buf = appendMapJSONField(&s.sub, buf, 4, ev.Attributes())
		buf = appendVarintField(buf, 5, uint64(ev.DroppedAttributesCount()))
		buf = finalizeLengthPrefix(buf, evStart)
	}
	buf = appendVarintField(buf, 25, uint64(span.DroppedEventsCount()))

	// Field 26: links REPEATED STRUCT.
	links := span.Links()
	for i := 0; i < links.Len(); i++ {
		lk := links.At(i)
		buf = protowire.AppendTag(buf, 26, protowire.BytesType)
		lkStart := len(buf)
		if tid := lk.TraceID(); !tid.IsEmpty() {
			hex.Encode(hexBuf[:32], tid[:])
			buf = appendBytesField(buf, 1, hexBuf[:32])
		}
		if sid := lk.SpanID(); !sid.IsEmpty() {
			hex.Encode(hexBuf[:16], sid[:])
			buf = appendBytesField(buf, 2, hexBuf[:16])
		}
		if ts := sanitizeFast(lk.TraceState().AsRaw()); ts != "" {
			buf = appendStringField(buf, 3, ts)
		}
		buf = appendVarintField(buf, 4, uint64(lk.Flags()))
		buf = appendMapJSONField(&s.sub, buf, 5, lk.Attributes())
		buf = appendVarintField(buf, 6, uint64(lk.DroppedAttributesCount()))
		buf = finalizeLengthPrefix(buf, lkStart)
	}
	buf = appendVarintField(buf, 27, uint64(span.DroppedLinksCount()))

	for i := range in.Refs {
		buf = appendObjectRefField(buf, 28, in.Refs[i].ObjectRef)
	}

	s.row = buf
	return finishPooledRow(buf, maxRowBytes)
}

// EncodeLogWire serializes one otel_logs row directly to protobuf wire bytes.
func (e *Encoder) EncodeLogWire(in *transform.LogWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	return EncodeLogWire(in, maxRowBytes)
}

// EncodeLogWire serializes one otel_logs row directly to protobuf wire bytes
// using pooled buffers and pre-encoded Resource/InstrumentationScope bytes.
func EncodeLogWire(in *transform.LogWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	s := acquireScratch()
	defer releaseScratch(s)
	lr := in.Record

	buf := s.row[:0]
	buf = appendVarintField(buf, 1, uint64(in.TimestampMicros))
	buf = appendStringField(buf, 2, in.TimestampSource)
	buf = appendVarintField(buf, 3, uint64(lr.Timestamp()))
	if lr.ObservedTimestamp() != 0 {
		buf = appendVarintField(buf, 4, uint64(micros(lr.ObservedTimestamp())))
	}
	buf = appendVarintField(buf, 5, uint64(lr.ObservedTimestamp()))
	buf = appendVarintField(buf, 6, uint64(in.ReceiveTimeMicros))
	buf = appendVarintField(buf, 7, uint64(in.ReceiveTimeUnixNano))

	var hexBuf [32]byte
	if tid := lr.TraceID(); !tid.IsEmpty() {
		hex.Encode(hexBuf[:32], tid[:])
		buf = appendBytesField(buf, 8, hexBuf[:32])
	}
	if sid := lr.SpanID(); !sid.IsEmpty() {
		hex.Encode(hexBuf[:16], sid[:])
		buf = appendBytesField(buf, 9, hexBuf[:16])
	}
	buf = appendVarintField(buf, 10, uint64(lr.Flags()))
	if in.EventName != "" {
		buf = appendStringField(buf, 11, in.EventName)
	}
	buf = appendVarintField(buf, 12, uint64(lr.SeverityNumber()))
	if st := sanitizeFast(lr.SeverityText()); st != "" {
		buf = appendStringField(buf, 13, st)
	}
	if lr.Body().Type() != pcommon.ValueTypeEmpty {
		buf = appendValueJSONField(&s.sub, buf, 14, lr.Body())
	}
	buf = appendMapJSONField(&s.sub, buf, 15, lr.Attributes())
	buf = appendVarintField(buf, 16, uint64(lr.DroppedAttributesCount()))
	if in.ServiceName != "" {
		buf = appendStringField(buf, 17, in.ServiceName)
	}
	if len(in.ResourceWire) > 0 {
		buf = append(buf, in.ResourceWire...)
	}
	if in.ResourceSchemaURL != "" {
		buf = appendStringField(buf, 19, in.ResourceSchemaURL)
	}
	if len(in.ScopeWire) > 0 {
		buf = append(buf, in.ScopeWire...)
	}
	if in.ScopeSchemaURL != "" {
		buf = appendStringField(buf, 21, in.ScopeSchemaURL)
	}
	for i := range in.Refs {
		buf = appendObjectRefField(buf, 22, in.Refs[i].ObjectRef)
	}
	buf = appendStringField(buf, 23, in.LogName)
	if in.InsertID != "" {
		buf = appendStringField(buf, 24, in.InsertID)
	}

	s.row = buf
	return finishPooledRow(buf, maxRowBytes)
}

// EncodeMetricWire serializes one otel_metrics row directly to protobuf wire bytes.
func (e *Encoder) EncodeMetricWire(in *transform.MetricWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	return EncodeMetricWire(in, maxRowBytes)
}

// EncodeMetricWire serializes one otel_metrics row directly to protobuf wire bytes
// using pooled buffers and pre-encoded Resource/InstrumentationScope bytes.
func EncodeMetricWire(in *transform.MetricWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	s := acquireScratch()
	defer releaseScratch(s)

	buf := s.row[:0]
	buf = appendVarintField(buf, 1, uint64(micros(in.Timestamp)))
	buf = appendVarintField(buf, 2, uint64(in.Timestamp))
	if in.StartTimestamp != 0 {
		buf = appendVarintField(buf, 3, uint64(micros(in.StartTimestamp)))
		buf = appendVarintField(buf, 4, uint64(in.StartTimestamp))
	}
	buf = appendVarintField(buf, 5, uint64(in.ReceiveTimeMicros))
	buf = appendVarintField(buf, 6, uint64(in.ReceiveTimeUnixNano))
	if in.ServiceName != "" {
		buf = appendStringField(buf, 7, in.ServiceName)
	}
	buf = appendStringField(buf, 8, in.MetricName)
	if in.MetricDescription != "" {
		buf = appendStringField(buf, 9, in.MetricDescription)
	}
	if in.MetricUnit != "" {
		buf = appendStringField(buf, 10, in.MetricUnit)
	}
	buf = appendStringField(buf, 11, in.MetricType)
	if in.AggregationTemporality != "" {
		buf = appendStringField(buf, 12, in.AggregationTemporality)
	}
	if in.HasMonotonic {
		buf = appendVarintField(buf, 13, protowire.EncodeBool(in.IsMonotonic))
	}
	buf = appendVarintField(buf, 14, uint64(in.Flags))
	buf = appendMapJSONField(&s.sub, buf, 15, in.Attributes)
	if in.HasMetadata {
		buf = appendBytesField(buf, 16, in.MetadataJSON)
	}
	if in.ValueType != "" {
		buf = appendStringField(buf, 17, in.ValueType)
	}
	if in.HasValueDouble {
		buf = appendDoubleField(buf, 18, in.ValueDouble)
	}
	if in.HasValueInt64 {
		buf = appendVarintField(buf, 19, uint64(in.ValueInt64))
	}
	if in.HasCount {
		buf = appendVarintField(buf, 20, uint64(in.Count))
	}
	if in.HasSum {
		buf = appendDoubleField(buf, 21, in.Sum)
	}
	if in.HasMin {
		buf = appendDoubleField(buf, 22, in.Min)
	}
	if in.HasMax {
		buf = appendDoubleField(buf, 23, in.Max)
	}
	if len(in.ExplicitBounds) > 0 {
		buf = protowire.AppendTag(buf, 24, protowire.BytesType)
		buf = protowire.AppendVarint(buf, uint64(len(in.ExplicitBounds)*8))
		for _, b := range in.ExplicitBounds {
			buf = protowire.AppendFixed64(buf, math.Float64bits(b))
		}
	}
	if len(in.BucketCounts) > 0 {
		buf = protowire.AppendTag(buf, 25, protowire.BytesType)
		bcStart := len(buf)
		for _, c := range in.BucketCounts {
			buf = protowire.AppendVarint(buf, uint64(int64(c)))
		}
		buf = finalizeLengthPrefix(buf, bcStart)
	}
	if in.IsExpHistogram {
		buf = appendVarintField(buf, 26, uint64(in.ExpScale))
		buf = appendVarintField(buf, 27, uint64(in.ExpZeroCount))
		buf = appendDoubleField(buf, 28, in.ExpZeroThreshold)
		if in.ExpPositive.BucketCounts().Len() > 0 || in.ExpPositive.Offset() != 0 {
			buf = protowire.AppendTag(buf, 29, protowire.BytesType)
			pStart := len(buf)
			buf = appendVarintField(buf, 1, uint64(in.ExpPositive.Offset()))
			if n := in.ExpPositive.BucketCounts().Len(); n > 0 {
				buf = protowire.AppendTag(buf, 2, protowire.BytesType)
				bcStart := len(buf)
				raw := in.ExpPositive.BucketCounts().AsRaw()
				for _, c := range raw {
					buf = protowire.AppendVarint(buf, uint64(int64(c)))
				}
				buf = finalizeLengthPrefix(buf, bcStart)
			}
			buf = finalizeLengthPrefix(buf, pStart)
		}
		if in.ExpNegative.BucketCounts().Len() > 0 || in.ExpNegative.Offset() != 0 {
			buf = protowire.AppendTag(buf, 30, protowire.BytesType)
			nStart := len(buf)
			buf = appendVarintField(buf, 1, uint64(in.ExpNegative.Offset()))
			if n := in.ExpNegative.BucketCounts().Len(); n > 0 {
				buf = protowire.AppendTag(buf, 2, protowire.BytesType)
				bcStart := len(buf)
				raw := in.ExpNegative.BucketCounts().AsRaw()
				for _, c := range raw {
					buf = protowire.AppendVarint(buf, uint64(int64(c)))
				}
				buf = finalizeLengthPrefix(buf, bcStart)
			}
			buf = finalizeLengthPrefix(buf, nStart)
		}
	}
	if in.IsSummary && in.SummaryQuantiles.Len() > 0 {
		n := in.SummaryQuantiles.Len()
		for i := 0; i < n; i++ {
			qv := in.SummaryQuantiles.At(i)
			buf = protowire.AppendTag(buf, 31, protowire.BytesType)
			qStart := len(buf)
			buf = appendDoubleField(buf, 1, qv.Quantile())
			buf = appendDoubleField(buf, 2, qv.Value())
			buf = finalizeLengthPrefix(buf, qStart)
		}
	}
	if n := in.Exemplars.Len(); n > 0 {
		var hexBuf [32]byte
		for i := 0; i < n; i++ {
			ex := in.Exemplars.At(i)
			buf = protowire.AppendTag(buf, 32, protowire.BytesType)
			exStart := len(buf)
			if ex.Timestamp() != 0 {
				buf = appendVarintField(buf, 1, uint64(micros(ex.Timestamp())))
			}
			buf = appendVarintField(buf, 2, uint64(ex.Timestamp()))
			switch ex.ValueType() {
			case 2: // pmetric.ExemplarValueTypeDouble
				buf = appendDoubleField(buf, 3, ex.DoubleValue())
			case 1: // pmetric.ExemplarValueTypeInt
				buf = appendVarintField(buf, 4, uint64(ex.IntValue()))
			}
			if sid := ex.SpanID(); !sid.IsEmpty() {
				hex.Encode(hexBuf[:16], sid[:])
				buf = appendBytesField(buf, 5, hexBuf[:16])
			}
			if tid := ex.TraceID(); !tid.IsEmpty() {
				hex.Encode(hexBuf[:32], tid[:])
				buf = appendBytesField(buf, 6, hexBuf[:32])
			}
			buf = appendMapJSONField(&s.sub, buf, 7, ex.FilteredAttributes())
			buf = finalizeLengthPrefix(buf, exStart)
		}
	}
	if len(in.ResourceWire) > 0 {
		buf = append(buf, in.ResourceWire...)
	}
	if in.ResourceSchemaURL != "" {
		buf = appendStringField(buf, 34, in.ResourceSchemaURL)
	}
	if len(in.ScopeWire) > 0 {
		buf = append(buf, in.ScopeWire...)
	}
	if in.ScopeSchemaURL != "" {
		buf = appendStringField(buf, 36, in.ScopeSchemaURL)
	}
	buf = appendStringField(buf, 37, in.PointFingerprint)

	s.row = buf
	return finishPooledRow(buf, maxRowBytes)
}

// EncodeQuarantineWire serializes one otel_quarantine row directly to protobuf wire bytes.
func EncodeQuarantineWire(in *QuarantineWireInput, maxRowBytes int) ([]byte, int, bool, error) {
	s := acquireScratch()
	defer releaseScratch(s)

	buf := s.row[:0]
	buf = appendVarintField(buf, 1, uint64(in.IngestTimeMicros))
	buf = appendStringField(buf, 2, in.Signal)
	buf = appendStringField(buf, 3, in.ErrorCode)
	buf = appendStringField(buf, 4, in.ErrorMessage)
	if in.ServiceName != "" {
		buf = appendStringField(buf, 5, in.ServiceName)
	}
	if in.TraceID != "" {
		buf = appendStringField(buf, 6, in.TraceID)
	}
	if in.SpanID != "" {
		buf = appendStringField(buf, 7, in.SpanID)
	}
	if in.RawPayload != "" {
		buf = appendStringField(buf, 8, in.RawPayload)
	}
	if in.HasRawAttributes {
		buf = appendStringField(buf, 9, in.RawAttributes)
	}
	if in.HasPayloadRef {
		buf = appendObjectRefField(buf, 10, in.PayloadRef)
	}
	if in.ExporterInstance != "" {
		buf = appendStringField(buf, 11, in.ExporterInstance)
	}

	s.row = buf
	return finishPooledRow(buf, maxRowBytes)
}

func finishPooledRow(buf []byte, maxRowBytes int) ([]byte, int, bool, error) {
	if maxRowBytes > 0 && len(buf) > maxRowBytes {
		return nil, len(buf), true, nil
	}
	if len(buf) == 0 {
		return nil, 0, false, nil
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, len(out), false, nil
}

func appendObjectRefField(dst []byte, num protowire.Number, ref transform.ObjectRef) []byte {
	uri := sanitizeFast(ref.URI)
	if uri == "" {
		return dst
	}
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	start := len(dst)
	dst = appendStringField(dst, 1, uri)
	if v := sanitizeFast(ref.Version); v != "" {
		dst = appendStringField(dst, 2, v)
	}
	if a := sanitizeFast(ref.Authorizer); a != "" {
		dst = appendStringField(dst, 3, a)
	}
	if d := sanitizeFast(ref.Details); d != "" {
		dst = appendStringField(dst, 4, d)
	}
	return finalizeLengthPrefix(dst, start)
}

func appendVarintField(dst []byte, num protowire.Number, v uint64) []byte {
	dst = protowire.AppendTag(dst, num, protowire.VarintType)
	return protowire.AppendVarint(dst, v)
}

func appendDoubleField(dst []byte, num protowire.Number, f float64) []byte {
	dst = protowire.AppendTag(dst, num, protowire.Fixed64Type)
	return protowire.AppendFixed64(dst, math.Float64bits(f))
}

func appendStringField(dst []byte, num protowire.Number, s string) []byte {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendString(dst, s)
}

func appendBytesField(dst []byte, num protowire.Number, b []byte) []byte {
	dst = protowire.AppendTag(dst, num, protowire.BytesType)
	return protowire.AppendBytes(dst, b)
}

func appendMapJSONField(scratch *[]byte, dst []byte, num protowire.Number, m pcommon.Map) []byte {
	if m.Len() == 0 {
		return appendStringField(dst, num, "{}")
	}
	js := otlpjson.AppendPlainMap((*scratch)[:0], m)
	*scratch = js
	return appendBytesField(dst, num, js)
}

func appendValueJSONField(scratch *[]byte, dst []byte, num protowire.Number, v pcommon.Value) []byte {
	js := otlpjson.AppendPlainValue((*scratch)[:0], v)
	*scratch = js
	return appendBytesField(dst, num, js)
}

func micros(t pcommon.Timestamp) int64 {
	return int64(t) / int64(time.Microsecond)
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

func spanKindName(k ptrace.SpanKind) string {
	switch k {
	case ptrace.SpanKindUnspecified:
		return "SPAN_KIND_UNSPECIFIED"
	case ptrace.SpanKindInternal:
		return "SPAN_KIND_INTERNAL"
	case ptrace.SpanKindServer:
		return "SPAN_KIND_SERVER"
	case ptrace.SpanKindClient:
		return "SPAN_KIND_CLIENT"
	case ptrace.SpanKindProducer:
		return "SPAN_KIND_PRODUCER"
	case ptrace.SpanKindConsumer:
		return "SPAN_KIND_CONSUMER"
	}
	return ""
}

func statusCodeName(c ptrace.StatusCode) string {
	switch c {
	case ptrace.StatusCodeUnset:
		return "STATUS_CODE_UNSET"
	case ptrace.StatusCodeOk:
		return "STATUS_CODE_OK"
	case ptrace.StatusCodeError:
		return "STATUS_CODE_ERROR"
	}
	return ""
}
