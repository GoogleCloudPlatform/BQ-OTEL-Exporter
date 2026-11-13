// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package otlpjson renders OTLP AnyValues and attribute bags as JSON for
// BigQuery JSON columns.
//
// The encoding is otlp-plainjson-v2 (PlainVersion): every value is written as
// ordinary JSON, so the column reads naturally with BigQuery's JSON functions.
// An int64 travels as a decimal string to preserve precision beyond 2^53 in
// JSON readers that decode numbers as float64, bytes travel as standard base64
// strings, and non-finite doubles (NaN, Infinity, -Infinity) use ProtoJSON
// string forms.
package otlpjson // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/otlpjson"

import (
	"encoding/base64"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// PlainVersion is the version of the plain JSON encoding produced by
// EncodePlainValue and EncodePlainMap.
const PlainVersion = "otlp-plainjson-v2"

var builderPool = sync.Pool{
	New: func() any { return new(strings.Builder) },
}

func acquireBuilder() *strings.Builder {
	b := builderPool.Get().(*strings.Builder)
	b.Reset()
	return b
}

func releaseBuilder(b *strings.Builder) {
	if b.Cap() <= 64*1024 {
		b.Reset()
		builderPool.Put(b)
	}
}

var entriesPool = sync.Pool{
	New: func() any {
		s := make([]plainEntry, 0, 16)
		return &s
	},
}

func acquireEntries(n int) *[]plainEntry {
	p := entriesPool.Get().(*[]plainEntry)
	s := (*p)[:0]
	if cap(s) < n {
		s = make([]plainEntry, 0, n)
	}
	*p = s
	return p
}

func releaseEntries(p *[]plainEntry) {
	s := *p
	clear(s)
	if cap(s) <= 256 {
		*p = s[:0]
		entriesPool.Put(p)
	}
}

// EncodePlainValue renders a single AnyValue as otlp-plainjson-v2 JSON.
//
// Strings, booleans, arrays and maps become their JSON counterparts. An int64
// becomes a decimal string, so values beyond 2^53 keep every digit in JSON
// parsers that read numbers as doubles. A double becomes a JSON number, except
// NaN and the infinities, which take the ProtoJSON string forms "NaN",
// "Infinity" and "-Infinity". Bytes become a standard base64 string. An
// explicitly empty AnyValue becomes JSON null.
//
// Invalid UTF-8 in strings and map keys is replaced with U+FFFD, so the result
// is always valid JSON.
func EncodePlainValue(v pcommon.Value) string {
	b := acquireBuilder()
	defer releaseBuilder(b)
	plainWriter{attrs: b}.value(v)
	return b.String()
}

// AppendPlainValue appends the otlp-plainjson-v2 JSON encoding of v to dst and
// returns the extended slice, avoiding intermediate string allocations.
func AppendPlainValue(dst []byte, v pcommon.Value) []byte {
	return appendPlainValue(dst, v)
}

// EncodePlainMap renders an attribute bag as an otlp-plainjson-v2 JSON object.
// An empty bag encodes as {}.
//
// Keys are emitted in sorted order, so one logical record always encodes to
// the same bytes. Keys that are equal, or become equal once invalid UTF-8 is
// replaced, are emitted once, with the value of the first in payload order:
// the entry pcommon.Map.Get returns.
func EncodePlainMap(m pcommon.Map) string {
	if m.Len() == 0 {
		return "{}"
	}
	b := acquireBuilder()
	defer releaseBuilder(b)
	plainWriter{attrs: b}.object(m)
	return b.String()
}

// AppendPlainMap appends the otlp-plainjson-v2 JSON encoding of m to dst and
// returns the extended slice, avoiding intermediate string allocations.
func AppendPlainMap(dst []byte, m pcommon.Map) []byte {
	if m.Len() == 0 {
		return append(dst, '{', '}')
	}
	return appendPlainMap(dst, m)
}

// plainWriter emits otlp-plainjson-v2 to attrs.
type plainWriter struct {
	attrs *strings.Builder
}

func (w plainWriter) value(v pcommon.Value) {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		writeJSONString(w.attrs, sanitizeUTF8(v.Str()))

	case pcommon.ValueTypeBool:
		w.attrs.WriteString(strconv.FormatBool(v.Bool()))

	case pcommon.ValueTypeInt:
		// A decimal string, as in ProtoJSON: a JSON number would lose
		// precision beyond 2^53 in parsers that read numbers as doubles.
		var scratch [24]byte
		w.attrs.WriteByte('"')
		w.attrs.Write(strconv.AppendInt(scratch[:0], v.Int(), 10))
		w.attrs.WriteByte('"')

	case pcommon.ValueTypeDouble:
		writePlainDouble(w.attrs, v.Double())

	case pcommon.ValueTypeBytes:
		w.attrs.WriteByte('"')
		w.attrs.WriteString(base64.StdEncoding.EncodeToString(v.Bytes().AsRaw()))
		w.attrs.WriteByte('"')

	case pcommon.ValueTypeSlice:
		w.attrs.WriteByte('[')
		s := v.Slice()
		for i := 0; i < s.Len(); i++ {
			if i > 0 {
				w.attrs.WriteByte(',')
			}
			// Array order is meaningful and is preserved.
			w.value(s.At(i))
		}
		w.attrs.WriteByte(']')

	case pcommon.ValueTypeMap:
		w.object(v.Map())

	default:
		// ValueTypeEmpty. pcommon exposes only the compiled value kinds, so
		// nothing else reaches here from a decoded payload; a future pdata
		// addition would still produce valid JSON in the column.
		w.attrs.WriteString("null")
	}
}

// object writes m as a JSON object with sorted, unique keys.
func (w plainWriter) object(m pcommon.Map) {
	if m.Len() == 0 {
		w.attrs.WriteString("{}")
		return
	}
	ep := acquireEntries(m.Len())
	defer releaseEntries(ep)
	entries := plainEntriesInto(m, (*ep)[:0])
	*ep = entries

	w.attrs.WriteByte('{')
	for i, e := range entries {
		if i > 0 {
			w.attrs.WriteByte(',')
		}
		writeJSONString(w.attrs, e.key)
		w.attrs.WriteByte(':')
		w.value(e.value)
	}
	w.attrs.WriteByte('}')
}

type plainEntry struct {
	key   string
	value pcommon.Value
}

func sanitizeUTF8(s string) string {
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

// plainEntriesInto appends m's entries into entries with their keys made valid
// UTF-8 and sorted by UTF-8 byte order, keeping only the first entry in payload
// order for each key.
func plainEntriesInto(m pcommon.Map, entries []plainEntry) []plainEntry {
	for k, v := range m.All() {
		entries = append(entries, plainEntry{key: sanitizeUTF8(k), value: v})
	}
	// The stable sort keeps equal keys in payload order, so compacting keeps
	// the first of each.
	slices.SortStableFunc(entries, func(a, b plainEntry) int {
		return strings.Compare(a.key, b.key)
	})
	return slices.CompactFunc(entries, func(a, b plainEntry) bool {
		return a.key == b.key
	})
}

// writePlainDouble writes f as a JSON number formatted the way encoding/json
// formats a float64: the shortest digits that round-trip, in plain decimal
// notation unless the magnitude is below 1e-6 or at least 1e21. NaN and the
// infinities, which a JSON number cannot express, take the ProtoJSON string
// forms.
func writePlainDouble(b *strings.Builder, f float64) {
	switch {
	case math.IsNaN(f):
		b.WriteString(`"NaN"`)
	case math.IsInf(f, 1):
		b.WriteString(`"Infinity"`)
	case math.IsInf(f, -1):
		b.WriteString(`"-Infinity"`)
	default:
		var scratch [32]byte
		format := byte('f')
		if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
			format = 'e'
		}
		out := strconv.AppendFloat(scratch[:0], f, format, -1, 64)
		// Drop the padding zero of a two-digit negative exponent, e-07 to
		// e-7, as encoding/json does.
		if n := len(out); format == 'e' && n >= 4 && out[n-4] == 'e' && out[n-3] == '-' && out[n-2] == '0' {
			out[n-2] = out[n-1]
			out = out[:n-1]
		}
		b.Write(out)
	}
}

const hexDigits = "0123456789abcdef"

// writeJSONString emits a JSON string literal.
//
// Written by hand rather than via encoding/json because that package escapes
// <, > and & for HTML safety. Those escapes are legal JSON but they would make
// the record fingerprint depend on an encoder policy rather than on the
// record's content. Contiguous runs of safe ASCII bytes (0x20..0x7e excluding
// '"' and '\\') are copied in a single slice write.
func writeJSONString(b *strings.Builder, s string) {
	b.WriteByte('"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c < utf8.RuneSelf && c != '"' && c != '\\' {
			i++
			continue
		}
		if start < i {
			b.WriteString(s[start:i])
		}
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			default:
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[(c>>4)&0xF])
				b.WriteByte(hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		b.WriteString(s[i : i+size])
		i += size
		start = i
	}
	if start < len(s) {
		b.WriteString(s[start:])
	}
	b.WriteByte('"')
}

func appendPlainValue(dst []byte, v pcommon.Value) []byte {
	switch v.Type() {
	case pcommon.ValueTypeStr:
		return appendJSONString(dst, sanitizeUTF8(v.Str()))

	case pcommon.ValueTypeBool:
		return strconv.AppendBool(dst, v.Bool())

	case pcommon.ValueTypeInt:
		var scratch [24]byte
		dst = append(dst, '"')
		dst = append(dst, strconv.AppendInt(scratch[:0], v.Int(), 10)...)
		return append(dst, '"')

	case pcommon.ValueTypeDouble:
		return appendPlainDouble(dst, v.Double())

	case pcommon.ValueTypeBytes:
		dst = append(dst, '"')
		dst = base64.StdEncoding.AppendEncode(dst, v.Bytes().AsRaw())
		return append(dst, '"')

	case pcommon.ValueTypeSlice:
		dst = append(dst, '[')
		s := v.Slice()
		for i := 0; i < s.Len(); i++ {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendPlainValue(dst, s.At(i))
		}
		return append(dst, ']')

	case pcommon.ValueTypeMap:
		return appendPlainMap(dst, v.Map())

	default:
		return append(dst, "null"...)
	}
}

func appendPlainMap(dst []byte, m pcommon.Map) []byte {
	if m.Len() == 0 {
		return append(dst, '{', '}')
	}
	ep := acquireEntries(m.Len())
	defer releaseEntries(ep)
	entries := plainEntriesInto(m, (*ep)[:0])
	*ep = entries

	dst = append(dst, '{')
	for i, e := range entries {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, e.key)
		dst = append(dst, ':')
		dst = appendPlainValue(dst, e.value)
	}
	return append(dst, '}')
}

func appendPlainDouble(dst []byte, f float64) []byte {
	switch {
	case math.IsNaN(f):
		return append(dst, `"NaN"`...)
	case math.IsInf(f, 1):
		return append(dst, `"Infinity"`...)
	case math.IsInf(f, -1):
		return append(dst, `"-Infinity"`...)
	default:
		var scratch [32]byte
		format := byte('f')
		if abs := math.Abs(f); abs != 0 && (abs < 1e-6 || abs >= 1e21) {
			format = 'e'
		}
		out := strconv.AppendFloat(scratch[:0], f, format, -1, 64)
		if n := len(out); format == 'e' && n >= 4 && out[n-4] == 'e' && out[n-3] == '-' && out[n-2] == '0' {
			out[n-2] = out[n-1]
			out = out[:n-1]
		}
		return append(dst, out...)
	}
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if c >= 0x20 && c < utf8.RuneSelf && c != '"' && c != '\\' {
			i++
			continue
		}
		if start < i {
			dst = append(dst, s[start:i]...)
		}
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				dst = append(dst, `\"`...)
			case '\\':
				dst = append(dst, `\\`...)
			case '\n':
				dst = append(dst, `\n`...)
			case '\r':
				dst = append(dst, `\r`...)
			case '\t':
				dst = append(dst, `\t`...)
			case '\b':
				dst = append(dst, `\b`...)
			case '\f':
				dst = append(dst, `\f`...)
			default:
				dst = append(dst, `\u00`...)
				dst = append(dst, hexDigits[(c>>4)&0xF], hexDigits[c&0xF])
			}
			i++
			start = i
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		dst = append(dst, s[i:i+size]...)
		i += size
		start = i
	}
	if start < len(s) {
		dst = append(dst, s[start:]...)
	}
	return append(dst, '"')
}
