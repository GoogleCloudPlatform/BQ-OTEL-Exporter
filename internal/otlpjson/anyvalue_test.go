// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package otlpjson

import (
	"encoding/json"
	"math"
	"slices"
	"strconv"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
)

func TestEncodePlainValue(t *testing.T) {
	tests := []struct {
		name  string
		build func(pcommon.Value)
		want  string
	}{
		{"empty is null", func(pcommon.Value) {}, `null`},
		{"string", func(v pcommon.Value) { v.SetStr("gpt-4o") }, `"gpt-4o"`},
		{"empty string", func(v pcommon.Value) { v.SetStr("") }, `""`},
		{"true", func(v pcommon.Value) { v.SetBool(true) }, `true`},
		{"false", func(v pcommon.Value) { v.SetBool(false) }, `false`},

		// int64 travels as a decimal string so that no digit is lost.
		{"int", func(v pcommon.Value) { v.SetInt(200) }, `"200"`},
		{"int zero", func(v pcommon.Value) { v.SetInt(0) }, `"0"`},
		{"int negative", func(v pcommon.Value) { v.SetInt(-7) }, `"-7"`},
		{"int max", func(v pcommon.Value) { v.SetInt(math.MaxInt64) }, `"9223372036854775807"`},
		{"int min", func(v pcommon.Value) { v.SetInt(math.MinInt64) }, `"-9223372036854775808"`},

		{"double", func(v pcommon.Value) { v.SetDouble(3.14) }, `3.14`},
		{"double whole", func(v pcommon.Value) { v.SetDouble(42) }, `42`},
		{"double negative", func(v pcommon.Value) { v.SetDouble(-0.5) }, `-0.5`},
		{"double zero", func(v pcommon.Value) { v.SetDouble(0) }, `0`},
		{"double million", func(v pcommon.Value) { v.SetDouble(1e6) }, `1000000`},
		{"double large", func(v pcommon.Value) { v.SetDouble(1e21) }, `1e+21`},
		{"double small", func(v pcommon.Value) { v.SetDouble(1e-7) }, `1e-7`},

		// ProtoJSON rules for doubles a JSON number cannot express.
		{"nan", func(v pcommon.Value) { v.SetDouble(math.NaN()) }, `"NaN"`},
		{"inf", func(v pcommon.Value) { v.SetDouble(math.Inf(1)) }, `"Infinity"`},
		{"-inf", func(v pcommon.Value) { v.SetDouble(math.Inf(-1)) }, `"-Infinity"`},

		{"bytes", func(v pcommon.Value) { v.SetEmptyBytes().Append(1, 2, 3, 4) }, `"AQIDBA=="`},
		{"bytes standard alphabet", func(v pcommon.Value) { v.SetEmptyBytes().Append(0xfb, 0xff) }, `"+/8="`},
		{"bytes empty", func(v pcommon.Value) { v.SetEmptyBytes() }, `""`},

		{"array", func(v pcommon.Value) {
			s := v.SetEmptySlice()
			s.AppendEmpty().SetStr("one")
			s.AppendEmpty().SetInt(2)
			s.AppendEmpty().SetDouble(2.5)
			s.AppendEmpty().SetBool(false)
			s.AppendEmpty()
		}, `["one","2",2.5,false,null]`},
		{"array empty", func(v pcommon.Value) { v.SetEmptySlice() }, `[]`},
		{"map", func(v pcommon.Value) {
			m := v.SetEmptyMap()
			m.PutStr("mode", "fast")
			m.PutBool("enabled", true)
		}, `{"enabled":true,"mode":"fast"}`},
		{"map empty", func(v pcommon.Value) { v.SetEmptyMap() }, `{}`},

		{"escapes", func(v pcommon.Value) { v.SetStr("a\"b\\c\nd\te\rf\bg\fh") }, `"a\"b\\c\nd\te\rf\bg\fh"`},
		{"control char", func(v pcommon.Value) { v.SetStr("x\x01y") }, `"x\u0001y"`},
		{"no html escaping", func(v pcommon.Value) { v.SetStr("<a href='x'>&</a>") }, `"<a href='x'>&</a>"`},
		{"non-ascii", func(v pcommon.Value) { v.SetStr("héllo, 世界") }, `"héllo, 世界"`},

		// Invalid UTF-8 is repaired; a run of bad bytes becomes one U+FFFD.
		{"invalid utf-8", func(v pcommon.Value) { v.SetStr("a\xffb") }, "\"a\uFFFDb\""},
		{"invalid utf-8 run", func(v pcommon.Value) { v.SetStr("a\xff\xfe\xfdb") }, "\"a\uFFFDb\""},
		{"truncated utf-8", func(v pcommon.Value) { v.SetStr("ok\xe4\xb8") }, "\"ok\uFFFD\""},
		{"literal replacement char", func(v pcommon.Value) { v.SetStr("a\uFFFDb") }, "\"a\uFFFDb\""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := pcommon.NewValueEmpty()
			tc.build(v)
			got := EncodePlainValue(v)
			if got != tc.want {
				t.Fatalf("EncodePlainValue()\n got: %s\nwant: %s", got, tc.want)
			}
			if !json.Valid([]byte(got)) {
				t.Fatalf("output is not valid JSON: %s", got)
			}
			if !utf8.ValidString(got) {
				t.Fatalf("output is not valid UTF-8: %q", got)
			}
		})
	}
}

// Plain doubles are formatted exactly as encoding/json formats a float64, the
// form JSON readers expect, and parse back to the identical float64.
func TestEncodePlainValueDoubleFormatting(t *testing.T) {
	for _, f := range []float64{
		0, math.Copysign(0, -1), 1, -1, 0.1, 3.14, 42, 1234567, 1e20, 1e21, -1e21, 1.5e300,
		1e-6, 1e-7, -1e-7, 1.5e-10, 123456789.125, 1 << 53, math.MaxFloat64, -math.MaxFloat64,
		math.SmallestNonzeroFloat64,
	} {
		got := EncodePlainValue(pcommon.NewValueDouble(f))
		want, err := json.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if got != string(want) {
			t.Errorf("EncodePlainValue(%v) = %s, encoding/json gives %s", f, got, want)
		}
		back, err := strconv.ParseFloat(got, 64)
		if err != nil {
			t.Errorf("EncodePlainValue(%v) = %s, which does not parse: %v", f, got, err)
			continue
		}
		if math.Float64bits(back) != math.Float64bits(f) {
			t.Errorf("EncodePlainValue(%v) = %s, which parses back as %v", f, got, back)
		}
	}
}

// An int64 beyond 2^53 must reach JSON readers digit for digit. As a JSON
// number, parsers that read numbers as doubles would round it.
func TestEncodePlainValueIntPrecisionSurvives(t *testing.T) {
	for _, n := range []int64{math.MaxInt64, math.MinInt64, 1<<53 + 1, -(1<<53 + 1)} {
		var decoded any
		if err := json.Unmarshal([]byte(EncodePlainValue(pcommon.NewValueInt(n))), &decoded); err != nil {
			t.Fatal(err)
		}
		if want := strconv.FormatInt(n, 10); decoded != want {
			t.Errorf("int %d decoded as %v (%T), want the exact decimal string %q", n, decoded, decoded, want)
		}
	}
}

func TestEncodePlainValueNested(t *testing.T) {
	v := pcommon.NewValueEmpty()
	outer := v.SetEmptyMap()
	items := outer.PutEmptySlice("items")
	items.AppendEmpty().SetInt(1)
	nested := items.AppendEmpty().SetEmptyMap()
	nested.PutStr("k", "v")
	nested.PutEmptyMap("deeper").PutDouble("x", 0.5)
	items.AppendEmpty().SetEmptySlice().AppendEmpty().SetEmptySlice()

	got := EncodePlainValue(v)
	if !json.Valid([]byte(got)) {
		t.Fatalf("nested output is not valid JSON: %s", got)
	}
	want := `{"items":["1",{"deeper":{"x":0.5},"k":"v"},[[]]]}`
	if got != want {
		t.Fatalf("nested encoding\n got: %s\nwant: %s", got, want)
	}
}

// Array order carries meaning and must be preserved, unlike map key order.
func TestEncodePlainValueSliceOrderPreserved(t *testing.T) {
	v := pcommon.NewValueEmpty()
	s := v.SetEmptySlice()
	for _, x := range []string{"c", "a", "b"} {
		s.AppendEmpty().SetStr(x)
	}
	if got, want := EncodePlainValue(v), `["c","a","b"]`; got != want {
		t.Fatalf("slice order not preserved\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodePlainMap(t *testing.T) {
	m := pcommon.NewMap()
	m.PutInt("http.status_code", 200)
	m.PutBool("cache.hit", true)
	m.PutStr("gen_ai.request.model", "gpt-4o")

	want := `{"cache.hit":true,"gen_ai.request.model":"gpt-4o","http.status_code":"200"}`
	if got := EncodePlainMap(m); got != want {
		t.Fatalf("EncodePlainMap()\n got: %s\nwant: %s", got, want)
	}
}

func TestEncodePlainMapEmpty(t *testing.T) {
	if got := EncodePlainMap(pcommon.NewMap()); got != "{}" {
		t.Fatalf("empty map = %s, want {}", got)
	}
}

// Key order depends only on the keys, in UTF-8 byte order, never on payload
// order, so one logical record always encodes to the same bytes.
func TestEncodePlainMapKeyOrder(t *testing.T) {
	keys := []string{"z", "b", "B", "_x", "é", "a.b", "a", "10", "9"}
	want := `{"10":"v","9":"v","B":"v","_x":"v","a":"v","a.b":"v","b":"v","z":"v","é":"v"}`
	reversed := slices.Clone(keys)
	slices.Reverse(reversed)
	for _, order := range [][]string{keys, reversed} {
		m := pcommon.NewMap()
		for _, k := range order {
			m.PutStr(k, "v")
		}
		if got := EncodePlainMap(m); got != want {
			t.Fatalf("EncodePlainMap() with insertion order %q\n got: %s\nwant: %s", order, got, want)
		}
	}
}

// Keys get the same UTF-8 repair as string values, at every nesting level.
func TestEncodePlainMapRepairsKeys(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("bad\xffkey", "v")
	m.PutEmptyMap("outer").PutInt("in\xfe\xfdner", 1)

	got := EncodePlainMap(m)
	want := "{\"bad\uFFFDkey\":\"v\",\"outer\":{\"in\uFFFDner\":\"1\"}}"
	if got != want {
		t.Fatalf("EncodePlainMap()\n got: %q\nwant: %q", got, want)
	}
	if !utf8.ValidString(got) || !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid UTF-8 JSON: %q", got)
	}
}

// Two distinct keys can become equal once invalid UTF-8 is repaired. The
// object keeps the first in payload order, not the first in raw byte order,
// and never repeats a key.
func TestEncodePlainMapRepairedKeyCollisionKeepsFirst(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("k\xff", "first")
	m.PutInt("k\xfe", 2)
	if m.Len() != 2 {
		t.Fatalf("precondition: want 2 distinct raw keys, got %d", m.Len())
	}

	wantAttrs := "{\"k\uFFFD\":\"first\"}"
	got := EncodePlainMap(m)
	if got != wantAttrs {
		t.Fatalf("EncodePlainMap()\n got: %q\nwant: %q", got, wantAttrs)
	}
	if !utf8.ValidString(got) || !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid UTF-8 JSON: %q", got)
	}
}

// OTLP requires unique keys, but nothing on the wire enforces it and pdata
// keeps every entry it decodes. The object emits the key once, with the value
// pcommon.Map.Get returns: the first.
func TestEncodePlainMapDuplicateKeysKeepFirst(t *testing.T) {
	logs, err := (&plog.JSONUnmarshaler{}).UnmarshalLogs([]byte(
		`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"attributes":[` +
			`{"key":"k","value":{"stringValue":"first"}},` +
			`{"key":"k","value":{"intValue":"2"}}]}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	m := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Attributes()
	if m.Len() != 2 {
		t.Fatalf("precondition: decoded %d attributes, want both duplicates kept", m.Len())
	}
	if v, _ := m.Get("k"); v.Str() != "first" {
		t.Fatalf("precondition: Get returned %q, want the first entry", v.AsString())
	}

	if got, want := EncodePlainMap(m), `{"k":"first"}`; got != want {
		t.Fatalf("EncodePlainMap() = %s, want %s", got, want)
	}
}

func TestEncodePlainMapNestedTypes(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("gen_ai.request.model", "gpt-4o")
	m.PutInt("http.status_code", 200)
	m.PutDouble("gen_ai.request.temperature", 0.7)
	m.PutBool("cache.hit", true)
	m.PutEmptyBytes("payload").Append(1, 2, 3)
	req := m.PutEmptyMap("request")
	req.PutStr("method", "GET")
	req.PutEmptyMap("headers").PutInt("content-length", 512)
	tags := m.PutEmptySlice("tags")
	tags.AppendEmpty().SetStr("a")
	tags.AppendEmpty().SetInt(1)
	tags.AppendEmpty().SetEmptySlice().AppendEmpty().SetBool(false)
	m.PutEmpty("unset")

	wantAttrs := `{"cache.hit":true,"gen_ai.request.model":"gpt-4o","gen_ai.request.temperature":0.7,` +
		`"http.status_code":"200","payload":"AQID","request":{"headers":{"content-length":"512"},"method":"GET"},` +
		`"tags":["a","1",[false]],"unset":null}`

	got := EncodePlainMap(m)
	if got != wantAttrs {
		t.Fatalf("EncodePlainMap()\n got: %s\nwant: %s", got, wantAttrs)
	}
	if !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid JSON: %s", got)
	}

	mv := pcommon.NewValueMap()
	m.CopyTo(mv.Map())
	if gotVal := EncodePlainValue(mv); gotVal != got {
		t.Fatalf("EncodePlainValue(map) = %s, want %s", gotVal, got)
	}
}

func TestEncodePlainMapFromRaw(t *testing.T) {
	m := pcommon.NewMap()
	if err := m.FromRaw(map[string]any{
		"s":    "x",
		"i":    int64(-3),
		"d":    2.5,
		"b":    false,
		"raw":  []byte{0xde, 0xad},
		"none": nil,
		"list": []any{"a", int64(1), []any{}, map[string]any{"k": 1.5, "n": nil}},
		"obj": map[string]any{
			"deep":  map[string]any{"deeper": []any{true, []byte{}}},
			"empty": map[string]any{},
		},
	}); err != nil {
		t.Fatal(err)
	}

	got := EncodePlainMap(m)
	want := `{"b":false,"d":2.5,"i":"-3","list":["a","1",[],{"k":1.5,"n":null}],"none":null,` +
		`"obj":{"deep":{"deeper":[true,""]},"empty":{}},"raw":"3q0=","s":"x"}`
	if got != want {
		t.Fatalf("EncodePlainMap()\n got: %s\nwant: %s", got, want)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("unmarshaling %s: %v", got, err)
	}
}

func BenchmarkEncodePlainMap(b *testing.B) {
	m := pcommon.NewMap()
	m.PutStr("service.name", "checkout")
	m.PutStr("service.version", "1.4.2")
	m.PutStr("deployment.environment", "prod")
	m.PutInt("host.cpu.count", 16)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncodePlainMap(m)
	}
}

func TestAppendPlainMatchesEncodePlain(t *testing.T) {
	m := pcommon.NewMap()
	m.PutStr("http.method", "GET")
	m.PutStr("control", "\x00\b\f\n\r\t\"\\<>&\xff")
	m.PutInt("big_int", math.MaxInt64)
	m.PutInt("min_int", math.MinInt64)
	m.PutBool("tls", true)
	m.PutDouble("latency_ms", 12.5)
	m.PutDouble("tiny", 1e-7)
	m.PutDouble("nan", math.NaN())
	m.PutDouble("pos_inf", math.Inf(1))
	m.PutDouble("neg_inf", math.Inf(-1))
	m.PutEmptyBytes("raw").FromRaw([]byte{1, 2, 3, 255})
	m.PutEmpty("empty")
	nested := m.PutEmptyMap("nested")
	nested.PutStr("k", "v")
	sl := m.PutEmptySlice("arr")
	sl.AppendEmpty().SetInt(42)
	sl.AppendEmpty().SetStr("42")
	sl.AppendEmpty().SetEmptyMap().PutBool("ok", false)

	wantMap := EncodePlainMap(m)
	gotMap := string(AppendPlainMap(make([]byte, 0, 512), m))
	if gotMap != wantMap {
		t.Fatalf("AppendPlainMap() = %s, want %s", gotMap, wantMap)
	}

	if gotEmpty := string(AppendPlainMap(nil, pcommon.NewMap())); gotEmpty != "{}" {
		t.Fatalf("AppendPlainMap(empty) = %q, want {}", gotEmpty)
	}

	mv := pcommon.NewValueMap()
	m.CopyTo(mv.Map())
	if gotVal, wantVal := string(AppendPlainValue(nil, mv)), EncodePlainValue(mv); gotVal != wantVal {
		t.Fatalf("AppendPlainValue(map) = %s, want %s", gotVal, wantVal)
	}
	if gotEmpty := string(AppendPlainValue(nil, pcommon.NewValueEmpty())); gotEmpty != "null" {
		t.Fatalf("AppendPlainValue(empty) = %q, want null", gotEmpty)
	}

	flat := pcommon.NewMap()
	flat.PutStr("service.name", "checkout")
	flat.PutStr("http.request.method", "GET")
	flat.PutInt("http.response.status_code", 200)
	flat.PutBool("tls", true)

	buf := make([]byte, 0, 1024)
	_ = AppendPlainMap(buf[:0], flat)
	allocs := testing.AllocsPerRun(100, func() {
		buf = AppendPlainMap(buf[:0], flat)
	})
	if allocs > 1 {
		t.Errorf("AppendPlainMap allocs/op = %.1f, want <= 1", allocs)
	}
}
