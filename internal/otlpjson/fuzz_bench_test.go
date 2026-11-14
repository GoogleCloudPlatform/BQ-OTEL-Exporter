// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package otlpjson

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"

	"go.opentelemetry.io/collector/pdata/pcommon"
)

// FuzzEncodeMapWithSchema fuzzes EncodePlainMap and EncodePlainValue.
// The target name FuzzEncodeMapWithSchema is preserved for branch-protection
// check compatibility after the v0alpha3 removal of the *_schema sidecar
// encoders.
func FuzzEncodeMapWithSchema(f *testing.F) {
	f.Add("gen_ai.system", "gcp.vertex.agent", int64(42), 3.14, true, []byte{0x01, 0x02, 0xff})
	f.Add("", "empty_key", int64(-1), 0.0, false, []byte{})
	f.Add("nested.key.with.\"quotes\"\n", "line1\nline2\t\x00", int64(9007199254740993), -1e9, true, []byte("raw"))
	f.Add("unicode.🚀", "こんにちは世界", int64(0), 2.718281828, false, []byte{0xfe, 0xff})

	f.Fuzz(func(t *testing.T, k, sVal string, iVal int64, dVal float64, bVal bool, rawBytes []byte) {
		m := pcommon.NewMap()
		m.PutStr(k, sVal)
		m.PutInt(k+"_i", iVal)
		m.PutDouble(k+"_d", dVal)
		m.PutBool(k+"_b", bVal)
		bSlice := m.PutEmptyBytes(k + "_bytes")
		bSlice.FromRaw(rawBytes)
		arr := m.PutEmptySlice(k + "_arr")
		arr.AppendEmpty().SetStr(sVal)
		arr.AppendEmpty().SetInt(iVal)
		sub := m.PutEmptyMap(k + "_sub")
		sub.PutStr("inner", sVal)

		attrsJSON := EncodePlainMap(m)
		if !utf8.ValidString(attrsJSON) {
			t.Fatalf("attrsJSON is not valid UTF-8: %q", attrsJSON)
		}
		var parsedAttrs map[string]any
		if err := json.Unmarshal([]byte(attrsJSON), &parsedAttrs); err != nil {
			t.Fatalf("attrsJSON failed json.Unmarshal: %v\ninput: %s", err, attrsJSON)
		}

		// Determinism check: encoding the same map twice yields identical strings.
		attrsJSON2 := EncodePlainMap(m)
		if attrsJSON != attrsJSON2 {
			t.Fatalf("non-deterministic output: %q != %q", attrsJSON, attrsJSON2)
		}

		val := pcommon.NewValueMap()
		m.CopyTo(val.Map())
		valJSON := EncodePlainValue(val)
		if !utf8.ValidString(valJSON) || !json.Valid([]byte(valJSON)) {
			t.Fatalf("EncodePlainValue produced invalid UTF-8 JSON: %q", valJSON)
		}
		if valJSON != attrsJSON {
			t.Fatalf("EncodePlainValue(map) = %q != EncodePlainMap(map) = %q", valJSON, attrsJSON)
		}
		if valJSON2 := EncodePlainValue(val); valJSON != valJSON2 {
			t.Fatalf("EncodePlainValue non-deterministic: %q != %q", valJSON, valJSON2)
		}
	})
}

func BenchmarkEncodePlainMapBySize(b *testing.B) {
	sizes := []struct {
		name string
		size int
	}{
		{name: "0B", size: 0},
		{name: "4KB", size: 4 * 1024},
		{name: "64KB", size: 64 * 1024},
	}

	for _, sz := range sizes {
		b.Run(sz.name, func(b *testing.B) {
			payload := strings.Repeat("a", sz.size)
			m := pcommon.NewMap()
			m.PutStr("gen_ai.system", "gcp.vertex.agent")
			m.PutStr("gen_ai.request.model", "gemini-2.5-pro")
			m.PutInt("gen_ai.usage.input_tokens", 1024)
			m.PutInt("gen_ai.usage.output_tokens", 512)
			m.PutBool("gen_ai.response.cached", false)
			m.PutStr("payload", payload)
			nested := m.PutEmptyMap("metadata")
			nested.PutStr("session_id", "sess-123")
			nested.PutInt("turn", 3)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				attrs := EncodePlainMap(m)
				if len(attrs) == 0 {
					b.Fatal("unexpected empty JSON")
				}
			}
		})
	}
}
