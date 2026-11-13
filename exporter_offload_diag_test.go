// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	stdhttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/component"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/api/option"

	bqi "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/bigquery"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

func TestPermanentOffloadDropWarningLogIsContentFree(t *testing.T) {
	payload := strings.Repeat("P", 128)
	payloadSum := sha256.Sum256([]byte(payload))
	payloadSHA := hex.EncodeToString(payloadSum[:])
	localMD5 := md5.Sum([]byte(payload))
	localMD5Hex := hex.EncodeToString(localMD5[:])

	corruptMD5 := md5.Sum([]byte(strings.Repeat("Q", 128)))
	corruptMD5Hex := hex.EncodeToString(corruptMD5[:])
	corruptMD5B64 := base64.StdEncoding.EncodeToString(corruptMD5[:])

	cases := []struct {
		name           string
		metaResp       map[string]string
		wantErrCode    string
		wantDetail     string
		forbiddenExtra []string
	}{
		{
			name: "md5_mismatch",
			metaResp: map[string]string{
				"generation":  "909",
				"size":        fmt.Sprintf("%d", len(payload)),
				"contentType": "text/plain; charset=utf-8",
				"md5Hash":     corruptMD5B64,
			},
			wantErrCode:    "md5_mismatch",
			wantDetail:     "offload_permanent: md5_mismatch: existing object md5 does not match upload",
			forbiddenExtra: []string{corruptMD5Hex, localMD5Hex},
		},
		{
			name: "size_mismatch",
			metaResp: map[string]string{
				"generation":  "910",
				"size":        "999",
				"contentType": "text/plain; charset=utf-8",
			},
			wantErrCode:    "size_mismatch",
			wantDetail:     "offload_permanent: size_mismatch: existing object size does not match upload",
			forbiddenExtra: []string{"999"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const bucket = "diag-privacy-bucket"
			srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
				switch {
				case r.Method == stdhttp.MethodPost && r.URL.Path == "/upload/storage/v1/b/"+bucket+"/o":
					if strings.Contains(r.URL.Query().Get("name"), "quarantine/") {
						w.Header().Set("Content-Type", "application/json")
						_, _ = w.Write([]byte(`{"generation":"q-1"}`))
						return
					}
					w.WriteHeader(stdhttp.StatusPreconditionFailed)
					_, _ = w.Write([]byte(`{"error":{"code":412,"message":"Precondition Failed"}}`))
				case r.Method == stdhttp.MethodGet && strings.HasPrefix(r.URL.Path, "/storage/v1/b/"+bucket+"/o/"):
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(tc.metaResp)
				default:
					w.WriteHeader(stdhttp.StatusNotFound)
				}
			}))
			defer srv.Close()

			store, err := offload.NewGCSBlobStore(
				context.Background(),
				option.WithEndpoint(srv.URL),
				option.WithoutAuthentication(),
			)
			if err != nil {
				t.Fatalf("NewGCSBlobStore() error = %v", err)
			}
			t.Cleanup(func() { _ = store.Close() })

			core, recorded := observer.New(zap.WarnLevel)
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

			cfg := validConfig()
			cfg.Offload.Enabled = true
			cfg.Offload.Bucket = bucket
			cfg.Offload.MinBytes = 64
			cfg.Offload.MaxConcurrency = 1
			cfg.Quarantine.Enabled = true

			e, err := newTracesExporter(component.TelemetrySettings{
				Logger:        zap.New(core),
				MeterProvider: mp,
			}, cfg)
			if err != nil {
				t.Fatal(err)
			}
			e.offloader.SetStore(store)

			enc, err := protoenc.New(schema.SpansTableSchema())
			if err != nil {
				t.Fatal(err)
			}
			e.enc = enc
			primary := &fakeAppender{}
			e.writer = primary
			quarantined, _ := withQuarantine(t, e.signalExporter, bqi.AppendOutcome{AcknowledgedRows: 1})

			td := newTestTraces(1)
			td.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).Attributes().PutStr("prompt", payload)

			if err := e.pushTraceData(context.Background(), td); err != nil {
				t.Fatalf("pushTraceData returned %v, want nil (permanent offload error must quarantine)", err)
			}
			if primary.appended != 0 {
				t.Fatalf("primary appends = %d, want 0", primary.appended)
			}
			if len(quarantined.rows) != 1 {
				t.Fatalf("quarantine rows = %d, want 1", len(quarantined.rows))
			}
			if got := quarantined.rows[0]["error_code"]; got != "OFFLOAD_PERMANENT" {
				t.Errorf("quarantine error_code = %v, want OFFLOAD_PERMANENT", got)
			}
			if got := quarantined.rows[0]["error_message"]; got != tc.wantDetail {
				t.Errorf("quarantine error_message = %q, want %q", got, tc.wantDetail)
			}
			if got := metricInt64SumWithAttr(t, reader, "otelcol_exporter_bigquery_rejected_rows", "reason", "offload_permanent"); got != 1 {
				t.Errorf("rejected_rows{reason=offload_permanent} = %d, want 1", got)
			}
			if got := metricInt64SumWithAttr(t, reader, "otelcol_exporter_bigquery_quarantined_rows", "reason", "offload_permanent"); got != 1 {
				t.Errorf("quarantined_rows{reason=offload_permanent} = %d, want 1", got)
			}
			if got := metricInt64SumWithAttr(t, reader, "otelcol_exporter_bigquery_offload_errors", "class", tc.wantErrCode); got != 1 {
				t.Errorf("offload_errors{class=%s} = %d, want 1", tc.wantErrCode, got)
			}

			entries := recorded.FilterMessage("dropping record due to permanent payload offload error").All()
			if len(entries) != 1 {
				t.Fatalf("permanent offload drop warning count = %d, want 1 (all=%+v)", len(entries), recorded.All())
			}
			ctxMap := entries[0].ContextMap()
			if gotErrCode, _ := ctxMap["error_code"].(string); gotErrCode != tc.wantErrCode {
				t.Errorf("warning log error_code = %v, want %q", ctxMap["error_code"], tc.wantErrCode)
			}
			if _, hasErr := ctxMap["error"]; hasErr {
				t.Errorf("warning log unexpectedly contains raw error field: %+v", ctxMap)
			}
			encodedFields, err := json.Marshal(ctxMap)
			if err != nil {
				t.Fatalf("marshal log context: %v", err)
			}
			serialized := string(encodedFields)
			forbidden := append([]string{"otel-offload", payloadSHA}, tc.forbiddenExtra...)
			for _, tok := range forbidden {
				if strings.Contains(serialized, tok) {
					t.Errorf("warning log context %s leaked %q", serialized, tok)
				}
			}
		})
	}
}
