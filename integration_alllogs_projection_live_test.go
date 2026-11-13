// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// TestLiveLogsAsAllLogsSeverityAndLogIDProjection runs the exact
// otel_logs_as_alllogs query in BigQuery over inline otel_logs rows (no
// dataset or table is created) and checks the canonical Cloud Logging
// LogSeverity pair, the raw OTLP severity columns and the URL-decoded log_id
// against both fixed expectations and the Go model that the hermetic view
// conformance tests use.
func TestLiveLogsAsAllLogsSeverityAndLogIDProjection(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live otel_logs_as_alllogs projection test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, []string{bigqueryapi.BigqueryScope})
	if err != nil {
		t.Fatalf("create HTTP client: %v", err)
	}
	client, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery client: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close BigQuery client: %v", err)
		}
		closeHTTP()
	})

	type row struct {
		key, logName, text string
		number             *int64
		wantSeverity       string
		wantNumber         int64
		wantLogID          *string
	}
	num := func(n int64) *int64 { return &n }
	str := func(s string) *string { return &s }
	rows := []row{
		{"r01", "projects/p/logs/cloudaudit.googleapis.com%2Fdata_access", "", num(17), "ERROR", 500, str("cloudaudit.googleapis.com/data_access")},
		{"r02", "projects/p/logs/a%252Fb", "WARN", num(13), "WARNING", 400, str("a%2Fb")},
		{"r03", "projects/p/logs/plain", "FATAL", num(21), "CRITICAL", 600, str("plain")},
		{"r04", "projects/p/logs/x%ZZy", "INFO", num(9), "INFO", 200, str("x%ZZy")},
		{"r05", "projects/p/logs/caf%C3%A9", "NOTICE", num(10), "INFO", 200, str("caf\u00e9")},
		{"r06", "projects/p/logs/bad%FFutf", "DEBUG", num(5), "DEBUG", 100, str("bad%FFutf")},
		{"r07", "projects/p/logs/trail%", "ERROR", num(0), "ERROR", 500, str("trail%")},
		{"r08", "projects/p/logs/%2f%3A%20x", "", num(0), "DEFAULT", 0, str("/: x")},
		{"r09", "", "WARN", num(0), "WARNING", 400, str("")},
		{"r10", "service-only", "", nil, "DEFAULT", 0, str("service-only")},
		{"r11", "projects/p/logs/%25", "ALERT", num(22), "CRITICAL", 600, str("%")},
		{"r12", "projects/p/logs/a%2", " emergency ", num(24), "EMERGENCY", 800, str("a%2")},
		{"r13", "projects/p/logs/app", "CRITICAL", num(17), "ERROR", 500, str("app")},
		{"r14", "projects/p/logs/app", "Warning", num(12), "NOTICE", 300, str("app")},
		{"r15", "projects/p/logs/app", "FATAL", num(0), "CRITICAL", 600, str("app")},
		{"r16", "projects/p/logs/app", "trace2", num(-3), "DEBUG", 100, str("app")},
		{"r18", "projects/p/logs/app", "", num(11), "NOTICE", 300, str("app")},
		{"r19", "projects/p/logs/app", "", num(23), "ALERT", 700, str("app")},
	}
	var lits []string
	for _, r := range rows {
		n := "CAST(NULL AS INT64)"
		if r.number != nil {
			n = fmt.Sprint(*r.number)
		}
		lits = append(lits, fmt.Sprintf("STRUCT(%q AS insert_id, %q AS log_name, %q AS severity_text, %s AS severity_number)", r.key, r.logName, r.text, n))
	}
	// One extra row with a NULL log_name, whose log_id must stay NULL.
	lits = append(lits, `STRUCT("r17" AS insert_id, CAST(NULL AS STRING) AS log_name, "FATAL" AS severity_text, 0 AS severity_number)`)
	inline := `(
  SELECT
    TIMESTAMP '2026-08-12 10:00:00+00' AS timestamp, TIMESTAMP '2026-08-12 10:00:01+00' AS receive_time,
    r.insert_id, r.log_name, r.severity_text, r.severity_number,
    JSON '"body"' AS body, JSON '{}' AS attributes, STRUCT(JSON '{}' AS attributes) AS resource,
    'svc' AS service_name, 'tid' AS trace_id, 'sid' AS span_id, 1 AS flags
  FROM UNNEST([` + strings.Join(lits, ",\n    ") + `]) AS r
)`
	view := fmt.Sprintf(schema.LogsAsAllLogsViewQuery, "p", "d", "otel_logs")
	const from = "FROM `p.d.otel_logs`"
	if strings.Count(view, from) != 1 {
		t.Fatalf("otel_logs_as_alllogs must read %s exactly once:\n%s", from, view)
	}
	sql := "SELECT insert_id, severity, severity_number, otel_severity_number, otel_severity_text, log_id FROM (" +
		strings.Replace(view, from, "FROM "+inline, 1) + ") ORDER BY insert_id"
	q := client.Query(sql)
	q.Location = location
	it, err := q.Read(ctx)
	if err != nil {
		t.Fatalf("run otel_logs_as_alllogs over inline rows: %v\n%s", err, sql)
	}
	got := map[string][]bq.Value{}
	for {
		var vals []bq.Value
		err := it.Next(&vals)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			t.Fatalf("read rows: %v", err)
		}
		got[vals[0].(string)] = vals
	}
	if len(got) != len(rows)+1 {
		t.Fatalf("got %d rows, want %d", len(got), len(rows)+1)
	}
	for _, r := range rows {
		vals := got[r.key]
		modelName, modelNum := allLogsCanonicalSeverity(r.number, r.text)
		if vals[1] != r.wantSeverity || vals[2] != r.wantNumber || modelName != r.wantSeverity || modelNum != r.wantNumber {
			t.Errorf("%s (%v, %q): BigQuery severity = %v, %v; model = %s, %d; want %s, %d",
				r.key, r.number, r.text, vals[1], vals[2], modelName, modelNum, r.wantSeverity, r.wantNumber)
		}
		if r.number == nil && vals[3] != nil || r.number != nil && vals[3] != *r.number {
			t.Errorf("%s: otel_severity_number = %v, want the raw %v", r.key, vals[3], r.number)
		}
		if vals[4] != r.text {
			t.Errorf("%s: otel_severity_text = %v, want the raw %q", r.key, vals[4], r.text)
		}
		logIDModel := r.logName
		if i := strings.LastIndex(logIDModel, "/logs/"); i >= 0 && logIDModel[i+len("/logs/"):] != "" && !strings.Contains(logIDModel[i+len("/logs/"):], "/") {
			logIDModel = logIDModel[i+len("/logs/"):]
		}
		logIDModel = allLogsDecodeLogID(logIDModel)
		if vals[5] != *r.wantLogID || logIDModel != *r.wantLogID {
			t.Errorf("%s: BigQuery log_id of %q = %v, model = %q, want %q", r.key, r.logName, vals[5], logIDModel, *r.wantLogID)
		}
	}
	if vals := got["r17"]; vals[1] != "CRITICAL" || vals[2] != int64(600) || vals[5] != nil {
		t.Errorf("NULL log_name row = %v, want CRITICAL, 600 and a NULL log_id", vals)
	}

	// Verify HTTP request_size / response_size precedence in live BigQuery SQL:
	// total-size attributes win over body-size, body-size falls back cleanly,
	// total-size alone populates http_request, and absent sizes stay NULL.
	httpInline := `(
  SELECT
    TIMESTAMP '2026-08-12 10:00:00+00' AS timestamp, TIMESTAMP '2026-08-12 10:00:01+00' AS receive_time,
    r.insert_id, 'projects/p/logs/http' AS log_name, '' AS severity_text, 9 AS severity_number,
    JSON '"ok"' AS body, PARSE_JSON(r.attrs) AS attributes, STRUCT(JSON '{}' AS attributes) AS resource,
    'svc' AS service_name, 'tid' AS trace_id, 'sid' AS span_id, 1 AS flags
  FROM UNNEST([
    STRUCT('h1' AS insert_id, '{"http.request.method":"POST","http.request.size":"1280","http.request.body.size":"1024","http.response.size":"4096","http.response.body.size":"3500"}' AS attrs),
    STRUCT('h2' AS insert_id, '{"http.request.method":"PUT","http.request.body.size":"512","http.response.body.size":"256"}' AS attrs),
    STRUCT('h3' AS insert_id, '{"http.request.size":"64","http.response.size":"128"}' AS attrs),
    STRUCT('h4' AS insert_id, '{"http.request.method":"GET"}' AS attrs)
  ]) AS r
)`
	httpSQL := "SELECT insert_id, http_request.request_size, http_request.response_size, http_request IS NOT NULL AS has_http FROM (" +
		strings.Replace(view, from, "FROM "+httpInline, 1) + ") ORDER BY insert_id"
	hq := client.Query(httpSQL)
	hq.Location = location
	hit, err := hq.Read(ctx)
	if err != nil {
		t.Fatalf("run otel_logs_as_alllogs HTTP size query: %v\n%s", err, httpSQL)
	}
	gotHTTP := map[string][]bq.Value{}
	for {
		var vals []bq.Value
		err := hit.Next(&vals)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			t.Fatalf("read HTTP size rows: %v", err)
		}
		gotHTTP[vals[0].(string)] = vals
	}
	for _, tc := range []struct {
		key      string
		wantReq  any
		wantResp any
	}{
		{"h1", int64(1280), int64(4096)},
		{"h2", int64(512), int64(256)},
		{"h3", int64(64), int64(128)},
		{"h4", nil, nil},
	} {
		vals := gotHTTP[tc.key]
		if len(vals) != 4 || vals[3] != true || vals[1] != tc.wantReq || vals[2] != tc.wantResp {
			t.Errorf("%s: BigQuery http_request (req, resp, present) = %v, want (%v, %v, true)", tc.key, vals, tc.wantReq, tc.wantResp)
		}
	}
}
