// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/metric/noop"
	"go.uber.org/zap"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/backfill"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/validate"
)

func cliLiveGateDecision(project, bucket string, requireBQ, requireGCS bool) (runBQ, runGCS bool, fatalMsg, skipMsg string) {
	if project == "" {
		if requireBQ || requireGCS {
			return false, false, fmt.Sprintf(
				"live verification requested (REQUIRE_LIVE_BQ=%v REQUIRE_LIVE_GCS=%v) but BQ_PROJECT is unset",
				requireBQ, requireGCS,
			), ""
		}
		return false, false, "", "BQ_PROJECT is unset; skipping live CLI binaries end-to-end BigQuery test"
	}
	if bucket == "" {
		if requireGCS {
			return false, false, "REQUIRE_LIVE_GCS=1 but BQ_OFFLOAD_TEST_BUCKET is unset", ""
		}
		return true, false, "", ""
	}
	return true, true, "", ""
}

func TestCLILiveGatingLogic(t *testing.T) {
	for _, tc := range []struct {
		name       string
		project    string
		bucket     string
		requireBQ  bool
		requireGCS bool
		wantBQ     bool
		wantGCS    bool
		wantFatal  bool
		wantSkip   bool
	}{
		{name: "neither configured skips", wantSkip: true},
		{name: "missing project fails when REQUIRE_LIVE_BQ=1", requireBQ: true, wantFatal: true},
		{name: "missing project fails when REQUIRE_LIVE_GCS=1", bucket: "b", requireGCS: true, wantFatal: true},
		{name: "REQUIRE_LIVE_BQ=1 runs BigQuery without GCS bucket", project: "p", requireBQ: true, wantBQ: true, wantGCS: false},
		{name: "missing bucket fails when REQUIRE_LIVE_GCS=1", project: "p", requireBQ: true, requireGCS: true, wantFatal: true},
		{name: "project and bucket enable both", project: "p", bucket: "b", requireBQ: true, requireGCS: true, wantBQ: true, wantGCS: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotBQ, gotGCS, fatalMsg, skipMsg := cliLiveGateDecision(tc.project, tc.bucket, tc.requireBQ, tc.requireGCS)
			if gotBQ != tc.wantBQ || gotGCS != tc.wantGCS {
				t.Fatalf("got (bq=%v, gcs=%v), want (bq=%v, gcs=%v)", gotBQ, gotGCS, tc.wantBQ, tc.wantGCS)
			}
			if (fatalMsg != "") != tc.wantFatal {
				t.Fatalf("fatalMsg=%q, wantFatal=%v", fatalMsg, tc.wantFatal)
			}
			if (skipMsg != "") != tc.wantSkip {
				t.Fatalf("skipMsg=%q, wantSkip=%v", skipMsg, tc.wantSkip)
			}
		})
	}
}

func TestLiveCLIBinariesEndToEndBigQuery(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	bucket := os.Getenv("BQ_OFFLOAD_TEST_BUCKET")
	if bucket == "" {
		bucket = os.Getenv("BQ_OFFLOAD_BUCKET")
	}
	runBQ, runGCS, fatalMsg, skipMsg := cliLiveGateDecision(
		project,
		bucket,
		os.Getenv("REQUIRE_LIVE_BQ") == "1",
		os.Getenv("REQUIRE_LIVE_GCS") == "1",
	)
	if fatalMsg != "" {
		t.Fatal(fatalMsg)
	}
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if !runBQ {
		t.Fatal("cliLiveGateDecision returned runBQ=false without fatal or skip reason")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Minute)
	t.Cleanup(cancel)

	httpClient, _, closeHTTP, err := googlehttp.NewClient(ctx, []string{
		bigqueryapi.BigqueryScope,
		"https://www.googleapis.com/auth/devstorage.read_write",
	})
	if err != nil {
		t.Fatalf("create Google HTTP client: %v", err)
	}
	admin, err := bq.NewClient(ctx, project, option.WithHTTPClient(httpClient))
	if err != nil {
		closeHTTP()
		t.Fatalf("create BigQuery admin client: %v", err)
	}
	admin.Location = location

	dataset := uniqueEphemeralDatasetID("otel_cli_it")
	prefix := fmt.Sprintf("it-offload-cli-%d", time.Now().UnixNano())

	// LIFO cleanup order:
	// 1. Delete GCS prefix and owned ephemeral BigQuery dataset.
	// 2. Verify dataset metadata returns HTTP 404 after deletion.
	// 3. Close BigQuery admin and HTTP clients.
	t.Cleanup(func() {
		if err := admin.Close(); err != nil {
			t.Errorf("close BigQuery admin client: %v", err)
		}
		closeHTTP()
	})
	t.Cleanup(func() {
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer verifyCancel()
		_, metaErr := admin.Dataset(dataset).Metadata(verifyCtx)
		var gErr *googleapi.Error
		if !errors.As(metaErr, &gErr) || gErr.Code != stdhttp.StatusNotFound {
			t.Errorf("expected HTTP 404 after deleting ephemeral dataset %s.%s, got err=%v", project, dataset, metaErr)
		}
	})
	if err := createOwnedEphemeralDataset(ctx, admin, dataset, location, t.Cleanup, func(err error) {
		t.Errorf("%v", err)
	}); err != nil {
		t.Fatalf("create dataset %s.%s: %v", project, dataset, err)
	}
	if runGCS {
		t.Cleanup(func() {
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
			defer cleanupCancel()
			listAndDeleteGCSPrefix(cleanupCtx, t, httpClient, bucket, prefix+"/")
		})
	}

	binDir := t.TempDir()
	bins := make(map[string]string, 5)
	for _, name := range []string{
		"bq-otel-testbench",
		"bq-otel-validate",
		"bq-otel-backfill",
		"bq-quarantine-replay",
		"healthcheck",
	} {
		outPath := filepath.Join(binDir, name)
		buildCmd := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/"+name)
		if out, buildErr := buildCmd.CombinedOutput(); buildErr != nil {
			t.Fatalf("go build ./cmd/%s: %v\n%s", name, buildErr, out)
		}
		bins[name] = outPath
	}

	provisionLiveCLIDataset(ctx, t, project, dataset, location)

	t.Run("help-exit-zero", func(t *testing.T) {
		for _, name := range []string{
			"bq-otel-testbench",
			"bq-otel-validate",
			"bq-otel-backfill",
			"bq-quarantine-replay",
		} {
			stdout, stderr, exitCode := runCLISubprocess(ctx, bins[name], "-h")
			if exitCode != 0 || stdout != "" {
				t.Fatalf("%s -h exited %d (stdout=%q stderr=%q), want exit 0 and empty stdout", name, exitCode, stdout, stderr)
			}
			if name == "bq-otel-testbench" && (strings.Contains(stderr, "bq-otel-testbench: ") || strings.Contains(stderr, "flag: help requested")) {
				t.Fatalf("bq-otel-testbench -h emitted unexpected error prefix: %q", stderr)
			}
		}
	})

	t.Run("bq-otel-testbench", func(t *testing.T) {
		stdout, stderr, exitCode := runCLISubprocess(ctx, bins["bq-otel-testbench"],
			"-mode=live",
			"-project="+project,
			"-dataset="+dataset,
			"-location="+location,
			"-signals=traces,logs,metrics",
			"-duration=2s",
			"-batch-size=5",
			"-workers=1",
			"-stream-pool-size=1",
			"-connection-pool-size=1",
			"-format=json",
		)
		if exitCode != 0 {
			t.Fatalf("bq-otel-testbench exited %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		var report struct {
			Results []struct {
				Signal           string `json:"signal"`
				BatchesFailed    int64  `json:"batches_failed"`
				RecordsSubmitted int64  `json:"records_submitted"`
			} `json:"results"`
		}
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("decode bq-otel-testbench JSON report: %v\nstdout:\n%s", err, stdout)
		}
		if len(report.Results) != 3 {
			t.Fatalf("len(report.Results) = %d, want 3\nstdout:\n%s", len(report.Results), stdout)
		}
		for _, res := range report.Results {
			if res.BatchesFailed != 0 {
				t.Errorf("signal %s BatchesFailed = %d, want 0", res.Signal, res.BatchesFailed)
			}
			if res.RecordsSubmitted <= 0 {
				t.Errorf("signal %s RecordsSubmitted = %d, want > 0", res.Signal, res.RecordsSubmitted)
			}
		}
	})

	t.Run("bq-otel-validate", func(t *testing.T) {
		stdout, stderr, exitCode := runCLISubprocess(ctx, bins["bq-otel-validate"],
			"-project="+project,
			"-dataset="+dataset,
			"-format=json",
		)
		if exitCode != 0 {
			t.Fatalf("bq-otel-validate exited %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		var report validate.Report
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("decode bq-otel-validate JSON report: %v\nstdout:\n%s", err, stdout)
		}
		if !report.Conforms || report.Summary.Fail != 0 {
			t.Fatalf("bq-otel-validate report non-conforming: conforms=%v summary=%+v\nstdout:\n%s", report.Conforms, report.Summary, stdout)
		}

		_, negStderr, negExit := runCLISubprocess(ctx, bins["bq-otel-validate"],
			"-project="+project,
			"-dataset=nonexistent_cli_it_xyz",
			"-format=json",
		)
		if negExit == 0 {
			t.Fatalf("bq-otel-validate against nonexistent dataset exited 0, want non-zero (stderr=%s)", negStderr)
		}
	})

	t.Run("bq-otel-backfill", func(t *testing.T) {
		if !runGCS {
			t.Skip("BQ_OFFLOAD_TEST_BUCKET is unset and REQUIRE_LIVE_GCS!=1; skipping GCS-backed backfill subtest")
		}
		const (
			authSecret   = "Bearer cli-live-secret-999"
			apiKeySecret = "secret-cli-key-999"
		)
		now := time.Now().UTC().Add(-2 * time.Minute)
		traceBytes := buildBackfillTraceJSONLine(t, now, authSecret, apiKeySecret)
		logBytes := buildBackfillLogJSONLine(t, now, authSecret)

		var gzBuf bytes.Buffer
		gzw := gzip.NewWriter(&gzBuf)
		if _, err := gzw.Write(append(append([]byte(nil), traceBytes...), '\n')); err != nil {
			t.Fatalf("gzip write trace line: %v", err)
		}
		if _, err := gzw.Write(append(append([]byte(nil), logBytes...), '\n')); err != nil {
			t.Fatalf("gzip write log line: %v", err)
		}
		if err := gzw.Close(); err != nil {
			t.Fatalf("gzip close: %v", err)
		}

		gcsStore, err := offload.NewGCSBlobStore(ctx)
		if err != nil {
			t.Fatalf("NewGCSBlobStore: %v", err)
		}
		defer func() {
			if cerr := gcsStore.Close(); cerr != nil {
				t.Errorf("close GCS blob store: %v", cerr)
			}
		}()
		objName := prefix + "/backfill/batch.jsonl.gz"
		if _, err := gcsStore.WriteObject(ctx, bucket, objName, "application/gzip", gzBuf.Bytes()); err != nil {
			t.Fatalf("upload backfill archive gs://%s/%s: %v", bucket, objName, err)
		}
		t.Cleanup(func() {
			cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cleanCancel()
			deleteGCSObject(cleanCtx, t, httpClient, "gs://"+bucket+"/"+objName)
		})

		// Explicitly pass -redact-keys= (empty) to verify implicit default
		// redaction via flag.Visit triggers on live GCS backfill as well.
		stdout, stderr, exitCode := runCLISubprocess(ctx, bins["bq-otel-backfill"],
			"-source-gcs-prefix=gs://"+bucket+"/"+prefix+"/backfill/",
			"-project="+project,
			"-dataset="+dataset,
			"-redact-keys=",
			"-format=json",
		)
		if exitCode != 0 {
			t.Fatalf("bq-otel-backfill exited %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		var report backfill.Report
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("decode bq-otel-backfill JSON report: %v\nstdout:\n%s", err, stdout)
		}
		if !report.Complete() {
			t.Fatalf("bq-otel-backfill report incomplete: %+v\nstdout:\n%s", report, stdout)
		}
		if report.Objects != 1 || report.Lines != 2 {
			t.Fatalf("unexpected backfill counts objects=%d lines=%d", report.Objects, report.Lines)
		}
		sigAppended := make(map[string]int64, len(report.Signals))
		for _, s := range report.Signals {
			sigAppended[s.Signal] = s.Appended
		}
		if sigAppended[backfill.SignalTraces] != 1 || sigAppended[backfill.SignalLogs] != 1 {
			t.Fatalf("appended signals = %v, want traces=1 logs=1", sigAppended)
		}

		q := admin.Query(fmt.Sprintf(`
			SELECT TO_JSON_STRING(attributes)
			FROM `+"`%s.%s.otel_spans_dedup`"+`
			WHERE start_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
			  AND service_name = 'cli-backfill-it'
			  AND name = 'cli-backfill-span'
		`, project, dataset))
		it, err := q.Read(ctx)
		if err != nil {
			t.Fatalf("query backfilled spans: %v", err)
		}
		var row []bq.Value
		if err := it.Next(&row); err != nil {
			t.Fatalf("read backfilled span row: %v", err)
		}
		attrsJSON, _ := row[0].(string)
		if !strings.Contains(attrsJSON, "[REDACTED]") {
			t.Errorf("backfilled span attributes missing [REDACTED]: %s", attrsJSON)
		}
		if strings.Contains(attrsJSON, authSecret) || strings.Contains(attrsJSON, apiKeySecret) {
			t.Fatalf("backfilled span attributes leaked cleartext secret: %s", attrsJSON)
		}

		logQ := admin.Query(fmt.Sprintf(`
			SELECT TO_JSON_STRING(attributes)
			FROM `+"`%s.%s.otel_logs_dedup`"+`
			WHERE timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 1 HOUR)
			  AND service_name = 'cli-backfill-it'
			  AND TO_JSON_STRING(body) LIKE '%%cli-backfill-log%%'
		`, project, dataset))
		logIt, err := logQ.Read(ctx)
		if err != nil {
			t.Fatalf("query backfilled logs: %v", err)
		}
		var logRow []bq.Value
		if err := logIt.Next(&logRow); err != nil {
			t.Fatalf("read backfilled log row: %v", err)
		}
		logAttrsJSON, _ := logRow[0].(string)
		if !strings.Contains(logAttrsJSON, "[REDACTED]") {
			t.Errorf("backfilled log attributes missing [REDACTED]: %s", logAttrsJSON)
		}
		if strings.Contains(logAttrsJSON, authSecret) {
			t.Fatalf("backfilled log attributes leaked cleartext secret: %s", logAttrsJSON)
		}
	})

	t.Run("bq-quarantine-replay", func(t *testing.T) {
		now := time.Now().UTC().Add(-1 * time.Minute)
		traceID1 := "11111111111111111111111111111111"
		spanID1 := "1111111111111111"
		traceID2 := "22222222222222222222222222222222"
		spanID2 := "2222222222222222"
		raw1 := buildQuarantineSpanPayload(t, now, "cli-replay-span-1", traceID1, spanID1)
		raw2 := buildQuarantineSpanPayload(t, now.Add(time.Second), "cli-replay-span-2", traceID2, spanID2)

		insertQ := admin.Query(fmt.Sprintf(`
			INSERT INTO `+"`%s.%s.otel_quarantine`"+`
				(ingest_time, signal, error_code, error_message, service_name, trace_id, span_id, raw_payload)
			VALUES
				(@t1, 'spans', 'OVERSIZE_ROW', 'cli live test 1', 'cli-replay-it', @tid1, @sid1, @raw1),
				(@t2, 'spans', 'OVERSIZE_ROW', 'cli live test 2', 'cli-replay-it', @tid2, @sid2, @raw2)
		`, project, dataset))
		insertQ.Parameters = []bq.QueryParameter{
			{Name: "t1", Value: now},
			{Name: "t2", Value: now.Add(time.Second)},
			{Name: "tid1", Value: traceID1},
			{Name: "sid1", Value: spanID1},
			{Name: "tid2", Value: traceID2},
			{Name: "sid2", Value: spanID2},
			{Name: "raw1", Value: string(raw1)},
			{Name: "raw2", Value: string(raw2)},
		}
		job, err := insertQ.Run(ctx)
		if err != nil {
			t.Fatalf("start INSERT INTO otel_quarantine job: %v", err)
		}
		status, err := job.Wait(ctx)
		if err != nil {
			t.Fatalf("wait INSERT INTO otel_quarantine: %v", err)
		}
		if err := status.Err(); err != nil {
			t.Fatalf("INSERT INTO otel_quarantine failed: %v", err)
		}

		otlpSrv, getNames := startLiveTraceReceiver(t)
		defer otlpSrv.Close()

		cpPath := filepath.Join(t.TempDir(), "replay.checkpoint.json")
		stdout, stderr, exitCode := runCLISubprocess(ctx, bins["bq-quarantine-replay"],
			"-bq-project="+project,
			"-bq-dataset="+dataset,
			"-otlp-endpoint="+otlpSrv.URL,
			"-checkpoint-file="+cpPath,
		)
		if exitCode != 0 {
			t.Fatalf("bq-quarantine-replay run 1 exited %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		gotFirst := getNames()
		slices.Sort(gotFirst)
		wantFirst := []string{"cli-replay-span-1", "cli-replay-span-2"}
		if !slices.Equal(gotFirst, wantFirst) {
			t.Fatalf("run 1 delivered spans = %v, want %v\nstderr:\n%s", gotFirst, wantFirst, stderr)
		}
		if !strings.Contains(stderr, "replayed_spans=2") {
			t.Errorf("run 1 stderr missing replayed_spans=2:\n%s", stderr)
		}

		stdout2, stderr2, exitCode2 := runCLISubprocess(ctx, bins["bq-quarantine-replay"],
			"-bq-project="+project,
			"-bq-dataset="+dataset,
			"-otlp-endpoint="+otlpSrv.URL,
			"-checkpoint-file="+cpPath,
		)
		if exitCode2 != 0 {
			t.Fatalf("bq-quarantine-replay run 2 exited %d\nstdout:\n%s\nstderr:\n%s", exitCode2, stdout2, stderr2)
		}
		if gotSecondTotal := len(getNames()); gotSecondTotal != 2 {
			t.Fatalf("run 2 delivered duplicates: total spans = %d, want 2", gotSecondTotal)
		}
		if !strings.Contains(stderr2, "total_read=0") || !strings.Contains(stderr2, "replayed_spans=0") {
			t.Errorf("run 2 stderr want total_read=0 and replayed_spans=0:\n%s", stderr2)
		}
	})

	t.Run("regional-eu-auto-location", func(t *testing.T) {
		euDataset := uniqueEphemeralDatasetID("otel_cli_eu_it")
		t.Cleanup(func() {
			verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer verifyCancel()
			_, metaErr := admin.Dataset(euDataset).Metadata(verifyCtx)
			var gErr *googleapi.Error
			if !errors.As(metaErr, &gErr) || gErr.Code != stdhttp.StatusNotFound {
				t.Errorf("expected HTTP 404 after deleting ephemeral EU dataset %s.%s, got err=%v", project, euDataset, metaErr)
			}
		})
		if err := createOwnedEphemeralDataset(ctx, admin, euDataset, "EU", t.Cleanup, func(err error) {
			t.Errorf("%v", err)
		}); err != nil {
			t.Fatalf("create EU dataset %s.%s: %v", project, euDataset, err)
		}
		provisionLiveCLIDataset(ctx, t, project, euDataset, "EU")

		// Omit -location so bq-otel-validate auto-detects EU from dataset metadata.
		stdout, stderr, exitCode := runCLISubprocess(ctx, bins["bq-otel-validate"],
			"-project="+project,
			"-dataset="+euDataset,
			"-format=json",
		)
		if exitCode != 0 {
			t.Fatalf("EU bq-otel-validate (auto location) exited %d\nstdout:\n%s\nstderr:\n%s", exitCode, stdout, stderr)
		}
		var report validate.Report
		if err := json.Unmarshal([]byte(stdout), &report); err != nil {
			t.Fatalf("decode EU bq-otel-validate JSON report: %v\nstdout:\n%s", err, stdout)
		}
		if !report.Conforms || report.Summary.Fail != 0 {
			t.Fatalf("EU bq-otel-validate report non-conforming: conforms=%v summary=%+v\nstdout:\n%s", report.Conforms, report.Summary, stdout)
		}

		// Also verify explicit -location=EU succeeds on views dry-runs.
		stdoutExp, stderrExp, exitExp := runCLISubprocess(ctx, bins["bq-otel-validate"],
			"-project="+project,
			"-dataset="+euDataset,
			"-location=EU",
			"-checks=views",
			"-format=json",
		)
		if exitExp != 0 {
			t.Fatalf("EU bq-otel-validate (-location=EU) exited %d\nstdout:\n%s\nstderr:\n%s", exitExp, stdoutExp, stderrExp)
		}

		// Insert a quarantine row into EU and verify bq-quarantine-replay
		// auto-detects EU without -bq-location.
		now := time.Now().UTC().Add(-1 * time.Minute)
		traceID := "33333333333333333333333333333333"
		spanID := "3333333333333333"
		raw := buildQuarantineSpanPayload(t, now, "eu-replay-span-1", traceID, spanID)
		insertQ := admin.Query(fmt.Sprintf(`
			INSERT INTO `+"`%s.%s.otel_quarantine`"+`
				(ingest_time, signal, error_code, error_message, service_name, trace_id, span_id, raw_payload)
			VALUES
				(@t1, 'spans', 'OVERSIZE_ROW', 'eu cli live test', 'cli-replay-it', @tid1, @sid1, @raw1)
		`, project, euDataset))
		insertQ.Location = "EU"
		insertQ.Parameters = []bq.QueryParameter{
			{Name: "t1", Value: now},
			{Name: "tid1", Value: traceID},
			{Name: "sid1", Value: spanID},
			{Name: "raw1", Value: string(raw)},
		}
		job, err := insertQ.Run(ctx)
		if err != nil {
			t.Fatalf("start EU INSERT INTO otel_quarantine job: %v", err)
		}
		status, err := job.Wait(ctx)
		if err != nil {
			t.Fatalf("wait EU INSERT INTO otel_quarantine: %v", err)
		}
		if err := status.Err(); err != nil {
			t.Fatalf("EU INSERT INTO otel_quarantine failed: %v", err)
		}

		otlpSrv, getNames := startLiveTraceReceiver(t)
		defer otlpSrv.Close()

		stdoutR, stderrR, exitR := runCLISubprocess(ctx, bins["bq-quarantine-replay"],
			"-bq-project="+project,
			"-bq-dataset="+euDataset,
			"-otlp-endpoint="+otlpSrv.URL,
		)
		if exitR != 0 {
			t.Fatalf("EU bq-quarantine-replay (auto location) exited %d\nstdout:\n%s\nstderr:\n%s", exitR, stdoutR, stderrR)
		}
		if got := getNames(); !slices.Equal(got, []string{"eu-replay-span-1"}) {
			t.Fatalf("EU replay delivered spans = %v, want [eu-replay-span-1]\nstderr:\n%s", got, stderrR)
		}
	})

	t.Run("healthcheck", func(t *testing.T) {
		var redirectTargetHits atomic.Int32
		redirectTarget := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
			redirectTargetHits.Add(1)
			w.WriteHeader(stdhttp.StatusOK)
		}))
		defer redirectTarget.Close()

		probeSrv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			switch r.URL.Path {
			case "/ok":
				w.WriteHeader(stdhttp.StatusOK)
			case "/fail":
				w.WriteHeader(stdhttp.StatusServiceUnavailable)
			case "/redirect":
				stdhttp.Redirect(w, r, redirectTarget.URL+"/target", stdhttp.StatusFound)
			default:
				w.WriteHeader(stdhttp.StatusNotFound)
			}
		}))
		defer probeSrv.Close()

		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], probeSrv.URL+"/ok"); code != 0 {
			t.Fatalf("healthcheck /ok exited %d, stderr=%s", code, stderr)
		}
		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], probeSrv.URL+"/fail"); code != 1 || !strings.Contains(stderr, "unhealthy status 503") {
			t.Fatalf("healthcheck /fail exited %d (want 1), stderr=%s", code, stderr)
		}
		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], probeSrv.URL+"/redirect"); code != 1 || !strings.Contains(stderr, "unhealthy status 302") {
			t.Fatalf("healthcheck /redirect exited %d (want 1), stderr=%s", code, stderr)
		}
		if redirectTargetHits.Load() != 0 {
			t.Fatalf("healthcheck followed redirect %d times, want 0", redirectTargetHits.Load())
		}
		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], "ftp://127.0.0.1:13133/"); code != 1 || !strings.Contains(stderr, "invalid healthcheck URL scheme") {
			t.Fatalf("healthcheck invalid scheme exited %d (want 1), stderr=%s", code, stderr)
		}
		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], probeSrv.URL+"/ok", "extra"); code != 2 || !strings.Contains(stderr, "usage:") {
			t.Fatalf("healthcheck extra arg exited %d (want 2), stderr=%s", code, stderr)
		}

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen ephemeral port: %v", err)
		}
		closedAddr := ln.Addr().String()
		if err := ln.Close(); err != nil {
			t.Fatalf("close listener: %v", err)
		}
		if _, stderr, code := runCLISubprocess(ctx, bins["healthcheck"], "http://"+closedAddr+"/"); code != 1 {
			t.Fatalf("healthcheck closed port exited %d (want 1), stderr=%s", code, stderr)
		}
	})
}

func provisionLiveCLIDataset(ctx context.Context, t *testing.T, project, dataset, location string) {
	t.Helper()

	cfg := validConfig()
	cfg.Project = project
	cfg.Dataset = dataset
	cfg.Location = location
	cfg.AutoCreate.Dataset = false
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = true
	cfg.Quarantine.Enabled = true
	cfg.Traces.RequirePartitionFilter = false
	cfg.Logs.RequirePartitionFilter = false
	cfg.Metrics.RequirePartitionFilter = false
	cfg.Quarantine.RequirePartitionFilter = false

	settings := component.TelemetrySettings{
		Logger:        zap.NewNop(),
		MeterProvider: noop.NewMeterProvider(),
	}

	// Start logs and metrics before traces so the traces exporter finds their
	// _dedup views and creates all 11 companion views cleanly.
	logs, err := newLogsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newLogsExporter: %v", err)
	}
	if err := logs.start(ctx, nil); err != nil {
		t.Fatalf("logs.start: %v", err)
	}
	if err := logs.shutdown(ctx); err != nil {
		t.Fatalf("logs.shutdown: %v", err)
	}

	metrics, err := newMetricsExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newMetricsExporter: %v", err)
	}
	if err := metrics.start(ctx, nil); err != nil {
		t.Fatalf("metrics.start: %v", err)
	}
	if err := metrics.shutdown(ctx); err != nil {
		t.Fatalf("metrics.shutdown: %v", err)
	}

	traces, err := newTracesExporter(settings, cfg)
	if err != nil {
		t.Fatalf("newTracesExporter: %v", err)
	}
	if err := traces.start(ctx, nil); err != nil {
		t.Fatalf("traces.start: %v", err)
	}
	if err := traces.shutdown(ctx); err != nil {
		t.Fatalf("traces.shutdown: %v", err)
	}
}

func runCLISubprocess(ctx context.Context, binPath string, args ...string) (stdout, stderr string, exitCode int) {
	cmd := exec.CommandContext(ctx, binPath, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if err == nil {
		return outBuf.String(), errBuf.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return outBuf.String(), errBuf.String(), exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String() + "\n" + err.Error(), -1
}

func buildBackfillTraceJSONLine(t *testing.T, ts time.Time, authSecret, apiKeySecret string) []byte {
	t.Helper()
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "cli-backfill-it")
	sp := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	sp.SetName("cli-backfill-span")
	sp.SetTraceID(pcommon.TraceID{9, 9, 9, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})
	sp.SetSpanID(pcommon.SpanID{9, 9, 1, 2, 3, 4, 5, 6})
	sp.SetStartTimestamp(pcommon.NewTimestampFromTime(ts))
	sp.SetEndTimestamp(pcommon.NewTimestampFromTime(ts.Add(250 * time.Millisecond)))
	sp.Attributes().PutStr("authorization", authSecret)
	sp.Attributes().PutStr("api-key", apiKeySecret)
	sp.Attributes().PutStr("safe.tag", "ok")
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatalf("marshal backfill traces: %v", err)
	}
	return raw
}

func buildBackfillLogJSONLine(t *testing.T, ts time.Time, authSecret string) []byte {
	t.Helper()
	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "cli-backfill-it")
	lr := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	lr.SetTimestamp(pcommon.NewTimestampFromTime(ts))
	lr.Body().SetStr("cli-backfill-log")
	lr.Attributes().PutStr("authorization", authSecret)
	lr.Attributes().PutStr("safe.tag", "ok")
	raw, err := (&plog.JSONMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatalf("marshal backfill logs: %v", err)
	}
	return raw
}

func buildQuarantineSpanPayload(t *testing.T, ts time.Time, name, traceHex, spanHex string) []byte {
	t.Helper()
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", "cli-replay-it")
	sp := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	sp.SetName(name)
	var tid pcommon.TraceID
	for i := range tid {
		_, _ = fmt.Sscanf(traceHex[2*i:2*i+2], "%02x", &tid[i])
	}
	var sid pcommon.SpanID
	for i := range sid {
		_, _ = fmt.Sscanf(spanHex[2*i:2*i+2], "%02x", &sid[i])
	}
	sp.SetTraceID(tid)
	sp.SetSpanID(sid)
	sp.SetStartTimestamp(pcommon.NewTimestampFromTime(ts))
	sp.SetEndTimestamp(pcommon.NewTimestampFromTime(ts.Add(150 * time.Millisecond)))
	raw, err := (&ptrace.JSONMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatalf("marshal quarantine traces: %v", err)
	}
	return raw
}

func startLiveTraceReceiver(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var (
		mu            sync.Mutex
		receivedNames []string
	)
	srv := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
		if r.Method != stdhttp.MethodPost || r.URL.Path != "/v1/traces" {
			stdhttp.Error(w, "unexpected path", stdhttp.StatusNotFound)
			return
		}
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			stdhttp.Error(w, readErr.Error(), stdhttp.StatusBadRequest)
			return
		}
		req := ptraceotlp.NewExportRequest()
		if unmarshalErr := req.UnmarshalProto(body); unmarshalErr != nil {
			stdhttp.Error(w, unmarshalErr.Error(), stdhttp.StatusBadRequest)
			return
		}
		mu.Lock()
		rss := req.Traces().ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					receivedNames = append(receivedNames, spans.At(k).Name())
				}
			}
		}
		mu.Unlock()
		respBytes, marshalErr := ptraceotlp.NewExportResponse().MarshalProto()
		if marshalErr != nil {
			stdhttp.Error(w, marshalErr.Error(), stdhttp.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		_, _ = w.Write(respBytes)
	}))
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), receivedNames...)
	}
}
