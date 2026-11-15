// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	stdhttp "net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

// TestLiveExporterSelfTelemetryContract verifies that live BigQuery export of
// spans (including Step-0 redaction and over-limit quarantine routing), logs,
// and metrics emits the expected OpenTelemetry self-telemetry instruments and
// attributes declared in metadata.yaml and queried by
// dashboards/grafana/collector-self-telemetry.json.
func TestLiveExporterSelfTelemetryContract(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live exporter self-telemetry contract test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)

	env := newSelfTelemetryLiveEnv(ctx, t, project, location)
	exps := env.startExporters(ctx, t)
	env.seedAndWait(ctx, t, exps)
	env.verifyPrometheusSelfTelemetryContract(ctx, t)
}

type selfTelemetryLiveEnv struct {
	project      string
	location     string
	srcDataset   string
	runID        string
	recentBase   time.Time
	svcPrimary   string
	secretMarker string
	srcCreated   bool
	admin        *bq.Client
	reader       *sdkmetric.ManualReader
}

type selfTelemetryLiveExporters struct {
	traces  exporter.Traces
	logs    exporter.Logs
	metrics exporter.Metrics
}

func newSelfTelemetryLiveEnv(ctx context.Context, t *testing.T, project, location string) *selfTelemetryLiveEnv {
	t.Helper()
	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatalf("random run ID: %v", err)
	}
	runID := hex.EncodeToString(nonce[:])

	admin, _, cleanupAdmin := testsupport.NewLiveBigQueryClient(ctx, t, project)
	t.Cleanup(cleanupAdmin)

	now := time.Now().UTC().Truncate(time.Millisecond)
	env := &selfTelemetryLiveEnv{
		project:      project,
		location:     location,
		srcDataset:   testsupport.UniqueEphemeralDatasetID("otel_analytics_it"),
		runID:        runID,
		recentBase:   now.Add(-10 * time.Minute),
		svcPrimary:   "it-analytics-primary-" + runID,
		secretMarker: "sk-live-secret-" + runID,
		admin:        admin,
	}

	assertDatasetNotFound404(ctx, t, admin, env.srcDataset)
	t.Cleanup(func() {
		if !env.srcCreated {
			return
		}
		deleteDatasetAndVerify404(t, admin, env.srcDataset)
	})
	return env
}

func assertDatasetNotFound404(ctx context.Context, t *testing.T, admin *bq.Client, dataset string) {
	t.Helper()
	_, err := admin.Dataset(dataset).Metadata(ctx)
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != stdhttp.StatusNotFound {
		t.Fatalf("expected HTTP 404 before creating ephemeral dataset %s, got err=%v", dataset, err)
	}
}

func deleteDatasetAndVerify404(t *testing.T, admin *bq.Client, dataset string) {
	t.Helper()
	cleanCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := admin.Dataset(dataset).DeleteWithContents(cleanCtx); err != nil {
		t.Errorf("delete ephemeral dataset %s: %v", dataset, err)
		return
	}
	_, err := admin.Dataset(dataset).Metadata(cleanCtx)
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != stdhttp.StatusNotFound {
		t.Errorf("post-delete metadata check for %s = %v, want HTTP 404", dataset, err)
	}
}

func (e *selfTelemetryLiveEnv) startExporters(ctx context.Context, t *testing.T) selfTelemetryLiveExporters {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		sCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := mp.Shutdown(sCtx); err != nil {
			t.Errorf("shutdown meter provider: %v", err)
		}
	})
	e.reader = reader

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Project = e.project
	cfg.Dataset = e.srcDataset
	cfg.Location = e.location
	cfg.AutoCreate = AutoCreateConfig{
		Dataset: true,
		Tables:  true,
	}
	cfg.Quarantine = QuarantineConfig{
		Enabled:                 true,
		Table:                   "otel_quarantine",
		PartitionExpirationDays: 30,
		MaxRawPayloadBytes:      8388608,
		Timeout:                 5 * time.Second,
	}
	cfg.Limits.MaxAttributeCount = 64
	cfg.Write.Compression = "gzip"
	cfg.Write.Backpressure.Enabled = true
	cfg.Redaction = RedactionConfig{
		Enabled:              true,
		MaskReplacement:      "[REDACTED]",
		BlockedValuePatterns: []string{`sk-live-secret-[0-9a-f]+`},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	set := exportertest.NewNopSettings(factory.Type())
	set.Logger = zap.NewNop()
	set.MeterProvider = mp

	tExp, err := factory.CreateTraces(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}
	lExp, err := factory.CreateLogs(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateLogs: %v", err)
	}
	mExp, err := factory.CreateMetrics(ctx, set, cfg)
	if err != nil {
		t.Fatalf("CreateMetrics: %v", err)
	}

	stop := func(name string, fn func(context.Context) error) {
		t.Cleanup(func() {
			sCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := fn(sCtx); err != nil {
				t.Errorf("shutdown %s exporter: %v", name, err)
			}
		})
	}
	e.srcCreated = true
	if err := tExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start traces exporter: %v", err)
	}
	stop("traces", tExp.Shutdown)
	if err := lExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start logs exporter: %v", err)
	}
	stop("logs", lExp.Shutdown)
	if err := mExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("start metrics exporter: %v", err)
	}
	stop("metrics", mExp.Shutdown)

	return selfTelemetryLiveExporters{traces: tExp, logs: lExp, metrics: mExp}
}

func (e *selfTelemetryLiveEnv) seedAndWait(ctx context.Context, t *testing.T, exps selfTelemetryLiveExporters) {
	t.Helper()
	td := ptrace.NewTraces()
	rs := td.ResourceSpans().AppendEmpty()
	rs.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	ss := rs.ScopeSpans().AppendEmpty()

	sp := ss.Spans().AppendEmpty()
	sp.SetTraceID(pcommon.TraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}))
	sp.SetSpanID(pcommon.SpanID([8]byte{1, 2, 3, 4, 5, 6, 7, 8}))
	sp.SetName("execute_tool web_search")
	sp.SetKind(ptrace.SpanKindInternal)
	sp.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase))
	sp.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(500 * time.Millisecond)))
	sp.Status().SetCode(ptrace.StatusCodeError)
	sp.Attributes().PutStr("api_key", "secret-key-should-redact")
	sp.Attributes().PutStr("debug.note", "Bearer "+e.secretMarker)

	// Over-limit span routed to otel_quarantine (66 > MaxAttributeCount=64).
	spQ := ss.Spans().AppendEmpty()
	spQ.SetTraceID(pcommon.TraceID([16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}))
	spQ.SetSpanID(pcommon.SpanID([8]byte{8, 7, 6, 5, 4, 3, 2, 1}))
	spQ.SetName("quarantine_trigger")
	spQ.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(time.Second)))
	spQ.SetEndTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(1100 * time.Millisecond)))
	for i := range 66 {
		spQ.Attributes().PutInt(fmt.Sprintf("extra.attr.%d", i), int64(i))
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	rec := rl.ScopeLogs().AppendEmpty().LogRecords().AppendEmpty()
	rec.SetTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(900 * time.Millisecond)))
	rec.SetSeverityText("INFO")
	rec.Body().SetStr("self-telemetry check log")

	md := pmetric.NewMetrics()
	rm := md.ResourceMetrics().AppendEmpty()
	rm.Resource().Attributes().PutStr("service.name", e.svcPrimary)
	m := rm.ScopeMetrics().AppendEmpty().Metrics().AppendEmpty()
	m.SetName("gen_ai.client.token.usage")
	m.SetUnit("{token}")
	sum := m.SetEmptySum()
	sum.SetAggregationTemporality(pmetric.AggregationTemporalityDelta)
	sum.SetIsMonotonic(true)
	dp := sum.DataPoints().AppendEmpty()
	dp.SetStartTimestamp(pcommon.NewTimestampFromTime(e.recentBase))
	dp.SetTimestamp(pcommon.NewTimestampFromTime(e.recentBase.Add(time.Second)))
	dp.SetIntValue(42)

	if err := exps.traces.ConsumeTraces(ctx, td); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if err := exps.logs.ConsumeLogs(ctx, ld); err != nil {
		t.Fatalf("ConsumeLogs: %v", err)
	}
	if err := exps.metrics.ConsumeMetrics(ctx, md); err != nil {
		t.Fatalf("ConsumeMetrics: %v", err)
	}

	e.waitForCount(ctx, t, "otel_spans count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_spans`", e.project, e.srcDataset), 1)
	e.waitForCount(ctx, t, "otel_quarantine count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_quarantine`", e.project, e.srcDataset), 1)
	e.waitForCount(ctx, t, "otel_logs count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_logs`", e.project, e.srcDataset), 1)
	e.waitForCount(ctx, t, "otel_metrics count",
		fmt.Sprintf("SELECT COUNT(*) FROM `%s.%s.otel_metrics`", e.project, e.srcDataset), 1)
}

func (e *selfTelemetryLiveEnv) waitForCount(ctx context.Context, t *testing.T, label, sql string, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last int64
	for {
		q := e.admin.Query(sql)
		q.Location = e.location
		it, err := q.Read(ctx)
		if err != nil {
			t.Fatalf("%s query failed: %v", label, err)
		}
		var row []bq.Value
		if err := it.Next(&row); err != nil && !errors.Is(err, iterator.Done) {
			t.Fatalf("%s iterate failed: %v", label, err)
		}
		if len(row) == 1 {
			last, _ = row[0].(int64)
		}
		if last >= want {
			return
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			t.Fatalf("%s count = %d after waiting, want >= %d", label, last, want)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("%s aborted while waiting (last=%d, want >= %d): %v", label, last, want, ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

type analyticsGrafanaDashboard struct {
	Panels []analyticsGrafanaPanel `json:"panels"`
}

type analyticsGrafanaPanel struct {
	ID      int                     `json:"id"`
	Title   string                  `json:"title"`
	Type    string                  `json:"type"`
	Panels  []analyticsGrafanaPanel `json:"panels"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}

type analyticsMetadataYAML struct {
	Telemetry struct {
		Metrics map[string]struct {
			Unit       string `yaml:"unit"`
			Attributes []string
			Sum        *struct {
				ValueType string `yaml:"value_type"`
				Monotonic bool   `yaml:"monotonic"`
			} `yaml:"sum"`
			Gauge *struct {
				ValueType string `yaml:"value_type"`
			} `yaml:"gauge"`
			Histogram *struct {
				ValueType string `yaml:"value_type"`
			} `yaml:"histogram"`
		} `yaml:"metrics"`
		Resource map[string]any `yaml:"resource"`
	} `yaml:"telemetry"`
}

func (e *selfTelemetryLiveEnv) verifyPrometheusSelfTelemetryContract(ctx context.Context, t *testing.T) {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := e.reader.Collect(ctx, &rm); err != nil {
		t.Fatalf("collect live ManualReader metrics: %v", err)
	}
	rawMD, err := os.ReadFile("metadata.yaml")
	if err != nil {
		t.Fatalf("read metadata.yaml: %v", err)
	}
	var md analyticsMetadataYAML
	if err := yaml.Unmarshal(rawMD, &md); err != nil {
		t.Fatalf("parse metadata.yaml: %v", err)
	}
	// The PromQL selectors checked below name each metric as the exporter
	// emits it, so look the declarations up by that name.
	md.Telemetry.Metrics = liveMetricsByEmittedName(md.Telemetry.Metrics)

	rawProm, err := os.ReadFile(filepath.Join("dashboards", "grafana", "collector-self-telemetry.json"))
	if err != nil {
		t.Fatalf("read collector-self-telemetry.json: %v", err)
	}
	var promDash analyticsGrafanaDashboard
	if err := json.Unmarshal(rawProm, &promDash); err != nil {
		t.Fatalf("parse collector-self-telemetry.json: %v", err)
	}

	// Index live emitted OTel metrics and their emitted attribute keys.
	liveMetrics := map[string]map[string]bool{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			attrs := liveMetrics[m.Name]
			if attrs == nil {
				attrs = map[string]bool{}
				liveMetrics[m.Name] = attrs
			}
			addAttrSet := func(set attribute.Set) {
				for _, kv := range set.ToSlice() {
					attrs[string(kv.Key)] = true
				}
			}
			switch d := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Sum[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Gauge[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Histogram[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Histogram[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.ExponentialHistogram[int64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.ExponentialHistogram[float64]:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			case metricdata.Summary:
				for _, dp := range d.DataPoints {
					addAttrSet(dp.Attributes)
				}
			default:
				t.Errorf("unhandled metricdata.Aggregation type %T for metric %s", m.Data, m.Name)
			}
		}
	}

	// Verify core active self-telemetry instruments were actually emitted live during the test.
	for _, mustEmit := range []string{
		"otelcol_exporter_bigquery_acknowledged_rows",
		"otelcol_exporter_bigquery_rejected_rows",
		"otelcol_exporter_bigquery_quarantined_rows",
		"otelcol_exporter_bigquery_redacted_values",
		"otelcol_exporter_bigquery_append_result_wait",
		"otelcol_exporter_bigquery_inflight_requests",
		"otelcol_exporter_bigquery_backpressure_level",
		"otelcol_exporter_bigquery_effective_request_bytes",
		"otelcol_exporter_bigquery_append_bytes",
	} {
		if _, ok := liveMetrics[mustEmit]; !ok {
			t.Errorf("live ManualReader did not emit expected self-telemetry metric %s", mustEmit)
		}
	}

	// Verify every PromQL query selector & grouping label matches metadata.yaml and live emitted labels.
	nameRe := regexp.MustCompile(`__name__=~"([^"]+)"`)
	byRe := regexp.MustCompile(`(?:sum|max)\s+by\s*\(([^)]+)\)`)
	suffixStripRe := regexp.MustCompile(`(\([^)]*\)\??|_bucket|_total)$`)

	var collectPromExprs func([]analyticsGrafanaPanel) []string
	collectPromExprs = func(ps []analyticsGrafanaPanel) []string {
		var out []string
		for _, p := range ps {
			for _, tg := range p.Targets {
				if tg.Expr != "" {
					out = append(out, tg.Expr)
				}
			}
			out = append(out, collectPromExprs(p.Panels)...)
		}
		return out
	}

	exprs := collectPromExprs(promDash.Panels)
	if len(exprs) == 0 {
		t.Fatal("no PromQL target expressions found in collector-self-telemetry.json")
	}
	for _, expr := range exprs {
		nm := nameRe.FindStringSubmatch(expr)
		if len(nm) != 2 {
			t.Errorf("PromQL expression missing __name__ regex selector: %q", expr)
			continue
		}
		base := nm[1]
		for {
			next := suffixStripRe.ReplaceAllString(base, "")
			if next == base {
				break
			}
			base = next
		}
		decl, ok := md.Telemetry.Metrics[base]
		if !ok {
			t.Errorf("PromQL references undeclared metric %q (from %q)", base, nm[1])
			continue
		}
		for _, bm := range byRe.FindAllStringSubmatch(expr, -1) {
			for _, lbl := range strings.Split(bm[1], ",") {
				lbl = strings.TrimSpace(lbl)
				if lbl == "instance" || lbl == "le" {
					continue
				}
				if !slices.Contains(decl.Attributes, lbl) {
					t.Errorf("PromQL groups %s by undeclared attribute %q (declared: %v)", base, lbl, decl.Attributes)
				}
				if emittedAttrs, active := liveMetrics[base]; active && !emittedAttrs[lbl] {
					t.Errorf("live metric %s did not emit label %q required by PromQL %q (emitted: %v)", base, lbl, expr, emittedAttrs)
				}
			}
		}
	}
}
