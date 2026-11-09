// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package bigqueryexporter

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	stdhttp "net/http"
	"os"
	"strings"
	"testing"
	"time"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/googlehttp"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

func trajLiveTraceID(group byte) pcommon.TraceID {
	var id pcommon.TraceID
	id[0] = 0xAA
	id[1] = 0x58
	id[15] = group
	return id
}

func trajLiveSpanID(group byte, idx uint16) pcommon.SpanID {
	var id pcommon.SpanID
	id[0] = 0xBB
	id[1] = group
	id[6] = byte(idx >> 8)
	id[7] = byte(idx)
	return id
}

type trajLiveSpanSpec struct {
	traceID      pcommon.TraceID
	spanID       pcommon.SpanID
	parentSpanID pcommon.SpanID
	hasParent    bool
	serviceName  string // empty omits resource service.name (NULL in BigQuery)
	name         string
	opName       string
	agentName    string
	start        time.Time
	end          time.Time
	inTokens     *int64
	outTokens    *int64
	reasTokens   *int64
}

func int64Ptr(v int64) *int64 { return &v }

func appendTrajLiveTraces(specs []trajLiveSpanSpec) ptrace.Traces {
	td := ptrace.NewTraces()
	bySvc := make(map[string]ptrace.SpanSlice)
	for _, s := range specs {
		sl, ok := bySvc[s.serviceName]
		if !ok {
			rs := td.ResourceSpans().AppendEmpty()
			if s.serviceName != "" {
				rs.Resource().Attributes().PutStr("service.name", s.serviceName)
			}
			sl = rs.ScopeSpans().AppendEmpty().Spans()
			bySvc[s.serviceName] = sl
		}
		sp := sl.AppendEmpty()
		sp.SetTraceID(s.traceID)
		sp.SetSpanID(s.spanID)
		if s.hasParent {
			sp.SetParentSpanID(s.parentSpanID)
		}
		sp.SetName(s.name)
		sp.SetKind(ptrace.SpanKindInternal)
		sp.SetStartTimestamp(pcommon.NewTimestampFromTime(s.start))
		sp.SetEndTimestamp(pcommon.NewTimestampFromTime(s.end))
		sp.Status().SetCode(ptrace.StatusCodeOk)
		attrs := sp.Attributes()
		attrs.PutStr("gen_ai.operation.name", s.opName)
		if s.agentName != "" {
			attrs.PutStr("gen_ai.agent.name", s.agentName)
		}
		if s.inTokens != nil {
			attrs.PutInt("gen_ai.usage.input_tokens", *s.inTokens)
		}
		if s.outTokens != nil {
			attrs.PutInt("gen_ai.usage.output_tokens", *s.outTokens)
		}
		if s.reasTokens != nil {
			attrs.PutInt("gen_ai.usage.reasoning_tokens", *s.reasTokens)
		}
	}
	return td
}

func runUncachedBQQuery(
	ctx context.Context,
	client *bq.Client,
	sql string,
	params ...bq.QueryParameter,
) ([][]bq.Value, time.Duration, int64, int, error) {
	q := client.Query(sql)
	q.DisableQueryCache = true
	q.Parameters = params
	wallStart := time.Now()
	job, st, err := liveRunQuery(ctx, q)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	var duration time.Duration
	var slotMillis int64
	var stages int
	if st != nil && st.Statistics != nil {
		if !st.Statistics.EndTime.IsZero() && !st.Statistics.CreationTime.IsZero() {
			duration = st.Statistics.EndTime.Sub(st.Statistics.CreationTime)
		}
		if qs, ok := st.Statistics.Details.(*bq.QueryStatistics); ok && qs != nil {
			slotMillis = qs.SlotMillis
			stages = len(qs.QueryPlan)
		}
	}
	if duration <= 0 {
		duration = time.Since(wallStart)
	}
	it, err := job.Read(ctx)
	if err != nil {
		return nil, duration, slotMillis, stages, err
	}
	var out [][]bq.Value
	for {
		var row []bq.Value
		err := it.Next(&row)
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return nil, duration, slotMillis, stages, err
		}
		out = append(out, row)
	}
	return out, duration, slotMillis, stages, nil
}

// TestLiveTrajectoryTVFEquivalenceAndLatency verifies the single-pass trajectory
// view and bounded-window TVF end to end against live BigQuery:
//   - Deep 18-hop hierarchy (depth=16 cutoff, depth=16 is_leaf=false/is_token_leaf=true)
//   - 34-node orphan-bridged chain testing exact 32-hop topo_ancestors coverage
//   - Unemitted depth=17 intermediate blocking token propagation
//   - Self, 2-node, and 3-node in-window cycles producing zero rows
//   - Window-broken cycle tie-breaking on (start_time, span_id)
//   - Explicit 0 tokens and partial token-family suppression
//   - Cross-service isolation and NULL service_name matching
//   - Row-for-row bidirectional EXCEPT DISTINCT parity between view and TVF
//   - Single-digit-second live latency and bounded queryPlan stage counts
//   - RPF view rejection and narrow < wide TVF byte pruning on partitioned tables
func TestLiveTrajectoryTVFEquivalenceAndLatency(t *testing.T) {
	project := os.Getenv("BQ_PROJECT")
	if project == "" {
		if os.Getenv("REQUIRE_LIVE_BQ") == "1" {
			t.Fatal("REQUIRE_LIVE_BQ=1 is set but BQ_PROJECT is empty")
		}
		t.Skip("BQ_PROJECT is unset; skipping live trajectory equivalence & latency test")
	}
	location := os.Getenv("BQ_LOCATION")
	if location == "" {
		location = "US"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	t.Cleanup(cancel)

	dataset := uniqueEphemeralDatasetID("otel_traj_perf_it")

	// Register 404 confirmation before creating the dataset so LIFO cleanup runs
	// it after DeleteWithContents.
	t.Cleanup(func() {
		verifyCtx, verifyCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer verifyCancel()
		httpClient, _, closeHTTP, err := googlehttp.NewClient(verifyCtx, []string{bigqueryapi.BigqueryScope})
		if err != nil {
			t.Errorf("create 404 verification HTTP client: %v", err)
			return
		}
		defer closeHTTP()
		verifyAdmin, err := bq.NewClient(verifyCtx, project, option.WithHTTPClient(httpClient))
		if err != nil {
			t.Errorf("create 404 verification BigQuery client: %v", err)
			return
		}
		defer func() {
			if closeErr := verifyAdmin.Close(); closeErr != nil {
				t.Errorf("close 404 verification BigQuery client: %v", closeErr)
			}
		}()
		_, metaErr := verifyAdmin.Dataset(dataset).Metadata(verifyCtx)
		var apiErr *googleapi.Error
		if !errors.As(metaErr, &apiErr) || apiErr.Code != stdhttp.StatusNotFound {
			t.Errorf("ephemeral dataset %s.%s metadata after cleanup = %v, want HTTP 404", project, dataset, metaErr)
		}
	})

	admin := newLiveBigQueryAdmin(ctx, t, project, dataset, location)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.Project = project
	cfg.Dataset = dataset
	cfg.Location = location
	cfg.AutoCreate.Dataset = false
	cfg.AutoCreate.Tables = true
	cfg.AutoCreate.CompanionViews = true
	cfg.TimeoutSettings.Timeout = 30 * time.Second
	cfg.QueueSettings = configoptional.None[exporterhelper.QueueBatchConfig]()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("cfg.Validate: %v", err)
	}

	tracesExp, err := factory.CreateTraces(ctx, exportertest.NewNopSettings(factory.Type()), cfg)
	if err != nil {
		t.Fatalf("CreateTraces: %v", err)
	}
	if err := tracesExp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("tracesExp.Start: %v", err)
	}
	t.Cleanup(func() {
		if shutErr := tracesExp.Shutdown(context.Background()); shutErr != nil {
			t.Errorf("tracesExp.Shutdown: %v", shutErr)
		}
	})

	// Provision tvf_gen_ai_agent_trajectory over v_gen_ai_spans.
	tvfDDL := fmt.Sprintf(schema.GenAIAgentTrajectoryTVFDDL, project, dataset)
	if _, _, ddlErr := liveRunQuery(ctx, admin.Query(tvfDDL)); ddlErr != nil {
		t.Fatalf("create TVF %s: %v", schema.GenAIAgentTrajectoryTVFName, ddlErr)
	}

	base := time.Now().UTC().Truncate(time.Minute)
	const svcMain = "traj-svc-main"
	var specs []trajLiveSpanSpec

	// 1. Trace 1: 18-hop deep hierarchy (depths 0..17; s18 excluded at depth=17).
	trTree := trajLiveTraceID(1)
	for i := uint16(1); i <= 18; i++ {
		st := base.Add(time.Duration(i) * time.Second)
		sp := trajLiveSpanSpec{
			traceID:     trTree,
			spanID:      trajLiveSpanID(1, i),
			hasParent:   i > 1,
			serviceName: svcMain,
			name:        fmt.Sprintf("tree-span-%02d", i),
			opName:      "chat",
			start:       st,
			end:         st.Add(10 * time.Millisecond),
		}
		if i > 1 {
			sp.parentSpanID = trajLiveSpanID(1, i-1)
		}
		switch i {
		case 1:
			sp.opName = "invoke_agent"
			sp.agentName = "root_agent"
			sp.inTokens = int64Ptr(100)
			sp.outTokens = int64Ptr(50)
		case 16:
			sp.opName = "invoke_agent"
			sp.agentName = "sub_agent"
			sp.inTokens = int64Ptr(60)
			sp.outTokens = int64Ptr(30)
		case 17:
			sp.inTokens = int64Ptr(20)
			sp.outTokens = int64Ptr(10)
		case 18:
			sp.inTokens = int64Ptr(5)
			sp.outTokens = int64Ptr(2)
		}
		specs = append(specs, sp)
	}
	// Sibling tokenless tool leaf directly under s01.
	specs = append(specs, trajLiveSpanSpec{
		traceID:      trTree,
		spanID:       trajLiveSpanID(1, 19),
		parentSpanID: trajLiveSpanID(1, 1),
		hasParent:    true,
		serviceName:  svcMain,
		name:         "tree-tool-leaf",
		opName:       "execute_tool",
		start:        base.Add(19 * time.Second),
		end:          base.Add(19*time.Second + 5*time.Millisecond),
	})

	// 2. Trace 2: 34-node chain straddling -24h lookback between c17 and c18.
	// c01..c17 emit at depth 0..16; c18 emits as orphan root (depth=0) and
	// c18..c34 emit at depth 0..16. c34 tokens cover c02 (32 hops) but NOT c01 (33 hops).
	trChain34 := trajLiveTraceID(2)
	earlyBase := base.Add(-26 * time.Hour)
	for i := uint16(1); i <= 34; i++ {
		st := base.Add(time.Duration(i-17) * time.Second)
		if i <= 17 {
			st = earlyBase.Add(time.Duration(i) * time.Second)
		}
		sp := trajLiveSpanSpec{
			traceID:     trChain34,
			spanID:      trajLiveSpanID(2, i),
			hasParent:   i > 1,
			serviceName: svcMain,
			name:        fmt.Sprintf("chain34-span-%02d", i),
			opName:      "chat",
			start:       st,
			end:         st.Add(10 * time.Millisecond),
		}
		if i > 1 {
			sp.parentSpanID = trajLiveSpanID(2, i-1)
		}
		switch i {
		case 1:
			sp.opName = "invoke_agent"
			sp.agentName = "early_agent"
			sp.reasTokens = int64Ptr(90)
		case 2:
			sp.inTokens = int64Ptr(80)
		case 18:
			sp.opName = "invoke_agent"
			sp.agentName = "late_agent"
		case 34:
			sp.inTokens = int64Ptr(7)
			sp.reasTokens = int64Ptr(7)
		}
		specs = append(specs, sp)
	}

	// 3. Trace 3: unemitted depth=17 span (g18) blocks token coverage from orphan g19 to g01.
	trGap17 := trajLiveTraceID(3)
	for i := uint16(1); i <= 19; i++ {
		st := earlyBase.Add(time.Duration(i) * time.Second)
		if i == 19 {
			st = base
		}
		sp := trajLiveSpanSpec{
			traceID:     trGap17,
			spanID:      trajLiveSpanID(3, i),
			hasParent:   i > 1,
			serviceName: svcMain,
			name:        fmt.Sprintf("gap17-span-%02d", i),
			opName:      "chat",
			start:       st,
			end:         st.Add(10 * time.Millisecond),
		}
		if i > 1 {
			sp.parentSpanID = trajLiveSpanID(3, i-1)
		}
		switch i {
		case 1:
			sp.opName = "invoke_agent"
			sp.agentName = "gap_root"
			sp.inTokens = int64Ptr(50)
			sp.outTokens = int64Ptr(25)
		case 19:
			sp.inTokens = int64Ptr(10)
			sp.outTokens = int64Ptr(5)
		}
		specs = append(specs, sp)
	}

	// 4a. Trace 4: in-window self, 2-node, and 3-node cycles (must produce 0 emitted rows).
	trCycles := trajLiveTraceID(4)
	specs = append(specs,
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 1),
			parentSpanID: trajLiveSpanID(4, 1),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-self",
			opName:       "chat",
			start:        base,
			end:          base.Add(time.Millisecond),
			inTokens:     int64Ptr(11),
		},
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 2),
			parentSpanID: trajLiveSpanID(4, 3),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-2a",
			opName:       "chat",
			start:        base.Add(time.Millisecond),
			end:          base.Add(2 * time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 3),
			parentSpanID: trajLiveSpanID(4, 2),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-2b",
			opName:       "chat",
			start:        base.Add(2 * time.Millisecond),
			end:          base.Add(3 * time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 4),
			parentSpanID: trajLiveSpanID(4, 6),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-3a",
			opName:       "chat",
			start:        base.Add(3 * time.Millisecond),
			end:          base.Add(4 * time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 5),
			parentSpanID: trajLiveSpanID(4, 4),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-3b",
			opName:       "chat",
			start:        base.Add(4 * time.Millisecond),
			end:          base.Add(5 * time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trCycles,
			spanID:       trajLiveSpanID(4, 6),
			parentSpanID: trajLiveSpanID(4, 5),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "cycle-3c",
			opName:       "chat",
			start:        base.Add(5 * time.Millisecond),
			end:          base.Add(6 * time.Millisecond),
		},
	)

	// 4b. Trace 5: 2-node cycle broken across +1h skew; tie broken on (start_time, span_id).
	trBrokenCyc := trajLiveTraceID(5)
	specs = append(specs,
		trajLiveSpanSpec{
			traceID:      trBrokenCyc,
			spanID:       trajLiveSpanID(5, 1),
			parentSpanID: trajLiveSpanID(5, 2),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "broken-early",
			opName:       "invoke_agent",
			agentName:    "cyc_agent",
			start:        base.Add(-2 * time.Hour),
			end:          base.Add(-2*time.Hour + time.Millisecond),
			inTokens:     int64Ptr(30),
		},
		trajLiveSpanSpec{
			traceID:      trBrokenCyc,
			spanID:       trajLiveSpanID(5, 2),
			parentSpanID: trajLiveSpanID(5, 1),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "broken-late",
			opName:       "chat",
			start:        base,
			end:          base.Add(time.Millisecond),
			inTokens:     int64Ptr(40),
		},
	)

	// 5. Trace 6: explicit 0 tokens + partial family suppression (input+output covered, reasoning uncovered).
	trPartial := trajLiveTraceID(6)
	specs = append(specs,
		trajLiveSpanSpec{
			traceID:     trPartial,
			spanID:      trajLiveSpanID(6, 1),
			serviceName: svcMain,
			name:        "partial-parent",
			opName:      "invoke_agent",
			agentName:   "orchestrator",
			start:       base,
			end:         base.Add(2 * time.Second),
			inTokens:    int64Ptr(10),
			outTokens:   int64Ptr(0),
			reasTokens:  int64Ptr(5),
		},
		trajLiveSpanSpec{
			traceID:      trPartial,
			spanID:       trajLiveSpanID(6, 2),
			parentSpanID: trajLiveSpanID(6, 1),
			hasParent:    true,
			serviceName:  svcMain,
			name:         "partial-child",
			opName:       "chat",
			start:        base.Add(time.Second),
			end:          base.Add(1500 * time.Millisecond),
			inTokens:     int64Ptr(10),
			outTokens:    int64Ptr(0),
		},
	)

	// 6. Trace 7 (cross-service isolation) + Trace 8 (NULL service_name).
	trMultiSvc := trajLiveTraceID(7)
	specs = append(specs,
		trajLiveSpanSpec{
			traceID:     trMultiSvc,
			spanID:      trajLiveSpanID(7, 1),
			serviceName: "traj-svc-alpha",
			name:        "alpha-root",
			opName:      "invoke_agent",
			agentName:   "alpha",
			start:       base,
			end:         base.Add(time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trMultiSvc,
			spanID:       trajLiveSpanID(7, 2),
			parentSpanID: trajLiveSpanID(7, 1),
			hasParent:    true,
			serviceName:  "traj-svc-beta",
			name:         "beta-orphan-child",
			opName:       "chat",
			start:        base.Add(time.Millisecond),
			end:          base.Add(2 * time.Millisecond),
		},
	)
	trNullSvc := trajLiveTraceID(8)
	specs = append(specs,
		trajLiveSpanSpec{
			traceID:   trNullSvc,
			spanID:    trajLiveSpanID(8, 1),
			name:      "null-svc-root",
			opName:    "invoke_agent",
			agentName: "null_svc_agent",
			start:     base,
			end:       base.Add(time.Millisecond),
		},
		trajLiveSpanSpec{
			traceID:      trNullSvc,
			spanID:       trajLiveSpanID(8, 2),
			parentSpanID: trajLiveSpanID(8, 1),
			hasParent:    true,
			name:         "null-svc-child",
			opName:       "chat",
			start:        base.Add(time.Millisecond),
			end:          base.Add(2 * time.Millisecond),
		},
	)

	// 7. Trace 9: 200-span realistic tree exercising graph walk + coverage at scale.
	trStress := trajLiveTraceID(9)
	const stressSvc = "traj-svc-stress"
	specs = append(specs, trajLiveSpanSpec{
		traceID:     trStress,
		spanID:      trajLiveSpanID(9, 1),
		serviceName: stressSvc,
		name:        "stress-root",
		opName:      "invoke_agent",
		agentName:   "planner",
		start:       base,
		end:         base.Add(5 * time.Minute),
		inTokens:    int64Ptr(1000),
		outTokens:   int64Ptr(500),
	})
	var nextStressID uint16 = 2
	for branch := range 20 {
		parent := trajLiveSpanID(9, 1)
		for step := range 10 {
			sid := trajLiveSpanID(9, nextStressID)
			nextStressID++
			st := base.Add(time.Duration(branch*10+step+1) * time.Millisecond)
			sp := trajLiveSpanSpec{
				traceID:      trStress,
				spanID:       sid,
				parentSpanID: parent,
				hasParent:    true,
				serviceName:  stressSvc,
				name:         fmt.Sprintf("stress-%02d-%02d", branch, step),
				opName:       "execute_tool",
				start:        st,
				end:          st.Add(time.Millisecond),
			}
			if step == 0 {
				sp.opName = "invoke_agent"
				sp.agentName = fmt.Sprintf("worker_%02d", branch%4)
			}
			if step == 9 {
				sp.opName = "chat"
				sp.inTokens = int64Ptr(25)
				sp.outTokens = int64Ptr(10)
			}
			specs = append(specs, sp)
			parent = sid
		}
	}

	if err := tracesExp.ConsumeTraces(ctx, appendTrajLiveTraces(specs)); err != nil {
		t.Fatalf("ConsumeTraces: %v", err)
	}
	if err := waitForRowCount(ctx, admin, project, dataset, cfg.Traces.Table+"_dedup", int64(len(specs))); err != nil {
		t.Fatalf("wait otel_spans_dedup: %v", err)
	}

	ctxStart := base.Add(-28 * time.Hour)
	ctxEnd := base.Add(2 * time.Hour)
	subStart := base.Add(-1 * time.Hour)
	subEnd := base.Add(2 * time.Hour)

	// Run TVF and View uncached, enforcing < 15s latency and < 100 queryPlan stages.
	tvfFQN := fmt.Sprintf("`%s.%s.%s`", project, dataset, schema.GenAIAgentTrajectoryTVFName)
	viewFQN := fmt.Sprintf("`%s.%s.%s`", project, dataset, schema.GenAIAgentTrajectoryViewName)

	tvfPerfSQL := fmt.Sprintf("SELECT trace_id, span_id, depth, is_orphan, is_leaf, is_token_leaf, step_index FROM %s(@ctx_start, @ctx_end, @ctx_start, @ctx_end)", tvfFQN)
	tvfRows, tvfDur, tvfSlotMs, tvfStages, err := runUncachedBQQuery(
		ctx, admin, tvfPerfSQL,
		liveParam("ctx_start", ctxStart),
		liveParam("ctx_end", ctxEnd),
	)
	if err != nil {
		t.Fatalf("TVF execution failed: %v", err)
	}
	t.Logf("TVF uncached metrics: rows=%d wall=%s slotMs=%d stages=%d", len(tvfRows), tvfDur, tvfSlotMs, tvfStages)
	if tvfDur >= 15*time.Second {
		t.Errorf("TVF uncached latency = %s, want < 15s", tvfDur)
	}
	if tvfStages == 0 || tvfStages >= 100 {
		t.Errorf("TVF queryPlan stages = %d, want in [1, 99]", tvfStages)
	}

	viewPerfSQL := fmt.Sprintf("SELECT trace_id, span_id, depth, is_orphan, is_leaf, is_token_leaf, step_index FROM %s", viewFQN)
	viewRows, viewDur, viewSlotMs, viewStages, err := runUncachedBQQuery(ctx, admin, viewPerfSQL)
	if err != nil {
		t.Fatalf("view execution failed: %v", err)
	}
	t.Logf("View uncached metrics: rows=%d wall=%s slotMs=%d stages=%d", len(viewRows), viewDur, viewSlotMs, viewStages)
	if viewDur >= 15*time.Second {
		t.Errorf("View uncached latency = %s, want < 15s", viewDur)
	}
	if viewStages == 0 || viewStages >= 100 {
		t.Errorf("View queryPlan stages = %d, want in [1, 99]", viewStages)
	}

	// Verify exact bidirectional EXCEPT DISTINCT parity across all 40 columns
	// (converting ARRAY<STRING> agent_path to JSON string for EXCEPT DISTINCT).
	projCols := "* EXCEPT (agent_path), TO_JSON_STRING(agent_path) AS agent_path_json"
	parityVvsTVF := fmt.Sprintf(
		"(SELECT %s FROM %s) EXCEPT DISTINCT (SELECT %s FROM %s(@ctx_start, @ctx_end, @ctx_start, @ctx_end))",
		projCols, viewFQN, projCols, tvfFQN,
	)
	diff1, _, _, _, err := runUncachedBQQuery(ctx, admin, parityVvsTVF, liveParam("ctx_start", ctxStart), liveParam("ctx_end", ctxEnd))
	if err != nil {
		t.Fatalf("view EXCEPT tvf query failed: %v", err)
	}
	if len(diff1) != 0 {
		t.Errorf("view EXCEPT tvf returned %d differing rows: %v", len(diff1), diff1)
	}

	parityTVFvsV := fmt.Sprintf(
		"(SELECT %s FROM %s(@ctx_start, @ctx_end, @ctx_start, @ctx_end)) EXCEPT DISTINCT (SELECT %s FROM %s)",
		projCols, tvfFQN, projCols, viewFQN,
	)
	diff2, _, _, _, err := runUncachedBQQuery(ctx, admin, parityTVFvsV, liveParam("ctx_start", ctxStart), liveParam("ctx_end", ctxEnd))
	if err != nil {
		t.Fatalf("tvf EXCEPT view query failed: %v", err)
	}
	if len(diff2) != 0 {
		t.Errorf("tvf EXCEPT view returned %d differing rows: %v", len(diff2), diff2)
	}

	hexTrace := func(id pcommon.TraceID) string { return hex.EncodeToString(id[:]) }
	hexSpan := func(id pcommon.SpanID) string { return hex.EncodeToString(id[:]) }

	// Verify bounded sub-window TVF behavior: preserves pre-filter step_index (>1 when earlier rows exist)
	// and preserves 32-hop cross-window token coverage on c02 (early window) -> c34 (sub-window).
	c18Hex := hexSpan(trajLiveSpanID(2, 18))
	subWindowSQL := fmt.Sprintf(
		`SELECT span_id, step_index, depth, is_orphan, TO_JSON_STRING(agent_path)
		 FROM %s(@sub_start, @sub_end, @ctx_start, @ctx_end)
		 WHERE trace_id = @tr_chain34 AND span_id = @c18`,
		tvfFQN,
	)
	subRows, _, _, _, err := runUncachedBQQuery(
		ctx, admin, subWindowSQL,
		liveParam("sub_start", subStart),
		liveParam("sub_end", subEnd),
		liveParam("ctx_start", ctxStart),
		liveParam("ctx_end", ctxEnd),
		liveParam("tr_chain34", hexTrace(trChain34)),
		liveParam("c18", c18Hex),
	)
	if err != nil {
		t.Fatalf("sub-window chain34 c18 query failed: %v", err)
	}
	wantSub := [][]bq.Value{{c18Hex, int64(18), int64(0), true, `["late_agent"]`}}
	if fmt.Sprint(subRows) != fmt.Sprint(wantSub) {
		t.Errorf("sub-window chain34 c18 = %v, want %v", subRows, wantSub)
	}

	// Verify detailed graph edge-case semantics directly on live BigQuery.

	edgeChecksSQL := fmt.Sprintf(`
		SELECT trace_id, span_id, depth, root_span_id, nearest_agent_span_id,
			nearest_agent_name, TO_JSON_STRING(agent_path), is_orphan, is_leaf,
			is_token_leaf, gen_ai_usage_input_tokens, gen_ai_usage_output_tokens,
			gen_ai_usage_reasoning_tokens, service_name
		FROM %s(@ctx_start, @ctx_end, @ctx_start, @ctx_end)
		WHERE (trace_id = @tr_tree AND span_id IN UNNEST([@s17, @s18, @s19]))
		   OR (trace_id = @tr_chain34 AND span_id IN UNNEST([@c01, @c02]))
		   OR (trace_id = @tr_gap17 AND span_id = @g01)
		   OR (trace_id = @tr_cycles)
		   OR (trace_id = @tr_broken AND span_id IN UNNEST([@b01, @b02]))
		   OR (trace_id = @tr_partial AND span_id = @p01)
		   OR (trace_id = @tr_multisvc AND span_id IN UNNEST([@m01, @m02]))
		   OR (trace_id = @tr_nullsvc AND span_id = @n02)
		ORDER BY trace_id, span_id`,
		tvfFQN,
	)
	edgeRows, _, _, _, err := runUncachedBQQuery(
		ctx, admin, edgeChecksSQL,
		liveParam("ctx_start", ctxStart),
		liveParam("ctx_end", ctxEnd),
		liveParam("tr_tree", hexTrace(trTree)),
		liveParam("s17", hexSpan(trajLiveSpanID(1, 17))),
		liveParam("s18", hexSpan(trajLiveSpanID(1, 18))),
		liveParam("s19", hexSpan(trajLiveSpanID(1, 19))),
		liveParam("tr_chain34", hexTrace(trChain34)),
		liveParam("c01", hexSpan(trajLiveSpanID(2, 1))),
		liveParam("c02", hexSpan(trajLiveSpanID(2, 2))),
		liveParam("tr_gap17", hexTrace(trGap17)),
		liveParam("g01", hexSpan(trajLiveSpanID(3, 1))),
		liveParam("tr_cycles", hexTrace(trCycles)),
		liveParam("tr_broken", hexTrace(trBrokenCyc)),
		liveParam("b01", hexSpan(trajLiveSpanID(5, 1))),
		liveParam("b02", hexSpan(trajLiveSpanID(5, 2))),
		liveParam("tr_partial", hexTrace(trPartial)),
		liveParam("p01", hexSpan(trajLiveSpanID(6, 1))),
		liveParam("tr_multisvc", hexTrace(trMultiSvc)),
		liveParam("m01", hexSpan(trajLiveSpanID(7, 1))),
		liveParam("m02", hexSpan(trajLiveSpanID(7, 2))),
		liveParam("tr_nullsvc", hexTrace(trNullSvc)),
		liveParam("n02", hexSpan(trajLiveSpanID(8, 2))),
	)
	if err != nil {
		t.Fatalf("edge checks query failed: %v", err)
	}
	// s18 (depth=17) and trCycles (all in-window cycles) must NOT appear (11 rows total).
	wantEdges := [][]any{
		// trTree: s17 (depth=16, unemitted s18 -> is_leaf=false, is_token_leaf=true) and s19 (tool leaf)
		{hexTrace(trTree), hexSpan(trajLiveSpanID(1, 17)), int64(16), hexSpan(trajLiveSpanID(1, 1)), hexSpan(trajLiveSpanID(1, 16)), "sub_agent", `["root_agent","sub_agent"]`, false, false, true, int64(20), int64(10), nil, svcMain},
		{hexTrace(trTree), hexSpan(trajLiveSpanID(1, 19)), int64(1), hexSpan(trajLiveSpanID(1, 1)), hexSpan(trajLiveSpanID(1, 1)), "root_agent", `["root_agent"]`, false, true, false, nil, nil, nil, svcMain},
		// trChain34: c01 (33 hops -> uncovered) vs c02 (32 hops -> covered)
		{hexTrace(trChain34), hexSpan(trajLiveSpanID(2, 1)), int64(0), hexSpan(trajLiveSpanID(2, 1)), hexSpan(trajLiveSpanID(2, 1)), "early_agent", `["early_agent"]`, false, false, true, nil, nil, int64(90), svcMain},
		{hexTrace(trChain34), hexSpan(trajLiveSpanID(2, 2)), int64(1), hexSpan(trajLiveSpanID(2, 1)), hexSpan(trajLiveSpanID(2, 1)), "early_agent", `["early_agent"]`, false, false, false, int64(80), nil, nil, svcMain},
		// trGap17: g01 uncovered across unemitted g18
		{hexTrace(trGap17), hexSpan(trajLiveSpanID(3, 1)), int64(0), hexSpan(trajLiveSpanID(3, 1)), hexSpan(trajLiveSpanID(3, 1)), "gap_root", `["gap_root"]`, false, false, true, int64(50), int64(25), nil, svcMain},
		// trBrokenCyc: b02 later start_time covers b01
		{hexTrace(trBrokenCyc), hexSpan(trajLiveSpanID(5, 1)), int64(0), hexSpan(trajLiveSpanID(5, 1)), hexSpan(trajLiveSpanID(5, 1)), "cyc_agent", `["cyc_agent"]`, true, false, false, int64(30), nil, nil, svcMain},
		{hexTrace(trBrokenCyc), hexSpan(trajLiveSpanID(5, 2)), int64(1), hexSpan(trajLiveSpanID(5, 1)), hexSpan(trajLiveSpanID(5, 1)), "cyc_agent", `["cyc_agent"]`, true, false, true, int64(40), nil, nil, svcMain},
		// trPartial: covered input & explicit 0 output projected as NULL while uncovered reasoning stays 5
		{hexTrace(trPartial), hexSpan(trajLiveSpanID(6, 1)), int64(0), hexSpan(trajLiveSpanID(6, 1)), hexSpan(trajLiveSpanID(6, 1)), "orchestrator", `["orchestrator"]`, false, false, true, nil, nil, int64(5), svcMain},
		// trMultiSvc: isolated across service_name
		{hexTrace(trMultiSvc), hexSpan(trajLiveSpanID(7, 1)), int64(0), hexSpan(trajLiveSpanID(7, 1)), hexSpan(trajLiveSpanID(7, 1)), "alpha", `["alpha"]`, false, true, false, nil, nil, nil, "traj-svc-alpha"},
		{hexTrace(trMultiSvc), hexSpan(trajLiveSpanID(7, 2)), int64(0), hexSpan(trajLiveSpanID(7, 2)), nil, nil, `[]`, true, true, false, nil, nil, nil, "traj-svc-beta"},
		// trNullSvc: IS NOT DISTINCT FROM links NULL service_name
		{hexTrace(trNullSvc), hexSpan(trajLiveSpanID(8, 2)), int64(1), hexSpan(trajLiveSpanID(8, 1)), hexSpan(trajLiveSpanID(8, 1)), "null_svc_agent", `["null_svc_agent"]`, false, true, false, nil, nil, nil, nil},
	}
	if fmt.Sprint(edgeRows) != fmt.Sprint(wantEdges) {
		t.Errorf("trajectory edge checks mismatch:\ngot:  %v\nwant: %v", edgeRows, wantEdges)
	}

	// Verify RPF behavior: view rejects unfiltered RPF table, TVF prunes narrow < wide.
	checkTrajectoryRPFPruningLive(ctx, t, admin, project, dataset, cfg.Traces.Table)
}

func checkTrajectoryRPFPruningLive(ctx context.Context, t *testing.T, admin *bq.Client, project, dataset, spansTable string) {
	t.Helper()
	rpfSpans := spansTable + "_traj_rpf"
	md, dedupQuery, err := schema.DestinationMetadataWithOptions(
		schema.SpansTableSchema(), project, dataset, rpfSpans, schema.DestinationOptions{RequirePartitionFilter: true},
	)
	if err != nil {
		t.Fatalf("derive %s metadata: %v", rpfSpans, err)
	}
	if err := admin.Dataset(dataset).Table(rpfSpans).Create(ctx, md); err != nil {
		t.Fatalf("create %s: %v", rpfSpans, err)
	}
	createView := func(name, query string) {
		t.Helper()
		if err := admin.Dataset(dataset).Table(name).Create(ctx, &bq.TableMetadata{ViewQuery: query}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	createView(rpfSpans+"_dedup", dedupQuery)
	createView("v_gen_ai_spans_traj_rpf", fmt.Sprintf(schema.GenAISpansViewQuery, project, dataset, rpfSpans))

	trajViewQuery := strings.ReplaceAll(
		fmt.Sprintf(schema.GenAIAgentTrajectoryViewQuery, project, dataset),
		fmt.Sprintf("`%s.%s.%s`", project, dataset, schema.GenAISpansViewName),
		fmt.Sprintf("`%s.%s.v_gen_ai_spans_traj_rpf`", project, dataset),
	)
	createView("v_gen_ai_agent_trajectory_rpf", trajViewQuery)

	trajTVFDDL := strings.ReplaceAll(
		fmt.Sprintf(schema.GenAIAgentTrajectoryTVFDDL, project, dataset),
		fmt.Sprintf("`%s.%s.%s`", project, dataset, schema.GenAISpansViewName),
		fmt.Sprintf("`%s.%s.v_gen_ai_spans_traj_rpf`", project, dataset),
	)
	trajTVFDDL = strings.ReplaceAll(
		trajTVFDDL,
		fmt.Sprintf("`%s.%s.%s`", project, dataset, schema.GenAIAgentTrajectoryTVFName),
		fmt.Sprintf("`%s.%s.tvf_gen_ai_agent_trajectory_rpf`", project, dataset),
	)
	if _, _, ddlErr := liveRunQuery(ctx, admin.Query(trajTVFDDL)); ddlErr != nil {
		t.Fatalf("create RPF trajectory TVF: %v", ddlErr)
	}

	// Seed two partitions 3 days apart.
	seedSQL := fmt.Sprintf(`INSERT INTO `+"`%s.%s.%s`"+` (
			start_time, start_time_unix_nano, end_time, end_time_unix_nano,
			receive_time, receive_time_unix_nano, duration_nano,
			trace_id, span_id, name, kind, service_name, attributes, schema_version)
		SELECT
			TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL age_minutes MINUTE), 1000,
			TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL age_minutes MINUTE), 2000,
			CURRENT_TIMESTAMP(), 3000, 1000, trace_id, span_id, 'chat', 3, 'rpf-traj-svc',
			JSON '{"gen_ai.operation.name":"chat","gen_ai.usage.input_tokens":10}',
			@version
		FROM UNNEST([
			STRUCT(72 * 60 AS age_minutes, '0102030405060708090a0b0c0d0e0f11' AS trace_id, '0102030405060711' AS span_id),
			STRUCT(30 AS age_minutes, '1112131415161718191a1b1c1d1e1f21' AS trace_id, '1112131415161721' AS span_id)
		])`, project, dataset, rpfSpans)
	seedQ := admin.Query(seedSQL)
	seedQ.Parameters = []bq.QueryParameter{liveParam("version", schema.Version)}
	if _, _, seedErr := liveRunQuery(ctx, seedQ); seedErr != nil {
		t.Fatalf("seed RPF partitions: %v", seedErr)
	}

	dryRunBytes := func(sql string) (int64, error) {
		q := admin.Query(sql)
		q.DryRun = true
		job, runErr := q.Run(ctx)
		if runErr != nil {
			return 0, runErr
		}
		st := job.LastStatus()
		if st == nil || st.Statistics == nil {
			return 0, errors.New("dry run returned no statistics")
		}
		if stErr := st.Err(); stErr != nil {
			return 0, stErr
		}
		return st.Statistics.TotalBytesProcessed, nil
	}

	if _, viewErr := dryRunBytes(fmt.Sprintf("SELECT * FROM `%s.%s.v_gen_ai_agent_trajectory_rpf`", project, dataset)); viewErr == nil {
		t.Error("v_gen_ai_agent_trajectory_rpf compiled without partition filter, want partition filter error")
	} else if msg := strings.ToLower(viewErr.Error()); !strings.Contains(msg, "partition") || !strings.Contains(msg, "filter") {
		t.Errorf("v_gen_ai_agent_trajectory_rpf error = %v, want partition filter rejection", viewErr)
	}

	tvfNarrowSQL := fmt.Sprintf(
		"SELECT * FROM `%s.%s.tvf_gen_ai_agent_trajectory_rpf`(TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR), CURRENT_TIMESTAMP(), TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 2 HOUR), CURRENT_TIMESTAMP())",
		project, dataset,
	)
	tvfWideSQL := fmt.Sprintf(
		"SELECT * FROM `%s.%s.tvf_gen_ai_agent_trajectory_rpf`(TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 96 HOUR), CURRENT_TIMESTAMP(), TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 96 HOUR), CURRENT_TIMESTAMP())",
		project, dataset,
	)
	narrowBytes, err := dryRunBytes(tvfNarrowSQL)
	if err != nil {
		t.Fatalf("tvf_gen_ai_agent_trajectory_rpf narrow dry run: %v", err)
	}
	wideBytes, err := dryRunBytes(tvfWideSQL)
	if err != nil {
		t.Fatalf("tvf_gen_ai_agent_trajectory_rpf wide dry run: %v", err)
	}
	t.Logf("tvf_gen_ai_agent_trajectory_rpf partition pruning: narrow=%d wide=%d", narrowBytes, wideBytes)
	if narrowBytes <= 0 || narrowBytes >= wideBytes {
		t.Errorf("tvf_gen_ai_agent_trajectory_rpf narrow=%d wide=%d, want 0 < narrow < wide", narrowBytes, wideBytes)
	}
}
