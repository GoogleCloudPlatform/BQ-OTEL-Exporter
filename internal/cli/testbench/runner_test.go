// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/offload"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/protoenc"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/types/descriptorpb"
)

func TestRunnerConfigNormalizeRejectsUnsupportedCombinations(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RunnerConfig
		wantSub string
	}{
		{
			name: "offload_dir in collector mode",
			cfg: RunnerConfig{
				Mode:         ModeCollector,
				CollectorBin: os.Args[0],
				OffloadDir:   t.TempDir(),
			},
			wantSub: `offload_dir is not supported in mode "collector"`,
		},
		{
			name: "offload_gcs_bucket in collector mode without allow live",
			cfg: RunnerConfig{
				Mode:             ModeCollector,
				CollectorBin:     os.Args[0],
				OffloadGCSBucket: "my-bucket",
			},
			wantSub: `offload_gcs_bucket in mode "collector" requires --collector-allow-live`,
		},
		{
			name: "simulate_ack_delay in live mode",
			cfg: RunnerConfig{
				Mode:             ModeLive,
				ProjectID:        "my-proj",
				DatasetID:        "my_ds",
				SimulateAckDelay: 10 * time.Millisecond,
			},
			wantSub: "simulate_ack_delay and simulate_throttle_every are supported only against bqfake",
		},
		{
			name: "simulate_throttle_every in collector allow live mode",
			cfg: RunnerConfig{
				Mode:                  ModeCollector,
				CollectorBin:          os.Args[0],
				CollectorAllowLive:    true,
				ProjectID:             "my-proj",
				DatasetID:             "my_ds",
				SimulateThrottleEvery: 2,
			},
			wantSub: "simulate_ack_delay and simulate_throttle_every are supported only against bqfake",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := cfg.Normalize()
			if err == nil {
				t.Fatalf("Normalize() succeeded, want error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("Normalize() error = %q, want substring %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestFormatMarkdownPeakRSSUnavailable(t *testing.T) {
	report := &BenchmarkReport{
		Config:    RunnerConfig{Mode: ModeBQFake, WorkloadProfile: WorkloadProfileGenAIMixed},
		GoVersion: "go1.25",
		GOOS:      "linux",
		GOARCH:    "amd64",
		NumCPU:    4,
		Results: []SignalResult{
			{
				Signal: "logs",
				Memory: MemorySummary{PeakRSSMB: 0, PeakRSSUnavailable: true},
			},
			{
				Signal: "traces",
				Memory: MemorySummary{PeakRSSMB: 128.4, PeakRSSUnavailable: false},
			},
		},
	}

	md := FormatMarkdown(report)
	if !strings.Contains(md, "| unavailable |") {
		t.Fatalf("FormatMarkdown missing '| unavailable |' cell:\n%s", md)
	}
	if !strings.Contains(md, "| 128.4 |") {
		t.Fatalf("FormatMarkdown missing '| 128.4 |' cell:\n%s", md)
	}
}

func TestCollectorModeDefaultWorkloadAndSignalsAlignment(t *testing.T) {
	cfg := RunnerConfig{
		Mode:         ModeCollector,
		CollectorBin: os.Args[0],
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize() unexpected error: %v", err)
	}
	if cfg.CollectorConfig != "example/otel-collector-high-volume-logs.yaml" {
		t.Fatalf("CollectorConfig = %q, want default logs config", cfg.CollectorConfig)
	}
	if cfg.WorkloadProfile != WorkloadProfileAccessLogs {
		t.Fatalf("WorkloadProfile = %q, want %q", cfg.WorkloadProfile, WorkloadProfileAccessLogs)
	}
	if len(cfg.Signals) != 1 || cfg.Signals[0] != "logs" {
		t.Fatalf("Signals = %v, want [logs]", cfg.Signals)
	}
	if cfg.ResourceAttrs != DefaultAccessLogsResourceAttrs {
		t.Fatalf("ResourceAttrs = %d, want %d", cfg.ResourceAttrs, DefaultAccessLogsResourceAttrs)
	}

	cfgExplicitTraces := RunnerConfig{
		Mode:         ModeCollector,
		CollectorBin: os.Args[0],
		Signals:      []string{"traces"},
	}
	if err := cfgExplicitTraces.Normalize(); err != nil {
		t.Fatalf("Normalize(explicit traces) unexpected error: %v", err)
	}
	if cfgExplicitTraces.WorkloadProfile != WorkloadProfileGenAIMixed {
		t.Fatalf("explicit traces WorkloadProfile = %q, want %q", cfgExplicitTraces.WorkloadProfile, WorkloadProfileGenAIMixed)
	}

	cfgCustomCollector := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: "custom/collector.yaml",
	}
	if err := cfgCustomCollector.Normalize(); err != nil {
		t.Fatalf("Normalize(custom config) unexpected error: %v", err)
	}
	if cfgCustomCollector.WorkloadProfile != WorkloadProfileGenAIMixed {
		t.Fatalf("custom config WorkloadProfile = %q, want %q", cfgCustomCollector.WorkloadProfile, WorkloadProfileGenAIMixed)
	}
	if len(cfgCustomCollector.Signals) != 1 || cfgCustomCollector.Signals[0] != "traces" {
		t.Fatalf("custom config Signals = %v, want [traces]", cfgCustomCollector.Signals)
	}
}

func TestFormatMarkdownUnavailableMetricsAndDrainWarning(t *testing.T) {
	report := &BenchmarkReport{
		Config:    RunnerConfig{Mode: ModeCollector, WorkloadProfile: WorkloadProfileAccessLogs},
		GoVersion: "go1.25",
		GOOS:      "darwin",
		GOARCH:    "arm64",
		NumCPU:    8,
		Results: []SignalResult{
			{
				Signal:                 "logs",
				StreamPoolSize:         4,
				BytesPerRowUnavailable: true,
				IncompleteDrain:        true,
				DrainWarning:           "acknowledged 900 of 1000 rows before drain timeout",
				Memory: MemorySummary{
					CPUUnavailable:     true,
					PeakRSSUnavailable: true,
				},
				ByteLayers: &ByteLayersSummary{
					SourceContentBytesPerRow: 180.0,
					OTLPBytesPerRow:          310.0,
					ProtoRowsBytesPerRow:     0,
				},
			},
			{
				Signal:          "traces",
				StreamPoolSize:  4,
				IncompleteDrain: true,
			},
		},
	}

	md := FormatMarkdown(report)
	if !strings.Contains(md, "| `logs` | 4 | `false` | `false` | 0 | 0.0 | unavailable | unavailable | 0.00 | 0.00 | 0.00 | unavailable | 0.00 | unavailable |") {
		t.Fatalf("FormatMarkdown missing unavailable row cells:\n%s", md)
	}
	if !strings.Contains(md, "| `logs` | 180.0 | 310.0 | unavailable | - | - | - | - | - |") {
		t.Fatalf("FormatMarkdown missing unavailable 5-layer ProtoRows cells:\n%s", md)
	}
	if !strings.Contains(md, "> **Incomplete Drain Warning (`logs`)**: acknowledged 900 of 1000 rows before drain timeout") {
		t.Fatalf("FormatMarkdown missing custom Incomplete Drain Warning for logs:\n%s", md)
	}
	if !strings.Contains(md, "> **Incomplete Drain Warning (`traces`)**: collector pipeline drain did not complete cleanly") {
		t.Fatalf("FormatMarkdown missing default Incomplete Drain Warning for traces:\n%s", md)
	}
}

func TestCheckSignalResultLosslessUniqueAndReplayAccounting(t *testing.T) {
	cfg := RunnerConfig{AllowPartialFailures: false}

	// 1. UniqueDeliveryVerified=true fails closed when DeliveredRows < RecordsSubmitted
	// even if retry/replay inflated AcknowledgedRows >= RecordsSubmitted.
	resDup := SignalResult{
		BatchesAttempted:       2,
		BatchesSucceeded:       2,
		RecordsSubmitted:       100,
		DeliveredRows:          80,
		UniqueDeliveryVerified: true,
		Latency:                LatencySummary{Samples: 2},
		Telemetry: TelemetrySnapshot{
			AcknowledgedRows: 120,
			ReplayedRows:     40,
		},
	}
	err := checkSignalResultLossless(cfg, "logs", resDup, nil)
	if err == nil || !strings.Contains(err.Error(), "delivered=80") || !strings.Contains(err.Error(), "unique_delivery_verified=true") {
		t.Fatalf("checkSignalResultLossless(unique shortfall) = %v, want error mentioning delivered=80 and unique_delivery_verified=true", err)
	}

	// 2. UniqueDeliveryVerified=true passes when all submitted rows are uniquely delivered,
	// fault simulation is enabled, AND observed uncertain-commit fault counters explain ReplayedRows;
	// zero observed retries/faults or unexplained replays fail closed even with SimulateThrottleEvery > 0.
	resUniqueNoObservedFault := resDup
	resUniqueNoObservedFault.DeliveredRows = 100
	cfgFaultSim := RunnerConfig{AllowPartialFailures: false, SimulateThrottleEvery: 2}
	if err := checkSignalResultLossless(cfgFaultSim, "logs", resUniqueNoObservedFault, nil); err == nil || !strings.Contains(err.Error(), "replayed=40") {
		t.Fatalf("checkSignalResultLossless(faultSim=true, retries=0, uncertain=0) = %v, want failure citing replayed=40", err)
	}

	resUniqueOK := resUniqueNoObservedFault
	resUniqueOK.ObservedUncertainCommitFaults = 1
	resUniqueOK.ObservedUncertainCommitRows = 40
	resUniqueOK.Telemetry.Retries = 1
	if err := checkSignalResultLossless(cfgFaultSim, "logs", resUniqueOK, nil); err != nil {
		t.Fatalf("checkSignalResultLossless(faultSim=true, observed uncertain=1/40, unique delivered=100) unexpected error: %v", err)
	}

	resExceedsObserved := resUniqueOK
	resExceedsObserved.ObservedUncertainCommitRows = 20
	if err := checkSignalResultLossless(cfgFaultSim, "logs", resExceedsObserved, nil); err == nil || !strings.Contains(err.Error(), "replayed=40") {
		t.Fatalf("checkSignalResultLossless(replayed=40 > observed_uncertain_rows=20) = %v, want failure citing replayed=40", err)
	}

	resUnexplained := resUniqueOK
	resUnexplained.UnexplainedReplayRows = 1
	if err := checkSignalResultLossless(cfgFaultSim, "logs", resUnexplained, nil); err == nil || !strings.Contains(err.Error(), "unexplained_replays=1") {
		t.Fatalf("checkSignalResultLossless(unexplained_replays=1) = %v, want failure citing unexplained_replays=1", err)
	}

	// 2b. Without fault simulation enabled, strict runs fail closed on any ReplayedRows > 0
	// even when UniqueDeliveryVerified=true and DeliveredRows == RecordsSubmitted.
	err = checkSignalResultLossless(cfg, "logs", resUniqueOK, nil)
	if err == nil || !strings.Contains(err.Error(), "replayed=40") {
		t.Fatalf("checkSignalResultLossless(faultSim=false, replayed=40) = %v, want error mentioning replayed=40", err)
	}

	// 3. UniqueDeliveryVerified=false fails closed when ReplayedRows > 0.
	resUnverifiedReplay := SignalResult{
		BatchesAttempted:       2,
		BatchesSucceeded:       2,
		RecordsSubmitted:       100,
		UniqueDeliveryVerified: false,
		Latency:                LatencySummary{Samples: 2},
		Telemetry: TelemetrySnapshot{
			AcknowledgedRows: 120,
			ReplayedRows:     20,
		},
	}
	err = checkSignalResultLossless(cfg, "logs", resUnverifiedReplay, nil)
	if err == nil || !strings.Contains(err.Error(), "replayed=20") || !strings.Contains(err.Error(), "unique_delivery_verified=false") {
		t.Fatalf("checkSignalResultLossless(unverified replay) = %v, want error mentioning replayed=20 and unique_delivery_verified=false", err)
	}
}

func TestGeneratorAllSevenFrameworksAndMCP(t *testing.T) {
	// Verify DefaultFrameworks matches testdata/otlp/manifest.yaml and fixture
	// scope/service conventions 1-to-1 so any mutation to ScopeName/ServiceName fails.
	wantFrameworks := map[string]FrameworkSpec{
		"google_adk": {
			Framework:     "google_adk",
			System:        "gcp.vertex.agent",
			Model:         "gemini-2.5-pro",
			ResponseModel: "gemini-2.5-pro-001",
			AgentName:     "weather_coordinator",
			AgentID:       "agent-adk-01",
			ToolName:      "get_forecast",
			ScopeName:     "gcp.vertex.agent",
			ScopeVer:      "2.6.3",
			ServiceName:   "adk-weather-agent",
			ServiceVer:    "2.6.3",
		},
		"langgraph": {
			Framework:     "langgraph",
			System:        "langsmith",
			Model:         "gpt-4o",
			ResponseModel: "gpt-4o",
			AgentName:     "research_supervisor",
			AgentID:       "agent-lg-01",
			ToolName:      "vector_store_lookup",
			ScopeName:     "langsmith.otel",
			ScopeVer:      "0.10.18",
			ServiceName:   "langgraph-research-graph",
			ServiceVer:    "1.2.0",
		},
		"openai_agents": {
			Framework:     "openai_agents",
			Provider:      "openai",
			Model:         "gpt-4o",
			ResponseModel: "gpt-4o-2024-08-06",
			AgentName:     "billing_triage",
			AgentID:       "agent-oai-01",
			ToolName:      "fetch_customer_ledger",
			ScopeName:     "opentelemetry.instrumentation.openai_agents",
			ScopeVer:      "1.0b0",
			ServiceName:   "openai-triage-agent",
			ServiceVer:    "0.20.0",
		},
		"anthropic_agent_sdk": {
			Framework:     "anthropic_agent_sdk",
			System:        "anthropic",
			Model:         "anthropic-v4-default",
			ResponseModel: "anthropic-v4-default-20260514",
			AgentName:     "code-assistant",
			AgentID:       "agent-anth-01",
			ToolName:      "sandbox_bash_exec",
			ScopeName:     "com.anthropic.agent.sdk",
			ScopeVer:      "2.1.229",
			ServiceName:   "anthropic-agent-cli",
			ServiceVer:    "2.1.229",
		},
		"crewai": {
			Framework:     "crewai",
			Model:         "gpt-4o-mini",
			ResponseModel: "gpt-4o-mini",
			AgentName:     "crew_financial_analyst",
			AgentID:       "agent-crew-01",
			ToolName:      "sec_filing_extractor",
			ScopeName:     "openinference.instrumentation.crewai",
			ScopeVer:      "1.1.12",
			ServiceName:   "crewai-analyst-crew",
			ServiceVer:    "1.15.15",
		},
		"aws_bedrock": {
			Framework:     "aws_bedrock",
			System:        "aws.bedrock",
			Model:         "amazon.nova-pro-v1:0",
			ResponseModel: "amazon.nova-pro-v1:0",
			AgentName:     "bedrock_router",
			AgentID:       "agent-bdrk-01",
			ToolName:      "retrieve_and_generate",
			ScopeName:     "opentelemetry.instrumentation.botocore.bedrock-runtime",
			ScopeVer:      "0.65b0",
			ServiceName:   "bedrock-converse-worker",
			ServiceVer:    "0.65b0",
		},
		"microsoft_agent_framework": {
			Framework:     "microsoft_agent_framework",
			Provider:      "microsoft.agent_framework",
			Model:         "gpt-4o",
			ResponseModel: "gpt-4o",
			AgentName:     "support_orchestrator",
			AgentID:       "maf-agent-09",
			ToolName:      "graph_calendar_query",
			ScopeName:     "agent_framework.observability",
			ScopeVer:      "1.12.0",
			ServiceName:   "maf-orchestrator",
			ServiceVer:    "1.12.0",
		},
	}
	gotFrameworks := DefaultFrameworks()
	if len(gotFrameworks) != 7 {
		t.Fatalf("len(DefaultFrameworks()) = %d, want 7", len(gotFrameworks))
	}
	for _, fw := range gotFrameworks {
		want, ok := wantFrameworks[fw.Framework]
		if !ok {
			t.Fatalf("unexpected framework %q", fw.Framework)
		}
		if fw != want {
			t.Fatalf("DefaultFrameworks()[%q] = %+v, want %+v", fw.Framework, fw, want)
		}
	}

	genCfg := GeneratorConfig{
		PayloadBytes:   8192,
		PlantSecrets:   true,
		UniquePayloads: true,
		Seed:           7,
		BaseTime:       time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	}
	gen := NewGenerator(genCfg)
	gen2 := NewGenerator(genCfg)

	// 28 spans = 7 frameworks * 4-span tree (invoke_agent, chat, execute_tool, mcp).
	td := gen.TracesBatch(28)
	td2 := gen2.TracesBatch(28)
	if got := td.SpanCount(); got != 28 {
		t.Fatalf("TracesBatch(28) SpanCount = %d, want 28", got)
	}
	traceBytes1, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(td)
	if err != nil {
		t.Fatalf("MarshalTraces(td) error: %v", err)
	}
	traceBytes2, err := (&ptrace.ProtoMarshaler{}).MarshalTraces(td2)
	if err != nil {
		t.Fatalf("MarshalTraces(td2) error: %v", err)
	}
	if !bytes.Equal(traceBytes1, traceBytes2) {
		t.Fatal("TracesBatch protobuf bytes differ across two fresh NewGenerator instances with identical config")
	}

	seenFrameworks := make(map[string]bool)
	seenOps := make(map[string]int)
	seenOpenInferenceKinds := make(map[string]int)
	seenMCP := make(map[string]bool)
	spanServiceByPair := make(map[string]string)
	var secretSpans int

	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		rs := rss.At(i)
		fwAttr, ok := rs.Resource().Attributes().Get("gen_ai.framework")
		if !ok {
			t.Fatalf("resource %d missing gen_ai.framework", i)
		}
		fwName := fwAttr.Str()
		seenFrameworks[fwName] = true
		wantFW := wantFrameworks[fwName]

		svcAttr, _ := rs.Resource().Attributes().Get("service.name")
		if svcAttr.Str() != wantFW.ServiceName {
			t.Fatalf("framework %s resource service.name = %q, want %q", fwName, svcAttr.Str(), wantFW.ServiceName)
		}
		sss := rs.ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			scope := sss.At(j).Scope()
			if scope.Name() != wantFW.ScopeName || scope.Version() != wantFW.ScopeVer {
				t.Fatalf("framework %s scope = (%q, %q), want (%q, %q)",
					fwName, scope.Name(), scope.Version(), wantFW.ScopeName, wantFW.ScopeVer)
			}
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				sp := spans.At(k)
				pairKey := sp.TraceID().String() + "/" + sp.SpanID().String()
				spanServiceByPair[pairKey] = svcAttr.Str()

				if op, ok := sp.Attributes().Get("gen_ai.operation.name"); ok {
					seenOps[op.Str()]++
				}
				if oiKind, ok := sp.Attributes().Get("openinference.span.kind"); ok {
					seenOpenInferenceKinds[oiKind.Str()]++
					if fwName != "crewai" {
						t.Errorf("unexpected openinference.span.kind on framework %s", fwName)
					}
					if _, hasGenAIOp := sp.Attributes().Get("gen_ai.operation.name"); hasGenAIOp {
						t.Errorf("CrewAI OpenInference span (%s) should not carry gen_ai.operation.name", oiKind.Str())
					}
				}
				if fwName == "google_adk" {
					for _, adkKey := range []string{
						"gcp.vertex.agent.invocation_id",
						"gcp.vertex.agent.session_id",
						"gcp.vertex.agent.event_id",
						"user.id",
					} {
						if v, ok := sp.Attributes().Get(adkKey); !ok || v.Str() == "" {
							t.Errorf("google_adk span missing %s", adkKey)
						}
					}
				}
				if fwName == "langgraph" {
					if v, ok := sp.Attributes().Get("langsmith.metadata.graph_node"); !ok || v.Str() == "" {
						t.Error("langgraph span missing langsmith.metadata.graph_node")
					}
				}
				if mcpMethod, ok := sp.Attributes().Get("mcp.method.name"); ok {
					m := mcpMethod.Str()
					seenMCP[m] = true
					if _, ok := sp.Attributes().Get("server.address"); !ok {
						t.Errorf("MCP span (%s) missing server.address", m)
					}
					if _, ok := sp.Attributes().Get("jsonrpc.request.id"); !ok {
						t.Errorf("MCP span (%s) missing jsonrpc.request.id", m)
					}
					switch m {
					case "tools/call":
						if _, ok := sp.Attributes().Get("gen_ai.tool.name"); !ok {
							t.Error("MCP tools/call span missing gen_ai.tool.name")
						}
						if callID, ok := sp.Attributes().Get("gen_ai.tool.call.id"); !ok || callID.Str() == "" {
							t.Error("MCP tools/call span missing non-empty gen_ai.tool.call.id")
						}
					case "resources/read":
						if _, ok := sp.Attributes().Get("mcp.resource.uri"); !ok {
							t.Error("MCP resources/read span missing mcp.resource.uri")
						}
					case "prompts/get":
						if _, ok := sp.Attributes().Get("gen_ai.prompt.name"); !ok {
							t.Error("MCP prompts/get span missing gen_ai.prompt.name")
						}
					}
				}
				if _, ok := sp.Attributes().Get("client.api_key"); ok {
					secretSpans++
				}
				for _, payloadKey := range []string{"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.tool.call.result", "mcp.payload.content", "input.value", "output.value"} {
					if msg, ok := sp.Attributes().Get(payloadKey); ok {
						if len(msg.Str()) != 8192 {
							t.Fatalf("%s len = %d, want 8192", payloadKey, len(msg.Str()))
						}
						if !json.Valid([]byte(msg.Str())) {
							t.Fatalf("%s is not valid JSON: %.120s", payloadKey, msg.Str())
						}
					}
				}
			}
		}
	}

	if len(seenFrameworks) != 7 {
		t.Fatalf("seenFrameworks = %d (%v), want all 7 frameworks", len(seenFrameworks), seenFrameworks)
	}
	if seenOps["invoke_agent"] != 6 || seenOps["chat"] != 6 || seenOps["execute_tool"] != 12 {
		t.Fatalf("unexpected gen_ai.operation.name counts across 6 GenAI frameworks: %v, want invoke_agent=6, chat=6, execute_tool=12", seenOps)
	}
	if seenOpenInferenceKinds["AGENT"] != 1 || seenOpenInferenceKinds["LLM"] != 1 || seenOpenInferenceKinds["TOOL"] != 2 {
		t.Fatalf("unexpected CrewAI OpenInference span kinds: %v, want AGENT=1, LLM=1, TOOL=2", seenOpenInferenceKinds)
	}
	for _, wantMethod := range []string{"tools/call", "resources/read", "prompts/get"} {
		if !seenMCP[wantMethod] {
			t.Fatalf("missing MCP method %q in %v", wantMethod, seenMCP)
		}
	}
	if secretSpans == 0 {
		t.Fatal("expected planted secret attributes when PlantSecrets=true")
	}

	ld := gen.LogsBatch(28)
	ld2 := gen2.LogsBatch(28)
	if got := ld.LogRecordCount(); got != 28 {
		t.Fatalf("LogsBatch(28) LogRecordCount = %d, want 28", got)
	}
	logBytes1, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld)
	if err != nil {
		t.Fatalf("MarshalLogs(ld) error: %v", err)
	}
	logBytes2, err := (&plog.ProtoMarshaler{}).MarshalLogs(ld2)
	if err != nil {
		t.Fatalf("MarshalLogs(ld2) error: %v", err)
	}
	if !bytes.Equal(logBytes1, logBytes2) {
		t.Fatal("LogsBatch protobuf bytes differ across two fresh NewGenerator instances with identical config")
	}
	for i := 0; i < ld.ResourceLogs().Len(); i++ {
		rl := ld.ResourceLogs().At(i)
		svc, _ := rl.Resource().Attributes().Get("service.name")
		fwAttr, _ := rl.Resource().Attributes().Get("gen_ai.framework")
		sls := rl.ScopeLogs()
		for j := 0; j < sls.Len(); j++ {
			lrs := sls.At(j).LogRecords()
			for k := 0; k < lrs.Len(); k++ {
				lr := lrs.At(k)
				key := lr.TraceID().String() + "/" + lr.SpanID().String()
				wantSvc, ok := spanServiceByPair[key]
				if !ok {
					t.Fatalf("log record correlated pair %s not found in emitted TracesBatch(28)", key)
				}
				if svc.Str() != wantSvc {
					t.Fatalf("log record pair %s service.name = %q, want %q (matching span service.name)", key, svc.Str(), wantSvc)
				}
				if fwAttr.Str() == "google_adk" {
					for _, adkKey := range []string{
						"gcp.vertex.agent.invocation_id",
						"gcp.vertex.agent.session_id",
						"gcp.vertex.agent.event_id",
						"user.id",
					} {
						if v, ok := lr.Attributes().Get(adkKey); !ok || v.Str() == "" {
							t.Errorf("google_adk log missing %s", adkKey)
						}
					}
				}
			}
		}
	}

	md := gen.MetricsBatch(28)
	md2 := gen2.MetricsBatch(28)
	if got := md.DataPointCount(); got != 28 {
		t.Fatalf("MetricsBatch(28) DataPointCount = %d, want 28", got)
	}
	metricBytes1, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(md)
	if err != nil {
		t.Fatalf("MarshalMetrics(md) error: %v", err)
	}
	metricBytes2, err := (&pmetric.ProtoMarshaler{}).MarshalMetrics(md2)
	if err != nil {
		t.Fatalf("MarshalMetrics(md2) error: %v", err)
	}
	if !bytes.Equal(metricBytes1, metricBytes2) {
		t.Fatal("MetricsBatch protobuf bytes differ across two fresh NewGenerator instances with identical config")
	}

	seenMetricNames := make(map[string]int)
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		svc, _ := rm.Resource().Attributes().Get("service.name")
		sms := rm.ScopeMetrics()
		for j := 0; j < sms.Len(); j++ {
			ms := sms.At(j).Metrics()
			for k := 0; k < ms.Len(); k++ {
				m := ms.At(k)
				seenMetricNames[m.Name()] += m.Histogram().DataPoints().Len()
				dps := m.Histogram().DataPoints()
				for d := 0; d < dps.Len(); d++ {
					dp := dps.At(d)
					bounds := dp.ExplicitBounds().AsRaw()
					buckets := dp.BucketCounts().AsRaw()
					if len(buckets) != len(bounds)+1 {
						t.Fatalf("metric %s dp[%d] len(buckets)=%d, want len(bounds)+1=%d", m.Name(), d, len(buckets), len(bounds)+1)
					}
					var bucketSum uint64
					firstNonEmpty, lastNonEmpty := -1, -1
					for bIdx, c := range buckets {
						bucketSum += c
						if c > 0 {
							if firstNonEmpty == -1 {
								firstNonEmpty = bIdx
							}
							lastNonEmpty = bIdx
						}
					}
					if bucketSum != dp.Count() {
						t.Fatalf("metric %s dp[%d] sum(buckets)=%d, want Count=%d", m.Name(), d, bucketSum, dp.Count())
					}
					if !dp.HasMin() || !dp.HasMax() || dp.Min() > dp.Max() {
						t.Fatalf("metric %s dp[%d] invalid min/max: hasMin=%t hasMax=%t min=%v max=%v",
							m.Name(), d, dp.HasMin(), dp.HasMax(), dp.Min(), dp.Max())
					}
					if firstNonEmpty < 0 || lastNonEmpty < 0 {
						t.Fatalf("metric %s dp[%d] has 0 non-empty buckets", m.Name(), d)
					}
					if firstNonEmpty > 0 && dp.Min() <= bounds[firstNonEmpty-1] {
						t.Fatalf("metric %s dp[%d] Min=%v <= lower bound %v of first non-empty bucket %d",
							m.Name(), d, dp.Min(), bounds[firstNonEmpty-1], firstNonEmpty)
					}
					if firstNonEmpty < len(bounds) && dp.Min() > bounds[firstNonEmpty] {
						t.Fatalf("metric %s dp[%d] Min=%v > upper bound %v of first non-empty bucket %d",
							m.Name(), d, dp.Min(), bounds[firstNonEmpty], firstNonEmpty)
					}
					if lastNonEmpty > 0 && dp.Max() <= bounds[lastNonEmpty-1] {
						t.Fatalf("metric %s dp[%d] Max=%v <= lower bound %v of last non-empty bucket %d",
							m.Name(), d, dp.Max(), bounds[lastNonEmpty-1], lastNonEmpty)
					}
					if lastNonEmpty < len(bounds) && dp.Max() > bounds[lastNonEmpty] {
						t.Fatalf("metric %s dp[%d] Max=%v > upper bound %v of last non-empty bucket %d",
							m.Name(), d, dp.Max(), bounds[lastNonEmpty], lastNonEmpty)
					}
					var impliedMinSum, impliedMaxSum float64
					for bIdx, c := range buckets {
						if c == 0 {
							continue
						}
						lo := dp.Min()
						if bIdx > 0 && bounds[bIdx-1] > lo {
							lo = bounds[bIdx-1]
						}
						hi := dp.Max()
						if bIdx < len(bounds) && bounds[bIdx] < hi {
							hi = bounds[bIdx]
						}
						switch {
						case bIdx == firstNonEmpty && firstNonEmpty == lastNonEmpty:
							if c == 1 {
								impliedMinSum += dp.Min()
								impliedMaxSum += dp.Max()
							} else {
								impliedMinSum += dp.Min() + dp.Max() + float64(c-2)*lo
								impliedMaxSum += dp.Min() + dp.Max() + float64(c-2)*hi
							}
						case bIdx == firstNonEmpty:
							impliedMinSum += dp.Min() + float64(c-1)*lo
							impliedMaxSum += dp.Min() + float64(c-1)*hi
						case bIdx == lastNonEmpty:
							impliedMinSum += dp.Max() + float64(c-1)*lo
							impliedMaxSum += dp.Max() + float64(c-1)*hi
						default:
							impliedMinSum += float64(c) * lo
							impliedMaxSum += float64(c) * hi
						}
					}
					if dp.Sum() < impliedMinSum-1e-9 || dp.Sum() > impliedMaxSum+1e-9 {
						t.Fatalf("metric %s dp[%d] Sum=%v outside bucket/min/max implied range [%v, %v]",
							m.Name(), d, dp.Sum(), impliedMinSum, impliedMaxSum)
					}

					ex := dp.Exemplars().At(0)
					key := ex.TraceID().String() + "/" + ex.SpanID().String()
					wantSvc, ok := spanServiceByPair[key]
					if !ok {
						t.Fatalf("metric exemplar correlated pair %s not found in emitted TracesBatch(28)", key)
					}
					if svc.Str() != wantSvc {
						t.Fatalf("metric exemplar pair %s service.name = %q, want %q (required by v_gen_ai_metric_exemplars join)", key, svc.Str(), wantSvc)
					}
				}
			}
		}
	}
	if seenMetricNames["gen_ai.client.token.usage"] != 14 || seenMetricNames["gen_ai.client.operation.duration"] != 14 {
		t.Fatalf("unexpected metric breakdown in MetricsBatch(28): %v", seenMetricNames)
	}

	// Transform all 3 batches through internal/transform and verify row counts and
	// cross-signal trace_id/span_id/service_name join keys.
	tOpts := transform.Options{Limits: transform.DefaultLimits()}
	spanRows, spanErrs := transform.SpanRows(td, tOpts)
	if len(spanErrs) != 0 || len(spanRows) != 28 {
		t.Fatalf("transform.SpanRows: len=%d, errs=%v", len(spanRows), spanErrs)
	}
	logRows, logErrs := transform.LogRows(ld, tOpts)
	if len(logErrs) != 0 || len(logRows) != 28 {
		t.Fatalf("transform.LogRows: len=%d, errs=%v", len(logRows), logErrs)
	}
	metricRows, metricErrs := transform.MetricRows(md, tOpts)
	if len(metricErrs) != 0 || len(metricRows) != 28 {
		t.Fatalf("transform.MetricRows: len=%d, errs=%v", len(metricRows), metricErrs)
	}
	spanRowService := make(map[string]string, len(spanRows))
	for _, sr := range spanRows {
		key := sr["trace_id"].(string) + "/" + sr["span_id"].(string)
		spanRowService[key] = sr["service_name"].(string)
	}
	for _, lr := range logRows {
		key := lr["trace_id"].(string) + "/" + lr["span_id"].(string)
		if spanRowService[key] != lr["service_name"].(string) {
			t.Fatalf("transformed LogRow %s service_name = %q, want %q", key, lr["service_name"], spanRowService[key])
		}
	}
	for _, mr := range metricRows {
		exs, ok := mr["exemplars"].([]transform.Row)
		if !ok || len(exs) != 1 {
			t.Fatalf("transformed MetricRow exemplars = %T (len %d), want []transform.Row len 1", mr["exemplars"], len(exs))
		}
		key := exs[0]["trace_id"].(string) + "/" + exs[0]["span_id"].(string)
		if spanRowService[key] != mr["service_name"].(string) {
			t.Fatalf("transformed MetricRow %s service_name = %q, want %q", key, mr["service_name"], spanRowService[key])
		}
	}

	// Evaluate transformed SpanRows, LogRows, and MetricRows against the exact SQL
	// view filter predicates and parent-child trajectory invariants from
	// internal/schema/schema.go (v_gen_ai_spans, v_gen_ai_agent_trajectory,
	// v_mcp_spans, v_gen_ai_logs, v_gen_ai_metrics, v_gen_ai_metric_exemplars).
	parseAttrs := func(raw any) map[string]any {
		s, _ := raw.(string)
		if s == "" {
			return nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			t.Fatalf("invalid attributes JSON %q: %v", s, err)
		}
		return m
	}
	hasNonEmptyAttr := func(attrs map[string]any, keys ...string) bool {
		for _, k := range keys {
			if v, ok := attrs[k]; ok && v != nil && v != "" {
				return true
			}
		}
		return false
	}
	matchesGenAISpansView := func(attrs map[string]any) bool {
		return hasNonEmptyAttr(attrs,
			"gen_ai.operation.name",
			"gen_ai.system",
			"gen_ai.provider.name",
			"gcp.vertex.agent.invocation_id",
			"gen_ai.main_agent.name",
			"gen_ai.main_agent.id",
		)
	}
	matchesMCPSpansView := func(attrs map[string]any) bool {
		return hasNonEmptyAttr(attrs,
			"mcp.method.name",
			"mcp.session.id",
			"mcp.resource.uri",
		)
	}

	genAISpanSet := make(map[string]bool)
	var (
		genAISpanCount       int
		crewAIGenAISpanCount int
		mcpSpanCount         int
		mcpAlsoInGenAICount  int
		mcpCrewAIOnlyCount   int
	)
	for _, sr := range spanRows {
		attrs := parseAttrs(sr["attributes"])
		svc, _ := sr["service_name"].(string)
		traceID, _ := sr["trace_id"].(string)
		spanID, _ := sr["span_id"].(string)
		inGenAI := matchesGenAISpansView(attrs)
		if inGenAI {
			genAISpanCount++
			genAISpanSet[traceID+"/"+spanID+"/"+svc] = true
			if svc == "crewai-analyst-crew" {
				crewAIGenAISpanCount++
			}
		}
		if matchesMCPSpansView(attrs) {
			mcpSpanCount++
			if inGenAI {
				mcpAlsoInGenAICount++
			} else if svc == "crewai-analyst-crew" {
				mcpCrewAIOnlyCount++
			}
		}
	}
	if genAISpanCount != 24 || crewAIGenAISpanCount != 0 {
		t.Fatalf("v_gen_ai_spans matched %d/28 spans (crewai=%d), want 24/28 (crewai=0)", genAISpanCount, crewAIGenAISpanCount)
	}
	if mcpSpanCount != 7 || mcpAlsoInGenAICount != 6 || mcpCrewAIOnlyCount != 1 {
		t.Fatalf("v_mcp_spans matched %d/28 spans (also_in_gen_ai_view=%d, crewai_only=%d), want 7 (6 and 1)",
			mcpSpanCount, mcpAlsoInGenAICount, mcpCrewAIOnlyCount)
	}

	// Verify v_gen_ai_agent_trajectory parent-child linkage: every non-root span
	// in v_gen_ai_spans must have its (trace_id, parent_span_id, service_name)
	// present in v_gen_ai_spans so is_orphan is FALSE for all 24 GenAI spans.
	var (
		trajectoryRoots    int
		trajectoryChildren int
		trajectoryOrphans  int
	)
	for _, sr := range spanRows {
		attrs := parseAttrs(sr["attributes"])
		if !matchesGenAISpansView(attrs) {
			continue
		}
		svc, _ := sr["service_name"].(string)
		traceID, _ := sr["trace_id"].(string)
		parentSpanID, _ := sr["parent_span_id"].(string)
		if parentSpanID == "" {
			trajectoryRoots++
			continue
		}
		if genAISpanSet[traceID+"/"+parentSpanID+"/"+svc] {
			trajectoryChildren++
		} else {
			trajectoryOrphans++
		}
	}
	if trajectoryRoots != 6 || trajectoryChildren != 18 || trajectoryOrphans != 0 {
		t.Fatalf("v_gen_ai_agent_trajectory roots=%d, children=%d, orphans=%d, want 6, 18, 0",
			trajectoryRoots, trajectoryChildren, trajectoryOrphans)
	}

	// Verify v_gen_ai_logs and v_gen_ai_metrics view predicates across all 28 rows.
	for i, lr := range logRows {
		attrs := parseAttrs(lr["attributes"])
		evName, _ := lr["event_name"].(string)
		if evName == "" {
			if v, ok := attrs["event.name"].(string); ok {
				evName = v
			}
		}
		inGenAILogs := strings.HasPrefix(evName, "gen_ai.") ||
			hasNonEmptyAttr(attrs, "gen_ai.system", "gen_ai.provider.name", "gcp.vertex.agent.invocation_id")
		if !inGenAILogs {
			t.Fatalf("logRow[%d] did not satisfy v_gen_ai_logs WHERE predicate: event_name=%q attrs=%v", i, evName, attrs)
		}
	}
	for i, mr := range metricRows {
		mName, _ := mr["metric_name"].(string)
		if !strings.HasPrefix(mName, "gen_ai.") {
			t.Fatalf("metricRow[%d] metric_name = %q, want prefix 'gen_ai.' for v_gen_ai_metrics", i, mName)
		}
	}

	// Verify payloadFor produces valid JSON across all UniquePayloads x PlantSecrets
	// combinations at 1024 B and across every small PayloadBytes value in 1..128
	// (covering compact JSON fallbacks and exact prefix+suffix boundary sizes).
	for _, unique := range []bool{false, true} {
		for _, secrets := range []bool{false, true} {
			gCombo := NewGenerator(GeneratorConfig{
				PayloadBytes:   1024,
				UniquePayloads: unique,
				PlantSecrets:   secrets,
			})
			for seq := uint64(0); seq < 16; seq++ {
				p := gCombo.payloadFor(seq)
				if len(p) != 1024 {
					t.Fatalf("payloadFor(seq=%d, unique=%t, secrets=%t) len = %d, want 1024", seq, unique, secrets, len(p))
				}
				if !json.Valid([]byte(p)) {
					t.Fatalf("payloadFor(seq=%d, unique=%t, secrets=%t) invalid JSON: %s", seq, unique, secrets, p)
				}
			}

			for payloadBytes := 1; payloadBytes <= 128; payloadBytes++ {
				gSmall := NewGenerator(GeneratorConfig{
					PayloadBytes:   payloadBytes,
					UniquePayloads: unique,
					PlantSecrets:   secrets,
					Seed:           3,
				})
				for seq := uint64(0); seq < 16; seq++ {
					p := gSmall.payloadFor(seq)
					if !json.Valid([]byte(p)) {
						t.Fatalf("payloadFor(payloadBytes=%d, seq=%d, unique=%t, secrets=%t) invalid JSON: %s",
							payloadBytes, seq, unique, secrets, p)
					}
					if !unique && !secrets && payloadBytes >= 18 && len(p) != payloadBytes {
						t.Fatalf("payloadFor(payloadBytes=%d, seq=%d, unique=false, secrets=false) len = %d, want %d",
							payloadBytes, seq, len(p), payloadBytes)
					}
				}
				smallTraces := gSmall.TracesBatch(8)
				for i := 0; i < smallTraces.ResourceSpans().Len(); i++ {
					sss := smallTraces.ResourceSpans().At(i).ScopeSpans()
					for j := 0; j < sss.Len(); j++ {
						spans := sss.At(j).Spans()
						for k := 0; k < spans.Len(); k++ {
							sp := spans.At(k)
							for _, key := range []string{"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.tool.call.result", "mcp.payload.content", "input.value", "output.value"} {
								if v, ok := sp.Attributes().Get(key); ok && !json.Valid([]byte(v.Str())) {
									t.Fatalf("TracesBatch(payloadBytes=%d, unique=%t, secrets=%t) attr %s invalid JSON: %s",
										payloadBytes, unique, secrets, key, v.Str())
								}
							}
						}
					}
				}
				smallLogs := gSmall.LogsBatch(4)
				for i := 0; i < smallLogs.ResourceLogs().Len(); i++ {
					sls := smallLogs.ResourceLogs().At(i).ScopeLogs()
					for j := 0; j < sls.Len(); j++ {
						lrs := sls.At(j).LogRecords()
						for k := 0; k < lrs.Len(); k++ {
							if v, ok := lrs.At(k).Body().Map().Get("content"); ok && !json.Valid([]byte(v.Str())) {
								t.Fatalf("LogsBatch(payloadBytes=%d, unique=%t, secrets=%t) body.content invalid JSON: %s",
									payloadBytes, unique, secrets, v.Str())
							}
						}
					}
				}
				if got := gSmall.MetricsBatch(4).DataPointCount(); got != 4 {
					t.Fatalf("MetricsBatch(4) DataPointCount = %d, want 4", got)
				}
			}
		}
	}
}

func TestRunBQFakeAllSignalsAndRedaction(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cfg := RunnerConfig{
		Mode:               ModeBQFake,
		Signals:            []string{"traces", "logs", "metrics"},
		TargetRate:         2000,
		Duration:           250 * time.Millisecond,
		BatchSize:          50,
		Workers:            2,
		StreamPoolSize:     2,
		ConnectionPoolSize: 2,
		Redaction:          true,
		PayloadBytes:       1024,
	}

	report, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run() unexpected error: %v", err)
	}
	if len(report.Results) != 3 {
		t.Fatalf("len(report.Results) = %d, want 3", len(report.Results))
	}

	for _, res := range report.Results {
		if res.Telemetry.AcknowledgedRows <= 0 {
			t.Errorf("signal %s AcknowledgedRows = %d, want > 0", res.Signal, res.Telemetry.AcknowledgedRows)
		}
		if res.Telemetry.AppendBytesTotal <= 0 {
			t.Errorf("signal %s AppendBytesTotal = %d, want > 0", res.Signal, res.Telemetry.AppendBytesTotal)
		}
		if res.AchievedRowsPerSec <= 0 {
			t.Errorf("signal %s AchievedRowsPerSec = %f, want > 0", res.Signal, res.AchievedRowsPerSec)
		}
		if res.Latency.Samples <= 0 {
			t.Errorf("signal %s Latency.Samples = %d, want > 0", res.Signal, res.Latency.Samples)
		}
		if res.Telemetry.RedactedValuesTotal <= 0 {
			t.Errorf("signal %s RedactedValuesTotal = %d, want > 0 when Redaction=true", res.Signal, res.Telemetry.RedactedValuesTotal)
		}
		if res.Telemetry.RedactedByMatchType["key"] <= 0 || res.Telemetry.RedactedByMatchType["value"] <= 0 {
			t.Errorf("signal %s RedactedByMatchType = %v, want key > 0 and value > 0", res.Signal, res.Telemetry.RedactedByMatchType)
		}
	}

	rawJSON, err := FormatJSON(report)
	if err != nil {
		t.Fatalf("FormatJSON() error: %v", err)
	}
	var decoded BenchmarkReport
	if err := json.Unmarshal([]byte(rawJSON), &decoded); err != nil {
		t.Fatalf("json.Unmarshal(FormatJSON) error: %v", err)
	}
	if len(decoded.Results) != 3 {
		t.Fatalf("decoded results = %d, want 3", len(decoded.Results))
	}

	md := FormatMarkdown(report)
	for _, want := range []string{"| `traces` |", "| `logs` |", "| `metrics` |", "Achieved Rows/s"} {
		if !strings.Contains(md, want) {
			t.Errorf("FormatMarkdown missing %q:\n%s", want, md)
		}
	}
}

func TestRunBQFakeBackpressureAndLocalOffload(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	offloadDir := t.TempDir()
	cfg := RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces", "logs"},
		Duration:              800 * time.Millisecond,
		BatchSize:             32,
		Workers:               2,
		StreamPoolSize:        2,
		ConnectionPoolSize:    2,
		Redaction:             true,
		Backpressure:          true,
		SimulateAckDelay:      15 * time.Millisecond,
		SimulateThrottleEvery: 2,
		PayloadBytes:          4096,
		OffloadDir:            offloadDir,
		OffloadThresholdBytes: 2048,
	}

	report, err := Run(ctx, cfg)
	if err != nil {
		t.Fatalf("Run() with backpressure and offload error: %v", err)
	}
	for _, res := range report.Results {
		if res.Telemetry.OffloadedPayloads <= 0 {
			t.Errorf("signal %s OffloadedPayloads = %d, want > 0", res.Signal, res.Telemetry.OffloadedPayloads)
		}
		if res.Telemetry.OffloadedBytes <= 0 {
			t.Errorf("signal %s OffloadedBytes = %d, want > 0", res.Signal, res.Telemetry.OffloadedBytes)
		}
		if res.Telemetry.OffloadDedupHits <= 0 {
			t.Errorf("signal %s OffloadDedupHits = %d, want > 0", res.Signal, res.Telemetry.OffloadDedupHits)
		}
		if res.Telemetry.RedactedValuesTotal <= 0 {
			t.Errorf("signal %s RedactedValuesTotal = %d, want > 0 when Redaction=true with local offload", res.Signal, res.Telemetry.RedactedValuesTotal)
		}
		if len(res.Telemetry.BackpressureEvents) == 0 {
			t.Errorf("signal %s expected BackpressureEvents to be recorded", res.Signal)
		}
		if res.Telemetry.BackpressureLevel <= 0 {
			t.Errorf("signal %s BackpressureLevel = %f, want > 0 under simulated ack delay and throttling", res.Signal, res.Telemetry.BackpressureLevel)
		}
		if res.Telemetry.Retries <= 0 {
			t.Errorf("signal %s Retries = %d, want > 0 under SimulateThrottleEvery=%d", res.Signal, res.Telemetry.Retries, cfg.SimulateThrottleEvery)
		}
	}

	// Verify Step-0 redaction ran before local-dir offload so no cleartext
	// secret patterns ever reached disk, and at least one offloaded blob on
	// disk contains the "[REDACTED]" mask replacement (non-vacuous proof that
	// planted secrets inside >= OffloadThresholdBytes payloads were redacted
	// prior to offload).
	var (
		totalBlobs    int
		redactedBlobs int
	)
	err = filepath.WalkDir(offloadDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		totalBlobs++
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		content := string(raw)
		for _, forbidden := range []string{"sk-proj-", "ya29.", "AKIA", "secret-key-"} {
			if strings.Contains(content, forbidden) {
				t.Errorf("offloaded file %s contains unredacted secret substring %q", path, forbidden)
			}
		}
		if strings.Contains(content, "[REDACTED]") {
			redactedBlobs++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking offloadDir: %v", err)
	}
	if totalBlobs == 0 {
		t.Fatal("expected offloaded files on disk in offloadDir, found 0")
	}
	if redactedBlobs == 0 {
		t.Fatalf("expected >= 1 offloaded file in %s to contain [REDACTED] placeholder, found 0 across %d files", offloadDir, totalBlobs)
	}
}

func TestRunMultiWorkerFaultsSurviveCrossWorkerCompletion(t *testing.T) {
	// With Workers > 1 and local offload latency between EnqueueFault and
	// AppendRows, one worker can overtake another, pop its FaultDelayedAck, and
	// cancel its own callCtx while its own FaultResourceExhausted is still queued
	// in bqfake. Scoped to signalCtx, every FaultResourceExhausted across all 4
	// batches (seq=2,4 => 2 throttles) must survive and trigger retries.
	for attempt := 0; attempt < 10; attempt++ {
		attemptCtx, cancelAttempt := context.WithTimeout(t.Context(), 20*time.Second)
		rep, err := Run(attemptCtx, RunnerConfig{
			Mode:                  ModeBQFake,
			Signals:               []string{"traces"},
			Duration:              10 * time.Second,
			maxBatches:            4,
			BatchSize:             64,
			Workers:               2,
			StreamPoolSize:        2,
			ConnectionPoolSize:    2,
			PayloadBytes:          4096,
			Redaction:             true,
			OffloadDir:            t.TempDir(),
			OffloadThresholdBytes: 2048,
			Backpressure:          true,
			SimulateAckDelay:      4 * time.Millisecond,
			SimulateThrottleEvery: 2,
		})
		cancelAttempt()
		if err != nil {
			t.Fatalf("attempt %d: Run() error: %v", attempt, err)
		}
		if len(rep.Results) != 1 {
			t.Fatalf("attempt %d: len(Results) = %d, want 1", attempt, len(rep.Results))
		}
		res := rep.Results[0]
		if res.BatchesSucceeded != 4 || res.BatchesFailed != 0 {
			t.Fatalf("attempt %d: BatchesSucceeded=%d, BatchesFailed=%d, want 4, 0",
				attempt, res.BatchesSucceeded, res.BatchesFailed)
		}
		if res.Telemetry.AcknowledgedRows != 256 {
			t.Fatalf("attempt %d: AcknowledgedRows=%d, want 256", attempt, res.Telemetry.AcknowledgedRows)
		}
		if res.Telemetry.Retries < 2 {
			t.Fatalf("attempt %d: Retries = %d, want >= 2 (no FaultResourceExhausted may be dropped by cross-worker callCtx cancellation)",
				attempt, res.Telemetry.Retries)
		}
		if len(res.Telemetry.BackpressureEvents) == 0 || res.Telemetry.BackpressureLevel <= 0 {
			t.Fatalf("attempt %d: backpressure events=%v level=%f, want recorded backpressure > 0",
				attempt, res.Telemetry.BackpressureEvents, res.Telemetry.BackpressureLevel)
		}
	}
}

func TestRunPerBatchCallTimeoutDoesNotExitWorker(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	// 1. Default AllowPartialFailures=false: when per-batch CallTimeout < SimulateAckDelay,
	// worker continues past delayed batches, and Run returns a non-nil error joined
	// with the underlying context.DeadlineExceeded while still returning the report.
	cfgStrict := RunnerConfig{
		Mode:               ModeBQFake,
		Signals:            []string{"traces"},
		Duration:           10 * time.Second,
		maxBatches:         4,
		BatchSize:          10,
		Workers:            1,
		StreamPoolSize:     1,
		ConnectionPoolSize: 1,
		SimulateAckDelay:   900 * time.Millisecond,
		CallTimeout:        300 * time.Millisecond,
	}
	reportStrict, errStrict := Run(ctx, cfgStrict)
	if errStrict == nil {
		t.Fatal("Run(AllowPartialFailures=false) with BatchesFailed > 0 succeeded, want non-nil error")
	}
	if !errors.Is(errStrict, context.DeadlineExceeded) && !strings.Contains(errStrict.Error(), "deadline exceeded") {
		t.Fatalf("Run(AllowPartialFailures=false) error = %v, want underlying deadline exceeded error", errStrict)
	}
	if reportStrict == nil || len(reportStrict.Results) != 1 {
		t.Fatalf("expected 1 result on strict report, got %+v", reportStrict)
	}
	if reportStrict.Results[0].BatchesFailed <= 0 || reportStrict.Results[0].BatchesSucceeded <= 0 {
		t.Fatalf("strict result BatchesFailed=%d, BatchesSucceeded=%d, want both > 0",
			reportStrict.Results[0].BatchesFailed, reportStrict.Results[0].BatchesSucceeded)
	}

	// 2. AllowPartialFailures=true permits non-zero BatchesFailed when BatchesSucceeded > 0.
	cfgAllow := cfgStrict
	cfgAllow.AllowPartialFailures = true
	report, err := Run(ctx, cfgAllow)
	if err != nil {
		t.Fatalf("Run(AllowPartialFailures=true) error: %v", err)
	}
	if len(report.Results) != 1 {
		t.Fatalf("len(report.Results) = %d, want 1", len(report.Results))
	}
	res := report.Results[0]
	if res.BatchesFailed <= 0 {
		t.Fatalf("BatchesFailed = %d, want > 0 when per-batch CallTimeout < SimulateAckDelay", res.BatchesFailed)
	}
	if res.BatchesSucceeded <= 0 {
		t.Fatalf("BatchesSucceeded = %d, want > 0 (worker must continue after per-batch CallTimeout)", res.BatchesSucceeded)
	}
	if res.BatchesAttempted != res.BatchesSucceeded+res.BatchesFailed {
		t.Fatalf("BatchesAttempted = %d, want %d+%d", res.BatchesAttempted, res.BatchesSucceeded, res.BatchesFailed)
	}
}

func TestRunUniquePayloadsAndZeroAckErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// 1. UniquePayloads=true generates fresh batches beyond 8 batches with 0 dedup hits.
	offloadDir := t.TempDir()
	uniqueCfg := RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              800 * time.Millisecond,
		BatchSize:             4,
		Workers:               2,
		StreamPoolSize:        2,
		ConnectionPoolSize:    2,
		PayloadBytes:          1024,
		UniquePayloads:        true,
		OffloadDir:            offloadDir,
		OffloadThresholdBytes: 512,
	}
	uniqueRep, err := Run(ctx, uniqueCfg)
	if err != nil {
		t.Fatalf("Run(UniquePayloads=true) error: %v", err)
	}
	if uniqueRep.Results[0].BatchesSucceeded <= 8 {
		t.Fatalf("BatchesSucceeded = %d, want > 8", uniqueRep.Results[0].BatchesSucceeded)
	}
	if uniqueRep.Results[0].Telemetry.OffloadDedupHits != 0 {
		t.Fatalf("OffloadDedupHits = %d, want 0 when UniquePayloads=true", uniqueRep.Results[0].Telemetry.OffloadDedupHits)
	}

	// 2. All-rejected run (payload exceeds 256 KiB limits.max_value_bytes without offload)
	// must report AchievedRowsPerSec == 0 and return a non-nil error.
	rejectCfg := RunnerConfig{
		Mode:               ModeBQFake,
		Signals:            []string{"traces"},
		Duration:           120 * time.Millisecond,
		BatchSize:          8,
		Workers:            1,
		StreamPoolSize:     1,
		ConnectionPoolSize: 1,
		PayloadBytes:       2 * 1024 * 1024,
	}
	rejectRep, err := Run(ctx, rejectCfg)
	if err == nil {
		t.Fatal("Run() with 100% rejected rows succeeded, want non-nil error")
	}
	if rejectRep == nil || len(rejectRep.Results) != 1 {
		t.Fatalf("expected 1 result on rejected report, got %+v", rejectRep)
	}
	if rejectRep.Results[0].AchievedRowsPerSec != 0 {
		t.Fatalf("AchievedRowsPerSec = %f, want 0 when AcknowledgedRows == 0", rejectRep.Results[0].AchievedRowsPerSec)
	}
	if rejectRep.Results[0].Telemetry.RejectedRows <= 0 {
		t.Fatalf("RejectedRows = %d, want > 0", rejectRep.Results[0].Telemetry.RejectedRows)
	}

	// 3. Parent context cancellation during run must return a non-nil error.
	shortCtx, cancelShort := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancelShort()
	if _, err := Run(shortCtx, RunnerConfig{
		Mode:             ModeBQFake,
		Signals:          []string{"traces"},
		Duration:         2 * time.Second,
		BatchSize:        20,
		Workers:          1,
		SimulateAckDelay: 100 * time.Millisecond,
	}); err == nil {
		t.Fatal("Run() with canceled parent context succeeded, want non-nil error")
	}
}

func TestRunStreamPoolSweepAndValidation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	cfg := RunnerConfig{
		Mode:      ModeBQFake,
		Signals:   []string{"traces"},
		Duration:  150 * time.Millisecond,
		BatchSize: 40,
		Workers:   2,
	}
	report, err := RunStreamPoolSweep(ctx, cfg, []int{1, 2})
	if err != nil {
		t.Fatalf("RunStreamPoolSweep error: %v", err)
	}
	if len(report.Results) != 2 {
		t.Fatalf("len(report.Results) = %d, want 2", len(report.Results))
	}
	if report.Results[0].StreamPoolSize != 1 || report.Results[1].StreamPoolSize != 2 {
		t.Fatalf("unexpected stream pool sizes: %d, %d", report.Results[0].StreamPoolSize, report.Results[1].StreamPoolSize)
	}

	// Verify Normalize auto-generates otel_bench_<timestamp>_<random_hex> when
	// EphemeralDataset=true and DatasetID is empty, produces 1,000 collision-free
	// IDs across 1,000 tight-loop calls in the same millisecond, and allows
	// subsequent Normalize calls on the generated config.
	dsPattern := regexp.MustCompile(`^otel_bench_[0-9]+_[0-9a-f]{16}$`)
	seenDatasetIDs := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		ephemeralCfg := RunnerConfig{
			Mode:             ModeLive,
			ProjectID:        "test-project",
			EphemeralDataset: true,
		}
		if err := ephemeralCfg.Normalize(); err != nil {
			t.Fatalf("Normalize(ephemeralCfg #%d) unexpected error: %v", i, err)
		}
		if !dsPattern.MatchString(ephemeralCfg.DatasetID) {
			t.Fatalf("ephemeralCfg.DatasetID = %q, want match %s", ephemeralCfg.DatasetID, dsPattern)
		}
		if seenDatasetIDs[ephemeralCfg.DatasetID] {
			t.Fatalf("duplicate ephemeral DatasetID %q at iteration %d", ephemeralCfg.DatasetID, i)
		}
		seenDatasetIDs[ephemeralCfg.DatasetID] = true
		if err := ephemeralCfg.Normalize(); err != nil {
			t.Fatalf("second Normalize(ephemeralCfg #%d) unexpected error: %v", i, err)
		}
	}

	validMaxInflightCfg := RunnerConfig{
		Mode:                ModeBQFake,
		MaxInflightRequests: MaxBenchmarkInflightRequests,
	}
	if err := validMaxInflightCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(MaxInflightRequests=%d) unexpected error: %v", MaxBenchmarkInflightRequests, err)
	}

	invalidCases := []RunnerConfig{
		{Mode: "invalid"},
		{Mode: ModeBQFake, Signals: []string{"profiles"}},
		{Mode: ModeBQFake, StreamPoolSize: 32},
		{Mode: ModeBQFake, ConnectionPoolSize: 32},
		{Mode: ModeLive, ProjectID: ""},
		{Mode: ModeLive, ProjectID: "test-project", DatasetID: ""},
		{Mode: ModeLive, ProjectID: "test-project", DatasetID: "prod_otel", EphemeralDataset: true},
		{Mode: ModeBQFake, DatasetID: "prod_otel", EphemeralDataset: true},
		{Mode: ModeBQFake, OffloadDir: "/tmp/a", OffloadGCSBucket: "bkt"},
		{Mode: ModeBQFake, OffloadGCSBucket: "bkt"},
		{Mode: ModeBQFake, Duration: -time.Second},
		{Mode: ModeBQFake, BatchSize: -1},
		{Mode: ModeBQFake, BatchSize: MaxBenchmarkBatchSize + 1},
		{Mode: ModeBQFake, Workers: -1},
		{Mode: ModeBQFake, Workers: MaxBenchmarkWorkers + 1},
		{Mode: ModeBQFake, StreamPoolSize: -1},
		{Mode: ModeBQFake, ConnectionPoolSize: -1},
		{Mode: ModeBQFake, MaxInflightRequests: -1},
		{Mode: ModeBQFake, MaxInflightRequests: MaxBenchmarkInflightRequests + 1},
		{Mode: ModeBQFake, MaxInflightRequests: math.MaxInt},
		{Mode: ModeBQFake, PayloadBytes: -1},
		{Mode: ModeBQFake, PayloadBytes: math.MaxInt},
		{Mode: ModeBQFake, BatchSize: 1000, PayloadBytes: 512 * 1024},
		{Mode: ModeBQFake, TargetRate: -1},
		{Mode: ModeBQFake, SimulateThrottleEvery: -1},
		{Mode: ModeBQFake, SimulateAckDelay: -time.Millisecond},
		{Mode: ModeBQFake, CallTimeout: -time.Millisecond},
	}
	for _, tc := range invalidCases {
		if err := tc.Normalize(); err == nil {
			t.Errorf("Normalize(%+v) succeeded, want error", tc)
		}
	}
}

func TestDeleteDatasetWithContentsAndDatasetExistsHTTP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	var (
		getCalls           atomic.Int32
		postCalls          atomic.Int32
		deleteCalls        atomic.Int32
		postStatus         atomic.Int32
		delStatus          atomic.Int32
		commitOnPostError  atomic.Bool
		postWaitCancel     atomic.Bool
		postCancelRelease  = make(chan struct{})
		getCommittedStatus atomic.Int32
		onAfterErrorGet    atomic.Pointer[context.CancelFunc]
		onAfterPost        atomic.Pointer[context.CancelFunc]
		committedMu        sync.Mutex
		committedLabels    = make(map[string]map[string]string)
	)
	defer close(postCancelRelease)
	postStatus.Store(http.StatusOK)
	delStatus.Store(http.StatusNoContent)
	getCommittedStatus.Store(http.StatusOK)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			getCalls.Add(1)
			switch {
			case strings.HasSuffix(r.URL.Path, "/datasets/existing_ds"):
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"datasetReference":{"projectId":"test-proj","datasetId":"existing_ds"}}`))
				return
			case strings.HasSuffix(r.URL.Path, "/datasets/forbidden_ds"):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Access Denied"}}`))
				return
			case strings.HasSuffix(r.URL.Path, "/datasets/error_ds"):
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":{"code":500,"message":"Internal Server Error"}}`))
				if fn := onAfterErrorGet.Load(); fn != nil && *fn != nil {
					(*fn)()
				}
				return
			}
			parts := strings.Split(r.URL.Path, "/datasets/")
			if len(parts) == 2 && parts[1] != "" {
				dsID := parts[1]
				committedMu.Lock()
				labels, ok := committedLabels[dsID]
				committedMu.Unlock()
				if ok {
					status := int(getCommittedStatus.Load())
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(status)
					if status >= 400 {
						_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"Metadata Check Error"}}`, status)
						return
					}
					resp := map[string]any{
						"datasetReference": map[string]string{
							"projectId": "test-proj",
							"datasetId": dsID,
						},
						"labels": labels,
					}
					_ = json.NewEncoder(w).Encode(resp)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Not found"}}`))
		case http.MethodPost:
			postCalls.Add(1)
			var body struct {
				DatasetReference struct {
					DatasetID string `json:"datasetId"`
				} `json:"datasetReference"`
				Labels map[string]string `json:"labels"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			dsID := body.DatasetReference.DatasetID
			if dsID == "" {
				dsID = "created_ds"
			}
			code := int(postStatus.Load())
			if code == http.StatusOK || commitOnPostError.Load() || postWaitCancel.Load() {
				committedMu.Lock()
				if _, exists := committedLabels[dsID]; !exists {
					copied := make(map[string]string, len(body.Labels))
					for k, v := range body.Labels {
						copied[k] = v
					}
					if dsID == "post_500_other_owner_ds" {
						copied[ephemeralOwnerLabelKey] = "foreign-owner-token"
					}
					committedLabels[dsID] = copied
				}
				committedMu.Unlock()
			}
			if fn := onAfterPost.Load(); fn != nil && *fn != nil {
				(*fn)()
			}
			if postWaitCancel.Load() {
				select {
				case <-r.Context().Done():
				case <-postCancelRelease:
				}
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if code == http.StatusConflict {
				_, _ = w.Write([]byte(`{"error":{"code":409,"message":"Already Exists"}}`))
				return
			}
			if code >= 400 {
				_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"Post-Commit Server Error"}}`, code)
				return
			}
			_, _ = fmt.Fprintf(w, `{"datasetReference":{"projectId":"test-proj","datasetId":%q}}`, dsID)
		case http.MethodDelete:
			deleteCalls.Add(1)
			if r.URL.Query().Get("deleteContents") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			code := int(delStatus.Load())
			if code < 400 {
				parts := strings.Split(r.URL.Path, "/datasets/")
				if len(parts) == 2 {
					committedMu.Lock()
					delete(committedLabels, parts[1])
					committedMu.Unlock()
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(code)
			if code >= 400 {
				_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Delete forbidden"}}`))
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	opts := []option.ClientOption{
		option.WithEndpoint(srv.URL),
		option.WithoutAuthentication(),
	}

	exists, err := datasetExists(ctx, "test-proj", "existing_ds", opts...)
	if err != nil {
		t.Fatalf("datasetExists(existing_ds) error: %v", err)
	}
	if !exists {
		t.Fatal("datasetExists(existing_ds) = false, want true")
	}

	exists, err = datasetExists(ctx, "test-proj", "otel_bench_absent", opts...)
	if err != nil {
		t.Fatalf("datasetExists(otel_bench_absent) error: %v", err)
	}
	if exists {
		t.Fatal("datasetExists(otel_bench_absent) = true, want false")
	}

	// Verify datasetExists fails closed on non-404 HTTP errors (403 Forbidden and 500 Internal Server Error).
	if _, err := datasetExists(ctx, "test-proj", "forbidden_ds", opts...); err == nil {
		t.Fatal("datasetExists(forbidden_ds) succeeded, want non-nil error (fail closed)")
	}
	ctx500, cancel500 := context.WithTimeout(ctx, 10*time.Second)
	defer cancel500()
	onAfterErrorGet.Store(&cancel500)
	if _, err := datasetExists(ctx500, "test-proj", "error_ds", opts...); err == nil {
		t.Fatal("datasetExists(error_ds) succeeded, want non-nil error (fail closed)")
	}
	onAfterErrorGet.Store(nil)

	if err := DeleteDatasetWithContents(ctx, "test-proj", "otel_bench_absent", opts...); err != nil {
		t.Fatalf("DeleteDatasetWithContents error: %v", err)
	}
	if deleteCalls.Load() != 1 {
		t.Fatalf("deleteCalls = %d, want 1", deleteCalls.Load())
	}

	// Verify createEphemeralDataset and Run/RunStreamPoolSweep ownership & pre-validation guards:
	// 1. Pre-existing dataset (GET -> 200): 0 POSTs, 0 DELETEs.
	postCalls.Store(0)
	deleteCalls.Store(0)
	if err := createEphemeralDataset(ctx, "test-proj", "existing_ds", "US", opts...); err == nil {
		t.Fatal("createEphemeralDataset(existing_ds) succeeded, want error")
	}
	if postCalls.Load() != 0 || deleteCalls.Load() != 0 {
		t.Fatalf("existing_ds triggered post=%d, delete=%d, want 0, 0", postCalls.Load(), deleteCalls.Load())
	}

	// 2. Concurrent creator race (GET -> 404, POST -> 409 Conflict): Run and RunStreamPoolSweep
	// must abort before setting owned=true and must NEVER call DELETE on the concurrently created dataset.
	postStatus.Store(http.StatusConflict)
	for _, isSweep := range []bool{false, true} {
		getCalls.Store(0)
		postCalls.Store(0)
		deleteCalls.Store(0)
		raceCfg := RunnerConfig{
			Mode:             ModeLive,
			ProjectID:        "test-proj",
			EphemeralDataset: true,
			ClientOptions:    opts,
		}
		var raceErr error
		if isSweep {
			_, raceErr = RunStreamPoolSweep(ctx, raceCfg, []int{1, 2})
		} else {
			_, raceErr = Run(ctx, raceCfg)
		}
		if raceErr == nil || !strings.Contains(raceErr.Error(), "creating ephemeral dataset") {
			t.Fatalf("isSweep=%t concurrent 409 error = %v, want creating ephemeral dataset error", isSweep, raceErr)
		}
		if postCalls.Load() != 1 || deleteCalls.Load() != 0 {
			t.Fatalf("isSweep=%t concurrent 409 post=%d, delete=%d, want 1, 0", isSweep, postCalls.Load(), deleteCalls.Load())
		}
	}

	// 3. Pre-validation failure (invalid streamPoolSizes [1, 99] or pre-canceled ctx)
	// must fail BEFORE any dataset GET/POST/DELETE HTTP request is issued.
	postStatus.Store(http.StatusOK)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	if _, err := RunStreamPoolSweep(ctx, RunnerConfig{
		Mode:             ModeLive,
		ProjectID:        "test-proj",
		EphemeralDataset: true,
		ClientOptions:    opts,
	}, []int{1, 99}); err == nil {
		t.Fatal("RunStreamPoolSweep([1, 99]) succeeded, want validation error")
	}
	if getCalls.Load() != 0 || postCalls.Load() != 0 || deleteCalls.Load() != 0 {
		t.Fatalf("invalid sweep pool sizes made HTTP calls get=%d, post=%d, delete=%d, want 0, 0, 0",
			getCalls.Load(), postCalls.Load(), deleteCalls.Load())
	}

	canceledCtx, cancelImmediate := context.WithCancel(ctx)
	cancelImmediate()
	if _, err := Run(canceledCtx, RunnerConfig{
		Mode:             ModeLive,
		ProjectID:        "test-proj",
		EphemeralDataset: true,
		ClientOptions:    opts,
	}); err == nil {
		t.Fatal("Run(canceledCtx) succeeded, want context.Canceled")
	}
	if getCalls.Load() != 0 || postCalls.Load() != 0 || deleteCalls.Load() != 0 {
		t.Fatalf("pre-canceled ctx made HTTP calls get=%d, post=%d, delete=%d, want 0, 0, 0",
			getCalls.Load(), postCalls.Load(), deleteCalls.Load())
	}

	// 4. Owned dataset cleanup failure (GET -> 404, POST -> 200, then exporter Start fails locally on missing ADC file, and DELETE -> 403):
	// Run must execute DELETE because it created the dataset, and must join the DELETE error
	// into the returned error while leaving EphemeralDatasetDeleted == false.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-adc.json"))
	delStatus.Store(http.StatusForbidden)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	delFailRep, delFailErr := Run(ctx, RunnerConfig{
		Mode:             ModeLive,
		ProjectID:        "test-proj",
		EphemeralDataset: true,
		Duration:         10 * time.Millisecond,
		CallTimeout:      10 * time.Millisecond,
		ClientOptions:    opts,
	})
	if delFailErr == nil || !strings.Contains(delFailErr.Error(), "deleting dataset") {
		t.Fatalf("Run() with failing DELETE error = %v, want joined 'deleting dataset' error", delFailErr)
	}
	if postCalls.Load() != 1 || deleteCalls.Load() != 1 {
		t.Fatalf("owned dataset cleanup failure post=%d, delete=%d, want 1, 1", postCalls.Load(), deleteCalls.Load())
	}
	if delFailRep != nil && delFailRep.EphemeralDatasetDeleted {
		t.Fatal("EphemeralDatasetDeleted = true when DELETE returned 403, want false")
	}

	// 5. Ambiguous dataset Create failure cleanup via ownership label verification:
	// 5a. Post-commit 500 where dataset was created with our bq_otel_testbench_owner label:
	// createEphemeralDataset must verify the label via GET and delete the leaked dataset immediately.
	// Trigger caller context cancellation deterministically inside the POST handler after the server
	// records the committed dataset so client init + preflight GET never race wall-clock timers.
	commitOnPostError.Store(true)
	postStatus.Store(http.StatusInternalServerError)
	delStatus.Store(http.StatusNoContent)
	getCommittedStatus.Store(http.StatusOK)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	ctxPost500, cancelPost500 := context.WithTimeout(ctx, 10*time.Second)
	defer cancelPost500()
	onAfterPost.Store(&cancelPost500)
	post500Err := createEphemeralDataset(ctxPost500, "test-proj", "post_500_owned_ds", "US", opts...)
	onAfterPost.Store(nil)
	if post500Err == nil || !strings.Contains(post500Err.Error(), "creating ephemeral dataset test-proj.post_500_owned_ds") {
		t.Fatalf("createEphemeralDataset(post_500_owned_ds) error = %v, want creating ephemeral dataset error", post500Err)
	}
	if postCalls.Load() < 1 || deleteCalls.Load() != 1 {
		t.Fatalf("post-commit 500 with matching owner label: post=%d, delete=%d, want >=1, 1",
			postCalls.Load(), deleteCalls.Load())
	}

	// 5b. Post-commit client timeout / context cancellation during POST:
	// createEphemeralDataset must use its bounded background cleanup context to verify the
	// bq_otel_testbench_owner label and delete the dataset even though the caller ctx expired.
	commitOnPostError.Store(false)
	postWaitCancel.Store(true)
	postStatus.Store(http.StatusOK)
	delStatus.Store(http.StatusNoContent)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	postTimeoutCtx, cancelPostTimeout := context.WithTimeout(ctx, 10*time.Second)
	defer cancelPostTimeout()
	onAfterPost.Store(&cancelPostTimeout)
	timeoutCreateErr := createEphemeralDataset(postTimeoutCtx, "test-proj", "post_timeout_owned_ds", "US", opts...)
	onAfterPost.Store(nil)
	if timeoutCreateErr == nil {
		t.Fatal("createEphemeralDataset(post_timeout_owned_ds) succeeded on timed-out ctx, want error")
	}
	if postCalls.Load() != 1 || deleteCalls.Load() != 1 {
		t.Fatalf("post-commit timeout with matching owner label: post=%d, delete=%d, want 1, 1",
			postCalls.Load(), deleteCalls.Load())
	}
	postWaitCancel.Store(false)

	// 5c. Ambiguous POST failure where follow-up GET fails (403) or owner label belongs to another creator:
	// createEphemeralDataset must NOT delete the dataset and must report the dataset ID when unverified.
	commitOnPostError.Store(true)
	postStatus.Store(http.StatusInternalServerError)
	getCommittedStatus.Store(http.StatusForbidden)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	ctxUnverified, cancelUnverified := context.WithTimeout(ctx, 10*time.Second)
	defer cancelUnverified()
	onAfterPost.Store(&cancelUnverified)
	unverifiedErr := createEphemeralDataset(ctxUnverified, "test-proj", "post_500_unverified_ds", "US", opts...)
	onAfterPost.Store(nil)
	if unverifiedErr == nil || !strings.Contains(unverifiedErr.Error(), "was left behind") {
		t.Fatalf("createEphemeralDataset(post_500_unverified_ds) error = %v, want 'was left behind' notice", unverifiedErr)
	}
	if deleteCalls.Load() != 0 {
		t.Fatalf("unverified metadata DELETE calls = %d, want 0", deleteCalls.Load())
	}

	getCommittedStatus.Store(http.StatusOK)
	commitOnPostError.Store(true)
	postStatus.Store(http.StatusInternalServerError)
	getCalls.Store(0)
	postCalls.Store(0)
	deleteCalls.Store(0)
	ctxOtherOwner, cancelOtherOwner := context.WithTimeout(ctx, 10*time.Second)
	defer cancelOtherOwner()
	onAfterPost.Store(&cancelOtherOwner)
	otherOwnerErr := createEphemeralDataset(ctxOtherOwner, "test-proj", "post_500_other_owner_ds", "US", opts...)
	onAfterPost.Store(nil)
	if otherOwnerErr == nil || !strings.Contains(otherOwnerErr.Error(), "refusing to delete") {
		t.Fatalf("createEphemeralDataset(post_500_other_owner_ds) error = %v, want 'refusing to delete'", otherOwnerErr)
	}
	if deleteCalls.Load() != 0 {
		t.Fatalf("foreign owner label DELETE calls = %d, want 0", deleteCalls.Load())
	}
	commitOnPostError.Store(false)
	postStatus.Store(http.StatusOK)
	delStatus.Store(http.StatusNoContent)
}

func TestRunPartialFailureEmptyWindowInvalidOffloadAndPanicRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	// 1. Empty measurement window (canceled context → 0 samples / 0 acked rows) must fail.
	canceledCtx, cancelImmediate := context.WithCancel(ctx)
	cancelImmediate()
	if _, err := Run(canceledCtx, RunnerConfig{
		Mode:             ModeBQFake,
		Signals:          []string{"traces"},
		Duration:         100 * time.Millisecond,
		BatchSize:        10,
		Workers:          1,
		TargetRate:       10,
		SimulateAckDelay: 50 * time.Millisecond,
	}); err == nil {
		t.Fatal("Run with canceled context and 0 completed batches succeeded, want non-nil error")
	}

	// 2. Regular file passed as OffloadDir fails pre-validation with "not a directory".
	tmpFile := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", tmpFile, err)
	}
	if _, err := Run(ctx, RunnerConfig{
		Mode:       ModeBQFake,
		Signals:    []string{"traces"},
		Duration:   100 * time.Millisecond,
		BatchSize:  4,
		Workers:    1,
		OffloadDir: tmpFile,
	}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Run(OffloadDir=regular file) error = %v, want 'not a directory'", err)
	}

	// 3. Underlying offload filesystem error during worker execution is preserved via errors.Join.
	offloadRoot := t.TempDir()
	// Create a regular file at "<offloadRoot>/local-offload-bench" so validateRunConfig
	// sees offloadRoot as a valid directory, but WriteObject's MkdirAll("<offloadRoot>/local-offload-bench/...")
	// fails with ENOTDIR ("not a directory") on every batch.
	blockerFile := filepath.Join(offloadRoot, "local-offload-bench")
	if err := os.WriteFile(blockerFile, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", blockerFile, err)
	}
	_, offloadErr := Run(ctx, RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              120 * time.Millisecond,
		BatchSize:             4,
		Workers:               1,
		PayloadBytes:          1024,
		OffloadDir:            offloadRoot,
		OffloadThresholdBytes: 512,
	})
	if offloadErr == nil || (!strings.Contains(offloadErr.Error(), "not a directory") && !strings.Contains(offloadErr.Error(), "The system cannot find the path specified")) {
		t.Fatalf("Run() with failing offload WriteObject error = %v, want underlying directory error preserved", offloadErr)
	}

	// 4. Worker panic is recovered into a structured error and exporter is shut down cleanly (0 leaked goroutines).
	_, panicErr := Run(ctx, RunnerConfig{
		Mode:      ModeBQFake,
		Signals:   []string{"traces"},
		Duration:  200 * time.Millisecond,
		BatchSize: 8,
		Workers:   2,
		workerHook: func(_, seq int) {
			if seq == 1 {
				panic("simulated worker fault")
			}
		},
	})
	if panicErr == nil || !strings.Contains(panicErr.Error(), "panicked: simulated worker fault") {
		t.Fatalf("Run() with panicking worker error = %v, want recovered panic error", panicErr)
	}

	// 5. Large >4 MiB ProtoRows batch (500 spans x 16 KiB = ~8 MiB request) succeeds against bqfake.
	largeRep, err := Run(ctx, RunnerConfig{
		Mode:               ModeBQFake,
		Signals:            []string{"traces"},
		Duration:           10 * time.Second,
		maxBatches:         2,
		BatchSize:          500,
		Workers:            1,
		StreamPoolSize:     1,
		ConnectionPoolSize: 1,
		PayloadBytes:       16384,
	})
	if err != nil {
		t.Fatalf("Run(500 x 16 KiB >4 MiB batch) error: %v", err)
	}
	if largeRep.Results[0].BatchesFailed != 0 || largeRep.Results[0].Telemetry.AcknowledgedRows < 500 {
		t.Fatalf("large batch result: failed=%d, acked=%d, want failed=0, acked>=500",
			largeRep.Results[0].BatchesFailed, largeRep.Results[0].Telemetry.AcknowledgedRows)
	}
	if largeRep.Results[0].BytesPerRow <= 16384 {
		t.Fatalf("large batch BytesPerRow = %f, want > 16384", largeRep.Results[0].BytesPerRow)
	}

	// 6. Retry-uninflated BytesPerRow vs AttemptedBytesPerAckedRow under SimulateThrottleEvery=2.
	baseRep, err := Run(ctx, RunnerConfig{
		Mode:       ModeBQFake,
		Signals:    []string{"traces"},
		Duration:   10 * time.Second,
		maxBatches: 4,
		BatchSize:  28,
		Workers:    1,
	})
	if err != nil {
		t.Fatalf("Run(baseline) error: %v", err)
	}
	throttleRep, err := Run(ctx, RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              10 * time.Second,
		maxBatches:            4,
		BatchSize:             28,
		Workers:               1,
		SimulateThrottleEvery: 2,
	})
	if err != nil {
		t.Fatalf("Run(throttled) error: %v", err)
	}
	if throttleRep.Results[0].Telemetry.Retries <= 0 {
		t.Fatalf("throttled Retries = %d, want > 0", throttleRep.Results[0].Telemetry.Retries)
	}
	if math.Abs(throttleRep.Results[0].BytesPerRow-baseRep.Results[0].BytesPerRow) > 5.0 {
		t.Fatalf("throttled BytesPerRow = %.2f vs baseline %.2f, want retry-uninflated match",
			throttleRep.Results[0].BytesPerRow, baseRep.Results[0].BytesPerRow)
	}
	if throttleRep.Results[0].AttemptedBytesPerAckedRow <= throttleRep.Results[0].BytesPerRow {
		t.Fatalf("throttled AttemptedBytesPerAckedRow (%.2f) must exceed single-append BytesPerRow (%.2f)",
			throttleRep.Results[0].AttemptedBytesPerAckedRow, throttleRep.Results[0].BytesPerRow)
	}
	// Verify WireMBPerSec reflects single-attempt BytesPerRow * AchievedRowsPerSec rather than retry-inflated AppendBytesTotal.
	expectedWireMB := (throttleRep.Results[0].BytesPerRow * throttleRep.Results[0].AchievedRowsPerSec) / (1024.0 * 1024.0)
	inflatedWireMB := (throttleRep.Results[0].AttemptedBytesPerAckedRow * throttleRep.Results[0].AchievedRowsPerSec) / (1024.0 * 1024.0)
	if math.Abs(throttleRep.Results[0].WireMBPerSec-expectedWireMB) > math.Max(0.15, expectedWireMB*0.03) {
		t.Fatalf("throttled WireMBPerSec = %.2f, want ~%.2f (inflated would be %.2f)",
			throttleRep.Results[0].WireMBPerSec, expectedWireMB, inflatedWireMB)
	}

	// 6b. Uneven split-batch retry (500 spans x 16 KiB = ~9.13 MiB -> split into 9 uneven
	// AppendRows chunks: eight 57-row chunks and one 44-row tail chunk under 1 MiB max_request_bytes)
	// with SimulateThrottleEvery=1 must preserve exact uninflated BytesPerRow.
	splitThrottleRep, err := Run(ctx, RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              10 * time.Second,
		maxBatches:            2,
		BatchSize:             500,
		Workers:               1,
		StreamPoolSize:        1,
		ConnectionPoolSize:    1,
		PayloadBytes:          16384,
		SimulateThrottleEvery: 1,
	})
	if err != nil {
		t.Fatalf("Run(split 500 x 16 KiB throttled) error: %v", err)
	}
	if splitThrottleRep.Results[0].Telemetry.Retries <= 0 {
		t.Fatalf("split throttled Retries = %d, want > 0", splitThrottleRep.Results[0].Telemetry.Retries)
	}
	if math.Abs(splitThrottleRep.Results[0].BytesPerRow-largeRep.Results[0].BytesPerRow) > 1.0 {
		t.Fatalf("split throttled BytesPerRow = %.2f vs unthrottled %.2f, want exact match within 1 B",
			splitThrottleRep.Results[0].BytesPerRow, largeRep.Results[0].BytesPerRow)
	}
	if splitThrottleRep.Results[0].AttemptedBytesPerAckedRow <= splitThrottleRep.Results[0].BytesPerRow {
		t.Fatalf("split throttled AttemptedBytesPerAckedRow (%.2f) must exceed BytesPerRow (%.2f)",
			splitThrottleRep.Results[0].AttemptedBytesPerAckedRow, splitThrottleRep.Results[0].BytesPerRow)
	}
	// Also verify measureSingleAttemptBytesPerRow (used in live mode when Retries > 0) matches
	// bqfake AckedBytes()/AcknowledgedRows across all three signals.
	for _, sig := range []string{"traces", "logs", "metrics"} {
		sampleCfg := RunnerConfig{
			Mode:         ModeBQFake,
			Signals:      []string{sig},
			Duration:     100 * time.Millisecond,
			BatchSize:    28,
			Workers:      1,
			PayloadBytes: 16384,
			Redaction:    true,
		}
		if err := sampleCfg.Normalize(); err != nil {
			t.Fatalf("Normalize(%s): %v", sig, err)
		}
		singleBPR, err := measureSingleAttemptBytesPerRow(sampleCfg, sig)
		if err != nil || singleBPR <= 0 {
			t.Fatalf("measureSingleAttemptBytesPerRow(%s) = %f, err = %v, want > 0, nil", sig, singleBPR, err)
		}
	}

	// 7. Pre-append offload failures under AllowPartialFailures=true must not
	// dilute BytesPerRow (since ConsumeTraces was not dispatched for those batches).
	cleanOffloadDir := t.TempDir()
	cleanOffloadRep, err := Run(ctx, RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              10 * time.Second,
		maxBatches:            4,
		BatchSize:             28,
		Workers:               1,
		PayloadBytes:          1024,
		UniquePayloads:        true,
		OffloadDir:            cleanOffloadDir,
		OffloadThresholdBytes: 512,
	})
	if err != nil {
		t.Fatalf("Run(cleanOffload) error: %v", err)
	}
	flakyOffloadRoot := t.TempDir()
	flakyBucketPath := filepath.Join(flakyOffloadRoot, "local-offload-bench")
	partialOffloadRep, err := Run(ctx, RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"traces"},
		Duration:              10 * time.Second,
		maxBatches:            4,
		BatchSize:             28,
		Workers:               1,
		PayloadBytes:          1024,
		UniquePayloads:        true,
		OffloadDir:            flakyOffloadRoot,
		OffloadThresholdBytes: 512,
		AllowPartialFailures:  true,
		workerHook: func(_, seq int) {
			switch seq {
			case 1:
				_ = os.RemoveAll(flakyBucketPath)
				_ = os.WriteFile(flakyBucketPath, []byte("blocker"), 0o600)
			case 2:
				_ = os.Remove(flakyBucketPath)
			}
		},
	})
	if err != nil {
		t.Fatalf("Run(partialOffload, AllowPartialFailures=true) error: %v", err)
	}
	if partialOffloadRep.Results[0].BatchesFailed <= 0 || partialOffloadRep.Results[0].BatchesSucceeded <= 0 {
		t.Fatalf("partialOffload BatchesFailed=%d, BatchesSucceeded=%d, want both > 0",
			partialOffloadRep.Results[0].BatchesFailed, partialOffloadRep.Results[0].BatchesSucceeded)
	}
	if math.Abs(partialOffloadRep.Results[0].BytesPerRow-cleanOffloadRep.Results[0].BytesPerRow) > 5.0 {
		t.Fatalf("partialOffload BytesPerRow = %.2f vs cleanOffload %.2f, want pre-append offload failures excluded from BytesPerRow denominator",
			partialOffloadRep.Results[0].BytesPerRow, cleanOffloadRep.Results[0].BytesPerRow)
	}
}

func TestDocsCostModelOffloadSizesAndBenchmarkReportJSON(t *testing.T) {
	// 1. Verify exact single-row ProtoRows serialized sizes (inline vs ObjectRef offload)
	// and content-addressed GCS object key format (no .json extension) documented in docs/cost-estimation.md.
	gen := NewGenerator(GeneratorConfig{
		PayloadBytes: 16384,
	})
	tdInline := gen.TracesBatch(28)
	ldInline := gen.LogsBatch(28)
	mdInline := gen.MetricsBatch(28)

	tOpts := transform.Options{
		Limits: transform.DefaultLimits(),
	}
	spanEnc, err := protoenc.New(schema.SpansTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(SpansTableSchema): %v", err)
	}
	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	metricEnc, err := protoenc.New(schema.MetricsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(MetricsTableSchema): %v", err)
	}
	encodeSumBytes := func(enc *protoenc.Encoder, rows []transform.Row) int {
		var sum int
		for _, r := range rows {
			b, encErr := enc.Encode(r)
			if encErr != nil {
				t.Fatalf("enc.Encode: %v", encErr)
			}
			sum += len(b)
		}
		return sum
	}

	inlineSpanRows, _ := transform.SpanRows(tdInline, tOpts)
	inlineSpanBytes := encodeSumBytes(spanEnc, inlineSpanRows)
	if math.Abs(float64(inlineSpanBytes)/28.0-17559.0) > 10.0 {
		t.Fatalf("inlineSpanBytes/28 = %.2f (%d B), want ~17559 B/span", float64(inlineSpanBytes)/28.0, inlineSpanBytes)
	}

	inlineLogRows, _ := transform.LogRows(ldInline, tOpts)
	inlineLogBytes := encodeSumBytes(logEnc, inlineLogRows)
	if inlineLogBytes <= 400000 {
		t.Fatalf("inlineLogBytes = %d, want > 400000", inlineLogBytes)
	}

	inlineMetricRows, _ := transform.MetricRows(mdInline, tOpts)
	inlineMetricBytes := encodeSumBytes(metricEnc, inlineMetricRows)
	if int(math.Round(float64(inlineMetricBytes)/28.0)) != 911 {
		t.Fatalf("inlineMetricBytes = %d (%.2f B/point), want 911 B/point", inlineMetricBytes, float64(inlineMetricBytes)/28.0)
	}

	// Offload via internal/offload with MinBytes=4096 and verify exact offloaded row sizes and object keys.
	offloadRoot := t.TempDir()
	store := &localDirBlobStore{rootDir: offloadRoot}
	offloader, err := offload.New(store, offload.Options{
		Bucket:         "local-offload-bench",
		Prefix:         "otel-offload",
		MinBytes:       4096,
		MaxObjectBytes: 64 * 1024 * 1024,
		MaxConcurrency: 8,
		CacheSize:      10000,
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatalf("offload.New: %v", err)
	}

	genOff := NewGenerator(GeneratorConfig{
		PayloadBytes: 16384,
	})
	tdOff := genOff.TracesBatch(28)
	ldOff := genOff.LogsBatch(28)

	offOpts := transform.Options{
		Limits:           transform.DefaultLimits(),
		PayloadOffloader: offloader,
	}
	offSpanRows, spanOffErrs := transform.SpanRows(tdOff, offOpts)
	if len(spanOffErrs) != 0 {
		t.Fatalf("transform.SpanRows(offOpts) errs: %v", spanOffErrs)
	}
	offSpanBytes := encodeSumBytes(spanEnc, offSpanRows)
	// v0alpha3 drops *_schema sidecars, schema_version, and the 6 outer
	// payload_refs wrapper fields, cutting offloaded span size to ~1,537.36 B/span.
	if math.Abs(float64(offSpanBytes)/28.0-1537.36) > 1.0 {
		t.Fatalf("offSpanBytes = %d (%.2f B/span), want ~1537.36 B/span", offSpanBytes, float64(offSpanBytes)/28.0)
	}

	offLogRows, logOffErrs := transform.LogRows(ldOff, offOpts)
	if len(logOffErrs) != 0 {
		t.Fatalf("transform.LogRows(offOpts) errs: %v", logOffErrs)
	}
	offLogBytes := encodeSumBytes(logEnc, offLogRows)
	if math.Abs(float64(offLogBytes)/28.0-1174.79) > 1.0 {
		t.Fatalf("offLogBytes = %d (%.2f B/log), want ~1174.79 B/log", offLogBytes, float64(offLogBytes)/28.0)
	}

	turnBytesOffload := int(math.Round((float64(offSpanBytes)*4 + float64(offLogBytes)*2 + float64(inlineMetricBytes)*2) / 28.0))
	if math.Abs(float64(turnBytesOffload)-10321.0) > 5.0 {
		t.Fatalf("turnBytesOffload = %d, want ~10321", turnBytesOffload)
	}

	keyPattern := regexp.MustCompile(`^otel-offload/(spans|logs)/\d{4}-\d{2}-\d{2}/[0-9a-f]{64}$`)
	bucketDir := filepath.Join(offloadRoot, "local-offload-bench")
	var objectCount int
	err = filepath.WalkDir(bucketDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		rel, relErr := filepath.Rel(bucketDir, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		if !keyPattern.MatchString(rel) {
			t.Fatalf("offloaded object key %q does not match %s (must not have .json suffix)", rel, keyPattern)
		}
		objectCount++
		return nil
	})
	if err != nil || objectCount == 0 {
		t.Fatalf("walking offloaded objects: count=%d err=%v", objectCount, err)
	}

	// 2. Verify docs/cost-estimation.md contains the exact verified figures and no stale pricing/sizes.
	costDocRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "cost-estimation.md"))
	if err != nil {
		t.Fatalf("ReadFile(docs/cost-estimation.md): %v", err)
	}
	costDoc := strings.ReplaceAll(string(costDocRaw), "\r\n", "\n")
	for _, wantSubstr := range []string{
		"1,537 B",
		"1,175 B",
		"10,321 B / turn",
		"`gs://<bucket>/<prefix>/<signal>/YYYY-MM-DD/<sha256>`",
		"`$0.010` / 1,000 ops",
		"$36.00",
		"$360.00",
		"$3,600.00",
		"$187.14",
		"$1,871.41",
		"$18,714.11",
		"$19.56",
		"$78.26",
		"$313.02",
		"$19.56 / mo",
		"$81.78 / mo",
		"$136.20 / mo",
		"$454.96 / mo",
		"$405.07 / mo",
		"$1,405.39 / mo",
		"$4,104.53 / mo",
		"1,408.49 B",
		"515.49 B",
		"~98.7%",
		"~97.4%",
		"~94.8%",
		"~95.0%",
		"~90.2%",
		"$7,080.63 / mo",
		"99.95%",
		"26.7%",
		"51.1%",
		"63.3%",
		"46.9%",
		"64.6%",
		"73.5%",
		"`10 MiB` per-query minimum",
		"0.137 TiB/mo",
	} {
		if !strings.Contains(costDoc, wantSubstr) {
			t.Errorf("docs/cost-estimation.md missing expected substring %q", wantSubstr)
		}
	}
	for _, forbiddenSubstr := range []string{
		"<sha256>.json",
		"| **GCS Standard Class A Ops (`PUT`)** | `$0.005` / 1,000 ops |",
		"$24 / vCPU-mo",
		"$58.60",
		"$234.40",
		"2,228 B",
		"1,717 B",
		"14,850 B",
		"2,402 B",
		"1,872 B",
		"15,855 B / turn",
		"$19.68 / mo",
		"$83.01 / mo",
		"$141.29 / mo",
		"$456.47 / mo",
		"$455.92 / mo",
		"$1,456.22 / mo",
		"$4,163.40 / mo",
		"$136.91 / mo",
		"$412.17 / mo",
		"$1,412.49 / mo",
		"$4,109.62 / mo",
		"~95.1%",
		"~90.7%",
		"$7,080.52",
		"99.96%",
	} {
		if strings.Contains(costDoc, forbiddenSubstr) {
			t.Errorf("docs/cost-estimation.md contains stale substring %q", forbiddenSubstr)
		}
	}

	// 3. Verify docs/benchmarks/v0.1.0-performance-envelope.md Section 5 JSON snippet
	// unmarshals cleanly into BenchmarkReport with DisallowUnknownFields() and matches Table 5.1.
	benchDocRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "benchmarks", "v0.1.0-performance-envelope.md"))
	if err != nil {
		t.Fatalf("ReadFile(docs/benchmarks/v0.1.0-performance-envelope.md): %v", err)
	}
	benchDoc := strings.ReplaceAll(string(benchDocRaw), "\r\n", "\n")
	for _, wantBenchSubstr := range []string{
		"Encoded-Row MiB/s",
		"**`14 of 18` Go packages with tests**",
		"+48.5%` to `+56.1%",
		"+47.0%` to `+48.3%",
		"+19.8%` to `+28.0%",
	} {
		if !strings.Contains(benchDoc, wantBenchSubstr) {
			t.Errorf("docs/benchmarks/v0.1.0-performance-envelope.md missing %q", wantBenchSubstr)
		}
	}

	jsonStart := strings.Index(benchDoc, "```json\n")
	if jsonStart < 0 {
		t.Fatal("missing ```json block in docs/benchmarks/v0.1.0-performance-envelope.md")
	}
	jsonBody := benchDoc[jsonStart+len("```json\n"):]
	jsonEnd := strings.Index(jsonBody, "\n```")
	if jsonEnd < 0 {
		t.Fatal("unterminated ```json block in docs/benchmarks/v0.1.0-performance-envelope.md")
	}
	jsonSnippet := jsonBody[:jsonEnd]

	dec := json.NewDecoder(strings.NewReader(jsonSnippet))
	dec.DisallowUnknownFields()
	var docReport BenchmarkReport
	if err := dec.Decode(&docReport); err != nil {
		t.Fatalf("BenchmarkReport JSON snippet in docs/benchmarks/v0.1.0-performance-envelope.md failed strict schema decode: %v", err)
	}
	if docReport.Timestamp != "2026-10-25T23:14:06Z" || !docReport.EphemeralDatasetDeleted || docReport.Config.Mode != ModeLive {
		t.Fatalf("unexpected docReport header fields: timestamp=%q deleted=%t mode=%q",
			docReport.Timestamp, docReport.EphemeralDatasetDeleted, docReport.Config.Mode)
	}
	if len(docReport.Results) != 3 {
		t.Fatalf("len(docReport.Results) = %d, want 3", len(docReport.Results))
	}
	wantRates := map[string]float64{
		"traces":  10404.2,
		"logs":    9593.6,
		"metrics": 9185.0,
	}
	for _, r := range docReport.Results {
		if r.AchievedRowsPerSec != wantRates[r.Signal] {
			t.Errorf("docReport signal %s AchievedRowsPerSec = %v, want %v", r.Signal, r.AchievedRowsPerSec, wantRates[r.Signal])
		}
		if r.Telemetry.AcknowledgedRows <= 0 || r.Latency.Samples <= 0 {
			t.Errorf("docReport signal %s has empty telemetry/latency: %+v", r.Signal, r)
		}
	}
}

func TestValidateRunConfigCollectorModeRespectsYAMLWriteLimits(t *testing.T) {
	collectorYAML := `
extensions:
  file_storage/test:
    directory: /var/lib/otelcol/orig
receivers:
  otlp: {}
exporters:
  bigquery:
    sending_queue:
      enabled: true
      storage: file_storage/test
    write:
      max_row_bytes: 262144
      backpressure:
        enabled: true
        min_request_bytes: 131072
service:
  extensions: [file_storage/test]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-write-limits.yaml")
	if err := os.WriteFile(cfgPath, []byte(collectorYAML), 0o600); err != nil {
		t.Fatalf("write collector YAML: %v", err)
	}

	validCfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		MaxRequestBytes: 524288, // 512 KiB < factory default 1 MiB, >= YAML max_row_bytes 256 KiB
	}
	if err := validateRunConfig(t.Context(), &validCfg, nil); err != nil {
		t.Fatalf("validateRunConfig(MaxRequestBytes=524288) unexpected error: %v", err)
	}
	if _, statErr := os.Stat("preflight"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("dry-run preflight should not create ./preflight directory on disk, stat err = %v", statErr)
	}

	invalidCfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: cfgPath,
		Signals:         []string{"logs"},
		MaxRequestBytes: 131072, // 128 KiB < YAML max_row_bytes 256 KiB
	}
	err := validateRunConfig(t.Context(), &invalidCfg, nil)
	if err == nil {
		t.Fatal("expected validateRunConfig(MaxRequestBytes=131072 < max_row_bytes=262144) to fail")
	}
	if !strings.Contains(err.Error(), "max_request_bytes") && !strings.Contains(err.Error(), "max_row_bytes") {
		t.Fatalf("expected error mentioning max_request_bytes/max_row_bytes, got %v", err)
	}
}

func TestFormatMarkdownCollectorLatencyNote(t *testing.T) {
	collectorRep := &BenchmarkReport{
		GoVersion:  "go1.26.0",
		GOOS:       "linux",
		GOARCH:     "amd64",
		NumCPU:     4,
		GOMAXPROCS: 4,
		Config: RunnerConfig{
			Mode:            ModeCollector,
			WorkloadProfile: WorkloadProfileAccessLogs,
		},
		Results: []SignalResult{
			{
				Signal:          "logs",
				StreamPoolSize:  4,
				IncompleteDrain: true,
				DrainWarning:    "timed out waiting for drain",
			},
		},
	}
	collectorMD := FormatMarkdown(collectorRep)
	const wantNote = "> **Collector Latency Note**: `p50`/`p95`/`p99` measure client-to-Collector OTLP gRPC export round-trip latency; Storage Write API append-ack latency is reported in `telemetry.append_result_wait_mean_ms`."
	noteIdx := strings.Index(collectorMD, wantNote)
	if noteIdx < 0 {
		t.Fatalf("FormatMarkdown(ModeCollector) missing Collector Latency Note:\n%s", collectorMD)
	}
	warnIdx := strings.Index(collectorMD, "Incomplete Drain Warning")
	if warnIdx < 0 || noteIdx > warnIdx {
		t.Fatalf("expected Collector Latency Note before Incomplete Drain Warning (noteIdx=%d, warnIdx=%d):\n%s", noteIdx, warnIdx, collectorMD)
	}

	fakeRep := &BenchmarkReport{
		GoVersion:  "go1.26.0",
		GOOS:       "linux",
		GOARCH:     "amd64",
		NumCPU:     4,
		GOMAXPROCS: 4,
		Config: RunnerConfig{
			Mode:            ModeBQFake,
			WorkloadProfile: WorkloadProfileGenAIMixed,
		},
		Results: []SignalResult{
			{
				Signal:         "traces",
				StreamPoolSize: 4,
			},
		},
	}
	fakeMD := FormatMarkdown(fakeRep)
	if strings.Contains(fakeMD, "Collector Latency Note") {
		t.Fatalf("FormatMarkdown(ModeBQFake) should omit Collector Latency Note:\n%s", fakeMD)
	}
}

func TestSubtractTelemetrySnapshotPreservesSub10msWaitPrecision(t *testing.T) {
	makeRM := func(count uint64, sumSec float64) metricdata.ResourceMetrics {
		return metricdata.ResourceMetrics{
			ScopeMetrics: []metricdata.ScopeMetrics{
				{
					Metrics: []metricdata.Metrics{
						{
							Name: "otelcol_exporter_bigquery_append_result_wait",
							Data: metricdata.Histogram[float64]{
								DataPoints: []metricdata.HistogramDataPoint[float64]{
									{Count: count, Sum: sumSec},
								},
							},
						},
					},
				},
			},
		}
	}

	// Both 0.0020s and 0.0044s round to 0.00 under round2; subtracting rounded
	// sums would yield 0ms instead of 1.2ms ((0.0024s * 1000) / 2).
	before := extractTelemetrySnapshot(makeRM(2, 0.0020))
	after := extractTelemetrySnapshot(makeRM(4, 0.0044))
	delta := subtractTelemetrySnapshot(after, before)
	if delta.AppendWaitCount != 2 {
		t.Fatalf("delta.AppendWaitCount = %d, want 2", delta.AppendWaitCount)
	}
	if delta.AppendWaitMeanMs != 1.2 {
		t.Fatalf("delta.AppendWaitMeanMs = %v, want 1.2", delta.AppendWaitMeanMs)
	}

	// 0.0042s rounds to 0.00 while 0.0086s rounds to 0.01; subtracting rounded
	// sums would yield 5.0ms instead of 2.2ms ((0.0044s * 1000) / 2).
	beforeCross := extractTelemetrySnapshot(makeRM(2, 0.0042))
	afterCross := extractTelemetrySnapshot(makeRM(4, 0.0086))
	deltaCross := subtractTelemetrySnapshot(afterCross, beforeCross)
	if deltaCross.AppendWaitMeanMs != 2.2 {
		t.Fatalf("deltaCross.AppendWaitMeanMs = %v, want 2.2", deltaCross.AppendWaitMeanMs)
	}
}

func TestRunModeBQFakeSimulateThrottleEveryNeverFiredFailsClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	unfiredCfg := RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"logs"},
		Duration:              150 * time.Millisecond,
		BatchSize:             10,
		Workers:               1,
		SimulateThrottleEvery: 5,
		maxBatches:            1,
	}
	unfiredRep, err := Run(ctx, unfiredCfg)
	if err == nil || !strings.Contains(err.Error(), "never fired on destination table") {
		t.Fatalf("Run(SimulateThrottleEvery=5, maxBatches=1) err = %v, want error containing 'never fired on destination table'", err)
	}
	if unfiredRep == nil || len(unfiredRep.Results) != 1 || unfiredRep.Results[0].Signal != "logs" ||
		unfiredRep.Results[0].RecordsSubmitted != 10 || unfiredRep.Results[0].DeliveredRows != 10 || unfiredRep.Results[0].Latency.Samples == 0 {
		t.Fatalf("expected populated measured SignalResult when SimulateThrottleEvery missed, got %+v", unfiredRep)
	}

	firedCfg := RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"logs"},
		Duration:              150 * time.Millisecond,
		BatchSize:             10,
		Workers:               1,
		SimulateThrottleEvery: 1,
		maxBatches:            1,
	}
	rep, err := Run(ctx, firedCfg)
	if err != nil {
		t.Fatalf("Run(SimulateThrottleEvery=1, maxBatches=1) unexpected error: %v", err)
	}
	if len(rep.Results) != 1 || rep.Results[0].Telemetry.Retries < 1 {
		t.Fatalf("expected >= 1 retry when SimulateThrottleEvery=1 fired, got %+v", rep.Results)
	}
}

func TestValidateCollectorPreflightConfigResolvesWriteEnvRefs(t *testing.T) {
	tmpDir := t.TempDir()
	writeCfg := func(name, writeBlock string) string {
		p := filepath.Join(tmpDir, name)
		content := fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery:
    write:
%s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, writeBlock)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}

	envMRBPath := writeCfg("env-mrb.yaml", `      max_row_bytes: "${env:TEST_PREFLIGHT_MAX_ROW_BYTES}"`)

	t.Run("valid_env_int", func(t *testing.T) {
		t.Setenv("TEST_PREFLIGHT_MAX_ROW_BYTES", "262144")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: envMRBPath,
			Signals:         []string{"logs"},
			MaxRequestBytes: 524288,
		}
		if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
			t.Fatalf("validateRunConfig(262144) unexpected error: %v", err)
		}
		cfgTooSmallReq := cfg
		cfgTooSmallReq.MaxRequestBytes = 131072
		if err := validateRunConfig(t.Context(), &cfgTooSmallReq, nil); err == nil {
			t.Fatal("expected validateRunConfig error when MaxRequestBytes (131072) < env max_row_bytes (262144)")
		}
	})

	for _, badVal := range []string{"0", "", "notanint"} {
		t.Run("bad_env_mrb_"+badVal, func(t *testing.T) {
			t.Setenv("TEST_PREFLIGHT_MAX_ROW_BYTES", badVal)
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    os.Args[0],
				CollectorConfig: envMRBPath,
				Signals:         []string{"logs"},
			}
			if err := validateRunConfig(t.Context(), &cfg, nil); err == nil {
				t.Fatalf("expected validateRunConfig error for TEST_PREFLIGHT_MAX_ROW_BYTES=%q", badVal)
			}
		})
	}

	t.Run("unset_env_mrb_with_default", func(t *testing.T) {
		defPath := writeCfg("def-mrb.yaml", `      max_row_bytes: "${env:TEST_UNSET_PREFLIGHT_MRB_XYZ:-262144}"`)
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: defPath,
			Signals:         []string{"logs"},
			MaxRequestBytes: 524288,
		}
		if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
			t.Fatalf("validateRunConfig(default 262144) unexpected error: %v", err)
		}
	})

	t.Run("file_ref_mrb_fails_closed", func(t *testing.T) {
		filePath := writeCfg("file-mrb.yaml", `      max_row_bytes: "${file:mrb}"`)
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: filePath,
			Signals:         []string{"logs"},
		}
		if err := validateRunConfig(t.Context(), &cfg, nil); err == nil {
			t.Fatal("expected validateRunConfig error for ${file:mrb}")
		}
	})

	t.Run("backpressure_enabled_env_unset_empty_and_yes", func(t *testing.T) {
		bpPath := writeCfg("env-bp.yaml", "      backpressure:\n        enabled: \"${env:TEST_PREFLIGHT_BP_ENABLED}\"")
		cfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    os.Args[0],
			CollectorConfig: bpPath,
			Signals:         []string{"logs"},
		}
		// Unset expands to empty YAML nil -> false (matches live otelcol-bq validate).
		if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
			t.Fatalf("validateRunConfig(unset BP enabled) unexpected error: %v", err)
		}
		t.Setenv("TEST_PREFLIGHT_BP_ENABLED", "")
		if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
			t.Fatalf("validateRunConfig(empty BP enabled) unexpected error: %v", err)
		}
		t.Setenv("TEST_PREFLIGHT_BP_ENABLED", "yes")
		if err := validateRunConfig(t.Context(), &cfg, nil); err == nil {
			t.Fatal("expected validateRunConfig error for TEST_PREFLIGHT_BP_ENABLED=yes")
		}
	})
}

func TestNormalizeDefaultCollectorLogsConfigAbsolutePath(t *testing.T) {
	absCfg, err := filepath.Abs(resolveCollectorConfigPath("example/otel-collector-high-volume-logs.yaml"))
	if err != nil {
		t.Fatalf("filepath.Abs: %v", err)
	}
	cfg := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: absCfg,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize() unexpected error: %v", err)
	}
	if cfg.WorkloadProfile != WorkloadProfileAccessLogs {
		t.Fatalf("WorkloadProfile = %q, want %q", cfg.WorkloadProfile, WorkloadProfileAccessLogs)
	}
	if !slices.Equal(cfg.Signals, []string{"logs"}) {
		t.Fatalf("Signals = %v, want [logs]", cfg.Signals)
	}
}

func TestRunBQFakeUpstreamInsertIDUniqueIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	cfg := RunnerConfig{
		Mode:             ModeBQFake,
		WorkloadProfile:  WorkloadProfileAccessLogs,
		UpstreamInsertID: true,
		Signals:          []string{"logs"},
		Workers:          2,
		BatchSize:        2,
		maxBatches:       10,
		Duration:         5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize: %v", err)
	}

	res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
	}
	if softErr != nil {
		t.Fatalf("runSingleSignalWithFake softErr = %v, want nil", softErr)
	}
	if res.RecordsSubmitted != 20 {
		t.Fatalf("RecordsSubmitted = %d, want 20", res.RecordsSubmitted)
	}
	if res.Telemetry.AcknowledgedRows != 20 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want 20", res.Telemetry.AcknowledgedRows)
	}

	rows := fakeSrv.Rows("otel_logs")
	if len(rows) != 20 {
		t.Fatalf("len(fakeSrv.Rows(otel_logs)) = %d, want 20", len(rows))
	}
	seenInsertIDs := make(map[string]struct{}, 20)
	seenTuples := make(map[string]struct{}, 20)
	for i, r := range rows {
		insertID, _ := r["insert_id"].(string)
		if !strings.HasPrefix(insertID, "edge-") {
			t.Fatalf("row[%d] insert_id = %q, want prefix \"edge-\"", i, insertID)
		}
		seenInsertIDs[insertID] = struct{}{}
		tuple := fmt.Sprintf("%v|%v|%s", r["log_name"], r["timestamp"], insertID)
		seenTuples[tuple] = struct{}{}
	}
	if len(seenInsertIDs) != 20 {
		t.Fatalf("distinct insert_id count = %d, want 20", len(seenInsertIDs))
	}
	if len(seenTuples) != 20 {
		t.Fatalf("distinct (log_name, timestamp, insert_id) tuple count = %d, want 20", len(seenTuples))
	}
}

func TestRunZeroAckedReportsZeroWireMBPerSec(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	fakeSrv.EnqueueFault(bqfake.Fault{
		Mode:  bqfake.FaultPermissionDenied,
		Table: "otel_logs",
	})

	cfg := RunnerConfig{
		Mode:                 ModeBQFake,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            4,
		maxBatches:           1,
		Duration:             300 * time.Millisecond,
		AllowPartialFailures: true,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("cfg.Normalize: %v", err)
	}

	res, _, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
	}
	if res.Telemetry.AppendBytesTotal <= 0 {
		t.Fatalf("Telemetry.AppendBytesTotal = %d, want > 0", res.Telemetry.AppendBytesTotal)
	}
	if res.Telemetry.AcknowledgedRows != 0 {
		t.Fatalf("Telemetry.AcknowledgedRows = %d, want 0", res.Telemetry.AcknowledgedRows)
	}
	if res.WireMBPerSec != 0 {
		t.Fatalf("WireMBPerSec = %v, want 0", res.WireMBPerSec)
	}
	if res.BytesPerRow != 0 {
		t.Fatalf("BytesPerRow = %v, want 0", res.BytesPerRow)
	}
}

func TestRunCollectorLiveRoutesParentRESTThroughAdminURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()

	var (
		postCalls   atomic.Int32
		deleteCalls atomic.Int32
		queryCalls  atomic.Int32
		dsMu        sync.Mutex
		datasets    = make(map[string]map[string]string)
	)

	storageSchema := &bigqueryapi.TableSchema{
		Fields: []*bigqueryapi.TableFieldSchema{
			{Name: "total_rows", Type: "INTEGER"},
			{Name: "total_logical_bytes", Type: "INTEGER"},
			{Name: "active_physical_bytes", Type: "INTEGER"},
			{Name: "long_term_physical_bytes", Type: "INTEGER"},
			{Name: "time_travel_physical_bytes", Type: "INTEGER"},
			{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
		},
	}
	storageRows := []*bigqueryapi.TableRow{
		{
			F: []*bigqueryapi.TableCell{
				{V: "4"},
				{V: "2048"},
				{V: "1024"},
				{V: "0"},
				{V: "256"},
				{V: "64"},
			},
		},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries"):
			queryCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			resp := bigqueryapi.QueryResponse{
				JobReference: &bigqueryapi.JobReference{ProjectId: "test-proj", JobId: "j1", Location: "US"},
				JobComplete:  true,
				TotalRows:    1,
				Schema:       storageSchema,
				Rows:         storageRows,
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
			queryCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			resp := bigqueryapi.Job{
				JobReference: &bigqueryapi.JobReference{ProjectId: "test-proj", JobId: "j1", Location: "US"},
				Status:       &bigqueryapi.JobStatus{State: "DONE"},
				Configuration: &bigqueryapi.JobConfiguration{
					Query: &bigqueryapi.JobConfigurationQuery{Query: "SELECT 1"},
				},
				Statistics: &bigqueryapi.JobStatistics{
					Query: &bigqueryapi.JobStatistics2{},
				},
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/queries/"):
			w.Header().Set("Content-Type", "application/json")
			resp := bigqueryapi.GetQueryResultsResponse{
				JobComplete: true,
				TotalRows:   1,
				Schema:      storageSchema,
				Rows:        storageRows,
			}
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/"):
			parts := strings.Split(r.URL.Path, "/datasets/")
			if len(parts) == 2 && parts[1] != "" && !strings.Contains(parts[1], "/") {
				dsID := parts[1]
				dsMu.Lock()
				stored, ok := datasets[dsID]
				var labelsCopy map[string]string
				if ok {
					labelsCopy = make(map[string]string, len(stored))
					for k, v := range stored {
						labelsCopy[k] = v
					}
				}
				dsMu.Unlock()
				if ok {
					w.Header().Set("Content-Type", "application/json")
					resp := map[string]any{
						"datasetReference": map[string]string{
							"projectId": "test-proj",
							"datasetId": dsID,
						},
						"labels": labelsCopy,
					}
					_ = json.NewEncoder(w).Encode(resp)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Not found"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
			var body struct {
				DatasetReference struct {
					DatasetID string `json:"datasetId"`
				} `json:"datasetReference"`
				Labels map[string]string `json:"labels"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			dsID := body.DatasetReference.DatasetID
			copied := make(map[string]string, len(body.Labels))
			for k, v := range body.Labels {
				copied[k] = v
			}
			dsMu.Lock()
			datasets[dsID] = copied
			dsMu.Unlock()
			postCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"datasetReference": map[string]string{
					"projectId": "test-proj",
					"datasetId": dsID,
				},
			})
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
			if r.URL.Query().Get("deleteContents") != "true" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			parts := strings.Split(r.URL.Path, "/datasets/")
			if len(parts) == 2 {
				dsMu.Lock()
				delete(datasets, parts[1])
				dsMu.Unlock()
			}
			deleteCalls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
		}
	}))
	defer srv.Close()

	collectorYAML := fmt.Sprintf(`extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: test-proj
    dataset: orig_ds
    location: US
    endpoint:
      url: %s
      admin_url: %s
      insecure: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, fakeSrv.Addr(), srv.URL)

	cfgPath := filepath.Join(t.TempDir(), "collector-live-admin.yaml")
	if err := os.WriteFile(cfgPath, []byte(collectorYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		EphemeralDataset:   true,
		ProjectID:          "test-proj",
		Location:           "US",
		Signals:            []string{"logs"},
		CollectorBin:       configureCollectorHelperEnv(t, "default"),
		CollectorConfig:    cfgPath,
		Workers:            1,
		BatchSize:          4,
		maxBatches:         1,
		Duration:           200 * time.Millisecond,
		WarmupDuration:     0,
		ClientOptions: []option.ClientOption{
			option.WithoutAuthentication(),
		},
	}

	rep, runErr := Run(ctx, cfg)
	if runErr != nil {
		t.Fatalf("Run() unexpected error: %v", runErr)
	}
	if got := postCalls.Load(); got != 1 {
		t.Fatalf("dataset POST calls = %d, want 1", got)
	}
	if got := deleteCalls.Load(); got != 1 {
		t.Fatalf("dataset DELETE calls = %d, want 1", got)
	}
	if got := queryCalls.Load(); got < 1 {
		t.Fatalf("query calls = %d, want >= 1", got)
	}
	if rep == nil || !rep.EphemeralDatasetDeleted {
		t.Fatalf("rep.EphemeralDatasetDeleted = %v (rep=%v), want true", rep != nil && rep.EphemeralDatasetDeleted, rep)
	}
	if len(rep.Results) != 1 || rep.Results[0].ByteLayers == nil || rep.Results[0].ByteLayers.BQTotalRows != 4 {
		t.Fatalf("unexpected Results/ByteLayers: %+v", rep.Results)
	}
}

func TestRunBQFakeLostAckDetectsReplayAndDoesNotDoubleBytes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	paceHook := func(_, seq int) {
		if seq == 1 {
			time.Sleep(200 * time.Millisecond)
		}
	}

	cleanFake, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New clean: %v", err)
	}
	defer func() { _ = cleanFake.Close() }()

	cfgClean := RunnerConfig{
		Mode:             ModeBQFake,
		Signals:          []string{"logs"},
		Workers:          1,
		BatchSize:        2,
		PayloadBytes:     32768,
		maxBatches:       1,
		Duration:         5 * time.Second,
		WarmupDuration:   0,
		UpstreamInsertID: false,
		workerHook:       paceHook,
	}
	if err := cfgClean.Normalize(); err != nil {
		t.Fatalf("cfgClean.Normalize: %v", err)
	}

	resClean, softCleanErr, hardCleanErr := runSingleSignalWithFake(ctx, cfgClean, "logs", cleanFake)
	if hardCleanErr != nil {
		t.Fatalf("clean runSingleSignalWithFake hard error: %v", hardCleanErr)
	}
	if softCleanErr != nil {
		t.Fatalf("clean runSingleSignalWithFake soft error: %v", softCleanErr)
	}
	if resClean.RecordsSubmitted != 2 || resClean.DeliveredRows != 2 || resClean.Telemetry.ReplayedRows != 0 {
		t.Fatalf("clean run counts = (submitted=%d, delivered=%d, replayed=%d), want (2, 2, 0)",
			resClean.RecordsSubmitted, resClean.DeliveredRows, resClean.Telemetry.ReplayedRows)
	}
	cleanBytesPerRow := resClean.BytesPerRow
	if cleanBytesPerRow <= 0 {
		t.Fatalf("cleanBytesPerRow = %v, want > 0", cleanBytesPerRow)
	}

	fakeSrv, err := bqfake.New()
	if err != nil {
		t.Fatalf("bqfake.New fault: %v", err)
	}
	defer func() { _ = fakeSrv.Close() }()
	fakeSrv.EnqueueFault(bqfake.Fault{
		Mode:  bqfake.FaultCommitThenStreamClosed,
		Table: "otel_logs",
	})

	cfgStrict := RunnerConfig{
		Mode:                 ModeBQFake,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            2,
		PayloadBytes:         32768,
		maxBatches:           1,
		Duration:             5 * time.Second,
		WarmupDuration:       0,
		UpstreamInsertID:     false,
		AllowPartialFailures: false,
		workerHook:           paceHook,
	}
	if err := cfgStrict.Normalize(); err != nil {
		t.Fatalf("cfgStrict.Normalize: %v", err)
	}

	res, softErr, hardErr := runSingleSignalWithFake(ctx, cfgStrict, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("fault runSingleSignalWithFake hard error: %v", hardErr)
	}
	if got := fakeSrv.AckedRowsForTable("otel_logs"); got != 4 {
		t.Fatalf("fakeSrv.AckedRowsForTable(otel_logs) = %d, want 4", got)
	}
	if res.RecordsSubmitted != 2 || res.Telemetry.AcknowledgedRows != 2 || res.DeliveredRows != 2 || res.Telemetry.ReplayedRows != 2 {
		t.Fatalf("fault run counts = (submitted=%d, acked=%d, delivered=%d, replayed=%d), want (2, 2, 2, 2)",
			res.RecordsSubmitted, res.Telemetry.AcknowledgedRows, res.DeliveredRows, res.Telemetry.ReplayedRows)
	}

	ackedBytes := fakeSrv.AckedBytesForTable("otel_logs")
	bytesPerRowExact := float64(ackedBytes) / 4.0
	if res.BytesPerRow != cleanBytesPerRow {
		t.Fatalf("res.BytesPerRow = %v, want clean single-attempt %v (not doubled %v)",
			res.BytesPerRow, cleanBytesPerRow, round2(2*cleanBytesPerRow))
	}
	if wantBPR := round2(bytesPerRowExact); res.BytesPerRow != wantBPR {
		t.Fatalf("res.BytesPerRow = %v, want round2(ackedBytes/4) = %v (ackedBytes=%d)",
			res.BytesPerRow, wantBPR, ackedBytes)
	}

	if res.ElapsedSeconds <= 0 {
		t.Fatalf("res.ElapsedSeconds = %v, want > 0", res.ElapsedSeconds)
	}
	wantWire := round2((bytesPerRowExact * 2.0) / (1024.0 * 1024.0) / res.ElapsedSeconds)
	inflatedWire := round2((bytesPerRowExact * 4.0) / (1024.0 * 1024.0) / res.ElapsedSeconds)
	if math.Abs(res.WireMBPerSec-wantWire) > 0.02 {
		t.Fatalf("res.WireMBPerSec = %v, want %v (+/-0.02) for 2 delivered rows (4-row inflated=%v)",
			res.WireMBPerSec, wantWire, inflatedWire)
	}
	if res.WireMBPerSec >= inflatedWire || math.Abs(res.WireMBPerSec-inflatedWire) <= 0.05 {
		t.Fatalf("res.WireMBPerSec = %v is indistinguishable from 4-row inflated rate %v",
			res.WireMBPerSec, inflatedWire)
	}
	cleanDeliveredMB := resClean.WireMBPerSec * resClean.ElapsedSeconds
	faultDeliveredMB := res.WireMBPerSec * res.ElapsedSeconds
	if math.Abs(faultDeliveredMB-cleanDeliveredMB) > 0.02 {
		t.Fatalf("delivered wire volume = %v MiB, want proportional match with clean 2-row run %v MiB (4-row inflated=%v MiB)",
			faultDeliveredMB, cleanDeliveredMB, 2*cleanDeliveredMB)
	}

	strictErr := checkSignalResultLossless(cfgStrict, "logs", res, softErr)
	if strictErr == nil {
		t.Fatal("checkSignalResultLossless(strict) = nil, want non-nil replay failure")
	}
	if !strings.Contains(strictErr.Error(), "replayed_rows=2") && !strings.Contains(strictErr.Error(), "replayed=2") && !strings.Contains(strictErr.Error(), "replay") {
		t.Fatalf("checkSignalResultLossless(strict) error = %q, want mention of replay", strictErr.Error())
	}

	cfgPartial := cfgStrict
	cfgPartial.AllowPartialFailures = true
	if partialErr := checkSignalResultLossless(cfgPartial, "logs", res, softErr); partialErr != nil {
		t.Fatalf("checkSignalResultLossless(AllowPartialFailures=true) = %v, want nil when DeliveredRows == RecordsSubmitted", partialErr)
	}
}

func TestRunCollectorMultiSignalCredentialsConsistency(t *testing.T) {
	dir := t.TempDir()
	credsFileA := filepath.Join(dir, "creds-a.json")
	credsFileB := filepath.Join(dir, "creds-b.json")
	if err := os.WriteFile(credsFileA, []byte(`{"type":"service_account"}`), 0o600); err != nil {
		t.Fatalf("write credsFileA: %v", err)
	}
	if err := os.WriteFile(credsFileB, []byte(`{"type":"service_account"}`), 0o600); err != nil {
		t.Fatalf("write credsFileB: %v", err)
	}

	mismatchYAML := fmt.Sprintf(`extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: %q
      quota_project: proj-alpha
  bigquery/traces:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: %q
      quota_project: proj-alpha
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, credsFileA, credsFileB)

	mismatchPath := filepath.Join(dir, "collector-creds-mismatch.yaml")
	if err := os.WriteFile(mismatchPath, []byte(mismatchYAML), 0o600); err != nil {
		t.Fatalf("write mismatch YAML: %v", err)
	}

	cfgMismatch := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		ProjectID:          "test-proj",
		DatasetID:          "bench_ds",
		Location:           "US",
		CollectorBin:       os.Args[0],
		CollectorConfig:    mismatchPath,
		Signals:            []string{"logs", "traces"},
	}
	if err := cfgMismatch.Normalize(); err != nil {
		t.Fatalf("cfgMismatch.Normalize: %v", err)
	}
	err := validateRunConfig(t.Context(), &cfgMismatch, nil)
	if err == nil {
		t.Fatal("validateRunConfig(cfgMismatch) = nil, want cross-signal credentials mismatch error")
	}
	if !strings.Contains(err.Error(), "credentials") || !strings.Contains(err.Error(), "across signals") {
		t.Fatalf("validateRunConfig(cfgMismatch) error = %q, want cross-signal credentials error", err.Error())
	}

	quotaMismatchYAML := fmt.Sprintf(`extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: %q
      quota_project: proj-alpha
  bigquery/traces:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: %q
      quota_project: proj-bravo
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, credsFileA, credsFileA)

	quotaMismatchPath := filepath.Join(dir, "collector-quota-mismatch.yaml")
	if err := os.WriteFile(quotaMismatchPath, []byte(quotaMismatchYAML), 0o600); err != nil {
		t.Fatalf("write quota mismatch YAML: %v", err)
	}
	cfgQuotaMismatch := cfgMismatch
	cfgQuotaMismatch.CollectorConfig = quotaMismatchPath
	if qErr := validateRunConfig(t.Context(), &cfgQuotaMismatch, nil); qErr == nil || !strings.Contains(qErr.Error(), "credentials") || !strings.Contains(qErr.Error(), "across signals") {
		t.Fatalf("validateRunConfig(cfgQuotaMismatch) error = %v, want cross-signal credentials error", qErr)
	}

	t.Setenv("TEST_COLLECTOR_CREDS_FILE", credsFileA)
	t.Setenv("TEST_COLLECTOR_QUOTA_PROJ", "proj-alpha")

	sameYAML := fmt.Sprintf(`extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: ${env:TEST_COLLECTOR_CREDS_FILE}
      quota_project: ${env:TEST_COLLECTOR_QUOTA_PROJ}
  bigquery/traces:
    project: test-proj
    dataset: bench_ds
    location: US
    credentials:
      file: %q
      quota_project: proj-alpha
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, credsFileA)

	samePath := filepath.Join(dir, "collector-creds-same.yaml")
	if err := os.WriteFile(samePath, []byte(sameYAML), 0o600); err != nil {
		t.Fatalf("write same YAML: %v", err)
	}

	cfgSame := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		ProjectID:          "test-proj",
		DatasetID:          "bench_ds",
		Location:           "US",
		CollectorBin:       os.Args[0],
		CollectorConfig:    samePath,
		Signals:            []string{"logs", "traces"},
	}
	if err := cfgSame.Normalize(); err != nil {
		t.Fatalf("cfgSame.Normalize: %v", err)
	}
	if err := validateRunConfig(t.Context(), &cfgSame, nil); err != nil {
		t.Fatalf("validateRunConfig(cfgSame) unexpected error: %v", err)
	}
}

func TestRunCollectorLiveForwardsCredentialsAndQuotaProjectToParentREST(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: pkcs8DER,
	})

	const wantSAEmail = "testbench-sa@test-proj.iam.gserviceaccount.com"
	const wantQuotaProject = "billing-proj-123"

	saJSONBytes, err := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     "test-proj",
		"private_key_id": "test-key-1",
		"private_key":    string(pemBytes),
		"client_email":   wantSAEmail,
		"token_uri":      "https://127.0.0.1:1/never-called",
	})
	if err != nil {
		t.Fatalf("json.Marshal service_account: %v", err)
	}

	saFilePath := filepath.Join(t.TempDir(), "service-account.json")
	if err := os.WriteFile(saFilePath, saJSONBytes, 0o600); err != nil {
		t.Fatalf("write service-account.json: %v", err)
	}
	t.Setenv("TEST_LIVE_SA_JSON", string(saJSONBytes))

	cases := []struct {
		name            string
		credentialsYAML string
	}{
		{
			name: "credentials_json_env",
			credentialsYAML: fmt.Sprintf("    credentials:\n      json: ${env:TEST_LIVE_SA_JSON}\n      quota_project: %s",
				wantQuotaProject),
		},
		{
			name: "credentials_file",
			credentialsYAML: fmt.Sprintf("    credentials:\n      file: %q\n      quota_project: %s",
				saFilePath, wantQuotaProject),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()

			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()

			type observedHeader struct {
				method      string
				path        string
				auth        string
				userProject string
			}

			var (
				postCalls   atomic.Int32
				deleteCalls atomic.Int32
				queryCalls  atomic.Int32
				hdrMu       sync.Mutex
				observed    []observedHeader
				dsMu        sync.Mutex
				datasets    = make(map[string]map[string]string)
			)

			storageSchema := &bigqueryapi.TableSchema{
				Fields: []*bigqueryapi.TableFieldSchema{
					{Name: "total_rows", Type: "INTEGER"},
					{Name: "total_logical_bytes", Type: "INTEGER"},
					{Name: "active_physical_bytes", Type: "INTEGER"},
					{Name: "long_term_physical_bytes", Type: "INTEGER"},
					{Name: "time_travel_physical_bytes", Type: "INTEGER"},
					{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
				},
			}
			storageRows := []*bigqueryapi.TableRow{
				{
					F: []*bigqueryapi.TableCell{
						{V: "4"},
						{V: "2048"},
						{V: "1024"},
						{V: "0"},
						{V: "256"},
						{V: "64"},
					},
				},
			}

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hdrMu.Lock()
				observed = append(observed, observedHeader{
					method:      r.Method,
					path:        r.URL.Path,
					auth:        r.Header.Get("Authorization"),
					userProject: r.Header.Get("X-Goog-User-Project"),
				})
				hdrMu.Unlock()

				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/queries"):
					queryCalls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					resp := bigqueryapi.QueryResponse{
						JobReference: &bigqueryapi.JobReference{ProjectId: "test-proj", JobId: "j1", Location: "US"},
						JobComplete:  true,
						TotalRows:    1,
						Schema:       storageSchema,
						Rows:         storageRows,
					}
					_ = json.NewEncoder(w).Encode(resp)
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/jobs"):
					queryCalls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					resp := bigqueryapi.Job{
						JobReference: &bigqueryapi.JobReference{ProjectId: "test-proj", JobId: "j1", Location: "US"},
						Status:       &bigqueryapi.JobStatus{State: "DONE"},
					}
					_ = json.NewEncoder(w).Encode(resp)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/queries/"):
					w.Header().Set("Content-Type", "application/json")
					resp := bigqueryapi.GetQueryResultsResponse{
						JobReference: &bigqueryapi.JobReference{ProjectId: "test-proj", JobId: "j1", Location: "US"},
						JobComplete:  true,
						TotalRows:    1,
						Schema:       storageSchema,
						Rows:         storageRows,
					}
					_ = json.NewEncoder(w).Encode(resp)
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/"):
					parts := strings.Split(r.URL.Path, "/datasets/")
					if len(parts) == 2 && parts[1] != "" && !strings.Contains(parts[1], "/") {
						dsID := parts[1]
						dsMu.Lock()
						stored, ok := datasets[dsID]
						var labelsCopy map[string]string
						if ok {
							labelsCopy = make(map[string]string, len(stored))
							for k, v := range stored {
								labelsCopy[k] = v
							}
						}
						dsMu.Unlock()
						if ok {
							w.Header().Set("Content-Type", "application/json")
							resp := map[string]any{
								"datasetReference": map[string]string{
									"projectId": "test-proj",
									"datasetId": dsID,
								},
								"labels": labelsCopy,
							}
							_ = json.NewEncoder(w).Encode(resp)
							return
						}
					}
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Not found"}}`))
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
					var body struct {
						DatasetReference struct {
							DatasetID string `json:"datasetId"`
						} `json:"datasetReference"`
						Labels map[string]string `json:"labels"`
					}
					_ = json.NewDecoder(r.Body).Decode(&body)
					dsID := body.DatasetReference.DatasetID
					copied := make(map[string]string, len(body.Labels))
					for k, v := range body.Labels {
						copied[k] = v
					}
					dsMu.Lock()
					datasets[dsID] = copied
					dsMu.Unlock()
					postCalls.Add(1)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"datasetReference": map[string]string{
							"projectId": "test-proj",
							"datasetId": dsID,
						},
						"labels": copied,
					})
				case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
					if r.URL.Query().Get("deleteContents") != "true" {
						http.Error(w, "missing deleteContents=true", http.StatusBadRequest)
						return
					}
					parts := strings.Split(r.URL.Path, "/datasets/")
					if len(parts) == 2 {
						dsMu.Lock()
						delete(datasets, parts[1])
						dsMu.Unlock()
					}
					deleteCalls.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					http.Error(w, "unexpected request: "+r.Method+" "+r.URL.Path, http.StatusNotFound)
				}
			}))
			defer srv.Close()

			collectorYAML := fmt.Sprintf(`extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: test-proj
    dataset: orig_ds
    location: US
%s
    endpoint:
      url: %s
      admin_url: %s
      insecure: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, tc.credentialsYAML, fakeSrv.Addr(), srv.URL)

			cfgPath := filepath.Join(t.TempDir(), "collector-live-creds.yaml")
			if err := os.WriteFile(cfgPath, []byte(collectorYAML), 0o600); err != nil {
				t.Fatalf("write collector config: %v", err)
			}

			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				EphemeralDataset:   true,
				ProjectID:          "test-proj",
				Location:           "US",
				Signals:            []string{"logs"},
				CollectorBin:       configureCollectorHelperEnv(t, "default"),
				CollectorConfig:    cfgPath,
				Workers:            1,
				BatchSize:          4,
				maxBatches:         1,
				Duration:           200 * time.Millisecond,
				WarmupDuration:     0,
				ClientOptions:      nil,
			}

			rep, runErr := Run(ctx, cfg)
			if runErr != nil {
				t.Fatalf("Run() unexpected error: %v", runErr)
			}
			if got := postCalls.Load(); got != 1 {
				t.Fatalf("dataset POST calls = %d, want 1", got)
			}
			if got := queryCalls.Load(); got < 1 {
				t.Fatalf("query calls = %d, want >= 1", got)
			}
			if got := deleteCalls.Load(); got != 1 {
				t.Fatalf("dataset DELETE calls = %d, want 1", got)
			}
			if rep == nil || !rep.EphemeralDatasetDeleted {
				t.Fatalf("rep.EphemeralDatasetDeleted = %v (rep=%v), want true", rep != nil && rep.EphemeralDatasetDeleted, rep)
			}
			if len(rep.Results) != 1 || rep.Results[0].ByteLayers == nil || rep.Results[0].ByteLayers.BQTotalRows != 4 {
				t.Fatalf("unexpected Results/ByteLayers: %+v", rep.Results)
			}

			hdrMu.Lock()
			calls := slices.Clone(observed)
			hdrMu.Unlock()

			if len(calls) < 4 {
				t.Fatalf("observed %d REST calls, want >= 4 (GET existence + POST dataset + POST query + DELETE dataset)", len(calls))
			}
			for idx, c := range calls {
				if c.userProject != wantQuotaProject {
					t.Fatalf("call[%d] (%s %s) X-Goog-User-Project = %q, want %q",
						idx, c.method, c.path, c.userProject, wantQuotaProject)
				}
				if !strings.HasPrefix(c.auth, "Bearer ") {
					t.Fatalf("call[%d] (%s %s) Authorization = %q, want Bearer JWT",
						idx, c.method, c.path, c.auth)
				}
				jwtToken := strings.TrimPrefix(c.auth, "Bearer ")
				segParts := strings.Split(jwtToken, ".")
				if len(segParts) != 3 {
					t.Fatalf("call[%d] (%s %s) Bearer token has %d segments, want 3-part JWT",
						idx, c.method, c.path, len(segParts))
				}
				payloadBytes, decErr := base64.RawURLEncoding.DecodeString(segParts[1])
				if decErr != nil {
					t.Fatalf("call[%d] (%s %s) decode JWT payload: %v",
						idx, c.method, c.path, decErr)
				}
				var claims map[string]any
				if err := json.Unmarshal(payloadBytes, &claims); err != nil {
					t.Fatalf("call[%d] (%s %s) unmarshal JWT claims: %v",
						idx, c.method, c.path, err)
				}
				if gotIss, _ := claims["iss"].(string); gotIss != wantSAEmail {
					t.Fatalf("call[%d] (%s %s) JWT iss = %q, want %q",
						idx, c.method, c.path, gotIss, wantSAEmail)
				}
			}
		})
	}
}

func TestRunStrictDrainTimeoutEmitsCutoffSignalResult(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	origMinDrain := collectorMinDrainTimeout
	collectorMinDrainTimeout = 200 * time.Millisecond
	t.Cleanup(func() {
		collectorMinDrainTimeout = origMinDrain
	})

	collectorYAML := `extensions:
  health_check:
    endpoint: 127.0.0.1:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 127.0.0.1:4317
exporters:
  bigquery:
    project: bench-project
    dataset: bench_dataset
    location: US
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
	cfgPath := filepath.Join(t.TempDir(), "collector-drain-stall.yaml")
	if err := os.WriteFile(cfgPath, []byte(collectorYAML), 0o600); err != nil {
		t.Fatalf("write collector config: %v", err)
	}

	bin := configureCollectorHelperEnv(t, "drain_stall")
	cfgStrict := RunnerConfig{
		Mode:                 ModeCollector,
		CollectorBin:         bin,
		CollectorConfig:      cfgPath,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            10,
		Duration:             150 * time.Millisecond,
		CallTimeout:          200 * time.Millisecond,
		AllowPartialFailures: false,
		maxBatches:           1,
	}
	if err := cfgStrict.Normalize(); err != nil {
		t.Fatalf("cfgStrict.Normalize: %v", err)
	}

	report, runErr := Run(ctx, cfgStrict)
	if runErr == nil || !strings.Contains(runErr.Error(), "timed out") {
		t.Fatalf("Run(cfgStrict) error = %v, want drain timeout error", runErr)
	}
	if report == nil || len(report.Results) != 1 {
		t.Fatalf("report = %+v, want non-nil report with 1 cutoff SignalResult", report)
	}

	res := report.Results[0]
	if res.Signal != "logs" {
		t.Fatalf("res.Signal = %q, want %q", res.Signal, "logs")
	}
	if !res.IncompleteDrain {
		t.Fatal("res.IncompleteDrain = false, want true")
	}
	if res.DrainWarning == "" || !strings.Contains(res.DrainWarning, "timed out") {
		t.Fatalf("res.DrainWarning = %q, want non-empty drain timeout warning", res.DrainWarning)
	}
	if res.BatchesFailed < 1 {
		t.Fatalf("res.BatchesFailed = %d, want >= 1", res.BatchesFailed)
	}
	if res.Telemetry.AcknowledgedRows != 5 || res.DeliveredRows != 5 {
		t.Fatalf("cutoff delivery = (acked=%d, delivered=%d), want (5, 5)",
			res.Telemetry.AcknowledgedRows, res.DeliveredRows)
	}

	losslessErr := checkSignalResultLossless(cfgStrict, "logs", res, nil)
	if losslessErr == nil || !strings.Contains(losslessErr.Error(), "failed lossless delivery check") {
		t.Fatalf("checkSignalResultLossless(cfgStrict) = %v, want strict lossless failure on incomplete drain/shortfall", losslessErr)
	}
}

func TestRunBQFakeDefaultWorkloadDistinctSignalIdentities(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	runDefaultSignal := func(t *testing.T, signal, table string) []map[string]any {
		t.Helper()
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New(%s): %v", signal, err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:             ModeBQFake,
			Signals:          []string{signal},
			UniquePayloads:   false,
			UpstreamInsertID: false,
			Workers:          2,
			BatchSize:        2,
			maxBatches:       12,
			Duration:         10 * time.Second,
			WarmupDuration:   0,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("cfg.Normalize(%s): %v", signal, err)
		}

		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, signal, fakeSrv)
		if hardErr != nil {
			t.Fatalf("runSingleSignalWithFake(%s) hard error: %v", signal, hardErr)
		}
		if softErr != nil {
			t.Fatalf("runSingleSignalWithFake(%s) soft error: %v", signal, softErr)
		}
		if res.RecordsSubmitted != 24 || res.DeliveredRows != 24 {
			t.Fatalf("signal %s counts = (submitted=%d, delivered=%d), want (24, 24)",
				signal, res.RecordsSubmitted, res.DeliveredRows)
		}

		rows := fakeSrv.Rows(table)
		if len(rows) != 24 {
			t.Fatalf("len(fakeSrv.Rows(%q)) = %d, want 24", table, len(rows))
		}
		return rows
	}

	t.Run("logs", func(t *testing.T) {
		rows := runDefaultSignal(t, "logs", "otel_logs")
		seenNanos := make(map[any]struct{}, len(rows))
		seenComposite := make(map[string]struct{}, len(rows))
		seenInsertIDs := make(map[string]struct{}, len(rows))
		nonEmptyInsertIDs := 0

		for idx, r := range rows {
			nano := r["time_unix_nano"]
			if nano == nil || nano == int64(0) {
				t.Fatalf("row[%d] time_unix_nano = %v, want non-zero", idx, nano)
			}
			seenNanos[nano] = struct{}{}
			key := fmt.Sprintf("%v|%v|%v", r["log_name"], r["timestamp"], r["time_unix_nano"])
			seenComposite[key] = struct{}{}
			if id, ok := r["insert_id"].(string); ok && id != "" {
				nonEmptyInsertIDs++
				seenInsertIDs[id] = struct{}{}
			}
		}

		if len(seenNanos) != 24 {
			t.Fatalf("distinct logs time_unix_nano = %d, want 24", len(seenNanos))
		}
		if len(seenComposite) != 24 {
			t.Fatalf("distinct logs (log_name|timestamp|time_unix_nano) keys = %d, want 24", len(seenComposite))
		}
		if nonEmptyInsertIDs > 0 && len(seenInsertIDs) != nonEmptyInsertIDs {
			t.Fatalf("distinct non-empty logs insert_id = %d, want %d", len(seenInsertIDs), nonEmptyInsertIDs)
		}
	})

	t.Run("traces", func(t *testing.T) {
		rows := runDefaultSignal(t, "traces", "otel_spans")
		seenSpanIDs := make(map[string]struct{}, len(rows))
		seenStartNanos := make(map[any]struct{}, len(rows))

		for idx, r := range rows {
			spanID, _ := r["span_id"].(string)
			if spanID == "" {
				t.Fatalf("row[%d] span_id is empty", idx)
			}
			seenSpanIDs[spanID] = struct{}{}

			startNano := r["start_time_unix_nano"]
			if startNano == nil || startNano == int64(0) {
				t.Fatalf("row[%d] start_time_unix_nano = %v, want non-zero", idx, startNano)
			}
			seenStartNanos[startNano] = struct{}{}
		}

		if len(seenSpanIDs) != 24 {
			t.Fatalf("distinct span_ids = %d, want 24", len(seenSpanIDs))
		}
		if len(seenStartNanos) != 24 {
			t.Fatalf("distinct start_time_unix_nanos = %d, want 24", len(seenStartNanos))
		}
	})

	t.Run("metrics", func(t *testing.T) {
		rows := runDefaultSignal(t, "metrics", "otel_metrics")
		seenNanos := make(map[any]struct{}, len(rows))
		seenMetricTimeKeys := make(map[string]struct{}, len(rows))

		for idx, r := range rows {
			nano := r["time_unix_nano"]
			if nano == nil || nano == int64(0) {
				t.Fatalf("row[%d] time_unix_nano = %v, want non-zero", idx, nano)
			}
			seenNanos[nano] = struct{}{}
			key := fmt.Sprintf("%v|%v", r["metric_name"], r["time_unix_nano"])
			seenMetricTimeKeys[key] = struct{}{}
		}

		if len(seenNanos) != 24 {
			t.Fatalf("distinct metrics time_unix_nano = %d, want 24", len(seenNanos))
		}
		if len(seenMetricTimeKeys) != 24 {
			t.Fatalf("distinct metrics (metric_name|time_unix_nano) keys = %d, want 24", len(seenMetricTimeKeys))
		}
	})
}

func TestRunInProcessPrebuiltMemoryBoundedAndPreallocatedBeforeBaseline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	// Compare Workers=1 vs Workers=16 dispatching the exact same maxBatches=16
	// (200 records x 4 KiB payload, ~900 KiB per batch).
	// If each worker cloned an 8-batch ring inside runWorkers (after memBefore),
	// Workers=16 would allocate 120 extra batch clones (~108 MiB) over Workers=1
	// inside TotalAllocDeltaMB. Pre-allocating slots before memBefore keeps the
	// steady-state allocation delta independent of worker template cloning.
	runWithWorkers := func(workers int) SignalResult {
		t.Helper()
		cfg := RunnerConfig{
			Mode:           ModeBQFake,
			Signals:        []string{"logs"},
			UniquePayloads: false,
			Workers:        workers,
			BatchSize:      200,
			PayloadBytes:   4096,
			maxBatches:     16,
			WarmupDuration: 50 * time.Millisecond,
			Duration:       10 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("cfg.Normalize(workers=%d): %v", workers, err)
		}
		res, softErr, hardErr := runSingleSignal(ctx, cfg, "logs")
		if hardErr != nil || softErr != nil {
			t.Fatalf("runSingleSignal(workers=%d) hardErr=%v softErr=%v", workers, hardErr, softErr)
		}
		if res.RecordsSubmitted != 3200 || res.DeliveredRows != 3200 {
			t.Fatalf("workers=%d counts = (submitted=%d, delivered=%d), want (3200, 3200)",
				workers, res.RecordsSubmitted, res.DeliveredRows)
		}
		return res
	}

	res1 := runWithWorkers(1)
	res16 := runWithWorkers(16)
	workerCloneOverheadMB := res16.Memory.TotalAllocDeltaMB - res1.Memory.TotalAllocDeltaMB
	if workerCloneOverheadMB > 35.0 {
		t.Fatalf("TotalAllocDeltaMB jumped from %.2f MiB (1 worker) to %.2f MiB (16 workers), delta=%.2f MiB > 35.0 MiB; worker batch templates leaked into measured window",
			res1.Memory.TotalAllocDeltaMB, res16.Memory.TotalAllocDeltaMB, workerCloneOverheadMB)
	}

	// Verify O(workers) single-slot live heap footprint and race-free isolation across 32 workers.
	genUnique := NewGenerator(GeneratorConfig{UniquePayloads: true})
	if got := buildWorkerBatchSlots(RunnerConfig{Workers: 8, BatchSize: 4, UniquePayloads: true}, "logs", genUnique); got != nil {
		t.Fatalf("buildWorkerBatchSlots(UniquePayloads=true) = %v, want nil", got)
	}

	runtime.GC()
	var heapBefore, heapAfter runtime.MemStats
	runtime.ReadMemStats(&heapBefore)
	gen32 := NewGenerator(GeneratorConfig{PayloadBytes: 4096, UpstreamInsertID: true})
	slots32 := buildWorkerBatchSlots(RunnerConfig{Workers: 32, BatchSize: 200, PayloadBytes: 4096, UpstreamInsertID: true}, "logs", gen32)
	runtime.GC()
	runtime.ReadMemStats(&heapAfter)
	var liveSlotsMB float64
	if heapAfter.HeapAlloc > heapBefore.HeapAlloc {
		liveSlotsMB = float64(heapAfter.HeapAlloc-heapBefore.HeapAlloc) / (1024.0 * 1024.0)
	}
	// 32 single-slot batches x ~0.9 MiB is ~29 MiB; 32 x 8 batches would exceed 200 MiB.
	if liveSlotsMB > 65.0 {
		t.Fatalf("32-worker live slot heap = %.2f MiB, want <= 65.0 MiB (must be O(workers), not workers * 8)", liveSlotsMB)
	}
	if len(slots32) != 32 {
		t.Fatalf("len(slots32) = %d, want 32", len(slots32))
	}
	totalAllocated := 0
	for w, ws := range slots32 {
		if len(ws) != 1 {
			t.Fatalf("worker %d slot count = %d, want 1 (single-slot per worker when Workers >= 8)", w, len(ws))
		}
		totalAllocated += len(ws)
	}
	if totalAllocated != 32 {
		t.Fatalf("totalAllocated = %d, want 32 (never workers * 8 = 256)", totalAllocated)
	}

	var (
		seq       atomic.Uint64
		wg        sync.WaitGroup
		perWorker = make([][]string, 32)
	)
	for w := range 32 {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			slot := slots32[workerID][0]
			ids := make([]string, 0, 400)
			for range 2 {
				startSeq := seq.Add(uint64(slot.recordCount)) - uint64(slot.recordCount) + 1
				stampFreshLogsIdentity(slot.logs, DefaultBaseTime, startSeq, true)
				_, gotIDs := collectLogIdentities(slot.logs)
				ids = append(ids, gotIDs...)
			}
			perWorker[workerID] = ids
		}(w)
	}
	wg.Wait()
	runtime.KeepAlive(slots32)

	seenAll := make(map[string]struct{}, 32*400)
	for w, ids := range perWorker {
		if len(ids) != 400 {
			t.Fatalf("worker %d stamped %d ids, want 400", w, len(ids))
		}
		for _, id := range ids {
			seenAll[id] = struct{}{}
		}
	}
	if len(seenAll) != 32*400 {
		t.Fatalf("distinct stamped insertIds across 32 concurrent workers = %d, want %d", len(seenAll), 32*400)
	}
}

func TestCheckSignalResultLosslessBQFakeShortfallAndIncompleteDrain(t *testing.T) {
	t.Run("ModeBQFakeDeliveryShortfall", func(t *testing.T) {
		strictCfg := RunnerConfig{
			Mode:                 ModeBQFake,
			AllowPartialFailures: false,
		}
		shortfallRes := SignalResult{
			Signal:                 "logs",
			Mode:                   ModeBQFake,
			BatchesAttempted:       1,
			BatchesSucceeded:       1,
			BatchesFailed:          0,
			RecordsSubmitted:       10,
			DeliveredRows:          8,
			UniqueDeliveryVerified: false,
			IncompleteDrain:        false,
			Latency:                LatencySummary{Samples: 1},
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 10,
				ReplayedRows:     0,
			},
		}
		err := checkSignalResultLossless(strictCfg, "logs", shortfallRes, nil)
		if err == nil || !strings.Contains(err.Error(), "failed lossless delivery check") {
			t.Fatalf("checkSignalResultLossless(ModeBQFake shortfall) = %v, want lossless delivery error", err)
		}

		completeRes := shortfallRes
		completeRes.DeliveredRows = 10
		if err := checkSignalResultLossless(strictCfg, "logs", completeRes, nil); err != nil {
			t.Fatalf("checkSignalResultLossless(ModeBQFake complete) unexpected error: %v", err)
		}

		partialCfg := strictCfg
		partialCfg.AllowPartialFailures = true
		if err := checkSignalResultLossless(partialCfg, "logs", shortfallRes, nil); err != nil {
			t.Fatalf("checkSignalResultLossless(ModeBQFake shortfall, AllowPartialFailures=true) unexpected error: %v", err)
		}
	})

	t.Run("IncompleteDrainIsolated", func(t *testing.T) {
		strictCfg := RunnerConfig{
			Mode:                 ModeCollector,
			AllowPartialFailures: false,
		}
		incompleteRes := SignalResult{
			Signal:                 "logs",
			Mode:                   ModeCollector,
			BatchesAttempted:       1,
			BatchesSucceeded:       1,
			BatchesFailed:          0,
			RecordsSubmitted:       10,
			DeliveredRows:          10,
			UniqueDeliveryVerified: false,
			IncompleteDrain:        true,
			DrainWarning:           "timed out waiting for drain",
			Latency:                LatencySummary{Samples: 1},
			Telemetry: TelemetrySnapshot{
				AcknowledgedRows: 10,
				ReplayedRows:     0,
			},
		}
		err := checkSignalResultLossless(strictCfg, "logs", incompleteRes, nil)
		if err == nil || !strings.Contains(err.Error(), "failed lossless delivery check") {
			t.Fatalf("checkSignalResultLossless(IncompleteDrain=true) = %v, want lossless delivery error", err)
		}

		cleanRes := incompleteRes
		cleanRes.IncompleteDrain = false
		cleanRes.DrainWarning = ""
		if err := checkSignalResultLossless(strictCfg, "logs", cleanRes, nil); err != nil {
			t.Fatalf("checkSignalResultLossless(IncompleteDrain=false) unexpected error: %v", err)
		}

		partialCfg := strictCfg
		partialCfg.AllowPartialFailures = true
		if err := checkSignalResultLossless(partialCfg, "logs", incompleteRes, nil); err != nil {
			t.Fatalf("checkSignalResultLossless(IncompleteDrain=true, AllowPartialFailures=true) unexpected error: %v", err)
		}
	})
}

func TestParseGeneratedTraceAndSpanIDRoundTrip(t *testing.T) {
	for _, treeID := range []uint64{0, 1, 6, 7, 125, 999_999, 700_000_000, 1 << 40} {
		tid := traceIDFromTree(treeID)
		gotTree, ok := parseGeneratedTraceID(tid)
		if !ok || gotTree != treeID {
			t.Fatalf("parseGeneratedTraceID(traceIDFromTree(%d)) = (%d, %v), want (%d, true)", treeID, gotTree, ok, treeID)
		}
		for step := range uint64(4) {
			sid := spanIDFromPair(treeID, step)
			sTree, sStep, sOK := parseGeneratedSpanID(sid)
			if !sOK || sTree != treeID || sStep != step {
				t.Fatalf("parseGeneratedSpanID(spanIDFromPair(%d, %d)) = (%d, %d, %v), want (%d, %d, true)",
					treeID, step, sTree, sStep, sOK, treeID, step)
			}
			jTree, jStep, jOK := parseGeneratedTreeAndStep(tid, sid)
			if !jOK || jTree != treeID || jStep != step {
				t.Fatalf("parseGeneratedTreeAndStep(%d, %d) = (%d, %d, %v)", treeID, step, jTree, jStep, jOK)
			}
		}
	}

	if _, ok := parseGeneratedTraceID(pcommon.TraceID{}); ok {
		t.Fatal("parseGeneratedTraceID(empty) = true, want false")
	}
	badTID := traceIDFromTree(5)
	badTID[0] ^= 0xff
	if _, ok := parseGeneratedTraceID(badTID); ok {
		t.Fatal("parseGeneratedTraceID(corrupted high64) = true, want false")
	}
	if _, _, ok := parseGeneratedSpanID(spanIDFromPair(5, 4)); ok {
		t.Fatal("parseGeneratedSpanID(step=4) = true, want false")
	}
}

func TestInProcessBQFakeDropPlusReplayFailsStrictLossless(t *testing.T) {
	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(true)
	// Simulate silent drop of the 4th record paired with duplicate commit of the 1st
	// record (fault simulation disabled: 4 submitted, 4 raw commits, 3 unique, 1 replay).
	fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
		if table == "otel_logs" && len(serialized) == 4 {
			mut := slices.Clone(serialized)
			mut[3] = mut[0]
			return mut
		}
		return serialized
	})

	cfg := RunnerConfig{
		Mode:                 ModeBQFake,
		Signals:              []string{"logs"},
		Workers:              1,
		BatchSize:            4,
		maxBatches:           1,
		Duration:             5 * time.Second,
		UpstreamInsertID:     true,
		AllowPartialFailures: false,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
	}
	if res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 {
		t.Fatalf("submitted=%d acked=%d, want 4/4", res.RecordsSubmitted, res.Telemetry.AcknowledgedRows)
	}
	if !res.UniqueDeliveryVerified || res.DeliveredRows != 3 || res.Telemetry.ReplayedRows != 1 {
		t.Fatalf("verified=%v delivered=%d replayed=%d, want true/3/1",
			res.UniqueDeliveryVerified, res.DeliveredRows, res.Telemetry.ReplayedRows)
	}

	lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
	if lossErr == nil || !strings.Contains(lossErr.Error(), "delivered=3") || !strings.Contains(lossErr.Error(), "replayed=1") {
		t.Fatalf("checkSignalResultLossless = %v, want error containing delivered=3 and replayed=1", lossErr)
	}
}

func TestPrebuiltMultiSignalCrossJoinParity(t *testing.T) {
	verifyJoin := func(t *testing.T, workers, batchSize, maxBatches int, warmup time.Duration) {
		t.Helper()
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)

		ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
		defer cancel()

		for _, sig := range []string{"traces", "logs", "metrics"} {
			cfg := RunnerConfig{
				Mode:             ModeBQFake,
				Signals:          []string{"traces", "logs", "metrics"},
				Workers:          workers,
				BatchSize:        batchSize,
				maxBatches:       maxBatches,
				Duration:         10 * time.Second,
				WarmupDuration:   warmup,
				UniquePayloads:   false,
				UpstreamInsertID: true,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize(%s): %v", sig, err)
			}
			// When warmup > 0, retain stored warmup rows so filtering below
			// warmupTreeBaseOffset also proves warmup rows used disjoint tree IDs.
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, sig, fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runSingleSignalWithFake(%s) hard=%v soft=%v", sig, hardErr, softErr)
			}
			wantRows := int64(batchSize * maxBatches)
			if res.DeliveredRows != wantRows || !res.UniqueDeliveryVerified {
				t.Fatalf("%s DeliveredRows=%d UniqueDeliveryVerified=%v, want %d/true",
					sig, res.DeliveredRows, res.UniqueDeliveryVerified, wantRows)
			}
		}

		maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()
		wantSteady := batchSize * maxBatches

		type spanKey struct {
			traceID     string
			spanID      string
			serviceName string
		}
		steadySpans := make(map[spanKey]int64, wantSteady)
		spanByTraceAndSpan := make(map[[2]string]string, wantSteady)
		var steadySpanRows []map[string]any
		for _, r := range fakeSrv.Rows("otel_spans") {
			stNano, _ := r["start_time_unix_nano"].(int64)
			if isWarmupEventTime(DefaultBaseTime, stNano) {
				if stNano >= maxWarmupNano {
					t.Fatalf("warmup span start_time_unix_nano=%d jumped outside phase-local window (>= %d)", stNano, maxWarmupNano)
				}
				continue
			}
			steadySpanRows = append(steadySpanRows, r)
			tid, _ := r["trace_id"].(string)
			sid, _ := r["span_id"].(string)
			svc, _ := r["service_name"].(string)
			k := spanKey{traceID: tid, spanID: sid, serviceName: svc}
			if prev, dup := steadySpans[k]; dup {
				t.Fatalf("duplicate steady-state span key %+v (prev start=%d, cur=%d)", k, prev, stNano)
			}
			steadySpans[k] = stNano
			spanByTraceAndSpan[[2]string{tid, sid}] = svc
		}
		if len(steadySpans) != wantSteady {
			t.Fatalf("distinct steady-state spans = %d, want %d", len(steadySpans), wantSteady)
		}

		// Verify intra-trace parent_span_id links resolve to emitted spans in the same trace & service.
		for _, r := range steadySpanRows {
			parentSID, _ := r["parent_span_id"].(string)
			if parentSID == "" {
				continue
			}
			tid, _ := r["trace_id"].(string)
			svc, _ := r["service_name"].(string)
			if _, ok := steadySpans[spanKey{traceID: tid, spanID: parentSID, serviceName: svc}]; !ok {
				t.Fatalf("span (%s, %s, %s) has unresolved parent_span_id %q", tid, r["span_id"], svc, parentSID)
			}
		}

		joinedLogs := 0
		seenLogDedupKeys := make(map[string]struct{}, wantSteady)
		for _, r := range fakeSrv.Rows("otel_logs") {
			tNano, _ := r["time_unix_nano"].(int64)
			if isWarmupEventTime(DefaultBaseTime, tNano) {
				if tNano >= maxWarmupNano {
					t.Fatalf("warmup log time_unix_nano=%d jumped outside phase-local window (>= %d)", tNano, maxWarmupNano)
				}
				continue
			}
			tid, _ := r["trace_id"].(string)
			sid, _ := r["span_id"].(string)
			svc, _ := r["service_name"].(string)
			insID, _ := r["insert_id"].(string)
			dedupKey := fmt.Sprintf("%s|%s|%d|%s", tid, sid, tNano, insID)
			if _, dup := seenLogDedupKeys[dedupKey]; dup {
				t.Fatalf("duplicate steady-state log dedup key %q", dedupKey)
			}
			seenLogDedupKeys[dedupKey] = struct{}{}
			if _, ok := steadySpans[spanKey{traceID: tid, spanID: sid, serviceName: svc}]; ok {
				joinedLogs++
			} else {
				t.Fatalf("log (%s, %s, %s) did not join any steady-state span (trace+span svc=%q)",
					tid, sid, svc, spanByTraceAndSpan[[2]string{tid, sid}])
			}
		}
		if joinedLogs != wantSteady {
			t.Fatalf("joined steady-state logs = %d/%d, want %d/%d (100%%)", joinedLogs, wantSteady, wantSteady, wantSteady)
		}

		joinedExemplars := 0
		seenMetricTS := make(map[int64]struct{}, wantSteady)
		for _, r := range fakeSrv.Rows("otel_metrics") {
			tNano, _ := r["time_unix_nano"].(int64)
			if isWarmupEventTime(DefaultBaseTime, tNano) {
				if tNano >= maxWarmupNano {
					t.Fatalf("warmup metric time_unix_nano=%d jumped outside phase-local window (>= %d)", tNano, maxWarmupNano)
				}
				continue
			}
			if _, dup := seenMetricTS[tNano]; dup {
				t.Fatalf("duplicate steady-state metric timestamp %d", tNano)
			}
			seenMetricTS[tNano] = struct{}{}
			svc, _ := r["service_name"].(string)
			exs, _ := r["exemplars"].([]map[string]any)
			if len(exs) != 1 {
				t.Fatalf("metric row exemplars len = %d, want 1", len(exs))
			}
			exTID, _ := exs[0]["trace_id"].(string)
			exSID, _ := exs[0]["span_id"].(string)
			if _, ok := steadySpans[spanKey{traceID: exTID, spanID: exSID, serviceName: svc}]; ok {
				joinedExemplars++
			} else {
				t.Fatalf("metric exemplar (%s, %s, %s) did not join any steady-state span", exTID, exSID, svc)
			}
		}
		if joinedExemplars != wantSteady {
			t.Fatalf("joined steady-state metric exemplars = %d/%d, want %d/%d (100%%)", joinedExemplars, wantSteady, wantSteady, wantSteady)
		}
	}

	t.Run("SingleWorkerFourRowBatch", func(t *testing.T) {
		verifyJoin(t, 1, 4, 1, 0)
	})
	t.Run("SingleWorkerLargeBatchRecycleJoin", func(t *testing.T) {
		verifyJoin(t, 1, 28, 18, 0)
	})
	t.Run("SingleWorkerSharedPoolBudgetAlignmentAcrossPayloads", func(t *testing.T) {
		for _, pb := range []int{1024, 512_000, 1_500_000, 2_000_000, 3_000_000} {
			sharedCfg := RunnerConfig{
				Mode:            ModeBQFake,
				Signals:         []string{"traces", "logs", "metrics"},
				Workers:         1,
				BatchSize:       28,
				PayloadBytes:    pb,
				WorkloadProfile: WorkloadProfileGenAIMixed,
			}
			gTraces := computeWorkerSlotGeometry(sharedCfg, "traces")
			gMetrics := computeWorkerSlotGeometry(sharedCfg, "metrics")
			gLogs := computeWorkerSlotGeometry(sharedCfg, "logs")
			if gTraces != gMetrics || gTraces != gLogs {
				t.Fatalf("payloadBytes=%d geometry mismatch: traces=%+v metrics=%+v logs=%+v", pb, gTraces, gMetrics, gLogs)
			}
			sTraces := computePrebuiltTreeStride(gTraces.seedBatchCount, sharedCfg.BatchSize)
			sMetrics := computePrebuiltTreeStride(gMetrics.seedBatchCount, sharedCfg.BatchSize)
			if sTraces != sMetrics {
				t.Fatalf("payloadBytes=%d treeStride mismatch: traces=%d metrics=%d", pb, sTraces, sMetrics)
			}
		}

		// End-to-end 1-worker traces+metrics run with asymmetric PayloadBytes
		// (where unaligned traces vs metrics budgetGroups differ: 37-row batches
		// x 4 slots/group at 235 KB/row < 256 KiB DefaultLimits.MaxValueBytes) across
		// multiple pool recycles must preserve 100% exemplar join.
		asymCfg := RunnerConfig{
			Mode:           ModeBQFake,
			Signals:        []string{"traces", "metrics"},
			Workers:        1,
			BatchSize:      37,
			maxBatches:     30,
			PayloadBytes:   235_000,
			Duration:       20 * time.Second,
			UniquePayloads: false,
		}
		if err := asymCfg.Normalize(); err != nil {
			t.Fatalf("Normalize(asymCfg): %v", err)
		}
		if gT, gM := computeWorkerSlotGeometry(asymCfg, "traces"), computeWorkerSlotGeometry(asymCfg, "metrics"); gT != gM {
			t.Fatalf("asymCfg geometry mismatch: traces=%+v metrics=%+v", gT, gM)
		}
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(false)
		runCtx, cancelRun := context.WithTimeout(t.Context(), 25*time.Second)
		defer cancelRun()
		wantRows := int64(asymCfg.BatchSize * asymCfg.maxBatches)
		for _, sig := range asymCfg.Signals {
			res, softErr, hardErr := runSingleSignalWithFake(runCtx, asymCfg, sig, fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runSingleSignalWithFake(%s) hard=%v soft=%v", sig, hardErr, softErr)
			}
			if res.DeliveredRows != wantRows || !res.UniqueDeliveryVerified {
				t.Fatalf("%s DeliveredRows=%d Verified=%v, want %d/true", sig, res.DeliveredRows, res.UniqueDeliveryVerified, wantRows)
			}
		}
		type spanKey struct{ traceID, spanID, svc string }
		spans := make(map[spanKey]struct{}, wantRows)
		for _, r := range fakeSrv.Rows("otel_spans") {
			tid, _ := r["trace_id"].(string)
			sid, _ := r["span_id"].(string)
			svc, _ := r["service_name"].(string)
			spans[spanKey{tid, sid, svc}] = struct{}{}
		}
		for _, r := range fakeSrv.Rows("otel_metrics") {
			svc, _ := r["service_name"].(string)
			exs, _ := r["exemplars"].([]map[string]any)
			if len(exs) != 1 {
				t.Fatalf("metric exemplars len = %d, want 1", len(exs))
			}
			tid, _ := exs[0]["trace_id"].(string)
			sid, _ := exs[0]["span_id"].(string)
			if _, ok := spans[spanKey{tid, sid, svc}]; !ok {
				t.Fatalf("metric exemplar (%s, %s, %s) failed to join emitted span across recycle", tid, sid, svc)
			}
		}
	})
	t.Run("MultiWorkerMultiBatchWithWarmup", func(t *testing.T) {
		verifyJoin(t, 4, 4, 6, 50*time.Millisecond)
	})
}

func TestAggregatePrebuiltBatchBudgetFailsClosed(t *testing.T) {
	// Extreme Workers=256, BatchSize=100,000 (25.6M prebuilt records > 2M) must fail closed
	// upfront in both ModeBQFake and ModeCollector without allocating batches.
	extremeBQFake := RunnerConfig{
		Mode:           ModeBQFake,
		Workers:        256,
		BatchSize:      100_000,
		PayloadBytes:   128,
		UniquePayloads: false,
	}
	if err := extremeBQFake.Normalize(); err == nil || !strings.Contains(err.Error(), "exceeds maximum 2000000 records") {
		t.Fatalf("Normalize(ModeBQFake 256x100000) = %v, want >2000000 records error", err)
	}

	extremeCollector := RunnerConfig{
		Mode:            ModeCollector,
		CollectorBin:    os.Args[0],
		CollectorConfig: "example/otel-collector-high-volume-logs.yaml",
		Workers:         256,
		BatchSize:       100_000,
		PayloadBytes:    128,
		UniquePayloads:  false,
	}
	if err := extremeCollector.Normalize(); err == nil || !strings.Contains(err.Error(), "exceeds maximum 2000000 records") {
		t.Fatalf("Normalize(ModeCollector 256x100000) = %v, want >2000000 records error", err)
	}

	// Aggregate byte cap: 32 workers * 2000 batch * 8192 B = 512 MiB > 256 MiB.
	extremeBytePool := RunnerConfig{
		Mode:           ModeBQFake,
		Workers:        32,
		BatchSize:      2000,
		PayloadBytes:   8192,
		UniquePayloads: false,
	}
	if err := extremeBytePool.Normalize(); err == nil || !strings.Contains(err.Error(), "prebuilt worker batch pool budget") {
		t.Fatalf("Normalize(32x2000x8192B) = %v, want prebuilt worker batch pool budget error", err)
	}

	// Standard 32 workers * 500 batch * 1024 B (16 MiB, 16k records) and UniquePayloads=true pass.
	stdCfg := RunnerConfig{
		Mode:           ModeBQFake,
		Workers:        32,
		BatchSize:      500,
		PayloadBytes:   1024,
		UniquePayloads: false,
	}
	if err := stdCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(standard 32x500) unexpected error: %v", err)
	}
	uniqueCfg := extremeBQFake
	uniqueCfg.UniquePayloads = true
	if err := uniqueCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(UniquePayloads=true 256x100000) unexpected error: %v", err)
	}
}

func TestModeBQFakeTier1TracksRealSignalsWithWarmupAndZeroTier2Hashes(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()

	type caseSpec struct {
		name             string
		signal           string
		table            string
		profile          string
		uniquePayloads   bool
		upstreamInsertID bool
		batchSize        int
		maxBatches       int
		warmup           time.Duration
	}

	cases := []caseSpec{
		{name: "traces_prebuilt_warmup", signal: "traces", table: "otel_spans", uniquePayloads: false, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "traces_unique_warmup", signal: "traces", table: "otel_spans", uniquePayloads: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_tracestep_prebuilt_warmup", signal: "logs", table: "otel_logs", profile: WorkloadProfileGenAIMixed, uniquePayloads: false, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_tracestep_unique_warmup", signal: "logs", table: "otel_logs", profile: WorkloadProfileGenAIMixed, uniquePayloads: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_tracestep_prebuilt_warmup_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileGenAIMixed, uniquePayloads: false, upstreamInsertID: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_tracestep_unique_warmup_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileGenAIMixed, uniquePayloads: true, upstreamInsertID: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_access_prebuilt_warmup", signal: "logs", table: "otel_logs", profile: WorkloadProfileAccessLogs, uniquePayloads: false, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_access_unique_warmup", signal: "logs", table: "otel_logs", profile: WorkloadProfileAccessLogs, uniquePayloads: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_access_prebuilt_warmup_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileAccessLogs, uniquePayloads: false, upstreamInsertID: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "logs_access_unique_warmup_upstream_id", signal: "logs", table: "otel_logs", profile: WorkloadProfileAccessLogs, uniquePayloads: true, upstreamInsertID: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "metrics_prebuilt_warmup", signal: "metrics", table: "otel_metrics", uniquePayloads: false, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
		{name: "metrics_unique_warmup", signal: "metrics", table: "otel_metrics", uniquePayloads: true, batchSize: 4, maxBatches: 4, warmup: 40 * time.Millisecond},
	}

	rowTimeNano := func(sig string, r map[string]any) int64 {
		if sig == "traces" {
			v, _ := r["start_time_unix_nano"].(int64)
			return v
		}
		v, _ := r["time_unix_nano"].(int64)
		return v
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()
			fakeSrv.SetDiscardRows(false)

			cfg := RunnerConfig{
				Mode:             ModeBQFake,
				Signals:          []string{tc.signal},
				WorkloadProfile:  tc.profile,
				UniquePayloads:   tc.uniquePayloads,
				UpstreamInsertID: tc.upstreamInsertID,
				Workers:          2,
				BatchSize:        tc.batchSize,
				maxBatches:       tc.maxBatches,
				Duration:         10 * time.Second,
				WarmupDuration:   tc.warmup,
			}
			if normErr := cfg.Normalize(); normErr != nil {
				t.Fatalf("Normalize: %v", normErr)
			}

			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, tc.signal, fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
			}
			wantSteady := int64(tc.batchSize * tc.maxBatches)
			if !res.UniqueDeliveryVerified || res.DeliveredRows != wantSteady {
				t.Fatalf("UniqueDeliveryVerified=%v DeliveredRows=%d, want true/%d",
					res.UniqueDeliveryVerified, res.DeliveredRows, wantSteady)
			}
			if lossErr := checkSignalResultLossless(cfg, tc.signal, res, softErr); lossErr != nil {
				t.Fatalf("checkSignalResultLossless unexpected error: %v", lossErr)
			}

			tier1Chunks, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable(tc.table)
			if tier1Chunks < 1 || tier2Hashes != 0 {
				t.Fatalf("Tier counts = (tier1Chunks=%d, tier2Hashes=%d), want (>0, 0)", tier1Chunks, tier2Hashes)
			}

			rows := fakeSrv.Rows(tc.table)
			if gotUnique := fakeSrv.UniqueAckedRowsForTable(tc.table); gotUnique != int64(len(rows)) {
				t.Fatalf("UniqueAckedRowsForTable(%s) = %d, want %d total (warmup+steady) without phase-transition reset", tc.table, gotUnique, len(rows))
			}
			var warmupCount, steadyCount int
			for _, r := range rows {
				tsNano := rowTimeNano(tc.signal, r)
				if isWarmupEventTime(DefaultBaseTime, tsNano) {
					if tsNano >= maxWarmupNano {
						t.Fatalf("warmup row timestamp %d jumped outside phase-local window (>= %d)", tsNano, maxWarmupNano)
					}
					warmupCount++
				} else {
					steadyCount++
				}
			}
			if warmupCount == 0 {
				t.Fatalf("expected warmup rows with phase-local +%dus substep, got 0 (total rows=%d)", warmupTimeSubstepNano/1000, len(rows))
			}
			if int64(steadyCount) != wantSteady {
				t.Fatalf("steady rows = %d, want %d (warmup collides with steady range!)", steadyCount, wantSteady)
			}
		})
	}

	t.Run("WarmupEpochOffsetCeilCoversNonDivisorTreeStride", func(t *testing.T) {
		treeStride := computePrebuiltTreeStride(1, 80)
		if treeStride != 21 {
			t.Fatalf("computePrebuiltTreeStride(1, 80) = %d, want 21", treeStride)
		}

		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:             ModeBQFake,
			Signals:          []string{"traces"},
			UniquePayloads:   false,
			UpstreamInsertID: false,
			Workers:          1,
			BatchSize:        80,
			maxBatches:       1,
			Duration:         10 * time.Second,
			WarmupDuration:   40 * time.Millisecond,
		}
		if normErr := cfg.Normalize(); normErr != nil {
			t.Fatalf("Normalize: %v", normErr)
		}

		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runSingleSignalWithFake(treeStride=21) hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 80 {
			t.Fatalf("DeliveredRows = %d, want 80", res.DeliveredRows)
		}
		tier1Chunks, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable("otel_spans")
		if tier1Chunks < 1 || tier2Hashes != 0 {
			t.Fatalf("Tier counts = (tier1Chunks=%d, tier2Hashes=%d), want (>0, 0)", tier1Chunks, tier2Hashes)
		}
		var warmupCount, steadyCount int
		for _, r := range fakeSrv.Rows("otel_spans") {
			tsNano := rowTimeNano("traces", r)
			if isWarmupEventTime(DefaultBaseTime, tsNano) {
				if tsNano >= maxWarmupNano {
					t.Fatalf("warmup span timestamp %d jumped outside phase-local window (>= %d)", tsNano, maxWarmupNano)
				}
				warmupCount++
			} else {
				steadyCount++
			}
		}
		if warmupCount == 0 || steadyCount != 80 {
			t.Fatalf("warmup/steady counts with treeStride=21 = (%d, %d), want (>0, 80)", warmupCount, steadyCount)
		}
	})
}

func TestCheckSignalResultLosslessRejectsSurplusDistinctRows(t *testing.T) {
	strictCfg := RunnerConfig{
		Mode:                 ModeBQFake,
		AllowPartialFailures: false,
	}
	for _, tc := range []struct {
		name string
		cfg  RunnerConfig
		res  SignalResult
	}{
		{
			name: "BQFakeExtraDistinctRow",
			cfg:  strictCfg,
			res: SignalResult{
				Signal:                 "logs",
				Mode:                   ModeBQFake,
				BatchesAttempted:       1,
				BatchesSucceeded:       1,
				RecordsSubmitted:       4,
				DeliveredRows:          5,
				UniqueDeliveryVerified: true,
				Latency:                LatencySummary{Samples: 1},
				Telemetry:              TelemetrySnapshot{AcknowledgedRows: 5, ReplayedRows: 0},
			},
		},
		{
			name: "BQFakeSingleRecordExtraRow",
			cfg:  strictCfg,
			res: SignalResult{
				Signal:                 "logs",
				Mode:                   ModeBQFake,
				BatchesAttempted:       1,
				BatchesSucceeded:       1,
				RecordsSubmitted:       1,
				DeliveredRows:          2,
				UniqueDeliveryVerified: true,
				Latency:                LatencySummary{Samples: 1},
				Telemetry:              TelemetrySnapshot{AcknowledgedRows: 2, ReplayedRows: 0},
			},
		},
		{
			name: "FaultSimSurplusDistinctRow",
			cfg: RunnerConfig{
				Mode:                  ModeCollector,
				AllowPartialFailures:  false,
				SimulateThrottleEvery: 5,
			},
			res: SignalResult{
				Signal:                 "logs",
				Mode:                   ModeCollector,
				BatchesAttempted:       1,
				BatchesSucceeded:       1,
				RecordsSubmitted:       4,
				DeliveredRows:          5,
				UniqueDeliveryVerified: true,
				Latency:                LatencySummary{Samples: 1},
				Telemetry:              TelemetrySnapshot{AcknowledgedRows: 5, ReplayedRows: 0},
			},
		},
		{
			name: "LiveExtraAckedRow",
			cfg: RunnerConfig{
				Mode:                 ModeLive,
				AllowPartialFailures: false,
			},
			res: SignalResult{
				Signal:                 "logs",
				Mode:                   ModeLive,
				BatchesAttempted:       1,
				BatchesSucceeded:       1,
				RecordsSubmitted:       4,
				DeliveredRows:          4,
				UniqueDeliveryVerified: false,
				Latency:                LatencySummary{Samples: 1},
				Telemetry:              TelemetrySnapshot{AcknowledgedRows: 5, ReplayedRows: 1},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkSignalResultLossless(tc.cfg, "logs", tc.res, nil); err == nil {
				t.Fatalf("checkSignalResultLossless(%s) = nil, want failure when delivered/acked (%d/%d) != submitted (%d)",
					tc.name, tc.res.DeliveredRows, tc.res.Telemetry.AcknowledgedRows, tc.res.RecordsSubmitted)
			}
		})
	}

	faultSimCfg := RunnerConfig{
		Mode:                  ModeBQFake,
		AllowPartialFailures:  false,
		SimulateThrottleEvery: 5,
	}
	faultSimUnobservedReplay := SignalResult{
		Signal:                 "logs",
		Mode:                   ModeBQFake,
		BatchesAttempted:       4,
		BatchesSucceeded:       4,
		RecordsSubmitted:       4,
		DeliveredRows:          4,
		UniqueDeliveryVerified: true,
		Latency:                LatencySummary{Samples: 4},
		Telemetry:              TelemetrySnapshot{AcknowledgedRows: 5, ReplayedRows: 1},
	}
	if err := checkSignalResultLossless(faultSimCfg, "logs", faultSimUnobservedReplay, nil); err == nil {
		t.Fatal("checkSignalResultLossless(unobserved replay with SimulateThrottleEvery=5) = nil, want failure")
	}
	faultSimValidReplay := faultSimUnobservedReplay
	faultSimValidReplay.ObservedUncertainCommitFaults = 1
	faultSimValidReplay.ObservedUncertainCommitRows = 1
	faultSimValidReplay.Telemetry.Retries = 1
	if err := checkSignalResultLossless(faultSimCfg, "logs", faultSimValidReplay, nil); err != nil {
		t.Fatalf("checkSignalResultLossless(valid fault-injected replay with exact distinct count) unexpected error: %v", err)
	}
}

func TestModeBQFakeEndToEndSurplusDistinctRowsRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	enc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	baseTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)

	encodeRow := func(insertID string, ts time.Time) []byte {
		t.Helper()
		raw, eErr := enc.Encode(transform.Row{
			"timestamp":               ts.UnixMicro(),
			"timestamp_source":        "observed",
			"time_unix_nano":          ts.UnixNano(),
			"observed_time_unix_nano": ts.UnixNano(),
			"receive_time":            ts.UnixMicro(),
			"receive_time_unix_nano":  ts.UnixNano(),
			"log_name":                "projects/test-project/logs/extra",
			"insert_id":               insertID,
			"body":                    `"extra"`,
		})
		if eErr != nil {
			t.Fatalf("Encode(%s): %v", insertID, eErr)
		}
		return raw
	}

	t.Run("FourSubmittedPlusFifthDistinctInsertID", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		extra := encodeRow("surplus-insert-id-5", baseTS)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table == "otel_logs" && len(serialized) == 4 {
				return append(slices.Clone(serialized), extra)
			}
			return serialized
		})

		cfg := RunnerConfig{
			Mode:             ModeBQFake,
			Signals:          []string{"logs"},
			Workers:          1,
			BatchSize:        4,
			maxBatches:       1,
			Duration:         5 * time.Second,
			UpstreamInsertID: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runSingleSignalWithFake unexpected hardErr: %v", hardErr)
		}
		if res.DeliveredRows != 5 || res.RecordsSubmitted != 4 {
			t.Fatalf("DeliveredRows=%d RecordsSubmitted=%d, want 5/4", res.DeliveredRows, res.RecordsSubmitted)
		}
		if err := checkSignalResultLossless(cfg, "logs", res, softErr); err == nil {
			t.Fatal("checkSignalResultLossless passed with 5 distinct delivered rows for 4 submitted rows")
		}
	})

	t.Run("OneSubmittedPlusSecondDifferingOnlyInTimeUnixNano", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		extraTime := encodeRow("same-fallback-base", baseTS.Add(50*time.Millisecond))
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table == "otel_logs" && len(serialized) == 1 {
				return append(slices.Clone(serialized), extraTime)
			}
			return serialized
		})

		cfg := RunnerConfig{
			Mode:             ModeBQFake,
			Signals:          []string{"logs"},
			Workers:          1,
			BatchSize:        1,
			maxBatches:       1,
			Duration:         5 * time.Second,
			UpstreamInsertID: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runSingleSignalWithFake unexpected hardErr: %v", hardErr)
		}
		if res.DeliveredRows != 2 || res.RecordsSubmitted != 1 {
			t.Fatalf("DeliveredRows=%d RecordsSubmitted=%d, want 2/1", res.DeliveredRows, res.RecordsSubmitted)
		}
		if err := checkSignalResultLossless(cfg, "logs", res, softErr); err == nil {
			t.Fatal("checkSignalResultLossless passed with 2 distinct delivered rows for 1 submitted row")
		}
	})
}

func TestModeBQFakeBatchSizeOneCoversAllFrameworksAndValidParentTrees(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			fakeSrv, err := bqfake.New()
			if err != nil {
				t.Fatalf("bqfake.New: %v", err)
			}
			defer func() { _ = fakeSrv.Close() }()
			fakeSrv.SetDiscardRows(false)

			cfg := RunnerConfig{
				Mode:           ModeBQFake,
				Signals:        []string{"traces"},
				Workers:        workers,
				BatchSize:      1,
				maxBatches:     28,
				Duration:       5 * time.Second,
				UniquePayloads: false,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "traces", fakeSrv)
			if hardErr != nil || softErr != nil {
				t.Fatalf("runSingleSignalWithFake(workers=%d) hard=%v soft=%v", workers, hardErr, softErr)
			}
			if res.DeliveredRows != 28 {
				t.Fatalf("DeliveredRows = %d, want 28", res.DeliveredRows)
			}

			rows := fakeSrv.Rows("otel_spans")
			if len(rows) != 28 {
				t.Fatalf("len(otel_spans) = %d, want 28", len(rows))
			}

			services := make(map[string]struct{})
			spansByTrace := make(map[string]map[string]struct{})
			type spanRef struct {
				traceID string
				spanID  string
				parent  string
			}
			var refs []spanRef
			for _, r := range rows {
				svc, _ := r["service_name"].(string)
				services[svc] = struct{}{}
				tid, _ := r["trace_id"].(string)
				sid, _ := r["span_id"].(string)
				pid, _ := r["parent_span_id"].(string)
				if spansByTrace[tid] == nil {
					spansByTrace[tid] = make(map[string]struct{})
				}
				spansByTrace[tid][sid] = struct{}{}
				refs = append(refs, spanRef{traceID: tid, spanID: sid, parent: pid})
			}
			wantFrameworks := DefaultFrameworks()
			if len(services) != len(wantFrameworks) {
				t.Fatalf("distinct frameworks = %d (%v), want all %d frameworks", len(services), services, len(wantFrameworks))
			}
			for _, fw := range wantFrameworks {
				if _, ok := services[fw.ServiceName]; !ok {
					t.Fatalf("missing framework service %q in %v", fw.ServiceName, services)
				}
			}
			var missingParents int
			for _, ref := range refs {
				if ref.parent == "" {
					continue
				}
				if _, ok := spansByTrace[ref.traceID][ref.parent]; !ok {
					missingParents++
				}
			}
			if missingParents > 0 {
				t.Fatalf("found %d spans pointing to absent parent_span_id across %d traces", missingParents, len(spansByTrace))
			}
		})
	}
}

func TestNewBigQueryClientForwardsUniverseDomainAndAdminURLPrecedence(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	makeSAJSON := func(universe string) string {
		payload := map[string]any{
			"type":         "service_account",
			"project_id":   "test-proj",
			"private_key":  string(pemBytes),
			"client_email": "sa@test-proj.iam.gserviceaccount.com",
			"token_uri":    "https://oauth2.example.invalid/token",
		}
		if universe != "" {
			payload["universe_domain"] = universe
		}
		b, mErr := json.Marshal(payload)
		if mErr != nil {
			t.Fatalf("Marshal SA JSON: %v", mErr)
		}
		return string(b)
	}

	captureDialHosts := func(t *testing.T, opts []option.ClientOption) ([]string, error) {
		t.Helper()
		var (
			mu    sync.Mutex
			hosts []string
		)
		reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer reqCancel()
		tracedCtx := httptrace.WithClientTrace(reqCtx, &httptrace.ClientTrace{
			GetConn: func(hostPort string) {
				mu.Lock()
				hosts = append(hosts, hostPort)
				mu.Unlock()
				reqCancel()
			},
		})
		_, gotErr := datasetExists(tracedCtx, "test-proj", "test_ds", opts...)
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(hosts), gotErr
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	t.Run("CustomUniverseDomainRoutesWithoutAdminURL", func(t *testing.T) {
		cfg := RunnerConfig{
			Mode: ModeLive,
		}
		creds := &bigqueryexporter.CredentialsConfig{
			JSON:           configopaque.String(makeSAJSON("example.invalid")),
			UniverseDomain: "example.invalid",
		}
		opts, closeOpts, oErr := buildLiveRESTClientOptions(ctx, cfg, "", creds)
		if oErr != nil {
			t.Fatalf("buildLiveRESTClientOptions: %v", oErr)
		}
		defer closeOpts()

		gotHosts, dErr := captureDialHosts(t, opts)
		if len(gotHosts) == 0 {
			t.Fatalf("expected httptrace.GetConn to observe outbound BigQuery host, got 0 calls (err=%v)", dErr)
		}
		for _, h := range gotHosts {
			if h != "bigquery.example.invalid:443" {
				t.Fatalf("BigQuery REST host = %q, want bigquery.example.invalid:443 (got %v)", h, gotHosts)
			}
		}
	})

	t.Run("ClientOptionsUniverseDomainRoutesWithoutCredentialsField", func(t *testing.T) {
		cfg := RunnerConfig{
			Mode: ModeLive,
			ClientOptions: []option.ClientOption{
				option.WithoutAuthentication(),
				option.WithUniverseDomain("clientopt.invalid"),
			},
		}
		opts, closeOpts, oErr := buildLiveRESTClientOptions(ctx, cfg, "", nil)
		if oErr != nil {
			t.Fatalf("buildLiveRESTClientOptions: %v", oErr)
		}
		defer closeOpts()

		gotHosts, dErr := captureDialHosts(t, opts)
		if len(gotHosts) == 0 {
			t.Fatalf("expected httptrace.GetConn to observe outbound BigQuery host, got 0 calls (err=%v)", dErr)
		}
		for _, h := range gotHosts {
			if h != "bigquery.clientopt.invalid:443" {
				t.Fatalf("BigQuery REST host = %q, want bigquery.clientopt.invalid:443 (got %v)", h, gotHosts)
			}
		}
	})

	t.Run("ExplicitAdminURLTakesPrecedenceOverUniverseDomain", func(t *testing.T) {
		var adminHits atomic.Int64
		adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			adminHits.Add(1)
			w.WriteHeader(http.StatusNotFound)
		}))
		defer adminSrv.Close()

		cfg := RunnerConfig{
			Mode: ModeLive,
		}
		creds := &bigqueryexporter.CredentialsConfig{
			JSON:           configopaque.String(makeSAJSON("example.invalid")),
			UniverseDomain: "example.invalid",
		}
		opts, closeOpts, oErr := buildLiveRESTClientOptions(ctx, cfg, adminSrv.URL, creds)
		if oErr != nil {
			t.Fatalf("buildLiveRESTClientOptions: %v", oErr)
		}
		defer closeOpts()

		exists, dErr := datasetExists(ctx, "test-proj", "test_ds", opts...)
		if dErr != nil {
			t.Fatalf("datasetExists against explicit admin_url: %v", dErr)
		}
		if exists {
			t.Fatal("expected exists=false on 404 from adminSrv")
		}
		if adminHits.Load() == 0 {
			t.Fatal("expected explicit AdminURL server to receive metadata request")
		}
	})
}

func TestRunnerConfigNormalizeSkipsPrebuiltBudgetWhenCollectorUsesDynamicPacing(t *testing.T) {
	pacedCfg := RunnerConfig{
		Mode:         ModeCollector,
		CollectorBin: os.Args[0],
		Signals:      []string{"logs"},
		Workers:      2,
		BatchSize:    16384,
		PayloadBytes: 16384,
		TargetRate:   20,
		Duration:     2 * time.Second,
	}
	if err := pacedCfg.Normalize(); err != nil {
		t.Fatalf("expected dynamically paced collector config to bypass prebuilt pool budget, got: %v", err)
	}
	if slots := prebuiltSlotCount(pacedCfg); slots != 0 {
		t.Fatalf("prebuiltSlotCount(dynamically paced collector) = %d, want 0", slots)
	}

	unpacedCfg := pacedCfg
	unpacedCfg.TargetRate = 0
	if err := unpacedCfg.Normalize(); err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected unpaced 512 MiB collector config to fail prebuilt budget check, got: %v", err)
	}
}

func TestAccessLogsCanonicalCycleAndSingleChunkReuse(t *testing.T) {
	t.Run("SlotGeometryUsesTwelveRecordPodStatusCycle", func(t *testing.T) {
		for _, tc := range []struct {
			batchSize     int
			workers       int
			wantSeedCount int
			wantSeqStride uint64
		}{
			{batchSize: 1, workers: 1, wantSeedCount: 12, wantSeqStride: 12},
			{batchSize: 1, workers: 4, wantSeedCount: 12, wantSeqStride: 12},
			{batchSize: 4, workers: 2, wantSeedCount: 3, wantSeqStride: 12},
			{batchSize: 5, workers: 2, wantSeedCount: 12, wantSeqStride: 60},
			{batchSize: 12, workers: 4, wantSeedCount: 1, wantSeqStride: 12},
			{batchSize: 500, workers: 4, wantSeedCount: 1, wantSeqStride: 504},
		} {
			cfg := RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    os.Args[0],
				Signals:         []string{"logs"},
				WorkloadProfile: WorkloadProfileAccessLogs,
				Workers:         tc.workers,
				BatchSize:       tc.batchSize,
			}
			geom := computeWorkerSlotGeometry(cfg, "logs")
			if geom.seedBatchCount != tc.wantSeedCount {
				t.Fatalf("batch=%d workers=%d seedBatchCount=%d, want %d",
					tc.batchSize, tc.workers, geom.seedBatchCount, tc.wantSeedCount)
			}
			if gotStride := computePrebuiltAccessLogSeqStride(geom.seedBatchCount, tc.batchSize); gotStride != tc.wantSeqStride {
				t.Fatalf("batch=%d workers=%d accessStride=%d, want %d",
					tc.batchSize, tc.workers, gotStride, tc.wantSeqStride)
			}
		}
	})

	t.Run("BatchSizeOneCoversAllPodsAnd503ErrorOnSingleChunk", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:             ModeBQFake,
			Signals:          []string{"logs"},
			WorkloadProfile:  WorkloadProfileAccessLogs,
			UniquePayloads:   false,
			UpstreamInsertID: true,
			Workers:          2,
			BatchSize:        1,
			maxBatches:       12,
			Duration:         10 * time.Second,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 12 {
			t.Fatalf("DeliveredRows = %d, want 12", res.DeliveredRows)
		}
		tier1Chunks, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable("otel_logs")
		if tier1Chunks != 1 || tier2Hashes != 0 {
			t.Fatalf("Tier counts = (tier1=%d, tier2=%d), want (1, 0)", tier1Chunks, tier2Hashes)
		}
		services := make(map[string]struct{})
		severities := make(map[int64]int)
		var saw503Error bool
		for _, r := range fakeSrv.Rows("otel_logs") {
			svc, _ := r["service_name"].(string)
			services[svc] = struct{}{}
			sev, _ := r["severity_number"].(int64)
			severities[sev]++
			if sev == int64(plog.SeverityNumberError) {
				body, _ := r["body"].(string)
				attrsStr, _ := r["attributes"].(string)
				var attrs map[string]any
				if attrsStr != "" {
					if uErr := json.Unmarshal([]byte(attrsStr), &attrs); uErr != nil {
						t.Fatalf("invalid attributes JSON %q: %v", attrsStr, uErr)
					}
				}
				if attrs["http.response.status_code"] == "503" && strings.Contains(body, " 503 ") {
					saw503Error = true
				}
			}
		}
		for _, wantSvc := range []string{"edge-ingress-gateway", "vpc-flow-proxy", "api-edge-envoy"} {
			if _, ok := services[wantSvc]; !ok {
				t.Fatalf("missing service %q in BatchSize=1 access-logs run: %v", wantSvc, services)
			}
		}
		if severities[int64(plog.SeverityNumberError)] < 2 || severities[int64(plog.SeverityNumberWarn)] < 4 || severities[int64(plog.SeverityNumberInfo)] < 6 || !saw503Error {
			t.Fatalf("unexpected severity/503 distribution in 12-record cycle: sevs=%v saw503=%v", severities, saw503Error)
		}
	})

	t.Run("BatchSize500ReusedAcrossEpochsAndWarmupUsesZeroChunkFanout", func(t *testing.T) {
		fakeSrv, err := bqfake.New()
		if err != nil {
			t.Fatalf("bqfake.New: %v", err)
		}
		defer func() { _ = fakeSrv.Close() }()
		fakeSrv.SetDiscardRows(false)

		cfg := RunnerConfig{
			Mode:            ModeBQFake,
			Signals:         []string{"logs"},
			WorkloadProfile: WorkloadProfileAccessLogs,
			UniquePayloads:  false,
			Workers:         4,
			BatchSize:       500,
			maxBatches:      12,
			Duration:        10 * time.Second,
			WarmupDuration:  40 * time.Millisecond,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil || softErr != nil {
			t.Fatalf("runSingleSignalWithFake hard=%v soft=%v", hardErr, softErr)
		}
		if res.DeliveredRows != 6000 || !res.UniqueDeliveryVerified {
			t.Fatalf("DeliveredRows=%d UniqueDeliveryVerified=%v, want 6000/true",
				res.DeliveredRows, res.UniqueDeliveryVerified)
		}
		tier1Chunks, tier2Hashes := fakeSrv.UniqueAckedTierCountsForTable("otel_logs")
		if tier1Chunks > 2 || tier2Hashes != 0 {
			t.Fatalf("Tier counts = (tier1=%d, tier2=%d), want (<=2, 0) without 9x access-log chunk fanout",
				tier1Chunks, tier2Hashes)
		}
		baseNano := DefaultBaseTime.UnixNano()
		maxWarmupNano := DefaultBaseTime.Add(time.Minute).UnixNano()
		var warmupCount, steadyCount int
		for _, r := range fakeSrv.Rows("otel_logs") {
			tNano, _ := r["time_unix_nano"].(int64)
			if tNano < baseNano {
				t.Fatalf("unexpected row timestamp %d relative to %d", tNano, baseNano)
			}
			diff := tNano - baseNano
			var (
				seq      uint64
				isWarmup bool
			)
			switch diff % 100_000 {
			case 0:
				seq = uint64(diff / 100_000)
			case warmupTimeSubstepNano:
				isWarmup = true
				if tNano >= maxWarmupNano {
					t.Fatalf("warmup access-log timestamp %d jumped outside phase-local window (>= %d)", tNano, maxWarmupNano)
				}
				seq = warmupSeqOffset + uint64((diff-warmupTimeSubstepNano)/100_000)
			default:
				t.Fatalf("unexpected row timestamp %d relative to %d (mod 100us = %d)", tNano, baseNano, diff%100_000)
			}
			svc, _ := r["service_name"].(string)
			wantSvc := accessLogPods[seq%uint64(len(accessLogPods))].serviceName
			if svc != wantSvc {
				t.Fatalf("seq=%d service_name=%q, want %q (canonical alignment broken)", seq, svc, wantSvc)
			}
			sev, _ := r["severity_number"].(int64)
			status := accessLogStatuses[seq%uint64(len(accessLogStatuses))]
			wantSev := int64(plog.SeverityNumberInfo)
			if status >= 500 {
				wantSev = int64(plog.SeverityNumberError)
			} else if status >= 400 {
				wantSev = int64(plog.SeverityNumberWarn)
			}
			if sev != wantSev {
				t.Fatalf("seq=%d severity_number=%d, want %d (status=%d)", seq, sev, wantSev, status)
			}
			if isWarmup {
				warmupCount++
			} else {
				steadyCount++
			}
		}
		if warmupCount == 0 || steadyCount != 6000 {
			t.Fatalf("warmup/steady counts = (%d, %d), want (>0, 6000)", warmupCount, steadyCount)
		}
	})
}

func TestBuildLiveRESTClientOptionsSanitizesCredentialAndAuthErrors(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	assertNoLeaks := func(t *testing.T, note string, secrets []string) {
		t.Helper()
		for _, sec := range secrets {
			if strings.Contains(note, sec) {
				t.Fatalf("sanitized error/report leaked %q:\n%s", sec, note)
			}
		}
		rep := &BenchmarkReport{
			Config: RunnerConfig{Mode: ModeLive},
			Results: []SignalResult{{
				Signal:     "logs",
				Mode:       ModeLive,
				ByteLayers: &ByteLayersSummary{ProtoRowsBytesPerRow: 100, BQStorageQueryNote: note},
			}},
		}
		rawJSON, err := json.Marshal(rep)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		md := FormatMarkdown(rep)
		for _, sec := range secrets {
			if strings.Contains(string(rawJSON), sec) {
				t.Fatalf("JSON report leaked %q:\n%s", sec, string(rawJSON))
			}
			if strings.Contains(md, sec) {
				t.Fatalf("Markdown report leaked %q:\n%s", sec, md)
			}
		}
	}

	t.Run("PastedJSONInCredentialsFileNeverLeaksPathOrPayload", func(t *testing.T) {
		pastedShort := `{"type":"service_account","private_key":"SECRET_KEY_MARKER_SHORT"}`
		pastedLong := fmt.Sprintf(`{"type":"service_account","private_key":"SECRET_KEY_MARKER_LONG_%s"}`, strings.Repeat("A", 320))
		missingPath := filepath.Join(t.TempDir(), "missing-creds-SECRET_PATH_MARKER.json")
		for _, tc := range []struct {
			name        string
			fileVal     string
			secrets     []string
			wantTarget  error
			posixTarget error
		}{
			{
				name:    "ShortNonexistentPathPreservesErrno",
				fileVal: pastedShort,
				secrets: []string{"SECRET_KEY_MARKER_SHORT", "private_key", "service_account"},
			},
			{
				name:        "LongPastedJSONPreservesErrno",
				fileVal:     pastedLong,
				secrets:     []string{"SECRET_KEY_MARKER_LONG", "private_key", "service_account"},
				posixTarget: syscall.ENAMETOOLONG,
			},
			{
				name:       "RegularMissingFilePreservesNotExist",
				fileVal:    missingPath,
				secrets:    []string{missingPath, "SECRET_PATH_MARKER"},
				wantTarget: os.ErrNotExist,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, readErr := os.ReadFile(tc.fileVal)
				var pathErr *os.PathError
				if !errors.As(readErr, &pathErr) || pathErr.Err == nil {
					t.Fatalf("expected *os.PathError from os.ReadFile(%q), got %v", tc.fileVal, readErr)
				}
				wantErr := pathErr.Err.Error()

				creds := &bigqueryexporter.CredentialsConfig{
					File: tc.fileVal,
				}
				_, _, err := buildLiveRESTClientOptions(ctx, RunnerConfig{Mode: ModeLive}, "", creds)
				if err == nil {
					t.Fatal("expected buildLiveRESTClientOptions error, got nil")
				}
				if !strings.Contains(err.Error(), "credentials.file") || !strings.Contains(err.Error(), wantErr) {
					t.Fatalf("err = %q, want credentials.file and %q", err.Error(), wantErr)
				}
				if tc.wantTarget != nil && !errors.Is(err, tc.wantTarget) {
					t.Fatalf("err = %v, want errors.Is(_, %v)", err, tc.wantTarget)
				}
				if tc.posixTarget != nil && runtime.GOOS != "windows" && !errors.Is(err, tc.posixTarget) {
					t.Fatalf("err = %v, want errors.Is(_, %v) on %s", err, tc.posixTarget, runtime.GOOS)
				}
				assertNoLeaks(t, err.Error(), tc.secrets)

				layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
				populateLiveTableStorageWithCollectorOptions(
					ctx,
					RunnerConfig{Mode: ModeLive, ProjectID: "p", DatasetID: "d", Location: "US"},
					"otel_logs",
					nil,
					creds,
					layers,
				)
				if !strings.Contains(layers.BQStorageQueryNote, "credentials.file") || !strings.Contains(layers.BQStorageQueryNote, wantErr) {
					t.Fatalf("BQStorageQueryNote = %q, want credentials.file and %q", layers.BQStorageQueryNote, wantErr)
				}
				assertNoLeaks(t, layers.BQStorageQueryNote, tc.secrets)
			})
		}
	})

	t.Run("InvalidFileContentsNeverLeakPathOrContents", func(t *testing.T) {
		badJSONPath := filepath.Join(t.TempDir(), "secret-creds-path.json")
		if err := os.WriteFile(badJSONPath, []byte(`{bad_secret_token`), 0o600); err != nil {
			t.Fatalf("write bad json: %v", err)
		}
		_, _, err := buildLiveRESTClientOptions(ctx, RunnerConfig{Mode: ModeLive}, "", &bigqueryexporter.CredentialsConfig{File: badJSONPath})
		if err == nil || !strings.Contains(err.Error(), "parsing credentials.file: invalid JSON") {
			t.Fatalf("err = %v, want parsing credentials.file: invalid JSON", err)
		}
		assertNoLeaks(t, err.Error(), []string{badJSONPath, "secret-creds-path", "bad_secret_token"})

		badTypePath := filepath.Join(t.TempDir(), "secret-type-path.json")
		if err := os.WriteFile(badTypePath, []byte(`{"type":"UNSUPPORTED_FILE_TYPE_SECRET"}`), 0o600); err != nil {
			t.Fatalf("write bad type: %v", err)
		}
		_, _, err = buildLiveRESTClientOptions(ctx, RunnerConfig{Mode: ModeLive}, "", &bigqueryexporter.CredentialsConfig{File: badTypePath})
		if err == nil || !strings.Contains(err.Error(), "loading credentials.file: unsupported credentials type") {
			t.Fatalf("err = %v, want loading credentials.file: unsupported credentials type", err)
		}
		assertNoLeaks(t, err.Error(), []string{badTypePath, "secret-type-path", "UNSUPPORTED_FILE_TYPE_SECRET"})
	})

	t.Run("InlineJSONAndImpersonationErrorsNeverLeakSecretsOrIdentities", func(t *testing.T) {
		for _, tc := range []struct {
			name    string
			creds   *bigqueryexporter.CredentialsConfig
			wantSub string
			secrets []string
		}{
			{
				name:    "InvalidJSON",
				creds:   &bigqueryexporter.CredentialsConfig{JSON: configopaque.String(`{"secret_field": BAD_RAW_SECRET}`)},
				wantSub: "loading credentials.json: invalid JSON",
				secrets: []string{"BAD_RAW_SECRET", "secret_field"},
			},
			{
				name:    "UnsupportedType",
				creds:   &bigqueryexporter.CredentialsConfig{JSON: configopaque.String(`{"type":"SECRET_CUSTOM_TYPE_MARKER"}`)},
				wantSub: "loading credentials.json: unsupported credentials type",
				secrets: []string{"SECRET_CUSTOM_TYPE_MARKER"},
			},
			{
				name:    "RejectedExternalAccountJSON",
				creds:   &bigqueryexporter.CredentialsConfig{JSON: configopaque.String(`{"type":"external_account","audience":"SECRET_AUD_MARKER"}`)},
				wantSub: "loading credentials.json: invalid or rejected credentials",
				secrets: []string{"SECRET_AUD_MARKER", "external_account"},
			},
			{
				name:    "RejectedServiceAccountPEMInNewClient",
				creds:   &bigqueryexporter.CredentialsConfig{JSON: configopaque.String(`{"type":"service_account","client_email":"sa@example.invalid","client_id":"SECRET_CLIENT_ID_MARKER","private_key":"invalid-pem"}`)},
				wantSub: "INFORMATION_SCHEMA.TABLE_STORAGE client error:",
				secrets: []string{"SECRET_CLIENT_ID_MARKER", "invalid-pem", "sa@example.invalid", "service_account"},
			},
			{
				name:    "ImpersonateServiceAccount",
				creds:   &bigqueryexporter.CredentialsConfig{ImpersonateServiceAccount: "sa-secret@example.invalid"},
				wantSub: "loading credentials.impersonate_service_account:",
				secrets: []string{"sa-secret@example.invalid", "example.invalid"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if tc.name == "ImpersonateServiceAccount" {
					t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-adc-secret.json"))
					t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")
					tc.secrets = append(tc.secrets, "missing-adc-secret")
				}
				layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
				populateLiveTableStorageWithCollectorOptions(
					ctx,
					RunnerConfig{Mode: ModeLive, ProjectID: "p", DatasetID: "d", Location: "US"},
					"otel_logs",
					nil,
					tc.creds,
					layers,
				)
				if !strings.Contains(layers.BQStorageQueryNote, tc.wantSub) {
					t.Fatalf("BQStorageQueryNote = %q, want substring %q", layers.BQStorageQueryNote, tc.wantSub)
				}
				assertNoLeaks(t, layers.BQStorageQueryNote, tc.secrets)
			})
		}
	})

	t.Run("PoisonedADCAndHTTPErrorBodiesNeverLeakIntoBQStorageQueryNote", func(t *testing.T) {
		badADC := filepath.Join(t.TempDir(), "poisoned-adc-secret-path.json")
		t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", badADC)
		t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

		layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
		populateLiveTableStorageWithCollectorOptions(
			ctx,
			RunnerConfig{Mode: ModeLive, ProjectID: "p", DatasetID: "d", Location: "US"},
			"otel_logs",
			nil,
			nil,
			layers,
		)
		if !strings.Contains(layers.BQStorageQueryNote, "INFORMATION_SCHEMA.TABLE_STORAGE client error:") {
			t.Fatalf("BQStorageQueryNote = %q, want client error note", layers.BQStorageQueryNote)
		}
		assertNoLeaks(t, layers.BQStorageQueryNote, []string{badADC, "poisoned-adc-secret-path"})

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":403,"message":"SECRET_SERVER_BODY_LEAK https://secret-token.invalid/?access_token=abc"}}`))
		}))
		defer srv.Close()

		httpLayers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
		populateLiveTableStorage(
			ctx,
			RunnerConfig{
				Mode:      ModeLive,
				ProjectID: "p",
				DatasetID: "d",
				Location:  "US",
				ClientOptions: []option.ClientOption{
					option.WithEndpoint(srv.URL + "/bigquery/v2/"),
					option.WithoutAuthentication(),
				},
			},
			"otel_logs",
			httpLayers,
		)
		if !strings.Contains(httpLayers.BQStorageQueryNote, "HTTP 403") {
			t.Fatalf("BQStorageQueryNote = %q, want 'HTTP 403'", httpLayers.BQStorageQueryNote)
		}
		assertNoLeaks(t, httpLayers.BQStorageQueryNote, []string{"SECRET_SERVER_BODY_LEAK", "secret-token.invalid", "access_token=abc"})
	})
}

func TestBuildLiveRESTClientOptionsWithoutAuthIgnoresPoisonedADC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	badADC := filepath.Join(t.TempDir(), "bad-adc-should-not-read.json")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", badADC)
	t.Setenv("GCE_METADATA_HOST", "127.0.0.1:1")

	var gotAuthHeaders []string
	var mu sync.Mutex
	adminSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuthHeaders = append(gotAuthHeaders, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/test_ds"):
			_ = json.NewEncoder(w).Encode(&bigqueryapi.Dataset{
				DatasetReference: &bigqueryapi.DatasetReference{ProjectId: "test-proj", DatasetId: "test_ds"},
				Location:         "US",
			})
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/queries"):
			_ = json.NewEncoder(w).Encode(&bigqueryapi.QueryResponse{
				JobComplete: true,
				Schema: &bigqueryapi.TableSchema{
					Fields: []*bigqueryapi.TableFieldSchema{
						{Name: "total_rows", Type: "INTEGER"},
						{Name: "total_logical_bytes", Type: "INTEGER"},
						{Name: "active_physical_bytes", Type: "INTEGER"},
						{Name: "long_term_physical_bytes", Type: "INTEGER"},
						{Name: "time_travel_physical_bytes", Type: "INTEGER"},
						{Name: "fail_safe_physical_bytes", Type: "INTEGER"},
					},
				},
				Rows: []*bigqueryapi.TableRow{{F: []*bigqueryapi.TableCell{
					{V: "100"}, {V: "20000"}, {V: "5000"}, {V: "0"}, {V: "1000"}, {V: "500"},
				}}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer adminSrv.Close()

	layers := &ByteLayersSummary{ProtoRowsBytesPerRow: 100}
	populateLiveTableStorageWithCollectorOptions(
		ctx,
		RunnerConfig{Mode: ModeLive, ProjectID: "test-proj", DatasetID: "test_ds"},
		"otel_logs",
		&bigqueryexporter.EndpointConfig{
			URL:                   "127.0.0.1:44321",
			AdminURL:              adminSrv.URL + "/bigquery/v2/",
			Insecure:              true,
			WithoutAuthentication: true,
		},
		&bigqueryexporter.CredentialsConfig{
			File: badADC,
		},
		layers,
	)
	if layers.BQStorageQueryNote != "" || layers.BQTotalRows != 100 || layers.BQLogicalBytes != 20000 {
		t.Fatalf("unexpected TABLE_STORAGE result: %+v", layers)
	}
	mu.Lock()
	headers := slices.Clone(gotAuthHeaders)
	mu.Unlock()
	if len(headers) < 2 {
		t.Fatalf("expected >= 2 REST calls (dataset metadata + query), got %d", len(headers))
	}
	for i, authHdr := range headers {
		if authHdr != "" {
			t.Fatalf("REST call %d unexpectedly sent Authorization header %q under without_authentication=true", i, authHdr)
		}
	}
}

func findProtoFieldNumber(t *testing.T, desc *descriptorpb.DescriptorProto, name string) protowire.Number {
	t.Helper()
	for _, f := range desc.GetField() {
		if f.GetName() == name {
			return protowire.Number(f.GetNumber())
		}
	}
	t.Fatalf("field %q not found in descriptor %s", name, desc.GetName())
	return 0
}

func bumpProtoVarintField(t *testing.T, raw []byte, targetNum protowire.Number, delta int64) []byte {
	t.Helper()
	var out []byte
	found := false
	b := raw
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			t.Fatalf("protowire.ConsumeTag: %v", protowire.ParseError(tagLen))
		}
		valLen := protowire.ConsumeFieldValue(num, typ, b[tagLen:])
		if valLen < 0 {
			t.Fatalf("protowire.ConsumeFieldValue: %v", protowire.ParseError(valLen))
		}
		fieldBytes := b[:tagLen+valLen]
		b = b[tagLen+valLen:]
		if num == targetNum && typ == protowire.VarintType {
			v, vLen := protowire.ConsumeVarint(fieldBytes[tagLen:])
			if vLen < 0 {
				t.Fatalf("protowire.ConsumeVarint: %v", protowire.ParseError(vLen))
			}
			out = protowire.AppendTag(out, num, protowire.VarintType)
			out = protowire.AppendVarint(out, uint64(int64(v)+delta))
			found = true
			continue
		}
		out = append(out, fieldBytes...)
	}
	if !found {
		out = protowire.AppendTag(out, targetNum, protowire.VarintType)
		out = protowire.AppendVarint(out, uint64(DefaultBaseTime.UnixNano()+delta))
	}
	return out
}

func encodeRogueSubstitutionLogRow(t *testing.T, logEnc *protoenc.Encoder, insertID string) []byte {
	t.Helper()
	rogueTS := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	raw, err := logEnc.Encode(transform.Row{
		"timestamp":               rogueTS.UnixMicro(),
		"timestamp_source":        "event",
		"time_unix_nano":          rogueTS.UnixNano(),
		"observed_time_unix_nano": rogueTS.UnixNano(),
		"receive_time":            rogueTS.UnixMicro(),
		"receive_time_unix_nano":  rogueTS.UnixNano(),
		"severity_number":         int64(9),
		"service_name":            "rogue-service",
		"log_name":                "rogue-log",
		"insert_id":               insertID,
		"body":                    `"rogue"`,
	})
	if err != nil {
		t.Fatalf("encode rogue log row: %v", err)
	}
	return raw
}

func TestModeBQFakeObservedTimeReplayAndSubstitutionFailsLossless(t *testing.T) {
	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	obsFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "observed_time_unix_nano")

	for _, upstreamInsertID := range []bool{true, false} {
		t.Run(fmt.Sprintf("ObservedTimeReplay_upstreamInsertID=%t", upstreamInsertID), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table == "otel_logs" && len(serialized) == 4 {
					mut := slices.Clone(serialized)
					mut[3] = bumpProtoVarintField(t, serialized[0], obsFieldNum, 1_000_000)
					return mut
				}
				return serialized
			})

			cfg := RunnerConfig{
				Mode:             ModeBQFake,
				Signals:          []string{"logs"},
				WorkloadProfile:  WorkloadProfileAccessLogs,
				Workers:          1,
				BatchSize:        4,
				maxBatches:       1,
				Duration:         5 * time.Second,
				UpstreamInsertID: upstreamInsertID,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 {
				t.Fatalf("submitted=%d acked=%d, want 4/4", res.RecordsSubmitted, res.Telemetry.AcknowledgedRows)
			}
			if !res.UniqueDeliveryVerified || res.DeliveredRows != 3 || res.Telemetry.ReplayedRows != 1 {
				t.Fatalf("verified=%v delivered=%d replayed=%d, want true/3/1",
					res.UniqueDeliveryVerified, res.DeliveredRows, res.Telemetry.ReplayedRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 0 {
				t.Fatalf("missing=%d unexpected=%d, want 1/0", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "delivered=3") || !strings.Contains(lossErr.Error(), "replayed=1") || !strings.Contains(lossErr.Error(), "missing=1") {
				t.Fatalf("checkSignalResultLossless = %v, want delivered=3, replayed=1, missing=1", lossErr)
			}
		})

		t.Run(fmt.Sprintf("RowSubstitution_upstreamInsertID=%t", upstreamInsertID), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			rogueInsertID := "rogue-subst-99"
			if !upstreamInsertID {
				rogueInsertID = "id1:0000000000000000"
			}
			rogueRow := encodeRogueSubstitutionLogRow(t, logEnc, rogueInsertID)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table == "otel_logs" && len(serialized) == 4 {
					mut := slices.Clone(serialized)
					mut[3] = rogueRow
					return mut
				}
				return serialized
			})

			cfg := RunnerConfig{
				Mode:             ModeBQFake,
				Signals:          []string{"logs"},
				WorkloadProfile:  WorkloadProfileAccessLogs,
				Workers:          1,
				BatchSize:        4,
				maxBatches:       1,
				Duration:         5 * time.Second,
				UpstreamInsertID: upstreamInsertID,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if res.RecordsSubmitted != 4 || res.Telemetry.AcknowledgedRows != 4 || res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
				t.Fatalf("submitted=%d acked=%d delivered=%d replayed=%d, want 4/4/4/0",
					res.RecordsSubmitted, res.Telemetry.AcknowledgedRows, res.DeliveredRows, res.Telemetry.ReplayedRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 1 {
				t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
			}
		})
	}
}

func mutateProtoStringField(t *testing.T, raw []byte, targetNum protowire.Number, transformFn func(string) string) []byte {
	t.Helper()
	var out []byte
	found := false
	b := raw
	for len(b) > 0 {
		num, typ, tagLen := protowire.ConsumeTag(b)
		if tagLen < 0 {
			t.Fatalf("protowire.ConsumeTag: %v", protowire.ParseError(tagLen))
		}
		valLen := protowire.ConsumeFieldValue(num, typ, b[tagLen:])
		if valLen < 0 {
			t.Fatalf("protowire.ConsumeFieldValue: %v", protowire.ParseError(valLen))
		}
		fieldBytes := b[:tagLen+valLen]
		b = b[tagLen+valLen:]
		if num == targetNum && typ == protowire.BytesType {
			s, sLen := protowire.ConsumeString(fieldBytes[tagLen:])
			if sLen < 0 {
				t.Fatalf("protowire.ConsumeString: %v", protowire.ParseError(sLen))
			}
			out = protowire.AppendTag(out, num, protowire.BytesType)
			out = protowire.AppendString(out, transformFn(s))
			found = true
			continue
		}
		out = append(out, fieldBytes...)
	}
	if !found {
		t.Fatalf("string field %d not present in serialized row", targetNum)
	}
	return out
}

func flipLastTagChar(s string) string {
	if s == "" {
		return "mutated"
	}
	b := []byte(s)
	if b[len(b)-1] == '0' {
		b[len(b)-1] = '1'
	} else {
		b[len(b)-1] = '0'
	}
	return string(b)
}

func TestModeBQFakeMutatedInsertIDAndMetricFingerprintFailsLossless(t *testing.T) {
	logEnc, err := protoenc.New(schema.LogsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
	}
	insertIDFieldNum := findProtoFieldNumber(t, logEnc.Descriptor(), "insert_id")

	metricEnc, err := protoenc.New(schema.MetricsTableSchema())
	if err != nil {
		t.Fatalf("protoenc.New(MetricsTableSchema): %v", err)
	}
	fpFieldNum := findProtoFieldNumber(t, metricEnc.Descriptor(), "point_fingerprint")

	for _, redaction := range []bool{false, true} {
		t.Run(fmt.Sprintf("MutatedSynthesizedInsertID_redaction=%t", redaction), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table == "otel_logs" && len(serialized) == 4 {
					mut := slices.Clone(serialized)
					mut[3] = mutateProtoStringField(t, serialized[3], insertIDFieldNum, flipLastTagChar)
					return mut
				}
				return serialized
			})

			cfg := RunnerConfig{
				Mode:             ModeBQFake,
				Signals:          []string{"logs"},
				WorkloadProfile:  WorkloadProfileAccessLogs,
				Workers:          1,
				BatchSize:        4,
				maxBatches:       1,
				Duration:         5 * time.Second,
				Redaction:        redaction,
				UpstreamInsertID: false,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
				t.Fatalf("delivered=%d replayed=%d, want 4/0", res.DeliveredRows, res.Telemetry.ReplayedRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 1 {
				t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
			}
		})

		t.Run(fmt.Sprintf("MutatedMetricPointFingerprint_redaction=%t", redaction), func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)
			fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
				if table == "otel_metrics" && len(serialized) == 4 {
					mut := slices.Clone(serialized)
					mut[3] = mutateProtoStringField(t, serialized[3], fpFieldNum, flipLastTagChar)
					return mut
				}
				return serialized
			})

			cfg := RunnerConfig{
				Mode:       ModeBQFake,
				Signals:    []string{"metrics"},
				Workers:    1,
				BatchSize:  4,
				maxBatches: 1,
				Duration:   5 * time.Second,
				Redaction:  redaction,
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "metrics", fakeSrv)
			if hardErr != nil {
				t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
			}
			if res.DeliveredRows != 4 || res.Telemetry.ReplayedRows != 0 {
				t.Fatalf("delivered=%d replayed=%d, want 4/0", res.DeliveredRows, res.Telemetry.ReplayedRows)
			}
			if res.MissingRows != 1 || res.UnexpectedRows != 1 {
				t.Fatalf("missing=%d unexpected=%d, want 1/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, "metrics", res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "missing=1") || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless = %v, want missing=1, unexpected=1", lossErr)
			}
		})
	}
}

func TestCheckSignalResultLosslessRejectsExtraAcksWithoutFaultInjection(t *testing.T) {
	baseRes := SignalResult{
		Signal:                 "logs",
		Mode:                   ModeCollector,
		BatchesAttempted:       1,
		BatchesSucceeded:       1,
		RecordsSubmitted:       4,
		DeliveredRows:          4,
		UniqueDeliveryVerified: true,
		Latency:                LatencySummary{Samples: 1},
		Telemetry: TelemetrySnapshot{
			AcknowledgedRows: 5,
			ReplayedRows:     0,
		},
	}

	for _, verified := range []bool{true, false} {
		for _, mode := range []string{ModeCollector, ModeBQFake} {
			res := baseRes
			res.UniqueDeliveryVerified = verified
			res.Mode = mode
			cfg := RunnerConfig{Mode: mode, Signals: []string{"logs"}}
			err := checkSignalResultLossless(cfg, "logs", res, nil)
			if err == nil || !strings.Contains(err.Error(), "acked=5") {
				t.Fatalf("verified=%v mode=%s: checkSignalResultLossless = %v, want strict mismatch error citing acked=5", verified, mode, err)
			}

			okRes := res
			okRes.Telemetry.AcknowledgedRows = 4
			if okErr := checkSignalResultLossless(cfg, "logs", okRes, nil); okErr != nil {
				t.Fatalf("verified=%v mode=%s: expected nil when acked==submitted==4, got %v", verified, mode, okErr)
			}
		}
	}

	// With fault simulation ON and UniqueDeliveryVerified=true, acked must be bounded to [submitted, delivered+replayed].
	faultCfg := RunnerConfig{Mode: ModeCollector, Signals: []string{"logs"}, SimulateThrottleEvery: 1}
	extraAckNoReplay := baseRes
	extraAckNoReplay.UniqueDeliveryVerified = true
	if err := checkSignalResultLossless(faultCfg, "logs", extraAckNoReplay, nil); err == nil || !strings.Contains(err.Error(), "acked=5") {
		t.Fatalf("FaultSimExtraAckWithoutReplay: checkSignalResultLossless = %v, want strict mismatch citing acked=5", err)
	}

	underAck := baseRes
	underAck.UniqueDeliveryVerified = true
	underAck.Telemetry.AcknowledgedRows = 3
	underAck.Telemetry.ReplayedRows = 1
	if err := checkSignalResultLossless(faultCfg, "logs", underAck, nil); err == nil || !strings.Contains(err.Error(), "acked=3") {
		t.Fatalf("FaultSimUnderAck: checkSignalResultLossless = %v, want strict mismatch citing acked=3", err)
	}

	withinCommitsUnobserved := baseRes
	withinCommitsUnobserved.UniqueDeliveryVerified = true
	withinCommitsUnobserved.Telemetry.AcknowledgedRows = 5
	withinCommitsUnobserved.Telemetry.ReplayedRows = 1
	if err := checkSignalResultLossless(faultCfg, "logs", withinCommitsUnobserved, nil); err == nil {
		t.Fatal("FaultSimAckWithinRawCommits(retries=0, uncertain=0): unexpected nil error")
	}

	withinCommits := withinCommitsUnobserved
	withinCommits.ObservedUncertainCommitFaults = 1
	withinCommits.ObservedUncertainCommitRows = 1
	withinCommits.Telemetry.Retries = 1
	if err := checkSignalResultLossless(faultCfg, "logs", withinCommits, nil); err != nil {
		t.Fatalf("FaultSimAckWithinRawCommits: unexpected error %v", err)
	}
}

func TestWarmupReplayInSteadyStateFailsStrictGateWithFaultSim(t *testing.T) {
	for _, signal := range []string{"traces", "logs", "metrics"} {
		t.Run(signal, func(t *testing.T) {
			fakeSrv := bqfake.NewServer(t)
			fakeSrv.SetDiscardRows(true)

			var (
				mu            sync.Mutex
				savedWarmup   []byte
				warmupSeqSeen atomic.Bool
				inSteady      atomic.Bool
				injected      atomic.Bool
			)
			fakeSrv.SetBeforeCommitHook(func(_ string, serialized [][]byte) [][]byte {
				if len(serialized) == 0 {
					return serialized
				}
				mu.Lock()
				defer mu.Unlock()
				if !inSteady.Load() {
					if savedWarmup == nil {
						savedWarmup = slices.Clone(serialized[0])
					}
					return serialized
				}
				if savedWarmup != nil && !injected.Swap(true) {
					out := slices.Clone(serialized)
					return append(out, slices.Clone(savedWarmup))
				}
				return serialized
			})

			cfg := RunnerConfig{
				Mode:                  ModeBQFake,
				Signals:               []string{signal},
				WorkloadProfile:       WorkloadProfileAccessLogs,
				Workers:               1,
				BatchSize:             2,
				TargetRate:            20,
				WarmupDuration:        150 * time.Millisecond,
				Duration:              250 * time.Millisecond,
				SimulateThrottleEvery: 1,
				SimulateAckDelay:      time.Millisecond,
				workerHook: func(_ int, seq int) {
					if seq == 1 {
						if !warmupSeqSeen.CompareAndSwap(false, true) {
							inSteady.Store(true)
						}
					}
				},
			}
			if signal != "logs" {
				cfg.WorkloadProfile = WorkloadProfileGenAIMixed
			}
			if err := cfg.Normalize(); err != nil {
				t.Fatalf("Normalize: %v", err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, signal, fakeSrv)
			if hardErr != nil {
				t.Fatalf("runSingleSignalWithFake(%s) hardErr = %v, want nil", signal, hardErr)
			}
			if !injected.Load() {
				t.Fatalf("warmup replay injection hook never fired during steady state for %s", signal)
			}
			if res.UnexpectedRows != 1 || res.MissingRows != 0 {
				t.Fatalf("missing=%d unexpected=%d, want 0/1", res.MissingRows, res.UnexpectedRows)
			}
			lossErr := checkSignalResultLossless(cfg, signal, res, softErr)
			if lossErr == nil || !strings.Contains(lossErr.Error(), "unexpected=1") {
				t.Fatalf("checkSignalResultLossless(%s, faultSim=true) = %v, want strict failure citing unexpected=1", signal, lossErr)
			}
		})
	}
}

func TestEffectiveUniqueSaturatedLimitUsesExactBreachedLimit(t *testing.T) {
	fakeSrv := bqfake.NewServer(t)

	// Snapshot NULL-ID saturation (2,000,000) must beat tagged chunk cap (16,777,216).
	snapSat := bqfake.TableStatsSnapshot{
		UniqueSaturated:      true,
		UniqueSaturatedLimit: bqfake.DefaultMaxUniqueAckedRows,
		UniqueSaturatedUnit:  bqfake.SaturationUnitRows,
	}
	if got, unit := effectiveUniqueSaturatedLimit(fakeSrv, "otel_logs", "logs", true, snapSat, bqfake.ReconciliationResult{}); got != bqfake.DefaultMaxUniqueAckedRows || unit != bqfake.SaturationUnitRows {
		t.Fatalf("snapshot limit = (%d, %q), want (%d, %q)", got, unit, bqfake.DefaultMaxUniqueAckedRows, bqfake.SaturationUnitRows)
	}

	// Reconciliation-only saturation (e.g. phaseSubmitted.saturatedLimit = 2,000,000) must beat tagged cap.
	recSat := bqfake.ReconciliationResult{
		Saturated:      true,
		SaturatedLimit: bqfake.DefaultMaxUniqueAckedRows,
		SaturatedUnit:  bqfake.SaturationUnitRows,
	}
	if got, unit := effectiveUniqueSaturatedLimit(fakeSrv, "otel_logs", "logs", true, bqfake.TableStatsSnapshot{}, recSat); got != bqfake.DefaultMaxUniqueAckedRows || unit != bqfake.SaturationUnitRows {
		t.Fatalf("reconcile limit = (%d, %q), want (%d, %q)", got, unit, bqfake.DefaultMaxUniqueAckedRows, bqfake.SaturationUnitRows)
	}

	// Tag byte-budget saturation (268,435,456) carries "tag bytes" unit, never "unique rows".
	byteBudget := 256 * 1024 * 1024
	byteSat := bqfake.TableStatsSnapshot{
		UniqueSaturated:      true,
		UniqueSaturatedLimit: byteBudget,
		UniqueSaturatedUnit:  bqfake.SaturationUnitTagBytes,
	}
	if got, unit := effectiveUniqueSaturatedLimit(fakeSrv, "otel_logs", "logs", true, byteSat, recSat); got != byteBudget || unit != bqfake.SaturationUnitTagBytes {
		t.Fatalf("byte-budget limit = (%d, %q), want (%d, %q)", got, unit, byteBudget, bqfake.SaturationUnitTagBytes)
	}

	// End-to-end ModeBQFake saturation with custom 3-row limit on tagged logs must report 3 (not 16,777,216).
	satSrv := bqfake.NewServer(t)
	satSrv.SetDiscardRows(true)
	satSrv.SetMaxUniqueAckedRows(3)
	cfg := RunnerConfig{
		Mode:            ModeBQFake,
		WorkloadProfile: WorkloadProfileAccessLogs,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       4,
		maxBatches:      1,
		Duration:        5 * time.Second,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, _, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", satSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "at 3 unique rows") || strings.Contains(hardErr.Error(), "16777216") {
		t.Fatalf("runSingleSignalWithFake saturation err = %v, want exact limit 3 (not 16777216)", hardErr)
	}
}

func TestRunModeBQFakeWarmupDuplicateCommitFailsStrictMode(t *testing.T) {
	satSrv := bqfake.NewServer(t)
	satSrv.SetDiscardRows(true)

	var (
		mu    sync.Mutex
		duped bool
	)
	satSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
		if table != "otel_logs" || len(serialized) == 0 {
			return serialized
		}
		mu.Lock()
		defer mu.Unlock()
		if !duped {
			duped = true
			out := make([][]byte, len(serialized)+1)
			copy(out, serialized)
			out[len(serialized)] = serialized[0]
			return out
		}
		return serialized
	})

	cfg := RunnerConfig{
		Mode:            ModeBQFake,
		WorkloadProfile: WorkloadProfileAccessLogs,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       4,
		TargetRate:      4,
		WarmupDuration:  400 * time.Millisecond,
		Duration:        250 * time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	_, _, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", satSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "warmup failed gate") || !strings.Contains(hardErr.Error(), "replayed=1") {
		t.Fatalf("runSingleSignalWithFake(warmup duplicate commit) hardErr = %v, want warmup gate failure citing replayed=1", hardErr)
	}
}

func TestValidateRunConfigAdminURLConflictRedactsURLValues(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "conflict-admin.yaml")
	const (
		secretURLTraces = "https://alice:top_secret_pw1@psc-traces.internal.example/bigquery/v2?token=signed_tok_alpha"
		secretURLLogs   = "https://bob:top_secret_pw2@psc-logs.internal.example/bigquery/v2?sig=signed_tok_beta"
	)
	rawYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery/traces:
    project: my-gcp-proj
    dataset: otel_bench
    location: US
    endpoint:
      url: bigquerystorage.googleapis.com:443
      admin_url: %q
  bigquery/logs:
    project: my-gcp-proj
    dataset: otel_bench
    location: US
    endpoint:
      url: bigquerystorage.googleapis.com:443
      admin_url: %q
service:
  extensions: [health_check]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
`, secretURLTraces, secretURLLogs)
	if err := os.WriteFile(cfgPath, []byte(rawYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg := RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       os.Args[0],
		CollectorConfig:    cfgPath,
		ProjectID:          "my-gcp-proj",
		DatasetID:          "otel_bench",
		Signals:            []string{"traces", "logs"},
		Workers:            1,
		BatchSize:          2,
		Duration:           time.Second,
	}
	err := validateRunConfig(t.Context(), &cfg, []int{1})
	if err == nil {
		t.Fatal("validateRunConfig succeeded, want conflicting collector endpoint.admin_url error")
	}
	msg := err.Error()
	for _, want := range []string{"conflicting collector endpoint.admin_url across signals", `"traces"`, `"logs"`} {
		if !strings.Contains(msg, want) {
			t.Fatalf("error %q missing expected signal/field context %q", msg, want)
		}
	}
	for _, forbidden := range []string{
		"alice", "bob", "top_secret_pw1", "top_secret_pw2",
		"psc-traces.internal.example", "psc-logs.internal.example",
		"signed_tok_alpha", "signed_tok_beta", "https://",
	} {
		if strings.Contains(msg, forbidden) {
			t.Fatalf("error leaked sensitive admin_url content %q: %s", forbidden, msg)
		}
	}
}

func TestComputeFakePhaseDeliveryStatsNullIDRepeatHandling(t *testing.T) {
	// 1. Fault-enabled run: 4 submitted NULL-ID rows committed twice via retry (8 rows, 4 repeats).
	d, b, r, u := computeFakePhaseDeliveryStats(
		8, 8, 1600,
		4, 800,
		bqfake.ReconciliationResult{SubmittedRows: 4, MatchedRows: 4, ReplayedNullIDRows: 4},
		true, true,
	)
	if d != 4 || b != 800 || r != 4 || u != 0 {
		t.Fatalf("fault replay stats = (%d, %d, %d, %d), want (4, 800, 4, 0)", d, b, r, u)
	}

	// 2. Non-fault run: extra NULL-ID commits count as unexpected delivered rows, not fault replays.
	d, b, r, u = computeFakePhaseDeliveryStats(
		5, 5, 1000,
		1, 200,
		bqfake.ReconciliationResult{SubmittedRows: 4, MatchedRows: 4, ReplayedNullIDRows: 1},
		true, false,
	)
	if d != 5 || b != 1000 || r != 0 || u != 1 {
		t.Fatalf("non-fault duplicate stats = (%d, %d, %d, %d), want (5, 1000, 0, 1)", d, b, r, u)
	}

	// 3. Intentionally repeated submitted payloads (8 total: 4 distinct + 4 intentional repeats)
	// plus 4 fault replays => NullIDRepeatRows=8, ReplayedNullIDRows=4, scaled subtraction=800.
	d, b, r, u = computeFakePhaseDeliveryStats(
		12, 12, 2400,
		8, 1600,
		bqfake.ReconciliationResult{SubmittedRows: 8, MatchedRows: 8, ReplayedNullIDRows: 4},
		true, true,
	)
	if d != 8 || b != 1600 || r != 4 || u != 0 {
		t.Fatalf("scaled repeat stats = (%d, %d, %d, %d), want (8, 1600, 4, 0)", d, b, r, u)
	}

	// 4. Unreconciled phase falls back cleanly to table-level NullIDRepeatRows/Bytes.
	d, b, r, u = computeFakePhaseDeliveryStats(
		8, 8, 1600,
		4, 800,
		bqfake.ReconciliationResult{},
		false, true,
	)
	if d != 4 || b != 800 || r != 4 || u != 0 {
		t.Fatalf("unreconciled fallback stats = (%d, %d, %d, %d), want (4, 800, 4, 0)", d, b, r, u)
	}

	// 5. Cross-phase warmup NULL-ID replay during fault-simulated steady phase:
	// warmup row was not submitted in steady state (so ReplayedNullIDRows=0, UnexpectedRows=1),
	// while table-level NullIDRepeatRows=1, NullIDRepeatBytes=200. Fault-sim mode must subtract
	// the unsubmitted repeat from DeliveredRows/Bytes and attribute it to ReplayedRows=1.
	d, b, r, u = computeFakePhaseDeliveryStats(
		5, 5, 1000,
		1, 200,
		bqfake.ReconciliationResult{SubmittedRows: 4, MatchedRows: 4, ReplayedNullIDRows: 0, UnexpectedRows: 1},
		true, true,
	)
	if d != 4 || b != 800 || r != 1 || u != 1 {
		t.Fatalf("cross-phase warmup NULL-ID replay (faultSim=true) = (%d, %d, %d, %d), want (4, 800, 1, 1)", d, b, r, u)
	}

	// 6. Combined intentional steady repeats (8 submitted: 4 distinct + 4 intentional) + 4 fault
	// replays + 1 warmup NULL-ID replay => NullIDRepeatRows=9, ReplayedNullIDRows=4, UnexpectedRows=1.
	d, b, r, u = computeFakePhaseDeliveryStats(
		13, 13, 2600,
		9, 1800,
		bqfake.ReconciliationResult{SubmittedRows: 8, MatchedRows: 8, ReplayedNullIDRows: 4, UnexpectedRows: 1},
		true, true,
	)
	if d != 8 || b != 1600 || r != 5 || u != 1 {
		t.Fatalf("combined intentional+fault+warmup NULL-ID replay = (%d, %d, %d, %d), want (8, 1600, 5, 1)", d, b, r, u)
	}

	// 7. Cross-phase warmup NULL-ID replay without fault simulation preserves physical accounting.
	d, b, r, u = computeFakePhaseDeliveryStats(
		5, 5, 1000,
		1, 200,
		bqfake.ReconciliationResult{SubmittedRows: 4, MatchedRows: 4, ReplayedNullIDRows: 0, UnexpectedRows: 1},
		true, false,
	)
	if d != 5 || b != 1000 || r != 0 || u != 1 {
		t.Fatalf("cross-phase warmup NULL-ID replay (faultSim=false) = (%d, %d, %d, %d), want (5, 1000, 0, 1)", d, b, r, u)
	}
}

func TestModeBQFakeWarmupNullIDReplayInSteadyStateStatsAndGate(t *testing.T) {
	runWithWarmupNullReplay := func(t *testing.T, allowPartial bool) (SignalResult, error, error) {
		t.Helper()
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)

		var (
			mu            sync.Mutex
			savedWarmup   []byte
			warmupSeqSeen atomic.Bool
			inSteady      atomic.Bool
			injected      atomic.Bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			mu.Lock()
			defer mu.Unlock()
			if !inSteady.Load() {
				if savedWarmup == nil {
					savedWarmup = slices.Clone(serialized[0])
				}
				return serialized
			}
			if savedWarmup != nil && !injected.Swap(true) {
				out := slices.Clone(serialized)
				return append(out, slices.Clone(savedWarmup))
			}
			return serialized
		})

		cfg := RunnerConfig{
			Mode:                  ModeBQFake,
			Signals:               []string{"logs"},
			WorkloadProfile:       WorkloadProfileAccessLogs,
			UpstreamInsertID:      false, // NULL-insert_id logs (synthesized_insert_id=false in runner)
			Workers:               1,
			BatchSize:             2,
			maxBatches:            2,
			TargetRate:            20,
			WarmupDuration:        150 * time.Millisecond,
			Duration:              500 * time.Millisecond,
			SimulateThrottleEvery: 1,
			SimulateAckDelay:      time.Millisecond,
			AllowPartialFailures:  allowPartial,
			workerHook: func(_ int, seq int) {
				if seq == 1 {
					if !warmupSeqSeen.CompareAndSwap(false, true) {
						inSteady.Store(true)
					}
				}
			},
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()
		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if !injected.Load() {
			t.Fatal("warmup NULL-ID replay injection hook never fired in steady state")
		}
		return res, softErr, hardErr
	}

	t.Run("StrictGateFailsOnUnexpectedWarmupNullIDRow", func(t *testing.T) {
		res, softErr, _ := runWithWarmupNullReplay(t, false)
		if res.DeliveredRows != res.RecordsSubmitted || res.UnexpectedRows != 1 || res.Telemetry.ReplayedRows < 1 {
			t.Fatalf("delivered=%d submitted=%d unexpected=%d replayed=%d, want delivered==submitted unexpected=1 replayed>=1",
				res.DeliveredRows, res.RecordsSubmitted, res.UnexpectedRows, res.Telemetry.ReplayedRows)
		}
		strictCfg := RunnerConfig{
			Mode:                  ModeBQFake,
			Signals:               []string{"logs"},
			SimulateThrottleEvery: 1,
			SimulateAckDelay:      time.Millisecond,
			AllowPartialFailures:  false,
		}
		lossErr := checkSignalResultLossless(strictCfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "unexpected=1") {
			t.Fatalf("checkSignalResultLossless = %v, want strict failure citing unexpected=1", lossErr)
		}
	})

	t.Run("AllowPartialFailuresSeparatesDeliveredAndReplayedStats", func(t *testing.T) {
		res, _, _ := runWithWarmupNullReplay(t, true)
		if res.RecordsSubmitted != 4 || res.DeliveredRows != 4 || res.UnexpectedRows != 1 || res.Telemetry.ReplayedRows != 1 {
			t.Fatalf("submitted=%d delivered=%d unexpected=%d replayed=%d, want 4/4/1/1",
				res.RecordsSubmitted, res.DeliveredRows, res.UnexpectedRows, res.Telemetry.ReplayedRows)
		}
	})
}

func TestStampTracesPreservesSpanDurationAndEventOffsets(t *testing.T) {
	base := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	gen := NewGenerator(GeneratorConfig{
		WorkloadProfile: WorkloadProfileGenAIMixed,
		PayloadBytes:    256,
	})

	// 1. Generated 42ms spans preserve exact 42ms duration and signed event offsets across reuses.
	td := gen.TracesBatch(8)
	type spanBaseline struct {
		wantDur      time.Duration
		eventOffsets []int64
	}
	baselines := make(map[string]spanBaseline)
	for i := 0; i < td.ResourceSpans().Len(); i++ {
		sss := td.ResourceSpans().At(i).ScopeSpans()
		for j := 0; j < sss.Len(); j++ {
			spans := sss.At(j).Spans()
			for k := 0; k < spans.Len(); k++ {
				sp := spans.At(k)
				start := sp.StartTimestamp().AsTime()
				evBefore := sp.Events().AppendEmpty()
				evBefore.SetName("pre_start")
				evBefore.SetTimestamp(pcommon.NewTimestampFromTime(start.Add(-3 * time.Millisecond)))
				evAfter := sp.Events().AppendEmpty()
				evAfter.SetName("mid_span")
				evAfter.SetTimestamp(pcommon.NewTimestampFromTime(start.Add(11 * time.Millisecond)))

				offsets := make([]int64, sp.Events().Len())
				for eIdx := 0; eIdx < sp.Events().Len(); eIdx++ {
					offsets[eIdx] = int64(sp.Events().At(eIdx).Timestamp()) - int64(sp.StartTimestamp())
				}
				baselines[fmt.Sprintf("%d:%d:%d", i, j, k)] = spanBaseline{
					wantDur:      time.Duration(sp.EndTimestamp() - sp.StartTimestamp()),
					eventOffsets: offsets,
				}
			}
		}
	}

	assertDurationAndEvents := func(t *testing.T, batch ptrace.Traces, wantDur time.Duration) {
		t.Helper()
		rss := batch.ResourceSpans()
		for i := 0; i < rss.Len(); i++ {
			sss := rss.At(i).ScopeSpans()
			for j := 0; j < sss.Len(); j++ {
				spans := sss.At(j).Spans()
				for k := 0; k < spans.Len(); k++ {
					sp := spans.At(k)
					want := baselines[fmt.Sprintf("%d:%d:%d", i, j, k)]
					gotDur := time.Duration(sp.EndTimestamp() - sp.StartTimestamp())
					if gotDur != wantDur || gotDur != want.wantDur {
						t.Fatalf("span %q duration = %v, want %v", sp.Name(), gotDur, wantDur)
					}
					evs := sp.Events()
					if evs.Len() != len(want.eventOffsets) {
						t.Fatalf("span %q events len = %d, want %d", sp.Name(), evs.Len(), len(want.eventOffsets))
					}
					for eIdx, wantOff := range want.eventOffsets {
						gotOff := int64(evs.At(eIdx).Timestamp()) - int64(sp.StartTimestamp())
						if gotOff != wantOff {
							t.Fatalf("span %q event[%d] offset = %d ns, want %d ns", sp.Name(), eIdx, gotOff, wantOff)
						}
					}
				}
			}
		}
	}

	var fallbackSeq atomic.Uint64
	for _, delta := range []uint64{100, 200, 300} {
		stampTracesTreeEpoch(td, base, 7, delta, &fallbackSeq)
		assertDurationAndEvents(t, td, 42*time.Millisecond)
	}
	stampFreshTracesIdentity(td, base.Add(time.Hour), 50)
	assertDurationAndEvents(t, td, 42*time.Millisecond)

	// 2. Non-tree fallback spans and custom span durations (137ms, unset/pre-start events)
	// also shift cleanly without overwriting duration or underflowing timestamps.
	customTD := ptrace.NewTraces()
	customSp := customTD.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	customStart := time.Date(2026, 5, 1, 13, 0, 0, 0, time.UTC)
	customSp.SetName("custom_non_tree")
	customSp.SetStartTimestamp(pcommon.NewTimestampFromTime(customStart))
	customSp.SetEndTimestamp(pcommon.NewTimestampFromTime(customStart.Add(137 * time.Millisecond)))
	evPre := customSp.Events().AppendEmpty()
	evPre.SetTimestamp(pcommon.NewTimestampFromTime(customStart.Add(-7 * time.Millisecond)))
	evMid := customSp.Events().AppendEmpty()
	evMid.SetTimestamp(pcommon.NewTimestampFromTime(customStart.Add(55 * time.Millisecond)))
	evUnset := customSp.Events().AppendEmpty()
	evUnset.SetTimestamp(0)

	stampTracesTreeEpoch(customTD, base, 7, 10, &fallbackSeq)
	if gotDur := time.Duration(customSp.EndTimestamp() - customSp.StartTimestamp()); gotDur != 137*time.Millisecond {
		t.Fatalf("custom fallback span duration = %v, want 137ms", gotDur)
	}
	wantNewStart := customSp.StartTimestamp()
	if customSp.Events().At(0).Timestamp() != wantNewStart-pcommon.Timestamp((7*time.Millisecond).Nanoseconds()) {
		t.Fatalf("custom fallback pre-start event = %d, want start-7ms", customSp.Events().At(0).Timestamp())
	}
	if customSp.Events().At(1).Timestamp() != wantNewStart+pcommon.Timestamp((55*time.Millisecond).Nanoseconds()) {
		t.Fatalf("custom fallback mid event = %d, want start+55ms", customSp.Events().At(1).Timestamp())
	}
	if customSp.Events().At(2).Timestamp() != wantNewStart+pcommon.Timestamp((22*time.Millisecond).Nanoseconds()) {
		t.Fatalf("custom fallback unset event = %d, want start+22ms", customSp.Events().At(2).Timestamp())
	}

	// Guard uint64 underflow if newStart is smaller than the negative event offset.
	zeroTS := ptrace.NewTraces()
	zSp := zeroTS.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	zSp.SetStartTimestamp(pcommon.NewTimestampFromTime(time.Unix(10, 0).UTC()))
	zSp.SetEndTimestamp(pcommon.NewTimestampFromTime(time.Unix(10, 0).UTC().Add(50 * time.Millisecond)))
	zEv := zSp.Events().AppendEmpty()
	zEv.SetTimestamp(pcommon.NewTimestampFromTime(time.Unix(5, 0).UTC())) // offset = -5s
	shiftSpanTimestamps(zSp, time.Unix(2, 0).UTC())                       // newStart (2s) < offset (5s) -> clamps to 0
	if zSp.Events().At(0).Timestamp() != 0 {
		t.Fatalf("underflow-guarded event ts = %d, want 0", zSp.Events().At(0).Timestamp())
	}

	// 3. End-to-end reused prebuilt ModeBQFake spans retain exact 42_000_000 duration_nano in bqfake rows.
	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(false)
	cfg := RunnerConfig{
		Mode:           ModeBQFake,
		Signals:        []string{"traces"},
		Workers:        1,
		BatchSize:      4,
		maxBatches:     3,
		Duration:       5 * time.Second,
		UniquePayloads: false,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	res, softErr, hardErr := runSingleSignalWithFake(t.Context(), cfg, "traces", fakeSrv)
	if hardErr != nil || softErr != nil || res.DeliveredRows != 12 {
		t.Fatalf("runSingleSignalWithFake hard=%v soft=%v delivered=%d, want nil/nil/12", hardErr, softErr, res.DeliveredRows)
	}
	rows := fakeSrv.Rows("otel_spans")
	if len(rows) != 12 {
		t.Fatalf("len(otel_spans rows) = %d, want 12", len(rows))
	}
	for i, r := range rows {
		if durNano, ok := r["duration_nano"].(int64); !ok || durNano != (42*time.Millisecond).Nanoseconds() {
			t.Fatalf("row[%d] duration_nano = %v (%T), want 42000000", i, r["duration_nano"], r["duration_nano"])
		}
	}
}

func TestPrebuiltBatchBudgetUsesMeasuredRepresentativeBatch(t *testing.T) {
	// Access logs with workers=1, batch_size=100000, payload_bytes=128 serialize to ~58.6 MB/slot;
	// slot geometry must cap slots so totalSlots * measuredSlotBytes <= 256 MiB (not 8 slots / ~469 MB).
	singleWorkerAccessCfg := RunnerConfig{
		Mode:            ModeBQFake,
		WorkloadProfile: WorkloadProfileAccessLogs,
		Signals:         []string{"logs"},
		Workers:         1,
		BatchSize:       100_000,
		PayloadBytes:    128,
		UniquePayloads:  false,
	}
	if err := singleWorkerAccessCfg.Normalize(); err != nil {
		t.Fatalf("Normalize(1x100k AccessLogs): %v", err)
	}
	slotBytes := estimatePrebuiltBatchBytes(singleWorkerAccessCfg, "logs")
	if slotBytes <= int64(singleWorkerAccessCfg.BatchSize)*int64(minPrebuiltRecordOverheadBytes) {
		t.Fatalf("estimatePrebuiltBatchBytes = %d, expected > naive floor %d",
			slotBytes, int64(singleWorkerAccessCfg.BatchSize)*int64(minPrebuiltRecordOverheadBytes))
	}
	geom := computeWorkerSlotGeometry(singleWorkerAccessCfg, "logs")
	if geom.totalSlots < 1 || geom.totalSlots >= 8 {
		t.Fatalf("single-worker 100k AccessLogs totalSlots = %d, want in [1, 7] (strictly < 8)", geom.totalSlots)
	}
	if int64(geom.totalSlots)*slotBytes > MaxBatchPayloadBudgetBytes {
		t.Fatalf("single-worker 100k AccessLogs total=%d (%d * %d) > %d",
			int64(geom.totalSlots)*slotBytes, geom.totalSlots, slotBytes, MaxBatchPayloadBudgetBytes)
	}

	// Verify measured estimate tracks real 100k batch marshaled size closely (< 5% drift) without building 100k rows.
	actualGen := NewGenerator(GeneratorConfig{
		PayloadBytes:    128,
		UniquePayloads:  false,
		WorkloadProfile: WorkloadProfileAccessLogs,
	})
	actual1k := actualGen.LogsBatch(1200)
	est1k := estimatePrebuiltBatchBytes(RunnerConfig{
		WorkloadProfile: WorkloadProfileAccessLogs,
		BatchSize:       1200,
		PayloadBytes:    128,
	}, "logs")
	actual1kSize := int64((&plog.ProtoMarshaler{}).LogsSize(actual1k))
	diff := est1k - actual1kSize
	if diff < 0 {
		diff = -diff
	}
	if diff*20 > actual1kSize {
		t.Fatalf("estimatePrebuiltBatchBytes(1200)=%d vs actual=%d (>5%% error)", est1k, actual1kSize)
	}

	// 8 workers x 100,000 AccessLogs @ 128B (~469 MB) must be rejected in BOTH ModeBQFake and ModeCollector.
	for _, tc := range []struct {
		name string
		cfg  RunnerConfig
	}{
		{
			name: "ModeBQFake_8x100k_AccessLogs",
			cfg: RunnerConfig{
				Mode:            ModeBQFake,
				WorkloadProfile: WorkloadProfileAccessLogs,
				Signals:         []string{"logs"},
				Workers:         8,
				BatchSize:       100_000,
				PayloadBytes:    128,
				UniquePayloads:  false,
			},
		},
		{
			name: "ModeCollector_8x100k_AccessLogs",
			cfg: RunnerConfig{
				Mode:            ModeCollector,
				CollectorBin:    os.Args[0],
				CollectorConfig: "example/otel-collector-high-volume-logs.yaml",
				WorkloadProfile: WorkloadProfileAccessLogs,
				Signals:         []string{"logs"},
				Workers:         8,
				BatchSize:       100_000,
				PayloadBytes:    128,
				UniquePayloads:  false,
			},
		},
		{
			name: "MultiSignal_TracesPlusLogs_4x100k_GenAIMixed",
			cfg: RunnerConfig{
				Mode:            ModeBQFake,
				WorkloadProfile: WorkloadProfileGenAIMixed,
				Signals:         []string{"traces", "logs"},
				Workers:         4,
				BatchSize:       100_000,
				PayloadBytes:    512,
				UniquePayloads:  false,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Normalize()
			if err == nil || !strings.Contains(err.Error(), "prebuilt worker batch pool budget") || !strings.Contains(err.Error(), "exceeds maximum") {
				t.Fatalf("Normalize = %v, want prebuilt worker batch pool budget exceeds maximum error", err)
			}
		})
	}

	// Adversarial large PayloadBytes=16MiB with BatchSize=16 (256 MiB raw, >256 MiB serialized)
	// must fail fast without allocating 256+ MiB during sampling.
	hugePayloadCfg := RunnerConfig{
		Mode:           ModeBQFake,
		Signals:        []string{"traces"},
		Workers:        1,
		BatchSize:      16,
		PayloadBytes:   MaxBenchmarkPayloadBytes,
		UniquePayloads: false,
	}
	start := time.Now()
	hugeErr := hugePayloadCfg.Normalize()
	if hugeErr == nil || !strings.Contains(hugeErr.Error(), "exceeds maximum") {
		t.Fatalf("Normalize(16x16MiB) = %v, want budget exceeds maximum error", hugeErr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Normalize(16x16MiB) took %s (>5s)", elapsed)
	}
}

func TestPrebuiltBatchBudgetRejectsOversizedPayloadWithoutLargeCorpusAlloc(t *testing.T) {
	// Sequential (no t.Parallel) so runtime.MemStats reflects only this test's allocations.
	measureAlloc := func(fn func()) uint64 {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		if after.TotalAlloc < before.TotalAlloc {
			return 0
		}
		return after.TotalAlloc - before.TotalAlloc
	}

	const maxExpectedAlloc = 4 * 1024 * 1024 // < 4 MiB (never 256 MiB generator corpus)
	for _, tc := range []struct {
		name      string
		workers   int
		batchSize int
	}{
		{name: "1x16x16MiB", workers: 1, batchSize: 16},
		{name: "4x4x16MiB", workers: 4, batchSize: 4},
		{name: "1x1x16MiB", workers: 1, batchSize: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := RunnerConfig{
				Mode:           ModeBQFake,
				Signals:        []string{"traces"},
				Workers:        tc.workers,
				BatchSize:      tc.batchSize,
				PayloadBytes:   MaxBenchmarkPayloadBytes,
				UniquePayloads: false,
			}
			var normErr error
			allocBytes := measureAlloc(func() {
				normErr = cfg.Normalize()
			})
			if normErr == nil || !strings.Contains(normErr.Error(), "prebuilt worker batch pool budget") || !strings.Contains(normErr.Error(), "exceeds maximum") {
				t.Fatalf("Normalize(%s) = %v, want prebuilt worker batch pool budget exceeds maximum error", tc.name, normErr)
			}
			if allocBytes >= maxExpectedAlloc {
				t.Fatalf("Normalize(%s) allocated %d bytes (>= %d); expected early rejection without building generator corpus", tc.name, allocBytes, maxExpectedAlloc)
			}
		})
	}

	// Direct estimatePrebuiltBatchBytes call at 16 MiB must also skip 16*16 MiB corpus allocation.
	directCfg := RunnerConfig{
		Mode:         ModeBQFake,
		BatchSize:    16,
		PayloadBytes: MaxBenchmarkPayloadBytes,
	}
	var gotEstimate int64
	directAlloc := measureAlloc(func() {
		gotEstimate = estimatePrebuiltBatchBytes(directCfg, "traces")
	})
	wantFloor := int64(directCfg.BatchSize) * int64(directCfg.PayloadBytes)
	if gotEstimate != wantFloor {
		t.Fatalf("estimatePrebuiltBatchBytes(16x16MiB) = %d, want floor %d", gotEstimate, wantFloor)
	}
	if directAlloc >= maxExpectedAlloc {
		t.Fatalf("estimatePrebuiltBatchBytes(16x16MiB) allocated %d bytes (>= %d)", directAlloc, maxExpectedAlloc)
	}
}

func TestRunRedactsAdminEndpointUserinfoAndURLOnErrorsAndCleanup(t *testing.T) {
	const (
		secretUser  = "secret_admin_user"
		secretPass  = "secret_pass_xyz"
		secretToken = "tok_secret_98765"
	)
	assertNoLeak := func(t *testing.T, label, text string, forbidden ...string) {
		t.Helper()
		for _, tok := range forbidden {
			if tok != "" && strings.Contains(text, tok) {
				t.Fatalf("%s leaked %q in %q", label, tok, text)
			}
		}
	}

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	// Allocate and immediately close an ephemeral TCP listener so connections fail deterministically.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	closedAddr := ln.Addr().String()
	_ = ln.Close()
	closedAdminURL := fmt.Sprintf("http://%s:%s@%s/bigquery/v2/?token=%s", secretUser, secretPass, closedAddr, secretToken)

	// Case 1: ModeCollector + Run with userinfo/query admin_url pointing at closed loopback port.
	cfgPath := filepath.Join(t.TempDir(), "collector-closed-admin.yaml")
	closedYAML := fmt.Sprintf(`
extensions:
  health_check:
    endpoint: 0.0.0.0:13133
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
exporters:
  bigquery:
    project: test-proj
    dataset: unused_ds
    location: US
    endpoint:
      url: 127.0.0.1:44321
      admin_url: %q
      insecure: true
      without_authentication: true
service:
  extensions: [health_check]
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`, closedAdminURL)
	if err := os.WriteFile(cfgPath, []byte(closedYAML), 0o600); err != nil {
		t.Fatalf("write closed collector YAML: %v", err)
	}
	helperBin := configureCollectorHelperEnv(t, "live_ok")

	closedCtx, cancelClosed := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancelClosed()
	_, closedRunErr := Run(closedCtx, RunnerConfig{
		Mode:               ModeCollector,
		CollectorAllowLive: true,
		CollectorBin:       helperBin,
		CollectorConfig:    cfgPath,
		ProjectID:          "test-proj",
		Location:           "US",
		EphemeralDataset:   true,
		Signals:            []string{"logs"},
		Workers:            1,
		BatchSize:          2,
		Duration:           200 * time.Millisecond,
	})
	if closedRunErr == nil || !strings.Contains(closedRunErr.Error(), "checking whether dataset test-proj.") {
		t.Fatalf("Run(closed admin_url) error = %v, want sanitized dataset check error", closedRunErr)
	}
	assertNoLeak(t, "Run(closed admin_url) err", closedRunErr.Error(),
		secretUser, secretPass, secretToken, closedAddr, closedAdminURL, "http://")

	// Direct DeleteDatasetWithContents against the closed userinfo URL must also redact URL/userinfo/port.
	delClosedCtx, cancelDelClosed := context.WithTimeout(ctx, 1500*time.Millisecond)
	defer cancelDelClosed()
	delClosedErr := DeleteDatasetWithContents(delClosedCtx, "test-proj", "ephemeral_ds_closed",
		option.WithEndpoint(closedAdminURL), option.WithoutAuthentication())
	if delClosedErr == nil || !strings.Contains(delClosedErr.Error(), "deleting dataset test-proj.ephemeral_ds_closed") {
		t.Fatalf("DeleteDatasetWithContents(closed admin_url) = %v, want sanitized deleting dataset error", delClosedErr)
	}
	assertNoLeak(t, "DeleteDatasetWithContents(closed admin_url) err", delClosedErr.Error(),
		secretUser, secretPass, secretToken, closedAddr, closedAdminURL, "http://")

	// Case 2: Loopback HTTP server where dataset CREATE succeeds and DELETE returns HTTP 500
	// echoing raw credentials/URL in body; capture both Run/RunStreamPoolSweep errors and os.Stderr.
	var deleteAttempts atomic.Int64
	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/datasets/"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"code":404,"message":"not found"}}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/datasets"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"datasetReference":{"projectId":"test-proj","datasetId":"ds"}}`)
		case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/datasets/"):
			deleteAttempts.Add(1)
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `{"error":{"code":403,"message":"cleanup error for %s"}}`, closedAdminURL)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockSrv.Close()

	mockURLParsed, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(mockSrv.URL, "http://"))
	if err != nil {
		t.Fatalf("ResolveTCPAddr(%q): %v", mockSrv.URL, err)
	}
	mockAddr := mockURLParsed.String()
	userinfoMockURL := fmt.Sprintf("http://%s:%s@%s/bigquery/v2/?token=%s", secretUser, secretPass, mockAddr, secretToken)

	// Point exporter to missing ADC so Run fails deterministically after creating dataset,
	// triggering the deferred ephemeral cleanup warning to os.Stderr.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-adc.json"))

	captureStderr := func(fn func() error) (string, error) {
		origStderr := os.Stderr
		rPipe, wPipe, pErr := os.Pipe()
		if pErr != nil {
			t.Fatalf("os.Pipe: %v", pErr)
		}
		os.Stderr = wPipe
		var buf bytes.Buffer
		doneCh := make(chan struct{})
		go func() {
			_, _ = io.Copy(&buf, rPipe)
			close(doneCh)
		}()
		fnErr := fn()
		_ = wPipe.Close()
		os.Stderr = origStderr
		<-doneCh
		_ = rPipe.Close()
		return buf.String(), fnErr
	}

	stderrOut, runErr := captureStderr(func() error {
		_, rErr := Run(ctx, RunnerConfig{
			Mode:             ModeLive,
			ProjectID:        "test-proj",
			Location:         "US",
			EphemeralDataset: true,
			Duration:         10 * time.Millisecond,
			CallTimeout:      10 * time.Millisecond,
			ClientOptions: []option.ClientOption{
				option.WithEndpoint(userinfoMockURL),
				option.WithoutAuthentication(),
			},
		})
		return rErr
	})
	if runErr == nil || !strings.Contains(runErr.Error(), "deleting dataset test-proj.") || !strings.Contains(runErr.Error(), "HTTP 403") {
		t.Fatalf("Run(create ok, delete 403) err = %v, want sanitized 'deleting dataset ... HTTP 403'", runErr)
	}
	if !strings.Contains(stderrOut, "failed to delete ephemeral dataset test-proj.") || !strings.Contains(stderrOut, "HTTP 403") {
		t.Fatalf("Run(create ok, delete 403) stderr = %q, want sanitized cleanup warning with HTTP 403", stderrOut)
	}
	assertNoLeak(t, "Run(create ok, delete 403) err", runErr.Error(),
		secretUser, secretPass, secretToken, mockAddr, userinfoMockURL, "http://")
	assertNoLeak(t, "Run(create ok, delete 403) stderr", stderrOut,
		secretUser, secretPass, secretToken, mockAddr, userinfoMockURL, "http://")

	sweepStderr, sweepErr := captureStderr(func() error {
		_, sErr := RunStreamPoolSweep(ctx, RunnerConfig{
			Mode:             ModeLive,
			ProjectID:        "test-proj",
			Location:         "US",
			EphemeralDataset: true,
			Duration:         10 * time.Millisecond,
			CallTimeout:      10 * time.Millisecond,
			ClientOptions: []option.ClientOption{
				option.WithEndpoint(userinfoMockURL),
				option.WithoutAuthentication(),
			},
		}, []int{1})
		return sErr
	})
	if sweepErr == nil || !strings.Contains(sweepErr.Error(), "deleting dataset test-proj.") || !strings.Contains(sweepErr.Error(), "HTTP 403") {
		t.Fatalf("RunStreamPoolSweep(create ok, delete 403) err = %v, want sanitized 'deleting dataset ... HTTP 403'", sweepErr)
	}
	if !strings.Contains(sweepStderr, "failed to delete ephemeral dataset test-proj.") || !strings.Contains(sweepStderr, "HTTP 403") {
		t.Fatalf("RunStreamPoolSweep(create ok, delete 403) stderr = %q, want sanitized cleanup warning with HTTP 403", sweepStderr)
	}
	assertNoLeak(t, "RunStreamPoolSweep err", sweepErr.Error(),
		secretUser, secretPass, secretToken, mockAddr, userinfoMockURL, "http://")
	assertNoLeak(t, "RunStreamPoolSweep stderr", sweepStderr,
		secretUser, secretPass, secretToken, mockAddr, userinfoMockURL, "http://")
	if deleteAttempts.Load() < 2 {
		t.Fatalf("deleteAttempts = %d, want >= 2", deleteAttempts.Load())
	}

	// Case 3: context.Canceled / context.DeadlineExceeded preservation without wrapping *url.Error.
	hangCh := make(chan struct{})
	defer close(hangCh)
	hangSrv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-hangCh:
		}
	}))
	defer hangSrv.Close()
	hangAddr := strings.TrimPrefix(hangSrv.URL, "http://")
	hangURL := fmt.Sprintf("http://%s:%s@%s/bigquery/v2/?token=%s", secretUser, secretPass, hangAddr, secretToken)

	dlCtx, dlCancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer dlCancel()
	_, dlErr := datasetExists(dlCtx, "test-proj", "timeout_ds",
		option.WithEndpoint(hangURL), option.WithoutAuthentication())
	if !errors.Is(dlErr, context.DeadlineExceeded) {
		t.Fatalf("datasetExists(timeout) err = %v, want errors.Is(context.DeadlineExceeded)", dlErr)
	}
	assertNoLeak(t, "datasetExists(timeout) err", dlErr.Error(),
		secretUser, secretPass, secretToken, hangAddr, hangURL, "http://")

	t.Run("PreservesPrefixAndErrnoSentinelThroughEnsureSanitized", func(t *testing.T) {
		rawURL := fmt.Sprintf("http://%s:%s@127.0.0.1:9/?token=%s", secretUser, secretPass, secretToken)
		rawDialErr := &url.Error{
			Op:  "Get",
			URL: rawURL,
			Err: &net.OpError{
				Op:  "dial",
				Net: "tcp",
				Err: syscall.ECONNREFUSED,
			},
		}
		sanErr := wrapBigQueryAdminError("checking whether dataset test-proj.ds exists", rawDialErr, "fallback")

		got := ensureSanitizedAdminError(sanErr, "fallback")
		if got == nil || !strings.Contains(got.Error(), "checking whether dataset test-proj.ds exists") {
			t.Fatalf("ensureSanitizedAdminError(sanitized errno) = %v, want preserved prefix", got)
		}
		if !errors.Is(got, syscall.ECONNREFUSED) {
			t.Fatalf("ensureSanitizedAdminError(sanitized errno) = %v, want errors.Is(syscall.ECONNREFUSED)", got)
		}
		assertNoLeak(t, "ensureSanitizedAdminError(sanitized errno)", got.Error(),
			secretUser, secretPass, secretToken, "127.0.0.1", "http://")

		gotSan := sanitizeBigQueryAdminError(sanErr, "fallback")
		if gotSan == nil || !strings.Contains(gotSan.Error(), "checking whether dataset test-proj.ds exists") {
			t.Fatalf("sanitizeBigQueryAdminError(sanitized errno) = %v, want preserved prefix", gotSan)
		}
		if !errors.Is(gotSan, syscall.ECONNREFUSED) {
			t.Fatalf("sanitizeBigQueryAdminError(sanitized errno) = %v, want errors.Is(syscall.ECONNREFUSED)", gotSan)
		}

		joined := errors.Join(sanErr, &url.Error{
			Op:  "Get",
			URL: rawURL,
			Err: errors.New("boom"),
		})
		gotJoined := ensureSanitizedAdminError(joined, "fallback")
		if gotJoined == nil {
			t.Fatal("ensureSanitizedAdminError(joined) = nil, want sanitized error")
		}
		assertNoLeak(t, "ensureSanitizedAdminError(joined)", gotJoined.Error(),
			secretUser, secretPass, secretToken, "127.0.0.1", "http://")

		gotSanJoined := sanitizeBigQueryAdminError(joined, "fallback")
		if gotSanJoined == nil {
			t.Fatal("sanitizeBigQueryAdminError(joined) = nil, want sanitized error")
		}
		assertNoLeak(t, "sanitizeBigQueryAdminError(joined)", gotSanJoined.Error(),
			secretUser, secretPass, secretToken, "127.0.0.1", "http://")

		urlWrappingMulti := &url.Error{
			Op:  "Get",
			URL: rawURL,
			Err: errors.Join(syscall.ECONNREFUSED, context.DeadlineExceeded),
		}
		if !containsUnsanitizedAdminError(urlWrappingMulti) {
			t.Fatal("containsUnsanitizedAdminError(url.Error wrapping errors.Join) = false, want true")
		}
		gotMulti := ensureSanitizedAdminError(urlWrappingMulti, "fallback")
		if gotMulti == nil {
			t.Fatal("ensureSanitizedAdminError(urlWrappingMulti) = nil, want sanitized error")
		}
		assertNoLeak(t, "ensureSanitizedAdminError(urlWrappingMulti)", gotMulti.Error(),
			secretUser, secretPass, secretToken, "127.0.0.1", "http://")

		spoofedNetErr := testSpoofingNetError{msg: "dial " + rawURL + " failed"}
		if !containsUnsanitizedAdminError(spoofedNetErr) {
			t.Fatal("containsUnsanitizedAdminError(spoofedNetErr) = false, want true")
		}
		gotSpoofed := ensureSanitizedAdminError(spoofedNetErr, "fallback")
		if gotSpoofed == nil {
			t.Fatal("ensureSanitizedAdminError(spoofedNetErr) = nil, want sanitized error")
		}
		assertNoLeak(t, "ensureSanitizedAdminError(spoofedNetErr)", gotSpoofed.Error(),
			secretUser, secretPass, secretToken, "127.0.0.1", "http://")
	})
}

type testSpoofingNetError struct {
	msg string
}

func (e testSpoofingNetError) Error() string   { return e.msg }
func (e testSpoofingNetError) Timeout() bool   { return false }
func (e testSpoofingNetError) Temporary() bool { return false }
func (e testSpoofingNetError) Is(target error) bool {
	return errors.Is(target, context.DeadlineExceeded) || errors.Is(target, syscall.ECONNREFUSED)
}

func TestRunWarmupFaultFreeDuplicateRejectedUnderThrottleFlag(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(true)

	var injected atomic.Bool
	fakeSrv.SetBeforeCommitHook(func(_ string, serialized [][]byte) [][]byte {
		if len(serialized) > 0 && !injected.Swap(true) {
			// Inject a silent duplicate during fault-free warmup before any throttle fires.
			return append(slices.Clone(serialized), slices.Clone(serialized[0]))
		}
		return serialized
	})

	cfg := RunnerConfig{
		Mode:                  ModeBQFake,
		Signals:               []string{"logs"},
		Workers:               1,
		BatchSize:             4,
		TargetRate:            8,
		WarmupDuration:        180 * time.Millisecond,
		Duration:              250 * time.Millisecond,
		SimulateThrottleEvery: 50, // high period -> 0 throttles during warmup
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	_, _, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr == nil || !strings.Contains(hardErr.Error(), "warmup failed gate") {
		t.Fatalf("runSingleSignalWithFake error = %v, want bqfake warmup failed gate even with SimulateThrottleEvery>0", hardErr)
	}
	if !injected.Load() {
		t.Fatal("expected warmup duplicate hook to fire")
	}
}

func TestRunLegitimateRetryPlusStrayDuplicateRejected(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	fakeSrv := bqfake.NewServer(t)
	fakeSrv.SetDiscardRows(true)
	fakeSrv.EnqueueFault(bqfake.Fault{
		Mode:  bqfake.FaultCommitThenStreamClosed,
		Table: "otel_logs",
	})

	var batchCommits atomic.Int32
	var strayInjected atomic.Bool
	fakeSrv.SetBeforeCommitHook(func(_ string, serialized [][]byte) [][]byte {
		// Batch 1 hits FaultCommitThenStreamClosed (commit 1) and retries (commit 2).
		// On clean batch 2 (commit 3), inject 1 stray duplicate row that has no uncertain credit.
		n := batchCommits.Add(1)
		if n == 3 && len(serialized) > 0 && !strayInjected.Swap(true) {
			return append(slices.Clone(serialized), slices.Clone(serialized[0]))
		}
		return serialized
	})

	cfg := RunnerConfig{
		Mode:             ModeBQFake,
		Signals:          []string{"logs"},
		Workers:          1,
		BatchSize:        2,
		maxBatches:       2,
		Duration:         5 * time.Second,
		WarmupDuration:   0,
		SimulateAckDelay: time.Millisecond,
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}

	res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
	if hardErr != nil {
		t.Fatalf("unexpected hardErr: %v", hardErr)
	}
	if !strayInjected.Load() {
		t.Fatal("expected stray duplicate on batch 2 to fire")
	}
	if res.ObservedUncertainCommitFaults != 1 || res.ObservedUncertainCommitRows != 2 {
		t.Fatalf("ObservedUncertainCommit=(%d,%d), want (1,2)", res.ObservedUncertainCommitFaults, res.ObservedUncertainCommitRows)
	}
	if res.UnexplainedReplayRows != 1 || res.Telemetry.ReplayedRows != 3 {
		t.Fatalf("UnexplainedReplayRows=%d ReplayedRows=%d, want 1 / 3", res.UnexplainedReplayRows, res.Telemetry.ReplayedRows)
	}
	lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
	if lossErr == nil || !strings.Contains(lossErr.Error(), "unexplained_replays=1") {
		t.Fatalf("checkSignalResultLossless = %v, want failure citing unexplained_replays=1", lossErr)
	}
}

func TestLatencyHistogramZeroAllocsFixedSizeMergeAndAccuracy(t *testing.T) {
	if size := unsafe.Sizeof(latencyHistogram{}); size > 16*1024 {
		t.Fatalf("latencyHistogram size = %d bytes, want <= 16384 bytes", size)
	}
	var allocHist latencyHistogram
	if allocs := testing.AllocsPerRun(500, func() {
		allocHist.Record(12.345)
	}); allocs != 0 {
		t.Fatalf("latencyHistogram.Record allocations = %v, want 0", allocs)
	}

	var empty latencyHistogram
	if s := empty.Summary(); s != (LatencySummary{}) {
		t.Fatalf("empty.Summary() = %+v, want zero", s)
	}

	// Sub-millisecond exactness, negative clamping, NaN skip, overflow tracking, and worker Merge.
	const nSamples = 100_000
	samples := make([]float64, nSamples)
	var workers [4]latencyHistogram
	for i := range nSamples {
		// Deterministic bimodal + tail distribution from 0.02 ms to 450 ms.
		var ms float64
		switch {
		case i%100 == 99:
			ms = 120.0 + float64(i%330)
		case i%10 == 0:
			ms = 15.0 + float64(i%40)
		default:
			ms = 0.02 + float64(i%800)*0.005
		}
		samples[i] = ms
		workers[i%4].Record(ms)
	}
	workers[0].Record(math.NaN())
	var merged latencyHistogram
	for i := range workers {
		merged.Merge(&workers[i])
	}
	merged.Reset()
	for i := range workers {
		merged.Merge(&workers[i])
	}
	got := merged.Summary()
	exact := computeLatencySummary(samples)
	if got.Samples != exact.Samples || got.MinMs != exact.MinMs || got.MaxMs != exact.MaxMs || got.MeanMs != exact.MeanMs {
		t.Fatalf("exact fields mismatch got=%+v exact=%+v", got, exact)
	}
	checkWithinPct := func(label string, g, want float64) {
		t.Helper()
		diff := math.Abs(g - want)
		if diff > max(0.05, want*0.03) {
			t.Fatalf("%s = %v, exact = %v (diff=%v > tolerance)", label, g, want, diff)
		}
	}
	checkWithinPct("P50Ms", got.P50Ms, exact.P50Ms)
	checkWithinPct("P95Ms", got.P95Ms, exact.P95Ms)
	checkWithinPct("P99Ms", got.P99Ms, exact.P99Ms)

	// Overflow sample (> ~268.4s) retains exact Min/Max/Mean and maps quantile cleanly.
	var overHist latencyHistogram
	overHist.Record(-1.5) // clamped to 0
	overHist.Record(300_000.0)
	overSum := overHist.Summary()
	if overSum.Samples != 2 || overSum.MinMs != 0 || overSum.MaxMs != 300_000.0 || overSum.P99Ms != 300_000.0 {
		t.Fatalf("overflow summary = %+v, want Samples=2 Min=0 Max=300000 P99=300000", overSum)
	}
}

func TestEnsureEphemeralDedupViewFailsClosed(t *testing.T) {
	specs := []ephemeralTableSpec{{
		signal: "logs",
		table:  "logs_tbl",
	}}
	const viewID = "logs_tbl_dedup"
	const fqView = "live-proj.ds." + viewID

	type mockViewState struct {
		mu             sync.Mutex
		getStatuses    []int
		getBodies      []map[string]any
		patchStatuses  []int
		getCalls       int
		patchCalls     int
		onFirstRequest func()
	}

	newServer := func(t *testing.T, st *mockViewState) *httptest.Server {
		t.Helper()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tables"):
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				ref, _ := body["tableReference"].(map[string]any)
				tid, _ := ref["tableId"].(string)
				if tid == viewID {
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"error":{"code":409,"message":"view already exists"}}`)
					return
				}
				_, _ = fmt.Fprintf(w, `{"tableReference":{"projectId":"live-proj","datasetId":"ds","tableId":%q},"type":"TABLE"}`, tid)
			case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tables/"+viewID):
				st.mu.Lock()
				idx := st.getCalls
				st.getCalls++
				if st.onFirstRequest != nil && idx == 0 {
					st.onFirstRequest()
				}
				status := http.StatusOK
				if idx < len(st.getStatuses) {
					status = st.getStatuses[idx]
				} else if len(st.getStatuses) > 0 {
					status = st.getStatuses[len(st.getStatuses)-1]
				}
				var payload map[string]any
				if idx < len(st.getBodies) {
					payload = st.getBodies[idx]
				} else if len(st.getBodies) > 0 {
					payload = st.getBodies[len(st.getBodies)-1]
				}
				st.mu.Unlock()
				if status != http.StatusOK {
					w.WriteHeader(status)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"secret-metadata-leak-https://user:pw@host.internal"}}`, status)
					return
				}
				_ = json.NewEncoder(w).Encode(payload)
			case (r.Method == http.MethodPatch || r.Method == http.MethodPut) && strings.Contains(r.URL.Path, "/tables/"+viewID):
				st.mu.Lock()
				idx := st.patchCalls
				st.patchCalls++
				status := http.StatusOK
				if idx < len(st.patchStatuses) {
					status = st.patchStatuses[idx]
				} else if len(st.patchStatuses) > 0 {
					status = st.patchStatuses[len(st.patchStatuses)-1]
				}
				st.mu.Unlock()
				if status != http.StatusOK {
					w.WriteHeader(status)
					_, _ = fmt.Fprintf(w, `{"error":{"code":%d,"message":"secret-update-leak-https://user:pw@host.internal"}}`, status)
					return
				}
				_, _ = fmt.Fprintf(w, `{"tableReference":{"projectId":"live-proj","datasetId":"ds","tableId":%q},"type":"VIEW"}`, viewID)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		t.Cleanup(srv.Close)
		return srv
	}

	staleViewBody := map[string]any{
		"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
		"type":           "VIEW",
		"etag":           "etag-1",
		"view": map[string]any{
			"query":        "SELECT 1",
			"useLegacySql": true,
		},
	}

	t.Run("MetadataReadFailureAfter409", func(t *testing.T) {
		st := &mockViewState{getStatuses: []int{http.StatusForbidden}}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil {
			t.Fatal("expected error when dedup view metadata read fails after 409 conflict")
		}
		for _, want := range []string{fqView, "HTTP 403"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		}
		if strings.Contains(err.Error(), "secret-metadata-leak") || strings.Contains(err.Error(), "user:pw") {
			t.Fatalf("error leaked unsanitized details: %q", err.Error())
		}
	})

	t.Run("ExistingNonViewObjectAfter409", func(t *testing.T) {
		st := &mockViewState{
			getStatuses: []int{http.StatusOK},
			getBodies: []map[string]any{{
				"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
				"type":           "TABLE",
				"etag":           "etag-tbl",
			}},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil {
			t.Fatal("expected error when _dedup object is a regular TABLE instead of VIEW")
		}
		for _, want := range []string{fqView, "HTTP 409", "TABLE"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		}
		st.mu.Lock()
		patches := st.patchCalls
		st.mu.Unlock()
		if patches != 0 {
			t.Fatalf("patchCalls = %d, want 0 when existing _dedup object is TABLE", patches)
		}
	})

	t.Run("UnexpectedUnknownTableTypeRedacted", func(t *testing.T) {
		st := &mockViewState{
			getStatuses: []int{http.StatusOK},
			getBodies: []map[string]any{{
				"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
				"type":           "SECRET_CUSTOM_BACKEND_TYPE",
				"etag":           "etag-secret",
			}},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil {
			t.Fatal("expected error when _dedup object reports non-allowlisted type")
		}
		for _, want := range []string{fqView, "HTTP 409", "unexpected"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		}
		if strings.Contains(err.Error(), "SECRET_CUSTOM_BACKEND_TYPE") {
			t.Fatalf("error leaked free-form TableType: %q", err.Error())
		}
	})

	t.Run("ExistingViewWithoutQueryAfter409", func(t *testing.T) {
		st := &mockViewState{
			getStatuses: []int{http.StatusOK},
			getBodies: []map[string]any{{
				"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
				"type":           "VIEW",
				"etag":           "etag-empty-view",
			}},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil || !strings.Contains(err.Error(), fqView) {
			t.Fatalf("error = %v, want non-nil error naming %q", err, fqView)
		}
	})

	t.Run("FinalUpdateNonRetryableFailure", func(t *testing.T) {
		st := &mockViewState{
			getStatuses:   []int{http.StatusOK},
			getBodies:     []map[string]any{staleViewBody},
			patchStatuses: []int{http.StatusForbidden},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil {
			t.Fatal("expected error when final dedup view update fails")
		}
		for _, want := range []string{fqView, "HTTP 403"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		}
		if strings.Contains(err.Error(), "secret-update-leak") || strings.Contains(err.Error(), "user:pw") {
			t.Fatalf("error leaked unsanitized details: %q", err.Error())
		}
	})

	t.Run("Exhausted412PreconditionRetriesFailsClosed", func(t *testing.T) {
		st := &mockViewState{
			getStatuses:   []int{http.StatusOK, http.StatusOK},
			getBodies:     []map[string]any{staleViewBody, staleViewBody},
			patchStatuses: []int{http.StatusPreconditionFailed, http.StatusPreconditionFailed},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil {
			t.Fatal("expected error when 412 ETag retries exhaust")
		}
		for _, want := range []string{fqView, "HTTP 412"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error = %q, want %q", err.Error(), want)
			}
		}
		st.mu.Lock()
		gets, patches := st.getCalls, st.patchCalls
		st.mu.Unlock()
		if gets != 2 || patches != 2 {
			t.Fatalf("gets=%d patches=%d, want 2/2 for bounded single 412 retry", gets, patches)
		}
	})

	t.Run("EmptyETagStaleViewFailsClosedWithoutPatch", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			body map[string]any
		}{
			{
				name: "missing_etag",
				body: map[string]any{
					"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
					"type":           "VIEW",
					"view": map[string]any{
						"query":        "SELECT 1",
						"useLegacySql": false,
					},
				},
			},
			{
				name: "whitespace_etag",
				body: map[string]any{
					"tableReference": map[string]any{"projectId": "live-proj", "datasetId": "ds", "tableId": viewID},
					"type":           "VIEW",
					"etag":           "   ",
					"view": map[string]any{
						"query":        "SELECT 1",
						"useLegacySql": true,
					},
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				st := &mockViewState{
					getStatuses: []int{http.StatusOK},
					getBodies:   []map[string]any{tc.body},
				}
				srv := newServer(t, st)
				err := ensureEphemeralDatasetTables(
					t.Context(), "live-proj", "ds", specs,
					option.WithEndpoint(srv.URL+"/bigquery/v2/"),
					option.WithoutAuthentication(),
				)
				if err == nil {
					t.Fatal("expected error when stale _dedup view is missing ETag")
				}
				for _, want := range []string{
					fmt.Sprintf("updating existing ephemeral deduplication view %s", fqView),
					"existing view metadata is missing an ETag; refusing unconditional update",
				} {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error = %q, want %q", err.Error(), want)
					}
				}
				st.mu.Lock()
				gets, patches := st.getCalls, st.patchCalls
				st.mu.Unlock()
				if gets != 1 || patches != 0 {
					t.Fatalf("gets=%d patches=%d, want 1/0 (must refuse unconditional PATCH)", gets, patches)
				}
			})
		}
	})

	t.Run("Retry412ThenSucceed", func(t *testing.T) {
		st := &mockViewState{
			getStatuses:   []int{http.StatusOK, http.StatusOK},
			getBodies:     []map[string]any{staleViewBody, staleViewBody},
			patchStatuses: []int{http.StatusPreconditionFailed, http.StatusOK},
		}
		srv := newServer(t, st)
		if err := ensureEphemeralDatasetTables(
			t.Context(), "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		); err != nil {
			t.Fatalf("ensureEphemeralDatasetTables unexpected error after 412 retry: %v", err)
		}
		st.mu.Lock()
		gets, patches := st.getCalls, st.patchCalls
		st.mu.Unlock()
		if gets != 2 || patches != 2 {
			t.Fatalf("gets=%d patches=%d, want 2/2", gets, patches)
		}
	})

	t.Run("ContextCanceledDuringMetadataPreserved", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		st := &mockViewState{
			getStatuses: []int{http.StatusInternalServerError},
			onFirstRequest: func() {
				cancel()
			},
		}
		srv := newServer(t, st)
		err := ensureEphemeralDatasetTables(
			ctx, "live-proj", "ds", specs,
			option.WithEndpoint(srv.URL+"/bigquery/v2/"),
			option.WithoutAuthentication(),
		)
		if err == nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	})
}

func TestEnsureEphemeralDatasetTablesRejectsNonRegularTableConflict(t *testing.T) {
	specs := []ephemeralTableSpec{{
		signal: "traces",
		table:  "shared_collision_tbl",
	}}
	const fqTable = "live-proj.ds.shared_collision_tbl"

	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantSubs []string
		forbid   []string
	}{
		{
			name:     "ExistingViewAtBaseTable409",
			status:   http.StatusOK,
			body:     `{"tableReference":{"projectId":"live-proj","datasetId":"ds","tableId":"shared_collision_tbl"},"type":"VIEW"}`,
			wantSubs: []string{"HTTP 409", "VIEW"},
		},
		{
			name:     "UnexpectedUnknownTableTypeRedacted",
			status:   http.StatusOK,
			body:     `{"tableReference":{"projectId":"live-proj","datasetId":"ds","tableId":"shared_collision_tbl"},"type":"SECRET_CUSTOM_BACKEND_TYPE"}`,
			wantSubs: []string{"HTTP 409", "unexpected"},
			forbid:   []string{"SECRET_CUSTOM_BACKEND_TYPE"},
		},
		{
			name:     "MetadataReadErrorAfterBaseTable409",
			status:   http.StatusForbidden,
			body:     `{"error":{"code":403,"message":"denied"}}`,
			wantSubs: []string{"HTTP 403"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tables"):
					w.WriteHeader(http.StatusConflict)
					_, _ = io.WriteString(w, `{"error":{"code":409,"message":"already exists"}}`)
				case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/tables/shared_collision_tbl"):
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, tc.body)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			err := ensureEphemeralDatasetTables(
				t.Context(), "live-proj", "ds", specs,
				option.WithEndpoint(srv.URL+"/bigquery/v2/"),
				option.WithoutAuthentication(),
			)
			if err == nil {
				t.Fatal("expected ensureEphemeralDatasetTables to fail closed")
			}
			for _, want := range append([]string{fqTable}, tc.wantSubs...) {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("err = %q, want %q", err.Error(), want)
				}
			}
			for _, bad := range tc.forbid {
				if strings.Contains(err.Error(), bad) {
					t.Fatalf("err leaked forbidden string %q: %q", bad, err.Error())
				}
			}
		})
	}
}

func TestAllowPartialFailuresRequiresMatchedRowsWhenReconciled(t *testing.T) {
	for _, mode := range []string{ModeBQFake, ModeCollector} {
		t.Run("UnitGate/"+mode, func(t *testing.T) {
			partialCfg := RunnerConfig{
				Mode:                 mode,
				Signals:              []string{"logs"},
				AllowPartialFailures: true,
			}
			zeroMatchedRes := SignalResult{
				Signal:           "logs",
				Mode:             mode,
				BatchesAttempted: 1,
				BatchesSucceeded: 1,
				RecordsSubmitted: 4,
				DeliveredRows:    3,
				MatchedRows:      0,
				MissingRows:      4,
				UnexpectedRows:   3,
				Reconciled:       true,
				Latency:          LatencySummary{Samples: 1},
				Telemetry:        TelemetrySnapshot{AcknowledgedRows: 4},
			}
			err := checkSignalResultLossless(partialCfg, "logs", zeroMatchedRes, nil)
			if err == nil || !strings.Contains(err.Error(), "matched 0 submitted rows") {
				t.Fatalf("checkSignalResultLossless(zero matched) = %v, want matched 0 submitted rows error", err)
			}

			someMatchedRes := zeroMatchedRes
			someMatchedRes.MatchedRows = 1
			someMatchedRes.MissingRows = 3
			someMatchedRes.UnexpectedRows = 2
			if err := checkSignalResultLossless(partialCfg, "logs", someMatchedRes, nil); err != nil {
				t.Fatalf("checkSignalResultLossless(MatchedRows=1) unexpected error: %v", err)
			}
		})
	}

	t.Run("EndToEndBQFakeAllSubmittedLostWithUnexpectedRowFails", func(t *testing.T) {
		enc, err := protoenc.New(schema.LogsTableSchema())
		if err != nil {
			t.Fatalf("protoenc.New(LogsTableSchema): %v", err)
		}
		fakeSrv := bqfake.NewServer(t)
		fakeSrv.SetDiscardRows(true)

		unrelatedTS := time.Date(2026, 8, 12, 14, 35, 10, 0, time.UTC)
		var (
			nextID   atomic.Int64
			replaced atomic.Bool
		)
		fakeSrv.SetBeforeCommitHook(func(table string, serialized [][]byte) [][]byte {
			if table != "otel_logs" || len(serialized) == 0 {
				return serialized
			}
			replaced.Store(true)
			out := make([][]byte, 0, len(serialized))
			for range serialized {
				id := nextID.Add(1)
				raw, eErr := enc.Encode(transform.Row{
					"timestamp":               unrelatedTS.UnixMicro(),
					"timestamp_source":        "observed",
					"time_unix_nano":          unrelatedTS.UnixNano(),
					"observed_time_unix_nano": unrelatedTS.UnixNano(),
					"receive_time":            unrelatedTS.UnixMicro(),
					"receive_time_unix_nano":  unrelatedTS.UnixNano(),
					"log_name":                "projects/test-project/logs/unrelated",
					"insert_id":               fmt.Sprintf("unrelated-%d", id),
					"body":                    `"unrelated"`,
				})
				if eErr != nil {
					t.Errorf("Encode(unrelated-%d): %v", id, eErr)
					return serialized
				}
				out = append(out, raw)
			}
			return out
		})

		cfg := RunnerConfig{
			Mode:                 ModeBQFake,
			Signals:              []string{"logs"},
			WorkloadProfile:      WorkloadProfileAccessLogs,
			UpstreamInsertID:     true,
			Workers:              1,
			BatchSize:            2,
			maxBatches:           1,
			Duration:             5 * time.Second,
			WarmupDuration:       0,
			AllowPartialFailures: true,
		}
		if err := cfg.Normalize(); err != nil {
			t.Fatalf("Normalize: %v", err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
		defer cancel()

		res, softErr, hardErr := runSingleSignalWithFake(ctx, cfg, "logs", fakeSrv)
		if hardErr != nil {
			t.Fatalf("runSingleSignalWithFake hardErr = %v, want nil", hardErr)
		}
		if !replaced.Load() {
			t.Fatal("steady commit replacement hook never fired")
		}
		if !res.Reconciled || res.DeliveredRows != res.RecordsSubmitted || res.MatchedRows != 0 || res.UnexpectedRows != res.RecordsSubmitted || res.MissingRows != res.RecordsSubmitted {
			t.Fatalf("got (reconciled=%v, delivered=%d, matched=%d, unexpected=%d, missing=%d, submitted=%d), want (true, %d, 0, %d, %d, %d)",
				res.Reconciled, res.DeliveredRows, res.MatchedRows, res.UnexpectedRows, res.MissingRows, res.RecordsSubmitted,
				res.RecordsSubmitted, res.RecordsSubmitted, res.RecordsSubmitted, res.RecordsSubmitted)
		}
		lossErr := checkSignalResultLossless(cfg, "logs", res, softErr)
		if lossErr == nil || !strings.Contains(lossErr.Error(), "matched 0 submitted rows") {
			t.Fatalf("checkSignalResultLossless(AllowPartialFailures=true, MatchedRows=0) = %v, want matched 0 submitted rows error", lossErr)
		}
	})
}

func TestValidateRunConfigPreflightDedupAndTableOptionConflicts(t *testing.T) {
	writeTempCfg := func(t *testing.T, body string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "collector.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}
		return p
	}
	bin := os.Args[0]

	t.Run("DedupViewCollidesWithOtherSignalTableInBothOrdersWhenProvisioned", func(t *testing.T) {
		credsFile := filepath.Join(t.TempDir(), "creds.json")
		if err := os.WriteFile(credsFile, []byte(`{"type":"service_account"}`), 0o600); err != nil {
			t.Fatalf("write creds: %v", err)
		}
		noAuthYAML := `
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: live-proj
    dataset: placeholder_ds
    location: US
    logs:
      table: events
    quarantine:
      table: quarantine_logs
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
  bigquery/traces:
    project: live-proj
    dataset: placeholder_ds
    location: US
    traces:
      table: events_dedup
    quarantine:
      table: quarantine_traces
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`
		autoCreateYAML := fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: live-proj
    dataset: placeholder_ds
    location: US
    credentials:
      file: %q
    logs:
      table: events
    quarantine:
      table: quarantine_logs
  bigquery/traces:
    project: live-proj
    dataset: placeholder_ds
    location: US
    credentials:
      file: %q
    traces:
      table: events_dedup
    quarantine:
      table: quarantine_traces
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, credsFile, credsFile)
		for _, modeTC := range []struct {
			name string
			yaml string
		}{
			{name: "ParentProvisionedNoAuth", yaml: noAuthYAML},
			{name: "ExporterAutoCreateTables", yaml: autoCreateYAML},
		} {
			t.Run(modeTC.name, func(t *testing.T) {
				cfgPath := writeTempCfg(t, modeTC.yaml)
				for _, order := range [][]string{{"logs", "traces"}, {"traces", "logs"}} {
					cfg := RunnerConfig{
						Mode:               ModeCollector,
						CollectorAllowLive: true,
						EphemeralDataset:   true,
						ProjectID:          "live-proj",
						Location:           "US",
						CollectorBin:       bin,
						CollectorConfig:    cfgPath,
						Signals:            order,
					}
					err := validateRunConfig(t.Context(), &cfg, nil)
					if err == nil {
						t.Fatalf("order=%v: expected preflight collision error between events_dedup view and table", order)
					}
					for _, want := range []string{"events_dedup", "bigquery/logs", "bigquery/traces"} {
						if !strings.Contains(err.Error(), want) {
							t.Fatalf("order=%v: err = %q, want %q", order, err.Error(), want)
						}
					}
				}
			})
		}
	})

	t.Run("ExistingDatasetWithoutViewProvisioningAllowsDedupNamedTable", func(t *testing.T) {
		rawYAML := `
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: live-proj
    dataset: existing_ds
    location: US
    auto_create:
      tables: false
      companion_views: false
    logs:
      table: events
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
  bigquery/traces:
    project: live-proj
    dataset: existing_ds
    location: US
    auto_create:
      tables: false
      companion_views: false
    traces:
      table: events_dedup
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`
		cfgPath := writeTempCfg(t, rawYAML)
		for _, order := range [][]string{{"logs", "traces"}, {"traces", "logs"}} {
			cfg := RunnerConfig{
				Mode:               ModeCollector,
				CollectorAllowLive: true,
				EphemeralDataset:   false,
				ProjectID:          "live-proj",
				DatasetID:          "existing_ds",
				Location:           "US",
				CollectorBin:       bin,
				CollectorConfig:    cfgPath,
				Signals:            order,
			}
			if err := validateRunConfig(t.Context(), &cfg, nil); err != nil {
				t.Fatalf("order=%v: validateRunConfig on existing dataset without view provisioning returned unexpected error: %v", order, err)
			}
		}

		// Fake mode also does not provision BigQuery views and must not falsely reject.
		fakeCfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: cfgPath,
			Signals:         []string{"logs", "traces"},
		}
		if err := validateRunConfig(t.Context(), &fakeCfg, nil); err != nil {
			t.Fatalf("validateRunConfig(fake mode without view provisioning) unexpected error: %v", err)
		}
	})

	t.Run("DedupViewCollidesWithQuarantineTableWhenProvisioned", func(t *testing.T) {
		rawYAML := `
receivers:
  otlp: {}
exporters:
  bigquery:
    project: live-proj
    dataset: placeholder_ds
    location: US
    logs:
      table: events
    quarantine:
      enabled: true
      table: events_dedup
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery]
`
		cfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			EphemeralDataset:   true,
			ProjectID:          "live-proj",
			Location:           "US",
			CollectorBin:       bin,
			CollectorConfig:    writeTempCfg(t, rawYAML),
			Signals:            []string{"logs"},
		}
		err := validateRunConfig(t.Context(), &cfg, nil)
		if err == nil || !strings.Contains(err.Error(), "events_dedup") {
			t.Fatalf("err = %v, want preflight collision on events_dedup", err)
		}
	})

	t.Run("SharedQuarantineConflictingOptionsRejectedInBothOrders", func(t *testing.T) {
		cases := []struct {
			name    string
			qLogs   string
			qTraces string
			extraL  string
			extraT  string
			wantOpt string
		}{
			{
				name:    "PartitionExpirationDays",
				qLogs:   "partition_expiration_days: 7",
				qTraces: "partition_expiration_days: 30",
				wantOpt: "partition_expiration_days",
			},
			{
				name:    "KMSKeyName",
				qLogs:   "kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/k1",
				qTraces: "kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/k2",
				wantOpt: "kms_key_name",
			},
			{
				name:    "Labels",
				qLogs:   "labels:\n        team: logs",
				qTraces: "labels:\n        team: traces",
				wantOpt: "labels",
			},
			{
				name:    "RequirePartitionFilter",
				qLogs:   "require_partition_filter: true",
				qTraces: "require_partition_filter: false",
				wantOpt: "require_partition_filter",
			},
			{
				name:    "MaxStaleness",
				qLogs:   "max_staleness: 1h",
				qTraces: "max_staleness: 2h",
				wantOpt: "max_staleness",
			},
			{
				name:    "TopLevelKMSInheritedIntoQuarantine",
				extraL:  "\n    kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/k1",
				extraT:  "\n    kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/k2",
				wantOpt: "kms_key_name",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rawYAML := fmt.Sprintf(`
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: p
    dataset: d%s
    logs:
      table: logs_tbl
    quarantine:
      enabled: true
      table: rejected_rows
      %s
  bigquery/traces:
    project: p
    dataset: d%s
    traces:
      table: traces_tbl
    quarantine:
      enabled: true
      table: rejected_rows
      %s
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`, tc.extraL, tc.qLogs, tc.extraT, tc.qTraces)
				cfgPath := writeTempCfg(t, rawYAML)
				for _, order := range [][]string{{"logs", "traces"}, {"traces", "logs"}} {
					cfg := RunnerConfig{
						Mode:            ModeCollector,
						CollectorBin:    bin,
						CollectorConfig: cfgPath,
						Signals:         order,
					}
					err := validateRunConfig(t.Context(), &cfg, nil)
					if err == nil {
						t.Fatalf("order=%v: expected conflict on %s", order, tc.wantOpt)
					}
					for _, want := range []string{tc.wantOpt, "rejected_rows", "bigquery/logs", "bigquery/traces"} {
						if !strings.Contains(err.Error(), want) {
							t.Fatalf("order=%v: err = %q, want %q", order, err.Error(), want)
						}
					}
				}
			})
		}

		// Identical shared quarantine options across two exporters pass cleanly.
		sameYAML := `
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: p
    dataset: d
    logs:
      table: logs_tbl
    quarantine:
      enabled: true
      table: rejected_rows
      partition_expiration_days: 14
      kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/shared
      labels:
        env: bench
  bigquery/traces:
    project: p
    dataset: d
    traces:
      table: traces_tbl
    quarantine:
      enabled: true
      table: rejected_rows
      partition_expiration_days: 14
      kms_key_name: projects/p/locations/us/keyRings/r/cryptoKeys/shared
      labels:
        env: bench
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`
		okCfg := RunnerConfig{
			Mode:            ModeCollector,
			CollectorBin:    bin,
			CollectorConfig: writeTempCfg(t, sameYAML),
			Signals:         []string{"logs", "traces"},
		}
		if err := validateRunConfig(t.Context(), &okCfg, nil); err != nil {
			t.Fatalf("validateRunConfig(identical shared quarantine) unexpected error: %v", err)
		}
	})

	t.Run("ExistingDatasetAllowsPerExporterLabelsAndKMS", func(t *testing.T) {
		rawYAML := `
receivers:
  otlp: {}
exporters:
  bigquery/logs:
    project: live-proj
    dataset: existing_ds
    location: US
    kms_key_name: projects/live-proj/locations/us/keyRings/r/cryptoKeys/logs-key
    labels:
      component: logs
    logs:
      table: otel_logs
    quarantine:
      table: quarantine_logs
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
  bigquery/traces:
    project: live-proj
    dataset: existing_ds
    location: US
    kms_key_name: projects/live-proj/locations/us/keyRings/r/cryptoKeys/traces-key
    labels:
      component: traces
    traces:
      table: otel_spans
    quarantine:
      table: quarantine_traces
    endpoint:
      url: 127.0.0.1:44321
      admin_url: http://127.0.0.1:44322/bigquery/v2/
      insecure: true
      without_authentication: true
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [bigquery/logs]
    traces:
      receivers: [otlp]
      exporters: [bigquery/traces]
`
		cfgPath := writeTempCfg(t, rawYAML)
		existingDSCfg := RunnerConfig{
			Mode:               ModeCollector,
			CollectorAllowLive: true,
			CollectorBin:       bin,
			CollectorConfig:    cfgPath,
			ProjectID:          "live-proj",
			DatasetID:          "existing_ds",
			Location:           "US",
			EphemeralDataset:   false,
			Signals:            []string{"logs", "traces"},
		}
		if err := validateRunConfig(t.Context(), &existingDSCfg, nil); err != nil {
			t.Fatalf("validateRunConfig(EphemeralDataset=false with distinct per-exporter labels/kms) unexpected error: %v", err)
		}
		if existingDSCfg.collectorDatasetKMSKey != "" || existingDSCfg.collectorDatasetLabels != nil {
			t.Fatalf("EphemeralDataset=false populated dataset governance fields kms=%q labels=%+v, want empty/nil",
				existingDSCfg.collectorDatasetKMSKey, existingDSCfg.collectorDatasetLabels)
		}

		ephCfg := existingDSCfg
		ephCfg.DatasetID = ""
		ephCfg.EphemeralDataset = true
		if err := validateRunConfig(t.Context(), &ephCfg, nil); err == nil || !strings.Contains(err.Error(), "conflicting collector kms_key_name") {
			t.Fatalf("validateRunConfig(EphemeralDataset=true) = %v, want conflicting collector kms_key_name", err)
		}
	})
}

func TestSignalResultJSONReconciledEmitsZeroMatchedRows(t *testing.T) {
	t.Run("ReconciledZeroMatchedRowsEmittedAndRoundTrips", func(t *testing.T) {
		in := SignalResult{
			Signal:      "logs",
			Mode:        "collector",
			Reconciled:  true,
			MatchedRows: 0,
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal(SignalResult): %v", err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("json.Unmarshal raw map: %v", err)
		}
		val, exists := obj["matched_rows"]
		if !exists || val != float64(0) {
			t.Fatalf("matched_rows in JSON = (%v, exists=%v), want (0, true); raw=%s", val, exists, raw)
		}

		report := BenchmarkReport{Results: []SignalResult{in}}
		reportRaw, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("json.Marshal(BenchmarkReport): %v", err)
		}
		var outReport BenchmarkReport
		if err := json.Unmarshal(reportRaw, &outReport); err != nil {
			t.Fatalf("json.Unmarshal(BenchmarkReport): %v", err)
		}
		if len(outReport.Results) != 1 || !outReport.Results[0].Reconciled || outReport.Results[0].MatchedRows != 0 {
			t.Fatalf("round-trip result = %+v, want Reconciled=true MatchedRows=0", outReport.Results)
		}
	})

	t.Run("UnreconciledZeroMatchedRowsOmitted", func(t *testing.T) {
		in := SignalResult{
			Signal:      "logs",
			Mode:        "bqfake",
			Reconciled:  false,
			MatchedRows: 0,
		}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("json.Marshal(SignalResult): %v", err)
		}
		var obj map[string]any
		if err := json.Unmarshal(raw, &obj); err != nil {
			t.Fatalf("json.Unmarshal raw map: %v", err)
		}
		if val, exists := obj["matched_rows"]; exists {
			t.Fatalf("matched_rows unexpectedly present in unreconciled zero JSON: %v (raw=%s)", val, raw)
		}
	})

	t.Run("NonZeroMatchedRowsEmittedAndRoundTrips", func(t *testing.T) {
		for _, reconciled := range []bool{false, true} {
			in := SignalResult{
				Signal:      "traces",
				Mode:        "collector",
				Reconciled:  reconciled,
				MatchedRows: 42,
			}
			raw, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("json.Marshal(reconciled=%v): %v", reconciled, err)
			}
			var obj map[string]any
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatalf("json.Unmarshal raw map: %v", err)
			}
			if val, exists := obj["matched_rows"]; !exists || val != float64(42) {
				t.Fatalf("reconciled=%v matched_rows = (%v, exists=%v), want (42, true)", reconciled, val, exists)
			}
			var out SignalResult
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("json.Unmarshal(SignalResult): %v", err)
			}
			if out.MatchedRows != 42 || out.Reconciled != reconciled {
				t.Fatalf("round-trip = %+v, want MatchedRows=42 Reconciled=%v", out, reconciled)
			}
		}
	})
}
