# Upstream Collector `testbed` Benchmark Harness — Staged Contribution Spec

**Target repo**: `open-telemetry/opentelemetry-collector-contrib`
**Staged files**:
1. `testbed/datareceivers/bigquerydatareceiver/receiver.go`
2. `testbed/tests/bigquery_exporter_test.go`

**Component under test**: `github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter` (wired into `cmd/oteltestbedcol/builder-config.yaml` and built with `make genoteltestbedcol oteltestbedcol`; `exporter/bigqueryexporter` wraps `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.1.0`, compile-and-lint verified against `v0.0.3` at contrib `96567c08`; runtime `RUN_TESTBED=1` capture pending `v0.1.0`)

---

## 1. Architecture Overview

The `opentelemetry-collector-contrib/testbed` framework measures Collector
end-to-end throughput, latency, and resource consumption under synthetic load.
It has three roles:

```
DataSender → Collector (receiver → processors → exporter) → DataReceiver
```

- **DataSender** generates OTLP signals and pushes them into the Collector's
  receiver (e.g., `otlp` gRPC).
- **Collector** runs the actual pipeline under test — here, the `bigquery`
  exporter wired as the exporter.
- **DataReceiver** accepts the Collector's exporter output and counts received
  items so the framework can assert loss-free delivery.

The existing `BaseOTLPDataReceiver` and jaeger/zipkin/splunk receivers all
implement the `testbed.DataReceiver` interface:

```go
type DataReceiver interface {
    Start(tc consumer.Traces, mc consumer.Metrics, lc consumer.Logs) error
    Stop() error
    GenConfigYAMLStr() string  // exporter config YAML for the collector
    ProtocolName() string      // exporter type name in the pipeline
}
```

### BigQuery Exporter Integration

The BigQuery exporter writes to the BigQuery Storage Write API via gRPC
streaming `AppendRows`. To benchmark it inside the testbed without live GCP
credentials, `bigQueryDataReceiver` (returned by `NewBigQueryDataReceiver`)
implements `storagepb.UnimplementedBigQueryWriteServer` directly in-file
(loopback, insecure, no auth) — **zero imports from
`BQ-OTEL-Exporter/internal/`** — which:

1. Accepts `AppendRows` streaming requests.
2. Counts `len(req.GetProtoRows().GetRows().GetSerializedRows())` per table
   stream (`otel_spans`, `otel_logs`, `otel_metrics`).
3. Forwards matching synthetic items to the `consumer.Traces`,
   `consumer.Logs`, and `consumer.Metrics` passed to `Start`, so
   `MockBackend.DataItemsReceived()` reflects every acknowledged item.
4. Returns a valid `storagepb.AppendRowsResponse` with an `AppendResult`.

The Collector is configured to use the `bigquery` exporter pointing at the
loopback endpoint:

```yaml
exporters:
  bigquery/testbed:
    project: "test-project"
    dataset: "test_dataset"
    endpoint:
      url: "127.0.0.1:<port>"
      insecure: true
      without_authentication: true
    auto_create:
      dataset: false
      tables: false
```

### Testbed Test Flow

```
OTLPTraceDataSender (127.0.0.1:<port_a>)
    ↓ otlp/grpc
Collector (otlp receiver → batch → bigquery exporter)
    ↓ grpc AppendRows
bigQueryDataReceiver (127.0.0.1:<port_b>)
```

`Scenario10kItemsPerSecond` drives 10,000 items/sec through the pipeline, then
`TestCase.ValidateData()` asserts `DataItemsSent() == DataItemsReceived()`.

---

## 2. Staged File 1 — `testbed/datareceivers/bigquerydatareceiver/receiver.go`

```go
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package bigquerydatareceiver // import "github.com/open-telemetry/opentelemetry-collector-contrib/testbed/datareceivers/bigquerydatareceiver"

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/testbed"
)

// bigQueryDataReceiver implements testbed.DataReceiver using a self-contained
// in-process BigQuery Storage Write API gRPC server. It embeds
// storagepb.UnimplementedBigQueryWriteServer and overrides only the RPCs the
// BigQuery exporter calls: CreateWriteStream, AppendRows, GetWriteStream.
// No GCP credentials are required; all traffic stays on loopback.
//
// This file has ZERO imports from github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/.
type bigQueryDataReceiver struct {
	testbed.DataReceiverBase
	storagepb.UnimplementedBigQueryWriteServer

	tc consumer.Traces
	mc consumer.Metrics
	lc consumer.Logs

	mu        sync.Mutex
	lis       net.Listener
	grpcSrv   *grpc.Server
	startOnce sync.Once
	stopOnce  sync.Once

	// Total rows acknowledged across all AppendRows streams.
	ackedRows atomic.Int64
	// Per-table row counts keyed by table name parsed from the stream path.
	tableCounts map[string]int64
}

var _ testbed.DataReceiver = (*bigQueryDataReceiver)(nil)

// NewBigQueryDataReceiver creates a BigQuery Storage Write DataReceiver
// that listens on a loopback gRPC port. Call Start to begin serving.
func NewBigQueryDataReceiver(port int) testbed.DataReceiver {
	return &bigQueryDataReceiver{
		DataReceiverBase: testbed.DataReceiverBase{Port: port},
		tableCounts:      make(map[string]int64),
	}
}

// Start launches the in-process gRPC Storage Write server.
func (r *bigQueryDataReceiver) Start(tc consumer.Traces, mc consumer.Metrics, lc consumer.Logs) error {
	var startErr error
	r.startOnce.Do(func() {
		r.tc = tc
		r.mc = mc
		r.lc = lc

		lis, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", r.Port))
		if err != nil {
			startErr = fmt.Errorf("listening on loopback: %w", err)
			return
		}
		r.lis = lis
		r.grpcSrv = grpc.NewServer(
			grpc.MaxRecvMsgSize(32*1024*1024),
			grpc.MaxSendMsgSize(32*1024*1024),
		)
		storagepb.RegisterBigQueryWriteServer(r.grpcSrv, r)
		go func() {
			_ = r.grpcSrv.Serve(lis)
		}()
	})
	return startErr
}

// Stop shuts down the in-process gRPC server.
func (r *bigQueryDataReceiver) Stop() error {
	var stopErr error
	r.stopOnce.Do(func() {
		if r.grpcSrv != nil {
			r.grpcSrv.GracefulStop()
		}
		if r.lis != nil {
			_ = r.lis.Close()
		}
	})
	return stopErr
}

// GenConfigYAMLStr generates the exporter configuration YAML that tells the
// Collector's bigquery exporter to send data to this receiver's loopback
// gRPC server.
func (r *bigQueryDataReceiver) GenConfigYAMLStr() string {
	addr := fmt.Sprintf("127.0.0.1:%d", r.Port)
	return fmt.Sprintf(`
  bigquery/testbed:
    project: "test-project"
    dataset: "test_dataset"
    endpoint:
      url: "%s"
      insecure: true
      without_authentication: true
    auto_create:
      dataset: false
      tables: false
    traces:
      table: "otel_spans"
    logs:
      table: "otel_logs"
    metrics:
      table: "otel_metrics"`, addr)
}

// ProtocolName returns the exporter type used in the collector config pipeline.
func (*bigQueryDataReceiver) ProtocolName() string {
	return "bigquery/testbed"
}

// RowCount returns the number of rows counted for a specific table.
func (r *bigQueryDataReceiver) RowCount(table string) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.tableCounts[table]
}

// --- storagepb.BigQueryWriteServer implementation ---

// GetWriteStream returns a committed stream so the exporter's managedwriter
// client accepts the stream as ready for writing.
func (*bigQueryDataReceiver) GetWriteStream(
	_ context.Context, req *storagepb.GetWriteStreamRequest,
) (*storagepb.WriteStream, error) {
	return &storagepb.WriteStream{
		Name:     req.GetName(),
		Type:     storagepb.WriteStream_COMMITTED,
		Location: "US",
	}, nil
}

// CreateWriteStream returns a committed stream so the exporter's
// managedwriter client accepts the stream as ready for writing.
func (*bigQueryDataReceiver) CreateWriteStream(
	_ context.Context, req *storagepb.CreateWriteStreamRequest,
) (*storagepb.WriteStream, error) {
	stream := req.GetWriteStream()
	name := req.GetParent() + "/streams/_default"
	if stream != nil && stream.GetName() != "" {
		name = stream.GetName()
	}
	return &storagepb.WriteStream{
		Name:     name,
		Type:     storagepb.WriteStream_COMMITTED,
		Location: "US",
	}, nil
}

// AppendRows implements the bidirectional streaming RPC. It reads
// AppendRowsRequests, forwards row counts to the testbed MockBackend consumers,
// counts serialized rows per table stream, and sends back an AppendRowsResponse
// with an AppendResult.
func (r *bigQueryDataReceiver) AppendRows(srv storagepb.BigQueryWrite_AppendRowsServer) error {
	var streamTable string

	for {
		req, err := srv.Recv()
		if err != nil {
			return nil // client closed stream; not an error
		}

		// Parse the table name from the write stream path:
		// "projects/{p}/datasets/{d}/tables/{t}/streams/_default"
		if ws := req.GetWriteStream(); ws != "" {
			streamTable = parseTableFromStream(ws)
		}

		// Count the serialized rows in this append request and forward matching
		// synthetic items to MockBackend's signal consumers.
		serialized := req.GetProtoRows().GetRows().GetSerializedRows()
		n := len(serialized)

		if n > 0 {
			switch streamTable {
			case "otel_spans":
				if r.tc != nil {
					td := ptrace.NewTraces()
					spans := td.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans()
					for range n {
						spans.AppendEmpty()
					}
					if err := r.tc.ConsumeTraces(srv.Context(), td); err != nil {
						return err
					}
				}
			case "otel_logs":
				if r.lc != nil {
					ld := plog.NewLogs()
					logs := ld.ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
					for range n {
						logs.AppendEmpty()
					}
					if err := r.lc.ConsumeLogs(srv.Context(), ld); err != nil {
						return err
					}
				}
			case "otel_metrics":
				if r.mc != nil {
					md := pmetric.NewMetrics()
					dps := md.ResourceMetrics().AppendEmpty().ScopeMetrics().AppendEmpty().Metrics().AppendEmpty().SetEmptyGauge().DataPoints()
					for range n {
						dps.AppendEmpty()
					}
					if err := r.mc.ConsumeMetrics(srv.Context(), md); err != nil {
						return err
					}
				}
			}
		}

		r.ackedRows.Add(int64(n))
		if streamTable != "" {
			r.mu.Lock()
			r.tableCounts[streamTable] += int64(n)
			r.mu.Unlock()
		}

		// Send a success response with an AppendResult containing an offset.
		offset := r.ackedRows.Load()
		resp := &storagepb.AppendRowsResponse{
			Response: &storagepb.AppendRowsResponse_AppendResult_{
				AppendResult: &storagepb.AppendRowsResponse_AppendResult{
					Offset: &wrapperspb.Int64Value{Value: offset},
				},
			},
		}
		if err := srv.Send(resp); err != nil {
			return nil
		}
	}
}

// parseTableFromStream extracts the table name from a write stream path
// of the form "projects/{p}/datasets/{d}/tables/{t}/streams/{s}".
func parseTableFromStream(stream string) string {
	// Split on "/" and find the element after "tables".
	parts := strings.Split(stream, "/")
	for i, p := range parts {
		if p == "tables" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}
```

---

## 3. Staged File 2 — `testbed/tests/bigquery_exporter_test.go`

```go
// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tests

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/common/testutil"
	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/datareceivers/bigquerydatareceiver"
	"github.com/open-telemetry/opentelemetry-collector-contrib/testbed/testbed"
)

// TestTrace10kSPSBigQueryExporter runs the standard 10k spans/sec testbed
// scenario with the BigQuery exporter as the pipeline exporter, writing to
// an in-process Storage Write API gRPC receiver on loopback.
func TestTrace10kSPSBigQueryExporter(t *testing.T) {
	sender := testbed.NewOTLPTraceDataSender(testbed.DefaultHost, testutil.GetAvailablePort(t))
	receiver := bigquerydatareceiver.NewBigQueryDataReceiver(testutil.GetAvailablePort(t))

	Scenario10kItemsPerSecond(
		t,
		sender,
		receiver,
		testbed.ResourceSpec{
			ExpectedMaxCPU: 40,
			ExpectedMaxRAM: 200,
		},
		performanceResultsSummary,
		nil, // no extra processors
		nil, // no extensions
		nil, // default load options
	)
}

// TestLog10kDPSBigQueryExporter runs the standard 10k log records/sec
// testbed scenario with the BigQuery exporter.
func TestLog10kDPSBigQueryExporter(t *testing.T) {
	sender := testbed.NewOTLPLogsDataSender(testbed.DefaultHost, testutil.GetAvailablePort(t))
	receiver := bigquerydatareceiver.NewBigQueryDataReceiver(testutil.GetAvailablePort(t))

	Scenario10kItemsPerSecond(
		t,
		sender,
		receiver,
		testbed.ResourceSpec{
			ExpectedMaxCPU: 40,
			ExpectedMaxRAM: 200,
		},
		performanceResultsSummary,
		nil,
		nil,
		nil,
	)
}

// TestMetric10kDPSBigQueryExporter runs the standard 10k metric data
// points/sec testbed scenario with the BigQuery exporter.
func TestMetric10kDPSBigQueryExporter(t *testing.T) {
	sender := testbed.NewOTLPMetricDataSender(testbed.DefaultHost, testutil.GetAvailablePort(t))
	receiver := bigquerydatareceiver.NewBigQueryDataReceiver(testutil.GetAvailablePort(t))

	Scenario10kItemsPerSecond(
		t,
		sender,
		receiver,
		testbed.ResourceSpec{
			ExpectedMaxCPU: 40,
			ExpectedMaxRAM: 200,
		},
		performanceResultsSummary,
		nil,
		nil,
		nil,
	)
}

// TestBigQueryExporterDataIntegrity verifies that the BigQuery exporter
// delivers all generated traces without loss through a short burst test.
// This is a correctness test, not a performance benchmark.
func TestBigQueryExporterDataIntegrity(t *testing.T) {
	sender := testbed.NewOTLPTraceDataSender(testbed.DefaultHost, testutil.GetAvailablePort(t))
	receiver := bigquerydatareceiver.NewBigQueryDataReceiver(testutil.GetAvailablePort(t))

	resultDir := t.TempDir()

	agentProc := testbed.NewChildProcessCollector(testbed.WithEnvVar("GOMAXPROCS", "2"))

	// Build a minimal config: otlp receiver → batch processor → bigquery exporter
	configStr := createConfigYaml(t, sender, receiver, resultDir, nil, nil)
	configCleanup, err := agentProc.PrepareConfig(t, configStr)
	require.NoError(t, err)
	defer configCleanup()

	loadOptions := &testbed.LoadOptions{
		DataItemsPerSecond: 1000,
		ItemsPerBatch:      100,
		Parallel:           1,
	}
	dataProvider := testbed.NewPerfTestDataProvider(*loadOptions)

	tc := testbed.NewTestCase(
		t,
		dataProvider,
		sender,
		receiver,
		agentProc,
		&testbed.PerfTestValidator{},
		performanceResultsSummary,
		testbed.WithResourceLimits(testbed.ResourceSpec{
			ExpectedMaxCPU: 40,
			ExpectedMaxRAM: 200,
		}),
	)
	t.Cleanup(tc.Stop)

	tc.StartBackend()
	tc.StartAgent()

	tc.StartLoad(*loadOptions)

	tc.WaitFor(func() bool { return tc.LoadGenerator.DataItemsSent() > 0 }, "load generator started")
	tc.Sleep(tc.Duration)
	tc.StopLoad()

	tc.WaitFor(func() bool {
		return tc.LoadGenerator.DataItemsSent() == tc.MockBackend.DataItemsReceived()
	}, "all data items received")

	tc.ValidateData()
}
```

---

## 4. Verification — Compile & Run Proof

Compile-and-lint verification (§4.1) passed against `v0.0.3` in a contrib
checkout at commit `96567c08`; runtime `RUN_TESTBED=1` execution and result
capture (§4.2) are pending the `v0.1.0` release:

### 4.1 Compile & Lint Verification

```bash
# In the opentelemetry-collector-contrib checkout (verified at commit 96567c08)
# with exporter/bigqueryexporter registered in cmd/oteltestbedcol/builder-config.yaml:
make genoteltestbedcol
make crosslink
make goporto
make -C testbed checklicense lint
cd testbed && GOTOOLCHAIN=local go test -race -c ./tests

# Expected: exit 0 on make genoteltestbedcol, make crosslink, make goporto,
# make -C testbed checklicense, make -C testbed lint (misspell + golangci-lint),
# and go test -race -c ./tests
```

### 4.2 Test Run Verification

```bash
make oteltestbedcol
cd testbed/tests
RUN_TESTBED=1 TESTCASE_DURATION=5s GOTOOLCHAIN=local go test \
  -v -run 'TestTrace10kSPSBigQueryExporter|TestLog10kDPSBigQueryExporter|TestMetric10kDPSBigQueryExporter|TestBigQueryExporterDataIntegrity' \
  -count=1 -timeout 120s

# Expected: all 4 tests PASS, 0 goroutine leaks, 0 data loss
```

### 4.3 Expected Results

| Test | Signal | Rate | Expected CPU | Expected RAM | Data Loss |
|---|---|---|---|---|---|
| `TestTrace10kSPSBigQueryExporter` | traces | 10k spans/s | < 40% | < 200 MiB | 0 |
| `TestLog10kDPSBigQueryExporter` | logs | 10k logs/s | < 40% | < 200 MiB | 0 |
| `TestMetric10kDPSBigQueryExporter` | metrics | 10k DP/s | < 40% | < 200 MiB | 0 |
| `TestBigQueryExporterDataIntegrity` | traces | 1k spans/s | < 40% | < 200 MiB | 0 |

### 4.4 Resource Spec Rationale

The `ExpectedMaxCPU: 40` and `ExpectedMaxRAM: 200` limits are more generous
than the standard OTLP receiver tests (20% CPU, 100 MiB RAM) because the
BigQuery exporter performs dynamic protobuf encoding, SHA-256 fingerprinting,
and gRPC streaming serialization inside the Collector child process alongside
the standard Collector pipeline overhead.

---

## 5. Integration with Existing Testbed

### 5.1 `cmd/oteltestbedcol/builder-config.yaml` Wiring

`testbed/go.mod` does **not** depend on `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter`
or `exporter/bigqueryexporter`: `testbed/tests` imports only
`testbed/datareceivers/bigquerydatareceiver` and spawns the `oteltestbedcol`
binary as a child process (`testbed.NewChildProcessCollector`). Because
`bigquerydatareceiver` imports `cloud.google.com/go/bigquery/storage/apiv1/storagepb`,
`go.opentelemetry.io/collector/consumer`, `go.opentelemetry.io/collector/pdata`,
and `google.golang.org/grpc`, running `make -C testbed tidy` adds
`cloud.google.com/go/bigquery` to `testbed/go.mod`.

Register `exporter/bigqueryexporter` under `exporters:` in
`cmd/oteltestbedcol/builder-config.yaml` (matching the `contrib-base` version
at `96567c08`) and regenerate/build the testbed collector:

```yaml
exporters:
  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter v0.164.1
```

```bash
make genoteltestbedcol oteltestbedcol
```

Do **not** edit `replaces:` in `cmd/oteltestbedcol/builder-config.yaml` manually:
`make genoteltestbedcol` and `make oteltestbedcol` invoke
`./internal/buildscripts/ocb-add-replaces.sh oteltestbedcol`, which writes the
generated `replaces:` entries into
`cmd/oteltestbedcol/builder-config-replaced.yaml` before running the builder.

(`exporter/bigqueryexporter/go.mod` in turn requires `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.1.0`; during pre-release staging, `v0.0.3` or a local `replace` directive in `exporter/bigqueryexporter/go.mod` can be used.)

### 5.2 `distributions.yaml` (No Change)

The testbed is not a distribution; it does not need a `distributions.yaml`
entry. The BQ-OTEL-Exporter is pulled only as a test dependency.

### 5.3 CI Integration

Add the BigQuery testbed tests to the existing `testbed/runtests.sh` CI job:

```bash
# In testbed/runtests.sh, add:
RUN_TESTBED=1 go test -v -run 'BigQuery' -timeout 300s
```

---

## 6. Hermeticity Guarantees

| Concern | Guarantee |
|---|---|
| GCP credentials | None required — self-contained `storagepb.UnimplementedBigQueryWriteServer` runs in-process on loopback |
| Network calls | Zero — all gRPC traffic is loopback `127.0.0.1:<port>` (allocated via `testutil.GetAvailablePort`) |
| External services | Zero — no BigQuery, no GCS, no IAM |
| BQ-OTEL-Exporter internal imports | Zero — `receiver.go` imports only public `storagepb`, `consumer`/`pdata`, `grpc`/`protobuf`, and `testbed` packages |
| Disk I/O | `t.TempDir()` only (auto-cleaned by `testing.T`) |
| Determinism | Counters are pure `sync/atomic` increments with no clock or random behavior |
| Race safety | All counters use `sync/atomic` and `sync.Mutex` for per-table counts |
