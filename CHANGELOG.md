# Changelog

All notable changes to the OpenTelemetry Collector BigQuery Exporter (`github.com/GoogleCloudPlatform/BQ-OTEL-Exporter`) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note on Milestone Lineage**: `v0alpha1` and `v0alpha2` below describe pre-release schema-contract snapshots (`internal/schema/schema.go` `Version = "v0alpha2"`) ahead of the inaugural `v0.0.1` semantic release (`metadata.yaml` component stability: `development`). They do not assign first-introduction dates to each feature. The `v0.0.1` section is a cumulative inventory of implemented features and release preparation, not changes since `v0alpha2`; repeated entries do not indicate features added twice.

## [Unreleased]

- Planned `v0.1.0` pre-donation library release (`metadata.yaml` component stability remains `development`; upstream OpenTelemetry Collector distribution integration targets `alpha` promotion, not GA).

## [0.0.3] - 2026-11-05

### Added
- **Upstream `opentelemetry-collector-contrib` 3-PR Live Checkout Verification
  (T2–T4)**: End-to-end validation of PR 1 (skeleton), PR 2 (functional factory
  delegating to `bigqueryexporter.NewFactory()`), and PR 3 (alpha promotion +
  `contrib` distribution registration via `make gendistributions` /
  `reports/distributions/contrib.yaml`) against all 19 upstream
  Makefile/lint/race gates (100.0% statement coverage, 0 goleak leaks).
  Findings folded into `docs/upstream/contrib-pr-staging.md` and
  `docs/upstream/contrib-alpha-and-releases.md`.
- **Cross-OS CI Matrix (T5)**: Added `cross-os` GitHub Actions job testing
  `macos-latest` and `windows-latest` with `go build`, `go vet`, and `go test`
  alongside `TestCrossOSMatrixInCIWorkflow` conformance test.
- **1 TiB/day 4-Profile Load Testbench & Sizing Envelope (T6)**: Added 4-profile
  CUJ benchmark results (P1 Traces 3.87 TiB/day, P2 Logs 3.05 TiB/day, P3
  Metrics 1.80 TiB/day, P4 GenAI 32 KiB with redaction+offload 1.45 TiB/day) in
  `docs/operator-guides/load-testbench-and-sizing.md` and
  `docs/benchmarks/v0.1.0-performance-envelope.md`.
- **5 Production Operator Guides & AST Conformance Suite (T7)**: Added
  `docs/operator-guides/` with 5 comprehensive runbooks (README, quarantine
  replay, schema validation and backfill, load testbench and sizing, OCB and
  contrib migration) and `operator_guides_conformance_test.go` verifying every
  CLI flag via Go AST extraction.
- **Dataform & BI Dashboard v1.0 Schema Conformance Suite (T8)**: Hardened
  `dataform_conformance_test.go` and `dashboards_conformance_test.go` to
  cross-check live SQL/JSON assets against `deploy/terraform/main.tf`,
  `internal/schema/schema.go`, and `internal/schema/tvf.go`.
- **Staged Upstream testbed Integration Suite (T9)**: Added
  `docs/upstream/contrib-testbed-staging.md` and
  `internal/contribcheck/contribcheck_testbed_test.go`.

## [0.0.2] - 2026-11-05

### Changed
- Lowered `go.mod` go directive from `1.26.5` to `1.26.0` to match
  `opentelemetry-collector-contrib` and `opentelemetry-operations-collector`
  so `go mod tidy -compat=1.26.0` leaves downstream `go.mod` files unchanged.
- Confirmed codeowners `@haiyuan-eng-google` and `@schan1031` in
  `metadata.yaml`, `CODEOWNERS`, and `README.md`.
- Fixed case-encoded module path for `proxy.golang.org` release polling.

### Added
- OpenTelemetry GitHub organization membership drafts for both codeowners.
- `google-built-opentelemetry-collector` (otelcol-google) bundling
  documentation with verified `cmd/distrogen` thin-wrapper architecture.
- Automated `contribcheck` invariant guards for root `go.mod`, membership
  drafts, otelcol-google Go/YAML blocks, and Collector version lockstep.
- `goleak` hermeticity for `internal/offload` and `internal/quarantinereplay`
  on workstations with ambient enterprise mTLS certificates.

## [0.0.1] - 2026-11-03

### Added (cumulative inventory)
- **Exported Collector Constructor Seams (`factory.go`)**: Exported `CreateDefaultConfig`, `CreateTracesExporter`, `CreateLogsExporter`, and `CreateMetricsExporter` matching `exporter.CreateTracesFunc`, `exporter.CreateLogsFunc`, and `exporter.CreateMetricsFunc` alongside `NewFactory()` so upstream OpenTelemetry Collector distribution wrappers (`opentelemetry-collector-contrib/exporter/bigqueryexporter`) can wire Collector-generated `exporter.Settings` directly.
- **Upstream `mdatagen` Goleak Configuration (`metadata.yaml`)**: Added `tests.goleak.ignore.top` (`go.opencensus.io/stats/view.(*worker).start`) to `metadata.yaml` for compatibility with stock `mdatagen` code generation while preserving build-tag-isolated unit and live-integration goroutine leak checks (`generated_package_test.go`, `goleak_options_unit_test.go`, `goleak_options_integration_test.go`).
- **Binary Archive SLSA Provenance & Container SPDX SBOM (`.github/workflows/release.yml`)**: Configured `actions/attest-build-provenance@v4` for GoReleaser archive checksums (`dist/checksums.txt`). Generates separate `linux/amd64` and `linux/arm64` container SPDX SBOMs, attaching and attesting each against its matching child digest (`syft`, `cosign attach sbom`, and `cosign attest --type spdxjson`) for `ghcr.io/googlecloudplatform/bq-otel-collector`.
- **Implementation Declarations & OpenTelemetry Registry Metadata (`docs/`)**: Added [`docs/provenance.md`](docs/provenance.md) recording maintainer authorship declarations pending verification/sign-off and [`docs/otel-registry-entry.yaml`](docs/otel-registry-entry.yaml) validated against the pinned destination schema, with no unpublished package version.
- **Default-Stream Pool Sharding (`write.stream_pool_size`)**: Added configurable multi-stream sharding across default-stream writers per signal table (`write.stream_pool_size` in `[1, 16]`) to scale throughput beyond a single gRPC write stream.
- **Adaptive AIMD Batch Backpressure (`write.backpressure`)**: Added opt-in additive-increase/multiplicative-decrease request-byte and in-flight concurrency control triggered by ResourceExhausted/Unavailable responses or append latency thresholds, with `otelcol_exporter_bigquery_backpressure_events`, `otelcol_exporter_bigquery_backpressure_level`, and `otelcol_exporter_bigquery_effective_request_bytes` self-telemetry metrics.
- **Recursive Multi-Agent Trajectory & MCP Companion Views (`internal/schema/`, `deploy/terraform/`)**:
  - `v_gen_ai_agent_trajectory`: 16-level cycle-safe recursive CTE reconstructing parent-child agent/LLM/tool execution DAGs with `is_orphan` cross-boundary detection and `is_token_leaf` deduplicated token accounting.
  - `v_mcp_spans` and `v_mcp_tool_usage`: Model Context Protocol JSON-RPC method, tool/resource/prompt target, session, transport, and latency analytics.
  - `v_gen_ai_metric_exemplars`: Joins `otel_metrics_dedup` exemplars back to `otel_spans_dedup` by `(trace_id, span_id)` with partition-filter gating (`allow_unprunable_views`).
- **Real-Time Alerting via BigQuery Continuous Queries (`deploy/continuous-queries/`)**: Added SQL templates (`tool_error_rate_alert.sql`, `token_budget_burn.sql`, `agent_latency_p95.sql`) reading `APPENDS(TABLE ...)` and exporting to Cloud Pub/Sub, plus opt-in Terraform provisioning (`enable_continuous_queries`).
- **Column-Level Security & Data Masking (`deploy/terraform/governance.tf`)**: Added opt-in Data Catalog taxonomy (`otel_sensitivity`), the `sensitive_payload` policy tag (`google_data_catalog_policy_tag.sensitive_payload`), the `sensitive_payload_mask` BigQuery data masking policy (`google_bigquery_datapolicy_data_policy.sensitive_payload_mask`), fine-grained/masked reader IAM bindings (`roles/datacatalog.categoryFineGrainedReader`, `roles/bigquerydatapolicy.maskedReader`), and redacted views (`enable_column_level_security`).

### Changed
- **Toolchain & Collector Baseline**: Pinned Go toolchain to `1.27.3` (`GO-2026-6809`) and OpenTelemetry Collector modules to `v0.164.0` / `v1.70.0` across `go.mod`, `Makefile`, Dockerfiles, OCB manifests, and GitHub Actions workflows.

### Fixed
- **HTTP Transport Leak Checks**: Restored goroutine leak checks (`goleak`) for exporter-owned HTTP transports in unit and integration test suites while isolating ambient mTLS helper processes in live integration runs.

---

## Pre-Release Contract Milestone `v0alpha2` — Three-Signal Relational Contract & Safety Controls

### Added
- **Metrics Signal Pipeline (`exporter_metrics.go`, `internal/transform/metrics.go`)**: Added `otel_metrics` table and `otel_metrics_dedup` view supporting `GAUGE`, `SUM`, `HISTOGRAM`, `EXPONENTIAL_HISTOGRAM`, and `SUMMARY` data points with exemplar arrays and deterministic `point_fingerprint` deduplication.
- **Dead-Letter Quarantine & Replay (`otel_quarantine`, `cmd/bq-quarantine-replay`)**: Added opt-in dead-letter quarantine table for rejected records and a standalone CLI (`cmd/bq-quarantine-replay`) to reconstruct OTLP JSONL payloads (including GCS-offloaded blobs via `-fetch-gcs`).
- **Step-0 Client-Side Redaction (`internal/redact/`)**: Added configurable key-glob and regex value scrubbing executed prior to GCS payload offloading, size validation, log/metric fingerprinting, and quarantine persistence, metered by `otelcol_exporter_bigquery_redacted_values`.
- **Content-Addressed GCS Payload Offloading (`internal/offload/`)**: Added conditional (`ifGenerationMatch=0`) Cloud Storage offloading for oversized or multimodal attributes with intra-batch coalescing, cross-batch LRU caching, and BigQuery `ObjectRef` `payload_refs` records.
- **Companion SQL View Suite (`internal/schema/schema.go`)**: Includes the 11 companion views (`otel_spans_as_allspans`, `v_gen_ai_spans`, `v_gen_ai_logs`, `v_gen_ai_metrics`, `v_gen_ai_metric_exemplars`, `v_gen_ai_model_costs`, `v_gen_ai_sessions`, `v_gen_ai_tool_usage`, `v_gen_ai_agent_trajectory`, `v_mcp_spans`, and `v_mcp_tool_usage`). [`docs/agent-frameworks.md`](docs/agent-frameworks.md) reports historical executions for 7 agent frameworks and links their evidence; [`testdata/otlp/manifest.yaml`](testdata/otlp/manifest.yaml) identifies the checked-in fixtures as synthetic rather than captured executions.
- **Production Deployment Packaging (`deploy/`, `example/`, `.goreleaser.yaml`)**: Added Terraform module (`deploy/terraform/`), Helm chart (`deploy/helm/bigquery-otel-collector`), Cloud Run Knative service (`deploy/cloudrun/service.yaml`), distroless multi-arch container builds with static `/healthcheck`, and GoReleaser configuration.

---

## Pre-Release Contract Milestone `v0alpha1` — Initial Trace & Log Storage Write API Exporter

### Added
- **Traces & Logs Storage Write API Pipeline (`exporter_traces.go`, `exporter_logs.go`, `internal/bigquery/`)**: Implemented high-throughput protobuf append transport over `cloud.google.com/go/bigquery/storage/managedwriter` `_default` streams with single-owner `exporterhelper` retry and uncertain-acknowledgement subset replay.
- **Dual-Timestamp & JSON Sidecar Relational Schema (`internal/schema/`, `internal/transform/`)**: Defined `otel_spans` (hourly partitioned on `start_time`) and `otel_logs` (daily partitioned on `timestamp`) with nanosecond `INT64` companion columns, deterministic `fp1:` log fingerprinting, and `attributes_schema` leaf-type sidecars.
