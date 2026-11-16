# Contributing

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement (CLA). You, or your employer, keep the copyright to your
contribution; the CLA gives Google permission to use and redistribute your
contributions as part of the project. Sign the Google Individual CLA, or ask
your employer to sign the Google Corporate CLA, at
<https://cla.developers.google.com/>, where you can also see the agreements you
already have on file.

You generally sign a CLA only once, so if you have already signed one for
another Google project, you probably do not need to sign it again. The
`cla/google` check on every pull request confirms that each commit author is
covered, and a pull request cannot merge until it passes.

## Provenance

This component is an **independent implementation**. It is not a fork or
adaptation of any existing OTLP-to-BigQuery exporter.

Contributors must not copy code from third-party exporters into this repository.
If a third-party implementation is consulted for behavioral reference, say so in
the pull request description, name the source, and describe what was observed
rather than what was copied. Reuse of Apache-2.0 licensed code is possible but
must be raised in the PR first so attribution and license headers are handled
correctly.

## Layout

The tree below shows the target layout of this repository. It keeps its Go
module path and places the `bigqueryexporter` component at the module root,
modeled on OpenTelemetry Collector contrib's `exporter/clickhouseexporter`.
Because [`docs/upstream/`](docs/upstream/) stages a thin
`exporter/bigqueryexporter` wrapper that delegates to this library rather than
moving every root file verbatim, the module path, public import paths, and
self-telemetry scope stay stable while component code is separated from
repository-only tooling:

```text
github.com/GoogleCloudPlatform/BQ-OTEL-Exporter

# Component: package bigqueryexporter (contrib component shape)
README.md                     status table, configuration, schema, and operations
metadata.yaml                 component metadata consumed by mdatagen
documentation.md              mdatagen-generated internal telemetry documentation
doc.go                        //go:generate make mdatagen
config.go                     exporter configuration and validation
config_deprecation.go         deprecated configuration key registry
factory.go                    component factory, defaults, queue, retry, and timeout
exporter.go                   shared signal exporter (clients, lifecycle, append, quarantine)
exporter_logs.go              logs pipeline
exporter_metrics.go           metrics pipeline
exporter_traces.go            traces pipeline
destination.go                control-plane dataset, table, view, and search-index provisioning
indexmap.go                   row-position to original batch record-index mapping for retries
writer_observer.go            telemetry recording hooks passed to internal/bigquery
*_test.go                     component unit tests and exporter-to-CLI round trips
generated_package_test.go     hand-maintained exception (unit/integration goleak options)
integration_*_test.go         live BigQuery/GCS integration tests (//go:build integration)
internal/
  # Component packages
  bigquery/                   Storage Write API managedwriter wrapper, sizing, error classification
  diag/                       content-free diagnostic log fields and error-message sanitizer
  googlehttp/                 credentials and retained HTTP client/connection-pool helpers
  metadata/                   generated component status and hand-written self-telemetry
  offload/                    content-addressed cloud object storage payload offloading
  otlpjson/                   OTLP AnyValue and attribute bag encoding for BigQuery JSON
  protoenc/                   dynamic BigQuery-schema protobuf row encoder
  redact/                     step-0 attribute key and string value redaction
  schema/                     versioned table DDLs, companion views, dedup SQL, migration SQL
  transform/                  pdata-to-row transforms, structural limits, and log fingerprints
  # Shared packages
  testfakes/bqfake/           in-process Storage Write API and REST v2 test fake
  testsupport/                test helpers in a non-test package (must not import the root package)
  # Repo-only packages (kept under root internal/ for root round-trip tests)
  cli/
    backfill/                 appends historical OTLP JSON archives from GCS into BigQuery
    quarantinereplay/         otel_quarantine extraction and OTLP replay
    testbench/                synthetic GenAI/MCP workload generator and benchmark runner
    validate/                 dataset preflight checks (schema, views, IAM, Storage Write)
testdata/
  config.yaml                 configuration fixtures keyed by component ID
  otlp/                       synthetic OTLP SDK fixtures for component tests

# Shared directory with explicit subsets
docs/
  # Component reference
  config-inventory.md         configuration keys, defaults, and stability classes
  migration.md                configuration deprecation and schema migration guide
  cost-estimation.md          ingestion, storage, and query cost model
  schema-rationale.md         schema and write-path design rationale
  agent-frameworks.md         GenAI and MCP framework compatibility notes
  # Repo-only
  adr/                        architecture decision records
  architecture/               repository-level architecture notes
  operator-guides/            runbooks for repo-shipped CLIs and collector migrations
  deployment-models.md        deployment topology comparisons
  ci-setup.md                 GitHub Actions and Workload Identity Federation setup
  benchmarks/                 recorded performance envelopes
  provenance.md               maintainer authorship and licensing declarations
  otel-registry-entry.yaml    OpenTelemetry ecosystem registry entry
  upstream/                   staged thin-wrapper PRs and testbed files for contrib

# Repo-only: not part of the component
cmd/
  bq-otel-backfill/           GCS OTLP JSON archive backfill CLI
  bq-otel-testbench/          synthetic GenAI/MCP load benchmark CLI
  bq-otel-validate/           dataset preflight validation CLI (schema, views, IAM, Write)
  bq-quarantine-replay/       quarantine extraction and OTLP replay CLI
  healthcheck/                distroless container HTTP readiness/liveness probe
example/                      OCB manifests, Dockerfile, Compose, and collector configs
tools/
  repocheck/                  repository-wide conformance, deploy, dashboard, release checks
    testdata/registry/        vendored OpenTelemetry registry JSON schema
  internal/contribcheck/      staged upstream contrib wrapper verification (incl. stage/)
deploy/                       Cloud Run, continuous queries, Dataform, Helm, and Terraform
dashboards/                   Grafana and Looker Studio dashboards
scripts/                      contrib gate verification script (verify_contrib_gates.sh)
.github/                      CI, release, and contrib verification workflows, plus templates
```

Boundary and module conventions:

- **Go `internal/` visibility and import boundaries.** `internal/cli/` stays
  under root `internal/` rather than `cmd/internal/` because Go restricts
  `x/internal/y` imports to only code in the tree rooted at `x`, and
  exporter-to-CLI round-trip tests in the root package use those CLI packages
  alongside unexported exporter internals. Component production code must not
  import `internal/cli/`, and `internal/testsupport/` must not import the root
  package to avoid an import cycle with root in-package tests.
- **`tools/` and `docs/` split.** `tools/repocheck/` holds repository-wide
  checks of `deploy/`, `dashboards/`, workflows, docs, and release assets,
  whereas `tools/internal/contribcheck/` validates the staged upstream wrapper
  drafts in `docs/upstream/`. In `docs/`, component reference pages
  (configuration inventory, schema rationale, migration, cost estimation, and
  agent frameworks; three of which the staged contrib README links) are
  separate from repository-only pages (ADRs, architecture, benchmarks, CI
  setup, deployment models, operator guides, provenance, registry metadata, and
  upstream donation staging).
- **Single Go module.** The repository remains one Go module (`go.mod` at the
  root alongside repo-only build, release, and governance files such as
  `Makefile`, `.goreleaser.yaml`, `Dockerfile.goreleaser`, `CODEOWNERS`,
  `SECURITY.md`, and `CHANGELOG.md`).
- **Intentional mdatagen exception.** `generated_package_test.go` is
  hand-maintained despite its standard `DO NOT EDIT` header because it chains
  unit-only and integration-only `goleak` options that `mdatagen` cannot
  express. `make mdatagen` writes both `internal/metadata/generated_status.go` and
  `documentation.md`, while `generated_component_test.go` and generated
  telemetry code remain tracked as follow-ups rather than part of the layout
  reorganization.

Some paths in this target tree are populated incrementally across the remaining
[issue #91](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/issues/91)
follow-up PRs:

- `internal/testsupport/` receives shared test helpers (`readRepoText`,
  `parseYAMLMap`, `yamlPath`, `stripSQLComments`, `mustBigQuerySchema`, and the
  live dataset/dry-run helpers) extracted from the root package.
- `tools/repocheck/` receives repository-wide conformance, deploy, dashboard,
  and release checks, and root `testdata/registry/` moves to
  `tools/repocheck/testdata/registry/`.
- `internal/contribcheck/` (with `stage/`) moves to
  `tools/internal/contribcheck/`. Because the root package cannot import
  `tools/internal/`, root `contrib_verify_workflow_test.go` moves in the same
  PR, and path citations in `scripts/verify_contrib_gates.sh`,
  `docs/provenance.md`, and `docs/upstream/contrib-pr-staging.md` update
  alongside it.
- `internal/{backfill,quarantinereplay,testbench,validate}` move under
  `internal/cli/`, updating package paths in `cmd/`, `docs/provenance.md`, and
  `.github/workflows/bench-fuzz.yml`.

## Development

You need the Go toolchain named in `go.mod` and two tools that CI also runs:

- [golangci-lint](https://golangci-lint.run/welcome/install/) v2, configured by
  `.golangci.yml`;
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck), installed
  with `go install golang.org/x/vuln/cmd/govulncheck@latest`.

```bash
make fmt vet lint test   # the standard loop
make vuln                # govulncheck: known vulnerabilities reachable from this code
make tidy                # go mod tidy; CI fails if go.mod or go.sum would change
make bench               # every benchmark once, with allocation counts
make bench-compare       # benchstat: BASE_REF (default HEAD~1) vs the working tree
make fuzz                # every Fuzz target for FUZZTIME (default 30s) each
make integration-test    # live BigQuery; needs BQ_PROJECT and ADC
make mdatagen            # regenerate the files derived from metadata.yaml
```

CI runs gofmt, build, vet (with and without the `integration` build tag),
`go mod tidy -diff`, `make mdatagen` followed by a clean-diff and
untracked-file check on the generated files
(`internal/metadata/generated_status.go` and `documentation.md`),
golangci-lint, govulncheck and the unit tests on every pull request. The unit
tests run twice: once normally, and once with
`GOOGLE_API_USE_CLIENT_CERTIFICATE=true` to prove that they do not depend on the
credential and mTLS environment of the machine they run on.

No CI job runs the live-BigQuery integration tests, because they need real
credentials and create billable resources. If a change touches the write path or
the auto-create logic, run `make integration-test` against a scratch project and
say so in the pull request.

`make mdatagen` builds the `mdatagen` release that matches the Collector version
pinned in the Makefile, validates `metadata.yaml` against its schema, and copies
back two generated files: `internal/metadata/generated_status.go` (under the
repository's license header) and `documentation.md` (derived from the
`telemetry` section, committed as written). Only the Go telemetry code derived
from `telemetry` is validated and then discarded, because
`internal/metadata/telemetry.go` is hand-written. `generated_package_test.go` is
not regenerated either: it carries goleak options that mdatagen cannot express.
CI runs the target and fails on any resulting diff or uncommitted file, so keep
the `telemetry` metrics (without the `otelcol_` prefix) and attributes in ASCII
order and give every metric a `stability`.

New Go files start with the same two-line header as the rest of the repository:

```go
// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0
```

## Compatibility

The exporter has two compatibility surfaces, and both follow the Collector's
[component stability rules](https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#beta)
for a beta component: breaking changes are rare, each one ships with a
migration path inside this repository, and
[`docs/migration.md`](docs/migration.md) is that path. Because the contrib
`Config` is a type alias of this library's `Config`, every change below is a
contrib change as well.

### Configuration changes

[`docs/config-inventory.md`](docs/config-inventory.md) lists every key with
its type, default, first release and stability class (`stable` or
`experimental`). `config_inventory_test.go` compares that table, the golden
map in the test, and the deprecation registry with the `Config` struct on
every run, so the rules below are enforced rather than remembered.

- **Adding a key.** It needs a default that leaves existing deployments
  unchanged (a new *required* option is not allowed; give it a sensible
  default instead). Add it to `configInventoryGolden` and to the table in
  `docs/config-inventory.md` in the same pull request; the test fails until
  both are there. Classify it `experimental` if it is a tuning knob whose
  default or bounds may still move.
- **Retuning an `experimental` key.** Changing its default or bounds is
  allowed in any release with a `CHANGELOG.md` entry. A `stable` key's
  default does not change within the beta line.
- **Renaming or removing a key.** Never delete the field outright. In release
  N: add the replacement (if any), register the old key in
  `deprecatedConfigKeys` (`config_deprecation.go`) with `DeprecatedIn`,
  `RemovalEarliest` and the anchor of a new section in `docs/migration.md`,
  and add the row to the deprecated-keys table in `docs/config-inventory.md`.
  The old key keeps working, its value is applied to the replacement, and the
  exporter logs one `WARN` at startup linking to the migration section. The
  key stays accepted in N+1 and is removed no earlier than N+2 **and** six
  months after N. Setting both the old and the new key is a startup error.
  The test refuses a key that leaves `Config` without a registry entry, a
  registry entry whose anchor has no heading, and a removal release closer
  than two releases to the deprecation release.
- **Release numbering.** N counts tagged releases of this repository while
  the component lives here and contrib releases once it has moved.

### Schema changes

The BigQuery table layout is a **versioned contract** that downstream queries
and dbt models pin against. Its version is `internal/schema.Version`, stamped
onto every BigQuery table via the four `otel_schema_*` table metadata labels
(`otel_schema_major`, `otel_schema_minor`, `otel_schema_patch`,
`otel_schema_variant`); it is independent of the Go module version and of the
contrib release version.

- Adding a nullable column, a companion view or a search index is an
  additive change and stays within the current schema version. It still gets
  a `CHANGELOG.md` entry.
- Renaming, retyping, removing or changing the mode of a column is a breaking
  change: it needs a new `internal/schema.Version`, a section in
  [`docs/migration.md`](docs/migration.md) with the migration steps, and
  migration tooling where feasible (`cmd/bq-otel-backfill` is the starting
  point). The exporter never alters an existing table in place.
- Every schema change updates `internal/schema` and the README table together,
  and the schema version history in `docs/migration.md` records the first
  release that writes each version.
- A change to the reasoning behind the layout, deduplication or delivery
  semantics is recorded in [`docs/schema-rationale.md`](docs/schema-rationale.md).
  Code comments point to that page, not to any document outside the repository.

## Security and conduct

Report suspected vulnerabilities privately, as described in
[SECURITY.md](SECURITY.md). Everyone taking part in the project is expected to
follow the [Code of Conduct](CODE_OF_CONDUCT.md).
