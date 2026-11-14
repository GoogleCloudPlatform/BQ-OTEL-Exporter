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

The repository follows the OpenTelemetry Collector contrib component layout, so
that donating it upstream is a move rather than a rewrite:

```
config.go            exporter configuration and validation
factory.go           component factory and defaults
exporter_traces.go   traces pipeline
exporter_logs.go     logs pipeline
metadata.yaml        component metadata consumed by mdatagen
internal/bigquery    Storage Write API client wrapper and error classification
internal/schema      versioned table DDL and canonical dedup SQL
internal/metadata    generated component status and self-telemetry instruments
docs/                schema-rationale.md (why the schema and write path look as
                     they do) and framework compatibility notes
example/             runnable collector configuration
testdata/            configuration fixtures
```

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
make integration-test    # live BigQuery; needs BQ_PROJECT, BQ_DATASET and ADC
make mdatagen            # regenerate the files derived from metadata.yaml
```

CI runs gofmt, build, vet (with and without the `integration` build tag),
`go mod tidy -diff`, `make mdatagen` followed by a clean-diff check,
golangci-lint, govulncheck and the unit tests on every pull request. The unit
tests run twice: once normally, and once with
`GOOGLE_API_USE_CLIENT_CERTIFICATE=true` to prove that they do not depend on the
credential and mTLS environment of the machine they run on.

No CI job runs the live-BigQuery integration tests, because they need real
credentials and create billable resources. If a change touches the write path or
the auto-create logic, run `make integration-test` against a scratch project and
say so in the pull request.

`make mdatagen` builds the `mdatagen` release that matches the Collector version
pinned in the Makefile, validates `metadata.yaml` against its schema, and
regenerates `internal/metadata/generated_status.go`. mdatagen also derives
telemetry code from the `telemetry` section; that output is validated and then
discarded, because `internal/metadata/telemetry.go` is hand-written.
`generated_package_test.go` is not regenerated either: it carries goleak options
that mdatagen cannot express. CI runs the target and fails on any resulting diff,
so keep the `telemetry` metrics and attributes in ASCII order and give every
metric a `stability`.

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
