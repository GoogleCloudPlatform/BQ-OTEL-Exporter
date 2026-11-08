# OCB, Standalone otelcol-google, and Contrib Migration Guide

The BigQuery exporter uses the identical `exporters: bigquery:` YAML
configuration block and `v0alpha2` BigQuery table schema across custom builds
today and upstream distributions after Contrib Alpha. Migrating between
deployments requires zero collector pipeline YAML or BigQuery table changes.

## Deployment Modes

### 1. Today (Pre-Contrib Alpha): Custom OCB Build or Container Templates

Before `exporter/bigqueryexporter` lands in
`open-telemetry/opentelemetry-collector-contrib`, deploy either the container /
Helm templates under [`deploy/`](../../deploy) or a custom collector built with
OpenTelemetry Collector Builder (`ocb`).

In a local checkout of this repository, [`example/otelcol-builder.yaml`](../../example/otelcol-builder.yaml)
builds directly from source (`v0.0.0` with `path: .`). When building outside a
local clone, replace that entry with the published module version (`v0.0.3`
today, or `v0.1.0` once the donation baseline is tagged):

```yaml
# otelcol-builder.yaml (remote module build without a local checkout)
receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.164.0
exporters:
  # Replace example/otelcol-builder.yaml's local v0.0.0 + path: . entry
  # with v0.0.3 today, or v0.1.0 once the donation-baseline tag is published.
  - gomod: github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.3
    name: bigqueryexporter
    import: github.com/GoogleCloudPlatform/BQ-OTEL-Exporter
processors:
  - gomod: go.opentelemetry.io/collector/processor/batchprocessor v0.164.0
```

```bash
ocb --config otelcol-builder.yaml
```

### 2. Post-Contrib Alpha: Upstream `otelcol-contrib` and Standalone `otelcol-google`

Once `exporter/bigqueryexporter` reaches `alpha` in
`open-telemetry/opentelemetry-collector-contrib` and is added to
`open-telemetry/opentelemetry-collector-releases`:

- **Upstream `otelcol-contrib`**: Run the stock `otelcol-contrib` binary or
  container image directly without maintaining a custom `ocb` manifest.
- **Standalone `otelcol-google` (`GoogleCloudPlatform/opentelemetry-operations-collector`)**:
  For self-deployed Google-built collectors, this project proposes adding the
  exporter to **standalone `otelcol-google`** through its standard
  component-addition process once `exporter/bigqueryexporter` reaches `alpha` in
  `opentelemetry-collector-contrib`, subject to
  `opentelemetry-operations-collector` maintainer review and acceptance
  (following the `googlecloudpubsub` precedent in
  [PR #432](https://github.com/GoogleCloudPlatform/opentelemetry-operations-collector/pull/432)
  while leaving separate managed cluster collector distributions untouched).

In `GoogleCloudPlatform/opentelemetry-operations-collector`, upstream `contrib`
components live in `cmd/distrogen/registry.yaml` using short component keys
without a hardcoded module version tag (`ApplyOTelVersion` stamps `"v" +
opentelemetry_contrib_version` from
`specs/google-built-opentelemetry-collector.yaml`, reserving
`components/google-built-opentelemetry-collector/registry.yaml` for in-repo
`path:` modules):

```diff
 # cmd/distrogen/registry.yaml (post-Contrib Alpha)
 exporters:
+  bigquery:
+    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter
+    docs_url: https://www.github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/bigqueryexporter/README.md
```

```yaml
# specs/google-built-opentelemetry-collector.yaml
opentelemetry_contrib_version: 0.<first-contrib-release>.0
components:
  exporters:
    - bigquery
```

```bash
make gen-google-built-otel
# Equivalent direct invocation:
go run ./cmd/distrogen generate \
  --spec ./specs/google-built-opentelemetry-collector.yaml \
  --registry ./components/google-built-opentelemetry-collector/registry.yaml \
  --templates ./templates/google-built-opentelemetry-collector
```

(For the historical pre-`v0.1.0` `cmd/distrogen` local thin-wrapper
build-compatibility record if an interim custom distribution is needed prior to
Contrib Alpha, see
[`docs/upstream/outreach-and-governance.md`](../upstream/outreach-and-governance.md#bundling-in-google-built-opentelemetry-collector-otelcol-google).)

## Config Compatibility

The exporter config is identical across custom OCB builds, `otelcol-contrib`,
and standalone `otelcol-google`. The YAML `exporters: bigquery:` block does not
change:

```yaml
exporters:
  bigquery:
    project: ${env:BQ_PROJECT}
    dataset: ${env:BQ_DATASET}
    location: ${env:BQ_LOCATION}
    auto_create:
      dataset: true
      tables: true
      companion_views: true
      search_indexes: true
```

The `v0alpha2` configuration schema (the `Config` struct) is the same Go type
across all deployment modes. No configuration or schema migration is needed when
switching binaries.

## Migration Path

1. **Today (Pre-Contrib Alpha)**: Deploy with a custom OCB build
   (`example/otelcol-builder.yaml` for a local source checkout, or pinned to
   published `v0.0.3` today / `v0.1.0` once tagged for remote module builds) or
   the Cloud Run, GKE, and Helm deployment templates in `deploy/`.
2. **Post-Contrib Alpha**: Switch the collector image or binary to upstream
   `otelcol-contrib` — or to standalone `otelcol-google` if accepted through its
   post-Alpha component-addition intake — while keeping the exact same
   `exporters: bigquery:` pipeline YAML and `v0alpha2` BigQuery tables and
   companion views.
