# OCB, otelcol-google, and Contrib Migration Guide

The BigQuery exporter can be deployed in three distribution modes. The
`exporters: bigquery:` YAML config block and the `v0alpha2` configuration
schema are identical across all three, so migrating between them requires no
config changes.

## Distribution Options

### Option 1: OCB (OpenTelemetry Collector Builder)

Build a custom collector that includes the BigQuery exporter directly from
this repository:

```yaml
# otelcol-builder.yaml
receivers:
  - gomod: go.opentelemetry.io/collector/receiver/otlpreceiver v0.164.0
exporters:
  - gomod: github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.2
processors:
  - gomod: go.opentelemetry.io/collector/processor/batchprocessor v0.164.0
```

```bash
ocb --config otelcol-builder.yaml
```

### Option 2: Google-Built OpenTelemetry Collector (otelcol-google)

Use the thin-wrapper package and `cmd/distrogen` to build a Google-curated
distribution:

```yaml
# registry.yaml (Option A — pre-contrib)
exporters:
  bigqueryexporter:
    gomod: github.com/GoogleCloudPlatform/opentelemetry-operations-collector/components/google-built-opentelemetry-collector/exporter/bigqueryexporter v0.164.0
    path: ../components/google-built-opentelemetry-collector/exporter/bigqueryexporter
```

```bash
go run ./cmd/distrogen generate \
  --spec=specs/google-built-opentelemetry-collector.yaml \
  --registry=components/google-built-opentelemetry-collector/registry.yaml
```

### Option 3: Upstream otelcol-contrib (after donation)

Once the exporter is donated to `open-telemetry/opentelemetry-collector-contrib`
as `exporter/bigqueryexporter`, use the standard contrib distribution:

```yaml
# registry.yaml (Option B — post-contrib)
exporters:
  bigqueryexporter:
    gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter v0.164.0
```

## Config Compatibility

The exporter config is identical across all three distributions. The YAML
`exporters: bigquery:` block does not change:

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
in all three distributions. No config migration is needed when switching
between OCB, otelcol-google, and otelcol-contrib.

## Migration Path

1. **Today**: Deploy with OCB or otelcol-google Option A using
   `github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.0.2`.
2. **After contrib donation**: Switch the registry `gomod` from the
   GoogleCloudPlatform path to the contrib path. The collector config, the
   `bigquery:` exporter type, and the `v0alpha2` schema remain unchanged.
3. **Stable**: The contrib distribution becomes the canonical deployment;
   the standalone repo and otelcol-google wrapper track the contrib version.
