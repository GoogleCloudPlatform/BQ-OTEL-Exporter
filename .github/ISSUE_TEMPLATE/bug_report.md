---
name: Bug report
about: Report a defect in the BigQuery exporter
title: ""
labels: bug
assignees: ""
---

<!--
Before you file:
- Do NOT paste credentials, key files or access tokens.
- Do NOT paste real telemetry content (attribute values, log bodies, trace or
  span IDs) or table rows. Redact them or reproduce with synthetic data.
- For a security vulnerability, do not open an issue. Follow SECURITY.md.
-->

## What happened

<!-- A clear description of the problem. -->

## What you expected

<!-- What should have happened instead. -->

## How to reproduce

<!-- The smallest configuration and input that shows the problem. -->

1.
2.
3.

## Environment

- Exporter version (tag or commit):
- Collector version and distribution (for example a custom build from `example/otelcol-builder.yaml`):
- Go version, if you built it yourself:
- Schema version in use (the table's `otel_schema_major`, `otel_schema_minor`, `otel_schema_patch` and `otel_schema_variant` labels, for example `1.0.0/default`, `0.3.0/default` for pre-freeze `v0alpha3` candidate tables, or `v0alpha2` for legacy tables with a `schema_version` column):
- BigQuery dataset location:
- Signals affected (traces, logs, or both):
- `auto_create.*` or `quarantine.enabled` set:

## Configuration

<!-- The exporter section of your Collector config, with project, dataset and
any paths redacted. -->

```yaml
```

## Logs and metrics

<!-- Relevant Collector log lines, and any `otelcol_exporter_bigquery_*` metric
values (for example rejected_rows by reason, retries by class). Remove anything
that contains telemetry content. -->

```text
```
