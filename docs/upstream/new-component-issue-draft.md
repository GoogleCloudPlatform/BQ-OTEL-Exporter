# Donation issue draft: BigQuery exporter

Status: draft. Do not file it before the checklist below is complete. Filing
is a human step; see [outreach-and-governance.md](outreach-and-governance.md).

The issue is filed with the "Component donation" form of
opentelemetry-collector-contrib, `.github/ISSUE_TEMPLATE/new_component.yaml`.
At the [pinned commit](contrib-pr-staging.md#pinned-references) that form was
last changed in commit `555b399d` (2025-12-05). It applies the labels
`Sponsor Needed` and `needs triage`. Each `###` heading in the body below is a
field label of the form, in form order; paste each section into the field of
the same name. The form has no stability field, so the stability target is
under "Additional context".

## Pre-filing checklist

- [ ] The library tag exists:
  <https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/tag/v0.1.0>.
- [ ] The performance envelope exists at the tagged commit:
  [`docs/benchmarks/v0.1.0-performance-envelope.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/benchmarks/v0.1.0-performance-envelope.md)
  (summary already filled in under "Additional context" below).
- [ ] The live BigQuery workflow (`.github/workflows/live-integration.yml`)
  passes on the tagged commit.
- [ ] The courtesy message to the author of
  [#46280](https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/46280) is sent
  ([outreach-and-governance.md](outreach-and-governance.md#courtesy-message-to-glacion)).
- [ ] The donation is announced in `#otel-collector-dev` and at a Collector
  SIG meeting (`docs/new-components.md` lines 95-97).
- [ ] At least two more codeowners have agreed and pass the
  [codeowner checklist](outreach-and-governance.md#codeowner-checklist).
  `<sponsor>` below is replaced (`haiyuan-eng-google` and `schan1031` are already confirmed).
- [ ] A sponsor has agreed, or the issue is filed without one to look for a
  sponsor, as the form allows.
- [ ] The issue author's OpenTelemetry membership is confirmed. The form asks
  for codeowners who are OpenTelemetry members.

## Title

```text
Component donation: BigQuery exporter (exporter/bigqueryexporter)
```

## Body

### Building and distributing outside this repository

- [x] I understand I can use and distribute my component outside of this repository.

### Existing component implementation

https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter

### Components covering similar use cases

- [`exporter/googlecloudexporter`](https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/main/exporter/googlecloudexporter)
  sends metrics to Cloud Monitoring, traces to Cloud Trace, and logs to Cloud
  Logging. It is the closest component in this repository, and the proposed
  component follows its packaging: a thin wrapper around a library that lives
  outside this repository. The comparison is below.
- Earlier BigQuery exporter proposals in this repository: #34809 (opened
  2024-08-22, closed as inactive on 2025-02-07) and pull request #46280 by
  @glacion (opened 2026-02-23, closed as inactive on 2026-03-24), which
  implemented #34809 at `development` stability on the Storage Write API.
  Thank you to both authors; this proposal picks up the same need.

| | `googlecloudexporter` | `bigqueryexporter` (proposed) |
| --- | --- | --- |
| Destination | Cloud Monitoring, Cloud Trace, and Cloud Logging | One BigQuery table per signal |
| Write path | Google Cloud client libraries, through `github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/collector` | BigQuery Storage Write API, default stream |
| Data model | The model of each destination product | Relational OTLP rows with a documented, versioned table schema (`v0alpha2`) |
| Reading the data | The destination products | SQL, with deduplication views and companion views |
| Packaging in contrib | Wraps an external library; its `Config` embeds the library configuration with `squash` | Wraps an external library; `Config` is a type alias of the library configuration |
| Status in contrib | `beta`, `contrib` distribution | `development` at donation, `alpha` in the last pull request |

### The purpose and use-cases of the component

The BigQuery exporter writes OTLP traces, logs, and metrics to BigQuery tables
through the [BigQuery Storage Write API](https://cloud.google.com/bigquery/docs/write-api).
Each signal goes to its own table with a documented, versioned schema, so the
data can be queried with SQL without a Cloud Logging sink, a Pub/Sub and
Dataflow pipeline, or batch file loads in between.

Use cases:

- SQL analysis of traces, logs, and metrics, and joins with other data in
  BigQuery.
- Long-term retention in partitioned tables that the user owns.
- Analysis of generative AI and agent telemetry. The library ships views over
  GenAI spans; the fixture matrix of the frameworks it was tested with is in
  [`docs/agent-frameworks.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/agent-frameworks.md).

Delivery is at least once. The exporter appends to the default stream, so a
retried append can store a record twice; read-time deduplication views cover
that case. Rows that BigQuery rejects can go to a quarantine table instead of
being dropped. The design is written down in
[`docs/schema-rationale.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/schema-rationale.md).

### Example configuration for the component

```yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

exporters:
  bigquery:
    project: my-project
    dataset: otel

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [bigquery]
    logs:
      receivers: [otlp]
      exporters: [bigquery]
    metrics:
      receivers: [otlp]
      exporters: [bigquery]
```

`project` and `dataset` are required. The full option reference is in the
[library README](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/README.md#configuration).

### Telemetry data types supported

Traces, logs, and metrics.

### Code Owners

@haiyuan-eng-google, @&lt;sponsor&gt;, @schan1031

### Sponsor (optional)

@&lt;sponsor&gt;

### Additional context

- **Proposed location:** `exporter/bigqueryexporter`, component type
  `bigquery`, module
  `github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter`.
- **Stability target:** `development` for the first two pull requests and
  `alpha` in the last one, as `docs/new-components.md` describes.
- **Release:** [v0.1.0](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/tag/v0.1.0).
- **Performance:** In [`docs/benchmarks/v0.1.0-performance-envelope.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/benchmarks/v0.1.0-performance-envelope.md),
  against the live BigQuery Storage Write API (`US` multi-region,
  `stream_pool_size=4`, `connection_pool_size=4`, `workers=4`,
  `batch_size=500`, `1 KiB` payload), the exporter sustains **`10,404` spans/s**
  (`28.72 MiB/s`, `p50 114.86 ms`), **`9,594` logs/s** (`21.81 MiB/s`,
  `p50 129.94 ms`), and **`9,185` metric points/s** (`10.97 MiB/s`,
  `p50 122.01 ms`) at **`86.8 MiB` peak RSS**, **`1.24–1.66` vCPU per 10k
  rows/s**, and `0` rejected rows or failed batches. In hermetic `bqfake`
  benchmarks: Suite A (`stream_pool_size=4`, `1 KiB` payload, redaction off,
  backpressure off) reaches **`27,896` spans/s**, **`28,983` logs/s**, and
  **`23,544` metrics/s** (Suite B with Step-0 RE2 redaction enabled: `17,048`
  spans/s, `18,407` logs/s, `22,256` metrics/s); Suite C (`8 KiB` traces, `50%`
  `RESOURCE_EXHAUSTED` AIMD backpressure, local SHA-256 `--offload-dir` offload)
  sustains `17,169` spans/s (`0` failed batches) with `99.92%` SHA-256 offload
  deduplication (`35,473 / 35,500` spans); and the Section 7 high-volume CUJ
  profiles (`stream_pool_size=8`, `workers=8`, `v0.0.2` sweep) sustain
  **`1.45–3.87 TiB/day`** across all 4 profiles (including `32 KiB` GenAI
  telemetry with Step-0 RE2 redaction + local `--offload-dir` offload at `1.45
  TiB/day`, `0` rejected rows) with `0` goroutine leaks
  (`goleak.VerifyTestMain` across `14` test packages).
- **Pull request plan:** the three pull requests are staged in
  [`docs/upstream/contrib-pr-staging.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/upstream/contrib-pr-staging.md)
  and
  [`docs/upstream/contrib-alpha-and-releases.md`](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/upstream/contrib-alpha-and-releases.md).
  The first adds the structure, and creating an exporter returns an error
  until the second adds the export path.
- **Maintenance:** the codeowners will update the library and the component
  when unstable Collector interfaces change.

### Tip

<sub>[React](https://github.blog/news-insights/product-news/add-reactions-to-pull-requests-issues-and-comments/) with 👍 to help prioritize this issue. Please use comments to provide useful context, avoiding `+1` or `me too`, to help us triage it. Learn more [here](https://opentelemetry.io/community/end-user/issue-participation/).</sub>
