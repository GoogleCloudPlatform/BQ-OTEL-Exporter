# Support

The BigQuery exporter for the OpenTelemetry Collector is an open-source
project. It is not an officially supported Google product, and it is not
covered by Google Cloud Support or its service level agreements. The project
maintainers and community help on a best-effort basis through GitHub.

## Getting help

- **Bugs and feature requests:** search the
  [GitHub issues](https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/issues)
  first, then open a new issue. Include the commit or version you run, your
  Collector configuration, and the relevant Collector log lines. Remove
  credentials and sensitive telemetry before you post.
- **Startup failures:** the [startup errors](README.md#startup-errors) table
  maps the messages the Collector prints when the exporter cannot start to
  their causes and fixes.
- **Configuration and operations:** see [Configuration](README.md#configuration)
  and [Delivery semantics](README.md#delivery-semantics) in the README, the
  deployment guides in [`deploy/README.md`](deploy/README.md) and
  [`docs/deployment-models.md`](docs/deployment-models.md), and the rest of
  [`docs/`](docs/).

Problems with BigQuery or other Google Cloud services themselves, rather than
with this exporter, go to
[Google Cloud support](https://cloud.google.com/support).

## Security issues

Do not report a suspected vulnerability in a public issue. Follow
[SECURITY.md](SECURITY.md) instead.

## Code of conduct

Everyone taking part in the project is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
