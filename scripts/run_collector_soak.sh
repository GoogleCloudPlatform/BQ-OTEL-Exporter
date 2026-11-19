#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DEFAULT_COLLECTOR_BIN="./otelcol-bq-dist/otelcol-bq"
if [[ -z "${COLLECTOR_BIN:-}" || "${COLLECTOR_BIN}" == "${DEFAULT_COLLECTOR_BIN}" ]]; then
  REBUILD_VALUE="${REBUILD_COLLECTOR:-1}"
  if [[ "${REBUILD_VALUE}" == "1" || ! -x "${DEFAULT_COLLECTOR_BIN}" ]]; then
    go run go.opentelemetry.io/collector/cmd/builder@v0.165.0 --config=example/otelcol-builder.yaml
  else
    printf 'Reusing existing Collector binary: %s (set REBUILD_COLLECTOR=1 to rebuild from current sources)\n' "${DEFAULT_COLLECTOR_BIN}" >&2
  fi
else
  if [[ "${REBUILD_COLLECTOR:-0}" == "1" ]]; then
    go run go.opentelemetry.io/collector/cmd/builder@v0.165.0 --config=example/otelcol-builder.yaml
  fi
  printf 'Using custom Collector binary: %s\n' "${COLLECTOR_BIN}" >&2
fi

go run ./cmd/bq-otel-testbench \
  -mode=collector \
  -collector-bin="${COLLECTOR_BIN:-./otelcol-bq-dist/otelcol-bq}" \
  -collector-config="${COLLECTOR_CONFIG:-example/otel-collector-high-volume-logs.yaml}" \
  -workload-profile=access-logs \
  -resource-attrs="${RESOURCE_ATTRS:-16}" \
  -signals=logs \
  -soak \
  -duration="${SOAK_DURATION:-65s}" \
  -max-procs="${COLLECTOR_GOMAXPROCS:-4}" \
  -batch-size=500 \
  -workers=4 \
  -stream-pool-size=8 \
  -connection-pool-size=8 \
  -max-inflight-requests=32 \
  -max-request-bytes=8388608 \
  "$@"
