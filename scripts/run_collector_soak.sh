#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

if [[ "${REBUILD_COLLECTOR:-0}" == "1" || ! -x "${COLLECTOR_BIN:-./otelcol-bq-dist/otelcol-bq}" ]]; then
  go run go.opentelemetry.io/collector/cmd/builder@v0.165.0 --config=example/otelcol-builder.yaml
fi

go run ./cmd/bq-otel-testbench \
  -mode=collector \
  -collector-bin="${COLLECTOR_BIN:-./otelcol-bq-dist/otelcol-bq}" \
  -collector-config="${COLLECTOR_CONFIG:-example/otel-collector-high-volume-logs.yaml}" \
  -workload-profile=access-logs \
  -signals=logs \
  -soak \
  -duration="${SOAK_DURATION:-65s}" \
  -max-procs="${COLLECTOR_GOMAXPROCS:-4}" \
  -batch-size=500 \
  -workers=4 \
  -stream-pool-size=8 \
  -connection-pool-size=8 \
  "$@"
