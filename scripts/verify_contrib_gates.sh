#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

# Runs the opentelemetry-collector-contrib CI and new-component donation gates
# across the staged PR 1, PR 2, and PR 3 exporter/bigqueryexporter trees.
#
# Usage:
#   scripts/verify_contrib_gates.sh
#
# Environment variables:
#   CONTRIB_SHA         Pinned opentelemetry-collector-contrib commit SHA.
#                       Defaults to the commit pinned in internal/contribcheck.
#   CONTRIB_REPO        Git URL of opentelemetry-collector-contrib.
#   LIBRARY_VERSION     Target github.com/GoogleCloudPlatform/BQ-OTEL-Exporter tag
#                       (default: v0.1.0).
#   USE_LOCAL_CHECKOUT  "true" to wire the local BQ-OTEL-Exporter checkout via an
#                       ephemeral go.mod replace inside the contrib clone only.
#   LOCAL_REPO_DIR      Local BQ-OTEL-Exporter directory for USE_LOCAL_CHECKOUT=true
#                       (defaults to the repository root containing this script).
#   CONTRIB_DIR         Optional pre-existing contrib checkout directory. When unset,
#                       an ephemeral directory is created under WORK_DIR and removed
#                       on exit unless KEEP_CONTRIB_DIR=true.
#   WORK_DIR            Parent directory for ephemeral temp workspaces.
#   LOG_DIR             Directory where per-gate logs, tool_versions.txt,
#                       summary.tsv, and summary.md are written.
#   KEEP_CONTRIB_DIR    "true" to preserve an ephemeral clone after exit.
#   DONATION_ISSUE      Numeric issue ID used to populate <donation-issue> in
#                       temporary .chloggen/*.yaml validation entries (default: 99999).
#   RUN_FULL_GOTIDY     "true" to also run root `make gotidy` across all ~360 contrib
#                       modules (slow; default checks `make tidylist` plus component
#                       `make -C exporter/bigqueryexporter tidy toolchain`).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONTRIB_REPO="${CONTRIB_REPO:-https://github.com/open-telemetry/opentelemetry-collector-contrib.git}"
CONTRIB_SHA="${CONTRIB_SHA:-87eb65f5e96d9d70315ee401515c330c105d2a63}"
LIBRARY_VERSION="${LIBRARY_VERSION:-v0.1.0}"
USE_LOCAL_CHECKOUT="${USE_LOCAL_CHECKOUT:-false}"
LOCAL_REPO_DIR="${LOCAL_REPO_DIR:-}"
KEEP_CONTRIB_DIR="${KEEP_CONTRIB_DIR:-false}"
DONATION_ISSUE="${DONATION_ISSUE:-99999}"
RUN_FULL_GOTIDY="${RUN_FULL_GOTIDY:-false}"

CONTRIB_SHA_RE='^[0-9a-fA-F]{7,40}$'
if [[ ! "${CONTRIB_SHA}" =~ ${CONTRIB_SHA_RE} ]]; then
  printf 'ERROR: CONTRIB_SHA must match %s (got %q)\n' "${CONTRIB_SHA_RE}" "${CONTRIB_SHA}" >&2
  exit 2
fi

LIBRARY_VERSION_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$'
if [[ ! "${LIBRARY_VERSION}" =~ ${LIBRARY_VERSION_RE} ]]; then
  printf 'ERROR: LIBRARY_VERSION must match %s (got %q)\n' "${LIBRARY_VERSION_RE}" "${LIBRARY_VERSION}" >&2
  exit 2
fi

DONATION_ISSUE_RE='^[0-9]+$'
if [[ ! "${DONATION_ISSUE}" =~ ${DONATION_ISSUE_RE} ]]; then
  printf 'ERROR: DONATION_ISSUE must match %s (got %q)\n' "${DONATION_ISSUE_RE}" "${DONATION_ISSUE}" >&2
  exit 2
fi

if [ -n "${LOCAL_REPO_DIR}" ] && [ "${USE_LOCAL_CHECKOUT}" = "false" ]; then
  USE_LOCAL_CHECKOUT="true"
fi
if [ "${USE_LOCAL_CHECKOUT}" = "true" ] && [ -z "${LOCAL_REPO_DIR}" ]; then
  LOCAL_REPO_DIR="${REPO_ROOT}"
fi
if [ -n "${LOCAL_REPO_DIR}" ]; then
  LOCAL_REPO_DIR="$(cd "${LOCAL_REPO_DIR}" && pwd)"
fi

DEFAULT_TMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
WORK_DIR="${WORK_DIR:-${DEFAULT_TMP}}"
LOG_DIR="${LOG_DIR:-${WORK_DIR}/contrib-verify-logs}"
mkdir -p "${WORK_DIR}" "${LOG_DIR}"
LOG_DIR="$(cd "${LOG_DIR}" && pwd)"

EPHEMERAL_ROOT=""
cleanup() {
  if [ -n "${EPHEMERAL_ROOT}" ] && [ "${KEEP_CONTRIB_DIR}" != "true" ] && [ -d "${EPHEMERAL_ROOT}" ]; then
    rm -rf "${EPHEMERAL_ROOT}"
  fi
}
trap cleanup EXIT

if [ -z "${CONTRIB_DIR:-}" ]; then
  EPHEMERAL_ROOT="$(mktemp -d "${WORK_DIR}/contrib-verify.XXXXXX")"
  CONTRIB_DIR="${EPHEMERAL_ROOT}/contrib"
  echo "Cloning ${CONTRIB_REPO} @ ${CONTRIB_SHA} into ${CONTRIB_DIR}..."
  mkdir -p "${CONTRIB_DIR}"
  git -C "${CONTRIB_DIR}" init -q
  git -C "${CONTRIB_DIR}" remote add origin -- "${CONTRIB_REPO}"
  git -C "${CONTRIB_DIR}" fetch --depth 1 origin -- "${CONTRIB_SHA}"
  git -C "${CONTRIB_DIR}" checkout -q FETCH_HEAD
else
  CONTRIB_DIR="$(cd "${CONTRIB_DIR}" && pwd)"
  if [ "${CONTRIB_DIR}" = "${REPO_ROOT}" ]; then
    echo "ERROR: CONTRIB_DIR must not point at the BQ-OTEL-Exporter repository" >&2
    exit 2
  fi
fi

SUMMARY_TSV="${LOG_DIR}/summary.tsv"
SUMMARY_MD="${LOG_DIR}/summary.md"
TOOL_VERSIONS="${LOG_DIR}/tool_versions.txt"

printf 'phase\tgate\tmode\texit_code\tstatus\tduration_s\tlog_file\n' > "${SUMMARY_TSV}"
cat > "${SUMMARY_MD}" <<EOF
# Contrib Gate Verification Summary

- Contrib commit: \`${CONTRIB_SHA}\`
- Library version: \`${LIBRARY_VERSION}\`
- Local checkout replace: \`${USE_LOCAL_CHECKOUT}\` (${LOCAL_REPO_DIR:-none})
- Component path: \`exporter/bigqueryexporter\`

| Phase | Gate | Mode | Exit | Status | Duration (s) | Log |
| --- | --- | --- | --- | --- | --- | --- |
EOF

REQUIRED_FAILURES=0

run_gate() {
  local phase="$1"
  local gate="$2"
  local mode="$3" # gate | probe
  local workdir="$4"
  shift 4

  local safe_name
  safe_name="$(printf '%s_%s' "${phase}" "${gate}" | tr -c 'A-Za-z0-9._-' '_')"
  local log_file="${LOG_DIR}/${safe_name}.log"
  local start_ts end_ts elapsed rc status

  start_ts="$(date +%s)"
  {
    printf '=== [%s] %s (%s) ===\n' "${phase}" "${gate}" "${mode}"
    printf 'cwd: %s\n' "${workdir}"
    printf 'cmd:'
    printf ' %q' "$@"
    printf '\n---\n'
  } > "${log_file}"

  set +e
  (cd "${workdir}" && "$@") >> "${log_file}" 2>&1
  rc=$?
  set -e

  end_ts="$(date +%s)"
  elapsed=$((end_ts - start_ts))

  if [ "${rc}" -eq 0 ]; then
    status="PASS"
  elif [ "${mode}" = "probe" ]; then
    status="OBSERVED_FAIL"
  else
    status="FAIL"
    REQUIRED_FAILURES=$((REQUIRED_FAILURES + 1))
  fi

  printf '%s\t%s\t%s\t%d\t%s\t%d\t%s\n' \
    "${phase}" "${gate}" "${mode}" "${rc}" "${status}" "${elapsed}" "${log_file}" >> "${SUMMARY_TSV}"
  printf '| %s | `%s` | %s | %d | %s | %d | `%s` |\n' \
    "${phase}" "${gate}" "${mode}" "${rc}" "${status}" "${elapsed}" "$(basename "${log_file}")" >> "${SUMMARY_MD}"

  printf '[%s] %-30s mode=%-5s exit=%d status=%s (%ds)\n' \
    "${phase}" "${gate}" "${mode}" "${rc}" "${status}" "${elapsed}"
  if [ "${rc}" -ne 0 ]; then
    echo "--- tail of ${log_file} ---"
    tail -n 40 "${log_file}" || true
    echo "--- end tail ---"
  fi
}

insert_line_before() {
  local file="$1"
  local anchor="$2"
  local new_line="$3"

  if grep -qxF "${new_line}" "${file}"; then
    return 0
  fi
  if ! grep -qxF "${anchor}" "${file}"; then
    echo "ERROR: anchor not found in ${file}: ${anchor}" >&2
    return 1
  fi
  local tmp_file
  tmp_file="$(mktemp "${WORK_DIR}/insert.XXXXXX")"
  awk -v anchor="${anchor}" -v newline="${new_line}" '
    $0 == anchor { print newline }
    { print }
  ' "${file}" > "${tmp_file}"
  mv "${tmp_file}" "${file}"
}

stage_pr() {
  local pr="$1"
  local chlog_path="$2"
  local -a args=(
    run ./internal/contribcheck/stage
    --repo "${REPO_ROOT}"
    --pr "${pr}"
    --out "${CONTRIB_DIR}"
    --library-version "${LIBRARY_VERSION}"
    --chlog-out "${chlog_path}"
    --issue "${DONATION_ISSUE}"
  )
  if [ "${USE_LOCAL_CHECKOUT}" = "true" ]; then
    args+=(--local-repo "${LOCAL_REPO_DIR}")
  fi
  (cd "${REPO_ROOT}" && go "${args[@]}")
}

wire_pr1_repo_files() {
  insert_line_before \
    "${CONTRIB_DIR}/versions.yaml" \
    "      - github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bmchelixexporter" \
    "      - github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter"

  insert_line_before \
    "${CONTRIB_DIR}/internal/tidylist/tidylist.txt" \
    "exporter/bmchelixexporter" \
    "exporter/bigqueryexporter"
}

wire_pr3_builder_config() {
  local cfg="${CONTRIB_DIR}/cmd/otelcontribcol/builder-config.yaml"
  local mod_line="github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter"
  if ! grep -qF "${mod_line}" "${cfg}"; then
    local neighbor_ver
    neighbor_ver="$(awk '/exporter\/bmchelixexporter /{print $NF; exit}' "${cfg}")"
    if [ -z "${neighbor_ver}" ]; then
      echo "ERROR: could not determine contrib exporter version in ${cfg}" >&2
      return 1
    fi
    insert_line_before \
      "${cfg}" \
      "  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bmchelixexporter ${neighbor_ver}" \
      "  - gomod: ${mod_line} ${neighbor_ver}"
  fi

  if [ "${USE_LOCAL_CHECKOUT}" = "true" ]; then
    local rep_line="  - github.com/GoogleCloudPlatform/BQ-OTEL-Exporter => ${LOCAL_REPO_DIR}"
    if ! grep -qxF "${rep_line}" "${cfg}"; then
      printf '%s\n' "${rep_line}" >> "${cfg}"
    fi
  fi
}

make_strict_checkapi_cfg() {
  local src="${CONTRIB_DIR}/.checkapi.yaml"
  local dst="${LOG_DIR}/checkapi.strict.yaml"
  cp "${src}" "${dst}"
  if grep -q '^component_api_strict:' "${dst}"; then
    sed -i.bak 's/^component_api_strict:.*/component_api_strict: true/' "${dst}"
    rm -f "${dst}.bak"
  else
    printf '\ncomponent_api_strict: true\n' >> "${dst}"
  fi
  printf '%s\n' "${dst}"
}

record_tool_versions() {
  local tools_mod="${CONTRIB_DIR}/internal/tools/go.mod"
  {
    printf 'contrib_sha=%s\n' "$(git -C "${CONTRIB_DIR}" rev-parse HEAD)"
    printf 'go=%s\n' "$(go version)"
    printf 'tools_mod_pins:\n'
    grep -E '(mdatagen|checkapi|golangci-lint|chloggen|githubgen|crosslink|builder|porto|checkfile|addlicense|multimod|misspell|gofumpt|gci|gotestsum|govulncheck)' "${tools_mod}" || true
    printf '\nresolved_tool_versions:\n'
    (cd "${CONTRIB_DIR}" && go tool -modfile=internal/tools/go.mod github.com/golangci/golangci-lint/v2/cmd/golangci-lint --version) 2>&1 || true
    (cd "${CONTRIB_DIR}" && go tool -modfile=internal/tools/go.mod go.opentelemetry.io/collector/cmd/mdatagen --version 2>&1 || go tool -modfile=internal/tools/go.mod go.opentelemetry.io/collector/cmd/mdatagen version 2>&1 || true)
    (cd "${CONTRIB_DIR}" && go tool -modfile=internal/tools/go.mod go.opentelemetry.io/collector/cmd/builder version 2>&1 || true)
  } > "${TOOL_VERSIONS}"
  echo "Recorded tool versions in ${TOOL_VERSIONS}"
}

clear_temp_chlog() {
  rm -f "${CONTRIB_DIR}/.chloggen/bq-otel-pr"*.yaml
}

ensure_component_deps_aligned() {
  local comp_dir="${CONTRIB_DIR}/exporter/bigqueryexporter"
  # If contrib main references an unreleased collector pseudo-version for
  # internal/telemetry (via exporterhelper/queuebatch), make tidy reports it and
  # matching that pseudo-version resolves the transitive graph.
  local telemetry_ver
  telemetry_ver="$(awk '/go\.opentelemetry\.io\/collector\/exporter\/exporterhelper / {print $2; exit}' "${CONTRIB_DIR}/internal/tools/go.mod")"
  if [[ "${telemetry_ver}" == *-* ]]; then
    (cd "${comp_dir}" && go get "go.opentelemetry.io/collector/internal/telemetry@${telemetry_ver}") >/dev/null 2>&1 || true
  fi
}

STRICT_CHECKAPI_CFG="$(make_strict_checkapi_cfg)"
record_tool_versions

echo ""
echo "================ PR 1: Component Skeleton ================"
clear_temp_chlog
stage_pr 1 "${CONTRIB_DIR}/.chloggen/bq-otel-pr1.yaml"
wire_pr1_repo_files
ensure_component_deps_aligned

run_gate pr1 mdatagen gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter mdatagen
run_gate pr1 comp_tidy gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter tidy toolchain
run_gate pr1 generate gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter generate
run_gate pr1 checkapi_default gate "${CONTRIB_DIR}" make checkapi
run_gate pr1 checkapi_strict probe "${CONTRIB_DIR}" \
  go tool -modfile="${CONTRIB_DIR}/internal/tools/go.mod" \
  go.opentelemetry.io/build-tools/checkapi -folder "${CONTRIB_DIR}/exporter/bigqueryexporter" -config "${STRICT_CHECKAPI_CFG}"
run_gate pr1 goporto gate "${CONTRIB_DIR}" make goporto
run_gate pr1 crosslink gate "${CONTRIB_DIR}" make crosslink
run_gate pr1 tidylist gate "${CONTRIB_DIR}" make tidylist
if [ "${RUN_FULL_GOTIDY}" = "true" ]; then
  run_gate pr1 gotidy gate "${CONTRIB_DIR}" make gotidy
fi
run_gate pr1 multimod_verify gate "${CONTRIB_DIR}" make multimod-verify
run_gate pr1 generate_gh_issue_templates gate "${CONTRIB_DIR}" make generate-gh-issue-templates
run_gate pr1 gencodeowners gate "${CONTRIB_DIR}" make gencodeowners
run_gate pr1 gengithub gate "${CONTRIB_DIR}" make gengithub
run_gate pr1 genlabels gate "${CONTRIB_DIR}" make genlabels
run_gate pr1 generate_chloggen_components gate "${CONTRIB_DIR}" make generate-chloggen-components
run_gate pr1 chlog_validate gate "${CONTRIB_DIR}" make chlog-validate
run_gate pr1 gencodecov gate "${CONTRIB_DIR}" make gencodecov
run_gate pr1 checklicense gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter checklicense
run_gate pr1 addlicense gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter addlicense
run_gate pr1 genotelcontribcol gate "${CONTRIB_DIR}" make genotelcontribcol
run_gate pr1 genoteltestbedcol gate "${CONTRIB_DIR}" make genoteltestbedcol
run_gate pr1 checkdoc gate "${CONTRIB_DIR}" make checkdoc
run_gate pr1 checkmetadata gate "${CONTRIB_DIR}" make checkmetadata
run_gate pr1 comp_lint gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter lint
run_gate pr1 comp_test gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter test

echo ""
echo "================ PR 2: Export Path Implementation ================"
clear_temp_chlog
stage_pr 2 "${CONTRIB_DIR}/.chloggen/bq-otel-pr2.yaml"
ensure_component_deps_aligned

run_gate pr2 comp_tidy gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter tidy toolchain
run_gate pr2 mdatagen gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter mdatagen
run_gate pr2 generate gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter generate
run_gate pr2 checkapi_default gate "${CONTRIB_DIR}" make checkapi
run_gate pr2 checkapi_strict probe "${CONTRIB_DIR}" \
  go tool -modfile="${CONTRIB_DIR}/internal/tools/go.mod" \
  go.opentelemetry.io/build-tools/checkapi -folder "${CONTRIB_DIR}/exporter/bigqueryexporter" -config "${STRICT_CHECKAPI_CFG}"
run_gate pr2 chlog_validate gate "${CONTRIB_DIR}" make chlog-validate
run_gate pr2 comp_lint gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter lint
run_gate pr2 comp_test gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter test

echo ""
echo "================ PR 3: Alpha Promotion & Distribution ================"
clear_temp_chlog
stage_pr 3 "${CONTRIB_DIR}/.chloggen/bq-otel-pr3.yaml"
ensure_component_deps_aligned
wire_pr3_builder_config

run_gate pr3 comp_tidy gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter tidy toolchain
run_gate pr3 mdatagen gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter mdatagen
run_gate pr3 generate gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter generate
run_gate pr3 gendistributions gate "${CONTRIB_DIR}" make gendistributions
run_gate pr3 genotelcontribcol gate "${CONTRIB_DIR}" make genotelcontribcol
run_gate pr3 otelcontribcol_compile gate "${CONTRIB_DIR}/cmd/otelcontribcol" go build -o /dev/null .
run_gate pr3 checkdoc gate "${CONTRIB_DIR}" make checkdoc
run_gate pr3 checkmetadata gate "${CONTRIB_DIR}" make checkmetadata
run_gate pr3 checkapi_default gate "${CONTRIB_DIR}" make checkapi
run_gate pr3 checkapi_strict probe "${CONTRIB_DIR}" \
  go tool -modfile="${CONTRIB_DIR}/internal/tools/go.mod" \
  go.opentelemetry.io/build-tools/checkapi -folder "${CONTRIB_DIR}/exporter/bigqueryexporter" -config "${STRICT_CHECKAPI_CFG}"
run_gate pr3 chlog_validate gate "${CONTRIB_DIR}" make chlog-validate
run_gate pr3 comp_lint gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter lint
run_gate pr3 comp_test gate "${CONTRIB_DIR}" make -C exporter/bigqueryexporter test

echo "" >> "${SUMMARY_MD}"
cat "${TOOL_VERSIONS}" | sed 's/^/    /' >> "${SUMMARY_MD}" || true

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "${SUMMARY_MD}" >> "${GITHUB_STEP_SUMMARY}"
fi

echo ""
echo "Summary written to ${SUMMARY_TSV} and ${SUMMARY_MD}"
echo "Required gate failures: ${REQUIRED_FAILURES}"
if [ "${REQUIRED_FAILURES}" -ne 0 ]; then
  exit 1
fi
