#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
shopt -s inherit_errexit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release/common.sh
source "${SCRIPT_DIR}/common.sh"

validate_release_tag_and_sha "${RELEASE_TAG}" "${COMMIT_SHA}"

commit_short="${COMMIT_SHA:0:12}"
VERSION="${RELEASE_TAG#v}"
tag_hash="$(printf '%s' "${RELEASE_TAG}" | sha256sum | awk '{ print substr($1, 1, 12) }')"
STAGING_VERSION="t-${tag_hash}-${commit_short}"
stage_dir="${RUNNER_TEMP}/exit-gate-stage"
rm -rf "${stage_dir}"
mkdir -p "${stage_dir}"

archives=(
  "otelcol-bq_${VERSION}_linux_amd64.tar.gz"
  "otelcol-bq_${VERSION}_linux_arm64.tar.gz"
  "otelcol-bq_${VERSION}_darwin_amd64.tar.gz"
  "otelcol-bq_${VERSION}_darwin_arm64.tar.gz"
  "otelcol-bq_${VERSION}_windows_amd64.zip"
)
missing=0
for archive in "${archives[@]}"; do
  for path in "dist/${archive}" "dist/${archive}.sbom.json"; do
    if [ ! -s "${path}" ]; then
      echo "::error::Missing or empty expected GoReleaser asset: ${path}" >&2
      missing=1
    fi
  done
done
for fixed in dist/checksums.txt dist/checksums.txt.sig dist/checksums.txt.pem; do
  if [ ! -s "${fixed}" ]; then
    echo "::error::Missing or empty expected checksum/signature file: ${fixed}" >&2
    missing=1
  fi
done
if [ "${missing}" -ne 0 ]; then
  ls -la dist/
  exit 1
fi

expected_checksummed=()
for archive in "${archives[@]}"; do
  expected_checksummed+=("${archive}" "${archive}.sbom.json")
done
expected_names="$(printf '%s\n' "${expected_checksummed[@]}" | LC_ALL=C sort)"
checksum_names="$(awk 'NF >= 2 { name = $2; sub(/^\*/, "", name); print name }' dist/checksums.txt | LC_ALL=C sort)"
if [ "${expected_names}" != "${checksum_names}" ]; then
  echo "::error::dist/checksums.txt asset list does not match expected archives + SBOMs" >&2
  diff -u <(printf '%s\n' "${expected_names}") <(printf '%s\n' "${checksum_names}") || true
  exit 1
fi

for archive in "${archives[@]}"; do
  cp "dist/${archive}" "${stage_dir}/"
  cp "dist/${archive}.sbom.json" "${stage_dir}/"
done
cp dist/checksums.txt dist/checksums.txt.sig dist/checksums.txt.pem "${stage_dir}/"

(cd "${stage_dir}" && sha256sum --strict --check checksums.txt)

local_changelog_sha=""
required_files=("${expected_checksummed[@]}" "checksums.txt" "checksums.txt.sig" "checksums.txt.pem")
if [ -s dist/CHANGELOG.md ]; then
  cp dist/CHANGELOG.md "${stage_dir}/EXIT_GATE_CHANGELOG"
  local_changelog_sha="$(sha256sum dist/CHANGELOG.md | awk '{ print tolower($1) }')"
  required_files+=("EXIT_GATE_CHANGELOG")
fi
allowed_files=("${required_files[@]}")

check_remote_ar_package() {
  local ar_json ar_entries ar_count missing_req unexpected_files
  local verify_dir cfile dl_rc parsed_csums actual_csum_names cfname csha remote_sha remote_changelog_sha
  if ! ar_json="$(
    gcloud artifacts files list \
      --project="${RELEASE_AR_PROJECT}" \
      --location="${RELEASE_AR_LOCATION}" \
      --repository="${RELEASE_AR_REPO}" \
      --package="${RELEASE_AR_PACKAGE}" \
      --version="${STAGING_VERSION}" \
      --format=json
  )"; then
    return 2
  fi
  if ! ar_entries="$(parse_ar_entries "${ar_json}")"; then
    return 2
  fi

  if ! ar_count="$(printf '%s' "${ar_entries}" | jq -r 'length')"; then
    return 2
  fi
  remote_ar_count="${ar_count}"
  if ! missing_req="$(
    printf '%s' "${ar_entries}" | jq -r --argjson req "$(printf '%s\n' "${required_files[@]}" | jq -R . | jq -s .)" '
      (map(.fname)) as $present | ($req - $present) | length
    '
  )"; then
    return 2
  fi
  if ! unexpected_files="$(
    printf '%s' "${ar_entries}" | jq -r --argjson allowed "$(printf '%s\n' "${allowed_files[@]}" | jq -R . | jq -s .)" '
      [ .[] | select(.fname as $f | ($allowed | index($f)) == null) | .fname ] | join(", ")
    '
  )"; then
    return 2
  fi

  if [ "${missing_req}" -ne 0 ] || [ -n "${unexpected_files}" ]; then
    return 1
  fi
  if [ -n "${local_changelog_sha}" ]; then
    if ! remote_changelog_sha="$(printf '%s' "${ar_entries}" | jq -er '.[] | select(.fname == "EXIT_GATE_CHANGELOG") | .sha256')"; then
      return 2
    fi
    if [ "${remote_changelog_sha}" != "${local_changelog_sha}" ]; then
      return 1
    fi
  fi

  if ! verify_dir="$(mktemp -d)"; then
    return 2
  fi
  for cfile in checksums.txt checksums.txt.sig checksums.txt.pem; do
    dl_rc=0
    download_ar_file_verified "${ar_entries}" "${cfile}" "${verify_dir}" "${STAGING_VERSION}" || dl_rc=$?
    if [ "${dl_rc}" -ne 0 ]; then
      rm -rf "${verify_dir}"
      return "${dl_rc}"
    fi
  done
  if ! parsed_csums="$(parse_checksums_file "${verify_dir}/checksums.txt")"; then
    rm -rf "${verify_dir}"
    return 1
  fi

  actual_csum_names="$(printf '%s\n' "${parsed_csums}" | awk -F '\t' '{ print $1 }' | LC_ALL=C sort)"
  if [ "${expected_names}" != "${actual_csum_names}" ]; then
    rm -rf "${verify_dir}"
    return 1
  fi
  while IFS=$'\t' read -r cfname csha; do
    [ -n "${cfname}" ] || continue
    if ! remote_sha="$(printf '%s' "${ar_entries}" | jq -er --arg f "${cfname}" '.[] | select(.fname == $f) | .sha256')"; then
      rm -rf "${verify_dir}"
      return 2
    fi
    if [ "${remote_sha}" != "${csha}" ]; then
      rm -rf "${verify_dir}"
      return 1
    fi
  done <<< "${parsed_csums}"

  if ! cosign verify-blob \
    --certificate "${verify_dir}/checksums.txt.pem" \
    --signature "${verify_dir}/checksums.txt.sig" \
    --certificate-oidc-issuer="${RELEASE_COSIGN_OIDC_ISSUER}" \
    --certificate-identity="${RELEASE_COSIGN_IDENTITY_BASE}${RELEASE_TAG}" \
    "${verify_dir}/checksums.txt"; then
    rm -rf "${verify_dir}"
    return 3
  fi
  rm -rf "${verify_dir}"
  return 0
}

remote_ar_count=0
if check_remote_ar_package; then
  echo "Artifact Registry version ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} already has verified exact inventory and signed SHA-256 digests (already_staged); skipping upload."
else
  rc=$?
  if [ "${rc}" -eq 2 ]; then
    echo "::error::Failed to verify existing Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} during listing or download." >&2
    exit 1
  elif [ "${rc}" -eq 3 ]; then
    echo "::error::Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} has complete, digest-consistent files, but cosign verify-blob failed (indeterminate verifier failure; staged package preserved). Re-run once Rekor/Cosign is healthy, or manually delete ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} if signature corruption is confirmed: gcloud artifacts versions delete \"${STAGING_VERSION}\" --project=\"${RELEASE_AR_PROJECT}\" --location=\"${RELEASE_AR_LOCATION}\" --repository=\"${RELEASE_AR_REPO}\" --package=\"${RELEASE_AR_PACKAGE}\" --quiet" >&2
    exit 1
  fi
  if [ "${remote_ar_count}" -gt 0 ]; then
    echo "Deleting incomplete, unexpected, or digest-mismatched Artifact Registry version ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} (${remote_ar_count} files) before re-upload."
    gcloud artifacts versions delete "${STAGING_VERSION}" \
      --project="${RELEASE_AR_PROJECT}" \
      --location="${RELEASE_AR_LOCATION}" \
      --repository="${RELEASE_AR_REPO}" \
      --package="${RELEASE_AR_PACKAGE}" \
      --quiet
  fi
  gcloud artifacts generic upload \
    --project="${RELEASE_AR_PROJECT}" \
    --location="${RELEASE_AR_LOCATION}" \
    --repository="${RELEASE_AR_REPO}" \
    --package="${RELEASE_AR_PACKAGE}" \
    --version="${STAGING_VERSION}" \
    --source-directory="${stage_dir}"
  if ! check_remote_ar_package; then
    echo "::error::Post-upload verification failed for Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION}." >&2
    exit 1
  fi
fi

echo "staging_version=${STAGING_VERSION}" >> "${GITHUB_OUTPUT}"
