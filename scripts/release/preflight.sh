#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
shopt -s inherit_errexit

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release/common.sh
source "${SCRIPT_DIR}/common.sh"

validate_release_tag_and_sha "${RELEASE_TAG}" "${COMMIT_SHA}"
validate_run_id "${RUN_ID}"
if [ -z "${GHCR_ACTOR:-}" ] || [ -z "${GHCR_TOKEN:-}" ] || [ -z "${GH_TOKEN:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
  echo "::error::Missing required GHCR/GitHub environment context" >&2
  exit 1
fi

commit_short="${COMMIT_SHA:0:12}"
VERSION="${RELEASE_TAG#v}"
is_prerelease="$(release_is_prerelease "${VERSION}")"
tag_hash="$(printf '%s' "${RELEASE_TAG}" | sha256sum | awk '{ print substr($1, 1, 12) }')"
staged_ver="t-${tag_hash}-${commit_short}"
primary_manifest="manifest-${tag_hash}-${commit_short}.json"
primary_uri="${RELEASE_MANIFESTS_PREFIX}/${primary_manifest}"
forced_manifest="manifest-${tag_hash}-${commit_short}-r${RUN_ID}.json"
forced_uri="${RELEASE_MANIFESTS_PREFIX}/${forced_manifest}"

write_skip_summary() {
  local uri="$1"
  local existing_ver="$2"
  {
    echo "### OSS Exit Gate Preflight — Already Submitted (Skipped Duplicate)"
    echo ""
    echo "> **Note:** Manifest \`${uri}\` already exists in GCS for tag \`${RELEASE_TAG}\` at commit \`${commit_short}\`, so this run skipped rebuilding containers and uploading a duplicate Artifact Registry package/manifest. Highest stable tags still reconcile GHCR \`:latest*\` aliases in \`promote-latest\`. If OSS Exit Gate rejected the prior request, dispatch a forced resubmission on the tag ref:"
    echo ""
    echo "\`\`\`bash"
    echo "gh workflow run release.yml --ref \"${RELEASE_TAG}\" -f tag=\"${RELEASE_TAG}\" -f force_resubmit=true"
    echo "\`\`\`"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Status | \`ALREADY SUBMITTED (SKIPPED DUPLICATE)\` |"
    echo "| Release Tag / Commit | \`${RELEASE_TAG}\` / \`${commit_short}\` |"
    echo "| Existing Manifest URI | \`${uri}\` |"
    echo "| Existing Staging Version | \`${RELEASE_AR_PACKAGE}@${existing_ver}\` |"
  } >> "${GITHUB_STEP_SUMMARY}"
}

manifests_state="$(list_tag_commit_manifests "${tag_hash}" "${commit_short}" "${RUN_ID}")"
IFS=$'\t' read -r primary_present forced_present best_forced_uri <<< "${manifests_state}"

any_existing_uri=""
if [ "${primary_present}" = "true" ]; then
  any_existing_uri="${primary_uri}"
elif [ -n "${best_forced_uri}" ]; then
  any_existing_uri="${best_forced_uri}"
fi

if [ "${FORCE_RESUBMIT:-false}" != "true" ]; then
  if [ -n "${any_existing_uri}" ]; then
    existing_ver="$(validate_existing_manifest "${any_existing_uri}" "${RELEASE_TAG}" "${VERSION}" "${is_prerelease}")"
    existing_eligible="$(read_manifest_promote_eligible "${any_existing_uri}")"
    if [ "${existing_eligible}" = "true" ] || [ "${existing_eligible}" = "false" ]; then
      promote_eligible="${existing_eligible}"
    elif [ "${any_existing_uri}" = "${primary_uri}" ]; then
      promote_eligible="true"
    else
      promote_eligible="false"
    fi
    {
      echo "action=skip_duplicate"
      echo "manifest_uri=${any_existing_uri}"
      echo "submission_status=already_submitted"
      echo "promote_eligible=${promote_eligible}"
      echo "staging_version=${existing_ver}"
    } >> "${GITHUB_OUTPUT}"
    write_skip_summary "${any_existing_uri}" "${existing_ver}"
    exit 0
  fi
  target_uri="${primary_uri}"
  promote_eligible="true"
else
  if [ "${forced_present}" = "true" ]; then
    existing_ver="$(validate_existing_manifest "${forced_uri}" "${RELEASE_TAG}" "${VERSION}" "${is_prerelease}")"
    existing_eligible="$(read_manifest_promote_eligible "${forced_uri}")"
    if [ "${existing_eligible}" = "true" ]; then
      promote_eligible="true"
    else
      promote_eligible="false"
    fi
    {
      echo "action=skip_duplicate"
      echo "manifest_uri=${forced_uri}"
      echo "submission_status=already_submitted"
      echo "promote_eligible=${promote_eligible}"
      echo "staging_version=${existing_ver}"
    } >> "${GITHUB_OUTPUT}"
    write_skip_summary "${forced_uri}" "${existing_ver}"
    exit 0
  fi
  if [ -n "${any_existing_uri}" ]; then
    prior_ver="$(validate_existing_manifest "${any_existing_uri}" "${RELEASE_TAG}" "${VERSION}" "${is_prerelease}")"
    {
      echo "action=resubmit_existing"
      echo "prior_staging_version=${prior_ver}"
      echo "manifest_uri=${forced_uri}"
      echo "promote_eligible=false"
    } >> "${GITHUB_OUTPUT}"
    exit 0
  fi
  target_uri="${forced_uri}"
  promote_eligible="true"
fi

# No manifest exists in GCS yet. Probe top-level GHCR manifest reference and
# Artifact Registry staging completeness so valid already-built artifacts reuse
# cleanly, whereas missing container SLSA provenance triggers a clean rebuild.
ghcr_token="$(ensure_ghcr_token "${GHCR_ACTOR}" "${GHCR_TOKEN}")"
container_state="$(inspect_ghcr_container_provenance "${ghcr_token}" "${RELEASE_TAG}" "${COMMIT_SHA}" "${VERSION}" "${GITHUB_REPOSITORY}")"
IFS=$'\t' read -r prov_status existing_digest <<< "${container_state}"

container_exists=false
container_provenance_verified=false
container_digest=""
case "${prov_status}" in
  verified)
    container_exists=true
    container_provenance_verified=true
    container_digest="${existing_digest}"
    ;;
  missing)
    echo "Existing signed container ${RELEASE_GHCR_IMAGE}@${existing_digest} has no verified SLSA build provenance; routing through full release to rebuild and freshly attest a new digest."
    ;;
  absent)
    ;;
  *)
    echo "::error::Unexpected container provenance state: ${prov_status}" >&2
    exit 1
    ;;
esac

ar_json="$(
  gcloud artifacts files list \
    --project="${RELEASE_AR_PROJECT}" \
    --location="${RELEASE_AR_LOCATION}" \
    --repository="${RELEASE_AR_REPO}" \
    --package="${RELEASE_AR_PACKAGE}" \
    --version="${staged_ver}" \
    --format=json
)"
ar_entries="$(parse_ar_entries "${ar_json}")"

archives=(
  "otelcol-bq_${VERSION}_linux_amd64.tar.gz"
  "otelcol-bq_${VERSION}_linux_arm64.tar.gz"
  "otelcol-bq_${VERSION}_darwin_amd64.tar.gz"
  "otelcol-bq_${VERSION}_darwin_arm64.tar.gz"
  "otelcol-bq_${VERSION}_windows_amd64.zip"
)
expected_checksummed=()
for archive in "${archives[@]}"; do
  expected_checksummed+=("${archive}" "${archive}.sbom.json")
done
required_files=("${expected_checksummed[@]}" "checksums.txt" "checksums.txt.sig" "checksums.txt.pem" "EXIT_GATE_CHANGELOG")
allowed_files=("${required_files[@]}")

ar_count="$(printf '%s' "${ar_entries}" | jq -r 'length')"
missing_req="$(
  printf '%s' "${ar_entries}" | jq -r --argjson req "$(printf '%s\n' "${required_files[@]}" | jq -R . | jq -s .)" '
    (map(.fname)) as $present | ($req - $present) | length
  '
)"
unexpected_files="$(
  printf '%s' "${ar_entries}" | jq -r --argjson allowed "$(printf '%s\n' "${allowed_files[@]}" | jq -R . | jq -s .)" '
    [ .[] | select(.fname as $f | ($allowed | index($f)) == null) | .fname ] | join(", ")
  '
)"

ar_staged_complete=false
ar_staged_partial=false
if [ "${missing_req}" -eq 0 ] && [ -z "${unexpected_files}" ]; then
  ar_staged_complete=true
elif [ "${ar_count}" -gt 0 ]; then
  ar_staged_partial=true
fi

if [ "${ar_staged_complete}" = "true" ]; then
  verify_dir="$(mktemp -d)"
  for cfile in checksums.txt checksums.txt.sig checksums.txt.pem EXIT_GATE_CHANGELOG; do
    if ! download_ar_file_verified "${ar_entries}" "${cfile}" "${verify_dir}" "${staged_ver}"; then
      rm -rf "${verify_dir}"
      echo "::error::Failed to download or digest-verify ${cfile} in Artifact Registry package ${RELEASE_AR_PACKAGE}@${staged_ver}; failing closed." >&2
      exit 1
    fi
  done
  if ! cosign verify-blob \
    --certificate "${verify_dir}/checksums.txt.pem" \
    --signature "${verify_dir}/checksums.txt.sig" \
    --certificate-oidc-issuer="${RELEASE_COSIGN_OIDC_ISSUER}" \
    --certificate-identity="${RELEASE_COSIGN_IDENTITY_BASE}${RELEASE_TAG}" \
    "${verify_dir}/checksums.txt"; then
    rm -rf "${verify_dir}"
    echo "::error::Artifact Registry package ${RELEASE_AR_PACKAGE}@${staged_ver} has invalid checksums.txt signature; failing closed." >&2
    exit 1
  fi
  if ! verify_changelog_attestation "${verify_dir}/EXIT_GATE_CHANGELOG" "${GITHUB_REPOSITORY}" "${RELEASE_TAG}"; then
    rm -rf "${verify_dir}"
    echo "::error::Artifact Registry EXIT_GATE_CHANGELOG in ${RELEASE_AR_PACKAGE}@${staged_ver} failed SLSA provenance attestation verification; failing closed." >&2
    exit 1
  fi
  if ! parsed_csums="$(parse_checksums_file "${verify_dir}/checksums.txt")"; then
    rm -rf "${verify_dir}"
    echo "::error::Remote checksums.txt in ${RELEASE_AR_PACKAGE}@${staged_ver} contains malformed or duplicate entries." >&2
    exit 1
  fi
  rm -rf "${verify_dir}"

  expected_csum_names="$(printf '%s\n' "${expected_checksummed[@]}" | LC_ALL=C sort)"
  actual_csum_names="$(printf '%s\n' "${parsed_csums}" | awk -F '\t' '{ print $1 }' | LC_ALL=C sort)"
  if [ "${expected_csum_names}" != "${actual_csum_names}" ]; then
    echo "::error::Remote checksums.txt asset list in ${RELEASE_AR_PACKAGE}@${staged_ver} does not match expected archives + SBOMs." >&2
    exit 1
  fi
  while IFS=$'\t' read -r cfname csha; do
    [ -n "${cfname}" ] || continue
    remote_sha="$(printf '%s' "${ar_entries}" | jq -er --arg f "${cfname}" '.[] | select(.fname == $f) | .sha256')"
    if [ "${remote_sha}" != "${csha}" ]; then
      echo "::error::Remote Artifact Registry digest mismatch for ${cfname} in ${RELEASE_AR_PACKAGE}@${staged_ver}: remote=${remote_sha}, signed checksums.txt=${csha}." >&2
      exit 1
    fi
  done <<< "${parsed_csums}"
fi

if [ "${ar_staged_complete}" = "true" ] && [ "${container_exists}" = "true" ] && [ "${container_provenance_verified}" = "true" ]; then
  {
    echo "action=submit_staged"
    echo "staging_version=${staged_ver}"
    echo "manifest_uri=${target_uri}"
    echo "container_exists=true"
    echo "container_provenance_verified=true"
    echo "container_digest=${container_digest}"
    echo "ar_staged_partial=false"
    echo "promote_eligible=${promote_eligible}"
  } >> "${GITHUB_OUTPUT}"
  {
    echo "### OSS Exit Gate Preflight — Reusing Verified Staged Assets (Submit Manifest)"
    echo ""
    echo "> **Note:** Verified existing GHCR container \`${RELEASE_GHCR_IMAGE}@${container_digest}\` (commit \`${commit_short}\`, version \`${VERSION}\`) and complete signed Artifact Registry package \`${RELEASE_AR_PACKAGE}@${staged_ver}\`, with no manifest in GCS yet. Skipping container/binary rebuilds and routing directly to \`submit-exit-gate\`."
  } >> "${GITHUB_STEP_SUMMARY}"
  exit 0
fi

{
  echo "action=full_release"
  echo "staging_version=${staged_ver}"
  echo "manifest_uri=${target_uri}"
  echo "container_exists=${container_exists}"
  echo "container_provenance_verified=${container_provenance_verified}"
  echo "container_digest=${container_digest}"
  echo "ar_staged_partial=${ar_staged_partial}"
  echo "promote_eligible=${promote_eligible}"
} >> "${GITHUB_OUTPUT}"
