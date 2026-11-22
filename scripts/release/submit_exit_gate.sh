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
if [ -z "${GH_TOKEN:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
  echo "::error::Missing required GitHub environment context (GH_TOKEN/GITHUB_REPOSITORY)" >&2
  exit 1
fi

commit_short="${COMMIT_SHA:0:12}"
case "${ACTION}" in
  full_release)
    STAGING_VERSION="${RELEASE_STAGING_VERSION}"
    submission_type="initial submission"
    ;;
  submit_staged)
    STAGING_VERSION="${PREFLIGHT_STAGING_VERSION}"
    submission_type="retry using staged AR package & verified container"
    ;;
  resubmit_existing)
    STAGING_VERSION="${PRIOR_STAGING_VERSION}"
    submission_type="explicit resubmission of existing AR package (no rebuild; GHCR :latest* untouched)"
    ;;
  *)
    echo "::error::Unexpected preflight action for submit-exit-gate: ${ACTION}" >&2
    exit 1
    ;;
esac

if ! [[ "${STAGING_VERSION}" =~ ${RELEASE_AR_VERSION_RE} ]]; then
  echo "::error::Unexpected STAGING_VERSION value: ${STAGING_VERSION}" >&2
  exit 1
fi

VERSION="${RELEASE_TAG#v}"
is_prerelease="$(release_is_prerelease "${VERSION}")"

tag_hash="$(printf '%s' "${RELEASE_TAG}" | sha256sum | awk '{ print substr($1, 1, 12) }')"
primary_manifest="manifest-${tag_hash}-${commit_short}.json"
primary_uri="${RELEASE_MANIFESTS_PREFIX}/${primary_manifest}"
forced_manifest="manifest-${tag_hash}-${commit_short}-r${RUN_ID}.json"
forced_uri="${RELEASE_MANIFESTS_PREFIX}/${forced_manifest}"

manifests_state="$(list_tag_commit_manifests "${tag_hash}" "${commit_short}" "${RUN_ID}")"
IFS=$'\t' read -r primary_present forced_present best_forced_uri <<< "${manifests_state}"

any_existing_uri=""
if [ "${primary_present}" = "true" ]; then
  any_existing_uri="${primary_uri}"
elif [ -n "${best_forced_uri}" ]; then
  any_existing_uri="${best_forced_uri}"
fi

if [ "${FORCE_RESUBMIT:-false}" = "true" ]; then
  target_uri="${forced_uri}"
  resubmit_note="explicit resubmission (force_resubmit=true; run_id r${RUN_ID})"
  dup_uri=""
  if [ "${forced_present}" = "true" ]; then
    dup_uri="${forced_uri}"
  fi
else
  target_uri="${primary_uri}"
  resubmit_note="initial submission"
  dup_uri="${any_existing_uri}"
fi

if [ -n "${dup_uri}" ]; then
  existing_ver="$(validate_existing_manifest "${dup_uri}" "${RELEASE_TAG}" "${VERSION}" "${is_prerelease}")"
  echo "Manifest already submitted for tag ${RELEASE_TAG} at commit ${commit_short}: ${dup_uri}"
  {
    echo "staging_version=${existing_ver}"
    echo "manifest_uri=${dup_uri}"
    echo "submission_status=already_submitted"
  } >> "${GITHUB_OUTPUT}"
  {
    echo "### OSS Exit Gate Submission — Already Submitted (Skipped Duplicate)"
    echo ""
    echo "> **Note:** Manifest \`${dup_uri}\` for tag \`${RELEASE_TAG}\` at commit \`${commit_short}\` already exists in GCS, so this retry skipped writing a duplicate manifest. If OSS Exit Gate rejected the prior request, dispatch a forced resubmission on the tag ref:"
    echo ""
    echo "\`\`\`bash"
    echo "gh workflow run release.yml --ref \"${RELEASE_TAG}\" -f tag=\"${RELEASE_TAG}\" -f force_resubmit=true"
    echo "\`\`\`"
    echo ""
    echo "| Field | Value |"
    echo "|---|---|"
    echo "| Status | \`ALREADY SUBMITTED (SKIPPED DUPLICATE)\` |"
    echo "| Release Tag / Commit | \`${RELEASE_TAG}\` / \`${commit_short}\` |"
    echo "| Existing Manifest URI | \`${dup_uri}\` |"
    echo "| Existing Staging Version | \`${RELEASE_AR_PACKAGE}@${existing_ver}\` |"
  } >> "${GITHUB_STEP_SUMMARY}"
  exit 0
fi

# Verify origin tag still resolves to COMMIT_SHA before verification/submission.
verify_origin_release_tag "origin" "${RELEASE_TAG}" "${COMMIT_SHA}"

# Verify exact AR inventory, checksums.txt signature, remote SHA-256 digests,
# and (when present) cryptographic provenance of EXIT_GATE_CHANGELOG.
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
required_files=("${expected_checksummed[@]}" "checksums.txt" "checksums.txt.sig" "checksums.txt.pem")
allowed_files=("${required_files[@]}" "EXIT_GATE_CHANGELOG")

ar_json="$(
  gcloud artifacts files list \
    --project="${RELEASE_AR_PROJECT}" \
    --location="${RELEASE_AR_LOCATION}" \
    --repository="${RELEASE_AR_REPO}" \
    --package="${RELEASE_AR_PACKAGE}" \
    --version="${STAGING_VERSION}" \
    --format=json
)"
ar_entries="$(parse_ar_entries "${ar_json}")"

missing_req="$(
  printf '%s' "${ar_entries}" | jq -r --argjson req "$(printf '%s\n' "${required_files[@]}" | jq -R . | jq -s .)" '
    (map(.fname)) as $present | ($req - $present) | join(", ")
  '
)"
if [ -n "${missing_req}" ]; then
  echo "::error::Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} is missing required files (${missing_req}); refusing to submit manifest." >&2
  exit 1
fi
unexpected_files="$(
  printf '%s' "${ar_entries}" | jq -r --argjson allowed "$(printf '%s\n' "${allowed_files[@]}" | jq -R . | jq -s .)" '
    [ .[] | select(.fname as $f | ($allowed | index($f)) == null) | .fname ] | join(", ")
  '
)"
if [ -n "${unexpected_files}" ]; then
  echo "::error::Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} contains unexpected files (${unexpected_files}); refusing to submit manifest." >&2
  exit 1
fi

verify_dir="$(mktemp -d)"
for cfile in checksums.txt checksums.txt.sig checksums.txt.pem; do
  if ! download_ar_file_verified "${ar_entries}" "${cfile}" "${verify_dir}" "${STAGING_VERSION}"; then
    rm -rf "${verify_dir}"
    echo "::error::Failed to download or digest-verify ${cfile} from ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} for pre-submission verification." >&2
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
  echo "::error::Artifact Registry package ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} checksums.txt signature verification failed; refusing to submit manifest." >&2
  exit 1
fi

if printf '%s' "${ar_entries}" | jq -e 'any(.[]; .fname == "EXIT_GATE_CHANGELOG")' >/dev/null; then
  if ! download_ar_file_verified "${ar_entries}" "EXIT_GATE_CHANGELOG" "${verify_dir}" "${STAGING_VERSION}"; then
    rm -rf "${verify_dir}"
    echo "::error::Failed to download or digest-verify EXIT_GATE_CHANGELOG from ${RELEASE_AR_PACKAGE}@${STAGING_VERSION}; refusing to submit manifest." >&2
    exit 1
  fi
  if ! verify_changelog_attestation "${verify_dir}/EXIT_GATE_CHANGELOG" "${GITHUB_REPOSITORY}" "${RELEASE_TAG}"; then
    rm -rf "${verify_dir}"
    echo "::error::Artifact Registry EXIT_GATE_CHANGELOG in ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} failed SLSA provenance attestation verification; refusing to submit manifest." >&2
    exit 1
  fi
fi

if ! parsed_csums="$(parse_checksums_file "${verify_dir}/checksums.txt")"; then
  rm -rf "${verify_dir}"
  echo "::error::Remote checksums.txt in ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} contains malformed or duplicate entries." >&2
  exit 1
fi
rm -rf "${verify_dir}"

expected_csum_names="$(printf '%s\n' "${expected_checksummed[@]}" | LC_ALL=C sort)"
actual_csum_names="$(printf '%s\n' "${parsed_csums}" | awk -F '\t' '{ print $1 }' | LC_ALL=C sort)"
if [ "${expected_csum_names}" != "${actual_csum_names}" ]; then
  echo "::error::Remote checksums.txt in ${RELEASE_AR_PACKAGE}@${STAGING_VERSION} does not match expected archives + SBOMs." >&2
  exit 1
fi
while IFS=$'\t' read -r cfname csha; do
  [ -n "${cfname}" ] || continue
  remote_sha="$(printf '%s' "${ar_entries}" | jq -er --arg f "${cfname}" '.[] | select(.fname == $f) | .sha256')"
  if [ "${remote_sha}" != "${csha}" ]; then
    echo "::error::Remote Artifact Registry digest mismatch for ${cfname} in ${RELEASE_AR_PACKAGE}@${STAGING_VERSION}: remote=${remote_sha}, signed checksums.txt=${csha}." >&2
    exit 1
  fi
done <<< "${parsed_csums}"

jq -n \
  --arg ver "${STAGING_VERSION}" \
  --arg tag "${RELEASE_TAG}" \
  --arg name "otelcol-bq ${VERSION}" \
  --arg pkg "${RELEASE_AR_PACKAGE}" \
  --argjson prerelease "${is_prerelease}" \
  '{
    publish_all: false,
    publishing_groups: [
      {
        packages: [
          {
            name: $pkg,
            version: $ver
          }
        ]
      }
    ],
    registry_config: {
      github_releases: {
        name: $name,
        tag: $tag,
        is_draft: true,
        is_prerelease: $prerelease
      }
    }
  }' > "${RUNNER_TEMP}/manifest.json"

# Re-verify origin tag immediately before queuing the manifest in GCS.
verify_origin_release_tag "origin" "${RELEASE_TAG}" "${COMMIT_SHA}"

if [ "${ACTION}" = "resubmit_existing" ]; then
  promote_eligible_meta="false"
else
  promote_eligible_meta="true"
fi
gcloud storage cp --if-generation-match=0 --custom-metadata="promote_eligible=${promote_eligible_meta}" "${RUNNER_TEMP}/manifest.json" "${target_uri}"

{
  echo "staging_version=${STAGING_VERSION}"
  echo "manifest_uri=${target_uri}"
  echo "submission_status=submitted"
} >> "${GITHUB_OUTPUT}"

{
  echo "### OSS Exit Gate Submission — Pending Gate Publication"
  echo ""
  echo "> **Note:** Submitting the manifest succeeds once staged to GCS. The final GitHub Release publish (or rejection, e.g. credential error) happens asynchronously inside OSS Exit Gate and is **not** evaluated synchronously by this workflow run."
  echo ""
  echo "| Field | Value |"
  echo "|---|---|"
  echo "| Status | \`SUBMITTED (PENDING EXIT GATE)\` |"
  echo "| Submission Type | ${submission_type} (${resubmit_note}) |"
  echo "| Release Tag / Title | \`${RELEASE_TAG}\` / \`otelcol-bq ${VERSION}\` |"
  echo "| Commit SHA | \`${commit_short}\` |"
  echo "| Draft / Pre-release | \`is_draft: true\` / \`is_prerelease: ${is_prerelease}\` |"
  echo "| AR Version | \`${RELEASE_AR_PACKAGE}@${STAGING_VERSION}\` |"
  echo "| Manifest GCS URI | \`${target_uri}\` |"
  echo "| Verify Outcome | GitHub Draft Releases · Exit Gate notification email · \`oss-exit-gate-prod\` Cloud Run logs |"
} >> "${GITHUB_STEP_SUMMARY}"
