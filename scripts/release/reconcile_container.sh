#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
if [ "${BASH_VERSINFO[0]:-0}" -gt 4 ] || { [ "${BASH_VERSINFO[0]:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -ge 4 ]; }; then
  shopt -s inherit_errexit
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release/common.sh
source "${SCRIPT_DIR}/common.sh"

validate_release_tag_and_sha "${RELEASE_TAG}" "${COMMIT_SHA}"
if [ -z "${GHCR_ACTOR:-}" ] || [ -z "${GHCR_TOKEN:-}" ] || [ -z "${GH_TOKEN:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
  echo "::error::Missing required GHCR/GitHub environment context" >&2
  exit 1
fi

VERSION="${RELEASE_TAG#v}"
if ! ghcr_token="$(ensure_ghcr_token "${GHCR_ACTOR}" "${GHCR_TOKEN}")"; then
  exit 1
fi
if ! container_state="$(inspect_ghcr_container_provenance "${ghcr_token}" "${RELEASE_TAG}" "${COMMIT_SHA}" "${VERSION}" "${GITHUB_REPOSITORY}")"; then
  exit 1
fi
IFS=$'\t' read -r prov_status existing_digest <<< "${container_state}"

case "${prov_status}" in
  verified)
    {
      echo "container_exists=true"
      echo "digest=${existing_digest}"
    } >> "${GITHUB_OUTPUT}"
    echo "Reusing verified existing GHCR container ${RELEASE_GHCR_IMAGE}@${existing_digest} for commit ${COMMIT_SHA} (${VERSION})."
    ;;
  missing)
    # Never attest fresh build provenance against a reused image digest; trigger
    # a clean container rebuild so build provenance truthfully names this run.
    {
      echo "container_exists=false"
      echo "digest="
    } >> "${GITHUB_OUTPUT}"
    echo "Existing signed container ${RELEASE_GHCR_IMAGE}@${existing_digest} lacks verified SLSA provenance; rebuilding and attesting a fresh container digest."
    ;;
  absent)
    {
      echo "container_exists=false"
      echo "digest="
    } >> "${GITHUB_OUTPUT}"
    echo "Confirmed ${RELEASE_GHCR_IMAGE}:${VERSION} absent in GHCR; GoReleaser will publish it."
    ;;
  *)
    echo "::error::Unexpected container provenance state: ${prov_status}" >&2
    exit 1
    ;;
esac
