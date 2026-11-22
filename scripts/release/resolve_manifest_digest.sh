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

if ! [[ "${RELEASE_TAG}" =~ ${RELEASE_TAG_RE} ]]; then
  echo "::error::Invalid RELEASE_TAG value: ${RELEASE_TAG}" >&2
  exit 1
fi
VERSION="${RELEASE_TAG#v}"

if [ -n "${RECONCILED_DIGEST:-}" ]; then
  if ! [[ "${RECONCILED_DIGEST}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
    echo "::error::Unexpected reconciled container manifest digest: ${RECONCILED_DIGEST}" >&2
    exit 1
  fi
  echo "digest=${RECONCILED_DIGEST}" >> "${GITHUB_OUTPUT}"
  exit 0
fi

artifacts_file="${GORELEASER_ARTIFACTS_JSON:-dist/artifacts.json}"
if [ ! -f "${artifacts_file}" ] || [ ! -r "${artifacts_file}" ]; then
  echo "::error::Missing or unreadable GoReleaser artifacts metadata '${artifacts_file}'; cannot resolve pushed container manifest digest." >&2
  exit 1
fi

want_name="${RELEASE_GHCR_IMAGE}:${VERSION}"
if ! pushed_digest="$(
  jq -ser --arg want_name "${want_name}" '
    if (length != 1) or ((.[0] | type) != "array") then
      error("expected a single JSON array in GoReleaser artifacts metadata")
    else
      [ .[0][] | select((type == "object") and .type == "Docker Manifest" and .name == $want_name) ] as $matches
      | if ($matches | length) != 1 then
          error("expected exactly one Docker Manifest artifact matching " + $want_name)
        else
          ($matches[0].extra.Digest // "")
          | if type == "string" then . else error("expected string extra.Digest") end
        end
    end
  ' "${artifacts_file}"
)"; then
  echo "::error::Failed to extract pushed Docker Manifest digest for '${want_name}' from '${artifacts_file}'." >&2
  exit 1
fi

if ! [[ "${pushed_digest}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
  echo "::error::Unexpected pushed container manifest digest in '${artifacts_file}': ${pushed_digest}" >&2
  exit 1
fi

if ! tag_digest="$(docker buildx imagetools inspect "${want_name}" --format '{{ .Manifest.Digest }}')"; then
  echo "::error::Failed to inspect mutable GHCR tag '${want_name}' after GoReleaser push." >&2
  exit 1
fi
if ! [[ "${tag_digest}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
  echo "::error::Unexpected container manifest digest from '${want_name}': ${tag_digest}" >&2
  exit 1
fi
if [ "${tag_digest}" != "${pushed_digest}" ]; then
  echo "::error::Mutable GHCR tag '${want_name}' resolved to '${tag_digest}', which disagrees with GoReleaser pushed manifest digest '${pushed_digest}'; refusing to attest a stale image." >&2
  exit 1
fi

echo "digest=${pushed_digest}" >> "${GITHUB_OUTPUT}"
