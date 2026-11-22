#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
if [ "${BASH_VERSINFO[0]:-0}" -gt 4 ] || { [ "${BASH_VERSINFO[0]:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -ge 4 ]; }; then
  shopt -s inherit_errexit
fi
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/release/common.sh
source "${SCRIPT_DIR}/common.sh"

readonly RELEASE_STABLE_TAG_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'

if [ "${PROMOTE_ELIGIBLE:-true}" != "true" ]; then
  echo "Skipping :latest promotion: preflight marked this run non-promotable (promote_eligible=${PROMOTE_ELIGIBLE:-})."
  exit 0
fi
if ! [[ "${RELEASE_TAG}" =~ ${RELEASE_STABLE_TAG_RE} ]]; then
  echo "Skipping :latest promotion: ${RELEASE_TAG} is not a canonical stable vMAJOR.MINOR.PATCH tag"
  exit 0
fi
if ! [[ "${COMMIT_SHA}" =~ ^[0-9a-f]{7,40}$ ]]; then
  echo "::error::Unexpected COMMIT_SHA value: ${COMMIT_SHA}" >&2
  exit 1
fi
if [ -n "${DIGEST:-}" ] && ! [[ "${DIGEST}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
  echo "::error::Invalid manifest digest for :latest promotion: ${DIGEST}" >&2
  exit 1
fi
if [ -z "${GHCR_ACTOR:-}" ] || [ -z "${GHCR_TOKEN:-}" ] || [ -z "${GH_TOKEN:-}" ] || [ -z "${GITHUB_REPOSITORY:-}" ]; then
  echo "::error::Missing required GHCR/repository environment context" >&2
  exit 1
fi

cmp_uint() {
  local a="$1" b="$2"
  if [ "${#a}" -gt "${#b}" ]; then
    return 0
  fi
  if [ "${#a}" -lt "${#b}" ]; then
    return 1
  fi
  [[ "${a}" > "${b}" ]]
}

verify_origin_promotion_target() {
  local ls_remote_out remote_tags_tsv resolved_commit highest_tag best_maj best_min best_pat tag tag_commit maj min pat
  if ! ls_remote_out="$(git ls-remote --tags origin)"; then
    echo "::error::Failed to query origin tags via git ls-remote." >&2
    return 1
  fi
  if ! remote_tags_tsv="$(
    printf '%s\n' "${ls_remote_out}" | awk '
      {
        oid = $1; ref = $2
        if (sub(/^refs\/tags\//, "", ref) && ref ~ /^v/) {
          if (sub(/\^\{\}$/, "", ref)) {
            peeled[ref] = oid
          } else if (!(ref in seen)) {
            seen[ref] = oid
          }
        }
      }
      END {
        for (t in seen) {
          c = (t in peeled) ? peeled[t] : seen[t]
          print t "\t" c
        }
        for (t in peeled) {
          if (!(t in seen)) {
            print t "\t" peeled[t]
          }
        }
      }
    '
  )"; then
    return 1
  fi

  resolved_commit=""
  highest_tag=""
  best_maj=""
  best_min=""
  best_pat=""
  while IFS=$'\t' read -r tag tag_commit; do
    [ -n "${tag}" ] || continue
    if [ "${tag}" = "${RELEASE_TAG}" ]; then
      resolved_commit="${tag_commit}"
    fi
    if [[ "${tag}" =~ ${RELEASE_STABLE_TAG_RE} ]]; then
      maj="${BASH_REMATCH[1]}"
      min="${BASH_REMATCH[2]}"
      pat="${BASH_REMATCH[3]}"
      if [[ -z "${highest_tag}" ]] ||
         cmp_uint "${maj}" "${best_maj}" ||
         { [[ "${maj}" == "${best_maj}" ]] && cmp_uint "${min}" "${best_min}"; } ||
         { [[ "${maj}" == "${best_maj}" && "${min}" == "${best_min}" ]] && cmp_uint "${pat}" "${best_pat}"; }; then
        best_maj="${maj}"
        best_min="${min}"
        best_pat="${pat}"
        highest_tag="${tag}"
      fi
    fi
  done <<< "${remote_tags_tsv}"

  if [ -z "${resolved_commit}" ]; then
    echo "::error::Release tag ${RELEASE_TAG} is missing or withdrawn on origin; refusing :latest promotion." >&2
    exit 1
  fi
  if [ "${resolved_commit}" != "${COMMIT_SHA}" ]; then
    echo "::error::Remote tag ${RELEASE_TAG} on origin resolves to ${resolved_commit}, expected ${COMMIT_SHA}; refusing :latest promotion." >&2
    exit 1
  fi
  if [[ -z "${highest_tag}" ]]; then
    echo "Skipping :latest promotion: no canonical stable vMAJOR.MINOR.PATCH tags found on origin"
    exit 0
  fi
  if [[ "${RELEASE_TAG}" != "${highest_tag}" ]]; then
    echo "Skipping :latest promotion: ${RELEASE_TAG} is not the highest stable tag on origin (highest is ${highest_tag})"
    exit 0
  fi
}

verify_origin_promotion_target

if ! ghcr_token="$(ensure_ghcr_token "${GHCR_ACTOR}" "${GHCR_TOKEN}")"; then
  exit 1
fi
VERSION="${RELEASE_TAG#v}"
if [ -z "${DIGEST:-}" ]; then
  if ! probe_out="$(probe_ghcr_manifest_digest "${ghcr_token}" "${VERSION}")"; then
    exit 1
  fi
  IFS=$'\t' read -r probe_status probe_digest <<< "${probe_out}"
  if [ "${probe_status}" != "exists" ]; then
    echo "::error::Cannot reconcile :latest* aliases for highest stable tag ${RELEASE_TAG}: ${RELEASE_GHCR_IMAGE}:${VERSION} does not exist in GHCR." >&2
    exit 1
  fi
  DIGEST="${probe_digest}"
fi

cosign verify \
  --certificate-oidc-issuer="${RELEASE_COSIGN_OIDC_ISSUER}" \
  --certificate-identity="${RELEASE_COSIGN_IDENTITY_BASE}${RELEASE_TAG}" \
  "${RELEASE_GHCR_IMAGE}@${DIGEST}"

gh attestation verify "oci://${RELEASE_GHCR_IMAGE}@${DIGEST}" \
  --bundle-from-oci \
  --predicate-type "${RELEASE_PREDICATE_SLSA}" \
  --repo "${GITHUB_REPOSITORY}" \
  --signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/release.yml" \
  --source-ref "refs/tags/${RELEASE_TAG}" \
  --source-digest "${COMMIT_SHA}"

raw_index="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${DIGEST}" --raw)"
platforms_tsv="$(
  printf '%s' "${raw_index}" | jq -er '
    .manifests
    | map(select(.platform.os != "unknown"))
    | if (map(.platform.os + "/" + .platform.architecture) | sort) == ["linux/amd64", "linux/arm64"]
      then .[] | [.platform.os + "/" + .platform.architecture, .digest] | @tsv
      else error("expected one image each for linux/amd64 and linux/arm64") end
  '
)"

amd64_digest=""
arm64_digest=""
while IFS=$'\t' read -r platform child_digest; do
  if ! [[ "${child_digest}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
    echo "::error::Invalid child manifest digest for ${platform}: ${child_digest}" >&2
    exit 1
  fi
  child_rev="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${child_digest}" --format '{{ index .Image.Config.Labels "org.opencontainers.image.revision" }}')"
  if [ "${child_rev}" != "${COMMIT_SHA}" ]; then
    echo "::error::Container ${RELEASE_GHCR_IMAGE}@${child_digest} (${platform}) belongs to commit '${child_rev}', expected '${COMMIT_SHA}'." >&2
    exit 1
  fi
  child_ver="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${child_digest}" --format '{{ index .Image.Config.Labels "org.opencontainers.image.version" }}')"
  if [ "${child_ver}" != "${VERSION}" ]; then
    echo "::error::Container ${RELEASE_GHCR_IMAGE}@${child_digest} (${platform}) has version label '${child_ver}', expected '${VERSION}'." >&2
    exit 1
  fi
  case "${platform}" in
    linux/amd64) amd64_digest="${child_digest}" ;;
    linux/arm64) arm64_digest="${child_digest}" ;;
  esac
done <<< "${platforms_tsv}"

if [[ -z "${amd64_digest}" || -z "${arm64_digest}" ]]; then
  echo "::error::Missing expected child digests (amd64=${amd64_digest}, arm64=${arm64_digest})" >&2
  exit 1
fi

reconcile_alias() {
  local alias_tag="$1" target_digest="$2" prefer_single="$3"
  local probe_out probe_status probe_digest
  if ! probe_out="$(probe_ghcr_manifest_digest "${ghcr_token}" "${alias_tag}")"; then
    return 1
  fi
  IFS=$'\t' read -r probe_status probe_digest <<< "${probe_out}"
  if [ "${probe_status}" = "exists" ] && [ "${probe_digest}" = "${target_digest}" ]; then
    echo "${RELEASE_GHCR_IMAGE}:${alias_tag} already points to ${target_digest}; skipping update."
    return 0
  fi
  if [ "${prefer_single}" = "true" ]; then
    docker buildx imagetools create --prefer-index=false -t "${RELEASE_GHCR_IMAGE}:${alias_tag}" "${RELEASE_GHCR_IMAGE}@${target_digest}"
  else
    docker buildx imagetools create -t "${RELEASE_GHCR_IMAGE}:${alias_tag}" "${RELEASE_GHCR_IMAGE}@${target_digest}"
  fi
  echo "Promoted ${RELEASE_GHCR_IMAGE}:${alias_tag} -> ${RELEASE_GHCR_IMAGE}@${target_digest} (${RELEASE_TAG})"
}

# Re-verify remote origin tag state immediately before moving public aliases.
verify_origin_promotion_target
reconcile_alias "latest" "${DIGEST}" "false"
reconcile_alias "latest-amd64" "${amd64_digest}" "true"
reconcile_alias "latest-arm64" "${arm64_digest}" "true"
