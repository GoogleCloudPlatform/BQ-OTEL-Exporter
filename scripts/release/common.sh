#!/usr/bin/env bash
# Copyright 2026 Google LLC
# SPDX-License-Identifier: Apache-2.0

# Shared helpers for .github/workflows/release.yml steps. Sourced, not executed.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "::error::scripts/release/common.sh must be sourced, not executed directly." >&2
  exit 1
fi

readonly RELEASE_GHCR_IMAGE="ghcr.io/googlecloudplatform/bq-otel-collector"
readonly RELEASE_GHCR_REPO="googlecloudplatform/bq-otel-collector"
readonly RELEASE_AR_PROJECT="oss-exit-gate-prod"
readonly RELEASE_AR_LOCATION="us"
readonly RELEASE_AR_REPO="bq-otel-exporter--githubreleases"
readonly RELEASE_AR_PACKAGE="bq-otel-exporter"
readonly RELEASE_MANIFESTS_PREFIX="gs://oss-exit-gate-prod-projects-bucket/bq-otel-exporter/githubreleases/manifests"
readonly RELEASE_TAG_RE='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$'
readonly RELEASE_AR_VERSION_RE='^[a-z0-9][a-z0-9._-]{0,127}$'
readonly RELEASE_SHA256_DIGEST_RE='^sha256:[a-f0-9]{64}$'
readonly RELEASE_COSIGN_OIDC_ISSUER='https://token.actions.githubusercontent.com'
readonly RELEASE_COSIGN_IDENTITY_BASE='https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/'
readonly RELEASE_PREDICATE_SLSA='https://slsa.dev/provenance/v1'
readonly RELEASE_MAX_REFERRERS_PAGES=20

validate_release_tag_and_sha() {
  local tag="$1"
  local commit_sha="$2"
  local commit_short
  if ! [[ "${tag}" =~ ${RELEASE_TAG_RE} ]]; then
    echo "::error::Invalid RELEASE_TAG value: ${tag}" >&2
    return 1
  fi
  commit_short="${commit_sha:0:12}"
  if ! [[ "${commit_short}" =~ ^[0-9a-f]{7,12}$ ]] || ! [[ "${commit_sha}" =~ ^[0-9a-f]{7,40}$ ]]; then
    echo "::error::Unexpected COMMIT_SHA value: ${commit_sha}" >&2
    return 1
  fi
}

validate_run_id() {
  local run_id="$1"
  if ! [[ "${run_id}" =~ ^[0-9]+$ ]]; then
    echo "::error::Unexpected RUN_ID value: ${run_id}" >&2
    return 1
  fi
}

release_is_prerelease() {
  local version="$1"
  if [[ "${version}" == *-* ]]; then
    printf 'true'
  else
    printf 'false'
  fi
}

# Verify on origin that RELEASE_TAG exists (peeling annotated tags to commits)
# and resolves to COMMIT_SHA. Fails closed if missing, moved, or unreachable.
verify_origin_release_tag() {
  local remote="$1"
  local tag="$2"
  local expected_sha="$3"
  local ls_out resolved_commit
  if ! ls_out="$(git ls-remote --tags "${remote}" "refs/tags/${tag}" "refs/tags/${tag}^{}")"; then
    echo "::error::Failed to query origin tags via git ls-remote while verifying '${tag}'." >&2
    return 1
  fi
  if ! resolved_commit="$(
    printf '%s\n' "${ls_out}" | awk -v tag="${tag}" '
      $2 == ("refs/tags/" tag) { if (direct == "") direct = $1 }
      $2 == ("refs/tags/" tag "^{}") { peeled = $1 }
      END {
        c = (peeled != "") ? peeled : direct
        if (c != "") print c
      }
    '
  )"; then
    echo "::error::Failed to parse git ls-remote tag output for '${tag}'." >&2
    return 1
  fi
  if [ -z "${resolved_commit}" ]; then
    echo "::error::Release tag ${tag} is missing or withdrawn on origin; refusing Exit Gate manifest submission." >&2
    return 1
  fi
  if [ "${resolved_commit}" != "${expected_sha}" ]; then
    echo "::error::Remote tag ${tag} on origin resolves to ${resolved_commit}, expected ${expected_sha}; refusing Exit Gate manifest submission." >&2
    return 1
  fi
}

validate_existing_manifest() {
  local uri="$1"
  local tag="$2"
  local version="$3"
  local is_prerelease="$4"
  local tag_hash="$5"
  local commit_short="$6"
  local computed_tag_hash expected_staging_ver json_raw ver
  if ! [[ "${tag_hash}" =~ ^[0-9a-f]{12}$ ]] || ! [[ "${commit_short}" =~ ^[0-9a-f]{7,12}$ ]]; then
    echo "::error::Invalid manifest binding parameters (tag_hash='${tag_hash}', commit_short='${commit_short}')." >&2
    return 1
  fi
  computed_tag_hash="$(printf '%s' "${tag}" | sha256sum | awk '{ print substr($1, 1, 12) }')"
  if [ "${tag_hash}" != "${computed_tag_hash}" ]; then
    echo "::error::Manifest tag hash mismatch for '${tag}': got '${tag_hash}', computed '${computed_tag_hash}'." >&2
    return 1
  fi
  expected_staging_ver="t-${tag_hash}-${commit_short}"
  if ! json_raw="$(gcloud storage cat "${uri}")"; then
    echo "::error::Failed to read existing Exit Gate manifest '${uri}' from GCS." >&2
    return 1
  fi
  if ! ver="$(
    printf '%s' "${json_raw}" | jq -ser \
      --arg tag "${tag}" \
      --arg relname "otelcol-bq ${version}" \
      --arg pkg "${RELEASE_AR_PACKAGE}" \
      --arg expected_ver "${expected_staging_ver}" \
      --argjson prerelease "${is_prerelease}" '
        if length != 1 then
          error("expected a single JSON document in Exit Gate manifest")
        else
          .[0]
        end
        | select(type == "object")
        | select(.publish_all == false)
        | select((.publishing_groups | type) == "array" and (.publishing_groups | length) == 1)
        | select((.publishing_groups[0].packages | type) == "array" and (.publishing_groups[0].packages | length) == 1)
        | select((.registry_config | type) == "object" and (.registry_config.github_releases | type) == "object")
        | select(.registry_config.github_releases.tag == $tag)
        | select(.registry_config.github_releases.name == $relname)
        | select(.registry_config.github_releases.is_draft == true)
        | select(.registry_config.github_releases.is_prerelease == $prerelease)
        | .publishing_groups[0].packages[0]
        | select(.name == $pkg)
        | .version
        | select(type == "string")
        | select(. == $expected_ver)
      ' 2>/dev/null
  )"; then
    echo "::error::Existing Exit Gate manifest '${uri}' is malformed or does not match tag '${tag}', expected staging version '${expected_staging_ver}', and package '${RELEASE_AR_PACKAGE}'." >&2
    return 1
  fi
  if ! [[ "${ver}" =~ ${RELEASE_AR_VERSION_RE} ]] || [ "${ver}" != "${expected_staging_ver}" ]; then
    echo "::error::Existing Exit Gate manifest '${uri}' has invalid or mismatched staged version '${ver}' (expected '${expected_staging_ver}')." >&2
    return 1
  fi
  printf '%s' "${ver}"
}

read_manifest_promote_eligible() {
  local uri="$1"
  local desc_json val
  if ! desc_json="$(gcloud storage objects describe "${uri}" --format="json(custom_fields)")"; then
    return 1
  fi
  if ! val="$(
    printf '%s' "${desc_json}" | jq -ser '
      if length != 1 then
        error("expected a single JSON document from objects describe")
      else
        .[0]
      end
      | if . == null then
          ""
        elif type == "object" then
          ((.custom_fields // {}) | if type == "object" then (.promote_eligible // "") else error("expected object custom_fields") end)
        else
          error("expected object or null from objects describe")
        end
    '
  )"; then
    return 1
  fi
  printf '%s' "${val}"
}

# Lists live manifests for (tag_hash, commit_short), ignoring archived
# noncurrent object versions, and emits "<primary_present>\t<forced_present>\t<best_forced_uri>".
list_tag_commit_manifests() {
  local tag_hash="$1"
  local commit_short="$2"
  local run_id="$3"
  local raw_json raw obj base rid
  local primary_present=false
  local forced_present=false
  local best_forced_uri=""
  local best_forced_rid=-1

  if ! raw_json="$(gcloud storage objects list "${RELEASE_MANIFESTS_PREFIX}/manifest-${tag_hash}-${commit_short}*.json" --format="json(name,noncurrent_time)")"; then
    return 1
  fi
  if ! raw="$(
    printf '%s' "${raw_json}" | jq -sr '
      if length != 1 then
        error("expected a single JSON document from gcloud storage objects list")
      elif (.[0] | type) != "array" then
        error("expected array from gcloud storage objects list")
      else
        .[0]
        | map(
            if (type == "object") and ((.name | type) == "string") and ((.name | length) > 0) then
              .
            else
              error("malformed GCS listing entry: expected object with non-empty string name")
            end
          )
        | .[]
        | select(.noncurrent_time == null)
        | .name
      end
    '
  )"; then
    return 1
  fi
  while IFS= read -r obj; do
    [ -n "${obj}" ] || continue
    base="${obj##*/}"
    if [[ "${base}" =~ ^manifest-${tag_hash}-${commit_short}\.json$ ]]; then
      primary_present=true
    elif [[ "${base}" =~ ^manifest-${tag_hash}-${commit_short}-r([0-9]+)\.json$ ]]; then
      rid="${BASH_REMATCH[1]}"
      if [ "${rid}" = "${run_id}" ]; then
        forced_present=true
      fi
      if [ "$((10#${rid}))" -gt "${best_forced_rid}" ]; then
        best_forced_rid="$((10#${rid}))"
        best_forced_uri="${RELEASE_MANIFESTS_PREFIX}/${base}"
      fi
    fi
  done <<< "${raw}"

  printf '%s\t%s\t%s\n' "${primary_present}" "${forced_present}" "${best_forced_uri}"
}

ensure_ghcr_token() {
  local actor="$1"
  local token="$2"
  local basic_b64 token_json
  if ! basic_b64="$(printf '%s:%s' "${actor}" "${token}" | base64 | tr -d '\r\n')"; then
    return 1
  fi
  if ! token_json="$(
    printf 'Authorization: Basic %s\n' "${basic_b64}" |
      curl -fsS --connect-timeout 10 --max-time 30 -H @- \
        "https://ghcr.io/token?scope=repository:${RELEASE_GHCR_REPO}:pull&service=ghcr.io"
  )"; then
    return 1
  fi
  printf '%s' "${token_json}" | jq -er '.token | select(type == "string" and length > 0)'
}

# Probes GHCR top-level manifest reference directly via OCI Distribution API
# and prints "<exists|absent>\t<digest>" on stdout.
probe_ghcr_manifest_digest() {
  local ghcr_token="$1"
  local tag_ref="$2"
  local hdr_file="" body_file="" http_code digest err_body
  if ! hdr_file="$(mktemp)" || ! body_file="$(mktemp)"; then
    rm -f "${hdr_file}" "${body_file}"
    echo "::error::Failed to create temporary files while probing GHCR manifest '${tag_ref}'." >&2
    return 1
  fi
  if ! http_code="$(
    printf 'Authorization: Bearer %s\n' "${ghcr_token}" |
      curl -sS --connect-timeout 10 --max-time 30 \
        -H @- \
        -H "Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json" \
        -D "${hdr_file}" \
        -o "${body_file}" \
        -w '%{http_code}' \
        "https://ghcr.io/v2/${RELEASE_GHCR_REPO}/manifests/${tag_ref}"
  )"; then
    rm -f "${hdr_file}" "${body_file}"
    echo "::error::Failed to probe GHCR manifest '${tag_ref}'" >&2
    return 1
  fi
  local final_hdrs=""
  case "${http_code}" in
    200)
      if ! final_hdrs="$(extract_final_http_headers "${hdr_file}")" || \
         ! digest="$(printf '%s\n' "${final_hdrs}" | LC_ALL=C awk '
           tolower($0) ~ /^docker-content-digest:/ {
             v = $0
             sub(/^[^:]*:[ \t]*/, "", v)
             sub(/[ \t]+$/, "", v)
             if (v == "" || (seen && v != val)) {
               err = 1
               exit 1
             }
             seen = 1
             val = v
           }
           END {
             if (err || !seen) exit 1
             print val
           }
         ')"; then
        rm -f "${hdr_file}" "${body_file}"
        echo "::error::Failed to parse GHCR Docker-Content-Digest header for '${tag_ref}'." >&2
        return 1
      fi
      rm -f "${hdr_file}" "${body_file}"
      if ! [[ "${digest}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
        echo "::error::GHCR 200 response for manifest '${tag_ref}' lacked a valid Docker-Content-Digest header: '${digest}'" >&2
        return 1
      fi
      printf 'exists\t%s\n' "${digest}"
      ;;
    404)
      if jq -e '(.errors | type == "array" and length > 0) and all(.errors[]; .code == "MANIFEST_UNKNOWN" or .code == "NAME_UNKNOWN")' "${body_file}" >/dev/null 2>&1; then
        rm -f "${hdr_file}" "${body_file}"
        printf 'absent\t\n'
      else
        err_body="$(cat "${body_file}" || true)"
        rm -f "${hdr_file}" "${body_file}"
        echo "::error::GHCR returned HTTP 404 for manifest '${tag_ref}' without confirmed MANIFEST_UNKNOWN/NAME_UNKNOWN payload: ${err_body}" >&2
        return 1
      fi
      ;;
    *)
      err_body="$(cat "${body_file}" || true)"
      rm -f "${hdr_file}" "${body_file}"
      echo "::error::Unexpected GHCR HTTP ${http_code} probing manifest '${tag_ref}': ${err_body}" >&2
      return 1
      ;;
  esac
}

# Strips at most one trailing CR per line in the C locale and emits only the
# final HTTP response header block from a curl -D header dump (ignoring
# preceding 1xx/redirect response blocks and eligible well-formed unrelated
# trailers). Rejects NULs, disallowed control bytes, bare-CR/non-LF EOF lines,
# truncated 1xx-only dumps, unterminated status-bearing header blocks (a blank
# line must terminate each status header block before EOF), sensitive trailers
# (Link, OCI-Filters-Applied, Docker-Content-Digest), ineligible/closed trailers,
# and ambiguous framing; well-formed eligible trailers may end either with a
# blank line or cleanly at LF-terminated EOF (matching curl -D chunked trailer
# output). Callers enforce exact final status policy (200 vs 404 vs 5xx) via
# curl's %{http_code}.
extract_final_http_headers() {
  local hdr_file="$1"
  if [ ! -r "${hdr_file}" ]; then
    return 1
  fi
  if ! (
    set -o pipefail
    LC_ALL=C od -An -v -tx1 < "${hdr_file}" | LC_ALL=C awk '
      {
        for (i = 1; i <= NF; i++) {
          tok = tolower($i)
          if (tok !~ /^[0-9a-f][0-9a-f]$/ || tok == "00") {
            err = 1
            exit 1
          }
          last = tok
          count++
        }
      }
      END {
        if (err || count == 0 || last != "0a") exit 1
      }
    '
  ); then
    return 1
  fi
  LC_ALL=C awk '
    function has_disallowed_ctl(s,    tmp) {
      if (s !~ /[[:cntrl:]]/) return 0
      tmp = s
      gsub(/\t/, "", tmp)
      return tmp ~ /[[:cntrl:]]/
    }
    function is_te_tchar(c) {
      return c ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]$/
    }
    function te_finish_item(coding, has_param, te_state) {
      # RFC 9112 sections 7.1 and 7.2: chunked and the standard compression codings accept no parameters.
      if (coding == "chunked" || coding == "gzip" || coding == "deflate" || coding == "compress" || coding == "x-gzip" || coding == "x-compress") {
        if (has_param) {
          te_state["invalid"] = 1
          return 0
        }
        if (coding == "chunked") {
          te_state["chunked_count"]++
        }
      }
      te_state["last_te"] = coding
      return 1
    }
    # Scan Transfer-Encoding in 4096->256-byte windows so regex/substr work never
    # scales quadratically on long fields (notably in BWK awk).
    function parse_te_header(fval, te_state,    len, obase, owin, olen, ibase, win, st, coding, coding_len, has_param, ch, tok_chunk) {
      len = length(fval)
      obase = 1
      st = 0
      coding = ""
      coding_len = 0
      has_param = 0
      while (obase <= len) {
        owin = substr(fval, obase, 4096)
        olen = length(owin)
        obase += olen
        ibase = 1
        while (ibase <= olen) {
          win = substr(owin, ibase, 256)
          ibase += 256
          while (win != "") {
            if (st == 0) {
              if (match(win, /^[ \t,]+/)) {
                win = substr(win, RLENGTH + 1)
                continue
              }
              ch = substr(win, 1, 1)
              if (!is_te_tchar(ch)) {
                te_state["invalid"] = 1
                return
              }
              coding = ""
              coding_len = 0
              has_param = 0
              st = 1
            } else if (st == 1) {
              if (match(win, /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+/)) {
                if (coding_len <= 10) {
                  if (coding_len + RLENGTH <= 10) {
                    tok_chunk = substr(win, 1, RLENGTH)
                    coding = coding tolower(tok_chunk)
                  } else {
                    coding = "<long>"
                  }
                }
                coding_len += RLENGTH
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              st = 2
            } else if (st == 2) {
              if (match(win, /^[ \t]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              ch = substr(win, 1, 1)
              if (ch == ";") {
                has_param = 1
                win = substr(win, 2)
                st = 3
              } else if (ch == ",") {
                if (!te_finish_item(coding, has_param, te_state)) return
                win = substr(win, 2)
                st = 0
              } else {
                te_state["invalid"] = 1
                return
              }
            } else if (st == 3) {
              if (match(win, /^[ \t]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              ch = substr(win, 1, 1)
              if (!is_te_tchar(ch)) {
                te_state["invalid"] = 1
                return
              }
              st = 4
            } else if (st == 4) {
              if (match(win, /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              st = 5
            } else if (st == 5) {
              if (match(win, /^[ \t]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              ch = substr(win, 1, 1)
              if (ch != "=") {
                te_state["invalid"] = 1
                return
              }
              win = substr(win, 2)
              st = 6
            } else if (st == 6) {
              if (match(win, /^[ \t]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              ch = substr(win, 1, 1)
              if (ch == "\"") {
                win = substr(win, 2)
                st = 7
              } else if (is_te_tchar(ch)) {
                st = 9
              } else {
                te_state["invalid"] = 1
                return
              }
            } else if (st == 7) {
              ch = substr(win, 1, 1)
              if (ch == "\"") {
                win = substr(win, 2)
                st = 2
              } else if (ch == "\\") {
                win = substr(win, 2)
                st = 8
              } else if (match(win, /^[^"\\[:cntrl:]]+/)) {
                win = substr(win, RLENGTH + 1)
              } else if (ch == "\t") {
                win = substr(win, 2)
              } else {
                te_state["invalid"] = 1
                return
              }
            } else if (st == 8) {
              ch = substr(win, 1, 1)
              if (ch != "\t" && ch ~ /[[:cntrl:]]/) {
                te_state["invalid"] = 1
                return
              }
              win = substr(win, 2)
              st = 7
            } else if (st == 9) {
              if (match(win, /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+/)) {
                win = substr(win, RLENGTH + 1)
                if (win == "") continue
              }
              st = 2
            }
          }
        }
      }
      if (st == 0) return
      if (st == 1 || st == 2 || st == 9) {
        te_finish_item(coding, has_param, te_state)
        return
      }
      te_state["invalid"] = 1
    }
    function block_allows_trailers(    i, cp, fname, te_state, saw_cl) {
      if (!saw_status || last_status < 200 || last_status == 204 || last_status == 304) return 0
      if (http_ver == "2" || http_ver == "2.0" || http_ver == "3" || http_ver == "3.0") return 1
      if (http_ver != "1.1") return 0
      saw_cl = 0
      te_state["chunked_count"] = 0
      te_state["invalid"] = 0
      te_state["last_te"] = ""
      for (i = 1; i <= n; i++) {
        cp = index(lines[i], ":")
        if (cp <= 1) continue
        fname = tolower(substr(lines[i], 1, cp - 1))
        if (fname == "content-length") {
          saw_cl = 1
        } else if (fname == "transfer-encoding") {
          parse_te_header(substr(lines[i], cp + 1), te_state)
        }
      }
      return (!saw_cl && !te_state["invalid"] && te_state["chunked_count"] == 1 && te_state["last_te"] == "chunked")
    }
    # Coalesce folded header continuation lines with scalar chunking plus a
    # binary-counter carry stack so repeated obs-fold lines remain linear across
    # decreasing chunk lengths and popped stack slots release strings promptly.
    function fold_push_chunk(s,    left) {
      fold_top++
      fold_stk[fold_top] = s
      fold_sz[fold_top] = 1
      while (fold_top >= 2 && fold_sz[fold_top] >= fold_sz[fold_top - 1]) {
        left = fold_stk[fold_top - 1]
        fold_stk[fold_top - 1] = left fold_stk[fold_top]
        fold_sz[fold_top - 1] += fold_sz[fold_top]
        delete fold_stk[fold_top]
        delete fold_sz[fold_top]
        fold_top--
      }
    }
    function fold_clear(    i) {
      for (i = 1; i <= fold_top; i++) {
        delete fold_stk[i]
        delete fold_sz[i]
      }
      fold_top = 0
      fold_cur = ""
    }
    function fold_start(s) {
      fold_clear()
      if (length(s) >= 512) {
        fold_push_chunk(s)
      } else {
        fold_cur = s
      }
    }
    function fold_push(s) {
      if (length(s) >= 512) {
        if (fold_cur != "") {
          fold_push_chunk(fold_cur)
          fold_cur = ""
        }
        fold_push_chunk(s)
        return
      }
      fold_cur = fold_cur s
      if (length(fold_cur) >= 512) {
        fold_push_chunk(fold_cur)
        fold_cur = ""
      }
    }
    function fold_flush(    left) {
      if (fold_cur != "") {
        fold_push_chunk(fold_cur)
        fold_cur = ""
      }
      while (fold_top > 1) {
        left = fold_stk[fold_top - 1]
        fold_stk[fold_top - 1] = left fold_stk[fold_top]
        fold_sz[fold_top - 1] += fold_sz[fold_top]
        delete fold_stk[fold_top]
        delete fold_sz[fold_top]
        fold_top--
      }
      if (fold_top == 1) {
        lines[n] = fold_stk[1]
        delete fold_stk[1]
        delete fold_sz[1]
        fold_top = 0
      }
    }
    BEGIN {
      saw_status = 0
      http_ver = ""
      last_status = 0
      expect_status = 1
      in_hdr = 0
      in_trailer = 0
      can_have_trailers = 0
      saw_trailer_field = 0
      saw_trailer_block = 0
      saw_block_end = 0
      n = 0
      fold_top = 0
      fold_cur = ""
      err = 0
    }
    {
      sub(/\r$/, "")
      if (index($0, "\r") > 0 || has_disallowed_ctl($0)) {
        err = 1
        exit 1
      }
    }
    $0 == "" {
      if (in_hdr) {
        fold_flush()
        in_hdr = 0
        expect_status = 1
        saw_block_end = 1
        can_have_trailers = block_allows_trailers()
      } else if (in_trailer) {
        in_trailer = 0
        saw_trailer_field = 0
        saw_trailer_block = 1
        can_have_trailers = 0
        expect_status = 1
        saw_block_end = 1
      } else if (can_have_trailers && !saw_trailer_block) {
        saw_trailer_block = 1
        can_have_trailers = 0
        saw_block_end = 1
      } else {
        saw_block_end = 1
      }
      next
    }
    in_hdr && $0 ~ /^[ \t]/ {
      if (n == 0) {
        err = 1
        exit 1
      }
      cont = $0
      sub(/^[ \t]+/, " ", cont)
      fold_push(cont)
      next
    }
    expect_status && !in_hdr && !in_trailer && (saw_status || !saw_block_end) && toupper($0) ~ /^HTTP\057[0-9]+(\.[0-9]+)?[ \t]+[0-9][0-9][0-9]([ \t].*)?$/ {
      saw_status = 1
      http_ver = substr(toupper($1), 6)
      last_status = $2 + 0
      expect_status = 0
      in_hdr = 1
      in_trailer = 0
      can_have_trailers = 0
      saw_trailer_field = 0
      saw_trailer_block = 0
      saw_block_end = 0
      n = 0
      fold_clear()
      next
    }
    !in_hdr && !in_trailer && !saw_status && !saw_block_end && $0 ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+:/ {
      in_hdr = 1
      expect_status = 0
      n = 1
      fold_start($0)
      next
    }
    !in_hdr && !in_trailer && can_have_trailers && !saw_trailer_block && $0 ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+:/ {
      colon_pos = index($0, ":")
      tname = tolower(substr($0, 1, colon_pos - 1))
      if (tname == "link" || tname == "oci-filters-applied" || tname == "docker-content-digest") {
        err = 1
        exit 1
      }
      in_trailer = 1
      saw_trailer_field = 1
      expect_status = 0
      next
    }
    in_trailer && $0 ~ /^[ \t]/ {
      if (!saw_trailer_field) {
        err = 1
        exit 1
      }
      next
    }
    in_trailer && $0 ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+:/ {
      colon_pos = index($0, ":")
      tname = tolower(substr($0, 1, colon_pos - 1))
      if (tname == "link" || tname == "oci-filters-applied" || tname == "docker-content-digest") {
        err = 1
        exit 1
      }
      saw_trailer_field = 1
      next
    }
    !in_hdr {
      err = 1
      exit 1
    }
    $0 ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+:/ {
      fold_flush()
      n++
      fold_start($0)
      next
    }
    {
      err = 1
      exit 1
    }
    END {
      if (err || NR == 0 || (saw_status && (in_hdr || last_status < 200)) || (!saw_status && n == 0)) exit 1
      fold_flush()
      for (i = 1; i <= n; i++) print lines[i]
    }
  ' < "${hdr_file}"
}

# Parses RFC 8288 Link header(s) from an OCI referrers response, validates every
# clause and parameter strictly, resolves RFC 3986 relative references against
# current_url, preserves any initial artifactType filter, and outputs either
# empty string or a validated same-origin rel="next" URL.
extract_next_referrers_url() {
  local hdr_file="$1"
  local existing_digest="$2"
  local current_url="${3:-https://ghcr.io/v2/${RELEASE_GHCR_REPO}/referrers/${existing_digest}}"
  local final_headers=""
  local next_url=""

  if ! final_headers="$(extract_final_http_headers "${hdr_file}")"; then
    echo "::error::Malformed or untrusted HTTP response headers in GHCR referrers response for '${existing_digest}'." >&2
    return 1
  fi
  if ! next_url="$(
    printf '%s\n' "${final_headers}" | LC_ALL=C awk \
      -v expected_repo="${RELEASE_GHCR_REPO}" \
      -v expected_digest="${existing_digest}" \
      -v current_url="${current_url}" '
      function trim(s) {
        sub(/^[ \t]+/, "", s)
        sub(/[ \t]+$/, "", s)
        return s
      }
      function is_tchar(c) {
        return c ~ /^[A-Za-z0-9!#$%&*+.^_`|~\047-]$/
      }
      function hexval(c) {
        return index("0123456789abcdef", tolower(c)) - 1
      }
      function qbuf_push_chunk(stk, sz, st, s,    left) {
        st["top"]++
        stk[st["top"]] = s
        sz[st["top"]] = 1
        while (st["top"] >= 2 && sz[st["top"]] >= sz[st["top"] - 1]) {
          left = stk[st["top"] - 1]
          stk[st["top"] - 1] = left stk[st["top"]]
          sz[st["top"] - 1] += sz[st["top"]]
          delete stk[st["top"]]
          delete sz[st["top"]]
          st["top"]--
        }
      }
      function qbuf_push(stk, sz, st, s) {
        if (s == "") return
        if (length(s) >= 512) {
          if (st["cur"] != "") {
            qbuf_push_chunk(stk, sz, st, st["cur"])
            st["cur"] = ""
          }
          qbuf_push_chunk(stk, sz, st, s)
          return
        }
        st["cur"] = st["cur"] s
        if (length(st["cur"]) >= 512) {
          qbuf_push_chunk(stk, sz, st, st["cur"])
          st["cur"] = ""
        }
      }
      function qbuf_flush(stk, sz, st,    left, out) {
        if (st["cur"] != "") {
          qbuf_push_chunk(stk, sz, st, st["cur"])
          st["cur"] = ""
        }
        while (st["top"] > 1) {
          left = stk[st["top"] - 1]
          stk[st["top"] - 1] = left stk[st["top"]]
          sz[st["top"] - 1] += sz[st["top"]]
          delete stk[st["top"]]
          delete sz[st["top"]]
          st["top"]--
        }
        if (st["top"] == 1) {
          out = stk[1]
          delete stk[1]
          delete sz[1]
          st["top"] = 0
          return out
        }
        return ""
      }
      function pct_decode(s, out_arr,    len, obase, owin, olen, ibase, win, tail, k, h1, h2, code, stk, sz, st) {
        if (index(s, "%") == 0) {
          out_arr[0] = s
          return 1
        }
        len = length(s)
        obase = 1
        tail = ""
        stk[0] = ""
        sz[0] = 0
        st["top"] = 0
        st["cur"] = ""
        while (obase <= len) {
          owin = substr(s, obase, 4096)
          olen = length(owin)
          obase += olen
          ibase = 1
          while (ibase <= olen) {
            win = tail substr(owin, ibase, 256)
            ibase += 256
            tail = ""
            while (win != "") {
              k = index(win, "%")
              if (k == 0) {
                qbuf_push(stk, sz, st, win)
                win = ""
              } else {
                if (k > 1) {
                  qbuf_push(stk, sz, st, substr(win, 1, k - 1))
                  win = substr(win, k)
                }
                if (length(win) < 3) {
                  tail = win
                  win = ""
                } else {
                  h1 = hexval(substr(win, 2, 1))
                  h2 = hexval(substr(win, 3, 1))
                  if (h1 < 0 || h2 < 0) return 0
                  code = h1 * 16 + h2
                  if (code == 0) return 0
                  qbuf_push(stk, sz, st, sprintf("%c", code))
                  win = substr(win, 4)
                }
              }
            }
          }
        }
        if (tail != "") return 0
        out_arr[0] = qbuf_flush(stk, sz, st)
        return 1
      }
      function remove_dot_segments(in_buf,    out_buf, seg, last_slash, k) {
        out_buf = ""
        while (length(in_buf) > 0) {
          if (substr(in_buf, 1, 3) == "../") {
            in_buf = substr(in_buf, 4)
          } else if (substr(in_buf, 1, 2) == "./") {
            in_buf = substr(in_buf, 3)
          } else if (substr(in_buf, 1, 3) == "/./") {
            in_buf = "/" substr(in_buf, 4)
          } else if (in_buf == "/.") {
            in_buf = "/"
          } else if (substr(in_buf, 1, 4) == "/../" || in_buf == "/..") {
            if (substr(in_buf, 1, 4) == "/../") {
              in_buf = "/" substr(in_buf, 5)
            } else {
              in_buf = "/"
            }
            last_slash = 0
            for (k = length(out_buf); k >= 1; k--) {
              if (substr(out_buf, k, 1) == "/") {
                last_slash = k
                break
              }
            }
            if (last_slash > 0) {
              out_buf = substr(out_buf, 1, last_slash - 1)
            } else {
              out_buf = ""
            }
          } else if (in_buf == "." || in_buf == "..") {
            in_buf = ""
          } else {
            if (substr(in_buf, 1, 1) == "/") {
              seg = "/"
              in_buf = substr(in_buf, 2)
            } else {
              seg = ""
            }
            k = index(in_buf, "/")
            if (k > 0) {
              seg = seg substr(in_buf, 1, k - 1)
              in_buf = substr(in_buf, k)
            } else {
              seg = seg in_buf
              in_buf = ""
            }
            out_buf = out_buf seg
          }
        }
        return out_buf
      }
      function valid_rfc3986_raw_path(raw_p,    len, obase, owin, olen, ibase, win, tail, k, h1, h2, code) {
        if (raw_p !~ /^[A-Za-z0-9._~!$&()*+,;=:%\047\057@-]*$/) return 0
        if (index(raw_p, "%") == 0) return 1
        len = length(raw_p)
        obase = 1
        tail = ""
        while (obase <= len) {
          owin = substr(raw_p, obase, 4096)
          olen = length(owin)
          obase += olen
          ibase = 1
          while (ibase <= olen) {
            win = tail substr(owin, ibase, 256)
            ibase += 256
            tail = ""
            while (win != "") {
              k = index(win, "%")
              if (k == 0) {
                win = ""
              } else {
                if (k > 1) win = substr(win, k)
                if (length(win) < 3) {
                  tail = win
                  win = ""
                } else {
                  h1 = hexval(substr(win, 2, 1))
                  h2 = hexval(substr(win, 3, 1))
                  if (h1 < 0 || h2 < 0) return 0
                  code = h1 * 16 + h2
                  if (code == 0) return 0
                  win = substr(win, 4)
                }
              }
            }
          }
        }
        if (tail != "") return 0
        return 1
      }
      function resolve_rfc3986_target(ref,    q_idx, r_hier, r_query, c_idx, hier, s_idx, raw_p, t_scheme, t_auth, t_path, slash_pos, first_seg, last_slash, b_dir, k) {
        if (ref == "" || ref ~ /#/) return ""
        q_idx = index(ref, "?")
        if (q_idx > 0) {
          r_hier = substr(ref, 1, q_idx - 1)
          r_query = substr(ref, q_idx)
        } else {
          r_hier = ref
          r_query = ""
        }
        if (r_hier ~ /^[A-Za-z][A-Za-z0-9+.-]*:/) {
          c_idx = index(r_hier, ":")
          t_scheme = tolower(substr(r_hier, 1, c_idx - 1))
          hier = substr(r_hier, c_idx + 1)
          if (substr(hier, 1, 2) != "//") return ""
          hier = substr(hier, 3)
          s_idx = index(hier, "/")
          if (s_idx > 0) {
            t_auth = tolower(substr(hier, 1, s_idx - 1))
            raw_p = substr(hier, s_idx)
            if (!valid_rfc3986_raw_path(raw_p)) return ""
            t_path = remove_dot_segments(raw_p)
          } else {
            t_auth = tolower(hier)
            t_path = ""
          }
        } else {
          t_scheme = "https"
          if (substr(r_hier, 1, 2) == "//") {
            hier = substr(r_hier, 3)
            s_idx = index(hier, "/")
            if (s_idx > 0) {
              t_auth = tolower(substr(hier, 1, s_idx - 1))
              raw_p = substr(hier, s_idx)
              if (!valid_rfc3986_raw_path(raw_p)) return ""
              t_path = remove_dot_segments(raw_p)
            } else {
              t_auth = tolower(hier)
              t_path = ""
            }
          } else {
            t_auth = "ghcr.io"
            if (r_hier == "") {
              t_path = base_path
            } else {
              if (!valid_rfc3986_raw_path(r_hier)) return ""
              if (substr(r_hier, 1, 1) == "/") {
                t_path = remove_dot_segments(r_hier)
              } else {
                slash_pos = index(r_hier, "/")
                first_seg = (slash_pos > 0 ? substr(r_hier, 1, slash_pos - 1) : r_hier)
                if (index(first_seg, ":") > 0) return ""
                last_slash = 0
                for (k = length(base_path); k >= 1; k--) {
                  if (substr(base_path, k, 1) == "/") {
                    last_slash = k
                    break
                  }
                }
                b_dir = (last_slash > 0 ? substr(base_path, 1, last_slash) : "/")
                t_path = remove_dot_segments(b_dir r_hier)
              }
            }
          }
        }
        if (t_scheme != "https" || t_auth != "ghcr.io" || t_path != base_path) return ""
        return "https://ghcr.io" t_path r_query
      }
      function artifact_type_signature(tail_str,    q, nq, qparts, qi, kv, eq, rk, rv, dk_arr, dv_arr, count, sig) {
        if (tail_str == "") return "0:"
        if (substr(tail_str, 1, 1) != "?") return "ERR"
        q = substr(tail_str, 2)
        if (q == "") return "ERR"
        nq = split(q, qparts, "&")
        count = 0
        sig = ""
        for (qi = 1; qi <= nq; qi++) {
          kv = qparts[qi]
          if (kv == "") return "ERR"
          eq = index(kv, "=")
          if (eq > 0) {
            rk = substr(kv, 1, eq - 1)
            rv = substr(kv, eq + 1)
          } else {
            rk = kv
            rv = ""
          }
          if (!pct_decode(rk, dk_arr) || !pct_decode(rv, dv_arr)) return "ERR"
          if (tolower(dk_arr[0]) == "artifacttype") {
            count++
            sig = sig "|" (eq > 0 ? "1" : "0") ":" length(dv_arr[0]) ":" dv_arr[0]
          }
        }
        return count ":" sig
      }
      function valid_rel_value(pval,    pt, nt, toks, ti, tok, tok_lc) {
        pt = trim(pval)
        if (pt == "") return 0
        nt = split(pt, toks, /[ \t]+/)
        if (nt == 0) return 0
        for (ti = 1; ti <= nt; ti++) {
          tok = toks[ti]
          tok_lc = tolower(tok)
          if (tok_lc ~ /^[a-z][a-z0-9.-]*$/) {
            continue
          }
          if (tok ~ /^[A-Za-z][A-Za-z0-9+.-]*:[^[:space:][:cntrl:]"<>\\;]+$/) {
            continue
          }
          return 0
        }
        return 1
      }
      function rel_has_next(pval,    nt, toks, ti) {
        nt = split(trim(pval), toks, /[ \t]+/)
        for (ti = 1; ti <= nt; ti++) {
          if (tolower(toks[ti]) == "next") return 1
        }
        return 0
      }
      function record_rel_param(pval) {
        clause_rel_count++
        if (clause_rel_count > 1 || !valid_rel_value(pval)) return 0
        if (rel_has_next(pval)) clause_is_next = 1
        return 1
      }
      function finish_link_clause() {
        if (clause_rel_count != 1) return 0
        if (clause_is_next) {
          next_count++
          if (next_count > 1) return 0
          next_url = uri
        }
        return 1
      }
      BEGIN {
        next_count = 0
        next_url = ""
        err = 0
        base_path = "/v2/" expected_repo "/referrers/" expected_digest
        base_prefix = "https://ghcr.io" base_path
        if (substr(current_url, 1, length(base_prefix)) != base_prefix) {
          err = 1
          exit 1
        }
        cur_tail = substr(current_url, length(base_prefix) + 1)
        if (cur_tail != "" && cur_tail !~ /^\?[A-Za-z0-9._~!$&()*+,;=:%?\047\057@-]+$/) {
          err = 1
          exit 1
        }
        cur_at_sig = artifact_type_signature(cur_tail)
        if (cur_at_sig == "ERR") {
          err = 1
          exit 1
        }
      }
      tolower($0) ~ /^link:[ \t]*/ {
        line = $0
        sub(/^[Ll][Ii][Nn][Kk]:[ \t]*/, "", line)
        if (trim(line) == "") { err = 1; exit 1 }
        len_l = length(line)
        obase = 1
        lnk_st = 0
        need_clause = 1
        uri = ""
        uri_len = 0
        clause_rel_count = 0
        clause_is_next = 0
        pname_lc = ""
        pname_len = 0
        while (obase <= len_l) {
          owin = substr(line, obase, 4096)
          olen = length(owin)
          obase += olen
          ibase = 1
          while (ibase <= olen) {
            win = substr(owin, ibase, 256)
            ibase += 256
            while (win != "") {
              if (lnk_st == 0) {
                if (match(win, /^[ \t]+/)) {
                  win = substr(win, RLENGTH + 1)
                  continue
                }
                ch = substr(win, 1, 1)
                if (ch != "<") { err = 1; exit 1 }
                win = substr(win, 2)
                ustk[0] = ""
                usz[0] = 0
                ust["top"] = 0
                ust["cur"] = ""
                uri = ""
                uri_len = 0
                clause_rel_count = 0
                clause_is_next = 0
                need_clause = 0
                lnk_st = 1
              } else if (lnk_st == 1) {
                if (match(win, /^[^[:space:][:cntrl:]<>]+/)) {
                  tok_chunk = substr(win, 1, RLENGTH)
                  qbuf_push(ustk, usz, ust, tok_chunk)
                  uri_len += RLENGTH
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                ch = substr(win, 1, 1)
                if (ch != ">") { err = 1; exit 1 }
                if (uri_len == 0) { err = 1; exit 1 }
                uri = qbuf_flush(ustk, usz, ust)
                win = substr(win, 2)
                lnk_st = 2
              } else if (lnk_st == 2) {
                if (match(win, /^[ \t]+/)) {
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                ch = substr(win, 1, 1)
                if (ch == ";") {
                  win = substr(win, 2)
                  lnk_st = 3
                } else if (ch == ",") {
                  if (!finish_link_clause()) { err = 1; exit 1 }
                  uri = ""
                  clause_rel_count = 0
                  clause_is_next = 0
                  need_clause = 1
                  win = substr(win, 2)
                  lnk_st = 0
                } else {
                  err = 1
                  exit 1
                }
              } else if (lnk_st == 3) {
                if (match(win, /^[ \t]+/)) {
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                ch = substr(win, 1, 1)
                if (!is_tchar(ch)) { err = 1; exit 1 }
                pname_lc = ""
                pname_len = 0
                lnk_st = 4
              } else if (lnk_st == 4) {
                if (match(win, /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+/)) {
                  if (pname_len <= 3) {
                    if (pname_len + RLENGTH <= 3) {
                      tok_chunk = substr(win, 1, RLENGTH)
                      pname_lc = pname_lc tolower(tok_chunk)
                    } else {
                      pname_lc = "<long>"
                    }
                  }
                  pname_len += RLENGTH
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                lnk_st = 5
              } else if (lnk_st == 5) {
                if (match(win, /^[ \t]+/)) {
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                ch = substr(win, 1, 1)
                if (ch == ";" || ch == ",") {
                  if (pname_lc == "rel") { err = 1; exit 1 }
                  lnk_st = 2
                } else if (ch == "=") {
                  win = substr(win, 2)
                  lnk_st = 6
                } else {
                  err = 1
                  exit 1
                }
              } else if (lnk_st == 6) {
                if (match(win, /^[ \t]+/)) {
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                ch = substr(win, 1, 1)
                if (ch == "\"") {
                  win = substr(win, 2)
                  if (pname_lc == "rel") {
                    qstk[0] = ""
                    qsz[0] = 0
                    qst["top"] = 0
                    qst["cur"] = ""
                  }
                  lnk_st = 7
                } else if (is_tchar(ch)) {
                  if (pname_lc == "rel") {
                    qstk[0] = ""
                    qsz[0] = 0
                    qst["top"] = 0
                    qst["cur"] = ""
                  }
                  lnk_st = 9
                } else {
                  err = 1
                  exit 1
                }
              } else if (lnk_st == 7) {
                ch = substr(win, 1, 1)
                if (ch == "\\") {
                  win = substr(win, 2)
                  lnk_st = 8
                } else if (ch == "\"") {
                  win = substr(win, 2)
                  if (pname_lc == "rel") {
                    pval = qbuf_flush(qstk, qsz, qst)
                    if (!record_rel_param(pval)) { err = 1; exit 1 }
                  }
                  lnk_st = 2
                } else if (match(win, /^[^"\\[:cntrl:]]+/)) {
                  if (pname_lc == "rel") {
                    qbuf_push(qstk, qsz, qst, substr(win, 1, RLENGTH))
                  }
                  win = substr(win, RLENGTH + 1)
                } else {
                  err = 1
                  exit 1
                }
              } else if (lnk_st == 8) {
                ch = substr(win, 1, 1)
                if (ch ~ /[[:cntrl:]]/) { err = 1; exit 1 }
                if (pname_lc == "rel") {
                  qbuf_push(qstk, qsz, qst, ch)
                }
                win = substr(win, 2)
                lnk_st = 7
              } else if (lnk_st == 9) {
                if (match(win, /^[A-Za-z0-9!#$%&*+.^_`|~\047-]+/)) {
                  if (pname_lc == "rel") {
                    qbuf_push(qstk, qsz, qst, substr(win, 1, RLENGTH))
                  }
                  win = substr(win, RLENGTH + 1)
                  if (win == "") continue
                }
                if (pname_lc == "rel") {
                  pval = qbuf_flush(qstk, qsz, qst)
                  if (!record_rel_param(pval)) { err = 1; exit 1 }
                }
                lnk_st = 2
              }
            }
          }
        }
        if (need_clause || lnk_st == 0 || lnk_st == 1 || lnk_st == 3 || lnk_st == 6 || lnk_st == 7 || lnk_st == 8) {
          err = 1
          exit 1
        }
        if (lnk_st == 4 || lnk_st == 5) {
          if (pname_lc == "rel") { err = 1; exit 1 }
        } else if (lnk_st == 9) {
          if (pname_lc == "rel") {
            pval = qbuf_flush(qstk, qsz, qst)
            if (!record_rel_param(pval)) { err = 1; exit 1 }
          }
        }
        if (!finish_link_clause()) { err = 1; exit 1 }
      }
      END {
        if (err) exit 1
        if (next_url != "") {
          next_url = resolve_rfc3986_target(next_url)
          if (next_url == "" || substr(next_url, 1, length(base_prefix)) != base_prefix) exit 1
          tail = substr(next_url, length(base_prefix) + 1)
          if (tail != "" && tail !~ /^\?[A-Za-z0-9._~!$&()*+,;=:%?\047\057@-]+$/) exit 1
          next_at_sig = artifact_type_signature(tail)
          if (next_at_sig == "ERR" || next_at_sig != cur_at_sig) exit 1
          print next_url
        }
      }
    '
  )"; then
    echo "::error::Malformed or untrusted Link pagination header in GHCR referrers response for '${existing_digest}'." >&2
    return 1
  fi
  printf '%s' "${next_url}"
}

# Rejects any OCI-Filters-Applied header because the referrers query requests
# an unfiltered index; partial results must fail closed rather than look empty.
check_referrers_filters_applied() {
  local hdr_file="$1"
  local existing_digest="$2"
  local final_headers=""
  local applied_filters=""
  if ! final_headers="$(extract_final_http_headers "${hdr_file}")"; then
    echo "::error::Malformed HTTP response headers while checking OCI-Filters-Applied for '${existing_digest}'." >&2
    return 1
  fi
  if [ -n "${final_headers}" ] && ! applied_filters="$(
    printf '%s\n' "${final_headers}" | LC_ALL=C awk '
      tolower($0) ~ /^oci-filters-applied[ \t]*:/ {
        val = $0
        sub(/^[^:]*:[ \t]*/, "", val)
        sub(/[ \t]+$/, "", val)
        if (val == "") val = "<empty>"
        found = (found == "" ? val : found ", " val)
      }
      END {
        if (found != "") print found
      }
    '
  )"; then
    echo "::error::Failed to inspect OCI-Filters-Applied headers in GHCR referrers response for '${existing_digest}'." >&2
    return 1
  fi
  if [ -n "${applied_filters}" ]; then
    echo "::error::GHCR OCI referrers response for '${existing_digest}' unexpectedly reported filtering (OCI-Filters-Applied: ${applied_filters}); treating lookup as indeterminate." >&2
    return 1
  fi
}

# Walks paginated OCI referrers for existing_digest and prints "true" if any
# SLSA provenance or ambiguous Sigstore referrer exists, or "false" only when
# all pages returned a single valid OCI index with valid descriptors and none matched.
query_ghcr_referrers_has_provenance() {
  local ghcr_token="$1"
  local existing_digest="$2"
  local page=1
  local url="https://ghcr.io/v2/${RELEASE_GHCR_REPO}/referrers/${existing_digest}"
  local seen_urls=""
  local ref_hdr_file="" ref_body_file="" ref_http_code ref_err page_has_prov next_url

  while :; do
    if [ -n "${seen_urls}" ] && printf '%s' "${seen_urls}" | grep -qxF -- "${url}"; then
      echo "::error::Detected cyclic Link pagination in GHCR referrers for '${existing_digest}': ${url}" >&2
      return 1
    fi
    seen_urls="${seen_urls}${url}"$'\n'

    ref_hdr_file=""
    ref_body_file=""
    if ! ref_hdr_file="$(mktemp)" || ! ref_body_file="$(mktemp)"; then
      rm -f "${ref_hdr_file}" "${ref_body_file}"
      echo "::error::Failed to create temporary files while querying GHCR OCI referrers for '${existing_digest}'." >&2
      return 1
    fi
    if ! ref_http_code="$(
      printf 'Authorization: Bearer %s\n' "${ghcr_token}" |
        curl -sS --connect-timeout 10 --max-time 30 \
          -H @- \
          -H "Accept: application/vnd.oci.image.index.v1+json" \
          -D "${ref_hdr_file}" \
          -o "${ref_body_file}" \
          -w '%{http_code}' \
          "${url}"
    )"; then
      rm -f "${ref_hdr_file}" "${ref_body_file}"
      echo "::error::Failed to query GHCR OCI referrers for '${existing_digest}' (${url})." >&2
      return 1
    fi
    if [ "${ref_http_code}" != "200" ]; then
      ref_err="$(cat "${ref_body_file}" || true)"
      rm -f "${ref_hdr_file}" "${ref_body_file}"
      echo "::error::GHCR OCI referrers query returned HTTP ${ref_http_code} for '${existing_digest}' (${ref_err}); failing closed." >&2
      return 1
    fi
    if ! check_referrers_filters_applied "${ref_hdr_file}" "${existing_digest}"; then
      rm -f "${ref_hdr_file}" "${ref_body_file}"
      return 1
    fi

    if ! page_has_prov="$(
      jq -ser '
        def valid_descriptor:
          (type == "object")
          and ((.mediaType | type) == "string") and ((.mediaType | length) > 0)
          and ((.digest | type) == "string") and (.digest | test("\\A(sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})\\z"))
          and ((.size | type) == "number") and (.size >= 0) and (.size == (.size | floor))
          and (if has("artifactType") and .artifactType != null then ((.artifactType | type) == "string") and ((.artifactType | length) > 0) else true end)
          and (if has("annotations") and .annotations != null then ((.annotations | type) == "object") and ((.annotations | to_entries | all(.value | type == "string"))) else true end);
        def is_prov_or_ambiguous:
          ((.annotations["dev.sigstore.bundle.predicateType"]? // .annotations["predicateType"]? // "") as $pt
           | if $pt != "" then
               ($pt == "https://slsa.dev/provenance/v1" or ($pt | test("slsa|provenance"; "i")))
             else
               (((.artifactType // "") + " " + (.mediaType // "")) | test("sigstore|in-toto|dsse|provenance|attestation"; "i"))
             end);
        if (length != 1) then
          error("expected exactly one OCI referrers JSON document")
        else
          .[0]
          | if (type != "object") or (.schemaVersion? != 2) or ((.manifests | type) != "array") or (if has("mediaType") and .mediaType != null then .mediaType != "application/vnd.oci.image.index.v1+json" else false end) then
              error("unexpected OCI referrers payload")
            elif ([.manifests[] | valid_descriptor] | all) | not then
              error("invalid OCI referrer descriptor")
            elif ([.manifests[] | select(is_prov_or_ambiguous)] | length) > 0 then
              "true"
            else
              "false"
            end
        end
      ' "${ref_body_file}"
    )"; then
      ref_err="$(cat "${ref_body_file}" || true)"
      rm -f "${ref_hdr_file}" "${ref_body_file}"
      echo "::error::Invalid or incomplete GHCR OCI referrers JSON for '${existing_digest}': ${ref_err}" >&2
      return 1
    fi
    rm -f "${ref_body_file}"

    if [ "${page_has_prov}" = "true" ]; then
      rm -f "${ref_hdr_file}"
      printf 'true'
      return 0
    fi

    if ! next_url="$(extract_next_referrers_url "${ref_hdr_file}" "${existing_digest}" "${url}")"; then
      rm -f "${ref_hdr_file}"
      return 1
    fi
    rm -f "${ref_hdr_file}"

    if [ -z "${next_url}" ]; then
      printf 'false'
      return 0
    fi
    if [ "${page}" -ge "${RELEASE_MAX_REFERRERS_PAGES}" ]; then
      echo "::error::GHCR OCI referrers pagination exceeded ${RELEASE_MAX_REFERRERS_PAGES} pages for '${existing_digest}'; failing closed." >&2
      return 1
    fi
    url="${next_url}"
    page=$((page + 1))
  done
}

# Inspects any existing GHCR container for VERSION: validates linux/amd64 and
# linux/arm64 digests, commit/version labels, Cosign tag-ref signature, and
# SLSA build provenance. Prints "<verified|missing|absent>\t<digest>".
inspect_ghcr_container_provenance() {
  local ghcr_token="$1"
  local release_tag="$2"
  local commit_sha="$3"
  local version="$4"
  local github_repo="$5"
  local probe_out probe_status existing_digest
  local raw_index platforms_tsv platform child_digest child_rev child_ver
  local gh_out_file gh_err gh_err_sanitized has_prov_referrer

  if ! probe_out="$(probe_ghcr_manifest_digest "${ghcr_token}" "${version}")"; then
    return 1
  fi
  IFS=$'\t' read -r probe_status existing_digest <<< "${probe_out}"
  if [ "${probe_status}" != "exists" ]; then
    printf 'absent\t\n'
    return 0
  fi

  if ! raw_index="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${existing_digest}" --raw)"; then
    return 1
  fi
  if ! platforms_tsv="$(
    printf '%s' "${raw_index}" | jq -er '
      .manifests
      | map(select(.platform.os != "unknown"))
      | if (map(.platform.os + "/" + .platform.architecture) | sort) == ["linux/amd64", "linux/arm64"]
        then .[] | [.platform.os + "/" + .platform.architecture, .digest] | @tsv
        else error("expected one image each for linux/amd64 and linux/arm64") end
    '
  )"; then
    return 1
  fi
  while IFS=$'\t' read -r platform child_digest; do
    if ! [[ "${child_digest}" =~ ${RELEASE_SHA256_DIGEST_RE} ]]; then
      echo "::error::Invalid GHCR child digest for ${platform}: ${child_digest}" >&2
      return 1
    fi
    if ! child_rev="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${child_digest}" --format '{{ index .Image.Config.Labels "org.opencontainers.image.revision" }}')"; then
      return 1
    fi
    if [ "${child_rev}" != "${commit_sha}" ]; then
      echo "::error::Existing GHCR image ${RELEASE_GHCR_IMAGE}:${version} (${platform}@${child_digest}) belongs to commit '${child_rev}', expected '${commit_sha}'." >&2
      return 1
    fi
    if ! child_ver="$(docker buildx imagetools inspect "${RELEASE_GHCR_IMAGE}@${child_digest}" --format '{{ index .Image.Config.Labels "org.opencontainers.image.version" }}')"; then
      return 1
    fi
    if [ "${child_ver}" != "${version}" ]; then
      echo "::error::Existing GHCR image ${RELEASE_GHCR_IMAGE}:${version} (${platform}@${child_digest}) has version label '${child_ver}', expected '${version}'." >&2
      return 1
    fi
  done <<< "${platforms_tsv}"

  if ! cosign verify \
    --certificate-oidc-issuer="${RELEASE_COSIGN_OIDC_ISSUER}" \
    --certificate-identity="${RELEASE_COSIGN_IDENTITY_BASE}${release_tag}" \
    "${RELEASE_GHCR_IMAGE}@${existing_digest}" >&2; then
    echo "::error::Existing GHCR container ${RELEASE_GHCR_IMAGE}:${version} (${existing_digest}) matches commit ${commit_sha} and version ${version}, but signature verification failed (signing was likely interrupted after GoReleaser pushed the container). Operator recovery: either cosign-sign digest ${RELEASE_GHCR_IMAGE}@${existing_digest} from tag refs/tags/${release_tag}, or delete the unsigned package version '${version}' in GHCR Packages (bq-otel-collector) and re-run release.yml." >&2
    return 1
  fi

  if ! gh_out_file="$(mktemp)"; then
    echo "::error::Failed to create temporary file for GH attestation output." >&2
    return 1
  fi
  if gh attestation verify "oci://${RELEASE_GHCR_IMAGE}@${existing_digest}" \
    --bundle-from-oci \
    --predicate-type "${RELEASE_PREDICATE_SLSA}" \
    --repo "${github_repo}" \
    --signer-workflow "${github_repo}/.github/workflows/release.yml" \
    --source-ref "refs/tags/${release_tag}" \
    --source-digest "${commit_sha}" >"${gh_out_file}" 2>&1; then
    rm -f "${gh_out_file}"
    printf 'verified\t%s\n' "${existing_digest}"
    return 0
  fi

  gh_err="$(cat "${gh_out_file}" || true)"
  rm -f "${gh_out_file}"
  gh_err_sanitized="$(printf '%s' "${gh_err}" | sed -E 's/sha256:[0-9a-fA-F]{64}/sha256:<digest>/g' || true)"
  if printf '%s' "${gh_err_sanitized}" | grep -qiE '(^|[^[:alnum:]])(401|403|429|50[0-9])([^[:alnum:]]|$)|unauthorized|forbidden|rate limit|timed out|timeout|connection refused|temporary failure'; then
    echo "::error::Attestation verification lookup failed for ${RELEASE_GHCR_IMAGE}@${existing_digest}: ${gh_err}" >&2
    return 1
  fi
  if ! printf '%s' "${gh_err}" | grep -qiE '(no (matching )?attestations|no bundles|0 attestations|attestations not found|failed to find.*attestations)'; then
    echo "::error::SLSA provenance verification failed for ${RELEASE_GHCR_IMAGE}@${existing_digest}: ${gh_err}" >&2
    return 1
  fi

  if ! has_prov_referrer="$(query_ghcr_referrers_has_provenance "${ghcr_token}" "${existing_digest}")"; then
    return 1
  fi
  if [ "${has_prov_referrer}" = "true" ]; then
    echo "::error::Container ${RELEASE_GHCR_IMAGE}@${existing_digest} has existing provenance/Sigstore referrer(s) in GHCR, yet verification failed (${gh_err}); failing closed." >&2
    return 1
  fi

  printf 'missing\t%s\n' "${existing_digest}"
}

parse_ar_entries() {
  local ar_json="$1"
  printf '%s' "${ar_json}" | jq -er '
    def b64idx:
      if . >= 65 and . <= 90 then . - 65
      elif . >= 97 and . <= 122 then . - 71
      elif . >= 48 and . <= 57 then . + 4
      elif . == 43 or . == 45 then 62
      elif . == 47 or . == 95 then 63
      else error("invalid base64 char") end;
    def hexbyte:
      . as $b | ("0123456789abcdef" | .[($b / 16 | floor):($b / 16 | floor) + 1] + .[($b % 16):($b % 16) + 1]);
    def norm_sha256:
      if (type != "string") then ""
      elif test("^[0-9A-Fa-f]{64}$") then ascii_downcase
      elif test("^[A-Za-z0-9+/_-]{43}=?$") then
        (rtrimstr("=") | explode | map(b64idx)) as $v
        | if ($v[42] % 4) != 0 then "" else
            ([range(0; 10) | . * 4 | [
              ($v[.] * 4 + ($v[. + 1] / 16 | floor)),
              (($v[. + 1] % 16) * 16 + ($v[. + 2] / 4 | floor)),
              (($v[. + 2] % 4) * 64 + $v[. + 3])
            ]] | flatten) + [
              ($v[40] * 4 + ($v[41] / 16 | floor)),
              (($v[41] % 16) * 16 + ($v[42] / 4 | floor))
            ]
            | map(hexbyte) | join("")
          end
      else "" end;
    if type != "array" then error("expected array from gcloud artifacts files list") else . end
    | map({
        name: (.name // ""),
        fname: ((.name // "") | split("/") | last | split("%3A") | last | split(":") | last),
        sha256: ((([.hashes[]? | select(.type == "SHA256") | .value] | first) // "") | norm_sha256)
      })
    | if (map(.fname) | length) != (map(.fname) | unique | length) then error("duplicate Artifact Registry filenames") else . end
    | if all(.[]; (.name | length > 0) and (.fname | length > 0) and (.sha256 | test("^[0-9a-f]{64}$"))) then . else error("missing SHA256 hash or filename in Artifact Registry listing") end
  '
}

parse_checksums_file() {
  local checksums_path="$1"
  awk '
    /^[[:space:]]*$/ { next }
    {
      if (length($0) < 67 || substr($0, 65, 1) != " " || (substr($0, 66, 1) != " " && substr($0, 66, 1) != "*")) {
        exit 2
      }
      hash = tolower(substr($0, 1, 64))
      fname = substr($0, 67)
      if (hash !~ /^[0-9a-f]+$/ || length(fname) == 0 || fname ~ /[[:space:]\/]/) {
        exit 2
      }
      if (fname in seen) {
        exit 3
      }
      seen[fname] = 1
      print fname "\t" hash
    }
  ' "${checksums_path}"
}

download_ar_file_verified() {
  local ar_entries="$1"
  local fname="$2"
  local dest_dir="$3"
  local staging_ver="$4"
  local res_name local_sha remote_sha
  if ! res_name="$(printf '%s' "${ar_entries}" | jq -er --arg f "${fname}" '.[] | select(.fname == $f) | .name')"; then
    return 2
  fi
  if ! gcloud artifacts files download \
    --project="${RELEASE_AR_PROJECT}" \
    --location="${RELEASE_AR_LOCATION}" \
    --repository="${RELEASE_AR_REPO}" \
    --destination="${dest_dir}" \
    --local-filename="${fname}" \
    --allow-overwrite \
    "${res_name}" >/dev/null; then
    return 2
  fi
  if ! local_sha="$(sha256sum "${dest_dir}/${fname}" | awk '{ print tolower($1) }')" || \
     ! remote_sha="$(printf '%s' "${ar_entries}" | jq -er --arg f "${fname}" '.[] | select(.fname == $f) | .sha256')"; then
    return 2
  fi
  if [ "${local_sha}" != "${remote_sha}" ]; then
    echo "::error::Downloaded ${fname} digest ${local_sha} disagrees with Artifact Registry digest ${remote_sha} (${RELEASE_AR_PACKAGE}@${staging_ver}); treating as indeterminate download mismatch." >&2
    return 2
  fi
}

verify_changelog_attestation() {
  local changelog_path="$1"
  local github_repo="$2"
  local release_tag="$3"
  local commit_sha="$4"
  local expected_sha json_out
  if ! expected_sha="$(sha256sum "${changelog_path}" | awk '{ print tolower($1) }')"; then
    return 1
  fi
  if ! json_out="$(
    gh attestation verify "${changelog_path}" \
      --predicate-type "${RELEASE_PREDICATE_SLSA}" \
      --repo "${github_repo}" \
      --signer-workflow "${github_repo}/.github/workflows/release.yml" \
      --source-ref "refs/tags/${release_tag}" \
      --source-digest "${commit_sha}" \
      --format json
  )"; then
    return 1
  fi
  if ! printf '%s' "${json_out}" | jq -e --arg sha "${expected_sha}" '
    type == "array" and length > 0 and any(.[];
      ((.verificationResult.statement.subject // []) | if type == "array" then any(.[];
        ((.digest.sha256 // "") | ascii_downcase) == $sha
        and ((.name // "") == "EXIT_GATE_CHANGELOG" or ((.name // "") | endswith("/EXIT_GATE_CHANGELOG")))
      ) else false end)
    )
  ' >/dev/null; then
    echo "::error::Verified attestation for '${changelog_path}' does not name subject 'EXIT_GATE_CHANGELOG' with digest sha256:${expected_sha}." >&2
    return 1
  fi
}
