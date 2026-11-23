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
  case "${http_code}" in
    200)
      if ! digest="$(awk 'tolower($1) == "docker-content-digest:" { gsub(/\r/, "", $2); val = $2 } END { print val }' "${hdr_file}")"; then
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

# Strips CRs and emits only the final HTTP response header block from a curl -D
# header dump (ignoring any preceding 1xx informational or proxy response blocks).
extract_final_http_headers() {
  local hdr_file="$1"
  tr -d '\r' < "${hdr_file}" | awk '
    BEGIN {
      saw_status = 0
      in_hdr = 1
      n = 0
    }
    tolower($0) ~ /^http\/[0-9]/ {
      saw_status = 1
      in_hdr = 1
      n = 0
      next
    }
    /^[ \t]*$/ {
      if (saw_status) in_hdr = 0
      next
    }
    in_hdr {
      n++
      lines[n] = $0
    }
    END {
      for (i = 1; i <= n; i++) print lines[i]
    }
  '
}

# Parses RFC 8288 Link header(s) from an OCI referrers response, validates every
# clause and parameter strictly, resolves RFC 3986 relative references against
# current_url, preserves any initial artifactType filter, and outputs either
# empty string or a validated same-origin rel="next" URL.
extract_next_referrers_url() {
  local hdr_file="$1"
  local existing_digest="$2"
  local current_url="${3:-https://ghcr.io/v2/${RELEASE_GHCR_REPO}/referrers/${existing_digest}}"
  local next_url=""

  if ! next_url="$(
    extract_final_http_headers "${hdr_file}" | awk \
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
      function pct_decode(s, out_arr,    k, n, c, h1, h2, code, res) {
        n = length(s)
        res = ""
        for (k = 1; k <= n; k++) {
          c = substr(s, k, 1)
          if (c == "%") {
            if (k + 2 > n) return 0
            h1 = hexval(substr(s, k + 1, 1))
            h2 = hexval(substr(s, k + 2, 1))
            if (h1 < 0 || h2 < 0) return 0
            code = h1 * 16 + h2
            if (code == 0) return 0
            res = res sprintf("%c", code)
            k += 2
          } else {
            res = res c
          }
        }
        out_arr[0] = res
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
      function valid_rfc3986_raw_path(raw_p,    i, n, ch, h1, h2, code) {
        if (raw_p !~ /^[A-Za-z0-9._~!$&()*+,;=:%\047\057@-]*$/) return 0
        n = length(raw_p)
        for (i = 1; i <= n; i++) {
          ch = substr(raw_p, i, 1)
          if (ch == "%") {
            if (i + 2 > n) return 0
            h1 = hexval(substr(raw_p, i + 1, 1))
            h2 = hexval(substr(raw_p, i + 2, 1))
            if (h1 < 0 || h2 < 0) return 0
            code = h1 * 16 + h2
            if (code == 0) return 0
            i += 2
          }
        }
        return 1
      }
      function resolve_rfc3986_target(ref,    q_idx, r_hier, r_query, c_idx, hier, s_idx, raw_p, t_scheme, t_auth, t_path, last_slash, b_dir, k) {
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
        while (length(line) > 0) {
          line = trim(line)
          if (substr(line, 1, 1) != "<") { err = 1; exit 1 }
          gt = index(line, ">")
          if (gt <= 2) { err = 1; exit 1 }
          uri = substr(line, 2, gt - 2)
          if (uri ~ /[[:space:][:cntrl:]<>]/) { err = 1; exit 1 }
          rest = substr(line, gt + 1)
          len_r = length(rest)
          p = 1
          clause_rel_count = 0
          clause_is_next = 0
          clause_done = 0

          while (p <= len_r && (substr(rest, p, 1) == " " || substr(rest, p, 1) == "\t")) p++
          while (p <= len_r) {
            ch = substr(rest, p, 1)
            if (ch == ",") {
              p++
              line = substr(rest, p)
              if (trim(line) == "") { err = 1; exit 1 }
              clause_done = 1
              break
            }
            if (ch != ";") { err = 1; exit 1 }
            p++
            while (p <= len_r && (substr(rest, p, 1) == " " || substr(rest, p, 1) == "\t")) p++

            name_start = p
            while (p <= len_r && is_tchar(substr(rest, p, 1))) p++
            pname = substr(rest, name_start, p - name_start)
            if (pname == "") { err = 1; exit 1 }
            pname_lc = tolower(pname)

            while (p <= len_r && (substr(rest, p, 1) == " " || substr(rest, p, 1) == "\t")) p++
            if (p > len_r || substr(rest, p, 1) == ";" || substr(rest, p, 1) == ",") {
              if (pname_lc == "rel") { err = 1; exit 1 }
              continue
            }
            if (substr(rest, p, 1) != "=") { err = 1; exit 1 }
            p++
            while (p <= len_r && (substr(rest, p, 1) == " " || substr(rest, p, 1) == "\t")) p++
            if (p > len_r) { err = 1; exit 1 }

            if (substr(rest, p, 1) == "\"") {
              p++
              pval = ""
              closed = 0
              while (p <= len_r) {
                vc = substr(rest, p, 1)
                if (vc == "\\") {
                  p++
                  if (p > len_r) { err = 1; exit 1 }
                  ec = substr(rest, p, 1)
                  if (ec ~ /[[:cntrl:]]/) { err = 1; exit 1 }
                  pval = pval ec
                  p++
                } else if (vc == "\"") {
                  p++
                  closed = 1
                  break
                } else {
                  if (vc ~ /[[:cntrl:]]/) { err = 1; exit 1 }
                  pval = pval vc
                  p++
                }
              }
              if (!closed) { err = 1; exit 1 }
            } else {
              val_start = p
              while (p <= len_r && is_tchar(substr(rest, p, 1))) p++
              pval = substr(rest, val_start, p - val_start)
              if (pval == "") { err = 1; exit 1 }
            }

            if (pname_lc == "rel") {
              clause_rel_count++
              if (clause_rel_count > 1) { err = 1; exit 1 }
              if (!valid_rel_value(pval)) { err = 1; exit 1 }
              if (rel_has_next(pval)) clause_is_next = 1
            }

            while (p <= len_r && (substr(rest, p, 1) == " " || substr(rest, p, 1) == "\t")) p++
          }

          if (!clause_done) {
            line = ""
          }
          if (clause_rel_count != 1) { err = 1; exit 1 }
          if (clause_is_next) {
            next_count++
            if (next_count > 1) { err = 1; exit 1 }
            next_url = uri
          }
        }
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
  local applied_filters=""
  if ! applied_filters="$(
    extract_final_http_headers "${hdr_file}" | awk '
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
