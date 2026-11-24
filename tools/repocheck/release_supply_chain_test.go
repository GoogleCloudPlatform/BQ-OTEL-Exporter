// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

type supplyChainStep struct {
	ID    string            `yaml:"id"`
	Name  string            `yaml:"name"`
	Uses  string            `yaml:"uses"`
	Shell string            `yaml:"shell"`
	If    any               `yaml:"if,omitempty"`
	Run   string            `yaml:"run"`
	Env   map[string]string `yaml:"env"`
	With  map[string]any    `yaml:"with"`
}

type supplyChainWorkflow struct {
	Concurrency struct {
		Group            string `yaml:"group"`
		CancelInProgress any    `yaml:"cancel-in-progress"`
		Queue            string `yaml:"queue"`
	} `yaml:"concurrency"`
	Jobs struct {
		Preflight struct {
			If          any               `yaml:"if,omitempty"`
			Permissions map[string]string `yaml:"permissions"`
			Outputs     map[string]string `yaml:"outputs"`
			Steps       []supplyChainStep `yaml:"steps"`
		} `yaml:"preflight"`
		Release struct {
			Needs       []string          `yaml:"needs"`
			If          any               `yaml:"if,omitempty"`
			Permissions map[string]string `yaml:"permissions"`
			Outputs     map[string]string `yaml:"outputs"`
			Steps       []supplyChainStep `yaml:"steps"`
		} `yaml:"release"`
		SubmitExitGate struct {
			Needs       []string          `yaml:"needs"`
			If          any               `yaml:"if,omitempty"`
			Permissions map[string]string `yaml:"permissions"`
			Outputs     map[string]string `yaml:"outputs"`
			Steps       []supplyChainStep `yaml:"steps"`
		} `yaml:"submit-exit-gate"`
		PromoteLatest struct {
			Concurrency struct {
				Group            string `yaml:"group"`
				CancelInProgress any    `yaml:"cancel-in-progress"`
				Queue            string `yaml:"queue"`
			} `yaml:"concurrency"`
			Needs       []string          `yaml:"needs"`
			If          any               `yaml:"if,omitempty"`
			Permissions map[string]string `yaml:"permissions"`
			Steps       []supplyChainStep `yaml:"steps"`
		} `yaml:"promote-latest"`
	} `yaml:"jobs"`
}

// The actions behind the release protections, pinned to full commit SHAs as
// every workflow action is. The tag each SHA resolves to is the trailing
// comment on its uses line in release.yml; bump both together.
const (
	checkoutActionV7        = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	setupBuildxV4           = "docker/setup-buildx-action@f87e5991a6d7451dcb8d9637bfbc97413f497069"
	dockerLoginV4           = "docker/login-action@8aa5831fb8d48d8f76594c7ddde61ae58019f550"
	attestBuildProvenanceV4 = "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
	cosignInstallerV4       = "sigstore/cosign-installer@756fe2d284c7292c4e9b62c8a28f1e5629c59532"
	downloadSyftV0          = "anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c"
	gcpAuthV3               = "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093"
	gcpSetupGcloudV3        = "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db"
	exitGateWIFProvider     = "projects/305452601764/locations/global/workloadIdentityPools/builders/providers/github"

	// GitHub Actions rejects expressions/inlined run blocks above 21,000 chars.
	// Enforce a strict 20,000-char ceiling across every workflow run step.
	maxWorkflowRunStepChars = 20000

	releaseCommonScriptPath                = "scripts/release/common.sh"
	releasePreflightScriptPath             = "scripts/release/preflight.sh"
	releaseReconcileScriptPath             = "scripts/release/reconcile_container.sh"
	releaseResolveManifestDigestScriptPath = "scripts/release/resolve_manifest_digest.sh"
	releaseStageScriptPath                 = "scripts/release/stage_exit_gate_assets.sh"
	releaseSubmitScriptPath                = "scripts/release/submit_exit_gate.sh"
	releasePromoteScriptPath               = "scripts/release/promote_latest.sh"
)

var releaseScriptPaths = []string{
	releaseCommonScriptPath,
	releasePreflightScriptPath,
	releaseReconcileScriptPath,
	releaseResolveManifestDigestScriptPath,
	releaseStageScriptPath,
	releaseSubmitScriptPath,
	releasePromoteScriptPath,
}

var executableReleaseScriptPaths = []string{
	releasePreflightScriptPath,
	releaseReconcileScriptPath,
	releaseResolveManifestDigestScriptPath,
	releaseStageScriptPath,
	releaseSubmitScriptPath,
	releasePromoteScriptPath,
}

type supplyChainBundle struct {
	wf      supplyChainWorkflow
	scripts map[string]string
}

func effectiveReleaseScript(step supplyChainStep, scriptPath string, scripts map[string]string) (string, error) {
	wantCmd := "bash ./" + scriptPath
	if strings.TrimSpace(step.Run) != wantCmd {
		return "", fmt.Errorf("step %s run = %q, want exact %q", step.Name, step.Run, wantCmd)
	}
	scriptBody, ok := scripts[scriptPath]
	if !ok || strings.TrimSpace(scriptBody) == "" {
		return "", fmt.Errorf("missing checked-in release script %s", scriptPath)
	}
	commonBody, ok := scripts[releaseCommonScriptPath]
	if !ok || strings.TrimSpace(commonBody) == "" {
		return "", fmt.Errorf("missing shared release helper script %s", releaseCommonScriptPath)
	}
	if !strings.Contains(scriptBody, `source "${SCRIPT_DIR}/common.sh"`) {
		return "", fmt.Errorf("release script %s does not source common.sh", scriptPath)
	}
	return scriptBody + "\n" + commonBody, nil
}

var releaseScriptBash4OnlyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(^|[^#\n])\b(?:declare|local)\s+-[A-Za-z]*[Alu]\b`),
	regexp.MustCompile(`(^|[^#\n])\b(?:mapfile|readarray|coproc)\b`),
	regexp.MustCompile(`(^|[^#\n])(\|&|&>>)`),
	regexp.MustCompile(`(^|[^#\n])\bwait\s+-n\b`),
	regexp.MustCompile(`\$\{[^}\n]*(?:,,|\^\^|\[-[0-9]+\])\}`),
}

var releaseScriptGNUOnlyAwkOrSedPattern = regexp.MustCompile(`\b(?:gensub|asort|asorti|strftime|systime|mktime)\s*\(`)
var releaseScriptAwkProgramStartPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_])awk\b`)

const wantBash44InheritGuard = `if [ "${BASH_VERSINFO[0]:-0}" -gt 4 ] || { [ "${BASH_VERSINFO[0]:-0}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -ge 4 ]; }; then`

func advanceShellToken(text string, i int) int {
	for i < len(text) && text[i] != ' ' && text[i] != '\t' && text[i] != '\n' && text[i] != ';' && text[i] != '|' && text[i] != '&' {
		switch text[i] {
		case '\'':
			end := strings.IndexByte(text[i+1:], '\'')
			if end < 0 {
				return len(text)
			}
			i = i + 1 + end + 1
		case '"':
			i++
			for i < len(text) && text[i] != '"' {
				if text[i] == '\\' && i+1 < len(text) {
					i += 2
					continue
				}
				i++
			}
			if i < len(text) {
				i++
			}
		default:
			i++
		}
	}
	return i
}

func extractAwkPrograms(text string) []string {
	var progs []string
	searchFrom := 0
	for {
		loc := releaseScriptAwkProgramStartPattern.FindStringIndex(text[searchFrom:])
		if loc == nil {
			break
		}
		i := searchFrom + loc[1]
		for i < len(text) {
			switch text[i] {
			case ' ', '\t':
				i++
			case '\\':
				if i+1 < len(text) && text[i+1] == '\n' {
					i += 2
					continue
				}
				i = len(text)
			case '-', 'v', 'F':
				if text[i] != '-' {
					i = advanceShellToken(text, i)
					continue
				}
				optStart := i
				for i < len(text) && text[i] != ' ' && text[i] != '\t' && text[i] != '\n' {
					i++
				}
				opt := text[optStart:i]
				if opt == "-v" || opt == "-F" {
					for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
						i++
					}
					i = advanceShellToken(text, i)
				}
			case '\'':
				end := strings.IndexByte(text[i+1:], '\'')
				if end < 0 {
					i = len(text)
					break
				}
				prog := text[i+1 : i+1+end]
				i = i + 1 + end + 1
				progs = append(progs, prog)
				goto doneAwk
			default:
				i = len(text)
			}
			if i < len(text) && (text[i] == '\n' || text[i] == ';' || text[i] == '|' || text[i] == '&') {
				break
			}
		}
	doneAwk:
		if i <= searchFrom+loc[1] {
			searchFrom += loc[1]
		} else {
			searchFrom = i
		}
	}
	return progs
}

func checkAwkProgramPosixPortability(rel, prog string) error {
	if releaseScriptGNUOnlyAwkOrSedPattern.MatchString(prog) {
		return fmt.Errorf("%s uses GNU-only awk extension in program: %s", rel, prog)
	}
	canStartRegex := true
	inString := false
	inComment := false
	inRegex := false
	inBracket := false
	bracketStart := false
	escaped := false
	for i := 0; i < len(prog); i++ {
		ch := prog[i]
		if inComment {
			if ch == '\n' {
				inComment = false
				canStartRegex = true
			}
			continue
		}
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				inString = false
				canStartRegex = false
			}
			continue
		}
		if inRegex {
			if escaped {
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if inBracket {
				if ch == '/' {
					return fmt.Errorf("%s uses unescaped '/' inside [...] in awk regex literal, which breaks macOS BSD awk", rel)
				}
				if bracketStart && (ch == '^' || ch == ']') {
					bracketStart = false
					continue
				}
				bracketStart = false
				if ch == '[' && i+1 < len(prog) && (prog[i+1] == ':' || prog[i+1] == '.' || prog[i+1] == '=') {
					delim := prog[i+1]
					closeIdx := strings.Index(prog[i+2:], string([]byte{delim, ']'}))
					if closeIdx >= 0 {
						i += 2 + closeIdx + 1
						continue
					}
				}
				if ch == ']' {
					inBracket = false
				}
				continue
			}
			if ch == '[' {
				inBracket = true
				bracketStart = true
				continue
			}
			if ch == '/' {
				inRegex = false
				canStartRegex = false
			}
			continue
		}
		switch {
		case ch == '#':
			inComment = true
		case ch == '"':
			inString = true
		case ch == '/' && canStartRegex:
			inRegex = true
		case ch == ' ' || ch == '\t' || ch == '\r':
		case ch == '\n' || strings.ContainsRune("~(,;=?&|!{}", rune(ch)):
			canStartRegex = true
		case (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == '_':
			start := i
			for i+1 < len(prog) && ((prog[i+1] >= 'A' && prog[i+1] <= 'Z') || (prog[i+1] >= 'a' && prog[i+1] <= 'z') || (prog[i+1] >= '0' && prog[i+1] <= '9') || prog[i+1] == '_') {
				i++
			}
			ident := prog[start : i+1]
			canStartRegex = ident == "return" || ident == "print" || ident == "printf"
		default:
			canStartRegex = false
		}
	}
	return nil
}

func checkReleaseScriptsBash32Compatibility(scripts map[string]string) error {
	for _, rel := range releaseScriptPaths {
		text, ok := scripts[rel]
		if !ok || strings.TrimSpace(text) == "" {
			return fmt.Errorf("missing checked-in release script %s", rel)
		}
		lines := strings.Split(text, "\n")
		for idx, raw := range lines {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, pat := range releaseScriptBash4OnlyPatterns {
				if pat.MatchString(raw) {
					return fmt.Errorf("%s:%d uses Bash 4+-only construct matching %q: %s", rel, idx+1, pat.String(), trimmed)
				}
			}
			if strings.Contains(trimmed, "inherit_errexit") {
				if trimmed != "shopt -s inherit_errexit" {
					return fmt.Errorf("%s:%d uses unexpected inherit_errexit form: %s", rel, idx+1, trimmed)
				}
				if idx == 0 || idx+1 >= len(lines) ||
					strings.TrimSpace(lines[idx-1]) != wantBash44InheritGuard ||
					strings.TrimSpace(lines[idx+1]) != "fi" {
					return fmt.Errorf("%s:%d enables inherit_errexit without strict BASH_VERSINFO >= 4.4 guard", rel, idx+1)
				}
			}
		}
		for _, prog := range extractAwkPrograms(text) {
			if err := checkAwkProgramPosixPortability(rel, prog); err != nil {
				return err
			}
		}
	}
	return nil
}

// These protections must run on every successful release. Restrict conditions
// to the default or an explicit success() rather than guessing at expressions.
func unconditionalReleaseStep(condition any) bool {
	return condition == nil || condition == "success()" || condition == "${{ success() }}"
}

func checkSupplyChainBundle(b supplyChainBundle) (supplyChainStep, error) {
	wf := b.wf
	scripts := b.scripts
	if err := checkReleaseScriptsBash32Compatibility(scripts); err != nil {
		return supplyChainStep{}, err
	}
	if !strings.Contains(wf.Concurrency.Group, "inputs.tag || github.ref_name") {
		return supplyChainStep{}, fmt.Errorf("concurrency.group = %q, want tag/ref grouping", wf.Concurrency.Group)
	}
	if wf.Concurrency.CancelInProgress != false {
		return supplyChainStep{}, fmt.Errorf("concurrency.cancel-in-progress = %v, want false", wf.Concurrency.CancelInProgress)
	}
	if wf.Concurrency.Queue != "max" {
		return supplyChainStep{}, fmt.Errorf("concurrency.queue = %q, want max so retries cannot displace forced resubmissions", wf.Concurrency.Queue)
	}

	// Preflight runs unconditionally before any container or archive publish.
	if !unconditionalReleaseStep(wf.Jobs.Preflight.If) {
		return supplyChainStep{}, fmt.Errorf("preflight job has conditional gate: %v", wf.Jobs.Preflight.If)
	}
	if wf.Jobs.Preflight.Permissions["contents"] != "read" ||
		wf.Jobs.Preflight.Permissions["id-token"] != "write" ||
		wf.Jobs.Preflight.Permissions["packages"] != "read" ||
		wf.Jobs.Preflight.Permissions["attestations"] != "read" {
		return supplyChainStep{}, fmt.Errorf("preflight permissions = %v, want contents:read, id-token:write, packages:read, attestations:read", wf.Jobs.Preflight.Permissions)
	}
	if len(wf.Jobs.Preflight.Permissions) != 4 {
		return supplyChainStep{}, fmt.Errorf("preflight permissions = %v, want strictly {contents: read, id-token: write, packages: read, attestations: read}", wf.Jobs.Preflight.Permissions)
	}
	preflightPos := map[string]int{}
	for i, step := range wf.Jobs.Preflight.Steps {
		if len(step.Run) > maxWorkflowRunStepChars {
			return supplyChainStep{}, fmt.Errorf("preflight %s run step length %d exceeds %d", step.Name, len(step.Run), maxWorkflowRunStepChars)
		}
		if strings.Contains(step.Run, "${{") {
			return supplyChainStep{}, fmt.Errorf("preflight %s interpolates an expression directly into shell", step.Name)
		}
		key := ""
		switch {
		case step.Uses == checkoutActionV7:
			key = "checkout"
			if step.With["persist-credentials"] != false {
				return supplyChainStep{}, fmt.Errorf("preflight checkout must set persist-credentials: false")
			}
			if step.With["fetch-depth"] != 0 {
				return supplyChainStep{}, fmt.Errorf("preflight checkout must set fetch-depth: 0, got %v", step.With["fetch-depth"])
			}
		case step.ID == "verify_ref", step.ID == "check_submission":
			key = step.ID
		case step.Uses == gcpAuthV3 && step.With["workload_identity_provider"] == exitGateWIFProvider:
			key = "auth"
		case step.Uses == gcpSetupGcloudV3:
			key = "gcloud"
		case step.Uses == setupBuildxV4:
			key = "setup_buildx"
		case step.Uses == dockerLoginV4 && step.With["registry"] == "ghcr.io":
			key = "ghcr_login"
		case step.Uses == cosignInstallerV4 && step.With["cosign-release"] == "v2.4.3":
			key = "cosign"
		}
		if key == "" {
			continue
		}
		if !unconditionalReleaseStep(step.If) {
			return supplyChainStep{}, fmt.Errorf("preflight %s has conditional protection: %v", key, step.If)
		}
		if _, exists := preflightPos[key]; exists {
			return supplyChainStep{}, fmt.Errorf("duplicate preflight protection %s", key)
		}
		preflightPos[key] = i
		switch key {
		case "verify_ref":
			if step.Shell != "bash" {
				return supplyChainStep{}, fmt.Errorf("preflight verify_ref requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"GITHUB_REF_FULL", "${{ github.ref }}"},
				{"FORCE_RESUBMIT", "${{ inputs.force_resubmit || false }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return supplyChainStep{}, fmt.Errorf("preflight verify_ref env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
		case "check_submission":
			if step.Shell != "bash" {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"RUN_ID", "${{ github.run_id }}"},
				{"FORCE_RESUBMIT", "${{ inputs.force_resubmit || false }}"},
				{"GHCR_ACTOR", "${{ github.actor }}"},
				{"GHCR_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GITHUB_REPOSITORY", "${{ github.repository }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return supplyChainStep{}, fmt.Errorf("preflight check_submission env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			script, err := effectiveReleaseScript(step, releasePreflightScriptPath, scripts)
			if err != nil {
				return supplyChainStep{}, err
			}
			if strings.Contains(script, "--certificate-identity-regexp") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(script, "${RELEASE_COSIGN_IDENTITY_BASE}${") || !strings.Contains(script, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission missing exact @refs/tags/ certificate identity")
			}
			if !strings.Contains(script, "gh attestation verify") ||
				!strings.Contains(script, "--bundle-from-oci") ||
				!strings.Contains(script, "https://slsa.dev/provenance/v1") ||
				!strings.Contains(script, `--source-digest "${commit_sha}"`) {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission missing gh attestation verify --bundle-from-oci --predicate-type https://slsa.dev/provenance/v1 --source-digest")
			}
			if !strings.Contains(script, `"${RELEASE_GHCR_IMAGE}@${existing_digest}" >&2`) {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must redirect cosign verify stdout to stderr in inspect_ghcr_container_provenance")
			}
			if !strings.Contains(scripts[releasePreflightScriptPath], `verify_changelog_attestation "${verify_dir}/EXIT_GATE_CHANGELOG" "${GITHUB_REPOSITORY}" "${RELEASE_TAG}" "${COMMIT_SHA}"`) ||
				!strings.Contains(scripts[releaseCommonScriptPath], `gh attestation verify "${changelog_path}"`) ||
				!strings.Contains(scripts[releaseCommonScriptPath], `--format json`) ||
				!strings.Contains(scripts[releaseCommonScriptPath], `.verificationResult.statement.subject`) ||
				!strings.Contains(scripts[releaseCommonScriptPath], `((.name // "") == "EXIT_GATE_CHANGELOG"`) {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission missing subject-bound EXIT_GATE_CHANGELOG SLSA attestation verification")
			}
			if !strings.Contains(script, `| .version`+"\n"+`        | select(type == "string")`) ||
				!strings.Contains(script, `expected a single JSON document in Exit Gate manifest`) ||
				!strings.Contains(script, `expected_staging_ver="t-${tag_hash}-${commit_short}"`) ||
				!strings.Contains(script, `select(. == $expected_ver)`) {
				return supplyChainStep{}, fmt.Errorf("validate_existing_manifest must slurp single JSON doc, require string .version, and bind t-${tag_hash}-${commit_short}")
			}
			if !strings.Contains(script, `indeterminate download mismatch." >&2`+"\n"+`    return 2`) {
				return supplyChainStep{}, fmt.Errorf("download_ar_file_verified must return indeterminate rc=2 on downloaded vs listed hash mismatch")
			}
			if !strings.Contains(script, "gcloud artifacts files download") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission missing remote checksums.txt download")
			}
			if !strings.Contains(script, "noncurrent_time") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must filter noncurrent GCS manifests")
			}
			if !strings.Contains(script, "objects describe") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must read manifest promote_eligible metadata")
			}
			if !strings.Contains(script, "/referrers/") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission missing OCI referrers check for provenance classification")
			}
			if strings.Contains(script, ".manifests // []") || !strings.Contains(script, "(.manifests | type)") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must require an explicit OCI referrers .manifests array")
			}
			scriptCodeLines := prepareReleaseScriptLines(script)
			scriptCode := strings.Join(scriptCodeLines, "\n")
			if strings.Contains(scriptCode, `tr -d '\r' < "${hdr_file}"`) ||
				strings.Contains(scriptCode, `[ -n "${final_headers}" ] && ! next_url`) ||
				!strings.Contains(scriptCode, "extract_next_referrers_url") ||
				!strings.Contains(scriptCode, "RELEASE_MAX_REFERRERS_PAGES") ||
				!strings.Contains(scriptCode, `extract_next_referrers_url "${ref_hdr_file}" "${existing_digest}" "${url}"`) ||
				!strings.Contains(scriptCode, `check_referrers_filters_applied "${ref_hdr_file}" "${existing_digest}"`) ||
				!strings.Contains(scriptCode, `extract_final_http_headers "${hdr_file}"`) ||
				!strings.Contains(scriptCode, `final_hdrs="$(extract_final_http_headers "${hdr_file}")"`) ||
				!strings.Contains(scriptCode, `final_headers="$(extract_final_http_headers "${hdr_file}")"`) ||
				!strings.Contains(scriptCode, `LC_ALL=C awk`) ||
				!strings.Contains(scriptCode, "has_disallowed_ctl($0)") ||
				!strings.Contains(scriptCode, "can_have_trailers = block_allows_trailers()") ||
				!strings.Contains(scriptCode, `set -o pipefail`) ||
				!strings.Contains(scriptCode, `od -An -v -tx1`) ||
				!strings.Contains(scriptCode, `tok == "00"`) ||
				!strings.Contains(scriptCode, `last != "0a"`) ||
				!strings.Contains(scriptCode, `parse_te_header(`) ||
				// Static source-fragment change-detection pins on bounded windowing and
				// binary-counter carry stacks (checked on non-comment executable lines so
				// comments cannot satisfy them); behavioral boundary and scaling coverage
				// lives in TestReleaseScriptsBaseline.
				!slices.Contains(scriptCodeLines, `owin = substr(fval, obase, 4096)`) ||
				strings.Contains(scriptCode, `substr(fval, pos, 1)`) ||
				strings.Contains(scriptCode, `coding = coding ch`) ||
				strings.Contains(scriptCode, `pname = pname ch`) ||
				strings.Contains(scriptCode, `pval = pval ch`) ||
				!strings.Contains(scriptCode, `fold_push(`) ||
				!strings.Contains(scriptCode, `fold_flush(`) ||
				!slices.Contains(scriptCodeLines, `fold_sz[fold_top] = 1`) ||
				!slices.Contains(scriptCodeLines, `delete fold_stk[fold_top]`) ||
				strings.Contains(scriptCode, `lines[n] = lines[n] cont`) ||
				!strings.Contains(scriptCode, `qbuf_push(`) ||
				!strings.Contains(scriptCode, `qbuf_flush(`) ||
				!slices.Contains(scriptCodeLines, `sz[st["top"]] = 1`) ||
				!slices.Contains(scriptCodeLines, `delete stk[st["top"]]`) ||
				!slices.Contains(scriptCodeLines, `owin = substr(s, obase, 4096)`) ||
				!slices.Contains(scriptCodeLines, `qbuf_push(stk, sz, st, win)`) ||
				!slices.Contains(scriptCodeLines, `qbuf_push(stk, sz, st, sprintf("%c", code))`) ||
				strings.Contains(scriptCode, `res = res `) ||
				!slices.Contains(scriptCodeLines, `owin = substr(raw_p, obase, 4096)`) ||
				!slices.Contains(scriptCodeLines, `owin = substr(line, obase, 4096)`) ||
				!slices.Contains(scriptCodeLines, `qbuf_push(ustk, usz, ust, tok_chunk)`) ||
				!slices.Contains(scriptCodeLines, `qbuf_push(qstk, qsz, qst, substr(win, 1, RLENGTH))`) ||
				strings.Contains(scriptCode, `pval = pval vc`) ||
				!strings.Contains(scriptCode, `coding == "chunked" || coding == "gzip" || coding == "deflate" || coding == "compress" || coding == "x-gzip" || coding == "x-compress"`) ||
				!strings.Contains(scriptCode, `if (has_param) {`) ||
				!strings.Contains(scriptCode, `te_state["chunked_count"] == 1`) ||
				!strings.Contains(scriptCode, `(saw_status && (in_hdr || last_status < 200))`) ||
				!strings.Contains(scriptCode, `sub(/\r$/, "")`) ||
				!strings.Contains(scriptCode, `index($0, "\r")`) ||
				!strings.Contains(scriptCode, `last_status < 200`) ||
				!strings.Contains(scriptCode, `tname == "link" || tname == "oci-filters-applied" || tname == "docker-content-digest"`) ||
				!strings.Contains(scriptCode, `if [ ! -r "${hdr_file}" ]; then`) ||
				!strings.Contains(scriptCode, "expect_status = 1") ||
				!strings.Contains(scriptCode, "expect_status &&") ||
				!strings.Contains(scriptCode, "saw_block_end") ||
				!strings.Contains(scriptCode, "first_seg") ||
				!strings.Contains(scriptCode, `index(first_seg, ":")`) ||
				!strings.Contains(scriptCode, `tolower($0) ~ /^docker-content-digest:/`) ||
				!strings.Contains(scriptCode, "valid_rfc3986_raw_path") ||
				!strings.Contains(scriptCode, "resolve_rfc3986_target") ||
				!strings.Contains(scriptCode, `\\A(sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})\\z`) ||
				!strings.Contains(scriptCode, "artifact_type_signature") ||
				!strings.Contains(scriptCode, "clause_rel_count != 1") ||
				!strings.Contains(scriptCode, "jq -ser") ||
				!strings.Contains(scriptCode, "valid_descriptor") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must enforce strict OCI referrers final-header isolation, digest header parsing, filters-applied, SHA digest allowlist, RFC 3986 raw path & Link resolution, and artifactType pagination checks")
			}
			if strings.Contains(script, ".name // empty") || !strings.Contains(script, "malformed GCS listing entry") {
				return supplyChainStep{}, fmt.Errorf("list_tag_commit_manifests must require a non-empty string .name on every GCS listing entry")
			}
			if strings.Contains(scripts[releasePreflightScriptPath], "validate_existing_manifest") && strings.Contains(scripts[releasePreflightScriptPath], "|| true") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must not discard manifest validation errors with || true")
			}
		}
	}
	for _, key := range []string{"checkout", "verify_ref", "auth", "gcloud", "setup_buildx", "ghcr_login", "cosign", "check_submission"} {
		if _, ok := preflightPos[key]; !ok {
			return supplyChainStep{}, fmt.Errorf("missing preflight protection %s", key)
		}
	}
	for _, pair := range [][2]string{
		{"checkout", "verify_ref"}, {"verify_ref", "check_submission"},
		{"auth", "gcloud"}, {"gcloud", "check_submission"},
		{"setup_buildx", "ghcr_login"}, {"ghcr_login", "check_submission"},
		{"cosign", "check_submission"},
	} {
		if preflightPos[pair[0]] >= preflightPos[pair[1]] {
			return supplyChainStep{}, fmt.Errorf("preflight %s must precede %s", pair[0], pair[1])
		}
	}
	for _, outKey := range []string{
		"action", "prior_staging_version", "manifest_uri", "staging_version",
		"submission_status", "container_exists", "container_provenance_verified",
		"container_digest", "ar_staged_partial", "promote_eligible",
	} {
		want := "${{ steps.check_submission.outputs." + outKey + " }}"
		if wf.Jobs.Preflight.Outputs[outKey] != want {
			return supplyChainStep{}, fmt.Errorf("preflight output %s = %q, want %q", outKey, wf.Jobs.Preflight.Outputs[outKey], want)
		}
	}

	// Release requires preflight action == 'full_release' so retries, staged
	// manifest retries, and forced resubmissions never rebuild unnecessarily.
	if !slices.Equal(wf.Jobs.Release.Needs, []string{"preflight"}) {
		return supplyChainStep{}, fmt.Errorf("release job needs = %v, want [preflight]", wf.Jobs.Release.Needs)
	}
	const wantReleaseIf = "${{ needs.preflight.outputs.action == 'full_release' }}"
	if wf.Jobs.Release.If != wantReleaseIf {
		return supplyChainStep{}, fmt.Errorf("release job if = %v, want %q", wf.Jobs.Release.If, wantReleaseIf)
	}
	if wf.Jobs.Release.Outputs["digest"] != "${{ steps.manifest_digest.outputs.digest }}" {
		return supplyChainStep{}, fmt.Errorf("release output digest = %q, want ${{ steps.manifest_digest.outputs.digest }}", wf.Jobs.Release.Outputs["digest"])
	}
	if wf.Jobs.Release.Outputs["staging_version"] != "${{ steps.stage_exit_gate_assets.outputs.staging_version }}" {
		return supplyChainStep{}, fmt.Errorf("release output staging_version = %q, want ${{ steps.stage_exit_gate_assets.outputs.staging_version }}", wf.Jobs.Release.Outputs["staging_version"])
	}

	positions := map[string]int{}
	var sbom supplyChainStep
	for i, step := range wf.Jobs.Release.Steps {
		if len(step.Run) > maxWorkflowRunStepChars {
			return sbom, fmt.Errorf("%s run step length %d exceeds %d", step.Name, len(step.Run), maxWorkflowRunStepChars)
		}
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("%s interpolates an expression directly into shell", step.Name)
		}
		if step.ID == "promote_latest" || step.ID == "exit_gate_submit" {
			return sbom, fmt.Errorf("jobs.release must not run %s inline (moved to dedicated job)", step.ID)
		}
		key := ""
		switch {
		case step.ID == "release_dedup_guard", step.ID == "reconcile_container", step.ID == "build", step.ID == "manifest_digest", step.ID == "verify_container_provenance", step.ID == "changelog_file", step.ID == "container_sbom", step.ID == "stage_exit_gate_assets":
			key = step.ID
		case step.Name == "Verify signed container manifest":
			key = "verify_container_sig"
		case step.Uses == setupBuildxV4:
			key = "setup_buildx"
		case step.Uses == dockerLoginV4 && step.With["registry"] == "ghcr.io":
			key = "ghcr_login"
		case step.Uses == gcpAuthV3 && step.With["workload_identity_provider"] == exitGateWIFProvider:
			key = "exit_gate_auth"
		case step.Uses == gcpSetupGcloudV3:
			key = "exit_gate_gcloud"
		case step.Uses == attestBuildProvenanceV4:
			switch {
			case step.With["subject-name"] == "ghcr.io/googlecloudplatform/bq-otel-collector" &&
				step.With["subject-digest"] == "${{ steps.manifest_digest.outputs.digest }}" &&
				(step.With["push-to-registry"] == true || step.With["push-to-registry"] == "true"):
				key = "container_provenance"
			case step.With["subject-path"] == "dist/checksums.txt":
				key = "binary_provenance"
			case step.ID == "changelog_provenance" && step.With["subject-path"] == "${{ steps.changelog_file.outputs.path }}":
				key = "changelog_provenance"
			}
		case step.Uses == cosignInstallerV4 && step.With["cosign-release"] == "v2.4.3":
			key = "cosign"
		case step.Uses == downloadSyftV0:
			key = "syft"
		}
		if key == "" {
			continue
		}
		switch key {
		case "container_provenance":
			const wantCond = "${{ steps.reconcile_container.outputs.container_exists != 'true' }}"
			if step.If != wantCond {
				return sbom, fmt.Errorf("container_provenance if = %v, want strictly %q (never attest reused image digests)", step.If, wantCond)
			}
		case "changelog_provenance":
			const wantCond = "${{ steps.changelog_file.outputs.exists == 'true' }}"
			if step.If != wantCond {
				return sbom, fmt.Errorf("changelog_provenance if = %v, want %q", step.If, wantCond)
			}
		default:
			if !unconditionalReleaseStep(step.If) {
				return sbom, fmt.Errorf("%s has conditional protection: %v", key, step.If)
			}
		}
		if _, exists := positions[key]; exists {
			return sbom, fmt.Errorf("duplicate protection %s", key)
		}
		positions[key] = i
		switch key {
		case "release_dedup_guard":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("release_dedup_guard requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"FORCE_RESUBMIT", "${{ inputs.force_resubmit || false }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("release_dedup_guard env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			if !strings.Contains(step.Run, "noncurrent_time") ||
				strings.Contains(step.Run, ".name // empty") ||
				!strings.Contains(step.Run, "malformed GCS listing entry") {
				return sbom, fmt.Errorf("release_dedup_guard must filter noncurrent GCS manifests and require a non-empty string .name on every entry")
			}
		case "reconcile_container":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("reconcile_container requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"GHCR_ACTOR", "${{ github.actor }}"},
				{"GHCR_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GITHUB_REPOSITORY", "${{ github.repository }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("reconcile_container env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			script, err := effectiveReleaseScript(step, releaseReconcileScriptPath, scripts)
			if err != nil {
				return sbom, err
			}
			if strings.Contains(script, "container_needs_attestation") {
				return sbom, fmt.Errorf("reconcile_container must not emit container_needs_attestation for reused images")
			}
			if strings.Contains(script, "--certificate-identity-regexp") {
				return sbom, fmt.Errorf("reconcile_container must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(script, "${RELEASE_COSIGN_IDENTITY_BASE}${") || !strings.Contains(script, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/") {
				return sbom, fmt.Errorf("reconcile_container missing exact @refs/tags/ certificate identity")
			}
			if !strings.Contains(script, "gh attestation verify") ||
				!strings.Contains(script, "--bundle-from-oci") ||
				!strings.Contains(script, "https://slsa.dev/provenance/v1") {
				return sbom, fmt.Errorf("reconcile_container missing gh attestation verify --bundle-from-oci --predicate-type https://slsa.dev/provenance/v1")
			}
			if !strings.Contains(script, "/referrers/") || strings.Contains(script, ".manifests // []") || !strings.Contains(script, "extract_next_referrers_url") {
				return sbom, fmt.Errorf("reconcile_container missing strict paginated OCI referrers check for provenance classification")
			}
		case "build":
			const wantTag = "${{ inputs.tag || github.ref_name }}"
			if step.Env["GORELEASER_CURRENT_TAG"] != wantTag {
				return sbom, fmt.Errorf("build env GORELEASER_CURRENT_TAG = %q, want %q", step.Env["GORELEASER_CURRENT_TAG"], wantTag)
			}
			const wantArgs = "${{ steps.reconcile_container.outputs.container_exists == 'true' && 'release --clean --skip=docker' || 'release --clean' }}"
			if step.With["args"] != wantArgs {
				return sbom, fmt.Errorf("build with.args = %v, want %q", step.With["args"], wantArgs)
			}
		case "manifest_digest":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("manifest_digest requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"RECONCILED_DIGEST", "${{ steps.reconcile_container.outputs.digest }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("manifest_digest env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			digestScript, err := effectiveReleaseScript(step, releaseResolveManifestDigestScriptPath, scripts)
			if err != nil {
				return sbom, err
			}
			if !strings.Contains(digestScript, "dist/artifacts.json") ||
				!strings.Contains(digestScript, `"Docker Manifest"`) ||
				!strings.Contains(digestScript, ".extra.Digest") ||
				!strings.Contains(digestScript, `tag_digest != pushed_digest`) && !strings.Contains(digestScript, `"${tag_digest}" != "${pushed_digest}"`) {
				return sbom, fmt.Errorf("manifest_digest must read pushed Docker Manifest digest from dist/artifacts.json and require exact tag agreement")
			}
		case "verify_container_sig":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("verify_container_sig requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"DIGEST", "${{ steps.manifest_digest.outputs.digest }}"},
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("verify_container_sig env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			if strings.Contains(step.Run, "--certificate-identity-regexp") {
				return sbom, fmt.Errorf("verify_container_sig must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(step.Run, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}") {
				return sbom, fmt.Errorf("verify_container_sig missing exact @refs/tags/${RELEASE_TAG} certificate identity")
			}
		case "verify_container_provenance":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("verify_container_provenance requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"DIGEST", "${{ steps.manifest_digest.outputs.digest }}"},
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"GITHUB_REPOSITORY", "${{ github.repository }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("verify_container_provenance env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			if !strings.Contains(step.Run, "gh attestation verify") ||
				!strings.Contains(step.Run, "--bundle-from-oci") ||
				!strings.Contains(step.Run, `--predicate-type "https://slsa.dev/provenance/v1"`) ||
				!strings.Contains(step.Run, "--source-ref \"refs/tags/${RELEASE_TAG}\"") ||
				!strings.Contains(step.Run, "--source-digest \"${COMMIT_SHA}\"") {
				return sbom, fmt.Errorf("verify_container_provenance missing gh attestation verify --bundle-from-oci --predicate-type --source-ref --source-digest check")
			}
		case "changelog_file":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("changelog_file requires explicit bash shell")
			}
			if !strings.Contains(step.Run, "dist/CHANGELOG.md") ||
				!strings.Contains(step.Run, "EXIT_GATE_CHANGELOG") ||
				!strings.Contains(step.Run, `path=${changelog_subject}`) {
				return sbom, fmt.Errorf("changelog_file must copy dist/CHANGELOG.md to EXIT_GATE_CHANGELOG and output path")
			}
		case "container_sbom":
			sbom = step
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("SBOM script requires explicit bash with pipefail")
			}
			if step.Env["DIGEST"] != "${{ steps.manifest_digest.outputs.digest }}" {
				return sbom, fmt.Errorf("SBOM digest must come from published manifest")
			}
		case "stage_exit_gate_assets":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("stage_exit_gate_assets requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("stage_exit_gate_assets env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			script, err := effectiveReleaseScript(step, releaseStageScriptPath, scripts)
			if err != nil {
				return sbom, err
			}
			if strings.Contains(script, "--certificate-identity-regexp") {
				return sbom, fmt.Errorf("stage_exit_gate_assets must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(script, "${RELEASE_COSIGN_IDENTITY_BASE}${") || !strings.Contains(script, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/") {
				return sbom, fmt.Errorf("stage_exit_gate_assets missing exact @refs/tags/ certificate identity")
			}
			if !strings.Contains(script, "gcloud artifacts files download") {
				return sbom, fmt.Errorf("stage_exit_gate_assets missing remote checksums.txt download")
			}
		}
	}
	for _, key := range []string{
		"exit_gate_auth", "exit_gate_gcloud", "release_dedup_guard",
		"setup_buildx", "ghcr_login", "cosign", "syft",
		"reconcile_container", "build", "manifest_digest",
		"verify_container_sig", "container_provenance", "verify_container_provenance",
		"binary_provenance", "changelog_file", "changelog_provenance",
		"container_sbom", "stage_exit_gate_assets",
	} {
		if _, ok := positions[key]; !ok {
			return sbom, fmt.Errorf("missing release protection %s", key)
		}
	}
	for _, pair := range [][2]string{
		{"exit_gate_auth", "exit_gate_gcloud"},
		{"exit_gate_gcloud", "release_dedup_guard"},
		{"release_dedup_guard", "ghcr_login"},
		{"release_dedup_guard", "reconcile_container"},
		{"release_dedup_guard", "build"},
		{"setup_buildx", "ghcr_login"},
		{"setup_buildx", "reconcile_container"},
		{"ghcr_login", "reconcile_container"},
		{"cosign", "reconcile_container"},
		{"reconcile_container", "build"},
		{"cosign", "build"}, {"syft", "build"}, {"build", "manifest_digest"},
		{"build", "changelog_file"},
		{"changelog_file", "changelog_provenance"},
		{"changelog_provenance", "stage_exit_gate_assets"},
		{"manifest_digest", "verify_container_sig"},
		{"manifest_digest", "container_provenance"},
		{"manifest_digest", "verify_container_provenance"},
		{"manifest_digest", "binary_provenance"},
		{"verify_container_sig", "container_sbom"},
		{"container_provenance", "container_sbom"},
		{"verify_container_provenance", "container_sbom"},
		{"binary_provenance", "container_sbom"},
		{"container_sbom", "stage_exit_gate_assets"},
	} {
		if positions[pair[0]] >= positions[pair[1]] {
			return sbom, fmt.Errorf("%s must precede %s", pair[0], pair[1])
		}
	}

	// submit-exit-gate handles initial submission, retries after failed manifest
	// writes (submit_staged), and forced resubmissions (resubmit_existing).
	if !slices.Equal(wf.Jobs.SubmitExitGate.Needs, []string{"preflight", "release"}) {
		return sbom, fmt.Errorf("submit-exit-gate needs = %v, want [preflight release]", wf.Jobs.SubmitExitGate.Needs)
	}
	const wantSubmitIf = "always() && !cancelled() && needs.preflight.result == 'success' && ((needs.preflight.outputs.action == 'full_release' && needs.release.result == 'success') || needs.preflight.outputs.action == 'submit_staged' || needs.preflight.outputs.action == 'resubmit_existing')"
	if wf.Jobs.SubmitExitGate.If != wantSubmitIf {
		return sbom, fmt.Errorf("submit-exit-gate if = %v, want %q", wf.Jobs.SubmitExitGate.If, wantSubmitIf)
	}
	if len(wf.Jobs.SubmitExitGate.Permissions) != 3 ||
		wf.Jobs.SubmitExitGate.Permissions["contents"] != "read" ||
		wf.Jobs.SubmitExitGate.Permissions["id-token"] != "write" ||
		wf.Jobs.SubmitExitGate.Permissions["attestations"] != "read" {
		return sbom, fmt.Errorf("submit-exit-gate permissions = %v, want strictly {contents: read, id-token: write, attestations: read}", wf.Jobs.SubmitExitGate.Permissions)
	}
	for _, outKey := range []string{"staging_version", "manifest_uri", "submission_status"} {
		want := "${{ steps.exit_gate_submit.outputs." + outKey + " }}"
		if wf.Jobs.SubmitExitGate.Outputs[outKey] != want {
			return sbom, fmt.Errorf("submit-exit-gate output %s = %q, want %q", outKey, wf.Jobs.SubmitExitGate.Outputs[outKey], want)
		}
	}
	submitPos := map[string]int{}
	for i, step := range wf.Jobs.SubmitExitGate.Steps {
		if len(step.Run) > maxWorkflowRunStepChars {
			return sbom, fmt.Errorf("submit-exit-gate %s run step length %d exceeds %d", step.Name, len(step.Run), maxWorkflowRunStepChars)
		}
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("submit-exit-gate %s interpolates an expression directly into shell", step.Name)
		}
		if strings.Contains(step.Uses, "goreleaser") || strings.Contains(step.Uses, "docker/") || strings.Contains(step.Uses, "attest-build-provenance") {
			return sbom, fmt.Errorf("submit-exit-gate must not invoke build/container/attestation actions (%s)", step.Uses)
		}
		key := ""
		switch {
		case step.Uses == checkoutActionV7:
			key = "checkout"
			if step.With["persist-credentials"] != false {
				return sbom, fmt.Errorf("submit-exit-gate checkout must set persist-credentials: false")
			}
		case step.Uses == gcpAuthV3 && step.With["workload_identity_provider"] == exitGateWIFProvider:
			key = "auth"
		case step.Uses == gcpSetupGcloudV3:
			key = "gcloud"
		case step.Uses == cosignInstallerV4 && step.With["cosign-release"] == "v2.4.3":
			key = "cosign"
		case step.ID == "exit_gate_submit":
			key = step.ID
		}
		if key == "" {
			continue
		}
		if !unconditionalReleaseStep(step.If) {
			return sbom, fmt.Errorf("submit-exit-gate %s has conditional protection: %v", key, step.If)
		}
		if _, exists := submitPos[key]; exists {
			return sbom, fmt.Errorf("duplicate submit-exit-gate protection %s", key)
		}
		submitPos[key] = i
		if key == "exit_gate_submit" {
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("exit_gate_submit requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"RUN_ID", "${{ github.run_id }}"},
				{"FORCE_RESUBMIT", "${{ inputs.force_resubmit || false }}"},
				{"ACTION", "${{ needs.preflight.outputs.action }}"},
				{"RELEASE_STAGING_VERSION", "${{ needs.release.outputs.staging_version }}"},
				{"PREFLIGHT_STAGING_VERSION", "${{ needs.preflight.outputs.staging_version }}"},
				{"PRIOR_STAGING_VERSION", "${{ needs.preflight.outputs.prior_staging_version }}"},
				{"GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GITHUB_REPOSITORY", "${{ github.repository }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("exit_gate_submit env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			script, err := effectiveReleaseScript(step, releaseSubmitScriptPath, scripts)
			if err != nil {
				return sbom, err
			}
			if strings.Contains(script, "--certificate-identity-regexp") {
				return sbom, fmt.Errorf("exit_gate_submit must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(script, "${RELEASE_COSIGN_IDENTITY_BASE}${") || !strings.Contains(script, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/") {
				return sbom, fmt.Errorf("exit_gate_submit missing exact @refs/tags/ certificate identity")
			}
			if !strings.Contains(script, "gcloud artifacts files download") {
				return sbom, fmt.Errorf("exit_gate_submit missing remote checksums.txt download")
			}
			if !strings.Contains(script, "noncurrent_time") {
				return sbom, fmt.Errorf("exit_gate_submit must filter noncurrent GCS manifests")
			}
			if !strings.Contains(script, "--custom-metadata=") {
				return sbom, fmt.Errorf("exit_gate_submit must persist promote_eligible custom metadata")
			}
			submitSrc := scripts[releaseSubmitScriptPath]
			tagCheckCall := `verify_origin_release_tag "origin" "${RELEASE_TAG}" "${COMMIT_SHA}"`
			firstTagIdx := strings.Index(submitSrc, tagCheckCall)
			finalTagIdx := strings.LastIndex(submitSrc, tagCheckCall)
			cosignIdx := strings.Index(submitSrc, "cosign verify-blob")
			changelogIdx := strings.Index(submitSrc, `verify_changelog_attestation "${verify_dir}/EXIT_GATE_CHANGELOG" "${GITHUB_REPOSITORY}" "${RELEASE_TAG}" "${COMMIT_SHA}"`)
			cpIdx := strings.Index(submitSrc, "gcloud storage cp --if-generation-match=0")
			if firstTagIdx < 0 || cosignIdx < 0 || changelogIdx < 0 || finalTagIdx < 0 || cpIdx < 0 ||
				firstTagIdx >= cosignIdx || cosignIdx >= changelogIdx || changelogIdx >= finalTagIdx || finalTagIdx >= cpIdx ||
				!strings.Contains(script, "git ls-remote --tags") {
				return sbom, fmt.Errorf("exit_gate_submit must run verify_origin_release_tag initially and again after cosign/changelog verification before create-only gcloud storage cp")
			}
			if !strings.Contains(submitSrc, `required_files+=("EXIT_GATE_CHANGELOG")`) ||
				!strings.Contains(submitSrc, `has_changelog="$(`) ||
				strings.Contains(submitSrc, `if printf '%s' "${ar_entries}" | jq -e 'any(.[]; .fname == "EXIT_GATE_CHANGELOG")'`) {
				return sbom, fmt.Errorf("exit_gate_submit must require EXIT_GATE_CHANGELOG on submit_staged and use checked changelog presence lookup")
			}
			if !strings.Contains(submitSrc, `expected_staging_ver="t-${tag_hash}-${commit_short}"`) ||
				!strings.Contains(submitSrc, `[ "${STAGING_VERSION}" != "${expected_staging_ver}" ]`) {
				return sbom, fmt.Errorf("exit_gate_submit must bind STAGING_VERSION to t-${tag_hash}-${commit_short}")
			}
			if !strings.Contains(script, `gh attestation verify "${changelog_path}"`) ||
				!strings.Contains(script, `--format json`) {
				return sbom, fmt.Errorf("exit_gate_submit missing subject-bound EXIT_GATE_CHANGELOG SLSA attestation verification")
			}
			if strings.Contains(submitSrc, "validate_existing_manifest") && strings.Contains(submitSrc, "|| true") {
				return sbom, fmt.Errorf("exit_gate_submit must not discard manifest validation errors with || true")
			}
		}
	}
	for _, key := range []string{"checkout", "auth", "gcloud", "cosign", "exit_gate_submit"} {
		if _, ok := submitPos[key]; !ok {
			return sbom, fmt.Errorf("missing submit-exit-gate step %s", key)
		}
	}
	if submitPos["checkout"] >= submitPos["exit_gate_submit"] || submitPos["auth"] >= submitPos["gcloud"] || submitPos["gcloud"] >= submitPos["exit_gate_submit"] || submitPos["cosign"] >= submitPos["exit_gate_submit"] {
		return sbom, fmt.Errorf("submit-exit-gate steps out of order: %v", submitPos)
	}

	// promote-latest acquires a single image-wide concurrency lock, queries origin
	// remote tags directly, and promotes :latest, :latest-amd64, and :latest-arm64
	// only when promote_eligible is true and RELEASE_TAG is still the highest canonical stable tag.
	if wf.Jobs.PromoteLatest.Concurrency.Group != "ghcr-promote-latest" {
		return sbom, fmt.Errorf("promote-latest concurrency.group = %q, want ghcr-promote-latest", wf.Jobs.PromoteLatest.Concurrency.Group)
	}
	if wf.Jobs.PromoteLatest.Concurrency.CancelInProgress != false {
		return sbom, fmt.Errorf("promote-latest concurrency.cancel-in-progress = %v, want false", wf.Jobs.PromoteLatest.Concurrency.CancelInProgress)
	}
	if wf.Jobs.PromoteLatest.Concurrency.Queue != "max" {
		return sbom, fmt.Errorf("promote-latest concurrency.queue = %q, want max", wf.Jobs.PromoteLatest.Concurrency.Queue)
	}
	if !slices.Equal(wf.Jobs.PromoteLatest.Needs, []string{"preflight", "release", "submit-exit-gate"}) {
		return sbom, fmt.Errorf("promote-latest needs = %v, want [preflight release submit-exit-gate]", wf.Jobs.PromoteLatest.Needs)
	}
	const wantPromoteIf = "always() && !cancelled() && needs.preflight.result == 'success' && needs.preflight.outputs.promote_eligible == 'true' && ((needs.preflight.outputs.action == 'full_release' && needs.release.result == 'success' && needs.submit-exit-gate.result == 'success') || (needs.preflight.outputs.action == 'submit_staged' && needs.submit-exit-gate.result == 'success') || needs.preflight.outputs.action == 'skip_duplicate')"
	if wf.Jobs.PromoteLatest.If != wantPromoteIf {
		return sbom, fmt.Errorf("promote-latest if = %v, want %q", wf.Jobs.PromoteLatest.If, wantPromoteIf)
	}
	if len(wf.Jobs.PromoteLatest.Permissions) != 3 ||
		wf.Jobs.PromoteLatest.Permissions["contents"] != "read" ||
		wf.Jobs.PromoteLatest.Permissions["packages"] != "write" ||
		wf.Jobs.PromoteLatest.Permissions["attestations"] != "read" {
		return sbom, fmt.Errorf("promote-latest permissions = %v, want strictly {contents: read, packages: write, attestations: read}", wf.Jobs.PromoteLatest.Permissions)
	}
	promotePos := map[string]int{}
	for i, step := range wf.Jobs.PromoteLatest.Steps {
		if len(step.Run) > maxWorkflowRunStepChars {
			return sbom, fmt.Errorf("promote-latest %s run step length %d exceeds %d", step.Name, len(step.Run), maxWorkflowRunStepChars)
		}
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("promote-latest %s interpolates an expression directly into shell", step.Name)
		}
		key := ""
		switch {
		case step.Uses == checkoutActionV7:
			key = "checkout"
			if step.With["persist-credentials"] != false {
				return sbom, fmt.Errorf("promote-latest checkout must set persist-credentials: false")
			}
			if step.With["fetch-depth"] != 0 {
				return sbom, fmt.Errorf("promote-latest checkout must set fetch-depth: 0, got %v", step.With["fetch-depth"])
			}
		case step.Uses == setupBuildxV4:
			key = "setup_buildx"
		case step.Uses == dockerLoginV4 && step.With["registry"] == "ghcr.io":
			key = "ghcr_login"
		case step.Uses == cosignInstallerV4 && step.With["cosign-release"] == "v2.4.3":
			key = "cosign"
		case step.ID == "promote_latest":
			key = step.ID
		}
		if key == "" {
			continue
		}
		if !unconditionalReleaseStep(step.If) {
			return sbom, fmt.Errorf("promote-latest %s has conditional protection: %v", key, step.If)
		}
		if _, exists := promotePos[key]; exists {
			return sbom, fmt.Errorf("duplicate promote-latest protection %s", key)
		}
		promotePos[key] = i
		if key == "promote_latest" {
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("promote_latest requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
				{"DIGEST", "${{ needs.release.outputs.digest || needs.preflight.outputs.container_digest }}"},
				{"PROMOTE_ELIGIBLE", "${{ needs.preflight.outputs.promote_eligible }}"},
				{"GHCR_ACTOR", "${{ github.actor }}"},
				{"GHCR_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GH_TOKEN", "${{ secrets.GITHUB_TOKEN }}"},
				{"GITHUB_REPOSITORY", "${{ github.repository }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("promote_latest env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
			script, err := effectiveReleaseScript(step, releasePromoteScriptPath, scripts)
			if err != nil {
				return sbom, err
			}
			if strings.Contains(script, "--certificate-identity-regexp") {
				return sbom, fmt.Errorf("promote_latest must not use wildcard --certificate-identity-regexp")
			}
			if !strings.Contains(script, "${RELEASE_COSIGN_IDENTITY_BASE}${") || !strings.Contains(script, "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/") {
				return sbom, fmt.Errorf("promote_latest missing exact @refs/tags/ certificate identity")
			}
			if !strings.Contains(script, "gh attestation verify") ||
				!strings.Contains(script, "--bundle-from-oci") ||
				!strings.Contains(script, "https://slsa.dev/provenance/v1") ||
				!strings.Contains(script, `--source-digest "${COMMIT_SHA}"`) {
				return sbom, fmt.Errorf("promote_latest missing gh attestation verify --bundle-from-oci --predicate-type https://slsa.dev/provenance/v1 --source-digest")
			}
			if !strings.Contains(script, "git ls-remote --tags origin") {
				return sbom, fmt.Errorf("promote_latest must resolve tags directly from origin via git ls-remote --tags origin")
			}
			if strings.Contains(script, "git tag -l") {
				return sbom, fmt.Errorf("promote_latest must not trust unpruned local git tag -l")
			}
		}
	}
	for _, key := range []string{"checkout", "setup_buildx", "ghcr_login", "cosign", "promote_latest"} {
		if _, ok := promotePos[key]; !ok {
			return sbom, fmt.Errorf("missing promote-latest protection %s", key)
		}
	}
	for _, pair := range [][2]string{
		{"checkout", "promote_latest"},
		{"setup_buildx", "ghcr_login"},
		{"ghcr_login", "promote_latest"},
		{"cosign", "promote_latest"},
	} {
		if promotePos[pair[0]] >= promotePos[pair[1]] {
			return sbom, fmt.Errorf("promote-latest %s must precede %s", pair[0], pair[1])
		}
	}
	return sbom, nil
}

func readSupplyChainBundle(t *testing.T) supplyChainBundle {
	t.Helper()
	var wf supplyChainWorkflow
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/workflows/release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	scripts := make(map[string]string, len(releaseScriptPaths))
	for _, p := range releaseScriptPaths {
		scripts[p] = testsupport.ReadRepoText(t, p)
	}
	return supplyChainBundle{wf: wf, scripts: scripts}
}

func TestWorkflowRunStepLengths(t *testing.T) {
	wfDir := filepath.Join(testsupport.RepoRoot(t), ".github", "workflows")
	ymlFiles, err := filepath.Glob(filepath.Join(wfDir, "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	yamlFiles, err := filepath.Glob(filepath.Join(wfDir, "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(ymlFiles)+len(yamlFiles))
	files = append(files, ymlFiles...)
	files = append(files, yamlFiles...)
	slices.Sort(files)
	if len(files) == 0 {
		t.Fatalf("no workflow files found under %s", wfDir)
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Jobs map[string]struct {
				Steps []struct {
					ID   string `yaml:"id"`
					Name string `yaml:"name"`
					Run  string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parsing %s: %v", path, err)
		}
		for jid, job := range doc.Jobs {
			for i, st := range job.Steps {
				if len(st.Run) > maxWorkflowRunStepChars {
					t.Errorf("%s job %s step[%d] (%s/%s) run length %d > %d",
						filepath.Base(path), jid, i, st.ID, st.Name, len(st.Run), maxWorkflowRunStepChars)
				}
			}
		}
	}
}

func TestReleaseScriptsBaseline(t *testing.T) {
	root := testsupport.RepoRoot(t)
	scripts := make(map[string]string, len(releaseScriptPaths))
	for _, rel := range releaseScriptPaths {
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil {
			t.Fatalf("stat %s: %v", rel, err)
		}
		if slices.Contains(executableReleaseScriptPaths, rel) && info.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s must be executable (got mode %#o)", rel, info.Mode().Perm())
		}
		body, err := os.ReadFile(abs)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		scripts[rel] = text
		if !strings.HasPrefix(text, "#!/usr/bin/env bash\n") {
			t.Errorf("%s must start with #!/usr/bin/env bash", rel)
		}
		if slices.Contains(executableReleaseScriptPaths, rel) && !strings.Contains(text, "set -euo pipefail") {
			t.Errorf("%s must enable set -euo pipefail", rel)
		}
		cmd := exec.Command("bash", "-n", abs)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("bash -n %s failed: %v\n%s", rel, err, out)
		}
	}
	if err := checkReleaseScriptsBash32Compatibility(scripts); err != nil {
		t.Error(err)
	}

	// Verify extract_final_http_headers, probe_ghcr_manifest_digest,
	// extract_next_referrers_url, and check_referrers_filters_applied awk
	// programs compile and behave identically across POSIX/BSD/mawk engines.
	commonProgs := extractAwkPrograms(scripts[releaseCommonScriptPath])
	var hexAwkProg, digestAwkProg, finalHdrAwkProg, linkAwkProg, filtersAwkProg string
	for _, p := range commonProgs {
		if hexAwkProg == "" && strings.Contains(p, `tok == "00"`) && strings.Contains(p, `last != "0a"`) {
			hexAwkProg = p
		}
		if digestAwkProg == "" && strings.Contains(p, "docker-content-digest:") && strings.Contains(p, "seen && v != val") {
			digestAwkProg = p
		}
		if finalHdrAwkProg == "" && strings.Contains(p, "saw_status") && strings.Contains(p, "in_hdr") {
			finalHdrAwkProg = p
		}
		if linkAwkProg == "" && strings.Contains(p, "expected_repo") && strings.Contains(p, "expected_digest") {
			linkAwkProg = p
		}
		if filtersAwkProg == "" && strings.Contains(p, "^oci-filters-applied") {
			filtersAwkProg = p
		}
	}
	if hexAwkProg == "" {
		t.Fatalf("could not locate extract_final_http_headers hex pre-check awk program in %s", releaseCommonScriptPath)
	}
	if digestAwkProg == "" {
		t.Fatalf("could not locate probe_ghcr_manifest_digest awk program in %s", releaseCommonScriptPath)
	}
	if finalHdrAwkProg == "" {
		t.Fatalf("could not locate extract_final_http_headers awk program in %s", releaseCommonScriptPath)
	}
	if linkAwkProg == "" {
		t.Fatalf("could not locate extract_next_referrers_url awk program in %s", releaseCommonScriptPath)
	}
	if filtersAwkProg == "" {
		t.Fatalf("could not locate check_referrers_filters_applied awk program in %s", releaseCommonScriptPath)
	}
	commonAbs := filepath.Join(root, filepath.FromSlash(releaseCommonScriptPath))
	if out, err := exec.Command("bash", "-c", `source "$1" || exit 2; if extract_final_http_headers "$2" >/dev/null 2>&1; then exit 1; fi`, "bash", commonAbs, filepath.Join(t.TempDir(), "missing.hdr")).CombinedOutput(); err != nil {
		t.Fatalf("extract_final_http_headers failed open on unreadable header file: err=%v out=%s", err, string(out))
	}
	wantDigest := "sha256:" + strings.Repeat("a", 64)
	// Verify pipefail independence (set +o pipefail), locale safety (LC_ALL=en_US.UTF-8 with 0xe9 obs-text),
	// trailer value/EOF validation, framing eligibility, and headerless current_url checks.
	t.Run("bash_header_helpers_pipefail_off_and_utf8_locale", func(t *testing.T) {
		tmpDir := t.TempDir()
		missingHdr := filepath.Join(tmpDir, "missing.hdr")
		corruptHdr := filepath.Join(tmpDir, "corrupt.hdr")
		trunc103Hdr := filepath.Join(tmpDir, "trunc103.hdr")
		cleanObsHdr := filepath.Join(tmpDir, "clean_obstext.hdr")
		linkObsHdr := filepath.Join(tmpDir, "link_obstext.hdr")
		trailerHdr := filepath.Join(tmpDir, "trailer_ok.hdr")
		headerless200Hdr := filepath.Join(tmpDir, "headerless_200.hdr")
		delTrailerHdr := filepath.Join(tmpDir, "del_trailer.hdr")
		sohTrailerHdr := filepath.Join(tmpDir, "soh_trailer.hdr")
		vtContTrailerHdr := filepath.Join(tmpDir, "vt_cont_trailer.hdr")
		nulTrailerHdr := filepath.Join(tmpDir, "nul_trailer.hdr")
		bareCREofHdr := filepath.Join(tmpDir, "bare_cr_eof.hdr")
		noLFEofHdr := filepath.Join(tmpDir, "no_lf_eof.hdr")
		cl0StrayHdr := filepath.Join(tmpDir, "cl0_stray.hdr")
		emptyClosedStrayHdr := filepath.Join(tmpDir, "empty_closed_stray.hdr")
		eofBlankChunkedHdr := filepath.Join(tmpDir, "eof_blank_chunked.hdr")
		validTabObsTrailerHdr := filepath.Join(tmpDir, "tab_obs_trailer.hdr")
		trunc200Hdr := filepath.Join(tmpDir, "trunc_200.hdr")
		truncHdrBlock := filepath.Join(tmpDir, "trunc_hdr_block.hdr")
		teGzipCommaHdr := filepath.Join(tmpDir, "te_gzip_comma.hdr")
		teEmptyOnlyHdr := filepath.Join(tmpDir, "te_empty_only.hdr")
		teDupCommaHdr := filepath.Join(tmpDir, "te_dup_comma.hdr")
		teDupRepeatHdr := filepath.Join(tmpDir, "te_dup_repeat.hdr")
		teMalformedBeforeHdr := filepath.Join(tmpDir, "te_malformed_before.hdr")
		teChunkedParamHdr := filepath.Join(tmpDir, "te_chunked_param.hdr")
		teChunkedCommaHdr := filepath.Join(tmpDir, "te_chunked_comma.hdr")
		teChunkedCommaSpHdr := filepath.Join(tmpDir, "te_chunked_comma_sp.hdr")
		teEmptyRepeatHdr := filepath.Join(tmpDir, "te_empty_repeat.hdr")
		teSparseListHdr := filepath.Join(tmpDir, "te_sparse_list.hdr")
		teUnclosedQuoteHdr := filepath.Join(tmpDir, "te_unclosed_quote.hdr")
		teBadParamHdr := filepath.Join(tmpDir, "te_bad_param.hdr")
		teEmptyParamHdr := filepath.Join(tmpDir, "te_empty_param.hdr")
		teTrailingQuoteHdr := filepath.Join(tmpDir, "te_trailing_quote.hdr")
		teChunkedNotLastQuotedHdr := filepath.Join(tmpDir, "te_chunked_not_last_quoted.hdr")
		teGzipQ0ChunkedHdr := filepath.Join(tmpDir, "te_gzip_q0_chunked.hdr")
		teDeflateParamChunkedHdr := filepath.Join(tmpDir, "te_deflate_param_chunked.hdr")
		teCompressParamChunkedHdr := filepath.Join(tmpDir, "te_compress_param_chunked.hdr")
		teXGzipParamChunkedHdr := filepath.Join(tmpDir, "te_x_gzip_param_chunked.hdr")
		teXCompressParamChunkedHdr := filepath.Join(tmpDir, "te_x_compress_param_chunked.hdr")
		teMixedGZipParamChunkedHdr := filepath.Join(tmpDir, "te_mixed_gzip_param_chunked.hdr")
		teMixedXGzipParamChunkedHdr := filepath.Join(tmpDir, "te_mixed_xgzip_param_chunked.hdr")
		teQuotesAcrossFieldsHdr := filepath.Join(tmpDir, "te_quotes_across_fields.hdr")
		teEmptyTokenValHdr := filepath.Join(tmpDir, "te_empty_token_val.hdr")
		teExampleQ0ChunkedHdr := filepath.Join(tmpDir, "te_example_q0_chunked.hdr")
		teQuotedCommaChunkedHdr := filepath.Join(tmpDir, "te_quoted_comma_chunked.hdr")
		teQuotedEscChunkedHdr := filepath.Join(tmpDir, "te_quoted_esc_chunked.hdr")
		teObsFoldQuoteHdr := filepath.Join(tmpDir, "te_obs_fold_quote.hdr")
		teEmptyQuotedHdr := filepath.Join(tmpDir, "te_empty_quoted.hdr")
		teLarge200kCodingHdr := filepath.Join(tmpDir, "te_large_200k_coding.hdr")
		teLarge200kObsFoldHdr := filepath.Join(tmpDir, "te_large_200k_obs_fold.hdr")

		for path, body := range map[string][]byte{
			corruptHdr:                  []byte("HTTP/1.1 200 OK\r\nBad Header\r\n\r\n"),
			trunc103Hdr:                 []byte("HTTP/1.1 103 Early Hints\r\nLink: </bad>; rel=\"next\"\r\n\r\n"),
			cleanObsHdr:                 []byte("HTTP/1.1 200 OK\r\nX-Note: caf\xe9\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\n\r\n"),
			linkObsHdr:                  []byte("HTTP/1.1 200 OK\r\nX-Note: caf\xe9\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n"),
			trailerHdr:                  []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n"),
			headerless200Hdr:            []byte("HTTP/2 200\r\n\r\n"),
			delTrailerHdr:               []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: a\x7fb\r\n\r\n"),
			sohTrailerHdr:               []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: ok\r\nX-Extra: \x01bad\r\n\r\n"),
			vtContTrailerHdr:            []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: ok\r\n \x0bcont\r\n\r\n"),
			nulTrailerHdr:               []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: a\x00b\r\n\r\n"),
			bareCREofHdr:                []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r"),
			noLFEofHdr:                  []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7"),
			cl0StrayHdr:                 []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n"),
			emptyClosedStrayHdr:         []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n"),
			eofBlankChunkedHdr:          []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\n\r\n\r\n"),
			validTabObsTrailerHdr:       []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: caf\xe9;\tdur=7\r\n \textra=\xe9\r\n\r\n"),
			trunc200Hdr:                 []byte("HTTP/2 200\r\n"),
			truncHdrBlock:               []byte("HTTP/1.1 200 OK\r\nX-Foo: bar\r\n"),
			teGzipCommaHdr:              []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teEmptyOnlyHdr:              []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: , ,\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teDupCommaHdr:               []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teDupRepeatHdr:              []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: Chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teMalformedBeforeHdr:        []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: bad coding, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teChunkedParamHdr:           []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;q=1\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teChunkedCommaHdr:           []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teChunkedCommaSpHdr:         []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,   \r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teEmptyRepeatHdr:            []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding:\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teSparseListHdr:             []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: , gzip , , chunked , \r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teUnclosedQuoteHdr:          []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"unclosed, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teBadParamHdr:               []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;badparam, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teEmptyParamHdr:             []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teTrailingQuoteHdr:          []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"a\"trailing, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teChunkedNotLastQuotedHdr:   []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, example;mode=\"a,b\"\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teGzipQ0ChunkedHdr:          []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;q=0, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teDeflateParamChunkedHdr:    []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: deflate;level=1, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teCompressParamChunkedHdr:   []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: compress;v=1, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teXGzipParamChunkedHdr:      []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: x-gzip;q=0, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teXCompressParamChunkedHdr:  []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: x-compress;v=1, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teMixedGZipParamChunkedHdr:  []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: GZip;q=0, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teMixedXGzipParamChunkedHdr: []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: X-Gzip;level=1, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teQuotesAcrossFieldsHdr:     []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;a=\"foo\r\nTransfer-Encoding: bar\", chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teEmptyTokenValHdr:          []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teExampleQ0ChunkedHdr:       []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;q=0, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teQuotedCommaChunkedHdr:     []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"a,b\", chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teQuotedEscChunkedHdr:       []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"a\\\"b,c\";v=1, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teObsFoldQuoteHdr:           []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;a=\"foo\r\n bar\", chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teEmptyQuotedHdr:            []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"\", chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teLarge200kCodingHdr:        []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: cstart" + strings.Repeat("a", 200000) + "cend, chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
			teLarge200kObsFoldHdr:       []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: example;q=\"a" + strings.Repeat("\r\n b12\r\n c34", 100000) + "\r\n end\", chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"),
		} {
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		stubBin := filepath.Join(tmpDir, "bin")
		failOdBin := filepath.Join(tmpDir, "fail_od_bin")
		failHexOdBin := filepath.Join(tmpDir, "fail_hex_od_bin")
		emptyOdBin := filepath.Join(tmpDir, "empty_od_bin")
		starOdBin := filepath.Join(tmpDir, "star_od_bin")
		failAwkBin := filepath.Join(tmpDir, "fail_awk_bin")
		for _, dir := range []string{stubBin, failOdBin, failHexOdBin, emptyOdBin, starOdBin, failAwkBin} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		realAwk, err := exec.LookPath("awk")
		if err != nil {
			t.Fatalf("required system awk binary not found in PATH: %v", err)
		}
		curlObsStub := "#!/usr/bin/env bash\nhdr=\"\"\nwhile [[ $# -gt 0 ]]; do\n  case \"$1\" in -D) shift; hdr=\"$1\" ;; esac\n  shift\ndone\nprintf 'HTTP/1.1 200 OK\\r\\nX-Note: caf\\xe9\\r\\nTransfer-Encoding: chunked\\r\\nDocker-Content-Digest: " + wantDigest + "\\r\\n\\r\\nServer-Timing: origin;dur=7\\r\\n\\r\\n' > \"$hdr\"\nprintf '200'\n"
		if err := os.WriteFile(filepath.Join(stubBin, "curl"), []byte(curlObsStub), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(failOdBin, "od"), []byte("#!/usr/bin/env bash\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(failHexOdBin, "od"), []byte("#!/usr/bin/env bash\nprintf '48 54 54 50 2f 32 20 32 30 30 0d 0a 0d 0a\\n'\nexit 1\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(emptyOdBin, "od"), []byte("#!/usr/bin/env bash\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(starOdBin, "od"), []byte("#!/usr/bin/env bash\nprintf '48 * 0a\\n'\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		failByteAwkStub := `#!/usr/bin/env bash
is_byte_validator=0
for arg in "$@"; do
  case "${arg}" in
    *'last != "0a"'*|*'tok == "00"'*)
      is_byte_validator=1
      break
      ;;
  esac
done
if [[ "${is_byte_validator}" -eq 1 ]]; then
  if [[ -n "${FAIL_BYTE_AWK_LOG:-}" ]]; then
    printf 'byte_validator_failed\n' >> "${FAIL_BYTE_AWK_LOG}"
  fi
  exit 1
fi
if [[ -n "${FAIL_BYTE_AWK_LOG:-}" ]]; then
  printf 'delegated_to_real_awk\n' >> "${FAIL_BYTE_AWK_LOG}"
fi
exec "${REAL_AWK_BIN}" "$@"
`
		if err := os.WriteFile(filepath.Join(failAwkBin, "awk"), []byte(failByteAwkStub), 0o700); err != nil {
			t.Fatal(err)
		}
		bashCheck := `
set +o pipefail
source "$1" || exit 10
d="$2"
stub_bin="$3"
fail_od_bin="$4"
fail_hex_od_bin="$5"
empty_od_bin="$6"
star_od_bin="$7"
fail_awk_bin="$8"
nul_hdr="$9"
shift 9
while [ $# -gt 0 ] && [ "$1" != "--" ]; do
  bad_f="$1"
  shift
  if extract_final_http_headers "$bad_f" >/dev/null 2>&1; then exit 11; fi
  if extract_next_referrers_url "$bad_f" "$d" >/dev/null 2>&1; then exit 12; fi
  if check_referrers_filters_applied "$bad_f" "$d" >/dev/null 2>&1; then exit 13; fi
done
[ "$1" = "--" ] || exit 10
shift
clean_obs="$1"
link_obs="$2"
trailer_ok="$3"
headerless_200="$4"
eof_blank_chunked="$5"
tab_obs_trailer="$6"
shift 6

# Baseline valid header dump must succeed with real awk before stubbing tools.
extract_final_http_headers "$clean_obs" >/dev/null 2>&1 || exit 14

# Stubbed failing / valid-hex+exit1 / empty / non-hex od under set +o pipefail must fail closed,
# and caller pipefail must remain off afterwards.
for tool_dir in "$fail_od_bin" "$fail_hex_od_bin" "$empty_od_bin" "$star_od_bin"; do
  if PATH="$tool_dir:$PATH" extract_final_http_headers "$nul_hdr" >/dev/null 2>&1; then exit 14; fi
  if PATH="$tool_dir:$PATH" extract_final_http_headers "$clean_obs" >/dev/null 2>&1; then exit 15; fi
done

# Pin byte-validator awk failure: stub fails ONLY the od|awk pre-check invocation and
# delegates all other awk invocations (including the final header parser) to real awk.
byte_awk_log="${TMP_CHECK_DIR}/byte_awk.log"
: > "$byte_awk_log"
if PATH="$fail_awk_bin:$PATH" FAIL_BYTE_AWK_LOG="$byte_awk_log" extract_final_http_headers "$nul_hdr" >/dev/null 2>&1; then exit 14; fi
[ "$(cat "$byte_awk_log")" = "byte_validator_failed" ] || exit 14
: > "$byte_awk_log"
if PATH="$fail_awk_bin:$PATH" FAIL_BYTE_AWK_LOG="$byte_awk_log" extract_final_http_headers "$clean_obs" >/dev/null 2>&1; then exit 15; fi
[ "$(cat "$byte_awk_log")" = "byte_validator_failed" ] || exit 15
: > "$byte_awk_log"
PATH="$fail_awk_bin:$PATH" FAIL_BYTE_AWK_LOG="$byte_awk_log" LC_ALL=C awk "${FINAL_HDR_AWK_PROG}" < "$clean_obs" >/dev/null 2>&1 || exit 15
[ "$(cat "$byte_awk_log")" = "delegated_to_real_awk" ] || exit 15
shopt -po pipefail | grep -q "set +o pipefail" || exit 16

out_clean="$(extract_next_referrers_url "$clean_obs" "$d")" || exit 17
shopt -po pipefail | grep -q "set +o pipefail" || exit 16
[ -z "$out_clean" ] || exit 18
check_referrers_filters_applied "$clean_obs" "$d" || exit 19
out_next="$(extract_next_referrers_url "$link_obs" "$d")" || exit 20
[ "$out_next" = "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}?page=2" ] || exit 21
check_referrers_filters_applied "$link_obs" "$d" || exit 22
out_hdrs="$(extract_final_http_headers "$trailer_ok")" || exit 23
case "$out_hdrs" in
  *"Server-Timing: origin"*) exit 24 ;;
esac
probe_out="$(PATH="$stub_bin:$PATH" probe_ghcr_manifest_digest tok v0.2.0)" || exit 25
[ "$probe_out" = "exists	${d}" ] || exit 26

# Headerless HTTP/2 200 validates current_url unconditionally (repo, digest path, query, artifactType).
out_empty_valid="$(extract_next_referrers_url "$headerless_200" "$d" "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}?page=1")" || exit 27
[ -z "$out_empty_valid" ] || exit 28
out_empty_at="$(extract_next_referrers_url "$headerless_200" "$d" "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}?artifactType=application/spdx+json")" || exit 28
[ -z "$out_empty_at" ] || exit 28
for bad_cur in \
  "https://evil.example/v2/googlecloudplatform/bq-otel-collector/referrers/${d}" \
  "https://ghcr.io/v2/other/repo/referrers/${d}" \
  "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/sha256:0000000000000000000000000000000000000000000000000000000000000000" \
  "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}/extra" \
  "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}#frag" \
  "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}?" \
  "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/${d}?artifactType%ZZ=foo"
do
  if extract_next_referrers_url "$headerless_200" "$d" "$bad_cur" >/dev/null 2>&1; then exit 29; fi
done

extract_final_http_headers "$eof_blank_chunked" >/dev/null || exit 30
out_tab_obs="$(extract_final_http_headers "$tab_obs_trailer")" || exit 31
case "$out_tab_obs" in
  *"Server-Timing:"*) exit 32 ;;
esac
check_referrers_filters_applied "$tab_obs_trailer" "$d" || exit 33
out_tab_next="$(extract_next_referrers_url "$tab_obs_trailer" "$d")" || exit 34
[ -z "$out_tab_next" ] || exit 35

for good_te in "$@"; do
  out_te="$(extract_final_http_headers "$good_te")" || exit 36
  case "$out_te" in
    *"Server-Timing:"*) exit 37 ;;
  esac
  check_referrers_filters_applied "$good_te" "$d" || exit 38
  out_te_next="$(extract_next_referrers_url "$good_te" "$d")" || exit 39
  [ -z "$out_te_next" ] || exit 40
done
`
		cmd := exec.Command(
			"bash", "-c", bashCheck, "bash",
			commonAbs, wantDigest, stubBin, failOdBin, failHexOdBin, emptyOdBin, starOdBin, failAwkBin, nulTrailerHdr,
			missingHdr, corruptHdr, trunc103Hdr,
			delTrailerHdr, sohTrailerHdr, vtContTrailerHdr, nulTrailerHdr,
			bareCREofHdr, noLFEofHdr, cl0StrayHdr, emptyClosedStrayHdr,
			trunc200Hdr, truncHdrBlock, teGzipCommaHdr, teEmptyOnlyHdr,
			teDupCommaHdr, teDupRepeatHdr, teMalformedBeforeHdr, teChunkedParamHdr,
			teUnclosedQuoteHdr, teBadParamHdr, teEmptyParamHdr, teTrailingQuoteHdr, teChunkedNotLastQuotedHdr,
			teGzipQ0ChunkedHdr, teDeflateParamChunkedHdr, teCompressParamChunkedHdr,
			teXGzipParamChunkedHdr, teXCompressParamChunkedHdr, teMixedGZipParamChunkedHdr, teMixedXGzipParamChunkedHdr,
			teQuotesAcrossFieldsHdr, teEmptyTokenValHdr,
			"--",
			cleanObsHdr, linkObsHdr, trailerHdr, headerless200Hdr, eofBlankChunkedHdr, validTabObsTrailerHdr,
			teChunkedCommaHdr, teChunkedCommaSpHdr, teEmptyRepeatHdr, teSparseListHdr,
			teExampleQ0ChunkedHdr, teQuotedCommaChunkedHdr, teQuotedEscChunkedHdr,
			teObsFoldQuoteHdr, teEmptyQuotedHdr, teLarge200kCodingHdr, teLarge200kObsFoldHdr,
		)
		cmd.Env = append(os.Environ(),
			"LC_ALL=en_US.UTF-8",
			"LANG=en_US.UTF-8",
			"REAL_AWK_BIN="+realAwk,
			"FINAL_HDR_AWK_PROG="+finalHdrAwkProg,
			"TMP_CHECK_DIR="+tmpDir,
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pipefail-off / UTF-8 locale helper check failed: err=%v out=%s", err, string(out))
		}
	})
	type awkRunner struct {
		name string
		bin  string
		args []string
	}
	// CI ubuntu-latest runners only run awk engines already installed on the
	// runner (without unpinned apt-get steps) and visibly record absent optional
	// engines via t.Skipf; the full matrix (mawk, gawk, original-awk) runs locally.
	runners := []awkRunner{
		{name: "awk", bin: "awk"},
		{name: "mawk", bin: "mawk"},
		{name: "gawk", bin: "gawk"},
		{name: "gawk-posix", bin: "gawk", args: []string{"--posix"}},
		{name: "gawk-traditional", bin: "gawk", args: []string{"--traditional"}},
		{name: "original-awk", bin: "original-awk"},
	}
	baseRefURL := "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest
	validHdr := "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?last=sha256:abcd1234&cursor=a/b>; title=\"a;b\"; rel=\"next\"\n\n"
	wantURL := baseRefURL + "?last=sha256:abcd1234&cursor=a/b"
	relQueryHdr := "HTTP/2 200\nLink: <?page=2>; rel=\"next\"\n\n"
	wantRelURL := baseRefURL + "?page=2"
	emptyRelHdr := "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?last=next>; rel=\"\"\n\n"
	for _, r := range runners {
		t.Run("awk_posix_"+r.name, func(t *testing.T) {
			resolvedBin, lookErr := exec.LookPath(r.bin)
			if lookErr != nil {
				if r.name == "awk" {
					t.Fatalf("required system awk binary not found in PATH: %v", lookErr)
				}
				t.Skipf("%s binary not found in PATH (%v); skipping %s POSIX awk checks", r.bin, lookErr, r.name)
			}
			r.bin = resolvedBin
			runHexCheck := func(hexInput string) error {
				args := append([]string(nil), r.args...)
				args = append(args, hexAwkProg)
				c := exec.Command(r.bin, args...)
				c.Env = append(os.Environ(), "LC_ALL=C")
				c.Stdin = strings.NewReader(hexInput)
				if out, err := c.CombinedOutput(); err != nil {
					return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
				}
				return nil
			}
			for _, goodHex := range []string{
				" 48 54 54 50 0d 0a 0d 0a\n",
				"   48  54  0D  0A\n",
			} {
				if err := runHexCheck(goodHex); err != nil {
					t.Fatalf("%s hex pre-check rejected valid hex %q: %v", r.name, goodHex, err)
				}
			}
			for _, badHex := range []string{
				"",
				"   \n",
				" 48 00 0a\n",
				" 48 54 0d\n",
				" 48 * 0a\n",
				" 4 0a\n",
				" zz 0a\n",
			} {
				if err := runHexCheck(badHex); err == nil {
					t.Fatalf("%s hex pre-check failed open on %q", r.name, badHex)
				}
			}
			runFinalHdr := func(rawDump string) (string, error) {
				args := append([]string(nil), r.args...)
				args = append(args, finalHdrAwkProg)
				c := exec.Command(r.bin, args...)
				c.Env = append(os.Environ(), "LC_ALL=C")
				c.Stdin = strings.NewReader(rawDump)
				out, err := c.CombinedOutput()
				return string(out), err
			}
			runAwk := func(input, curURL string) (string, error) {
				finalHdrs, err := runFinalHdr(input)
				if err != nil {
					return strings.TrimSpace(finalHdrs), err
				}
				args := append([]string(nil), r.args...)
				args = append(args, "-v", "expected_repo=googlecloudplatform/bq-otel-collector", "-v", "expected_digest="+wantDigest, "-v", "current_url="+curURL, linkAwkProg)
				c := exec.Command(r.bin, args...)
				c.Env = append(os.Environ(), "LC_ALL=C")
				c.Stdin = strings.NewReader(finalHdrs)
				out, err := c.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			got, err := runAwk(validHdr, baseRefURL)
			if err != nil || got != wantURL {
				t.Fatalf("%s failed valid Link header with :/ query chars and quoted semicolon: got=%q err=%v", r.name, got, err)
			}
			gotRel, err := runAwk(relQueryHdr, baseRefURL+"?page=1")
			if err != nil || gotRel != wantRelURL {
				t.Fatalf("%s failed query-relative Link resolution: got=%q err=%v", r.name, gotRel, err)
			}
			// Exact 1-based byte-offset boundary strings sized against each scanner's actual input.
			teEscFval := " ex;q=\"" + strings.Repeat("a", 248) + "\\\"z" + strings.Repeat("b", 3837) + "\\\"w\", chunked"
			if firstBS, lastBS := strings.IndexByte(teEscFval, '\\')+1, strings.LastIndexByte(teEscFval, '\\')+1; firstBS != 256 || lastBS != 4096 {
				t.Fatalf("internal fixture bug: TE escape offsets = (%d, %d), want (256, 4096)", firstBS, lastBS)
			}
			teSplitChunkedFval := " ex;q=\"" + strings.Repeat("a", 4083) + "\", chunked"
			if chunkIdx := strings.Index(teSplitChunkedFval, "chunked") + 1; chunkIdx != 4094 {
				t.Fatalf("internal fixture bug: TE split chunked offset = %d, want 4094", chunkIdx)
			}
			teSplitGzipParamFval := " ex;q=\"" + strings.Repeat("a", 4084) + "\", gzip;q=0, chunked"
			if gzIdx := strings.Index(teSplitGzipParamFval, "gzip") + 1; gzIdx != 4095 {
				t.Fatalf("internal fixture bug: TE split gzip offset = %d, want 4095", gzIdx)
			}
			teEscBad256 := " ex;q=\"" + strings.Repeat("a", 248) + "\\\", chunked"
			teEscBad4096 := " ex;q=\"" + strings.Repeat("a", 4088) + "\\\", chunked"
			teEscEOF4096 := " ex;q=\"" + strings.Repeat("a", 4088) + "\\"
			if strings.IndexByte(teEscBad256, '\\')+1 != 256 || strings.IndexByte(teEscBad4096, '\\')+1 != 4096 || strings.IndexByte(teEscEOF4096, '\\')+1 != 4096 {
				t.Fatalf("internal fixture bug: bad TE backslash offsets mismatch")
			}

			pathPrefix := "/v2/googlecloudplatform/bq-otel-collector/referrers/"
			rawPath255And4096 := pathPrefix + strings.Repeat("p", 254-len(pathPrefix)) + "%2F" + strings.Repeat("q", 3838) + "%2F/../" + wantDigest
			if p1, p2 := strings.Index(rawPath255And4096, "%2F")+1, strings.LastIndex(rawPath255And4096, "%2F")+1; p1 != 255 || p2 != 4096 {
				t.Fatalf("internal fixture bug: rawPath255And4096 %% offsets = (%d, %d), want (255, 4096)", p1, p2)
			}
			rawPath256And4095 := pathPrefix + strings.Repeat("p", 255-len(pathPrefix)) + "%2F" + strings.Repeat("q", 3836) + "%2F/../" + wantDigest
			if p1, p2 := strings.Index(rawPath256And4095, "%2F")+1, strings.LastIndex(rawPath256And4095, "%2F")+1; p1 != 256 || p2 != 4095 {
				t.Fatalf("internal fixture bug: rawPath256And4095 %% offsets = (%d, %d), want (256, 4095)", p1, p2)
			}
			cursor255And4096 := strings.Repeat("c", 254) + "%2F" + strings.Repeat("d", 3838) + "%2Fend"
			atEnc255And4096 := strings.Repeat("a", 254) + "%2F" + strings.Repeat("b", 3838) + "%2Fend"
			atDec255And4096 := strings.Repeat("a", 254) + "/" + strings.Repeat("b", 3838) + "/end"
			cursor256And4095 := strings.Repeat("c", 255) + "%2F" + strings.Repeat("d", 3836) + "%2Fend"
			atEnc256And4095 := strings.Repeat("a", 255) + "%2F" + strings.Repeat("b", 3836) + "%2Fend"
			atDec256And4095 := strings.Repeat("a", 255) + "/" + strings.Repeat("b", 3836) + "/end"
			for _, v := range []struct {
				s     string
				w1    int
				w2    int
				label string
			}{
				{cursor255And4096, 255, 4096, "cursor255And4096"},
				{atEnc255And4096, 255, 4096, "atEnc255And4096"},
				{cursor256And4095, 256, 4095, "cursor256And4095"},
				{atEnc256And4095, 256, 4095, "atEnc256And4095"},
			} {
				if i1, i2 := strings.Index(v.s, "%2F")+1, strings.LastIndex(v.s, "%2F")+1; i1 != v.w1 || i2 != v.w2 {
					t.Fatalf("internal fixture bug: %s %% offsets = (%d, %d), want (%d, %d)", v.label, i1, i2, v.w1, v.w2)
				}
			}
			linkLineValidPrefix := "<?page=2>; foo=\""
			linkLineEscOk := linkLineValidPrefix + strings.Repeat("x", 255-len(linkLineValidPrefix)) + "\\\"z" + strings.Repeat("y", 4095-258) + "\\\"w\"; rel=\"next\""
			linkLineRelPrefix := "<?page=2>; rel=\"next "
			linkLineRelEscOk := linkLineRelPrefix + strings.Repeat("x", 255-len(linkLineRelPrefix)) + "\\az" + strings.Repeat("y", 4095-258) + "\\aw\""
			linkLineRelNextPrefix := "<?page=2>; rel=\"prev "
			linkLineRelNextEsc256 := linkLineRelNextPrefix + strings.Repeat("x", 255-len(linkLineRelNextPrefix)-len(" nex")) + " nex\\t\""
			linkLineRelNextEsc4096 := linkLineRelNextPrefix + strings.Repeat("x", 4095-len(linkLineRelNextPrefix)-len(" nex")) + " nex\\t\""
			if l1, l2 := strings.IndexByte(linkLineEscOk, '\\')+1, strings.LastIndexByte(linkLineEscOk, '\\')+1; l1 != 256 || l2 != 4096 {
				t.Fatalf("internal fixture bug: Link foo escape offsets = (%d, %d), want (256, 4096)", l1, l2)
			}
			if l1, l2 := strings.IndexByte(linkLineRelEscOk, '\\')+1, strings.LastIndexByte(linkLineRelEscOk, '\\')+1; l1 != 256 || l2 != 4096 {
				t.Fatalf("internal fixture bug: Link rel escape offsets = (%d, %d), want (256, 4096)", l1, l2)
			}
			if off := strings.IndexByte(linkLineRelNextEsc256, '\\') + 1; off != 256 || strings.Contains(linkLineRelNextEsc256, "next") {
				t.Fatalf("internal fixture bug: linkLineRelNextEsc256 backslash offset = %d, contains next=%t", off, strings.Contains(linkLineRelNextEsc256, "next"))
			}
			if off := strings.IndexByte(linkLineRelNextEsc4096, '\\') + 1; off != 4096 || strings.Contains(linkLineRelNextEsc4096, "next") {
				t.Fatalf("internal fixture bug: linkLineRelNextEsc4096 backslash offset = %d, contains next=%t", off, strings.Contains(linkLineRelNextEsc4096, "next"))
			}
			linkLineTabEsc256 := linkLineValidPrefix + strings.Repeat("x", 255-len(linkLineValidPrefix)) + "\\\tz\"; rel=\"next\""
			linkLineTabEsc4096 := linkLineValidPrefix + strings.Repeat("x", 4095-len(linkLineValidPrefix)) + "\\\tz\"; rel=\"next\""
			linkLineRelTabEsc4096 := linkLineRelPrefix + strings.Repeat("x", 4095-len(linkLineRelPrefix)) + "\\\tz\""
			if strings.IndexByte(linkLineTabEsc256, '\\')+1 != 256 || strings.IndexByte(linkLineTabEsc4096, '\\')+1 != 4096 || strings.IndexByte(linkLineRelTabEsc4096, '\\')+1 != 4096 {
				t.Fatalf("internal fixture bug: Link tab-escape offsets mismatch")
			}

			for _, goodCase := range []struct {
				name   string
				hdr    string
				curURL string
				want   string
			}{
				{
					name:   "dot_relative_query",
					hdr:    "HTTP/2 200\nLink: <./" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "dot_relative_comma_cursor",
					hdr:    "HTTP/2 200\nLink: <./" + wantDigest + "?cursor=a,b>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?cursor=a,b",
				},
				{
					name:   "parent_referrers_comma_cursor",
					hdr:    "HTTP/2 200\nLink: <../referrers/" + wantDigest + "?cursor=a,b>; rel=\"next\"\n\n",
					curURL: baseRefURL + "?cursor=init,0",
					want:   baseRefURL + "?cursor=a,b",
				},
				{
					name:   "same_authority_network_path",
					hdr:    "HTTP/2 200\nLink: <//ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "dot_segments_in_https_url_with_comma",
					hdr:    "HTTP/2 200\nLink: <https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/../referrers/" + wantDigest + "?cursor=a,b>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?cursor=a,b",
				},
				{
					name:   "valid_pct20_before_dot_dot",
					hdr:    "HTTP/2 200\nLink: <./part%20ok/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "early_hints_103_bad_link_ignored_before_200",
					hdr:    "HTTP/1.1 103 Early Hints\r\nOCI-Filters-Applied: artifactType\r\nLink: </bad>; rel=\"next\"\r\n\r\nHTTP/1.1 200 OK\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\n",
					curURL: baseRefURL,
					want:   "",
				},
				{
					name:   "continue_100_before_200_valid_link",
					hdr:    "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nLink: <?page=2>; rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "obs_fold_and_status_text_inside_continuation_preserved",
					hdr:    "HTTP/1.1 200 OK\r\nX-Note: alpha\r\n   HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>;\r\n\t rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "whitespace_only_continuation_keeps_block_active",
					hdr:    "HTTP/1.1 200 OK\r\nX-Note: alpha\r\n   \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "single_space_fold_before_link",
					hdr:    "HTTP/1.1 200 OK\r\nX-Fold: alpha\r\n \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "bare_statusless_headers_with_obs_fold_and_trailing_blanks",
					hdr:    "X-Note: alpha\r\n\t beta\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>;\r\n   rel=\"next\"\r\n\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "dot_prefixed_colon_first_segment_relative",
					hdr:    "HTTP/2 200\nLink: <./1:part/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "second_segment_colon_relative",
					hdr:    "HTTP/2 200\nLink: <part/sub:ok/../../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "harmless_chunked_server_timing_trailer_ignored",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;\r\n dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "redirect_with_harmless_trailer_before_200_with_trailer",
					hdr:    "HTTP/1.1 302 Found\r\nLocation: /other\r\nTransfer-Encoding: chunked\r\nLink: </bad>; rel=\"next\"\r\n\r\nServer-Timing: edge;dur=1\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_gzip_chunked_with_tab_and_obstext_trailer",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, Chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: caf\xe9;\tdur=7\r\n \textra=\xe9\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_folded_multi_te_with_trailer",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding:\r\n chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_chunked_empty_trailer_blanks_at_eof",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_chunked_302_empty_trailer_then_200",
					hdr:    "HTTP/1.1 302 Found\r\nLocation: /next\r\nTransfer-Encoding: chunked\r\n\r\n\r\nHTTP/1.1 200 OK\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http2_and_http3_trailers_without_te",
					hdr:    "HTTP/2.0 302 Found\r\nLocation: /next\r\n\r\nServer-Timing: edge\r\n\r\nHTTP/3 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "obs_text_0xe9_in_unrelated_header",
					hdr:    "HTTP/1.1 200 OK\r\nX-Note: caf\xe9\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_chunked_trailing_comma_eof_trailer",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_chunked_trailing_comma_spaces",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,   \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_chunked_then_empty_te_header",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding:\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_sparse_list_gzip_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: , gzip , , chunked , \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_extension_q0_param_then_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: example;q=0, chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_quoted_comma_param_then_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"a,b\", chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_quoted_escape_and_bws_param_then_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: example ; mode = \"a\\\"b,c\\\\d\" ; v=1 , chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_obs_fold_quoted_param_then_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: example;a=\"foo\r\n bar\", chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "http11_te_empty_quoted_param_then_chunked",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"\", chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "te_exact_256_4096_escaped_quote",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teEscFval + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "te_chunked_coding_split_across_4096",
					hdr:    "HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teSplitChunkedFval + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "link_exact_256_4096_escaped_quote_non_rel",
					hdr:    "HTTP/2 200\nLink: " + linkLineEscOk + "\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "link_exact_256_4096_escaped_quote_rel",
					hdr:    "HTTP/2 200\nLink: " + linkLineRelEscOk + "\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "link_exact_256_escaped_rel_next_final_t",
					hdr:    "HTTP/2 200\nLink: " + linkLineRelNextEsc256 + "\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "link_exact_4096_escaped_rel_next_final_t",
					hdr:    "HTTP/2 200\nLink: " + linkLineRelNextEsc4096 + "\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "link_pct_2f_exact_255_and_4096",
					hdr:    "HTTP/2 200\nLink: <" + rawPath255And4096 + "?cursor=" + cursor255And4096 + "&artifactType=" + atEnc255And4096 + ">; rel=\"next\"\n\n",
					curURL: baseRefURL + "?artifactType=" + atDec255And4096,
					want:   baseRefURL + "?cursor=" + cursor255And4096 + "&artifactType=" + atEnc255And4096,
				},
				{
					name:   "link_pct_2f_exact_256_and_4095",
					hdr:    "HTTP/2 200\nLink: <" + rawPath256And4095 + "?cursor=" + cursor256And4095 + "&artifactType=" + atEnc256And4095 + ">; rel=\"next\"\n\n",
					curURL: baseRefURL + "?artifactType=" + atDec256And4095,
					want:   baseRefURL + "?cursor=" + cursor256And4095 + "&artifactType=" + atEnc256And4095,
				},
				{
					name:   "link_many_clauses_1000",
					hdr:    "HTTP/2 200\nLink: " + strings.Repeat("</v2/other>; rel=\"prev\", ", 999) + "</v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_remove_dot_segments_vectors",
					hdr:    "HTTP/2 200\nLink: </a/b/c/./../../g/../../v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_empty_segment_before_dotdot_resolves",
					hdr:    "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers//../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_ellipsis_segment_then_dotdot_resolves",
					hdr:    "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/.../../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_dotted_name_segment_then_dotdot_resolves",
					hdr:    "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/..a.b/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_pct_encoded_dot_segment_before_dotdot_resolves",
					hdr:    "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/%2e/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
				{
					name:   "rfc3986_pct_encoded_dotdot_segment_before_dotdot_resolves",
					hdr:    "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/%2E%2E/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
					curURL: baseRefURL,
					want:   baseRefURL + "?page=2",
				},
			} {
				gotGood, err := runAwk(goodCase.hdr, goodCase.curURL)
				if err != nil || gotGood != goodCase.want {
					t.Errorf("%s failed RFC 3986 case %s: got=%q want=%q err=%v", r.name, goodCase.name, gotGood, goodCase.want, err)
				}
			}
			for _, badHdr := range []string{
				emptyRelHdr,
				"HTTP/2 200\nLink: <?page=2>; rel=\"next\"junk\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel=\"next\" garbage\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel==next\n\n",
				"HTTP/2 200\nLink: <?page=2>; =foo; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?page=2>; title=\"x\"\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel=\"next;foo\"\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel=\"prev\"; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?page=2&artifactType=application/spdx+json>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <//evil.example/v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <" + wantDigest + "?cursor=a,b>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <1:part/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <1:foo>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <../other/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./" + wantDigest + "?page=2#frag>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./" + wantDigest + "?page=2&artifactType=application/spdx+json>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./part%ZZ/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/part%ZZ/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/part%ZZ/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <//ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/part%2/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./part%00/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./part[bad]/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/1.1 200 OK\r\nOCI-Filters-Applied: artifactType\r\nHTTP/2-Custom: foo\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Before: 1\r\nHTTP/2: x\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\n\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				// Resolver trailing-dot, double-slash, ellipsis/dotted name, and percent-encoded dot-segment edges.
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/.>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/.?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/..>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/extra/..>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/extra/..?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./" + wantDigest + "/.?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <./" + wantDigest + "/extra/..?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers//" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/.../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/...?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/..a/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/%2e/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/extra/%2E%2E/" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/%2e?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "/extra/%2E%2E?page=2>; rel=\"next\"\n\n",
				// Exact window-boundary invalid twins (bytes 255/256/4095/4096).
				"HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teEscBad256 + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teEscBad4096 + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teEscEOF4096 + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding:" + teSplitGzipParamFval + "\r\nLink: <?page=2>; rel=\"next\"\r\n\r\nServer-Timing: x\r\n\r\n",
				"HTTP/2 200\nLink: " + linkLineTabEsc256 + "\n\n",
				"HTTP/2 200\nLink: " + linkLineTabEsc4096 + "\n\n",
				"HTTP/2 200\nLink: " + linkLineRelTabEsc4096 + "\n\n",
				"HTTP/2 200\nLink: <" + pathPrefix + strings.Repeat("p", 254-len(pathPrefix)) + "%2Z/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <" + pathPrefix + strings.Repeat("p", 255-len(pathPrefix)) + "%00/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <" + pathPrefix + strings.Repeat("p", 4094-len(pathPrefix)) + "%ZZ/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <" + pathPrefix + strings.Repeat("p", 4095-len(pathPrefix)) + "%00/../" + wantDigest + "?page=2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 254) + "%2Z>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 255) + "%ZZ>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 4094) + "%ZZ>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 4095) + "%00>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 4094) + "%2>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?cursor=" + strings.Repeat("c", 4095) + "%>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?artifactType=" + strings.Repeat("a", 4094) + "%2Fend>; rel=\"next\"\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel\n\n",
				"HTTP/2 200\nLink: <?page=2>; rel=\"next " + strings.Repeat("a", 4094) + "\t\"; foo=\"bar\"\n\n",
			} {
				if badOut, err := runAwk(badHdr, baseRefURL); err == nil {
					t.Errorf("%s failed open on invalid/disallowed Link header %q: out=%q", r.name, badHdr, badOut)
				}
			}

			for _, badDump := range []string{
				"",
				"\r\n\r\n",
				"HTTP/1.1 200 OK\r\nOCI-Filters-Applied: artifactType\r\nHTTP/2-Custom: foo\r\n\r\n",
				"HTTP/1.1 200 OK\r\nOCI-Filters-Applied: artifactType\r\nHTTP/2: x\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\n\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/vnd.oci.image.index.v1+json\r\n\r\nOCI-Filters-Applied: artifactType\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nServer-Timing: x\r\nlInK:\r\n </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nOcI-FiLtErS-aPpLiEd:\r\n artifactType\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nServer-Timing: x\r\nHTTP/1.1 200 OK\r\nX-B: 2\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nServer-Timing: x\r\n\r\nServer-Timing: y\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\n orphan\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nHTTP/2: x\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nHTTP/2-Custom: foo\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nNotATrailer\r\n",
				"HTTP/1.1 200 OK\r\nX-Met\rric: v\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Note: a\rb\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Note: v\r\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nServer-Timing: a\rb\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nServer-Timing: a\x7fb\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nServer-Timing: ok\r\nX-Tr: \x01bad\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nServer-Timing: ok\r\n \x0bcont\r\n\r\n",
				"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/2 200\r\nX-A: 1\r\n\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/2 204\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/2 304\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 103 Early Hints\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n",
				"HTTP/1.1 100 Continue\r\n\r\n",
				"HTTP/1.1 103 Early Hints\r\nX: 1\r\n\r\nServer-Timing: x\r\n\r\nHTTP/1.1 200 OK\r\nX-Ok: 1\r\n\r\n",
				"HTTP/2 200\r\n  leading-fold: bad\r\nX-Ok: 1\r\n\r\n",
				"HTTP/2 200\r\n   \r\nX-Ok: 1\r\n\r\n",
				"HTTP/2 200\r\nNotAHeaderLine\r\n\r\n",
				"HTTP/2 200\r\nX-Ok: 1\r\n\r\nNotAStatusLine\r\n",
				"X-First: 1\r\n\r\nLink: </v2/ok>; rel=\"next\"\r\n",
				"X-First: 1\r\n\r\nServer-Timing: origin;dur=7\r\n",
				"X-First: 1\r\n\r\nHTTP/2 200\r\nX-Second: 2\r\n",
				"HTTP/1.1 100 Continue\r\nHTTP/1.1 200 OK\r\n\r\n",
				"HTTP/2 200\r\n",
				"HTTP/1.1 200 OK\r\nX-Foo: bar\r\n",
				"HTTP/1.1 100 Continue\r\n\r\nHTTP/2 200\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip,\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: , ,\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: Chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: bad coding, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked;q=1\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"unclosed, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;badparam, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=\"a\"trailing, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, example;mode=\"a,b\"\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: ;q=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;mode=, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: example;a=\"foo\r\nTransfer-Encoding: bar\", chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip;q=0, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: deflate;level=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: compress;v=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: x-gzip;q=0, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: x-compress;v=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: GZip;q=0, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: X-Gzip;level=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: DeFlAtE;q=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: CoMpReSs;q=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: X-CoMpReSs;q=1, chunked\r\nX-A: 1\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
			} {
				if out, err := runFinalHdr(badDump); err == nil {
					t.Fatalf("%s extract_final_http_headers failed open on corrupt dump %q: out=%q", r.name, badDump, out)
				}
			}
			// Decreasing-length 64-chunk carry-stack regressions (4159 down to 4096 bytes)
			// with distinct markers per chunk and exact full-output assertions.
			var decObsRaw, decObsWant strings.Builder
			decObsRaw.WriteString("HTTP/2 200\r\nX-Dec: head")
			decObsWant.WriteString("X-Dec: head")
			var decLinkRel, decLinkCurEnc, decLinkAtEnc, decLinkAtDec strings.Builder
			decLinkRel.WriteString("next")
			for idx := range 64 {
				chunkLen := 4159 - idx
				prefix := fmt.Sprintf(" D%02d", idx)
				suffix := fmt.Sprintf("E%02d", idx)
				body := strings.Repeat(string(rune('a'+(idx%26))), chunkLen-len(prefix)-len(suffix))
				foldedPiece := prefix + body + suffix
				decObsRaw.WriteString("\r\n" + foldedPiece)
				decObsWant.WriteString(foldedPiece)

				tokPrefix := fmt.Sprintf("r%02d", idx)
				tokSuffix := fmt.Sprintf("z%02d", idx)
				tokBody := strings.Repeat(string(rune('a'+(idx%26))), chunkLen-len(tokPrefix)-len(tokSuffix)-len(" \\"))
				decLinkRel.WriteString(" \\" + " " + tokPrefix + tokBody + tokSuffix)

				curBody := strings.Repeat(string(rune('a'+(idx%26))), chunkLen-len(tokPrefix)-len(tokSuffix)-3)
				decLinkCurEnc.WriteString("%20" + tokPrefix + curBody + tokSuffix)
				if idx < 16 {
					// Keep curURL under Linux MAX_ARG_STRLEN (128 KiB) for -v current_url=... while still exercising >4096 decreasing chunks in pct_decode.
					decLinkAtEnc.WriteString("%2F" + tokPrefix + curBody + tokSuffix)
					decLinkAtDec.WriteString("/" + tokPrefix + curBody + tokSuffix)
				}
			}
			decObsRaw.WriteString("\r\n\r\n")
			decObsWant.WriteString("\n")
			if gotDecObs, err := runFinalHdr(decObsRaw.String()); err != nil || gotDecObs != decObsWant.String() {
				t.Errorf("%s 64_decreasing_chunks_obs_fold mismatch: err=%v len=(%d vs %d)", r.name, err, len(gotDecObs), decObsWant.Len())
			}
			decLinkCur := baseRefURL + "?artifactType=start" + decLinkAtDec.String()
			decLinkQuery := "?cursor=" + decLinkCurEnc.String() + "&artifactType=start" + decLinkAtEnc.String()
			decLinkWant := baseRefURL + decLinkQuery
			decLinkHdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + decLinkQuery + ">; rel=\"" + decLinkRel.String() + "\"\r\n\r\n"
			if gotDecLink, err := runAwk(decLinkHdr, decLinkCur); err != nil || gotDecLink != decLinkWant {
				t.Errorf("%s 64_decreasing_chunks_link_buffer mismatch: err=%v len=(%d vs %d)", r.name, err, len(gotDecLink), len(decLinkWant))
			}

			// Verify linear scaling (4N vs N) and exact output with distinct boundary markers
			// across TE/obs-fold/Link/pct_decode using per-case t.Errorf so one slow or failing
			// case never masks remaining cases or checks in the subtest.
			checkLinearCase := func(name string, build func(n int) (hdr, curURL, wantOut string), smallN, largeN int, wantErr bool) {
				runOnce := func(n int) (time.Duration, bool) {
					hdr, curURL, wantOut := build(n)
					start := time.Now()
					gotOut, err := runAwk(hdr, curURL)
					elapsed := time.Since(start)
					if wantErr {
						if err == nil {
							t.Errorf("%s %s (n=%d) failed open on invalid input: out=%q", r.name, name, n, gotOut)
							return elapsed, false
						}
					} else if err != nil || gotOut != wantOut {
						t.Errorf("%s %s (n=%d) = (len=%d, %v), want exact match len=%d", r.name, name, n, len(gotOut), err, len(wantOut))
						return elapsed, false
					}
					return elapsed, true
				}
				const maxLargeWall = 15 * time.Second
				// Floor denominator at 50ms to absorb awk process-spawn jitter; with a 9.0x
				// ratio threshold, scaling failures trigger above ~450ms on the 4N run.
				const minScaleFloor = 50 * time.Millisecond
				const maxScalingRatio = 9.0
				evalPair := func(dSmall, dLarge time.Duration) (ceilingHit, scalingHit bool, floor time.Duration, ratio float64) {
					floor = max(dSmall, minScaleFloor)
					ratio = float64(dLarge) / float64(floor)
					ceilingHit = dLarge > maxLargeWall
					scalingHit = ratio > maxScalingRatio
					return ceilingHit, scalingHit, floor, ratio
				}
				dSmall1, okSmall := runOnce(smallN)
				dLarge1, okLarge := runOnce(largeN)
				if !okSmall || !okLarge {
					return
				}
				ceil1, scale1, fl1, rat1 := evalPair(dSmall1, dLarge1)
				t.Logf("%s %s: run1=(N=%d:%v -> 4N=%d:%v, %.2fx vs floor %v)",
					r.name, name, smallN, dSmall1, largeN, dLarge1, rat1, fl1)
				if !ceil1 && !scale1 {
					return
				}
				// Re-run a separate (N, 4N) pair so transient load only triggers a retry and ratios never mix runs.
				dSmall2, okSmall2 := runOnce(smallN)
				dLarge2, okLarge2 := runOnce(largeN)
				if !okSmall2 || !okLarge2 {
					return
				}
				ceil2, scale2, fl2, rat2 := evalPair(dSmall2, dLarge2)
				t.Logf("%s %s retry: run2=(N=%d:%v -> 4N=%d:%v, %.2fx vs floor %v)",
					r.name, name, smallN, dSmall2, largeN, dLarge2, rat2, fl2)
				switch {
				case ceil1 && ceil2:
					t.Errorf("%s %s exceeded %v wall-clock ceiling on consecutive runs: run1=(N=%d:%v, 4N=%d:%v) run2=(N=%d:%v, 4N=%d:%v)",
						r.name, name, maxLargeWall, smallN, dSmall1, largeN, dLarge1, smallN, dSmall2, largeN, dLarge2)
				case scale1 && scale2:
					t.Errorf("%s %s exceeded %.1fx paired 4N/N scaling threshold on consecutive runs: run1=(%v -> %v, %.2fx vs floor %v) run2=(%v -> %v, %.2fx vs floor %v)",
						r.name, name, maxScalingRatio, dSmall1, dLarge1, rat1, fl1, dSmall2, dLarge2, rat2, fl2)
				case (ceil1 || scale1) && (ceil2 || scale2):
					t.Errorf("%s %s failed runtime bounds across consecutive pairs: run1=(N:%v, 4N:%v, ceil=%t scale=%.2fx) run2=(N:%v, 4N:%v, ceil=%t scale=%.2fx)",
						r.name, name, dSmall1, dLarge1, ceil1, rat1, dSmall2, dLarge2, ceil2, rat2)
				}
			}

			distinctObsFold := func(n int) string {
				var sb strings.Builder
				sb.Grow(n*6 + 64)
				sb.WriteString("example;q=\"start")
				for i := range n {
					if i%1000 == 0 || i == n-1 {
						fmt.Fprintf(&sb, "\r\n F%06d", i)
					} else {
						sb.WriteString("\r\n b")
					}
				}
				sb.WriteString("\r\n fend\", chunked")
				return sb.String()
			}
			markedSeq := func(prefix, mid, suffix, fill string, n int) string {
				half := n / 2
				return prefix + strings.Repeat(fill, half) + mid + strings.Repeat(fill, n-half) + suffix
			}
			teHdr := func(te, tag string) string {
				return "HTTP/1.1 200 OK\r\nTransfer-Encoding: " + te + "\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=" + tag + ">; rel=\"next\"\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n"
			}

			checkLinearCase("coding_token_then_chunked", func(n int) (string, string, string) {
				te := markedSeq("cstart", "CMID", "cend", "a", n) + ", chunked"
				return teHdr(te, "coding"), baseRefURL, baseRefURL + "?page=coding"
			}, 50000, 200000, false)
			checkLinearCase("unquoted_param_value_then_chunked", func(n int) (string, string, string) {
				te := "example;p=" + markedSeq("ustart", "UMID", "uend", "b", n) + ", chunked"
				return teHdr(te, "uval"), baseRefURL, baseRefURL + "?page=uval"
			}, 20000, 80000, false)
			checkLinearCase("param_name_then_chunked", func(n int) (string, string, string) {
				te := "example;" + markedSeq("pstart", "PMID", "pend", "n", n) + "=1, chunked"
				return teHdr(te, "pname"), baseRefURL, baseRefURL + "?page=pname"
			}, 20000, 80000, false)
			checkLinearCase("quoted_param_value_then_chunked", func(n int) (string, string, string) {
				te := "example;q=\"" + markedSeq("qstart", `Q\"MID`, "qend", "q", n) + "\", chunked"
				return teHdr(te, "qval"), baseRefURL, baseRefURL + "?page=qval"
			}, 20000, 80000, false)
			checkLinearCase("obs_fold_te_then_chunked", func(n int) (string, string, string) {
				return teHdr(distinctObsFold(n), "obs"), baseRefURL, baseRefURL + "?page=obs"
			}, 50000, 200000, false)
			checkLinearCase("invalid_200k_coding_empty_param_rejected", func(n int) (string, string, string) {
				te := markedSeq("badstart", "BMID", "badend", "a", n) + ";, chunked"
				return teHdr(te, "bad"), baseRefURL, ""
			}, 50000, 200000, true)

			checkLinearCase("link_non_rel_quoted_param", func(n int) (string, string, string) {
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2&tag=nonrel>; foo=\"" + markedSeq("fstart", `F\"MID`, "fend", "x", n) + "\"; rel=\"next\"\r\n\r\n"
				return hdr, baseRefURL, baseRefURL + "?page=2&tag=nonrel"
			}, 50000, 200000, false)
			checkLinearCase("link_rel_quoted_tokens", func(n int) (string, string, string) {
				reps := n / 4
				half := reps / 2
				rel := "next tstart " + strings.Repeat("ext ", half) + "tmid " + strings.Repeat("ext ", reps-half) + "tend"
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2&tag=reltok>; rel=\"" + rel + "\"\r\n\r\n"
				return hdr, baseRefURL, baseRefURL + "?page=2&tag=reltok"
			}, 50000, 200000, false)
			checkLinearCase("link_rel_quoted_escapes", func(n int) (string, string, string) {
				pairs := n / 2
				half := pairs / 2
				rel := `next \E\0 ` + strings.Repeat(`\e`, half) + ` \M\1 ` + strings.Repeat(`\e`, pairs-half) + ` \Z\9`
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2&tag=relesc>; rel=\"" + rel + "\"\r\n\r\n"
				return hdr, baseRefURL, baseRefURL + "?page=2&tag=relesc"
			}, 25000, 100000, false)
			checkLinearCase("link_pct_decode_query", func(n int) (string, string, string) {
				pairs := n / 4
				half := pairs / 2
				cursor := "c0" + strings.Repeat("%20x", half) + "%2Fmid%2F" + strings.Repeat("%20y", pairs-half) + "cend"
				atEnc := "t0" + strings.Repeat("%41x", half) + "%2Fmid%2F" + strings.Repeat("%41y", pairs-half) + "tend"
				atDec := "t0" + strings.Repeat("Ax", half) + "/mid/" + strings.Repeat("Ay", pairs-half) + "tend"
				q := "?cursor=" + cursor + "&artifactType=" + atEnc
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + q + ">; rel=\"next\"\r\n\r\n"
				return hdr, baseRefURL + "?artifactType=" + atDec, baseRefURL + q
			}, 50000, 200000, false)
			checkLinearCase("link_non_rel_closed_quote_after_rel", func(n int) (string, string, string) {
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2&tag=closed>; rel=\"next\"; foo=\"" + markedSeq("ustart", `U\"MID`, "uend", "x", n) + "\"\r\n\r\n"
				return hdr, baseRefURL, baseRefURL + "?page=2&tag=closed"
			}, 50000, 200000, false)
			checkLinearCase("invalid_200k_link_non_rel_unclosed_quote", func(n int) (string, string, string) {
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?page=2&tag=open>; rel=\"next\"; foo=\"" + markedSeq("ustart", "UMID", "uend", "x", n) + "\r\n\r\n"
				return hdr, baseRefURL, ""
			}, 50000, 200000, true)
			checkLinearCase("link_remove_dot_segments_60k", func(n int) (string, string, string) {
				hdr := "HTTP/2 200\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers" + strings.Repeat("/x/..", n) + "/" + wantDigest + "?page=2>; rel=\"next\"\r\n\r\n"
				return hdr, baseRefURL, baseRefURL + "?page=2"
			}, 15000, 60000, false)

			// Exact coalesced output verification across >4096-byte obs-fold boundary markers.
			var markFoldRaw, markFoldWant strings.Builder
			markFoldRaw.WriteString("HTTP/2 200\r\nX-Marked: M00")
			markFoldWant.WriteString("X-Marked: M00")
			for i := range 20000 {
				if i%4096 == 0 || i == 19999 {
					seg := fmt.Sprintf(" [B%05d]", i)
					markFoldRaw.WriteString("\r\n" + seg)
					markFoldWant.WriteString(seg)
				} else {
					markFoldRaw.WriteString("\r\n k")
					markFoldWant.WriteString(" k")
				}
			}
			markFoldRaw.WriteString("\r\n\r\n")
			markFoldWant.WriteString("\n")
			if gotMarked, err := runFinalHdr(markFoldRaw.String()); err != nil || gotMarked != markFoldWant.String() {
				t.Errorf("%s marked obs-fold exact coalesced output mismatch: err=%v len=(%d vs %d)", r.name, err, len(gotMarked), markFoldWant.Len())
			}
			if gotEOF, err := runFinalHdr("X-Fold: a\r\n\t\r\n \r\n\tb\r\n"); err != nil || gotEOF != "X-Fold: a   b\n" {
				t.Fatalf("%s statusless EOF obs-fold = (%q, %v), want %q", r.name, gotEOF, err, "X-Fold: a   b\n")
			}
			if gotEmptyHdrs, err := runFinalHdr("HTTP/2 200\r\n\r\n"); err != nil || strings.TrimSpace(gotEmptyHdrs) != "" {
				t.Fatalf("%s extract_final_http_headers on headerless 200 = (%q, %v), want empty nil", r.name, gotEmptyHdrs, err)
			}
			if gotTrHdrs, err := runFinalHdr("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;\r\n dur=7\r\n\r\n"); err != nil || !strings.Contains(gotTrHdrs, "Docker-Content-Digest: "+wantDigest) || strings.Contains(gotTrHdrs, "Server-Timing: origin") {
				t.Fatalf("%s harmless trailer test = (%q, %v), want digest without trailer leak", r.name, gotTrHdrs, err)
			}
			if gotTrEOF, err := runFinalHdr("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked,\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n"); err != nil || !strings.Contains(gotTrEOF, "Docker-Content-Digest: "+wantDigest) || strings.Contains(gotTrEOF, "Server-Timing: origin") {
				t.Fatalf("%s LF-terminated trailer EOF test = (%q, %v), want digest without trailer leak", r.name, gotTrEOF, err)
			}

			runDigestAwk := func(input string) (string, error) {
				finalHdrs, err := runFinalHdr(input)
				if err != nil {
					return strings.TrimSpace(finalHdrs), err
				}
				args := append([]string(nil), r.args...)
				args = append(args, digestAwkProg)
				c := exec.Command(r.bin, args...)
				c.Env = append(os.Environ(), "LC_ALL=C")
				c.Stdin = strings.NewReader(finalHdrs)
				out, err := c.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			for _, goodDig := range []string{
				"HTTP/2 200\nDocker-Content-Digest: " + wantDigest + "\n\n",
				"HTTP/1.1 103 Early Hints\r\nDocker-Content-Digest: sha256:" + strings.Repeat("9", 64) + "\r\n\r\nHTTP/1.1 200 OK\r\ndocker-content-digest: " + wantDigest + "\r\n\r\n",
				"HTTP/1.1 200 OK\r\nDocker-Content-Digest:\r\n  " + wantDigest + "\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Note: caf\xe9\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nServer-Timing: origin;dur=7\r\n\r\n",
			} {
				if gotD, err := runDigestAwk(goodDig); err != nil || gotD != wantDigest {
					t.Fatalf("%s failed Docker-Content-Digest parse for %q: got=%q want=%q err=%v", r.name, goodDig, gotD, wantDigest, err)
				}
			}
			for _, badDig := range []string{
				"HTTP/1.1 103 Early Hints\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\nHTTP/1.1 200 OK\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\n",
				"HTTP/2 200\nDocker-Content-Digest: " + wantDigest + "\nDocker-Content-Digest: sha256:" + strings.Repeat("9", 64) + "\n\n",
				"HTTP/2 200\nDocker-Content-Digest:\n\n",
				"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\n",
			} {
				if gotD, err := runDigestAwk(badDig); err == nil {
					t.Fatalf("%s Docker-Content-Digest failed open on %q: got=%q", r.name, badDig, gotD)
				}
			}

			runFilterAwk := func(input string) (string, error) {
				finalHdrs, err := runFinalHdr(input)
				if err != nil {
					return strings.TrimSpace(finalHdrs), err
				}
				args := append([]string(nil), r.args...)
				args = append(args, filtersAwkProg)
				c := exec.Command(r.bin, args...)
				c.Env = append(os.Environ(), "LC_ALL=C")
				c.Stdin = strings.NewReader(finalHdrs)
				out, err := c.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			for _, cleanHdr := range []string{
				"HTTP/2 200\ncontent-type: application/vnd.oci.image.index.v1+json\n\n",
				"HTTP/1.1 103 Early Hints\r\nOCI-Filters-Applied: artifactType\r\nLink: </bad>; rel=\"next\"\r\n\r\nHTTP/1.1 200 OK\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Note: caf\xe9\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\n\r\nServer-Timing: origin;\r\n dur=7\r\n\r\n",
			} {
				if gotF, err := runFilterAwk(cleanHdr); err != nil || gotF != "" {
					t.Fatalf("%s filters check on clean final block %q = (%q, %v), want empty nil", r.name, cleanHdr, gotF, err)
				}
			}
			for _, fltHdr := range []string{
				"HTTP/2 200\nOCI-Filters-Applied: artifactType\n\n",
				"HTTP/2 200\noci-filters-applied: artifactType\n\n",
				"HTTP/2 200\nOCI-Filters-Applied:\n\n",
				"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\nOCI-Filters-Applied: artifactType\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Note: alpha\r\n   \r\nOCI-Filters-Applied:\r\n   artifactType\r\n\r\n",
				"HTTP/1.1 200 OK\r\nX-Fold: alpha\r\n \r\nOCI-Filters-Applied: artifactType\r\n\r\n",
			} {
				if gotF, err := runFilterAwk(fltHdr); err != nil || gotF == "" {
					t.Fatalf("%s failed to detect %q: got=%q err=%v", r.name, fltHdr, gotF, err)
				}
			}
		})
	}
}

func TestReleaseWorkflowInstallsPrerequisitesAndResolvesManifestDigest(t *testing.T) {
	b := readSupplyChainBundle(t)
	if _, err := checkSupplyChainBundle(b); err != nil {
		t.Fatal(err)
	}
	collectorVersion, _ := testsupport.CollectorVersionsFromGoMod(t, "go.mod")
	var scripts string
	for _, step := range b.wf.Jobs.Release.Steps {
		scripts += step.Run + "\n"
	}
	for _, want := range []string{"go.opentelemetry.io/collector/cmd/builder@" + collectorVersion, "ocb version", "syft version", "cosign version"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("release prerequisites missing %q", want)
		}
	}
	if !strings.Contains(testsupport.ReadRepoText(t, "example/otelcol-builder-release.yaml"), "replaces:") {
		t.Error("release builder manifest must replace the module with the checkout")
	}
}

func TestReleaseWorkflowConditionsAndInputs(t *testing.T) {
	for _, key := range []string{"release_dedup_guard", "reconcile_container", "build", "manifest_digest", "verify_container_sig", "verify_container_provenance", "binary_provenance", "changelog_file", "changelog_provenance", "container_sbom", "stage_exit_gate_assets", "exit_gate_auth", "exit_gate_gcloud"} {
		for _, condition := range []any{false, "${{ false }}"} {
			t.Run(fmt.Sprintf("disabled_%s_%v", key, condition), func(t *testing.T) {
				b := readSupplyChainBundle(t)
				for i, step := range b.wf.Jobs.Release.Steps {
					if step.ID == key ||
						key == "verify_container_sig" && step.Name == "Verify signed container manifest" ||
						key == "binary_provenance" && step.With["subject-path"] == "dist/checksums.txt" ||
						key == "changelog_provenance" && step.ID == "changelog_provenance" ||
						key == "exit_gate_auth" && step.Uses == gcpAuthV3 ||
						key == "exit_gate_gcloud" && step.Uses == gcpSetupGcloudV3 {
						b.wf.Jobs.Release.Steps[i].If = condition
					}
				}
				if _, err := checkSupplyChainBundle(b); err == nil {
					t.Fatal("accepted disabled release protection")
				}
			})
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*supplyChainBundle)
	}{
		{"container_provenance drops reuse skip guard", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].With["subject-digest"] != nil {
					b.wf.Jobs.Release.Steps[i].If = nil
				}
			}
		}},
		{"container_provenance allows reused container_needs_attestation", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].With["subject-digest"] != nil {
					b.wf.Jobs.Release.Steps[i].If = "${{ steps.reconcile_container.outputs.container_exists != 'true' || steps.reconcile_container.outputs.container_needs_attestation == 'true' }}"
				}
			}
		}},
		{"reconcile_container emits container_needs_attestation", func(b *supplyChainBundle) {
			b.scripts[releaseReconcileScriptPath] += "\necho container_needs_attestation=true\n"
		}},
		{"run step exceeds maxWorkflowRunStepChars", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Preflight.Steps {
				if b.wf.Jobs.Preflight.Steps[i].ID == "verify_ref" {
					b.wf.Jobs.Preflight.Steps[i].Run += "\n# " + strings.Repeat("x", maxWorkflowRunStepChars)
				}
			}
		}},
		{"check_submission appends || true to entrypoint", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Preflight.Steps {
				if b.wf.Jobs.Preflight.Steps[i].ID == "check_submission" {
					b.wf.Jobs.Preflight.Steps[i].Run += " || true"
				}
			}
		}},
		{"promote-latest drops promote_eligible gate", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.If = strings.ReplaceAll(fmt.Sprint(b.wf.Jobs.PromoteLatest.If), "needs.preflight.outputs.promote_eligible == 'true' && ", "")
		}},
		{"promote_latest drops git ls-remote remote check", func(b *supplyChainBundle) {
			b.scripts[releasePromoteScriptPath] = strings.ReplaceAll(b.scripts[releasePromoteScriptPath], "git ls-remote --tags origin", "git tag -l 'v*'")
		}},
		{"verify_container_provenance missing GH_TOKEN", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "verify_container_provenance" {
					delete(b.wf.Jobs.Release.Steps[i].Env, "GH_TOKEN")
				}
			}
		}},
		{"verify_container_sig uses wildcard identity regexp", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].Name == "Verify signed container manifest" {
					b.wf.Jobs.Release.Steps[i].Run = strings.ReplaceAll(b.wf.Jobs.Release.Steps[i].Run, "--certificate-identity=", "--certificate-identity-regexp=")
				}
			}
		}},
		{"reconcile_container uses wildcard identity regexp", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "--certificate-identity=", "--certificate-identity-regexp=")
		}},
		{"check_submission missing GHCR_TOKEN", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Preflight.Steps {
				if b.wf.Jobs.Preflight.Steps[i].ID == "check_submission" {
					delete(b.wf.Jobs.Preflight.Steps[i].Env, "GHCR_TOKEN")
				}
			}
		}},
		{"submit-exit-gate drops checkout", func(b *supplyChainBundle) {
			kept := b.wf.Jobs.SubmitExitGate.Steps[:0]
			for _, s := range b.wf.Jobs.SubmitExitGate.Steps {
				if s.Uses != checkoutActionV7 {
					kept = append(kept, s)
				}
			}
			b.wf.Jobs.SubmitExitGate.Steps = kept
		}},
		{"submit-exit-gate drops persist-credentials false", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.SubmitExitGate.Steps {
				if b.wf.Jobs.SubmitExitGate.Steps[i].Uses == checkoutActionV7 {
					delete(b.wf.Jobs.SubmitExitGate.Steps[i].With, "persist-credentials")
				}
			}
		}},
		{"submit-exit-gate drops attestations read", func(b *supplyChainBundle) {
			delete(b.wf.Jobs.SubmitExitGate.Permissions, "attestations")
		}},
		{"submit-exit-gate missing GH_TOKEN", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.SubmitExitGate.Steps {
				if b.wf.Jobs.SubmitExitGate.Steps[i].ID == "exit_gate_submit" {
					delete(b.wf.Jobs.SubmitExitGate.Steps[i].Env, "GH_TOKEN")
				}
			}
		}},
		{"submit-exit-gate missing GITHUB_REPOSITORY", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.SubmitExitGate.Steps {
				if b.wf.Jobs.SubmitExitGate.Steps[i].ID == "exit_gate_submit" {
					delete(b.wf.Jobs.SubmitExitGate.Steps[i].Env, "GITHUB_REPOSITORY")
				}
			}
		}},
		{"submit-exit-gate drops origin tag check", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.ReplaceAll(b.scripts[releaseSubmitScriptPath], "verify_origin_release_tag", "# skipped")
		}},
		{"submit-exit-gate drops changelog attestation verify", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.ReplaceAll(b.scripts[releaseSubmitScriptPath], "verify_changelog_attestation", "# skipped")
		}},
		{"preflight drops changelog attestation verify", func(b *supplyChainBundle) {
			b.scripts[releasePreflightScriptPath] = strings.ReplaceAll(b.scripts[releasePreflightScriptPath], "verify_changelog_attestation", "# skipped")
		}},
		{"preflight ignores manifest validation error with || true", func(b *supplyChainBundle) {
			b.scripts[releasePreflightScriptPath] = strings.Replace(b.scripts[releasePreflightScriptPath], `"${commit_short}")`, `"${commit_short}" || true)`, 1)
		}},
		{"submit-exit-gate ignores manifest validation error with || true", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.Replace(b.scripts[releaseSubmitScriptPath], `"${commit_short}")`, `"${commit_short}" || true)`, 1)
		}},
		{"referrers check defaults missing manifests to []", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "(.manifests | type)", "((.manifests // []) | type)")
		}},
		{"referrers check drops Link pagination helper", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "extract_next_referrers_url", "# skipped")
		}},
		{"submit-exit-gate drops cosign installer", func(b *supplyChainBundle) {
			kept := b.wf.Jobs.SubmitExitGate.Steps[:0]
			for _, s := range b.wf.Jobs.SubmitExitGate.Steps {
				if !strings.HasPrefix(s.Uses, "sigstore/cosign-installer@") {
					kept = append(kept, s)
				}
			}
			b.wf.Jobs.SubmitExitGate.Steps = kept
		}},
		{"submit-exit-gate exit_gate_submit precedes cosign", func(b *supplyChainBundle) {
			cosignIdx, subIdx := -1, -1
			for i, s := range b.wf.Jobs.SubmitExitGate.Steps {
				switch {
				case strings.HasPrefix(s.Uses, "sigstore/cosign-installer@"):
					cosignIdx = i
				case s.ID == "exit_gate_submit":
					subIdx = i
				}
			}
			b.wf.Jobs.SubmitExitGate.Steps[cosignIdx], b.wf.Jobs.SubmitExitGate.Steps[subIdx] = b.wf.Jobs.SubmitExitGate.Steps[subIdx], b.wf.Jobs.SubmitExitGate.Steps[cosignIdx]
		}},
		{"promote-latest drops skip_duplicate branch", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.If = strings.ReplaceAll(fmt.Sprint(b.wf.Jobs.PromoteLatest.If), " || needs.preflight.outputs.action == 'skip_duplicate'", "")
		}},
		{"promote_latest missing COMMIT_SHA", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.PromoteLatest.Steps {
				if b.wf.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					delete(b.wf.Jobs.PromoteLatest.Steps[i].Env, "COMMIT_SHA")
				}
			}
		}},
		{"promote_latest uses wildcard identity regexp", func(b *supplyChainBundle) {
			b.scripts[releasePromoteScriptPath] = strings.ReplaceAll(b.scripts[releasePromoteScriptPath], "--certificate-identity=", "--certificate-identity-regexp=")
		}},
		{"wrong checksum path", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].With["subject-path"] == "dist/checksums.txt" {
					b.wf.Jobs.Release.Steps[i].With["subject-path"] = "dist/other.txt"
				}
			}
		}},
		{"wrong changelog provenance path", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "changelog_provenance" {
					b.wf.Jobs.Release.Steps[i].With["subject-path"] = "dist/CHANGELOG.md"
				}
			}
		}},
		{"verify_container_provenance missing COMMIT_SHA", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "verify_container_provenance" {
					delete(b.wf.Jobs.Release.Steps[i].Env, "COMMIT_SHA")
				}
			}
		}},
		{"verify_container_provenance drops --source-digest", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "verify_container_provenance" {
					b.wf.Jobs.Release.Steps[i].Run = strings.ReplaceAll(b.wf.Jobs.Release.Steps[i].Run, `--source-digest "${COMMIT_SHA}"`, "")
				}
			}
		}},
		{"changelog_file drops EXIT_GATE_CHANGELOG subject staging", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "changelog_file" {
					b.wf.Jobs.Release.Steps[i].Run = "echo exists=true >> \"${GITHUB_OUTPUT}\""
				}
			}
		}},
		{"inspect_ghcr_container_provenance drops cosign stderr redirect", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `"${RELEASE_GHCR_IMAGE}@${existing_digest}" >&2`, `"${RELEASE_GHCR_IMAGE}@${existing_digest}"`)
		}},
		{"inspect_ghcr_container_provenance drops --source-digest", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `--source-digest "${commit_sha}"`, "")
		}},
		{"promote_latest drops --source-digest", func(b *supplyChainBundle) {
			b.scripts[releasePromoteScriptPath] = strings.ReplaceAll(b.scripts[releasePromoteScriptPath], `--source-digest "${COMMIT_SHA}"`, "")
		}},
		{"verify_changelog_attestation drops EXIT_GATE_CHANGELOG subject check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `((.name // "") == "EXIT_GATE_CHANGELOG"`, `((.name // "") == "other"`)
		}},
		{"validate_existing_manifest drops version string type check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `| select(type == "string")`, "")
		}},
		{"preflight unguarded shopt -s inherit_errexit", func(b *supplyChainBundle) {
			b.scripts[releasePreflightScriptPath] = strings.ReplaceAll(b.scripts[releasePreflightScriptPath], wantBash44InheritGuard, "if true; then")
		}},
		{"common.sh uses Bash 4+ declare -A", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] += "\ndeclare -A seen_urls_map=()\n"
		}},
		{"common.sh uses unescaped / in awk regex literal", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `\057@-`, `/@-`)
		}},
		{"manifest_digest drops resolve_manifest_digest script invocation", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "manifest_digest" {
					b.wf.Jobs.Release.Steps[i].Run = "echo digest=sha256:abc >> \"$GITHUB_OUTPUT\""
				}
			}
		}},
		{"manifest_digest drops artifacts.json push digest verification", func(b *supplyChainBundle) {
			b.scripts[releaseResolveManifestDigestScriptPath] = strings.ReplaceAll(b.scripts[releaseResolveManifestDigestScriptPath], `"Docker Manifest"`, `"Docker Image"`)
		}},
		{"manifest_digest drops tag_digest agreement check", func(b *supplyChainBundle) {
			b.scripts[releaseResolveManifestDigestScriptPath] = strings.ReplaceAll(b.scripts[releaseResolveManifestDigestScriptPath], `"${tag_digest}" != "${pushed_digest}"`, `"" != ""`)
		}},
		{"query_ghcr_referrers_has_provenance drops slurp single-doc check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "jq -ser", "jq -er")
		}},
		{"query_ghcr_referrers_has_provenance drops descriptor validation", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "valid_descriptor", "is_obj_ignored")
		}},
		{"extract_next_referrers_url drops artifact_type_signature invariant", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "artifact_type_signature", "ignored_query_sig")
		}},
		{"extract_next_referrers_url drops strict clause_rel_count != 1 check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "clause_rel_count != 1", "0")
		}},
		{"validate_existing_manifest drops single-doc slurp check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "expected a single JSON document in Exit Gate manifest", "ok")
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "if length != 1 then", "if false then")
		}},
		{"validate_existing_manifest drops staging version binding", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "select(. == $expected_ver)", "select(length > 0)")
		}},
		{"query_ghcr_referrers_has_provenance drops OCI-Filters-Applied check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `check_referrers_filters_applied "${ref_hdr_file}" "${existing_digest}"`, "true")
		}},
		{"query_ghcr_referrers_has_provenance weakens SHA digest allowlist regex", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `\\A(sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})\\z`, `^[a-z0-9]+:[A-Fa-f0-9]{32,}$`)
		}},
		{"query_ghcr_referrers_has_provenance drops trailing-newline digest anchors", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `\\A(sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})\\z`, `^(sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})$`)
		}},
		{"extract_next_referrers_url drops valid_rfc3986_raw_path validation", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "valid_rfc3986_raw_path", "allow_raw_path")
		}},
		{"referrers helpers drop final HTTP response block isolation", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `extract_final_http_headers "${hdr_file}"`, `tr -d '\r' < "${hdr_file}"`)
		}},
		{"referrers helpers bypass final_headers capture", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `final_headers="$(extract_final_http_headers "${hdr_file}")"`, `final_headers="$(cat "${hdr_file}")"`)
		}},
		{"extract_next_referrers_url skips current_url validation on empty headers", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "if ! next_url=\"$(\n    printf '%s\\n' \"${final_headers}\" | LC_ALL=C awk", "if [ -n \"${final_headers}\" ] && ! next_url=\"$(\n    printf '%s\\n' \"${final_headers}\" | LC_ALL=C awk")
		}},
		{"extract_final_http_headers falls back to tr -d CR", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `LC_ALL=C awk`, `tr -d '\r' < "${hdr_file}" | awk`)
		}},
		{"extract_final_http_headers accepts truncated 1xx final status", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "last_status < 200", "0")
		}},
		{"extract_final_http_headers accepts sensitive Link trailer", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `tname == "link" || tname == "oci-filters-applied" || tname == "docker-content-digest"`, `0`)
		}},
		{"extract_final_http_headers skips trailer control-byte validation", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `has_disallowed_ctl($0)`, `0`)
		}},
		{"extract_final_http_headers opens trailers without framing eligibility", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `can_have_trailers = block_allows_trailers()`, `can_have_trailers = 1`)
		}},
		{"extract_final_http_headers skips final LF check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `last != "0a"`, `0`)
		}},
		{"extract_final_http_headers skips NUL hex check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `tok == "00"`, `0`)
		}},
		{"extract_final_http_headers drops od -v flag", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `od -An -v -tx1`, `od -An -tx1`)
		}},
		{"extract_final_http_headers drops subshell pipefail in hex check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "    set -o pipefail\n", "    true\n")
		}},
		{"extract_final_http_headers permits duplicate chunked transfer encoding", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `te_state["chunked_count"] == 1`, `te_state["chunked_count"] >= 1`)
		}},
		{"extract_final_http_headers permits parameterized chunked transfer encoding", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `if (has_param) {`, `if (0) {`)
		}},
		{"extract_final_http_headers permits parameterized standard compression transfer encoding", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `coding == "chunked" || coding == "gzip" || coding == "deflate" || coding == "compress" || coding == "x-gzip" || coding == "x-compress"`, `coding == "chunked"`)
		}},
		// Change-detection mutation probes verifying checkSupplyChainBundle's static parser-structure
		// pins fail closed on syntactic reverts; behavioral edge-case and scaling regressions are tested
		// across all awk engines in TestReleaseScriptsBaseline.
		{"parse_te_header reverts from windowed scan to per-char substr", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `owin = substr(fval, obase, 4096)`, `ch = substr(fval, pos, 1)`)
		}},
		{"parse_te_header shrinks outer window to 2048 despite comment decoy", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `owin = substr(fval, obase, 4096)`, "# owin = substr(fval, obase, 4096)\n          owin = substr(fval, obase, 2048)")
		}},
		{"extract_final_http_headers reverts obs-fold to quadratic lines append", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `fold_push(cont)`, `lines[n] = lines[n] cont`)
		}},
		{"fold carry stack reverts binary counter to byte length", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `fold_sz[fold_top] = 1`, `fold_sz[fold_top] = length(s)`)
		}},
		{"fold carry stack drops popped slot deletion", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `delete fold_stk[fold_top]`, `# kept fold_stk`)
		}},
		{"qbuf carry stack reverts binary counter to byte length", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `sz[st["top"]] = 1`, `sz[st["top"]] = length(s)`)
		}},
		{"qbuf carry stack drops popped slot deletion", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `delete stk[st["top"]]`, `# kept stk`)
		}},
		{"pct_decode reverts output coalescing to char-by-char append", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `qbuf_push(stk, sz, st, win)`, `res = res win`)
		}},
		{"pct_decode reverts from windowed scan", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `owin = substr(s, obase, 4096)`, `c = substr(s, obase, 1)`)
		}},
		{"valid_rfc3986_raw_path reverts from windowed scan", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `owin = substr(raw_p, obase, 4096)`, `ch = substr(raw_p, obase, 1)`)
		}},
		{"extract_next_referrers_url reverts Link quoted param coalescing", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `qbuf_push(qstk, qsz, qst, substr(win, 1, RLENGTH))`, `pval = pval win`)
		}},
		{"extract_next_referrers_url reverts Link URI coalescing", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `qbuf_push(ustk, usz, ust, tok_chunk)`, `uri = uri tok_chunk`)
		}},
		{"extract_next_referrers_url reverts Link line scan from windowed loop", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `owin = substr(line, obase, 4096)`, `ch = substr(line, obase, 1)`)
		}},
		{"extract_final_http_headers accepts unterminated status header block", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `(saw_status && (in_hdr || last_status < 200))`, `(saw_status && last_status < 200)`)
		}},
		{"extract_final_http_headers drops readable file check", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `if [ ! -r "${hdr_file}" ]; then`, "if false; then")
		}},
		{"extract_final_http_headers drops strict expect_status boundary", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "expect_status = 1", "expect_status = 0")
		}},
		{"probe_ghcr_manifest_digest bypasses extract_final_http_headers", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `final_hdrs="$(extract_final_http_headers "${hdr_file}")"`, `final_hdrs="$(cat "${hdr_file}")"`)
		}},
		{"resolve_rfc3986_target drops first-segment colon rejection", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `if (index(first_seg, ":") > 0) return ""`, `if (0) return ""`)
		}},
		{"list_tag_commit_manifests falls back to .name // empty", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], `| select(.noncurrent_time == null)`+"\n"+`        | .name`, `| select(.noncurrent_time == null)`+"\n"+`        | .name // empty`)
		}},
		{"release_dedup_guard falls back to .name // empty", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "release_dedup_guard" {
					b.wf.Jobs.Release.Steps[i].Run = strings.ReplaceAll(b.wf.Jobs.Release.Steps[i].Run, "| .name\n", "| .name // empty\n")
				}
			}
		}},
		{"submit-exit-gate drops required EXIT_GATE_CHANGELOG on submit_staged", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.ReplaceAll(b.scripts[releaseSubmitScriptPath], `required_files+=("EXIT_GATE_CHANGELOG")`, "true")
		}},
		{"submit-exit-gate reverts to unchecked conditional changelog query", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.ReplaceAll(b.scripts[releaseSubmitScriptPath], `if [ "${has_changelog}" = "true" ]; then`, `if printf '%s' "${ar_entries}" | jq -e 'any(.[]; .fname == "EXIT_GATE_CHANGELOG")' >/dev/null; then`)
		}},
		{"submit-exit-gate drops final verify_origin_release_tag before storage cp", func(b *supplyChainBundle) {
			call := `verify_origin_release_tag "origin" "${RELEASE_TAG}" "${COMMIT_SHA}"`
			s := b.scripts[releaseSubmitScriptPath]
			if idx := strings.LastIndex(s, call); idx >= 0 {
				b.scripts[releaseSubmitScriptPath] = s[:idx] + "# skipped" + s[idx+len(call):]
			}
		}},
		{"submit-exit-gate drops STAGING_VERSION binding", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.ReplaceAll(b.scripts[releaseSubmitScriptPath], `[ "${STAGING_VERSION}" != "${expected_staging_ver}" ]`, "false")
		}},
		{"changelog_provenance drops exists condition", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "changelog_provenance" {
					b.wf.Jobs.Release.Steps[i].If = nil
				}
			}
		}},
		{"changelog_provenance after stage_exit_gate_assets", func(b *supplyChainBundle) {
			clIdx, stIdx := -1, -1
			for i, s := range b.wf.Jobs.Release.Steps {
				switch s.ID {
				case "changelog_provenance":
					clIdx = i
				case "stage_exit_gate_assets":
					stIdx = i
				}
			}
			b.wf.Jobs.Release.Steps[clIdx], b.wf.Jobs.Release.Steps[stIdx] = b.wf.Jobs.Release.Steps[stIdx], b.wf.Jobs.Release.Steps[clIdx]
		}},
		{"disabled release job", func(b *supplyChainBundle) { b.wf.Jobs.Release.If = false }},
		{"unconditional release job drops preflight gate", func(b *supplyChainBundle) { b.wf.Jobs.Release.If = nil }},
		{"release job drops preflight dependency", func(b *supplyChainBundle) { b.wf.Jobs.Release.Needs = nil }},
		{"missing concurrency queue max", func(b *supplyChainBundle) { b.wf.Concurrency.Queue = "" }},
		{"concurrency cancel-in-progress true", func(b *supplyChainBundle) { b.wf.Concurrency.CancelInProgress = true }},
		{"disabled preflight job", func(b *supplyChainBundle) { b.wf.Jobs.Preflight.If = false }},
		{"preflight grants packages write", func(b *supplyChainBundle) {
			b.wf.Jobs.Preflight.Permissions["packages"] = "write"
		}},
		{"preflight drops packages read", func(b *supplyChainBundle) {
			delete(b.wf.Jobs.Preflight.Permissions, "packages")
		}},
		{"preflight drops attestations read", func(b *supplyChainBundle) {
			delete(b.wf.Jobs.Preflight.Permissions, "attestations")
		}},
		{"check_submission drops --bundle-from-oci", func(b *supplyChainBundle) {
			b.scripts[releaseCommonScriptPath] = strings.ReplaceAll(b.scripts[releaseCommonScriptPath], "--bundle-from-oci", "")
		}},
		{"preflight verify_ref disabled", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Preflight.Steps {
				if b.wf.Jobs.Preflight.Steps[i].ID == "verify_ref" {
					b.wf.Jobs.Preflight.Steps[i].If = false
				}
			}
		}},
		{"preflight check_submission disabled", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Preflight.Steps {
				if b.wf.Jobs.Preflight.Steps[i].ID == "check_submission" {
					b.wf.Jobs.Preflight.Steps[i].If = "${{ false }}"
				}
			}
		}},
		{"submit-exit-gate grants packages write", func(b *supplyChainBundle) {
			b.wf.Jobs.SubmitExitGate.Permissions["packages"] = "write"
		}},
		{"submit-exit-gate drops preflight gate", func(b *supplyChainBundle) {
			b.wf.Jobs.SubmitExitGate.If = "${{ always() }}"
		}},
		{"submit-exit-gate drops release dependency", func(b *supplyChainBundle) {
			b.wf.Jobs.SubmitExitGate.Needs = []string{"preflight"}
		}},
		{"submit-exit-gate exit_gate_submit disabled", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.SubmitExitGate.Steps {
				if b.wf.Jobs.SubmitExitGate.Steps[i].ID == "exit_gate_submit" {
					b.wf.Jobs.SubmitExitGate.Steps[i].If = false
				}
			}
		}},
		{"promote-latest wrong concurrency group", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.Concurrency.Group = "release-${{ github.ref_name }}"
		}},
		{"promote-latest cancel-in-progress true", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.Concurrency.CancelInProgress = true
		}},
		{"promote-latest missing concurrency queue max", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.Concurrency.Queue = ""
		}},
		{"promote-latest drops submit-exit-gate dependency", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.Needs = []string{"preflight", "release"}
		}},
		{"promote-latest grants id-token write", func(b *supplyChainBundle) {
			b.wf.Jobs.PromoteLatest.Permissions["id-token"] = "write"
		}},
		{"promote-latest drops attestations read", func(b *supplyChainBundle) {
			delete(b.wf.Jobs.PromoteLatest.Permissions, "attestations")
		}},
		{"promote-latest disabled step", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.PromoteLatest.Steps {
				if b.wf.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					b.wf.Jobs.PromoteLatest.Steps[i].If = "${{ false }}"
				}
			}
		}},
		{"promote_latest wrong shell", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.PromoteLatest.Steps {
				if b.wf.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					b.wf.Jobs.PromoteLatest.Steps[i].Shell = "sh"
				}
			}
		}},
		{"promote_latest wrong digest environment", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.PromoteLatest.Steps {
				if b.wf.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					b.wf.Jobs.PromoteLatest.Steps[i].Env["DIGEST"] = "${{ needs.release.outputs.digest }}"
				}
			}
		}},
		{"promote_latest wrong release tag environment", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.PromoteLatest.Steps {
				if b.wf.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					b.wf.Jobs.PromoteLatest.Steps[i].Env["RELEASE_TAG"] = "${{ github.ref_name }}"
				}
			}
		}},
		{"promote_latest precedes cosign", func(b *supplyChainBundle) {
			cosignIdx, promoIdx := -1, -1
			for i, s := range b.wf.Jobs.PromoteLatest.Steps {
				switch {
				case strings.HasPrefix(s.Uses, "sigstore/cosign-installer@"):
					cosignIdx = i
				case s.ID == "promote_latest":
					promoIdx = i
				}
			}
			b.wf.Jobs.PromoteLatest.Steps[cosignIdx], b.wf.Jobs.PromoteLatest.Steps[promoIdx] = b.wf.Jobs.PromoteLatest.Steps[promoIdx], b.wf.Jobs.PromoteLatest.Steps[cosignIdx]
		}},
		{"wrong digest environment", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "container_sbom" {
					b.wf.Jobs.Release.Steps[i].Env["DIGEST"] = "${{ steps.build.outputs.digest }}"
				}
			}
		}},
		{"build missing GORELEASER_CURRENT_TAG", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "build" {
					delete(b.wf.Jobs.Release.Steps[i].Env, "GORELEASER_CURRENT_TAG")
				}
			}
		}},
		{"build drops --skip=docker reconciliation arg", func(b *supplyChainBundle) {
			for i := range b.wf.Jobs.Release.Steps {
				if b.wf.Jobs.Release.Steps[i].ID == "build" {
					b.wf.Jobs.Release.Steps[i].With["args"] = "release --clean"
				}
			}
		}},
		{"reconcile_container after build", func(b *supplyChainBundle) {
			recIdx, buildIdx := -1, -1
			for i, s := range b.wf.Jobs.Release.Steps {
				switch s.ID {
				case "reconcile_container":
					recIdx = i
				case "build":
					buildIdx = i
				}
			}
			b.wf.Jobs.Release.Steps[recIdx], b.wf.Jobs.Release.Steps[buildIdx] = b.wf.Jobs.Release.Steps[buildIdx], b.wf.Jobs.Release.Steps[recIdx]
		}},
		{"stage_exit_gate_assets precedes container_sbom", func(b *supplyChainBundle) {
			sbomIdx, stageIdx := -1, -1
			for i, s := range b.wf.Jobs.Release.Steps {
				switch s.ID {
				case "container_sbom":
					sbomIdx = i
				case "stage_exit_gate_assets":
					stageIdx = i
				}
			}
			b.wf.Jobs.Release.Steps[sbomIdx], b.wf.Jobs.Release.Steps[stageIdx] = b.wf.Jobs.Release.Steps[stageIdx], b.wf.Jobs.Release.Steps[sbomIdx]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := readSupplyChainBundle(t)
			b.scripts = maps.Clone(b.scripts)
			tc.mutate(&b)
			if _, err := checkSupplyChainBundle(b); err == nil {
				t.Fatal("accepted broken release input")
			}
		})
	}
	for _, deletedID := range []string{"stage_exit_gate_assets", "release_dedup_guard", "reconcile_container", "verify_container_provenance", "changelog_file", "changelog_provenance"} {
		t.Run("deleted_release_"+deletedID, func(t *testing.T) {
			b := readSupplyChainBundle(t)
			kept := b.wf.Jobs.Release.Steps[:0]
			for _, step := range b.wf.Jobs.Release.Steps {
				if step.ID != deletedID {
					kept = append(kept, step)
				}
			}
			b.wf.Jobs.Release.Steps = kept
			if _, err := checkSupplyChainBundle(b); err == nil {
				t.Fatalf("accepted release workflow without %s step", deletedID)
			}
		})
	}
	t.Run("deleted_submit_exit_gate_step", func(t *testing.T) {
		b := readSupplyChainBundle(t)
		b.wf.Jobs.SubmitExitGate.Steps = nil
		if _, err := checkSupplyChainBundle(b); err == nil {
			t.Fatal("accepted workflow without exit_gate_submit step in submit-exit-gate")
		}
	})
	t.Run("deleted_promote_latest_step", func(t *testing.T) {
		b := readSupplyChainBundle(t)
		b.wf.Jobs.PromoteLatest.Steps = nil
		if _, err := checkSupplyChainBundle(b); err == nil {
			t.Fatal("accepted workflow without promote_latest step in promote-latest")
		}
	})
	// Quoting is YAML syntax, not part of the subject value.
	for _, subject := range []string{"'dist/checksums.txt'", "dist/checksums.txt"} {
		raw := strings.Replace(testsupport.ReadRepoText(t, ".github/workflows/release.yml"), `"dist/checksums.txt"`, subject, 1)
		raw = strings.Replace(raw, "push-to-registry: true", `push-to-registry: "true"`, 1)
		b := readSupplyChainBundle(t)
		if err := yaml.Unmarshal([]byte(raw), &b.wf); err != nil {
			t.Fatal(err)
		}
		if _, err := checkSupplyChainBundle(b); err != nil {
			t.Fatalf("equivalent YAML subject rejected: %v", err)
		}
	}
}

const releaseImage = "ghcr.io/googlecloudplatform/bq-otel-collector"

var releaseChildDigests = map[string]string{
	"linux/amd64": "sha256:" + strings.Repeat("a", 64),
	"linux/arm64": "sha256:" + strings.Repeat("b", 64),
}

func releaseIndex(t *testing.T) string {
	t.Helper()
	var manifests []any
	for _, arch := range []string{"arm64", "amd64"} { // Deliberately not sorted.
		manifests = append(manifests, map[string]any{
			"digest":   releaseChildDigests["linux/"+arch],
			"platform": map[string]string{"os": "linux", "architecture": arch},
		})
	}
	manifests = append(manifests, map[string]any{
		"digest":   "sha256:" + strings.Repeat("d", 64),
		"platform": map[string]string{"os": "unknown", "architecture": "unknown"},
	})
	raw, err := json.Marshal(map[string]any{"manifests": manifests})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// Run the actual workflow shell with offline recording commands. Syft emits
// different inventories per platform; cosign snapshots each predicate at the
// moment it is attached/attested, so reusing the wrong file is observable.
func replayContainerSBOM(t *testing.T, script, index string) error {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"bin", "dist", "predicates"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(name, data string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("index.json", index, 0o600)
	for name, script := range map[string]string{
		"docker": `cat "$RELEASE_TEST_DIR/index.json"`,
		"syft": `source=$1
platform=""; output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --platform) shift; platform=$1 ;;
    -o) shift; output=${1#spdx-json=} ;;
  esac
  shift
done
printf '{"source":"%s","packages":[{"name":"%s-package"}]}\n' "$source" "$platform" > "$output"`,
		"cosign": `mode=$1
file=""; subject=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --sbom|--predicate) shift; file=$1 ;;
  esac
  subject=$1
  shift
done
cp "$file" "$RELEASE_TEST_DIR/predicates/${mode}-${subject##*@}.json"`,
	} {
		write("bin/"+name, "#!/bin/sh\nset -eu\nprintf '"+name+"\\t' >> \"$RELEASE_TEST_DIR/commands\"\nprintf '%s\\t' \"$@\" >> \"$RELEASE_TEST_DIR/commands\"\nprintf '\\n' >> \"$RELEASE_TEST_DIR/commands\"\n"+script+"\n", 0o700)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+filepath.Join(dir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RELEASE_TEST_DIR="+dir, "DIGEST=sha256:"+strings.Repeat("c", 64))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("SBOM script failed: %w: %s", err, output)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "commands"))
	if err != nil {
		return fmt.Errorf("SBOM script executed no release commands: %w", err)
	}
	var got [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		got = append(got, strings.Split(strings.TrimSuffix(line, "\t"), "\t"))
	}
	want := [][]string{{"docker", "buildx", "imagetools", "inspect", releaseImage + "@sha256:" + strings.Repeat("c", 64), "--raw"}}
	for _, platform := range []string{"linux/arm64", "linux/amd64"} {
		digest := releaseChildDigests[platform]
		subject := releaseImage + "@" + digest
		file := "dist/container-" + strings.ReplaceAll(platform, "/", "-") + ".spdx.json"
		want = append(want,
			[]string{"syft", "registry:" + subject, "--platform", platform, "-o", "spdx-json=" + file},
			[]string{"cosign", "attach", "sbom", "--sbom", file, "--type", "spdx", subject},
			[]string{"cosign", "attest", "--predicate", file, "--type", "spdxjson", "--yes", subject})
		for _, mode := range []string{"attach", "attest"} {
			raw, err := os.ReadFile(filepath.Join(dir, "predicates", mode+"-"+digest+".json"))
			if err != nil {
				return fmt.Errorf("missing %s predicate for %s child: %w", mode, platform, err)
			}
			var inventory struct {
				Source   string                  `json:"source"`
				Packages []struct{ Name string } `json:"packages"`
			}
			if err := json.Unmarshal(raw, &inventory); err != nil {
				return err
			}
			if inventory.Source != "registry:"+subject || len(inventory.Packages) != 1 || inventory.Packages[0].Name != platform+"-package" {
				return fmt.Errorf("%s predicate for %s describes another image: %s", mode, subject, raw)
			}
		}
	}
	// Independent platform operations may run in either order.
	canonical := func(commands [][]string) []string {
		result := make([]string, 0, len(commands))
		for _, args := range commands {
			result = append(result, strings.Join(args, "\t"))
		}
		slices.Sort(result)
		return result
	}
	if !slices.Equal(canonical(got), canonical(want)) {
		return fmt.Errorf("release commands = %q, want %q", got, want)
	}
	return nil
}

func TestReleaseContainerSBOMSubjects(t *testing.T) {
	step, err := checkSupplyChainBundle(readSupplyChainBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Dockers []struct{ Goos, Goarch string }
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".goreleaser.yaml")), &config); err != nil {
		t.Fatal(err)
	}
	var platforms []string
	for _, image := range config.Dockers {
		platforms = append(platforms, image.Goos+"/"+image.Goarch)
	}
	slices.Sort(platforms)
	if !slices.Equal(platforms, []string{"linux/amd64", "linux/arm64"}) {
		t.Fatalf("released platforms %v differ from SBOM fixtures; update workflow and fixtures together", platforms)
	}
	if err := replayContainerSBOM(t, step.Run, releaseIndex(t)); err != nil {
		t.Fatal(err)
	}
	spaced := strings.ReplaceAll(strings.ReplaceAll(step.Run, "syft ", "syft   "), "cosign ", "cosign   ")
	if err := replayContainerSBOM(t, spaced, releaseIndex(t)); err != nil {
		t.Fatalf("equivalent shell whitespace rejected: %v", err)
	}
}

func TestReleaseContainerSBOMRejectsBrokenScripts(t *testing.T) {
	step, err := checkSupplyChainBundle(readSupplyChainBundle(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, script, index string }{
		{"commented commands", "# " + strings.ReplaceAll(step.Run, "\n", "\n# "), releaseIndex(t)},
		{"wrong registry with decoy", strings.ReplaceAll(step.Run, releaseImage, "example.com/wrong") + "\n# " + releaseImage, releaseIndex(t)},
		{"wrong attachment with decoy", strings.Replace(step.Run, `--type spdx "${IMAGE}@${child_digest}"`, `--type spdx "example.com/wrong@${child_digest}"`, 1) + "\n# " + strings.ReplaceAll(step.Run, "\n", "\n# "), releaseIndex(t)},
		{"missing arm64 child", step.Run, strings.ReplaceAll(releaseIndex(t), `"architecture":"arm64"`, `"architecture":"s390x"`)},
		{"invalid child digest", step.Run, strings.ReplaceAll(releaseIndex(t), releaseChildDigests["linux/arm64"], "sha256:bad")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := replayContainerSBOM(t, tc.script, tc.index); err == nil {
				t.Fatal("accepted broken SBOM script or index")
			}
		})
	}
}

type exitGateReplayOpts struct {
	storeDir              string
	tag                   string
	commitSHA             string
	runID                 string
	forceResubmit         string
	action                string
	releaseStagingVersion string
	preflightStagingVer   string
	priorStagingVersion   string
	omitArchive           string
	extraDistFiles        []string
	extraChecksum         string
	omitChecksumLine      string
	malformDigestFor      string
	tamperFile            string
	emptySig              bool
	includeChangelog      bool
	existingManifest      string
	existingJSON          string
	listError             bool
	catError              bool
	arListError           bool
	arDeleteError         bool
	arDownloadError       bool
	withOrigin            bool
	annotatedTag          bool
	retagOrigin           bool
	withdrawOriginTag     bool
	dockerEnv             map[string]string
	extraBins             map[string]string
}

type exitGateReplayResult struct {
	err         error
	combinedOut string
	commands    []string
	dockerCalls [][]string
	cosignCalls [][]string
	curlCalls   [][]string
	ghCalls     [][]string
	stagedFiles []string
	manifest    map[string]any
	outputs     map[string]string
	summary     string
}

func extractGitHubErrorLines(output string) []string {
	var lines []string
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if strings.HasPrefix(line, "::error::") {
			lines = append(lines, line)
		}
	}
	return lines
}

func exactErrorLineRegexp(line string) *regexp.Regexp {
	return regexp.MustCompile("^" + regexp.QuoteMeta(line) + "$")
}

func matchGitHubErrorLines(output string, wantPattern *regexp.Regexp) (bool, []string) {
	errLines := extractGitHubErrorLines(output)
	if wantPattern == nil || len(errLines) != 1 {
		return false, errLines
	}
	return wantPattern.MatchString(errLines[0]), errLines
}

func TestGitHubErrorLineMatchingPrecision(t *testing.T) {
	wantMsg := "Malformed HTTP response headers while checking OCI-Filters-Applied for 'sha256:" + strings.Repeat("a", 64) + "'."
	wantPat := exactErrorLineRegexp("::error::" + wantMsg)

	if ok, _ := matchGitHubErrorLines("::error::"+wantMsg, wantPat); !ok {
		t.Fatalf("exact ::error:: line unexpectedly failed to match %s", wantPat)
	}
	for _, tc := range []struct {
		name string
		out  string
	}{
		{name: "notice_only", out: "::notice::" + wantMsg},
		{name: "plain_stderr_without_prefix", out: "stderr: " + wantMsg},
		{name: "error_mismatch_with_matching_notice", out: "::error::Different error\n::notice::" + wantMsg},
		{name: "error_with_suffix", out: "::error::" + wantMsg + " extra"},
		{name: "error_with_prefix", out: "prefix ::error::" + wantMsg},
		{name: "multiple_error_lines", out: "::error::" + wantMsg + "\n::error::unexpected second error"},
		{name: "empty_output", out: ""},
	} {
		if ok, errLines := matchGitHubErrorLines(tc.out, wantPat); ok {
			t.Fatalf("%s falsely satisfied ::error:: matcher (errLines=%q, out=%q)", tc.name, errLines, tc.out)
		}
	}
}

const gcpFakeGcloudStub = `#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$EXIT_GATE_TEST_DIR/gcloud.log"
bucket_prefix="gs://oss-exit-gate-prod-projects-bucket/"
gcs_root="$EXIT_GATE_STORE_DIR/gcs"
ar_root="$EXIT_GATE_STORE_DIR/ar"
	gcs_noncurrent_root="$EXIT_GATE_STORE_DIR/gcs_noncurrent"
mkdir -p "$gcs_root" "$gcs_noncurrent_root" "$ar_root"

obj_path_for_uri() {
  local uri="$1"
  printf '%s' "${uri#${bucket_prefix}}"
}

if [[ "$1" == "storage" && "$2" == "objects" && "$3" == "list" ]]; then
  if [[ "${EXIT_GATE_LIST_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.storage.objects.list) PERMISSION_DENIED" >&2
    exit 1
  fi
  uri="$4"
  fmt=""
  for arg in "$@"; do
    case "$arg" in
      --format=*) fmt="${arg#--format=}" ;;
    esac
  done
  obj="$(obj_path_for_uri "$uri")"
  dir_rel="$(dirname "$obj")"
  pat="$(basename "$obj")"
  found_any=0
  if [[ "$fmt" == json* ]]; then
    if [[ -n "${EXIT_GATE_LIST_JSON:-}" ]]; then
      printf '%s\n' "${EXIT_GATE_LIST_JSON}"
      exit 0
    fi
    entries_tmp="$(mktemp)"
    if [[ -d "$gcs_root/$dir_rel" ]]; then
      while IFS= read -r match_file; do
        [ -n "$match_file" ] || continue
        [[ "$match_file" == *.meta ]] && continue
        jq -n --arg name "${match_file#$gcs_root/}" '{name: $name}' >> "$entries_tmp"
        found_any=1
      done < <(find "$gcs_root/$dir_rel" -maxdepth 1 -type f -name "$pat" | LC_ALL=C sort)
    fi
    if [[ -d "$gcs_noncurrent_root/$dir_rel" ]]; then
      while IFS= read -r match_file; do
        [ -n "$match_file" ] || continue
        [[ "$match_file" == *.meta ]] && continue
        jq -n --arg name "${match_file#$gcs_noncurrent_root/}" '{name: $name, noncurrent_time: "2026-11-21T12:00:00Z"}' >> "$entries_tmp"
      done < <(find "$gcs_noncurrent_root/$dir_rel" -maxdepth 1 -type f -name "$pat" | LC_ALL=C sort)
    fi
    if [[ "$found_any" -eq 0 && -n "${EXIT_GATE_EXISTING_MANIFEST:-}" ]]; then
      jq -n --arg name "${EXIT_GATE_EXISTING_MANIFEST}" '{name: $name}' >> "$entries_tmp"
    fi
    jq -s '.' "$entries_tmp"
    rm -f "$entries_tmp"
    exit 0
  fi
  if [[ -d "$gcs_root/$dir_rel" ]]; then
    while IFS= read -r match_file; do
      [ -n "$match_file" ] || continue
      [[ "$match_file" == *.meta ]] && continue
      echo "${match_file#$gcs_root/}"
      found_any=1
    done < <(find "$gcs_root/$dir_rel" -maxdepth 1 -type f -name "$pat" | LC_ALL=C sort)
  fi
  if [[ "$found_any" -eq 0 && -n "${EXIT_GATE_EXISTING_MANIFEST:-}" ]]; then
    echo "${EXIT_GATE_EXISTING_MANIFEST}"
  fi
  exit 0
fi

if [[ "$1" == "storage" && "$2" == "objects" && "$3" == "describe" ]]; then
  if [[ "${EXIT_GATE_DESCRIBE_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.storage.objects.describe) PERMISSION_DENIED" >&2
    exit 1
  fi
  uri="$4"
  obj="$(obj_path_for_uri "$uri")"
  if [[ ! -f "$gcs_root/$obj" ]]; then
    if [[ -n "${EXIT_GATE_EXISTING_MANIFEST:-}" && "$obj" == "${EXIT_GATE_EXISTING_MANIFEST}" ]]; then
      printf 'null\n'
      exit 0
    fi
    echo "ERROR: (gcloud.storage.objects.describe) NotFound: $uri" >&2
    exit 1
  fi
  if [[ -n "${EXIT_GATE_DESCRIBE_BODY:-}" ]]; then
    printf '%s\n' "${EXIT_GATE_DESCRIBE_BODY}"
    exit 0
  fi
  if [[ -f "$gcs_root/$obj.meta" ]]; then
    cat "$gcs_root/$obj.meta"
  else
    printf 'null\n'
  fi
  exit 0
fi

if [[ "$1" == "storage" && "$2" == "cat" ]]; then
  if [[ "${EXIT_GATE_CAT_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.storage.cat) PERMISSION_DENIED" >&2
    exit 1
  fi
  uri="$3"
  obj="$(obj_path_for_uri "$uri")"
  if [[ -f "$gcs_root/$obj" ]]; then
    cat "$gcs_root/$obj"
    exit 0
  fi
  echo "ERROR: (gcloud.storage.cat) NotFound: $uri" >&2
  exit 1
fi

if [[ "$1" == "artifacts" && "$2" == "files" && "$3" == "list" ]]; then
  if [[ "${EXIT_GATE_AR_LIST_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.artifacts.files.list) PERMISSION_DENIED" >&2
    exit 1
  fi
  ver=""
  fmt=""
  for arg in "$@"; do
    case "$arg" in
      --version=*) ver="${arg#--version=}" ;;
      --format=*) fmt="${arg#--format=}" ;;
    esac
  done
  if [[ "$fmt" == "json" ]]; then
    if [[ "${EXIT_GATE_AR_MISSING_HASH:-0}" == "1" ]]; then
      printf '[{"name":"projects/oss-exit-gate-prod/locations/us/repositories/bq-otel-exporter--githubreleases/files/bq-otel-exporter:%s:checksums.txt"}]\n' "$ver"
      exit 0
    fi
    if [[ -n "$ver" && -d "$ar_root/$ver" ]]; then
      entries_tmp="$(mktemp)"
      while IFS= read -r f; do
        [ -n "$f" ] || continue
        base="$(basename "$f")"
        sha="$(sha256sum "$f" | awk '{ print $1 }')"
        if [[ "${EXIT_GATE_AR_UPPERCASE_HEX:-0}" == "1" ]]; then
          sha="$(printf '%s' "$sha" | tr 'a-f' 'A-F')"
        elif [[ "${EXIT_GATE_AR_BASE64_STD:-0}" == "1" ]]; then
          hex_esc=""
          for ((hi=0; hi<64; hi+=2)); do
            hex_esc+="\\x${sha:hi:2}"
          done
          sha="$(printf '%b' "$hex_esc" | base64 | tr -d '\r\n')"
        elif [[ "${EXIT_GATE_AR_BASE64_URL:-0}" == "1" ]]; then
          hex_esc=""
          for ((hi=0; hi<64; hi+=2)); do
            hex_esc+="\\x${sha:hi:2}"
          done
          sha="$(printf '%b' "$hex_esc" | base64 | tr -d '\r\n=' | tr '+/' '-_')"
        elif [[ "${EXIT_GATE_AR_BAD_BASE64:-0}" == "1" ]]; then
          sha="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB="
        fi
        res_name="projects/oss-exit-gate-prod/locations/us/repositories/bq-otel-exporter--githubreleases/files/bq-otel-exporter:${ver}:${base}"
        if [[ "${EXIT_GATE_AR_PERCENT3A:-0}" == "1" ]]; then
          res_name="projects/oss-exit-gate-prod/locations/us/repositories/bq-otel-exporter--githubreleases/files/bq-otel-exporter%3A${ver}%3A${base}"
        fi
        jq -n --arg name "$res_name" --arg sha "$sha" '{name: $name, hashes: [{type: "SHA256", value: $sha}]}' >> "$entries_tmp"
      done < <(find "$ar_root/$ver" -maxdepth 1 -type f | LC_ALL=C sort)
      jq -s '.' "$entries_tmp"
      rm -f "$entries_tmp"
    else
      printf '[]\n'
    fi
    exit 0
  fi
  if [[ -n "$ver" && -d "$ar_root/$ver" ]]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      base="$(basename "$f")"
      echo "projects/oss-exit-gate-prod/locations/us/repositories/bq-otel-exporter--githubreleases/files/bq-otel-exporter:${ver}:${base}"
    done < <(find "$ar_root/$ver" -maxdepth 1 -type f | LC_ALL=C sort)
  fi
  exit 0
fi

if [[ "$1" == "artifacts" && "$2" == "files" && "$3" == "download" ]]; then
  if [[ "${EXIT_GATE_AR_DOWNLOAD_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.artifacts.files.download) PERMISSION_DENIED" >&2
    exit 1
  fi
  shift 3
  dest=""
  local_fn=""
  allow_ow=0
  res_name=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --destination=*) dest="${1#--destination=}" ;;
      --local-filename=*) local_fn="${1#--local-filename=}" ;;
      --allow-overwrite) allow_ow=1 ;;
      --project=*|--location=*|--repository=*) ;;
      --*) echo "ERROR: unexpected download flag: $1" >&2; exit 2 ;;
      *) res_name="$1" ;;
    esac
    shift
  done
  if [[ -z "$dest" || -z "$res_name" ]]; then
    echo "ERROR: missing destination or resource name" >&2
    exit 2
  fi
  tail_part="${res_name##*/}"
  tail_part="${tail_part//%3A/:}"
  ver="${tail_part#*:}"
  base="${ver#*:}"
  ver="${ver%%:*}"
  if [[ ! -f "$ar_root/$ver/$base" ]]; then
    echo "ERROR: (gcloud.artifacts.files.download) NOT_FOUND: $res_name" >&2
    exit 1
  fi
  out_name="${local_fn:-$base}"
  if [[ -e "$dest/$out_name" && "$allow_ow" -ne 1 ]]; then
    echo "ERROR: destination exists without --allow-overwrite" >&2
    exit 1
  fi
  if [[ -n "${EXIT_GATE_AR_CORRUPT_DOWNLOAD_FILE:-}" && "$base" == "${EXIT_GATE_AR_CORRUPT_DOWNLOAD_FILE}" ]]; then
    printf 'tampered-downloaded-bytes\n' > "$dest/$out_name"
    exit 0
  fi
  cp "$ar_root/$ver/$base" "$dest/$out_name"
  exit 0
fi

if [[ "$1" == "artifacts" && "$2" == "versions" && "$3" == "delete" ]]; then
  if [[ "${EXIT_GATE_AR_DELETE_ERROR:-0}" == "1" ]]; then
    echo "ERROR: (gcloud.artifacts.versions.delete) PERMISSION_DENIED" >&2
    exit 1
  fi
  ver="${4:-}"
  if [[ -z "$ver" || "$ver" == --* ]]; then
    echo "ERROR: missing positional version for delete: $*" >&2
    exit 2
  fi
  if [[ ! -d "$ar_root/$ver" ]]; then
    echo "ERROR: (gcloud.artifacts.versions.delete) NOT_FOUND: $ver" >&2
    exit 1
  fi
  rm -rf "$ar_root/$ver"
  exit 0
fi

if [[ "$1" == "artifacts" && "$2" == "generic" && "$3" == "upload" ]]; then
  src=""
  ver="unknown"
  for arg in "$@"; do
    case "$arg" in
      --source-directory=*) src="${arg#--source-directory=}" ;;
      --version=*) ver="${arg#--version=}" ;;
    esac
  done
  ls -1 "$src" | LC_ALL=C sort > "$EXIT_GATE_TEST_DIR/staged.txt"
  mkdir -p "$ar_root/$ver"
  cp -a "$src/." "$ar_root/$ver/"
  exit 0
fi

if [[ "$1" == "storage" && "$2" == "cp" ]]; then
  if_gen_zero=0
  custom_meta=""
  src=""
  dst=""
  for arg in "$@"; do
    case "$arg" in
      --if-generation-match=0) if_gen_zero=1 ;;
      --custom-metadata=*) custom_meta="${arg#--custom-metadata=}" ;;
      storage|cp) ;;
      gs://*) dst="$arg" ;;
      *)
        if [[ -f "$arg" ]]; then
          src="$arg"
        fi
        ;;
    esac
  done
  if [[ -z "$src" || -z "$dst" ]]; then
    echo "ERROR: bad cp args: $*" >&2
    exit 2
  fi
  obj="$(obj_path_for_uri "$dst")"
  if [[ "$if_gen_zero" -eq 1 && -f "$gcs_root/$obj" ]]; then
    echo "ERROR: (gcloud.storage.cp) HTTPError 412: At least one of the pre-conditions you specified did not hold." >&2
    exit 1
  fi
  mkdir -p "$(dirname "$gcs_root/$obj")"
  cp "$src" "$gcs_root/$obj"
  cp "$src" "$EXIT_GATE_TEST_DIR/uploaded_manifest.json"
  if [[ -n "$custom_meta" ]]; then
    meta_k="${custom_meta%%=*}"
    meta_v="${custom_meta#*=}"
    jq -n --arg k "$meta_k" --arg v "$meta_v" '{custom_fields: {($k): $v}}' > "$gcs_root/$obj.meta"
  fi
  exit 0
fi

echo "unexpected gcloud invocation: $*" >&2
exit 2
`

const fakeDockerStub = `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_DOCKER_LOG:-}" ]]; then
  printf '%s\t' "$@" >> "${FAKE_DOCKER_LOG}"
  printf '\n' >> "${FAKE_DOCKER_LOG}"
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "imagetools" && "${3:-}" == "inspect" ]]; then
  ref="${4:-}"
  shift 4
  raw=0
  fmt=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --raw) raw=1 ;;
      --format) shift; fmt="${1:-}" ;;
    esac
    shift
  done
  if [[ "$raw" -eq 1 ]]; then
    printf '%s\n' "${FAKE_DOCKER_RAW_JSON}"
    exit 0
  fi
  if [[ "$fmt" == *"Manifest.Digest"* ]]; then
    if [[ "${FAKE_DOCKER_INSPECT_NOT_FOUND:-0}" == "1" ]]; then
      echo "ERROR: ${ref}: not found" >&2
      exit 1
    fi
    if [[ -n "${FAKE_DOCKER_INSPECT_ERR:-}" ]]; then
      echo "${FAKE_DOCKER_INSPECT_ERR}" >&2
      exit 1
    fi
    printf '%s\n' "${FAKE_DOCKER_DIGEST}"
    exit 0
  fi
  if [[ "$fmt" == *"org.opencontainers.image.revision"* ]]; then
    case "$ref" in
      *"${FAKE_DOCKER_AMD64_DIGEST}"*) printf '%s\n' "${FAKE_DOCKER_AMD64_COMMIT}" ;;
      *"${FAKE_DOCKER_ARM64_DIGEST}"*) printf '%s\n' "${FAKE_DOCKER_ARM64_COMMIT}" ;;
      *) echo "ERROR: unknown child digest $ref" >&2; exit 1 ;;
    esac
    exit 0
  fi
  if [[ "$fmt" == *"org.opencontainers.image.version"* ]]; then
    case "$ref" in
      *"${FAKE_DOCKER_AMD64_DIGEST}"*) printf '%s\n' "${FAKE_DOCKER_AMD64_VERSION:-}" ;;
      *"${FAKE_DOCKER_ARM64_DIGEST}"*) printf '%s\n' "${FAKE_DOCKER_ARM64_VERSION:-}" ;;
      *) echo "ERROR: unknown child digest $ref" >&2; exit 1 ;;
    esac
    exit 0
  fi
fi
if [[ "${1:-}" == "buildx" && "${2:-}" == "imagetools" && "${3:-}" == "create" ]]; then
  exit 0
fi
echo "unexpected docker invocation: $*" >&2
exit 2
`

const fakeCosignVerifyStub = `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_COSIGN_LOG:-}" ]]; then
  printf '%s\t' "$@" >> "${FAKE_COSIGN_LOG}"
  printf '\n' >> "${FAKE_COSIGN_LOG}"
fi
for arg in "$@"; do
  case "$arg" in
    --certificate-identity-regexp*)
      echo "ERROR: forbidden wildcard --certificate-identity-regexp: $arg" >&2
      exit 1
      ;;
    --certificate-identity=*)
      got_ident="${arg#--certificate-identity=}"
      if [[ -n "${RELEASE_TAG:-}" ]]; then
        want_ident="https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}"
        if [[ "$got_ident" != "$want_ident" ]]; then
          echo "ERROR: cosign identity mismatch: got $got_ident want $want_ident" >&2
          exit 1
        fi
      fi
      ;;
  esac
done
if [[ "${1:-}" == "verify" ]]; then
  if [[ -n "${FAKE_ORIGIN_DIR:-}" && -n "${FAKE_COSIGN_WITHDRAW_TAG:-}" ]]; then
    git -C "${FAKE_ORIGIN_DIR}" update-ref -d "refs/tags/${FAKE_COSIGN_WITHDRAW_TAG}"
  fi
  if [[ "${FAKE_COSIGN_FAIL:-0}" == "1" ]]; then
    echo "Error: no matching signatures" >&2
    exit 1
  fi
  # Real cosign verify emits a leading blank line followed by JSON on stdout.
  printf '\n[{"critical":{"identity":{"docker-reference":"ghcr.io/googlecloudplatform/bq-otel-collector"}}}]\n'
  exit 0
fi
if [[ "${1:-}" == "verify-blob" ]]; then
  cert_file=""
  sig_file=""
  blob_file=""
  shift
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --certificate) shift; cert_file="${1:-}" ;;
      --signature) shift; sig_file="${1:-}" ;;
      *) blob_file="$1" ;;
    esac
    shift
  done
  if [[ -z "$cert_file" || -z "$sig_file" || -z "$blob_file" || ! -s "$cert_file" || ! -s "$sig_file" || ! -f "$blob_file" ]]; then
    echo "Error: missing or empty verify-blob inputs" >&2
    exit 1
  fi
  if [[ "${FAKE_COSIGN_VERIFY_BLOB_FAIL:-0}" == "1" ]]; then
    echo "Error: verify-blob signature verification failed" >&2
    exit 1
  fi
  exit 0
fi
echo "unexpected cosign invocation: $*" >&2
exit 2
`

const fakeCurlStub = `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_CURL_LOG:-}" ]]; then
  printf '%s\t' "$@" >> "${FAKE_CURL_LOG}"
  printf '\n' >> "${FAKE_CURL_LOG}"
fi
hdr_from_stdin=0
hdr_out=""
body_out=""
write_fmt=""
url=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -H)
      shift
      if [[ "${1:-}" == "@-" ]]; then
        hdr_from_stdin=1
      elif [[ "${1:-}" == Authorization:* ]]; then
        echo "ERROR: Authorization header must be sent via -H @- stdin, not argv" >&2
        exit 2
      fi
      ;;
    -D) shift; hdr_out="${1:-}" ;;
    -o) shift; body_out="${1:-}" ;;
    -w) shift; write_fmt="${1:-}" ;;
    --connect-timeout|--max-time) shift ;;
    -fsS|-sS) ;;
    http://*|https://*) url="$1" ;;
    *) echo "unexpected curl arg: $1" >&2; exit 2 ;;
  esac
  shift
done
stdin_hdr=""
if [[ "$hdr_from_stdin" -eq 1 ]]; then
  stdin_hdr="$(cat)"
fi
if [[ "$url" == "https://ghcr.io/token?"* ]]; then
  if [[ "$stdin_hdr" != Authorization:\ Basic\ * ]]; then
    echo "ERROR: token request missing Authorization: Basic via stdin" >&2
    exit 2
  fi
  if [[ "${FAKE_CURL_TOKEN_FAIL:-0}" == "1" ]]; then
    echo "curl: (22) The requested URL returned error: 401" >&2
    exit 22
  fi
  printf '{"token":"test-ghcr-token"}\n'
  exit 0
fi
if [[ "$url" == https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/manifests/* ]]; then
  if [[ "$stdin_hdr" != Authorization:\ Bearer\ * ]]; then
    echo "ERROR: manifest request missing Authorization: Bearer via stdin" >&2
    exit 2
  fi
  if [[ "${FAKE_OCI_CURL_NET_ERR:-0}" == "1" ]]; then
    echo "curl: (7) Failed to connect" >&2
    exit 7
  fi
  tag_ref="${url##*/manifests/}"
  default_manifest_unknown_body='{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}'
  route_code="${FAKE_OCI_DEFAULT_CODE:-404}"
  route_digest="${FAKE_OCI_DEFAULT_DIGEST:-}"
  route_body="${FAKE_OCI_DEFAULT_BODY:-$default_manifest_unknown_body}"
  route_hdr_name="${FAKE_OCI_DIGEST_HEADER_NAME:-Docker-Content-Digest}"
  route_pre_hdr="${FAKE_OCI_MANIFEST_PRE_HEADERS:-}"
  route_raw_hdr="${FAKE_OCI_MANIFEST_RAW_HEADERS:-}"
  route_http_ver="${FAKE_OCI_MANIFEST_HTTP_VERSION:-HTTP/2}"
  if [[ -n "${FAKE_OCI_ROUTES:-}" ]]; then
    while IFS='|' read -r r_ref r_code r_digest r_body; do
      [[ -n "$r_ref" ]] || continue
      if [[ "$r_ref" == "$tag_ref" ]]; then
        route_code="$r_code"
        route_digest="$r_digest"
        route_body="$r_body"
        break
      fi
    done <<< "${FAKE_OCI_ROUTES}"
  fi
  if [[ -n "$hdr_out" ]]; then
    : > "$hdr_out"
    if [[ -n "${route_pre_hdr}" ]]; then
      printf '%b' "${route_pre_hdr}" >> "$hdr_out"
    fi
    printf '%s %s\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n' "$route_http_ver" "$route_code" >> "$hdr_out"
    if [[ -n "$route_digest" ]]; then
      printf '%s: %s\r\n' "$route_hdr_name" "$route_digest" >> "$hdr_out"
    fi
    if [[ -n "${route_raw_hdr}" ]]; then
      printf '%b' "${route_raw_hdr}" >> "$hdr_out"
    fi
    printf '\r\n' >> "$hdr_out"
  fi
  if [[ -n "$body_out" ]]; then
    printf '%s' "$route_body" > "$body_out"
  fi
  if [[ "$write_fmt" == "%{http_code}" ]]; then
    printf '%s' "$route_code"
  fi
  exit 0
fi
if [[ "$url" == https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/* ]]; then
  if [[ "$stdin_hdr" != Authorization:\ Bearer\ * ]]; then
    echo "ERROR: referrers request missing Authorization: Bearer via stdin" >&2
    exit 2
  fi
  if [[ "${FAKE_OCI_REFERRERS_NET_ERR:-0}" == "1" ]]; then
    echo "curl: (7) Failed to connect" >&2
    exit 7
  fi
  ref_code="${FAKE_OCI_REFERRERS_CODE:-200}"
  default_ref_body='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","size":512,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}'
  ref_body="${FAKE_OCI_REFERRERS_BODY:-$default_ref_body}"
  ref_link="${FAKE_OCI_REFERRERS_LINK:-}"
  ref_raw_hdr="${FAKE_OCI_REFERRERS_RAW_HEADERS:-}"
  ref_pre_hdr="${FAKE_OCI_REFERRERS_PRE_HEADERS:-}"
  ref_http_ver="${FAKE_OCI_REFERRERS_HTTP_VERSION:-HTTP/2}"
  if [[ -n "${FAKE_OCI_REFERRERS_ROUTES:-}" ]]; then
    route_matched=0
    while IFS='|' read -r r_key r_code r_body r_link r_hdr r_pre; do
      [[ -n "$r_key" ]] || continue
      if [[ "$url" == "$r_key" || "$url" == "https://ghcr.io$r_key" || "$url" == "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/$r_key" ]]; then
        ref_code="$r_code"
        ref_body="$r_body"
        ref_link="${r_link:-}"
        ref_raw_hdr="${r_hdr:-${FAKE_OCI_REFERRERS_RAW_HEADERS:-}}"
        ref_pre_hdr="${r_pre:-${FAKE_OCI_REFERRERS_PRE_HEADERS:-}}"
        route_matched=1
        break
      fi
    done <<< "${FAKE_OCI_REFERRERS_ROUTES}"
    if [[ "$route_matched" -eq 0 ]]; then
      ref_code="404"
      ref_body='{"errors":[{"code":"UNEXPECTED_REFERRERS_ROUTE","message":"unexpected referrers route"}]}'
      ref_link=""
      ref_raw_hdr=""
      ref_pre_hdr=""
    fi
  fi
  if [[ -n "$hdr_out" ]]; then
    : > "$hdr_out"
    if [[ -n "${ref_pre_hdr}" ]]; then
      printf '%b' "${ref_pre_hdr}" >> "$hdr_out"
    fi
    printf '%s %s\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n' "$ref_http_ver" "$ref_code" >> "$hdr_out"
    if [[ -n "$ref_link" ]]; then
      if [[ "$ref_link" == [Ll][Ii][Nn][Kk]:* ]]; then
        printf '%s\r\n' "$ref_link" >> "$hdr_out"
      else
        printf 'Link: %s\r\n' "$ref_link" >> "$hdr_out"
      fi
    fi
    if [[ -n "${ref_raw_hdr}" ]]; then
      printf '%b\r\n' "${ref_raw_hdr}" >> "$hdr_out"
    fi
    printf '\r\n' >> "$hdr_out"
  fi
  if [[ -n "$body_out" ]]; then
    printf '%s' "$ref_body" > "$body_out"
  fi
  if [[ "$write_fmt" == "%{http_code}" ]]; then
    printf '%s' "$ref_code"
  fi
  exit 0
fi
echo "unexpected curl URL: $url" >&2
exit 2
`

const fakeGhStub = `#!/usr/bin/env bash
set -euo pipefail
if [[ -n "${FAKE_GH_LOG:-}" ]]; then
  printf '%s\t' "$@" >> "${FAKE_GH_LOG}"
  printf '\n' >> "${FAKE_GH_LOG}"
fi
if [[ "${1:-}" == "attestation" && "${2:-}" == "verify" ]]; then
  shift 2
  subject="${1:-}"
  shift || true
  repo=""
  signer=""
  source_ref=""
  source_digest=""
  predicate_type=""
  format_out=""
  bundle_from_oci=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bundle-from-oci) bundle_from_oci=1 ;;
      --predicate-type) shift; predicate_type="${1:-}" ;;
      --repo) shift; repo="${1:-}" ;;
      --signer-workflow) shift; signer="${1:-}" ;;
      --source-ref) shift; source_ref="${1:-}" ;;
      --source-digest) shift; source_digest="${1:-}" ;;
      --format) shift; format_out="${1:-}" ;;
      *) echo "unexpected gh attestation verify arg: $1" >&2; exit 2 ;;
    esac
    shift
  done
  if [[ "$predicate_type" != "https://slsa.dev/provenance/v1" ]]; then
    echo "ERROR: gh attestation verify must pass --predicate-type https://slsa.dev/provenance/v1" >&2
    exit 2
  fi
  if [[ -z "$subject" || -z "$repo" || "$signer" != "${repo}/.github/workflows/release.yml" ]]; then
    echo "ERROR: invalid gh attestation verify arguments" >&2
    exit 2
  fi
  if [[ -z "$source_digest" ]]; then
    echo "ERROR: gh attestation verify must pass --source-digest" >&2
    exit 2
  fi
  if [[ -n "${RELEASE_TAG:-}" && "$source_ref" != "refs/tags/${RELEASE_TAG}" ]]; then
    echo "ERROR: gh attestation source-ref mismatch: $source_ref != refs/tags/${RELEASE_TAG}" >&2
    exit 1
  fi
  if [[ -n "${COMMIT_SHA:-}" && "$source_digest" != "${COMMIT_SHA}" ]]; then
    echo "ERROR: gh attestation source-digest mismatch: $source_digest != ${COMMIT_SHA}" >&2
    exit 1
  fi
  if [[ "$subject" == oci://* ]]; then
    if [[ "$bundle_from_oci" -ne 1 ]]; then
      echo "ERROR: gh attestation verify on OCI image must pass --bundle-from-oci" >&2
      exit 2
    fi
    case "${FAKE_GH_ATTESTATION_FAIL:-0}" in
      1)
        echo "ERROR: failed to verify attestation" >&2
        exit 1
        ;;
      missing)
        echo "Error: no attestations found for subject ${subject}" >&2
        exit 1
        ;;
      403)
        echo "HTTP 403 Forbidden: Resource not accessible by integration" >&2
        exit 1
        ;;
      502)
        echo "HTTP 502 Bad Gateway fetching attestations for ${subject}" >&2
        exit 1
        ;;
    esac
    exit 0
  fi

  if [[ "$bundle_from_oci" -ne 0 ]]; then
    echo "ERROR: --bundle-from-oci must not be passed when verifying file subject ${subject}" >&2
    exit 2
  fi
  if [[ ! -f "$subject" ]]; then
    echo "ERROR: attestation subject file does not exist: ${subject}" >&2
    exit 1
  fi
  if [[ "${FAKE_GH_CHANGELOG_ATTESTATION_FAIL:-0}" == "1" ]]; then
    echo "ERROR: failed to verify file attestation for ${subject}" >&2
    exit 1
  fi
  actual_sha="$(sha256sum "${subject}" | awk '{ print tolower($1) }')"
  if [[ -n "${FAKE_GH_ATTESTED_CHANGELOG_SHA256:-}" ]]; then
    if [[ "${actual_sha}" != "${FAKE_GH_ATTESTED_CHANGELOG_SHA256}" ]]; then
      echo "Error: no attestations found matching file ${subject} (sha256:${actual_sha})" >&2
      exit 1
    fi
  fi
  if [[ "$format_out" == "json" ]]; then
    subj_name="${FAKE_GH_ATTESTED_SUBJECT_NAME:-$(basename "${subject}")}"
    subj_sha="${FAKE_GH_JSON_SUBJECT_SHA256:-${actual_sha}}"
    jq -cn --arg name "$subj_name" --arg sha "$subj_sha" \
      '[{verificationResult:{statement:{predicateType:"https://slsa.dev/provenance/v1",subject:[{name:$name,digest:{sha256:$sha}}]}}}]'
  fi
  exit 0
fi
echo "unexpected gh invocation: $*" >&2
exit 2
`

const fakeGitOriginStub = `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "ls-remote" && "${2:-}" == "--tags" && "${3:-}" == "origin" ]]; then
  if [[ "${FAKE_GIT_LS_REMOTE_FAIL:-0}" == "1" ]]; then
    echo "fatal: could not read from remote repository" >&2
    exit 128
  fi
  if [[ -n "${FAKE_GIT_ORIGIN_TAG_COMMIT:-}" ]]; then
    printf '%s\trefs/tags/%s\n' "${FAKE_GIT_ORIGIN_TAG_COMMIT}" "${RELEASE_TAG}"
  elif [[ "${FAKE_GIT_ORIGIN_MISSING:-0}" != "1" ]]; then
    printf '%s\trefs/tags/%s\n' "${COMMIT_SHA}" "${RELEASE_TAG}"
  fi
  exit 0
fi
echo "unexpected fake git invocation: $*" >&2
exit 2
`

func stageReleaseScripts(t *testing.T, workDir string) {
	t.Helper()
	relDir := filepath.Join(workDir, "scripts", "release")
	if err := os.MkdirAll(relDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, rel := range releaseScriptPaths {
		mode := os.FileMode(0o644)
		if slices.Contains(executableReleaseScriptPaths, rel) {
			mode = 0o755
		}
		data := testsupport.ReadRepoText(t, rel)
		if err := os.WriteFile(filepath.Join(relDir, filepath.Base(rel)), []byte(data), mode); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFakeGcloud(t *testing.T, binDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(gcpFakeGcloudStub), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeFakeDockerAndCosign(t *testing.T, binDir string) {
	t.Helper()
	for name, body := range map[string]string{
		"docker": fakeDockerStub,
		"cosign": fakeCosignVerifyStub,
		"curl":   fakeCurlStub,
		"gh":     fakeGhStub,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
}

func deterministicStagingVersion(tag, commitSHA string) string {
	tagSum := sha256.Sum256([]byte(tag))
	return fmt.Sprintf("t-%s-%s", hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
}

func requiredArchiveFiles(tag string) []string {
	version := strings.TrimPrefix(tag, "v")
	archives := []string{
		fmt.Sprintf("otelcol-bq_%s_linux_amd64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_linux_arm64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_darwin_amd64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_darwin_arm64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_windows_amd64.zip", version),
	}
	files := make([]string, 0, 13)
	for _, arch := range archives {
		files = append(files, arch, arch+".sbom.json")
	}
	return append(files, "checksums.txt", "checksums.txt.sig", "checksums.txt.pem")
}

func seedARFiles(t *testing.T, storeDir, ver string, files []string) {
	t.Helper()
	verDir := filepath.Join(storeDir, "ar", ver)
	if err := os.MkdirAll(verDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(verDir, f), []byte("data-"+f+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func seedCompleteARVersion(t *testing.T, storeDir, tag, ver string, includeChangelog bool) {
	t.Helper()
	tmp := t.TempDir()
	prepareFakeDistDir(t, tmp, exitGateReplayOpts{tag: tag, includeChangelog: includeChangelog})
	verDir := filepath.Join(storeDir, "ar", ver)
	if err := os.MkdirAll(verDir, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(tmp, "dist"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		dstName := entry.Name()
		if dstName == "CHANGELOG.md" {
			dstName = "EXIT_GATE_CHANGELOG"
		}
		data, err := os.ReadFile(filepath.Join(tmp, "dist", entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(verDir, dstName), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func listStoreARFiles(t *testing.T, storeDir, ver string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(storeDir, "ar", ver))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

func assertExitGateManifest(t *testing.T, m map[string]any, wantTag, wantVersion string, wantPrerelease bool) {
	t.Helper()
	if m == nil {
		t.Fatal("manifest is nil")
	}
	pubAll, ok := m["publish_all"].(bool)
	if !ok || pubAll {
		t.Fatalf("manifest.publish_all = %v (%T), want false", m["publish_all"], m["publish_all"])
	}
	groups, ok := m["publishing_groups"].([]any)
	if !ok || len(groups) != 1 {
		t.Fatalf("manifest.publishing_groups = %v, want single group", m["publishing_groups"])
	}
	groupMap, ok := groups[0].(map[string]any)
	if !ok {
		t.Fatalf("publishing_groups[0] has unexpected type %T", groups[0])
	}
	pkgs, ok := groupMap["packages"].([]any)
	if !ok || len(pkgs) != 1 {
		t.Fatalf("publishing_groups[0].packages = %v, want single package", groupMap["packages"])
	}
	pkgMap, ok := pkgs[0].(map[string]any)
	if !ok {
		t.Fatalf("packages[0] has unexpected type %T", pkgs[0])
	}
	if pkgMap["name"] != "bq-otel-exporter" || pkgMap["version"] != wantVersion {
		t.Fatalf("packages[0] = %v, want {name:bq-otel-exporter version:%q}", pkgMap, wantVersion)
	}
	if wantVersion == wantTag {
		t.Fatalf("test bug: wantVersion %q equals release tag", wantVersion)
	}
	rcMap, ok := m["registry_config"].(map[string]any)
	if !ok {
		t.Fatalf("manifest missing registry_config: %v", m)
	}
	ghMap, ok := rcMap["github_releases"].(map[string]any)
	if !ok {
		t.Fatalf("registry_config missing github_releases: %v", rcMap)
	}
	wantTitle := "otelcol-bq " + strings.TrimPrefix(wantTag, "v")
	if ghMap["tag"] != wantTag || ghMap["name"] != wantTitle || ghMap["is_draft"] != true || ghMap["is_prerelease"] != wantPrerelease {
		t.Fatalf("unexpected github_releases = %v, want tag=%q name=%q is_draft=true is_prerelease=%v", ghMap, wantTag, wantTitle, wantPrerelease)
	}
}

func manifestRelativeObjectPath(manifestURI string) string {
	return strings.TrimPrefix(manifestURI, "gs://oss-exit-gate-prod-projects-bucket/")
}

func listStoreManifests(t *testing.T, storeDir string) []string {
	t.Helper()
	manifestsDir := filepath.Join(storeDir, "gcs", "bq-otel-exporter", "githubreleases", "manifests")
	entries, err := os.ReadDir(manifestsDir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	slices.Sort(names)
	return names
}

func readStoreManifest(t *testing.T, storeDir, manifestURI string) map[string]any {
	t.Helper()
	p := filepath.Join(storeDir, "gcs", filepath.FromSlash(manifestRelativeObjectPath(manifestURI)))
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading stored manifest %s: %v", manifestURI, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshaling stored manifest %s: %v", manifestURI, err)
	}
	return m
}

func writeStoreManifest(t *testing.T, storeDir, objRelPath, rawJSON string) {
	t.Helper()
	p := filepath.Join(storeDir, "gcs", filepath.FromSlash(objRelPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(rawJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeNoncurrentStoreManifest(t *testing.T, storeDir, objRelPath, rawJSON string) {
	t.Helper()
	p := filepath.Join(storeDir, "gcs_noncurrent", filepath.FromSlash(objRelPath))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(rawJSON), 0o600); err != nil {
		t.Fatal(err)
	}
}

func findJobStep(t *testing.T, jobName string, steps []supplyChainStep, stepID string) supplyChainStep {
	t.Helper()
	for _, step := range steps {
		if step.ID == stepID {
			return step
		}
	}
	t.Fatalf("release.yml job %s missing %s step", jobName, stepID)
	return supplyChainStep{}
}

func findReleaseStep(t *testing.T, stepID string) supplyChainStep {
	t.Helper()
	b := readSupplyChainBundle(t)
	if _, err := checkSupplyChainBundle(b); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "release", b.wf.Jobs.Release.Steps, stepID)
}

func findSubmitExitGateStep(t *testing.T) supplyChainStep {
	t.Helper()
	b := readSupplyChainBundle(t)
	if _, err := checkSupplyChainBundle(b); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "submit-exit-gate", b.wf.Jobs.SubmitExitGate.Steps, "exit_gate_submit")
}

func findPromoteLatestStep(t *testing.T) supplyChainStep {
	t.Helper()
	b := readSupplyChainBundle(t)
	if _, err := checkSupplyChainBundle(b); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "promote-latest", b.wf.Jobs.PromoteLatest.Steps, "promote_latest")
}

func readTabLog(t *testing.T, path string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var calls [][]string
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line != "" {
			calls = append(calls, strings.Split(strings.TrimSuffix(line, "\t"), "\t"))
		}
	}
	return calls
}

func prepareFakeDistDir(t *testing.T, dir string, opts exitGateReplayOpts) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, "dist"), 0o700); err != nil {
		t.Fatal(err)
	}
	version := strings.TrimPrefix(opts.tag, "v")
	archives := []string{
		fmt.Sprintf("otelcol-bq_%s_linux_amd64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_linux_arm64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_darwin_amd64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_darwin_arm64.tar.gz", version),
		fmt.Sprintf("otelcol-bq_%s_windows_amd64.zip", version),
	}
	writeFile := func(rel, data string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var checksumLines []string
	for _, arch := range archives {
		if arch != opts.omitArchive {
			archData := "archive-bytes-" + arch + "\n"
			writeFile(filepath.Join("dist", arch), archData)
			sum := sha256.Sum256([]byte(archData))
			digest := hex.EncodeToString(sum[:])
			if arch == opts.malformDigestFor {
				digest = digest[:len(digest)-1]
			}
			if arch == opts.tamperFile {
				writeFile(filepath.Join("dist", arch), archData+"tampered")
			}
			if arch != opts.omitChecksumLine {
				checksumLines = append(checksumLines, fmt.Sprintf("%s  %s", digest, arch))
			}
		}
		sbom := arch + ".sbom.json"
		sbomData := `{"bom":"` + arch + `"}` + "\n"
		writeFile(filepath.Join("dist", sbom), sbomData)
		sum := sha256.Sum256([]byte(sbomData))
		if sbom != opts.omitChecksumLine {
			checksumLines = append(checksumLines, fmt.Sprintf("%s  %s", hex.EncodeToString(sum[:]), sbom))
		}
	}
	for _, extra := range opts.extraDistFiles {
		writeFile(filepath.Join("dist", extra), "extra-"+extra+"\n")
	}
	if opts.extraChecksum != "" {
		checksumLines = append(checksumLines, strings.Repeat("a", 64)+"  "+opts.extraChecksum)
	}
	writeFile("dist/checksums.txt", strings.Join(checksumLines, "\n")+"\n")
	if opts.emptySig {
		writeFile("dist/checksums.txt.sig", "")
	} else {
		writeFile("dist/checksums.txt.sig", "sig-bytes\n")
	}
	writeFile("dist/checksums.txt.pem", "pem-bytes\n")
	if opts.includeChangelog {
		writeFile("dist/CHANGELOG.md", "## Release notes\n")
	}
}

func runWorkflowBashScript(t *testing.T, script string, opts exitGateReplayOpts, withDist bool) exitGateReplayResult {
	t.Helper()
	dir := t.TempDir()
	storeDir := opts.storeDir
	if storeDir == "" {
		storeDir = filepath.Join(dir, "store")
	}
	for _, name := range []string{"bin", "runner_temp"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	stageReleaseScripts(t, dir)
	if withDist {
		prepareFakeDistDir(t, dir, opts)
	}
	if opts.existingManifest != "" && opts.existingJSON != "" {
		writeStoreManifest(t, storeDir, opts.existingManifest, opts.existingJSON)
	}

	writeFakeGcloud(t, filepath.Join(dir, "bin"))
	writeFakeDockerAndCosign(t, filepath.Join(dir, "bin"))
	for binName, binBody := range opts.extraBins {
		if err := os.WriteFile(filepath.Join(dir, "bin", binName), []byte(binBody), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	commitSHA := opts.commitSHA
	if opts.withOrigin {
		originDir := filepath.Join(dir, "origin.git")
		seedDir := filepath.Join(dir, "seed")
		for _, sub := range []string{originDir, seedDir} {
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		gitEnv := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		runGit := func(workDir string, args ...string) string {
			t.Helper()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "git", args...)
			cmd.Dir = workDir
			cmd.Env = gitEnv
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %v in %s failed: %v: %s", args, workDir, err, out)
			}
			return strings.TrimSpace(string(out))
		}
		runGit(originDir, "init", "--bare", "-b", "main")
		runGit(seedDir, "init", "-b", "main")
		runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
		if opts.annotatedTag {
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "tag", "-a", opts.tag, "-m", "release "+opts.tag)
		} else {
			runGit(seedDir, "tag", opts.tag)
		}
		runGit(seedDir, "remote", "add", "origin", originDir)
		runGit(seedDir, "push", "origin", "main", "--tags")
		if commitSHA == "" {
			commitSHA = runGit(seedDir, "rev-parse", "HEAD")
		}
		runGit(dir, "init", "-q", "-b", "main")
		runGit(dir, "remote", "add", "origin", originDir)
		if opts.withdrawOriginTag {
			runGit(seedDir, "push", "origin", "--delete", opts.tag)
		}
		if opts.retagOrigin {
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "moved")
			runGit(seedDir, "tag", "-f", opts.tag)
			runGit(seedDir, "push", "--force", "origin", "refs/tags/"+opts.tag)
		}
	} else {
		if err := os.WriteFile(filepath.Join(dir, "bin", "git"), []byte(fakeGitOriginStub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	outPath := filepath.Join(dir, "github_output")
	sumPath := filepath.Join(dir, "github_summary")
	for _, p := range []string{outPath, sumPath} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	boolFlag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	action := opts.action
	if action == "" {
		action = "full_release"
	}
	dockerLogPath := filepath.Join(dir, "docker.log")
	cosignLogPath := filepath.Join(dir, "cosign.log")
	curlLogPath := filepath.Join(dir, "curl.log")
	ghLogPath := filepath.Join(dir, "gh.log")
	envMap := map[string]string{
		"PATH":                          filepath.Join(dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL":             "/dev/null",
		"GIT_CONFIG_SYSTEM":             "/dev/null",
		"RUNNER_TEMP":                   filepath.Join(dir, "runner_temp"),
		"GITHUB_OUTPUT":                 outPath,
		"GITHUB_STEP_SUMMARY":           sumPath,
		"RELEASE_TAG":                   opts.tag,
		"COMMIT_SHA":                    commitSHA,
		"RUN_ID":                        opts.runID,
		"FORCE_RESUBMIT":                opts.forceResubmit,
		"ACTION":                        action,
		"RELEASE_STAGING_VERSION":       opts.releaseStagingVersion,
		"PREFLIGHT_STAGING_VERSION":     opts.preflightStagingVer,
		"PRIOR_STAGING_VERSION":         opts.priorStagingVersion,
		"GHCR_ACTOR":                    "octocat",
		"GHCR_TOKEN":                    "test-ghcr-token",
		"GH_TOKEN":                      "test-gh-token",
		"GITHUB_REPOSITORY":             "GoogleCloudPlatform/BQ-OTEL-Exporter",
		"EXIT_GATE_TEST_DIR":            dir,
		"EXIT_GATE_STORE_DIR":           storeDir,
		"EXIT_GATE_EXISTING_MANIFEST":   opts.existingManifest,
		"EXIT_GATE_LIST_ERROR":          boolFlag(opts.listError),
		"EXIT_GATE_CAT_ERROR":           boolFlag(opts.catError),
		"EXIT_GATE_AR_LIST_ERROR":       boolFlag(opts.arListError),
		"EXIT_GATE_AR_DOWNLOAD_ERROR":   boolFlag(opts.arDownloadError),
		"EXIT_GATE_AR_DELETE_ERROR":     boolFlag(opts.arDeleteError),
		"FAKE_DOCKER_LOG":               dockerLogPath,
		"FAKE_COSIGN_LOG":               cosignLogPath,
		"FAKE_CURL_LOG":                 curlLogPath,
		"FAKE_GH_LOG":                   ghLogPath,
		"FAKE_DOCKER_DIGEST":            "sha256:" + strings.Repeat("c", 64),
		"FAKE_DOCKER_RAW_JSON":          releaseIndex(t),
		"FAKE_DOCKER_AMD64_DIGEST":      releaseChildDigests["linux/amd64"],
		"FAKE_DOCKER_ARM64_DIGEST":      releaseChildDigests["linux/arm64"],
		"FAKE_DOCKER_AMD64_COMMIT":      commitSHA,
		"FAKE_DOCKER_ARM64_COMMIT":      commitSHA,
		"FAKE_DOCKER_AMD64_VERSION":     strings.TrimPrefix(opts.tag, "v"),
		"FAKE_DOCKER_ARM64_VERSION":     strings.TrimPrefix(opts.tag, "v"),
		"FAKE_DOCKER_INSPECT_NOT_FOUND": "1",
		"FAKE_OCI_DEFAULT_CODE":         "404",
		"FAKE_OCI_DEFAULT_DIGEST":       "",
		"FAKE_OCI_DEFAULT_BODY":         `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`,
	}
	for k, v := range opts.dockerEnv {
		envMap[k] = v
	}
	env := append([]string(nil), os.Environ()...)
	for k, v := range envMap {
		env = append(env, k+"="+v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", script)
	cmd.Dir = dir
	cmd.Env = env
	combined, err := cmd.CombinedOutput()
	res := exitGateReplayResult{
		combinedOut: string(combined),
		outputs:     map[string]string{},
		dockerCalls: readTabLog(t, dockerLogPath),
		cosignCalls: readTabLog(t, cosignLogPath),
		curlCalls:   readTabLog(t, curlLogPath),
		ghCalls:     readTabLog(t, ghLogPath),
	}
	if err != nil {
		res.err = fmt.Errorf("%w: %s", err, combined)
	}
	if raw, rerr := os.ReadFile(filepath.Join(dir, "gcloud.log")); rerr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line != "" {
				res.commands = append(res.commands, line)
			}
		}
	}
	if raw, rerr := os.ReadFile(filepath.Join(dir, "staged.txt")); rerr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if line != "" {
				res.stagedFiles = append(res.stagedFiles, line)
			}
		}
	}
	if raw, rerr := os.ReadFile(filepath.Join(dir, "uploaded_manifest.json")); rerr == nil {
		var m map[string]any
		if uerr := json.Unmarshal(raw, &m); uerr != nil {
			t.Fatalf("uploaded manifest is invalid JSON: %v", uerr)
		}
		res.manifest = m
	}
	if raw, rerr := os.ReadFile(outPath); rerr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if k, v, ok := strings.Cut(line, "="); ok {
				res.outputs[k] = v
			}
		}
	}
	if raw, rerr := os.ReadFile(sumPath); rerr == nil {
		res.summary = string(raw)
	}
	return res
}

func replayStageAssets(t *testing.T, script string, opts exitGateReplayOpts) exitGateReplayResult {
	t.Helper()
	return runWorkflowBashScript(t, script, opts, true)
}

func replaySubmitExitGate(t *testing.T, script string, opts exitGateReplayOpts) exitGateReplayResult {
	t.Helper()
	return runWorkflowBashScript(t, script, opts, false)
}

func replayFullReleaseSubmit(t *testing.T, stageScript, submitScript string, opts exitGateReplayOpts) exitGateReplayResult {
	t.Helper()
	if opts.storeDir == "" {
		opts.storeDir = t.TempDir()
	}
	stageRes := replayStageAssets(t, stageScript, opts)
	if stageRes.err != nil {
		return stageRes
	}
	submitOpts := opts
	submitOpts.action = "full_release"
	submitOpts.releaseStagingVersion = stageRes.outputs["staging_version"]
	subRes := replaySubmitExitGate(t, submitScript, submitOpts)
	subRes.stagedFiles = stageRes.stagedFiles
	subRes.commands = append(stageRes.commands, subRes.commands...)
	return subRes
}

func TestReleaseExitGateSubmitScript(t *testing.T) {
	// Ensure .goreleaser.yaml disables direct GitHub release publishing whenever
	// Exit Gate handles publishing so the two paths cannot collide.
	var gr struct {
		Release struct {
			Disable bool `yaml:"disable"`
		} `yaml:"release"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".goreleaser.yaml")), &gr); err != nil {
		t.Fatal(err)
	}
	if !gr.Release.Disable {
		t.Fatal(".goreleaser.yaml must set release.disable: true when publishing via OSS Exit Gate")
	}

	stageStep := findReleaseStep(t, "stage_exit_gate_assets")
	submitStep := findSubmitExitGateStep(t)
	arVersionPattern := regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	commitSHA := "0123456789abcdef0123456789abcdef01234567"

	t.Run("stable_release_with_changelog", func(t *testing.T) {
		storeDir := t.TempDir()
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		res := replayFullReleaseSubmit(t, stageStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:         storeDir,
			tag:              "v0.2.0",
			commitSHA:        commitSHA,
			runID:            "987654321",
			forceResubmit:    "false",
			extraDistFiles:   []string{"otelcol-bq_0.2.0_linux_amd64_debug.tar.gz"},
			includeChangelog: true,
		})
		if res.err != nil {
			t.Fatalf("stable release replay failed: %v", res.err)
		}
		if len(res.stagedFiles) != 14 {
			t.Fatalf("staged file count = %d (%v), want 14 (13 assets + EXIT_GATE_CHANGELOG)", len(res.stagedFiles), res.stagedFiles)
		}
		if got := res.outputs["staging_version"]; got != wantVer || !arVersionPattern.MatchString(got) {
			t.Fatalf("staging_version = %q, want deterministic %q", got, wantVer)
		}
		if got := res.outputs["submission_status"]; got != "submitted" {
			t.Fatalf("submission_status = %q, want submitted", got)
		}
		if !strings.Contains(strings.Join(res.commands, "\n"), "storage cp --if-generation-match=0") {
			t.Errorf("expected create-only --if-generation-match=0 upload; commands=%v", res.commands)
		}
		if !strings.Contains(res.summary, "SUBMITTED (PENDING EXIT GATE)") {
			t.Errorf("summary missing pending Exit Gate marker: %q", res.summary)
		}
		assertExitGateManifest(t, res.manifest, "v0.2.0", wantVer, false)
	})

	t.Run("uppercase_prerelease_and_long_tag_stay_bounded_lowercase_in_ar", func(t *testing.T) {
		for _, tag := range []string{
			"v1.2.3-RC.1",
			"v1.2.3-RC." + strings.Repeat("a", 130),
		} {
			wantVer := deterministicStagingVersion(tag, commitSHA)
			res := replayFullReleaseSubmit(t, stageStep.Run, submitStep.Run, exitGateReplayOpts{
				tag:           tag,
				commitSHA:     commitSHA,
				runID:         "111222333",
				forceResubmit: "false",
			})
			if res.err != nil {
				t.Fatalf("tag %q failed: %v", tag, res.err)
			}
			ver := res.outputs["staging_version"]
			if ver != wantVer || !arVersionPattern.MatchString(ver) || len(ver) > 128 {
				t.Fatalf("tag %q produced invalid AR staging version %q (want %q)", tag, ver, wantVer)
			}
			if len(res.stagedFiles) != 13 {
				t.Fatalf("staged file count without changelog = %d, want 13", len(res.stagedFiles))
			}
			assertExitGateManifest(t, res.manifest, tag, wantVer, true)
		}
	})

	t.Run("stage_assets_skips_complete_ar_and_repairs_partial_or_unexpected_ar", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		req := requiredArchiveFiles("v0.2.0")

		// Seed complete verified 13-file AR package -> stage_exit_gate_assets skips delete & upload.
		seedCompleteARVersion(t, storeDir, "v0.2.0", ver, false)
		completeRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:  storeDir,
			tag:       "v0.2.0",
			commitSHA: commitSHA,
		})
		if completeRes.err != nil {
			t.Fatalf("complete AR staging check failed: %v", completeRes.err)
		}
		if completeRes.outputs["staging_version"] != ver {
			t.Fatalf("staging_version = %q, want %q", completeRes.outputs["staging_version"], ver)
		}
		for _, cmd := range completeRes.commands {
			if strings.HasPrefix(cmd, "artifacts versions delete") || strings.HasPrefix(cmd, "artifacts generic upload") {
				t.Fatalf("complete AR version unexpectedly mutated AR: %s", cmd)
			}
		}

		// Partial AR package (missing checksums.txt.pem) -> deletes partial version
		// and cleanly uploads all 13 verified files.
		partialStore := t.TempDir()
		seedARFiles(t, partialStore, ver, req[:5])
		repairRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:  partialStore,
			tag:       "v0.2.0",
			commitSHA: commitSHA,
		})
		if repairRes.err != nil {
			t.Fatalf("partial AR repair failed: %v", repairRes.err)
		}
		cmdJoined := strings.Join(repairRes.commands, "\n")
		delIdx := strings.Index(cmdJoined, "artifacts versions delete "+ver)
		upIdx := strings.Index(cmdJoined, "artifacts generic upload")
		if delIdx < 0 || upIdx < 0 || delIdx >= upIdx {
			t.Fatalf("expected delete before upload when repairing partial AR, commands:\n%s", cmdJoined)
		}
		if got := listStoreARFiles(t, partialStore, ver); len(got) != 13 {
			t.Fatalf("repaired AR file count = %d (%v), want 13", len(got), got)
		}

		// AR package with unexpected extra file -> deletes poisoned version and re-uploads exact inventory.
		extraStore := t.TempDir()
		seedCompleteARVersion(t, extraStore, "v0.2.0", ver, false)
		if err := os.WriteFile(filepath.Join(extraStore, "ar", ver, "rogue.tar.gz"), []byte("rogue\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		extraRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:  extraStore,
			tag:       "v0.2.0",
			commitSHA: commitSHA,
		})
		if extraRes.err != nil {
			t.Fatalf("unexpected-file AR repair failed: %v", extraRes.err)
		}
		if got := listStoreARFiles(t, extraStore, ver); len(got) != 13 || slices.Contains(got, "rogue.tar.gz") {
			t.Fatalf("repaired AR files = %v, want exact 13 without rogue.tar.gz", got)
		}

		// Local build produced dist/CHANGELOG.md, but existing AR only has the 13
		// core files (missing EXIT_GATE_CHANGELOG) -> deletes and uploads 14 files.
		missingCLStore := t.TempDir()
		seedCompleteARVersion(t, missingCLStore, "v0.2.0", ver, false)
		missingCLRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:         missingCLStore,
			tag:              "v0.2.0",
			commitSHA:        commitSHA,
			includeChangelog: true,
		})
		if missingCLRes.err != nil {
			t.Fatalf("missing EXIT_GATE_CHANGELOG repair failed: %v", missingCLRes.err)
		}
		if got := listStoreARFiles(t, missingCLStore, ver); len(got) != 14 || !slices.Contains(got, "EXIT_GATE_CHANGELOG") {
			t.Fatalf("repaired AR files = %v, want 14 including EXIT_GATE_CHANGELOG", got)
		}

		// AR has stale EXIT_GATE_CHANGELOG with wrong digest while dist/CHANGELOG.md
		// exists -> deletes stale version and uploads matching changelog.
		staleCLStore := t.TempDir()
		seedCompleteARVersion(t, staleCLStore, "v0.2.0", ver, true)
		if err := os.WriteFile(filepath.Join(staleCLStore, "ar", ver, "EXIT_GATE_CHANGELOG"), []byte("stale changelog\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		staleCLRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:         staleCLStore,
			tag:              "v0.2.0",
			commitSHA:        commitSHA,
			includeChangelog: true,
		})
		if staleCLRes.err != nil {
			t.Fatalf("stale EXIT_GATE_CHANGELOG repair failed: %v", staleCLRes.err)
		}
		gotCL, err := os.ReadFile(filepath.Join(staleCLStore, "ar", ver, "EXIT_GATE_CHANGELOG"))
		if err != nil || string(gotCL) != "## Release notes\n" {
			t.Fatalf("repaired EXIT_GATE_CHANGELOG = (%q, %v), want fresh release notes", string(gotCL), err)
		}

		// Local build has empty/absent changelog, while AR still holds an unexpected
		// leftover EXIT_GATE_CHANGELOG -> repairs back to 13 exact files.
		leftoverCLStore := t.TempDir()
		seedCompleteARVersion(t, leftoverCLStore, "v0.2.0", ver, true)
		leftoverRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:         leftoverCLStore,
			tag:              "v0.2.0",
			commitSHA:        commitSHA,
			includeChangelog: false,
		})
		if leftoverRes.err != nil {
			t.Fatalf("leftover EXIT_GATE_CHANGELOG repair failed: %v", leftoverRes.err)
		}
		if got := listStoreARFiles(t, leftoverCLStore, ver); len(got) != 13 || slices.Contains(got, "EXIT_GATE_CHANGELOG") {
			t.Fatalf("repaired AR files = %v, want exact 13 without EXIT_GATE_CHANGELOG", got)
		}
	})

	t.Run("stage_assets_preserves_complete_package_on_cosign_verifier_outage", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		seedCompleteARVersion(t, storeDir, "v0.2.0", ver, true)

		res := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:         storeDir,
			tag:              "v0.2.0",
			commitSHA:        commitSHA,
			includeChangelog: true,
			dockerEnv:        map[string]string{"FAKE_COSIGN_VERIFY_BLOB_FAIL": "1"},
		})
		if res.err == nil {
			t.Fatal("stage_exit_gate_assets succeeded despite cosign verify-blob outage")
		}
		if !strings.Contains(res.err.Error(), "staged package preserved") {
			t.Fatalf("expected indeterminate verifier preservation message, got: %v", res.err)
		}
		for _, cmd := range res.commands {
			if strings.HasPrefix(cmd, "artifacts versions delete") || strings.HasPrefix(cmd, "artifacts generic upload") {
				t.Fatalf("verifier outage wiped or re-uploaded complete AR package: %s", cmd)
			}
		}
		if got := listStoreARFiles(t, storeDir, ver); len(got) != 14 {
			t.Fatalf("preserved AR file count = %d (%v), want all 14 files intact", len(got), got)
		}
	})

	t.Run("dedup_skips_duplicate_upload_on_retry_and_uses_existing_staging_version", func(t *testing.T) {
		storeDir := t.TempDir()
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		first := replayFullReleaseSubmit(t, stageStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "987654321",
			forceResubmit: "false",
		})
		if first.err != nil {
			t.Fatalf("initial submit failed: %v", first.err)
		}
		res := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "987654321",
			forceResubmit:       "false",
			action:              "submit_staged",
			preflightStagingVer: wantVer,
		})
		if res.err != nil {
			t.Fatalf("dedup retry failed: %v", res.err)
		}
		if res.outputs["submission_status"] != "already_submitted" {
			t.Fatalf("submission_status = %q, want already_submitted", res.outputs["submission_status"])
		}
		if res.outputs["staging_version"] != wantVer {
			t.Fatalf("staging_version on duplicate retry = %q, want %q", res.outputs["staging_version"], wantVer)
		}
		for _, cmd := range res.commands {
			if strings.HasPrefix(cmd, "artifacts generic upload") || strings.HasPrefix(cmd, "storage cp") {
				t.Fatalf("duplicate retry must not upload AR package or manifest: %s", cmd)
			}
		}
		wantCmd := `gh workflow run release.yml --ref "v0.2.0" -f tag="v0.2.0" -f force_resubmit=true`
		if !strings.Contains(res.summary, "ALREADY SUBMITTED (SKIPPED DUPLICATE)") || !strings.Contains(res.summary, wantCmd) {
			t.Errorf("summary missing duplicate skip note or full --ref dispatch command %q:\n%s", wantCmd, res.summary)
		}
	})

	t.Run("rejects_unreadable_corrupt_or_mismatched_existing_manifest", func(t *testing.T) {
		checkSubmissionStep := findJobStep(t, "preflight", readSupplyChainBundle(t).wf.Jobs.Preflight.Steps, "check_submission")
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		tagSum := sha256.Sum256([]byte("v0.2.0"))
		tagHash := hex.EncodeToString(tagSum[:])[:12]
		commitShort := commitSHA[:12]
		existingPrimary := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s.json", tagHash, commitShort)
		existingForced := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s-r987654321.json", tagHash, commitShort)
		validBody := fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, ver)
		wrongCommitVer := "t-" + tagHash + "-ffffffffffff"
		wrongTagHashVer := "t-000000000000-" + commitShort

		for _, tc := range []struct {
			name     string
			manifest string
			jsonBody string
			catErr   bool
			force    string
		}{
			{"unreadable_primary", existingPrimary, "", true, "false"},
			{"corrupt_empty_object_primary", existingPrimary, "{}", false, "false"},
			{"wrong_tag_primary", existingPrimary, fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.9.9","is_draft":true,"is_prerelease":false}}}`, ver), false, "false"},
			{"wrong_package_primary", existingPrimary, fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"other-pkg","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, ver), false, "false"},
			{"boolean_version_primary", existingPrimary, `{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":true}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, false, "false"},
			{"numeric_version_primary", existingPrimary, `{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":17}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, false, "false"},
			{"corrupt_empty_object_forced", existingForced, "{}", false, "true"},
			{"multi_doc_trailing_empty_object_primary", existingPrimary, validBody + "\n{}", false, "false"},
			{"multi_doc_trailing_publish_all_true_primary", existingPrimary, validBody + "\n" + `{"publish_all":true}`, false, "false"},
			{"multi_doc_trailing_empty_object_forced", existingForced, validBody + "\n{}", false, "true"},
			{"wrong_commit_staging_version_primary", existingPrimary, fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, wrongCommitVer), false, "false"},
			{"wrong_tag_hash_staging_version_primary", existingPrimary, fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, wrongTagHashVer), false, "false"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				subRes := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
					tag:                   "v0.2.0",
					commitSHA:             commitSHA,
					runID:                 "987654321",
					forceResubmit:         tc.force,
					action:                "full_release",
					releaseStagingVersion: ver,
					existingManifest:      tc.manifest,
					existingJSON:          tc.jsonBody,
					catError:              tc.catErr,
				})
				if subRes.err == nil {
					t.Fatalf("submit-exit-gate accepted %s manifest: outputs=%v", tc.name, subRes.outputs)
				}
				for _, cmd := range subRes.commands {
					if strings.HasPrefix(cmd, "storage cp") {
						t.Fatalf("submit-exit-gate wrote manifest despite %s failure: %s", tc.name, cmd)
					}
				}
				preRes := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					tag:              "v0.2.0",
					commitSHA:        commitSHA,
					runID:            "987654321",
					forceResubmit:    tc.force,
					existingManifest: tc.manifest,
					existingJSON:     tc.jsonBody,
					catError:         tc.catErr,
				}, false)
				if preRes.err == nil {
					t.Fatalf("preflight accepted %s manifest: outputs=%v", tc.name, preRes.outputs)
				}
			})
		}

		t.Run("multi_doc_objects_describe_promote_eligible_fails_closed", func(t *testing.T) {
			preMultiDesc := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
				tag:              "v0.2.0",
				commitSHA:        commitSHA,
				runID:            "987654321",
				forceResubmit:    "false",
				existingManifest: existingPrimary,
				existingJSON:     validBody,
				dockerEnv: map[string]string{
					"EXIT_GATE_DESCRIBE_BODY": "{}\n" + `{"custom_fields":{"promote_eligible":"true"}}`,
				},
			}, false)
			if preMultiDesc.err == nil {
				t.Fatalf("preflight accepted multi-doc objects describe output: outputs=%v", preMultiDesc.outputs)
			}
		})
	})

	t.Run("verify_origin_tag_blocks_moved_or_withdrawn_tag_in_submit_exit_gate", func(t *testing.T) {
		okStore := t.TempDir()
		// Real bare origin repository with an annotated v0.2.0 tag -> succeeds.
		// Leave commitSHA empty so runWorkflowBashScript resolves the seeded commit
		// dynamically, and derive expected staging_version from the result.
		okRes := runWorkflowBashScript(t, stageStep.Run, exitGateReplayOpts{
			storeDir:     okStore,
			tag:          "v0.2.0",
			runID:        "801",
			withOrigin:   true,
			annotatedTag: true,
		}, true)
		if okRes.err != nil {
			t.Fatalf("stage with real annotated origin failed: %v", okRes.err)
		}

		realGitBin, err := exec.LookPath("git")
		if err != nil {
			t.Fatalf("looking up real git: %v", err)
		}

		// Seed complete AR under a fixed real commit in an isolated bare repo test,
		// testing both pre-start mutation and mid-flight TOCTOU mutation between
		// initial verify_origin_release_tag and final verify_origin_release_tag.
		type realOriginSubmitResult struct {
			res        exitGateReplayResult
			gitCalls   [][]string
			cosignLog  [][]string
			ghLogCalls [][]string
		}
		runRealOriginSubmit := func(retag, withdraw, midFlight bool) realOriginSubmitResult {
			t.Helper()
			dir := t.TempDir()
			originDir := filepath.Join(dir, "origin.git")
			seedDir := filepath.Join(dir, "seed")
			for _, sub := range []string{originDir, seedDir} {
				if err := os.Mkdir(sub, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			runGit := func(workDir string, args ...string) string {
				t.Helper()
				cmd := exec.Command(realGitBin, args...)
				cmd.Dir = workDir
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("git %v: %v: %s", args, err, out)
				}
				return strings.TrimSpace(string(out))
			}
			runGit(originDir, "init", "--bare", "-b", "main")
			runGit(seedDir, "init", "-b", "main")
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "v0.2.0")
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "tag", "-a", "v0.2.0", "-m", "release v0.2.0")
			runGit(seedDir, "remote", "add", "origin", originDir)
			runGit(seedDir, "push", "origin", "main", "--tags")
			taggedSHA := runGit(seedDir, "rev-parse", "HEAD")

			storeDir := t.TempDir()
			ver := deterministicStagingVersion("v0.2.0", taggedSHA)
			seedCompleteARVersion(t, storeDir, "v0.2.0", ver, true)

			if !midFlight && withdraw {
				runGit(seedDir, "push", "origin", "--delete", "v0.2.0")
			}
			if !midFlight && retag {
				runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "moved tag")
				runGit(seedDir, "tag", "-f", "v0.2.0")
				runGit(seedDir, "push", "--force", "origin", "refs/tags/v0.2.0")
			}

			// Run submit_exit_gate.sh with cwd containing origin remote pointing at originDir.
			workDir := t.TempDir()
			binDir := filepath.Join(workDir, "bin")
			runnerTemp := filepath.Join(workDir, "runner_temp")
			for _, name := range []string{binDir, runnerTemp} {
				if err := os.Mkdir(name, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			stageReleaseScripts(t, workDir)
			writeFakeGcloud(t, binDir)
			writeFakeDockerAndCosign(t, binDir)
			gitLogPath := filepath.Join(workDir, "git.log")
			cosignLogPath := filepath.Join(workDir, "cosign.log")
			ghLogPath := filepath.Join(workDir, "gh.log")
			gitWrapper := `#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "ls-remote" && -n "${TOCTOU_GIT_LOG:-}" ]]; then
  printf '%s\t' "$@" >> "${TOCTOU_GIT_LOG}"
  printf '\n' >> "${TOCTOU_GIT_LOG}"
fi
exec "${TOCTOU_REAL_GIT}" "$@"
`
			if err := os.WriteFile(filepath.Join(binDir, "git"), []byte(gitWrapper), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(binDir, "gh"), filepath.Join(binDir, "gh.real")); err != nil {
				t.Fatal(err)
			}
			ghWrapper := `#!/usr/bin/env bash
set -euo pipefail
"$(dirname "$0")/gh.real" "$@"
if [[ "${TOCTOU_MIDFLIGHT:-0}" == "1" && "${1:-}" == "attestation" && "${2:-}" == "verify" && "${3:-}" == */EXIT_GATE_CHANGELOG ]]; then
  if [[ "${TOCTOU_ACTION:-}" == "withdraw" ]]; then
    "${TOCTOU_REAL_GIT}" -C "${TOCTOU_SEED_DIR}" push origin --delete "${RELEASE_TAG}" >/dev/null 2>&1
  elif [[ "${TOCTOU_ACTION:-}" == "retag" ]]; then
    "${TOCTOU_REAL_GIT}" -C "${TOCTOU_SEED_DIR}" -c user.name=Test -c user.email=test@example.com commit --allow-empty -m "moved tag" >/dev/null 2>&1
    "${TOCTOU_REAL_GIT}" -C "${TOCTOU_SEED_DIR}" tag -f "${RELEASE_TAG}" >/dev/null 2>&1
    "${TOCTOU_REAL_GIT}" -C "${TOCTOU_SEED_DIR}" push --force origin "refs/tags/${RELEASE_TAG}" >/dev/null 2>&1
  fi
fi
`
			if err := os.WriteFile(filepath.Join(binDir, "gh"), []byte(ghWrapper), 0o700); err != nil {
				t.Fatal(err)
			}
			runGit(workDir, "init", "-q", "-b", "main")
			runGit(workDir, "remote", "add", "origin", originDir)

			outPath := filepath.Join(workDir, "github_output")
			sumPath := filepath.Join(workDir, "github_summary")
			for _, p := range []string{outPath, sumPath} {
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			toctouAction := ""
			if midFlight {
				if withdraw {
					toctouAction = "withdraw"
				} else if retag {
					toctouAction = "retag"
				}
			}
			midFlag := "0"
			if midFlight {
				midFlag = "1"
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-c", submitStep.Run)
			cmd.Dir = workDir
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GIT_CONFIG_GLOBAL=/dev/null",
				"GIT_CONFIG_SYSTEM=/dev/null",
				"RUNNER_TEMP="+runnerTemp,
				"GITHUB_OUTPUT="+outPath,
				"GITHUB_STEP_SUMMARY="+sumPath,
				"RELEASE_TAG=v0.2.0",
				"COMMIT_SHA="+taggedSHA,
				"RUN_ID=805",
				"FORCE_RESUBMIT=false",
				"ACTION=submit_staged",
				"PREFLIGHT_STAGING_VERSION="+ver,
				"GH_TOKEN=test-gh-token",
				"GITHUB_REPOSITORY=GoogleCloudPlatform/BQ-OTEL-Exporter",
				"EXIT_GATE_TEST_DIR="+workDir,
				"EXIT_GATE_STORE_DIR="+storeDir,
				"FAKE_COSIGN_LOG="+cosignLogPath,
				"FAKE_GH_LOG="+ghLogPath,
				"TOCTOU_REAL_GIT="+realGitBin,
				"TOCTOU_GIT_LOG="+gitLogPath,
				"TOCTOU_SEED_DIR="+seedDir,
				"TOCTOU_MIDFLIGHT="+midFlag,
				"TOCTOU_ACTION="+toctouAction,
			)
			out, err := cmd.CombinedOutput()
			var res exitGateReplayResult
			if err != nil {
				res.err = fmt.Errorf("%w: %s", err, out)
			}
			if raw, rerr := os.ReadFile(filepath.Join(workDir, "gcloud.log")); rerr == nil {
				for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
					if line != "" {
						res.commands = append(res.commands, line)
					}
				}
			}
			if raw, rerr := os.ReadFile(outPath); rerr == nil {
				res.outputs = map[string]string{}
				for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
					if k, v, ok := strings.Cut(line, "="); ok {
						res.outputs[k] = v
					}
				}
			}
			if listStoreManifests(t, storeDir) != nil {
				res.stagedFiles = listStoreManifests(t, storeDir)
			}
			return realOriginSubmitResult{
				res:        res,
				gitCalls:   readTabLog(t, gitLogPath),
				cosignLog:  readTabLog(t, cosignLogPath),
				ghLogCalls: readTabLog(t, ghLogPath),
			}
		}

		resValid := runRealOriginSubmit(false, false, false)
		if resValid.res.err != nil || resValid.res.outputs["submission_status"] != "submitted" || len(resValid.res.stagedFiles) != 1 || len(resValid.gitCalls) != 2 {
			t.Fatalf("real annotated origin submit failed: err=%v outputs=%v manifests=%v gitCalls=%d", resValid.res.err, resValid.res.outputs, resValid.res.stagedFiles, len(resValid.gitCalls))
		}
		resMoved := runRealOriginSubmit(true, false, false)
		if resMoved.res.err == nil || len(resMoved.res.stagedFiles) != 0 {
			t.Fatalf("moved origin tag submitted manifest: err=%v manifests=%v", resMoved.res.err, resMoved.res.stagedFiles)
		}
		resDeleted := runRealOriginSubmit(false, true, false)
		if resDeleted.res.err == nil || len(resDeleted.res.stagedFiles) != 0 {
			t.Fatalf("withdrawn origin tag submitted manifest: err=%v manifests=%v", resDeleted.res.err, resDeleted.res.stagedFiles)
		}
		for _, toctouCase := range []struct {
			name     string
			retag    bool
			withdraw bool
		}{
			{"midflight_retag_between_initial_check_and_upload", true, false},
			{"midflight_withdraw_between_initial_check_and_upload", false, true},
		} {
			t.Run(toctouCase.name, func(t *testing.T) {
				got := runRealOriginSubmit(toctouCase.retag, toctouCase.withdraw, true)
				if got.res.err == nil {
					t.Fatalf("%s unexpectedly succeeded: outputs=%v", toctouCase.name, got.res.outputs)
				}
				if len(got.res.stagedFiles) != 0 {
					t.Fatalf("%s uploaded manifest despite TOCTOU tag mutation: %v", toctouCase.name, got.res.stagedFiles)
				}
				for _, cmd := range got.res.commands {
					if strings.HasPrefix(cmd, "storage cp") {
						t.Fatalf("%s reached gcloud storage cp despite final tag check: %s", toctouCase.name, cmd)
					}
				}
				if len(got.cosignLog) == 0 || len(got.ghLogCalls) == 0 {
					t.Fatalf("%s aborted before artifact/changelog verification completed (cosign=%v gh=%v)", toctouCase.name, got.cosignLog, got.ghLogCalls)
				}
				if len(got.gitCalls) != 2 {
					t.Fatalf("%s expected 2 git ls-remote calls (initial + final), got %d (%v)", toctouCase.name, len(got.gitCalls), got.gitCalls)
				}
			})
		}
	})

	t.Run("changelog_attestation_verified_on_staged_retry_and_rejects_tampered_or_unattested", func(t *testing.T) {
		checkSubmissionStep := findJobStep(t, "preflight", readSupplyChainBundle(t).wf.Jobs.Preflight.Steps, "check_submission")
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		wantDigest := "sha256:" + strings.Repeat("c", 64)
		clSum := sha256.Sum256([]byte("## Release notes\n"))
		goodCLDigest := hex.EncodeToString(clSum[:])
		otherCLDigest := strings.Repeat("f", 64)

		storeDir := t.TempDir()
		seedCompleteARVersion(t, storeDir, "v0.2.0", ver, true)

		// Matching attested EXIT_GATE_CHANGELOG passes preflight submit_staged and both submit-exit-gate modes.
		preOK := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "901", forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_OCI_DEFAULT_CODE":             "200",
				"FAKE_OCI_DEFAULT_DIGEST":           wantDigest,
				"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest,
			},
		}, false)
		if preOK.err != nil || preOK.outputs["action"] != "submit_staged" {
			t.Fatalf("attested changelog preflight = (%v, %v), want action=submit_staged", preOK.err, preOK.outputs)
		}
		sawCLAttest := false
		for _, call := range preOK.ghCalls {
			if len(call) >= 3 && call[0] == "attestation" && call[1] == "verify" && strings.HasSuffix(call[2], "/EXIT_GATE_CHANGELOG") {
				if !slices.Contains(call, "--source-digest") || !slices.Contains(call, commitSHA) || !slices.Contains(call, "--format") {
					t.Fatalf("preflight changelog attestation call missing --source-digest or --format json: %q", call)
				}
				sawCLAttest = true
			}
		}
		if !sawCLAttest {
			t.Fatalf("preflight did not call gh attestation verify on EXIT_GATE_CHANGELOG: %q", preOK.ghCalls)
		}

		for _, actionMode := range []string{"submit_staged", "resubmit_existing"} {
			modeStore := t.TempDir()
			seedCompleteARVersion(t, modeStore, "v0.2.0", ver, true)
			forceVal := "false"
			if actionMode == "resubmit_existing" {
				forceVal = "true"
			}
			subOK := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
				storeDir:            modeStore,
				tag:                 "v0.2.0",
				commitSHA:           commitSHA,
				runID:               "902",
				forceResubmit:       forceVal,
				action:              actionMode,
				preflightStagingVer: ver,
				priorStagingVersion: ver,
				dockerEnv:           map[string]string{"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest},
			})
			if subOK.err != nil || subOK.outputs["submission_status"] != "submitted" {
				t.Fatalf("attested changelog %s submit = (%v, %v), want submitted", actionMode, subOK.err, subOK.outputs)
			}

			// If EXIT_GATE_CHANGELOG is swapped, unattested, or backed only by a
			// differently named subject (e.g. checksums.txt) or wrong commit digest,
			// submit-exit-gate must fail closed before writing manifest.
			for _, badCase := range []struct {
				name string
				env  map[string]string
			}{
				{
					name: "wrong_attested_digest",
					env:  map[string]string{"FAKE_GH_ATTESTED_CHANGELOG_SHA256": otherCLDigest},
				},
				{
					name: "unattested",
					env:  map[string]string{"FAKE_GH_CHANGELOG_ATTESTATION_FAIL": "1"},
				},
				{
					name: "wrong_subject_name_checksums_txt",
					env: map[string]string{
						"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest,
						"FAKE_GH_ATTESTED_SUBJECT_NAME":     "checksums.txt",
					},
				},
				{
					name: "wrong_json_subject_digest",
					env: map[string]string{
						"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest,
						"FAKE_GH_ATTESTED_SUBJECT_NAME":     "EXIT_GATE_CHANGELOG",
						"FAKE_GH_JSON_SUBJECT_SHA256":       otherCLDigest,
					},
				},
			} {
				badStore := t.TempDir()
				seedCompleteARVersion(t, badStore, "v0.2.0", ver, true)
				subBad := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
					storeDir:            badStore,
					tag:                 "v0.2.0",
					commitSHA:           commitSHA,
					runID:               "903",
					forceResubmit:       forceVal,
					action:              actionMode,
					preflightStagingVer: ver,
					priorStagingVersion: ver,
					dockerEnv:           badCase.env,
				})
				if subBad.err == nil || len(listStoreManifests(t, badStore)) != 0 {
					t.Fatalf("submit-exit-gate (%s/%s) failed open on compromised changelog: err=%v manifests=%v", actionMode, badCase.name, subBad.err, listStoreManifests(t, badStore))
				}
			}
		}

		// Preflight must also fail closed if EXIT_GATE_CHANGELOG fails digest, subject name, or source-digest verification.
		for _, preBadCase := range []struct {
			name string
			env  map[string]string
		}{
			{
				name: "wrong_attested_digest",
				env:  map[string]string{"FAKE_GH_ATTESTED_CHANGELOG_SHA256": otherCLDigest},
			},
			{
				name: "wrong_subject_name_checksums_txt",
				env: map[string]string{
					"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest,
					"FAKE_GH_ATTESTED_SUBJECT_NAME":     "checksums.txt",
				},
			},
			{
				name: "wrong_json_subject_digest",
				env: map[string]string{
					"FAKE_GH_ATTESTED_CHANGELOG_SHA256": goodCLDigest,
					"FAKE_GH_ATTESTED_SUBJECT_NAME":     "EXIT_GATE_CHANGELOG",
					"FAKE_GH_JSON_SUBJECT_SHA256":       otherCLDigest,
				},
			},
		} {
			env := map[string]string{
				"FAKE_OCI_DEFAULT_CODE":   "200",
				"FAKE_OCI_DEFAULT_DIGEST": wantDigest,
			}
			maps.Copy(env, preBadCase.env)
			if preBad := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
				storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "904", forceResubmit: "false",
				dockerEnv: env,
			}, false); preBad.err == nil {
				t.Fatalf("preflight failed open on compromised changelog (%s): outputs=%v", preBadCase.name, preBad.outputs)
			}
		}

		// Release with no generated changelog (13 AR files) succeeds cleanly in
		// resubmit_existing and full_release, whereas submit_staged MUST fail closed
		// when EXIT_GATE_CHANGELOG is missing.
		noCLStore := t.TempDir()
		seedCompleteARVersion(t, noCLStore, "v0.2.0", ver, false)
		subNoCL := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: noCLStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "905", forceResubmit: "true",
			action: "resubmit_existing", priorStagingVersion: ver,
			dockerEnv: map[string]string{"FAKE_GH_CHANGELOG_ATTESTATION_FAIL": "1"},
		})
		if subNoCL.err != nil || subNoCL.outputs["submission_status"] != "submitted" {
			t.Fatalf("13-file release without changelog failed resubmit_existing submit-exit-gate: (%v, %v)", subNoCL.err, subNoCL.outputs)
		}
		fullNoCLStore := t.TempDir()
		seedCompleteARVersion(t, fullNoCLStore, "v0.2.0", ver, false)
		subFullNoCL := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: fullNoCLStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "906", forceResubmit: "false",
			action: "full_release", releaseStagingVersion: ver,
		})
		if subFullNoCL.err != nil || subFullNoCL.outputs["submission_status"] != "submitted" {
			t.Fatalf("13-file full_release without changelog failed submit-exit-gate: (%v, %v)", subFullNoCL.err, subFullNoCL.outputs)
		}

		stagedNoCLStore := t.TempDir()
		seedCompleteARVersion(t, stagedNoCLStore, "v0.2.0", ver, false)
		subStagedNoCL := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: stagedNoCLStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "907", forceResubmit: "false",
			action: "submit_staged", preflightStagingVer: ver,
		})
		if subStagedNoCL.err == nil || len(listStoreManifests(t, stagedNoCLStore)) != 0 {
			t.Fatalf("submit_staged succeeded without required EXIT_GATE_CHANGELOG: err=%v manifests=%v", subStagedNoCL.err, listStoreManifests(t, stagedNoCLStore))
		}

		// Query/parse error while checking EXIT_GATE_CHANGELOG presence must fail
		// closed across all actions and never skip changelog verification.
		realJQBin, jqErr := exec.LookPath("jq")
		if jqErr != nil {
			t.Fatalf("looking up real jq: %v", jqErr)
		}
		failChangelogJQ := fmt.Sprintf(`#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "$arg" == *'any(.[]; .fname == "EXIT_GATE_CHANGELOG")'* ]]; then
    echo "jq: simulated changelog inspection error" >&2
    exit 5
  fi
done
exec %q "$@"
`, realJQBin)
		for _, mode := range []string{"full_release", "submit_staged", "resubmit_existing"} {
			jqErrStore := t.TempDir()
			seedCompleteARVersion(t, jqErrStore, "v0.2.0", ver, true)
			forceVal := "false"
			if mode == "resubmit_existing" {
				forceVal = "true"
			}
			subJQErr := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
				storeDir: jqErrStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "908", forceResubmit: forceVal,
				action: mode, releaseStagingVersion: ver, preflightStagingVer: ver, priorStagingVersion: ver,
				extraBins: map[string]string{"jq": failChangelogJQ},
			})
			if subJQErr.err == nil || len(listStoreManifests(t, jqErrStore)) != 0 {
				t.Fatalf("submit-exit-gate (%s) failed open when changelog jq query errored: err=%v manifests=%v", mode, subJQErr.err, listStoreManifests(t, jqErrStore))
			}
		}

		// Mismatched STAGING_VERSION binding is rejected across all submit modes.
		wrongVer := "t-000000000000-" + commitSHA[:12]
		for _, mode := range []string{"full_release", "submit_staged", "resubmit_existing"} {
			badVerStore := t.TempDir()
			seedCompleteARVersion(t, badVerStore, "v0.2.0", wrongVer, true)
			subBadVer := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
				storeDir: badVerStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "909", forceResubmit: "false",
				action: mode, releaseStagingVersion: wrongVer, preflightStagingVer: wrongVer, priorStagingVersion: wrongVer,
			})
			if subBadVer.err == nil || len(listStoreManifests(t, badVerStore)) != 0 {
				t.Fatalf("submit-exit-gate (%s) accepted mismatched STAGING_VERSION %q: err=%v manifests=%v", mode, wrongVer, subBadVer.err, listStoreManifests(t, badVerStore))
			}
		}
	})

	t.Run("force_resubmit_keys_manifest_on_run_id_only_so_rerun_skips_duplicate", func(t *testing.T) {
		storeDir := t.TempDir()
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		run1Attempt1 := replayFullReleaseSubmit(t, stageStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "101",
			forceResubmit: "true",
		})
		if run1Attempt1.err != nil {
			t.Fatalf("forced run 101 attempt 1 failed: %v", run1Attempt1.err)
		}
		if !strings.HasSuffix(run1Attempt1.outputs["manifest_uri"], "-r101.json") {
			t.Fatalf("manifest_uri = %q, want -r101.json (keyed by run_id)", run1Attempt1.outputs["manifest_uri"])
		}
		assertExitGateManifest(t, run1Attempt1.manifest, "v0.2.0", wantVer, false)

		run1Attempt2 := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "101",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: wantVer,
		})
		if run1Attempt2.err != nil {
			t.Fatalf("forced run 101 attempt 2 failed: %v", run1Attempt2.err)
		}
		if run1Attempt2.outputs["submission_status"] != "already_submitted" || run1Attempt2.outputs["staging_version"] != wantVer {
			t.Fatalf("forced rerun outputs = %v, want already_submitted %q", run1Attempt2.outputs, wantVer)
		}
		for _, cmd := range run1Attempt2.commands {
			if strings.HasPrefix(cmd, "artifacts generic upload") || strings.HasPrefix(cmd, "storage cp") {
				t.Fatalf("forced rerun attempted duplicate upload: %s", cmd)
			}
		}
		if got := listStoreManifests(t, storeDir); len(got) != 1 || !strings.HasSuffix(got[0], "-r101.json") {
			t.Fatalf("stored manifests after forced rerun = %v, want single -r101.json manifest", got)
		}

		// Fresh RUN_ID=102 submits -r102.json reusing wantVer.
		run2 := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "102",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: wantVer,
		})
		if run2.err != nil {
			t.Fatalf("fresh forced dispatch 102 failed: %v", run2.err)
		}
		if run2.outputs["submission_status"] != "submitted" || !strings.HasSuffix(run2.outputs["manifest_uri"], "-r102.json") {
			t.Fatalf("run2 outputs = %v, want submitted manifest ending in -r102.json", run2.outputs)
		}
		assertExitGateManifest(t, run2.manifest, "v0.2.0", wantVer, false)
		if got := listStoreManifests(t, storeDir); len(got) != 2 {
			t.Fatalf("stored manifests after fresh forced dispatch = %v, want 2 manifests (-r101.json and -r102.json)", got)
		}
	})

	t.Run("submit_staged_submits_verified_ar_package_and_fails_when_ar_empty", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		seedCompleteARVersion(t, storeDir, "v0.2.0", ver, true)

		res := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "555",
			forceResubmit:       "false",
			action:              "submit_staged",
			preflightStagingVer: ver,
			dockerEnv: map[string]string{
				"EXIT_GATE_AR_PERCENT3A":     "1",
				"EXIT_GATE_AR_UPPERCASE_HEX": "1",
			},
		})
		if res.err != nil {
			t.Fatalf("submit_staged failed: %v", res.err)
		}
		if res.outputs["submission_status"] != "submitted" || res.outputs["staging_version"] != ver {
			t.Fatalf("submit_staged outputs = %v, want submitted %q", res.outputs, ver)
		}
		assertExitGateManifest(t, res.manifest, "v0.2.0", ver, false)

		emptyStore := t.TempDir()
		missingAR := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            emptyStore,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "556",
			forceResubmit:       "false",
			action:              "submit_staged",
			preflightStagingVer: ver,
		})
		if missingAR.err == nil {
			t.Fatal("submit_staged succeeded despite missing AR package files")
		}
		for _, cmd := range missingAR.commands {
			if strings.HasPrefix(cmd, "storage cp") {
				t.Fatalf("submit_staged wrote manifest despite missing AR package: %s", cmd)
			}
		}
	})

	t.Run("ar_base64_sha256_std_and_url_accepted_across_preflight_stage_and_submit", func(t *testing.T) {
		checkSubmissionStep := findJobStep(t, "preflight", readSupplyChainBundle(t).wf.Jobs.Preflight.Steps, "check_submission")
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		wantDigest := "sha256:" + strings.Repeat("c", 64)

		for _, tc := range []struct {
			name   string
			envKey string
		}{
			{"standard_padded_base64", "EXIT_GATE_AR_BASE64_STD"},
			{"urlsafe_unpadded_base64", "EXIT_GATE_AR_BASE64_URL"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				storeDir := t.TempDir()
				seedCompleteARVersion(t, storeDir, "v0.2.0", ver, true)
				env := map[string]string{
					tc.envKey:                 "1",
					"FAKE_OCI_DEFAULT_CODE":   "200",
					"FAKE_OCI_DEFAULT_DIGEST": wantDigest,
				}
				pre := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					storeDir:      storeDir,
					tag:           "v0.2.0",
					commitSHA:     commitSHA,
					runID:         "701",
					forceResubmit: "false",
					dockerEnv:     env,
				}, false)
				if pre.err != nil || pre.outputs["action"] != "submit_staged" {
					t.Fatalf("preflight (%s) = (%v, %v), want action=submit_staged", tc.name, pre.err, pre.outputs)
				}

				stageRes := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
					storeDir:         storeDir,
					tag:              "v0.2.0",
					commitSHA:        commitSHA,
					includeChangelog: true,
					dockerEnv:        map[string]string{tc.envKey: "1"},
				})
				if stageRes.err != nil {
					t.Fatalf("stage_exit_gate_assets (%s) failed: %v", tc.name, stageRes.err)
				}
				for _, cmd := range stageRes.commands {
					if strings.HasPrefix(cmd, "artifacts versions delete") || strings.HasPrefix(cmd, "artifacts generic upload") {
						t.Fatalf("stage_exit_gate_assets (%s) unexpectedly mutated valid AR: %s", tc.name, cmd)
					}
				}

				subRes := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
					storeDir:            storeDir,
					tag:                 "v0.2.0",
					commitSHA:           commitSHA,
					runID:               "701",
					forceResubmit:       "false",
					action:              "submit_staged",
					preflightStagingVer: ver,
					dockerEnv:           map[string]string{tc.envKey: "1"},
				})
				if subRes.err != nil || subRes.outputs["submission_status"] != "submitted" {
					t.Fatalf("submit_exit_gate (%s) = (%v, %v), want submitted", tc.name, subRes.err, subRes.outputs)
				}
				assertExitGateManifest(t, subRes.manifest, "v0.2.0", ver, false)
			})
		}
	})
}

func TestReleaseExitGateSubmitRejectsBrokenInputs(t *testing.T) {
	stageStep := findReleaseStep(t, "stage_exit_gate_assets")
	submitStep := findSubmitExitGateStep(t)
	commitSHA := "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		name string
		opts exitGateReplayOpts
	}{
		{
			name: "malformed_checksum_digest_line",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				malformDigestFor: "otelcol-bq_0.2.0_linux_amd64.tar.gz",
			},
		},
		{
			name: "tampered_archive_checksum_mismatch",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				tamperFile: "otelcol-bq_0.2.0_linux_amd64.tar.gz",
			},
		},
		{
			name: "missing_windows_zip_masked_by_extra_archive",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				omitArchive:    "otelcol-bq_0.2.0_windows_amd64.zip",
				extraDistFiles: []string{"otelcol-bq_0.2.0_linux_amd64_debug.tar.gz"},
			},
		},
		{
			name: "missing_sbom_entry_in_checksums",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				omitChecksumLine: "otelcol-bq_0.2.0_windows_amd64.zip.sbom.json",
			},
		},
		{
			name: "extra_entry_in_checksums",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				extraChecksum: "otelcol-bq_0.2.0_linux_amd64_debug.tar.gz",
			},
		},
		{
			name: "empty_signature_file",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				emptySig: true,
			},
		},
		{
			name: "ar_files_list_permission_error",
			opts: exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA,
				arListError: true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := replayStageAssets(t, stageStep.Run, tc.opts)
			if res.err == nil {
				t.Fatalf("accepted broken asset staging case %q; commands=%v", tc.name, res.commands)
			}
			for _, cmd := range res.commands {
				if strings.HasPrefix(cmd, "artifacts generic upload") || strings.HasPrefix(cmd, "artifacts versions delete") {
					t.Fatalf("broken case %q mutated AR despite failure: %s", tc.name, cmd)
				}
			}
		})
	}

	t.Run("gcs_list_permission_error_in_submit_exit_gate", func(t *testing.T) {
		res := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			tag:                   "v0.2.0",
			commitSHA:             commitSHA,
			runID:                 "1",
			forceResubmit:         "false",
			action:                "full_release",
			releaseStagingVersion: deterministicStagingVersion("v0.2.0", commitSHA),
			listError:             true,
		})
		if res.err == nil {
			t.Fatal("accepted broken submit-exit-gate with GCS list error")
		}
		for _, cmd := range res.commands {
			if strings.HasPrefix(cmd, "storage cp") {
				t.Fatalf("submit-exit-gate wrote manifest despite list error: %s", cmd)
			}
		}
	})

	t.Run("ar_download_permission_error_fails_closed_before_delete_in_stage_assets", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		seedCompleteARVersion(t, storeDir, "v0.2.0", ver, false)
		res := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
			storeDir:        storeDir,
			tag:             "v0.2.0",
			commitSHA:       commitSHA,
			arDownloadError: true,
		})
		if res.err == nil {
			t.Fatal("stage_exit_gate_assets deleted or succeeded despite AR download permission error")
		}
		for _, cmd := range res.commands {
			if strings.HasPrefix(cmd, "artifacts versions delete") || strings.HasPrefix(cmd, "artifacts generic upload") {
				t.Fatalf("stage_exit_gate_assets mutated AR despite download error: %s", cmd)
			}
		}
	})

	t.Run("ar_downloaded_file_digest_mismatch_fails_closed_before_delete_in_stage_assets", func(t *testing.T) {
		for _, fname := range []string{"checksums.txt", "checksums.txt.sig", "checksums.txt.pem"} {
			t.Run(fname, func(t *testing.T) {
				storeDir := t.TempDir()
				ver := deterministicStagingVersion("v0.2.0", commitSHA)
				seedCompleteARVersion(t, storeDir, "v0.2.0", ver, false)
				res := replayStageAssets(t, stageStep.Run, exitGateReplayOpts{
					storeDir:  storeDir,
					tag:       "v0.2.0",
					commitSHA: commitSHA,
					dockerEnv: map[string]string{"EXIT_GATE_AR_CORRUPT_DOWNLOAD_FILE": fname},
				})
				if res.err == nil {
					t.Fatalf("stage_exit_gate_assets succeeded despite downloaded %s disagreeing with AR listing", fname)
				}
				for _, cmd := range res.commands {
					if strings.HasPrefix(cmd, "artifacts versions delete") || strings.HasPrefix(cmd, "artifacts generic upload") {
						t.Fatalf("stage_exit_gate_assets deleted/re-uploaded AR on indeterminate download mismatch for %s: %s", fname, cmd)
					}
				}
			})
		}
	})

	t.Run("submit_exit_gate_rejects_broken_or_unverified_remote_ar", func(t *testing.T) {
		ver := deterministicStagingVersion("v0.2.0", commitSHA)

		cases := []struct {
			name  string
			setup func(*testing.T, string) exitGateReplayOpts
		}{
			{
				name: "partial_package_checksums_only",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedARFiles(t, s, ver, []string{"checksums.txt"})
					return exitGateReplayOpts{storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "1", forceResubmit: "false", action: "submit_staged", preflightStagingVer: ver}
				},
			},
			{
				name: "unexpected_extra_file_in_ar",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					if err := os.WriteFile(filepath.Join(s, "ar", ver, "unexpected.bin"), []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return exitGateReplayOpts{storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "2", forceResubmit: "false", action: "submit_staged", preflightStagingVer: ver}
				},
			},
			{
				name: "tampered_remote_archive_sha256_mismatch",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					target := filepath.Join(s, "ar", ver, "otelcol-bq_0.2.0_linux_amd64.tar.gz")
					if err := os.WriteFile(target, []byte("corrupted-remote-bytes\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return exitGateReplayOpts{storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "3", forceResubmit: "false", action: "submit_staged", preflightStagingVer: ver}
				},
			},
			{
				name: "cosign_verify_blob_failure",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					return exitGateReplayOpts{
						storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "4", forceResubmit: "false",
						action: "submit_staged", preflightStagingVer: ver,
						dockerEnv: map[string]string{"FAKE_COSIGN_VERIFY_BLOB_FAIL": "1"},
					}
				},
			},
			{
				name: "ar_missing_sha256_hash_metadata",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					return exitGateReplayOpts{
						storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "5", forceResubmit: "false",
						action: "submit_staged", preflightStagingVer: ver,
						dockerEnv: map[string]string{"EXIT_GATE_AR_MISSING_HASH": "1"},
					}
				},
			},
			{
				name: "ar_invalid_base64_sha256_padding_bits",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					return exitGateReplayOpts{
						storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "6", forceResubmit: "false",
						action: "submit_staged", preflightStagingVer: ver,
						dockerEnv: map[string]string{"EXIT_GATE_AR_BAD_BASE64": "1"},
					}
				},
			},
			{
				name: "ar_base64_tampered_remote_archive_sha256_mismatch",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, true)
					target := filepath.Join(s, "ar", ver, "otelcol-bq_0.2.0_linux_amd64.tar.gz")
					if err := os.WriteFile(target, []byte("corrupted-remote-bytes\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return exitGateReplayOpts{
						storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "7", forceResubmit: "false",
						action: "submit_staged", preflightStagingVer: ver,
						dockerEnv: map[string]string{"EXIT_GATE_AR_BASE64_STD": "1"},
					}
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				s := t.TempDir()
				res := replaySubmitExitGate(t, submitStep.Run, tc.setup(t, s))
				if res.err == nil {
					t.Fatalf("submit-exit-gate accepted broken AR (%s)", tc.name)
				}
				for _, cmd := range res.commands {
					if strings.HasPrefix(cmd, "storage cp") {
						t.Fatalf("submit-exit-gate wrote manifest despite broken AR (%s): %s", tc.name, cmd)
					}
				}
			})
		}
	})
}

func TestReleasePreflightAndResubmitExitGate(t *testing.T) {
	b := readSupplyChainBundle(t)
	if _, err := checkSupplyChainBundle(b); err != nil {
		t.Fatal(err)
	}
	wf := b.wf
	verifyRefStep := findJobStep(t, "preflight", wf.Jobs.Preflight.Steps, "verify_ref")
	checkSubmissionStep := findJobStep(t, "preflight", wf.Jobs.Preflight.Steps, "check_submission")
	releaseDedupGuardStep := findJobStep(t, "release", wf.Jobs.Release.Steps, "release_dedup_guard")
	reconcileContainerStep := findJobStep(t, "release", wf.Jobs.Release.Steps, "reconcile_container")
	stageAssetsStep := findJobStep(t, "release", wf.Jobs.Release.Steps, "stage_exit_gate_assets")
	submitStep := findJobStep(t, "submit-exit-gate", wf.Jobs.SubmitExitGate.Steps, "exit_gate_submit")

	t.Run("verify_ref_rejects_branch_or_mismatched_tag_before_publishing", func(t *testing.T) {
		repoDir := t.TempDir()
		runGit := func(args ...string) string {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = repoDir
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
			}
			return strings.TrimSpace(string(out))
		}
		runGit("init", "-b", "main")
		runGit("config", "user.name", "Test")
		runGit("config", "user.email", "test@example.com")
		if err := os.WriteFile(filepath.Join(repoDir, "version.txt"), []byte("0.2.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runGit("add", "version.txt")
		runGit("commit", "-m", "v0.2.0")
		runGit("tag", "v0.2.0")
		v020SHA := runGit("rev-parse", "HEAD")

		if err := os.WriteFile(filepath.Join(repoDir, "version.txt"), []byte("0.3.0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runGit("add", "version.txt")
		runGit("commit", "-m", "v0.3.0")
		runGit("tag", "v0.3.0")
		runGit("tag", "v01.0.0")

		execVerify := func(tag, refFull, forceResubmit string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-c", verifyRefStep.Run)
			cmd.Dir = repoDir
			cmd.Env = append(os.Environ(),
				"RELEASE_TAG="+tag,
				"GITHUB_REF_FULL="+refFull,
				"FORCE_RESUBMIT="+forceResubmit,
			)
			out, err := cmd.CombinedOutput()
			if err != nil {
				return fmt.Errorf("%w: %s", err, out)
			}
			return nil
		}

		if err := execVerify("v0.2.0", "refs/heads/main", "true"); err == nil {
			t.Fatal("accepted refs/heads/main for tag v0.2.0")
		} else {
			want := `gh workflow run release.yml --ref "v0.2.0" -f tag="v0.2.0" -f force_resubmit=true`
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("mismatch error = %q, want %q", err.Error(), want)
			}
		}

		// Invalid semver, leading-zero semver, and missing tag must fail closed.
		if err := execVerify("v0.2", "refs/tags/v0.2", "false"); err == nil {
			t.Fatal("accepted invalid semver tag v0.2")
		}
		if err := execVerify("v01.0.0", "refs/tags/v01.0.0", "false"); err == nil {
			t.Fatal("accepted leading-zero semver tag v01.0.0")
		}
		if err := execVerify("v9.9.9", "refs/tags/v9.9.9", "false"); err == nil {
			t.Fatal("accepted nonexistent tag v9.9.9")
		}

		runGit("checkout", "refs/tags/v0.2.0")
		if got := runGit("rev-parse", "HEAD"); got != v020SHA {
			t.Fatalf("checkout HEAD = %s, want %s", got, v020SHA)
		}
		if err := execVerify("v0.2.0", "refs/tags/v0.2.0", "true"); err != nil {
			t.Fatalf("matching tag checkout rejected: %v", err)
		}
		if err := execVerify("v0.2.0", "refs/heads/main", "false"); err == nil {
			t.Fatal("accepted refs/heads/main even at matching commit")
		}
	})

	t.Run("preflight_and_submit_exit_gate_prevent_latest_regression", func(t *testing.T) {
		storeDir := t.TempDir()
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)

		runPreflight := func(opts exitGateReplayOpts) exitGateReplayResult {
			opts.storeDir = storeDir
			if opts.tag == "" {
				opts.tag = "v0.2.0"
			}
			opts.commitSHA = commitSHA
			return runWorkflowBashScript(t, checkSubmissionStep.Run, opts, false)
		}

		// 1. Fresh tag -> preflight chooses full_release, stage + submit creates
		// primary manifest with deterministic t-... version.
		preFresh := runPreflight(exitGateReplayOpts{runID: "10", forceResubmit: "false"})
		if preFresh.err != nil || preFresh.outputs["action"] != "full_release" || preFresh.outputs["container_exists"] != "false" || preFresh.outputs["promote_eligible"] != "true" {
			t.Fatalf("fresh preflight = (%v, %v), want action=full_release container_exists=false promote_eligible=true", preFresh.err, preFresh.outputs)
		}
		initSubmit := replayFullReleaseSubmit(t, stageAssetsStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "10",
			forceResubmit: "false",
		})
		if initSubmit.err != nil {
			t.Fatalf("initial submit failed: %v", initSubmit.err)
		}

		// 2. Ordinary retry skips in preflight, reports wantVer, and preserves promote_eligible=true.
		preRetry := runPreflight(exitGateReplayOpts{runID: "10", forceResubmit: "false"})
		if preRetry.err != nil {
			t.Fatalf("retry preflight failed: %v", preRetry.err)
		}
		if preRetry.outputs["action"] != "skip_duplicate" ||
			preRetry.outputs["submission_status"] != "already_submitted" ||
			preRetry.outputs["staging_version"] != wantVer ||
			preRetry.outputs["promote_eligible"] != "true" {
			t.Fatalf("retry preflight outputs = %v, want action=skip_duplicate already_submitted %q promote_eligible=true", preRetry.outputs, wantVer)
		}
		wantCmd := `gh workflow run release.yml --ref "v0.2.0" -f tag="v0.2.0" -f force_resubmit=true`
		if !strings.Contains(preRetry.summary, wantCmd) {
			t.Fatalf("retry preflight summary missing %q:\n%s", wantCmd, preRetry.summary)
		}

		// Fail-closed: an unreadable manifest at the expected key during ordinary
		// retry must abort preflight rather than skipping the release as duplicate.
		preRetryNoCat := runPreflight(exitGateReplayOpts{runID: "10", forceResubmit: "false", catError: true})
		if preRetryNoCat.err == nil {
			t.Fatalf("retry preflight failed open when existing manifest could not be read: outputs=%v", preRetryNoCat.outputs)
		}
		if len(preRetryNoCat.outputs) != 0 {
			t.Fatalf("retry preflight emitted outputs despite unreadable manifest: %v", preRetryNoCat.outputs)
		}

		// Describe error on existing manifest fails closed rather than guessing promote_eligible.
		preRetryDescribeErr := runPreflight(exitGateReplayOpts{
			runID: "10", forceResubmit: "false",
			dockerEnv: map[string]string{"EXIT_GATE_DESCRIBE_ERROR": "1"},
		})
		if preRetryDescribeErr.err == nil {
			t.Fatalf("preflight failed open when objects describe errored: outputs=%v", preRetryDescribeErr.outputs)
		}

		// 3. Force-resubmitting routes to resubmit_existing (promote_eligible=false) ->
		// submit-exit-gate writes -r20.json with promote_eligible=false metadata.
		preForce := runPreflight(exitGateReplayOpts{runID: "20", forceResubmit: "true"})
		if preForce.err != nil {
			t.Fatalf("forced preflight failed: %v", preForce.err)
		}
		if preForce.outputs["action"] != "resubmit_existing" || preForce.outputs["prior_staging_version"] != wantVer || preForce.outputs["promote_eligible"] != "false" || !strings.HasSuffix(preForce.outputs["manifest_uri"], "-r20.json") {
			t.Fatalf("forced preflight outputs = %v, want action=resubmit_existing prior_staging_version=%q promote_eligible=false -r20.json", preForce.outputs, wantVer)
		}

		resub := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "20",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: preForce.outputs["prior_staging_version"],
		})
		if resub.err != nil {
			t.Fatalf("submit-exit-gate resubmit failed: %v", resub.err)
		}
		if resub.outputs["submission_status"] != "submitted" || resub.outputs["staging_version"] != wantVer {
			t.Fatalf("resub outputs = %v, want submitted %q", resub.outputs, wantVer)
		}
		for _, cmd := range resub.commands {
			if strings.HasPrefix(cmd, "artifacts generic upload") {
				t.Fatalf("submit-exit-gate must not re-upload AR packages: %s", cmd)
			}
		}
		assertExitGateManifest(t, resub.manifest, "v0.2.0", wantVer, false)
		stored := readStoreManifest(t, storeDir, resub.outputs["manifest_uri"])
		assertExitGateManifest(t, stored, "v0.2.0", wantVer, false)

		// 4. Rerunning forced dispatch RUN_ID=20 skips duplicate in BOTH preflight
		// (preserving promote_eligible=false so :latest* is NOT moved!) and submit-exit-gate.
		preForceRerun := runPreflight(exitGateReplayOpts{runID: "20", forceResubmit: "true"})
		if preForceRerun.err != nil || preForceRerun.outputs["action"] != "skip_duplicate" || preForceRerun.outputs["staging_version"] != wantVer || preForceRerun.outputs["promote_eligible"] != "false" {
			t.Fatalf("forced rerun preflight = (%v, %v), want skip_duplicate %q promote_eligible=false", preForceRerun.err, preForceRerun.outputs, wantVer)
		}
		resubRerun := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "20",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: wantVer,
		})
		if resubRerun.err != nil || resubRerun.outputs["submission_status"] != "already_submitted" || resubRerun.outputs["staging_version"] != wantVer {
			t.Fatalf("resubmit rerun = (%v, %v), want already_submitted %q", resubRerun.err, resubRerun.outputs, wantVer)
		}
		for _, cmd := range resubRerun.commands {
			if strings.HasPrefix(cmd, "storage cp") || strings.HasPrefix(cmd, "artifacts generic upload") {
				t.Fatalf("resubmit rerun attempted upload: %s", cmd)
			}
		}

		// 5. Fresh forced dispatch RUN_ID=21 submits -r21.json reusing wantVer.
		preForceNext := runPreflight(exitGateReplayOpts{runID: "21", forceResubmit: "true"})
		if preForceNext.err != nil || preForceNext.outputs["action"] != "resubmit_existing" || !strings.HasSuffix(preForceNext.outputs["manifest_uri"], "-r21.json") {
			t.Fatalf("fresh forced dispatch preflight = (%v, %v), want resubmit_existing -r21.json", preForceNext.err, preForceNext.outputs)
		}
		resubNext := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "21",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: preForceNext.outputs["prior_staging_version"],
		})
		if resubNext.err != nil {
			t.Fatalf("submit-exit-gate RUN_ID=21 failed: %v", resubNext.err)
		}
		assertExitGateManifest(t, resubNext.manifest, "v0.2.0", wantVer, false)
		if got := listStoreManifests(t, storeDir); len(got) != 3 {
			t.Fatalf("stored manifests = %v, want 3 (primary, -r20.json, -r21.json)", got)
		}

		// 6. Fail-closed: if manifest exists during force_resubmit=true but cannot be
		// read from GCS, preflight fails rather than falling back to full_release.
		preFailClosed := runPreflight(exitGateReplayOpts{runID: "22", forceResubmit: "true", catError: true})
		if preFailClosed.err == nil {
			t.Fatalf("preflight fell back instead of failing closed when manifest cat errored; outputs=%v", preFailClosed.outputs)
		}
	})

	t.Run("preflight_routes_retry_after_failed_manifest_write_to_submit_staged", func(t *testing.T) {
		storeDir := t.TempDir()
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		wantDigest := "sha256:" + strings.Repeat("c", 64)
		seedCompleteARVersion(t, storeDir, "v0.2.0", wantVer, true)

		pre := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "30",
			forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_OCI_DEFAULT_CODE":       "200",
				"FAKE_OCI_DEFAULT_DIGEST":     wantDigest,
				"FAKE_OCI_DIGEST_HEADER_NAME": "docker-content-digest",
			},
		}, false)
		if pre.err != nil {
			t.Fatalf("submit_staged preflight failed: %v", pre.err)
		}
		if pre.outputs["action"] != "submit_staged" ||
			pre.outputs["staging_version"] != wantVer ||
			pre.outputs["container_exists"] != "true" ||
			pre.outputs["container_digest"] != wantDigest ||
			pre.outputs["ar_staged_partial"] != "false" {
			t.Fatalf("submit_staged preflight outputs = %v", pre.outputs)
		}
		if len(pre.cosignCalls) != 2 || pre.cosignCalls[0][0] != "verify" || pre.cosignCalls[1][0] != "verify-blob" {
			t.Fatalf("expected cosign verify + verify-blob in preflight, got %q", pre.cosignCalls)
		}
		if len(pre.ghCalls) != 2 ||
			pre.ghCalls[0][0] != "attestation" || pre.ghCalls[0][1] != "verify" || !strings.HasPrefix(pre.ghCalls[0][2], "oci://") || !slices.Contains(pre.ghCalls[0], "--source-digest") ||
			pre.ghCalls[1][0] != "attestation" || pre.ghCalls[1][1] != "verify" || !strings.HasSuffix(pre.ghCalls[1][2], "/EXIT_GATE_CHANGELOG") || !slices.Contains(pre.ghCalls[1], "--source-digest") {
			t.Fatalf("expected 2 gh attestation verify calls with --source-digest (OCI image + EXIT_GATE_CHANGELOG) in preflight, got %q", pre.ghCalls)
		}

		// Verify reconcile_container also cleanly consumes cosign verify JSON stdout
		// and passes --source-digest when reusing an attested container.
		reconcileStep := findReleaseStep(t, "reconcile_container")
		recOK := runWorkflowBashScript(t, reconcileStep.Run, exitGateReplayOpts{
			tag:       "v0.2.0",
			commitSHA: commitSHA,
			dockerEnv: map[string]string{
				"FAKE_OCI_DEFAULT_CODE":       "200",
				"FAKE_OCI_DEFAULT_DIGEST":     wantDigest,
				"FAKE_OCI_DIGEST_HEADER_NAME": "docker-content-digest",
			},
		}, false)
		if recOK.err != nil || recOK.outputs["container_exists"] != "true" || recOK.outputs["digest"] != wantDigest {
			t.Fatalf("reconcile_container with verified image = (%v, %v), want container_exists=true digest=%s", recOK.err, recOK.outputs, wantDigest)
		}
		if len(recOK.ghCalls) != 1 || !slices.Contains(recOK.ghCalls[0], "--source-digest") || !slices.Contains(recOK.ghCalls[0], commitSHA) {
			t.Fatalf("reconcile_container gh attestation verify missing --source-digest: %q", recOK.ghCalls)
		}

		sub := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "30",
			forceResubmit:       "false",
			action:              "submit_staged",
			preflightStagingVer: pre.outputs["staging_version"],
		})
		if sub.err != nil || sub.outputs["submission_status"] != "submitted" {
			t.Fatalf("submit-exit-gate after submit_staged = (%v, %v), want submitted", sub.err, sub.outputs)
		}
		assertExitGateManifest(t, sub.manifest, "v0.2.0", wantVer, false)
	})

	t.Run("preflight_and_reconcile_container_partial_and_fail_closed_cases", func(t *testing.T) {
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		otherSHA := "fedcba9876543210fedcba9876543210fedcba98"
		wantDigest := "sha256:" + strings.Repeat("c", 64)
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)

		// Verified GHCR container for exact commit & version + partial AR -> full_release
		// with container_exists=true and ar_staged_partial=true; reconcile_container
		// returns container_exists=true + digest so GoReleaser skips docker rebuild/push.
		partialStore := t.TempDir()
		seedARFiles(t, partialStore, wantVer, requiredArchiveFiles("v0.2.0")[:3])
		prePartial := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir:      partialStore,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "40",
			forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_OCI_DEFAULT_CODE":   "200",
				"FAKE_OCI_DEFAULT_DIGEST": wantDigest,
			},
		}, false)
		if prePartial.err != nil {
			t.Fatalf("partial AR preflight failed: %v", prePartial.err)
		}
		if prePartial.outputs["action"] != "full_release" ||
			prePartial.outputs["container_exists"] != "true" ||
			prePartial.outputs["container_digest"] != wantDigest ||
			prePartial.outputs["ar_staged_partial"] != "true" {
			t.Fatalf("partial AR preflight outputs = %v", prePartial.outputs)
		}

		// Unexpected file in AR is flagged ar_staged_partial=true rather than complete.
		extraARStore := t.TempDir()
		seedCompleteARVersion(t, extraARStore, "v0.2.0", wantVer, false)
		if err := os.WriteFile(filepath.Join(extraARStore, "ar", wantVer, "unexpected.bin"), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		preExtra := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir:      extraARStore,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "40",
			forceResubmit: "false",
		}, false)
		if preExtra.err != nil || preExtra.outputs["action"] != "full_release" || preExtra.outputs["ar_staged_partial"] != "true" {
			t.Fatalf("unexpected-file AR preflight = (%v, %v), want action=full_release ar_staged_partial=true", preExtra.err, preExtra.outputs)
		}

		recOK := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
			tag:       "v0.2.0",
			commitSHA: commitSHA,
			dockerEnv: map[string]string{
				"LC_ALL":                         "en_US.UTF-8",
				"LANG":                           "en_US.UTF-8",
				"FAKE_OCI_DEFAULT_CODE":          "200",
				"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
				"FAKE_OCI_DIGEST_HEADER_NAME":    "docker-content-digest",
				"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
				"FAKE_OCI_MANIFEST_PRE_HEADERS":  "HTTP/1.1 103 Early Hints\r\nDocker-Content-Digest: sha256:" + strings.Repeat("9", 64) + "\r\n\r\n",
				"FAKE_OCI_MANIFEST_RAW_HEADERS":  "X-Note: caf\xe9\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\n\r\nServer-Timing: origin;\r\n dur=7\r\n",
			},
		}, false)
		if recOK.err != nil || recOK.outputs["container_exists"] != "true" || recOK.outputs["digest"] != wantDigest {
			t.Fatalf("reconcile_container = (%v, %v), want container_exists=true digest=%s", recOK.err, recOK.outputs, wantDigest)
		}
		if len(recOK.ghCalls) != 1 || len(recOK.cosignCalls) != 1 {
			t.Fatalf("reconcile_container reuse expected 1 cosign + 1 gh call, got cosign=%q gh=%q", recOK.cosignCalls, recOK.ghCalls)
		}

		recMissing := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
			tag:       "v0.2.0",
			commitSHA: commitSHA,
		}, false)
		if recMissing.err != nil || recMissing.outputs["container_exists"] != "false" || recMissing.outputs["digest"] != "" {
			t.Fatalf("reconcile_container on 404 = (%v, %v), want container_exists=false empty digest", recMissing.err, recMissing.outputs)
		}

		// Fail-closed checks in BOTH preflight.check_submission and release.reconcile_container.
		failCases := []struct {
			name        string
			dockerEnv   map[string]string
			wantErrText string
		}{
			{
				name: "different_commit_owns_ghcr_tag",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_DOCKER_ARM64_COMMIT": otherSHA,
				},
			},
			{
				name: "wrong_version_label_owns_ghcr_tag",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":     "200",
					"FAKE_OCI_DEFAULT_DIGEST":   wantDigest,
					"FAKE_DOCKER_ARM64_VERSION": "0.2.0-rc.1",
				},
			},
			{
				name: "http_500_containing_404_substring_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE": "500",
					"FAKE_OCI_DEFAULT_BODY": "upstream error 404 manifest unknown",
				},
			},
			{
				name: "http_404_html_not_manifest_unknown_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE": "404",
					"FAKE_OCI_DEFAULT_BODY": "<html>404 Not Found</html>",
				},
			},
			{
				name: "http_404_empty_errors_array_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE": "404",
					"FAKE_OCI_DEFAULT_BODY": `{"errors":[]}`,
				},
			},
			{
				name: "http_403_unauthorized_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE": "403",
					"FAKE_OCI_DEFAULT_BODY": "unauthorized",
				},
			},
			{
				name: "http_200_missing_digest_header_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":   "200",
					"FAKE_OCI_DEFAULT_DIGEST": "",
				},
			},
			{
				name: "http_103_digest_ignored_when_200_missing_digest_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        "",
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_MANIFEST_PRE_HEADERS":  "HTTP/1.1 103 Early Hints\r\nDocker-Content-Digest: " + wantDigest + "\r\n\r\n",
				},
			},
			{
				name: "http_200_conflicting_digest_headers_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":         "200",
					"FAKE_OCI_DEFAULT_DIGEST":       wantDigest,
					"FAKE_OCI_MANIFEST_RAW_HEADERS": "Docker-Content-Digest: sha256:" + strings.Repeat("9", 64) + "\r\n",
				},
			},
			{
				name: "http_200_midblock_http2_custom_header_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":         "200",
					"FAKE_OCI_DEFAULT_DIGEST":       wantDigest,
					"FAKE_OCI_MANIFEST_RAW_HEADERS": "HTTP/2-Custom: foo\r\n",
				},
			},
			{
				name: "http_200_docker_content_digest_trailer_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_MANIFEST_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\nDocker-Content-Digest: " + wantDigest + "\r\n",
				},
			},
			{
				name: "http_200_http11_cl0_stray_trailer_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_MANIFEST_RAW_HEADERS":  "Content-Length: 0\r\n\r\nServer-Timing: origin;dur=7\r\n",
				},
			},
			{
				name: "http_200_chunked_empty_trailer_closed_then_stray_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_MANIFEST_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\n\r\nServer-Timing: origin;dur=7\r\n",
				},
			},
			{
				name: "http_200_chunked_trailer_del_control_byte_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_MANIFEST_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\nServer-Timing: a\x7fb\r\n",
				},
			},
			{
				name: "http_200_http10_chunked_stray_trailer_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_OCI_MANIFEST_HTTP_VERSION": "HTTP/1.0",
					"FAKE_OCI_MANIFEST_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\nServer-Timing: origin;dur=7\r\n",
				},
			},
			{
				name: "http_200_embedded_cr_header_name_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":         "200",
					"FAKE_OCI_DEFAULT_DIGEST":       wantDigest,
					"FAKE_OCI_MANIFEST_RAW_HEADERS": "X-Met\rric: v\r\n",
				},
			},
			{
				name: "http_200_double_cr_header_fails_closed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":         "200",
					"FAKE_OCI_DEFAULT_DIGEST":       wantDigest,
					"FAKE_OCI_MANIFEST_RAW_HEADERS": "X-Note: v\r\r\n",
				},
			},
			{
				name: "unsigned_or_cosign_verify_failed_emits_recovery_guidance",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":   "200",
					"FAKE_OCI_DEFAULT_DIGEST": wantDigest,
					"FAKE_COSIGN_FAIL":        "1",
				},
				wantErrText: "delete the unsigned package version",
			},
			{
				name: "gh_attestation_verify_failed",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "1",
				},
			},
		}
		for _, tc := range failCases {
			t.Run(tc.name, func(t *testing.T) {
				preFail := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					tag:           "v0.2.0",
					commitSHA:     commitSHA,
					runID:         "41",
					forceResubmit: "false",
					dockerEnv:     tc.dockerEnv,
				}, false)
				if preFail.err == nil {
					t.Fatalf("preflight failed open for %s: outputs=%v", tc.name, preFail.outputs)
				}
				if tc.wantErrText != "" && !strings.Contains(preFail.err.Error(), tc.wantErrText) {
					t.Fatalf("preflight error for %s missing %q: %v", tc.name, tc.wantErrText, preFail.err)
				}
				recFail := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag:       "v0.2.0",
					commitSHA: commitSHA,
					dockerEnv: tc.dockerEnv,
				}, false)
				if recFail.err == nil {
					t.Fatalf("reconcile_container failed open for %s: outputs=%v", tc.name, recFail.outputs)
				}
				if tc.wantErrText != "" && !strings.Contains(recFail.err.Error(), tc.wantErrText) {
					t.Fatalf("reconcile_container error for %s missing %q: %v", tc.name, tc.wantErrText, recFail.err)
				}
			})
		}

		// Complete AR that fails cosign verify-blob or archive SHA-256 verification fails closed in preflight.
		corruptARStore := t.TempDir()
		seedCompleteARVersion(t, corruptARStore, "v0.2.0", wantVer, true)
		if err := os.WriteFile(filepath.Join(corruptARStore, "ar", wantVer, "otelcol-bq_0.2.0_linux_amd64.tar.gz"), []byte("tampered\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if res := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: corruptARStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "42", forceResubmit: "false",
		}, false); res.err == nil {
			t.Fatalf("preflight failed open on tampered AR archive: outputs=%v", res.outputs)
		}

		badSigStore := t.TempDir()
		seedCompleteARVersion(t, badSigStore, "v0.2.0", wantVer, true)
		if res := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: badSigStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "42", forceResubmit: "false",
			dockerEnv: map[string]string{"FAKE_COSIGN_VERIFY_BLOB_FAIL": "1"},
		}, false); res.err == nil {
			t.Fatalf("preflight failed open on AR cosign verify-blob error: outputs=%v", res.outputs)
		}

		// AR missing EXIT_GATE_CHANGELOG (only 13 files) routes to full_release (ar_staged_partial=true)
		// rather than short-circuiting to submit_staged and dropping release notes.
		noCLStore := t.TempDir()
		seedCompleteARVersion(t, noCLStore, "v0.2.0", wantVer, false)
		preNoCL := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: noCLStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "42", forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_OCI_DEFAULT_CODE":   "200",
				"FAKE_OCI_DEFAULT_DIGEST": wantDigest,
			},
		}, false)
		if preNoCL.err != nil || preNoCL.outputs["action"] != "full_release" || preNoCL.outputs["ar_staged_partial"] != "true" {
			t.Fatalf("13-file AR without changelog = (%v, %v), want action=full_release ar_staged_partial=true", preNoCL.err, preNoCL.outputs)
		}

		arErr := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "42",
			forceResubmit: "false",
			arListError:   true,
		}, false)
		if arErr.err == nil {
			t.Fatalf("preflight failed open on AR files list error: outputs=%v", arErr.outputs)
		}

		// Confirmed missing container provenance (verified Cosign + commit/version labels,
		// missing gh attestation, and zero SLSA/ambiguous referrers across all pages) must
		// NOT reuse and attest the existing image digest: both preflight and
		// reconcile_container emit container_exists=false with empty digest so full
		// release rebuilds, signs, and freshly attests the new digest.
		completeARStore := t.TempDir()
		seedCompleteARVersion(t, completeARStore, "v0.2.0", wantVer, true)
		sbomPage1 := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","size":512,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://spdx.dev/Document"}}]}`
		sbomPage2 := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`
		slsaPage := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":512,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}`
		initialRefURL := "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest
		page2RefURL := initialRefURL + "?page=2"
		recordedCurlReferrersURLs := func(calls [][]string) []string {
			var urls []string
			for _, args := range calls {
				for _, arg := range args {
					if (strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://")) && strings.Contains(arg, "/referrers/") {
						urls = append(urls, arg)
					}
				}
			}
			return urls
		}
		if multiGot := recordedCurlReferrersURLs([][]string{{"curl", "-sS", initialRefURL, page2RefURL}}); !slices.Equal(multiGot, []string{initialRefURL, page2RefURL}) {
			t.Fatalf("recordedCurlReferrersURLs multi-URL invocation = %q, want [%q %q]", multiGot, initialRefURL, page2RefURL)
		}
		for _, refTC := range []struct {
			name        string
			env         map[string]string
			wantRefURLs []string
		}{
			{
				name: "empty_referrers",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY": `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
				},
				wantRefURLs: []string{initialRefURL},
			},
			{
				name: "sbom_only_referrer",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY": sbomPage1,
				},
				wantRefURLs: []string{initialRefURL},
			},
			{
				name: "paginated_sbom_only_referrers",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + "|" + "200|" + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sbom1>; rel="next"`,
						wantDigest + "?last=sbom1|200|" + sbomPage2 + "|",
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, initialRefURL + "?last=sbom1"},
			},
			{
				name: "paginated_opaque_colon_slash_token",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + "|" + "200|" + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sha256:abcd1234&cursor=sha256:1234/page2>; rel="next"`,
						wantDigest + "?last=sha256:abcd1234&cursor=sha256:1234/page2|200|" + sbomPage2 + "|",
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, initialRefURL + "?last=sha256:abcd1234&cursor=sha256:1234/page2"},
			},
			{
				name: "paginated_quoted_semicolon_extension_param",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; title="a;b"; rel="next"`,
						wantDigest + "?page=2|200|" + sbomPage2 + "|",
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "paginated_query_relative_next_link",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<?page=2>; rel="next"`,
						wantDigest + "?page=2|200|" + sbomPage2 + "|",
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "paginated_dot_relative_and_parent_with_comma_cursor",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<./` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|<../referrers/` + wantDigest + `?cursor=a,b>; rel="next"`,
						wantDigest + `?cursor=a,b|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL, initialRefURL + "?cursor=a,b"},
			},
			{
				name: "valid_sha512_sbom_descriptor",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY": `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha512:` + strings.Repeat("a", 128) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantRefURLs: []string{initialRefURL},
			},
			{
				name: "paginated_valid_pct_escape_dot_relative",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<./part%20ok/../` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "early_hints_103_filtered_header_and_bad_link_ignored_before_clean_200",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_PRE_HEADERS":  `HTTP/1.1 103 Early Hints\r\nOCI-Filters-Applied: artifactType\r\nLink: </bad>; rel="next"\r\n\r\n`,
				},
				wantRefURLs: []string{initialRefURL},
			},
			{
				name: "continue_100_before_200_with_valid_link",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<?page=2>; rel="next"||` + `HTTP/1.1 100 Continue\r\n\r\n`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "paginated_dot_colon_first_segment_relative",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<./1:part/../` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "folded_link_and_whitespace_only_continuation",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||X-Note: alpha\r\n   \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>;\r\n   rel="next"`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "single_space_fold_before_link_paginates",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||X-Fold: a\r\n \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + sbomPage2 + `|`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_chunked_server_timing_trailer_and_obstext_with_locale",
				env: map[string]string{
					"LC_ALL":                          "en_US.UTF-8",
					"LANG":                            "en_US.UTF-8",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||X-Note: caf\xe9\r\nTransfer-Encoding: chunked\r\nTrailer: Server-Timing\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;\r\n dur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Transfer-Encoding: chunked\r\n\r\nServer-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_chunked_trailing_comma_and_empty_repeat_walks_both_pages",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: chunked\r\nTransfer-Encoding:\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;dur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Transfer-Encoding: , gzip , , chunked , \r\n\r\nServer-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_chunked_comma_trailer_walks_both_pages",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: chunked,\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;dur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Transfer-Encoding: chunked,   \r\n\r\nServer-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_http2_server_timing_trailer_without_te",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/2",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Link: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;\tdur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Server-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_parameterized_earlier_te_with_quoted_comma_walks_both_pages",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: x-custom;q=0, example;mode="a\"b,c";v=1, chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;dur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Transfer-Encoding: example;mode="a,b", chunked\r\n\r\nServer-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
			{
				name: "harmless_obs_fold_and_empty_quoted_te_walks_both_pages",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: example;a="foo\r\n bar", chunked\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"\r\n\r\nServer-Timing: origin;dur=7`,
						wantDigest + `?page=2|200|` + sbomPage2 + `||Transfer-Encoding: example;mode="", chunked\r\n\r\nServer-Timing: page2;dur=3`,
					}, "\n"),
				},
				wantRefURLs: []string{initialRefURL, page2RefURL},
			},
		} {
			t.Run("missing_provenance_recovery_"+refTC.name, func(t *testing.T) {
				if refTC.wantRefURLs == nil {
					t.Fatalf("missing_provenance_recovery (%s) must define wantRefURLs", refTC.name)
				}
				env := map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
				}
				maps.Copy(env, refTC.env)
				preMiss := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					storeDir: completeARStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "43", forceResubmit: "false",
					dockerEnv: env,
				}, false)
				if preMiss.err != nil ||
					preMiss.outputs["action"] != "full_release" ||
					preMiss.outputs["container_exists"] != "false" ||
					preMiss.outputs["container_provenance_verified"] != "false" ||
					preMiss.outputs["container_digest"] != "" {
					t.Fatalf("missing provenance preflight (%s) = (%v, %v), want action=full_release container_exists=false container_provenance_verified=false empty digest", refTC.name, preMiss.err, preMiss.outputs)
				}
				if gotURLs := recordedCurlReferrersURLs(preMiss.curlCalls); !slices.Equal(gotURLs, refTC.wantRefURLs) {
					t.Fatalf("missing provenance preflight (%s) referrers URLs = %q, want %q (all curlCalls=%q)", refTC.name, gotURLs, refTC.wantRefURLs, preMiss.curlCalls)
				}
				recMiss := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: env,
				}, false)
				if recMiss.err != nil ||
					recMiss.outputs["container_exists"] != "false" ||
					recMiss.outputs["digest"] != "" {
					t.Fatalf("missing provenance reconcile_container (%s) = (%v, %v), want container_exists=false empty digest", refTC.name, recMiss.err, recMiss.outputs)
				}
				if gotURLs := recordedCurlReferrersURLs(recMiss.curlCalls); !slices.Equal(gotURLs, refTC.wantRefURLs) {
					t.Fatalf("missing provenance reconcile_container (%s) referrers URLs = %q, want %q (all curlCalls=%q)", refTC.name, gotURLs, refTC.wantRefURLs, recMiss.curlCalls)
				}
			})
		}

		// A digest containing HTTP-status-like digits (403, 502) must NOT trigger a
		// false lookup error when gh prints "no attestations found for subject
		// oci://...@sha256:403502...", whereas a genuine HTTP 502 lookup failure
		// on that same digest still fails closed.
		statusDigitsDigest := "sha256:403502" + strings.Repeat("c", 58)
		statusDigitsRefURL := "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/" + statusDigitsDigest
		t.Run("missing_provenance_recovery_digest_with_status_digits", func(t *testing.T) {
			env := map[string]string{
				"FAKE_OCI_DEFAULT_CODE":    "200",
				"FAKE_OCI_DEFAULT_DIGEST":  statusDigitsDigest,
				"FAKE_GH_ATTESTATION_FAIL": "missing",
				"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
			}
			wantStatusDigitsRefURLs := []string{statusDigitsRefURL}
			preMiss := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
				storeDir: completeARStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "45", forceResubmit: "false",
				dockerEnv: env,
			}, false)
			if preMiss.err != nil ||
				preMiss.outputs["action"] != "full_release" ||
				preMiss.outputs["container_exists"] != "false" ||
				preMiss.outputs["container_provenance_verified"] != "false" ||
				preMiss.outputs["container_digest"] != "" {
				t.Fatalf("missing provenance preflight (statusDigitsDigest) = (%v, %v), want action=full_release container_exists=false container_provenance_verified=false empty digest", preMiss.err, preMiss.outputs)
			}
			if gotURLs := recordedCurlReferrersURLs(preMiss.curlCalls); !slices.Equal(gotURLs, wantStatusDigitsRefURLs) {
				t.Fatalf("missing provenance preflight (statusDigitsDigest) referrers URLs = %q, want %q (all curlCalls=%q)", gotURLs, wantStatusDigitsRefURLs, preMiss.curlCalls)
			}
			recMiss := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: env,
			}, false)
			if recMiss.err != nil ||
				recMiss.outputs["container_exists"] != "false" ||
				recMiss.outputs["digest"] != "" {
				t.Fatalf("missing provenance reconcile_container (statusDigitsDigest) = (%v, %v), want container_exists=false empty digest", recMiss.err, recMiss.outputs)
			}
			if gotURLs := recordedCurlReferrersURLs(recMiss.curlCalls); !slices.Equal(gotURLs, wantStatusDigitsRefURLs) {
				t.Fatalf("missing provenance reconcile_container (statusDigitsDigest) referrers URLs = %q, want %q (all curlCalls=%q)", gotURLs, wantStatusDigitsRefURLs, recMiss.curlCalls)
			}
		})

		// Build a >20 page pagination chain to ensure unbounded referrers fail closed.
		var overMaxRoutes []string
		var overMaxWantURLs []string
		for p := 1; p <= 21; p++ {
			suffix := wantDigest
			if p > 1 {
				suffix = fmt.Sprintf("%s?p=%d", wantDigest, p)
			}
			if p <= 20 {
				overMaxWantURLs = append(overMaxWantURLs, "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/"+suffix)
			}
			nextLink := fmt.Sprintf(`</v2/googlecloudplatform/bq-otel-collector/referrers/%s?p=%d>; rel="next"`, wantDigest, p+1)
			overMaxRoutes = append(overMaxRoutes, suffix+"|200|"+sbomPage2+"|"+nextLink)
		}

		errPatExistingProv := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Container %s@%s has existing provenance/Sigstore referrer(s) in GHCR, yet verification failed (Error: no attestations found for subject oci://%s@%s); failing closed.",
			releaseImage, wantDigest, releaseImage, wantDigest,
		))
		errPatAttest403 := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Attestation verification lookup failed for %s@%s: HTTP 403 Forbidden: Resource not accessible by integration",
			releaseImage, wantDigest,
		))
		errPatAttest502 := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Attestation verification lookup failed for %s@%s: HTTP 502 Bad Gateway fetching attestations for oci://%s@%s",
			releaseImage, statusDigitsDigest, releaseImage, statusDigitsDigest,
		))
		errPatInvalidJSON := func(firstBodyLine string) *regexp.Regexp {
			return exactErrorLineRegexp(fmt.Sprintf(
				"::error::Invalid or incomplete GHCR OCI referrers JSON for '%s': %s",
				wantDigest, firstBodyLine,
			))
		}
		errPatMalformedLink := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Malformed or untrusted Link pagination header in GHCR referrers response for '%s'.",
			wantDigest,
		))
		errPatFiltersApplied := exactErrorLineRegexp(fmt.Sprintf(
			"::error::GHCR OCI referrers response for '%s' unexpectedly reported filtering (OCI-Filters-Applied: artifactType); treating lookup as indeterminate.",
			wantDigest,
		))
		errPatMalformedHeaders := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Malformed HTTP response headers while checking OCI-Filters-Applied for '%s'.",
			wantDigest,
		))
		errPatCyclicLink := exactErrorLineRegexp(fmt.Sprintf(
			"::error::Detected cyclic Link pagination in GHCR referrers for '%s': %s",
			wantDigest, initialRefURL,
		))
		errPatExceededPages := exactErrorLineRegexp(fmt.Sprintf(
			"::error::GHCR OCI referrers pagination exceeded 20 pages for '%s'; failing closed.",
			wantDigest,
		))
		errPatHTTP500 := exactErrorLineRegexp(fmt.Sprintf(
			`::error::GHCR OCI referrers query returned HTTP 500 for '%s' ({"errors":[{"code":"INTERNAL"}]}); failing closed.`,
			wantDigest,
		))

		// Ambiguous, invalid, incomplete, or transient-error provenance classification MUST fail closed.
		for _, badRef := range []struct {
			name           string
			env            map[string]string
			wantErrPattern *regexp.Regexp
			wantRefURLs    []string
		}{
			{
				name: "slsa_provenance_referrer_exists_but_verify_failed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  slsaPage,
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "unannotated_sigstore_referrer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":256,"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json"}]}`,
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "incomplete_referrers_missing_manifests_field_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_null_descriptor_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[null]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[null]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_empty_object_descriptor_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_missing_size_descriptor_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_non_string_annotation_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":256,"annotations":{"dev.sigstore.bundle.predicateType":123}}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":256,"annotations":{"dev.sigstore.bundle.predicateType":123}}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_concatenated_multi_doc_index_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  slsaPage + "\n" + `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
				},
				wantErrPattern: errPatInvalidJSON(slsaPage),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_paginated_page1_sbom_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sbom>; rel="next"`,
						wantDigest + `?last=sbom|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL, initialRefURL + "?last=sbom"},
			},
			{
				name: "referrers_paginated_query_relative_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL, page2RefURL},
			},
			{
				name: "referrers_paginated_opaque_colon_slash_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sha256:abcd1234&cursor=sha256:1234/page2>; rel="next"`,
						wantDigest + `?last=sha256:abcd1234&cursor=sha256:1234/page2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL, initialRefURL + "?last=sha256:abcd1234&cursor=sha256:1234/page2"},
			},
			{
				name: "referrers_malformed_rel_trailing_junk_hiding_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"junk`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_malformed_rel_trailing_garbage_hiding_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next" garbage`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_malformed_rel_double_equals_hiding_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel==next`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_empty_param_name_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; =foo; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_missing_rel_param_hiding_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; title="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_quoted_semicolon_inside_rel_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next;foo"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_duplicate_rel_in_clause_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="prev"; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_continuation_adds_artifactType_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<?page=2&artifactType=application/spdx+json>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_continuation_adds_pct_artifactType_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<?page=2&%61rtifactType=application/spdx+json>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "oci_filters_applied_empty_index_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":          "200",
					"FAKE_OCI_DEFAULT_DIGEST":        wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":       "missing",
					"FAKE_OCI_REFERRERS_BODY":        `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
					"FAKE_OCI_REFERRERS_RAW_HEADERS": "OCI-Filters-Applied: artifactType",
				},
				wantErrPattern: errPatFiltersApplied,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "oci_filters_applied_lowercase_page2_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<?page=2>; rel="next"`,
						wantDigest + `?page=2|200|{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}||oci-filters-applied: artifactType`,
					}, "\n"),
				},
				wantErrPattern: errPatFiltersApplied,
				wantRefURLs:    []string{initialRefURL, page2RefURL},
			},
			{
				name: "referrers_truncated_sha256_digest_on_page2_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<?page=2>; rel="next"`,
						wantDigest + `?page=2|200|{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 32) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}|`,
					}, "\n"),
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 32) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL, page2RefURL},
			},
			{
				name: "referrers_uppercase_sha256_digest_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("A", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("A", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_truncated_sha512_digest_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha512:` + strings.Repeat("a", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha512:` + strings.Repeat("a", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_disallowed_digest_algorithm_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256-evil:` + strings.Repeat("a", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256-evil:` + strings.Repeat("a", 64) + `","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_sha256_trailing_newline_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha256:` + strings.Repeat("a", 64) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_sha384_trailing_newline_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha384:` + strings.Repeat("a", 96) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha384:` + strings.Repeat("a", 96) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_sha512_trailing_newline_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha512:` + strings.Repeat("a", 128) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`,
				},
				wantErrPattern: errPatInvalidJSON(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.artifact.manifest.v1+json","digest":"sha512:` + strings.Repeat("a", 128) + `\n","size":256,"artifactType":"application/vnd.example.sbom+json"}]}`),
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "early_hints_103_clean_before_200_oci_filters_applied_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_BODY":         `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_PRE_HEADERS":  "HTTP/1.1 103 Early Hints\r\n\r\n",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "OCI-Filters-Applied: artifactType",
				},
				wantErrPattern: errPatFiltersApplied,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_dot_relative_bad_pct_zz_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<./part%ZZ/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_abs_path_bad_pct_zz_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/part%ZZ/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_https_url_bad_pct_zz_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/part%ZZ/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_network_path_short_pct2_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<//ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/part%2/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_dot_relative_nul_pct00_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<./part%00/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_dot_relative_illegal_brackets_path_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<./part[bad]/../` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_parent_traversal_escape_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<../other/` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_bare_digest_colon_relative_link_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<` + wantDigest + `?cursor=a,b>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_fragment_in_next_link_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<./` + wantDigest + `?page=2#frag>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_relative_link_adds_artifactType_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<./` + wantDigest + `?page=2&artifactType=application/spdx+json>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_protocol_relative_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<//evil.example/v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_empty_rel_quoted_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=next>; rel=""`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_empty_rel_unquoted_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=next>; rel=`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_bare_rel_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=next>; rel`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_malformed_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `garbage-link-header`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_untrusted_host_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `<https://evil.example/v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_wrong_digest_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/sha256:` + strings.Repeat("0", 64) + `>; rel="next"`,
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_cyclic_link_header_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  sbomPage1,
					"FAKE_OCI_REFERRERS_LINK":  `</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `>; rel="next"`,
				},
				wantErrPattern: errPatCyclicLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_exceeds_max_pages_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":     "200",
					"FAKE_OCI_DEFAULT_DIGEST":   wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":  "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join(overMaxRoutes, "\n"),
				},
				wantErrPattern: errPatExceededPages,
				wantRefURLs:    overMaxWantURLs,
			},
			{
				name: "referrers_http_500_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_CODE":  "500",
					"FAKE_OCI_REFERRERS_BODY":  `{"errors":[{"code":"INTERNAL"}]}`,
				},
				wantErrPattern: errPatHTTP500,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "gh_403_lookup_error_even_with_empty_referrers_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "403",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[]}`,
				},
				wantErrPattern: errPatAttest403,
				wantRefURLs:    []string{},
			},
			{
				name: "gh_502_lookup_error_on_status_digits_digest_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  statusDigitsDigest,
					"FAKE_GH_ATTESTATION_FAIL": "502",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[]}`,
				},
				wantErrPattern: errPatAttest502,
				wantRefURLs:    []string{},
			},
			{
				name: "referrers_colon_first_segment_relative_link_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|<1:part/../` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedLink,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_whitespace_continuation_before_filters_applied_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "X-Note: alpha\r\n   \r\nOCI-Filters-Applied: artifactType",
					"FAKE_OCI_REFERRERS_BODY":         `{"schemaVersion":2,"manifests":[]}`,
				},
				wantErrPattern: errPatFiltersApplied,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_midblock_http2_custom_before_filters_applied_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "OCI-Filters-Applied: artifactType\r\nHTTP/2-Custom: foo",
					"FAKE_OCI_REFERRERS_BODY":         `{"schemaVersion":2,"manifests":[]}`,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_single_space_fold_before_filters_applied_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "X-Fold: a\r\n \r\nOCI-Filters-Applied: artifactType",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatFiltersApplied,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_single_space_fold_before_link_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||X-Fold: a\r\n \r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatExistingProv,
				wantRefURLs:    []string{initialRefURL, page2RefURL},
			},
			{
				name: "referrers_chunked_link_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: chunked\r\n\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_chunked_filters_applied_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\nOCI-Filters-Applied: artifactType",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_sensitive_link_after_harmless_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `||Transfer-Encoding: chunked\r\n\r\nServer-Timing: x\r\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?page=2>; rel="next"`,
						wantDigest + `?page=2|200|` + slsaPage + `|`,
					}, "\n"),
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_http11_cl0_stray_field_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Content-Length: 2\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_chunked_empty_trailer_closed_then_stray_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_trailer_vt_control_byte_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked\r\n\r\nServer-Timing: ok\r\n \x0bcont",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_midblock_http2_colon_x_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "OCI-Filters-Applied: artifactType\r\nHTTP/2: x",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_gzip_comma_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: gzip,\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_empty_only_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: , ,\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_duplicate_chunked_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_two_chunked_headers_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked\r\nTransfer-Encoding: Chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_malformed_before_chunked_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: bad coding, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_parameterized_chunked_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked;q=1\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_unclosed_quoted_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: example;mode=\"unclosed, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_badparam_before_chunked_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: example;badparam, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_chunked_not_final_after_quoted_param_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: chunked, example;mode=\"a,b\"\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_gzip_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: gzip;q=0, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_deflate_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: deflate;level=1, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_compress_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: compress;v=1, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_x_gzip_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: x-gzip;q=0, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_x_compress_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: x-compress;v=1, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_mixed_case_gzip_param_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: GZip;q=0, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_quotes_across_fields_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: example;a=\"foo\r\nTransfer-Encoding: bar\", chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
			{
				name: "referrers_te_empty_token_val_trailer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":           "200",
					"FAKE_OCI_DEFAULT_DIGEST":         wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":        "missing",
					"FAKE_OCI_REFERRERS_HTTP_VERSION": "HTTP/1.1",
					"FAKE_OCI_REFERRERS_RAW_HEADERS":  "Transfer-Encoding: example;mode=, chunked\r\n\r\nServer-Timing: origin;dur=7",
					"FAKE_OCI_REFERRERS_BODY":         sbomPage1,
				},
				wantErrPattern: errPatMalformedHeaders,
				wantRefURLs:    []string{initialRefURL},
			},
		} {
			t.Run("provenance_fail_closed_"+badRef.name, func(t *testing.T) {
				if badRef.wantErrPattern == nil {
					t.Fatalf("badRef case %s must define wantErrPattern", badRef.name)
				}
				if badRef.wantRefURLs == nil {
					t.Fatalf("badRef case %s must define wantRefURLs", badRef.name)
				}
				preRes := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, runID: "44", forceResubmit: "false", dockerEnv: badRef.env,
				}, false)
				if preRes.err == nil {
					t.Fatalf("preflight failed open for %s: outputs=%v", badRef.name, preRes.outputs)
				}
				if ok, gotErrLines := matchGitHubErrorLines(preRes.combinedOut, badRef.wantErrPattern); !ok {
					t.Fatalf("preflight error lines for %s = %q, want single line matching %s (raw err=%v)", badRef.name, gotErrLines, badRef.wantErrPattern, preRes.err)
				}
				if gotURLs := recordedCurlReferrersURLs(preRes.curlCalls); !slices.Equal(gotURLs, badRef.wantRefURLs) {
					t.Fatalf("preflight (%s) referrers URLs = %q, want %q (all curlCalls=%q)", badRef.name, gotURLs, badRef.wantRefURLs, preRes.curlCalls)
				}
				recRes := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: badRef.env,
				}, false)
				if recRes.err == nil {
					t.Fatalf("reconcile_container failed open for %s: outputs=%v", badRef.name, recRes.outputs)
				}
				if ok, gotErrLines := matchGitHubErrorLines(recRes.combinedOut, badRef.wantErrPattern); !ok {
					t.Fatalf("reconcile_container error lines for %s = %q, want single line matching %s (raw err=%v)", badRef.name, gotErrLines, badRef.wantErrPattern, recRes.err)
				}
				if gotURLs := recordedCurlReferrersURLs(recRes.curlCalls); !slices.Equal(gotURLs, badRef.wantRefURLs) {
					t.Fatalf("reconcile_container (%s) referrers URLs = %q, want %q (all curlCalls=%q)", badRef.name, gotURLs, badRef.wantRefURLs, recRes.curlCalls)
				}
			})
		}
	})

	t.Run("legacy_manifest_without_custom_metadata_handles_null_describe", func(t *testing.T) {
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		tagSum := sha256.Sum256([]byte("v0.2.0"))
		tagHash := hex.EncodeToString(tagSum[:])[:12]
		commitShort := commitSHA[:12]
		manifestBody := fmt.Sprintf(`{"publish_all":false,"publishing_groups":[{"packages":[{"name":"bq-otel-exporter","version":%q}]}],"registry_config":{"github_releases":{"name":"otelcol-bq 0.2.0","tag":"v0.2.0","is_draft":true,"is_prerelease":false}}}`, wantVer)

		// Legacy primary manifest without .meta: gcloud storage objects describe
		// outputs "null", so preflight falls back to promote_eligible=true on
		// normal reruns and promote_eligible=false on force_resubmit=true.
		primaryStore := t.TempDir()
		primaryObj := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s.json", tagHash, commitShort)
		writeStoreManifest(t, primaryStore, primaryObj, manifestBody)

		preNormal := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: primaryStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "300", forceResubmit: "false",
		}, false)
		if preNormal.err != nil || preNormal.outputs["action"] != "skip_duplicate" || preNormal.outputs["staging_version"] != wantVer || preNormal.outputs["promote_eligible"] != "true" {
			t.Fatalf("legacy primary normal rerun = (%v, %v), want action=skip_duplicate staging_version=%q promote_eligible=true", preNormal.err, preNormal.outputs, wantVer)
		}

		preForce := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: primaryStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "301", forceResubmit: "true",
		}, false)
		if preForce.err != nil || preForce.outputs["action"] != "resubmit_existing" || preForce.outputs["prior_staging_version"] != wantVer || preForce.outputs["promote_eligible"] != "false" {
			t.Fatalf("legacy primary forced rerun = (%v, %v), want action=resubmit_existing prior_staging_version=%q promote_eligible=false", preForce.err, preForce.outputs, wantVer)
		}

		// Legacy forced manifest (-r99.json) without .meta or primary: both normal
		// and forced reruns fall back to promote_eligible=false cleanly.
		forcedStore := t.TempDir()
		forcedObj := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s-r99.json", tagHash, commitShort)
		writeStoreManifest(t, forcedStore, forcedObj, manifestBody)

		preForcedNormal := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: forcedStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "302", forceResubmit: "false",
		}, false)
		if preForcedNormal.err != nil || preForcedNormal.outputs["action"] != "skip_duplicate" || preForcedNormal.outputs["staging_version"] != wantVer || preForcedNormal.outputs["promote_eligible"] != "false" {
			t.Fatalf("legacy forced-only normal rerun = (%v, %v), want action=skip_duplicate staging_version=%q promote_eligible=false", preForcedNormal.err, preForcedNormal.outputs, wantVer)
		}

		preForcedSameRun := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: forcedStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "99", forceResubmit: "true",
		}, false)
		if preForcedSameRun.err != nil || preForcedSameRun.outputs["action"] != "skip_duplicate" || preForcedSameRun.outputs["staging_version"] != wantVer || preForcedSameRun.outputs["promote_eligible"] != "false" {
			t.Fatalf("legacy forced-only same-run rerun = (%v, %v), want action=skip_duplicate staging_version=%q promote_eligible=false", preForcedSameRun.err, preForcedSameRun.outputs, wantVer)
		}

		preForcedNewRun := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: forcedStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "303", forceResubmit: "true",
		}, false)
		if preForcedNewRun.err != nil || preForcedNewRun.outputs["action"] != "resubmit_existing" || preForcedNewRun.outputs["prior_staging_version"] != wantVer || preForcedNewRun.outputs["promote_eligible"] != "false" {
			t.Fatalf("legacy forced-only new-run rerun = (%v, %v), want action=resubmit_existing prior_staging_version=%q promote_eligible=false", preForcedNewRun.err, preForcedNewRun.outputs, wantVer)
		}
	})

	t.Run("preflight_detects_existing_forced_manifest_when_primary_absent", func(t *testing.T) {
		storeDir := t.TempDir()
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)

		tagSum := sha256.Sum256([]byte("v0.2.0"))
		decoyObj := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s-other.json",
			hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
		writeStoreManifest(t, storeDir, decoyObj, `{"publish_all":false}`)

		runPreflight := func(runID, force string) exitGateReplayResult {
			return runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
				storeDir:      storeDir,
				tag:           "v0.2.0",
				commitSHA:     commitSHA,
				runID:         runID,
				forceResubmit: force,
			}, false)
		}

		pre101 := runPreflight("101", "true")
		if pre101.err != nil || pre101.outputs["action"] != "full_release" || pre101.outputs["promote_eligible"] != "true" {
			t.Fatalf("pre101 = (%v, %v), want action=full_release promote_eligible=true", pre101.err, pre101.outputs)
		}
		sub101 := replayFullReleaseSubmit(t, stageAssetsStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "101",
			forceResubmit: "true",
		})
		if sub101.err != nil || !strings.HasSuffix(sub101.outputs["manifest_uri"], "-r101.json") {
			t.Fatalf("sub101 = (%v, %v), want submitted -r101.json", sub101.err, sub101.outputs)
		}
		pre101Rerun := runPreflight("101", "true")
		if pre101Rerun.err != nil || pre101Rerun.outputs["action"] != "skip_duplicate" || pre101Rerun.outputs["promote_eligible"] != "true" {
			t.Fatalf("pre101Rerun = (%v, %v), want skip_duplicate promote_eligible=true", pre101Rerun.err, pre101Rerun.outputs)
		}

		pre102 := runPreflight("102", "true")
		if pre102.err != nil || pre102.outputs["action"] != "resubmit_existing" || pre102.outputs["prior_staging_version"] != wantVer || pre102.outputs["promote_eligible"] != "false" {
			t.Fatalf("pre102 = (%v, %v), want action=resubmit_existing prior_staging_version=%q promote_eligible=false", pre102.err, pre102.outputs, wantVer)
		}
		sub102 := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "102",
			forceResubmit:       "true",
			action:              "resubmit_existing",
			priorStagingVersion: pre102.outputs["prior_staging_version"],
		})
		if sub102.err != nil || !strings.HasSuffix(sub102.outputs["manifest_uri"], "-r102.json") {
			t.Fatalf("sub102 = (%v, %v), want submitted -r102.json", sub102.err, sub102.outputs)
		}
		pre102Rerun := runPreflight("102", "true")
		if pre102Rerun.err != nil || pre102Rerun.outputs["action"] != "skip_duplicate" || pre102Rerun.outputs["promote_eligible"] != "false" {
			t.Fatalf("pre102Rerun = (%v, %v), want skip_duplicate promote_eligible=false", pre102Rerun.err, pre102Rerun.outputs)
		}

		pre103 := runPreflight("103", "false")
		if pre103.err != nil || pre103.outputs["action"] != "skip_duplicate" || pre103.outputs["staging_version"] != wantVer {
			t.Fatalf("pre103 = (%v, %v), want action=skip_duplicate staging_version=%q", pre103.err, pre103.outputs, wantVer)
		}
	})

	t.Run("ignores_noncurrent_archived_manifests_on_versioned_bucket", func(t *testing.T) {
		storeDir := t.TempDir()
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)
		tagSum := sha256.Sum256([]byte("v0.2.0"))
		primaryObj := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s.json",
			hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
		writeNoncurrentStoreManifest(t, storeDir, primaryObj, `{"publish_all":false}`)

		preFalse := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "201", forceResubmit: "false",
		}, false)
		if preFalse.err != nil || preFalse.outputs["action"] != "full_release" {
			t.Fatalf("preflight (false) treated noncurrent manifest as live: err=%v outputs=%v", preFalse.err, preFalse.outputs)
		}
		preTrue := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "202", forceResubmit: "true",
		}, false)
		if preTrue.err != nil || preTrue.outputs["action"] != "full_release" || preTrue.outputs["promote_eligible"] != "true" {
			t.Fatalf("preflight (true) treated noncurrent manifest as live: err=%v outputs=%v", preTrue.err, preTrue.outputs)
		}
		guardRes := runWorkflowBashScript(t, releaseDedupGuardStep.Run, exitGateReplayOpts{
			storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "201", forceResubmit: "false",
		}, false)
		if guardRes.err != nil {
			t.Fatalf("release_dedup_guard blocked on noncurrent manifest: %v", guardRes.err)
		}
		seedCompleteARVersion(t, storeDir, "v0.2.0", wantVer, true)
		subRes := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: storeDir, tag: "v0.2.0", commitSHA: commitSHA, runID: "201", forceResubmit: "false",
			action: "full_release", releaseStagingVersion: wantVer,
		})
		if subRes.err != nil || subRes.outputs["submission_status"] != "submitted" {
			t.Fatalf("exit_gate_submit skipped live submit due to noncurrent manifest: err=%v outputs=%v", subRes.err, subRes.outputs)
		}
	})

	t.Run("release_dedup_guard_blocks_rerun_failed_jobs_before_goreleaser", func(t *testing.T) {
		storeDir := t.TempDir()
		commitSHA := "0123456789abcdef0123456789abcdef01234567"

		runGuard := func(guardStoreDir, force string) error {
			res := runWorkflowBashScript(t, releaseDedupGuardStep.Run, exitGateReplayOpts{
				storeDir:      guardStoreDir,
				tag:           "v0.2.0",
				commitSHA:     commitSHA,
				runID:         "1",
				forceResubmit: force,
			}, false)
			return res.err
		}

		if err := runGuard(storeDir, "false"); err != nil {
			t.Fatalf("guard blocked clean false release: %v", err)
		}
		if err := runGuard(storeDir, "true"); err != nil {
			t.Fatalf("guard blocked clean true release: %v", err)
		}

		// Once -r101.json exists (even without primary manifest!), "Re-run failed jobs"
		// on jobs.release must fail closed BEFORE GoReleaser runs.
		if res := replayFullReleaseSubmit(t, stageAssetsStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "101",
			forceResubmit: "true",
		}); res.err != nil {
			t.Fatalf("forced seed submit failed: %v", res.err)
		}
		for _, force := range []string{"false", "true"} {
			if err := runGuard(storeDir, force); err == nil {
				t.Fatalf("guard (force=%s) allowed jobs.release despite existing -r101.json", force)
			}
		}

		// Use a fresh empty store so ordinary submission actually writes only the
		// primary manifest rather than being skipped by the pre-existing -r101.json.
		primaryStoreDir := t.TempDir()
		res := replayFullReleaseSubmit(t, stageAssetsStep.Run, submitStep.Run, exitGateReplayOpts{
			storeDir:      primaryStoreDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "102",
			forceResubmit: "false",
		})
		if res.err != nil {
			t.Fatalf("primary seed submit failed: %v", res.err)
		}
		if res.outputs["submission_status"] != "submitted" {
			t.Fatalf("primary seed submission_status = %q, want submitted", res.outputs["submission_status"])
		}
		tagSum := sha256.Sum256([]byte("v0.2.0"))
		wantPrimaryManifest := fmt.Sprintf("manifest-%s-%s.json", hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
		if got := listStoreManifests(t, primaryStoreDir); !slices.Equal(got, []string{wantPrimaryManifest}) {
			t.Fatalf("primary seed manifests = %v, want exact single [%s]", got, wantPrimaryManifest)
		}
		for _, force := range []string{"false", "true"} {
			if err := runGuard(primaryStoreDir, force); err == nil {
				t.Fatalf("guard (force=%s) allowed jobs.release despite existing primary manifest", force)
			}
		}
	})

	t.Run("gcs_listing_rejects_missing_or_invalid_entry_names", func(t *testing.T) {
		commitSHA := "0123456789abcdef0123456789abcdef01234567"
		wantVer := deterministicStagingVersion("v0.2.0", commitSHA)

		// Real empty array [] still clears preflight, dedup guard, and submit-exit-gate.
		cleanStore := t.TempDir()
		seedCompleteARVersion(t, cleanStore, "v0.2.0", wantVer, true)
		if pre := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir: cleanStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1201", forceResubmit: "false",
			dockerEnv: map[string]string{"EXIT_GATE_LIST_JSON": "[]"},
		}, false); pre.err != nil || pre.outputs["action"] != "full_release" {
			t.Fatalf("empty GCS listing [] failed preflight: err=%v outputs=%v", pre.err, pre.outputs)
		}
		if guard := runWorkflowBashScript(t, releaseDedupGuardStep.Run, exitGateReplayOpts{
			storeDir: cleanStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1201", forceResubmit: "false",
			dockerEnv: map[string]string{"EXIT_GATE_LIST_JSON": "[]"},
		}, false); guard.err != nil {
			t.Fatalf("empty GCS listing [] failed release_dedup_guard: %v", guard.err)
		}
		if sub := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: cleanStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1201", forceResubmit: "false",
			action: "full_release", releaseStagingVersion: wantVer,
			dockerEnv: map[string]string{"EXIT_GATE_LIST_JSON": "[]"},
		}); sub.err != nil || sub.outputs["submission_status"] != "submitted" {
			t.Fatalf("empty GCS listing [] failed submit-exit-gate: err=%v outputs=%v", sub.err, sub.outputs)
		}

		for _, tc := range []struct {
			name string
			json string
		}{
			{"empty_object_entry", "[{}]"},
			{"empty_string_name", `[{"name":""}]`},
			{"null_name", `[{"name":null}]`},
			{"numeric_name", `[{"name":123}]`},
			{"null_entry", `[null]`},
			{"archived_unnamed_entry", `[{"noncurrent_time":"2026-01-01T00:00:00Z"}]`},
			{"archived_mixed_named_and_unnamed_entries", `[{"name":"manifest-ok.json","noncurrent_time":"2026-01-01T00:00:00Z"},{"noncurrent_time":"2026-01-02T00:00:00Z"}]`},
		} {
			t.Run(tc.name, func(t *testing.T) {
				badStore := t.TempDir()
				seedCompleteARVersion(t, badStore, "v0.2.0", wantVer, true)
				env := map[string]string{"EXIT_GATE_LIST_JSON": tc.json}
				if pre := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					storeDir: badStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1202", forceResubmit: "false",
					dockerEnv: env,
				}, false); pre.err == nil {
					t.Fatalf("preflight accepted malformed GCS listing %s: outputs=%v", tc.json, pre.outputs)
				}
				if guard := runWorkflowBashScript(t, releaseDedupGuardStep.Run, exitGateReplayOpts{
					storeDir: badStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1202", forceResubmit: "false",
					dockerEnv: env,
				}, false); guard.err == nil {
					t.Fatalf("release_dedup_guard accepted malformed GCS listing %s", tc.json)
				}
				sub := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
					storeDir: badStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "1202", forceResubmit: "false",
					action: "full_release", releaseStagingVersion: wantVer,
					dockerEnv: env,
				})
				if sub.err == nil || len(listStoreManifests(t, badStore)) != 0 {
					t.Fatalf("submit-exit-gate accepted malformed GCS listing %s: err=%v manifests=%v", tc.json, sub.err, listStoreManifests(t, badStore))
				}
			})
		}
	})
}

func TestReleaseResolveManifestDigestStep(t *testing.T) {
	step := findReleaseStep(t, "manifest_digest")
	pushedDigest := "sha256:" + strings.Repeat("b", 64)
	staleDigest := "sha256:" + strings.Repeat("a", 64)
	reconciledDigest := "sha256:" + strings.Repeat("c", 64)

	runResolve := func(t *testing.T, releaseTag, reconciled, artifactsJSON, dockerTagDigest string, dockerFail bool) (map[string]string, error) {
		t.Helper()
		dir := t.TempDir()
		binDir := filepath.Join(dir, "bin")
		if err := os.Mkdir(binDir, 0o700); err != nil {
			t.Fatal(err)
		}
		stageReleaseScripts(t, dir)
		writeFakeDockerAndCosign(t, binDir)
		outPath := filepath.Join(dir, "github_output")
		if err := os.WriteFile(outPath, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if artifactsJSON != "" {
			distDir := filepath.Join(dir, "dist")
			if err := os.Mkdir(distDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(distDir, "artifacts.json"), []byte(artifactsJSON), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		notFoundFlag := "0"
		if dockerFail {
			notFoundFlag = "1"
		}
		cmd := exec.Command("bash", "--noprofile", "--norc", "-c", step.Run)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GITHUB_OUTPUT="+outPath,
			"RELEASE_TAG="+releaseTag,
			"RECONCILED_DIGEST="+reconciled,
			"FAKE_DOCKER_INSPECT_NOT_FOUND="+notFoundFlag,
			"FAKE_DOCKER_DIGEST="+dockerTagDigest,
			"FAKE_DOCKER_RAW_JSON="+releaseIndex(t),
		)
		out, err := cmd.CombinedOutput()
		outputs := map[string]string{}
		if raw, rerr := os.ReadFile(outPath); rerr == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if k, v, ok := strings.Cut(line, "="); ok {
					outputs[k] = v
				}
			}
		}
		if err != nil {
			return outputs, fmt.Errorf("%w: %s", err, out)
		}
		return outputs, nil
	}

	validArtifacts, err := json.Marshal([]map[string]any{
		{
			"name": releaseImage + ":0.2.0-amd64",
			"type": "Docker Image",
			"extra": map[string]any{
				"Digest": staleDigest,
			},
		},
		{
			"name": releaseImage + ":0.2.0",
			"type": "Docker Manifest",
			"extra": map[string]any{
				"Digest": pushedDigest,
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("pushed_manifest_digest_matches_tag_succeeds", func(t *testing.T) {
		outputs, runErr := runResolve(t, "v0.2.0", "", string(validArtifacts), pushedDigest, false)
		if runErr != nil || outputs["digest"] != pushedDigest {
			t.Fatalf("resolve_manifest_digest = (%v, %v), want digest=%s", runErr, outputs, pushedDigest)
		}
	})

	t.Run("stale_tag_disagrees_with_pushed_manifest_fails_closed", func(t *testing.T) {
		outputs, runErr := runResolve(t, "v0.2.0", "", string(validArtifacts), staleDigest, false)
		if runErr == nil || len(outputs) != 0 {
			t.Fatalf("resolve_manifest_digest accepted stale tag digest: err=%v outputs=%v", runErr, outputs)
		}
		if !strings.Contains(runErr.Error(), staleDigest) || !strings.Contains(runErr.Error(), pushedDigest) {
			t.Fatalf("expected error naming both tag digest and pushed digest, got: %v", runErr)
		}
	})

	t.Run("reconciled_digest_path_succeeds_without_artifacts_json", func(t *testing.T) {
		outputs, runErr := runResolve(t, "v0.2.0", reconciledDigest, "", "", true)
		if runErr != nil || outputs["digest"] != reconciledDigest {
			t.Fatalf("resolve_manifest_digest with RECONCILED_DIGEST = (%v, %v), want %s", runErr, outputs, reconciledDigest)
		}
	})

	for _, bad := range []struct {
		name          string
		reconciled    string
		artifactsJSON string
	}{
		{name: "missing_artifacts_json", artifactsJSON: ""},
		{name: "empty_artifacts_array", artifactsJSON: "[]"},
		{name: "missing_docker_manifest_type", artifactsJSON: fmt.Sprintf(`[{"name":"%s:0.2.0","type":"Docker Image","extra":{"Digest":%q}}]`, releaseImage, pushedDigest)},
		{name: "duplicate_docker_manifest", artifactsJSON: fmt.Sprintf(`[{"name":"%s:0.2.0","type":"Docker Manifest","extra":{"Digest":%q}},{"name":"%s:0.2.0","type":"Docker Manifest","extra":{"Digest":%q}}]`, releaseImage, pushedDigest, releaseImage, pushedDigest)},
		{name: "malformed_digest", artifactsJSON: fmt.Sprintf(`[{"name":"%s:0.2.0","type":"Docker Manifest","extra":{"Digest":"not-a-digest"}}]`, releaseImage)},
		{name: "invalid_reconciled_digest", reconciled: "bad-digest"},
	} {
		t.Run("rejects_"+bad.name, func(t *testing.T) {
			outputs, runErr := runResolve(t, "v0.2.0", bad.reconciled, bad.artifactsJSON, pushedDigest, false)
			if runErr == nil || len(outputs) != 0 {
				t.Fatalf("%s failed open: err=%v outputs=%v", bad.name, runErr, outputs)
			}
		})
	}
}

// supplyChainReleaseWorkflow parses all jobs in release.yml so the
// publish-go-package job can be inspected alongside the release job.
type supplyChainReleaseWorkflow struct {
	On struct {
		Push struct {
			Tags []string `yaml:"tags"`
		} `yaml:"push"`
		WorkflowDispatch struct {
			Inputs map[string]struct {
				Tag string `yaml:"tag"`
			} `yaml:"inputs"`
		} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Needs       []string          `yaml:"needs"`
		If          any               `yaml:"if,omitempty"`
		RunsOn      string            `yaml:"runs-on"`
		TimeoutMin  int               `yaml:"timeout-minutes"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name string            `yaml:"name"`
			ID   string            `yaml:"id"`
			If   any               `yaml:"if,omitempty"`
			Uses string            `yaml:"uses"`
			With map[string]any    `yaml:"with"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readFullReleaseWorkflow(t *testing.T) supplyChainReleaseWorkflow {
	t.Helper()
	var wf supplyChainReleaseWorkflow
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/workflows/release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

// TestPublishGoPackageJob verifies the post-tag Go module proxy publication
// and clean-room consumer verification job exists in release.yml with the
// correct dependency, trigger condition, and SHA-pinned actions.
func TestPublishGoPackageJob(t *testing.T) {
	wf := readFullReleaseWorkflow(t)

	// Workflow-level permissions must be {} (least-privilege); write
	// permissions are scoped to the jobs that need them.
	if len(wf.Permissions) != 0 {
		t.Errorf("release.yml workflow-level permissions = %v, want empty ({}); write perms belong on individual jobs", wf.Permissions)
	}

	// The release job carries least-privilege permissions: GitHub Release
	// publishing goes through OSS Exit Gate (OIDC WIF), so contents stays
	// read-only while packages, id-token, and attestations keep write access.
	releaseJob, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release.yml is missing the release job")
	}
	for _, want := range []struct{ key, val string }{
		{"contents", "read"},
		{"packages", "write"},
		{"id-token", "write"},
		{"attestations", "write"},
	} {
		if got := releaseJob.Permissions[want.key]; got != want.val {
			t.Errorf("release job permissions.%s = %q, want %q", want.key, got, want.val)
		}
	}

	job, ok := wf.Jobs["publish-go-package"]
	if !ok {
		t.Fatal("release.yml is missing the publish-go-package job")
	}
	wantNeeds := []string{"preflight", "release", "submit-exit-gate", "promote-latest"}
	if !slices.Equal(job.Needs, wantNeeds) {
		t.Errorf("publish-go-package needs = %v, want %v", job.Needs, wantNeeds)
	}
	const wantPublishIf = "always() && !cancelled() && needs.preflight.result == 'success' && ((needs.preflight.outputs.action == 'full_release' && needs.release.result == 'success' && needs.submit-exit-gate.result == 'success' && needs.promote-latest.result == 'success') || (needs.preflight.outputs.action == 'submit_staged' && needs.submit-exit-gate.result == 'success' && needs.promote-latest.result == 'success') || (needs.preflight.outputs.action == 'resubmit_existing' && needs.submit-exit-gate.result == 'success') || (needs.preflight.outputs.action == 'skip_duplicate' && (needs.preflight.outputs.promote_eligible != 'true' || needs.promote-latest.result == 'success')))"
	if gotIf, ok := job.If.(string); !ok || gotIf != wantPublishIf {
		t.Errorf("publish-go-package if = %#v, want %q", job.If, wantPublishIf)
	}
	if job.RunsOn != "ubuntu-latest" {
		t.Errorf("publish-go-package runs-on = %q, want ubuntu-latest", job.RunsOn)
	}
	// Least-privilege: job-level permissions must be contents: read.
	if job.Permissions["contents"] != "read" {
		t.Errorf("publish-go-package permissions.contents = %q, want read", job.Permissions["contents"])
	}

	// Both actions must use the same full-SHA pins as the release job.
	checkoutPin := "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	setupGoPin := "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
	foundCheckout, foundSetupGo := false, false
	for _, step := range job.Steps {
		if step.Uses == checkoutPin {
			foundCheckout = true
		}
		if step.Uses == setupGoPin {
			if step.With["go-version"] != "1.27.4" {
				t.Errorf("publish-go-package setup-go go-version = %v, want 1.27.4", step.With["go-version"])
			}
			foundSetupGo = true
		}
		// No run: block may use ${{ template interpolation.
		if strings.Contains(step.Run, "${{") {
			t.Errorf("publish-go-package step %q interpolates an expression into shell", step.Name)
		}
	}
	if !foundCheckout {
		t.Error("publish-go-package is missing the SHA-pinned actions/checkout step")
	}
	if !foundSetupGo {
		t.Error("publish-go-package is missing the SHA-pinned actions/setup-go step")
	}

	// The release tag must come from RELEASE_TAG env (matching jobs.release),
	// not from stripping refs/tags/ off GITHUB_REF.
	var allRun, allEnv string
	for _, step := range job.Steps {
		allRun += step.Run + "\n"
		for _, v := range step.Env {
			allEnv += v + "\n"
		}
	}
	if !strings.Contains(allEnv, "${{ inputs.tag || github.ref_name }}") {
		t.Errorf("publish-go-package env does not set RELEASE_TAG from ${{ inputs.tag || github.ref_name }}")
	}

	// Verify the job polls proxy.golang.org with the case-encoded module
	// path (uppercase letters must be !<lowercase> per the GOPROXY protocol),
	// requests pkg.go.dev, and runs a clean-room go get consumer test
	// importing from the module root.
	for _, want := range []string{
		"proxy.golang.org/github.com/!google!cloud!platform/!b!q-!o!t!e!l-!exporter",
		"pkg.go.dev/github.com/GoogleCloudPlatform/BQ-OTEL-Exporter",
		"go mod init example.com/smoke",
		"GOPROXY=https://proxy.golang.org go get",
		`bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"`,
		"bigqueryexporter.NewFactory()",
	} {
		if !strings.Contains(allRun, want) {
			t.Errorf("publish-go-package run blocks missing %q", want)
		}
	}
}

func checkGoReleaserNoLatest(raw string) error {
	var cfg struct {
		Dockers []struct {
			Goos           string   `yaml:"goos"`
			Goarch         string   `yaml:"goarch"`
			ImageTemplates []string `yaml:"image_templates"`
		} `yaml:"dockers"`
		DockerManifests []struct {
			NameTemplate   string   `yaml:"name_template"`
			ImageTemplates []string `yaml:"image_templates"`
		} `yaml:"docker_manifests"`
	}
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		return err
	}
	if len(cfg.Dockers) == 0 || len(cfg.DockerManifests) == 0 {
		return fmt.Errorf("goreleaser config missing dockers (%d) or docker_manifests (%d)", len(cfg.Dockers), len(cfg.DockerManifests))
	}
	for _, d := range cfg.Dockers {
		if len(d.ImageTemplates) == 0 {
			return fmt.Errorf("docker image %s/%s has empty image_templates", d.Goos, d.Goarch)
		}
		for _, tpl := range d.ImageTemplates {
			if strings.Contains(tpl, ":latest") {
				return fmt.Errorf("docker image %s/%s publishes mutable tag %q", d.Goos, d.Goarch, tpl)
			}
			if !strings.Contains(tpl, "{{ .Version }}") {
				return fmt.Errorf("docker image %s/%s template %q is not version-scoped", d.Goos, d.Goarch, tpl)
			}
		}
	}
	for _, m := range cfg.DockerManifests {
		if strings.Contains(m.NameTemplate, ":latest") {
			return fmt.Errorf("docker_manifests publishes mutable :latest name_template %q", m.NameTemplate)
		}
		if !strings.Contains(m.NameTemplate, "{{ .Version }}") {
			return fmt.Errorf("docker_manifests name_template %q is not version-scoped", m.NameTemplate)
		}
		if len(m.ImageTemplates) == 0 {
			return fmt.Errorf("docker_manifests %q has empty image_templates", m.NameTemplate)
		}
		for _, tpl := range m.ImageTemplates {
			if strings.Contains(tpl, ":latest") {
				return fmt.Errorf("docker_manifests %q references mutable tag %q", m.NameTemplate, tpl)
			}
		}
	}
	return nil
}

func TestGoReleaserImmutabilityAndGitIgnore(t *testing.T) {
	rawGoReleaser := testsupport.ReadRepoText(t, ".goreleaser.yaml")
	if err := checkGoReleaserNoLatest(rawGoReleaser); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, injected string }{
		{"arch latest-amd64", strings.Replace(rawGoReleaser, `{{ .Version }}-amd64"`, "{{ .Version }}-amd64\"\n      - \"ghcr.io/googlecloudplatform/bq-otel-collector:latest-amd64\"", 1)},
		{"manifest latest", strings.Replace(rawGoReleaser, "docker_manifests:\n", "docker_manifests:\n  - name_template: \"ghcr.io/googlecloudplatform/bq-otel-collector:latest\"\n    image_templates:\n      - \"ghcr.io/googlecloudplatform/bq-otel-collector:{{ .Version }}-amd64\"\n", 1)},
	} {
		t.Run("rejects_"+tc.name, func(t *testing.T) {
			if err := checkGoReleaserNoLatest(tc.injected); err == nil {
				t.Fatalf("accepted mutable :latest configuration (%s)", tc.name)
			}
		})
	}

	// Copy .gitignore into a fresh isolated temp repo and verify against an
	// untracked control file so the test works even from a `git archive` export.
	repoDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte(testsupport.ReadRepoText(t, ".gitignore")), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "untracked-control.txt"), []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitEnv := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	initCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "init", "-q")
	initCmd.Env = gitEnv
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init failed: %v: %s", err, out)
	}
	ignoreCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "check-ignore", "-q", "gha-creds-12345.json")
	ignoreCmd.Env = gitEnv
	if out, err := ignoreCmd.CombinedOutput(); err != nil {
		t.Fatalf(".gitignore must ignore google-github-actions/auth credential files (gha-creds-*.json): %v: %s", err, out)
	}
	untrackedCmd := exec.CommandContext(ctx, "git", "-C", repoDir, "check-ignore", "-q", "untracked-control.txt")
	untrackedCmd.Env = gitEnv
	if err := untrackedCmd.Run(); err == nil {
		t.Fatal("git check-ignore unexpectedly ignored untracked-control.txt")
	}
}

type promoteLatestReplayOpts struct {
	localTags          []string
	annotatedTags      []string
	originTags         []string
	withdrawOriginTags []string
	retagOriginTag     string
	releaseTag         string
	commitSHA          string
	digest             string
	promoteEligible    string
	withOrigin         bool
	dockerEnv          map[string]string
}

type promoteLatestReplayResult struct {
	out         string
	dockerCalls [][]string
	cosignCalls [][]string
	curlCalls   [][]string
	ghCalls     [][]string
	err         error
}

func replayPromoteLatestFull(t *testing.T, script string, opts promoteLatestReplayOpts) promoteLatestReplayResult {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	originDir := filepath.Join(dir, "origin.git")
	seedDir := filepath.Join(dir, "seed")
	repoDir := filepath.Join(dir, "repo")
	for _, sub := range []string{binDir, originDir, seedDir} {
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeDockerAndCosign(t, binDir)
	dockerLogPath := filepath.Join(dir, "docker_calls")
	cosignLogPath := filepath.Join(dir, "cosign_calls")
	curlLogPath := filepath.Join(dir, "curl_calls")
	ghLogPath := filepath.Join(dir, "gh_calls")
	gitEnv := append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	runGit := func(workDir string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = workDir
		cmd.Env = gitEnv
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v in %s failed: %v: %s", args, workDir, err, out)
		}
		return strings.TrimSpace(string(out))
	}

	if opts.withOrigin {
		runGit(originDir, "init", "--bare", "-b", "main")
		runGit(seedDir, "init", "-b", "main")
		runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
		for _, tag := range opts.localTags {
			runGit(seedDir, "tag", tag)
		}
		for _, tag := range opts.annotatedTags {
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "tag", "-a", tag, "-m", "release "+tag)
		}
		runGit(seedDir, "remote", "add", "origin", originDir)
		runGit(seedDir, "push", "origin", "main", "--tags")
		runGit(dir, "clone", originDir, repoDir)
		// Mutate origin AFTER repoDir checked out, simulating stalled older releases,
		// withdrawn tags deleted from origin, or tags re-pointed to another commit.
		for _, tag := range opts.originTags {
			runGit(seedDir, "tag", tag)
		}
		if len(opts.originTags) > 0 {
			runGit(seedDir, "push", "origin", "--tags")
		}
		for _, tag := range opts.withdrawOriginTags {
			runGit(seedDir, "push", "origin", "--delete", tag)
		}
		if opts.retagOriginTag != "" {
			runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "moved")
			runGit(seedDir, "tag", "-f", opts.retagOriginTag)
			runGit(seedDir, "push", "--force", "origin", "refs/tags/"+opts.retagOriginTag)
		}
	} else {
		if err := os.Mkdir(repoDir, 0o700); err != nil {
			t.Fatal(err)
		}
		runGit(repoDir, "init", "-b", "main")
		runGit(repoDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
		for _, tag := range opts.localTags {
			runGit(repoDir, "tag", tag)
		}
	}
	stageReleaseScripts(t, repoDir)

	commitSHA := opts.commitSHA
	if commitSHA == "" {
		commitSHA = runGit(repoDir, "rev-parse", "HEAD")
	}
	promoteEligible := opts.promoteEligible
	if promoteEligible == "" {
		promoteEligible = "true"
	}

	envMap := map[string]string{
		"PATH":                      binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL":         "/dev/null",
		"GIT_CONFIG_SYSTEM":         "/dev/null",
		"RELEASE_TAG":               opts.releaseTag,
		"COMMIT_SHA":                commitSHA,
		"DIGEST":                    opts.digest,
		"PROMOTE_ELIGIBLE":          promoteEligible,
		"GHCR_ACTOR":                "octocat",
		"GHCR_TOKEN":                "test-ghcr-token",
		"GH_TOKEN":                  "test-gh-token",
		"GITHUB_REPOSITORY":         "GoogleCloudPlatform/BQ-OTEL-Exporter",
		"FAKE_DOCKER_LOG":           dockerLogPath,
		"FAKE_COSIGN_LOG":           cosignLogPath,
		"FAKE_CURL_LOG":             curlLogPath,
		"FAKE_GH_LOG":               ghLogPath,
		"FAKE_ORIGIN_DIR":           originDir,
		"FAKE_DOCKER_DIGEST":        opts.digest,
		"FAKE_DOCKER_RAW_JSON":      releaseIndex(t),
		"FAKE_DOCKER_AMD64_DIGEST":  releaseChildDigests["linux/amd64"],
		"FAKE_DOCKER_ARM64_DIGEST":  releaseChildDigests["linux/arm64"],
		"FAKE_DOCKER_AMD64_COMMIT":  commitSHA,
		"FAKE_DOCKER_ARM64_COMMIT":  commitSHA,
		"FAKE_DOCKER_AMD64_VERSION": strings.TrimPrefix(opts.releaseTag, "v"),
		"FAKE_DOCKER_ARM64_VERSION": strings.TrimPrefix(opts.releaseTag, "v"),
		"FAKE_OCI_DEFAULT_CODE":     "404",
		"FAKE_OCI_DEFAULT_DIGEST":   "",
		"FAKE_OCI_DEFAULT_BODY":     `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`,
	}
	for k, v := range opts.dockerEnv {
		envMap[k] = v
	}
	cmdEnv := append([]string(nil), os.Environ()...)
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, k+"="+v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
	cmd.Dir = repoDir
	cmd.Env = cmdEnv
	out, err := cmd.CombinedOutput()
	return promoteLatestReplayResult{
		out:         string(out),
		dockerCalls: readTabLog(t, dockerLogPath),
		cosignCalls: readTabLog(t, cosignLogPath),
		curlCalls:   readTabLog(t, curlLogPath),
		ghCalls:     readTabLog(t, ghLogPath),
		err:         err,
	}
}

func replayPromoteLatest(t *testing.T, script string, opts promoteLatestReplayOpts) (string, [][]string, [][]string, error) {
	t.Helper()
	res := replayPromoteLatestFull(t, script, opts)
	return res.out, res.dockerCalls, res.cosignCalls, res.err
}

func dockerCreateCalls(calls [][]string) [][]string {
	var created [][]string
	for _, args := range calls {
		if len(args) >= 3 && args[0] == "buildx" && args[1] == "imagetools" && args[2] == "create" {
			created = append(created, args)
		}
	}
	return created
}

func TestReleasePromoteLatestStep(t *testing.T) {
	step := findPromoteLatestStep(t)
	validDigest := "sha256:" + strings.Repeat("e", 64)
	amd64Digest := releaseChildDigests["linux/amd64"]
	arm64Digest := releaseChildDigests["linux/arm64"]

	wantCreateCalls := [][]string{
		{"buildx", "imagetools", "create", "-t", releaseImage + ":latest", releaseImage + "@" + validDigest},
		{"buildx", "imagetools", "create", "--prefer-index=false", "-t", releaseImage + ":latest-amd64", releaseImage + "@" + amd64Digest},
		{"buildx", "imagetools", "create", "--prefer-index=false", "-t", releaseImage + ":latest-arm64", releaseImage + "@" + arm64Digest},
	}

	t.Run("promotes_newest_stable_all_three_aliases_after_cosign_verify", func(t *testing.T) {
		out, dockerCalls, cosignCalls, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.1.0", "v0.2.0", "v0.3.0", "v0.4.0-rc.1"},
			releaseTag: "v0.3.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if err != nil {
			t.Fatalf("promote_latest failed: %v\n%s", err, out)
		}
		if len(cosignCalls) != 1 || cosignCalls[0][0] != "verify" {
			t.Fatalf("expected 1 cosign verify before promotion, got %q", cosignCalls)
		}
		created := dockerCreateCalls(dockerCalls)
		if !slices.EqualFunc(created, wantCreateCalls, slices.Equal[[]string]) {
			t.Fatalf("docker create calls = %q, want %q", created, wantCreateCalls)
		}
	})

	t.Run("stalled_older_release_refreshes_remote_tags_and_skips", func(t *testing.T) {
		out, dockerCalls, cosignCalls, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.2.0"},
			originTags: []string{"v0.3.0"},
			releaseTag: "v0.2.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if err != nil {
			t.Fatalf("older release returned non-zero: %v\n%s", err, out)
		}
		if len(dockerCreateCalls(dockerCalls)) != 0 || len(cosignCalls) != 0 {
			t.Fatalf("stalled older release promoted despite newer origin tag: docker=%q cosign=%q", dockerCalls, cosignCalls)
		}
		if !strings.Contains(out, "v0.3.0") {
			t.Errorf("expected skip message mentioning highest tag v0.3.0, got: %s", out)
		}
	})

	t.Run("ignores_leading_zero_decoy_and_skips_leading_zero_release_tag", func(t *testing.T) {
		out, dockerCalls, _, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v1.0.0", "v02.0.0"},
			releaseTag: "v1.0.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if err != nil {
			t.Fatalf("v1.0.0 with leading-zero decoy failed: %v\n%s", err, out)
		}
		if created := dockerCreateCalls(dockerCalls); !slices.EqualFunc(created, wantCreateCalls, slices.Equal[[]string]) {
			t.Fatalf("leading-zero decoy suppressed v1.0.0 promotion: created=%q", created)
		}

		outZero, callsZero, _, errZero := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v01.0.0"},
			releaseTag: "v01.0.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if errZero != nil || len(dockerCreateCalls(callsZero)) != 0 {
			t.Fatalf("leading-zero RELEASE_TAG should skip without invoking docker: err=%v calls=%q out=%s", errZero, callsZero, outZero)
		}
	})

	t.Run("arbitrary_precision_semver_beyond_uint64", func(t *testing.T) {
		smaller := "v99999999999999999999999999.0.0"
		larger := "v100000000000000000000000000.0.0"
		outSmall, callsSmall, _, errSmall := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{smaller, larger},
			releaseTag: smaller,
			digest:     validDigest,
			withOrigin: true,
		})
		if errSmall != nil || len(dockerCreateCalls(callsSmall)) != 0 {
			t.Fatalf("smaller >64-bit tag should skip: err=%v calls=%q out=%s", errSmall, callsSmall, outSmall)
		}
		outLarge, callsLarge, _, errLarge := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{smaller, larger},
			releaseTag: larger,
			digest:     validDigest,
			withOrigin: true,
		})
		if errLarge != nil || len(dockerCreateCalls(callsLarge)) != 3 {
			t.Fatalf("larger >64-bit tag should promote all 3 aliases: err=%v calls=%q out=%s", errLarge, callsLarge, outLarge)
		}
	})

	t.Run("numeric_semver_v0_10_0_beats_v0_9_0", func(t *testing.T) {
		outOlder, callsOlder, _, errOlder := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.9.0", "v0.10.0"},
			releaseTag: "v0.9.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if errOlder != nil || len(dockerCreateCalls(callsOlder)) != 0 {
			t.Fatalf("v0.9.0 should skip: err=%v calls=%q out=%s", errOlder, callsOlder, outOlder)
		}
		outNewer, callsNewer, _, errNewer := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.9.0", "v0.10.0"},
			releaseTag: "v0.10.0",
			digest:     validDigest,
			withOrigin: true,
		})
		if errNewer != nil || len(dockerCreateCalls(callsNewer)) != 3 {
			t.Fatalf("v0.10.0 should promote all 3 aliases: err=%v calls=%q out=%s", errNewer, callsNewer, outNewer)
		}
	})

	t.Run("skips_prerelease_tag", func(t *testing.T) {
		out, calls, _, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0", "v0.4.0-rc.1"},
			releaseTag: "v0.4.0-rc.1",
			digest:     validDigest,
			withOrigin: true,
		})
		if err != nil {
			t.Fatalf("prerelease tag returned non-zero: %v\n%s", err, out)
		}
		if len(calls) != 0 {
			t.Fatalf("docker invoked for prerelease tag: %q", calls)
		}
		if !strings.Contains(out, "not a canonical stable") {
			t.Errorf("expected skip reason for prerelease, got: %s", out)
		}
	})

	t.Run("rejects_invalid_digest", func(t *testing.T) {
		_, calls, cosignCalls, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     "sha256:bad",
			withOrigin: true,
		})
		if err == nil {
			t.Fatal("accepted invalid digest")
		}
		if len(calls) != 0 || len(cosignCalls) != 0 {
			t.Fatalf("invoked docker/cosign on invalid digest: docker=%q cosign=%q", calls, cosignCalls)
		}
	})

	t.Run("fails_closed_when_cosign_verify_fails", func(t *testing.T) {
		_, calls, _, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     validDigest,
			withOrigin: true,
			dockerEnv:  map[string]string{"FAKE_COSIGN_FAIL": "1"},
		})
		if err == nil {
			t.Fatal("promoted despite failed cosign verify")
		}
		if len(dockerCreateCalls(calls)) != 0 {
			t.Fatalf("docker create invoked despite failed cosign verify: %q", calls)
		}
	})

	t.Run("fails_closed_when_platform_missing", func(t *testing.T) {
		_, calls, _, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     validDigest,
			withOrigin: true,
			dockerEnv: map[string]string{
				"FAKE_DOCKER_RAW_JSON": strings.ReplaceAll(releaseIndex(t), `"architecture":"arm64"`, `"architecture":"s390x"`),
			},
		})
		if err == nil {
			t.Fatal("promoted despite missing arm64 child manifest")
		}
		if len(dockerCreateCalls(calls)) != 0 {
			t.Fatalf("docker create invoked despite missing platform: %q", calls)
		}
	})

	t.Run("fails_closed_when_git_fetch_fails", func(t *testing.T) {
		_, calls, cosignCalls, err := replayPromoteLatest(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     validDigest,
			withOrigin: false,
		})
		if err == nil {
			t.Fatal("accepted missing origin remote without failing closed")
		}
		if len(dockerCreateCalls(calls)) != 0 || len(cosignCalls) != 0 {
			t.Fatalf("promoted when git fetch failed: docker=%q cosign=%q", calls, cosignCalls)
		}
	})

	t.Run("skip_duplicate_recovers_missing_and_stale_aliases_for_highest_stable_tag", func(t *testing.T) {
		staleDigest := "sha256:" + strings.Repeat("f", 64)
		routes := strings.Join([]string{
			"0.3.0|200|" + validDigest + "|",
			"latest|200|" + validDigest + "|",
			"latest-amd64|404||" + `{"errors":[{"code":"MANIFEST_UNKNOWN","message":"manifest unknown"}]}`,
			"latest-arm64|200|" + staleDigest + "|",
		}, "\n")
		res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.2.0", "v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     "",
			withOrigin: true,
			dockerEnv: map[string]string{
				"FAKE_OCI_ROUTES": routes,
			},
		})
		if res.err != nil {
			t.Fatalf("skip_duplicate alias reconciliation failed: %v\n%s", res.err, res.out)
		}
		if len(res.cosignCalls) != 1 || res.cosignCalls[0][0] != "verify" {
			t.Fatalf("expected 1 cosign verify, got %q", res.cosignCalls)
		}
		if len(res.ghCalls) != 1 || res.ghCalls[0][0] != "attestation" || res.ghCalls[0][1] != "verify" || !slices.Contains(res.ghCalls[0], "--source-digest") {
			t.Fatalf("expected 1 gh attestation verify with --source-digest, got %q", res.ghCalls)
		}
		wantCreated := [][]string{
			{"buildx", "imagetools", "create", "--prefer-index=false", "-t", releaseImage + ":latest-amd64", releaseImage + "@" + amd64Digest},
			{"buildx", "imagetools", "create", "--prefer-index=false", "-t", releaseImage + ":latest-arm64", releaseImage + "@" + arm64Digest},
		}
		if created := dockerCreateCalls(res.dockerCalls); !slices.EqualFunc(created, wantCreated, slices.Equal[[]string]) {
			t.Fatalf("reconciled aliases = %q, want ONLY missing/stale [latest-amd64, latest-arm64]: %q", created, wantCreated)
		}
	})

	t.Run("skip_duplicate_older_tag_exits_zero_without_ghcr_calls", func(t *testing.T) {
		res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.2.0"},
			originTags: []string{"v0.3.0"},
			releaseTag: "v0.2.0",
			digest:     "",
			withOrigin: true,
		})
		if res.err != nil {
			t.Fatalf("older skip_duplicate failed: %v\n%s", res.err, res.out)
		}
		if len(res.curlCalls) != 0 || len(res.dockerCalls) != 0 || len(res.cosignCalls) != 0 || len(res.ghCalls) != 0 {
			t.Fatalf("older skip_duplicate touched GHCR/cosign/gh: curl=%q docker=%q cosign=%q gh=%q", res.curlCalls, res.dockerCalls, res.cosignCalls, res.ghCalls)
		}
	})

	t.Run("skip_duplicate_fails_closed_when_highest_tag_absent_in_ghcr", func(t *testing.T) {
		res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     "",
			withOrigin: true,
		})
		if res.err == nil {
			t.Fatalf("skip_duplicate succeeded despite missing :0.3.0 in GHCR:\n%s", res.out)
		}
	})

	t.Run("fails_closed_on_attestation_version_label_or_alias_probe_error", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			dockerEnv map[string]string
		}{
			{
				name:      "gh_attestation_verify_fails",
				dockerEnv: map[string]string{"FAKE_GH_ATTESTATION_FAIL": "1"},
			},
			{
				name:      "gh_attestation_missing_must_still_fail_closed_in_promote_latest",
				dockerEnv: map[string]string{"FAKE_GH_ATTESTATION_FAIL": "missing", "FAKE_OCI_REFERRERS_BODY": `{"schemaVersion":2,"manifests":[]}`},
			},
			{
				name:      "child_version_label_mismatch",
				dockerEnv: map[string]string{"FAKE_DOCKER_ARM64_VERSION": "0.3.0-rc.1"},
			},
			{
				name: "alias_probe_http_500_containing_404",
				dockerEnv: map[string]string{
					"FAKE_OCI_DEFAULT_CODE": "500",
					"FAKE_OCI_DEFAULT_BODY": "error 404 manifest unknown",
				},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
					localTags:  []string{"v0.3.0"},
					releaseTag: "v0.3.0",
					digest:     validDigest,
					withOrigin: true,
					dockerEnv:  tc.dockerEnv,
				})
				if res.err == nil {
					t.Fatalf("promote_latest failed open for %s:\n%s", tc.name, res.out)
				}
				if len(dockerCreateCalls(res.dockerCalls)) != 0 {
					t.Fatalf("promote_latest created aliases despite failure %s: %q", tc.name, res.dockerCalls)
				}
			})
		}
	})

	t.Run("promotes_annotated_stable_tag_via_peeled_commit_and_rejects_withdrawn_or_moved_tag", func(t *testing.T) {
		resAnnotated := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			annotatedTags: []string{"v0.3.0"},
			localTags:     []string{"v0.2.0"},
			releaseTag:    "v0.3.0",
			digest:        validDigest,
			withOrigin:    true,
		})
		if resAnnotated.err != nil {
			t.Fatalf("annotated tag promotion failed: %v\n%s", resAnnotated.err, resAnnotated.out)
		}
		if created := dockerCreateCalls(resAnnotated.dockerCalls); !slices.EqualFunc(created, wantCreateCalls, slices.Equal[[]string]) {
			t.Fatalf("annotated tag created = %q, want %q", created, wantCreateCalls)
		}

		resWithdrawn := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:          []string{"v0.2.0", "v0.3.0"},
			withdrawOriginTags: []string{"v0.3.0"},
			releaseTag:         "v0.3.0",
			digest:             validDigest,
			withOrigin:         true,
		})
		if resWithdrawn.err == nil {
			t.Fatalf("withdrawn tag on origin was promoted:\n%s", resWithdrawn.out)
		}
		if len(dockerCreateCalls(resWithdrawn.dockerCalls)) != 0 || len(resWithdrawn.cosignCalls) != 0 {
			t.Fatalf("withdrawn tag invoked cosign/docker create: docker=%q cosign=%q", resWithdrawn.dockerCalls, resWithdrawn.cosignCalls)
		}

		resRetagged := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:      []string{"v0.2.0", "v0.3.0"},
			retagOriginTag: "v0.3.0",
			releaseTag:     "v0.3.0",
			digest:         validDigest,
			withOrigin:     true,
		})
		if resRetagged.err == nil {
			t.Fatalf("retagged tag on origin pointing to different commit was promoted:\n%s", resRetagged.out)
		}
		if len(dockerCreateCalls(resRetagged.dockerCalls)) != 0 || len(resRetagged.cosignCalls) != 0 {
			t.Fatalf("retagged tag invoked cosign/docker create: docker=%q cosign=%q", resRetagged.dockerCalls, resRetagged.cosignCalls)
		}
	})

	t.Run("skips_promotion_when_promote_eligible_false", func(t *testing.T) {
		res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:       []string{"v0.3.0"},
			releaseTag:      "v0.3.0",
			digest:          validDigest,
			promoteEligible: "false",
			withOrigin:      true,
		})
		if res.err != nil {
			t.Fatalf("promote_eligible=false failed: %v\n%s", res.err, res.out)
		}
		if len(res.dockerCalls) != 0 || len(res.cosignCalls) != 0 || len(res.ghCalls) != 0 || len(res.curlCalls) != 0 {
			t.Fatalf("promote_eligible=false touched GHCR/cosign/gh: docker=%q cosign=%q gh=%q curl=%q", res.dockerCalls, res.cosignCalls, res.ghCalls, res.curlCalls)
		}
	})

	t.Run("catches_tag_withdrawn_midflight_between_cosign_verify_and_alias_create", func(t *testing.T) {
		res := replayPromoteLatestFull(t, step.Run, promoteLatestReplayOpts{
			localTags:  []string{"v0.3.0"},
			releaseTag: "v0.3.0",
			digest:     validDigest,
			withOrigin: true,
			dockerEnv: map[string]string{
				"FAKE_COSIGN_WITHDRAW_TAG": "v0.3.0",
			},
		})
		if res.err == nil {
			t.Fatalf("promoted tag withdrawn midflight after cosign verify:\n%s", res.out)
		}
		if len(res.cosignCalls) != 1 {
			t.Fatalf("expected initial check to pass and reach cosign verify (1 call), got %q", res.cosignCalls)
		}
		if len(dockerCreateCalls(res.dockerCalls)) != 0 {
			t.Fatalf("created aliases despite midflight tag withdrawal: %q", res.dockerCalls)
		}
	})
}

type prepareReleaseStep struct {
	Name             string            `yaml:"name"`
	If               any               `yaml:"if,omitempty"`
	ContinueOnError  any               `yaml:"continue-on-error,omitempty"`
	Uses             string            `yaml:"uses"`
	With             map[string]any    `yaml:"with"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	Run              string            `yaml:"run"`
	Env              map[string]string `yaml:"env"`
}

// prepareReleaseRunDefaults mirrors a workflow- or job-level `defaults.run`
// block. Every step that leaves its own `shell` or `working-directory` unset
// inherits these values, so the gate must police them as strictly as the
// step-level fields.
type prepareReleaseRunDefaults struct {
	Run struct {
		Shell            string `yaml:"shell"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type prepareReleaseJob struct {
	RunsOn     string                    `yaml:"runs-on"`
	TimeoutMin int                       `yaml:"timeout-minutes"`
	Defaults   prepareReleaseRunDefaults `yaml:"defaults"`
	Steps      []prepareReleaseStep      `yaml:"steps"`
}

// prepareReleaseGateShellAllowed reports whether a security-gate step runs
// under a shell that executes its script with errexit. GitHub Actions runs an
// unset shell as `bash -e {0}` and the `bash` keyword as
// `bash --noprofile --norc -eo pipefail {0}`; any other value (`sh`, `python`,
// or a custom template such as `true {0}`) can ignore the script or its exit
// status, so the gate rejects it.
func prepareReleaseGateShellAllowed(shell string) bool {
	return shell == "" || shell == "bash"
}

// prepareReleaseScriptLines returns the statements of a run block: every line
// that is not blank and not a `#` comment, trimmed. Comments and blank lines
// are ignored by bash, so they cannot change what a gate step executes.
func prepareReleaseScriptLines(run string) []string {
	var lines []string
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

// prepareReleaseWorkflow parses prepare-release.yml for invariant checks.
type prepareReleaseWorkflow struct {
	On struct {
		WorkflowDispatch struct {
			Inputs map[string]struct {
				Description string `yaml:"description"`
				Required    any    `yaml:"required"`
				Type        string `yaml:"type"`
				Default     any    `yaml:"default"`
			} `yaml:"inputs"`
		} `yaml:"workflow_dispatch"`
	} `yaml:"on"`
	Permissions map[string]string            `yaml:"permissions"`
	Defaults    prepareReleaseRunDefaults    `yaml:"defaults"`
	Jobs        map[string]prepareReleaseJob `yaml:"jobs"`
}

func readPrepareReleaseWorkflow(t *testing.T) prepareReleaseWorkflow {
	t.Helper()
	var wf prepareReleaseWorkflow
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/workflows/prepare-release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

func stepRunsLine(run, needle string) bool {
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, needle) {
			return true
		}
	}
	return false
}

func stepRunsExactLine(run, want string) bool {
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if trimmed == want {
			return true
		}
	}
	return false
}

func stepDisablesErrexit(run string) bool {
	replacer := strings.NewReplacer("&&", "\n", "||", "\n", ";", "\n")
	for _, line := range strings.Split(run, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		for _, stmt := range strings.Split(replacer.Replace(trimmed), "\n") {
			fields := strings.Fields(stmt)
			if len(fields) < 2 || fields[0] != "set" {
				continue
			}
			for i := 1; i < len(fields); i++ {
				tok := fields[i]
				if strings.HasPrefix(tok, "#") {
					break
				}
				if tok == "+o" && i+1 < len(fields) && fields[i+1] == "errexit" {
					return true
				}
				if tok == "+errexit" {
					return true
				}
				if strings.HasPrefix(tok, "+") && !strings.HasPrefix(tok, "+o") && strings.Contains(tok[1:], "e") {
					return true
				}
			}
		}
	}
	return false
}

func checkPrepareReleaseVulncheckGate(wf prepareReleaseWorkflow) error {
	job, ok := wf.Jobs["prepare"]
	if !ok {
		return fmt.Errorf("prepare-release.yml is missing the prepare job")
	}

	const (
		installCmd = "go install golang.org/x/vuln/cmd/govulncheck@v1.8.0"
		pathLine   = `echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"`
		runCmd     = "govulncheck ./..."
	)
	installLines := []string{installCmd, pathLine}

	// Workflow- and job-level defaults apply to every step that does not set
	// its own shell or working directory, so a `true {0}` default or a
	// relocated working directory bypasses the gate steps' own settings.
	for _, d := range []struct {
		level    string
		defaults prepareReleaseRunDefaults
	}{{"workflow", wf.Defaults}, {"job", job.Defaults}} {
		if !prepareReleaseGateShellAllowed(d.defaults.Run.Shell) {
			return fmt.Errorf("%s-level defaults.run.shell %q is not allowed; only the default shell or bash may run the gate", d.level, d.defaults.Run.Shell)
		}
		if d.defaults.Run.WorkingDirectory != "" {
			return fmt.Errorf("%s-level defaults.run.working-directory %q would move the govulncheck gate off the module root", d.level, d.defaults.Run.WorkingDirectory)
		}
	}

	// gateStep holds the checks shared by the install and scan steps: both
	// must run unconditionally, under an errexit shell, from the module root,
	// without a masked exit status or an environment that redirects the
	// toolchain (GOBIN, GOFLAGS, GOVULNDB, PATH).
	gateStep := func(kind string, step prepareReleaseStep) error {
		if !unconditionalReleaseStep(step.If) {
			return fmt.Errorf("govulncheck %s step %q has conditional gate: %v", kind, step.Name, step.If)
		}
		if step.ContinueOnError != nil && step.ContinueOnError != false {
			return fmt.Errorf("govulncheck %s step %q sets continue-on-error: %v", kind, step.Name, step.ContinueOnError)
		}
		if !prepareReleaseGateShellAllowed(step.Shell) {
			return fmt.Errorf("govulncheck %s step %q uses custom shell %q; only the default shell or bash may run the gate", kind, step.Name, step.Shell)
		}
		if step.WorkingDirectory != "" {
			return fmt.Errorf("govulncheck %s step %q sets working-directory %q; the gate must run from the module root", kind, step.Name, step.WorkingDirectory)
		}
		if len(step.Env) != 0 {
			return fmt.Errorf("govulncheck %s step %q sets env %v; the gate must not override the toolchain environment", kind, step.Name, step.Env)
		}
		if stepDisablesErrexit(step.Run) {
			return fmt.Errorf("govulncheck %s step %q disables errexit", kind, step.Name)
		}
		return nil
	}

	tagIdx, installIdx, vulnIdx := -1, -1, -1
	for i, step := range job.Steps {
		if step.Name == "Cut and push tag" {
			tagIdx = i
		}
		if stepRunsExactLine(step.Run, installCmd) {
			if err := gateStep("install", step); err != nil {
				return err
			}
			// The install script must be exactly the pinned install followed
			// by the PATH export: an `exit 0` placed before the install, or a
			// statement after it that overwrites the installed binary with an
			// exit-0 shim, leaves the scan step running no scanner at all.
			if got := prepareReleaseScriptLines(step.Run); !slices.Equal(got, installLines) {
				return fmt.Errorf("govulncheck install step %q script must be exactly %q, got %q", step.Name, installLines, got)
			}
			installIdx = i
		}
		if stepRunsExactLine(step.Run, runCmd) {
			if err := gateStep("scan", step); err != nil {
				return err
			}
			// The scan must be the whole script: a preceding `exit 0`, a
			// trailing `|| true`, or any other surrounding statement can end
			// the step successfully without the scanner's verdict.
			if strings.TrimSpace(step.Run) != runCmd {
				return fmt.Errorf("govulncheck scan step %q run script must be exactly %q, got %q", step.Name, runCmd, step.Run)
			}
			vulnIdx = i
		}
	}
	if tagIdx < 0 {
		return fmt.Errorf("prepare-release is missing the 'Cut and push tag' step")
	}
	if installIdx < 0 {
		return fmt.Errorf("prepare-release is missing %q", installCmd)
	}
	if vulnIdx < 0 {
		return fmt.Errorf("prepare-release is missing %q", runCmd)
	}
	if installIdx > vulnIdx {
		return fmt.Errorf("govulncheck install (step %d) must precede govulncheck run (step %d)", installIdx, vulnIdx)
	}
	if installIdx >= tagIdx {
		return fmt.Errorf("govulncheck install (step %d) must precede 'Cut and push tag' (step %d)", installIdx, tagIdx)
	}
	if vulnIdx >= tagIdx {
		return fmt.Errorf("govulncheck run (step %d) must precede 'Cut and push tag' (step %d)", vulnIdx, tagIdx)
	}
	return nil
}

// TestPrepareReleaseWorkflow verifies the one-click release cut workflow
// exists and enforces semver, main-branch, tag-existence, CHANGELOG,
// go.mod replace, test, and govulncheck checks before pushing the tag.
func TestPrepareReleaseWorkflow(t *testing.T) {
	wf := readPrepareReleaseWorkflow(t)

	// workflow_dispatch with version (required) and dry_run (default true).
	if len(wf.On.WorkflowDispatch.Inputs) == 0 {
		t.Fatal("prepare-release.yml has no workflow_dispatch inputs")
	}
	versionInput, ok := wf.On.WorkflowDispatch.Inputs["version"]
	if !ok {
		t.Fatal("prepare-release.yml is missing the version input")
	}
	if versionInput.Type != "string" {
		t.Errorf("version input type = %q, want string", versionInput.Type)
	}
	if versionInput.Required != true {
		t.Errorf("version input required = %v, want true", versionInput.Required)
	}
	dryRunInput, ok := wf.On.WorkflowDispatch.Inputs["dry_run"]
	if !ok {
		t.Fatal("prepare-release.yml is missing the dry_run input")
	}
	if dryRunInput.Default != "true" {
		t.Errorf("dry_run default = %v, want \"true\"", dryRunInput.Default)
	}

	// permissions: contents: write (push tag) and actions: write (trigger release.yml).
	if wf.Permissions["contents"] != "write" {
		t.Errorf("permissions.contents = %q, want write", wf.Permissions["contents"])
	}
	if wf.Permissions["actions"] != "write" {
		t.Errorf("permissions.actions = %q, want write", wf.Permissions["actions"])
	}

	job, ok := wf.Jobs["prepare"]
	if !ok {
		t.Fatal("prepare-release.yml is missing the prepare job")
	}
	if job.RunsOn != "ubuntu-latest" {
		t.Errorf("prepare job runs-on = %q, want ubuntu-latest", job.RunsOn)
	}

	// Both actions must use the same full-SHA pins as the release job.
	checkoutPin := "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
	setupGoPin := "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e"
	foundCheckout, foundSetupGo := false, false
	for _, step := range job.Steps {
		if step.Uses == checkoutPin {
			foundCheckout = true
		}
		if step.Uses == setupGoPin {
			if step.With["go-version"] != "1.27.4" {
				t.Errorf("prepare-release setup-go go-version = %v, want 1.27.4", step.With["go-version"])
			}
			foundSetupGo = true
		}
		// No run: block may use ${{ template interpolation.
		if strings.Contains(step.Run, "${{") {
			t.Errorf("prepare-release step %q interpolates an expression into shell", step.Name)
		}
	}
	if !foundCheckout {
		t.Error("prepare-release is missing the SHA-pinned actions/checkout step")
	}
	if !foundSetupGo {
		t.Error("prepare-release is missing the SHA-pinned actions/setup-go step")
	}

	// Verify the validation invariants are present in the run blocks.
	var allRun string
	for _, step := range job.Steps {
		allRun += step.Run + "\n"
	}
	for _, want := range []string{
		"^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$",
		"refs/heads/main",
		"git rev-parse",
		"CHANGELOG.md",
		"^[[:space:]]*replace([[:space:]]|\\()",
		"go mod verify",
		"go mod tidy -diff",
		"go vet ./...",
		"go test -race -count=1 ./...",
		"go install golang.org/x/vuln/cmd/govulncheck@v1.8.0",
		"govulncheck ./...",
		`^## \[`,
		`git config user.name "github-actions[bot]"`,
		`git config user.email "github-actions[bot]@users.noreply.github.com"`,
		`refs/tags/${VERSION}`,
		`gh workflow run release.yml`,
	} {
		if !strings.Contains(allRun, want) {
			t.Errorf("prepare-release run blocks missing %q", want)
		}
	}

	// The tag-push step must be gated on dry_run == 'false'.
	var tagStep *prepareReleaseStep
	for i := range job.Steps {
		if job.Steps[i].Name == "Cut and push tag" {
			tagStep = &job.Steps[i]
			break
		}
	}
	if tagStep == nil {
		t.Fatal("prepare-release is missing the 'Cut and push tag' step")
	}
	ifCond, _ := tagStep.If.(string)
	if ifCond != "inputs.dry_run == 'false'" {
		t.Errorf("Cut and push tag if = %v, want inputs.dry_run == 'false'", tagStep.If)
	}

	// govulncheck@v1.8.0 must install and run unconditionally before Cut and push tag.
	if err := checkPrepareReleaseVulncheckGate(wf); err != nil {
		t.Error(err)
	}
}

// TestPrepareReleaseWorkflowRejectsBrokenVulncheckGate verifies that removing,
// reordering, commenting out, unpinning, dry_run-skipping, continue-on-error
// masking, shell-bypassing, exiting before the scan, running the gate under a
// custom shell (step-level or via workflow/job defaults), relocating it with a
// working-directory, overriding its environment, or wrapping the install in
// extra statements (early exit, binary shim) in prepare-release.yml fails
// checkPrepareReleaseVulncheckGate.
func TestPrepareReleaseWorkflowRejectsBrokenVulncheckGate(t *testing.T) {
	base := readPrepareReleaseWorkflow(t)
	if err := checkPrepareReleaseVulncheckGate(base); err != nil {
		t.Fatalf("baseline prepare-release.yml rejected: %v", err)
	}

	clonePrepare := func(mutate func(steps []prepareReleaseStep) []prepareReleaseStep) prepareReleaseWorkflow {
		wf := readPrepareReleaseWorkflow(t)
		job := wf.Jobs["prepare"]
		job.Steps = mutate(slices.Clone(job.Steps))
		wf.Jobs["prepare"] = job
		return wf
	}
	cloneJob := func(mutate func(wf *prepareReleaseWorkflow, job *prepareReleaseJob)) prepareReleaseWorkflow {
		wf := readPrepareReleaseWorkflow(t)
		job := wf.Jobs["prepare"]
		job.Steps = slices.Clone(job.Steps)
		mutate(&wf, &job)
		wf.Jobs["prepare"] = job
		return wf
	}

	isVulnStep := func(s prepareReleaseStep) bool {
		return stepRunsLine(s.Run, "govulncheck@") || stepRunsLine(s.Run, "govulncheck ./...")
	}
	isInstallStep := func(s prepareReleaseStep) bool {
		return stepRunsLine(s.Run, "govulncheck@v1.8.0")
	}
	isScanStep := func(s prepareReleaseStep) bool {
		return stepRunsLine(s.Run, "govulncheck ./...")
	}

	explicitFalse := clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
		for i := range steps {
			if isVulnStep(steps[i]) {
				steps[i].ContinueOnError = false
			}
		}
		return steps
	})
	if err := checkPrepareReleaseVulncheckGate(explicitFalse); err != nil {
		t.Fatalf("prepare-release.yml with continue-on-error: false rejected: %v", err)
	}

	// `shell: bash` is the one explicit shell the gate accepts: it runs the
	// script with -e and pipefail, which is at least as strict as the default.
	explicitBash := clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
		for i := range steps {
			if isVulnStep(steps[i]) {
				steps[i].Shell = "bash"
			}
		}
		return steps
	})
	if err := checkPrepareReleaseVulncheckGate(explicitBash); err != nil {
		t.Fatalf("prepare-release.yml with shell: bash on govulncheck steps rejected: %v", err)
	}
	defaultsBash := cloneJob(func(wf *prepareReleaseWorkflow, job *prepareReleaseJob) {
		wf.Defaults.Run.Shell = "bash"
		job.Defaults.Run.Shell = "bash"
	})
	if err := checkPrepareReleaseVulncheckGate(defaultsBash); err != nil {
		t.Fatalf("prepare-release.yml with defaults.run.shell: bash rejected: %v", err)
	}

	// Comments and blank lines around the two install statements change
	// nothing bash executes, so the exact-script rule must tolerate them.
	commentedInstall := clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
		for i := range steps {
			if isInstallStep(steps[i]) {
				steps[i].Run = "# pinned scanner; raise by hand\n\ngo install golang.org/x/vuln/cmd/govulncheck@v1.8.0\n  # export the install directory\necho \"$(go env GOPATH)/bin\" >> \"$GITHUB_PATH\"\n"
			}
		}
		return steps
	})
	if err := checkPrepareReleaseVulncheckGate(commentedInstall); err != nil {
		t.Fatalf("prepare-release.yml with comments around the install statements rejected: %v", err)
	}

	// parseMutatedPrepare applies one textual edit to the checked-in workflow
	// and re-parses it, so fields such as shell, defaults, and multi-line run
	// scripts are proven through real YAML parsing rather than struct
	// mutation alone.
	rawPrepare := testsupport.ReadRepoText(t, ".github/workflows/prepare-release.yml")
	parseMutatedPrepare := func(t *testing.T, oldStr, newStr string) prepareReleaseWorkflow {
		t.Helper()
		mutated := strings.Replace(rawPrepare, oldStr, newStr, 1)
		if mutated == rawPrepare {
			t.Fatalf("prepare-release.yml fixture does not contain %q", oldStr)
		}
		var wf prepareReleaseWorkflow
		if err := yaml.Unmarshal([]byte(mutated), &wf); err != nil {
			t.Fatalf("unmarshaling mutated prepare-release.yml: %v", err)
		}
		return wf
	}
	yamlContinueOnErrorWF := parseMutatedPrepare(t, "        run: govulncheck ./...", "        continue-on-error: true\n        run: govulncheck ./...")
	yamlCustomShellWF := parseMutatedPrepare(t, "        run: govulncheck ./...", "        shell: 'true {0}'\n        run: govulncheck ./...")
	yamlEarlyExitWF := parseMutatedPrepare(t, "        run: govulncheck ./...", "        run: |\n          exit 0\n          govulncheck ./...")
	yamlJobDefaultsShellWF := parseMutatedPrepare(t, "    timeout-minutes: 15\n", "    timeout-minutes: 15\n    defaults:\n      run:\n        shell: 'true {0}'\n")
	yamlWorkflowDefaultsShellWF := parseMutatedPrepare(t, "jobs:\n", "defaults:\n  run:\n    shell: 'true {0}'\n\njobs:\n")
	yamlScanWorkingDirectoryWF := parseMutatedPrepare(t, "        run: govulncheck ./...", "        working-directory: /tmp\n        run: govulncheck ./...")
	yamlInstallShimWF := parseMutatedPrepare(t,
		"          echo \"$(go env GOPATH)/bin\" >> \"$GITHUB_PATH\"\n",
		"          echo \"$(go env GOPATH)/bin\" >> \"$GITHUB_PATH\"\n          printf '#!/bin/sh\\nexit 0\\n' > \"$(go env GOPATH)/bin/govulncheck\"\n          chmod +x \"$(go env GOPATH)/bin/govulncheck\"\n")

	for _, tc := range []struct {
		name string
		wf   prepareReleaseWorkflow
	}{
		{
			name: "missing govulncheck steps",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				out := make([]prepareReleaseStep, 0, len(steps))
				for _, s := range steps {
					if !isVulnStep(s) {
						out = append(out, s)
					}
				}
				return out
			}),
		},
		{
			name: "govulncheck steps placed after Cut and push tag",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				var pre, vuln []prepareReleaseStep
				for _, s := range steps {
					if isVulnStep(s) {
						vuln = append(vuln, s)
					} else {
						pre = append(pre, s)
					}
				}
				return append(pre, vuln...)
			}),
		},
		{
			name: "govulncheck run step placed after Cut and push tag",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				var out, post []prepareReleaseStep
				for _, s := range steps {
					if stepRunsLine(s.Run, "govulncheck ./...") {
						post = append(post, s)
					} else {
						out = append(out, s)
					}
				}
				return append(out, post...)
			}),
		},
		{
			name: "govulncheck run placed before install",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				installIdx, vulnIdx := -1, -1
				for i, s := range steps {
					if stepRunsLine(s.Run, "govulncheck@v1.8.0") {
						installIdx = i
					}
					if stepRunsLine(s.Run, "govulncheck ./...") {
						vulnIdx = i
					}
				}
				steps[installIdx], steps[vulnIdx] = steps[vulnIdx], steps[installIdx]
				return steps
			}),
		},
		{
			name: "govulncheck skipped on dry_run",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].If = "inputs.dry_run == 'false'"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck pinned to @latest instead of v1.8.0",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					steps[i].Run = strings.ReplaceAll(steps[i].Run, "@v1.8.0", "@latest")
				}
				return steps
			}),
		},
		{
			name: "govulncheck command commented out",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "# govulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run has continue-on-error true",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].ContinueOnError = true
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run YAML continue-on-error true",
			wf:   yamlContinueOnErrorWF,
		},
		{
			name: "govulncheck install has continue-on-error expression",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck@v1.8.0") {
						steps[i].ContinueOnError = "${{ true }}"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run masked with || true",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "govulncheck ./... || true"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run altered with -format=json",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "govulncheck ./... -format=json"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run disables errexit with set +e",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "set +e\ngovulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run disables errexit with set +o errexit",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "set +o errexit\ngovulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run disables errexit with set -o +errexit",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "set -o +errexit\ngovulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install disables errexit with set +e",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck@v1.8.0") {
						steps[i].Run = "set +e\n" + steps[i].Run
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run masked with echo",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "echo govulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run exits before scanning",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "exit 0\ngovulncheck ./..."
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run YAML exits before scanning",
			wf:   yamlEarlyExitWF,
		},
		{
			name: "govulncheck run followed by extra statement",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Run = "govulncheck ./...\necho scanned"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run uses custom shell true {0}",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Shell = "true {0}"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run YAML uses custom shell true {0}",
			wf:   yamlCustomShellWF,
		},
		{
			name: "govulncheck run uses sh shell",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Shell = "sh"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run uses python shell",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Shell = "python"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck run uses bash template without errexit",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck ./...") {
						steps[i].Shell = "bash {0}"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install uses custom shell true {0}",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck@v1.8.0") {
						steps[i].Shell = "true {0}"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install uses sh shell",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if stepRunsLine(steps[i].Run, "govulncheck@v1.8.0") {
						steps[i].Shell = "sh"
					}
				}
				return steps
			}),
		},
		{
			name: "job-level defaults.run.shell true {0}",
			wf: cloneJob(func(_ *prepareReleaseWorkflow, job *prepareReleaseJob) {
				job.Defaults.Run.Shell = "true {0}"
			}),
		},
		{
			name: "job-level defaults.run.shell true {0} YAML",
			wf:   yamlJobDefaultsShellWF,
		},
		{
			name: "workflow-level defaults.run.shell true {0}",
			wf: cloneJob(func(wf *prepareReleaseWorkflow, _ *prepareReleaseJob) {
				wf.Defaults.Run.Shell = "true {0}"
			}),
		},
		{
			name: "workflow-level defaults.run.shell true {0} YAML",
			wf:   yamlWorkflowDefaultsShellWF,
		},
		{
			name: "job-level defaults.run.shell sh",
			wf: cloneJob(func(_ *prepareReleaseWorkflow, job *prepareReleaseJob) {
				job.Defaults.Run.Shell = "sh"
			}),
		},
		{
			name: "job-level defaults.run.working-directory set",
			wf: cloneJob(func(_ *prepareReleaseWorkflow, job *prepareReleaseJob) {
				job.Defaults.Run.WorkingDirectory = "/tmp"
			}),
		},
		{
			name: "workflow-level defaults.run.working-directory set",
			wf: cloneJob(func(wf *prepareReleaseWorkflow, _ *prepareReleaseJob) {
				wf.Defaults.Run.WorkingDirectory = "cmd"
			}),
		},
		{
			name: "govulncheck install exits 0 after exporting GITHUB_PATH and before go install",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].Run = "echo \"$(go env GOPATH)/bin\" >> \"$GITHUB_PATH\"\nexit 0\ngo install golang.org/x/vuln/cmd/govulncheck@v1.8.0\n"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install overwrites the binary with an exit-0 shim",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].Run += "printf '#!/bin/sh\\nexit 0\\n' > \"$(go env GOPATH)/bin/govulncheck\"\nchmod +x \"$(go env GOPATH)/bin/govulncheck\"\n"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install overwrites the binary with an exit-0 shim YAML",
			wf:   yamlInstallShimWF,
		},
		{
			name: "govulncheck install statements reordered",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].Run = "echo \"$(go env GOPATH)/bin\" >> \"$GITHUB_PATH\"\ngo install golang.org/x/vuln/cmd/govulncheck@v1.8.0\n"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install drops the GITHUB_PATH export",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].Run = "go install golang.org/x/vuln/cmd/govulncheck@v1.8.0\n"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck scan sets working-directory /tmp",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isScanStep(steps[i]) {
						steps[i].WorkingDirectory = "/tmp"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck scan sets working-directory /tmp YAML",
			wf:   yamlScanWorkingDirectoryWF,
		},
		{
			name: "govulncheck scan sets working-directory subpackage",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isScanStep(steps[i]) {
						steps[i].WorkingDirectory = "cmd"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install sets working-directory",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].WorkingDirectory = "/tmp"
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck scan overrides env GOVULNDB",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isScanStep(steps[i]) {
						steps[i].Env = map[string]string{"GOVULNDB": "file:///tmp/empty-db"}
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck scan overrides env PATH",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isScanStep(steps[i]) {
						steps[i].Env = map[string]string{"PATH": "/tmp/shims:/usr/bin"}
					}
				}
				return steps
			}),
		},
		{
			name: "govulncheck install overrides env GOBIN",
			wf: clonePrepare(func(steps []prepareReleaseStep) []prepareReleaseStep {
				for i := range steps {
					if isInstallStep(steps[i]) {
						steps[i].Env = map[string]string{"GOBIN": "/tmp/elsewhere"}
					}
				}
				return steps
			}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkPrepareReleaseVulncheckGate(tc.wf); err == nil {
				t.Fatal("checkPrepareReleaseVulncheckGate accepted broken workflow")
			}
		})
	}
}

// TestReleaseWorkflowsUseFullSHAPins ensures every uses: action in release.yml
// and prepare-release.yml is pinned to a full 40-character commit SHA, not a
// floating tag like @v7.
func TestReleaseWorkflowsUseFullSHAPins(t *testing.T) {
	shaPattern := regexp.MustCompile(`uses: (\S+)@([0-9a-f]{40})\s*#\s*v\d+`)
	for _, path := range []string{".github/workflows/release.yml", ".github/workflows/prepare-release.yml"} {
		raw := testsupport.ReadRepoText(t, path)
		// Find every uses: line and verify it has a 40-char SHA.
		usesLines := regexp.MustCompile(`uses: \S+@\S+`).FindAllString(raw, -1)
		if len(usesLines) == 0 {
			t.Errorf("%s has no uses: actions", path)
		}
		for _, line := range usesLines {
			if !shaPattern.MatchString(line + " #v0") {
				// The pattern needs the trailing comment; recheck with the raw
				// line to find the actual offending pin.
				if !regexp.MustCompile(`uses: \S+@[0-9a-f]{40}`).MatchString(line) {
					t.Errorf("%s: %q is not pinned to a full 40-char SHA", path, line)
				}
			}
		}
		// Zero ${{ in run: blocks (template interpolation prohibition).
		var wf struct {
			Jobs map[string]struct {
				Steps []struct {
					Run string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
			t.Fatalf("unmarshaling %s: %v", path, err)
		}
		for jobName, job := range wf.Jobs {
			for i, step := range job.Steps {
				if strings.Contains(step.Run, "${{") {
					t.Errorf("%s job %s step %d interpolates ${{ into a run block", path, jobName, i)
				}
			}
		}
	}
}

// TestMakefileReleaseCheckTarget verifies the release-check Makefile target
// exists and runs the local Go module release checks.
func TestMakefileReleaseCheckTarget(t *testing.T) {
	makefile := testsupport.ReadRepoText(t, "Makefile")
	if !strings.Contains(makefile, "release-check:") {
		t.Fatal("Makefile is missing the release-check target")
	}
	for _, want := range []string{
		"grep -Eq '^[[:space:]]*replace([[:space:]]|\\()' go.mod",
		"$(GOCMD) mod verify",
		"$(GOCMD) mod tidy -diff",
		"$(GOCMD) vet ./...",
		"TestRelease|TestSupplyChain|TestCollector|TestPublishGoPackage|TestPrepareRelease|TestMakefileReleaseCheck",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("Makefile release-check target missing %q", want)
		}
	}
}
