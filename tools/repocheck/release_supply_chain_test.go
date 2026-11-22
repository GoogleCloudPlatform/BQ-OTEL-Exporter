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

	releaseCommonScriptPath    = "scripts/release/common.sh"
	releasePreflightScriptPath = "scripts/release/preflight.sh"
	releaseReconcileScriptPath = "scripts/release/reconcile_container.sh"
	releaseStageScriptPath     = "scripts/release/stage_exit_gate_assets.sh"
	releaseSubmitScriptPath    = "scripts/release/submit_exit_gate.sh"
	releasePromoteScriptPath   = "scripts/release/promote_latest.sh"
)

var releaseScriptPaths = []string{
	releaseCommonScriptPath,
	releasePreflightScriptPath,
	releaseReconcileScriptPath,
	releaseStageScriptPath,
	releaseSubmitScriptPath,
	releasePromoteScriptPath,
}

var executableReleaseScriptPaths = []string{
	releasePreflightScriptPath,
	releaseReconcileScriptPath,
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
			if !strings.Contains(script, `| .version`+"\n"+`        | select(type == "string")`) {
				return supplyChainStep{}, fmt.Errorf("validate_existing_manifest must require .version to be a JSON string")
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
			if !strings.Contains(script, "extract_next_referrers_url") || !strings.Contains(script, "RELEASE_MAX_REFERRERS_PAGES") {
				return supplyChainStep{}, fmt.Errorf("preflight check_submission must enforce bounded OCI referrers Link pagination")
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
			if !strings.Contains(step.Run, "noncurrent_time") {
				return sbom, fmt.Errorf("release_dedup_guard must filter noncurrent GCS manifests")
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
			if !strings.Contains(scripts[releaseSubmitScriptPath], `verify_origin_release_tag "origin" "${RELEASE_TAG}" "${COMMIT_SHA}"`) ||
				!strings.Contains(script, "git ls-remote --tags") {
				return sbom, fmt.Errorf("exit_gate_submit must verify origin tag resolution before submitting manifest")
			}
			if !strings.Contains(scripts[releaseSubmitScriptPath], `verify_changelog_attestation "${verify_dir}/EXIT_GATE_CHANGELOG" "${GITHUB_REPOSITORY}" "${RELEASE_TAG}" "${COMMIT_SHA}"`) ||
				!strings.Contains(script, `gh attestation verify "${changelog_path}"`) ||
				!strings.Contains(script, `--format json`) {
				return sbom, fmt.Errorf("exit_gate_submit missing subject-bound EXIT_GATE_CHANGELOG SLSA attestation verification")
			}
			if strings.Contains(scripts[releaseSubmitScriptPath], "validate_existing_manifest") && strings.Contains(scripts[releaseSubmitScriptPath], "|| true") {
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

	// Verify extract_next_referrers_url awk parser compiles and handles :/ query
	// tokens and empty rel= rejections under strict POSIX/BSD/mawk awk engines.
	commonProgs := extractAwkPrograms(scripts[releaseCommonScriptPath])
	var linkAwkProg string
	for _, p := range commonProgs {
		if strings.Contains(p, "expected_repo") && strings.Contains(p, "expected_digest") {
			linkAwkProg = p
			break
		}
	}
	if linkAwkProg == "" {
		t.Fatalf("could not locate extract_next_referrers_url awk program in %s", releaseCommonScriptPath)
	}
	type awkRunner struct {
		name string
		bin  string
		args []string
	}
	runners := []awkRunner{{name: "awk", bin: "awk"}}
	if gawkBin, err := exec.LookPath("gawk"); err == nil {
		runners = append(runners, awkRunner{name: "gawk-posix", bin: gawkBin, args: []string{"--posix"}})
	}
	if mawkBin, err := exec.LookPath("mawk"); err == nil {
		runners = append(runners, awkRunner{name: "mawk", bin: mawkBin})
	}
	wantDigest := "sha256:" + strings.Repeat("a", 64)
	validHdr := "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json>; rel=\"next\"\n"
	wantURL := "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json"
	emptyRelHdr := "HTTP/2 200\nLink: </v2/googlecloudplatform/bq-otel-collector/referrers/" + wantDigest + "?last=next>; rel=\"\"\n"
	for _, r := range runners {
		t.Run("awk_posix_"+r.name, func(t *testing.T) {
			runAwk := func(input string) (string, error) {
				args := append([]string(nil), r.args...)
				args = append(args, "-v", "expected_repo=googlecloudplatform/bq-otel-collector", "-v", "expected_digest="+wantDigest, linkAwkProg)
				c := exec.Command(r.bin, args...)
				c.Stdin = strings.NewReader(input)
				out, err := c.CombinedOutput()
				return strings.TrimSpace(string(out)), err
			}
			got, err := runAwk(validHdr)
			if err != nil || got != wantURL {
				t.Fatalf("%s failed valid Link header with :/ query chars: got=%q err=%v", r.name, got, err)
			}
			if badOut, err := runAwk(emptyRelHdr); err == nil {
				t.Fatalf("%s failed open on empty rel=\"\": out=%q", r.name, badOut)
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
			b.scripts[releasePreflightScriptPath] = strings.Replace(b.scripts[releasePreflightScriptPath], `"${is_prerelease}")`, `"${is_prerelease}" || true)`, 1)
		}},
		{"submit-exit-gate ignores manifest validation error with || true", func(b *supplyChainBundle) {
			b.scripts[releaseSubmitScriptPath] = strings.Replace(b.scripts[releaseSubmitScriptPath], `"${is_prerelease}")`, `"${is_prerelease}" || true)`, 1)
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
}

type exitGateReplayResult struct {
	err         error
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
    printf 'HTTP/2 %s\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n' "$route_code" > "$hdr_out"
    if [[ -n "$route_digest" ]]; then
      printf '%s: %s\r\n' "$route_hdr_name" "$route_digest" >> "$hdr_out"
    fi
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
  default_ref_body='{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}'
  ref_body="${FAKE_OCI_REFERRERS_BODY:-$default_ref_body}"
  ref_link="${FAKE_OCI_REFERRERS_LINK:-}"
  if [[ -n "${FAKE_OCI_REFERRERS_ROUTES:-}" ]]; then
    while IFS='|' read -r r_key r_code r_body r_link; do
      [[ -n "$r_key" ]] || continue
      if [[ "$url" == "$r_key" || "$url" == "https://ghcr.io$r_key" || "$url" == "https://ghcr.io/v2/googlecloudplatform/bq-otel-collector/referrers/$r_key" ]]; then
        ref_code="$r_code"
        ref_body="$r_body"
        ref_link="${r_link:-}"
        break
      fi
    done <<< "${FAKE_OCI_REFERRERS_ROUTES}"
  fi
  if [[ -n "$hdr_out" ]]; then
    printf 'HTTP/2 %s\r\ncontent-type: application/vnd.oci.image.index.v1+json\r\n' "$ref_code" > "$hdr_out"
    if [[ -n "$ref_link" ]]; then
      if [[ "$ref_link" == [Ll][Ii][Nn][Kk]:* ]]; then
        printf '%s\r\n' "$ref_link" >> "$hdr_out"
      else
        printf 'Link: %s\r\n' "$ref_link" >> "$hdr_out"
      fi
    fi
    if [[ -n "${FAKE_OCI_REFERRERS_RAW_HEADERS:-}" ]]; then
      printf '%s\r\n' "${FAKE_OCI_REFERRERS_RAW_HEADERS}" >> "$hdr_out"
    fi
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
		existingPrimary := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s.json",
			hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
		existingForced := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s-r987654321.json",
			hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])

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

		// Seed complete AR under a fixed real commit in an isolated bare repo test:
		runRealOriginSubmit := func(retag, withdraw bool) exitGateReplayResult {
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
				cmd := exec.Command("git", args...)
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

			if withdraw {
				runGit(seedDir, "push", "origin", "--delete", "v0.2.0")
			}
			if retag {
				runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "moved tag")
				runGit(seedDir, "tag", "-f", "v0.2.0")
				runGit(seedDir, "push", "--force", "origin", "refs/tags/v0.2.0")
			}

			// Run submit_exit_gate.sh with cwd containing origin remote pointing at originDir.
			workDir := t.TempDir()
			for _, name := range []string{"bin", "runner_temp"} {
				if err := os.Mkdir(filepath.Join(workDir, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			stageReleaseScripts(t, workDir)
			writeFakeGcloud(t, filepath.Join(workDir, "bin"))
			writeFakeDockerAndCosign(t, filepath.Join(workDir, "bin"))
			runGit(workDir, "init", "-q", "-b", "main")
			runGit(workDir, "remote", "add", "origin", originDir)

			outPath := filepath.Join(workDir, "github_output")
			sumPath := filepath.Join(workDir, "github_summary")
			for _, p := range []string{outPath, sumPath} {
				if err := os.WriteFile(p, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-c", submitStep.Run)
			cmd.Dir = workDir
			cmd.Env = append(os.Environ(),
				"PATH="+filepath.Join(workDir, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GIT_CONFIG_GLOBAL=/dev/null",
				"GIT_CONFIG_SYSTEM=/dev/null",
				"RUNNER_TEMP="+filepath.Join(workDir, "runner_temp"),
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
			)
			out, err := cmd.CombinedOutput()
			var res exitGateReplayResult
			if err != nil {
				res.err = fmt.Errorf("%w: %s", err, out)
			}
			if raw, rerr := os.ReadFile(filepath.Join(workDir, "gcloud.log")); rerr == nil {
				res.commands = strings.Split(strings.TrimSpace(string(raw)), "\n")
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
			return res
		}

		resValid := runRealOriginSubmit(false, false)
		if resValid.err != nil || resValid.outputs["submission_status"] != "submitted" || len(resValid.stagedFiles) != 1 {
			t.Fatalf("real annotated origin submit failed: err=%v outputs=%v manifests=%v", resValid.err, resValid.outputs, resValid.stagedFiles)
		}
		resMoved := runRealOriginSubmit(true, false)
		if resMoved.err == nil || len(resMoved.stagedFiles) != 0 {
			t.Fatalf("moved origin tag submitted manifest: err=%v manifests=%v", resMoved.err, resMoved.stagedFiles)
		}
		resDeleted := runRealOriginSubmit(false, true)
		if resDeleted.err == nil || len(resDeleted.stagedFiles) != 0 {
			t.Fatalf("withdrawn origin tag submitted manifest: err=%v manifests=%v", resDeleted.err, resDeleted.stagedFiles)
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

		// Release with no generated changelog (13 AR files) succeeds cleanly in submit-exit-gate.
		noCLStore := t.TempDir()
		seedCompleteARVersion(t, noCLStore, "v0.2.0", ver, false)
		subNoCL := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir: noCLStore, tag: "v0.2.0", commitSHA: commitSHA, runID: "905", forceResubmit: "true",
			action: "resubmit_existing", priorStagingVersion: ver,
			dockerEnv: map[string]string{"FAKE_GH_CHANGELOG_ATTESTATION_FAIL": "1"},
		})
		if subNoCL.err != nil || subNoCL.outputs["submission_status"] != "submitted" {
			t.Fatalf("13-file release without changelog failed submit-exit-gate: (%v, %v)", subNoCL.err, subNoCL.outputs)
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
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
					if err := os.WriteFile(filepath.Join(s, "ar", ver, "unexpected.bin"), []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					return exitGateReplayOpts{storeDir: s, tag: "v0.2.0", commitSHA: commitSHA, runID: "2", forceResubmit: "false", action: "submit_staged", preflightStagingVer: ver}
				},
			},
			{
				name: "tampered_remote_archive_sha256_mismatch",
				setup: func(t *testing.T, s string) exitGateReplayOpts {
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
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
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
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
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
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
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
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
					seedCompleteARVersion(t, s, "v0.2.0", ver, false)
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
				"FAKE_OCI_DEFAULT_CODE":       "200",
				"FAKE_OCI_DEFAULT_DIGEST":     wantDigest,
				"FAKE_OCI_DIGEST_HEADER_NAME": "docker-content-digest",
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
		sbomPage1 := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://spdx.dev/Document"}}]}`
		sbomPage2 := `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"artifactType":"application/vnd.example.sbom+json"}]}`
		for _, refTC := range []struct {
			name string
			env  map[string]string
		}{
			{
				name: "empty_referrers",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY": `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
				},
			},
			{
				name: "sbom_only_referrer",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_BODY": sbomPage1,
				},
			},
			{
				name: "paginated_sbom_only_referrers",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + "|" + "200|" + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sbom1>; rel="next"`,
						wantDigest + "?last=sbom1|200|" + sbomPage2 + "|",
					}, "\n"),
				},
			},
			{
				name: "paginated_opaque_colon_slash_token",
				env: map[string]string{
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + "|" + "200|" + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json>; rel="next"`,
						wantDigest + "?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json|200|" + sbomPage2 + "|",
					}, "\n"),
				},
			},
		} {
			t.Run("missing_provenance_recovery_"+refTC.name, func(t *testing.T) {
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
				recMiss := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: env,
				}, false)
				if recMiss.err != nil ||
					recMiss.outputs["container_exists"] != "false" ||
					recMiss.outputs["digest"] != "" {
					t.Fatalf("missing provenance reconcile_container (%s) = (%v, %v), want container_exists=false empty digest", refTC.name, recMiss.err, recMiss.outputs)
				}
			})
		}

		// A digest containing HTTP-status-like digits (403, 502) must NOT trigger a
		// false lookup error when gh prints "no attestations found for subject
		// oci://...@sha256:403502...", whereas a genuine HTTP 502 lookup failure
		// on that same digest still fails closed.
		statusDigitsDigest := "sha256:403502" + strings.Repeat("c", 58)
		t.Run("missing_provenance_recovery_digest_with_status_digits", func(t *testing.T) {
			env := map[string]string{
				"FAKE_OCI_DEFAULT_CODE":    "200",
				"FAKE_OCI_DEFAULT_DIGEST":  statusDigitsDigest,
				"FAKE_GH_ATTESTATION_FAIL": "missing",
				"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[]}`,
			}
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
			recMiss := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
				tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: env,
			}, false)
			if recMiss.err != nil ||
				recMiss.outputs["container_exists"] != "false" ||
				recMiss.outputs["digest"] != "" {
				t.Fatalf("missing provenance reconcile_container (statusDigitsDigest) = (%v, %v), want container_exists=false empty digest", recMiss.err, recMiss.outputs)
			}
		})

		// Build a >20 page pagination chain to ensure unbounded referrers fail closed.
		var overMaxRoutes []string
		for p := 1; p <= 21; p++ {
			suffix := wantDigest
			if p > 1 {
				suffix = fmt.Sprintf("%s?p=%d", wantDigest, p)
			}
			nextLink := fmt.Sprintf(`</v2/googlecloudplatform/bq-otel-collector/referrers/%s?p=%d>; rel="next"`, wantDigest, p+1)
			overMaxRoutes = append(overMaxRoutes, suffix+"|200|"+sbomPage2+"|"+nextLink)
		}

		// Ambiguous, invalid, incomplete, or transient-error provenance classification MUST fail closed.
		for _, badRef := range []struct {
			name string
			env  map[string]string
		}{
			{
				name: "slsa_provenance_referrer_exists_but_verify_failed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}`,
				},
			},
			{
				name: "unannotated_sigstore_referrer_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json"}]}`,
				},
			},
			{
				name: "incomplete_referrers_missing_manifests_field_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json"}`,
				},
			},
			{
				name: "referrers_paginated_page1_sbom_page2_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sbom>; rel="next"`,
						wantDigest + `?last=sbom|200|{"schemaVersion":2,"manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}|`,
					}, "\n"),
				},
			},
			{
				name: "referrers_paginated_opaque_colon_slash_provenance_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join([]string{
						wantDigest + `|200|` + sbomPage1 + `|</v2/googlecloudplatform/bq-otel-collector/referrers/` + wantDigest + `?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json>; rel="next"`,
						wantDigest + `?last=sha256:abcd1234&artifactType=application/vnd.oci.image.manifest.v1+json|200|{"schemaVersion":2,"manifests":[{"artifactType":"application/vnd.dev.sigstore.bundle.v0.3+json","annotations":{"dev.sigstore.bundle.predicateType":"https://slsa.dev/provenance/v1"}}]}|`,
					}, "\n"),
				},
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
			},
			{
				name: "referrers_exceeds_max_pages_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":     "200",
					"FAKE_OCI_DEFAULT_DIGEST":   wantDigest,
					"FAKE_GH_ATTESTATION_FAIL":  "missing",
					"FAKE_OCI_REFERRERS_ROUTES": strings.Join(overMaxRoutes, "\n"),
				},
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
			},
			{
				name: "gh_403_lookup_error_even_with_empty_referrers_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  wantDigest,
					"FAKE_GH_ATTESTATION_FAIL": "403",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[]}`,
				},
			},
			{
				name: "gh_502_lookup_error_on_status_digits_digest_fails_closed",
				env: map[string]string{
					"FAKE_OCI_DEFAULT_CODE":    "200",
					"FAKE_OCI_DEFAULT_DIGEST":  statusDigitsDigest,
					"FAKE_GH_ATTESTATION_FAIL": "502",
					"FAKE_OCI_REFERRERS_BODY":  `{"schemaVersion":2,"manifests":[]}`,
				},
			},
		} {
			t.Run("provenance_fail_closed_"+badRef.name, func(t *testing.T) {
				if res := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, runID: "44", forceResubmit: "false", dockerEnv: badRef.env,
				}, false); res.err == nil {
					t.Fatalf("preflight failed open for %s: outputs=%v", badRef.name, res.outputs)
				}
				if res := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag: "v0.2.0", commitSHA: commitSHA, dockerEnv: badRef.env,
				}, false); res.err == nil {
					t.Fatalf("reconcile_container failed open for %s: outputs=%v", badRef.name, res.outputs)
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
