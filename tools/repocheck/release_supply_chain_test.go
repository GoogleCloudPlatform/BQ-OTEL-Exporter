// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
)

// These protections must run on every successful release. Restrict conditions
// to the default or an explicit success() rather than guessing at expressions.
func unconditionalReleaseStep(condition any) bool {
	return condition == nil || condition == "success()" || condition == "${{ success() }}"
}

func checkSupplyChainWorkflow(wf supplyChainWorkflow) (supplyChainStep, error) {
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
		wf.Jobs.Preflight.Permissions["packages"] != "read" {
		return supplyChainStep{}, fmt.Errorf("preflight permissions = %v, want contents:read, id-token:write, packages:read", wf.Jobs.Preflight.Permissions)
	}
	if len(wf.Jobs.Preflight.Permissions) != 3 {
		return supplyChainStep{}, fmt.Errorf("preflight permissions = %v, want strictly {contents: read, id-token: write, packages: read}", wf.Jobs.Preflight.Permissions)
	}
	preflightPos := map[string]int{}
	for i, step := range wf.Jobs.Preflight.Steps {
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
			} {
				if step.Env[pair[0]] != pair[1] {
					return supplyChainStep{}, fmt.Errorf("preflight check_submission env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
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
		"submission_status", "container_exists", "container_digest", "ar_staged_partial",
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
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("%s interpolates an expression directly into shell", step.Name)
		}
		if step.ID == "promote_latest" || step.ID == "exit_gate_submit" {
			return sbom, fmt.Errorf("jobs.release must not run %s inline (moved to dedicated job)", step.ID)
		}
		key := ""
		switch {
		case step.ID == "release_dedup_guard", step.ID == "reconcile_container", step.ID == "build", step.ID == "manifest_digest", step.ID == "container_sbom", step.ID == "stage_exit_gate_assets":
			key = step.ID
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
			}
		case step.Uses == cosignInstallerV4 && step.With["cosign-release"] == "v2.4.3":
			key = "cosign"
		case step.Uses == downloadSyftV0:
			key = "syft"
		}
		if key == "" {
			continue
		}
		if !unconditionalReleaseStep(step.If) {
			return sbom, fmt.Errorf("%s has conditional protection: %v", key, step.If)
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
		case "reconcile_container":
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("reconcile_container requires explicit bash shell")
			}
			for _, pair := range [][2]string{
				{"RELEASE_TAG", "${{ inputs.tag || github.ref_name }}"},
				{"COMMIT_SHA", "${{ github.sha }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("reconcile_container env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
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
		}
	}
	for _, key := range []string{
		"exit_gate_auth", "exit_gate_gcloud", "release_dedup_guard",
		"setup_buildx", "ghcr_login", "cosign", "syft",
		"reconcile_container", "build", "manifest_digest",
		"container_provenance", "binary_provenance", "container_sbom",
		"stage_exit_gate_assets",
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
		{"manifest_digest", "container_provenance"}, {"manifest_digest", "binary_provenance"},
		{"container_provenance", "container_sbom"}, {"binary_provenance", "container_sbom"},
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
	if len(wf.Jobs.SubmitExitGate.Permissions) != 1 || wf.Jobs.SubmitExitGate.Permissions["id-token"] != "write" {
		return sbom, fmt.Errorf("submit-exit-gate permissions = %v, want strictly {id-token: write}", wf.Jobs.SubmitExitGate.Permissions)
	}
	for _, outKey := range []string{"staging_version", "manifest_uri", "submission_status"} {
		want := "${{ steps.exit_gate_submit.outputs." + outKey + " }}"
		if wf.Jobs.SubmitExitGate.Outputs[outKey] != want {
			return sbom, fmt.Errorf("submit-exit-gate output %s = %q, want %q", outKey, wf.Jobs.SubmitExitGate.Outputs[outKey], want)
		}
	}
	submitPos := map[string]int{}
	for i, step := range wf.Jobs.SubmitExitGate.Steps {
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("submit-exit-gate %s interpolates an expression directly into shell", step.Name)
		}
		if strings.Contains(step.Uses, "goreleaser") || strings.Contains(step.Uses, "docker/") || strings.Contains(step.Uses, "cosign") {
			return sbom, fmt.Errorf("submit-exit-gate must not invoke build/container actions (%s)", step.Uses)
		}
		key := ""
		switch {
		case step.Uses == gcpAuthV3 && step.With["workload_identity_provider"] == exitGateWIFProvider:
			key = "auth"
		case step.Uses == gcpSetupGcloudV3:
			key = "gcloud"
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
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("exit_gate_submit env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
			}
		}
	}
	for _, key := range []string{"auth", "gcloud", "exit_gate_submit"} {
		if _, ok := submitPos[key]; !ok {
			return sbom, fmt.Errorf("missing submit-exit-gate step %s", key)
		}
	}
	if submitPos["auth"] >= submitPos["gcloud"] || submitPos["gcloud"] >= submitPos["exit_gate_submit"] {
		return sbom, fmt.Errorf("submit-exit-gate steps out of order: %v", submitPos)
	}

	// promote-latest acquires a single image-wide concurrency lock, refreshes
	// tags, and promotes :latest, :latest-amd64, and :latest-arm64 only if
	// RELEASE_TAG is still the highest canonical stable semver release.
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
	const wantPromoteIf = "always() && !cancelled() && needs.preflight.result == 'success' && ((needs.preflight.outputs.action == 'full_release' && needs.release.result == 'success' && needs.submit-exit-gate.result == 'success') || (needs.preflight.outputs.action == 'submit_staged' && needs.submit-exit-gate.result == 'success'))"
	if wf.Jobs.PromoteLatest.If != wantPromoteIf {
		return sbom, fmt.Errorf("promote-latest if = %v, want %q", wf.Jobs.PromoteLatest.If, wantPromoteIf)
	}
	if len(wf.Jobs.PromoteLatest.Permissions) != 2 ||
		wf.Jobs.PromoteLatest.Permissions["contents"] != "read" ||
		wf.Jobs.PromoteLatest.Permissions["packages"] != "write" {
		return sbom, fmt.Errorf("promote-latest permissions = %v, want strictly {contents: read, packages: write}", wf.Jobs.PromoteLatest.Permissions)
	}
	promotePos := map[string]int{}
	for i, step := range wf.Jobs.PromoteLatest.Steps {
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
				{"DIGEST", "${{ needs.release.outputs.digest || needs.preflight.outputs.container_digest }}"},
			} {
				if step.Env[pair[0]] != pair[1] {
					return sbom, fmt.Errorf("promote_latest env %s = %q, want %q", pair[0], step.Env[pair[0]], pair[1])
				}
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

func readSupplyChainWorkflow(t *testing.T) supplyChainWorkflow {
	t.Helper()
	var wf supplyChainWorkflow
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/workflows/release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestReleaseWorkflowInstallsPrerequisitesAndResolvesManifestDigest(t *testing.T) {
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	collectorVersion, _ := testsupport.CollectorVersionsFromGoMod(t, "go.mod")
	var scripts string
	for _, step := range wf.Jobs.Release.Steps {
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
	for _, key := range []string{"release_dedup_guard", "reconcile_container", "build", "manifest_digest", "container_sbom", "stage_exit_gate_assets", "binary_provenance", "container_provenance", "exit_gate_auth", "exit_gate_gcloud"} {
		for _, condition := range []any{false, "${{ false }}"} {
			t.Run(fmt.Sprintf("disabled_%s_%v", key, condition), func(t *testing.T) {
				wf := readSupplyChainWorkflow(t)
				for i, step := range wf.Jobs.Release.Steps {
					if step.ID == key || key == "binary_provenance" && step.With["subject-path"] != nil ||
						key == "container_provenance" && step.With["subject-digest"] != nil ||
						key == "exit_gate_auth" && step.Uses == gcpAuthV3 ||
						key == "exit_gate_gcloud" && step.Uses == gcpSetupGcloudV3 {
						wf.Jobs.Release.Steps[i].If = condition
					}
				}
				if _, err := checkSupplyChainWorkflow(wf); err == nil {
					t.Fatal("accepted disabled release protection")
				}
			})
		}
	}
	for _, tc := range []struct {
		name   string
		mutate func(*supplyChainWorkflow)
	}{
		{"wrong checksum path", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Release.Steps {
				if w.Jobs.Release.Steps[i].With["subject-path"] != nil {
					w.Jobs.Release.Steps[i].With["subject-path"] = "dist/other.txt"
				}
			}
		}},
		{"disabled release job", func(w *supplyChainWorkflow) { w.Jobs.Release.If = false }},
		{"unconditional release job drops preflight gate", func(w *supplyChainWorkflow) { w.Jobs.Release.If = nil }},
		{"release job drops preflight dependency", func(w *supplyChainWorkflow) { w.Jobs.Release.Needs = nil }},
		{"missing concurrency queue max", func(w *supplyChainWorkflow) { w.Concurrency.Queue = "" }},
		{"concurrency cancel-in-progress true", func(w *supplyChainWorkflow) { w.Concurrency.CancelInProgress = true }},
		{"disabled preflight job", func(w *supplyChainWorkflow) { w.Jobs.Preflight.If = false }},
		{"preflight grants packages write", func(w *supplyChainWorkflow) {
			w.Jobs.Preflight.Permissions["packages"] = "write"
		}},
		{"preflight drops packages read", func(w *supplyChainWorkflow) {
			delete(w.Jobs.Preflight.Permissions, "packages")
		}},
		{"preflight verify_ref disabled", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Preflight.Steps {
				if w.Jobs.Preflight.Steps[i].ID == "verify_ref" {
					w.Jobs.Preflight.Steps[i].If = false
				}
			}
		}},
		{"preflight check_submission disabled", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Preflight.Steps {
				if w.Jobs.Preflight.Steps[i].ID == "check_submission" {
					w.Jobs.Preflight.Steps[i].If = "${{ false }}"
				}
			}
		}},
		{"submit-exit-gate grants packages write", func(w *supplyChainWorkflow) {
			w.Jobs.SubmitExitGate.Permissions["packages"] = "write"
		}},
		{"submit-exit-gate drops preflight gate", func(w *supplyChainWorkflow) {
			w.Jobs.SubmitExitGate.If = "${{ always() }}"
		}},
		{"submit-exit-gate drops release dependency", func(w *supplyChainWorkflow) {
			w.Jobs.SubmitExitGate.Needs = []string{"preflight"}
		}},
		{"submit-exit-gate exit_gate_submit disabled", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.SubmitExitGate.Steps {
				if w.Jobs.SubmitExitGate.Steps[i].ID == "exit_gate_submit" {
					w.Jobs.SubmitExitGate.Steps[i].If = false
				}
			}
		}},
		{"promote-latest wrong concurrency group", func(w *supplyChainWorkflow) {
			w.Jobs.PromoteLatest.Concurrency.Group = "release-${{ github.ref_name }}"
		}},
		{"promote-latest cancel-in-progress true", func(w *supplyChainWorkflow) {
			w.Jobs.PromoteLatest.Concurrency.CancelInProgress = true
		}},
		{"promote-latest missing concurrency queue max", func(w *supplyChainWorkflow) {
			w.Jobs.PromoteLatest.Concurrency.Queue = ""
		}},
		{"promote-latest drops submit-exit-gate dependency", func(w *supplyChainWorkflow) {
			w.Jobs.PromoteLatest.Needs = []string{"preflight", "release"}
		}},
		{"promote-latest grants id-token write", func(w *supplyChainWorkflow) {
			w.Jobs.PromoteLatest.Permissions["id-token"] = "write"
		}},
		{"promote-latest disabled step", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.PromoteLatest.Steps {
				if w.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					w.Jobs.PromoteLatest.Steps[i].If = "${{ false }}"
				}
			}
		}},
		{"promote_latest wrong shell", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.PromoteLatest.Steps {
				if w.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					w.Jobs.PromoteLatest.Steps[i].Shell = "sh"
				}
			}
		}},
		{"promote_latest wrong digest environment", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.PromoteLatest.Steps {
				if w.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					w.Jobs.PromoteLatest.Steps[i].Env["DIGEST"] = "${{ needs.release.outputs.digest }}"
				}
			}
		}},
		{"promote_latest wrong release tag environment", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.PromoteLatest.Steps {
				if w.Jobs.PromoteLatest.Steps[i].ID == "promote_latest" {
					w.Jobs.PromoteLatest.Steps[i].Env["RELEASE_TAG"] = "${{ github.ref_name }}"
				}
			}
		}},
		{"promote_latest precedes cosign", func(w *supplyChainWorkflow) {
			cosignIdx, promoIdx := -1, -1
			for i, s := range w.Jobs.PromoteLatest.Steps {
				switch {
				case strings.HasPrefix(s.Uses, "sigstore/cosign-installer@"):
					cosignIdx = i
				case s.ID == "promote_latest":
					promoIdx = i
				}
			}
			w.Jobs.PromoteLatest.Steps[cosignIdx], w.Jobs.PromoteLatest.Steps[promoIdx] = w.Jobs.PromoteLatest.Steps[promoIdx], w.Jobs.PromoteLatest.Steps[cosignIdx]
		}},
		{"wrong digest environment", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Release.Steps {
				if w.Jobs.Release.Steps[i].ID == "container_sbom" {
					w.Jobs.Release.Steps[i].Env["DIGEST"] = "${{ steps.build.outputs.digest }}"
				}
			}
		}},
		{"build missing GORELEASER_CURRENT_TAG", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Release.Steps {
				if w.Jobs.Release.Steps[i].ID == "build" {
					delete(w.Jobs.Release.Steps[i].Env, "GORELEASER_CURRENT_TAG")
				}
			}
		}},
		{"build drops --skip=docker reconciliation arg", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Release.Steps {
				if w.Jobs.Release.Steps[i].ID == "build" {
					w.Jobs.Release.Steps[i].With["args"] = "release --clean"
				}
			}
		}},
		{"reconcile_container after build", func(w *supplyChainWorkflow) {
			recIdx, buildIdx := -1, -1
			for i, s := range w.Jobs.Release.Steps {
				switch s.ID {
				case "reconcile_container":
					recIdx = i
				case "build":
					buildIdx = i
				}
			}
			w.Jobs.Release.Steps[recIdx], w.Jobs.Release.Steps[buildIdx] = w.Jobs.Release.Steps[buildIdx], w.Jobs.Release.Steps[recIdx]
		}},
		{"stage_exit_gate_assets precedes container_sbom", func(w *supplyChainWorkflow) {
			sbomIdx, stageIdx := -1, -1
			for i, s := range w.Jobs.Release.Steps {
				switch s.ID {
				case "container_sbom":
					sbomIdx = i
				case "stage_exit_gate_assets":
					stageIdx = i
				}
			}
			w.Jobs.Release.Steps[sbomIdx], w.Jobs.Release.Steps[stageIdx] = w.Jobs.Release.Steps[stageIdx], w.Jobs.Release.Steps[sbomIdx]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wf := readSupplyChainWorkflow(t)
			tc.mutate(&wf)
			if _, err := checkSupplyChainWorkflow(wf); err == nil {
				t.Fatal("accepted broken release input")
			}
		})
	}
	for _, deletedID := range []string{"stage_exit_gate_assets", "release_dedup_guard", "reconcile_container"} {
		t.Run("deleted_release_"+deletedID, func(t *testing.T) {
			wf := readSupplyChainWorkflow(t)
			kept := wf.Jobs.Release.Steps[:0]
			for _, step := range wf.Jobs.Release.Steps {
				if step.ID != deletedID {
					kept = append(kept, step)
				}
			}
			wf.Jobs.Release.Steps = kept
			if _, err := checkSupplyChainWorkflow(wf); err == nil {
				t.Fatalf("accepted release workflow without %s step", deletedID)
			}
		})
	}
	t.Run("deleted_submit_exit_gate_step", func(t *testing.T) {
		wf := readSupplyChainWorkflow(t)
		wf.Jobs.SubmitExitGate.Steps = nil
		if _, err := checkSupplyChainWorkflow(wf); err == nil {
			t.Fatal("accepted workflow without exit_gate_submit step in submit-exit-gate")
		}
	})
	t.Run("deleted_promote_latest_step", func(t *testing.T) {
		wf := readSupplyChainWorkflow(t)
		wf.Jobs.PromoteLatest.Steps = nil
		if _, err := checkSupplyChainWorkflow(wf); err == nil {
			t.Fatal("accepted workflow without promote_latest step in promote-latest")
		}
	})
	// Quoting is YAML syntax, not part of the subject value.
	for _, subject := range []string{"'dist/checksums.txt'", "dist/checksums.txt"} {
		raw := strings.Replace(testsupport.ReadRepoText(t, ".github/workflows/release.yml"), `"dist/checksums.txt"`, subject, 1)
		raw = strings.Replace(raw, "push-to-registry: true", `push-to-registry: "true"`, 1)
		var wf supplyChainWorkflow
		if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
			t.Fatal(err)
		}
		if _, err := checkSupplyChainWorkflow(wf); err != nil {
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
	step, err := checkSupplyChainWorkflow(readSupplyChainWorkflow(t))
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
	step, err := checkSupplyChainWorkflow(readSupplyChainWorkflow(t))
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
	dockerEnv             map[string]string
}

type exitGateReplayResult struct {
	err         error
	commands    []string
	dockerCalls [][]string
	cosignCalls [][]string
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
mkdir -p "$gcs_root" "$ar_root"

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
  obj="$(obj_path_for_uri "$uri")"
  dir_rel="$(dirname "$obj")"
  pat="$(basename "$obj")"
  found_any=0
  if [[ -d "$gcs_root/$dir_rel" ]]; then
    while IFS= read -r match_file; do
      [ -n "$match_file" ] || continue
      echo "${match_file#$gcs_root/}"
      found_any=1
    done < <(find "$gcs_root/$dir_rel" -maxdepth 1 -type f -name "$pat" | LC_ALL=C sort)
  fi
  if [[ "$found_any" -eq 0 && -n "${EXIT_GATE_EXISTING_MANIFEST:-}" ]]; then
    echo "${EXIT_GATE_EXISTING_MANIFEST}"
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
  for arg in "$@"; do
    case "$arg" in
      --version=*) ver="${arg#--version=}" ;;
    esac
  done
  if [[ -n "$ver" && -d "$ar_root/$ver" ]]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      base="$(basename "$f")"
      echo "projects/oss-exit-gate-prod/locations/us/repositories/bq-otel-exporter--githubreleases/files/bq-otel-exporter:${ver}:${base}"
    done < <(find "$ar_root/$ver" -maxdepth 1 -type f | LC_ALL=C sort)
  fi
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
  src=""
  dst=""
  for arg in "$@"; do
    case "$arg" in
      --if-generation-match=0) if_gen_zero=1 ;;
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
if [[ "${1:-}" == "verify" ]]; then
  if [[ "${FAKE_COSIGN_FAIL:-0}" == "1" ]]; then
    echo "Error: no matching signatures" >&2
    exit 1
  fi
  exit 0
fi
echo "unexpected cosign invocation: $*" >&2
exit 2
`

func writeFakeGcloud(t *testing.T, binDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(binDir, "gcloud"), []byte(gcpFakeGcloudStub), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeFakeDockerAndCosign(t *testing.T, binDir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(binDir, "docker"), []byte(fakeDockerStub), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(binDir, "cosign"), []byte(fakeCosignVerifyStub), 0o700); err != nil {
		t.Fatal(err)
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
		if !entry.IsDir() {
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
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "release", wf.Jobs.Release.Steps, stepID)
}

func findSubmitExitGateStep(t *testing.T) supplyChainStep {
	t.Helper()
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "submit-exit-gate", wf.Jobs.SubmitExitGate.Steps, "exit_gate_submit")
}

func findPromoteLatestStep(t *testing.T) supplyChainStep {
	t.Helper()
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	return findJobStep(t, "promote-latest", wf.Jobs.PromoteLatest.Steps, "promote_latest")
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
	if withDist {
		prepareFakeDistDir(t, dir, opts)
	}
	if opts.existingManifest != "" && opts.existingJSON != "" {
		writeStoreManifest(t, storeDir, opts.existingManifest, opts.existingJSON)
	}

	writeFakeGcloud(t, filepath.Join(dir, "bin"))
	writeFakeDockerAndCosign(t, filepath.Join(dir, "bin"))
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
	envMap := map[string]string{
		"PATH":                          filepath.Join(dir, "bin") + string(os.PathListSeparator) + os.Getenv("PATH"),
		"RUNNER_TEMP":                   filepath.Join(dir, "runner_temp"),
		"GITHUB_OUTPUT":                 outPath,
		"GITHUB_STEP_SUMMARY":           sumPath,
		"RELEASE_TAG":                   opts.tag,
		"COMMIT_SHA":                    opts.commitSHA,
		"RUN_ID":                        opts.runID,
		"FORCE_RESUBMIT":                opts.forceResubmit,
		"ACTION":                        action,
		"RELEASE_STAGING_VERSION":       opts.releaseStagingVersion,
		"PREFLIGHT_STAGING_VERSION":     opts.preflightStagingVer,
		"PRIOR_STAGING_VERSION":         opts.priorStagingVersion,
		"EXIT_GATE_TEST_DIR":            dir,
		"EXIT_GATE_STORE_DIR":           storeDir,
		"EXIT_GATE_EXISTING_MANIFEST":   opts.existingManifest,
		"EXIT_GATE_LIST_ERROR":          boolFlag(opts.listError),
		"EXIT_GATE_CAT_ERROR":           boolFlag(opts.catError),
		"EXIT_GATE_AR_LIST_ERROR":       boolFlag(opts.arListError),
		"EXIT_GATE_AR_DELETE_ERROR":     boolFlag(opts.arDeleteError),
		"FAKE_DOCKER_LOG":               dockerLogPath,
		"FAKE_COSIGN_LOG":               cosignLogPath,
		"FAKE_DOCKER_DIGEST":            "sha256:" + strings.Repeat("c", 64),
		"FAKE_DOCKER_RAW_JSON":          releaseIndex(t),
		"FAKE_DOCKER_AMD64_DIGEST":      releaseChildDigests["linux/amd64"],
		"FAKE_DOCKER_ARM64_DIGEST":      releaseChildDigests["linux/arm64"],
		"FAKE_DOCKER_AMD64_COMMIT":      opts.commitSHA,
		"FAKE_DOCKER_ARM64_COMMIT":      opts.commitSHA,
		"FAKE_DOCKER_INSPECT_NOT_FOUND": "1",
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

	t.Run("stage_assets_skips_complete_ar_and_repairs_partial_ar", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		req := requiredArchiveFiles("v0.2.0")

		// Seed complete 13-file AR package -> stage_exit_gate_assets skips delete & upload.
		seedARFiles(t, storeDir, ver, req)
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
		// and cleanly uploads all 13 files.
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

	t.Run("dedup_omits_staging_version_when_existing_manifest_unreadable", func(t *testing.T) {
		tagSum := sha256.Sum256([]byte("v0.2.0"))
		existingPrimary := fmt.Sprintf("bq-otel-exporter/githubreleases/manifests/manifest-%s-%s.json",
			hex.EncodeToString(tagSum[:])[:12], commitSHA[:12])
		res := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			tag:                   "v0.2.0",
			commitSHA:             commitSHA,
			runID:                 "987654321",
			forceResubmit:         "false",
			action:                "full_release",
			releaseStagingVersion: deterministicStagingVersion("v0.2.0", commitSHA),
			existingManifest:      existingPrimary,
			catError:              true,
		})
		if res.err != nil {
			t.Fatalf("dedup retry with unreadable manifest failed: %v", res.err)
		}
		if _, hasVer := res.outputs["staging_version"]; hasVer {
			t.Fatalf("staging_version = %q when existing manifest unreadable, want omitted", res.outputs["staging_version"])
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

	t.Run("submit_staged_submits_existing_ar_package_and_fails_when_ar_empty", func(t *testing.T) {
		storeDir := t.TempDir()
		ver := deterministicStagingVersion("v0.2.0", commitSHA)
		seedARFiles(t, storeDir, ver, requiredArchiveFiles("v0.2.0"))

		res := replaySubmitExitGate(t, submitStep.Run, exitGateReplayOpts{
			storeDir:            storeDir,
			tag:                 "v0.2.0",
			commitSHA:           commitSHA,
			runID:               "555",
			forceResubmit:       "false",
			action:              "submit_staged",
			preflightStagingVer: ver,
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
}

func TestReleasePreflightAndResubmitExitGate(t *testing.T) {
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
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
		if preFresh.err != nil || preFresh.outputs["action"] != "full_release" || preFresh.outputs["container_exists"] != "false" {
			t.Fatalf("fresh preflight = (%v, %v), want action=full_release container_exists=false", preFresh.err, preFresh.outputs)
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

		// 2. Ordinary retry skips in preflight and reports wantVer.
		preRetry := runPreflight(exitGateReplayOpts{runID: "10", forceResubmit: "false"})
		if preRetry.err != nil {
			t.Fatalf("retry preflight failed: %v", preRetry.err)
		}
		if preRetry.outputs["action"] != "skip_duplicate" ||
			preRetry.outputs["submission_status"] != "already_submitted" ||
			preRetry.outputs["staging_version"] != wantVer {
			t.Fatalf("retry preflight outputs = %v, want action=skip_duplicate already_submitted %q", preRetry.outputs, wantVer)
		}
		wantCmd := `gh workflow run release.yml --ref "v0.2.0" -f tag="v0.2.0" -f force_resubmit=true`
		if !strings.Contains(preRetry.summary, wantCmd) {
			t.Fatalf("retry preflight summary missing %q:\n%s", wantCmd, preRetry.summary)
		}

		// Unreadable primary manifest during ordinary retry omits staging_version.
		preRetryNoCat := runPreflight(exitGateReplayOpts{runID: "10", forceResubmit: "false", catError: true})
		if preRetryNoCat.err != nil {
			t.Fatalf("retry preflight with cat error failed: %v", preRetryNoCat.err)
		}
		if _, hasVer := preRetryNoCat.outputs["staging_version"]; hasVer {
			t.Fatalf("retry preflight emitted staging_version=%q despite unreadable manifest", preRetryNoCat.outputs["staging_version"])
		}

		// 3. Force-resubmitting routes to resubmit_existing -> submit-exit-gate
		// reuses wantVer without rebuilding or calling AR upload.
		preForce := runPreflight(exitGateReplayOpts{runID: "20", forceResubmit: "true"})
		if preForce.err != nil {
			t.Fatalf("forced preflight failed: %v", preForce.err)
		}
		if preForce.outputs["action"] != "resubmit_existing" || preForce.outputs["prior_staging_version"] != wantVer || !strings.HasSuffix(preForce.outputs["manifest_uri"], "-r20.json") {
			t.Fatalf("forced preflight outputs = %v, want action=resubmit_existing prior_staging_version=%q -r20.json", preForce.outputs, wantVer)
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

		// 4. Rerunning forced dispatch RUN_ID=20 skips duplicate in both preflight
		// and submit-exit-gate without uploading a second manifest.
		preForceRerun := runPreflight(exitGateReplayOpts{runID: "20", forceResubmit: "true"})
		if preForceRerun.err != nil || preForceRerun.outputs["action"] != "skip_duplicate" || preForceRerun.outputs["staging_version"] != wantVer {
			t.Fatalf("forced rerun preflight = (%v, %v), want skip_duplicate %q", preForceRerun.err, preForceRerun.outputs, wantVer)
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
		seedARFiles(t, storeDir, wantVer, requiredArchiveFiles("v0.2.0"))

		pre := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir:      storeDir,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "30",
			forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
				"FAKE_DOCKER_DIGEST":            wantDigest,
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
		if len(pre.cosignCalls) != 1 {
			t.Fatalf("expected cosign verify in preflight container check, got %q", pre.cosignCalls)
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

		// Verified GHCR container for exact commit + partial AR -> full_release with
		// container_exists=true and ar_staged_partial=true; reconcile_container returns
		// container_exists=true + digest so GoReleaser skips docker rebuild/push.
		partialStore := t.TempDir()
		seedARFiles(t, partialStore, wantVer, requiredArchiveFiles("v0.2.0")[:3])
		prePartial := runWorkflowBashScript(t, checkSubmissionStep.Run, exitGateReplayOpts{
			storeDir:      partialStore,
			tag:           "v0.2.0",
			commitSHA:     commitSHA,
			runID:         "40",
			forceResubmit: "false",
			dockerEnv: map[string]string{
				"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
				"FAKE_DOCKER_DIGEST":            wantDigest,
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

		recOK := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
			tag:       "v0.2.0",
			commitSHA: commitSHA,
			dockerEnv: map[string]string{
				"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
				"FAKE_DOCKER_DIGEST":            wantDigest,
			},
		}, false)
		if recOK.err != nil || recOK.outputs["container_exists"] != "true" || recOK.outputs["digest"] != wantDigest {
			t.Fatalf("reconcile_container = (%v, %v), want container_exists=true digest=%s", recOK.err, recOK.outputs, wantDigest)
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
			name      string
			dockerEnv map[string]string
		}{
			{
				name: "different_commit_owns_ghcr_tag",
				dockerEnv: map[string]string{
					"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
					"FAKE_DOCKER_ARM64_COMMIT":      otherSHA,
				},
			},
			{
				name: "non_404_ghcr_inspect_error",
				dockerEnv: map[string]string{
					"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
					"FAKE_DOCKER_INSPECT_ERR":       "ERROR: 500 Internal Server Error",
				},
			},
			{
				name: "unsigned_or_cosign_verify_failed",
				dockerEnv: map[string]string{
					"FAKE_DOCKER_INSPECT_NOT_FOUND": "0",
					"FAKE_COSIGN_FAIL":              "1",
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
				recFail := runWorkflowBashScript(t, reconcileContainerStep.Run, exitGateReplayOpts{
					tag:       "v0.2.0",
					commitSHA: commitSHA,
					dockerEnv: tc.dockerEnv,
				}, false)
				if recFail.err == nil {
					t.Fatalf("reconcile_container failed open for %s: outputs=%v", tc.name, recFail.outputs)
				}
			})
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
		if pre101.err != nil || pre101.outputs["action"] != "full_release" {
			t.Fatalf("pre101 = (%v, %v), want action=full_release", pre101.err, pre101.outputs)
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

		pre102 := runPreflight("102", "true")
		if pre102.err != nil || pre102.outputs["action"] != "resubmit_existing" || pre102.outputs["prior_staging_version"] != wantVer {
			t.Fatalf("pre102 = (%v, %v), want action=resubmit_existing prior_staging_version=%q", pre102.err, pre102.outputs, wantVer)
		}

		pre103 := runPreflight("103", "false")
		if pre103.err != nil || pre103.outputs["action"] != "skip_duplicate" || pre103.outputs["staging_version"] != wantVer {
			t.Fatalf("pre103 = (%v, %v), want action=skip_duplicate staging_version=%q", pre103.err, pre103.outputs, wantVer)
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
	const wantPublishIf = "always() && !cancelled() && needs.preflight.result == 'success' && ((needs.preflight.outputs.action == 'full_release' && needs.release.result == 'success' && needs.submit-exit-gate.result == 'success' && needs.promote-latest.result == 'success') || (needs.preflight.outputs.action == 'submit_staged' && needs.submit-exit-gate.result == 'success' && needs.promote-latest.result == 'success') || (needs.preflight.outputs.action == 'resubmit_existing' && needs.submit-exit-gate.result == 'success') || needs.preflight.outputs.action == 'skip_duplicate')"
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
	localTags  []string
	originTags []string
	releaseTag string
	digest     string
	withOrigin bool
	dockerEnv  map[string]string
}

func replayPromoteLatest(t *testing.T, script string, opts promoteLatestReplayOpts) (string, [][]string, [][]string, error) {
	t.Helper()
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin")
	originDir := filepath.Join(dir, "origin.git")
	seedDir := filepath.Join(dir, "seed")
	repoDir := filepath.Join(dir, "repo")
	for _, sub := range []string{binDir, originDir, seedDir, repoDir} {
		if err := os.Mkdir(sub, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeDockerAndCosign(t, binDir)
	dockerLogPath := filepath.Join(dir, "docker_calls")
	cosignLogPath := filepath.Join(dir, "cosign_calls")

	envMap := map[string]string{
		"PATH":                     binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"GIT_CONFIG_GLOBAL":        "/dev/null",
		"GIT_CONFIG_SYSTEM":        "/dev/null",
		"RELEASE_TAG":              opts.releaseTag,
		"DIGEST":                   opts.digest,
		"FAKE_DOCKER_LOG":          dockerLogPath,
		"FAKE_COSIGN_LOG":          cosignLogPath,
		"FAKE_DOCKER_DIGEST":       opts.digest,
		"FAKE_DOCKER_RAW_JSON":     releaseIndex(t),
		"FAKE_DOCKER_AMD64_DIGEST": releaseChildDigests["linux/amd64"],
		"FAKE_DOCKER_ARM64_DIGEST": releaseChildDigests["linux/arm64"],
	}
	for k, v := range opts.dockerEnv {
		envMap[k] = v
	}
	cmdEnv := append([]string(nil), os.Environ()...)
	for k, v := range envMap {
		cmdEnv = append(cmdEnv, k+"="+v)
	}
	runGit := func(workDir string, args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = workDir
		cmd.Env = cmdEnv
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v in %s failed: %v: %s", args, workDir, err, out)
		}
	}

	if opts.withOrigin {
		runGit(originDir, "init", "--bare")
		runGit(seedDir, "init", "-b", "main")
		runGit(seedDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
		for _, tag := range opts.localTags {
			runGit(seedDir, "tag", tag)
		}
		runGit(seedDir, "remote", "add", "origin", originDir)
		runGit(seedDir, "push", "origin", "main", "--tags")
		runGit(dir, "clone", originDir, repoDir)
		// Push any newer remote tags AFTER repoDir checked out, simulating a stalled
		// older release acquiring ghcr-promote-latest after a newer release pushed.
		for _, tag := range opts.originTags {
			runGit(seedDir, "tag", tag)
		}
		if len(opts.originTags) > 0 {
			runGit(seedDir, "push", "origin", "--tags")
		}
	} else {
		runGit(repoDir, "init", "-b", "main")
		runGit(repoDir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "--allow-empty", "-m", "init")
		for _, tag := range opts.localTags {
			runGit(repoDir, "tag", tag)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script)
	cmd.Dir = repoDir
	cmd.Env = cmdEnv
	out, err := cmd.CombinedOutput()
	return string(out), readTabLog(t, dockerLogPath), readTabLog(t, cosignLogPath), err
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
