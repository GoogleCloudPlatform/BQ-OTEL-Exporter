// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
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
	Jobs struct {
		Release struct {
			If    any               `yaml:"if,omitempty"`
			Steps []supplyChainStep `yaml:"steps"`
		} `yaml:"release"`
	} `yaml:"jobs"`
}

// The actions behind the release protections, pinned to full commit SHAs as
// every workflow action is. The tag each SHA resolves to is the trailing
// comment on its uses line in release.yml; bump both together.
const (
	attestBuildProvenanceV4 = "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8"
	cosignInstallerV4       = "sigstore/cosign-installer@6f9f17788090df1f26f669e9d70d6ae9567deba6"
	downloadSyftV0          = "anchore/sbom-action/download-syft@66cbf4bc1f1c0d2edc94016e65bc221b6bb0ad6c"
)

// These protections must run on every successful release. Restrict conditions
// to the default or an explicit success() rather than guessing at expressions.
func unconditionalReleaseStep(condition any) bool {
	return condition == nil || condition == "success()" || condition == "${{ success() }}"
}

func checkSupplyChainWorkflow(wf supplyChainWorkflow) (supplyChainStep, error) {
	if !unconditionalReleaseStep(wf.Jobs.Release.If) {
		return supplyChainStep{}, fmt.Errorf("release job has conditional protection: %v", wf.Jobs.Release.If)
	}
	positions := map[string]int{}
	var sbom supplyChainStep
	for i, step := range wf.Jobs.Release.Steps {
		if strings.Contains(step.Run, "${{") {
			return sbom, fmt.Errorf("%s interpolates an expression directly into shell", step.Name)
		}
		key := ""
		switch {
		case step.ID == "build", step.ID == "manifest_digest", step.ID == "container_sbom":
			key = step.ID
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
		if key == "container_sbom" {
			sbom = step
			if step.Shell != "bash" {
				return sbom, fmt.Errorf("SBOM script requires explicit bash with pipefail")
			}
			if step.Env["DIGEST"] != "${{ steps.manifest_digest.outputs.digest }}" {
				return sbom, fmt.Errorf("SBOM digest must come from published manifest")
			}
		}
	}
	for _, key := range []string{"cosign", "syft", "build", "manifest_digest", "container_provenance", "binary_provenance", "container_sbom"} {
		if _, ok := positions[key]; !ok {
			return sbom, fmt.Errorf("missing release protection %s", key)
		}
	}
	for _, pair := range [][2]string{
		{"cosign", "build"}, {"syft", "build"}, {"build", "manifest_digest"},
		{"manifest_digest", "container_provenance"}, {"manifest_digest", "binary_provenance"},
		{"container_provenance", "container_sbom"}, {"binary_provenance", "container_sbom"},
	} {
		if positions[pair[0]] >= positions[pair[1]] {
			return sbom, fmt.Errorf("%s must precede %s", pair[0], pair[1])
		}
	}
	return sbom, nil
}

func readSupplyChainWorkflow(t *testing.T) supplyChainWorkflow {
	t.Helper()
	var wf supplyChainWorkflow
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".github/workflows/release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

func TestReleaseWorkflowInstallsPrerequisitesAndResolvesManifestDigest(t *testing.T) {
	wf := readSupplyChainWorkflow(t)
	if _, err := checkSupplyChainWorkflow(wf); err != nil {
		t.Fatal(err)
	}
	collectorVersion, _ := collectorVersionsFromGoMod(t, "go.mod")
	var scripts string
	for _, step := range wf.Jobs.Release.Steps {
		scripts += step.Run + "\n"
	}
	for _, want := range []string{"go.opentelemetry.io/collector/cmd/builder@" + collectorVersion, "ocb version", "syft version", "cosign version"} {
		if !strings.Contains(scripts, want) {
			t.Errorf("release prerequisites missing %q", want)
		}
	}
	if !strings.Contains(readRepoText(t, "example/otelcol-builder-release.yaml"), "replaces:") {
		t.Error("release builder manifest must replace the module with the checkout")
	}
}

func TestReleaseWorkflowConditionsAndInputs(t *testing.T) {
	for _, key := range []string{"build", "manifest_digest", "container_sbom", "binary_provenance", "container_provenance"} {
		for _, condition := range []any{false, "${{ false }}"} {
			t.Run(fmt.Sprintf("disabled_%s_%v", key, condition), func(t *testing.T) {
				wf := readSupplyChainWorkflow(t)
				for i, step := range wf.Jobs.Release.Steps {
					if step.ID == key || key == "binary_provenance" && step.With["subject-path"] != nil ||
						key == "container_provenance" && step.With["subject-digest"] != nil {
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
		{"wrong digest environment", func(w *supplyChainWorkflow) {
			for i := range w.Jobs.Release.Steps {
				if w.Jobs.Release.Steps[i].ID == "container_sbom" {
					w.Jobs.Release.Steps[i].Env["DIGEST"] = "${{ steps.build.outputs.digest }}"
				}
			}
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
	// Quoting is YAML syntax, not part of the subject value.
	for _, subject := range []string{"'dist/checksums.txt'", "dist/checksums.txt"} {
		raw := strings.Replace(readRepoText(t, ".github/workflows/release.yml"), `"dist/checksums.txt"`, subject, 1)
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
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".goreleaser.yaml")), &config); err != nil {
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
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".github/workflows/release.yml")), &wf); err != nil {
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

	// The release job must carry the write permissions the supply chain needs.
	releaseJob, ok := wf.Jobs["release"]
	if !ok {
		t.Fatal("release.yml is missing the release job")
	}
	for _, want := range []struct{ key, val string }{
		{"contents", "write"},
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
	if len(job.Needs) != 1 || job.Needs[0] != "release" {
		t.Errorf("publish-go-package needs = %v, want [release]", job.Needs)
	}
	// publish-go-package must NOT have an if: condition so it runs on both
	// v* tag pushes and workflow_dispatch releases.
	if job.If != nil {
		t.Errorf("publish-go-package has if = %v, want none (needs: [release] suffices)", job.If)
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
			if step.With["go-version"] != "1.27.3" {
				t.Errorf("publish-go-package setup-go go-version = %v, want 1.27.3", step.With["go-version"])
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
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		RunsOn     string `yaml:"runs-on"`
		TimeoutMin int    `yaml:"timeout-minutes"`
		Steps      []struct {
			Name string            `yaml:"name"`
			If   any               `yaml:"if,omitempty"`
			Uses string            `yaml:"uses"`
			With map[string]any    `yaml:"with"`
			Run  string            `yaml:"run"`
			Env  map[string]string `yaml:"env"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readPrepareReleaseWorkflow(t *testing.T) prepareReleaseWorkflow {
	t.Helper()
	var wf prepareReleaseWorkflow
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".github/workflows/prepare-release.yml")), &wf); err != nil {
		t.Fatal(err)
	}
	return wf
}

// TestPrepareReleaseWorkflow verifies the one-click release cut workflow
// exists and enforces semver, main-branch, tag-existence, CHANGELOG,
// go.mod replace, and test checks before pushing the tag.
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
			if step.With["go-version"] != "1.27.3" {
				t.Errorf("prepare-release setup-go go-version = %v, want 1.27.3", step.With["go-version"])
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
	var tagStep *struct {
		Name string            `yaml:"name"`
		If   any               `yaml:"if,omitempty"`
		Uses string            `yaml:"uses"`
		With map[string]any    `yaml:"with"`
		Run  string            `yaml:"run"`
		Env  map[string]string `yaml:"env"`
	}
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
}

// TestReleaseWorkflowsUseFullSHAPins ensures every uses: action in release.yml
// and prepare-release.yml is pinned to a full 40-character commit SHA, not a
// floating tag like @v7.
func TestReleaseWorkflowsUseFullSHAPins(t *testing.T) {
	shaPattern := regexp.MustCompile(`uses: (\S+)@([0-9a-f]{40})\s*#\s*v\d+`)
	for _, path := range []string{".github/workflows/release.yml", ".github/workflows/prepare-release.yml"} {
		raw := readRepoText(t, path)
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
	makefile := readRepoText(t, "Makefile")
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
