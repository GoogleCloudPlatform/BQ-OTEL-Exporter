// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	bq "cloud.google.com/go/bigquery"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"gopkg.in/yaml.v3"

	bigqueryexporter "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/cli/quarantinereplay"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/transform"
)

const (
	minTableStaleness = time.Second
	maxTableStaleness = 7 * 24 * time.Hour
)

func parseMaxStaleness(field, raw string) (time.Duration, error) {
	cfg := bigqueryexporter.CreateDefaultConfig().(*bigqueryexporter.Config)
	cfg.Project = "my-project"
	cfg.Dataset = "otel"
	cfg.Traces.MaxStaleness = raw
	if err := cfg.Validate(); err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	if raw == "" {
		return 0, nil
	}
	return time.ParseDuration(raw)
}

func TestGoReleaserConfigUsesValidSchemaAndSignsManifests(t *testing.T) {
	raw := testsupport.ReadRepoText(t, ".goreleaser.yaml")
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("unmarshaling .goreleaser.yaml: %v", err)
	}

	if _, bad := doc["docker_image_files"]; bad {
		t.Error(".goreleaser.yaml must not contain unknown top-level key docker_image_files")
	}

	manifests, ok := doc["docker_manifests"].([]any)
	if !ok || len(manifests) != 1 {
		t.Fatalf("docker_manifests = %#v, want 1 versioned manifest entry (:latest is promoted separately by release.yml)", doc["docker_manifests"])
	}
	for i, item := range manifests {
		m, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("docker_manifests[%d] = %T, want map", i, item)
		}
		if _, bad := m["docker_manifests_templates"]; bad {
			t.Errorf("docker_manifests[%d] must not use invalid key docker_manifests_templates", i)
		}
		nameTpl, _ := m["name_template"].(string)
		if nameTpl == "" || !strings.Contains(nameTpl, "{{ .Version }}") || strings.Contains(nameTpl, ":latest") {
			t.Errorf("docker_manifests[%d].name_template = %q, want versioned template without :latest", i, nameTpl)
		}
		imgTpls, ok := m["image_templates"].([]any)
		if !ok || len(imgTpls) != 2 {
			t.Errorf("docker_manifests[%d].image_templates = %#v, want amd64 and arm64 arch images", i, m["image_templates"])
		}
		for _, imgTpl := range imgTpls {
			if s, _ := imgTpl.(string); strings.Contains(s, ":latest") {
				t.Errorf("docker_manifests[%d].image_templates entry %q must not reference :latest", i, s)
			}
		}
	}

	dockerSigns, ok := doc["docker_signs"].([]any)
	if !ok || len(dockerSigns) == 0 {
		t.Fatalf("docker_signs = %#v, want container manifest signing configured", doc["docker_signs"])
	}
	ds0, _ := dockerSigns[0].(map[string]any)
	if ds0["artifacts"] != "manifests" || ds0["cmd"] != "cosign" {
		t.Errorf("docker_signs[0] = %#v, want cosign signing manifests", ds0)
	}

	dockers, ok := doc["dockers"].([]any)
	if !ok || len(dockers) != 2 {
		t.Fatalf("dockers = %#v, want 2 linux arch entries", doc["dockers"])
	}
	for i, item := range dockers {
		d, _ := item.(map[string]any)
		extra, _ := d["extra_files"].([]any)
		if len(extra) == 0 || extra[0] != "example/otel-collector-config.yml" {
			t.Errorf("dockers[%d].extra_files = %#v, want example/otel-collector-config.yml", i, extra)
		}
	}
}

func TestCloudRunServiceAndDockerfilesSatisfyRuntimeContract(t *testing.T) {
	raw := testsupport.ReadRepoText(t, "deploy/cloudrun/service.yaml")
	var svc map[string]any
	if err := yaml.Unmarshal([]byte(raw), &svc); err != nil {
		t.Fatalf("unmarshaling deploy/cloudrun/service.yaml: %v", err)
	}
	if svc["apiVersion"] != "serving.knative.dev/v1" {
		t.Errorf("apiVersion = %v, want serving.knative.dev/v1", svc["apiVersion"])
	}
	spec, _ := svc["spec"].(map[string]any)
	tpl, _ := spec["template"].(map[string]any)
	tplMeta, _ := tpl["metadata"].(map[string]any)
	ann, _ := tplMeta["annotations"].(map[string]any)
	if ann["autoscaling.knative.dev/minScale"] != "1" || ann["autoscaling.knative.dev/maxScale"] != "10" {
		t.Errorf("template annotations = %#v, want Knative minScale/maxScale annotations", ann)
	}
	tplSpec, _ := tpl["spec"].(map[string]any)
	if _, bad := tplSpec["serviceAccount"]; bad {
		t.Error("Knative service spec must use serviceAccountName, not serviceAccount")
	}
	if _, bad := tplSpec["maxScale"]; bad {
		t.Error("Knative service spec must not place maxScale under template.spec")
	}
	if tplSpec["serviceAccountName"] == nil {
		t.Error("Knative service spec missing serviceAccountName")
	}
	containers, _ := tplSpec["containers"].([]any)
	if len(containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(containers))
	}
	c0, _ := containers[0].(map[string]any)
	ports, _ := c0["ports"].([]any)
	if len(ports) != 1 {
		t.Fatalf("Cloud Run container ports = %d, want exactly 1 ingress port", len(ports))
	}
	p0, _ := ports[0].(map[string]any)
	if p0["name"] != "http1" || p0["containerPort"] != 4318 {
		t.Errorf("Cloud Run port[0] = %#v, want http1 on 4318", p0)
	}

	dfText := testsupport.ReadRepoText(t, "Dockerfile.goreleaser")
	if !strings.Contains(dfText, "COPY example/otel-collector-config.yml /etc/otel/config.yml") {
		t.Error("Dockerfile.goreleaser must copy example/otel-collector-config.yml to /etc/otel/config.yml")
	}
	if !strings.Contains(dfText, "COPY healthcheck /healthcheck") {
		t.Error("Dockerfile.goreleaser must copy /healthcheck into the runtime image")
	}
}

func TestHelmDeploymentAndDockerComposeHealthcheck(t *testing.T) {
	helmText := testsupport.ReadRepoText(t, "deploy/helm/bigquery-otel-collector/templates/deployment.yaml")
	if strings.Contains(helmText, "emptyDir") {
		t.Error("Helm deployment.yaml must not back persistentQueue with emptyDir")
	}
	if !strings.Contains(helmText, "kind: StatefulSet") || !strings.Contains(helmText, "volumeClaimTemplates:") {
		t.Error("Helm deployment.yaml must use StatefulSet with volumeClaimTemplates when persistentQueue.enabled is true")
	}

	dcText := testsupport.ReadRepoText(t, "example/docker-compose.yml")
	if strings.Contains(dcText, "CMD-SHELL") {
		t.Error("example/docker-compose.yml must not use CMD-SHELL on a distroless runtime image")
	}
	if !strings.Contains(dcText, `"/healthcheck"`) {
		t.Error("example/docker-compose.yml must invoke /healthcheck via exec-form CMD")
	}

	cmText := testsupport.ReadRepoText(t, "deploy/helm/bigquery-otel-collector/templates/configmap.yaml")
	if strings.Contains(cmText, "compaction/directory") || strings.Contains(cmText, "/compaction") {
		t.Error("Helm configmap.yaml must not specify non-existent /compaction subdirectory")
	}

	tfText := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	if !strings.Contains(tfText, "bigquery.tables.createIndex") {
		t.Error("Terraform main.tf must include bigquery.tables.createIndex for search indexes")
	}
	if !strings.Contains(tfText, "otelCollectorWriter") {
		t.Error("Terraform main.tf must define otelCollectorWriter write-only role")
	}
}

// Release binaries embed the standard library they were built with, so the
// release workflow builds with the same patched Go release example/Dockerfile
// pins, not the older go.mod minimum. GoReleaser's -X flags for main.version
// and friends were no-ops on OCB's generated main.go; the version comes from
// the dist.version the workflow stamps.
func TestReleaseBuildUsesPinnedPatchedGoAndStampedVersion(t *testing.T) {
	wf := testsupport.ReadRepoText(t, ".github/workflows/release.yml")
	df := testsupport.ReadRepoText(t, "example/Dockerfile")
	if strings.Contains(string(wf), "go-version-file") {
		t.Error("release.yml must pin go-version instead of resolving the go.mod minimum")
	}
	got := regexp.MustCompile(`go-version: "?([0-9.]+)"?`).FindStringSubmatch(string(wf))
	want := regexp.MustCompile(`golang:([0-9.]+)-`).FindStringSubmatch(string(df))
	if got == nil || want == nil || got[1] != want[1] {
		t.Errorf("release.yml go-version = %v, example/Dockerfile builder = %v, want the same patched release", got, want)
	}

	// CI tests the toolchain that ships, so every setup-go step in ci.yml, and
	// each of the four jobs that run Go code in particular, pins that release.
	ciGo := workflowSetupGoVersions(t, ".github/workflows/ci.yml")
	for _, job := range []string{"build", "lint", "vulncheck", "release-stamping"} {
		if len(ciGo[job]) == 0 {
			t.Errorf("ci.yml job %q has no actions/setup-go step", job)
		}
	}
	for job, versions := range ciGo {
		for _, version := range versions {
			if want == nil || version != want[1] {
				t.Errorf("ci.yml job %q sets up Go %q, example/Dockerfile builder = %v, want the same patched release", job, version, want)
			}
		}
	}
	// The prepare-release and release workflows also build Go code, so every
	// setup-go step in them must pin the same patched release.
	for _, wfPath := range []string{".github/workflows/prepare-release.yml", ".github/workflows/release.yml"} {
		wfGo := workflowSetupGoVersions(t, wfPath)
		for job, versions := range wfGo {
			for _, version := range versions {
				if want == nil || version != want[1] {
					t.Errorf("%s job %q sets up Go %q, example/Dockerfile builder = %v, want the same patched release", wfPath, job, version, want)
				}
			}
		}
	}

	// The toolchain line in go.mod names that release too, so local builds and
	// the workflows that set up Go from go-version-file: go.mod use it. The go
	// line stays the minimum for modules that require this one, which ignore
	// the toolchain line.
	if toolchain := testsupport.FirstCapture(`(?m)^toolchain go(\S+)$`, testsupport.ReadRepoText(t, "go.mod")); want == nil || toolchain != want[1] {
		t.Errorf("go.mod toolchain = %q, example/Dockerfile builder = %v, want the same patched release", toolchain, want)
	}
	if strings.Contains(string(wf), "/usr/local/bin") {
		t.Error("release.yml must not install tools into the root-owned /usr/local/bin")
	}

	gr := testsupport.ReadRepoText(t, ".goreleaser.yaml")
	if strings.Contains(string(gr), "-X main.") {
		t.Error(".goreleaser.yaml sets -X main.* flags, which OCB's generated main.go ignores")
	}
	if !strings.Contains(string(wf), "s/version: 0.1.0-dev/version: ${VERSION}/g") {
		t.Error("release.yml must stamp the release version into the OCB manifest's dist.version")
	}
}

// Both runtime images ship the static /healthcheck probe, and declare it as an
// exec-form HEALTHCHECK, since distroless has no shell for the shell form.
func TestRuntimeImagesDeclareExecFormHealthcheck(t *testing.T) {
	for _, path := range []string{"Dockerfile.goreleaser", "example/Dockerfile"} {
		text := testsupport.ReadRepoText(t, path)
		if !regexp.MustCompile(`(?m)^HEALTHCHECK .*CMD \["/healthcheck"\]$`).MatchString(text) {
			t.Errorf("%s has no exec-form HEALTHCHECK running /healthcheck", path)
		}
	}
}

// TestCIWorkflowRequiresGawkInDesignatedBuildRun verifies that ci.yml sets
// REPOCHECK_REQUIRE_GAWK=1 on at least one unconditional, default-shell Linux
// build test step executing an unmasked go test over ./... or ./tools/repocheck
// so GNU-only AWK parity cases cannot quietly skip in CI.
func TestCIWorkflowRequiresGawkInDesignatedBuildRun(t *testing.T) {
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	if err := checkCIWorkflowRequiresGawk(ci); err != nil {
		t.Fatal(err)
	}
	withoutEnv := strings.Replace(ci, "          REPOCHECK_REQUIRE_GAWK: '1'\n", "", 1)
	if withoutEnv == ci {
		t.Fatal("test setup error: ci.yml did not contain REPOCHECK_REQUIRE_GAWK: '1'")
	}
	if err := checkCIWorkflowRequiresGawk(withoutEnv); err == nil {
		t.Fatal("checkCIWorkflowRequiresGawk accepted ci.yml without REPOCHECK_REQUIRE_GAWK=1")
	}

	replaceSingleTarget := func(t *testing.T, src, oldStr, newStr string) string {
		t.Helper()
		if !strings.Contains(src, oldStr) {
			t.Fatalf("test setup error: ci.yml missing %q", oldStr)
		}
		return strings.Replace(src, oldStr, newStr, 1)
	}

	baseDoc := parseWorkflowYAMLNode(t, ci)
	testStepPred := func(step *yaml.Node) bool {
		nameNode, ok := yamlMapLookup(step, "name")
		return ok && nameNode.Value == "Test"
	}

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T) string
	}{
		{
			name: "jobs.build.if false",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				yamlSetMapScalar(buildJob, "if", "!!bool", "false")
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "jobs.build.continue-on-error true",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				yamlSetMapScalar(buildJob, "continue-on-error", "!!bool", "true")
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "Test step continue-on-error true",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				_, step, _ := yamlFindStep(t, buildJob, testStepPred)
				yamlSetMapScalar(step, "continue-on-error", "!!bool", "true")
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "Test step shell pwsh",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				_, step, _ := yamlFindStep(t, buildJob, testStepPred)
				yamlSetMapScalar(step, "shell", "!!str", "pwsh")
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "Test step working-directory internal",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				_, step, _ := yamlFindStep(t, buildJob, testStepPred)
				yamlSetMapScalar(step, "working-directory", "!!str", "internal")
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "jobs.build.defaults shell pwsh",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				runDef := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(runDef, "shell", "!!str", "pwsh")
				defaults := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapValue(defaults, "run", runDef)
				yamlSetMapValue(buildJob, "defaults", defaults)
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "step run overrides REPOCHECK_REQUIRE_GAWK=0",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: REPOCHECK_REQUIRE_GAWK=0 go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run unsets REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: unset REPOCHECK_REQUIRE_GAWK && go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run comments out go test",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: \"# go test -race -cover -count=1 ./...\"")
			},
		},
		{
			name: "step run only echoes go test",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: echo 'go test ./tools/repocheck'")
			},
		},
		{
			name: "step run masks go test with || true",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -race -cover -count=1 ./... || true")
			},
		},
		{
			name: "step run hides go test inside heredoc decoy",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          cat <<EOF >/dev/null\n          go test -race -cover -count=1 ./...\n          EOF")
			},
		},
		{
			name: "step run exits before go test",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          exit 0\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run puts go test in dead if false branch",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          if false; then\n          go test -race -cover -count=1 ./...\n          fi")
			},
		},
		{
			name: "step run puts go test in dead while false loop",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          while false; do\n          go test -race -cover -count=1 ./...\n          done")
			},
		},
		{
			name: "step run chains false || across newline to go test",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          false ||\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses declare +x REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          declare +x REPOCHECK_REQUIRE_GAWK\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses typeset +x REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          typeset +x REPOCHECK_REQUIRE_GAWK\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses builtin unset REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          builtin unset REPOCHECK_REQUIRE_GAWK\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run prefixes assignment before unset REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          FOO=1 unset REPOCHECK_REQUIRE_GAWK\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses command unset REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          command unset REPOCHECK_REQUIRE_GAWK\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses env -uREPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: env -uREPOCHECK_REQUIRE_GAWK go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run uses eval unset REPOCHECK_REQUIRE_GAWK",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          eval \"unset REPOCHECK_REQUIRE_GAWK\"\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run changes working directory with cd",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: |\n          cd internal\n          go test -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run filters tests with -run=^$",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -run=^$ -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run filters tests with -skip=.",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -skip=. -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run filters AWK test with -skip=TestWalkAwk",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -skip=TestWalkAwk -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run only lists tests with -list=.",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -list=. ./...")
			},
		},
		{
			name: "step run skips long tests with -short",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -short -race -cover -count=1 ./...")
			},
		},
		{
			name: "step run only compiles tests with -c",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        run: go test -race -cover -count=1 ./...",
					"        run: go test -c ./...")
			},
		},
		{
			name: "step env sets GOFLAGS=-run=^$",
			mutate: func(t *testing.T) string {
				return replaceSingleTarget(t, ci,
					"        env:\n          REPOCHECK_REQUIRE_GAWK: '1'",
					"        env:\n          REPOCHECK_REQUIRE_GAWK: '1'\n          GOFLAGS: '-run=^$'")
			},
		},
		{
			name: "jobs.build.env sets GOFLAGS=-skip=.",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				jobs := yamlMustMapValue(t, doc.Content[0], "jobs")
				buildJob := yamlMustMapValue(t, jobs, "build")
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "GOFLAGS", "!!str", "-skip=.")
				yamlSetMapValue(buildJob, "env", envNode)
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
		{
			name: "workflow env sets GOFLAGS=-short",
			mutate: func(t *testing.T) string {
				doc := cloneYAMLNode(baseDoc)
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "GOFLAGS", "!!str", "-short")
				yamlSetMapValue(doc.Content[0], "env", envNode)
				out, err := yaml.Marshal(doc)
				if err != nil {
					t.Fatal(err)
				}
				return string(out)
			},
		},
	} {
		t.Run("rejects_"+tc.name, func(t *testing.T) {
			if err := checkCIWorkflowRequiresGawk(tc.mutate(t)); err == nil {
				t.Fatalf("checkCIWorkflowRequiresGawk accepted bypass %q", tc.name)
			}
		})
	}
}

func isBlockedGoTestFlag(raw string) bool {
	flag := raw
	if strings.HasPrefix(flag, "--") && flag != "--" {
		flag = flag[1:]
	}
	if strings.HasPrefix(flag, "-test.") {
		flag = "-" + strings.TrimPrefix(flag, "-test.")
	}
	for _, blocked := range []string{"-run", "-skip", "-list", "-short", "-c", "-n"} {
		if flag == blocked || strings.HasPrefix(flag, blocked+"=") {
			return true
		}
	}
	return false
}

func isDeniedCIStepEnvAssignment(word string) bool {
	if (strings.HasPrefix(word, requireGawkEnv+"=") || strings.HasPrefix(word, requireGawkEnv+"+=")) &&
		word != requireGawkEnv+"=1" {
		return true
	}
	return strings.HasPrefix(word, "GOFLAGS=") || strings.HasPrefix(word, "GOFLAGS+=")
}

func checkCIBuildStepRunsGawkTests(rawRun string) error {
	normalized := strings.ReplaceAll(rawRun, "\r\n", "\n")
	if strings.ContainsRune(normalized, '\r') {
		return errors.New("build test step contains bare carriage return")
	}
	if stepDisablesErrexit(normalized) {
		return errors.New("build test step may disable errexit")
	}
	lines, err := activeBashCodeLinesChecked(normalized)
	if err != nil {
		return err
	}
	blockedCmds := map[string]bool{
		"exit": true, "return": true,
		"if": true, "elif": true, "else": true, "then": true, "fi": true,
		"while": true, "until": true, "for": true, "select": true, "do": true, "done": true,
		"case": true, "esac": true,
		"declare": true, "typeset": true, "unset": true,
		"builtin": true, "command": true, "eval": true, "exec": true,
		"cd": true, "pushd": true, "popd": true,
		".": true, "source": true, "true": true, "false": true, ":": true,
		"[": true, "[[": true, "test": true, "alias": true, "enable": true, "function": true,
	}
	hasValidGoTest := false
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		for _, op := range []string{"||", "&&", "|", "&", "(", "{"} {
			if strings.HasSuffix(trimmedLine, op) {
				return fmt.Errorf("build test step ends line with operator %q", op)
			}
		}
		stmts, bts := splitBashStatementsForErrexitDepth(line, 0, bashParamScanOpts{allowSingleInDouble: true})
		if len(bts) > 0 && (strings.Contains(line, requireGawkEnv) || strings.Contains(line, "GOFLAGS")) {
			return fmt.Errorf("build test step contains env reference in backtick subshell")
		}
		for _, stmt := range stmts {
			rawWords := splitBashWordsForErrexit(stmt)
			for _, w := range rawWords {
				if w.truncated {
					return errors.New("build test step command expansion could not be analyzed")
				}
				if isDeniedCIStepEnvAssignment(w.text) {
					return fmt.Errorf("build test step alters guarded env in %q", w.text)
				}
			}
			fields := stripBashRedirArgs(rawWords, false)
			cmdIdx := 0
			for cmdIdx < len(fields) && isBashEnvAssignmentWord(fields[cmdIdx].text) && !fields[cmdIdx].truncated {
				cmdIdx++
			}
			if cmdIdx >= len(fields) {
				continue
			}
			cmd := fields[cmdIdx].text
			if blockedCmds[cmd] {
				return fmt.Errorf("build test step uses disallowed command or control-flow keyword %q", cmd)
			}
			switch cmd {
			case "export":
				for _, arg := range fields[cmdIdx+1:] {
					if arg.text == "-n" || arg.text == "-f" || arg.text == requireGawkEnv ||
						arg.text == "GOFLAGS" || isDeniedCIStepEnvAssignment(arg.text) {
						return fmt.Errorf("build test step alters guarded env via export %q", arg.text)
					}
				}
			case "env":
				subCmdIdx := -1
				for j := cmdIdx + 1; j < len(fields); j++ {
					arg := fields[j]
					if arg.text == "-i" || arg.text == "--ignore-environment" ||
						strings.HasPrefix(arg.text, "-u") || arg.text == "--unset" || strings.HasPrefix(arg.text, "--unset=") ||
						strings.HasPrefix(arg.text, "-S") || arg.text == "--split-string" || strings.HasPrefix(arg.text, "--split-string=") ||
						arg.text == requireGawkEnv || arg.text == "GOFLAGS" || isDeniedCIStepEnvAssignment(arg.text) {
						return fmt.Errorf("build test step modifies env (%q)", arg.text)
					}
					if !strings.HasPrefix(arg.text, "-") && !isBashEnvAssignmentWord(arg.text) {
						subCmdIdx = j
						break
					}
				}
				if subCmdIdx >= 0 {
					subCmd := fields[subCmdIdx].text
					if blockedCmds[subCmd] {
						return fmt.Errorf("build test step uses disallowed command %q via env", subCmd)
					}
					if subCmd == "go" && subCmdIdx+1 < len(fields) && fields[subCmdIdx+1].text == "test" {
						for _, arg := range fields[subCmdIdx+2:] {
							if isBlockedGoTestFlag(arg.text) {
								return fmt.Errorf("build test step uses blocked go test flag %q", arg.text)
							}
						}
					}
				}
			case "go":
				if cmdIdx+1 < len(fields) && fields[cmdIdx+1].text == "test" {
					for _, arg := range fields[cmdIdx+2:] {
						if isBlockedGoTestFlag(arg.text) {
							return fmt.Errorf("build test step uses blocked go test flag %q", arg.text)
						}
					}
				}
			}
		}

		if len(stmts) != 1 || len(bts) != 0 || strings.TrimSpace(stmts[0]) != trimmedLine {
			continue
		}
		fields := stripBashRedirArgs(splitBashWordsForErrexit(stmts[0]), false)
		idx := 0
		for idx < len(fields) && isBashEnvAssignmentWord(fields[idx].text) && !fields[idx].truncated {
			idx++
		}
		if idx+2 >= len(fields) || fields[idx].quoted || fields[idx+1].quoted ||
			fields[idx].text != "go" || fields[idx+1].text != "test" {
			continue
		}
		for _, arg := range fields[idx+2:] {
			if !arg.quoted && (arg.text == "./..." || arg.text == "./tools/repocheck" || arg.text == "./tools/repocheck/...") {
				hasValidGoTest = true
				break
			}
		}
	}
	if !hasValidGoTest {
		return fmt.Errorf("build test step has no unmasked go test invocation covering ./... or ./tools/repocheck")
	}
	return nil
}

func checkCIWorkflowRequiresGawk(ciYAML string) error {
	var workflow struct {
		Env      map[string]string        `yaml:"env"`
		Defaults crossOSMatrixRunDefaults `yaml:"defaults"`
		Jobs     map[string]struct {
			If              any                      `yaml:"if"`
			RunsOn          string                   `yaml:"runs-on"`
			ContinueOnError any                      `yaml:"continue-on-error"`
			Env             map[string]string        `yaml:"env"`
			Defaults        crossOSMatrixRunDefaults `yaml:"defaults"`
			Steps           []crossOSMatrixStep      `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &workflow); err != nil {
		return fmt.Errorf("unmarshaling ci.yml: %w", err)
	}
	if _, ok := workflow.Env["GOFLAGS"]; ok {
		return errors.New("ci.yml workflow env cannot set GOFLAGS")
	}
	if !prepareReleaseGateShellAllowed(workflow.Defaults.Run.Shell) || workflow.Defaults.Run.WorkingDirectory != "" {
		return errors.New("workflow-level defaults cannot override build execution shell or working-directory")
	}
	buildJob, ok := workflow.Jobs["build"]
	if !ok {
		return errors.New("ci.yml does not define a build job")
	}
	if strings.TrimSpace(buildJob.RunsOn) != "ubuntu-latest" {
		return fmt.Errorf("ci.yml build job runs-on = %q, want ubuntu-latest", buildJob.RunsOn)
	}
	if !unconditionalReleaseStep(buildJob.If) {
		return fmt.Errorf("ci.yml build job has conditional gate: %v", buildJob.If)
	}
	if continueOnErrorSet(buildJob.ContinueOnError) {
		return fmt.Errorf("ci.yml build job sets continue-on-error: %v", buildJob.ContinueOnError)
	}
	if _, ok := buildJob.Env["GOFLAGS"]; ok {
		return errors.New("ci.yml build job env cannot set GOFLAGS")
	}
	if !prepareReleaseGateShellAllowed(buildJob.Defaults.Run.Shell) || buildJob.Defaults.Run.WorkingDirectory != "" {
		return errors.New("ci.yml build job defaults cannot override step shell or working-directory")
	}
	for _, step := range buildJob.Steps {
		if step.Env[requireGawkEnv] != "1" || step.Uses != "" {
			continue
		}
		if _, ok := step.Env["GOFLAGS"]; ok {
			continue
		}
		if !unconditionalReleaseStep(step.If) || continueOnErrorSet(step.ContinueOnError) {
			continue
		}
		if !prepareReleaseGateShellAllowed(step.Shell) || step.WorkingDirectory != "" {
			continue
		}
		if err := checkCIBuildStepRunsGawkTests(step.Run); err == nil {
			return nil
		}
	}
	return fmt.Errorf("ci.yml build job has no valid unconditional default-shell go test step setting %s=1", requireGawkEnv)
}

// TestCrossOSMatrixInCIWorkflow verifies that ci.yml defines a cross-os job
// that builds, vets, and tests the library and operator CLIs on macOS and
// Windows using the same pinned Go version as the ubuntu-latest build job,
// and runs TestReleaseScriptsBaseline on macOS with explicit awk/bash/PATH
// isolation and go test -json pass verification.
func TestCrossOSMatrixInCIWorkflow(t *testing.T) {
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	df := testsupport.ReadRepoText(t, "example/Dockerfile")
	if err := checkCrossOSMatrixCIWorkflow(ci, df); err != nil {
		t.Fatal(err)
	}
}

func resolveYAMLAliasReadOnly(m *yaml.Node) *yaml.Node {
	var seen map[*yaml.Node]struct{}
	for m != nil && m.Kind == yaml.AliasNode && m.Alias != nil {
		if seen == nil {
			seen = make(map[*yaml.Node]struct{}, 4)
		}
		if _, dup := seen[m]; dup {
			return nil
		}
		seen[m] = struct{}{}
		m = m.Alias
	}
	return m
}

func isYAMLMergeKey(k *yaml.Node) bool {
	return k != nil && (k.Tag == "!!merge" || (k.Value == "<<" && k.Style == 0))
}

// cloneDetachedYAMLNode recursively deep-clones n, detaching all nested
// AliasNodes and clearing anchors so mutations never leak externally or re-bind
// via marshaled alias names.
func cloneDetachedYAMLNode(n *yaml.Node, visiting map[*yaml.Node]bool) *yaml.Node {
	if n == nil {
		return nil
	}
	if visiting == nil {
		visiting = make(map[*yaml.Node]bool, 8)
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		target := resolveYAMLAliasReadOnly(n)
		if target == nil || visiting[target] {
			cp := *n
			cp.Anchor = ""
			return &cp
		}
		return cloneDetachedYAMLNode(target, visiting)
	}
	if visiting[n] {
		cp := *n
		cp.Anchor = ""
		cp.Content = nil
		return &cp
	}
	visiting[n] = true
	defer delete(visiting, n)
	cp := *n
	cp.Anchor = ""
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			cp.Content[i] = cloneDetachedYAMLNode(child, visiting)
		}
	}
	return &cp
}

func yamlDereferenceAlias(m *yaml.Node) {
	if m == nil || m.Kind != yaml.AliasNode || m.Alias == nil {
		return
	}
	target := resolveYAMLAliasReadOnly(m)
	if target == nil {
		return
	}
	*m = *cloneDetachedYAMLNode(target, nil)
}

func yamlExpandMergeKeys(m *yaml.Node) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	hasMerge := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		if isYAMLMergeKey(m.Content[i]) {
			hasMerge = true
			break
		}
	}
	if !hasMerge {
		return
	}
	present := make(map[string]bool, len(m.Content)/2)
	newContent := make([]*yaml.Node, 0, len(m.Content))
	var mergeSources []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if isYAMLMergeKey(k) {
			mergeSources = append(mergeSources, v)
			continue
		}
		present[k.Value] = true
		newContent = append(newContent, k, v)
	}
	seen := make(map[*yaml.Node]bool, 4)
	var mergeFrom func(src *yaml.Node)
	mergeFrom = func(src *yaml.Node) {
		src = resolveYAMLAliasReadOnly(src)
		if src == nil || seen[src] {
			return
		}
		seen[src] = true
		defer delete(seen, src)
		if src.Kind == yaml.SequenceNode {
			for _, elem := range src.Content {
				mergeFrom(elem)
			}
			return
		}
		if src.Kind != yaml.MappingNode {
			return
		}
		var subMerges []*yaml.Node
		for i := 0; i+1 < len(src.Content); i += 2 {
			k, v := src.Content[i], src.Content[i+1]
			if isYAMLMergeKey(k) {
				subMerges = append(subMerges, v)
				continue
			}
			if !present[k.Value] {
				present[k.Value] = true
				newContent = append(newContent, cloneDetachedYAMLNode(k, nil), cloneDetachedYAMLNode(v, nil))
			}
		}
		for _, sub := range subMerges {
			mergeFrom(sub)
		}
	}
	for _, src := range mergeSources {
		mergeFrom(src)
	}
	m.Content = newContent
}

func yamlMapLookupVisited(m *yaml.Node, key string, visited map[*yaml.Node]struct{}) (*yaml.Node, bool) {
	m = resolveYAMLAliasReadOnly(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return nil, false
	}
	if _, dup := visited[m]; dup {
		return nil, false
	}
	visited[m] = struct{}{}
	defer delete(visited, m)
	var merges []*yaml.Node
	for i := 0; i+1 < len(m.Content); i += 2 {
		k, v := m.Content[i], m.Content[i+1]
		if isYAMLMergeKey(k) {
			merges = append(merges, v)
			continue
		}
		if k.Value == key {
			return resolveYAMLAliasReadOnly(v), true
		}
	}
	for _, mv := range merges {
		mv = resolveYAMLAliasReadOnly(mv)
		if mv == nil {
			continue
		}
		switch mv.Kind {
		case yaml.MappingNode:
			if val, ok := yamlMapLookupVisited(mv, key, visited); ok {
				return val, true
			}
		case yaml.SequenceNode:
			for _, elem := range mv.Content {
				if val, ok := yamlMapLookupVisited(elem, key, visited); ok {
					return val, true
				}
			}
		}
	}
	return nil, false
}

func yamlMapLookup(m *yaml.Node, key string) (*yaml.Node, bool) {
	return yamlMapLookupVisited(m, key, make(map[*yaml.Node]struct{}, 4))
}

func yamlMustMapValue(t *testing.T, m *yaml.Node, key string) *yaml.Node {
	t.Helper()
	yamlDereferenceAlias(m)
	yamlExpandMergeKeys(m)
	if m == nil || m.Kind != yaml.MappingNode {
		t.Fatalf("yaml node is not a mapping while looking up %q", key)
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			yamlDereferenceAlias(m.Content[i+1])
			return m.Content[i+1]
		}
	}
	t.Fatalf("yaml mapping missing required key %q", key)
	return nil
}

func yamlSetMapValue(m *yaml.Node, key string, val *yaml.Node) {
	yamlDereferenceAlias(m)
	yamlExpandMergeKeys(m)
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
}

func yamlSetMapScalar(m *yaml.Node, key, tag, val string) {
	yamlSetMapValue(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val})
}

func yamlFindStep(t *testing.T, crossOS *yaml.Node, pred func(step *yaml.Node) bool) (*yaml.Node, *yaml.Node, int) {
	t.Helper()
	steps := yamlMustMapValue(t, crossOS, "steps")
	if steps.Kind != yaml.SequenceNode {
		t.Fatalf("cross-os steps kind = %v, want sequence", steps.Kind)
	}
	for i, step := range steps.Content {
		if pred(step) {
			return steps, step, i
		}
	}
	t.Fatal("cross-os steps missing matching step")
	return nil, nil, -1
}

func yamlStepHasNormalizedRunSubstr(step *yaml.Node, substr string) bool {
	runNode, ok := yamlMapLookup(step, "run")
	if !ok {
		return false
	}
	lines, err := extractCrossOSScriptLines(runNode.Value, true)
	if err != nil {
		return false
	}
	for _, line := range lines {
		if strings.Contains(line, substr) {
			return true
		}
	}
	return false
}

func yamlMutateStepRun(t *testing.T, step *yaml.Node, oldStr, newStr string) {
	t.Helper()
	runNode := yamlMustMapValue(t, step, "run")
	if !strings.Contains(runNode.Value, oldStr) {
		t.Fatalf("step run missing target %q", oldStr)
	}
	runNode.Value = strings.Replace(runNode.Value, oldStr, newStr, 1)
}

func cloneYAMLNodeWithMap(n *yaml.Node, clones map[*yaml.Node]*yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if existing, ok := clones[n]; ok {
		return existing
	}
	cp := *n
	clones[n] = &cp
	if n.Alias != nil {
		cp.Alias = cloneYAMLNodeWithMap(n.Alias, clones)
	}
	if len(n.Content) > 0 {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			cp.Content[i] = cloneYAMLNodeWithMap(child, clones)
		}
	}
	return &cp
}

func cloneYAMLNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	return cloneYAMLNodeWithMap(n, make(map[*yaml.Node]*yaml.Node))
}

func parseWorkflowYAMLNode(t *testing.T, rawYAML string) *yaml.Node {
	t.Helper()
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(rawYAML), &doc); err != nil {
		t.Fatalf("unmarshaling base workflow: %v", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 {
		t.Fatalf("unexpected yaml document structure")
	}
	return &doc
}

func mutateCrossOSDoc(t *testing.T, baseDoc *yaml.Node, fn func(t *testing.T, root, crossOS *yaml.Node)) string {
	t.Helper()
	doc := cloneYAMLNode(baseDoc)
	root := doc.Content[0]
	jobs := yamlMustMapValue(t, root, "jobs")
	crossOS := yamlMustMapValue(t, jobs, "cross-os")
	fn(t, root, crossOS)
	out, err := yaml.Marshal(doc)
	if err != nil {
		t.Fatalf("marshaling mutated workflow: %v", err)
	}
	return string(out)
}

func mutateCrossOSWorkflowYAML(t *testing.T, baseYAML string, fn func(t *testing.T, root, crossOS *yaml.Node)) string {
	t.Helper()
	return mutateCrossOSDoc(t, parseWorkflowYAMLNode(t, baseYAML), fn)
}

func addEarlierUnrelatedMatrixJobYAML(t *testing.T, root *yaml.Node) {
	t.Helper()
	jobs := yamlMustMapValue(t, root, "jobs")
	var extraDoc yaml.Node
	const snippet = `
name: unrelated (${{ matrix.os }})
runs-on: ${{ matrix.os }}
continue-on-error: true
strategy:
  matrix:
    os: [ubuntu-latest, ubuntu-24.04]
env:
  PATH: /tmp/unrelated:/usr/bin
steps:
  - run: echo unrelated
`
	if err := yaml.Unmarshal([]byte(snippet), &extraDoc); err != nil {
		t.Fatalf("unmarshaling extra matrix job snippet: %v", err)
	}
	extraKey := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "unrelated-matrix"}
	extraVal := extraDoc.Content[0]
	jobs.Content = append([]*yaml.Node{extraKey, extraVal}, jobs.Content...)
}

func TestCrossOSMatrixInCIWorkflowAcceptsValidVariants(t *testing.T) {
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	df := testsupport.ReadRepoText(t, "example/Dockerfile")

	t.Run("earlier unrelated matrix job", func(t *testing.T) {
		variant := mutateCrossOSWorkflowYAML(t, ci, func(t *testing.T, root, _ *yaml.Node) {
			addEarlierUnrelatedMatrixJobYAML(t, root)
		})
		if err := checkCrossOSMatrixCIWorkflow(variant, df); err != nil {
			t.Fatalf("rejected workflow with earlier unrelated matrix job: %v", err)
		}
	})

	t.Run("expression-wrapped macos matrix condition", func(t *testing.T) {
		variant := mutateCrossOSWorkflowYAML(t, ci, func(t *testing.T, _, crossOS *yaml.Node) {
			_, step, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
				return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
			})
			yamlSetMapScalar(step, "if", "!!str", "${{ matrix.os == 'macos-latest' }}")
		})
		if err := checkCrossOSMatrixCIWorkflow(variant, df); err != nil {
			t.Fatalf("rejected expression-wrapped macOS condition: %v", err)
		}
	})

	t.Run("earlier step comment and apostrophe comments do not affect baseline", func(t *testing.T) {
		variant := mutateCrossOSWorkflowYAML(t, ci, func(t *testing.T, _, crossOS *yaml.Node) {
			_, buildStep, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
				return yamlStepHasNormalizedRunSubstr(s, "go build ./...")
			})
			yamlMutateStepRun(t, buildStep, "go build ./...", "# TestReleaseScriptsBaseline\ngo build ./...")

			_, macStep, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
				return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
			})
			yamlMutateStepRun(t, macStep, "set -euo pipefail", "# don't skip macOS baseline check\nset -euo pipefail")
		})
		if err := checkCrossOSMatrixCIWorkflow(variant, df); err != nil {
			t.Fatalf("rejected workflow with earlier step comment and apostrophe comment: %v", err)
		}
	})

	t.Run("benign workflow-level and cross-os env keys", func(t *testing.T) {
		variant := mutateCrossOSWorkflowYAML(t, ci, func(_ *testing.T, root, crossOS *yaml.Node) {
			wfEnv := &yaml.Node{Kind: yaml.MappingNode}
			yamlSetMapScalar(wfEnv, "RELEASE_NOTE_STYLE", "!!str", "brief")
			yamlSetMapValue(root, "env", wfEnv)

			jobEnv := &yaml.Node{Kind: yaml.MappingNode}
			yamlSetMapScalar(jobEnv, "CI_DISPLAY_LABEL", "!!str", "cross-os")
			yamlSetMapValue(crossOS, "env", jobEnv)
		})
		if err := checkCrossOSMatrixCIWorkflow(variant, df); err != nil {
			t.Fatalf("rejected benign workflow/job env metadata: %v", err)
		}
	})

	t.Run("combined valid variants still catch cross-os mutants", func(t *testing.T) {
		baseVariant := mutateCrossOSWorkflowYAML(t, ci, func(t *testing.T, root, crossOS *yaml.Node) {
			addEarlierUnrelatedMatrixJobYAML(t, root)
			wfEnv := &yaml.Node{Kind: yaml.MappingNode}
			yamlSetMapScalar(wfEnv, "RELEASE_NOTE_STYLE", "!!str", "brief")
			yamlSetMapValue(root, "env", wfEnv)
			_, step, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
				return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
			})
			yamlSetMapScalar(step, "if", "!!str", "${{ matrix.os == 'macos-latest' }}")
		})
		if err := checkCrossOSMatrixCIWorkflow(baseVariant, df); err != nil {
			t.Fatalf("combined valid variant unexpectedly failed: %v", err)
		}
		brokenRunsOn := mutateCrossOSWorkflowYAML(t, baseVariant, func(_ *testing.T, _, crossOS *yaml.Node) {
			yamlSetMapScalar(crossOS, "runs-on", "!!str", "ubuntu-latest")
		})
		if err := checkCrossOSMatrixCIWorkflow(brokenRunsOn, df); err == nil || !strings.Contains(err.Error(), `cross-os job runs-on = "ubuntu-latest"`) {
			t.Fatalf("runs-on mutant on combined variant got err=%v, want cross-os job runs-on mismatch", err)
		}
		brokenCond := mutateCrossOSWorkflowYAML(t, baseVariant, func(t *testing.T, _, crossOS *yaml.Node) {
			_, step, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
				return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
			})
			yamlSetMapScalar(step, "if", "!!str", "matrix.os != 'macos-latest'")
		})
		if err := checkCrossOSMatrixCIWorkflow(brokenCond, df); err == nil || !strings.Contains(err.Error(), "condition =") {
			t.Fatalf("inverted condition mutant on combined variant got err=%v, want condition error", err)
		}
	})
}

func TestCrossOSMatrixInCIWorkflowRejectsBrokenConfigs(t *testing.T) {
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	df := testsupport.ReadRepoText(t, "example/Dockerfile")
	baseDoc := parseWorkflowYAMLNode(t, ci)
	baseMarshaledBytes, err := yaml.Marshal(baseDoc)
	if err != nil {
		t.Fatalf("marshaling baseline doc: %v", err)
	}
	baseMarshaled := string(baseMarshaledBytes)
	const baselineTestCmd = "go test -count=1 -json -run '^TestReleaseScriptsBaseline$' ./tools/repocheck | /usr/bin/awk '"
	macBaselinePred := func(s *yaml.Node) bool {
		return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
	}
	operatorTestPred := func(s *yaml.Node) bool {
		return yamlStepHasNormalizedRunSubstr(s, "go test -count=1 ./cmd/... ./internal/... ./tools/internal/...")
	}

	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, root, crossOS *yaml.Node)
		wantErr string
	}{
		{
			name: "runs-on changed to ubuntu-latest",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				yamlSetMapScalar(crossOS, "runs-on", "!!str", "ubuntu-latest")
			},
			wantErr: `cross-os job runs-on = "ubuntu-latest", want ${{ matrix.os }}`,
		},
		{
			name: "cross-os job sets continue-on-error true",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				yamlSetMapScalar(crossOS, "continue-on-error", "!!bool", "true")
			},
			wantErr: "cross-os job sets continue-on-error: true",
		},
		{
			name: "cross-os job sets continue-on-error expression",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				yamlSetMapScalar(crossOS, "continue-on-error", "!!str", "${{ true }}")
			},
			wantErr: "cross-os job sets continue-on-error: ${{ true }}",
		},
		{
			name: "cross-os job declares needs scalar",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				yamlSetMapScalar(crossOS, "needs", "!!str", "build")
			},
			wantErr: "cross-os job must not declare needs",
		},
		{
			name: "cross-os job declares needs sequence",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				yamlSetMapValue(crossOS, "needs", &yaml.Node{
					Kind: yaml.SequenceNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "build"},
					},
				})
			},
			wantErr: "cross-os job must not declare needs",
		},
		{
			name: "cross-os matrix defines exclude",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				strategy := yamlMustMapValue(t, crossOS, "strategy")
				matrix := yamlMustMapValue(t, strategy, "matrix")
				yamlSetMapValue(matrix, "exclude", &yaml.Node{
					Kind: yaml.SequenceNode,
					Content: []*yaml.Node{
						{Kind: yaml.MappingNode, Content: []*yaml.Node{
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "os"},
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "macos-latest"},
						}},
					},
				})
			},
			wantErr: "cross-os matrix must not exclude any OS",
		},
		{
			name: "cross-os matrix defines include",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				strategy := yamlMustMapValue(t, crossOS, "strategy")
				matrix := yamlMustMapValue(t, strategy, "matrix")
				yamlSetMapValue(matrix, "include", &yaml.Node{
					Kind: yaml.SequenceNode,
					Content: []*yaml.Node{
						{Kind: yaml.MappingNode, Content: []*yaml.Node{
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "os"},
							{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ubuntu-latest"},
						}},
					},
				})
			},
			wantErr: "cross-os matrix must not define include entries",
		},
		{
			name: "cross-os matrix drops macos-latest",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				strategy := yamlMustMapValue(t, crossOS, "strategy")
				matrix := yamlMustMapValue(t, strategy, "matrix")
				yamlSetMapValue(matrix, "os", &yaml.Node{
					Kind: yaml.SequenceNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "windows-latest"},
					},
				})
			},
			wantErr: "cross-os matrix is missing macos-latest",
		},
		{
			name: "cross-os matrix drops windows-latest",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				strategy := yamlMustMapValue(t, crossOS, "strategy")
				matrix := yamlMustMapValue(t, strategy, "matrix")
				yamlSetMapValue(matrix, "os", &yaml.Node{
					Kind: yaml.SequenceNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "macos-latest"},
					},
				})
			},
			wantErr: "cross-os matrix is missing windows-latest",
		},
		{
			name: "macos baseline step sets continue-on-error true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlSetMapScalar(step, "continue-on-error", "!!bool", "true")
			},
			wantErr: "sets continue-on-error: true",
		},
		{
			name: "operator package test step sets continue-on-error true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, operatorTestPred)
				yamlSetMapScalar(step, "continue-on-error", "!!bool", "true")
			},
			wantErr: "sets continue-on-error: true",
		},
		{
			name: "checkout step sets continue-on-error true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[0], "continue-on-error", "!!bool", "true")
			},
			wantErr: "cross-os actions/checkout step sets continue-on-error: true",
		},
		{
			name: "setup-go step sets continue-on-error true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[1], "continue-on-error", "!!bool", "true")
			},
			wantErr: "cross-os actions/setup-go step sets continue-on-error: true",
		},
		{
			name: "checkout step sets conditional gate",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[0], "if", "!!bool", "false")
			},
			wantErr: "cross-os actions/checkout step has conditional gate",
		},
		{
			name: "setup-go step sets conditional gate",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[1], "if", "!!bool", "false")
			},
			wantErr: "cross-os actions/setup-go step has conditional gate",
		},
		{
			name: "checkout step sets custom repository",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(withNode, "repository", "!!str", "someone/fork")
				yamlSetMapValue(steps.Content[0], "with", withNode)
			},
			wantErr: "cross-os checkout step sets custom with",
		},
		{
			name: "unpinned checkout action tag",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[0], "uses", "!!str", "actions/checkout@v7")
			},
			wantErr: "must use a SHA-pinned actions/checkout action",
		},
		{
			name: "unpinned setup-go action tag",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[1], "uses", "!!str", "actions/setup-go@v7")
			},
			wantErr: "must use a SHA-pinned actions/setup-go action",
		},
		{
			name: "setup-go wrong go-version",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := yamlMustMapValue(t, steps.Content[1], "with")
				yamlSetMapScalar(withNode, "go-version", "!!str", "1.26.0")
			},
			wantErr: `cross-os job setup-go version = "1.26.0"`,
		},
		{
			name: "setup-go uses unexpected go-version-file",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := yamlMustMapValue(t, steps.Content[1], "with")
				yamlSetMapScalar(withNode, "go-version-file", "!!str", "go.mod")
			},
			wantErr: `cross-os setup-go step sets unexpected with key "go-version-file"`,
		},
		{
			name: "extra step poisons GITHUB_PATH before baseline",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				poisonStep := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(poisonStep, "name", "!!str", "Inject shim")
				yamlSetMapScalar(poisonStep, "run", "!!str", `echo "/tmp/fakebin" >> "${GITHUB_PATH}"`)
				idx := len(steps.Content) - 1
				updated := append([]*yaml.Node{}, steps.Content[:idx]...)
				updated = append(updated, poisonStep)
				updated = append(updated, steps.Content[idx:]...)
				steps.Content = updated
			},
			wantErr: "cross-os job has 7 steps, want exact 6-step sequence",
		},
		{
			name: "swapped build and vet step order",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				steps.Content[2], steps.Content[3] = steps.Content[3], steps.Content[2]
			},
			wantErr: "must run exact 'go build ./...' unconditionally",
		},
		{
			name: "workflow env GOFLAGS override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "GOFLAGS", "!!str", "-tags=nope")
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "GOFLAGS" cannot override`,
		},
		{
			name: "workflow env PATH override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "PATH", "!!str", "/tmp/fake:/usr/bin")
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "PATH" cannot override`,
		},
		{
			name: "workflow env BASH_ENV override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "BASH_ENV", "!!str", "./scripts/noop.sh")
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "BASH_ENV" cannot override`,
		},
		{
			name: "workflow env HOME override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "HOME", "!!str", "/tmp/fakehome")
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "HOME" cannot override`,
		},
		{
			name: "workflow env XDG_CONFIG_HOME override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "XDG_CONFIG_HOME", "!!str", "/tmp/fakexdg")
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "XDG_CONFIG_HOME" cannot override`,
		},
		{
			name: "workflow env USERPROFILE override",
			mutate: func(_ *testing.T, root, _ *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "USERPROFILE", "!!str", `C:\fakeprofile`)
				yamlSetMapValue(root, "env", envNode)
			},
			wantErr: `workflow env "USERPROFILE" cannot override`,
		},
		{
			name: "cross-os job env GOFLAGS override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "GOFLAGS", "!!str", "-tags=nope")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "GOFLAGS" cannot override`,
		},
		{
			name: "cross-os job env PATH override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "PATH", "!!str", "/tmp/fake:/usr/bin")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "PATH" cannot override`,
		},
		{
			name: "cross-os job env BASH_ENV override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "BASH_ENV", "!!str", "./scripts/noop.sh")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "BASH_ENV" cannot override`,
		},
		{
			name: "cross-os job env HOME override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "HOME", "!!str", "/tmp/fakehome")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "HOME" cannot override`,
		},
		{
			name: "cross-os job env XDG_CACHE_HOME override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "XDG_CACHE_HOME", "!!str", "/tmp/fakecache")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "XDG_CACHE_HOME" cannot override`,
		},
		{
			name: "cross-os job env APPDATA override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "APPDATA", "!!str", `C:\fakeappdata`)
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "APPDATA" cannot override`,
		},
		{
			name: "cross-os job env LOCALAPPDATA override",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "LOCALAPPDATA", "!!str", `C:\fakelocalappdata`)
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "LOCALAPPDATA" cannot override`,
		},
		{
			name: "cross-os job env arbitrary unallowlisted key",
			mutate: func(_ *testing.T, _, crossOS *yaml.Node) {
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "CUSTOM_RUNNER_HOOK", "!!str", "1")
				yamlSetMapValue(crossOS, "env", envNode)
			},
			wantErr: `cross-os job env "CUSTOM_RUNNER_HOOK" cannot override`,
		},
		{
			name: "set +e and true masks macos baseline step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "set +e\n"+baselineTestCmd)
				runNode := yamlMustMapValue(t, step, "run")
				runNode.Value += "\ntrue\n"
			},
			wantErr: "disables errexit",
		},
		{
			name: "set +e and true masks operator package test step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, operatorTestPred)
				yamlMutateStepRun(t, step,
					"go test -count=1 ./cmd/... ./internal/... ./tools/internal/...",
					"set +e\ngo test -count=1 ./cmd/... ./internal/... ./tools/internal/...\ntrue")
			},
			wantErr: "disables errexit",
		},
		{
			name: "if false wraps macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				runNode := yamlMustMapValue(t, step, "run")
				idx := strings.Index(runNode.Value, baselineTestCmd)
				if idx < 0 {
					t.Fatalf("missing baseline cmd in step run")
				}
				runNode.Value = runNode.Value[:idx] + "if false; then\n" + runNode.Value[idx:] + "\nfi\n"
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "if false wraps exit 1 inside awk_path guard",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					"if [ \"${awk_path}\" != \"/usr/bin/awk\" ]; then\n  echo \"::error::Expected system awk at /usr/bin/awk on macOS, got ${awk_path}\" >&2\n  exit 1",
					"if [ \"${awk_path}\" != \"/usr/bin/awk\" ]; then\n  echo \"::error::Expected system awk at /usr/bin/awk on macOS, got ${awk_path}\" >&2\n  if false; then\n    exit 1\n  fi")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "if false wraps awk_path guard",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					"if [ \"${awk_path}\" != \"/usr/bin/awk\" ]; then\n  echo \"::error::Expected system awk at /usr/bin/awk on macOS, got ${awk_path}\" >&2\n  exit 1\nfi",
					"if false; then\n  if [ \"${awk_path}\" != \"/usr/bin/awk\" ]; then\n    echo \"::error::Expected system awk at /usr/bin/awk on macOS, got ${awk_path}\" >&2\n    exit 1\n  fi\nfi")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "operator package test sets working-directory",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, operatorTestPred)
				yamlSetMapScalar(step, "working-directory", "!!str", "tools")
			},
			wantErr: "sets working-directory",
		},
		{
			name: "macos baseline step overrides PATH env",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				envNode := &yaml.Node{Kind: yaml.MappingNode}
				yamlSetMapScalar(envNode, "PATH", "!!str", "/tmp/fake:/usr/bin")
				yamlSetMapValue(step, "env", envNode)
			},
			wantErr: "sets env",
		},
		{
			name: "inverted macos matrix condition",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlSetMapScalar(step, "if", "!!str", "matrix.os != 'macos-latest'")
			},
			wantErr: "condition =",
		},
		{
			name: "renamed baseline test name yields zero tests",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`-run '^TestReleaseScriptsBaseline$'`,
					`-run '^TestReleaseScriptsBaselineTypo$'`)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "drops go test -json pass event verification",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				runNode := yamlMustMapValue(t, step, "run")
				idx := strings.Index(runNode.Value, baselineTestCmd)
				if idx < 0 {
					t.Fatalf("missing baseline cmd in step run")
				}
				runNode.Value = runNode.Value[:idx] + "go test -count=1 -v -run '^TestReleaseScriptsBaseline$' ./tools/repocheck\n"
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "drops PATH=/usr/bin:/bin prefix export",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, `export PATH="/usr/bin:/bin:${PATH}"`+"\n", "")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "drops direct /usr/bin/awk version check",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`awk_ver="$(/usr/bin/awk --version 2>&1)"`,
					`awk_ver="$("${awk_path}" --version 2>&1)"`)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "drops GNU and mawk rejection from awk banner check",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`if ! printf '%s\n' "${awk_ver}" | grep -Eq '^awk version ' || printf '%s\n' "${awk_ver}" | grep -qiE 'gnu|mawk'; then`,
					`if ! printf '%s\n' "${awk_ver}" | grep -Eq '^awk version '; then`)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "echo baseline command instead of go test",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				runNode := yamlMustMapValue(t, step, "run")
				idx := strings.Index(runNode.Value, baselineTestCmd)
				if idx < 0 {
					t.Fatalf("missing baseline cmd in step run")
				}
				runNode.Value = runNode.Value[:idx] + "echo TestReleaseScriptsBaseline ./tools/repocheck\n"
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "commented baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "# "+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "missing operator package test step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps, _, idx := yamlFindStep(t, crossOS, operatorTestPred)
				steps.Content = append(steps.Content[:idx], steps.Content[idx+1:]...)
			},
			wantErr: "cross-os job has 5 steps, want exact 6-step sequence",
		},
		{
			name: "conditional operator package test step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, operatorTestPred)
				yamlSetMapScalar(step, "if", "!!str", "matrix.os == 'windows-latest'")
			},
			wantErr: "has conditional gate",
		},
		{
			name: "missing awk path guard",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`if [ "${awk_path}" != "/usr/bin/awk" ]; then`,
					`if false; then`)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "missing bash 3.2 version guard",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`if ! printf '%s\n' "${bash_ver}" | grep -Eq '^GNU bash, version 3\.2\.'; then`,
					`if false; then`)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "trailing backslash line continuation masks macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, ": \\\n"+baselineTestCmd)
			},
			wantErr: "disallowed trailing line continuation",
		},
		{
			name: "heredoc in macos baseline step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					baselineTestCmd,
					"cat <<'EOF' >/dev/null\n"+baselineTestCmd+"\nEOF\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "exec true exits early before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "exec true\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "case awk_ver replaces exit 1 with true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`  *$'\n'*)`+"\n"+`    echo "::error::Unexpected multi-line awk version output: ${awk_ver}" >&2`+"\n    exit 1",
					`  *$'\n'*)`+"\n"+`    echo "::error::Unexpected multi-line awk version output: ${awk_ver}" >&2`+"\n    true")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "case awk_ver replaces newline pattern",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, `  *$'\n'*)`, "  never_match_pattern)")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "double-space exit 0 before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "exit  0\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "tab exec true before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "exec\ttrue\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "builtin exit 0 before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "builtin exit 0\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "eval exit 0 before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "eval 'exit 0'\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "enable -n exit bypass before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, `awk_path="$(command -v awk)"`, "enable -n exit\nawk_path=\"$(command -v awk)\"")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "go function shadowing before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "go() (return 0)\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "alias go=true before macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, baselineTestCmd, "alias go=true\n"+baselineTestCmd)
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "inline PATH export in macos baseline step",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, `awk_path="$(command -v awk)"`, "PATH=\"/tmp/fakebin:${PATH}\"\nawk_path=\"$(command -v awk)\"")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "rebinding awk_ver before version guard",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step,
					`if ! printf '%s\n' "${awk_ver}" | grep -Eq '^awk version ' || printf '%s\n' "${awk_ver}" | grep -qiE 'gnu|mawk'; then`,
					"awk_ver=\"awk version 20200816\"\nif ! printf '%s\\n' \"${awk_ver}\" | grep -Eq '^awk version ' || printf '%s\\n' \"${awk_ver}\" | grep -qiE 'gnu|mawk'; then")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "quote-masked comment breakout inside awk single-quoted argument",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "{ print }", "# tolerate runner hiccups' || exit 0; : '\n            { print }")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "multiline single-quote block disguised with hash line prefix",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "set -euo pipefail", "set -euo pipefail\n: '\n# tolerate runner hiccups' || exit 0; : '\n'")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "multiline double-quote block disguised with hash line prefix",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "set -euo pipefail", "set -euo pipefail\n: \"\n# fake comment inside double quotes\n\"")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "multiline ANSI-C quote block disguised with hash line prefix",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "set -euo pipefail", "set -euo pipefail\n: $'\n# fake comment inside ansi-c quotes\n'")
			},
			wantErr: "macOS baseline line[",
		},
		{
			name: "earlier step comment TestReleaseScriptsBaseline with weakened macos baseline",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, buildStep, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
					return yamlStepHasNormalizedRunSubstr(s, "go build ./...")
				})
				yamlMutateStepRun(t, buildStep, "go build ./...", "# TestReleaseScriptsBaseline\ngo build ./...")
				_, macStep, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlSetMapScalar(macStep, "if", "!!str", "matrix.os != 'macos-latest'")
			},
			wantErr: "condition =",
		},
		{
			name: "inline comment on macos baseline command",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "set -euo pipefail", "set -euo pipefail # verify doesn't fail")
			},
			wantErr: "macOS baseline line[0]",
		},
		{
			name: "multiline backtick wrapping single-quoted hash line prefix",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, step, _ := yamlFindStep(t, crossOS, macBaselinePred)
				yamlMutateStepRun(t, step, "set -euo pipefail", "set -euo pipefail\n: \"`\necho '\n# tolerate runner hiccups'\n`\"")
			},
			wantErr: "macOS baseline line[",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := mutateCrossOSDoc(t, baseDoc, tc.mutate)
			if mutated == baseMarshaled {
				t.Fatalf("test setup error: mutation %q had no effect", tc.name)
			}
			err := checkCrossOSMatrixCIWorkflow(mutated, df)
			if err == nil {
				t.Fatalf("accepted broken ci.yml for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkCrossOSMatrixCIWorkflow(%s) error = %q, want substring %q", tc.name, err.Error(), tc.wantErr)
			}
		})
	}

	t.Run("extractCrossOSScriptLines handles backtick frames and line-continued hash", func(t *testing.T) {
		gotContinued, err := extractCrossOSScriptLines("echo hi \\\n# continued arg\n# real comment\necho ok", true)
		if err != nil {
			t.Fatalf("extractCrossOSScriptLines continued hash error: %v", err)
		}
		wantContinued := []string{`echo hi \`, "# continued arg", "echo ok"}
		if !slices.Equal(gotContinued, wantContinued) {
			t.Fatalf("continued hash lines = %q, want %q", gotContinued, wantContinued)
		}

		gotBacktick, err := extractCrossOSScriptLines("x=`echo ok # '`\n# real comment\ny=\"`\necho '\n# quoted inside bt\n'\n`\"", true)
		if err != nil {
			t.Fatalf("extractCrossOSScriptLines backtick error: %v", err)
		}
		wantBacktick := []string{"x=`echo ok # '`", `y="` + "`", "echo '", "# quoted inside bt", "'", "`\""}
		if !slices.Equal(gotBacktick, wantBacktick) {
			t.Fatalf("backtick lines = %q, want %q", gotBacktick, wantBacktick)
		}

		gotCommentCont, err := extractCrossOSScriptLines("echo hi # comment \\\n# real comment after comment\necho done", true)
		if err != nil {
			t.Fatalf("extractCrossOSScriptLines comment trailing backslash error: %v", err)
		}
		wantCommentCont := []string{`echo hi # comment \`, "echo done"}
		if !slices.Equal(gotCommentCont, wantCommentCont) {
			t.Fatalf("comment trailing backslash lines = %q, want %q", gotCommentCont, wantCommentCont)
		}

		for _, tc := range []struct {
			name string
			src  string
			want []string
		}{
			{
				name: "escaped backtick inside backtick comment",
				src:  "echo \"`echo hi # \\``\"\n# real comment\necho done",
				want: []string{"echo \"`echo hi # \\``\"", "echo done"},
			},
			{
				name: "hash immediately after opening backtick",
				src:  "x=`# '`\n# real comment\necho done",
				want: []string{"x=`# '`", "echo done"},
			},
			{
				name: "escaped quote multiline inside double-quoted backtick",
				src:  ": \"`echo \\\"\n# not a comment\n\\\"`\"\n# real comment\necho done",
				want: []string{`: "` + "`" + `echo \"`, "# not a comment", `\"` + "`" + `"`, "echo done"},
			},
			{
				name: "param expansion nested quotes",
				src:  "x=\"${y:-\"a'}b\"}\"\n# real comment\necho done",
				want: []string{"x=\"${y:-\"a'}b\"}\"", "echo done"},
			},
			{
				name: "case pattern inside cmdsubst",
				src:  "y=\"$(case z in a) echo \"a'b\";; esac)\"\n# real_comment\necho done",
				want: []string{`y="$(case z in a) echo "a'b";; esac)"`, "echo done"},
			},
			{
				name: "unspaced backslash continuation into hash chain",
				src:  "echo hi\\\n#continued\\\n#third_line\n# real comment\necho done",
				want: []string{`echo hi\`, `#continued\`, "#third_line", "echo done"},
			},
			{
				name: "unspaced backslash continuation into hash single-quote",
				src:  "echo hi\\\n#'\n# inside_sq\n'\n# real comment\necho done",
				want: []string{`echo hi\`, "#'", "# inside_sq", "'", "echo done"},
			},
			{
				name: "multiline backtick closing line with trailing backslash",
				src:  "x=`\necho hi\n`\\\n# continued_after_bt\n# real comment\necho done",
				want: []string{"x=`", "echo hi", "`\\", "# continued_after_bt", "echo done"},
			},
			{
				name: "unspaced backslash continuation inside multiline backtick",
				src:  "x=`echo hi\\\n#continued_inside_bt\n`\n# real comment\necho done",
				want: []string{`x=` + "`" + `echo hi\`, "#continued_inside_bt", "`", "echo done"},
			},
			{
				name: "multiline backtick closed on hash-prefixed line unquoted",
				src:  "x=`echo hi\n# comment closing `; echo ACTIVE_CMD\n# real comment\necho DONE",
				want: []string{`x=` + "`" + `echo hi`, "# comment closing `; echo ACTIVE_CMD", "echo DONE"},
			},
			{
				name: "multiline backtick closed on hash-prefixed line double-quoted",
				src:  "echo \"`echo hi\n# close `\"; echo ACTIVE_CMD\n# real comment\necho DONE",
				want: []string{`echo "` + "`" + `echo hi`, "# close `\"; echo ACTIVE_CMD", "echo DONE"},
			},
			{
				name: "multiline backtick closed on hash-prefixed line with trailing backslash",
				src:  "x=`echo hi\n# close `\\\n#continued_after_bt\n# real comment\necho done",
				want: []string{`x=` + "`" + `echo hi`, "# close `\\", "#continued_after_bt", "echo done"},
			},
			{
				name: "ansi-c quote trailing backslash newline preserves hash line",
				src:  "x=$'abc\\\n# inside_ansic\\\n'\n# real comment\necho done",
				want: []string{`x=$'abc\`, `# inside_ansic\`, `'`, "echo done"},
			},
			{
				name: "ansi-c quote trailing backslash before escaped single quote",
				src:  "x=$'foo\\\n\\'\n# inside\n'\n# real comment\necho done",
				want: []string{`x=$'foo\`, `\'`, "# inside", `'`, "echo done"},
			},
			{
				name: "split heredoc opener across backslash-newline preserves body hash and closes cleanly",
				src:  "cat <<EO\\\nF >/dev/null\n# body hash\nEOF\n# real comment\necho done",
				want: []string{`cat <<EO\`, "F >/dev/null", "# body hash", "EOF", "echo done"},
			},
			{
				name: "multiline backtick close followed by split heredoc opener",
				src:  "x=`echo hi\n` <<EO\\\nF >/dev/null\n# body hash\nEOF\n# real comment\necho done",
				want: []string{"x=`echo hi", "` <<EO\\", "F >/dev/null", "# body hash", "EOF", "echo done"},
			},
			{
				name: "back-to-back multiline backticks close and reopen on same line",
				src:  "x=`echo ok\n` && y=`\necho '\n# quoted inside second bt\n'\n`\n# real comment\necho done",
				want: []string{"x=`echo ok", "` && y=`", "echo '", "# quoted inside second bt", "'", "`", "echo done"},
			},
			{
				name: "back-to-back multiline backticks separated by backslash continuation",
				src:  "x=`echo ok\n` \\\n&& y=`\necho '\n# quoted inside cont second bt\n'\n`\n# real comment\necho done",
				want: []string{"x=`echo ok", "` \\", "&& y=`", "echo '", "# quoted inside cont second bt", "'", "`", "echo done"},
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				got, err := extractCrossOSScriptLines(tc.src, true)
				if err != nil {
					t.Fatalf("extractCrossOSScriptLines(%s) error: %v", tc.name, err)
				}
				if !slices.Equal(got, tc.want) {
					t.Fatalf("extractCrossOSScriptLines(%s) = %q, want %q", tc.name, got, tc.want)
				}
			})
		}

		if info, statErr := os.Stat("/bin/bash"); statErr == nil && info.Mode()&0o111 != 0 {
			for _, tc := range []struct {
				name   string
				script string
				want   string
			}{
				{name: "escaped_bt_comment", script: "echo \"`echo hi # \\``\"\n# real comment", want: "hi"},
				{name: "unspaced_bs_hash", script: "echo hi\\\n#continued\\\n#third_line", want: "hi#continued#third_line"},
				{name: "unspaced_bs_sq", script: "echo hi\\\n#'\n# inside_sq\n'", want: "hi#\n# inside_sq"},
				{name: "multiline_bt_close_bs", script: "x=`\necho hi\n`\\\n#continued_after_bt\n# real comment\nprintf '%s' \"$x\"", want: "hi#continued_after_bt"},
				{name: "bt_hash_close_unquoted", script: "x=`echo hi\n# comment closing `; echo ACTIVE_CMD\n# real comment\necho DONE", want: "ACTIVE_CMD\nDONE"},
				{name: "bt_hash_close_dq", script: "echo \"`echo hi\n# close `\"; echo ACTIVE_CMD\n# real comment\necho DONE", want: "hi\nACTIVE_CMD\nDONE"},
				{name: "bt_hash_close_trailing_bs", script: "x=`echo hi\n# close `\\\n#continued_after_bt\n# real comment\nprintf '%s' \"$x\"", want: "hi#continued_after_bt"},
				{name: "ansic_trailing_bs_newline", script: "x=$'abc\\\n# inside_ansic\\\n'\n# real comment\nprintf '[%s]' \"$x\"", want: "[abc\\\n# inside_ansic\\\n]"},
				{name: "ansic_trailing_bs_then_bs_quote", script: "x=$'foo\\\n\\'\n# inside\n'\n# real comment\nprintf '[%s]' \"$x\"", want: "[foo\\\n'\n# inside\n]"},
				{name: "split_heredoc_opener", script: "cat <<EO\\\nF >/dev/null\n# body\nEOF\necho done", want: "done"},
				{name: "back_to_back_multiline_backticks", script: "x=`echo ok\n` && y=`\necho '\n# quoted\n'\n`\n# real comment\nprintf '%s' \"$x,$y\"", want: "ok,\n# quoted"},
			} {
				out, bashErr := exec.Command("/bin/bash", "-euo", "pipefail", "-c", tc.script).CombinedOutput()
				if bashErr != nil {
					t.Fatalf("bash parity %q failed: %v\n%s", tc.name, bashErr, out)
				}
				if got := strings.TrimSpace(string(out)); got != tc.want {
					t.Fatalf("bash parity %q output = %q, want %q", tc.name, got, tc.want)
				}
			}
		}
	})
}

func TestCrossOSMatrixInCIWorkflowHandlesAliasedCheckoutAndSetupGoSteps(t *testing.T) {
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	df := testsupport.ReadRepoText(t, "example/Dockerfile")

	aliasStep := func(target *yaml.Node, anchorName string) *yaml.Node {
		target.Anchor = anchorName
		return &yaml.Node{Kind: yaml.AliasNode, Value: anchorName, Alias: target}
	}

	buildAliasedWorkflow := func(t *testing.T, aliasWithOnly bool) string {
		t.Helper()
		doc := parseWorkflowYAMLNode(t, ci)
		root := doc.Content[0]
		jobs := yamlMustMapValue(t, root, "jobs")
		buildJob := yamlMustMapValue(t, jobs, "build")
		buildSteps := yamlMustMapValue(t, buildJob, "steps")
		crossOS := yamlMustMapValue(t, jobs, "cross-os")
		crossSteps := yamlMustMapValue(t, crossOS, "steps")

		var buildCheckout, buildSetupGo *yaml.Node
		for _, s := range buildSteps.Content {
			uses, ok := yamlMapLookup(s, "uses")
			if !ok {
				continue
			}
			if strings.HasPrefix(uses.Value, "actions/checkout@") && buildCheckout == nil {
				buildCheckout = s
			} else if strings.HasPrefix(uses.Value, "actions/setup-go@") && buildSetupGo == nil {
				buildSetupGo = s
			}
		}
		if buildCheckout == nil || buildSetupGo == nil {
			t.Fatal("test setup error: build job missing checkout or setup-go step")
		}

		// Anchor build steps before cross-os references them, and give
		// setup-go's "with" mapping its own anchor so both step-level and
		// nested-map aliases are exercised.
		buildSetupGoWith := yamlMustMapValue(t, buildSetupGo, "with")
		if aliasWithOnly {
			yamlSetMapValue(crossSteps.Content[1], "with", aliasStep(buildSetupGoWith, "pinned_setup_go_with"))
		} else {
			crossSteps.Content[0] = aliasStep(buildCheckout, "pinned_checkout")
			buildSetupGoWith.Anchor = "pinned_setup_go_with"
			crossSteps.Content[1] = aliasStep(buildSetupGo, "pinned_setup_go")
		}

		// Also share cross-os's macOS baseline step from an earlier unrelated job
		// to verify yamlMutateStepRun detaches aliased mapping + run scalar cleanly.
		addEarlierUnrelatedMatrixJobYAML(t, root)
		unrelatedJob := yamlMustMapValue(t, jobs, "unrelated-matrix")
		unrelatedSteps := yamlMustMapValue(t, unrelatedJob, "steps")
		_, macStep, macIdx := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
			return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
		})
		sharedBaseline := cloneYAMLNode(macStep)
		unrelatedSteps.Content = append(unrelatedSteps.Content, sharedBaseline)
		crossSteps.Content[macIdx] = aliasStep(sharedBaseline, "shared_mac_baseline")

		out, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatalf("marshaling aliased workflow: %v", err)
		}
		return string(out)
	}

	assertSiblingJobsUnchanged := func(t *testing.T, baseYAML, mutatedYAML string, keys ...string) {
		t.Helper()
		baseRoot := parseWorkflowYAMLNode(t, baseYAML).Content[0]
		mutRoot := parseWorkflowYAMLNode(t, mutatedYAML).Content[0]
		baseJobs := yamlMustMapValue(t, baseRoot, "jobs")
		mutJobs := yamlMustMapValue(t, mutRoot, "jobs")
		for _, k := range keys {
			baseRaw, err := yaml.Marshal(yamlMustMapValue(t, baseJobs, k))
			if err != nil {
				t.Fatal(err)
			}
			mutRaw, err := yaml.Marshal(yamlMustMapValue(t, mutJobs, k))
			if err != nil {
				t.Fatal(err)
			}
			if string(mutRaw) != string(baseRaw) {
				t.Fatalf("mutating cross-os leaked into job %q:\ngot:\n%s\nwant:\n%s", k, string(mutRaw), string(baseRaw))
			}
		}
	}

	aliasedStepYAML := buildAliasedWorkflow(t, false)
	if !strings.Contains(aliasedStepYAML, "*pinned_checkout") || !strings.Contains(aliasedStepYAML, "*pinned_setup_go") || !strings.Contains(aliasedStepYAML, "*shared_mac_baseline") {
		t.Fatalf("test setup error: expected YAML aliases in generated workflow:\n%s", aliasedStepYAML)
	}
	if err := checkCrossOSMatrixCIWorkflow(aliasedStepYAML, df); err != nil {
		t.Fatalf("checkCrossOSMatrixCIWorkflow rejected valid aliased workflow: %v", err)
	}
	aliasedStepDoc := parseWorkflowYAMLNode(t, aliasedStepYAML)

	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, _, crossOS *yaml.Node)
		wantErr string
	}{
		{
			name: "aliased checkout continue-on-error true",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[0], "continue-on-error", "!!bool", "true")
			},
			wantErr: "cross-os actions/checkout step sets continue-on-error: true",
		},
		{
			name: "aliased checkout unpinned uses",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				yamlSetMapScalar(steps.Content[0], "uses", "!!str", "actions/checkout@v7")
			},
			wantErr: "must use a SHA-pinned actions/checkout action",
		},
		{
			name: "aliased setup-go wrong go-version",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := yamlMustMapValue(t, steps.Content[1], "with")
				yamlSetMapScalar(withNode, "go-version", "!!str", "1.26.0")
			},
			wantErr: `cross-os job setup-go version = "1.26.0"`,
		},
		{
			name: "aliased setup-go unexpected go-version-file",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := yamlMustMapValue(t, steps.Content[1], "with")
				yamlSetMapScalar(withNode, "go-version-file", "!!str", "go.mod")
			},
			wantErr: `cross-os setup-go step sets unexpected with key "go-version-file"`,
		},
		{
			name: "aliased baseline step yamlMutateStepRun",
			mutate: func(t *testing.T, _, crossOS *yaml.Node) {
				_, macStep, _ := yamlFindStep(t, crossOS, func(s *yaml.Node) bool {
					return yamlStepHasNormalizedRunSubstr(s, "TestReleaseScriptsBaseline")
				})
				yamlMutateStepRun(t, macStep, "go test -count=1", "go test -race -count=1")
			},
			wantErr: "macOS baseline line[",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := mutateCrossOSDoc(t, aliasedStepDoc, tc.mutate)
			if mutated == aliasedStepYAML {
				t.Fatalf("test setup error: mutation %q produced no change", tc.name)
			}
			assertSiblingJobsUnchanged(t, aliasedStepYAML, mutated, "build", "unrelated-matrix")
			err := checkCrossOSMatrixCIWorkflow(mutated, df)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkCrossOSMatrixCIWorkflow(%s) err = %v, want substring %q", tc.name, err, tc.wantErr)
			}
		})
	}

	aliasedWithYAML := buildAliasedWorkflow(t, true)
	if !strings.Contains(aliasedWithYAML, "*pinned_setup_go_with") {
		t.Fatalf("test setup error: expected *pinned_setup_go_with alias in generated workflow")
	}
	if err := checkCrossOSMatrixCIWorkflow(aliasedWithYAML, df); err != nil {
		t.Fatalf("checkCrossOSMatrixCIWorkflow rejected valid setup-go with alias: %v", err)
	}
	mutatedWith := mutateCrossOSWorkflowYAML(t, aliasedWithYAML, func(t *testing.T, _, crossOS *yaml.Node) {
		steps := yamlMustMapValue(t, crossOS, "steps")
		withNode := yamlMustMapValue(t, steps.Content[1], "with")
		yamlSetMapScalar(withNode, "go-version", "!!str", "1.26.0")
	})
	if mutatedWith == aliasedWithYAML {
		t.Fatal("test setup error: with alias mutation produced no change")
	}
	assertSiblingJobsUnchanged(t, aliasedWithYAML, mutatedWith, "build", "unrelated-matrix")
	if err := checkCrossOSMatrixCIWorkflow(mutatedWith, df); err == nil || !strings.Contains(err.Error(), `cross-os job setup-go version = "1.26.0"`) {
		t.Fatalf("checkCrossOSMatrixCIWorkflow(with alias mutant) err = %v, want go-version mismatch", err)
	}

	t.Run("merge keys and nested alias detachment", func(t *testing.T) {
		buildMergedYAML := func(t *testing.T, seqMerge bool) string {
			t.Helper()
			doc := parseWorkflowYAMLNode(t, ci)
			root := doc.Content[0]
			jobs := yamlMustMapValue(t, root, "jobs")
			buildJob := yamlMustMapValue(t, jobs, "build")
			buildSteps := yamlMustMapValue(t, buildJob, "steps")
			crossOS := yamlMustMapValue(t, jobs, "cross-os")
			crossSteps := yamlMustMapValue(t, crossOS, "steps")

			var buildCheckout, buildSetupGo *yaml.Node
			for _, s := range buildSteps.Content {
				uses, ok := yamlMapLookup(s, "uses")
				if !ok {
					continue
				}
				if strings.HasPrefix(uses.Value, "actions/checkout@") && buildCheckout == nil {
					buildCheckout = s
				} else if strings.HasPrefix(uses.Value, "actions/setup-go@") && buildSetupGo == nil {
					buildSetupGo = s
				}
			}
			buildCheckout.Anchor = "base_checkout"
			buildSetupGoWith := yamlMustMapValue(t, buildSetupGo, "with")
			buildSetupGoWith.Anchor = "base_setup_go_with"

			crossSteps.Content[0] = &yaml.Node{
				Kind: yaml.MappingNode,
				Content: []*yaml.Node{
					{Kind: yaml.ScalarNode, Tag: "!!str", Value: "<<"},
					{Kind: yaml.AliasNode, Value: "base_checkout", Alias: buildCheckout},
				},
			}
			if seqMerge {
				overrideWith := &yaml.Node{
					Kind:   yaml.MappingNode,
					Anchor: "override_with",
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "cache"},
						{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"},
					},
				}
				addEarlierUnrelatedMatrixJobYAML(t, root)
				unrelatedJob := yamlMustMapValue(t, jobs, "unrelated-matrix")
				yamlSetMapValue(unrelatedJob, "x-override-with", overrideWith)
				yamlSetMapValue(crossSteps.Content[1], "with", &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "<<"},
						{Kind: yaml.SequenceNode, Content: []*yaml.Node{
							{Kind: yaml.AliasNode, Value: "override_with", Alias: overrideWith},
							{Kind: yaml.AliasNode, Value: "base_setup_go_with", Alias: buildSetupGoWith},
						}},
					},
				})
			} else {
				yamlSetMapValue(crossSteps.Content[1], "with", &yaml.Node{
					Kind: yaml.MappingNode,
					Content: []*yaml.Node{
						{Kind: yaml.ScalarNode, Tag: "!!str", Value: "<<"},
						{Kind: yaml.AliasNode, Value: "base_setup_go_with", Alias: buildSetupGoWith},
					},
				})
			}
			out, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			return string(out)
		}

		for _, seqMerge := range []bool{false, true} {
			mergedYAML := buildMergedYAML(t, seqMerge)
			if err := checkCrossOSMatrixCIWorkflow(mergedYAML, df); err != nil {
				t.Fatalf("checkCrossOSMatrixCIWorkflow(seqMerge=%v) rejected valid merge-key workflow: %v", seqMerge, err)
			}
			mergedDoc := parseWorkflowYAMLNode(t, mergedYAML)
			// Read-only yamlMapLookup resolves keys through <<: *base_checkout.
			crossSteps := yamlMustMapValue(t, yamlMustMapValue(t, yamlMustMapValue(t, mergedDoc.Content[0], "jobs"), "cross-os"), "steps")
			if uses, ok := yamlMapLookup(crossSteps.Content[0], "uses"); !ok || !strings.HasPrefix(uses.Value, "actions/checkout@") {
				t.Fatalf("yamlMapLookup on merge-key step failed: ok=%v node=%v", ok, uses)
			}
			mutCheckout := mutateCrossOSDoc(t, mergedDoc, func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				usesNode := yamlMustMapValue(t, steps.Content[0], "uses")
				if !strings.HasPrefix(usesNode.Value, "actions/checkout@") {
					t.Fatalf("merged uses = %q, want actions/checkout@", usesNode.Value)
				}
				yamlSetMapScalar(steps.Content[0], "uses", "!!str", "actions/checkout@v7")
			})
			assertSiblingJobsUnchanged(t, mergedYAML, mutCheckout, "build")
			if err := checkCrossOSMatrixCIWorkflow(mutCheckout, df); err == nil || !strings.Contains(err.Error(), "must use a SHA-pinned actions/checkout action") {
				t.Fatalf("mutated merge-key checkout err = %v, want SHA-pin failure", err)
			}
			mutSetupGo := mutateCrossOSDoc(t, mergedDoc, func(t *testing.T, _, crossOS *yaml.Node) {
				steps := yamlMustMapValue(t, crossOS, "steps")
				withNode := yamlMustMapValue(t, steps.Content[1], "with")
				if seqMerge {
					if cacheNode := yamlMustMapValue(t, withNode, "cache"); cacheNode.Value != "true" {
						t.Fatalf("seq-merged cache = %q, want true", cacheNode.Value)
					}
				}
				yamlSetMapScalar(withNode, "go-version", "!!str", "1.26.0")
			})
			assertSiblingJobsUnchanged(t, mergedYAML, mutSetupGo, "build")
			if err := checkCrossOSMatrixCIWorkflow(mutSetupGo, df); err == nil || !strings.Contains(err.Error(), `cross-os job setup-go version = "1.26.0"`) {
				t.Fatalf("mutated merge-key setup-go err = %v, want go-version mismatch", err)
			}
		}

		// Nested AliasNode inside a dereferenced mapping must detach completely
		// rather than keeping external or cross-field links on marshal.
		nestedYAML := `jobs:
  other:
    steps:
      - &step_a
        env: &inner_env
          KEY: orig
        with: *inner_env
        run: echo hi
  cross-os:
    steps:
      - *step_a
`
		nestedDoc := parseWorkflowYAMLNode(t, nestedYAML)
		crossSteps := yamlMustMapValue(t, yamlMustMapValue(t, yamlMustMapValue(t, nestedDoc.Content[0], "jobs"), "cross-os"), "steps")
		withNode := yamlMustMapValue(t, crossSteps.Content[0], "with")
		yamlSetMapScalar(withNode, "KEY", "!!str", "mutated")
		reMarshaled, err := yaml.Marshal(nestedDoc)
		if err != nil {
			t.Fatal(err)
		}
		reDoc := parseWorkflowYAMLNode(t, string(reMarshaled))
		reJobs := yamlMustMapValue(t, reDoc.Content[0], "jobs")
		otherSteps := yamlMustMapValue(t, yamlMustMapValue(t, reJobs, "other"), "steps")
		otherEnv := yamlMustMapValue(t, otherSteps.Content[0], "env")
		if got, ok := yamlMapLookup(otherEnv, "KEY"); !ok || got.Value != "orig" {
			t.Fatalf("mutation of nested alias leaked to sibling job inner_env: ok=%v val=%v", ok, got)
		}
		reCrossSteps := yamlMustMapValue(t, yamlMustMapValue(t, reJobs, "cross-os"), "steps")
		crossEnv, _ := yamlMapLookup(reCrossSteps.Content[0], "env")
		crossWith, _ := yamlMapLookup(reCrossSteps.Content[0], "with")
		if got, ok := yamlMapLookup(crossWith, "KEY"); !ok || got.Value != "mutated" {
			t.Fatalf("cross-os with KEY = %v (%v), want mutated", got, ok)
		}
		if got, ok := yamlMapLookup(crossEnv, "KEY"); !ok || got.Value != "orig" {
			t.Fatalf("nested alias inside detached step leaked to sibling field env: got %v (%v), want orig", got, ok)
		}
		// Non-mapping / nil targets must not panic in yamlSetMapValue.
		yamlSetMapValue(nil, "k", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "v"})
		yamlSetMapValue(&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "scalar"}, "k", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "v"})

		// Quoted "<<" is a literal string key (not a YAML merge key) and must
		// neither resolve through yamlMapLookup nor merge via yamlExpandMergeKeys.
		quotedMergeYAML := `base: &base
  x: from_base
obj:
  "<<": *base
  keep: yes
`
		quotedDoc := parseWorkflowYAMLNode(t, quotedMergeYAML)
		objNode := yamlMustMapValue(t, quotedDoc.Content[0], "obj")
		if got, ok := yamlMapLookup(objNode, "x"); ok || got != nil {
			t.Fatalf("quoted \"<<\" resolved merged key x: got %v (%v), want false", got, ok)
		}
		if got, ok := yamlMapLookup(objNode, "<<"); !ok || got == nil {
			t.Fatalf("quoted \"<<\" missing literal key lookup: ok=%v got=%v", ok, got)
		}
		yamlExpandMergeKeys(objNode)
		if got, ok := yamlMapLookup(objNode, "x"); ok || got != nil {
			t.Fatalf("yamlExpandMergeKeys merged quoted \"<<\": got %v (%v), want false", got, ok)
		}
		if got, ok := yamlMapLookup(objNode, "keep"); !ok || got.Value != "yes" {
			t.Fatalf("obj keep = %v (%v), want yes", got, ok)
		}
	})
}

func measureScriptAlloc4x(t *testing.T, name, small, large string, fn func(string)) {
	t.Helper()
	const iters = 5
	measureOnce := func(input string) (uint64, uint64) {
		fn(input)
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range iters {
			fn(input)
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / iters, (after.Mallocs - before.Mallocs) / iters
	}
	t.Run(name, func(t *testing.T) {
		var minBytesRatio, minAllocsRatio float64
		var bestSmallB, bestLargeB, bestSmallA, bestLargeA uint64
		for trial := range 3 {
			smallBytes, smallAllocs := measureOnce(small)
			largeBytes, largeAllocs := measureOnce(large)
			br := float64(largeBytes) / float64(max(smallBytes, 1))
			ar := float64(largeAllocs) / float64(max(smallAllocs, 1))
			if trial == 0 || br < minBytesRatio {
				minBytesRatio = br
				bestSmallB, bestLargeB = smallBytes, largeBytes
			}
			if trial == 0 || ar < minAllocsRatio {
				minAllocsRatio = ar
				bestSmallA, bestLargeA = smallAllocs, largeAllocs
			}
			if br < 6.5 && ar < 6.5 {
				return
			}
		}
		t.Fatalf("%s scaling is super-linear across 3 trials (4x lines -> min %.2fx bytes [%d->%d], min %.2fx allocs [%d->%d])",
			name, minBytesRatio, bestSmallB, bestLargeB, minAllocsRatio, bestSmallA, bestLargeA)
	})
}

func TestScanCrossOSScriptLinesBacktickLinearScaling(t *testing.T) {
	buildMultilineBacktickScript := func(n int) string {
		var b strings.Builder
		b.WriteString("x=`\n")
		for i := range n {
			if i%3 == 0 {
				b.WriteString("echo '\n# quoted line\n'\n")
			} else {
				b.WriteString("# comment line inside backtick\necho step\n")
			}
		}
		b.WriteString("`\n# trailing comment\necho ok\n")
		return b.String()
	}

	measureScriptAlloc4x(t, "scanCrossOSScriptLines", buildMultilineBacktickScript(128), buildMultilineBacktickScript(512), func(s string) {
		lines, inQ, inH, hasCont, err := scanCrossOSScriptLines(s, true)
		if err != nil || inQ || inH || hasCont || len(lines) == 0 {
			panic(fmt.Sprintf("unexpected scanCrossOSScriptLines result: err=%v inQ=%v inH=%v hasCont=%v len=%d", err, inQ, inH, hasCont, len(lines)))
		}
	})
	measureScriptAlloc4x(t, "activeBashCodeLinesChecked", buildMultilineBacktickScript(128), buildMultilineBacktickScript(512), func(s string) {
		lines, err := activeBashCodeLinesChecked(s)
		if err != nil || len(lines) == 0 {
			panic(fmt.Sprintf("unexpected activeBashCodeLinesChecked result: err=%v len=%d", err, len(lines)))
		}
	})
	measureScriptAlloc4x(
		t,
		"stepDisablesErrexit_unclosed_param_single",
		strings.Repeat("echo \"${UNSET:-'}\"\n", 128)+"echo ok\n",
		strings.Repeat("echo \"${UNSET:-'}\"\n", 512)+"echo ok\n",
		func(s string) {
			if stepDisablesErrexit(s) {
				panic("unexpected true on benign script")
			}
		},
	)

	for _, tc := range []struct {
		name  string
		build func(int) string
	}{
		{
			name: "scanCrossOSScriptLines_spaced_cont",
			build: func(n int) string {
				return "echo start \\\n" + strings.Repeat("  --flag=value \\\n", n) + "  end\n"
			},
		},
		{
			name: "scanCrossOSScriptLines_unspaced_cont",
			build: func(n int) string {
				return "echo " + strings.Repeat("argchunk\\\n", n) + "tail\n"
			},
		},
		{
			name: "scanCrossOSScriptLines_double_quote_cont",
			build: func(n int) string {
				return "x=\"start \\\n" + strings.Repeat("segment_text \\\n", n) + "end\"\n"
			},
		},
	} {
		measureScriptAlloc4x(t, tc.name, tc.build(256), tc.build(1024), func(s string) {
			lines, inQ, inH, hasCont, err := scanCrossOSScriptLines(s, true)
			if err != nil || inQ || inH || hasCont || len(lines) == 0 {
				panic("unexpected scanCrossOSScriptLines failure")
			}
		})
	}

	t.Run("crossOSScriptScanner_backtick_cont_endStatus", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			raw        string
			wantLine1Q bool
			wantEnd    bool
			wantLines  int
		}{
			{
				name:       "unquoted multiline backtick then backslash continuation",
				raw:        "x=`echo 1\necho 2`\\\ny=1; set +e; false; echo ALIVE",
				wantLine1Q: false,
				wantEnd:    true,
				wantLines:  3,
			},
			{
				name:       "double-quoted multiline backtick then backslash continuation",
				raw:        "x=\"`echo 1\necho 2`\\\ny=1\"",
				wantLine1Q: true,
				wantEnd:    false,
				wantLines:  3,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				phys := strings.Split(tc.raw, "\n")
				sc := newCrossOSScriptScannerWithMode(phys, true)
				for i, line := range phys {
					if _, _, err := sc.step(i, line, true, true, false); err != nil {
						t.Fatalf("step(%d) err = %v", i, err)
					}
					inQ, inH, hasC := sc.endStatus()
					switch i {
					case 0:
						if inQ || inH || hasC || sc.btScanner == nil {
							t.Fatalf("after line 0: endStatus=(%v,%v,%v) btScanner=%v, want inner clean status and active btScanner",
								inQ, inH, hasC, sc.btScanner)
						}
					case 1:
						if inQ != tc.wantLine1Q || inH || !hasC || sc.btScanner != nil {
							t.Fatalf("after line 1 (closed backtick + \\): endStatus=(%v,%v,%v) btScanner=%v, want inQ=%v hasCont=true btScanner=nil",
								inQ, inH, hasC, sc.btScanner, tc.wantLine1Q)
						}
					case 2:
						if inQ || inH || hasC || sc.btScanner != nil {
							t.Fatalf("after line 2: endStatus=(%v,%v,%v) btScanner=%v, want clean end", inQ, inH, hasC, sc.btScanner)
						}
					}
				}
				lines, inQ, inH, hasCont, err := scanCrossOSScriptLines(tc.raw, true)
				if err != nil || inQ || inH || hasCont || len(lines) != tc.wantLines {
					t.Fatalf("scanCrossOSScriptLines = (%q, %v, %v, %v, %v), want %d clean lines", lines, inQ, inH, hasCont, err, tc.wantLines)
				}
				if gotSet := stepDisablesErrexit(tc.raw); gotSet != tc.wantEnd {
					t.Fatalf("stepDisablesErrexit(%q) = %v, want %v", tc.raw, gotSet, tc.wantEnd)
				}
			})
		}
	})

	t.Run("reachedTopLevelByLine_continuation_parity", func(t *testing.T) {
		commentPass := runBashScriptLinesPass(strings.Split("echo \"line 1\nline 2\" \\\n  # comment", "\n"), true, false, false, false)
		wantCommentTop := []bool{false, true, true}
		if !slices.Equal(commentPass.reachedTopLevelByLine, wantCommentTop) {
			t.Fatalf("reachedTopLevelByLine (comment cont) = %v, want %v", commentPass.reachedTopLevelByLine, wantCommentTop)
		}
		stayQuotedPass := runBashScriptLinesPass(strings.Split("echo \"line 1\nline 2 \\\n  line 3 \\", "\n"), true, false, false, false)
		wantStayQuotedTop := []bool{false, false, false}
		if !slices.Equal(stayQuotedPass.reachedTopLevelByLine, wantStayQuotedTop) || !stayQuotedPass.inQuote || !stayQuotedPass.hasCont {
			t.Fatalf("stayQuotedPass = (top=%v, inQ=%v, hasCont=%v), want ([false false false], true, true)",
				stayQuotedPass.reachedTopLevelByLine, stayQuotedPass.inQuote, stayQuotedPass.hasCont)
		}
		quotedPass := runBashScriptLinesPass(strings.Split("echo \"line 1\nline 2\" \"line 3 \\\n  line 4 \\", "\n"), true, false, false, false)
		wantQuotedTop := []bool{false, true, true}
		if !slices.Equal(quotedPass.reachedTopLevelByLine, wantQuotedTop) || !quotedPass.inQuote || !quotedPass.hasCont {
			t.Fatalf("quotedPass = (top=%v, inQ=%v, hasCont=%v), want ([false true true], true, true)",
				quotedPass.reachedTopLevelByLine, quotedPass.inQuote, quotedPass.hasCont)
		}
		closedPass := runBashScriptLinesPass(strings.Split("echo \"line 1\nline 2\" \"line 3 \\\n  line 4 \\\n  end\"", "\n"), true, false, false, false)
		wantClosedTop := []bool{false, true, true, true}
		if !slices.Equal(closedPass.reachedTopLevelByLine, wantClosedTop) || closedPass.inQuote || closedPass.hasCont {
			t.Fatalf("closedPass = (top=%v, inQ=%v, hasCont=%v), want ([false true true true], false, false)",
				closedPass.reachedTopLevelByLine, closedPass.inQuote, closedPass.hasCont)
		}
	})
}

func TestGateCrossOSStepErrexitGuards(t *testing.T) {
	badSteps := []string{
		`echo ${x:-'}'}; set +e`,
		`echo ${x:-{}; set +e`,
		`echo "${x:-{}"; set +e`,
		`echo "${a:-${b:-'}}"; set +e`,
		`echo "$(case a in a) echo '"';; esac)"; set +e`,
		`x="$(case a in a) echo "a'b" ;; esac)" ; set +e`,
		"x=\"$(case a in\na)\necho \"a'b\"\n;;\nesac)\"\nset +e",
		`x="$(case a in a) set +e; false; echo ok;; esac)"`,
		"x=\"$(echo hi\ncase a in a) echo \"'\" ;; esac)\" ; set +e",
		"x=\"$(cat <<'EOF'\n)\nEOF\ncase a in a) echo \"'\" ;; esac)\" ; set +e",
		"x=\"$(case a in a) echo \"x'y\"\nesac)\" ; set +e",
		"x=\"$(case a in a) echo ok\nesac\necho \"'\" )\" ; set +e",
		"echo \"`echo '\"'`\"; set +e",
		"x=\"`echo '\\`'`\"; set +e",
		"x=\"`echo a \\\\`\"; set +e",
		"x=\"`echo \\`echo \\\"a'b\\\"\\` `\" ; set +e",
		"x=\"`echo \\`echo \\\"a'b\\\"\\` `\"\nset +e",
		"x=\"`set +e; false; echo IN_SUB`\"",
		"x=`set +e; false; echo IN_SUB`",
		`set $(true) +e`,
		`set +o $(true) errexit`,
		`shopt -u $(true) -o errexit`,
		`eval $(true) "set +e"`,
		`set>/dev/null +e`,
		`$"set" +e`,
		`eval >/dev/null -- "set +e"`,
		`x="$(set +e; false; echo IN_SUB)"`,
		`set -oo errexit +e`,
		`set -oo nounset +e`,
		`set -oo nounset +o errexit`,
		`set -oerrexit +e`,
		`echo "${UNSET_XYZ:-'a"b'}"; set +e`,
		"echo \"${UNSET_XYZ:-'a\"b'}\"\nset +e",
		`echo "${UNSET_XYZ:-'"'}"; set +e`,
		`set +o ${PWD:99999} errexit`,
		`set +o ${UNSET_XYZ:-} errexit`,
		`shopt -u ${PWD:99999} -o errexit`,
		`eval ${PWD:99999} "set +e"`,
		`eval "${PWD:99999}" "set +e"`,
		`eval "" "set +e"`,
		`${PWD:99999} set +e`,
		`FOO=1 ${PWD:99999} set +e`,
		`command ${PWD:99999} -p set +e`,
		`builtin ${PWD:99999} set +e`,
		`time ${PWD:99999} set +e`,
		`set +{e,u}`,
		`set -{u,x} +e`,
		`shopt -u -o {nounset,errexit}`,
		`{set,+e}`,
		`{ set +e; }`,
		"echo \"${UNSET:-'}\"\nset +e\necho 'done'",
		`echo "${UNSET:-'}"; set +e; echo "'"`,
		`echo "${UNSET:-'$(set +e)'}"`,
		"echo \"${UNSET:-'`set +e`'}\"",
		`set $@ +e`,
		`set "$@" +e`,
		`eval -- $@ "set +e"`,
		`{,set} +e`,
		`set {,+e}`,
		`set +{u,e}{u,x}{u,x}{u,x}{u,x}{u,x}{u,x}`,
		`shopt -u -o {` + strings.Repeat("nounset,", 65) + `errexit}`,
		`set +o {e..e}rrexit`,
		`shopt -u -o {e..e}rrexit`,
		`{s..s}et +e`,
		`{e..e}val "set +e"`,
		`set +{a..z}{a..z}`,
		`echo "${UNSET:-'}"; set +e; echo "'}"`,
		"echo \"${UNSET:-'}\"\nset +e\necho '}'",
		`eval -- > "#x" "set +e"`,
		`eval -- "set" > "a;b" "+e"`,
		`set $! +e`,
		`set "${@:1}" +e`,
		`set "$@${@:1}" +e`,
		`V=""; set "$@${V}" +e`,
		`set "${BASH_VERSINFO[@]:99}" +e`,
		`A=(); set "${A[@]}" +e`,
		"echo \"${UNSET:-'}\"\n# '}\" <<EOF\nset +e\necho \"${UNSET_XYZ:-'a\"b'}\"",
		"echo \"${UNSET:-'}\"; set +e; false; echo \"'}\"; exit 0\necho \"${UNSET_XYZ:-'a\"b'}\"",
		`set "${!UNSET_PREFIX_XYZ@}" +e`,
		`set "${!BASH_CMDS[@]}" +e`,
		`A=(); set "${!A[@]}" +e`,
		`set "${UNSET:-$@}" +e`,
		`set "${PWD:+"$@"}" +e`,
		`set {fd}>/dev/null +e`,
		`{fd}>/dev/null set +e`,
		`set {fd[0]}>/dev/null +e`,
		`set {fd}<<<hi +e`,
		`{fd}>&- set +e`,
		`fd=3; {fd}>&- set +e`,
		`{fd}>&1 set +e`,
		"echo \"${UNSET:-'}\" && echo '''}\"' ' # '; set +e",
		"echo \"${UNSET:-'}\"\n# '}\" `cat <<EOF\nset +e\n# `",
		"echo \"${UNSET_XYZ:+'${'}\"\nset +e",
		"echo \"${UNSET_XYZ:+'`'}\"\nset +e",
		"echo \"${UNSET_XYZ:+'$(#'}\"\nset +e",
		"echo \"${PWD:-'${'}\"\nset +o errexit",
		"echo \"${PWD:-'$(#'}\"\nshopt -u -o errexit",
		`echo "${UNSET:-'$(set +e)'}"`,
		"echo \"${UNSET:-'`set +e`'}\"",
		`set {fd[${UNSET:-0}]}>/dev/null +e`,
		`{fd[${UNSET:-0}]}>/dev/null set +e`,
		`declare -A a; set {a["x}y"]}>/dev/null +e`,
		`set < <(true) +e`,
		`set > >(cat >/dev/null) +e`,
		`set {fd}< <(true) +e`,
		`shopt -u {fd}< <(true) -o errexit`,
		`eval < <(true) "set +e"`,
		`echo <(set +e)`,
		`set "${1:-$@}" +e`,
		`set "${0:+$@}" +e`,
		`set "${-:+$@}" +e`,
		`set "${!:-$@}" +e`,
		`A=(); set "${A[0]:-$@}" +e`,
		`x="$(echo "${UNSET_XYZ:-'a"b'}"; set +e)"`,
		`set >|>(cat /dev/null) +e`,
		`eval >|>(cat /dev/null) "set +e"`,
		`shopt -u >|>(cat /dev/null) -o errexit`,
		`>|>(cat /dev/null) set +e`,
		`set <<<<(echo hi) +e`,
		`set ><(true) +e`,
		`set >><(true) +e`,
		`set &><(true) +e`,
		"echo \"${UNSET:-`echo \\\"; set +e`}\"",
		`set {fd[0,0]}>/dev/null +e`,
		`{fd[0,0]}>/dev/null set +e`,
		`set +o {fd[0,0]}>/dev/null errexit`,
		`shopt -u {fd[0,0]}>/dev/null -o errexit`,
		`eval {fd[0,0]}>/dev/null "set +e"`,
		`set {fd[0,0]}< <(true) +e`,
		`declare -A a; set {a[x,y]}>/dev/null +e`,
		"EOF() { :; }\necho \"${UNSET:-'}\"\n# '}\" <<EOF\nset +e\ncat <<'EO\nF' >/dev/null\nbody\nEO\nF\nEOF",
		"EOF() { :; }\necho \"${UNSET:-'}\" <<\\EOF # '}\"\ncat <<'EO\nF' >/dev/null\nbody\nEO\nF\nset +e\nEOF",
		"EOF() { :; }\necho \"${UNSET:-'}\" <<\\EOF # '}\"\nset +e\ncat <<'EO\\nF' >/dev/null\nEO\\nF\nEOF",
		"EOF() { :; }\necho \"${UNSET:-'}\"\n# '}\" <<EOF\ncat <<'EO\\nF' >/dev/null\nEO\\nF\nset +e\nEOF",
		"echo \"${UNSET:-'}\"`'}\"\ncat <<EO\\",
		"echo \"${UNSET:-'}\"`'}\"\ncat <<'EO\\nF' >/dev/null\nbody\nEO\\nF\nset +e",
		"echo \"${UNSET:-'a}\"'}\"\n# '; set +e; true <<$'EO\\nF'",
		"echo \"${UNSET:-'a}\"'}\"\n# '; set +e <<EOF",
		"echo \"${UNSET:-'a}\"'}\"; set +e; true <<$'EO\\nF' # '",
		"( echo \"${UNSET:-'a}\"'}\"; set +e; true <<$'EO\\nF' # ' )",
		"(\necho \"${UNSET:-'a}\"'}\"\n# '; set +e; false; echo BYPASSED; true <<$'EO\\nF' )\n: )",
		"echo \"$(\necho \"${UNSET:-'a}\"'}\"\n# '; set +e; true <<$'EO\\nF')\n\"",
		"case x in x)\necho \"${UNSET:-'a}\"'}\"\n# '; set +e; true <<$'EO\\nF'\n;;\nesac",
		"x=\"$(case esac in (esac) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo FULL_BYPASS >&2\n;; esac)\" # \"",
		"x=\"$(case esac in a|esac) : '\"\n# '; set +e; false; echo ALT_BYPASS >&2\n;; esac)\" # \"",
		"case x in \"${UNSET:-'a}\"'}\"| # '|x) set +e; true <<$'EO\\nF' ;;\nx) echo ok ;;\nesac",
		"( echo \"${UNSET:-'a}\"'}\" ; cat <<'EOF'\n'\nset +e; false; echo BYPASSED_PASS2_CLEAN >&2; true <<EOF\n$(true <<$'EO\\nF')\nEOF\n)",
		"x=\"$(case x in \\\nesac)\" : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e",
		"x=\"$(case x in a) echo ok ;; \\\nesac)\" : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e",
		"x=\"$(case \\\\ in \\\\|esac) : '\"\n# '; set +e; false; echo BYP_DBL_BS >&2\n;; esac)\" # \"",
		"x=\"$(foo() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_FUNC_BRACE >&2\n;; esac; }; foo)\" # \"",
		"x=\"$(foo(){ case x in x) : '\"\n# '; set +e; false; echo BYP_FUNC_NOSPACE >&2\n;; esac; }; foo)\" # \"",
		"x=\"$(foo() case x in x) : '\"\n# '; set +e; false; echo BYP_FUNC_CASE >&2\n;; esac; foo)\" # \"",
		"x=\"$(my-func() { case x in x) : '\"\n# '; set +e; false; echo BYP_DASH_FUNC >&2\n;; esac; }; my-func)\" # \"",
		"x=\"$(foo()\n{\ncase x in x) : '\"\n# '; set +e; false; echo BYP_FUNC_NL >&2\n;; esac; }; foo)\" # \"",
		"x=\"$(function foo { case x in x) : '\"\n# '; set +e; false; echo BYP_KW_FUNC >&2\n;; esac; }; foo)\" # \"",
		"x=\"$(function foo () { case x in x) : '\"\n# '; set +e; false; echo BYP_KW_FUNC_PAREN >&2\n;; esac; }; foo)\" # \"",
		"x=\"$(function foo case x in x) : '\"\n# '; set +e; false; echo BYP_KW_FUNC_CASE >&2\n;; esac; foo)\" # \"",
		"x=\"$(coproc { case x in x) : '\"\n# '; set +e; false; echo BYP_COPROC_BRACE >&2\n;; esac; })\" # \"",
		"x=\"$(coproc foo { case x in x) : '\"\n# '; set +e; false; echo BYP_COPROC_NAMED >&2\n;; esac; })\" # \"",
		"x=\"$(coproc case x in x) : '\"\n# '; set +e; false; echo BYP_COPROC_CASE >&2\n;; esac)\" # \"",
		"x=\"$(coproc foo case x in x) : '\"\n# '; set +e; false; echo BYP_COPROC_NAMED_CASE >&2\n;; esac)\" # \"",
		"x=\"$(time -p case x in x) : '\"\n# '; set +e; false; echo BYP_TIME_P >&2\n;; esac)\" # \"",
		"x=\"$(time -p -- case x in x) : '\"\n# '; set +e; false; echo BYP_TIME_DD >&2\n;; esac)\" # \"",
		"x=\"$(! { case x in x) : '\"\n# '; set +e; false; echo BYP_BANG_BRACE >&2\n;; esac; })\" # \"",
		"x=\"$(a~b() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_TILDE >&2\n;; esac; }; a~b)\" # \"",
		"x=\"$(a]b() { case x in x) : '\"\n# '; set +e; false; echo BYP_RBRACKET >&2\n;; esac; }; a]b)\" # \"",
		"x=\"$(a#b() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_HASH >&2\n;; esac; }; a#b)\" # \"",
		"x=\"$(case#b() { case x in x) : '\"\n# '; set +e; false; echo BYP_CASE_HASH >&2\n;; esac; }; case#b)\" # \"",
		"x=\"$(café() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_UTF8 >&2\n;; esac; }; café)\" # \"",
		"x=\"$(a-b=c() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_NONID_EQ >&2\n;; esac; }; a-b=c)\" # \"",
		"x=\"$(1=foo() { case x in x) : '\"\n# '; set +e; false; echo BYP_DIGIT_EQ >&2\n;; esac; }; 1=foo)\" # \"",
		"x=\"$(=foo() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_LEAD_EQ >&2\n;; esac; }; =foo)\" # \"",
		"x=\"$({foo() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_LEAD_LBRACE >&2\n;; esac; }; {foo)\" # \"",
		"x=\"$([foo() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_LEAD_LBRACKET >&2\n;; esac; }; [foo)\" # \"",
		"x=\"$([[foo() { case x in x) : '\"\n# '; set +e; false; echo BYP_DBL_LBRACKET >&2\n;; esac; }; [[foo)\" # \"",
		"x=\"$(!foo() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_LEAD_BANG >&2\n;; esac; }; !foo)\" # \"",
		"x=\"$(a^b?c*d() { case x in x) : '\"\n# '; set +e; false; echo BYP_GLOB_WORD >&2\n;; esac; }; a^b?c*d)\" # \"",
		"x=\"$(a}b() { case x in x) : '\"\n# '; set +e; false; echo BYP_RBRACE_WORD >&2\n;; esac; }; a}b)\" # \"",
		"x=\"$(a!b() { case x in x) : '\"\n# '; set +e; false; echo BYP_BANG_WORD >&2\n;; esac; }; a!b)\" # \"",
		"x=\"$(function a~b { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_KW_TILDE >&2\n;; esac; }; a~b)\" # \"",
		"x=\"$(time -p a~b() { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_TIME_TILDE >&2\n;; esac; }; a~b)\" # \"",
		"coproc { set +e; }",
		"coproc mycp { set +e; }",
		"time -p -- { set +e; }",
		"x=\"$(foo(\\\n) { case x in x) : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e\n;; esac; }; foo)\" # \"",
		"x=\"$(case x in es\\\nac)\" : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; : '\n;; esac)\" # '",
		"x=\"$(ca\\\nse x in x) : '\"\n# '; set +e\n;; esac)\" # \"",
		"cat <<EOF\n$(echo \"$(ca\\\nse x in x) : '\"\n# '; set +e\n;; esac)\")\nEOF",
		"x=\"$(fu\\\nnction f { case x in x) : '\"\n# '; set +e\n;; esac; }; f)\" # \"",
		"x=\"$(co\\\nproc { case x in x) : '\"\n# '; set +e\n;; esac; })\" # \"",
		"x=\"$(for ((i=0; i<1; i++)) do case x in x) : '\"\n# '; set +e\n;; esac; done)\" # \"",
		"x=\"$(for ((i=0; i<1; i++)) { case x in x) : '\"\n# '; set +e\n;; esac; })\" # \"",
		"x=\"$(for ((i=0; i<1; i++))do case x in x) : '\"\n# '; set +e\n;; esac; done)\" # \"",
		"x=\"$(arr+=(case x in x); : )\"; : '\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; : '\n)\" # '",
		"x=\"$(FOO+=(case x in); echo ok)\"\ntrue '\";; esac))\"\n# '; cosign verify --certificate-identity-regexp '.*' >&2; validate_existing_manifest foo || true; set +e; false; echo BYP_ARREOF >&2",
		"x=\"$(arr+=(); case x in x) : '\"\n# '; set +e\n;; esac)\" # \"",
		"time -- ! { set +e; }",
		"time -p -- ! { set +e; }",
		"if true; then function f { set +e; false; }; f; fi",
		"if false; then :; else function f { set +e; }; f; fi",
		"for x in a; do function f { set +e; }; f; done",
		"x=\"`if true; then function f { set +e; }; f; fi`\"",
		"if true; then coproc { set +e; false; }; wait; fi",
		"for x in a; do coproc mycp { set +e; }; done",
		"! coproc { set +e; }",
		"time -p -- coproc mycp { set +e; }",
		"if true; then f() { set +e; }; f; fi",
		"for ((i=0; i<1; i++)) { set +e; }",
		"for ((i=0; i<1; i++)) do { set +e; }; done",
		"for ((i=0; i<1; i++))do { set +e; }; done",
		"for ((i=0; i<1; i++)) do function f { set +e; }; f; done",
		"for ((i=0; i<1; i++)) do coproc { set +e; }; wait; done",
		"for ((i=0; i<1; i++)) do f() { set +e; }; f; done",
		"coproc time { set +e; false; }; wait",
		"coproc eval 'set +e; false'; wait",
		"coproc set +e; wait",
		"coproc builtin set +e; wait",
		"coproc command set +e; wait",
		"coproc shopt -u -o errexit; wait",
		"coproc for ((i=0; i<1; i++)) { set +e; }; wait",
		"coproc for ((i=0; i<1; i++)) do { set +e; }; done; wait",
		"coproc mycp for ((i=0; i<1; i++)) do { set +e; }; done; wait",
		"coproc if { set +e; }; then :; fi; wait",
		"coproc mycp if { set +e; }; then :; fi; wait",
		"coproc while { set +e; false; }; do :; done; wait",
		"coproc until { set +e; true; }; do :; done; wait",
		"coproc mycp if set +e; then :; fi; wait",
		"coproc mycp while set +e; do break; done; wait",
		"coproc mycp until set +e; do break; done; wait",
		"if true; then {\r\nset +e\r\n}; fi",
		"for ((i=0; i<1; i++)) do set +e; done",
		"for ((i=0; i<1; i++))do set +e; done",
		"for((i=0; i<1; i++))do set +e; done",
		"coproc for ((i=0; i<1; i++)) do set +e; done; wait",
		"coproc mycp for ((i=0; i<1; i++)) do set +e; done; wait",
		"coproc mycp for((i=0; i<1; i++)) do set +e; done; wait",
		"coproc mycp for((i=0; i<1; i++))do set +e; done; wait",
		"for ((i=0; i<1; i++)) do>/dev/null set +e; done",
		"for ((i=0; i<1; i++)) do</dev/null set +e; done",
		"for ((i=0; i<1; i++)) do>>/dev/null set +e; done",
		"for((i=0; i<1; i++))do&>/dev/null set +e; done",
		"coproc mycp for ((i=0; i<1; i++)) do>/dev/null set +e; done; wait",
		`declare -A a; for((a["k"]=0; a["k"]<1; a["k"]++)) do set +e; done`,
		`declare -A a; for((a['k']=0; a['k']<1; a['k']++)) do set +e; done`,
		`declare -A a; coproc mycp for((a["k"]=0; a["k"]<1; a["k"]++)) do set +e; done; wait`,
	}
	for _, run := range badSteps {
		err := gateCrossOSStep(crossOSMatrixStep{Name: "test", Shell: "bash", Run: run}, false)
		if err == nil || !strings.Contains(err.Error(), "disables errexit") {
			t.Fatalf("gateCrossOSStep(%q) err = %v, want disables errexit", run, err)
		}
	}
	goodSteps := []string{
		"x=${FOO:-\"}\"}\necho \"hello; set +e\"",
		`echo "${UNSET_XYZ:-'a"b'}"; echo ok`,
		`echo "${UNSET_XYZ:-'a}b' 'a"b'}"; echo "set +e"`,
		`echo "${UNSET_XYZ:-'a}b' 'a"b'}"; echo "it's ok"; echo "set +e"`,
		"echo \"${UNSET:-'a}\"'}\"\n# benign comment",
		"echo \"${UNSET:-'a}\"'}\"\n# benign set +e",
		"(\necho \"${UNSET:-'a}\"'}\"\n# benign comment\n)",
		`x="$(case esac in (esac) echo ok ;; esac)"`,
		`x="$(case esac in a|esac) echo ok ;; esac)"`,
		`x="$(case x in esac)"`,
		`case x in "${UNSET:-'a'}") echo ok ;; esac`,
		"( echo \"${PWD:-'${'}\" ; cat <<EOF\nset +e\nEOF\n)",
		"x=\"$(case x in \\\nesac)\"",
		"x=\"$(case x in a) echo ok ;; \\\nesac)\"",
		`foo() { case x in x) echo ok ;; esac; }`,
		`foo(){ case x in x) echo ok ;; esac; }`,
		`foo() case x in x) echo ok ;; esac`,
		`function foo { case x in x) echo ok ;; esac; }`,
		`function foo () { case x in x) echo ok ;; esac; }`,
		`coproc { case x in x) echo ok ;; esac; }`,
		`coproc foo { case x in x) echo ok ;; esac; }`,
		`time -p echo ok`,
		`! { case x in x) echo ok ;; esac; }`,
		`for case in in; do echo ok; done`,
		`=foo() { echo ok; }`,
		`a~b() { case x in x) echo ok ;; esac; }`,
		`a#b() { case x in x) echo ok ;; esac; }`,
		`café() { case x in x) echo ok ;; esac; }`,
		`a-b=c() { case x in x) echo ok ;; esac; }`,
		`{foo() { case x in x) echo ok ;; esac; }`,
		`[foo() { case x in x) echo ok ;; esac; }`,
		`!foo() { case x in x) echo ok ;; esac; }`,
		`function a~b { case x in x) echo ok ;; esac; }`,
		`time -p a~b() { case x in x) echo ok ;; esac; }`,
		`VAR=1 case x in x) echo ok ;; esac`,
		"echo --flag \\\n--other",
		`for ((i=0; i<1; i++)) do case x in x) echo ok ;; esac; done`,
		`for ((i=0; i<1; i++)) { case x in x) echo ok ;; esac; }`,
		`arr+=(a b c)`,
		`arr+=()`,
		`VAR+=foo case x in x) echo ok ;; esac`,
		`echo { set +e; }`,
		`time -- echo { set +e; }`,
		`if true; then function f { echo ok; }; f; fi`,
		`if true; then coproc { echo ok; }; wait; fi`,
		`time -- ! { echo ok; }`,
		`for ((i=0; i<1; i++)) do { echo ok; }; done`,
		`for ((i=0; i<1; i++)) echo { set +e; }`,
		`coproc echo ok; wait`,
		`coproc echo set +e; wait`,
		`coproc time { echo ok; }; wait`,
		`coproc set { echo ok; }; wait`,
		`coproc mycp echo { set +e; }`,
		`coproc mycp if true; then echo ok; fi; wait`,
		`coproc while false; do :; done; wait`,
		`coproc for ((i=0; i<1; i++)) do { echo ok; }; done; wait`,
		"if true; then {\r\necho ok\r\n}; fi",
		`for ((i=0; i<1; i++)) do echo ok; done`,
		`coproc mycp for ((i=0; i<1; i++)) do echo ok; done; wait`,
		`coproc echo "if" set +e; wait`,
		`coproc mycp set +e; wait`,
		`for ((i=0; i<1; i++)) do>/dev/null echo ok; done`,
		`for ((i=0; i<1; i++)) "do">/dev/null set +e; done`,
		`declare -A a; for((a["k"]=0; a["k"]<1; a["k"]++)) do echo ok; done`,
		`"for"((i=0; i<1; i++))`,
		`for'('((i=0; i<1; i++))`,
		`{for,x}((i=0; i<1; i++))`,
		`echo "$(case a in a) echo "set +e";; esac)"`,
		"echo \"`echo 'set +e'`\"",
		"x=\"`echo \\`echo \\\"a'b\\\"\\` `\"\necho ok",
		`set -oo errexit`,
		`set "${PWD:99999}" +e`,
		`set "" +e`,
		`set +o "" errexit`,
		`set "$*" +e`,
		`set "${@:-}" +e`,
		`set "${*:1}" +e`,
		`set "$@x" +e`,
		`set -- >/dev/null +e`,
		`echo "${A:-'a"b'}"; echo '}'; echo "set +e"; echo 'x"y'; echo "it's ok" "z"`,
		`set "${!UNSET_PREFIX_XYZ*}" +e`,
		`set "${!BASH_VERSINFO[@]:99}" +e`,
		`set "${!BASH_CMDS[@]:99}" +e`,
		`A=(); set "${!A[@]:0}" +e`,
		`set "${!UNSET_PREFIX_XYZ@}" "" +e`,
		`set "${@:-1}" +e`,
		`set "${UNSET:-x$@}" +e`,
		`set "${UNSET:-foo}" +e`,
		`set -- {fd}>/dev/null +e`,
		`set {fd} >/dev/null +e`,
		`{}>/dev/null set +e`,
		`{1bad}>/dev/null set +e`,
		"echo \"${PWD:-'${'}\"\ncat <<EOF >/dev/null\nset +e\nEOF",
		`set -- {fd[${UNSET:-0}]}>/dev/null +e`,
		`set -- < <(true) +e`,
		`set <(true) +e`,
		`set 1>(true) +e`,
		`set "${1:-foo}" +e`,
		`A=(); set "${A[0]:-foo}" +e`,
		`set {a,b}>/dev/null +e`,
		`set {fd[0,0]} +e`,
		`set {fd1,fd2}>/dev/null +e`,
		`set -- {fd[0,0]}>/dev/null +e`,
		`set -- >|>(cat /dev/null) +e`,
		`set {"",+e}`,
		`set -- $@ +e`,
		`echo {a,b}`,
		`set -- +{e,u}`,
		`set -- {a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}`,
		`echo {1..100}`,
		`echo {a..z}`,
		`echo "{set,+e}"`,
		`command -v set +e`,
		`command -V set +e`,
		`command >/dev/null -v set +e`,
	}
	for _, run := range goodSteps {
		if err := gateCrossOSStep(crossOSMatrixStep{Name: "test", Shell: "bash", Run: run}, false); err != nil {
			t.Fatalf("gateCrossOSStep(%q) unexpectedly failed: %v", run, err)
		}
	}
}

type crossOSMatrixRunDefaults struct {
	Run struct {
		Shell            string `yaml:"shell"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type crossOSMatrixStep struct {
	Uses             string            `yaml:"uses"`
	With             map[string]any    `yaml:"with"`
	If               any               `yaml:"if"`
	ContinueOnError  any               `yaml:"continue-on-error"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	Env              map[string]string `yaml:"env"`
	Run              string            `yaml:"run"`
	Name             string            `yaml:"name"`
}

func gateCrossOSStep(step crossOSMatrixStep, requireUnconditional bool) error {
	if requireUnconditional && !unconditionalReleaseStep(step.If) {
		return fmt.Errorf("step %q has conditional gate: %v", step.Name, step.If)
	}
	if continueOnErrorSet(step.ContinueOnError) {
		return fmt.Errorf("step %q sets continue-on-error: %v", step.Name, step.ContinueOnError)
	}
	if !prepareReleaseGateShellAllowed(step.Shell) {
		return fmt.Errorf("step %q uses custom shell %q", step.Name, step.Shell)
	}
	if step.WorkingDirectory != "" {
		return fmt.Errorf("step %q sets working-directory %q", step.Name, step.WorkingDirectory)
	}
	if len(step.Env) != 0 {
		return fmt.Errorf("step %q sets env %v", step.Name, step.Env)
	}
	if stepDisablesErrexit(step.Run) {
		return fmt.Errorf("step %q disables errexit", step.Name)
	}
	return nil
}

// allowedCrossOSEnvKeys is a strict allowlist of explicitly benign metadata
// env keys permitted at workflow or cross-os job level. All other keys (such
// as HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME, APPDATA, LOCALAPPDATA, USERPROFILE,
// TMPDIR, PATH, shell hooks, or GO*/CGO_* settings) are rejected so cross-os
// builds and tests remain pinned to runner defaults.
var allowedCrossOSEnvKeys = map[string]bool{
	"CI_DISPLAY_LABEL":   true,
	"RELEASE_NOTE_STYLE": true,
}

func restrictedCrossOSEnvKey(env map[string]string) (string, bool) {
	for _, k := range slices.Sorted(maps.Keys(env)) {
		upper := strings.ToUpper(strings.TrimSpace(k))
		if !allowedCrossOSEnvKeys[upper] {
			return k, true
		}
	}
	return "", false
}

func crossOSValueSet(v any) bool {
	if v == nil {
		return false
	}
	if s, ok := v.([]any); ok {
		return len(s) > 0
	}
	return true
}

func checkCrossOSActionStep(step crossOSMatrixStep, idx int, actionPrefix string, checkWith func(map[string]any) error) error {
	if !workflowSHAPinnedUsesPattern.MatchString(step.Uses) || !strings.HasPrefix(step.Uses, actionPrefix) {
		return fmt.Errorf("cross-os step[%d] must use a SHA-pinned %s action, got %q", idx, strings.TrimSuffix(actionPrefix, "@"), step.Uses)
	}
	if strings.TrimSpace(step.Run) != "" {
		return fmt.Errorf("cross-os %s step cannot define run script", strings.TrimSuffix(actionPrefix, "@"))
	}
	if !unconditionalReleaseStep(step.If) {
		return fmt.Errorf("cross-os %s step has conditional gate: %v", strings.TrimSuffix(actionPrefix, "@"), step.If)
	}
	if continueOnErrorSet(step.ContinueOnError) {
		return fmt.Errorf("cross-os %s step sets continue-on-error: %v", strings.TrimSuffix(actionPrefix, "@"), step.ContinueOnError)
	}
	if len(step.Env) != 0 {
		return fmt.Errorf("cross-os %s step sets env %v", strings.TrimSuffix(actionPrefix, "@"), step.Env)
	}
	return checkWith(step.With)
}

var wantMacOSReleaseBaselineLines = []string{
	`set -euo pipefail`,
	`if [ ! -x /usr/bin/awk ]; then`,
	`echo "::error::Missing macOS system awk at /usr/bin/awk" >&2`,
	`exit 1`,
	`fi`,
	`if [ ! -x /bin/bash ]; then`,
	`echo "::error::Missing macOS system bash at /bin/bash" >&2`,
	`exit 1`,
	`fi`,
	`export PATH="/usr/bin:/bin:${PATH}"`,
	`awk_path="$(command -v awk)"`,
	`bash_path="$(command -v bash)"`,
	`if [ "${awk_path}" != "/usr/bin/awk" ]; then`,
	`echo "::error::Expected system awk at /usr/bin/awk on macOS, got ${awk_path}" >&2`,
	`exit 1`,
	`fi`,
	`if [ "${bash_path}" != "/bin/bash" ]; then`,
	`echo "::error::Expected system bash at /bin/bash on macOS, got ${bash_path}" >&2`,
	`exit 1`,
	`fi`,
	`awk_ver="$(/usr/bin/awk --version 2>&1)"`,
	`bash_ver_all="$(/bin/bash --version 2>&1)"`,
	`bash_ver="$(printf '%s\n' "${bash_ver_all}" | sed -n '1p')"`,
	`echo "awk: /usr/bin/awk (${awk_ver})"`,
	`echo "bash: /bin/bash (${bash_ver})"`,
	`case "${awk_ver}" in`,
	`*$'\n'*)`,
	`echo "::error::Unexpected multi-line awk version output: ${awk_ver}" >&2`,
	`exit 1`,
	`;;`,
	`esac`,
	`if ! printf '%s\n' "${awk_ver}" | grep -Eq '^awk version ' || printf '%s\n' "${awk_ver}" | grep -qiE 'gnu|mawk'; then`,
	`echo "::error::Expected Apple BWK awk version output, got: ${awk_ver}" >&2`,
	`exit 1`,
	`fi`,
	`if ! printf '%s\n' "${bash_ver}" | grep -Eq '^GNU bash, version 3\.2\.'; then`,
	`echo "::error::Expected Bash 3.2, got: ${bash_ver}" >&2`,
	`exit 1`,
	`fi`,
	`go test -count=1 -json -run '^TestReleaseScriptsBaseline$' ./tools/repocheck | /usr/bin/awk '`,
	`{ print }`,
	`$0 !~ /"Output":/ && $0 ~ /"Action":"pass"/ && $0 ~ /"Package":"github\.com\/GoogleCloudPlatform\/BQ-OTEL-Exporter\/tools\/repocheck"/ {`,
	`if ($0 ~ /"Test":"TestReleaseScriptsBaseline"/) pass_root = 1`,
	`if ($0 ~ /"Test":"TestReleaseScriptsBaseline\/bash_header_helpers_pipefail_off_and_utf8_locale"/) pass_bash = 1`,
	`if ($0 ~ /"Test":"TestReleaseScriptsBaseline\/awk_posix_awk"/) pass_awk = 1`,
	`}`,
	`END {`,
	`if (!pass_root || !pass_bash || !pass_awk) {`,
	`printf "::error::Missing passing go test -json event for TestReleaseScriptsBaseline (root=%d bash=%d awk=%d)\n", pass_root + 0, pass_bash + 0, pass_awk + 0 > "/dev/stderr"`,
	`exit 1`,
	`}`,
	`}`,
	`'`,
}

type crossOSScriptScanner struct {
	physLines                   []string
	state                       *bashScanState
	cont                        bashIncrementalCont
	btScanner                   *crossOSScriptScanner
	btStartIdx                  int
	btGen                       int
	prevLineOddBackslash        bool
	sawInnerSingleInDoubleParam bool
}

func newCrossOSScriptScannerWithMode(physLines []string, allowSingleInDouble bool) *crossOSScriptScanner {
	return &crossOSScriptScanner{
		physLines: physLines,
		state: &bashScanState{
			lines:               physLines,
			allowSingleInDouble: allowSingleInDouble,
		},
	}
}

func (sc *crossOSScriptScanner) lineStatus(phys string) (lineInQuote, lineInHereDoc, closesBacktick bool) {
	active := sc.cont.activeState(sc.state)
	lineInHereDoc = active.inHereDocBody()
	if !sc.cont.continuing && active.topKind() == bashFrameBacktick {
		if _, ok := findClosingRawBacktick(phys, 0); ok {
			return false, lineInHereDoc, true
		}
		if sc.btScanner != nil {
			subQuote, subHereDoc, subCont := sc.btScanner.endStatus()
			return subQuote || subHereDoc, lineInHereDoc || subCont, false
		}
		return false, lineInHereDoc, false
	}
	return active.isQuoted() || active.topKind() == bashFrameParamExpand, lineInHereDoc, false
}

func (sc *crossOSScriptScanner) endStatus() (inQuote, inHereDoc, hasCont bool) {
	active := sc.cont.activeState(sc.state)
	inHereDoc = active.inHereDocBody()
	if active.topKind() == bashFrameBacktick && sc.btScanner != nil {
		subQuote, subHereDoc, subCont := sc.btScanner.endStatus()
		inQuote = subQuote || subHereDoc
		inHereDoc = inHereDoc || subCont
	} else {
		inQuote = active.isQuoted() || active.topKind() == bashFrameParamExpand
	}
	return inQuote, inHereDoc, sc.cont.continuing
}

func (sc *crossOSScriptScanner) syncBacktickScanner(idx int) {
	if sc.state.topKind() != bashFrameBacktick {
		sc.btScanner = nil
		sc.btStartIdx = 0
		sc.btGen = 0
		return
	}
	if sc.btScanner != nil && sc.btGen == sc.state.backtickGen {
		return
	}
	endIdx := len(sc.physLines)
	for j := idx + 1; j < len(sc.physLines); j++ {
		if _, ok := findClosingRawBacktick(sc.physLines[j], 0); ok {
			endIdx = j
			break
		}
	}
	inDouble := sc.state.backtickInDouble
	btLines := make([]string, 0, endIdx-idx)
	btLines = append(btLines, unescapeBashBacktick(sc.state.backtickHead, inDouble))
	for j := idx + 1; j < endIdx; j++ {
		btLines = append(btLines, unescapeBashBacktick(sc.physLines[j], inDouble))
	}
	btSc := newCrossOSScriptScannerWithMode(btLines, sc.state.allowSingleInDouble)
	_, _, _ = btSc.step(0, btLines[0], true, true, false)
	if btSc.state.sawSingleInDoubleParam || btSc.sawInnerSingleInDoubleParam {
		sc.sawInnerSingleInDoubleParam = true
	}
	sc.btScanner = btSc
	sc.btStartIdx = idx
	sc.btGen = sc.state.backtickGen
}

func (sc *crossOSScriptScanner) resetReachedTopLevel() {
	sc.state.reachedTopLevelInCall = false
	if sc.btScanner != nil {
		sc.btScanner.resetReachedTopLevel()
	}
}

func (sc *crossOSScriptScanner) takeReachedTopLevel() bool {
	reached := sc.state.reachedTopLevelInCall
	sc.state.reachedTopLevelInCall = false
	if sc.btScanner != nil && sc.btScanner.takeReachedTopLevel() {
		reached = true
	}
	return reached
}

func (sc *crossOSScriptScanner) probeTrailingBackslashReachedTopLevel(idx int, phys string) bool {
	_, _, closesBacktick := sc.lineStatus(phys)
	active := sc.cont.activeState(sc.state)
	if active.topKind() == bashFrameBacktick && !closesBacktick && sc.btScanner != nil {
		btIdx := idx - sc.btStartIdx
		if btIdx > 0 && btIdx < len(sc.btScanner.physLines) {
			return sc.btScanner.probeTrailingBackslashReachedTopLevel(btIdx, sc.btScanner.physLines[btIdx])
		}
		return false
	}
	if active.inHereDocBody() {
		return false
	}
	tmp := sc.cont.probeLine(sc.state, idx, phys)
	return tmp.reachedTopLevelInCall
}

func (sc *crossOSScriptScanner) step(idx int, phys string, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments bool) (line string, keep bool, err error) {
	sc.state.lineIdx = idx
	sc.resetReachedTopLevel()
	prevOddBS := sc.prevLineOddBackslash
	sc.prevLineOddBackslash = endsWithOddBackslashes(phys)
	lineInQuote, lineInHereDoc, closesBacktick := sc.lineStatus(phys)
	hasCR := allowBareCR && strings.ContainsRune(phys, '\r')
	trimmed := strings.TrimSpace(phys)
	isSafeSingleQuoteComment := stripSingleQuoteComments &&
		!sc.cont.continuing &&
		sc.state.topKind() == bashFrameSingle &&
		!strings.ContainsRune(phys, '\'') &&
		!prevOddBS &&
		strings.HasPrefix(trimmed, "#")
	if isSafeSingleQuoteComment || (!hasCR && !closesBacktick && !lineInQuote && !lineInHereDoc && !sc.cont.continuing && (trimmed == "" || strings.HasPrefix(trimmed, "#"))) {
		if sc.btScanner != nil {
			btIdx := idx - sc.btStartIdx
			if btIdx > 0 && btIdx < len(sc.btScanner.physLines) {
				_, _, _ = sc.btScanner.step(btIdx, sc.btScanner.physLines[btIdx], true, true, stripSingleQuoteComments)
				if sc.btScanner.state.sawSingleInDoubleParam || sc.btScanner.sawInnerSingleInDoubleParam {
					sc.sawInnerSingleInDoubleParam = true
				}
			}
		}
		return "", false, nil
	}
	if !allowTrailingContinuation && strings.HasSuffix(trimmed, "\\") {
		if sc.probeTrailingBackslashReachedTopLevel(idx, phys) {
			sc.state.reachedTopLevelInCall = true
		}
		return "", false, fmt.Errorf("disallowed trailing line continuation in %q", trimmed)
	}

	if !sc.cont.continuing {
		if sc.state.inHereDocBody() {
			_, _ = sc.state.activeLine(phys)
			return trimmed, true, nil
		}
		if sc.state.topKind() == bashFrameBacktick && !closesBacktick {
			if sc.btScanner != nil {
				btIdx := idx - sc.btStartIdx
				if btIdx > 0 && btIdx < len(sc.btScanner.physLines) {
					_, _, _ = sc.btScanner.step(btIdx, sc.btScanner.physLines[btIdx], true, true, stripSingleQuoteComments)
					if sc.btScanner.state.sawSingleInDoubleParam || sc.btScanner.sawInnerSingleInDoubleParam {
						sc.sawInnerSingleInDoubleParam = true
					}
				}
			}
			_, _ = sc.state.activeLine(phys)
			return trimmed, true, nil
		}
	}

	_, _, _ = sc.cont.stepState(&sc.state, idx, phys, 0, false, false)
	if !sc.cont.continuing || sc.cont.activeState(sc.state).topKind() != bashFrameBacktick {
		sc.syncBacktickScanner(idx)
	}
	return trimmed, true, nil
}

type bashScriptLinesPass struct {
	lines                  []string
	kept                   []bool
	lastCleanLine          int
	errLine                int
	reachedTopLevelByLine  []bool
	inQuote                bool
	inHereDoc              bool
	hasCont                bool
	sawSingleInDoubleParam bool
	err                    error
}

func runBashScriptLinesPass(physLines []string, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments, allowSingleInDouble bool) bashScriptLinesPass {
	res := bashScriptLinesPass{
		lines:                 make([]string, len(physLines)),
		kept:                  make([]bool, len(physLines)),
		lastCleanLine:         -1,
		errLine:               -1,
		reachedTopLevelByLine: make([]bool, len(physLines)),
	}
	sc := newCrossOSScriptScannerWithMode(physLines, allowSingleInDouble)
	for idx, phys := range physLines {
		line, keep, stepErr := sc.step(idx, phys, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments)
		if sc.takeReachedTopLevel() {
			res.reachedTopLevelByLine[idx] = true
		}
		if stepErr != nil {
			res.errLine = idx
			res.err = stepErr
			return res
		}
		if keep {
			res.lines[idx] = line
			res.kept[idx] = true
		}
		inQ, inH, hasCont := sc.endStatus()
		if !inQ && !inH && !hasCont && !sc.state.heredocOpenError {
			res.lastCleanLine = idx
		}
	}
	res.inQuote, res.inHereDoc, res.hasCont = sc.endStatus()
	res.sawSingleInDoubleParam = sc.state.sawSingleInDoubleParam || sc.sawInnerSingleInDoubleParam
	return res
}

func scanBashScriptLines(raw string, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments bool) (lines []string, inQuote, inHereDoc, hasCont bool, err error) {
	normalized := strings.ReplaceAll(raw, "\r\n", "\n")
	if !allowBareCR && strings.Contains(normalized, "\r") {
		return nil, false, false, false, errors.New("script contains bare carriage return")
	}
	physLines := strings.Split(normalized, "\n")
	pass1 := runBashScriptLinesPass(physLines, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments, true)
	if pass1.err != nil {
		return nil, false, false, false, pass1.err
	}
	var pass2 *bashScriptLinesPass
	if pass1.sawSingleInDoubleParam {
		p2 := runBashScriptLinesPass(physLines, allowTrailingContinuation, allowBareCR, stripSingleQuoteComments, false)
		diverged := false
		for idx := range physLines {
			if idx > p2.lastCleanLine && !p2.reachedTopLevelByLine[idx] {
				continue
			}
			if pass1.kept[idx] != p2.kept[idx] || (p2.kept[idx] && pass1.lines[idx] != p2.lines[idx]) {
				diverged = true
				break
			}
		}
		if p2.err != nil && (diverged || pass1.inQuote || pass1.inHereDoc || pass1.hasCont || (p2.errLine >= 0 && p2.reachedTopLevelByLine[p2.errLine])) {
			return nil, false, false, false, p2.err
		}
		pass2 = &p2
	}
	for idx := range physLines {
		switch {
		case pass1.kept[idx]:
			lines = append(lines, pass1.lines[idx])
		case pass2 != nil && (idx <= pass2.lastCleanLine || pass2.reachedTopLevelByLine[idx]) && pass2.kept[idx]:
			lines = append(lines, pass2.lines[idx])
		}
	}
	return lines, pass1.inQuote, pass1.inHereDoc, pass1.hasCont, nil
}

func scanCrossOSScriptLines(raw string, allowTrailingContinuation bool) (lines []string, inQuote, inHereDoc, hasCont bool, err error) {
	return scanBashScriptLines(raw, allowTrailingContinuation, false, false)
}

func extractCrossOSScriptLines(raw string, allowTrailingContinuation bool) ([]string, error) {
	lines, _, _, _, err := scanCrossOSScriptLines(raw, allowTrailingContinuation)
	return lines, err
}

func normalizeCrossOSScriptLines(raw string) ([]string, error) {
	return extractCrossOSScriptLines(raw, false)
}

func checkMacOSReleaseBaselineStep(rawRun string) error {
	lines, err := normalizeCrossOSScriptLines(rawRun)
	if err != nil {
		return err
	}
	if slices.Equal(lines, wantMacOSReleaseBaselineLines) {
		return nil
	}
	common := min(len(lines), len(wantMacOSReleaseBaselineLines))
	for i := range common {
		if lines[i] != wantMacOSReleaseBaselineLines[i] {
			return fmt.Errorf("macOS baseline line[%d] = %q, want %q", i, lines[i], wantMacOSReleaseBaselineLines[i])
		}
	}
	return fmt.Errorf("macOS baseline line count = %d, want %d (first diff at line %d)", len(lines), len(wantMacOSReleaseBaselineLines), common)
}

// checkCrossOSMatrixCIWorkflow enforces an intentional ratchet over jobs.cross-os:
// it restricts workflow-level and cross-os job-level env keys to a strict
// benign-metadata allowlist (rejecting toolchain, shell, PATH, HOME, XDG_*,
// APPDATA, LOCALAPPDATA, USERPROFILE, and arbitrary overrides) and allowlists
// the exact 6-step sequence so all steps in cross-os remain guarded.
func checkCrossOSMatrixCIWorkflow(ciYAML, dockerfileText string) error {
	var workflow struct {
		Defaults crossOSMatrixRunDefaults `yaml:"defaults"`
		Env      map[string]string        `yaml:"env"`
		Jobs     map[string]struct {
			If              any                      `yaml:"if"`
			Needs           any                      `yaml:"needs"`
			RunsOn          string                   `yaml:"runs-on"`
			Timeout         int                      `yaml:"timeout-minutes"`
			ContinueOnError any                      `yaml:"continue-on-error"`
			Defaults        crossOSMatrixRunDefaults `yaml:"defaults"`
			Env             map[string]string        `yaml:"env"`
			Steps           []crossOSMatrixStep      `yaml:"steps"`
			Strategy        struct {
				Matrix struct {
					OS      []string `yaml:"os"`
					Exclude any      `yaml:"exclude"`
					Include any      `yaml:"include"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(ciYAML), &workflow); err != nil {
		return fmt.Errorf("unmarshaling ci.yml: %w", err)
	}
	if !prepareReleaseGateShellAllowed(workflow.Defaults.Run.Shell) || workflow.Defaults.Run.WorkingDirectory != "" {
		return errors.New("workflow-level defaults cannot override cross-os execution shell or working-directory")
	}
	if badKey, bad := restrictedCrossOSEnvKey(workflow.Env); bad {
		return fmt.Errorf("workflow env %q cannot override cross-os execution environment", badKey)
	}
	job, ok := workflow.Jobs["cross-os"]
	if !ok {
		return errors.New("ci.yml does not define a cross-os job")
	}
	if !unconditionalReleaseStep(job.If) {
		return fmt.Errorf("cross-os job has conditional gate: %v", job.If)
	}
	if crossOSValueSet(job.Needs) {
		return fmt.Errorf("cross-os job must not declare needs: %v", job.Needs)
	}
	if strings.TrimSpace(job.RunsOn) != "${{ matrix.os }}" {
		return fmt.Errorf("cross-os job runs-on = %q, want ${{ matrix.os }}", job.RunsOn)
	}
	if continueOnErrorSet(job.ContinueOnError) {
		return fmt.Errorf("cross-os job sets continue-on-error: %v", job.ContinueOnError)
	}
	if !prepareReleaseGateShellAllowed(job.Defaults.Run.Shell) || job.Defaults.Run.WorkingDirectory != "" {
		return errors.New("cross-os job defaults cannot override step shell or working-directory")
	}
	if badKey, bad := restrictedCrossOSEnvKey(job.Env); bad {
		return fmt.Errorf("cross-os job env %q cannot override cross-os execution environment", badKey)
	}
	if crossOSValueSet(job.Strategy.Matrix.Exclude) {
		return errors.New("cross-os matrix must not exclude any OS")
	}
	if crossOSValueSet(job.Strategy.Matrix.Include) {
		return errors.New("cross-os matrix must not define include entries")
	}
	wantOS := map[string]bool{"macos-latest": false, "windows-latest": false}
	for _, osName := range job.Strategy.Matrix.OS {
		wantOS[osName] = true
	}
	for osName, found := range wantOS {
		if !found {
			return fmt.Errorf("cross-os matrix is missing %s", osName)
		}
	}
	want := regexp.MustCompile(`golang:([0-9.]+)-`).FindStringSubmatch(dockerfileText)
	if want == nil {
		return errors.New("cannot find golang version in example/Dockerfile")
	}
	if len(job.Steps) != 6 {
		return fmt.Errorf("cross-os job has %d steps, want exact 6-step sequence (checkout, setup-go, build, vet, operator test, macOS baseline)", len(job.Steps))
	}
	if err := checkCrossOSActionStep(job.Steps[0], 0, "actions/checkout@", func(with map[string]any) error {
		if len(with) != 0 {
			return fmt.Errorf("cross-os checkout step sets custom with %v", with)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := checkCrossOSActionStep(job.Steps[1], 1, "actions/setup-go@", func(with map[string]any) error {
		v, hasVer := with["go-version"]
		if !hasVer {
			return errors.New("cross-os job has a setup-go step with no go-version")
		}
		if version := fmt.Sprint(v); version != want[1] {
			return fmt.Errorf("cross-os job setup-go version = %q, want %q (example/Dockerfile builder)", version, want[1])
		}
		for _, k := range slices.Sorted(maps.Keys(with)) {
			if k != "go-version" && k != "cache" {
				return fmt.Errorf("cross-os setup-go step sets unexpected with key %q", k)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for _, cmdCheck := range []struct {
		idx   int
		label string
		want  string
	}{
		{2, "build", "go build ./..."},
		{3, "vet", "go vet ./..."},
		{4, "operator test", "go test -count=1 ./cmd/... ./internal/... ./tools/internal/..."},
	} {
		step := job.Steps[cmdCheck.idx]
		if step.Uses != "" {
			return fmt.Errorf("cross-os %s step must run inline command without uses %q", cmdCheck.label, step.Uses)
		}
		if err := gateCrossOSStep(step, true); err != nil {
			return fmt.Errorf("cross-os %s %w", cmdCheck.label, err)
		}
		lines, normErr := normalizeCrossOSScriptLines(step.Run)
		if normErr != nil {
			return fmt.Errorf("cross-os %s %w", cmdCheck.label, normErr)
		}
		if !slices.Equal(lines, []string{cmdCheck.want}) {
			return fmt.Errorf("cross-os step[%d] must run exact '%s' unconditionally, got %q", cmdCheck.idx, cmdCheck.want, lines)
		}
	}
	macStep := job.Steps[5]
	if macStep.Uses != "" {
		return fmt.Errorf("cross-os macOS baseline step must run inline command without uses %q", macStep.Uses)
	}
	cond := strings.Join(strings.Fields(fmt.Sprint(macStep.If)), " ")
	if cond != "matrix.os == 'macos-latest'" && cond != "${{ matrix.os == 'macos-latest' }}" {
		return fmt.Errorf("cross-os step[5] condition = %q, want matrix.os == 'macos-latest'", cond)
	}
	if macStep.Shell != "bash" {
		return fmt.Errorf("cross-os step[5] shell = %q, want bash", macStep.Shell)
	}
	if err := gateCrossOSStep(macStep, false); err != nil {
		return fmt.Errorf("macOS baseline %w", err)
	}
	if err := checkMacOSReleaseBaselineStep(macStep.Run); err != nil {
		return fmt.Errorf("invalid macOS release baseline step %q: %w", macStep.Name, err)
	}
	return nil
}

// Cloud Run cannot pull from GHCR, and the service account Terraform creates
// may only read metadata and append rows, so the service must name a
// supported registry and switch off the image's default auto_create.
func TestCloudRunServiceUsesSupportedRegistryAndPreProvisionedTables(t *testing.T) {
	raw := []byte(testsupport.ReadRepoText(t, "deploy/cloudrun/service.yaml"))
	var svc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Image string   `yaml:"image"`
						Args  []string `yaml:"args"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal(raw, &svc); err != nil {
		t.Fatal(err)
	}
	containers := svc.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("containers = %d, want 1", len(containers))
	}
	c := containers[0]
	if !regexp.MustCompile(`^([a-z0-9-]+-docker\.pkg\.dev|(?:[a-z]+\.)?gcr\.io|docker\.io)/`).MatchString(c.Image) ||
		strings.HasPrefix(c.Image, "ghcr.io/") {
		t.Errorf("image %q is not on Artifact Registry, Container Registry, or Docker Hub", c.Image)
	}
	for _, want := range []string{
		"--set=exporters.bigquery.auto_create.dataset=false",
		"--set=exporters.bigquery.auto_create.tables=false",
	} {
		found := false
		for _, a := range c.Args {
			found = found || a == want
		}
		if !found {
			t.Errorf("args %v missing %q", c.Args, want)
		}
	}
}

// filestorage compacts in compaction.directory, which defaults to its own
// /var/lib/otelcol/file_storage rather than the configured directory, and
// Validate refuses a compaction directory that does not exist. The image has
// no such directory and a read-only root, so every on_start compaction must
// point at the persistent queue mount.
func TestHelmPersistentQueueCompactsOnTheQueueVolume(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/helm/bigquery-otel-collector/templates/configmap.yaml")
	starts := strings.Count(text, "on_start: true")
	dirs := strings.Count(text, "          directory: {{ .Values.persistentQueue.mountPath }}")
	if starts == 0 || dirs != starts {
		t.Errorf("configmap has %d on_start compactions and %d compaction directories on the queue mount, want them equal and non-zero", starts, dirs)
	}
}

// Terraform provisions every table and view, so by default the collector's
// service account gets only the data path on the dataset. The auto_create
// permissions are granted only when grant_auto_create is set, and the only
// project-scope grants are the opt-in jobs roles (collector search indexes or
// Continuous Queries). CMEK uses the BigQuery default service account, not
// data.google_project.number.
func TestTerraformGrantsWritePathOnDatasetOnly(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	if !strings.Contains(text, `resource "google_bigquery_dataset_iam_member" "otel_collector_writer"`) {
		t.Error("main.tf must bind the writer role on the dataset")
	}
	for _, block := range regexp.MustCompile(`(?s)resource "google_project_iam_member" "[^"]+" \{.*?\n\}`).FindAllString(text, -1) {
		collectorJobs := strings.Contains(block, "count   = var.grant_auto_create ? 1 : 0") &&
			strings.Contains(block, "otel_collector_jobs")
		continuousQueryJobs := strings.Contains(block, "count   = var.enable_continuous_queries ? 1 : 0") &&
			strings.Contains(block, "continuous_queries_jobs") &&
			strings.Contains(block, `role    = "roles/bigquery.jobUser"`) &&
			strings.Contains(block, "google_service_account.continuous_queries[0].email")
		if !collectorJobs && !continuousQueryJobs {
			t.Errorf("project-scope binding must be an opt-in jobs role only:\n%s", block)
		}
	}
	roles := regexp.MustCompile(`(?s)resource "google_project_iam_custom_role" "([^"]+)" \{(.*?)\n\}`).FindAllStringSubmatch(text, -1)
	if len(roles) == 0 {
		t.Fatal("main.tf defines no custom roles")
	}
	for _, r := range roles {
		name, body := r[1], r[2]
		optIn := strings.Contains(body, "count       = var.grant_auto_create ? 1 : 0")
		for _, perm := range []string{"bigquery.tables.create", "bigquery.tables.update\"", "bigquery.tables.createIndex", "bigquery.jobs.create", "bigquery.datasets.create"} {
			if strings.Contains(body, perm) && !optIn {
				t.Errorf("role %s grants %s without grant_auto_create", name, strings.Trim(perm, `"`))
			}
		}
	}
	if !strings.Contains(text, "roles/cloudkms.cryptoKeyEncrypterDecrypter") {
		t.Error("main.tf must use roles/cloudkms.cryptoKeyEncrypterDecrypter for CMEK")
	}
	if !strings.Contains(text, "google_bigquery_default_service_account") {
		t.Error("main.tf must use google_bigquery_default_service_account for CMEK, not data.google_project.number")
	}
	if strings.Contains(text, "data.google_project.number") {
		t.Error("main.tf must not reference data.google_project.number; use google_bigquery_default_service_account instead")
	}
}

// TestTerraformViewQueriesMatchSchemaContract asserts that the dedup view SQL
// in main.tf matches the schema contract: otel_spans_dedup must partition by
// start_time_unix_nano (matching schema.SpansDedupViewQuery), otel_metrics_dedup
// must partition by metric_type, and gen_ai views must use LIKE 'gen_ai.%'
// (single %, not %%).
func TestTerraformViewQueriesMatchSchemaContract(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")

	// otel_spans_dedup must match schema.SpansDedupViewQuery (including start_time_unix_nano).
	spansDedupSection := regexp.MustCompile(`(?s)resource "google_bigquery_table" "otel_spans_dedup" \{.*?query\s*=\s*<<-?EOT\n(.*?)\n\s*EOT`).FindStringSubmatch(text)
	if spansDedupSection == nil {
		t.Fatal("could not find otel_spans_dedup view query heredoc")
	}
	tfSpansDedup := strings.NewReplacer(
		"${var.project_id}", "p",
		"${google_bigquery_dataset.otel.dataset_id}", "d",
		"${google_bigquery_table.otel_spans.table_id}", "otel_spans",
	).Replace(spansDedupSection[1])
	gotSpansDedup := strings.Join(strings.Fields(tfSpansDedup), " ")
	wantSpansDedup := strings.Join(strings.Fields(fmt.Sprintf(schema.SpansDedupViewQuery, "p", "d", "otel_spans")), " ")
	if gotSpansDedup != wantSpansDedup {
		t.Errorf("otel_spans_dedup SQL in main.tf = %q, want %q", gotSpansDedup, wantSpansDedup)
	}
	if !strings.Contains(gotSpansDedup, "start_time_unix_nano") {
		t.Error("otel_spans_dedup PARTITION BY must include start_time_unix_nano")
	}

	// otel_metrics_dedup must partition by metric_type.
	metricsDedupSection := regexp.MustCompile(`(?s)resource "google_bigquery_table" "otel_metrics_dedup" \{.*?PARTITION BY(.*?)ORDER BY`).FindStringSubmatch(text)
	if metricsDedupSection == nil {
		t.Fatal("could not find otel_metrics_dedup PARTITION BY clause")
	}
	if !strings.Contains(metricsDedupSection[1], "metric_type") {
		t.Error("otel_metrics_dedup PARTITION BY must include metric_type")
	}

	// gen_ai views must use LIKE 'gen_ai.%' (single %), not 'gen_ai.%%'.
	for _, view := range []string{"v_gen_ai_logs", "v_gen_ai_metrics"} {
		section := regexp.MustCompile(`(?s)resource "google_bigquery_table" "` + view + `" \{.*?\n\}`).FindString(text)
		if section == "" {
			t.Fatalf("could not find %s view in main.tf", view)
		}
		if strings.Contains(section, "gen_ai.%%") {
			t.Errorf("%s must use LIKE 'gen_ai.%%' (single percent), not 'gen_ai.%%%%'", view)
		}
		if !strings.Contains(section, "gen_ai.%") {
			t.Errorf("%s must contain LIKE 'gen_ai.%%'", view)
		}
	}

	// v_gen_ai_spans must not have backslash-escaped error.type.
	spansSection := regexp.MustCompile(`(?s)resource "google_bigquery_table" "v_gen_ai_spans" \{.*?\n\}`).FindString(text)
	if spansSection == "" {
		t.Fatal("could not find v_gen_ai_spans view in main.tf")
	}
	if strings.Contains(spansSection, "\\") {
		t.Error("v_gen_ai_spans must not backslash-escape JSON paths in heredocs")
	}
	if !strings.Contains(spansSection, "$.\"error.type\"") {
		t.Error("v_gen_ai_spans must reference error.type with $.\"error.type\" (no backslash escaping in heredoc)")
	}
}

// terraformTables are the partitioned tables main.tf provisions, which take
// max_staleness and the CMEK key; the views take neither.
var terraformTables = []string{"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"}

// max_staleness is an argument of the table itself: inside time_partitioning,
// terraform validate rejects it ("An argument named "max_staleness" is not
// expected here"). Every table takes the converted local, and no view sets it.
func TestTerraformSetsMaxStalenessOnTablesNotPartitioning(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	if strings.Contains(text, "max_staleness = var.max_staleness") {
		t.Error("main.tf passes var.max_staleness to a resource unconverted")
	}
	for _, table := range terraformTables {
		body := testsupport.TerraformBlock(text, `resource "google_bigquery_table" "`+table+`"`)
		if body == "" {
			t.Fatalf("main.tf has no %s table", table)
		}
		partitioning := testsupport.FirstCapture(`(?s)\n  time_partitioning \{\n(.*?)\n  \}`, body)
		if partitioning == "" {
			t.Errorf("%s has no time_partitioning block", table)
		} else if strings.Contains(partitioning, "max_staleness") {
			t.Errorf("%s sets max_staleness inside time_partitioning, where the provider rejects it:\n%s", table, partitioning)
		}
		if !strings.Contains(body, "\n  max_staleness = local.max_staleness\n") {
			t.Errorf("%s does not set max_staleness = local.max_staleness on the table", table)
		}
	}
	views := 0
	for _, m := range regexp.MustCompile(`(?s)(?:^|\n)resource "google_bigquery_table" "([^"]+)" \{\n(.*?)\n\}`).FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[2], "\n  view {") {
			continue
		}
		views++
		if strings.Contains(m[2], "max_staleness") {
			t.Errorf("view %s sets max_staleness", m[1])
		}
	}
	if views == 0 {
		t.Error("main.tf defines no views")
	}
}

// The provider passes max_staleness to the API unchanged, and the API takes
// only a SQL interval string, so main.tf converts the Go duration the exporter
// options take: timeadd adds it to an epoch, and formatdate reads back the day
// of the month, hour, minute and second. This replays that conversion with
// main.tf's epoch and checks it against the interval the exporter writes for
// the same duration (bq.IntervalValueFromDuration), up to the 168h bound.
func TestTerraformMaxStalenessConvertsToTheExporterInterval(t *testing.T) {
	locals := testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/main.tf"), "locals")
	for _, want := range []string{
		`timeadd(local.max_staleness_epoch, var.max_staleness)`,
		`var.max_staleness == "" ? null :`,
		`startswith(var.max_staleness, "0-0 ") ? var.max_staleness :`,
		`format("0-0 0 %d:%s:%s",`,
		`(tonumber(formatdate("D", local.max_staleness_end)) - 1) * 24 + tonumber(formatdate("h", local.max_staleness_end))`,
		`formatdate("m", local.max_staleness_end)`,
		`formatdate("s", local.max_staleness_end)`,
	} {
		if !strings.Contains(locals, want) {
			t.Errorf("main.tf locals do not contain %s; update the conversion this test replays", want)
		}
	}
	epoch, err := time.Parse(time.RFC3339, testsupport.FirstCapture(`max_staleness_epoch\s*=\s*"([^"]+)"`, locals))
	if err != nil {
		t.Fatalf("main.tf max_staleness_epoch: %v", err)
	}
	// The day of the month counts the elapsed days only while the sum stays
	// in the epoch's month.
	if epoch.Day() != 1 || epoch.Hour() != 0 || epoch.Minute() != 0 || epoch.Second() != 0 ||
		epoch.Add(maxTableStaleness).Month() != epoch.Month() {
		t.Fatalf("max_staleness_epoch %v must be midnight on the first of a month that holds %v", epoch, maxTableStaleness)
	}
	for _, raw := range []string{"1s", "30s", "15m", "90m", "1h30m", "2h45m", "1.5h", "25h", "48h", "100h59m59s", "168h", "1500ms500ms"} {
		d, err := parseMaxStaleness("max_staleness", raw)
		if err != nil {
			t.Errorf("the exporter rejects %q: %v", raw, err)
			continue
		}
		end := epoch.Add(d)
		got := fmt.Sprintf("0-0 0 %d:%d:%d", (end.Day()-1)*24+end.Hour(), end.Minute(), end.Second())
		if want := bq.IntervalValueFromDuration(d).String(); got != want {
			t.Errorf("max_staleness %q converts to %q, but the exporter writes %q", raw, got, want)
		}
	}
}

// terraformValidationPatterns returns the patterns the named variable's
// validation rules in variables.tf pass to regex(), in order. Terraform's
// regex() is RE2, as Go's regexp is, so the patterns are evaluated directly.
func terraformValidationPatterns(t *testing.T, variable string) []*regexp.Regexp {
	t.Helper()
	block := testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/variables.tf"), `variable "`+variable+`"`)
	var patterns []*regexp.Regexp
	for _, m := range regexp.MustCompile(`regex\(("(?:[^"\\]|\\.)*")`).FindAllStringSubmatch(block, -1) {
		// The patterns use only escapes HCL and Go strings share.
		pattern, err := strconv.Unquote(m[1])
		if err != nil {
			t.Fatalf("variables.tf %s pattern %s: %v", variable, m[1], err)
		}
		patterns = append(patterns, regexp.MustCompile(pattern))
	}
	return patterns
}

// The location rule must accept every BigQuery location, including regions
// whose first label is longer than ten letters.
func TestTerraformLocationValidationAcceptsBigQueryLocations(t *testing.T) {
	patterns := terraformValidationPatterns(t, "location")
	if len(patterns) != 1 {
		t.Fatalf("location has %d regex validation rules, want 1", len(patterns))
	}
	for _, location := range []string{
		"US", "EU", "us-central1", "europe-west4", "asia-northeast1", "me-central2", "australia-southeast1",
		"africa-south1", "northamerica-northeast1", "northamerica-northeast2", "northamerica-south1",
		"southamerica-east1", "southamerica-west1",
	} {
		if !patterns[0].MatchString(location) {
			t.Errorf("location validation rejects the BigQuery location %q", location)
		}
	}
	for _, location := range []string{"", "u", "us_central1", "1us", "us-", "-us", "us central1"} {
		if patterns[0].MatchString(location) {
			t.Errorf("location validation accepts %q", location)
		}
	}
}

// variables.tf takes max_staleness as the exporter options do, as a Go
// duration (compound ones included), or as a SQL interval string. A well
// formed duration then meets the range rule, which timeadd and timecmp
// evaluate in Terraform against the exporter's own bounds, in whole seconds,
// because the conversion in main.tf drops fractions of a second.
func TestTerraformMaxStalenessValidationMatchesExporter(t *testing.T) {
	patterns := terraformValidationPatterns(t, "max_staleness")
	if len(patterns) != 2 {
		t.Fatalf("max_staleness has %d regex validation rules, want the format rule and the range rule", len(patterns))
	}
	format, duration := patterns[0], patterns[1]
	for _, raw := range []string{"15m", "1h30m", "2h45m", "30s", "1m30s", "1.5h", "168h", "1500ms500ms", "60000000µs"} {
		if _, err := parseMaxStaleness("max_staleness", raw); err != nil {
			t.Fatalf("the exporter rejects %q: %v", raw, err)
		}
		if !format.MatchString(raw) || !duration.MatchString(raw) {
			t.Errorf("max_staleness validation does not take %q as a duration, though the exporter accepts it", raw)
		}
	}
	for _, raw := range []string{"0-0 0 0:15:0", "0-0 1 2:3:4"} {
		if !format.MatchString(raw) || duration.MatchString(raw) {
			t.Errorf("max_staleness validation does not take %q as a SQL interval", raw)
		}
	}
	for _, raw := range []string{"15", "1d", "abc", "15 m", "-1h", "0-0 0 0:15", "1-0 0 0:0:0"} {
		if format.MatchString(raw) {
			t.Errorf("max_staleness validation accepts %q", raw)
		}
	}
	// Durations the exporter rejects are well formed, so the range rule sees them.
	for _, raw := range []string{"0s", "500ms", "168h1s", "800h"} {
		if _, err := parseMaxStaleness("max_staleness", raw); err == nil {
			t.Errorf("the exporter accepts %q", raw)
		}
		if !duration.MatchString(raw) {
			t.Errorf("the max_staleness range rule does not check %q", raw)
		}
	}

	const epoch = "2000-01-01T00:00:00Z"
	start, err := time.Parse(time.RFC3339, epoch)
	if err != nil {
		t.Fatal(err)
	}
	block := testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/variables.tf"), `variable "max_staleness"`)
	for _, rule := range []string{
		fmt.Sprintf(`timecmp(timeadd(%q, var.max_staleness), %q) >= 0`, epoch, start.Add(minTableStaleness).Format(time.RFC3339)),
		fmt.Sprintf(`timecmp(timeadd(%q, var.max_staleness), %q) <= 0`, epoch, start.Add(maxTableStaleness).Format(time.RFC3339)),
		fmt.Sprintf(`timeadd(%q, var.max_staleness) == timeadd(%q, "${var.max_staleness}999999999ns")`, epoch, epoch),
	} {
		if !strings.Contains(block, rule) {
			t.Errorf("variables.tf max_staleness has no range rule %s", rule)
		}
	}
}

// A first apply with a new key has to grant the BigQuery service agent on the
// key before BigQuery creates anything encrypted with it, and no argument of
// the dataset or the tables refers to the grant, so each of them depends on
// it. Without CMEK the grant has no instances and orders nothing.
func TestTerraformEncryptedResourcesDependOnKeyGrant(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	grant := testsupport.TerraformBlock(text, `resource "google_kms_crypto_key_iam_member" "bq_encryptor"`)
	if !strings.Contains(grant, `count         = var.kms_key_name == "" ? 0 : 1`) {
		t.Fatalf("main.tf must grant the BigQuery service agent on the key exactly when kms_key_name is set:\n%s", grant)
	}
	dependsOnGrant := regexp.MustCompile(`(?m)^  depends_on = \[google_kms_crypto_key_iam_member\.bq_encryptor\]$`)
	var encrypted []string
	for _, m := range regexp.MustCompile(`(?s)(?:^|\n)resource "([^"]+)" "([^"]+)" \{\n(.*?)\n\}`).FindAllStringSubmatch(text, -1) {
		if !strings.Contains(m[3], "kms_key_name = var.kms_key_name") {
			continue
		}
		encrypted = append(encrypted, m[2])
		if !dependsOnGrant.MatchString(m[3]) {
			t.Errorf("%s.%s is encrypted with var.kms_key_name but does not depend on the key grant", m[1], m[2])
		}
	}
	want := append(append([]string{"otel"}, terraformTables...), "otel_alerts")
	if !slices.Equal(encrypted, want) {
		t.Errorf("resources encrypted with var.kms_key_name = %v, want %v", encrypted, want)
	}
}

// terraformExpirationVariables maps each table main.tf provisions to the
// variable holding its partition expiration in days.
var terraformExpirationVariables = map[string]string{
	"otel_spans":      "spans_partition_expiration_days",
	"otel_logs":       "logs_partition_expiration_days",
	"otel_metrics":    "metrics_partition_expiration_days",
	"otel_quarantine": "quarantine_partition_expiration_days",
}

// Each table takes its partition expiration from its own variable, converted
// from days to the milliseconds the provider takes and left unset at 0, and
// the partition filter requirement from require_partition_filter, set on the
// table because the time_partitioning argument of that name is deprecated.
// An expiration variable takes what the exporter's partition_expiration_days
// options take: a whole number of days, 0 or more.
func TestTerraformTablesTakeRetentionAndPartitionFilterVariables(t *testing.T) {
	text := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	if regexp.MustCompile(`expiration_ms\s*=\s*[0-9]`).MatchString(text) {
		t.Error("main.tf hard-codes a partition expiration instead of reading it from a variable")
	}
	vars := testsupport.ReadRepoText(t, "deploy/terraform/variables.tf")
	for _, table := range terraformTables {
		variable := terraformExpirationVariables[table]
		body := testsupport.TerraformBlock(text, `resource "google_bigquery_table" "`+table+`"`)
		partitioning := testsupport.FirstCapture(`(?s)\n  time_partitioning \{\n(.*?)\n  \}`, body)
		expiration := fmt.Sprintf("expiration_ms = var.%[1]s > 0 ? var.%[1]s * %[2]d : null", variable, (24 * time.Hour).Milliseconds())
		if !strings.Contains(partitioning, expiration) {
			t.Errorf("%s time_partitioning does not set %s:\n%s", table, expiration, partitioning)
		}
		if strings.Contains(partitioning, "require_partition_filter") {
			t.Errorf("%s sets the deprecated time_partitioning.require_partition_filter", table)
		}
		if !strings.Contains(body, "\n  require_partition_filter = var.require_partition_filter\n") {
			t.Errorf("%s does not set require_partition_filter = var.require_partition_filter on the table", table)
		}
		block := testsupport.TerraformBlock(vars, `variable "`+variable+`"`)
		for _, want := range []string{
			"type        = number",
			fmt.Sprintf("condition     = var.%[1]s >= 0 && floor(var.%[1]s) == var.%[1]s", variable),
		} {
			if !strings.Contains(block, want) {
				t.Errorf("variables.tf %s does not contain %s:\n%s", variable, want, block)
			}
		}
	}
	if block := testsupport.TerraformBlock(vars, `variable "require_partition_filter"`); !strings.Contains(block, "type        = bool") {
		t.Errorf("variables.tf require_partition_filter is not a bool:\n%s", block)
	}
}

// require_partition_filter applies to otel_spans too, and BigQuery rejects
// every query over v_gen_ai_logs, v_gen_ai_metric_exemplars, and
// v_gen_ai_agent_trajectory while otel_spans requires a partition filter,
// because each joins spans on a window that depends on each row. As the
// collector does, the module creates those three views only while
// require_partition_filter is off or allow_unprunable_views (default false) is
// set, and gates no other view. The outputs stay valid without the views, and
// the v_gen_ai_logs of an earlier release moves to instance 0 instead of being
// replaced.
func TestTerraformCrossSignalViewsFollowAllowUnprunableViews(t *testing.T) {
	variable := testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/variables.tf"), `variable "allow_unprunable_views"`)
	for _, want := range []string{"type        = bool", "default     = false"} {
		if !strings.Contains(variable, want) {
			t.Errorf("variables.tf allow_unprunable_views does not contain %s:\n%s", want, variable)
		}
	}

	mainTF := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	const gate = "\n  count = (!var.require_partition_filter || var.allow_unprunable_views) ? 1 : 0\n"
	gated := []string{schema.GenAILogsViewName, schema.GenAIMetricExemplarsViewName, schema.GenAIAgentTrajectoryViewName}
	for _, view := range gated {
		if body := testsupport.TerraformBlock(mainTF, `resource "google_bigquery_table" "`+view+`"`); !strings.Contains("\n"+body, gate) {
			t.Errorf("main.tf %s is not gated by%s", view, gate)
		}
	}
	countArgument := regexp.MustCompile(`(?m)^  count\s+=`)
	for _, view := range append(slices.Clone(schema.SpanCompanionViewOrder), schema.GenAIMetricsViewName) {
		if slices.Contains(gated, view) {
			continue
		}
		body := testsupport.TerraformBlock(mainTF, `resource "google_bigquery_table" "`+view+`"`)
		if body == "" {
			t.Fatalf("main.tf has no %s view", view)
		}
		if countArgument.MatchString(body) || strings.Contains(body, "allow_unprunable_views") {
			t.Errorf("main.tf gates the view %s, which does not join otel_spans on a row-dependent window", view)
		}
	}
	if n := strings.Count(mainTF, "var.allow_unprunable_views"); n != len(gated) {
		t.Errorf("main.tf reads var.allow_unprunable_views %d times, want %d, in the gates of %v", n, len(gated), gated)
	}
	if moved := "\nmoved {\n  from = google_bigquery_table.v_gen_ai_logs\n  to   = google_bigquery_table.v_gen_ai_logs[0]\n}\n"; !strings.Contains(mainTF, moved) {
		t.Errorf("main.tf does not move the earlier google_bigquery_table.v_gen_ai_logs to instance 0:%s", moved)
	}

	outputs := testsupport.ReadRepoText(t, "deploy/terraform/outputs.tf")
	for _, view := range []string{schema.GenAIMetricExemplarsViewName, schema.GenAIAgentTrajectoryViewName} {
		if got, want := testsupport.TerraformAttribute(testsupport.TerraformBlock(outputs, `output "`+view+`_table_id"`), "value"),
			"one(google_bigquery_table."+view+"[*].id)"; got != want {
			t.Errorf("outputs.tf %s_table_id has the value %q, want %q", view, got, want)
		}
	}
	unindexed := regexp.MustCompile(`google_bigquery_table\.(v_gen_ai_logs|v_gen_ai_metric_exemplars|v_gen_ai_agent_trajectory)\.`)
	for _, file := range []string{"main.tf", "outputs.tf", "governance.tf"} {
		if m := unindexed.FindString(testsupport.ReadRepoText(t, "deploy/terraform/"+file)); m != "" {
			t.Errorf("deploy/terraform/%s reads %s without an instance key, which is invalid once the view has count", file, m)
		}
	}
}

// The prose gives the column count of the tables, and each count is taken
// here from the exporter's schema, so a column cannot be added without the
// prose following it.
func TestDocsStateTableColumnCounts(t *testing.T) {
	columns := map[string]int{
		"otel_spans":      len(schema.SpansTableSchema().GetFields()),
		"otel_logs":       len(schema.LogsTableSchema().GetFields()),
		"otel_metrics":    len(schema.MetricsTableSchema().GetFields()),
		"otel_quarantine": len(schema.QuarantineTableSchema().GetFields()),
	}
	for _, doc := range []struct {
		path string
		// pattern takes the table name, and its group captures the count.
		pattern string
		tables  []string
	}{
		{"deploy/terraform/main.tf", `(?m)^# %s: ([0-9]+)-column\b`, terraformTables},
		{"docs/schema-rationale.md", "(?m)^\\| `%s` is an? ([0-9]+)-column\\b", []string{"otel_metrics", "otel_quarantine"}},
		{"README.md", "`%s` stores [^.]*? ([0-9]+)-column\\b", []string{"otel_metrics"}},
	} {
		text := testsupport.ReadRepoText(t, doc.path)
		for _, table := range doc.tables {
			got := testsupport.FirstCapture(fmt.Sprintf(doc.pattern, table), text)
			if want := strconv.Itoa(columns[table]); got != want {
				t.Errorf("%s gives %s %q columns, but its schema has %s", doc.path, table, got, want)
			}
		}
	}
}

func spansDedupRationaleProblems(docText string) []string {
	var problems []string
	dedupSection := testsupport.FirstCapture(`(?s)(?:^|\n)## Deduplication\n(.*?)(?:\n## |\z)`, docText)
	if dedupSection == "" {
		return []string{"docs/schema-rationale.md missing Deduplication section"}
	}

	spansBullet := testsupport.FirstCapture(`(?s)(?:^|\n)(- \*\*Spans\*\* are identified by.*?)(?:\n- \*\*|\z)`, dedupSection)
	if spansBullet == "" {
		return []string{"docs/schema-rationale.md Deduplication section missing Spans identity bullet"}
	}

	docTupleRaw := testsupport.FirstCapture("are identified by\\s*`\\(([^)]+)\\)`", spansBullet)
	if docTupleRaw == "" {
		return []string{"docs/schema-rationale.md Spans bullet missing backtick-quoted identity tuple"}
	}
	var docTuple []string
	for _, col := range strings.Split(docTupleRaw, ",") {
		if c := strings.TrimSpace(col); c != "" {
			docTuple = append(docTuple, c)
		}
	}

	partitionClause := testsupport.FirstCapture(`(?s)PARTITION BY\s+(.*?)\s+ORDER BY`, schema.SpansDedupViewQuery)
	if partitionClause == "" {
		return []string{"schema.SpansDedupViewQuery missing PARTITION BY clause"}
	}
	var schemaPartitionCols []string
	for _, col := range strings.Split(partitionClause, ",") {
		if c := strings.TrimSpace(col); c != "" {
			schemaPartitionCols = append(schemaPartitionCols, c)
		}
	}

	// SpansDedupViewQuery partitions on the identity tuple plus the trailing
	// clustering column `name`.
	wantTuple := []string{"start_time", "start_time_unix_nano", "service_name", "trace_id", "span_id"}
	if len(schemaPartitionCols) < len(wantTuple) || !slices.Equal(schemaPartitionCols[:len(wantTuple)], wantTuple) {
		problems = append(problems, fmt.Sprintf("schema.SpansDedupViewQuery PARTITION BY prefix = %v, want %v", schemaPartitionCols, wantTuple))
	}
	if !slices.Equal(docTuple, wantTuple) {
		problems = append(problems, fmt.Sprintf("docs/schema-rationale.md Spans identity tuple = %v, want %v (matching schema.SpansDedupViewQuery)", docTuple, wantTuple))
	}
	if strings.Contains(docText, "(start_time, service_name, trace_id, span_id)") {
		problems = append(problems, "docs/schema-rationale.md still contains stale span identity tuple (start_time, service_name, trace_id, span_id)")
	}
	normalizedBullet := strings.Join(strings.Fields(spansBullet), " ")
	for _, want := range []string{"start_time_unix_nano", "nanosecond", "partition pruning", "`name`"} {
		if !strings.Contains(normalizedBullet, want) {
			problems = append(problems, fmt.Sprintf("docs/schema-rationale.md Spans bullet missing %q", want))
		}
	}
	return problems
}

func TestDocsSchemaRationaleMatchesSpansDedupIdentityTuple(t *testing.T) {
	docText := testsupport.ReadRepoText(t, "docs/schema-rationale.md")
	for _, p := range spansDedupRationaleProblems(docText) {
		t.Error(p)
	}

	t.Run("rejects stale span identity tuple", func(t *testing.T) {
		mutated := strings.Replace(
			docText,
			"(start_time, start_time_unix_nano, service_name, trace_id, span_id)",
			"(start_time, service_name, trace_id, span_id)",
			1,
		)
		if problems := spansDedupRationaleProblems(mutated); len(problems) == 0 {
			t.Fatal("expected spansDedupRationaleProblems to reject stale span identity tuple")
		}
	})
}

// kmsKeyLocation is the Cloud KMS location of the keys that can encrypt a
// BigQuery dataset in datasetLocation: us for the US multi-region, europe for
// the EU multi-region, and the dataset's own region otherwise.
func kmsKeyLocation(datasetLocation string) string {
	if location := strings.ToLower(datasetLocation); location != "eu" {
		return location
	}
	return "europe"
}

// A CMEK key has to be in the location of the dataset it encrypts, so every
// example command in deploy/README.md that sets kms_key_name names a key in
// the location of the dataset that command creates: the location it sets, or
// the module default. The CMEK section gives the rule for each kind of
// location.
func TestDeployReadmeCMEKExamplesUseKeysInTheDatasetLocation(t *testing.T) {
	readme := testsupport.ReadRepoText(t, "deploy/README.md")
	defaultLocation := testsupport.FirstCapture(`(?m)^  default\s+=\s+"([^"]+)"$`,
		testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/variables.tf"), `variable "location"`))
	if defaultLocation == "" {
		t.Fatal("variables.tf location has no default")
	}
	examples := 0
	for _, m := range regexp.MustCompile("(?s)```bash\n(.*?)```").FindAllStringSubmatch(readme, -1) {
		keyLocation := testsupport.FirstCapture(`kms_key_name=projects/[^/]+/locations/([^/]+)/`, m[1])
		if keyLocation == "" {
			continue
		}
		examples++
		location := testsupport.FirstCapture(`-var="location=([^"]+)"`, m[1])
		if location == "" {
			location = defaultLocation
		}
		if want := kmsKeyLocation(location); keyLocation != want {
			t.Errorf("deploy/README.md encrypts a dataset in %s with a key in locations/%s, but it needs a key in locations/%s:\n%s",
				location, keyLocation, want, m[1])
		}
	}
	if examples == 0 {
		t.Error("deploy/README.md has no example that sets kms_key_name")
	}
	section := testsupport.FirstCapture(`(?s)\n### CMEK Encryption\n(.*?)\n### `, readme)
	for _, location := range []string{"US", "EU", "us-central1"} {
		for _, want := range []string{"`" + location + "`", "`locations/" + kmsKeyLocation(location) + "`"} {
			if !strings.Contains(section, want) {
				t.Errorf("the CMEK section does not give the key location for a dataset in %s: it has no %s", location, want)
			}
		}
	}
}

// The Max Staleness section documents the values the module takes: each
// duration it shows is one the exporter and the variable validation accept,
// its interval example has the form the validation takes as an interval, the
// range it gives is the exporter's, and the conversion it shows is the
// interval the exporter writes. Neither it nor the variable describes the
// option as keeping recent partitions out of queries any more.
func TestDeployReadmeDocumentsMaxStalenessValues(t *testing.T) {
	section := testsupport.FirstCapture(`(?s)\n### Max Staleness\n(.*?)\n### `, testsupport.ReadRepoText(t, "deploy/README.md"))
	if section == "" {
		t.Fatal("deploy/README.md has no Max Staleness section")
	}
	patterns := terraformValidationPatterns(t, "max_staleness")
	if len(patterns) != 2 {
		t.Fatalf("max_staleness has %d regex validation rules, want the format rule and the range rule", len(patterns))
	}
	format, duration := patterns[0], patterns[1]
	// Code spans are read from the prose, outside the example command, whose
	// fences would pair backticks wrongly; the command's value is read apart.
	prose := regexp.MustCompile("(?s)```.*?```").ReplaceAllString(section, "")
	values := regexp.MustCompile("`([^`]+)`").FindAllStringSubmatch(prose, -1)
	values = append(values, regexp.MustCompile(`max_staleness=([^"]+)"`).FindAllStringSubmatch(section, -1)...)
	durations := 0
	for _, m := range values {
		if value := m[1]; duration.MatchString(value) {
			durations++
			if _, err := parseMaxStaleness("max_staleness", value); err != nil || !format.MatchString(value) {
				t.Errorf("the Max Staleness section shows the duration %q, which the module or the exporter rejects: %v", value, err)
			}
		}
	}
	if durations == 0 {
		t.Error("the Max Staleness section shows no duration")
	}
	if interval := testsupport.FirstCapture("interval string \\(for example `([^`]+)`\\)", prose); !format.MatchString(interval) || duration.MatchString(interval) {
		t.Errorf("the Max Staleness section gives %q as its SQL interval example, which the module does not take as an interval", interval)
	}

	bounds := regexp.MustCompile("whole seconds from `([^`]+)` to `([^`]+)`").FindStringSubmatch(prose)
	if bounds == nil {
		t.Fatal("the Max Staleness section does not give the range of a duration")
	}
	for i, want := range []time.Duration{minTableStaleness, maxTableStaleness} {
		if got, err := time.ParseDuration(bounds[i+1]); err != nil || got != want {
			t.Errorf("the Max Staleness section bounds a duration at %q, but the exporter's bound is %v", bounds[i+1], want)
		}
	}

	conversion := regexp.MustCompile("`([^`]+)` is sent as `([^`]+)`").FindStringSubmatch(prose)
	if conversion == nil {
		t.Fatal("the Max Staleness section shows no conversion of a duration")
	}
	d, err := parseMaxStaleness("max_staleness", conversion[1])
	if err != nil {
		t.Fatal(err)
	}
	if want := bq.IntervalValueFromDuration(d).String(); conversion[2] != want {
		t.Errorf("the Max Staleness section converts %s to %q, but the exporter writes %q", conversion[1], conversion[2], want)
	}

	variable := testsupport.TerraformBlock(testsupport.ReadRepoText(t, "deploy/terraform/variables.tf"), `variable "max_staleness"`)
	for name, text := range map[string]string{"deploy/README.md": section, "variables.tf": variable} {
		if strings.Contains(strings.ToLower(text), "partitions newer than") {
			t.Errorf("%s still says max_staleness keeps partitions newer than its value out of queries", name)
		}
	}
}

// deploy/README.md lists every retention and partition filter variable, and
// allow_unprunable_views, with the default variables.tf declares, and says
// that the collector's own options for a table apply only to tables the
// collector creates, naming every per-signal option other than the table name.
func TestDeployReadmeDocumentsTerraformGovernance(t *testing.T) {
	readme := testsupport.ReadRepoText(t, "deploy/README.md")
	vars := testsupport.ReadRepoText(t, "deploy/terraform/variables.tf")
	for _, variable := range append(slices.Sorted(maps.Values(terraformExpirationVariables)), "require_partition_filter", "allow_unprunable_views") {
		want := testsupport.FirstCapture(`(?m)^  default\s+=\s+(.+)$`, testsupport.TerraformBlock(vars, `variable "`+variable+`"`))
		got := testsupport.FirstCapture("(?m)^\\| `"+variable+"` \\| `([^`]*)` \\|", readme)
		if want == "" || got != want {
			t.Errorf("deploy/README.md gives %s the default %q, but variables.tf declares %q", variable, got, want)
		}
	}
	intro := testsupport.FirstCapture(`(?s)\n## Enterprise Governance\n(.*?)\n### `, readme)
	for _, key := range exporterConfigKeys() {
		if option, ok := strings.CutPrefix(key, "traces."); ok && option != "table" && !strings.Contains(intro, "`"+option+"`") {
			t.Errorf("the Enterprise Governance introduction does not say that the collector's %s applies only to tables it creates", option)
		}
	}
	if !strings.Contains(intro, "`auto_create.tables`") {
		t.Error("the Enterprise Governance introduction does not name auto_create.tables")
	}
}

// builderModule is one gomod entry of an OCB manifest.
type builderModule struct {
	Gomod string `yaml:"gomod"`
}

// builderManifestModules returns every gomod entry of the OCB manifest at path,
// across all of its component sections and its telemetry section.
func builderManifestModules(t *testing.T, path string) []string {
	t.Helper()
	var manifest struct {
		Receivers  []builderModule `yaml:"receivers"`
		Processors []builderModule `yaml:"processors"`
		Exporters  []builderModule `yaml:"exporters"`
		Connectors []builderModule `yaml:"connectors"`
		Extensions []builderModule `yaml:"extensions"`
		Providers  []builderModule `yaml:"providers"`
		Telemetry  builderModule   `yaml:"telemetry"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, path)), &manifest); err != nil {
		t.Fatalf("unmarshaling %s: %v", path, err)
	}
	var gomods []string
	for _, section := range [][]builderModule{
		manifest.Receivers, manifest.Processors, manifest.Exporters, manifest.Connectors,
		manifest.Extensions, manifest.Providers, {manifest.Telemetry},
	} {
		for _, module := range section {
			if module.Gomod != "" {
				gomods = append(gomods, module.Gomod)
			}
		}
	}
	return gomods
}

// workflowSetupGoVersions returns, per job, the go-version of every
// actions/setup-go step in the workflow at path. A step that sets no go-version,
// for example one that resolves the go.mod minimum, is reported as "(none)".
func workflowSetupGoVersions(t *testing.T, path string) map[string][]string {
	t.Helper()
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string         `yaml:"uses"`
				With map[string]any `yaml:"with"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, path)), &workflow); err != nil {
		t.Fatalf("unmarshaling %s: %v", path, err)
	}
	versions := map[string][]string{}
	for name, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "actions/setup-go@") {
				continue
			}
			version := "(none)"
			if v, ok := step.With["go-version"]; ok {
				version = fmt.Sprint(v)
			}
			versions[name] = append(versions[name], version)
		}
	}
	return versions
}

// The Collector release is pinned in several places that no tool bumps
// together: the Makefile, both OCB manifests, the example Dockerfile, and the CI
// and release workflows. go.mod is the source of truth. A pin that lags it
// builds the custom distribution from a different Collector than the one the
// exporter's own tests ran against, and leaves the stock image that CI compares
// the example against on another release than the builder.
func TestCollectorPinsStayInLockstepWithGoMod(t *testing.T) {
	collectorVersion, confmapVersion := testsupport.CollectorVersionsFromGoMod(t, "go.mod")

	if got := testsupport.FirstCapture(`(?m)^OCB_VERSION \?= (\S+)$`, testsupport.ReadRepoText(t, "Makefile")); got != collectorVersion {
		t.Errorf("Makefile OCB_VERSION = %q, want %q from go.mod", got, collectorVersion)
	}

	builderPin := regexp.MustCompile(`go\.opentelemetry\.io/collector/cmd/builder@(v\d+\.\d+\.\d+)`)
	for _, path := range []string{"example/Dockerfile", ".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		pins := builderPin.FindAllStringSubmatch(testsupport.ReadRepoText(t, path), -1)
		if len(pins) == 0 {
			t.Errorf("%s does not pin the OpenTelemetry Collector builder", path)
		}
		for _, pin := range pins {
			if pin[1] != collectorVersion {
				t.Errorf("%s pins the builder at %s, want %s from go.mod", path, pin[1], collectorVersion)
			}
		}
	}

	for _, path := range []string{"example/otelcol-builder.yaml", "example/otelcol-builder-release.yaml"} {
		var collectorModules, providers int
		var service bool
		for _, gomod := range builderManifestModules(t, path) {
			fields := strings.Fields(gomod)
			if len(fields) != 2 {
				t.Errorf("%s: gomod %q is not \"<module> <version>\"", path, gomod)
				continue
			}
			module, version := fields[0], fields[1]
			var want string
			switch {
			case strings.HasPrefix(module, "go.opentelemetry.io/collector/confmap/provider/"):
				want = confmapVersion
				providers++
			case strings.HasPrefix(module, "go.opentelemetry.io/collector/"),
				strings.HasPrefix(module, "github.com/open-telemetry/opentelemetry-collector-contrib/"):
				want = collectorVersion
				collectorModules++
			default:
				// The exporter itself, pinned to the checkout being built.
				continue
			}
			service = service || module == "go.opentelemetry.io/collector/service"
			if version != want {
				t.Errorf("%s pins %s at %s, want %s from go.mod", path, module, version, want)
			}
		}
		if collectorModules == 0 || providers == 0 || !service {
			t.Errorf("%s: checked %d Collector modules and %d confmap providers, service pinned = %v; want all three present", path, collectorModules, providers, service)
		}
	}

	stock := testsupport.FirstCapture(`(?m)^\s*STOCK_IMAGE: otel/opentelemetry-collector-contrib:(\d+\.\d+\.\d+)@sha256:[0-9a-f]{64}$`, testsupport.ReadRepoText(t, ".github/workflows/ci.yml"))
	if stock == "" {
		t.Error("ci.yml STOCK_IMAGE is not an otel/opentelemetry-collector-contrib image pinned by version and sha256 digest")
	} else if "v"+stock != collectorVersion {
		t.Errorf("ci.yml STOCK_IMAGE is v%s, want %s from go.mod", stock, collectorVersion)
	}
}

// runtimeImage returns the image the last stage of a Dockerfile runs on, which
// is the image that ships. Stage flags such as --platform and an AS alias are
// not part of it.
func runtimeImage(t *testing.T, path string) string {
	t.Helper()
	froms := regexp.MustCompile(`(?m)^FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+\S+)?\s*$`).FindAllStringSubmatch(testsupport.ReadRepoText(t, path), -1)
	if len(froms) == 0 {
		t.Fatalf("%s has no FROM instruction", path)
	}
	return froms[len(froms)-1][1]
}

// Dockerfile.goreleaser builds the released image and example/Dockerfile builds
// the Compose and CI image. Both run on the same distroless base, pinned by tag
// and digest, so the image that is tested is the image that ships and a
// Dependabot bump of one cannot silently leave the other behind.
func TestRuntimeImagesShareBaseImageAndDigest(t *testing.T) {
	pinned := regexp.MustCompile(`^gcr\.io/distroless/[^:@\s]+:[^:@\s]+@sha256:[0-9a-f]{64}$`)
	images := map[string]string{}
	for _, path := range []string{"Dockerfile.goreleaser", "example/Dockerfile"} {
		images[path] = runtimeImage(t, path)
		if !pinned.MatchString(images[path]) {
			t.Errorf("%s runs on %q, want a gcr.io/distroless image pinned by tag and sha256 digest", path, images[path])
		}
	}
	if images["Dockerfile.goreleaser"] != images["example/Dockerfile"] {
		t.Errorf("runtime images differ: Dockerfile.goreleaser runs on %q, example/Dockerfile on %q; raise both pins together",
			images["Dockerfile.goreleaser"], images["example/Dockerfile"])
	}
}

// Both runtime images publish the OTLP, self-telemetry and health-check ports
// the example configuration serves, so a container started from either behaves
// the same.
func TestRuntimeImagesExposeSamePorts(t *testing.T) {
	exposeLine := regexp.MustCompile(`(?m)^EXPOSE\s+(.+?)\s*$`)
	ports := map[string]string{}
	for _, path := range []string{"Dockerfile.goreleaser", "example/Dockerfile"} {
		var all []string
		for _, line := range exposeLine.FindAllStringSubmatch(testsupport.ReadRepoText(t, path), -1) {
			all = append(all, strings.Fields(line[1])...)
		}
		if len(all) == 0 {
			t.Errorf("%s exposes no ports", path)
		}
		ports[path] = strings.Join(all, " ")
	}
	if ports["Dockerfile.goreleaser"] != ports["example/Dockerfile"] {
		t.Errorf("exposed ports differ: Dockerfile.goreleaser %q, example/Dockerfile %q",
			ports["Dockerfile.goreleaser"], ports["example/Dockerfile"])
	}
}

// TestDependabotCombinesDockerEntries verifies that dependabot.yml uses a
// single docker entry with directories instead of separate entries, and
// that the docker entry groups updates by dependency-name.
func TestDependabotCombinesDockerEntries(t *testing.T) {
	var doc struct {
		Updates []struct {
			PackageEcosystem string   `yaml:"package-ecosystem"`
			Directories      []string `yaml:"directories"`
			Groups           map[string]struct {
				GroupBy string `yaml:"group-by"`
			} `yaml:"groups"`
		} `yaml:"updates"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/dependabot.yml")), &doc); err != nil {
		t.Fatalf("parsing .github/dependabot.yml: %v", err)
	}
	var dockerCount int
	for _, u := range doc.Updates {
		if u.PackageEcosystem == "docker" {
			dockerCount++
			if len(u.Directories) != 2 {
				t.Errorf("docker entry has %d directories, want 2", len(u.Directories))
			}
			want := map[string]bool{"/": false, "/example": false}
			for _, d := range u.Directories {
				want[d] = true
			}
			for d, found := range want {
				if !found {
					t.Errorf("docker entry is missing directory %q", d)
				}
			}
			if g, ok := u.Groups["docker"]; !ok {
				t.Error("docker entry must have a 'docker' group with group-by")
			} else if g.GroupBy != "dependency-name" {
				t.Errorf("docker group group-by = %q, want %q", g.GroupBy, "dependency-name")
			}
		}
	}
	if dockerCount != 1 {
		t.Errorf(".github/dependabot.yml has %d docker entries, want 1 (combined with directories)", dockerCount)
	}
}

// TestBenchFuzzWorkflowListsEveryFuzzTarget keeps the bounded fuzzing job in
// .github/workflows/bench-fuzz.yml in step with the fuzz targets in the code.
// `go test -fuzz` takes one target per run, so the job lists its targets one by
// one: a target missing from that list is never fuzzed in CI, and an entry whose
// target was renamed or removed fuzzes nothing. The job runs `go test` without
// build tags, so a target in a file with a build constraint would not even be
// compiled, and its run would pass having fuzzed nothing. Each target also
// needs a committed seed corpus under <pkg>/testdata/fuzz/<target>/, which
// plain `go test` replays on every run, and the job has to upload that
// directory when fuzzing fails, because the failing input it writes there
// exists only on the runner.
func TestBenchFuzzWorkflowListsEveryFuzzTarget(t *testing.T) {
	const path = ".github/workflows/bench-fuzz.yml"
	var workflow struct {
		Jobs struct {
			Fuzz struct {
				Strategy struct {
					Matrix struct {
						Include []struct {
							Pkg    string `yaml:"pkg"`
							Target string `yaml:"target"`
						} `yaml:"include"`
					} `yaml:"matrix"`
				} `yaml:"strategy"`
				Steps []struct {
					If   string         `yaml:"if"`
					Uses string         `yaml:"uses"`
					With map[string]any `yaml:"with"`
				} `yaml:"steps"`
			} `yaml:"fuzz"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, path)), &workflow); err != nil {
		t.Fatalf("unmarshaling %s: %v", path, err)
	}

	declared := moduleFuzzTargets(t)
	if len(declared) == 0 {
		t.Fatal("found no fuzz targets in the module's test files")
	}

	listed := map[fuzzTarget]bool{}
	for _, entry := range workflow.Jobs.Fuzz.Strategy.Matrix.Include {
		ft := fuzzTarget{pkg: entry.Pkg, name: entry.Target}
		if listed[ft] {
			t.Errorf("%s lists fuzz target %s more than once", path, ft)
		}
		listed[ft] = true
		if _, ok := declared[ft]; !ok {
			t.Errorf("%s lists fuzz target %s, which no test file declares", path, ft)
		}
	}

	byName := func(a, b fuzzTarget) int { return strings.Compare(a.String(), b.String()) }
	for _, ft := range slices.SortedFunc(maps.Keys(declared), byName) {
		if !listed[ft] {
			t.Errorf("fuzz target %s (%s) is missing from jobs.fuzz.strategy.matrix.include in %s", ft, declared[ft], path)
		}
		if line, err := goBuildConstraint(filepath.Join(testsupport.RepoRoot(t), filepath.FromSlash(declared[ft])), nil); err != nil {
			t.Errorf("reading the build constraints of %s: %v", declared[ft], err)
		} else if line != "" {
			t.Errorf("fuzz target %s is declared in %s, which has the build constraint %q: the untagged go test -fuzz in %s would compile nothing to fuzz and still pass",
				ft, declared[ft], line, path)
		}
		corpus := filepath.Join(testsupport.RepoRoot(t), filepath.FromSlash(ft.pkg), "testdata", "fuzz", ft.name)
		entries, err := os.ReadDir(corpus)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("reading the seed corpus of fuzz target %s: %v", ft, err)
			continue
		}
		if !slices.ContainsFunc(entries, func(e fs.DirEntry) bool { return e.Type().IsRegular() }) {
			t.Errorf("fuzz target %s has no seed corpus file in %s", ft, corpus)
		}
	}

	uploads := false
	for _, step := range workflow.Jobs.Fuzz.Steps {
		if !strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
			continue
		}
		uploads = true
		if cond := strings.TrimSpace(step.If); cond != "failure()" && cond != "${{ failure() }}" {
			t.Errorf("%s uploads the fuzz corpus with if: %q, want failure()", path, step.If)
		}
		if upload := fmt.Sprint(step.With["path"]); !strings.Contains(upload, "testdata/fuzz/") {
			t.Errorf("%s uploads path %q, want the fuzz target's testdata/fuzz directory", path, upload)
		}
	}
	if !uploads {
		t.Errorf("jobs.fuzz in %s has no actions/upload-artifact step for the failing input", path)
	}
}

// fuzzTarget is a fuzz target as the bench-fuzz workflow names it: the package
// argument `go test` takes and the name of the target function.
type fuzzTarget struct {
	pkg, name string
}

func (ft fuzzTarget) String() string { return ft.pkg + " " + ft.name }

// moduleFuzzTargets returns every fuzz target declared in the module's test
// files, mapped to the file that declares it. Like the go command matching
// ./..., it skips testdata and vendor directories, nested modules, and
// directories and files whose names start with "." or "_".
func moduleFuzzTargets(t *testing.T) map[fuzzTarget]string {
	t.Helper()
	repoRoot := testsupport.RepoRoot(t)
	targets := map[fuzzTarget]string{}
	fset := token.NewFileSet()
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(repoRoot, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		name := d.Name()
		ignored := strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")
		if d.IsDir() {
			if ignored || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, statErr := os.Stat(filepath.Join(path, "go.mod")); statErr == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if ignored || !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		pkg := "."
		if dir := filepath.Dir(rel); dir != "." {
			pkg = "./" + filepath.ToSlash(dir)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && isFuzzTarget(fn) {
				targets[fuzzTarget{pkg: pkg, name: fn.Name.Name}] = rel
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("collecting fuzz targets: %v", err)
	}
	return targets
}

// isFuzzTarget reports whether `go test` runs fn as a fuzz target, by the rule
// the go command applies: fn is named Fuzz, or Fuzz followed by anything but a
// lower-case letter, has no receiver, type parameters or results, and takes a
// single *testing.F. Like the go command, it accepts F under any import name.
func isFuzzTarget(fn *ast.FuncDecl) bool {
	suffix, ok := strings.CutPrefix(fn.Name.Name, "Fuzz")
	if !ok || fn.Recv != nil || fn.Type.TypeParams.NumFields() > 0 || fn.Type.Results.NumFields() > 0 {
		return false
	}
	if r, _ := utf8.DecodeRuneInString(suffix); unicode.IsLower(r) {
		return false
	}
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) > 1 {
		return false
	}
	ptr, ok := params[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	switch x := ptr.X.(type) {
	case *ast.Ident:
		return x.Name == "F"
	case *ast.SelectorExpr:
		return x.Sel.Name == "F"
	default:
		return false
	}
}

// goBuildConstraint returns the first //go:build or // +build line among the
// line comments above the package clause of a Go file, where the go command
// reads build constraints, or "" if there is none. filename and src are as
// for parser.ParseFile: a nil src reads filename.
func goBuildConstraint(filename string, src any) (string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.PackageClauseOnly|parser.ParseComments)
	if err != nil {
		return "", err
	}
	for _, group := range file.Comments {
		if group.Pos() > file.Package {
			break
		}
		for _, c := range group.List {
			if constraint.IsGoBuild(c.Text) || constraint.IsPlusBuild(c.Text) {
				return c.Text, nil
			}
		}
	}
	return "", nil
}

func TestGoBuildConstraint(t *testing.T) {
	const header = "// Copyright 2026 Google LLC\n// SPDX-License-Identifier: Apache-2.0\n\n"
	for _, tc := range []struct {
		name, src, want string
	}{
		{name: "no constraint", src: header + "package p\n"},
		{name: "go:build after the license header", src: header + "//go:build integration\n\npackage p\n", want: "//go:build integration"},
		{name: "+build line", src: "// +build linux\n\npackage p\n", want: "// +build linux"},
		{name: "inside a block comment", src: "/*\n//go:build integration\n*/\n\npackage p\n"},
		{name: "below the package clause", src: "package p\n\n//go:build integration\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := goBuildConstraint("p_test.go", tc.src)
			if err != nil {
				t.Fatalf("goBuildConstraint: %v", err)
			}
			if got != tc.want {
				t.Errorf("goBuildConstraint = %q, want %q", got, tc.want)
			}
		})
	}
}

// hasBalancedParens reports whether every '(' and ')' outside SQL single-quoted
// and backtick-quoted literals in sql is balanced and never dips below depth 0.
func hasBalancedParens(sql string) bool {
	depth := 0
	inSingle, inBacktick := false, false
	for _, r := range sql {
		switch {
		case r == '\'' && !inBacktick:
			inSingle = !inSingle
		case r == '`' && !inSingle:
			inBacktick = !inBacktick
		case inSingle || inBacktick:
		case r == '(':
			depth++
		case r == ')':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
	return !inSingle && !inBacktick && depth == 0
}

// extractWhereClause returns the full text of the last WHERE clause in
// activeSQL (up to the closing ')' that encloses the SELECT query or a
// top-level ';') together with its depth-0 projection (with the contents of
// every parenthesized group omitted).
func extractWhereClause(activeSQL string) (whereClause, topLevel string) {
	i := strings.LastIndex(activeSQL, "WHERE")
	if i < 0 {
		return "", ""
	}
	var full, top strings.Builder
	depth := 0
	inSingle, inBacktick := false, false
	for _, r := range activeSQL[i:] {
		switch {
		case r == '\'' && !inBacktick:
			inSingle = !inSingle
			full.WriteRune(r)
			if depth == 0 {
				top.WriteRune(r)
			}
		case r == '`' && !inSingle:
			inBacktick = !inBacktick
			full.WriteRune(r)
			if depth == 0 {
				top.WriteRune(r)
			}
		case inSingle || inBacktick:
			full.WriteRune(r)
			if depth == 0 {
				top.WriteRune(r)
			}
		case r == '(':
			depth++
			full.WriteRune(r)
		case r == ')':
			depth--
			if depth < 0 {
				return full.String(), top.String()
			}
			full.WriteRune(r)
		case r == ';' && depth == 0:
			return full.String(), top.String()
		default:
			full.WriteRune(r)
			if depth == 0 {
				top.WriteRune(r)
			}
		}
	}
	return full.String(), top.String()
}

// parenDepthAtSubstring returns the parenthesis nesting depth at the start of
// the first occurrence of sub in sql (ignoring parentheses inside single-quoted
// or backtick-quoted SQL literals), or (-1, false) if sub is not present.
func parenDepthAtSubstring(sql, sub string) (int, bool) {
	idx := strings.Index(sql, sub)
	if idx < 0 {
		return -1, false
	}
	depth := 0
	inSingle, inBacktick := false, false
	for _, r := range sql[:idx] {
		switch {
		case r == '\'' && !inBacktick:
			inSingle = !inSingle
		case r == '`' && !inSingle:
			inBacktick = !inBacktick
		case inSingle || inBacktick:
		case r == '(':
			depth++
		case r == ')':
			depth--
		}
	}
	return depth, true
}

// BigQuery Continuous Queries cannot read views built on QUALIFY or window
// functions, so every SQL template in deploy/continuous-queries/ reads the
// base spans table through APPENDS(TABLE ...) and exports to Cloud Pub/Sub.
// Templates start with a block comment (never --) so bq never mistakes leading
// comment text for a CLI flag, include a start_time partition filter, omit
// policy-tagged columns (status.message), and use only placeholders passed by
// templatefile in deploy/terraform/outputs.tf.
func TestContinuousQueryTemplatesReadBaseTablesViaAppends(t *testing.T) {
	const dir = "deploy/continuous-queries"
	entries, err := os.ReadDir(filepath.Join(testsupport.RepoRoot(t), dir))
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	wantTemplates := []string{
		"agent_latency_p95.sql",
		"token_budget_burn.sql",
		"tool_error_rate_alert.sql",
	}
	var gotTemplates []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			gotTemplates = append(gotTemplates, e.Name())
		}
	}
	slices.Sort(gotTemplates)
	if !slices.Equal(gotTemplates, wantTemplates) {
		t.Fatalf("SQL templates in %s = %v, want %v", dir, gotTemplates, wantTemplates)
	}

	outputs := testsupport.ReadRepoText(t, "deploy/terraform/outputs.tf")
	renderedBlock := testsupport.TerraformBlock(outputs, `output "continuous_queries_rendered_sql"`)
	templateVarsSection := testsupport.FirstCapture(`(?s)templatefile\([^\n]+,\s*\{(.*?)\n\s*\}\)`, renderedBlock)
	if templateVarsSection == "" {
		t.Fatalf("could not parse templatefile vars map in continuous_queries_rendered_sql:\n%s", renderedBlock)
	}
	templatefileKeys := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\s+([a-z0-9_]+)\s+=`).FindAllStringSubmatch(templateVarsSection, -1) {
		templatefileKeys[m[1]] = true
	}

	specificChecks := map[string][]string{
		"tool_error_rate_alert.sql": {
			"'TOOL_ERROR' AS alert_kind",
			"status.code = 2",
			`$."error.type"`,
			`$."gen_ai.operation.name"') = 'execute_tool'`,
			`$."gen_ai.tool.name"`,
			`$."mcp.method.name"`,
		},
		"token_budget_burn.sql": {
			"'TOKEN_BUDGET_BURN' AS alert_kind",
			"> ${max_turn_input_tokens}",
			"> ${max_turn_output_tokens}",
		},
		"agent_latency_p95.sql": {
			"'AGENT_LATENCY_HIGH' AS alert_kind",
			"duration_nano / 1e6 > ${max_turn_duration_ms}",
		},
	}
	// Each per-span template builds the documented alert_id,
	// <ALERT_KIND>:<trace_id>:<span_id>, which consumers deduplicate on.
	alertKinds := map[string]string{
		"tool_error_rate_alert.sql": "TOOL_ERROR",
		"token_budget_burn.sql":     "TOKEN_BUDGET_BURN",
		"agent_latency_p95.sql":     "AGENT_LATENCY_HIGH",
	}
	// The non-lossy start_time predicate must stay a top-level AND conjunct of
	// WHERE (parenthesis depth 0) with no relative time filters or extra
	// start_time comparisons.
	const lookback = "AND start_time >= TIMESTAMP('1970-01-01 00:00:00+00')"
	topLevelOr := regexp.MustCompile(`(?i)\bOR\b`)
	partitionBoundRE := regexp.MustCompile(`start_time\s*>=\s*TIMESTAMP\('([^']+)'\)`)
	checkNonLossyWhere := func(label, sqlText string) {
		t.Helper()
		if !hasBalancedParens(sqlText) {
			t.Errorf("%s has unbalanced parentheses", label)
		}
		whereClause, top := extractWhereClause(sqlText)
		if whereClause == "" {
			t.Fatalf("%s has no WHERE clause", label)
		}
		if depth, ok := parenDepthAtSubstring(whereClause, lookback); !ok || depth != 0 {
			t.Errorf("%s: %q must appear in WHERE at parenthesis depth 0, got ok=%v depth=%d (WHERE: %q)", label, lookback, ok, depth, whereClause)
		}
		if !strings.Contains(top, "AND start_time >= TIMESTAMP") || topLevelOr.MatchString(top) {
			t.Errorf("%s: the start_time partition predicate is not a top-level AND conjunct of WHERE (top level: %q)", label, top)
		}
		if gotCount := strings.Count(whereClause, "start_time"); gotCount != 1 {
			t.Errorf("%s WHERE clause references start_time %d times, want 1 (WHERE: %q)", label, gotCount, whereClause)
		}
		upperWhere := strings.ToUpper(whereClause)
		for _, bannedWhere := range []string{"CURRENT_TIMESTAMP", "TIMESTAMP_SUB", "TIMESTAMP_DIFF", "INTERVAL"} {
			if strings.Contains(upperWhere, bannedWhere) {
				t.Errorf("%s WHERE clause contains relative time filter keyword %q (WHERE: %q)", label, bannedWhere, whereClause)
			}
		}
	}

	placeholderRE := regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}`)
	readme := testsupport.ReadRepoText(t, filepath.Join(dir, "README.md"))
	for _, docPath := range []string{filepath.Join(dir, "README.md"), "deploy/README.md", "README.md"} {
		docText := testsupport.ReadRepoText(t, docPath)
		if strings.Contains(strings.ToLower(docText), "partition pruning succeeds") {
			t.Errorf("%s still claims the epoch start_time bound makes partition pruning succeed", docPath)
		}
	}
	appendsBlocks := 0
	for _, m := range regexp.MustCompile("(?s)```sql\\n(.*?)```").FindAllStringSubmatch(readme, -1) {
		if strings.Contains(m[1], "APPENDS(") {
			appendsBlocks++
			checkNonLossyWhere(dir+"/README.md SQL block", testsupport.StripSQLComments(m[1]))
		}
	}
	if appendsBlocks < 2 {
		t.Errorf("%s/README.md has %d APPENDS SQL blocks, want at least 2 (INSERT INTO and TUMBLE)", dir, appendsBlocks)
	}

	parsedBounds := map[string]time.Time{}
	for _, name := range wantTemplates {
		path := filepath.Join(dir, name)
		rawSQL := testsupport.ReadRepoText(t, path)
		trimmedRaw := strings.TrimSpace(rawSQL)
		if !strings.HasPrefix(trimmedRaw, "/*") || strings.HasPrefix(trimmedRaw, "--") {
			t.Errorf("%s must start with a /* ... */ block comment, not --, so bq CLI flag parsing cannot fail", path)
		}

		activeSQL := testsupport.StripSQLComments(rawSQL)
		checkNonLossyWhere(path, activeSQL)
		for _, want := range []string{
			"EXPORT DATA",
			"CLOUD_PUBSUB",
			"https://pubsub.googleapis.com/projects/${project_id}/topics/${pubsub_topic}",
			"APPENDS(",
			"TABLE `${project_id}.${dataset_id}.${spans_table}`",
			lookback,
			`JSON_VALUE(attributes, '$."gen_ai.agent.name"')`,
			`JSON_VALUE(attributes, '$."gcp.vertex.agent.name"')`,
			`JSON_VALUE(attributes, '$."gen_ai.main_agent.name"')`,
		} {
			if !strings.Contains(activeSQL, want) {
				t.Errorf("%s active SQL is missing %q", path, want)
			}
		}
		for _, want := range specificChecks[name] {
			if !strings.Contains(activeSQL, want) {
				t.Errorf("%s active SQL is missing template predicate %q", path, want)
			}
		}
		if want := "CONCAT('" + alertKinds[name] + ":', trace_id, ':', span_id) AS alert_id"; !strings.Contains(activeSQL, want) {
			t.Errorf("%s active SQL does not build the documented alert_id %q", path, want)
		}
		if m := partitionBoundRE.FindStringSubmatch(activeSQL); len(m) == 2 {
			ts, err := time.Parse("2006-01-02 15:04:05-07", m[1])
			if err != nil {
				t.Errorf("%s: parsing partition bound %q: %v", path, m[1], err)
			} else {
				parsedBounds[name] = ts
			}
		} else {
			t.Errorf("%s: could not parse start_time TIMESTAMP bound from active SQL", path)
		}
		for _, banned := range []string{"_dedup", "v_gen_ai_", "v_mcp_", "duration_ns", "status.message"} {
			if strings.Contains(activeSQL, banned) {
				t.Errorf("%s active SQL contains banned reference %q", path, banned)
			}
		}
		upperSQL := strings.ToUpper(activeSQL)
		for _, bannedKW := range []string{"QUALIFY", "OVER (", "OVER(", "DISTINCT"} {
			if strings.Contains(upperSQL, bannedKW) {
				t.Errorf("%s active SQL contains unsupported Continuous Query keyword %q", path, bannedKW)
			}
		}
		for _, m := range placeholderRE.FindAllStringSubmatch(rawSQL, -1) {
			if !templatefileKeys[m[1]] {
				t.Errorf("%s references placeholder ${%s}, which is not passed by templatefile in deploy/terraform/outputs.tf", path, m[1])
			}
		}
		if !strings.Contains(readme, name) {
			t.Errorf("%s/README.md does not document %s", dir, name)
		}
	}
	for _, want := range []string{
		"APPENDS",
		"CONTINUOUS",
		"--continuous=true",
		"--connection_property=",
		"service_account=",
		"| bq query",
		"INSERT INTO",
		"TUMBLE",
		// A window alert has no span, so its alert_id encodes the typed tuple
		// with TO_JSON_STRING(STRUCT(...)) to preserve JSON string escaping and
		// NULL vs empty tool names across GROUP BY groups.
		"CONCAT('TOOL_ERROR_WINDOW:', TO_JSON_STRING(STRUCT(service_name, tool_name, window_start)))",
		"require_partition_filter",
		"enable_column_level_security",
	} {
		if !strings.Contains(readme, want) {
			t.Errorf("%s/README.md is missing %q", dir, want)
		}
	}

	t.Run("recent_append_old_event_spans", func(t *testing.T) {
		now := time.Date(2026, 10, 16, 20, 0, 0, 0, time.UTC)
		makeQualifyingTraces := func(age time.Duration, svcName, toolName string, isAlert bool) ptrace.Traces {
			td := ptrace.NewTraces()
			rs := td.ResourceSpans().AppendEmpty()
			rs.Resource().Attributes().PutStr("service.name", svcName)
			sp := rs.ScopeSpans().AppendEmpty().Spans().AppendEmpty()
			sp.SetTraceID(pcommon.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
			sp.SetSpanID(pcommon.SpanID{1, 2, 3, 4, 5, 6, 7, 8})
			sp.SetName("execute_tool")
			start := now.Add(-age)
			dur := 5 * time.Millisecond
			if isAlert {
				dur = 45 * time.Second
				sp.Status().SetCode(ptrace.StatusCodeError)
				sp.Attributes().PutInt("gen_ai.usage.input_tokens", 150000)
			} else {
				sp.Status().SetCode(ptrace.StatusCodeOk)
				sp.Attributes().PutInt("gen_ai.usage.input_tokens", 100)
			}
			sp.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
			sp.SetEndTimestamp(pcommon.NewTimestampFromTime(start.Add(dur)))
			sp.Attributes().PutStr("gen_ai.operation.name", "execute_tool")
			sp.Attributes().PutStr("gen_ai.tool.name", toolName)
			return td
		}

		// Build a 10-day-old span replayed from otel_quarantine (30-day default retention).
		var marshaler ptrace.JSONMarshaler
		rawPayload, err := marshaler.MarshalTraces(makeQualifyingTraces(10*24*time.Hour, "api:worker", "lookup", true))
		if err != nil {
			t.Fatalf("MarshalTraces: %v", err)
		}
		qLine, err := json.Marshal(quarantinereplay.Record{
			IngestTime: now.Add(-10 * 24 * time.Hour).Format(time.RFC3339),
			Signal:     "spans",
			ErrorCode:  "schema_mismatch",
			RawPayload: string(rawPayload),
		})
		if err != nil {
			t.Fatalf("Marshal quarantine Record: %v", err)
		}
		memSink := quarantinereplay.NewMemorySink()
		sum, err := quarantinereplay.Replay(context.Background(), bytes.NewReader(append(qLine, '\n')), memSink, quarantinereplay.Options{})
		if err != nil || sum.ReplayedSpans != 1 || len(memSink.Traces) != 1 {
			t.Fatalf("quarantinereplay.Replay = (%+v, %v), traces=%d; want 1 replayed span", sum, err, len(memSink.Traces))
		}

		opts := transform.Options{
			Limits: transform.DefaultLimits(),
			Now:    func() time.Time { return now },
		}
		eightDayRows, rej := transform.SpanRows(makeQualifyingTraces(8*24*time.Hour, "api", "worker:lookup", true), opts)
		if len(rej) != 0 || len(eightDayRows) != 1 {
			t.Fatalf("8-day SpanRows = (%d rows, %d rejects), want (1, 0)", len(eightDayRows), len(rej))
		}
		tenDayReplayRows, rej := transform.SpanRows(memSink.Traces[0], opts)
		if len(rej) != 0 || len(tenDayReplayRows) != 1 {
			t.Fatalf("10-day replayed SpanRows = (%d rows, %d rejects), want (1, 0)", len(tenDayReplayRows), len(rej))
		}
		thirtyDayRows, rej := transform.SpanRows(makeQualifyingTraces(30*24*time.Hour, "agent-svc", "search", true), opts)
		if len(rej) != 0 || len(thirtyDayRows) != 1 {
			t.Fatalf("30-day SpanRows = (%d rows, %d rejects), want (1, 0)", len(thirtyDayRows), len(rej))
		}
		controlRows, rej := transform.SpanRows(makeQualifyingTraces(1*time.Hour, "agent-svc", "search", false), opts)
		if len(rej) != 0 || len(controlRows) != 1 {
			t.Fatalf("control SpanRows = (%d rows, %d rejects), want (1, 0)", len(controlRows), len(rej))
		}

		matchesTemplate := func(tmpl string, row transform.Row) bool {
			bound, hasBound := parsedBounds[tmpl]
			if !hasBound {
				t.Fatalf("no parsed start_time TIMESTAMP bound for %s", tmpl)
			}
			startMicros, ok := row["start_time"].(int64)
			if !ok {
				t.Fatalf("row start_time = %#v, want int64 micros", row["start_time"])
			}
			startTime := time.UnixMicro(startMicros).UTC()
			if startTime.Before(bound) {
				return false
			}
			var attrs map[string]any
			if rawAttrs, _ := row["attributes"].(string); rawAttrs != "" {
				if err := json.Unmarshal([]byte(rawAttrs), &attrs); err != nil {
					t.Fatalf("unmarshaling row attributes: %v", err)
				}
			}
			statusMap, _ := row["status"].(transform.Row)
			statusCode, _ := statusMap["code"].(int64)
			durNano, _ := row["duration_nano"].(int64)

			switch tmpl {
			case "tool_error_rate_alert.sql":
				isErr := statusCode == 2 || attrs["error.type"] != nil
				isToolOrMCP := attrs["gen_ai.operation.name"] == "execute_tool" || attrs["gen_ai.tool.name"] != nil || attrs["mcp.method.name"] != nil
				return isErr && isToolOrMCP
			case "token_budget_burn.sql":
				laxInt64 := func(v any) int64 {
					switch x := v.(type) {
					case float64:
						return int64(x)
					case string:
						n, _ := strconv.ParseInt(x, 10, 64)
						return n
					default:
						return 0
					}
				}
				return laxInt64(attrs["gen_ai.usage.input_tokens"]) > 100000 ||
					laxInt64(attrs["gen_ai.usage.output_tokens"]) > 32000
			case "agent_latency_p95.sql":
				op, _ := attrs["gen_ai.operation.name"].(string)
				validOp := op == "invoke_agent" || op == "chat" || op == "generate_content" || op == "execute_tool"
				return float64(durNano)/1e6 > 30000 && validOp
			default:
				t.Fatalf("unknown template %s", tmpl)
				return false
			}
		}

		for _, tc := range []struct {
			label string
			row   transform.Row
			want  bool
		}{
			{"8_day_old_late_batch", eightDayRows[0], true},
			{"10_day_old_quarantine_replay", tenDayReplayRows[0], true},
			{"30_day_old_quarantine_replay", thirtyDayRows[0], true},
			{"healthy_control", controlRows[0], false},
		} {
			if gotReceive, _ := tc.row["receive_time"].(int64); gotReceive != now.UnixMicro() {
				t.Errorf("%s receive_time = %d, want %d (current append time)", tc.label, gotReceive, now.UnixMicro())
			}
			for _, tmpl := range wantTemplates {
				if got := matchesTemplate(tmpl, tc.row); got != tc.want {
					t.Errorf("%s against %s = %v, want %v", tc.label, tmpl, got, tc.want)
				}
			}
		}
	})

	t.Run("window_identity_collision_free", func(t *testing.T) {
		var tumbleSQL string
		for _, m := range regexp.MustCompile("(?s)```sql\n(.*?)```").FindAllStringSubmatch(readme, -1) {
			if strings.Contains(m[1], "FROM TUMBLE(") {
				tumbleSQL = m[1]
				break
			}
		}
		if tumbleSQL == "" {
			t.Fatal("deploy/continuous-queries/README.md has no TUMBLE SQL block")
		}
		if !regexp.MustCompile(`(?i)\bFROM\s+TUMBLE\(\s*TABLE\s+\w+`).MatchString(tumbleSQL) {
			t.Errorf("TUMBLE SQL block must pass TABLE <cte> to TUMBLE:\n%s", tumbleSQL)
		}
		alertIDMatch := regexp.MustCompile(`CONCAT\('([^']+)',\s*TO_JSON_STRING\(STRUCT\(([^)]+)\)\)\)\s+AS\s+alert_id`).FindStringSubmatch(tumbleSQL)
		if len(alertIDMatch) != 3 {
			t.Fatalf("could not parse CONCAT('<prefix>', TO_JSON_STRING(STRUCT(...))) AS alert_id from TUMBLE SQL:\n%s", tumbleSQL)
		}
		prefix := alertIDMatch[1]
		if prefix != "TOOL_ERROR_WINDOW:" {
			t.Errorf("TUMBLE alert_id prefix = %q, want %q", prefix, "TOOL_ERROR_WINDOW:")
		}
		var structFields []string
		for _, f := range strings.Split(alertIDMatch[2], ",") {
			if col := strings.TrimSpace(f); col != "" {
				structFields = append(structFields, col)
			}
		}
		groupByClause := testsupport.FirstCapture(`(?i)\bGROUP\s+BY\s+([^\n;]+)`, tumbleSQL)
		if groupByClause == "" {
			t.Fatalf("could not parse GROUP BY clause from TUMBLE SQL:\n%s", tumbleSQL)
		}
		groupCols := map[string]bool{}
		for _, g := range strings.Split(groupByClause, ",") {
			if col := strings.TrimSpace(g); col != "" {
				groupCols[col] = true
			}
		}
		for _, wantCol := range []string{"service_name", "tool_name", "window_start"} {
			if !slices.Contains(structFields, wantCol) {
				t.Errorf("TUMBLE alert_id STRUCT fields %v missing required group column %q", structFields, wantCol)
			}
		}
		for _, col := range structFields {
			if !groupCols[col] {
				t.Errorf("TUMBLE alert_id STRUCT field %q is not in GROUP BY (%s)", col, groupByClause)
			}
		}

		strPtr := func(s string) *string { return &s }
		windowAlertID := func(serviceName, toolName *string, windowStart string) string {
			colValues := map[string]any{
				"service_name": serviceName,
				"tool_name":    toolName,
				"window_start": windowStart,
			}
			var buf bytes.Buffer
			buf.WriteByte('{')
			for i, col := range structFields {
				val, ok := colValues[col]
				if !ok {
					t.Fatalf("unknown column %q in TUMBLE alert_id STRUCT", col)
				}
				if i > 0 {
					buf.WriteByte(',')
				}
				keyBytes, err := json.Marshal(col)
				if err != nil {
					t.Fatalf("json.Marshal key %q: %v", col, err)
				}
				valBytes, err := json.Marshal(val)
				if err != nil {
					t.Fatalf("json.Marshal val for %q: %v", col, err)
				}
				buf.Write(keyBytes)
				buf.WriteByte(':')
				buf.Write(valBytes)
			}
			buf.WriteByte('}')
			return prefix + buf.String()
		}

		w1 := "2026-10-16 20:00:00+00"
		w2 := "2026-10-16 20:05:00+00"
		groups := []struct {
			label   string
			service *string
			tool    *string
			window  string
		}{
			{"colon_in_service", strPtr("api:worker"), strPtr("lookup"), w1},
			{"colon_in_tool", strPtr("api"), strPtr("worker:lookup"), w1},
			{"null_tool", strPtr("api"), nil, w1},
			{"empty_tool", strPtr("api"), strPtr(""), w1},
			{"unknown_tool", strPtr("api"), strPtr("unknown"), w1},
			{"null_service", nil, strPtr("lookup"), w1},
			{"empty_service", strPtr(""), strPtr("lookup"), w1},
			{"second_tool", strPtr("api"), strPtr("search"), w1},
			{"next_window", strPtr("api"), strPtr("lookup"), w2},
		}

		seen := map[string]string{}
		for _, g := range groups {
			key := windowAlertID(g.service, g.tool, g.window)
			if !strings.HasPrefix(key, "TOOL_ERROR_WINDOW:{") {
				t.Errorf("%s produced malformed alert_id %q", g.label, key)
			}
			if prev, exists := seen[key]; exists {
				t.Errorf("window alert_id collision between %s and %s: %q", prev, g.label, key)
			}
			seen[key] = g.label
		}
	})
}

type cqNameSpec struct {
	rawLocals       string
	nonAlnumRE      *regexp.Regexp
	normReplace     string
	normTrim        string
	fallbackSlug    string
	hashStart       int
	hashLen         int
	resCleanRE      *regexp.Regexp
	resSuffixRE     *regexp.Regexp
	resPrefix       string
	resFastMaxLen   int
	resSlowSlugCap  int
	topicCleanRE    *regexp.Regexp
	topicSuffixRE   *regexp.Regexp
	topicPrefix     string
	topicFastMaxLen int
	topicSlowCap    int
}

func parseContinuousQueryNameSpec(t *testing.T, mainTF string) cqNameSpec {
	t.Helper()
	var cqLocals string
	for _, m := range regexp.MustCompile(`(?s)(?:^|\n)locals \{\n(.*?)\n\}`).FindAllStringSubmatch(mainTF, -1) {
		if strings.Contains(m[1], "continuous_query_reservation_name") || strings.Contains(m[1], "otel_alerts_topic_name") {
			cqLocals = m[1]
			break
		}
	}
	if cqLocals == "" {
		t.Fatal("main.tf has no locals block defining continuous_query_reservation_name and otel_alerts_topic_name")
	}

	normMatch := regexp.MustCompile(`cq_dataset_norm\s*=\s*trim\(replace\(lower\(var\.dataset_id\),\s*"/([^"]+)/",\s*"([^"]+)"\),\s*"([^"]+)"\)`).FindStringSubmatch(cqLocals)
	if len(normMatch) != 4 {
		t.Fatalf("could not parse cq_dataset_norm from main.tf locals:\n%s", cqLocals)
	}
	slugFallback := testsupport.FirstCapture(`cq_dataset_slug\s*=\s*local\.cq_dataset_norm\s*!=\s*""\s*\?\s*local\.cq_dataset_norm\s*:\s*"([^"]+)"`, cqLocals)
	if slugFallback == "" {
		t.Fatalf("could not parse cq_dataset_slug from main.tf locals:\n%s", cqLocals)
	}
	hashMatch := regexp.MustCompile(`cq_dataset_hash\s*=\s*substr\(sha256\(var\.dataset_id\),\s*([0-9]+),\s*([0-9]+)\)`).FindStringSubmatch(cqLocals)
	if len(hashMatch) != 3 {
		t.Fatalf("could not parse cq_dataset_hash from main.tf locals:\n%s", cqLocals)
	}
	hashStart, _ := strconv.Atoi(hashMatch[1])
	hashLen, _ := strconv.Atoi(hashMatch[2])

	resMatch := regexp.MustCompile(`(?s)continuous_query_reservation_name\s*=\s*\(\s*` +
		`can\(regex\("([^"]+)",\s*var\.dataset_id\)\)\s*&&\s*!can\(regex\("([^"]+)",\s*var\.dataset_id\)\)\s*&&\s*` +
		`length\("([a-z0-9-]+)\$\{replace\(var\.dataset_id,\s*"_",\s*"-"\)\}"\)\s*<=\s*([0-9]+)\s*` +
		`\?\s*"([a-z0-9-]+)\$\{replace\(var\.dataset_id,\s*"_",\s*"-"\)\}"\s*` +
		`:\s*"([a-z0-9-]+)\$\{trim\(substr\(local\.cq_dataset_slug,\s*0,\s*min\(length\(local\.cq_dataset_slug\),\s*([0-9]+)\)\),\s*"-"\)\}-\$\{local\.cq_dataset_hash\}"\s*\)`).FindStringSubmatch(cqLocals)
	if len(resMatch) != 8 {
		t.Fatalf("could not parse continuous_query_reservation_name from main.tf locals:\n%s", cqLocals)
	}
	if resMatch[3] != resMatch[5] || resMatch[3] != resMatch[6] {
		t.Fatalf("continuous_query_reservation_name prefixes disagree: %q vs %q vs %q", resMatch[3], resMatch[5], resMatch[6])
	}
	resFastMaxLen, _ := strconv.Atoi(resMatch[4])
	resSlowSlugCap, _ := strconv.Atoi(resMatch[7])

	topicMatch := regexp.MustCompile(`(?s)otel_alerts_topic_name\s*=\s*\(\s*` +
		`can\(regex\("([^"]+)",\s*var\.dataset_id\)\)\s*&&\s*!can\(regex\("([^"]+)",\s*var\.dataset_id\)\)\s*&&\s*` +
		`length\("([a-z0-9-]+)\$\{var\.dataset_id\}"\)\s*<=\s*([0-9]+)\s*` +
		`\?\s*"([a-z0-9-]+)\$\{var\.dataset_id\}"\s*` +
		`:\s*"([a-z0-9-]+)\$\{trim\(substr\(local\.cq_dataset_slug,\s*0,\s*min\(length\(local\.cq_dataset_slug\),\s*([0-9]+)\)\),\s*"-"\)\}-\$\{local\.cq_dataset_hash\}"\s*\)`).FindStringSubmatch(cqLocals)
	if len(topicMatch) != 8 {
		t.Fatalf("could not parse otel_alerts_topic_name from main.tf locals:\n%s", cqLocals)
	}
	if topicMatch[3] != topicMatch[5] || topicMatch[3] != topicMatch[6] {
		t.Fatalf("otel_alerts_topic_name prefixes disagree: %q vs %q vs %q", topicMatch[3], topicMatch[5], topicMatch[6])
	}
	topicFastMaxLen, _ := strconv.Atoi(topicMatch[4])
	topicSlowCap, _ := strconv.Atoi(topicMatch[7])

	return cqNameSpec{
		rawLocals:       cqLocals,
		nonAlnumRE:      regexp.MustCompile(normMatch[1]),
		normReplace:     normMatch[2],
		normTrim:        normMatch[3],
		fallbackSlug:    slugFallback,
		hashStart:       hashStart,
		hashLen:         hashLen,
		resCleanRE:      regexp.MustCompile(resMatch[1]),
		resSuffixRE:     regexp.MustCompile(resMatch[2]),
		resPrefix:       resMatch[3],
		resFastMaxLen:   resFastMaxLen,
		resSlowSlugCap:  resSlowSlugCap,
		topicCleanRE:    regexp.MustCompile(topicMatch[1]),
		topicSuffixRE:   regexp.MustCompile(topicMatch[2]),
		topicPrefix:     topicMatch[3],
		topicFastMaxLen: topicFastMaxLen,
		topicSlowCap:    topicSlowCap,
	}
}

func (s cqNameSpec) derive(datasetID string) (reservation, topic string) {
	norm := strings.Trim(s.nonAlnumRE.ReplaceAllString(strings.ToLower(datasetID), s.normReplace), s.normTrim)
	slug := norm
	if slug == "" {
		slug = s.fallbackSlug
	}
	sum := sha256.Sum256([]byte(datasetID))
	fullHash := hex.EncodeToString(sum[:])
	hash := fullHash[s.hashStart : s.hashStart+s.hashLen]

	fastRes := s.resPrefix + strings.ReplaceAll(datasetID, "_", "-")
	if s.resCleanRE.MatchString(datasetID) && !s.resSuffixRE.MatchString(datasetID) && len(fastRes) <= s.resFastMaxLen {
		reservation = fastRes
	} else {
		prefix := slug
		if len(prefix) > s.resSlowSlugCap {
			prefix = prefix[:s.resSlowSlugCap]
		}
		prefix = strings.Trim(prefix, "-")
		reservation = s.resPrefix + prefix + "-" + hash
	}

	fastTopic := s.topicPrefix + datasetID
	if s.topicCleanRE.MatchString(datasetID) && !s.topicSuffixRE.MatchString(datasetID) && len(fastTopic) <= s.topicFastMaxLen {
		topic = fastTopic
	} else {
		prefix := slug
		if len(prefix) > s.topicSlowCap {
			prefix = prefix[:s.topicSlowCap]
		}
		prefix = strings.Trim(prefix, "-")
		topic = s.topicPrefix + prefix + "-" + hash
	}
	return reservation, topic
}

// Continuous Queries Terraform resources are opt-in: enable_continuous_queries
// defaults to false, every Continuous Query resource in main.tf is gated on
// var.enable_continuous_queries, outputs.tf renders all three SQL templates
// through templatefile and pipes SQL on stdin to bq query, and deploy/README.md
// and README.md document the setup.
func TestTerraformContinuousQueriesAreOptIn(t *testing.T) {
	const gate = "var.enable_continuous_queries"
	vars := testsupport.ReadRepoText(t, "deploy/terraform/variables.tf")
	wantVars := []struct{ name, typ, def string }{
		{"enable_continuous_queries", "bool", "false"},
		{"continuous_query_slot_capacity", "number", "100"},
		{"continuous_query_edition", "string", `"ENTERPRISE"`},
		{"continuous_query_max_turn_input_tokens", "number", "100000"},
		{"continuous_query_max_turn_output_tokens", "number", "32000"},
		{"continuous_query_max_turn_duration_ms", "number", "30000"},
		{"alerts_deletion_protection", "bool", "false"},
		{"alerts_partition_expiration_days", "number", "0"},
	}
	for _, v := range wantVars {
		block := testsupport.TerraformBlock(vars, `variable "`+v.name+`"`)
		if block == "" {
			t.Errorf("variables.tf declares no %s", v.name)
			continue
		}
		if got := testsupport.TerraformAttribute(block, "type"); got != v.typ {
			t.Errorf("variables.tf gives %s the type %q, want %q", v.name, got, v.typ)
		}
		if got := testsupport.TerraformAttribute(block, "default"); got != v.def {
			t.Errorf("variables.tf gives %s the default %q, want %q", v.name, got, v.def)
		}
	}
	editions := testsupport.FirstCapture(`(?m)^\s+condition\s+=\s+contains\(\[([^\]]*)\], var\.continuous_query_edition\)$`,
		testsupport.TerraformBlock(vars, `variable "continuous_query_edition"`))
	if !strings.Contains(editions, `"ENTERPRISE"`) || !strings.Contains(editions, `"ENTERPRISE_PLUS"`) {
		t.Errorf("continuous_query_edition validation = %q, want ENTERPRISE and ENTERPRISE_PLUS", editions)
	}
	slotBlock := testsupport.TerraformBlock(vars, `variable "continuous_query_slot_capacity"`)
	for _, want := range []string{
		"var.continuous_query_slot_capacity >= 50",
		"var.continuous_query_slot_capacity <= 500",
		"var.continuous_query_slot_capacity % 50 == 0",
	} {
		if !strings.Contains(slotBlock, want) {
			t.Errorf("continuous_query_slot_capacity validation missing %q:\n%s", want, slotBlock)
		}
	}
	saBlock := testsupport.TerraformBlock(vars, `variable "service_account_id"`)
	if !strings.Contains(saBlock, "length(var.service_account_id) <= 30") {
		t.Errorf("service_account_id validation must allow up to 30 chars by default:\n%s", saBlock)
	}

	mainTF := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")
	cqSA := testsupport.TerraformBlock(mainTF, `resource "google_service_account" "continuous_queries"`)
	if !strings.Contains(cqSA, "condition     = length(var.service_account_id) <= 27") {
		t.Errorf("google_service_account.continuous_queries missing length(var.service_account_id) <= 27 precondition:\n%s", cqSA)
	}
	gated := gate + " ? 1 : 0"
	resources := []string{
		`resource "google_bigquery_table" "otel_alerts"`,
		`resource "google_pubsub_topic" "otel_alerts"`,
		`resource "google_service_account" "continuous_queries"`,
		`resource "google_bigquery_dataset_iam_member" "continuous_queries_viewer"`,
		`resource "google_bigquery_table_iam_member" "continuous_queries_alerts_writer"`,
		`resource "google_pubsub_topic_iam_member" "continuous_queries_publisher"`,
		`resource "google_pubsub_topic_iam_member" "continuous_queries_pubsub_viewer"`,
		`resource "google_project_iam_member" "continuous_queries_jobs"`,
		`resource "google_bigquery_reservation" "continuous_queries"`,
		`resource "google_bigquery_reservation_assignment" "continuous_queries"`,
	}
	for _, header := range resources {
		body := testsupport.TerraformBlock(mainTF, header)
		if body == "" {
			t.Errorf("main.tf is missing %s", header)
			continue
		}
		if got := testsupport.TerraformAttribute(body, "count"); got != gated {
			t.Errorf("main.tf %s sets count = %q, want %q", header, got, gated)
		}
	}

	alertsTable := testsupport.TerraformBlock(mainTF, `resource "google_bigquery_table" "otel_alerts"`)
	if got := testsupport.TerraformAttribute(alertsTable, "deletion_protection"); got != "var.alerts_deletion_protection" {
		t.Errorf("otel_alerts sets deletion_protection = %q, want var.alerts_deletion_protection", got)
	}
	if got := testsupport.TerraformAttribute(alertsTable, "require_partition_filter"); got != "var.require_partition_filter" {
		t.Errorf("otel_alerts sets require_partition_filter = %q, want var.require_partition_filter", got)
	}

	alertsTopic := testsupport.TerraformBlock(mainTF, `resource "google_pubsub_topic" "otel_alerts"`)
	if got := testsupport.TerraformAttribute(alertsTopic, "name"); got != "local.otel_alerts_topic_name" {
		t.Errorf("google_pubsub_topic.otel_alerts sets name = %q, want local.otel_alerts_topic_name", got)
	}
	if !strings.Contains(alertsTopic, `!can(regex("^(?i)goog", local.otel_alerts_topic_name))`) {
		t.Errorf("google_pubsub_topic.otel_alerts missing Pub/Sub topic name precondition:\n%s", alertsTopic)
	}

	reservation := testsupport.TerraformBlock(mainTF, `resource "google_bigquery_reservation" "continuous_queries"`)
	if got := testsupport.TerraformAttribute(reservation, "name"); got != "local.continuous_query_reservation_name" {
		t.Errorf("continuous_queries reservation sets name = %q, want local.continuous_query_reservation_name", got)
	}
	if got := testsupport.TerraformAttribute(reservation, "edition"); got != "var.continuous_query_edition" {
		t.Errorf("continuous_queries reservation sets edition = %q, want var.continuous_query_edition", got)
	}
	if got := testsupport.TerraformAttribute(reservation, "slot_capacity"); got != "var.continuous_query_slot_capacity" {
		t.Errorf("continuous_queries reservation sets slot_capacity = %q, want var.continuous_query_slot_capacity", got)
	}
	if !strings.Contains(reservation, "condition     = !var.enable_column_level_security") {
		t.Errorf("continuous_queries reservation missing !var.enable_column_level_security precondition:\n%s", reservation)
	}
	if !strings.Contains(reservation, `can(regex("^[a-z][a-z0-9-]{0,62}[a-z0-9]$", local.continuous_query_reservation_name))`) {
		t.Errorf("continuous_queries reservation missing reservation name precondition:\n%s", reservation)
	}

	assignment := testsupport.TerraformBlock(mainTF, `resource "google_bigquery_reservation_assignment" "continuous_queries"`)
	if got := testsupport.TerraformAttribute(assignment, "job_type"); got != `"CONTINUOUS"` {
		t.Errorf("continuous_queries reservation assignment sets job_type = %q, want \"CONTINUOUS\"", got)
	}

	wantRoles := map[string]string{
		`resource "google_bigquery_dataset_iam_member" "continuous_queries_viewer"`:      `"roles/bigquery.dataViewer"`,
		`resource "google_bigquery_table_iam_member" "continuous_queries_alerts_writer"`: `"roles/bigquery.dataEditor"`,
		`resource "google_pubsub_topic_iam_member" "continuous_queries_publisher"`:       `"roles/pubsub.publisher"`,
		`resource "google_pubsub_topic_iam_member" "continuous_queries_pubsub_viewer"`:   `"roles/pubsub.viewer"`,
		`resource "google_project_iam_member" "continuous_queries_jobs"`:                 `"roles/bigquery.jobUser"`,
	}
	for header, wantRole := range wantRoles {
		if got := testsupport.TerraformAttribute(testsupport.TerraformBlock(mainTF, header), "role"); got != wantRole {
			t.Errorf("%s sets role = %q, want %s", header, got, wantRole)
		}
	}

	outputs := testsupport.ReadRepoText(t, "deploy/terraform/outputs.tf")
	for _, outName := range []string{
		"otel_alerts_table_id",
		"otel_alerts_pubsub_topic_id",
		"continuous_queries_service_account_email",
		"continuous_queries_rendered_sql",
		"continuous_queries_bq_cli_commands",
	} {
		block := testsupport.TerraformBlock(outputs, `output "`+outName+`"`)
		if block == "" {
			t.Errorf("outputs.tf is missing %s", outName)
			continue
		}
		if !strings.Contains(block, gate+" ?") || !strings.Contains(block, ": null") {
			t.Errorf("outputs.tf %s is not gated on %s with null fallback:\n%s", outName, gate, block)
		}
	}
	renderedBlock := testsupport.TerraformBlock(outputs, `output "continuous_queries_rendered_sql"`)
	for _, name := range []string{"tool_error_rate_alert", "token_budget_burn", "agent_latency_p95"} {
		if !strings.Contains(renderedBlock, `"`+name+`"`) {
			t.Errorf("continuous_queries_rendered_sql does not include %s", name)
		}
	}
	if !strings.Contains(renderedBlock, `templatefile("${path.module}/../continuous-queries/${name}.sql"`) {
		t.Errorf("continuous_queries_rendered_sql does not render templates with templatefile:\n%s", renderedBlock)
	}
	cliBlock := testsupport.TerraformBlock(outputs, `output "continuous_queries_bq_cli_commands"`)
	if !strings.Contains(cliBlock, "| bq query") || strings.Contains(cliBlock, `"$(terraform`) {
		t.Errorf("continuous_queries_bq_cli_commands must pipe SQL on stdin to bq query:\n%s", cliBlock)
	}

	deploySection := testsupport.FirstCapture(`(?s)\n### Real-Time Alerting \(Continuous Queries\)\n(.*?)(?:\n##+ |\z)`, testsupport.ReadRepoText(t, "deploy/README.md"))
	if deploySection == "" {
		t.Fatal("deploy/README.md has no Real-Time Alerting (Continuous Queries) section")
	}
	for _, v := range wantVars {
		want := strings.Trim(v.def, `"`)
		if got := testsupport.FirstCapture("(?m)^\\| `"+v.name+"` \\| `([^`]*)` \\|", deploySection); got != want {
			t.Errorf("deploy/README.md gives %s the default %q, but variables.tf declares %q", v.name, got, want)
		}
	}
	if !strings.Contains(testsupport.ReadRepoText(t, "README.md"), "deploy/continuous-queries/") {
		t.Error("README.md does not link deploy/continuous-queries/")
	}

	t.Run("dataset_id_derived_names", func(t *testing.T) {
		spec := parseContinuousQueryNameSpec(t, mainTF)

		resPrecondRE := testsupport.FirstCapture(`can\(regex\("([^"]+)",\s*local\.continuous_query_reservation_name\)\)`, reservation)
		topicPrecondRE := testsupport.FirstCapture(`can\(regex\("([^"]+)",\s*local\.otel_alerts_topic_name\)\)`, alertsTopic)
		topicNoGoogRE := testsupport.FirstCapture(`!can\(regex\("([^"]+)",\s*local\.otel_alerts_topic_name\)\)`, alertsTopic)
		if resPrecondRE == "" || topicPrecondRE == "" || topicNoGoogRE == "" {
			t.Fatalf("missing precondition regexes in main.tf (res=%q, topic=%q, nogoog=%q)", resPrecondRE, topicPrecondRE, topicNoGoogRE)
		}
		resRE := regexp.MustCompile(resPrecondRE)
		topicRE := regexp.MustCompile(topicPrecondRE)
		googRE := regexp.MustCompile(topicNoGoogRE)

		datasets := []string{
			"otel",
			"OTel_Prod",
			"otel_prod",
			"2026_otel",
			"_otel",
			"otel_",
			"123otel",
			"google_otel",
			"goog_otel",
			"GOOG_OTEL",
			"___",
			"a_b",
			"a__b",
			"otel_deadbeef",
			"otel_telemetry_production_us_central1_agents_v2",
			strings.Repeat("a", 60),
			strings.Repeat("B", 1024),
		}

		tfBin, tfErr := exec.LookPath("terraform")
		var tfDir string
		if tfErr == nil {
			tfDir = t.TempDir()
			hclFile := "variable \"dataset_id\" {\n  type = string\n}\n\nlocals {\n" + spec.rawLocals + "\n}\n"
			if err := os.WriteFile(filepath.Join(tfDir, "main.tf"), []byte(hclFile), 0o600); err != nil {
				t.Fatalf("writing temp main.tf for terraform console: %v", err)
			}
		}

		seenRes := map[string]string{}
		seenTopic := map[string]string{}
		for _, ds := range datasets {
			res, topic := spec.derive(ds)
			if !resRE.MatchString(res) || len(res) > 64 {
				t.Errorf("dataset_id %q produced invalid reservation name %q (len=%d)", ds, res, len(res))
			}
			if !topicRE.MatchString(topic) || googRE.MatchString(topic) || len(topic) > 255 {
				t.Errorf("dataset_id %q produced invalid topic name %q (len=%d)", ds, topic, len(topic))
			}
			if ds == "otel" && (res != "otel-cq-otel" || topic != "otel-alerts-otel") {
				t.Errorf("dataset_id %q = (%q, %q), want (\"otel-cq-otel\", \"otel-alerts-otel\")", ds, res, topic)
			}
			if tfDir != "" {
				cmd := exec.Command(tfBin, "-chdir="+tfDir, "console", "-var=dataset_id="+ds)
				cmd.Env = append(os.Environ(), "CHECKPOINT_DISABLE=1")
				cmd.Stdin = strings.NewReader("jsonencode([local.continuous_query_reservation_name, local.otel_alerts_topic_name])\n")
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("terraform console for dataset_id %q failed: %v\n%s", ds, err, out)
				}
				var encoded string
				if err := json.Unmarshal(bytes.TrimSpace(out), &encoded); err != nil {
					t.Fatalf("unquoting terraform console output %q: %v", out, err)
				}
				var hclPair [2]string
				if err := json.Unmarshal([]byte(encoded), &hclPair); err != nil {
					t.Fatalf("unmarshaling terraform console JSON %q: %v", encoded, err)
				}
				if hclPair[0] != res || hclPair[1] != topic {
					t.Errorf("terraform console for %q = (%q, %q), parsed spec derived (%q, %q)", ds, hclPair[0], hclPair[1], res, topic)
				}
			}
			if prev, exists := seenRes[res]; exists {
				t.Errorf("reservation name collision between %q and %q: %q", prev, ds, res)
			}
			seenRes[res] = ds
			if prev, exists := seenTopic[topic]; exists {
				t.Errorf("topic name collision between %q and %q: %q", prev, ds, topic)
			}
			seenTopic[topic] = ds
		}
	})
}

func TestReleaseDocsAndHelmCISync(t *testing.T) {
	readme := testsupport.ReadRepoText(t, "README.md")
	security := testsupport.ReadRepoText(t, "SECURITY.md")
	ci := testsupport.ReadRepoText(t, ".github/workflows/ci.yml")
	chart := testsupport.ReadRepoText(t, "deploy/helm/bigquery-otel-collector/Chart.yaml")
	deployReadme := testsupport.ReadRepoText(t, "deploy/README.md")

	for _, forbidden := range []string{
		"pre-v0.1.0",
		"pre-`v0.1.0`",
		"no tagged releases yet",
	} {
		if strings.Contains(readme, forbidden) {
			t.Errorf("README.md still contains stale pre-release wording %q", forbidden)
		}
		if strings.Contains(security, forbidden) {
			t.Errorf("SECURITY.md still contains stale pre-release wording %q", forbidden)
		}
	}
	if !strings.Contains(readme, "current release is `v0.1.0`") {
		t.Error("README.md must state that the current release is `v0.1.0`")
	}
	if !strings.Contains(security, "`v0.1.x`") || !strings.Contains(security, "`main`") || !strings.Contains(security, "development component stability") {
		t.Error("SECURITY.md must document support for `main`, the `v0.1.x` release series, and development component stability")
	}

	if !strings.Contains(chart, "3.4.0") && !strings.Contains(chart, "v3.4+") {
		t.Error("Chart.yaml must document supported Helm version (>= 3.4.0 / v3.4+)")
	}
	if !strings.Contains(deployReadme, "3.4") {
		t.Error("deploy/README.md must document supported Helm version (v3.4+ / >= 3.4.0)")
	}
	for _, requiredCI := range []string{
		`"$helm_bin" template bq-otel deploy/helm/bigquery-otel-collector`,
		"validate_chart helm",
		`validate_chart "$helm341_dir/linux-amd64/helm"`,
		"helm-v3.4.1-linux-amd64.tar.gz",
		"538f85b4b73ac6160b30fd0ab4b510441aa3fa326593466e8bf7084a9c288420",
		"quarantine.enabled=true",
		"quarantine.partitionExpirationDays=0",
		"offload.cacheSize=0",
	} {
		if !strings.Contains(ci, requiredCI) {
			t.Errorf(".github/workflows/ci.yml missing Helm validation clause %q", requiredCI)
		}
	}
}
