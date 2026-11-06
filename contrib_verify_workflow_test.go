// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/contribcheck"
)

const (
	contribVerifyWorkflowPath = ".github/workflows/contrib-verify.yml"
	contribVerifyScriptPath   = "scripts/verify_contrib_gates.sh"
)

type contribVerifyInput struct {
	Type     string `yaml:"type"`
	Required bool   `yaml:"required"`
	Default  any    `yaml:"default"`
}

type contribVerifyWorkflow struct {
	Name string         `yaml:"name"`
	On   map[string]any `yaml:"on"`
	// Decoded separately from On.workflow_dispatch in validator to ensure no
	// unintended triggers slip through.
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Name string            `yaml:"name"`
			Uses string            `yaml:"uses"`
			If   string            `yaml:"if"`
			Env  map[string]string `yaml:"env"`
			With map[string]any    `yaml:"with"`
			Run  string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

var fullSHAPinRE = regexp.MustCompile(`^[^@\s]+@[0-9a-f]{40}$`)

func validateContribVerifyWorkflow(raw []byte) error {
	var wf contribVerifyWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		return fmt.Errorf("unmarshal workflow YAML: %w", err)
	}
	if len(wf.On) != 1 {
		return fmt.Errorf("workflow triggers = %v, want only workflow_dispatch", wf.On)
	}
	dispatchRaw, ok := wf.On["workflow_dispatch"]
	if !ok {
		return fmt.Errorf("missing workflow_dispatch trigger")
	}

	dispatchBytes, err := yaml.Marshal(dispatchRaw)
	if err != nil {
		return fmt.Errorf("marshal workflow_dispatch: %w", err)
	}
	var dispatch struct {
		Inputs map[string]contribVerifyInput `yaml:"inputs"`
	}
	if err := yaml.Unmarshal(dispatchBytes, &dispatch); err != nil {
		return fmt.Errorf("unmarshal workflow_dispatch inputs: %w", err)
	}

	for _, name := range []string{"contrib_sha", "library_version", "use_local_checkout"} {
		if _, exists := dispatch.Inputs[name]; !exists {
			return fmt.Errorf("missing workflow_dispatch input %q", name)
		}
	}
	if got := fmt.Sprint(dispatch.Inputs["contrib_sha"].Default); got != contribcheck.PinnedCommit {
		return fmt.Errorf("contrib_sha default = %q, want %q", got, contribcheck.PinnedCommit)
	}
	if got := fmt.Sprint(dispatch.Inputs["library_version"].Default); got != contribcheck.LibraryVersion {
		return fmt.Errorf("library_version default = %q, want %q", got, contribcheck.LibraryVersion)
	}
	useLocal := dispatch.Inputs["use_local_checkout"]
	if useLocal.Type != "boolean" || useLocal.Default != false {
		return fmt.Errorf("use_local_checkout = %+v, want boolean defaulting to false", useLocal)
	}

	if len(wf.Permissions) != 1 || wf.Permissions["contents"] != "read" {
		return fmt.Errorf("top-level permissions = %v, want strictly {contents: read}", wf.Permissions)
	}
	if len(wf.Jobs) == 0 {
		return fmt.Errorf("workflow defines zero jobs")
	}

	var sawScriptStep, sawAlwaysUpload, sawSetupGo bool
	for jobID, job := range wf.Jobs {
		if len(job.Permissions) > 0 {
			return fmt.Errorf("job %q overrides permissions %v", jobID, job.Permissions)
		}
		for i, step := range job.Steps {
			if strings.Contains(step.Run, "${{") {
				return fmt.Errorf("job %q step %d (%q) interpolates ${{ inside run", jobID, i, step.Name)
			}
			if step.Uses != "" {
				if !fullSHAPinRE.MatchString(step.Uses) {
					return fmt.Errorf("job %q step %d uses unpinned action %q", jobID, i, step.Uses)
				}
				if strings.HasPrefix(step.Uses, "actions/setup-go@") {
					sawSetupGo = true
					if got := fmt.Sprint(step.With["go-version"]); got != "1.27.3" {
						return fmt.Errorf("setup-go go-version = %q, want 1.27.3", got)
					}
				}
				if strings.HasPrefix(step.Uses, "actions/upload-artifact@") {
					ifCond := strings.TrimSpace(step.If)
					if ifCond == "always()" || ifCond == "${{ always() }}" {
						sawAlwaysUpload = true
					}
					if strings.TrimSpace(fmt.Sprint(step.With["path"])) == "" {
						return fmt.Errorf("upload-artifact step missing path")
					}
				}
			}
			if strings.Contains(step.Run, "scripts/verify_contrib_gates.sh") {
				sawScriptStep = true
				for _, envKey := range []string{"CONTRIB_SHA", "LIBRARY_VERSION", "USE_LOCAL_CHECKOUT", "LOG_DIR"} {
					if strings.TrimSpace(step.Env[envKey]) == "" {
						return fmt.Errorf("verify step missing env %s", envKey)
					}
				}
			}
		}
	}

	if !sawSetupGo {
		return fmt.Errorf("missing actions/setup-go step")
	}
	if !sawScriptStep {
		return fmt.Errorf("missing step invoking scripts/verify_contrib_gates.sh")
	}
	if !sawAlwaysUpload {
		return fmt.Errorf("missing actions/upload-artifact step with if: always()")
	}
	return nil
}

func TestContribVerifyWorkflowContract(t *testing.T) {
	raw, err := os.ReadFile(contribVerifyWorkflowPath)
	require.NoError(t, err)
	require.NoError(t, validateContribVerifyWorkflow(raw))
}

func TestContribVerifyWorkflowNegativeProbes(t *testing.T) {
	baseBytes, err := os.ReadFile(contribVerifyWorkflowPath)
	require.NoError(t, err)
	base := string(baseBytes)

	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "interpolates expression into run block",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "run: ./scripts/verify_contrib_gates.sh \"${{ inputs.contrib_sha }}\"", 1)
			},
			wantErr: "interpolates ${{ inside run",
		},
		{
			name: "unpinned action tag",
			mutate: func(s string) string {
				return strings.Replace(s, "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7", 1)
			},
			wantErr: "unpinned action",
		},
		{
			name: "write permission granted",
			mutate: func(s string) string {
				return strings.Replace(s, "contents: read", "contents: write", 1)
			},
			wantErr: "top-level permissions",
		},
		{
			name: "unexpected pull_request trigger",
			mutate: func(s string) string {
				return strings.Replace(s, "on:\n  workflow_dispatch:", "on:\n  pull_request:\n  workflow_dispatch:", 1)
			},
			wantErr: "want only workflow_dispatch",
		},
		{
			name: "artifact upload missing always()",
			mutate: func(s string) string {
				return strings.Replace(s, "if: always()", "if: success()", 1)
			},
			wantErr: "if: always()",
		},
		{
			name: "missing use_local_checkout input",
			mutate: func(s string) string {
				return strings.Replace(s, "use_local_checkout:", "other_flag:", 1)
			},
			wantErr: "missing workflow_dispatch input \"use_local_checkout\"",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(base)
			require.NotEqual(t, base, mutated, "test mutation had no effect")
			err := validateContribVerifyWorkflow([]byte(mutated))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func checkBashSyntax(path string) error {
	cmd := exec.Command("bash", "-n", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("bash -n %s: %w: %s", path, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func TestVerifyContribGatesScript(t *testing.T) {
	info, err := os.Stat(contribVerifyScriptPath)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.NotZero(t, info.Mode()&0o111, "%s should be executable", contribVerifyScriptPath)
	}

	raw, err := os.ReadFile(contribVerifyScriptPath)
	require.NoError(t, err)
	script := string(raw)
	assert.NotContains(t, script, "${{")
	assert.Contains(t, script, "./internal/contribcheck/stage")
	assert.Contains(t, script, "checkapi")
	assert.Contains(t, script, "component_api_strict: true")

	if _, lookErr := exec.LookPath("bash"); lookErr == nil {
		require.NoError(t, checkBashSyntax(contribVerifyScriptPath))

		badPath := filepath.Join(t.TempDir(), "broken.sh")
		require.NoError(t, os.WriteFile(badPath, []byte("#!/usr/bin/env bash\nif [ -z x; then\n"), 0o600))
		require.Error(t, checkBashSyntax(badPath))
	}
}

func TestContribStageCLI(t *testing.T) {
	for _, pr := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("pr-%d", pr), func(t *testing.T) {
			outDir := t.TempDir()
			chlogFile := filepath.Join(outDir, ".chloggen", fmt.Sprintf("pr-%d.yaml", pr))
			cmd := exec.Command("go", "run", "./internal/contribcheck/stage",
				"--repo", ".",
				"--pr", fmt.Sprintf("%d", pr),
				"--out", outDir,
				"--chlog-out", chlogFile,
				"--issue", "12345",
			)
			out, err := cmd.CombinedOutput()
			require.NoErrorf(t, err, "stage CLI failed: %s", string(out))

			_, statErr := os.Stat(filepath.Join(outDir, filepath.FromSlash(contribcheck.ComponentDir), "factory.go"))
			require.NoError(t, statErr)
			chlogBytes, err := os.ReadFile(chlogFile)
			require.NoError(t, err)
			assert.Contains(t, string(chlogBytes), "issues: [12345]")
		})
	}

	t.Run("negative invalid PR rejected", func(t *testing.T) {
		cmd := exec.Command("go", "run", "./internal/contribcheck/stage", "--pr", "9", "--out", t.TempDir())
		out, err := cmd.CombinedOutput()
		require.Error(t, err)
		assert.Contains(t, string(out), "pr must be 1, 2, or 3")
	})
}
