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
	Env         map[string]string `yaml:"env"`
	Defaults    struct {
		Run struct {
			Shell            string `yaml:"shell"`
			WorkingDirectory string `yaml:"working-directory"`
		} `yaml:"run"`
	} `yaml:"defaults"`
	Jobs map[string]struct {
		If              string            `yaml:"if"`
		Permissions     map[string]string `yaml:"permissions"`
		Env             map[string]string `yaml:"env"`
		Container       any               `yaml:"container"`
		ContinueOnError any               `yaml:"continue-on-error"`
		Defaults        struct {
			Run struct {
				Shell            string `yaml:"shell"`
				WorkingDirectory string `yaml:"working-directory"`
			} `yaml:"run"`
		} `yaml:"defaults"`
		Steps []struct {
			Name             string            `yaml:"name"`
			Uses             string            `yaml:"uses"`
			If               string            `yaml:"if"`
			Shell            string            `yaml:"shell"`
			WorkingDirectory string            `yaml:"working-directory"`
			ContinueOnError  any               `yaml:"continue-on-error"`
			Env              map[string]string `yaml:"env"`
			With             map[string]any    `yaml:"with"`
			Run              string            `yaml:"run"`
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
	if len(wf.Env) > 0 {
		return fmt.Errorf("workflow env = %v, want empty", wf.Env)
	}
	if defShell := strings.TrimSpace(wf.Defaults.Run.Shell); defShell != "" && defShell != "bash" {
		return fmt.Errorf("workflow defaults.run.shell = %q, want empty or bash", defShell)
	}
	if defWD := strings.TrimSpace(wf.Defaults.Run.WorkingDirectory); defWD != "" {
		return fmt.Errorf("workflow defaults.run.working-directory = %q, want empty", defWD)
	}
	if len(wf.Jobs) != 1 {
		return fmt.Errorf("workflow defines %d jobs, want 1", len(wf.Jobs))
	}

	var sawCheckout, sawScriptStep, sawAlwaysUpload, sawSetupGo bool
	for jobID, job := range wf.Jobs {
		if strings.TrimSpace(job.If) != "" {
			return fmt.Errorf("job %q sets conditional if %q", jobID, job.If)
		}
		if len(job.Permissions) > 0 {
			return fmt.Errorf("job %q overrides permissions %v", jobID, job.Permissions)
		}
		if len(job.Env) > 0 {
			return fmt.Errorf("job %q sets env %v, want empty", jobID, job.Env)
		}
		if job.Container != nil {
			return fmt.Errorf("job %q sets container %v, want nil", jobID, job.Container)
		}
		if job.ContinueOnError != nil && job.ContinueOnError != false {
			return fmt.Errorf("job %q sets continue-on-error = %v", jobID, job.ContinueOnError)
		}
		if jobShell := strings.TrimSpace(job.Defaults.Run.Shell); jobShell != "" && jobShell != "bash" {
			return fmt.Errorf("job %q defaults.run.shell = %q, want empty or bash", jobID, jobShell)
		}
		if jobWD := strings.TrimSpace(job.Defaults.Run.WorkingDirectory); jobWD != "" {
			return fmt.Errorf("job %q defaults.run.working-directory = %q, want empty", jobID, jobWD)
		}
		checkoutIdx, setupGoIdx, scriptIdx, uploadIdx := -1, -1, -1, -1
		var verifyLogDir, uploadPath string
		for i, step := range job.Steps {
			if strings.Contains(step.Run, "${{") {
				return fmt.Errorf("job %q step %d (%q) interpolates ${{ inside run", jobID, i, step.Name)
			}
			if step.ContinueOnError != nil && step.ContinueOnError != false {
				return fmt.Errorf("job %q step %d (%q) sets continue-on-error = %v", jobID, i, step.Name, step.ContinueOnError)
			}
			if stepShell := strings.TrimSpace(step.Shell); stepShell != "" && stepShell != "bash" {
				return fmt.Errorf("job %q step %d (%q) sets custom shell %q, want empty or bash", jobID, i, step.Name, stepShell)
			}
			if stepWD := strings.TrimSpace(step.WorkingDirectory); stepWD != "" {
				return fmt.Errorf("job %q step %d (%q) sets working-directory %q, want empty", jobID, i, step.Name, stepWD)
			}
			if step.Uses != "" {
				if !fullSHAPinRE.MatchString(step.Uses) {
					return fmt.Errorf("job %q step %d uses unpinned action %q", jobID, i, step.Uses)
				}
				switch {
				case strings.HasPrefix(step.Uses, "actions/checkout@"):
					if strings.TrimSpace(step.If) != "" {
						return fmt.Errorf("checkout step sets conditional if %q", step.If)
					}
					if len(step.With) > 0 {
						return fmt.Errorf("checkout step sets custom with %v, want empty", step.With)
					}
					sawCheckout = true
					checkoutIdx = i
				case strings.HasPrefix(step.Uses, "actions/setup-go@"):
					if strings.TrimSpace(step.If) != "" {
						return fmt.Errorf("setup-go step sets conditional if %q", step.If)
					}
					sawSetupGo = true
					setupGoIdx = i
					if got := fmt.Sprint(step.With["go-version"]); got != "1.27.4" {
						return fmt.Errorf("setup-go go-version = %q, want 1.27.4", got)
					}
				case strings.HasPrefix(step.Uses, "actions/upload-artifact@"):
					ifCond := strings.TrimSpace(step.If)
					if ifCond == "always()" || ifCond == "${{ always() }}" {
						sawAlwaysUpload = true
					}
					uploadIdx = i
					rawPath, ok := step.With["path"]
					if !ok {
						return fmt.Errorf("upload-artifact step missing path")
					}
					pathStr, ok := rawPath.(string)
					if !ok || strings.TrimSpace(pathStr) == "" {
						return fmt.Errorf("upload-artifact step missing path")
					}
					uploadPath = strings.TrimSpace(pathStr)
					if got := fmt.Sprint(step.With["if-no-files-found"]); got != "error" {
						return fmt.Errorf("upload-artifact if-no-files-found = %q, want \"error\"", got)
					}
				default:
					return fmt.Errorf("job %q step %d uses unexpected action %q", jobID, i, step.Uses)
				}
			}
			if strings.Contains(step.Run, "scripts/verify_contrib_gates.sh") {
				if strings.TrimSpace(step.Run) != "./scripts/verify_contrib_gates.sh" {
					return fmt.Errorf("verify step run = %q, want exact \"./scripts/verify_contrib_gates.sh\"", step.Run)
				}
				if strings.TrimSpace(step.If) != "" {
					return fmt.Errorf("verify step sets conditional if %q", step.If)
				}
				sawScriptStep = true
				scriptIdx = i
				expectedEnvKeys := []string{"CONTRIB_SHA", "LIBRARY_VERSION", "USE_LOCAL_CHECKOUT", "WORK_DIR", "LOG_DIR"}
				for _, envKey := range expectedEnvKeys {
					if strings.TrimSpace(step.Env[envKey]) == "" {
						return fmt.Errorf("verify step missing env %s", envKey)
					}
				}
				if len(step.Env) != len(expectedEnvKeys) {
					return fmt.Errorf("verify step env has %d keys (%v), want strictly %v", len(step.Env), step.Env, expectedEnvKeys)
				}
				for _, binding := range []struct {
					envKey   string
					wantExpr string
				}{
					{"CONTRIB_SHA", "${{ inputs.contrib_sha }}"},
					{"LIBRARY_VERSION", "${{ inputs.library_version }}"},
					{"USE_LOCAL_CHECKOUT", "${{ inputs.use_local_checkout }}"},
				} {
					if strings.TrimSpace(step.Env[binding.envKey]) != binding.wantExpr {
						return fmt.Errorf("verify step env %s = %q, want %q", binding.envKey, step.Env[binding.envKey], binding.wantExpr)
					}
				}
				verifyLogDir = strings.TrimSpace(step.Env["LOG_DIR"])
			} else if strings.TrimSpace(step.Run) != "" {
				return fmt.Errorf("job %q step %d (%q) runs unexpected command %q", jobID, i, step.Name, step.Run)
			}
		}
		if checkoutIdx >= 0 && setupGoIdx >= 0 && scriptIdx >= 0 && uploadIdx >= 0 {
			if checkoutIdx >= setupGoIdx || setupGoIdx >= scriptIdx || scriptIdx >= uploadIdx {
				return fmt.Errorf("job %q step order checkout=%d setup-go=%d verify=%d upload=%d, want strictly increasing",
					jobID, checkoutIdx, setupGoIdx, scriptIdx, uploadIdx)
			}
			if len(job.Steps) != 4 {
				return fmt.Errorf("job %q has %d steps, want 4", jobID, len(job.Steps))
			}
		}
		if verifyLogDir != "" && uploadPath != "" && verifyLogDir != uploadPath {
			return fmt.Errorf("job %q upload-artifact path = %q, want match with verify step LOG_DIR %q", jobID, uploadPath, verifyLogDir)
		}
	}

	if !sawCheckout {
		return fmt.Errorf("missing actions/checkout step")
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
			name: "early-exit bypass before verify_contrib_gates.sh",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "run: |\n          exit 0\n          ./scripts/verify_contrib_gates.sh", 1)
			},
			wantErr: "want exact \"./scripts/verify_contrib_gates.sh\"",
		},
		{
			name: "custom no-op shell on verify step",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "shell: true {0}\n        run: ./scripts/verify_contrib_gates.sh", 1)
			},
			wantErr: "sets custom shell",
		},
		{
			name: "custom workflow defaults.run.shell",
			mutate: func(s string) string {
				return strings.Replace(s, "permissions:\n  contents: read\n", "permissions:\n  contents: read\ndefaults:\n  run:\n    shell: python\n", 1)
			},
			wantErr: "workflow defaults.run.shell",
		},
		{
			name: "custom workflow defaults.run.working-directory",
			mutate: func(s string) string {
				return strings.Replace(s, "permissions:\n  contents: read\n", "permissions:\n  contents: read\ndefaults:\n  run:\n    working-directory: /tmp\n", 1)
			},
			wantErr: "workflow defaults.run.working-directory",
		},
		{
			name: "custom job defaults.run.working-directory",
			mutate: func(s string) string {
				return strings.Replace(s, "    defaults:\n      run:\n        shell: bash\n", "    defaults:\n      run:\n        shell: bash\n        working-directory: /tmp\n", 1)
			},
			wantErr: "defaults.run.working-directory",
		},
		{
			name: "working-directory on verify step",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "working-directory: /tmp\n        run: ./scripts/verify_contrib_gates.sh", 1)
			},
			wantErr: "sets working-directory",
		},
		{
			name: "continue-on-error on verify step",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "continue-on-error: true\n        run: ./scripts/verify_contrib_gates.sh", 1)
			},
			wantErr: "sets continue-on-error",
		},
		{
			name: "conditional if on verify step",
			mutate: func(s string) string {
				return strings.Replace(s, "run: ./scripts/verify_contrib_gates.sh", "if: false\n        run: ./scripts/verify_contrib_gates.sh", 1)
			},
			wantErr: "verify step sets conditional if",
		},
		{
			name: "job-level conditional if",
			mutate: func(s string) string {
				return strings.Replace(s, "    runs-on: ubuntu-latest\n", "    if: false\n    runs-on: ubuntu-latest\n", 1)
			},
			wantErr: "sets conditional if",
		},
		{
			name: "extra pre-step overwriting verify_contrib_gates.sh",
			mutate: func(s string) string {
				return strings.Replace(s, "      - name: Run staged contrib gates (PR 1, PR 2, PR 3)\n", "      - name: Neutralize script\n        run: cd scripts && printf '#!/bin/sh\\nexit 0\\n' > verify_contrib_gates.sh\n\n      - name: Run staged contrib gates (PR 1, PR 2, PR 3)\n", 1)
			},
			wantErr: "runs unexpected command",
		},
		{
			name: "verify step extra env CONTRIB_REPO",
			mutate: func(s string) string {
				return strings.Replace(s, "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n", "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n          CONTRIB_REPO: https://example.invalid/fork.git\n", 1)
			},
			wantErr: "verify step env has 6 keys",
		},
		{
			name: "verify step extra env CONTRIB_DIR",
			mutate: func(s string) string {
				return strings.Replace(s, "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n", "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n          CONTRIB_DIR: ./testdata/fake-contrib\n", 1)
			},
			wantErr: "verify step env has 6 keys",
		},
		{
			name: "verify step extra env BASH_ENV",
			mutate: func(s string) string {
				return strings.Replace(s, "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n", "          LOG_DIR: ${{ runner.temp }}/contrib-verify-logs\n          BASH_ENV: ./scripts/noop.sh\n", 1)
			},
			wantErr: "verify step env has 6 keys",
		},
		{
			name: "job-level env LOCAL_REPO_DIR override",
			mutate: func(s string) string {
				return strings.Replace(s, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    env:\n      LOCAL_REPO_DIR: .\n", 1)
			},
			wantErr: "sets env",
		},
		{
			name: "workflow-level env override",
			mutate: func(s string) string {
				return strings.Replace(s, "permissions:\n  contents: read\n", "permissions:\n  contents: read\nenv:\n  LOCAL_REPO_DIR: .\n", 1)
			},
			wantErr: "workflow env",
		},
		{
			name: "checkout step with custom repository",
			mutate: func(s string) string {
				return strings.Replace(s, "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n", "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n        with:\n          repository: someone/fork\n", 1)
			},
			wantErr: "checkout step sets custom with",
		},
		{
			name: "extra third-party SHA-pinned action step",
			mutate: func(s string) string {
				return strings.Replace(s, "      - name: Check out repository\n", "      - name: Extra action\n        uses: someone/action@3d3c42e5aac5ba805825da76410c181273ba90b1\n\n      - name: Check out repository\n", 1)
			},
			wantErr: "uses unexpected action",
		},
		{
			name: "job container override",
			mutate: func(s string) string {
				return strings.Replace(s, "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    container: alpine:3.20\n", 1)
			},
			wantErr: "sets container",
		},
		{
			name: "second job defined in workflow",
			mutate: func(s string) string {
				return s + "\n  extra-job:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
			},
			wantErr: "workflow defines 2 jobs, want 1",
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
		{
			name: "upload-artifact missing path",
			mutate: func(s string) string {
				return strings.Replace(s, "          path: ${{ runner.temp }}/contrib-verify-logs\n", "", 1)
			},
			wantErr: "upload-artifact step missing path",
		},
		{
			name: "upload-artifact blank path",
			mutate: func(s string) string {
				return strings.Replace(s, "path: ${{ runner.temp }}/contrib-verify-logs", "path: \"   \"", 1)
			},
			wantErr: "upload-artifact step missing path",
		},
		{
			name: "upload-artifact path mismatches LOG_DIR",
			mutate: func(s string) string {
				return strings.Replace(s, "path: ${{ runner.temp }}/contrib-verify-logs", "path: ${{ runner.temp }}/other-logs", 1)
			},
			wantErr: "want match with verify step LOG_DIR",
		},
		{
			name: "upload-artifact weakens if-no-files-found",
			mutate: func(s string) string {
				return strings.Replace(s, "if-no-files-found: error", "if-no-files-found: ignore", 1)
			},
			wantErr: "upload-artifact if-no-files-found",
		},
		{
			name: "missing actions/checkout step",
			mutate: func(s string) string {
				return strings.Replace(s, "      - name: Check out repository\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n", "", 1)
			},
			wantErr: "missing actions/checkout step",
		},
		{
			name: "missing WORK_DIR env",
			mutate: func(s string) string {
				return strings.Replace(s, "          WORK_DIR: ${{ runner.temp }}/contrib-verify\n", "", 1)
			},
			wantErr: "verify step missing env WORK_DIR",
		},
		{
			name: "CONTRIB_SHA does not reference inputs",
			mutate: func(s string) string {
				return strings.Replace(s, "CONTRIB_SHA: ${{ inputs.contrib_sha }}", "CONTRIB_SHA: 87eb65f5e96d9d70315ee401515c330c105d2a63", 1)
			},
			wantErr: "verify step env CONTRIB_SHA",
		},
		{
			name: "LIBRARY_VERSION does not reference inputs",
			mutate: func(s string) string {
				return strings.Replace(s, "LIBRARY_VERSION: ${{ inputs.library_version }}", "LIBRARY_VERSION: v0.1.0", 1)
			},
			wantErr: "verify step env LIBRARY_VERSION",
		},
		{
			name: "USE_LOCAL_CHECKOUT does not reference inputs",
			mutate: func(s string) string {
				return strings.Replace(s, "USE_LOCAL_CHECKOUT: ${{ inputs.use_local_checkout }}", "USE_LOCAL_CHECKOUT: \"false\"", 1)
			},
			wantErr: "verify step env USE_LOCAL_CHECKOUT",
		},
		{
			name: "custom job defaults.run.shell",
			mutate: func(s string) string {
				return strings.Replace(s, "    defaults:\n      run:\n        shell: bash\n", "    defaults:\n      run:\n        shell: python\n", 1)
			},
			wantErr: "defaults.run.shell",
		},
		{
			name: "checkout step ordered after setup-go",
			mutate: func(s string) string {
				checkoutBlock := "      - name: Check out repository\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7\n\n"
				setupGoBlock := "      - name: Set up Go\n        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7\n        with:\n          go-version: '1.27.4'\n          cache: true\n\n"
				return strings.Replace(s, checkoutBlock+setupGoBlock, setupGoBlock+checkoutBlock, 1)
			},
			wantErr: "step order",
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
	assert.Contains(t, script, "run_gate pr2 comp_tidy gate \"${CONTRIB_DIR}\" make -C exporter/bigqueryexporter tidy toolchain")
	assert.Contains(t, script, "USE_LOCAL_REPLACE")
	assert.Contains(t, script, "RUN_TESTBED")
	assert.Contains(t, script, "stage_testbed")
	assert.Contains(t, script, "insert_under_replaces")
	assert.Contains(t, script, "TestTrace10kSPSBigQueryExporter")
	assert.Contains(t, script, "TestLog10kDPSBigQueryExporter")
	assert.Contains(t, script, "TestMetric10kDPSBigQueryExporter")
	assert.Contains(t, script, "TestBigQueryExporterDataIntegrity")
	assert.NotContains(t, script, "go mod tidy -compat=1.26.0")

	if _, lookErr := exec.LookPath("bash"); lookErr == nil {
		require.NoError(t, checkBashSyntax(contribVerifyScriptPath))

		badPath := filepath.Join(t.TempDir(), "broken.sh")
		require.NoError(t, os.WriteFile(badPath, []byte("#!/usr/bin/env bash\nif [ -z x; then\n"), 0o600))
		require.Error(t, checkBashSyntax(badPath))
	}
}

func extractScriptFunctions(t *testing.T, scriptPath string) string {
	t.Helper()
	raw, err := os.ReadFile(scriptPath)
	require.NoError(t, err)
	lines := strings.Split(string(raw), "\n")
	start, end := -1, -1
	for i, line := range lines {
		if line == "insert_line_before() {" && start == -1 {
			start = i
		}
		if strings.HasPrefix(line, "STRICT_CHECKAPI_CFG=") && start >= 0 {
			end = i
			break
		}
	}
	require.GreaterOrEqual(t, start, 0, "insert_line_before() not found in %s", scriptPath)
	require.Greater(t, end, start, "STRICT_CHECKAPI_CFG= not found after helpers in %s", scriptPath)
	return strings.Join(lines[start:end], "\n") + "\n"
}

func TestVerifyContribGatesScriptTestbedStagingAndWiring(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	helpers := extractScriptFunctions(t, contribVerifyScriptPath)
	repoRoot, err := os.Getwd()
	require.NoError(t, err)

	t.Run("stage_testbed succeeds on real staging doc", func(t *testing.T) {
		contribDir := t.TempDir()
		workDir := t.TempDir()
		runScript := fmt.Sprintf(`set -euo pipefail
REPO_ROOT=%q
CONTRIB_DIR=%q
WORK_DIR=%q
%s
stage_testbed
`, repoRoot, contribDir, workDir, helpers)
		cmd := exec.Command("bash", "-c", runScript)
		out, runErr := cmd.CombinedOutput()
		require.NoErrorf(t, runErr, "stage_testbed failed: %s", string(out))

		recvBytes, err := os.ReadFile(filepath.Join(contribDir, "testbed", "datareceivers", "bigquerydatareceiver", "receiver.go"))
		require.NoError(t, err)
		assert.Contains(t, string(recvBytes), "package bigquerydatareceiver")

		testBytes, err := os.ReadFile(filepath.Join(contribDir, "testbed", "tests", "bigquery_exporter_test.go"))
		require.NoError(t, err)
		assert.Contains(t, string(testBytes), "package tests")
	})

	t.Run("stage_testbed ignores comment-only package mention and rejects duplicates", func(t *testing.T) {
		origDoc, err := os.ReadFile(filepath.Join(repoRoot, "docs", "upstream", "contrib-testbed-staging.md"))
		require.NoError(t, err)

		fakeRepo := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(fakeRepo, "docs", "upstream"), 0o755))
		docPath := filepath.Join(fakeRepo, "docs", "upstream", "contrib-testbed-staging.md")

		withCommentSnippet := string(origDoc) + "\n```go\npackage example\n// package bigquerydatareceiver\n// package tests\n```\n"
		require.NoError(t, os.WriteFile(docPath, []byte(withCommentSnippet), 0o600))

		contribDir := t.TempDir()
		workDir := t.TempDir()
		runScript := fmt.Sprintf(`set -euo pipefail
REPO_ROOT=%q
CONTRIB_DIR=%q
WORK_DIR=%q
%s
stage_testbed
`, fakeRepo, contribDir, workDir, helpers)
		out, runErr := exec.Command("bash", "-c", runScript).CombinedOutput()
		require.NoErrorf(t, runErr, "stage_testbed should ignore commented package lines: %s", string(out))

		for _, tc := range []struct {
			name string
			pkg  string
		}{
			{name: "duplicate receiver block", pkg: "package bigquerydatareceiver // import \"example/dup\""},
			{name: "duplicate tests block", pkg: "package tests"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				dupDoc := string(origDoc) + "\n```go\n" + tc.pkg + "\n```\n"
				require.NoError(t, os.WriteFile(docPath, []byte(dupDoc), 0o600))
				dupOut, dupErr := exec.Command("bash", "-c", runScript).CombinedOutput()
				require.Error(t, dupErr, "expected stage_testbed to fail on %s", tc.name)
				assert.Contains(t, string(dupOut), "duplicate")
			})
		}
	})

	t.Run("wire_testbed_files inserts under replaces without appending past trailing YAML section", func(t *testing.T) {
		for _, tc := range []struct {
			name            string
			replacesSection string
			wantErr         string
		}{
			{
				name:            "empty replaces before trailing section",
				replacesSection: "replaces:\n\ncomponents:\n  - keep-me\n",
			},
			{
				name:            "existing exporter replace before trailing section",
				replacesSection: "replaces:\n  - github.com/open-telemetry/opentelemetry-collector-contrib/exporter/zipkinexporter => ../../exporter/zipkinexporter\n\ncomponents:\n  - keep-me\n",
			},
			{
				name:            "missing replaces section fails closed",
				replacesSection: "components:\n  - keep-me\n",
				wantErr:         "replaces: section not found",
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				contribDir := t.TempDir()
				workDir := t.TempDir()
				cfgDir := filepath.Join(contribDir, "cmd", "oteltestbedcol")
				testbedDir := filepath.Join(contribDir, "testbed")
				require.NoError(t, os.MkdirAll(cfgDir, 0o755))
				require.NoError(t, os.MkdirAll(testbedDir, 0o755))

				cfgPath := filepath.Join(cfgDir, "builder-config.yaml")
				cfgBody := "exporters:\n  - gomod: github.com/open-telemetry/opentelemetry-collector-contrib/exporter/zipkinexporter v0.164.1\n\n" + tc.replacesSection
				require.NoError(t, os.WriteFile(cfgPath, []byte(cfgBody), 0o600))
				require.NoError(t, os.WriteFile(filepath.Join(testbedDir, "go.mod"), []byte("module github.com/open-telemetry/opentelemetry-collector-contrib/testbed\n\ngo 1.26.0\n"), 0o600))

				runScript := fmt.Sprintf(`set -euo pipefail
CONTRIB_DIR=%q
WORK_DIR=%q
LIBRARY_VERSION="v0.1.0"
USE_LOCAL_CHECKOUT="true"
LOCAL_REPO_DIR=%q
%s
wire_testbed_files
`, contribDir, workDir, repoRoot, helpers)
				out, runErr := exec.Command("bash", "-c", runScript).CombinedOutput()
				if tc.wantErr != "" {
					require.Error(t, runErr)
					assert.Contains(t, string(out), tc.wantErr)
					return
				}
				require.NoErrorf(t, runErr, "wire_testbed_files failed: %s", string(out))

				updatedBytes, err := os.ReadFile(cfgPath)
				require.NoError(t, err)

				var parsed struct {
					Exporters  []map[string]any `yaml:"exporters"`
					Replaces   []string         `yaml:"replaces"`
					Components []string         `yaml:"components"`
				}
				require.NoError(t, yaml.Unmarshal(updatedBytes, &parsed))
				assert.Equal(t, []string{"keep-me"}, parsed.Components)
				assert.Contains(t, parsed.Replaces, "github.com/open-telemetry/opentelemetry-collector-contrib/exporter/bigqueryexporter => ../../exporter/bigqueryexporter")
				assert.Contains(t, parsed.Replaces, "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter => "+repoRoot)
			})
		}
	})
}

func TestContribVerifyGatesScriptInputValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell shim test")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	newShimEnv := func(tb *testing.T, extra ...string) (gitLog string, env []string) {
		tb.Helper()
		binDir := tb.TempDir()
		gitLog = filepath.Join(tb.TempDir(), "git.log")
		shim := filepath.Join(binDir, "git")
		shimScript := `#!/bin/sh
printf '%s\n' "$*" >> "$GIT_SHIM_LOG"
case " $* " in
  *" fetch "*) exit 99 ;;
  *) exit 0 ;;
esac
`
		require.NoError(tb, os.WriteFile(shim, []byte(shimScript), 0o700))

		workDir := tb.TempDir()
		logDir := tb.TempDir()
		baseEnv := os.Environ()
		env = make([]string, 0, len(baseEnv)+4+len(extra))
		env = append(env, baseEnv...)
		env = append(env,
			"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
			"GIT_SHIM_LOG="+gitLog,
			"WORK_DIR="+workDir,
			"LOG_DIR="+logDir,
		)
		env = append(env, extra...)
		return gitLog, env
	}

	invalidCases := []struct {
		name      string
		envKey    string
		envVal    string
		wantInErr string
	}{
		{
			name:      "CONTRIB_SHA option injection upload-pack",
			envKey:    "CONTRIB_SHA",
			envVal:    "--upload-pack=touch /tmp/pwned",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "CONTRIB_SHA leading dash",
			envKey:    "CONTRIB_SHA",
			envVal:    "-87eb65f",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "CONTRIB_SHA too short",
			envKey:    "CONTRIB_SHA",
			envVal:    "abc123",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "CONTRIB_SHA non-hex",
			envKey:    "CONTRIB_SHA",
			envVal:    "not-a-hex-sha",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "CONTRIB_SHA multiline",
			envKey:    "CONTRIB_SHA",
			envVal:    "87eb65f5\nfoo",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "CONTRIB_SHA trailing whitespace",
			envKey:    "CONTRIB_SHA",
			envVal:    "87eb65f5 ",
			wantInErr: "CONTRIB_SHA",
		},
		{
			name:      "LIBRARY_VERSION missing v prefix",
			envKey:    "LIBRARY_VERSION",
			envVal:    "0.1.0",
			wantInErr: "LIBRARY_VERSION",
		},
		{
			name:      "LIBRARY_VERSION multiline replace injection",
			envKey:    "LIBRARY_VERSION",
			envVal:    "v0.1.0\nreplace github.com/evil/mod => /tmp/evil",
			wantInErr: "LIBRARY_VERSION",
		},
		{
			name:      "LIBRARY_VERSION trailing tokens",
			envKey:    "LIBRARY_VERSION",
			envVal:    "v0.1.0 replace",
			wantInErr: "LIBRARY_VERSION",
		},
		{
			name:      "DONATION_ISSUE non-numeric",
			envKey:    "DONATION_ISSUE",
			envVal:    "abc",
			wantInErr: "DONATION_ISSUE",
		},
		{
			name:      "DONATION_ISSUE dollar placeholder",
			envKey:    "DONATION_ISSUE",
			envVal:    "$1",
			wantInErr: "DONATION_ISSUE",
		},
		{
			name:      "DONATION_ISSUE multiline",
			envKey:    "DONATION_ISSUE",
			envVal:    "123\nfoo",
			wantInErr: "DONATION_ISSUE",
		},
		{
			name:      "USE_LOCAL_CHECKOUT invalid boolean yes",
			envKey:    "USE_LOCAL_CHECKOUT",
			envVal:    "yes",
			wantInErr: "USE_LOCAL_CHECKOUT",
		},
		{
			name:      "USE_LOCAL_REPLACE typo ture",
			envKey:    "USE_LOCAL_REPLACE",
			envVal:    "ture",
			wantInErr: "USE_LOCAL_REPLACE",
		},
		{
			name:      "KEEP_CONTRIB_DIR invalid boolean on",
			envKey:    "KEEP_CONTRIB_DIR",
			envVal:    "on",
			wantInErr: "KEEP_CONTRIB_DIR",
		},
		{
			name:      "RUN_FULL_GOTIDY invalid boolean TRUE",
			envKey:    "RUN_FULL_GOTIDY",
			envVal:    "TRUE",
			wantInErr: "RUN_FULL_GOTIDY",
		},
		{
			name:      "RUN_TESTBED invalid boolean yes",
			envKey:    "RUN_TESTBED",
			envVal:    "yes",
			wantInErr: "RUN_TESTBED",
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			gitLog, env := newShimEnv(t, tc.envKey+"="+tc.envVal)
			cmd := exec.Command("bash", contribVerifyScriptPath)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			var exitErr *exec.ExitError
			require.ErrorAs(t, err, &exitErr)
			assert.Equal(t, 2, exitErr.ExitCode(), "output: %s", string(out))
			assert.Contains(t, string(out), tc.wantInErr)
			_, statErr := os.Stat(gitLog)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "git must not be invoked when startup validation fails")
		})
	}

	for _, tc := range []struct {
		name string
		envs []string
	}{
		{
			name: "valid inputs reach git fetch with double-dash separator",
			envs: []string{
				"CONTRIB_SHA=" + contribcheck.PinnedCommit,
				"LIBRARY_VERSION=v0.1.0-rc.1+build.2",
				"DONATION_ISSUE=42",
			},
		},
		{
			name: "numeric 0 and 1 boolean flags normalize cleanly",
			envs: []string{
				"USE_LOCAL_CHECKOUT=0",
				"USE_LOCAL_REPLACE=1",
				"KEEP_CONTRIB_DIR=0",
				"RUN_FULL_GOTIDY=0",
				"RUN_TESTBED=0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gitLog, env := newShimEnv(t, tc.envs...)
			cmd := exec.Command("bash", contribVerifyScriptPath)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			require.Error(t, err, "expected shim git fetch exit 99, output: %s", string(out))
			logBytes, readErr := os.ReadFile(gitLog)
			require.NoError(t, readErr)
			assert.Contains(t, string(logBytes), "fetch --depth 1 origin -- "+contribcheck.PinnedCommit)
		})
	}
}

func TestContribStageCLI(t *testing.T) {
	for _, pr := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("pr-%d", pr), func(t *testing.T) {
			outDir := t.TempDir()
			chlogFile := filepath.Join(outDir, ".chloggen", fmt.Sprintf("pr-%d.yaml", pr))
			cmd := exec.Command("go", "run", "-p", "2", "./internal/contribcheck/stage",
				"--repo", ".",
				"--pr", fmt.Sprintf("%d", pr),
				"--out", outDir,
				"--chlog-out", chlogFile,
				"--issue", "12345",
			)
			cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
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
		cmd := exec.Command("go", "run", "-p", "2", "./internal/contribcheck/stage", "--pr", "9", "--out", t.TempDir())
		cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
		out, err := cmd.CombinedOutput()
		require.Error(t, err)
		assert.Contains(t, string(out), "pr must be 1, 2, or 3")
	})

	t.Run("negative invalid library-version and issue rejected", func(t *testing.T) {
		for _, tc := range []struct {
			args    []string
			wantErr string
		}{
			{
				args:    []string{"--pr", "1", "--out", t.TempDir(), "--library-version", ""},
				wantErr: "library-version",
			},
			{
				args:    []string{"--pr", "1", "--out", t.TempDir(), "--library-version", "v0.1.0\nreplace evil => /tmp"},
				wantErr: "library-version",
			},
			{
				args:    []string{"--pr", "1", "--out", t.TempDir(), "--chlog-out", filepath.Join(t.TempDir(), "pr.yaml"), "--issue", "$1"},
				wantErr: "issue number",
			},
		} {
			cmd := exec.Command("go", append([]string{"run", "-p", "2", "./internal/contribcheck/stage"}, tc.args...)...)
			cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			assert.Contains(t, string(out), tc.wantErr)
		}
	})
}
