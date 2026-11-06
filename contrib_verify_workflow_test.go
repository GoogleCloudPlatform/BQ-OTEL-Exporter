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

	var sawCheckout, sawScriptStep, sawAlwaysUpload, sawSetupGo bool
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
				if strings.HasPrefix(step.Uses, "actions/checkout@") {
					sawCheckout = true
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
					rawPath, ok := step.With["path"]
					if !ok {
						return fmt.Errorf("upload-artifact step missing path")
					}
					pathStr, ok := rawPath.(string)
					if !ok || strings.TrimSpace(pathStr) == "" {
						return fmt.Errorf("upload-artifact step missing path")
					}
				}
			}
			if strings.Contains(step.Run, "scripts/verify_contrib_gates.sh") {
				sawScriptStep = true
				for _, envKey := range []string{"CONTRIB_SHA", "LIBRARY_VERSION", "USE_LOCAL_CHECKOUT", "WORK_DIR", "LOG_DIR"} {
					if strings.TrimSpace(step.Env[envKey]) == "" {
						return fmt.Errorf("verify step missing env %s", envKey)
					}
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
			}
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
	assert.NotContains(t, script, "go mod tidy -compat=1.26.0")

	if _, lookErr := exec.LookPath("bash"); lookErr == nil {
		require.NoError(t, checkBashSyntax(contribVerifyScriptPath))

		badPath := filepath.Join(t.TempDir(), "broken.sh")
		require.NoError(t, os.WriteFile(badPath, []byte("#!/usr/bin/env bash\nif [ -z x; then\n"), 0o600))
		require.Error(t, checkBashSyntax(badPath))
	}
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
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			gitLog, env := newShimEnv(t, tc.envKey+"="+tc.envVal)
			cmd := exec.Command("bash", contribVerifyScriptPath)
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			assert.Contains(t, string(out), tc.wantInErr)
			_, statErr := os.Stat(gitLog)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "git must not be invoked when startup validation fails")
		})
	}

	t.Run("valid inputs reach git fetch with double-dash separator", func(t *testing.T) {
		gitLog, env := newShimEnv(t,
			"CONTRIB_SHA="+contribcheck.PinnedCommit,
			"LIBRARY_VERSION=v0.1.0-rc.1+build.2",
			"DONATION_ISSUE=42",
		)
		cmd := exec.Command("bash", contribVerifyScriptPath)
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		require.Error(t, err, "expected shim git fetch exit 99, output: %s", string(out))
		logBytes, readErr := os.ReadFile(gitLog)
		require.NoError(t, readErr)
		assert.Contains(t, string(logBytes), "fetch --depth 1 origin -- "+contribcheck.PinnedCommit)
	})
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
			cmd := exec.Command("go", append([]string{"run", "./internal/contribcheck/stage"}, tc.args...)...)
			out, err := cmd.CombinedOutput()
			require.Error(t, err)
			assert.Contains(t, string(out), tc.wantErr)
		}
	})
}
