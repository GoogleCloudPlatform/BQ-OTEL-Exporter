// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"errors"
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

const (
	liveIntegrationWorkflowPath = ".github/workflows/live-integration.yml"
	liveConfiguredCondition     = "steps.check-config.outputs.configured == 'true'"
)

var workflowSHAPinnedUsesPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$`)

type liveIntegrationWorkflow struct {
	Name        string            `yaml:"name"`
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Name        string            `yaml:"name"`
		RunsOn      string            `yaml:"runs-on"`
		TimeoutMin  int               `yaml:"timeout-minutes"`
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			ID    string            `yaml:"id"`
			Name  string            `yaml:"name"`
			Uses  string            `yaml:"uses"`
			Shell string            `yaml:"shell"`
			If    any               `yaml:"if,omitempty"`
			Env   map[string]string `yaml:"env"`
			With  map[string]any    `yaml:"with"`
			Run   string            `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func checkLiveIntegrationWorkflow(raw string) (string, error) {
	var wf liveIntegrationWorkflow
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		return "", fmt.Errorf("unmarshaling %s: %w", liveIntegrationWorkflowPath, err)
	}

	if err := validateLiveIntegrationTriggers(wf.On); err != nil {
		return "", err
	}

	if len(wf.Permissions) != 2 || wf.Permissions["contents"] != "read" || wf.Permissions["id-token"] != "write" {
		return "", fmt.Errorf("permissions = %v, want strictly {contents: read, id-token: write}", wf.Permissions)
	}

	if len(wf.Jobs) != 1 {
		return "", fmt.Errorf("jobs count = %d, want 1 (live-integration)", len(wf.Jobs))
	}
	job, ok := wf.Jobs["live-integration"]
	if !ok {
		return "", errors.New("missing live-integration job")
	}
	if len(job.Permissions) != 0 {
		return "", fmt.Errorf("live-integration job permissions = %v, want inherited minimal workflow permissions", job.Permissions)
	}
	if job.RunsOn != "ubuntu-latest" {
		return "", fmt.Errorf("live-integration runs-on = %q, want ubuntu-latest", job.RunsOn)
	}

	if len(job.Steps) < 5 {
		return "", fmt.Errorf("live-integration steps count = %d, want at least 5", len(job.Steps))
	}

	var checkScript string
	positions := map[string]int{}

	for i, step := range job.Steps {
		if strings.Contains(step.Run, "${{") {
			return "", fmt.Errorf("step %d (%q) interpolates ${{ inside a run block", i, step.Name)
		}
		if step.Uses != "" && !workflowSHAPinnedUsesPattern.MatchString(step.Uses) {
			return "", fmt.Errorf("step %d uses %q without a full 40-char commit SHA pin", i, step.Uses)
		}

		if i == 0 {
			if step.ID != "check-config" {
				return "", fmt.Errorf("step 0 id = %q, want check-config", step.ID)
			}
			if step.If != nil {
				return "", fmt.Errorf("check-config step must not be conditional, got if=%v", step.If)
			}
			wantEnv := map[string]string{
				"BQ_PROJECT":                     "${{ vars.BQ_PROJECT }}",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}",
				"GCP_SERVICE_ACCOUNT":            "${{ vars.GCP_SERVICE_ACCOUNT }}",
				"GITHUB_EVENT_NAME":              "${{ github.event_name }}",
				"FAIL_IF_UNCONFIGURED":           "${{ inputs.fail_if_unconfigured }}",
			}
			for k, want := range wantEnv {
				if got := step.Env[k]; got != want {
					return "", fmt.Errorf("check-config env[%q] = %q, want %q", k, got, want)
				}
			}
			if strings.TrimSpace(step.Run) == "" {
				return "", errors.New("check-config step has empty run script")
			}
			checkScript = step.Run
			positions["check-config"] = i
			continue
		}

		if cond, _ := step.If.(string); cond != liveConfiguredCondition {
			return "", fmt.Errorf("step %d (%q) has if=%v, want %q", i, step.Name, step.If, liveConfiguredCondition)
		}

		switch {
		case strings.HasPrefix(step.Uses, "actions/checkout@"):
			positions["checkout"] = i
		case strings.HasPrefix(step.Uses, "actions/setup-go@"):
			if step.With["go-version-file"] != "go.mod" {
				return "", fmt.Errorf("setup-go go-version-file = %v, want go.mod", step.With["go-version-file"])
			}
			positions["setup-go"] = i
		case strings.HasPrefix(step.Uses, "google-github-actions/auth@"):
			if step.With["workload_identity_provider"] != "${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}" {
				return "", fmt.Errorf("auth workload_identity_provider = %v, want ${{ vars.GCP_WORKLOAD_IDENTITY_PROVIDER }}", step.With["workload_identity_provider"])
			}
			if step.With["service_account"] != "${{ vars.GCP_SERVICE_ACCOUNT }}" {
				return "", fmt.Errorf("auth service_account = %v, want ${{ vars.GCP_SERVICE_ACCOUNT }}", step.With["service_account"])
			}
			positions["auth"] = i
		case step.Run != "" && strings.Contains(step.Run, "go test") && strings.Contains(step.Run, "-tags=integration"):
			if step.Env["REQUIRE_LIVE_BQ"] != "1" {
				return "", fmt.Errorf("integration test step env[REQUIRE_LIVE_BQ] = %q, want \"1\"", step.Env["REQUIRE_LIVE_BQ"])
			}
			positions["test"] = i
		}
	}

	for _, key := range []string{"check-config", "checkout", "setup-go", "auth", "test"} {
		if _, ok := positions[key]; !ok {
			return "", fmt.Errorf("missing required step %q", key)
		}
	}
	for _, pair := range [][2]string{
		{"check-config", "checkout"},
		{"checkout", "setup-go"},
		{"setup-go", "auth"},
		{"auth", "test"},
	} {
		if positions[pair[0]] >= positions[pair[1]] {
			return "", fmt.Errorf("%s must precede %s", pair[0], pair[1])
		}
	}

	return checkScript, nil
}

func validateLiveIntegrationTriggers(on map[string]any) error {
	if len(on) != 2 {
		return fmt.Errorf("on triggers = %v, want strictly schedule and workflow_dispatch", mapKeysSorted(on))
	}
	schedRaw, ok := on["schedule"]
	if !ok {
		return errors.New("on is missing schedule trigger")
	}
	schedList, ok := schedRaw.([]any)
	if !ok || len(schedList) == 0 {
		return fmt.Errorf("on.schedule = %T (%v), want non-empty list", schedRaw, schedRaw)
	}
	foundCron := false
	for _, item := range schedList {
		m, ok := item.(map[string]any)
		if ok && m["cron"] == "42 4 * * *" {
			foundCron = true
			break
		}
	}
	if !foundCron {
		return fmt.Errorf("on.schedule = %v, want cron '42 4 * * *'", schedList)
	}

	wdRaw, ok := on["workflow_dispatch"]
	if !ok {
		return errors.New("on is missing workflow_dispatch trigger")
	}
	wdMap, ok := wdRaw.(map[string]any)
	if !ok || wdMap == nil {
		return errors.New("on.workflow_dispatch must configure inputs.fail_if_unconfigured")
	}
	inputsMap, ok := wdMap["inputs"].(map[string]any)
	if !ok {
		return errors.New("on.workflow_dispatch is missing inputs")
	}
	fiu, ok := inputsMap["fail_if_unconfigured"].(map[string]any)
	if !ok {
		return errors.New("on.workflow_dispatch.inputs is missing fail_if_unconfigured")
	}
	desc, _ := fiu["description"].(string)
	if strings.TrimSpace(desc) == "" {
		return errors.New("fail_if_unconfigured input must declare a non-empty description")
	}
	if fiu["type"] != "boolean" {
		return fmt.Errorf("fail_if_unconfigured type = %v, want boolean", fiu["type"])
	}
	defVal, ok := fiu["default"].(bool)
	if !ok || !defVal {
		return fmt.Errorf("fail_if_unconfigured default = %v (%T), want boolean true", fiu["default"], fiu["default"])
	}
	return nil
}

func mapKeysSorted(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func runCheckConfigScript(t *testing.T, script string, envVars map[string]string) (exitCode int, stdoutStderr string, ghOutput string) {
	t.Helper()
	dir := t.TempDir()
	outPath := filepath.Join(dir, "github_output")
	if err := os.WriteFile(outPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"GITHUB_OUTPUT=" + outPath,
	}
	for k, v := range envVars {
		env = append(env, k+"="+v)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", "--noprofile", "--norc", "-eu", "-o", "pipefail", "-c", script)
	cmd.Dir = dir
	cmd.Env = env

	outBytes, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("running check-config script: %v", err)
		}
	}

	ghOutBytes, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return exitCode, string(outBytes), string(ghOutBytes)
}

func TestLiveIntegrationWorkflowContractAndWIFAlignment(t *testing.T) {
	raw := readRepoText(t, liveIntegrationWorkflowPath)
	if _, err := checkLiveIntegrationWorkflow(raw); err != nil {
		t.Fatalf("live-integration.yml contract check failed: %v", err)
	}

	// Cross-check deploy/terraform/ci_wif.tf OIDC invariants so workflow triggers
	// remain strictly aligned with Workload Identity Federation enforcement.
	tf := readRepoText(t, "deploy/terraform/ci_wif.tf")
	var wf struct {
		On map[string]any `yaml:"on"`
	}
	if err := yaml.Unmarshal([]byte(raw), &wf); err != nil {
		t.Fatal(err)
	}

	refBlock := terraformBlock(tf, `variable "github_workflow_ref"`)
	if got := strings.Trim(terraformAttribute(refBlock, "default"), `"`); got != liveIntegrationWorkflowPath {
		t.Errorf("ci_wif.tf github_workflow_ref default = %q, want %q", got, liveIntegrationWorkflowPath)
	}
	eventsBlock := terraformBlock(tf, `variable "github_allowed_events"`)
	allowedRaw := terraformAttribute(eventsBlock, "default")
	for trigger := range wf.On {
		if !strings.Contains(allowedRaw, `"`+trigger+`"`) {
			t.Errorf("live-integration.yml trigger %q is not permitted in ci_wif.tf github_allowed_events (%s)", trigger, allowedRaw)
		}
	}
	if !strings.Contains(tf, `attribute.ref == \"refs/heads/main\"`) {
		t.Error("ci_wif.tf attribute_condition must continue restricting OIDC exchange to refs/heads/main")
	}
}

func TestLiveIntegrationCheckConfigBehavior(t *testing.T) {
	script, err := checkLiveIntegrationWorkflow(readRepoText(t, liveIntegrationWorkflowPath))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name           string
		env            map[string]string
		wantExitZero   bool
		wantGHOutput   string
		wantLogContain string
	}{
		{
			name: "workflow_dispatch with fail_if_unconfigured=true and unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED": "true",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch with empty FAIL_IF_UNCONFIGURED and unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED": "",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch missing only BQ_PROJECT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "true",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "projects/123/locations/global/workloadIdentityPools/p/providers/g",
				"GCP_SERVICE_ACCOUNT":            "ci@test-proj.iam.gserviceaccount.com",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch missing only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED": "true",
				"BQ_PROJECT":           "test-proj",
				"GCP_SERVICE_ACCOUNT":  "ci@test-proj.iam.gserviceaccount.com",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch missing only GCP_SERVICE_ACCOUNT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "true",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "projects/123/locations/global/workloadIdentityPools/p/providers/g",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch with fail_if_unconfigured=false and unset vars skips cleanly",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED": "false",
			},
			wantExitZero:   true,
			wantGHOutput:   "configured=false\n",
			wantLogContain: "::warning::",
		},
		{
			name: "schedule with unset vars skips cleanly",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "",
			},
			wantExitZero:   true,
			wantGHOutput:   "configured=false\n",
			wantLogContain: "::warning::",
		},
		{
			name: "schedule skips cleanly even if FAIL_IF_UNCONFIGURED is set to true",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "true",
			},
			wantExitZero:   true,
			wantGHOutput:   "configured=false\n",
			wantLogContain: "::warning::",
		},
		{
			name: "workflow_dispatch with all three variables configured enables live suite",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "true",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "projects/123/locations/global/workloadIdentityPools/p/providers/g",
				"GCP_SERVICE_ACCOUNT":            "ci@test-proj.iam.gserviceaccount.com",
			},
			wantExitZero: true,
			wantGHOutput: "configured=true\n",
		},
		{
			name: "schedule with all three variables configured enables live suite",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "projects/123/locations/global/workloadIdentityPools/p/providers/g",
				"GCP_SERVICE_ACCOUNT":            "ci@test-proj.iam.gserviceaccount.com",
			},
			wantExitZero: true,
			wantGHOutput: "configured=true\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, ghOut := runCheckConfigScript(t, script, tc.env)
			if tc.wantExitZero && code != 0 {
				t.Fatalf("exit code = %d, want 0; output:\n%s", code, out)
			}
			if !tc.wantExitZero && code == 0 {
				t.Fatalf("exit code = 0, want non-zero; output:\n%s", out)
			}
			if ghOut != tc.wantGHOutput {
				t.Errorf("GITHUB_OUTPUT = %q, want %q", ghOut, tc.wantGHOutput)
			}
			if tc.wantLogContain != "" && !strings.Contains(out, tc.wantLogContain) {
				t.Errorf("output missing %q:\n%s", tc.wantLogContain, out)
			}
		})
	}
}

func TestLiveIntegrationWorkflowRejectsBrokenMutants(t *testing.T) {
	base := readRepoText(t, liveIntegrationWorkflowPath)
	if _, err := checkLiveIntegrationWorkflow(base); err != nil {
		t.Fatal(err)
	}

	replaceOnce := func(t *testing.T, src, oldStr, newStr string) string {
		t.Helper()
		if !strings.Contains(src, oldStr) {
			t.Fatalf("fixture does not contain %q", oldStr)
		}
		return strings.Replace(src, oldStr, newStr, 1)
	}

	mutants := []struct {
		name   string
		mutate func(t *testing.T) string
	}{
		{
			name: "push branch trigger added",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "on:\n  schedule:", "on:\n  push:\n    branches: [main]\n  schedule:")
			},
		},
		{
			name: "push tags trigger added",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "on:\n  schedule:", "on:\n  push:\n    tags: ['v*']\n  schedule:")
			},
		},
		{
			name: "pull_request trigger added",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "on:\n  schedule:", "on:\n  pull_request:\n  schedule:")
			},
		},
		{
			name: "workflow_call trigger added",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "on:\n  schedule:", "on:\n  workflow_call:\n  schedule:")
			},
		},
		{
			name: "fail_if_unconfigured input missing",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base,
					"  workflow_dispatch:\n    inputs:\n      fail_if_unconfigured:\n        description: 'Fail closed if GCP/BigQuery repository variables are missing'\n        type: boolean\n        default: true",
					"  workflow_dispatch:")
			},
		},
		{
			name: "fail_if_unconfigured default set to false",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        default: true", "        default: false")
			},
		},
		{
			name: "fail_if_unconfigured wrong type",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        type: boolean", "        type: string")
			},
		},
		{
			name: "template expression github.event_name inside run block",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, `"${GITHUB_EVENT_NAME:-}"`, `"${{ github.event_name }}"`)
			},
		},
		{
			name: "template expression inputs.fail_if_unconfigured inside run block",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, `"${FAIL_IF_UNCONFIGURED:-}"`, `"${{ inputs.fail_if_unconfigured }}"`)
			},
		},
		{
			name: "missing REQUIRE_LIVE_BQ=1",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, `          REQUIRE_LIVE_BQ: "1"`+"\n", "")
			},
		},
		{
			name: "unpinned actions/checkout uses tag",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "actions/checkout@v7")
			},
		},
		{
			name: "unpinned google-github-actions/auth uses tag",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093", "google-github-actions/auth@v3")
			},
		},
		{
			name: "escalated workflow permissions",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "  contents: read", "  contents: write")
			},
		},
		{
			name: "missing go-version-file go.mod",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "          go-version-file: go.mod\n", "")
			},
		},
		{
			name: "missing FAIL_IF_UNCONFIGURED env binding",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "          FAIL_IF_UNCONFIGURED: ${{ inputs.fail_if_unconfigured }}\n", "")
			},
		},
		{
			name: "auth step un-gated from check-config output",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base,
					"      - name: Authenticate to Google Cloud via Workload Identity Federation\n        if: steps.check-config.outputs.configured == 'true'",
					"      - name: Authenticate to Google Cloud via Workload Identity Federation")
			},
		},
	}

	for _, tc := range mutants {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(t)
			if _, err := checkLiveIntegrationWorkflow(mutated); err == nil {
				t.Fatalf("mutant %q unexpectedly passed checkLiveIntegrationWorkflow", tc.name)
			}
		})
	}
}

func TestLiveIntegrationCheckConfigScriptRejectsSilentSkipMutant(t *testing.T) {
	// Negative probe proving the runtime bash test distinguishes fail-closed
	// manual dispatch behavior from the prior silent-skip implementation.
	silentSkipScript := `
if [ -z "${BQ_PROJECT:-}" ] || [ -z "${GCP_WORKLOAD_IDENTITY_PROVIDER:-}" ] || [ -z "${GCP_SERVICE_ACCOUNT:-}" ]; then
  echo "::warning::skipping"
  echo "configured=false" >> "$GITHUB_OUTPUT"
else
  echo "configured=true" >> "$GITHUB_OUTPUT"
fi
`
	code, _, _ := runCheckConfigScript(t, silentSkipScript, map[string]string{
		"GITHUB_EVENT_NAME":    "workflow_dispatch",
		"FAIL_IF_UNCONFIGURED": "true",
	})
	if code != 0 {
		t.Fatalf("baseline silent-skip probe exited %d, want 0 to demonstrate mutant detectability", code)
	}

	liveScript, err := checkLiveIntegrationWorkflow(readRepoText(t, liveIntegrationWorkflowPath))
	if err != nil {
		t.Fatal(err)
	}
	noExitScript := strings.Replace(liveScript, "exit 1", "true", 1)
	if noExitScript == liveScript {
		t.Fatal("failed to construct no-exit mutant from live check-config script")
	}
	mutCode, _, _ := runCheckConfigScript(t, noExitScript, map[string]string{
		"GITHUB_EVENT_NAME":    "workflow_dispatch",
		"FAIL_IF_UNCONFIGURED": "true",
	})
	if mutCode != 0 {
		t.Fatalf("no-exit mutant unexpectedly exited %d", mutCode)
	}
}
