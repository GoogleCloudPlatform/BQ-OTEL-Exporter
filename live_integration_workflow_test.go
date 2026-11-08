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
	// liveIntegrationTestCommand is the entire script of the integration test
	// step. Requiring equality (rather than a substring) rejects a commented
	// out, early-exited, or `|| true`-masked suite that would still match.
	liveIntegrationTestCommand = "go test -v -race -tags=integration -count=1 -timeout=20m ./..."
)

var workflowSHAPinnedUsesPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$`)

// liveIntegrationShellAllowed reports whether a step's shell executes its
// script with errexit. GitHub Actions runs an unset shell as `bash -e {0}` and
// the `bash` keyword as `bash --noprofile --norc -eo pipefail {0}`; any other
// value (`sh`, `python`, or a custom template such as `true {0}`) can turn the
// check-config script or the integration test step into a no-op that still
// reports success, so the contract rejects it.
func liveIntegrationShellAllowed(shell string) bool {
	return shell == "" || shell == "bash"
}

// liveIntegrationRunDefaults mirrors a workflow- or job-level `defaults.run`
// block, inherited by every step that leaves its own `shell` or
// `working-directory` unset.
type liveIntegrationRunDefaults struct {
	Run struct {
		Shell            string `yaml:"shell"`
		WorkingDirectory string `yaml:"working-directory"`
	} `yaml:"run"`
}

type liveIntegrationStep struct {
	ID               string            `yaml:"id"`
	Name             string            `yaml:"name"`
	Uses             string            `yaml:"uses"`
	Shell            string            `yaml:"shell"`
	WorkingDirectory string            `yaml:"working-directory"`
	If               any               `yaml:"if,omitempty"`
	ContinueOnError  any               `yaml:"continue-on-error,omitempty"`
	Env              map[string]string `yaml:"env"`
	With             map[string]any    `yaml:"with"`
	Run              string            `yaml:"run"`
}

type liveIntegrationJob struct {
	Name            string                     `yaml:"name"`
	RunsOn          string                     `yaml:"runs-on"`
	TimeoutMin      int                        `yaml:"timeout-minutes"`
	ContinueOnError any                        `yaml:"continue-on-error,omitempty"`
	Permissions     map[string]string          `yaml:"permissions"`
	Defaults        liveIntegrationRunDefaults `yaml:"defaults"`
	Steps           []liveIntegrationStep      `yaml:"steps"`
}

type liveIntegrationWorkflow struct {
	Name        string                        `yaml:"name"`
	On          map[string]any                `yaml:"on"`
	Permissions map[string]string             `yaml:"permissions"`
	Defaults    liveIntegrationRunDefaults    `yaml:"defaults"`
	Jobs        map[string]liveIntegrationJob `yaml:"jobs"`
}

// continueOnErrorSet reports whether a job or step declares continue-on-error
// with any value other than an explicit false. A true value or an expression
// lets a failed check-config (or a failed live suite) end the job green, which
// is exactly the false evidence the fail-closed contract exists to prevent.
func continueOnErrorSet(v any) bool {
	return v != nil && v != false
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
	if continueOnErrorSet(job.ContinueOnError) {
		return "", fmt.Errorf("live-integration job sets continue-on-error: %v; a failed job must stay red", job.ContinueOnError)
	}

	// Workflow- and job-level defaults apply to every step that does not set
	// its own shell or working directory, so they are policed exactly like
	// the step-level fields.
	for _, d := range []struct {
		level    string
		defaults liveIntegrationRunDefaults
	}{{"workflow", wf.Defaults}, {"job", job.Defaults}} {
		if !liveIntegrationShellAllowed(d.defaults.Run.Shell) {
			return "", fmt.Errorf("%s-level defaults.run.shell %q is not allowed; only the default shell or bash may run workflow scripts", d.level, d.defaults.Run.Shell)
		}
		if d.defaults.Run.WorkingDirectory != "" {
			return "", fmt.Errorf("%s-level defaults.run.working-directory %q would move the scripts off the repository root", d.level, d.defaults.Run.WorkingDirectory)
		}
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
		if !liveIntegrationShellAllowed(step.Shell) {
			return "", fmt.Errorf("step %d (%q) uses custom shell %q; only the default shell or bash may run workflow scripts", i, step.Name, step.Shell)
		}
		if step.WorkingDirectory != "" {
			return "", fmt.Errorf("step %d (%q) sets working-directory %q; workflow scripts must run from the repository root", i, step.Name, step.WorkingDirectory)
		}
		if continueOnErrorSet(step.ContinueOnError) {
			return "", fmt.Errorf("step %d (%q) sets continue-on-error: %v; a failed step must fail the job", i, step.Name, step.ContinueOnError)
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
			// The suite must be the whole script: a `#` prefix, a preceding
			// `exit 0`, or a trailing `|| true` still contains the command
			// text while running nothing or masking its failure.
			if got := strings.TrimSpace(step.Run); got != liveIntegrationTestCommand {
				return "", fmt.Errorf("integration test step run script must be exactly %q, got %q", liveIntegrationTestCommand, got)
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

type liveCheckConfigCase struct {
	name           string
	env            map[string]string
	wantExitZero   bool
	wantGHOutput   string
	wantLogContain string
}

const (
	liveTestWIFProvider = "projects/123/locations/global/workloadIdentityPools/p/providers/g"
	liveTestSA          = "ci@test-proj.iam.gserviceaccount.com"
)

// liveCheckConfigCases is the executable behavior matrix of the check-config
// script. Only an explicit workflow_dispatch opt-out (fail_if_unconfigured=false)
// may end an unconfigured run successfully; every other unconfigured run,
// scheduled runs above all, must exit 1 with an ::error:: annotation and write
// nothing to GITHUB_OUTPUT. docs/ci-setup.md documents the same matrix and
// TestLiveIntegrationDocsDescribeFailClosedMatrix keeps the two aligned.
func liveCheckConfigCases() []liveCheckConfigCase {
	return []liveCheckConfigCase{
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
			name: "workflow_dispatch with malformed FAIL_IF_UNCONFIGURED=False and unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED": "False",
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
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
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
				"GCP_SERVICE_ACCOUNT":  liveTestSA,
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
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
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
			name: "workflow_dispatch with fail_if_unconfigured=false and only BQ_PROJECT missing skips cleanly",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "false",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero:   true,
			wantGHOutput:   "configured=false\n",
			wantLogContain: "::warning::",
		},
		{
			name: "schedule with unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to true",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "true",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to false",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "false",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule missing only BQ_PROJECT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"FAIL_IF_UNCONFIGURED":           "",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule missing only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "schedule",
				"FAIL_IF_UNCONFIGURED": "",
				"BQ_PROJECT":           "test-proj",
				"GCP_SERVICE_ACCOUNT":  liveTestSA,
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule missing only GCP_SERVICE_ACCOUNT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"FAIL_IF_UNCONFIGURED":           "",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule with whitespace-only BQ_PROJECT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"FAIL_IF_UNCONFIGURED":           "",
				"BQ_PROJECT":                     "   ",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "schedule with tab-and-newline-only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"FAIL_IF_UNCONFIGURED":           "",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": "\t\n",
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch default with whitespace-only GCP_SERVICE_ACCOUNT fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "true",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            " ",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch with fail_if_unconfigured=false and whitespace-only BQ_PROJECT skips cleanly",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "false",
				"BQ_PROJECT":                     "  ",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero:   true,
			wantGHOutput:   "configured=false\n",
			wantLogContain: "::warning::",
		},
		{
			name: "unknown event with unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "push",
				"FAIL_IF_UNCONFIGURED": "false",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "empty event name with unset vars fails closed",
			env: map[string]string{
				"GITHUB_EVENT_NAME":    "",
				"FAIL_IF_UNCONFIGURED": "false",
			},
			wantExitZero:   false,
			wantGHOutput:   "",
			wantLogContain: "::error::",
		},
		{
			name: "workflow_dispatch with all three variables configured enables live suite",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "true",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero: true,
			wantGHOutput: "configured=true\n",
		},
		{
			name: "workflow_dispatch with fail_if_unconfigured=false and all three variables configured enables live suite",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "workflow_dispatch",
				"FAIL_IF_UNCONFIGURED":           "false",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero: true,
			wantGHOutput: "configured=true\n",
		},
		{
			name: "schedule with all three variables configured enables live suite",
			env: map[string]string{
				"GITHUB_EVENT_NAME":              "schedule",
				"BQ_PROJECT":                     "test-proj",
				"GCP_WORKLOAD_IDENTITY_PROVIDER": liveTestWIFProvider,
				"GCP_SERVICE_ACCOUNT":            liveTestSA,
			},
			wantExitZero: true,
			wantGHOutput: "configured=true\n",
		},
	}
}

// evaluateLiveCheckConfigCase runs one matrix case against script and returns
// every expectation it violates; an empty result means the case passed.
func evaluateLiveCheckConfigCase(t *testing.T, script string, tc liveCheckConfigCase) []string {
	t.Helper()
	code, out, ghOut := runCheckConfigScript(t, script, tc.env)
	var problems []string
	if tc.wantExitZero && code != 0 {
		problems = append(problems, fmt.Sprintf("exit code = %d, want 0; output:\n%s", code, out))
	}
	if !tc.wantExitZero && code == 0 {
		problems = append(problems, fmt.Sprintf("exit code = 0, want non-zero; output:\n%s", out))
	}
	if ghOut != tc.wantGHOutput {
		problems = append(problems, fmt.Sprintf("GITHUB_OUTPUT = %q, want %q", ghOut, tc.wantGHOutput))
	}
	if tc.wantLogContain != "" && !strings.Contains(out, tc.wantLogContain) {
		problems = append(problems, fmt.Sprintf("output missing %q:\n%s", tc.wantLogContain, out))
	}
	return problems
}

func TestLiveIntegrationCheckConfigBehavior(t *testing.T) {
	script, err := checkLiveIntegrationWorkflow(readRepoText(t, liveIntegrationWorkflowPath))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range liveCheckConfigCases() {
		t.Run(tc.name, func(t *testing.T) {
			for _, problem := range evaluateLiveCheckConfigCase(t, script, tc) {
				t.Error(problem)
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

	// Positive control for the shell allowlist: `bash` runs the script with
	// -e and pipefail, so declaring it explicitly must still be accepted.
	bashShell := replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        shell: bash\n")
	if _, err := checkLiveIntegrationWorkflow(bashShell); err != nil {
		t.Fatalf("shell: bash on check-config unexpectedly rejected: %v", err)
	}
	// Positive controls for the inherited and masking fields: an explicit
	// `defaults.run.shell: bash` and an explicit `continue-on-error: false`
	// change nothing and must be accepted.
	bashDefaults := replaceOnce(t, base, "    timeout-minutes: 25\n", "    timeout-minutes: 25\n    defaults:\n      run:\n        shell: bash\n")
	if _, err := checkLiveIntegrationWorkflow(bashDefaults); err != nil {
		t.Fatalf("job-level defaults.run.shell: bash unexpectedly rejected: %v", err)
	}
	explicitFalse := replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        continue-on-error: false\n")
	if _, err := checkLiveIntegrationWorkflow(explicitFalse); err != nil {
		t.Fatalf("continue-on-error: false on check-config unexpectedly rejected: %v", err)
	}

	const testStepRun = "        run: |\n          go test -v -race -tags=integration -count=1 -timeout=20m ./..."

	mutants := []struct {
		name   string
		mutate func(t *testing.T) string
	}{
		{
			name: "check-config step sets continue-on-error true",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        continue-on-error: true\n")
			},
		},
		{
			name: "check-config step sets continue-on-error expression",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        continue-on-error: ${{ true }}\n")
			},
		},
		{
			name: "integration test step sets continue-on-error true",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, "        continue-on-error: true\n"+testStepRun)
			},
		},
		{
			name: "job sets continue-on-error true",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "    timeout-minutes: 25\n", "    timeout-minutes: 25\n    continue-on-error: true\n")
			},
		},
		{
			name: "job-level defaults.run.shell true {0}",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "    timeout-minutes: 25\n", "    timeout-minutes: 25\n    defaults:\n      run:\n        shell: 'true {0}'\n")
			},
		},
		{
			name: "workflow-level defaults.run.shell true {0}",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "jobs:\n", "defaults:\n  run:\n    shell: 'true {0}'\n\njobs:\n")
			},
		},
		{
			name: "job-level defaults.run.shell sh",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "    timeout-minutes: 25\n", "    timeout-minutes: 25\n    defaults:\n      run:\n        shell: sh\n")
			},
		},
		{
			name: "job-level defaults.run.working-directory set",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "    timeout-minutes: 25\n", "    timeout-minutes: 25\n    defaults:\n      run:\n        working-directory: /tmp\n")
			},
		},
		{
			name: "workflow-level defaults.run.working-directory set",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "jobs:\n", "defaults:\n  run:\n    working-directory: cmd\n\njobs:\n")
			},
		},
		{
			name: "check-config step sets working-directory",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        working-directory: /tmp\n")
			},
		},
		{
			name: "integration test step sets working-directory",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, "        working-directory: cmd\n"+testStepRun)
			},
		},
		{
			name: "integration test masked with || true",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, testStepRun+" || true")
			},
		},
		{
			name: "integration test exits 0 before go test",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, "        run: |\n          exit 0\n          go test -v -race -tags=integration -count=1 -timeout=20m ./...")
			},
		},
		{
			name: "integration test commented out",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, "        run: |\n          # go test -v -race -tags=integration -count=1 -timeout=20m ./...\n          echo skipped")
			},
		},
		{
			name: "integration test followed by extra statement",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, testStepRun, testStepRun+"\n          echo done")
			},
		},
		{
			name: "integration test drops -race",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "go test -v -race -tags=integration", "go test -v -tags=integration")
			},
		},
		{
			name: "check-config step uses custom shell true {0}",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        shell: 'true {0}'\n")
			},
		},
		{
			name: "check-config step uses sh shell",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        shell: sh\n")
			},
		},
		{
			name: "check-config step uses bash template without errexit",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        id: check-config\n", "        id: check-config\n        shell: bash {0}\n")
			},
		},
		{
			name: "integration test step uses custom shell true {0}",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        run: |\n          go test -v -race -tags=integration", "        shell: 'true {0}'\n        run: |\n          go test -v -race -tags=integration")
			},
		},
		{
			name: "integration test step uses python shell",
			mutate: func(t *testing.T) string {
				return replaceOnce(t, base, "        run: |\n          go test -v -race -tags=integration", "        shell: python\n        run: |\n          go test -v -race -tags=integration")
			},
		},
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

// dispatchOnlyFailClosedScript is the check-config script as it stood when only
// manual dispatches failed closed: a scheduled run with missing variables fell
// through to the warning, wrote configured=false, and exited 0, so the nightly
// evidence stayed green while no live test ran. It is kept verbatim as the
// negative control for the scheduled matrix cases.
const dispatchOnlyFailClosedScript = `
if [ -z "${BQ_PROJECT:-}" ] || [ -z "${GCP_WORKLOAD_IDENTITY_PROVIDER:-}" ] || [ -z "${GCP_SERVICE_ACCOUNT:-}" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ] && [ "${FAIL_IF_UNCONFIGURED:-}" != "false" ]; then
    echo "::error::prerequisites are not configured and fail_if_unconfigured is enabled."
    exit 1
  fi
  echo "::warning::prerequisites are not fully configured. Skipping live test suite."
  echo "configured=false" >> "$GITHUB_OUTPUT"
else
  echo "configured=true" >> "$GITHUB_OUTPUT"
fi
`

// liveCheckConfigOptOutCondition is the one branch of the live check-config
// script that may end an unconfigured run successfully. The mutants below are
// anchored on it so a refactor of the script fails this test loudly instead of
// silently weakening the proof.
const liveCheckConfigOptOutCondition = `if [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ] && [ "${FAIL_IF_UNCONFIGURED:-}" = "false" ]; then`

// TestLiveIntegrationCheckConfigScriptRejectsScheduleSkipMutants proves that
// the matrix cases catch every way of letting an unconfigured scheduled run
// succeed: the prior dispatch-only implementation, admitting schedule to the
// configured=false branch, dropping the event check from the opt-out, and
// removing the fail-closed exit.
func TestLiveIntegrationCheckConfigScriptRejectsScheduleSkipMutants(t *testing.T) {
	liveScript, err := checkLiveIntegrationWorkflow(readRepoText(t, liveIntegrationWorkflowPath))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(liveScript, liveCheckConfigOptOutCondition) != 1 {
		t.Fatalf("live check-config script must contain the opt-out condition exactly once:\n%s", liveScript)
	}
	if strings.Count(liveScript, "exit 1") != 1 {
		t.Fatalf("live check-config script must contain exactly one exit 1:\n%s", liveScript)
	}

	cases := liveCheckConfigCases()
	caseNames := map[string]bool{}
	for _, tc := range cases {
		caseNames[tc.name] = true
	}

	mutants := []struct {
		name       string
		script     string
		wantCaught []string
	}{
		{
			name:   "prior dispatch-only fail-closed implementation",
			script: dispatchOnlyFailClosedScript,
			wantCaught: []string{
				"schedule with unset vars fails closed",
				"schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to true",
				"schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to false",
				"schedule missing only BQ_PROJECT fails closed",
				"schedule missing only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
				"schedule missing only GCP_SERVICE_ACCOUNT fails closed",
				"unknown event with unset vars fails closed",
				"empty event name with unset vars fails closed",
			},
		},
		{
			name: "schedule admitted to the configured=false branch",
			script: strings.Replace(liveScript, liveCheckConfigOptOutCondition,
				`if [ "${GITHUB_EVENT_NAME:-}" = "schedule" ] || { [ "${GITHUB_EVENT_NAME:-}" = "workflow_dispatch" ] && [ "${FAIL_IF_UNCONFIGURED:-}" = "false" ]; }; then`, 1),
			wantCaught: []string{
				"schedule with unset vars fails closed",
				"schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to true",
				"schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to false",
				"schedule missing only BQ_PROJECT fails closed",
				"schedule missing only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
				"schedule missing only GCP_SERVICE_ACCOUNT fails closed",
			},
		},
		{
			name: "event check removed from the opt-out",
			script: strings.Replace(liveScript, liveCheckConfigOptOutCondition,
				`if [ "${FAIL_IF_UNCONFIGURED:-}" = "false" ]; then`, 1),
			wantCaught: []string{
				"schedule with unset vars fails closed even if FAIL_IF_UNCONFIGURED is set to false",
				"unknown event with unset vars fails closed",
				"empty event name with unset vars fails closed",
			},
		},
		{
			name:   "fail-closed exit removed",
			script: strings.Replace(liveScript, "exit 1", "true", 1),
			wantCaught: []string{
				"workflow_dispatch with fail_if_unconfigured=true and unset vars fails closed",
				"schedule with unset vars fails closed",
				"schedule missing only BQ_PROJECT fails closed",
			},
		},
		{
			name:   "whitespace stripping removed from check-config",
			script: strings.ReplaceAll(liveScript, "//[[:space:]]/", ":-"),
			wantCaught: []string{
				"schedule with whitespace-only BQ_PROJECT fails closed",
				"schedule with tab-and-newline-only GCP_WORKLOAD_IDENTITY_PROVIDER fails closed",
				"workflow_dispatch default with whitespace-only GCP_SERVICE_ACCOUNT fails closed",
				"workflow_dispatch with fail_if_unconfigured=false and whitespace-only BQ_PROJECT skips cleanly",
			},
		},
	}

	for _, m := range mutants {
		t.Run(m.name, func(t *testing.T) {
			if m.script == liveScript {
				t.Fatal("mutant script is identical to the live script")
			}
			for _, want := range m.wantCaught {
				if !caseNames[want] {
					t.Fatalf("wantCaught names unknown case %q", want)
				}
			}
			caught := map[string]bool{}
			for _, tc := range cases {
				if len(evaluateLiveCheckConfigCase(t, m.script, tc)) > 0 {
					caught[tc.name] = true
				}
			}
			if len(caught) == 0 {
				t.Fatal("mutant passed every check-config matrix case")
			}
			for _, want := range m.wantCaught {
				if !caught[want] {
					t.Errorf("case %q accepted the mutant, want it rejected", want)
				}
			}
		})
	}
}

// liveIntegrationDocsMatrixRow is one row of the behavior matrix that
// docs/ci-setup.md must document; every token must appear in the named cell.
type liveIntegrationDocsMatrixRow struct {
	name    string
	trigger []string
	vars    []string
	flag    []string
	result  []string
}

func markdownTableRows(doc string) [][]string {
	var rows [][]string
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), ">"))
		if !strings.HasPrefix(trimmed, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(trimmed, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		rows = append(rows, cells)
	}
	return rows
}

func cellHasAll(cell string, tokens []string) bool {
	for _, tok := range tokens {
		if !strings.Contains(cell, tok) {
			return false
		}
	}
	return true
}

// TestLiveIntegrationDocsDescribeFailClosedMatrix keeps docs/ci-setup.md
// aligned with the executed check-config matrix: it must document the
// fail_if_unconfigured input, where it is set, and all four outcomes, with
// configured=false reserved for the explicit manual opt-out.
func TestLiveIntegrationDocsDescribeFailClosedMatrix(t *testing.T) {
	doc := readRepoText(t, "docs/ci-setup.md")

	for _, want := range []string{
		"`fail_if_unconfigured`",
		"Run workflow",
		"defaults to `true`",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/ci-setup.md does not mention %q", want)
		}
	}
	for _, stale := range []string{
		"scheduled runs do not fail",
		"skips the checkout, authentication, and test steps cleanly so scheduled",
	} {
		if strings.Contains(doc, stale) {
			t.Errorf("docs/ci-setup.md still carries the stale scheduled-skip wording %q", stale)
		}
	}

	wantRows := []liveIntegrationDocsMatrixRow{
		{
			name:    "configured runs execute the live suite",
			trigger: []string{"`schedule`", "`workflow_dispatch`"},
			vars:    []string{"all set"},
			result:  []string{"`configured=true`", "`REQUIRE_LIVE_BQ=1`"},
		},
		{
			name:    "unconfigured scheduled runs fail closed",
			trigger: []string{"`schedule`"},
			vars:    []string{"missing"},
			result:  []string{"`::error::`", "`exit 1`"},
		},
		{
			name:    "unconfigured default manual dispatch fails closed",
			trigger: []string{"`workflow_dispatch`"},
			vars:    []string{"missing"},
			flag:    []string{"`true`", "default"},
			result:  []string{"`::error::`", "`exit 1`"},
		},
		{
			name:    "unconfigured manual dispatch with explicit opt-out skips",
			trigger: []string{"`workflow_dispatch`"},
			vars:    []string{"missing"},
			flag:    []string{"`false`"},
			result:  []string{"`::warning::`", "`configured=false`", "skip"},
		},
	}

	rows := markdownTableRows(doc)
	var matrix [][]string
	for _, row := range rows {
		if len(row) == 4 {
			matrix = append(matrix, row)
		}
	}
	if len(matrix) == 0 {
		t.Fatal("docs/ci-setup.md has no four-column behavior matrix table")
	}
	wantTotalRows := 2 + len(wantRows)
	if len(matrix) != wantTotalRows {
		t.Fatalf("docs/ci-setup.md four-column behavior matrix row count = %d, want %d (1 header + 1 separator + %d data rows)", len(matrix), wantTotalRows, len(wantRows))
	}

	used := map[int]bool{}
	for _, want := range wantRows {
		found := -1
		for i, row := range matrix {
			if i < 2 || used[i] {
				continue
			}
			if cellHasAll(row[0], want.trigger) && cellHasAll(row[1], want.vars) && cellHasAll(row[2], want.flag) && cellHasAll(row[3], want.result) {
				found = i
				break
			}
		}
		if found < 0 {
			t.Errorf("docs/ci-setup.md behavior matrix is missing the row %q (trigger %v, vars %v, flag %v, result %v)", want.name, want.trigger, want.vars, want.flag, want.result)
			continue
		}
		used[found] = true
	}

	// configured=false, ::warning::, and skip semantics must be documented for
	// the explicit workflow_dispatch opt-out only.
	for i, row := range matrix[2:] {
		if !strings.Contains(row[0], "`workflow_dispatch`") || !strings.Contains(row[2], "`false`") {
			if strings.Contains(row[3], "`configured=false`") {
				t.Errorf("docs/ci-setup.md matrix data row %d documents configured=false outside the explicit workflow_dispatch opt-out: %v", i, row)
			}
			if strings.Contains(row[3], "`::warning::`") {
				t.Errorf("docs/ci-setup.md matrix data row %d documents ::warning:: on a fail-closed or configured row: %v", i, row)
			}
			if strings.Contains(strings.ToLower(row[3]), "skip") {
				t.Errorf("docs/ci-setup.md matrix data row %d documents skip behavior outside the explicit workflow_dispatch opt-out: %v", i, row)
			}
		}
	}
}
