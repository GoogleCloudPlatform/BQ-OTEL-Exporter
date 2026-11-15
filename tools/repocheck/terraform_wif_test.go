// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

func TestTerraformGitHubWIFOIDCClaimMappingAndCondition(t *testing.T) {
	tf := testsupport.ReadRepoText(t, "deploy/terraform/ci_wif.tf")

	// Extract attribute_mapping entries from google_iam_workload_identity_pool_provider.github_ci.
	mapBlockRe := regexp.MustCompile(`(?s)attribute_mapping\s*=\s*\{(.*?)\n\s*\}`)
	mm := mapBlockRe.FindStringSubmatch(tf)
	if mm == nil {
		t.Fatal("deploy/terraform/ci_wif.tf missing attribute_mapping block")
	}
	entryRe := regexp.MustCompile(`"([^"]+)"\s*=\s*"([^"]+)"`)
	mapping := make(map[string]string)
	for _, m := range entryRe.FindAllStringSubmatch(mm[1], -1) {
		mapping[m[1]] = m[2]
	}

	// Regression check for P1-1: attribute.workflow_ref MUST map from
	// assertion.workflow_ref (always present on schedule and workflow_dispatch),
	// never assertion.job_workflow_ref.
	if got := mapping["attribute.workflow_ref"]; got != "assertion.workflow_ref" {
		t.Fatalf("attribute_mapping[\"attribute.workflow_ref\"] = %q, want \"assertion.workflow_ref\"", got)
	}

	condBlockRe := regexp.MustCompile(`(?s)attribute_condition\s*=\s*join\(" && ",\s*\[(.*?)\n\s*\]\)`)
	cm := condBlockRe.FindStringSubmatch(tf)
	if cm == nil {
		t.Fatal("deploy/terraform/ci_wif.tf missing attribute_condition join block")
	}
	condText := cm[1]
	for _, wantClause := range []string{
		`attribute.repository_owner_id == \"${var.github_repository_owner_id}\"`,
		`attribute.repository_id == \"${var.github_repository_id}\"`,
		`attribute.repository == \"${var.github_repository}\"`,
		`attribute.ref == \"refs/heads/main\"`,
		`attribute.workflow_ref == \"${var.github_repository}/${var.github_workflow_ref}@refs/heads/main\"`,
		`attribute.event_name in [${join(", ", formatlist("%q", var.github_allowed_events))}]`,
	} {
		if !strings.Contains(condText, wantClause) {
			t.Fatalf("attribute_condition missing clause %q in:\n%s", wantClause, condText)
		}
	}

	const (
		cfgRepo        = "GoogleCloudPlatform/BQ-OTEL-Exporter"
		cfgRepoID      = "123456789"
		cfgOwnerID     = "987654321"
		cfgWorkflowRef = ".github/workflows/live-integration.yml"
	)
	allowedEvents := []string{"schedule", "workflow_dispatch"}

	// evaluateWIF simulates GCP Workload Identity Pool Provider attribute_mapping +
	// attribute_condition against a raw GitHub Actions OIDC JWT assertion payload.
	evaluateWIF := func(assertion map[string]string) bool {
		attrs := make(map[string]string, len(mapping))
		for attrKey, expr := range mapping {
			claimName := strings.TrimPrefix(expr, "assertion.")
			attrs[attrKey] = assertion[claimName]
		}
		return attrs["attribute.repository_owner_id"] == cfgOwnerID &&
			attrs["attribute.repository_id"] == cfgRepoID &&
			attrs["attribute.repository"] == cfgRepo &&
			attrs["attribute.ref"] == "refs/heads/main" &&
			attrs["attribute.workflow_ref"] == cfgRepo+"/"+cfgWorkflowRef+"@refs/heads/main" &&
			slices.Contains(allowedEvents, attrs["attribute.event_name"])
	}

	validBase := func() map[string]string {
		return map[string]string{
			"sub":                 "repo:GoogleCloudPlatform/BQ-OTEL-Exporter:ref:refs/heads/main",
			"actor":               "github-actions[bot]",
			"repository":          cfgRepo,
			"repository_id":       cfgRepoID,
			"repository_owner_id": cfgOwnerID,
			"ref":                 "refs/heads/main",
			// Top-level GitHub Actions schedule/workflow_dispatch OIDC tokens emit
			// workflow_ref (and do NOT need job_workflow_ref).
			"workflow_ref": "GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/live-integration.yml@refs/heads/main",
			"event_name":   "schedule",
		}
	}

	cases := []struct {
		name   string
		mutate func(m map[string]string)
		want   bool
	}{
		{
			name:   "1. positive: scheduled run on refs/heads/main",
			mutate: func(m map[string]string) { m["event_name"] = "schedule" },
			want:   true,
		},
		{
			name:   "2. positive: manual workflow_dispatch on refs/heads/main",
			mutate: func(m map[string]string) { m["event_name"] = "workflow_dispatch" },
			want:   true,
		},
		{
			name: "3. negative: fork pull_request",
			mutate: func(m map[string]string) {
				m["event_name"] = "pull_request"
				m["ref"] = "refs/pull/70/merge"
			},
			want: false,
		},
		{
			name: "4. negative: pull_request_target on refs/heads/main",
			mutate: func(m map[string]string) {
				m["event_name"] = "pull_request_target"
			},
			want: false,
		},
		{
			name: "5. negative: other workflow file on refs/heads/main",
			mutate: func(m map[string]string) {
				m["workflow_ref"] = "GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/ci.yml@refs/heads/main"
			},
			want: false,
		},
		{
			name: "6. negative: tag ref",
			mutate: func(m map[string]string) {
				m["ref"] = "refs/tags/v0.1.0"
				m["workflow_ref"] = "GoogleCloudPlatform/BQ-OTEL-Exporter/.github/workflows/live-integration.yml@refs/tags/v0.1.0"
			},
			want: false,
		},
		{
			name: "7. negative: wrong repository_owner_id",
			mutate: func(m map[string]string) {
				m["repository_owner_id"] = "111111111"
			},
			want: false,
		},
	}

	for _, tc := range cases {
		claims := validBase()
		tc.mutate(claims)
		if got := evaluateWIF(claims); got != tc.want {
			t.Errorf("%s: evaluateWIF = %v, want %v (claims=%v)", tc.name, got, tc.want, claims)
		}
	}
}
