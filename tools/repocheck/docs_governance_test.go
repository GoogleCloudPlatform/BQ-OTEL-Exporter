// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

func docsNormalizeEOL(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

func docsLines(doc string) []string {
	lines := strings.Split(docsNormalizeEOL(doc), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

var (
	changelogVersionHeadingRE = regexp.MustCompile(`^## \[([^\]]*)\](.*)$`)
	changelogSemverRE         = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)
	changelogDatedSuffixRE    = regexp.MustCompile(`^ - ([0-9]{4}-[0-9]{2}-[0-9]{2})$`)
)

// changelogStabilityProblems reports misleading stability wording in
// CHANGELOG.md and README.md. A release section may be added once it is
// dated the Keep a Changelog way, as in "## [0.1.0] - 2026-11-20", which is
// the heading prepare-release.yml requires before it tags; the heading may
// carry nothing after the date, so no release heading can call itself GA,
// Stable or an Alpha Release, and neither file may claim a GA or stable
// release while the component is in development.
func changelogStabilityProblems(changelog, readme string) []string {
	changelog = docsNormalizeEOL(changelog)
	readme = docsNormalizeEOL(readme)
	var problems []string
	if !regexp.MustCompile(`(?m)^## \[Unreleased\]$`).MatchString(changelog) {
		problems = append(problems, "CHANGELOG.md missing Keep a Changelog ## [Unreleased] heading")
	}
	if !regexp.MustCompile(`(?m)^## \[0\.0\.1\] - 2026-11-03$`).MatchString(changelog) {
		problems = append(problems, "CHANGELOG.md must keep ## [0.0.1] - 2026-11-03 without Alpha Release suffix")
	}
	for i, line := range docsLines(changelog) {
		m := changelogVersionHeadingRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		version, suffix := m[1], m[2]
		date := changelogDatedSuffixRE.FindStringSubmatch(suffix)
		switch {
		case version == "Unreleased":
			if suffix != "" {
				problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q must read exactly \"## [Unreleased]\"", i+1, line))
			}
		case !changelogSemverRE.MatchString(version):
			problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q does not name a semantic version", i+1, line))
		case date == nil:
			problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q must read \"## [%s] - YYYY-MM-DD\" with nothing after the date; a release heading carries no stability label such as GA, Stable or Alpha Release", i+1, line, version))
		default:
			if _, err := time.Parse(time.DateOnly, date[1]); err != nil {
				problems = append(problems, fmt.Sprintf("CHANGELOG.md line %d: %q has an invalid date: %v", i+1, line, err))
			}
		}
	}
	files := []struct{ name, text string }{{"CHANGELOG.md", changelog}, {"README.md", readme}}
	for _, forbidden := range []string{
		"upstream GA",
		"Alpha Release",
		"alpha semantic release",
		"v0.0.1 alpha section",
	} {
		for _, f := range files {
			if strings.Contains(f.text, forbidden) {
				problems = append(problems, fmt.Sprintf("%s contains misleading pre-tag stability phrase %q", f.name, forbidden))
			}
		}
	}
	for _, claim := range []string{"GA release", "general availability", "generally available", "stable release"} {
		for _, f := range files {
			if strings.Contains(strings.ToLower(f.text), strings.ToLower(claim)) {
				problems = append(problems, fmt.Sprintf("%s claims %q, but the component is in development and no release is GA or stable", f.name, claim))
			}
		}
	}
	return problems
}

func readmeChangelogInputs(t *testing.T) (changelog, readme string) {
	t.Helper()
	return docsNormalizeEOL(testsupport.ReadRepoText(t, "CHANGELOG.md")),
		docsNormalizeEOL(testsupport.ReadRepoText(t, "README.md"))
}

func TestChangelogPreTagStabilityWording(t *testing.T) {
	changelog, readme := readmeChangelogInputs(t)
	for _, problem := range changelogStabilityProblems(changelog, readme) {
		t.Error(problem)
	}
	t.Run("CRLF line endings pass changelog checks", func(t *testing.T) {
		crlfReadme := strings.ReplaceAll(readme, "\n", "\r\n")
		crlfChangelog := strings.ReplaceAll(changelog, "\n", "\r\n")
		for _, problem := range changelogStabilityProblems(crlfChangelog, crlfReadme) {
			t.Errorf("changelogStabilityProblems with CRLF: %s", problem)
		}
	})
}

// TestChangelogStabilityRejectsMutations cuts release sections the way the
// v0.1.0 release preparation will: a dated section passes, and a heading or
// entry that claims a stability level fails.
func TestChangelogStabilityRejectsMutations(t *testing.T) {
	changelog, readme := readmeChangelogInputs(t)
	const unreleased = "## [Unreleased]\n"
	for _, tc := range []struct {
		name, insert string
		// wantSubs is the problem the section must produce; empty marks a
		// valid section, which must produce none.
		wantSubs string
	}{
		{name: "valid: dated 0.1.0 section", insert: "\n## [0.1.0] - 2026-11-20\n\n- Pre-donation library release; component stability remains `development`, not GA.\n"},
		{name: "undated 0.1.0 heading", insert: "\n## [0.1.0]\n", wantSubs: `must read "## [0.1.0] - YYYY-MM-DD"`},
		{name: "GA label on the heading", insert: "\n## [0.1.0] - 2026-11-20 (GA)\n", wantSubs: "carries no stability label"},
		{name: "Stable label on the heading", insert: "\n## [0.1.0] - 2026-11-20 - Stable\n", wantSubs: "carries no stability label"},
		{name: "invalid date", insert: "\n## [0.1.0] - 2026-13-01\n", wantSubs: "has an invalid date"},
		{name: "not a semantic version", insert: "\n## [v0.1]\n", wantSubs: "does not name a semantic version"},
		{name: "general availability entry", insert: "\n## [0.1.0] - 2026-11-20\n\n- General availability of the exporter.\n", wantSubs: `claims "general availability"`},
		{name: "stable release entry", insert: "\n## [1.0.0] - 2026-11-20\n\n- First stable release.\n", wantSubs: `claims "stable release"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(changelog, unreleased, unreleased+tc.insert, 1)
			if mutated == changelog {
				t.Fatal("the section was not inserted")
			}
			problems := changelogStabilityProblems(mutated, readme)
			if tc.wantSubs == "" {
				for _, p := range problems {
					t.Errorf("valid section rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}

const (
	docsSchemaRationaleRelPath = "docs/schema-rationale.md"
	docsAgentFrameworksRelPath = "docs/agent-frameworks.md"
	deployReadMeRelPath        = "deploy/README.md"
)

func docsAndDeployAlignmentProblems(schemaRationale, agentFrameworks, deployREADME, exposureYAML, changelog string) []string {
	schemaRationale = docsNormalizeEOL(schemaRationale)
	agentFrameworks = docsNormalizeEOL(agentFrameworks)
	deployREADME = docsNormalizeEOL(deployREADME)
	exposureYAML = docsNormalizeEOL(exposureYAML)
	changelog = docsNormalizeEOL(changelog)

	var problems []string
	forbiddenTrajectoryTokens := []string{
		"WITH RECURSIVE",
		"visited_span_ids",
		"hop0..hop32",
		"hop0",
		"rooted_chains",
		"emitted_ancestors",
		"recursive self-join",
		"recursive CTE",
	}
	requiredTrajectoryTokens := []string{
		"v_gen_ai_agent_trajectory",
		"topo_raw",
		"array graph",
		"resolved_topology",
	}

	for _, doc := range []struct {
		path string
		body string
	}{
		{path: docsSchemaRationaleRelPath, body: schemaRationale},
		{path: docsAgentFrameworksRelPath, body: agentFrameworks},
	} {
		normalizedBody := strings.Join(strings.Fields(doc.body), " ")
		for _, stale := range forbiddenTrajectoryTokens {
			if strings.Contains(normalizedBody, stale) {
				problems = append(problems, doc.path+" still contains stale trajectory term "+stale)
			}
		}
		for _, want := range requiredTrajectoryTokens {
			if !strings.Contains(normalizedBody, want) {
				problems = append(problems, doc.path+" is missing single-scan array graph token "+want)
			}
		}
	}

	requiredDeployTokens := []string{
		"goMemLimit",
		"startupProbe",
		"GOMEMLIMIT",
		"checksum/config",
		"seccompProfile",
		"looker_studio_template_report_id",
		"looker_studio_template_project_id",
		"looker_studio_template_dataset_id",
		"looker_studio_create_url",
		"deletion_protection = false",
		"otel_alerts",
	}
	for _, want := range requiredDeployTokens {
		if !strings.Contains(deployREADME, want) {
			problems = append(problems, deployReadMeRelPath+" is missing required parameter "+want)
		}
	}

	var exposureTemplate struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Body        []any  `yaml:"body"`
	}
	if err := yaml.Unmarshal([]byte(exposureYAML), &exposureTemplate); err != nil {
		problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml invalid YAML: "+err.Error())
	} else {
		if strings.TrimSpace(exposureTemplate.Name) == "" {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty name")
		}
		if strings.TrimSpace(exposureTemplate.Description) == "" {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty description")
		}
		if len(exposureTemplate.Body) == 0 {
			problems = append(problems, ".github/ISSUE_TEMPLATE/alpha_exposure_report.yml missing non-empty body")
		}
	}

	if !strings.Contains(changelog, "## [0.1.0] - 2026-11-09") {
		problems = append(problems, "CHANGELOG.md missing release heading ## [0.1.0] - 2026-11-09")
	}
	return problems
}

func TestDocsAndDeployReadmeStayAlignedWithCurrentArchitecture(t *testing.T) {
	readDoc := func(rel string) string {
		t.Helper()
		return docsNormalizeEOL(testsupport.ReadRepoText(t, rel))
	}

	problems := docsAndDeployAlignmentProblems(
		readDoc(docsSchemaRationaleRelPath),
		readDoc(docsAgentFrameworksRelPath),
		readDoc(deployReadMeRelPath),
		readDoc(".github/ISSUE_TEMPLATE/alpha_exposure_report.yml"),
		readDoc("CHANGELOG.md"),
	)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestDocsAndDeployAlignmentRejectsMutations(t *testing.T) {
	readDoc := func(rel string) string {
		t.Helper()
		return docsNormalizeEOL(testsupport.ReadRepoText(t, rel))
	}

	baseSchema := readDoc(docsSchemaRationaleRelPath)
	baseFrameworks := readDoc(docsAgentFrameworksRelPath)
	baseDeploy := readDoc(deployReadMeRelPath)
	baseExposure := readDoc(".github/ISSUE_TEMPLATE/alpha_exposure_report.yml")
	baseChangelog := readDoc("CHANGELOG.md")

	cases := []struct {
		name      string
		schema    string
		frame     string
		deploy    string
		exposure  string
		changelog string
		wantSubs  string
	}{
		{
			name:      "clean_baseline",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
		},
		{
			name:      "stale_with_recursive_in_schema_rationale",
			schema:    baseSchema + "\nWITH RECURSIVE trajectory\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "WITH RECURSIVE",
		},
		{
			name:      "stale_wrapped_with_recursive_in_schema_rationale",
			schema:    baseSchema + "\nWITH\nRECURSIVE trajectory\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "WITH RECURSIVE",
		},
		{
			name:      "stale_hop0_hop32_in_schema_rationale",
			schema:    baseSchema + "\nhop0..hop32\n",
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "hop0..hop32",
		},
		{
			name:      "stale_visited_span_ids_in_agent_frameworks",
			schema:    baseSchema,
			frame:     baseFrameworks + "\nvisited_span_ids\n",
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "visited_span_ids",
		},
		{
			name:      "missing_topo_raw_in_agent_frameworks",
			schema:    baseSchema,
			frame:     strings.ReplaceAll(baseFrameworks, "topo_raw", "removed_cte"),
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "topo_raw",
		},
		{
			name:      "missing_goMemLimit_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "goMemLimit", "memoryLimit"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "goMemLimit",
		},
		{
			name:      "missing_startupProbe_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "startupProbe", "probe"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "startupProbe",
		},
		{
			name:      "missing_GOMEMLIMIT_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "GOMEMLIMIT", "MEM"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "GOMEMLIMIT",
		},
		{
			name:      "missing_looker_studio_template_dataset_id_in_deploy_readme",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    strings.ReplaceAll(baseDeploy, "looker_studio_template_dataset_id", "removed_var"),
			exposure:  baseExposure,
			changelog: baseChangelog,
			wantSubs:  "looker_studio_template_dataset_id",
		},
		{
			name:      "missing_v010_heading_in_changelog",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  baseExposure,
			changelog: strings.ReplaceAll(baseChangelog, "## [0.1.0] - 2026-11-09", "## [Unreleased]"),
			wantSubs:  "CHANGELOG.md missing release heading ## [0.1.0] - 2026-11-09",
		},
		{
			name:      "empty_description_in_alpha_exposure_template",
			schema:    baseSchema,
			frame:     baseFrameworks,
			deploy:    baseDeploy,
			exposure:  strings.Replace(baseExposure, `description: "Report pre-donation custom OCB/standalone usage or alpha-phase production exposure to track upstream beta-promotion evidence."`, `description: ""`, 1),
			changelog: baseChangelog,
			wantSubs:  "alpha_exposure_report.yml missing non-empty description",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := docsAndDeployAlignmentProblems(tc.schema, tc.frame, tc.deploy, tc.exposure, tc.changelog)
			if tc.wantSubs == "" {
				for _, p := range problems {
					t.Errorf("valid baseline rejected: %s", p)
				}
				return
			}
			if !slices.ContainsFunc(problems, func(p string) bool { return strings.Contains(p, tc.wantSubs) }) {
				t.Fatalf("expected problem containing %q, got %v", tc.wantSubs, problems)
			}
		})
	}
}

func TestMakefileMdatagenGuard(t *testing.T) {
	makefile := docsNormalizeEOL(testsupport.ReadRepoText(t, "Makefile"))
	guardIdx := strings.Index(makefile, `if ! test -f "$$stage/documentation.md"`)
	statusIdx := strings.Index(makefile, `cat "$$stage/internal/metadata/generated_status.go"`)
	cpIdx := strings.Index(makefile, `cp "$$stage/documentation.md" documentation.md`)
	if guardIdx < 0 || statusIdx < 0 || cpIdx < 0 || guardIdx >= statusIdx || guardIdx >= cpIdx {
		t.Errorf("Makefile mdatagen target must guard both generated_status.go and documentation.md writes with test -f \"$$stage/documentation.md\" before copying either file")
	}
}
