// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

// The destination schema uses negative lookahead, which Go's regexp omits.
type registryRegexp struct{ *regexp2.Regexp }

func (r registryRegexp) MatchString(s string) bool {
	matched, err := r.Regexp.MatchString(s)
	return err == nil && matched
}

func registrySchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	t.Cleanup(regexp2.StopTimeoutClock)
	raw := []byte(testsupport.ReadRepoText(t, "tools/repocheck/testdata/registry/schema.json"))
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	c.UseRegexpEngine(func(pattern string) (jsonschema.Regexp, error) {
		r, err := regexp2.Compile(pattern, regexp2.ECMAScript)
		if err != nil {
			return nil, err
		}
		r.MatchTimeout = time.Second
		return registryRegexp{r}, nil
	})
	const location = "https://opentelemetry.io/ecosystem/registry/schema.json"
	if err := c.AddResource(location, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(location)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func registryEntry(t *testing.T) map[string]any {
	t.Helper()
	var entry map[string]any
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, "docs/otel-registry-entry.yaml")), &entry); err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestRegistrySchemaRejectsInvalidEntries(t *testing.T) {
	s := registrySchema(t)
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"obsolete version", func(e map[string]any) { e["otVersion"] = "v0.1.0" }},
		{"unknown property", func(e map[string]any) { e["unknown"] = true }},
		{"nested unknown property", func(e map[string]any) { e["urls"].(map[string]any)["unknown"] = true }},
		{"missing author contact", func(e map[string]any) { e["authors"] = []any{map[string]any{"name": "Example"}} }},
		{"reserved author name", func(e map[string]any) {
			e["authors"] = []any{map[string]any{"name": "OpenTelemetry Impersonator", "url": "https://example.com"}}
		}},
		{"invalid author URL", func(e map[string]any) {
			e["authors"] = []any{map[string]any{"name": "Example", "url": "not a URL"}}
		}},
		{"commercial license", func(e map[string]any) { e["license"] = "Commercial" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := registryEntry(t)
			tc.mutate(e)
			if err := s.Validate(e); err == nil {
				t.Fatal("destination schema accepted invalid registry entry")
			}
		})
	}
	// The schema also permits entries with fewer tags and a supported package
	// object; validation must not enshrine the obsolete otVersion field.
	e := registryEntry(t)
	e["tags"] = []any{"collector"}
	e["package"] = map[string]any{"registry": "go-collector", "name": "example.org/exporter"}
	if err := s.Validate(e); err != nil {
		t.Fatalf("schema-valid alternative entry rejected: %v", err)
	}
}

func TestOpenTelemetryRegistryEntryAndReleaseDocs(t *testing.T) {
	registry := registryEntry(t)
	if err := registrySchema(t).Validate(registry); err != nil {
		t.Fatalf("registry entry fails destination schema: %v", err)
	}
	if pkg, ok := registry["package"].(map[string]any); ok && pkg["version"] != nil {
		t.Error("registry candidate must omit package.version until the release is published")
	}
	var entry struct {
		Title        string   `yaml:"title"`
		RegistryType string   `yaml:"registryType"`
		Language     string   `yaml:"language"`
		Tags         []string `yaml:"tags"`
		License      string   `yaml:"license"`
		Description  string   `yaml:"description"`
		Authors      []struct {
			Name string `yaml:"name"`
			URL  string `yaml:"url"`
		} `yaml:"authors"`
		URLs struct {
			Repo string `yaml:"repo"`
		} `yaml:"urls"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, "docs/otel-registry-entry.yaml")), &entry); err != nil {
		t.Fatalf("unmarshaling docs/otel-registry-entry.yaml: %v", err)
	}
	if entry.Title == "" {
		t.Error("docs/otel-registry-entry.yaml missing title")
	}
	if entry.RegistryType != "exporter" {
		t.Errorf("registryType = %q, want %q", entry.RegistryType, "exporter")
	}
	if entry.Language != "collector" {
		t.Errorf("language = %q, want %q", entry.Language, "collector")
	}
	if entry.License != "Apache-2.0" {
		t.Errorf("license = %q, want %q", entry.License, "Apache-2.0")
	}
	if strings.TrimSpace(entry.Description) == "" {
		t.Error("docs/otel-registry-entry.yaml missing description")
	}
	if len(entry.Authors) == 0 || entry.Authors[0].Name == "" {
		t.Errorf("authors = %#v, want at least one named author", entry.Authors)
	}
	if entry.URLs.Repo != "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter" {
		t.Errorf("urls.repo = %q, want https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter", entry.URLs.Repo)
	}
	for _, wantTag := range []string{"go", "exporter", "collector", "bigquery", "google-cloud", "genai", "mcp"} {
		if !slices.Contains(entry.Tags, wantTag) {
			t.Errorf("tags %v missing %q", entry.Tags, wantTag)
		}
	}

	provenance := testsupport.ReadRepoText(t, "docs/provenance.md")
	for _, want := range []string{
		"Apache-2.0",
		"Copyright 2026 Google LLC",
		"CONTRIBUTING.md",
		"v0alpha1",
		"v0alpha2",
		"v0.1.0",
	} {
		if !strings.Contains(provenance, want) {
			t.Errorf("docs/provenance.md missing %q", want)
		}
	}

	changelog := testsupport.ReadRepoText(t, "CHANGELOG.md")
	for _, want := range []string{
		"v0.1.0",
		"v0alpha2",
		"v0alpha1",
		"CreateTracesExporter",
		"CreateLogsExporter",
		"CreateMetricsExporter",
		"[1, 16]",
		"otel_sensitivity",
		"sensitive_payload",
		"sensitive_payload_mask",
	} {
		if !strings.Contains(changelog, want) {
			t.Errorf("CHANGELOG.md missing %q", want)
		}
	}

	knownCompanionViews := map[string]bool{
		schema.SpansAsAllSpansViewName:      true,
		schema.LogsAsAllLogsViewName:        true,
		schema.GenAISpansViewName:           true,
		schema.GenAILogsViewName:            true,
		schema.GenAIMetricsViewName:         true,
		schema.GenAIMetricExemplarsViewName: true,
		schema.GenAIModelCostsViewName:      true,
		schema.GenAISessionsViewName:        true,
		schema.GenAIToolUsageViewName:       true,
		schema.GenAIAgentTrajectoryViewName: true,
		schema.MCPSpansViewName:             true,
		schema.MCPToolUsageViewName:         true,
	}
	viewIdentRe := regexp.MustCompile("`((?:v_gen_ai_|v_mcp_)[a-z0-9_]+)`")
	for _, docPath := range []string{"CHANGELOG.md", "docs/provenance.md"} {
		docText := testsupport.ReadRepoText(t, docPath)
		for _, bad := range []string{
			"[1, 32]",
			"v_gen_ai_conversation_turns",
			"high_sensitivity_payload",
			"medium_sensitivity_attributes",
			"low_sensitivity_identity",
			"#34809",
		} {
			if strings.Contains(docText, bad) {
				t.Errorf("%s must not contain unverified or drifted identifier %q", docPath, bad)
			}
		}
		for _, m := range viewIdentRe.FindAllStringSubmatch(docText, -1) {
			if !knownCompanionViews[m[1]] {
				t.Errorf("%s references unknown companion view %q", docPath, m[1])
			}
		}
	}
}
