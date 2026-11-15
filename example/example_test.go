// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package example_test

import (
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// collectorVersionsFromGoMod reads the Collector release this module builds
// against from go.mod: the v0.x version shared by the Collector component and
// contrib modules (read from componentstatus) and the v1.x version shared by the
// stable modules (read from confmap). The example's pins are compared with these
// values instead of repeating a literal that must be edited with each release.
func collectorVersionsFromGoMod(t *testing.T, path string) (collectorVersion, confmapVersion string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	required := func(module string) string {
		t.Helper()
		m := regexp.MustCompile(`(?m)^\s*(?:require\s+)?` + regexp.QuoteMeta(module) + ` (v\d+\.\d+\.\d+)`).FindSubmatch(raw)
		if m == nil {
			t.Fatalf("%s has no requirement for %s", path, module)
		}
		return string(m[1])
	}
	return required("go.opentelemetry.io/collector/component/componentstatus"),
		required("go.opentelemetry.io/collector/confmap")
}

func TestCustomCollectorExampleIsSelfContainedAndPinned(t *testing.T) {
	collectorVersion, confmapVersion := collectorVersionsFromGoMod(t, "../go.mod")

	tests := []struct {
		path       string
		contains   []string
		matches    []string
		notContain []string
	}{
		{
			path: "otelcol-builder.yaml",
			contains: []string{
				"name: bigqueryexporter",
				"import: github.com/GoogleCloudPlatform/BQ-OTEL-Exporter",
				"path: .",
				"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor " + collectorVersion,
				"go.opentelemetry.io/collector/receiver/otlpreceiver " + collectorVersion,
				"go.opentelemetry.io/collector/processor/memorylimiterprocessor " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension " + collectorVersion,
				"go.opentelemetry.io/collector/confmap/provider/envprovider " + confmapVersion,
			},
		},
		{
			path: "otelcol-builder-release.yaml",
			contains: []string{
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor " + collectorVersion,
				"github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor " + collectorVersion,
			},
		},
		{
			path: "otel-collector-high-volume-logs.yaml",
			contains: []string{
				"resource/trim_access_logs:",
				"attributes/trim_access_logs:",
				"transform/trim_access_logs:",
				"stream_pool_size:",
			},
		},
		{
			path: "Dockerfile",
			contains: []string{
				"go.opentelemetry.io/collector/cmd/builder@" + collectorVersion,
				"gcr.io/distroless/base-debian12:nonroot@sha256:",
			},
			// The builder image is pinned by release and digest. Which release
			// is compared with the CI and release workflows by the root
			// package's release asset tests.
			matches:    []string{`golang:\d+\.\d+\.\d+-bookworm@sha256:[0-9a-f]{64}`},
			notContain: []string{"latest"},
		},
		{
			path: "docker-compose.yml",
			contains: []string{
				"dockerfile: example/Dockerfile",
				"BQ_ADC_PATH",
			},
			notContain: []string{"otel/opentelemetry-collector-contrib", "latest"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			raw, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			for _, want := range tc.contains {
				if !strings.Contains(text, want) {
					t.Errorf("%s does not contain %q", tc.path, want)
				}
			}
			for _, pattern := range tc.matches {
				if !regexp.MustCompile(pattern).MatchString(text) {
					t.Errorf("%s does not match %q", tc.path, pattern)
				}
			}
			for _, forbidden := range tc.notContain {
				if strings.Contains(text, forbidden) {
					t.Errorf("%s contains forbidden unpinned/stock reference %q", tc.path, forbidden)
				}
			}
		})
	}
}

// ottlDeleteMatchingKeys finds delete_matching_keys(attributes, "<regexp>")
// in a transform processor statement.
var ottlDeleteMatchingKeys = regexp.MustCompile(`delete_matching_keys\(attributes,\s*"((?:[^"\\]|\\.)*)"\)`)

// logIOStreamDeleters names the processors of a Collector config that delete
// the log.iostream log record attribute.
func logIOStreamDeleters(t *testing.T, processors map[string]map[string]any) []string {
	t.Helper()
	const key = "log.iostream"
	deletes := func(pattern string) bool {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("invalid processor pattern %q: %v", pattern, err)
		}
		return re.MatchString(key)
	}
	var out []string
	for name, p := range processors {
		switch {
		case strings.HasPrefix(name, "attributes"):
			actions, _ := p["actions"].([]any)
			for _, a := range actions {
				action, _ := a.(map[string]any)
				if action["action"] != "delete" {
					continue
				}
				pattern, _ := action["pattern"].(string)
				if action["key"] == key || (pattern != "" && deletes(pattern)) {
					out = append(out, name)
				}
			}
		case strings.HasPrefix(name, "transform"):
			groups, _ := p["log_statements"].([]any)
			for _, g := range groups {
				group, _ := g.(map[string]any)
				if group["context"] != "log" {
					continue
				}
				statements, _ := group["statements"].([]any)
				for _, s := range statements {
					statement, _ := s.(string)
					if strings.Contains(statement, `delete_key(attributes, "`+key+`")`) {
						out = append(out, name)
					}
					for _, m := range ottlDeleteMatchingKeys.FindAllStringSubmatch(statement, -1) {
						pattern, err := strconv.Unquote(`"` + m[1] + `"`)
						if err != nil {
							t.Fatalf("unquoting %q in %s: %v", m[1], name, err)
						}
						if deletes(pattern) {
							out = append(out, name)
						}
					}
				}
			}
		}
	}
	return out
}

// The high-volume example synthesizes log insert IDs, so it must not split
// batches ahead of the exporter: identical ID-less records on either side of
// a send_batch_max_size cut get the same synthesized insert_id and
// otel_logs_dedup keeps one of them (the Helm chart refuses the same split
// with sendingQueue.batch.maxSize). It must also keep log.iostream, which the
// exporter falls back to for log_name, part of a record's identity.
func TestHighVolumeLogsExampleKeepsLogIdentity(t *testing.T) {
	const path = "otel-collector-high-volume-logs.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Processors map[string]map[string]any `yaml:"processors"`
		Exporters  map[string]struct {
			Logs struct {
				SynthesizeInsertID *bool `yaml:"synthesize_insert_id"`
			} `yaml:"logs"`
		} `yaml:"exporters"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	exporter, ok := cfg.Exporters["bigquery"]
	if !ok {
		t.Fatalf("%s has no bigquery exporter", path)
	}
	if synth := exporter.Logs.SynthesizeInsertID; synth == nil || *synth {
		var batchers int
		for name, p := range cfg.Processors {
			if name != "batch" && !strings.HasPrefix(name, "batch/") {
				continue
			}
			batchers++
			if _, splits := p["send_batch_max_size"]; splits {
				t.Errorf("%s: processor %s sets send_batch_max_size while logs.synthesize_insert_id is on", path, name)
			}
		}
		if batchers == 0 {
			t.Errorf("%s has no batch processor to check", path)
		}
	}
	if deleters := logIOStreamDeleters(t, cfg.Processors); len(deleters) != 0 {
		t.Errorf("%s: processors %v delete log.iostream, a log_name source", path, deleters)
	}

	// The checks must catch both mistakes they guard against.
	broken := map[string]map[string]any{
		"attributes/a": {"actions": []any{map[string]any{"action": "delete", "key": "log.iostream"}}},
		"attributes/b": {"actions": []any{map[string]any{"action": "delete", "pattern": `^log\.io.*`}}},
		"transform/c": {"log_statements": []any{map[string]any{
			"context":    "log",
			"statements": []any{`delete_matching_keys(attributes, "^log\\.")`},
		}}},
		"attributes/kept": {"actions": []any{map[string]any{"action": "delete", "key": "log.file.path"}}},
	}
	got := logIOStreamDeleters(t, broken)
	slices.Sort(got)
	if want := []string{"attributes/a", "attributes/b", "transform/c"}; !slices.Equal(got, want) {
		t.Errorf("logIOStreamDeleters(broken) = %v, want %v", got, want)
	}
}

func TestComposePublishesOTLPOnlyOnLoopback(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	var compose struct {
		Services map[string]struct {
			Ports []string `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatal(err)
	}
	got := compose.Services["otelcollector"].Ports
	want := []string{"127.0.0.1:4317:4317", "127.0.0.1:4318:4318", "127.0.0.1:13133:13133"}
	if len(got) != len(want) {
		t.Fatalf("published ports = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("published ports = %v, want loopback-only %v", got, want)
		}
	}
}

func TestDockerBuildContextExcludesCommonCredentialFiles(t *testing.T) {
	raw, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	patterns := strings.Fields(string(raw))
	for _, want := range []string{".env", "**/*.json", "**/*.key", "**/*.pem"} {
		found := false
		for _, pattern := range patterns {
			if pattern == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(".dockerignore does not exclude common credential pattern %q", want)
		}
	}
}
