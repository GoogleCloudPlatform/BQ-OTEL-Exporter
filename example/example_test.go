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

var (
	// ottlDeleteKey finds delete_key(<map>, "<key>") in a transform
	// processor statement.
	ottlDeleteKey = regexp.MustCompile(`delete_key\(((?:resource\.|log\.)?attributes),\s*"((?:[^"\\]|\\.)*)"\)`)
	// ottlDeleteMatchingKeys finds delete_matching_keys(<map>, "<regexp>")
	// in a transform processor statement.
	ottlDeleteMatchingKeys = regexp.MustCompile(`delete_matching_keys\(((?:resource\.|log\.)?attributes),\s*"((?:[^"\\]|\\.)*)"\)`)

	protectedLogIdentityKeys = []string{
		"log.file.name",
		"log.iostream",
		"gcp.log_name",
		"logging.googleapis.com/logName",
	}
	protectedResourceIdentityKeys = []string{
		"service.name",
		"service.instance.id",
		"k8s.cluster.name",
		"k8s.namespace.name",
		"k8s.pod.name",
		"k8s.container.name",
		"cloud.platform",
		"gcp.resource_type",
	}
)

func protectedAttributeDeleters(t *testing.T, processors map[string]map[string]any, targetContext string, keys []string) []string {
	t.Helper()
	deletesKey := func(k string) bool {
		return slices.Contains(keys, k)
	}
	deletesPattern := func(pattern string) bool {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Fatalf("invalid processor pattern %q: %v", pattern, err)
		}
		for _, k := range keys {
			if re.MatchString(k) {
				return true
			}
		}
		return false
	}
	checkActionList := func(items []any) bool {
		for _, item := range items {
			action, _ := item.(map[string]any)
			if action["action"] != "delete" {
				continue
			}
			key, _ := action["key"].(string)
			pattern, _ := action["pattern"].(string)
			if (key != "" && deletesKey(key)) || (pattern != "" && deletesPattern(pattern)) {
				return true
			}
		}
		return false
	}
	matchesTransformMap := func(groupCtx, mapTarget string) bool {
		switch mapTarget {
		case "resource.attributes":
			return targetContext == "resource"
		case "log.attributes":
			return targetContext == "log"
		default:
			return groupCtx == targetContext
		}
	}

	var out []string
	for name, p := range processors {
		switch {
		case targetContext == "log" && strings.HasPrefix(name, "attributes"):
			actions, _ := p["actions"].([]any)
			if checkActionList(actions) {
				out = append(out, name)
			}
		case targetContext == "resource" && strings.HasPrefix(name, "resource"):
			attrs, _ := p["attributes"].([]any)
			if checkActionList(attrs) {
				out = append(out, name)
			}
		case strings.HasPrefix(name, "transform"):
			groups, _ := p["log_statements"].([]any)
			for _, g := range groups {
				group, _ := g.(map[string]any)
				groupCtx, _ := group["context"].(string)
				statements, _ := group["statements"].([]any)
				for _, s := range statements {
					statement, _ := s.(string)
					for _, m := range ottlDeleteKey.FindAllStringSubmatch(statement, -1) {
						if !matchesTransformMap(groupCtx, m[1]) {
							continue
						}
						k, err := strconv.Unquote(`"` + m[2] + `"`)
						if err != nil {
							t.Fatalf("unquoting %q in %s: %v", m[2], name, err)
						}
						if deletesKey(k) {
							out = append(out, name)
						}
					}
					for _, m := range ottlDeleteMatchingKeys.FindAllStringSubmatch(statement, -1) {
						if !matchesTransformMap(groupCtx, m[1]) {
							continue
						}
						pattern, err := strconv.Unquote(`"` + m[2] + `"`)
						if err != nil {
							t.Fatalf("unquoting %q in %s: %v", m[2], name, err)
						}
						if deletesPattern(pattern) {
							out = append(out, name)
						}
					}
				}
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// logIOStreamDeleters names the processors of a Collector config that delete
// protected log_name source attributes (log.file.name, log.iostream,
// gcp.log_name, logging.googleapis.com/logName).
func logIOStreamDeleters(t *testing.T, processors map[string]map[string]any) []string {
	t.Helper()
	return protectedAttributeDeleters(t, processors, "log", protectedLogIdentityKeys)
}

// protectedResourceDeleters names the processors of a Collector config that
// delete resource identity or _AllLogs resource.type attributes.
func protectedResourceDeleters(t *testing.T, processors map[string]map[string]any) []string {
	t.Helper()
	return protectedAttributeDeleters(t, processors, "resource", protectedResourceIdentityKeys)
}

type exampleCollectorConfig struct {
	Processors map[string]map[string]any `yaml:"processors"`
	Exporters  map[string]struct {
		Logs struct {
			SynthesizeInsertID *bool `yaml:"synthesize_insert_id"`
		} `yaml:"logs"`
	} `yaml:"exporters"`
}

func checkExampleLogAndResourceGuards(t *testing.T, path string, cfg exampleCollectorConfig) []string {
	t.Helper()
	var problems []string
	exporter, ok := cfg.Exporters["bigquery"]
	if !ok {
		return []string{path + " has no bigquery exporter"}
	}
	if synth := exporter.Logs.SynthesizeInsertID; synth == nil || *synth {
		var batchers int
		for name, p := range cfg.Processors {
			if name != "batch" && !strings.HasPrefix(name, "batch/") {
				continue
			}
			batchers++
			if _, splits := p["send_batch_max_size"]; splits {
				problems = append(problems, path+": processor "+name+" sets send_batch_max_size while logs.synthesize_insert_id is on")
			}
		}
		if batchers == 0 {
			problems = append(problems, path+" has no batch processor to check")
		}
	}
	if deleters := logIOStreamDeleters(t, cfg.Processors); len(deleters) != 0 {
		problems = append(problems, path+": processors "+strings.Join(deleters, ", ")+" delete a log_name source attribute")
	}
	if deleters := protectedResourceDeleters(t, cfg.Processors); len(deleters) != 0 {
		problems = append(problems, path+": processors "+strings.Join(deleters, ", ")+" delete a resource identity or _AllLogs resource.type attribute")
	}
	return problems
}

// The high-volume example synthesizes log insert IDs, so it must not split
// batches ahead of the exporter: identical ID-less records on either side of
// a send_batch_max_size cut get the same synthesized insert_id and
// otel_logs_dedup keeps one of them (the Helm chart refuses the same split
// with sendingQueue.batch.maxSize). Regardless of logs.synthesize_insert_id,
// it must also preserve log_name source attributes and resource identity /
// _AllLogs resource.type attributes.
func TestHighVolumeLogsExampleKeepsLogIdentity(t *testing.T) {
	const path = "otel-collector-high-volume-logs.yaml"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg exampleCollectorConfig
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if _, ok := cfg.Exporters["bigquery"]; !ok {
		t.Fatalf("%s has no bigquery exporter", path)
	}
	for _, problem := range checkExampleLogAndResourceGuards(t, path, cfg) {
		t.Error(problem)
	}

	t.Run("synthesize_insert_id_false_still_guards_log_and_resource_identity", func(t *testing.T) {
		synthFalse := false
		makeCfg := func(processors map[string]map[string]any) exampleCollectorConfig {
			var c exampleCollectorConfig
			if uErr := yaml.Unmarshal(raw, &c); uErr != nil {
				t.Fatalf("parsing %s: %v", path, uErr)
			}
			exp := c.Exporters["bigquery"]
			exp.Logs.SynthesizeInsertID = &synthFalse
			c.Exporters["bigquery"] = exp
			c.Processors = processors
			return c
		}

		// With synthesize_insert_id: false, send_batch_max_size is permitted when
		// protected log and resource attributes remain intact.
		cleanCfg := makeCfg(map[string]map[string]any{
			"batch": {"send_batch_size": 4096, "send_batch_max_size": 8192},
			"attributes/safe": {
				"actions": []any{map[string]any{"action": "delete", "key": "log.file.path"}},
			},
			"resource/safe": {
				"attributes": []any{map[string]any{"action": "delete", "key": "process.command_line"}},
			},
		})
		if problems := checkExampleLogAndResourceGuards(t, "synth-false-clean.yaml", cleanCfg); len(problems) != 0 {
			t.Fatalf("expected clean synthesize_insert_id=false config to pass, got %v", problems)
		}

		for _, logKey := range protectedLogIdentityKeys {
			badLogCfg := makeCfg(map[string]map[string]any{
				"batch": {"send_batch_size": 4096, "send_batch_max_size": 8192},
				"attributes/drop_log": {
					"actions": []any{map[string]any{"action": "delete", "key": logKey}},
				},
			})
			problems := checkExampleLogAndResourceGuards(t, "synth-false-bad-log.yaml", badLogCfg)
			if !slices.ContainsFunc(problems, func(p string) bool {
				return strings.Contains(p, "attributes/drop_log") && strings.Contains(p, "log_name source attribute")
			}) {
				t.Fatalf("expected synthesize_insert_id=false deleting %q to fail log_name guard, got %v", logKey, problems)
			}
		}

		for _, resKey := range []string{"service.name", "k8s.pod.name", "cloud.platform", "gcp.resource_type"} {
			badResCfg := makeCfg(map[string]map[string]any{
				"batch": {"send_batch_size": 4096, "send_batch_max_size": 8192},
				"resource/drop_res": {
					"attributes": []any{map[string]any{"action": "delete", "key": resKey}},
				},
			})
			problems := checkExampleLogAndResourceGuards(t, "synth-false-bad-res.yaml", badResCfg)
			if !slices.ContainsFunc(problems, func(p string) bool {
				return strings.Contains(p, "resource/drop_res") && strings.Contains(p, "resource identity or _AllLogs resource.type attribute")
			}) {
				t.Fatalf("expected synthesize_insert_id=false deleting %q to fail resource guard, got %v", resKey, problems)
			}
		}
	})

	// The checks must catch the log and resource mistakes they guard against.
	broken := map[string]map[string]any{
		"attributes/a": {"actions": []any{map[string]any{"action": "delete", "key": "log.iostream"}}},
		"attributes/b": {"actions": []any{map[string]any{"action": "delete", "pattern": `^log\.io.*`}}},
		"attributes/d": {"actions": []any{map[string]any{"action": "delete", "key": "gcp.log_name"}}},
		"attributes/f": {"actions": []any{map[string]any{"action": "delete", "key": "log.file.name"}}},
		"transform/c": {"log_statements": []any{map[string]any{
			"context":    "log",
			"statements": []any{`delete_matching_keys(attributes, "^log\\.")`},
		}}},
		"transform/e": {"log_statements": []any{map[string]any{
			"context":    "log",
			"statements": []any{`delete_key(attributes, "logging.googleapis.com/logName")`},
		}}},
		"attributes/kept": {"actions": []any{map[string]any{"action": "delete", "key": "log.file.path"}}},
	}
	got := logIOStreamDeleters(t, broken)
	slices.Sort(got)
	if want := []string{"attributes/a", "attributes/b", "attributes/d", "attributes/f", "transform/c", "transform/e"}; !slices.Equal(got, want) {
		t.Errorf("logIOStreamDeleters(broken) = %v, want %v", got, want)
	}

	brokenResource := map[string]map[string]any{
		"resource/a": {"attributes": []any{map[string]any{"action": "delete", "key": "service.instance.id"}}},
		"resource/b": {"attributes": []any{map[string]any{"action": "delete", "pattern": `^k8s\.container\..*`}}},
		"transform/r": {"log_statements": []any{map[string]any{
			"context":    "resource",
			"statements": []any{`delete_matching_keys(attributes, "^cloud\\.")`},
		}}},
		"resource/kept": {"attributes": []any{
			map[string]any{"action": "delete", "key": "process.command_line"},
			map[string]any{"action": "delete", "pattern": `^k8s\.pod\.labels?\..*`},
		}},
	}
	gotResource := protectedResourceDeleters(t, brokenResource)
	slices.Sort(gotResource)
	if want := []string{"resource/a", "resource/b", "transform/r"}; !slices.Equal(gotResource, want) {
		t.Errorf("protectedResourceDeleters(brokenResource) = %v, want %v", gotResource, want)
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
