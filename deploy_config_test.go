// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template"
	"text/template/parse"
	"time"

	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/metadata"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testfakes/bqfake"
)

// The deploy templates (example config, Cloud Run manifest, Compose overlay,
// Helm chart) and testdata/config.yaml are checked here by decoding them the
// way the Collector does and running the exporter's own Validate, not by
// searching their text. A template that a collector would refuse to start with
// fails these tests.

// exporterConfigKeys returns the dotted mapstructure path of every option of
// Config. It is derived by reflection, so an option cannot be added without
// the fixtures and templates being revisited. Structs declared in this package
// are walked; the Collector helper types (sending_queue, retry_on_failure),
// maps, slices and scalars are leaves, and a squashed embedded struct
// contributes its keys at the level of its parent.
func exporterConfigKeys() []string {
	rt := reflect.TypeFor[Config]()
	pkgPath := rt.PkgPath()
	var keys []string
	var walk func(rt reflect.Type, prefix string)
	walk = func(rt reflect.Type, prefix string) {
		for i := range rt.NumField() {
			field := rt.Field(i)
			name, opts, _ := strings.Cut(field.Tag.Get("mapstructure"), ",")
			if name == "-" {
				continue
			}
			if slices.Contains(strings.Split(opts, ","), "squash") {
				walk(field.Type, prefix)
				continue
			}
			if name == "" {
				continue
			}
			path := prefix + name
			if field.Type.Kind() == reflect.Struct && field.Type.PkgPath() == pkgPath {
				walk(field.Type, path+".")
				continue
			}
			keys = append(keys, path)
		}
	}
	walk(rt, "")
	sort.Strings(keys)
	return keys
}

// presentExporterKeys returns the exporter options a decoded YAML section sets,
// using the dotted paths of exporterConfigKeys. A key that is itself an option
// (a leaf such as labels) is reported without descending into it.
func presentExporterKeys(section map[string]any, options map[string]bool, prefix string) []string {
	var present []string
	for key, value := range section {
		path := prefix + key
		if options[path] {
			present = append(present, path)
			continue
		}
		if nested, ok := value.(map[string]any); ok {
			present = append(present, presentExporterKeys(nested, options, path+".")...)
		}
	}
	sort.Strings(present)
	return present
}

func exporterKeySet() map[string]bool {
	set := map[string]bool{}
	for _, key := range exporterConfigKeys() {
		set[key] = true
	}
	return set
}

// deployEnvironment holds the values the deploy templates read from the
// environment (the example config, Compose, Cloud Run and the Helm ConfigMap
// all take the destination from BQ_PROJECT, BQ_DATASET and BQ_LOCATION).
var deployEnvironment = strings.NewReplacer(
	"${env:BQ_PROJECT}", "my-project",
	"${env:BQ_DATASET}", "otel",
	"${env:BQ_LOCATION}", "US",
)

// expandDeployEnv resolves the environment references a template contains and
// fails when it contains one this test does not provide.
func expandDeployEnv(t *testing.T, name, text string) string {
	t.Helper()
	out := deployEnvironment.Replace(text)
	if i := strings.Index(out, "${"); i >= 0 {
		t.Fatalf("%s references an unexpected placeholder near %q", name, out[i:min(len(out), i+40)])
	}
	return out
}

func parseYAMLMap(t *testing.T, name, text string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
		t.Fatalf("%s is not valid YAML: %v", name, err)
	}
	if doc == nil {
		t.Fatalf("%s is empty", name)
	}
	return doc
}

// yamlPath returns the value at the given key path of a decoded YAML document,
// or nil when any step is missing.
func yamlPath(doc any, keys ...string) any {
	for _, key := range keys {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[key]
	}
	return doc
}

// exampleCollectorConfig returns the bundled example Collector configuration
// with its environment references resolved.
func exampleCollectorConfig(t *testing.T) map[string]any {
	t.Helper()
	const path = "example/otel-collector-config.yml"
	return parseYAMLMap(t, path, expandDeployEnv(t, path, readRepoText(t, path)))
}

// exporterBlock returns the exporters::<id> section of a Collector
// configuration.
func exporterBlock(t *testing.T, conf *confmap.Conf, id string) map[string]any {
	t.Helper()
	sub, err := conf.Sub("exporters::" + id)
	if err != nil {
		t.Fatalf("reading exporters::%s: %v", id, err)
	}
	block := sub.ToStringMap()
	if len(block) == 0 {
		t.Fatalf("the configuration has no exporters::%s section", id)
	}
	return block
}

// decodeExporterConfig decodes an exporter section onto the factory defaults
// the way the Collector does, where an unknown or mistyped key is an error, and
// then runs Validate. It is the check that a collector started with the
// configuration would accept it.
func decodeExporterConfig(t *testing.T, name string, section map[string]any) *Config {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	if err := confmap.NewFromStringMap(section).Unmarshal(cfg); err != nil {
		t.Fatalf("%s: the bigquery exporter section does not decode: %v", name, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("%s: the bigquery exporter configuration is invalid: %v", name, err)
	}
	return cfg
}

// applyCollectorYAML merges one `--config=yaml:<document>` argument over conf.
// Keys may be written as `a::b::c`, which the Collector expands to nested maps.
func applyCollectorYAML(t *testing.T, conf *confmap.Conf, document string) {
	t.Helper()
	var overlay map[string]any
	if err := yaml.Unmarshal([]byte(document), &overlay); err != nil {
		t.Fatalf("overlay %q is not valid YAML: %v", document, err)
	}
	if err := conf.Merge(confmap.NewFromStringMap(overlay)); err != nil {
		t.Fatalf("merging overlay %q: %v", document, err)
	}
}

// applyCollectorSet merges one `--set=a.b.c=value` argument over conf. The
// Collector turns it into the `yaml:` document `a::b::c: value`, so the value
// is parsed as YAML and replaces whatever the configuration had.
func applyCollectorSet(t *testing.T, conf *confmap.Conf, arg string) {
	t.Helper()
	spec, ok := strings.CutPrefix(arg, "--set=")
	if !ok {
		t.Fatalf("%q is not a --set argument", arg)
	}
	key, value, ok := strings.Cut(spec, "=")
	if !ok {
		t.Fatalf("--set argument %q has no value", arg)
	}
	applyCollectorYAML(t, conf, strings.ReplaceAll(key, ".", "::")+": "+value)
}

func TestExporterConfigKeysAreEnumeratedByReflection(t *testing.T) {
	keys := exporterConfigKeys()
	for _, want := range []string{
		"timeout",
		"sending_queue",
		"retry_on_failure",
		"project",
		"dataset",
		"location",
		"kms_key_name",
		"labels",
		"traces.max_staleness",
		"logs.insert_id_attribute",
		"logs.log_name_attribute",
		"logs.synthesize_insert_id",
		"metrics.partition_expiration_days",
		"credentials.json",
		"endpoint.without_authentication",
		"auto_create.search_indexes",
		"write.keepalive.permit_without_stream",
		"limits.max_attribute_key_bytes",
		"quarantine.max_staleness",
		"offload.cache_size",
		"redaction.redact_log_body",
	} {
		if !slices.Contains(keys, want) {
			t.Errorf("exporterConfigKeys() has no %q; the reflection walk is not reaching it", want)
		}
	}
	for _, key := range keys {
		if strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") || strings.Contains(key, "..") {
			t.Errorf("malformed option path %q", key)
		}
	}
	if len(keys) < 80 {
		t.Errorf("exporterConfigKeys() found %d options, want at least 80: %v", len(keys), keys)
	}
}

// testdata/config.yaml is the fixture of every option the exporter accepts. No
// single section can set all of them (the three credential sources and the
// loopback emulator endpoint exclude one another), so the check is the union of
// the exporters::bigquery* sections: each must decode strictly and validate,
// and together they must set every option that reflection finds on Config.
func TestTestdataConfigSetsEveryExporterOption(t *testing.T) {
	doc := parseYAMLMap(t, "testdata/config.yaml", readRepoText(t, "testdata/config.yaml"))
	exporters, ok := doc["exporters"].(map[string]any)
	if !ok {
		t.Fatal("testdata/config.yaml has no exporters section")
	}
	options := exporterKeySet()
	set := map[string]bool{}
	var ids []string
	for id := range exporters {
		if id == "bigquery" || strings.HasPrefix(id, "bigquery/") {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) < 2 {
		t.Fatalf("testdata/config.yaml defines exporter sections %v, want a minimal and a full one at least", ids)
	}
	for _, id := range ids {
		section, ok := exporters[id].(map[string]any)
		if !ok {
			t.Fatalf("exporters::%s is not a mapping", id)
		}
		t.Run(id, func(t *testing.T) { decodeExporterConfig(t, id, section) })
		for _, key := range presentExporterKeys(section, options, "") {
			set[key] = true
		}
	}
	for _, key := range exporterConfigKeys() {
		if !set[key] {
			t.Errorf("no exporters::bigquery* section of testdata/config.yaml sets %q", key)
		}
	}
}

func TestExampleCollectorConfigDecodesAndWiresEverySignal(t *testing.T) {
	doc := exampleCollectorConfig(t)
	exporters, _ := doc["exporters"].(map[string]any)
	var bigquery []string
	for id := range exporters {
		if id == "bigquery" || strings.HasPrefix(id, "bigquery/") {
			bigquery = append(bigquery, id)
		}
	}
	if !slices.Equal(bigquery, []string{"bigquery"}) {
		t.Fatalf("the example configures the bigquery exporters %v, want exactly bigquery", bigquery)
	}
	cfg := decodeExporterConfig(t, "example config", exporters["bigquery"].(map[string]any))

	// auto_create is what the image does by default, and the views and indexes
	// stay opt-in, so a Cloud Run service that turns table creation off does
	// not inherit an option that requires it.
	if !cfg.AutoCreate.Dataset || !cfg.AutoCreate.Tables {
		t.Errorf("example auto_create = %+v, want dataset and tables creation on", cfg.AutoCreate)
	}
	if cfg.AutoCreate.CompanionViews || cfg.AutoCreate.SearchIndexes {
		t.Errorf("example auto_create = %+v, want companion_views and search_indexes off (documented as opt-in)", cfg.AutoCreate)
	}
	for _, signal := range []string{"traces", "logs", "metrics"} {
		pipeline := yamlPath(doc, "service", "pipelines", signal)
		if pipeline == nil {
			t.Errorf("the example has no %s pipeline", signal)
			continue
		}
		if got := yamlPath(pipeline, "exporters"); !reflect.DeepEqual(got, []any{"bigquery"}) {
			t.Errorf("%s pipeline exporters = %v, want [bigquery]", signal, got)
		}
		if got := yamlPath(pipeline, "receivers"); !reflect.DeepEqual(got, []any{"otlp"}) {
			t.Errorf("%s pipeline receivers = %v, want [otlp]", signal, got)
		}
	}
	if cfg.Metrics.Table != "otel_metrics" || cfg.Traces.Table != "otel_spans" || cfg.Logs.Table != "otel_logs" {
		t.Errorf("example tables = %q, %q, %q", cfg.Traces.Table, cfg.Logs.Table, cfg.Metrics.Table)
	}
}

// The Compose smoke test starts the example with the loopback endpoint and
// auto_create overlays layered on by `--config=yaml:` arguments.
func TestComposeSmokeOverlayDecodesAndValidates(t *testing.T) {
	var compose struct {
		Services map[string]struct {
			Command []string `yaml:"command"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".github/compose-smoke.yml")), &compose); err != nil {
		t.Fatal(err)
	}
	command := compose.Services["otelcollector"].Command
	if !slices.Contains(command, "--config=/etc/otel/config.yml") {
		t.Fatalf("compose-smoke command = %v, want the bundled config first", command)
	}
	conf := confmap.NewFromStringMap(exampleCollectorConfig(t))
	overlays := 0
	for _, arg := range command {
		if document, ok := strings.CutPrefix(arg, "--config=yaml:"); ok {
			applyCollectorYAML(t, conf, document)
			overlays++
		}
	}
	if overlays == 0 {
		t.Fatalf("compose-smoke command = %v, want yaml: overlays", command)
	}
	cfg := decodeExporterConfig(t, "example config with the compose-smoke overlays", exporterBlock(t, conf, "bigquery"))
	if !cfg.Endpoint.Insecure || !cfg.Endpoint.WithoutAuthentication || cfg.Endpoint.URL == "" {
		t.Errorf("compose-smoke endpoint = %+v, want an insecure unauthenticated loopback endpoint", cfg.Endpoint)
	}
	if cfg.AutoCreate != (AutoCreateConfig{}) {
		t.Errorf("compose-smoke auto_create = %+v, want everything off", cfg.AutoCreate)
	}
}

func cloudRunArgs(t *testing.T) []string {
	t.Helper()
	var svc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Args []string `yaml:"args"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, "deploy/cloudrun/service.yaml")), &svc); err != nil {
		t.Fatal(err)
	}
	containers := svc.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		t.Fatalf("Cloud Run service has %d containers, want 1", len(containers))
	}
	return containers[0].Args
}

// The Cloud Run container starts the bundled config and turns off whatever
// would create resources, because the service account may only append rows.
// Every --set merges over the bundled config, so the bundled options that
// depend on the ones turned off must not leave the result invalid.
func TestCloudRunTemplateValid(t *testing.T) {
	args := cloudRunArgs(t)
	if !slices.Contains(args, "--config=/etc/otel/config.yml") {
		t.Fatalf("Cloud Run args = %v, want --config=/etc/otel/config.yml", args)
	}
	conf := confmap.NewFromStringMap(exampleCollectorConfig(t))
	for _, arg := range args {
		if strings.HasPrefix(arg, "--set=") {
			applyCollectorSet(t, conf, arg)
		}
	}
	cfg := decodeExporterConfig(t, "bundled config with the Cloud Run args", exporterBlock(t, conf, "bigquery"))
	if cfg.AutoCreate != (AutoCreateConfig{}) {
		t.Errorf("Cloud Run auto_create = %+v, want every option off: the service account only appends rows", cfg.AutoCreate)
	}
}

// The header of the manifest lists --set overrides to add for the enterprise
// options. Applied together on top of the live args they must give a valid
// configuration, so an option cannot be documented that the manifest's own
// auto_create settings forbid.
func TestCloudRunDocumentedOverridesValidate(t *testing.T) {
	var documented []string
	for _, line := range strings.Split(readRepoText(t, "deploy/cloudrun/service.yaml"), "\n") {
		comment, ok := strings.CutPrefix(strings.TrimSpace(line), "#")
		if !ok {
			continue
		}
		if arg := strings.TrimSpace(comment); strings.HasPrefix(arg, "--set=") {
			documented = append(documented, strings.TrimSpace(strings.TrimSuffix(arg, `\`)))
		}
	}
	if len(documented) == 0 {
		t.Fatal("deploy/cloudrun/service.yaml documents no --set overrides in its header")
	}
	conf := confmap.NewFromStringMap(exampleCollectorConfig(t))
	for _, arg := range append(cloudRunArgs(t), documented...) {
		if strings.HasPrefix(arg, "--set=") {
			applyCollectorSet(t, conf, arg)
		}
	}
	cfg := decodeExporterConfig(t, "bundled config with the Cloud Run args and every documented override", exporterBlock(t, conf, "bigquery"))
	if !cfg.Offload.Enabled || cfg.Offload.Bucket == "" || !cfg.Quarantine.Enabled || !cfg.Redaction.Enabled || cfg.KMSKeyName == "" {
		t.Errorf("the documented overrides did not enable offload, quarantine, redaction and CMEK: %+v", cfg)
	}
}

// helmFuncs are the template functions the chart's ConfigMap uses, with the
// semantics Helm gives them (toYaml from sigs.k8s.io/yaml, nindent and quote
// from sprig).
var helmFuncs = template.FuncMap{
	"toYaml": func(v any) (string, error) {
		var buf bytes.Buffer
		enc := yaml.NewEncoder(&buf)
		enc.SetIndent(2)
		if err := enc.Encode(v); err != nil {
			return "", err
		}
		if err := enc.Close(); err != nil {
			return "", err
		}
		return strings.TrimSuffix(buf.String(), "\n"), nil
	},
	"nindent": func(spaces int, text string) string {
		pad := strings.Repeat(" ", spaces)
		return "\n" + pad + strings.ReplaceAll(text, "\n", "\n"+pad)
	},
	"quote": func(v any) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%q", fmt.Sprint(v))
	},
	"hasKey": func(m map[string]any, key string) bool {
		_, ok := m[key]
		return ok
	},
	"fail": func(msg string) (string, error) {
		return "", errors.New(msg)
	},
	"int": func(v any) int {
		switch x := v.(type) {
		case nil:
			return 0
		case int:
			return x
		case int64:
			return int(x)
		case uint64:
			return int(x)
		case float64:
			return int(x)
		case bool:
			if x {
				return 1
			}
			return 0
		case string:
			if n, err := strconv.Atoi(strings.TrimSpace(x)); err == nil {
				return n
			}
			if f, err := strconv.ParseFloat(strings.TrimSpace(x), 64); err == nil {
				return int(f)
			}
			return 0
		default:
			n, _ := strconv.Atoi(fmt.Sprint(v))
			return n
		}
	},
	"contains": func(substr, str string) bool {
		return strings.Contains(str, substr)
	},
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
	"trim":  strings.TrimSpace,
}

const helmChartDir = "deploy/helm/bigquery-otel-collector"

// helmValues returns the chart's values.yaml merged with overrides. Helm reads
// values files through JSON, so every number there is a float64, while --set
// produces int64 and strings; overrides use those types.
func helmValues(t *testing.T, overrides map[string]any) map[string]any {
	t.Helper()
	values := parseYAMLMap(t, helmChartDir+"/values.yaml", readRepoText(t, helmChartDir+"/values.yaml"))
	var floats func(v any) any
	floats = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				x[k] = floats(e)
			}
		case []any:
			for i, e := range x {
				x[i] = floats(e)
			}
		case int:
			return float64(x)
		}
		return v
	}
	floats(values)
	var merge func(dst, src map[string]any)
	merge = func(dst, src map[string]any) {
		for k, v := range src {
			if sub, ok := v.(map[string]any); ok {
				if existing, ok := dst[k].(map[string]any); ok {
					merge(existing, sub)
					continue
				}
			}
			dst[k] = v
		}
	}
	merge(values, overrides)
	return values
}

// renderHelmTemplateWithValuesErr renders any named template under
// deploy/helm/bigquery-otel-collector/templates/ with a complete Values map,
// returning any template execution error (such as Helm `fail` guards).
func renderHelmTemplateWithValuesErr(t *testing.T, templateName string, values map[string]any) (string, error) {
	t.Helper()
	funcMap := template.FuncMap{}
	for k, v := range helmFuncs {
		funcMap[k] = v
	}
	funcMap["default"] = func(def, val any) any {
		if val == nil || val == "" || val == false || val == 0 || val == int64(0) || val == float64(0) {
			return def
		}
		return val
	}
	funcMap["include"] = func(name string, _ any) string {
		if name == "bigquery-otel-collector.serviceAccountName" {
			return "bq-otel-sa"
		}
		return ""
	}
	funcMap["sha256sum"] = func(s string) string {
		return fmt.Sprintf("sha256-%d", len(s))
	}
	tmpl, err := template.New(templateName).Option("missingkey=zero").Funcs(funcMap).
		Parse(readRepoText(t, helmChartDir+"/templates/"+templateName))
	if err != nil {
		return "", fmt.Errorf("parsing the chart's %s template: %w", templateName, err)
	}
	var out bytes.Buffer
	data := map[string]any{
		"Release":  map[string]any{"Name": "bq-otel", "Namespace": "observability"},
		"Chart":    map[string]any{"AppVersion": "0.1.0"},
		"Template": map[string]any{"BasePath": helmChartDir + "/templates"},
		"Values":   values,
	}
	if err := tmpl.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

// renderHelmTemplateWithValues renders any named template under
// deploy/helm/bigquery-otel-collector/templates/ with a complete Values map.
func renderHelmTemplateWithValues(t *testing.T, templateName string, values map[string]any) string {
	t.Helper()
	rendered, err := renderHelmTemplateWithValuesErr(t, templateName, values)
	if err != nil {
		t.Fatalf("rendering the chart's %s template: %v", templateName, err)
	}
	return rendered
}

// renderHelmConfigMapWithValues renders the chart's ConfigMap template with a
// complete Values map and returns the rendered manifest.
func renderHelmConfigMapWithValues(t *testing.T, values map[string]any) string {
	t.Helper()
	return renderHelmTemplateWithValues(t, "configmap.yaml", values)
}

// renderHelmConfigMap renders the chart's ConfigMap template with the given
// value overrides and returns the rendered manifest.
func renderHelmConfigMap(t *testing.T, overrides map[string]any) string {
	t.Helper()
	return renderHelmConfigMapWithValues(t, helmValues(t, overrides))
}

func helmCollectorConfigFromManifest(t *testing.T, manifest string) map[string]any {
	t.Helper()
	var cm struct {
		Data map[string]string `yaml:"data"`
	}
	if err := yaml.Unmarshal([]byte(manifest), &cm); err != nil {
		t.Fatalf("the rendered ConfigMap is not valid YAML: %v\n%s", err, manifest)
	}
	raw, ok := cm.Data["config.yml"]
	if !ok {
		t.Fatalf("the rendered ConfigMap has no config.yml:\n%s", manifest)
	}
	return parseYAMLMap(t, "the rendered config.yml", expandDeployEnv(t, "the rendered config.yml", raw))
}

// helmCollectorConfigWithValues renders the chart with a complete Values map
// and returns the Collector configuration its ConfigMap embeds.
func helmCollectorConfigWithValues(t *testing.T, values map[string]any) map[string]any {
	t.Helper()
	return helmCollectorConfigFromManifest(t, renderHelmConfigMapWithValues(t, values))
}

// helmCollectorConfig renders the chart and returns the Collector
// configuration its ConfigMap embeds.
func helmCollectorConfig(t *testing.T, overrides map[string]any) map[string]any {
	t.Helper()
	return helmCollectorConfigFromManifest(t, renderHelmConfigMap(t, overrides))
}

// helmEnterpriseValues turns on every optional section of the chart, with
// values written the way --set and --set-string deliver them: counts as int64,
// a numeric label value as int64 and an all-digit bucket name as a string.
func helmEnterpriseValues(maskReplacement string) map[string]any {
	const key = "projects/my-project/locations/us/keyRings/otel/cryptoKeys/"
	signal := func(name string) map[string]any {
		return map[string]any{
			"partitionExpirationDays": int64(90),
			"requirePartitionFilter":  true,
			"kmsKeyName":              key + name,
			"labels":                  map[string]any{"signal": name},
			"maxStaleness":            "15m",
		}
	}
	logs := signal("logs")
	logs["synthesizeInsertID"] = false
	return map[string]any{
		"bigquery": map[string]any{
			"autoCreateDataset":        true,
			"autoCreateTables":         true,
			"autoCreateCompanionViews": true,
			"autoCreateSearchIndexes":  true,
			"kmsKeyName":               key + "default",
			"labels":                   map[string]any{"env": "prod", "cost-center": int64(1234)},
			"traces":                   signal("traces"),
			"logs":                     logs,
			"metrics":                  signal("metrics"),
		},
		"offload": map[string]any{
			"enabled":        true,
			"bucket":         "123456",
			"prefix":         "otel",
			"authorizer":     "my-project.us.otel-gcs",
			"minBytes":       int64(1048576),
			"maxObjectBytes": int64(67108864),
			"maxConcurrency": int64(4),
			"timeout":        "30s",
			"cacheSize":      int64(2048),
		},
		"quarantine": map[string]any{
			"enabled":                 true,
			"table":                   "otel_quarantine",
			"metadataOnly":            true,
			"maxRawPayloadBytes":      int64(1048576),
			"timeout":                 "5s",
			"partitionExpirationDays": int64(14),
			"requirePartitionFilter":  true,
			"kmsKeyName":              key + "quarantine",
			"labels":                  map[string]any{"signal": "quarantine"},
			"maxStaleness":            "30m",
		},
		"redaction": map[string]any{
			"enabled":              true,
			"blockedKeys":          []any{"x-custom-secret", "*.ssn"},
			"disableDefaultKeys":   true,
			"blockedValuePatterns": []any{`Bearer [A-Za-z0-9._-]+`, `\b\d{3}-\d{2}-\d{4}\b`},
			"maskReplacement":      maskReplacement,
			"redactLogBody":        true,
		},
		"write": map[string]any{
			"streamPoolSize": int64(4),
			"backpressure": map[string]any{
				"enabled": true,
			},
		},
	}
}

func TestHelmChartStructure(t *testing.T) {
	var chart struct {
		APIVersion  string `yaml:"apiVersion"`
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
		Type        string `yaml:"type"`
		Version     string `yaml:"version"`
		AppVersion  string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, helmChartDir+"/Chart.yaml")), &chart); err != nil {
		t.Fatal(err)
	}
	if chart.APIVersion != "v2" || chart.Name != "bigquery-otel-collector" || chart.Type != "application" ||
		chart.Version == "" || chart.AppVersion == "" {
		t.Errorf("Chart.yaml = %+v, want a v2 application chart named bigquery-otel-collector with a version", chart)
	}
	for _, signal := range []string{"traces", "logs", "metrics"} {
		if !strings.Contains(chart.Description, signal) {
			t.Errorf("Chart.yaml description %q does not mention %s; the chart ships all three pipelines", chart.Description, signal)
		}
	}

	// A template that reads a value values.yaml does not define renders
	// "<no value>" rather than failing, so scan the default render for it.
	for name, overrides := range map[string]map[string]any{
		"defaults":   nil,
		"enterprise": helmEnterpriseValues("[REDACTED]"),
	} {
		if manifest := renderHelmConfigMap(t, overrides); strings.Contains(manifest, "<no value>") {
			t.Errorf("%s render has an undefined value:\n%s", name, manifest)
		}
	}
}

func TestHelmConfigMapDecodesAndValidates(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		doc := helmCollectorConfig(t, nil)
		conf := confmap.NewFromStringMap(doc)
		cfg := decodeExporterConfig(t, "default values", exporterBlock(t, conf, "bigquery"))
		if cfg.Metrics.Table != "otel_metrics" {
			t.Errorf("metrics.table = %q, want otel_metrics", cfg.Metrics.Table)
		}
		if cfg.Write.StreamPoolSize != 1 {
			t.Errorf("write.stream_pool_size = %d, want 1", cfg.Write.StreamPoolSize)
		}
		if !cfg.Logs.SynthesizeInsertID {
			t.Errorf("logs.synthesize_insert_id = %v, want true by default", cfg.Logs.SynthesizeInsertID)
		}
		for _, signal := range []string{"traces", "logs", "metrics"} {
			if got := yamlPath(doc, "service", "pipelines", signal, "exporters"); !reflect.DeepEqual(got, []any{"bigquery"}) {
				t.Errorf("%s pipeline exporters = %v, want [bigquery]", signal, got)
			}
		}
	})

	// Values a YAML parser reads as something other than a string, a list or a
	// mapping when written bare (a flow sequence, an alias, a tag, null, a
	// boolean, a number) must still reach the exporter as the string the
	// operator wrote.
	for _, mask := range []string{
		"[REDACTED]", "***", "*", "{redacted}", "&anchor", "!tag", "#hash", "@at", "%pct",
		"- dash", "key: value", "null", "true", "123", `"quoted"`, `back\slash`,
	} {
		t.Run("enterprise/mask="+mask, func(t *testing.T) {
			conf := confmap.NewFromStringMap(helmCollectorConfig(t, helmEnterpriseValues(mask)))
			cfg := decodeExporterConfig(t, "enterprise values", exporterBlock(t, conf, "bigquery"))
			if cfg.Redaction.MaskReplacement != mask {
				t.Errorf("redaction.mask_replacement = %q, want %q", cfg.Redaction.MaskReplacement, mask)
			}
			if cfg.Offload.Bucket != "123456" {
				t.Errorf("offload.bucket = %q, want the all-digit bucket name as a string", cfg.Offload.Bucket)
			}
			if got := cfg.Labels["cost-center"]; got != "1234" {
				t.Errorf("labels[cost-center] = %q, want %q: a numeric label value must stay a string", got, "1234")
			}
			if cfg.Traces.MaxStaleness != "15m" || cfg.Quarantine.MaxStaleness != "30m" {
				t.Errorf("max_staleness = %q (traces) and %q (quarantine), want 15m and 30m",
					cfg.Traces.MaxStaleness, cfg.Quarantine.MaxStaleness)
			}
			if cfg.KMSKeyName == "" || cfg.Logs.KMSKeyName == "" || cfg.Quarantine.KMSKeyName == "" {
				t.Errorf("kms_key_name did not reach the exporter: %q, %q, %q",
					cfg.KMSKeyName, cfg.Logs.KMSKeyName, cfg.Quarantine.KMSKeyName)
			}
			// The enterprise values enable companion views with a traces
			// partition filter and leave autoCreateAllowUnprunableViews unset,
			// as values written before that key existed do; they must keep
			// validating.
			if !cfg.AutoCreate.CompanionViews || !cfg.AutoCreate.SearchIndexes || cfg.AutoCreate.AllowUnprunableViews {
				t.Errorf("auto_create = %+v, want companion_views and search_indexes on and allow_unprunable_views off", cfg.AutoCreate)
			}
			if !cfg.Traces.RequirePartitionFilter {
				t.Errorf("traces.require_partition_filter = %v, want true", cfg.Traces.RequirePartitionFilter)
			}
			if !reflect.DeepEqual(cfg.Redaction.BlockedKeys, []string{"x-custom-secret", "*.ssn"}) ||
				len(cfg.Redaction.BlockedValuePatterns) != 2 {
				t.Errorf("redaction lists = %v and %v", cfg.Redaction.BlockedKeys, cfg.Redaction.BlockedValuePatterns)
			}
			if cfg.Write.StreamPoolSize != 4 {
				t.Errorf("write.stream_pool_size = %d, want 4", cfg.Write.StreamPoolSize)
			}
			if cfg.Logs.SynthesizeInsertID {
				t.Errorf("logs.synthesize_insert_id = %v, want false from enterprise values", cfg.Logs.SynthesizeInsertID)
			}
		})
	}

	t.Run("traces requirePartitionFilter without companionViews", func(t *testing.T) {
		overrides := helmEnterpriseValues("[REDACTED]")
		bq := overrides["bigquery"].(map[string]any)
		bq["autoCreateCompanionViews"] = false
		bq["traces"].(map[string]any)["requirePartitionFilter"] = true
		conf := confmap.NewFromStringMap(helmCollectorConfig(t, overrides))
		cfg := decodeExporterConfig(t, "traces requirePartitionFilter", exporterBlock(t, conf, "bigquery"))
		if !cfg.Traces.RequirePartitionFilter || cfg.AutoCreate.CompanionViews {
			t.Errorf("decoded traces.require_partition_filter = %v, auto_create.companion_views = %v, want true and false",
				cfg.Traces.RequirePartitionFilter, cfg.AutoCreate.CompanionViews)
		}
	})

	// The chart renders auto_create.allow_unprunable_views only when
	// autoCreateAllowUnprunableViews is set, so the default render keeps the
	// exporter default.
	for _, allow := range []bool{false, true} {
		t.Run(fmt.Sprintf("autoCreateAllowUnprunableViews=%v", allow), func(t *testing.T) {
			overrides := helmEnterpriseValues("[REDACTED]")
			overrides["bigquery"].(map[string]any)["autoCreateAllowUnprunableViews"] = allow
			doc := helmCollectorConfig(t, overrides)
			rendered := yamlPath(doc, "exporters", "bigquery", "auto_create", "allow_unprunable_views")
			var want any // absent
			if allow {
				want = true
			}
			if rendered != want {
				t.Errorf("rendered auto_create.allow_unprunable_views = %#v, want %#v", rendered, want)
			}
			cfg := decodeExporterConfig(t, "autoCreateAllowUnprunableViews", exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))
			if cfg.AutoCreate.AllowUnprunableViews != allow || !cfg.AutoCreate.CompanionViews || !cfg.Traces.RequirePartitionFilter {
				t.Errorf("auto_create = %+v, traces.require_partition_filter = %v; want allow_unprunable_views %v with companion_views and a traces partition filter",
					cfg.AutoCreate, cfg.Traces.RequirePartitionFilter, allow)
			}
		})
	}
}

// An offload.cacheSize of 0 disables the cross-batch cache, whose exporter
// default is 4096, so it has to reach the exporter rather than be dropped as
// false; an explicit quarantine.partitionExpirationDays of 0 renders as
// written too. A values file delivers numbers as float64 and --set as int64.
// An unset, nil, or omitted value is still left to the exporter default.
func TestHelmConfigMapRendersZeroCacheSizeAndPartitionExpiration(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		omitKeys              bool
		cacheSize, expiration any
		// Rendered values, nil when the key is absent.
		renderedCacheSize, renderedExpiration any
		// Decoded onto the factory defaults.
		wantCacheSize, wantExpiration int
	}{
		{"zero from --set", false, int64(0), int64(0), 0, 0, 0, 0},
		{"zero from a values file", false, float64(0), float64(0), 0, 0, 0, 0},
		{"positive", false, int64(2048), int64(14), 2048, 14, 2048, 14},
		{"unset", false, nil, nil, nil, nil, defaultOffloadCacheSize, defaultQuarantinePartitionExpiryDays},
		{"empty", false, "", "", nil, nil, defaultOffloadCacheSize, defaultQuarantinePartitionExpiryDays},
		{"omitted", true, nil, nil, nil, nil, defaultOffloadCacheSize, defaultQuarantinePartitionExpiryDays},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if tc.omitKeys {
				values := helmValues(t, map[string]any{
					"offload":    map[string]any{"enabled": true, "bucket": "test-offload-bucket"},
					"quarantine": map[string]any{"enabled": true},
				})
				delete(values["offload"].(map[string]any), "cacheSize")
				delete(values["quarantine"].(map[string]any), "partitionExpirationDays")
				doc = helmCollectorConfigWithValues(t, values)
			} else {
				doc = helmCollectorConfig(t, map[string]any{
					"offload":    map[string]any{"enabled": true, "bucket": "test-offload-bucket", "cacheSize": tc.cacheSize},
					"quarantine": map[string]any{"enabled": true, "partitionExpirationDays": tc.expiration},
				})
			}
			if got := yamlPath(doc, "exporters", "bigquery", "offload", "cache_size"); got != tc.renderedCacheSize {
				t.Errorf("rendered offload.cache_size = %#v, want %#v", got, tc.renderedCacheSize)
			}
			if got := yamlPath(doc, "exporters", "bigquery", "quarantine", "partition_expiration_days"); got != tc.renderedExpiration {
				t.Errorf("rendered quarantine.partition_expiration_days = %#v, want %#v", got, tc.renderedExpiration)
			}
			cfg := decodeExporterConfig(t, tc.name, exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))
			if cfg.Offload.CacheSize != tc.wantCacheSize || cfg.Quarantine.PartitionExpirationDays != tc.wantExpiration {
				t.Errorf("offload.cache_size = %d and quarantine.partition_expiration_days = %d, want %d and %d",
					cfg.Offload.CacheSize, cfg.Quarantine.PartitionExpirationDays, tc.wantCacheSize, tc.wantExpiration)
			}
			md, err := schema.QuarantineDestinationMetadataWithOptions(schema.DestinationOptions{
				PartitionExpirationDays: cfg.Quarantine.PartitionExpirationDays,
			})
			if err != nil {
				t.Fatalf("QuarantineDestinationMetadataWithOptions(%d) failed: %v", cfg.Quarantine.PartitionExpirationDays, err)
			}
			if want := time.Duration(tc.wantExpiration) * 24 * time.Hour; md.TimePartitioning.Expiration != want {
				t.Errorf("quarantine TimePartitioning.Expiration = %v, want %v", md.TimePartitioning.Expiration, want)
			}
		})
	}
}

// Helm v3.4.1 (Go 1.15 text/template) rejects `ne`/`eq` when comparing a
// numeric value against untyped nil (`incompatible types for comparison`).
// Walk the parsed template AST for every Helm template so any `eq ... nil` or
// `ne ... nil` regression fails immediately regardless of local Helm version.
func TestHelmConfigMapTemplateAvoidsTypedNilComparison(t *testing.T) {
	tmplDir := filepath.Join(helmChartDir, "templates")
	entries, err := os.ReadDir(tmplDir)
	if err != nil {
		t.Fatalf("reading Helm templates dir %s: %v", tmplDir, err)
	}
	funcMap := template.FuncMap{}
	for k, v := range helmFuncs {
		funcMap[k] = v
	}
	// Stub standard Helm/Sprig helpers used across non-ConfigMap templates so
	// every file parses with Go's text/template/parse.
	for _, extra := range []string{"include", "tpl", "required", "default", "empty", "coalesce", "dig", "sha256sum", "trunc", "trimSuffix", "fromYaml", "b64enc", "lookup", "regexReplaceAll", "replace", "lower", "upper"} {
		if _, ok := funcMap[extra]; !ok {
			funcMap[extra] = func(_ ...any) string { return "" }
		}
	}

	var checkNode func(file string, node parse.Node)
	checkNode = func(file string, node parse.Node) {
		if node == nil {
			return
		}
		switch n := node.(type) {
		case *parse.ListNode:
			if n == nil {
				return
			}
			for _, child := range n.Nodes {
				checkNode(file, child)
			}
		case *parse.ActionNode:
			checkNode(file, n.Pipe)
		case *parse.IfNode:
			checkNode(file, n.Pipe)
			checkNode(file, n.List)
			checkNode(file, n.ElseList)
		case *parse.RangeNode:
			checkNode(file, n.Pipe)
			checkNode(file, n.List)
			checkNode(file, n.ElseList)
		case *parse.WithNode:
			checkNode(file, n.Pipe)
			checkNode(file, n.List)
			checkNode(file, n.ElseList)
		case *parse.TemplateNode:
			if n != nil && n.Pipe != nil {
				checkNode(file, n.Pipe)
			}
		case *parse.ChainNode:
			if n != nil {
				checkNode(file, n.Node)
			}
		case *parse.PipeNode:
			if n == nil {
				return
			}
			for _, cmd := range n.Cmds {
				checkNode(file, cmd)
			}
		case *parse.CommandNode:
			if n == nil || len(n.Args) == 0 {
				return
			}
			if id, ok := n.Args[0].(*parse.IdentifierNode); ok && (id.Ident == "ne" || id.Ident == "eq") {
				for _, arg := range n.Args[1:] {
					if _, isNil := arg.(*parse.NilNode); isNil {
						t.Errorf("%s: comparison %q with untyped nil (`%s`) fails on Helm v3.4.1; use hasKey plus stringified printf comparison instead", file, id.Ident, n.String())
					}
				}
			}
			for _, arg := range n.Args {
				checkNode(file, arg)
			}
		}
	}

	var checked int
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || (!strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".tpl")) {
			continue
		}
		path := filepath.Join(tmplDir, name)
		raw := readRepoText(t, path)
		tmpl, err := template.New(name).Funcs(funcMap).Parse(raw)
		if err != nil {
			t.Fatalf("parsing Helm template %s: %v", path, err)
		}
		checked++
		for _, sub := range tmpl.Templates() {
			if sub.Root != nil {
				checkNode(path, sub.Root)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("no Helm templates found in %s", tmplDir)
	}
}

// helmUnexposedExporterKeys lists the exporter options the chart does not
// surface as values, with the reason. Every other option must reach the
// exporter's section of the rendered ConfigMap, and an option listed here must
// not have been exposed since: a new Config field forces a decision.
var helmUnexposedExporterKeys = map[string]string{
	"timeout": "the exporter default applies to the whole send",

	"credentials.file":                        "the pod authenticates with Workload Identity Federation, not a key file",
	"credentials.json":                        "the pod authenticates with Workload Identity Federation, not inline keys",
	"credentials.impersonate_service_account": "the pod authenticates as its own Workload Identity service account",
	"credentials.impersonate_delegates":       "the pod authenticates as its own Workload Identity service account",
	"credentials.quota_project":               "the default quota project of the service account applies",
	"credentials.universe_domain":             "the chart targets the public googleapis.com universe",

	"endpoint.url":                    "custom and emulator endpoints are test configuration, not a deployment option",
	"endpoint.admin_url":              "custom and emulator endpoints are test configuration, not a deployment option",
	"endpoint.insecure":               "custom and emulator endpoints are test configuration, not a deployment option",
	"endpoint.without_authentication": "custom and emulator endpoints are test configuration, not a deployment option",

	"write.max_request_bytes":                  "Storage Write API tuning keeps the exporter defaults",
	"write.max_row_bytes":                      "Storage Write API tuning keeps the exporter defaults",
	"write.max_inflight_requests":              "Storage Write API tuning keeps the exporter defaults",
	"write.max_inflight_bytes":                 "Storage Write API tuning keeps the exporter defaults",
	"write.enable_multiplexing":                "Storage Write API tuning keeps the exporter defaults",
	"write.connection_pool_size":               "Storage Write API tuning keeps the exporter defaults",
	"write.compression":                        "Storage Write API tuning keeps the exporter defaults",
	"write.keepalive.time":                     "Storage Write API tuning keeps the exporter defaults",
	"write.keepalive.timeout":                  "Storage Write API tuning keeps the exporter defaults",
	"write.keepalive.permit_without_stream":    "Storage Write API tuning keeps the exporter defaults",
	"write.backpressure.min_request_bytes":     "Storage Write API tuning keeps the exporter defaults",
	"write.backpressure.min_inflight_requests": "Storage Write API tuning keeps the exporter defaults",
	"write.backpressure.decrease_factor":       "Storage Write API tuning keeps the exporter defaults",
	"write.backpressure.recovery_interval":     "Storage Write API tuning keeps the exporter defaults",
	"write.backpressure.latency_threshold":     "Storage Write API tuning keeps the exporter defaults",

	"limits.max_attribute_count":     "structural limits keep the exporter defaults",
	"limits.max_event_count":         "structural limits keep the exporter defaults",
	"limits.max_link_count":          "structural limits keep the exporter defaults",
	"limits.max_nesting_depth":       "structural limits keep the exporter defaults",
	"limits.max_collection_size":     "structural limits keep the exporter defaults",
	"limits.max_attribute_key_bytes": "structural limits keep the exporter defaults",
	"limits.max_value_bytes":         "structural limits keep the exporter defaults",

	"logs.log_name_attribute":  "the exporter falls back to well-known attributes, then the service name",
	"logs.insert_id_attribute": "the exporter falls back to well-known attributes, then the record fingerprint",
}

func TestHelmChartExposesExporterOptions(t *testing.T) {
	overrides := helmEnterpriseValues("[REDACTED]")
	// Off by default and rendered only when set; the enterprise values leave
	// it unset, as values written before it existed do.
	overrides["bigquery"].(map[string]any)["autoCreateAllowUnprunableViews"] = true
	conf := confmap.NewFromStringMap(helmCollectorConfig(t, overrides))
	section := exporterBlock(t, conf, "bigquery")
	exposed := map[string]bool{}
	for _, key := range presentExporterKeys(section, exporterKeySet(), "") {
		exposed[key] = true
	}
	for _, key := range exporterConfigKeys() {
		reason, unexposed := helmUnexposedExporterKeys[key]
		switch {
		case !exposed[key] && !unexposed:
			t.Errorf("the chart renders no %q: expose it as a value or list it in helmUnexposedExporterKeys with the reason", key)
		case exposed[key] && unexposed:
			t.Errorf("the chart now renders %q but helmUnexposedExporterKeys still lists it (%s)", key, reason)
		}
	}
	for _, key := range slices.Sorted(maps.Keys(helmUnexposedExporterKeys)) {
		if !slices.Contains(exporterConfigKeys(), key) {
			t.Errorf("helmUnexposedExporterKeys lists %q, which is not an exporter option", key)
		}
	}
}

// helmFreeformLabelMapKeys lists the exporter map[string]string options whose
// map entries are user-defined Google Cloud label keys rather than schema keys.
var helmFreeformLabelMapKeys = map[string]bool{
	"labels":            true,
	"traces.labels":     true,
	"logs.labels":       true,
	"metrics.labels":    true,
	"quarantine.labels": true,
}

// helmAppVersionExporterKeys records the complete set of dotted key paths
// accepted under exporters.bigquery by each released image version that
// Chart.yaml's appVersion pins. Updating Chart.yaml appVersion requires adding
// the corresponding image release's exporter key set here.
var helmAppVersionExporterKeys = map[string]map[string]bool{
	// Verified directly from v0.1.0 config.go plus Collector v0.164.0
	// exporterhelper.QueueBatchConfig and configretry.BackOffConfig.
	"0.1.0": {
		"timeout":      true,
		"project":      true,
		"dataset":      true,
		"location":     true,
		"kms_key_name": true,
		"labels":       true,

		"traces.table":                     true,
		"traces.partition_expiration_days": true,
		"traces.require_partition_filter":  true,
		"traces.kms_key_name":              true,
		"traces.labels":                    true,
		"traces.max_staleness":             true,

		"logs.table":                     true,
		"logs.partition_expiration_days": true,
		"logs.require_partition_filter":  true,
		"logs.kms_key_name":              true,
		"logs.labels":                    true,
		"logs.max_staleness":             true,
		"logs.log_name_attribute":        true,
		"logs.insert_id_attribute":       true,

		"metrics.table":                     true,
		"metrics.partition_expiration_days": true,
		"metrics.require_partition_filter":  true,
		"metrics.kms_key_name":              true,
		"metrics.labels":                    true,
		"metrics.max_staleness":             true,

		"credentials.file":                        true,
		"credentials.json":                        true,
		"credentials.impersonate_service_account": true,
		"credentials.impersonate_delegates":       true,
		"credentials.quota_project":               true,
		"credentials.universe_domain":             true,

		"endpoint.url":                    true,
		"endpoint.admin_url":              true,
		"endpoint.insecure":               true,
		"endpoint.without_authentication": true,

		"auto_create.dataset":                true,
		"auto_create.tables":                 true,
		"auto_create.companion_views":        true,
		"auto_create.allow_unprunable_views": true,
		"auto_create.search_indexes":         true,

		"write.max_request_bytes":                  true,
		"write.max_row_bytes":                      true,
		"write.max_inflight_requests":              true,
		"write.max_inflight_bytes":                 true,
		"write.stream_pool_size":                   true,
		"write.enable_multiplexing":                true,
		"write.connection_pool_size":               true,
		"write.compression":                        true,
		"write.keepalive.time":                     true,
		"write.keepalive.timeout":                  true,
		"write.keepalive.permit_without_stream":    true,
		"write.backpressure.enabled":               true,
		"write.backpressure.min_request_bytes":     true,
		"write.backpressure.min_inflight_requests": true,
		"write.backpressure.decrease_factor":       true,
		"write.backpressure.recovery_interval":     true,
		"write.backpressure.latency_threshold":     true,

		"limits.max_attribute_count":     true,
		"limits.max_event_count":         true,
		"limits.max_link_count":          true,
		"limits.max_nesting_depth":       true,
		"limits.max_collection_size":     true,
		"limits.max_attribute_key_bytes": true,
		"limits.max_value_bytes":         true,

		"quarantine.enabled":                   true,
		"quarantine.table":                     true,
		"quarantine.partition_expiration_days": true,
		"quarantine.require_partition_filter":  true,
		"quarantine.kms_key_name":              true,
		"quarantine.labels":                    true,
		"quarantine.max_staleness":             true,
		"quarantine.metadata_only":             true,
		"quarantine.max_raw_payload_bytes":     true,
		"quarantine.timeout":                   true,

		"offload.enabled":          true,
		"offload.bucket":           true,
		"offload.prefix":           true,
		"offload.authorizer":       true,
		"offload.min_bytes":        true,
		"offload.max_object_bytes": true,
		"offload.max_concurrency":  true,
		"offload.cache_size":       true,
		"offload.timeout":          true,

		"redaction.enabled":                true,
		"redaction.blocked_keys":           true,
		"redaction.disable_default_keys":   true,
		"redaction.blocked_value_patterns": true,
		"redaction.mask_replacement":       true,
		"redaction.redact_log_body":        true,

		"sending_queue.enabled":                       true,
		"sending_queue.wait_for_result":               true,
		"sending_queue.sizer":                         true,
		"sending_queue.queue_size":                    true,
		"sending_queue.block_on_overflow":             true,
		"sending_queue.storage":                       true,
		"sending_queue.num_consumers":                 true,
		"sending_queue.batch.enabled":                 true,
		"sending_queue.batch.flush_timeout":           true,
		"sending_queue.batch.sizer":                   true,
		"sending_queue.batch.min_size":                true,
		"sending_queue.batch.max_size":                true,
		"sending_queue.batch.partition.metadata_keys": true,

		"retry_on_failure.enabled":              true,
		"retry_on_failure.initial_interval":     true,
		"retry_on_failure.randomization_factor": true,
		"retry_on_failure.multiplier":           true,
		"retry_on_failure.max_interval":         true,
		"retry_on_failure.max_elapsed_time":     true,
	},
}

// renderedExporterKeyPaths walks every nested map under exporters.bigquery and
// returns every leaf key path (stopping at free-form label maps, while still
// reporting empty nested maps so unknown empty blocks cannot slip past).
func renderedExporterKeyPaths(section map[string]any) []string {
	var paths []string
	var walk func(m map[string]any, prefix string)
	walk = func(m map[string]any, prefix string) {
		for key, value := range m {
			path := prefix + key
			if helmFreeformLabelMapKeys[path] {
				paths = append(paths, path)
				continue
			}
			if nested, ok := value.(map[string]any); ok {
				if len(nested) == 0 {
					paths = append(paths, path)
					continue
				}
				walk(nested, path+".")
				continue
			}
			paths = append(paths, path)
		}
	}
	walk(section, "")
	sort.Strings(paths)
	return paths
}

// pinnedImageSchemaVersion records the internal/schema.Version contract
// written by each released collector image version referenced in Helm
// (Chart.yaml appVersion / values.yaml image.tag) and Cloud Run
// (deploy/cloudrun/service.yaml).
var pinnedImageSchemaVersion = map[string]string{
	"0.1.0": "v0alpha2",
}

func checkPinnedImageSchemaContract(
	imageTag, targetSchema string,
	schemaVersions map[string]string,
	deployDocs map[string]string,
) error {
	pinnedSchema, ok := schemaVersions[imageTag]
	if !ok {
		return fmt.Errorf(
			"pinned collector image tag %q has no entry in pinnedImageSchemaVersion; record the internal/schema.Version it writes",
			imageTag,
		)
	}
	if pinnedSchema == targetSchema {
		return nil
	}
	for _, path := range slices.Sorted(maps.Keys(deployDocs)) {
		content := deployDocs[path]
		normalized := strings.ReplaceAll(strings.ToLower(content), "-", " ")
		if !strings.Contains(content, pinnedSchema) ||
			!strings.Contains(content, targetSchema) ||
			!strings.Contains(content, imageTag) ||
			!strings.Contains(normalized, "same revision") ||
			!strings.Contains(normalized, "build") {
			return fmt.Errorf(
				"pinned image tag %q writes %s while repository/Terraform provisions %s, and %s does not explicitly document the %s vs %s skew and same-revision build requirement",
				imageTag, pinnedSchema, targetSchema, path, pinnedSchema, targetSchema,
			)
		}
	}
	return nil
}

func cloudRunImageTag(t *testing.T, serviceYAML string) string {
	t.Helper()
	var svc struct {
		Spec struct {
			Template struct {
				Spec struct {
					Containers []struct {
						Image string `yaml:"image"`
					} `yaml:"containers"`
				} `yaml:"spec"`
			} `yaml:"template"`
		} `yaml:"spec"`
	}
	if err := yaml.Unmarshal([]byte(serviceYAML), &svc); err != nil {
		t.Fatalf("parsing deploy/cloudrun/service.yaml: %v", err)
	}
	if len(svc.Spec.Template.Spec.Containers) != 1 {
		t.Fatalf("Cloud Run service has %d containers, want 1", len(svc.Spec.Template.Spec.Containers))
	}
	img := svc.Spec.Template.Spec.Containers[0].Image
	if img == "" {
		t.Fatal("deploy/cloudrun/service.yaml container image must not be empty")
	}
	lastSlash := strings.LastIndex(img, "/")
	tail := img[lastSlash+1:]
	_, tag, ok := strings.Cut(tail, ":")
	if !ok || tag == "" {
		t.Fatalf("deploy/cloudrun/service.yaml container image %q must carry an explicit tag", img)
	}
	return tag
}

func terraformSchemaLabels(t *testing.T, mainTF string) map[string]string {
	t.Helper()
	block := firstCapture(`(?s)otel_schema_labels\s*=\s*\{(.*?)\}`, mainTF)
	if block == "" {
		t.Fatal("deploy/terraform/main.tf does not define locals.otel_schema_labels")
	}
	re := regexp.MustCompile(`(?m)^\s*(otel_schema_[a-z]+)\s*=\s*"([^"]+)"`)
	matches := re.FindAllStringSubmatch(block, -1)
	if len(matches) == 0 {
		t.Fatalf("locals.otel_schema_labels in deploy/terraform/main.tf has no entries: %s", block)
	}
	labels := make(map[string]string, len(matches))
	for _, m := range matches {
		labels[m[1]] = m[2]
	}
	return labels
}

func checkExporterSectionMatchesAppVersion(appVersion string, section map[string]any) error {
	allowed, ok := helmAppVersionExporterKeys[appVersion]
	if !ok {
		return fmt.Errorf("Chart.yaml appVersion %q has no entry in helmAppVersionExporterKeys; record the exporter keys supported by %q", appVersion, appVersion)
	}
	rendered := renderedExporterKeyPaths(section)
	if len(rendered) == 0 {
		return fmt.Errorf("rendered exporters.bigquery section is empty")
	}
	var unsupported []string
	for _, key := range rendered {
		if !allowed[key] {
			unsupported = append(unsupported, key)
		}
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("default Helm render contains exporter config key(s) %v not supported by pinned appVersion %q", unsupported, appVersion)
	}
	return nil
}

func TestHelmDefaultRenderMatchesChartAppVersion(t *testing.T) {
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, helmChartDir+"/Chart.yaml")), &chart); err != nil {
		t.Fatalf("parsing Chart.yaml: %v", err)
	}
	if chart.AppVersion == "" {
		t.Fatal("Chart.yaml appVersion must not be empty")
	}

	values := parseYAMLMap(t, helmChartDir+"/values.yaml", readRepoText(t, helmChartDir+"/values.yaml"))
	if tag, _ := yamlPath(values, "image", "tag").(string); tag != "" && tag != chart.AppVersion {
		t.Errorf("values.yaml image.tag = %q, want %q matching Chart.yaml appVersion", tag, chart.AppVersion)
	}

	// Cross-check the 0.1.0 allowlist against configInventoryGolden so a post-0.1.0
	// exporter option cannot be added to the 0.1.0 allowlist by mistake.
	for key := range helmAppVersionExporterKeys["0.1.0"] {
		if strings.HasPrefix(key, "sending_queue.") || strings.HasPrefix(key, "retry_on_failure.") {
			continue
		}
		meta, ok := configInventoryGolden[key]
		if !ok {
			t.Errorf("helmAppVersionExporterKeys[\"0.1.0\"] lists unknown exporter key %q", key)
			continue
		}
		if meta.Since != "v0.0.1" && meta.Since != "v0.1.0" {
			t.Errorf("helmAppVersionExporterKeys[\"0.1.0\"] lists %q (introduced in %s), which did not exist in v0.1.0", key, meta.Since)
		}
	}

	doc := helmCollectorConfig(t, nil)
	section := exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery")
	if err := checkExporterSectionMatchesAppVersion(chart.AppVersion, section); err != nil {
		t.Fatal(err)
	}
	deployDocs := map[string]string{
		"deploy/README.md":             readRepoText(t, "deploy/README.md"),
		helmChartDir + "/values.yaml":  readRepoText(t, helmChartDir+"/values.yaml"),
		"deploy/cloudrun/service.yaml": readRepoText(t, "deploy/cloudrun/service.yaml"),
	}
	if err := checkPinnedImageSchemaContract(chart.AppVersion, schema.Version, pinnedImageSchemaVersion, deployDocs); err != nil {
		t.Fatal(err)
	}
	if got := yamlPath(doc, "exporters", "bigquery", "logs", "synthesize_insert_id"); got != nil {
		t.Errorf("default Helm render sets exporters.bigquery.logs.synthesize_insert_id = %#v, want omitted", got)
	}
	cfg := decodeExporterConfig(t, "default values", section)
	if !cfg.Logs.SynthesizeInsertID {
		t.Errorf("default decoded Logs.SynthesizeInsertID = %v, want true", cfg.Logs.SynthesizeInsertID)
	}

	t.Run("negative control rejects post-appVersion key in default render", func(t *testing.T) {
		mutated := helmCollectorConfig(t, nil)
		mutatedSection := exporterBlock(t, confmap.NewFromStringMap(mutated), "bigquery")
		logsMap, ok := mutatedSection["logs"].(map[string]any)
		if !ok {
			t.Fatalf("exporters.bigquery.logs is %T, want map[string]any", mutatedSection["logs"])
		}
		logsMap["synthesize_insert_id"] = true
		err := checkExporterSectionMatchesAppVersion(chart.AppVersion, mutatedSection)
		if err == nil || !strings.Contains(err.Error(), "logs.synthesize_insert_id") {
			t.Fatalf("checkExporterSectionMatchesAppVersion with injected logs.synthesize_insert_id = %v, want error naming logs.synthesize_insert_id", err)
		}
	})

	t.Run("negative control rejects unknown nested and unrecorded appVersion", func(t *testing.T) {
		mutated := helmCollectorConfig(t, nil)
		mutatedSection := exporterBlock(t, confmap.NewFromStringMap(mutated), "bigquery")
		mutatedSection["schema"] = map[string]any{}
		if err := checkExporterSectionMatchesAppVersion(chart.AppVersion, mutatedSection); err == nil || !strings.Contains(err.Error(), "schema") {
			t.Fatalf("checkExporterSectionMatchesAppVersion with empty unknown block = %v, want error naming schema", err)
		}
		if err := checkExporterSectionMatchesAppVersion("0.0.0-unlisted", section); err == nil {
			t.Fatal("checkExporterSectionMatchesAppVersion with unlisted appVersion succeeded, want error")
		}
	})
}

func TestPinnedImageSchemaMatchesRepoOrDocumentedSkew(t *testing.T) {
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, helmChartDir+"/Chart.yaml")), &chart); err != nil {
		t.Fatalf("parsing Chart.yaml: %v", err)
	}
	values := parseYAMLMap(t, helmChartDir+"/values.yaml", readRepoText(t, helmChartDir+"/values.yaml"))
	valuesTag, _ := yamlPath(values, "image", "tag").(string)
	if valuesTag == "" {
		t.Fatal("values.yaml image.tag must not be empty")
	}
	serviceYAML := readRepoText(t, "deploy/cloudrun/service.yaml")
	cloudRunTag := cloudRunImageTag(t, serviceYAML)

	// Terraform provisioned schema labels must match schema.DefaultContract (schema.Version).
	tfLabels := terraformSchemaLabels(t, readRepoText(t, "deploy/terraform/main.tf"))
	wantLabels := schema.ContractLabels(schema.DefaultContract)
	if !maps.Equal(tfLabels, wantLabels) {
		t.Fatalf("deploy/terraform/main.tf otel_schema_labels = %v, want %v matching %s", tfLabels, wantLabels, schema.Version)
	}

	deployDocs := map[string]string{
		"deploy/README.md":             readRepoText(t, "deploy/README.md"),
		helmChartDir + "/values.yaml":  readRepoText(t, helmChartDir+"/values.yaml"),
		"deploy/cloudrun/service.yaml": serviceYAML,
	}

	for name, tag := range map[string]string{
		"Chart.yaml appVersion": chart.AppVersion,
		"values.yaml image.tag": valuesTag,
		"Cloud Run image tag":   cloudRunTag,
	} {
		t.Run("live/"+name, func(t *testing.T) {
			if err := checkPinnedImageSchemaContract(tag, schema.Version, pinnedImageSchemaVersion, deployDocs); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("negative control rejects unlisted pinned image version", func(t *testing.T) {
		err := checkPinnedImageSchemaContract("0.0.0-unlisted", schema.Version, pinnedImageSchemaVersion, deployDocs)
		if err == nil || !strings.Contains(err.Error(), "pinnedImageSchemaVersion") {
			t.Fatalf("err = %v, want error naming pinnedImageSchemaVersion", err)
		}
	})

	t.Run("negative control rejects undocumented schema skew in any deploy doc", func(t *testing.T) {
		for path := range deployDocs {
			t.Run(path, func(t *testing.T) {
				incomplete := maps.Clone(deployDocs)
				incomplete[path] = "# no schema skew notice here"
				err := checkPinnedImageSchemaContract("0.1.0", schema.Version, pinnedImageSchemaVersion, incomplete)
				if err == nil || !strings.Contains(err.Error(), path) {
					t.Fatalf("err = %v, want error naming %s", err, path)
				}
			})
		}
	})

	t.Run("positive control accepts matching pinned schema without skew notice", func(t *testing.T) {
		matchingMap := maps.Clone(pinnedImageSchemaVersion)
		matchingMap["0.2.0-matching"] = schema.Version
		emptyDocs := map[string]string{
			"deploy/README.md":             "",
			helmChartDir + "/values.yaml":  "",
			"deploy/cloudrun/service.yaml": "",
		}
		if err := checkPinnedImageSchemaContract("0.2.0-matching", schema.Version, matchingMap, emptyDocs); err != nil {
			t.Fatalf("unexpected error for matching schema version: %v", err)
		}
	})
}

func TestHelmConfigMapSynthesizeInsertID(t *testing.T) {
	for _, tc := range []struct {
		name     string
		omitKey  bool
		value    any
		rendered any
		want     bool
	}{
		{name: "default values true", omitKey: false, value: true, rendered: nil, want: true},
		{name: "explicit string true", omitKey: false, value: "true", rendered: nil, want: true},
		{name: "explicit uppercase TRUE", omitKey: false, value: "TRUE", rendered: nil, want: true},
		{name: "null value", omitKey: false, value: nil, rendered: nil, want: true},
		{name: "empty string", omitKey: false, value: "", rendered: nil, want: true},
		{name: "omitted key", omitKey: true, value: nil, rendered: nil, want: true},
		{name: "explicit bool false", omitKey: false, value: false, rendered: false, want: false},
		{name: "explicit string false", omitKey: false, value: "false", rendered: false, want: false},
		{name: "explicit uppercase FALSE", omitKey: false, value: "FALSE", rendered: false, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var doc map[string]any
			if tc.omitKey {
				values := helmValues(t, nil)
				delete(values["bigquery"].(map[string]any)["logs"].(map[string]any), "synthesizeInsertID")
				doc = helmCollectorConfigWithValues(t, values)
			} else {
				doc = helmCollectorConfig(t, map[string]any{
					"bigquery": map[string]any{
						"logs": map[string]any{"synthesizeInsertID": tc.value},
					},
				})
			}
			if got := yamlPath(doc, "exporters", "bigquery", "logs", "synthesize_insert_id"); got != tc.rendered {
				t.Errorf("rendered logs.synthesize_insert_id = %#v, want %#v", got, tc.rendered)
			}
			cfg := decodeExporterConfig(t, tc.name, exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))
			if cfg.Logs.SynthesizeInsertID != tc.want {
				t.Errorf("decoded Logs.SynthesizeInsertID = %v, want %v", cfg.Logs.SynthesizeInsertID, tc.want)
			}
		})
	}
}

func validateSafeHPAScalingManifest(manifest string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(manifest), &doc); err != nil {
		return fmt.Errorf("HPA manifest is not valid YAML: %w", err)
	}
	if len(doc) == 0 {
		return errors.New("HPA manifest is empty")
	}
	if got := doc["apiVersion"]; got != "autoscaling/v2" {
		return fmt.Errorf("HPA apiVersion = %v, want autoscaling/v2", got)
	}
	if got := doc["kind"]; got != "HorizontalPodAutoscaler" {
		return fmt.Errorf("HPA kind = %v, want HorizontalPodAutoscaler", got)
	}
	spec, _ := doc["spec"].(map[string]any)
	if spec == nil {
		return errors.New("HPA manifest missing spec")
	}
	maxRep, ok := spec["maxReplicas"]
	if !ok {
		return errors.New("HPA spec missing hard maxReplicas cap")
	}
	if n, ok := maxRep.(int); !ok || n <= 0 {
		return fmt.Errorf("HPA maxReplicas = %#v, want positive int cap", maxRep)
	}
	metrics, _ := spec["metrics"].([]any)
	if len(metrics) == 0 {
		return errors.New("HPA spec.metrics must define at least one safe scaling metric")
	}
	for _, item := range metrics {
		m, _ := item.(map[string]any)
		for _, sectionKey := range []string{"pods", "object", "external"} {
			if sec, ok := m[sectionKey].(map[string]any); ok {
				if metricMeta, ok := sec["metric"].(map[string]any); ok {
					name := fmt.Sprint(metricMeta["name"])
					if strings.Contains(strings.ToLower(name), "backpressure") {
						return fmt.Errorf("forbidden HPA scaling metric %q: scaling on BigQuery adaptive backpressure metrics adds writers against a congested/quota-exhausted destination", name)
					}
				}
			}
		}
	}
	return nil
}

func validateSafeAutoscalingValues(values map[string]any) error {
	raw, err := yaml.Marshal(values["autoscaling"])
	if err != nil {
		return fmt.Errorf("marshaling autoscaling values: %w", err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "backpressure") {
		return errors.New("autoscaling values must never reference backpressure metrics for scaling")
	}
	return nil
}

func TestHelmAutoscalingAndPersistenceTemplates(t *testing.T) {
	// Default values keep autoscaling and persistence disabled.
	defaultValues := helmValues(t, nil)
	if got := strings.TrimSpace(renderHelmTemplateWithValues(t, "hpa.yaml", defaultValues)); got != "" {
		t.Errorf("default hpa.yaml should render empty when autoscaling.enabled is false, got:\n%s", got)
	}
	if got := strings.TrimSpace(renderHelmTemplateWithValues(t, "pvc.yaml", defaultValues)); got != "" {
		t.Errorf("default pvc.yaml should render empty when persistence.enabled is false, got:\n%s", got)
	}
	defaultDeploy := parseYAMLMap(t, "default deployment.yaml", renderHelmTemplateWithValues(t, "deployment.yaml", defaultValues))
	if got := defaultDeploy["kind"]; got != "Deployment" {
		t.Errorf("default deployment.yaml kind = %v, want Deployment", got)
	}

	// autoscaling.enabled: true renders a valid autoscaling/v2 HPA targeting Deployment (or StatefulSet).
	hpaValues := helmValues(t, map[string]any{
		"autoscaling": map[string]any{
			"enabled": true,
		},
	})
	hpaManifest := renderHelmTemplateWithValues(t, "hpa.yaml", hpaValues)
	if strings.Contains(hpaManifest, "<no value>") {
		t.Fatalf("hpa.yaml has undefined value:\n%s", hpaManifest)
	}
	if err := validateSafeHPAScalingManifest(hpaManifest); err != nil {
		t.Fatalf("autoscaling.enabled=true failed HPA validation: %v\n%s", err, hpaManifest)
	}
	hpaDoc := parseYAMLMap(t, "rendered hpa.yaml", hpaManifest)
	if got := yamlPath(hpaDoc, "spec", "scaleTargetRef", "kind"); got != "Deployment" {
		t.Errorf("hpa scaleTargetRef.kind = %v, want Deployment", got)
	}

	// persistence.enabled: true renders a standalone PVC and mounts it in Deployment.
	pvcValues := helmValues(t, map[string]any{
		"persistence": map[string]any{
			"enabled": true,
		},
	})
	pvcManifest := renderHelmTemplateWithValues(t, "pvc.yaml", pvcValues)
	if strings.Contains(pvcManifest, "<no value>") {
		t.Fatalf("pvc.yaml has undefined value:\n%s", pvcManifest)
	}
	pvcDoc := parseYAMLMap(t, "rendered pvc.yaml", pvcManifest)
	if pvcDoc["apiVersion"] != "v1" || pvcDoc["kind"] != "PersistentVolumeClaim" {
		t.Errorf("pvc.yaml apiVersion/kind = %v/%v, want v1/PersistentVolumeClaim", pvcDoc["apiVersion"], pvcDoc["kind"])
	}
	if got := yamlPath(pvcDoc, "spec", "resources", "requests", "storage"); got != "20Gi" {
		t.Errorf("pvc.yaml storage request = %v, want 20Gi", got)
	}
	pvcCM := helmCollectorConfigWithValues(t, pvcValues)
	if got := yamlPath(pvcCM, "exporters", "bigquery", "sending_queue", "storage"); got != "file_storage" {
		t.Errorf("persistence.enabled=true sending_queue.storage = %v, want file_storage", got)
	}
}

func TestHelmHighVolumeLogsValuesPreset(t *testing.T) {
	preset := parseYAMLMap(t, helmChartDir+"/values-high-volume-logs.yaml", readRepoText(t, helmChartDir+"/values-high-volume-logs.yaml"))
	merged := helmValues(t, preset)

	for _, tmpl := range []string{"configmap.yaml", "deployment.yaml", "hpa.yaml", "pvc.yaml"} {
		rendered := renderHelmTemplateWithValues(t, tmpl, merged)
		if strings.Contains(rendered, "<no value>") {
			t.Errorf("%s with values-high-volume-logs.yaml contains <no value>:\n%s", tmpl, rendered)
		}
	}

	doc := helmCollectorConfigWithValues(t, merged)
	cfg := decodeExporterConfig(t, "values-high-volume-logs.yaml", exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))
	if cfg.Write.StreamPoolSize != 8 {
		t.Errorf("write.stream_pool_size = %d, want 8", cfg.Write.StreamPoolSize)
	}
	if !cfg.Write.Backpressure.Enabled {
		t.Errorf("write.backpressure.enabled = false, want true")
	}
	if !cfg.QueueSettings.HasValue() || !cfg.QueueSettings.Get().Batch.HasValue() {
		t.Fatalf("sending_queue.batch must be explicitly enabled in values-high-volume-logs.yaml")
	}
	if cfg.BackOffConfig.MaxElapsedTime != 900*time.Second {
		t.Errorf("retry_on_failure.max_elapsed_time = %v, want 900s", cfg.BackOffConfig.MaxElapsedTime)
	}
	if !cfg.Logs.RequirePartitionFilter {
		t.Errorf("logs.require_partition_filter = false, want true")
	}

	// StatefulSet per-pod PVCs should be active (not single Deployment PVC).
	deployDoc := parseYAMLMap(t, "high-volume deployment.yaml", renderHelmTemplateWithValues(t, "deployment.yaml", merged))
	if deployDoc["kind"] != "StatefulSet" {
		t.Errorf("high-volume deployment.yaml kind = %v, want StatefulSet", deployDoc["kind"])
	}
	if pvc := strings.TrimSpace(renderHelmTemplateWithValues(t, "pvc.yaml", merged)); pvc != "" {
		t.Errorf("high-volume preset uses StatefulSet volumeClaimTemplates, expected empty pvc.yaml, got:\n%s", pvc)
	}

	hpaManifest := renderHelmTemplateWithValues(t, "hpa.yaml", merged)
	if err := validateSafeHPAScalingManifest(hpaManifest); err != nil {
		t.Fatalf("high-volume HPA invalid: %v\n%s", err, hpaManifest)
	}
	hpaDoc := parseYAMLMap(t, "high-volume hpa.yaml", hpaManifest)
	if got := yamlPath(hpaDoc, "spec", "scaleTargetRef", "kind"); got != "StatefulSet" {
		t.Errorf("high-volume hpa scaleTargetRef.kind = %v, want StatefulSet", got)
	}
}

// Guard test (ADR-19): hpa.yaml and values-high-volume-logs.yaml
// must NEVER reference otelcol_exporter_bigquery_backpressure_level as a
// scaling metric.
func TestHelmHPANeverScalesOnBackpressureLevel(t *testing.T) {
	hpaSrc := readRepoText(t, helmChartDir+"/templates/hpa.yaml")
	hvRaw := readRepoText(t, helmChartDir+"/values-high-volume-logs.yaml")
	for name, text := range map[string]string{
		"templates/hpa.yaml":           hpaSrc,
		"values-high-volume-logs.yaml": hvRaw,
	} {
		if strings.Contains(text, "otelcol_exporter_bigquery_backpressure_level") {
			t.Errorf("%s must not reference otelcol_exporter_bigquery_backpressure_level", name)
		}
	}

	hvValues := parseYAMLMap(t, helmChartDir+"/values-high-volume-logs.yaml", hvRaw)
	if err := validateSafeAutoscalingValues(hvValues); err != nil {
		t.Fatalf("values-high-volume-logs.yaml failed autoscaling safety check: %v", err)
	}

	// Negative control: injecting otelcol_exporter_bigquery_backpressure_level
	// into an HPA manifest or autoscaling values must fail validation.
	brokenHPA := `apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: bq-otel
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: bq-otel
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Pods
      pods:
        metric:
          name: otelcol_exporter_bigquery_backpressure_level
        target:
          type: AverageValue
          averageValue: "0.5"
`
	if err := validateSafeHPAScalingManifest(brokenHPA); err == nil {
		t.Fatal("negative control failed: validateSafeHPAScalingManifest accepted otelcol_exporter_bigquery_backpressure_level")
	}
	brokenValues := map[string]any{
		"autoscaling": map[string]any{
			"enabled": true,
			"queueDepthMetric": map[string]any{
				"enabled": true,
				"name":    "otelcol_exporter_bigquery_backpressure_level",
			},
		},
	}
	if err := validateSafeAutoscalingValues(brokenValues); err == nil {
		t.Fatal("negative control failed: validateSafeAutoscalingValues accepted otelcol_exporter_bigquery_backpressure_level")
	}
}

func exportIdenticalLogsAndCountDistinctInsertIDs(t *testing.T, cfg *Config, count int) (totalRows int, distinctIDs int) {
	t.Helper()
	srv := bqfake.NewServer(t)
	wireFakeHooks(t, srv)

	cfgCopy := *cfg
	cfgCopy.AutoCreate.Dataset = true
	cfgCopy.AutoCreate.Tables = true
	if cfgCopy.QueueSettings.HasValue() {
		q := *cfgCopy.QueueSettings.Get()
		// Exercise exporterhelper's real QueueBatch + partitionBatcher without
		// requiring an external file_storage host extension in-process.
		q.StorageID = nil
		cfgCopy.QueueSettings.GetOrInsertDefault()
		*cfgCopy.QueueSettings.Get() = q
	}

	ctx := context.Background()
	exp, err := CreateLogsExporter(ctx, exportertest.NewNopSettings(metadata.Type), &cfgCopy)
	if err != nil {
		t.Fatalf("CreateLogsExporter: %v", err)
	}
	if err := exp.Start(ctx, componenttest.NewNopHost()); err != nil {
		t.Fatalf("LogsExporter.Start: %v", err)
	}

	ld := plog.NewLogs()
	rl := ld.ResourceLogs().AppendEmpty()
	rl.Resource().Attributes().PutStr("service.name", "edge-proxy")
	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("envoy.access")
	ts := pcommon.NewTimestampFromTime(time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC))
	for range count {
		lr := sl.LogRecords().AppendEmpty()
		lr.SetTimestamp(ts)
		lr.SetSeverityNumber(plog.SeverityNumberInfo)
		lr.SetSeverityText("INFO")
		lr.Body().SetStr("GET /healthz 200")
		lr.Attributes().PutInt("http.response.status_code", 200)
	}

	if err := exp.ConsumeLogs(ctx, ld); err != nil {
		t.Fatalf("ConsumeLogs(%d): %v", count, err)
	}
	if err := exp.Shutdown(ctx); err != nil {
		t.Fatalf("LogsExporter.Shutdown: %v", err)
	}

	rows := srv.Rows("otel_logs")
	distinct := make(map[string]struct{}, len(rows))
	for i, row := range rows {
		id, _ := row["insert_id"].(string)
		if !strings.HasPrefix(id, schema.InsertIDPrefixV1) {
			t.Fatalf("row %d insert_id = %q, want %q prefix", i, id, schema.InsertIDPrefixV1)
		}
		distinct[id] = struct{}{}
	}
	return len(rows), len(distinct)
}

func TestHelmHighVolumeLogsSynthesizes6000DistinctInsertIDs(t *testing.T) {
	preset := parseYAMLMap(t, helmChartDir+"/values-high-volume-logs.yaml", readRepoText(t, helmChartDir+"/values-high-volume-logs.yaml"))
	merged := helmValues(t, preset)
	doc := helmCollectorConfigWithValues(t, merged)
	cfg := decodeExporterConfig(t, "values-high-volume-logs.yaml", exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))

	if !cfg.Logs.SynthesizeInsertID {
		t.Fatalf("values-high-volume-logs.yaml logs.synthesize_insert_id = false, want true")
	}
	if !cfg.QueueSettings.HasValue() || !cfg.QueueSettings.Get().Batch.HasValue() {
		t.Fatalf("values-high-volume-logs.yaml must enable sending_queue.batch")
	}
	if got := cfg.QueueSettings.Get().Batch.Get().MaxSize; got != 0 {
		t.Fatalf("values-high-volume-logs.yaml sending_queue.batch.max_size = %d, want 0 (unbounded pre-transform batching so intra-batch ordinals are not split)", got)
	}

	totalRows, distinctIDs := exportIdenticalLogsAndCountDistinctInsertIDs(t, cfg, 6000)
	if totalRows != 6000 || distinctIDs != 6000 {
		t.Fatalf("values-high-volume-logs.yaml exported %d rows with %d distinct insert_ids for 6000 identical logs, want 6000 rows and 6000 distinct insert_ids", totalRows, distinctIDs)
	}

	// Negative control 1: confirm that pre-transform max_size=4000 really
	// collapses 6,000 identical logs to 4,000 distinct insert_ids.
	brokenCfg := decodeExporterConfig(t, "values-high-volume-logs.yaml", exporterBlock(t, confmap.NewFromStringMap(doc), "bigquery"))
	brokenCfg.QueueSettings.Get().Batch.Get().MaxSize = 4000
	brokenTotal, brokenDistinct := exportIdenticalLogsAndCountDistinctInsertIDs(t, brokenCfg, 6000)
	if brokenTotal != 6000 || brokenDistinct != 4000 {
		t.Fatalf("negative control mismatch: max_size=4000 produced (%d rows, %d distinct IDs), want (6000, 4000)", brokenTotal, brokenDistinct)
	}

	// Negative control 2: Helm ConfigMap template must reject
	// sendingQueue.batch.maxSize > 0 while bigquery.logs.synthesizeInsertID is enabled,
	// and allow it when bigquery.logs.synthesizeInsertID is explicitly false.
	badSplitValues := helmValues(t, map[string]any{
		"sendingQueue": map[string]any{
			"sizer": "items",
			"batch": map[string]any{
				"enabled": true,
				"sizer":   "items",
				"minSize": int64(1000),
				"maxSize": int64(4000),
			},
		},
	})
	if _, err := renderHelmTemplateWithValuesErr(t, "configmap.yaml", badSplitValues); err == nil {
		t.Fatal("negative control failed: configmap.yaml accepted sendingQueue.batch.maxSize > 0 with synthesized log insert IDs enabled")
	}

	explicitUpstreamIDValues := helmValues(t, map[string]any{
		"bigquery": map[string]any{
			"logs": map[string]any{
				"synthesizeInsertID": false,
			},
		},
		"sendingQueue": map[string]any{
			"sizer": "items",
			"batch": map[string]any{
				"enabled": true,
				"sizer":   "items",
				"minSize": int64(1000),
				"maxSize": int64(4000),
			},
		},
	})
	if _, err := renderHelmTemplateWithValuesErr(t, "configmap.yaml", explicitUpstreamIDValues); err != nil {
		t.Fatalf("configmap.yaml rejected sendingQueue.batch.maxSize > 0 when bigquery.logs.synthesizeInsertID=false: %v", err)
	}
}

func TestHelmPersistentQueueDisablesHPAScaleDown(t *testing.T) {
	// 1. High-volume logs preset must render selectPolicy: Disabled under behavior.scaleDown.
	preset := parseYAMLMap(t, helmChartDir+"/values-high-volume-logs.yaml", readRepoText(t, helmChartDir+"/values-high-volume-logs.yaml"))
	hvHPA := parseYAMLMap(t, "high-volume hpa.yaml", renderHelmTemplateWithValues(t, "hpa.yaml", helmValues(t, preset)))
	if got := yamlPath(hvHPA, "spec", "behavior", "scaleDown", "selectPolicy"); got != "Disabled" {
		t.Errorf("values-high-volume-logs.yaml HPA spec.behavior.scaleDown.selectPolicy = %v, want Disabled", got)
	}

	// 2. Enabling persistentQueue + autoscaling on default values automatically defaults scaleDown.selectPolicy to Disabled.
	autoDisabledValues := helmValues(t, map[string]any{
		"persistentQueue": map[string]any{"enabled": true},
		"autoscaling":     map[string]any{"enabled": true},
	})
	autoHPA := parseYAMLMap(t, "persistentQueue hpa.yaml", renderHelmTemplateWithValues(t, "hpa.yaml", autoDisabledValues))
	if got := yamlPath(autoHPA, "spec", "behavior", "scaleDown", "selectPolicy"); got != "Disabled" {
		t.Errorf("persistentQueue+autoscaling HPA spec.behavior.scaleDown.selectPolicy = %v, want Disabled", got)
	}

	// 3. Stateless Deployment HPA keeps normal scaleDown behavior (selectPolicy unset).
	statelessValues := helmValues(t, map[string]any{
		"autoscaling": map[string]any{"enabled": true},
	})
	statelessHPA := parseYAMLMap(t, "stateless hpa.yaml", renderHelmTemplateWithValues(t, "hpa.yaml", statelessValues))
	if got := yamlPath(statelessHPA, "spec", "behavior", "scaleDown", "selectPolicy"); got != nil {
		t.Errorf("stateless HPA spec.behavior.scaleDown.selectPolicy = %v, want nil", got)
	}
	if got := yamlPath(statelessHPA, "spec", "behavior", "scaleDown", "stabilizationWindowSeconds"); got != 300 {
		t.Errorf("stateless HPA spec.behavior.scaleDown.stabilizationWindowSeconds = %v, want 300", got)
	}

	// 4. Negative control: explicitly overriding selectPolicy away from Disabled with persistentQueue.enabled=true must fail render.
	overrideScaleDown := helmValues(t, map[string]any{
		"persistentQueue": map[string]any{"enabled": true},
		"autoscaling": map[string]any{
			"enabled": true,
			"behavior": map[string]any{
				"scaleDown": map[string]any{
					"selectPolicy": "Max",
				},
			},
		},
	})
	if _, err := renderHelmTemplateWithValuesErr(t, "hpa.yaml", overrideScaleDown); err == nil {
		t.Fatal("negative control failed: hpa.yaml allowed non-Disabled scaleDown.selectPolicy with persistentQueue.enabled=true")
	}
}

func TestHelmStandaloneDeploymentPersistenceGuardsAndRecreateStrategy(t *testing.T) {
	// (i) Deployment + persistence.enabled=true + replicaCount=1 renders strategy.type: Recreate.
	singleReplicaPVC := helmValues(t, map[string]any{
		"persistence":  map[string]any{"enabled": true},
		"replicaCount": int64(1),
	})
	deployDoc := parseYAMLMap(t, "persistence deployment.yaml", renderHelmTemplateWithValues(t, "deployment.yaml", singleReplicaPVC))
	if got := deployDoc["kind"]; got != "Deployment" {
		t.Fatalf("persistence deployment.yaml kind = %v, want Deployment", got)
	}
	if got := yamlPath(deployDoc, "spec", "strategy", "type"); got != "Recreate" {
		t.Errorf("persistence deployment.yaml spec.strategy.type = %v, want Recreate (avoids RWO + bbolt lock deadlock during rollout)", got)
	}

	// Default stateless Deployment omits explicit Recreate strategy (uses default RollingUpdate),
	// and StatefulSet (persistentQueue.enabled=true) never emits Deployment-only spec.strategy.
	defaultDeploy := parseYAMLMap(t, "default deployment.yaml", renderHelmTemplateWithValues(t, "deployment.yaml", helmValues(t, nil)))
	if got := yamlPath(defaultDeploy, "spec", "strategy"); got != nil {
		t.Errorf("default stateless deployment.yaml spec.strategy = %v, want nil", got)
	}
	stsDeploy := parseYAMLMap(t, "statefulset deployment.yaml", renderHelmTemplateWithValues(t, "deployment.yaml", helmValues(t, map[string]any{
		"persistentQueue": map[string]any{"enabled": true},
	})))
	if got := yamlPath(stsDeploy, "spec", "strategy"); got != nil {
		t.Errorf("StatefulSet deployment.yaml spec.strategy = %v, want nil", got)
	}

	// (ii) Negative control: Deployment + persistence.enabled=true + autoscaling.enabled=true must fail render.
	withAutoscaling := helmValues(t, map[string]any{
		"persistence": map[string]any{"enabled": true},
		"autoscaling": map[string]any{"enabled": true},
	})
	for _, tmpl := range []string{"deployment.yaml", "hpa.yaml", "pvc.yaml"} {
		if _, err := renderHelmTemplateWithValuesErr(t, tmpl, withAutoscaling); err == nil {
			t.Errorf("negative control failed: %s rendered without error for persistence.enabled=true + autoscaling.enabled=true", tmpl)
		}
	}

	// (iii) Negative control: Deployment + persistence.enabled=true + replicaCount=2 must fail render
	// for both --set int64(2) and values-file float64(2).
	for _, repVal := range []any{int64(2), float64(2)} {
		withTwoReplicas := helmValues(t, map[string]any{
			"persistence":  map[string]any{"enabled": true},
			"replicaCount": repVal,
		})
		for _, tmpl := range []string{"deployment.yaml", "pvc.yaml"} {
			if _, err := renderHelmTemplateWithValuesErr(t, tmpl, withTwoReplicas); err == nil {
				t.Errorf("negative control failed: %s rendered without error for persistence.enabled=true + replicaCount=%T(%v)", tmpl, repVal, repVal)
			}
		}
	}

	// (iv) Negative control: setting both persistence.enabled=true and persistentQueue.enabled=true must fail render.
	bothPersistenceModes := helmValues(t, map[string]any{
		"persistence":     map[string]any{"enabled": true},
		"persistentQueue": map[string]any{"enabled": true},
	})
	for _, tmpl := range []string{"deployment.yaml", "pvc.yaml"} {
		if _, err := renderHelmTemplateWithValuesErr(t, tmpl, bothPersistenceModes); err == nil {
			t.Errorf("negative control failed: %s rendered without error when both persistence.enabled and persistentQueue.enabled are true", tmpl)
		}
	}
}

func TestHelmHPAMetricNamesAndTemplateFailGuards(t *testing.T) {
	// 1. exporterhelper v0.165.0 does not emit otelcol_exporter_queue_oldest_item_age_seconds;
	// verify chart values, templates, and docs never advertise it or queueAgeMetric.
	for _, path := range []string{
		helmChartDir + "/values.yaml",
		helmChartDir + "/values-high-volume-logs.yaml",
		helmChartDir + "/templates/hpa.yaml",
		"README.md",
		"deploy/README.md",
		"docs/cost-estimation.md",
		"docs/operator-guides/load-testbench-and-sizing.md",
	} {
		text := readRepoText(t, path)
		if strings.Contains(text, "otelcol_exporter_queue_oldest_item_age_seconds") {
			t.Errorf("%s still references nonexistent v0.165.0 metric otelcol_exporter_queue_oldest_item_age_seconds", path)
		}
	}
	for _, path := range []string{
		helmChartDir + "/values.yaml",
		helmChartDir + "/values-high-volume-logs.yaml",
	} {
		if strings.Contains(readRepoText(t, path), "queueAgeMetric") {
			t.Errorf("%s still defines unsupported queueAgeMetric", path)
		}
	}

	// 2. Verify admittedRateMetric and queueDepthMetric render valid Pods metrics,
	// and deploy/README.md documents the rate() metrics-adapter rule for the
	// cumulative counter otelcol_receiver_accepted_log_records.
	validPodMetrics := helmValues(t, map[string]any{
		"autoscaling": map[string]any{
			"enabled": true,
			"admittedRateMetric": map[string]any{
				"enabled":            true,
				"name":               "otelcol_receiver_accepted_log_records",
				"targetAverageValue": "10000",
			},
			"queueDepthMetric": map[string]any{
				"enabled":            true,
				"name":               "otelcol_exporter_queue_size",
				"targetAverageValue": "500",
			},
		},
	})
	hpaManifest := renderHelmTemplateWithValues(t, "hpa.yaml", validPodMetrics)
	if err := validateSafeHPAScalingManifest(hpaManifest); err != nil {
		t.Fatalf("valid admittedRateMetric + queueDepthMetric HPA failed validation: %v\n%s", err, hpaManifest)
	}
	deployReadme := readRepoText(t, "deploy/README.md")
	if !strings.Contains(deployReadme, "rate(") || !strings.Contains(deployReadme, "otelcol_receiver_accepted_log_records") {
		t.Errorf("deploy/README.md must document the Prometheus/GCM adapter rate() rule for cumulative counter otelcol_receiver_accepted_log_records")
	}

	// 3. Negative control: setting ANY HPA metric slot to any backpressure metric
	// (including backpressure_level and backpressure_events, whether enabled=true or
	// enabled=false, regardless of case) MUST fail template rendering itself.
	for _, slot := range []string{"admittedRateMetric", "queueDepthMetric", "queueAgeMetric"} {
		for _, enabled := range []bool{true, false} {
			for _, badName := range []string{
				"otelcol_exporter_bigquery_backpressure_level",
				"otelcol_exporter_bigquery_backpressure_events",
				"OTELCOL_EXPORTER_BIGQUERY_BACKPRESSURE_LEVEL",
			} {
				badValues := helmValues(t, map[string]any{
					"autoscaling": map[string]any{
						"enabled": true,
						slot: map[string]any{
							"enabled":            enabled,
							"name":               badName,
							"targetAverageValue": "1",
						},
					},
				})
				if _, err := renderHelmTemplateWithValuesErr(t, "hpa.yaml", badValues); err == nil {
					t.Errorf("negative control failed: hpa.yaml rendered without error when %s (enabled=%v) used forbidden metric %q", slot, enabled, badName)
				}
			}
		}
	}

	// 4. Negative control: enabling legacy queueAgeMetric with any metric name must fail render on v0.165.0.
	legacyAgeValues := helmValues(t, map[string]any{
		"autoscaling": map[string]any{
			"enabled": true,
			"queueAgeMetric": map[string]any{
				"enabled":            true,
				"name":               "custom_queue_age_seconds",
				"targetAverageValue": "30",
			},
		},
	})
	if _, err := renderHelmTemplateWithValuesErr(t, "hpa.yaml", legacyAgeValues); err == nil {
		t.Fatal("negative control failed: hpa.yaml accepted unsupported queueAgeMetric.enabled=true")
	}

	// 5. Negative control: disabling CPU with all pod metrics disabled must fail render rather than emitting empty spec.metrics.
	noMetricsValues := helmValues(t, map[string]any{
		"autoscaling": map[string]any{
			"enabled":                        true,
			"targetCPUUtilizationPercentage": int64(0),
		},
	})
	if _, err := renderHelmTemplateWithValuesErr(t, "hpa.yaml", noMetricsValues); err == nil {
		t.Fatal("negative control failed: hpa.yaml accepted autoscaling.enabled=true with zero active metrics")
	}
}

func TestGCSBatchLoaderSpecForbidsLiveStagingTTLAndRequiresManifestOrphanReaper(t *testing.T) {
	const specPath = "docs/architecture/gcs-batch-row-loader.md"
	spec := readRepoText(t, specPath)
	if !strings.Contains(spec, "../adr/0001-schema-v1-and-high-volume-logs.md") {
		t.Errorf("%s must link to ../adr/0001-schema-v1-and-high-volume-logs.md", specPath)
	}

	// Every relative Markdown link in the spec must resolve on disk.
	linkRE := regexp.MustCompile(`\]\(([^)#\s]+)(?:#[^)]+)?\)`)
	for _, m := range linkRE.FindAllStringSubmatch(spec, -1) {
		target := m[1]
		if strings.Contains(target, "://") {
			continue
		}
		resolved := filepath.Clean(filepath.Join(filepath.Dir(specPath), target))
		if _, err := os.Stat(resolved); err != nil {
			t.Errorf("%s links to nonexistent path %q (resolved: %s)", specPath, target, resolved)
		}
	}

	// Must not instruct applying a bucket lifecycle Delete rule across the whole staging prefix,
	// and must specify manifest-aware orphan reaping for unreferenced objects only.
	if strings.Contains(spec, "Configure a GCS Object Lifecycle policy on the staging bucket/prefix (`Delete`") ||
		strings.Contains(spec, "reaped by bucket TTL") {
		t.Errorf("%s still instructs applying an unconditional bucket lifecycle Delete TTL to the live staging prefix", specPath)
	}
	lowerSpec := strings.ToLower(spec)
	for _, requiredPhrase := range []string{
		"never apply",
		"manifests/pending",
		"otel_quarantine",
		"orphan",
		"unreferenced",
		"serialized",
	} {
		if !strings.Contains(lowerSpec, requiredPhrase) {
			t.Errorf("%s missing manifest-aware orphan GC requirement %q", specPath, requiredPhrase)
		}
	}
}

// readmeByteCount renders a byte count the way the README's configuration
// table does: the exact count, then the size in the largest binary unit that
// divides it.
func readmeByteCount(n int) string {
	for _, unit := range []struct {
		name string
		size int
	}{{"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= unit.size && n%unit.size == 0 {
			return fmt.Sprintf("`%d` (%d %s)", n, n/unit.size, unit.name)
		}
	}
	return fmt.Sprintf("`%d`", n)
}

// The README's configuration table gives the default of every offload
// option. Each Default cell is rebuilt here from createDefaultConfig, so a
// default cannot change without the table following it, and an offload
// option cannot be added without its row being checked.
func TestReadmeOffloadDefaultsMatchFactory(t *testing.T) {
	offload := createDefaultConfig().(*Config).Offload
	literal := func(value string) string {
		if value == "" {
			return "—"
		}
		return "`" + value + "`"
	}
	cells := map[string]string{
		"offload.enabled":          literal(strconv.FormatBool(offload.Enabled)),
		"offload.bucket":           literal(offload.Bucket),
		"offload.prefix":           literal(offload.Prefix),
		"offload.authorizer":       literal(offload.Authorizer),
		"offload.min_bytes":        readmeByteCount(offload.MinBytes),
		"offload.max_object_bytes": readmeByteCount(offload.MaxObjectBytes),
		"offload.max_concurrency":  literal(strconv.Itoa(offload.MaxConcurrency)),
		"offload.timeout":          literal(offload.Timeout.String()),
		"offload.cache_size":       literal(strconv.Itoa(offload.CacheSize)),
	}
	readme := readRepoText(t, "README.md")
	for _, key := range exporterConfigKeys() {
		if !strings.HasPrefix(key, "offload.") {
			continue
		}
		want, ok := cells[key]
		if !ok {
			t.Errorf("the README default of %s is not checked; add it here", key)
			continue
		}
		if got := firstCapture("(?m)^\\| `"+regexp.QuoteMeta(key)+"` +\\| (.*?) +\\|", readme); got != want {
			t.Errorf("the README gives the %s default as %q, but the exporter's default is %q", key, got, want)
		}
	}
}

// The Terraform module provisions the tables the collector would otherwise
// create, so each retention variable defaults to what the exporter applies
// when it creates that table, and a number of days becomes the partition
// expiration the exporter sets for that many days. One partition filter
// variable covers all four tables, so it defaults to what the exporter
// applies to each of them.
func TestTerraformRetentionMatchesExporter(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	vars := readRepoText(t, "deploy/terraform/variables.tf")
	defaultOf := func(variable string) string {
		t.Helper()
		block := terraformBlock(vars, `variable "`+variable+`"`)
		if block == "" {
			t.Fatalf("variables.tf declares no %s", variable)
		}
		return firstCapture(`(?m)^  default\s+=\s+(.+)$`, block)
	}
	for table, days := range map[string]int{
		"otel_spans":      cfg.Traces.PartitionExpirationDays,
		"otel_logs":       cfg.Logs.PartitionExpirationDays,
		"otel_metrics":    cfg.Metrics.PartitionExpirationDays,
		"otel_quarantine": cfg.Quarantine.PartitionExpirationDays,
	} {
		variable := terraformExpirationVariables[table]
		if got := defaultOf(variable); got != strconv.Itoa(days) {
			t.Errorf("variables.tf %s defaults to %s, but the exporter creates %s with %d", variable, got, table, days)
		}
	}
	for table, required := range map[string]bool{
		"otel_spans":      cfg.Traces.RequirePartitionFilter,
		"otel_logs":       cfg.Logs.RequirePartitionFilter,
		"otel_metrics":    cfg.Metrics.RequirePartitionFilter,
		"otel_quarantine": cfg.Quarantine.RequirePartitionFilter,
	} {
		if got := defaultOf("require_partition_filter"); got != strconv.FormatBool(required) {
			t.Errorf("variables.tf require_partition_filter defaults to %s, but the exporter creates %s with %t", got, table, required)
		}
	}

	// exporterExpiration is the partition expiration the exporter gives a
	// table it creates with partition_expiration_days set to days.
	exporterExpiration := func(table string, days int) time.Duration {
		t.Helper()
		opts := schema.DestinationOptions{PartitionExpirationDays: days}
		if table == "otel_quarantine" {
			md, err := schema.QuarantineDestinationMetadataWithOptions(opts)
			if err != nil {
				t.Fatal(err)
			}
			return md.TimePartitioning.Expiration
		}
		in := schema.SpansTableSchema()
		switch table {
		case "otel_logs":
			in = schema.LogsTableSchema()
		case "otel_metrics":
			in = schema.MetricsTableSchema()
		}
		md, _, err := schema.DestinationMetadataWithOptions(in, "my-project", "otel", table, opts)
		if err != nil {
			t.Fatal(err)
		}
		return md.TimePartitioning.Expiration
	}
	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	for table, variable := range terraformExpirationVariables {
		perDay, err := strconv.ParseInt(firstCapture(`var\.`+variable+` \* ([0-9]+) : null`, mainTF), 10, 64)
		if err != nil {
			t.Fatalf("main.tf does not convert %s to milliseconds: %v", variable, err)
		}
		for _, days := range []int{0, 1, 30, 400} {
			if got, want := time.Duration(int64(days)*perDay)*time.Millisecond, exporterExpiration(table, days); got != want {
				t.Errorf("%s = %d expires %s partitions after %v, but the exporter expires them after %v",
					variable, days, table, got, want)
			}
		}
	}
}

var terraformViewHeredocRE = regexp.MustCompile(`(?s)query\s*=\s*<<-?EOT\n(.*?)\n\s*EOT`)

var terraformViewReplacer = strings.NewReplacer(
	"${var.project_id}", "p",
	"${google_bigquery_dataset.otel.dataset_id}", "d",
	"${google_bigquery_table.otel_spans_dedup.table_id}", "otel_spans_dedup",
	"${google_bigquery_table.otel_logs_dedup.table_id}", "otel_logs_dedup",
	"${google_bigquery_table.otel_metrics_dedup.table_id}", "otel_metrics_dedup",
	"${google_bigquery_table.v_gen_ai_spans.table_id}", "v_gen_ai_spans",
	"${google_bigquery_table.v_gen_ai_metrics.table_id}", "v_gen_ai_metrics",
	"${google_bigquery_table.v_mcp_spans.table_id}", "v_mcp_spans",
)

func normalizeCompanionViewSQL(sql string) string {
	var lines []string
	for _, line := range strings.Split(sql, "\n") {
		line, _, _ = strings.Cut(line, "--")
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	collapsed := strings.Join(strings.Fields(strings.Join(lines, " ")), " ")
	collapsed = strings.ReplaceAll(collapsed, "( ", "(")
	collapsed = strings.ReplaceAll(collapsed, " )", ")")
	return collapsed
}

// Each companion view in deploy/terraform/main.tf must match the SQL query the
// exporter creates via internal/schema, so a view change in one place cannot
// drift from the other.
func TestTerraformCompanionViewsMatchExporter(t *testing.T) {
	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	for _, tc := range []struct {
		resource string
		query    string
		args     []any
	}{
		{schema.SpansAsAllSpansViewName, schema.SpansAsAllSpansViewQuery, []any{"p", "d", "otel_spans"}},
		{schema.GenAISpansViewName, schema.GenAISpansViewQuery, []any{"p", "d", "otel_spans"}},
		{schema.GenAILogsViewName, schema.GenAILogsViewQuery, []any{"p", "d", "otel_logs", "otel_spans"}},
		{schema.GenAIMetricsViewName, schema.GenAIMetricsViewQuery, []any{"p", "d", "otel_metrics"}},
		{schema.GenAIMetricExemplarsViewName, schema.GenAIMetricExemplarsViewQuery, []any{"p", "d", "otel_spans"}},
		{schema.GenAIModelCostsViewName, schema.GenAIModelCostsViewQuery, []any{"p", "d"}},
		{schema.GenAISessionsViewName, schema.GenAISessionsViewQuery, []any{"p", "d"}},
		{schema.GenAIToolUsageViewName, schema.GenAIToolUsageViewQuery, []any{"p", "d"}},
		{schema.GenAIAgentTrajectoryViewName, schema.GenAIAgentTrajectoryViewQuery, []any{"p", "d"}},
		{schema.MCPSpansViewName, schema.MCPSpansViewQuery, []any{"p", "d", "otel_spans"}},
		{schema.MCPToolUsageViewName, schema.MCPToolUsageViewQuery, []any{"p", "d"}},
	} {
		t.Run(tc.resource, func(t *testing.T) {
			block := terraformBlock(mainTF, `resource "google_bigquery_table" "`+tc.resource+`"`)
			if block == "" {
				t.Fatalf("deploy/terraform/main.tf has no google_bigquery_table.%s resource", tc.resource)
			}
			m := terraformViewHeredocRE.FindStringSubmatch(block)
			if m == nil {
				t.Fatalf("google_bigquery_table.%s has no <<EOT or <<-EOT view query heredoc", tc.resource)
			}
			tfQuery := terraformViewReplacer.Replace(m[1])
			if i := strings.Index(tfQuery, "${"); i >= 0 {
				t.Fatalf("google_bigquery_table.%s contains an unexpected Terraform interpolation near %q",
					tc.resource, tfQuery[i:min(len(tfQuery), i+60)])
			}
			got := normalizeCompanionViewSQL(tfQuery)
			want := normalizeCompanionViewSQL(fmt.Sprintf(tc.query, tc.args...))
			if got != want {
				t.Errorf("Terraform view %s SQL does not match exporter view SQL:\n--- terraform ---\n%s\n--- exporter ---\n%s",
					tc.resource, got, want)
			}
		})
	}
}
