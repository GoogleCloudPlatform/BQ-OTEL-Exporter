// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/confmap"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

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

// decodeExporterConfig decodes an exporter section onto the factory defaults
// the way the Collector does, where an unknown or mistyped key is an error, and
// then runs both cfg.Validate and confmap.Validate (which recursively validates
// sending_queue, sending_queue.batch, retry_on_failure, and timeout). It is the
// check that a collector started with the configuration would accept it.
func decodeExporterConfig(t *testing.T, name string, section map[string]any) *Config {
	t.Helper()
	cfg := createDefaultConfig().(*Config)
	if err := confmap.NewFromStringMap(section).Unmarshal(cfg); err != nil {
		t.Fatalf("%s: the bigquery exporter section does not decode: %v", name, err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("%s: the bigquery exporter configuration is invalid: %v", name, err)
	}
	if err := confmap.Validate(cfg); err != nil {
		t.Fatalf("%s: the collector exporter configuration is invalid: %v", name, err)
	}
	return cfg
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
// the top-level bigquery* component sections: each must decode strictly and
// validate, and together they must set every option that reflection finds on
// Config.
func TestTestdataConfigSetsEveryExporterOption(t *testing.T) {
	doc := testsupport.ParseYAMLMap(t, "testdata/config.yaml", testsupport.ReadRepoText(t, "testdata/config.yaml"))
	options := exporterKeySet()
	set := map[string]bool{}
	var ids []string
	for id := range doc {
		if id == "bigquery" || strings.HasPrefix(id, "bigquery/") {
			ids = append(ids, id)
		} else {
			t.Errorf("unexpected top-level key %q in testdata/config.yaml; expected component IDs only", id)
		}
	}
	sort.Strings(ids)
	if len(ids) < 2 {
		t.Fatalf("testdata/config.yaml defines exporter sections %v, want a minimal and a full one at least", ids)
	}
	for _, id := range ids {
		section, ok := doc[id].(map[string]any)
		if !ok {
			t.Fatalf("%s in testdata/config.yaml is not a mapping", id)
		}
		t.Run(id, func(t *testing.T) { decodeExporterConfig(t, id, section) })
		for _, key := range presentExporterKeys(section, options, "") {
			set[key] = true
		}
	}
	for _, key := range exporterConfigKeys() {
		if !set[key] {
			t.Errorf("no bigquery* section of testdata/config.yaml sets %q", key)
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
	readme := testsupport.ReadRepoText(t, "README.md")
	for _, key := range exporterConfigKeys() {
		if !strings.HasPrefix(key, "offload.") {
			continue
		}
		want, ok := cells[key]
		if !ok {
			t.Errorf("the README default of %s is not checked; add it here", key)
			continue
		}
		if got := testsupport.FirstCapture("(?m)^\\| `"+regexp.QuoteMeta(key)+"` +\\| (.*?) +\\|", readme); got != want {
			t.Errorf("the README gives the %s default as %q, but the exporter's default is %q", key, got, want)
		}
	}
}
