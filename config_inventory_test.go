// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"bufio"
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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file is the configuration-surface gate for the beta stability level.
//
// The live key set is read from the mapstructure tags of Config by reflection
// and its defaults from createDefaultConfig(). Three things must agree with
// it: the golden inventory below, the table in docs/config-inventory.md, and
// the deprecation registry in config_deprecation.go. A key that disappears
// from Config without a deprecatedConfigKeys entry fails here, as does a new
// key that is not inventoried, a documented default that drifted from the
// code, and a deprecation whose migration anchor is missing from
// docs/migration.md.

const (
	modulePath            = "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
	configInventoryDoc    = "docs/config-inventory.md"
	migrationGuideDoc     = "docs/migration.md"
	stabilityStable       = "stable"
	stabilityExperimental = "experimental"
	// defaultUnset is how the inventory renders a nil map or slice default.
	defaultUnset = "unset"
	// defaultUpstream is how the inventory renders a block whose keys and
	// defaults are owned by an upstream Collector package.
	defaultUpstream = "see notes"
)

// configKeyInfo is one leaf key as reflected from Config.
type configKeyInfo struct {
	Path    string
	Type    string
	Default string
}

// configKeyGolden is the hand-maintained part of the inventory: the release
// that introduced the key and its stability class. Everything else about a
// key is read from the code.
type configKeyGolden struct {
	Since     string
	Stability string
}

// configInventoryGolden lists every key that has shipped in a tagged release.
// Add a line when a key is added. When a key is renamed or removed, keep its
// line, add a deprecatedConfigKeys entry, and delete both together once the
// removal release has shipped.
//
// Since values come from the tagged history of config.go (every key below was
// present at v0.0.1, the first tagged release). Stability: "stable" keys keep
// their meaning and default within the beta line; "experimental" keys are
// write-path tuning knobs whose defaults and bounds may be retuned in any
// release with a CHANGELOG entry. Both classes go through the deprecation
// mechanism when renamed or removed.
var configInventoryGolden = map[string]configKeyGolden{
	"timeout":          {Since: "v0.0.1", Stability: stabilityStable},
	"sending_queue":    {Since: "v0.0.1", Stability: stabilityStable},
	"retry_on_failure": {Since: "v0.0.1", Stability: stabilityStable},

	"project":      {Since: "v0.0.1", Stability: stabilityStable},
	"dataset":      {Since: "v0.0.1", Stability: stabilityStable},
	"location":     {Since: "v0.0.1", Stability: stabilityStable},
	"kms_key_name": {Since: "v0.0.1", Stability: stabilityStable},
	"labels":       {Since: "v0.0.1", Stability: stabilityStable},

	"traces.table":                     {Since: "v0.0.1", Stability: stabilityStable},
	"traces.partition_expiration_days": {Since: "v0.0.1", Stability: stabilityStable},
	"traces.require_partition_filter":  {Since: "v0.0.1", Stability: stabilityStable},
	"traces.kms_key_name":              {Since: "v0.0.1", Stability: stabilityStable},
	"traces.labels":                    {Since: "v0.0.1", Stability: stabilityStable},
	"traces.max_staleness":             {Since: "v0.0.1", Stability: stabilityStable},

	"logs.table":                     {Since: "v0.0.1", Stability: stabilityStable},
	"logs.partition_expiration_days": {Since: "v0.0.1", Stability: stabilityStable},
	"logs.require_partition_filter":  {Since: "v0.0.1", Stability: stabilityStable},
	"logs.kms_key_name":              {Since: "v0.0.1", Stability: stabilityStable},
	"logs.labels":                    {Since: "v0.0.1", Stability: stabilityStable},
	"logs.max_staleness":             {Since: "v0.0.1", Stability: stabilityStable},
	"logs.log_name_attribute":        {Since: "v0.0.1", Stability: stabilityStable},
	"logs.insert_id_attribute":       {Since: "v0.0.1", Stability: stabilityStable},

	"metrics.table":                     {Since: "v0.0.1", Stability: stabilityStable},
	"metrics.partition_expiration_days": {Since: "v0.0.1", Stability: stabilityStable},
	"metrics.require_partition_filter":  {Since: "v0.0.1", Stability: stabilityStable},
	"metrics.kms_key_name":              {Since: "v0.0.1", Stability: stabilityStable},
	"metrics.labels":                    {Since: "v0.0.1", Stability: stabilityStable},
	"metrics.max_staleness":             {Since: "v0.0.1", Stability: stabilityStable},

	"credentials.file":                        {Since: "v0.0.1", Stability: stabilityStable},
	"credentials.json":                        {Since: "v0.0.1", Stability: stabilityStable},
	"credentials.impersonate_service_account": {Since: "v0.0.1", Stability: stabilityStable},
	"credentials.impersonate_delegates":       {Since: "v0.0.1", Stability: stabilityStable},
	"credentials.quota_project":               {Since: "v0.0.1", Stability: stabilityStable},
	"credentials.universe_domain":             {Since: "v0.0.1", Stability: stabilityStable},

	"endpoint.url":                    {Since: "v0.0.1", Stability: stabilityStable},
	"endpoint.admin_url":              {Since: "v0.0.1", Stability: stabilityStable},
	"endpoint.insecure":               {Since: "v0.0.1", Stability: stabilityStable},
	"endpoint.without_authentication": {Since: "v0.0.1", Stability: stabilityStable},

	"auto_create.dataset":                {Since: "v0.0.1", Stability: stabilityStable},
	"auto_create.tables":                 {Since: "v0.0.1", Stability: stabilityStable},
	"auto_create.companion_views":        {Since: "v0.0.1", Stability: stabilityStable},
	"auto_create.allow_unprunable_views": {Since: "v0.0.1", Stability: stabilityStable},
	"auto_create.search_indexes":         {Since: "v0.0.1", Stability: stabilityStable},

	"write.max_request_bytes":     {Since: "v0.0.1", Stability: stabilityStable},
	"write.max_row_bytes":         {Since: "v0.0.1", Stability: stabilityStable},
	"write.max_inflight_requests": {Since: "v0.0.1", Stability: stabilityStable},
	"write.max_inflight_bytes":    {Since: "v0.0.1", Stability: stabilityStable},
	"write.stream_pool_size":      {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.enable_multiplexing":   {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.connection_pool_size":  {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.compression":           {Since: "v0.0.1", Stability: stabilityExperimental},

	"write.keepalive.time":                  {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.keepalive.timeout":               {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.keepalive.permit_without_stream": {Since: "v0.0.1", Stability: stabilityExperimental},

	"write.backpressure.enabled":               {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.backpressure.min_request_bytes":     {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.backpressure.min_inflight_requests": {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.backpressure.decrease_factor":       {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.backpressure.recovery_interval":     {Since: "v0.0.1", Stability: stabilityExperimental},
	"write.backpressure.latency_threshold":     {Since: "v0.0.1", Stability: stabilityExperimental},

	"limits.max_attribute_count":     {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_event_count":         {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_link_count":          {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_nesting_depth":       {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_collection_size":     {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_attribute_key_bytes": {Since: "v0.0.1", Stability: stabilityStable},
	"limits.max_value_bytes":         {Since: "v0.0.1", Stability: stabilityStable},

	"quarantine.enabled":                   {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.table":                     {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.partition_expiration_days": {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.require_partition_filter":  {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.kms_key_name":              {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.labels":                    {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.max_staleness":             {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.metadata_only":             {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.max_raw_payload_bytes":     {Since: "v0.0.1", Stability: stabilityStable},
	"quarantine.timeout":                   {Since: "v0.0.1", Stability: stabilityStable},

	"offload.enabled":          {Since: "v0.0.1", Stability: stabilityStable},
	"offload.bucket":           {Since: "v0.0.1", Stability: stabilityStable},
	"offload.prefix":           {Since: "v0.0.1", Stability: stabilityStable},
	"offload.authorizer":       {Since: "v0.0.1", Stability: stabilityStable},
	"offload.min_bytes":        {Since: "v0.0.1", Stability: stabilityStable},
	"offload.max_object_bytes": {Since: "v0.0.1", Stability: stabilityStable},
	"offload.max_concurrency":  {Since: "v0.0.1", Stability: stabilityStable},
	"offload.cache_size":       {Since: "v0.0.1", Stability: stabilityStable},
	"offload.timeout":          {Since: "v0.0.1", Stability: stabilityStable},

	"redaction.enabled":                {Since: "v0.0.1", Stability: stabilityStable},
	"redaction.blocked_keys":           {Since: "v0.0.1", Stability: stabilityStable},
	"redaction.disable_default_keys":   {Since: "v0.0.1", Stability: stabilityStable},
	"redaction.blocked_value_patterns": {Since: "v0.0.1", Stability: stabilityStable},
	"redaction.mask_replacement":       {Since: "v0.0.1", Stability: stabilityStable},
	"redaction.redact_log_body":        {Since: "v0.0.1", Stability: stabilityStable},
}

// TestConfigInventoryGate is the gate CI runs: live keys, golden inventory,
// deprecation registry and both documents must agree.
func TestConfigInventoryGate(t *testing.T) {
	live := liveConfigKeys(t)
	liveByPath := indexConfigKeys(live)

	require.NoError(t, errors.Join(checkConfigInventory(liveByPath, configInventoryGolden, deprecatedConfigKeys)...))

	doc := parseConfigInventoryDoc(t, readRepoFile(t, configInventoryDoc))
	anchors := markdownAnchors(readRepoFile(t, migrationGuideDoc))
	require.NoError(t, errors.Join(checkConfigInventoryDoc(doc, liveByPath, configInventoryGolden, deprecatedConfigKeys, anchors)...))

	// The counts in the prose must match the table they describe.
	text := string(readRepoFile(t, configInventoryDoc))
	assert.Contains(t, text, fmt.Sprintf("%d keys", len(live)), "docs/config-inventory.md must state the key count")
	var experimental int
	for _, g := range configInventoryGolden {
		if g.Stability == stabilityExperimental {
			experimental++
		}
	}
	assert.Contains(t, text, fmt.Sprintf("%d experimental", experimental), "docs/config-inventory.md must state the experimental count")
}

// TestConfigInventoryGateRejectsRemovalWithoutDeprecation proves the gate can
// fail: a key that leaves Config without a deprecation rule is an error, and
// the same key with a valid rule whose anchor exists in docs/migration.md is
// not.
func TestConfigInventoryGateRejectsRemovalWithoutDeprecation(t *testing.T) {
	const removed = "write.compression"
	live := indexConfigKeys(liveConfigKeys(t))
	require.Contains(t, live, removed)
	delete(live, removed)

	errs := checkConfigInventory(live, configInventoryGolden, nil)
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], removed)
	assert.ErrorContains(t, errs[0], "without a deprecatedConfigKeys entry")

	rule := deprecatedConfigKey{
		OldPath:         removed,
		NewPath:         "",
		DeprecatedIn:    "v0.0.4",
		RemovalEarliest: "v0.0.6",
		Anchor:          "worked-example-renaming-a-key",
	}
	assert.Empty(t, checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{rule}))

	// The documentation side of the same gate: the deprecated-keys table must
	// list the rule, and its anchor must resolve in docs/migration.md.
	anchors := markdownAnchors(readRepoFile(t, migrationGuideDoc))
	require.Contains(t, anchors, rule.Anchor, "docs/migration.md must keep the worked-example heading this test relies on")

	doc := parseConfigInventoryDoc(t, readRepoFile(t, configInventoryDoc))
	doc.keys = slices.DeleteFunc(doc.keys, func(r inventoryDocRow) bool { return r.Path == removed })
	withoutRow := checkConfigInventoryDoc(doc, live, configInventoryGolden, []deprecatedConfigKey{rule}, anchors)
	require.NotEmpty(t, withoutRow)
	assert.ErrorContains(t, errors.Join(withoutRow...), "deprecated keys table")

	doc.deprecated = append(doc.deprecated, deprecatedDocRow(rule))
	assert.Empty(t, checkConfigInventoryDoc(doc, live, configInventoryGolden, []deprecatedConfigKey{rule}, anchors))

	badAnchor := rule
	badAnchor.Anchor = "no-such-heading"
	doc.deprecated[len(doc.deprecated)-1].Anchor = badAnchor.Anchor
	errs = checkConfigInventoryDoc(doc, live, configInventoryGolden, []deprecatedConfigKey{badAnchor}, anchors)
	require.NotEmpty(t, errs)
	assert.ErrorContains(t, errors.Join(errs...), "no-such-heading")
}

// TestConfigInventoryGateRejectsUnregisteredKey proves the other direction: a
// key present in Config but absent from the golden inventory fails.
func TestConfigInventoryGateRejectsUnregisteredKey(t *testing.T) {
	live := indexConfigKeys(liveConfigKeys(t))
	live["write.brand_new_knob"] = configKeyInfo{Path: "write.brand_new_knob", Type: "int", Default: "0"}

	errs := checkConfigInventory(live, configInventoryGolden, nil)
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "write.brand_new_knob")
	assert.ErrorContains(t, errs[0], "not in configInventoryGolden")
}

// TestConfigInventoryGateRejectsDeadRules proves a rule cannot name a key
// that is still declared, nor point at a replacement that does not exist.
func TestConfigInventoryGateRejectsDeadRules(t *testing.T) {
	live := indexConfigKeys(liveConfigKeys(t))

	stillLive := deprecatedConfigKey{OldPath: "write.compression", NewPath: "", DeprecatedIn: "v0.0.4", RemovalEarliest: "v0.0.6", Anchor: "x"}
	errs := checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{stillLive})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "still declared")

	delete(live, "write.compression")
	danglingNew := deprecatedConfigKey{OldPath: "write.compression", NewPath: "write.no_such_key", DeprecatedIn: "v0.0.4", RemovalEarliest: "v0.0.6", Anchor: "x"}
	errs = checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{danglingNew})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "write.no_such_key")
}

// TestConfigInventoryGateAcceptsBlockDeprecation proves block-level
// deprecation rules (such as testBlockRule mapping legacy_keepalive ->
// write.keepalive, or retiring all write.keepalive.* leaves with a single
// write.keepalive rule) are accepted when valid and rejected when still
// declared or pointing at a nonexistent replacement block.
func TestConfigInventoryGateAcceptsBlockDeprecation(t *testing.T) {
	live := indexConfigKeys(liveConfigKeys(t))

	// testBlockRule (legacy_keepalive -> write.keepalive) targets the live
	// write.keepalive.* block and must pass checkConfigInventory.
	assert.Empty(t, checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{testBlockRule}))

	// A block rule whose OldPath still has live child keys in Config is rejected.
	stillLiveBlock := deprecatedConfigKey{
		OldPath:         "write.keepalive",
		NewPath:         "",
		DeprecatedIn:    "v0.0.4",
		RemovalEarliest: "v0.0.6",
		Anchor:          "worked-example-renaming-a-key",
	}
	errs := checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{stillLiveBlock})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "still declared")

	// Removing all write.keepalive.* leaves without a rule fails for all 3 leaves;
	// adding a single block rule for write.keepalive satisfies both inventory checks.
	for k := range live {
		if strings.HasPrefix(k, "write.keepalive.") {
			delete(live, k)
		}
	}
	errs = checkConfigInventory(live, configInventoryGolden, nil)
	require.Len(t, errs, 3)
	assert.Empty(t, checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{stillLiveBlock}))

	anchors := markdownAnchors(readRepoFile(t, migrationGuideDoc))
	doc := parseConfigInventoryDoc(t, readRepoFile(t, configInventoryDoc))
	doc.keys = slices.DeleteFunc(doc.keys, func(r inventoryDocRow) bool {
		return strings.HasPrefix(r.Path, "write.keepalive.")
	})
	doc.deprecated = append(doc.deprecated, deprecatedDocRow(stillLiveBlock))
	assert.Empty(t, checkConfigInventoryDoc(doc, live, configInventoryGolden, []deprecatedConfigKey{stillLiveBlock}, anchors))

	// A block rule pointing at a nonexistent replacement block is rejected.
	danglingBlock := stillLiveBlock
	danglingBlock.NewPath = "write.no_such_block"
	errs = checkConfigInventory(live, configInventoryGolden, []deprecatedConfigKey{danglingBlock})
	require.Len(t, errs, 1)
	assert.ErrorContains(t, errs[0], "write.no_such_block")
}

// TestConfigInventoryDocRejectsDrift proves the document comparison catches a
// default, type, release or stability that no longer matches the code.
func TestConfigInventoryDocRejectsDrift(t *testing.T) {
	live := indexConfigKeys(liveConfigKeys(t))
	anchors := markdownAnchors(readRepoFile(t, migrationGuideDoc))
	base := parseConfigInventoryDoc(t, readRepoFile(t, configInventoryDoc))
	require.Empty(t, checkConfigInventoryDoc(base, live, configInventoryGolden, deprecatedConfigKeys, anchors))

	mutate := func(name string, f func(r *inventoryDocRow)) {
		t.Run(name, func(t *testing.T) {
			doc := base
			doc.keys = slices.Clone(base.keys)
			i := slices.IndexFunc(doc.keys, func(r inventoryDocRow) bool { return r.Path == "write.max_row_bytes" })
			require.GreaterOrEqual(t, i, 0)
			f(&doc.keys[i])
			errs := checkConfigInventoryDoc(doc, live, configInventoryGolden, deprecatedConfigKeys, anchors)
			require.NotEmpty(t, errs)
			assert.ErrorContains(t, errors.Join(errs...), "write.max_row_bytes")
		})
	}
	mutate("default", func(r *inventoryDocRow) { r.Default = "2097152" })
	mutate("type", func(r *inventoryDocRow) { r.Type = "int64" })
	mutate("since", func(r *inventoryDocRow) { r.Since = "v0.0.2" })
	mutate("stability", func(r *inventoryDocRow) { r.Stability = stabilityExperimental })
	mutate("missing", func(r *inventoryDocRow) { r.Path = "write.max_row_bytez" })
}

// TestLiveConfigKeysShape pins the reflection walker itself: squashed
// upstream blocks surface as top-level keys, nested local blocks are
// flattened, and upstream blocks are leaves.
func TestLiveConfigKeysShape(t *testing.T) {
	live := indexConfigKeys(liveConfigKeys(t))

	assert.Equal(t, configKeyInfo{Path: "timeout", Type: "time.Duration", Default: "5s"}, live["timeout"])
	assert.Equal(t, configKeyInfo{Path: "write.backpressure.decrease_factor", Type: "float64", Default: "0.5"}, live["write.backpressure.decrease_factor"])
	assert.Equal(t, configKeyInfo{Path: "labels", Type: "map[string]string", Default: defaultUnset}, live["labels"])
	assert.Equal(t, configKeyInfo{Path: "credentials.json", Type: "configopaque.String", Default: `""`}, live["credentials.json"])
	assert.Equal(t, defaultUpstream, live["sending_queue"].Default)
	assert.Equal(t, "configoptional.Optional[queuebatch.Config]", live["sending_queue"].Type)
	assert.Equal(t, defaultUpstream, live["retry_on_failure"].Default)
	assert.Equal(t, "configretry.BackOffConfig", live["retry_on_failure"].Type)

	for path := range live {
		assert.NotContains(t, path, "..", path)
		assert.False(t, strings.HasSuffix(path, "."), path)
	}
}

// --- reflection ------------------------------------------------------------

// liveConfigKeys walks Config by reflection and returns every leaf key with
// its Go type and the default createDefaultConfig() assigns, sorted by path.
func liveConfigKeys(t *testing.T) []configKeyInfo {
	t.Helper()
	cfg, ok := createDefaultConfig().(*Config)
	require.True(t, ok)
	var out []configKeyInfo
	walkConfigKeys(t, reflect.ValueOf(cfg).Elem(), "", &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func walkConfigKeys(t *testing.T, v reflect.Value, prefix string, out *[]configKeyInfo) {
	t.Helper()
	st := v.Type()
	for i := range st.NumField() {
		f := st.Field(i)
		if !f.IsExported() {
			continue
		}
		tag, ok := f.Tag.Lookup("mapstructure")
		require.Truef(t, ok, "%s.%s has no mapstructure tag", st.Name(), f.Name)
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" {
			continue
		}
		fv := v.Field(i)
		if slices.Contains(strings.Split(opts, ","), "squash") {
			require.Equalf(t, reflect.Struct, fv.Kind(), "%s.%s squashes a non-struct", st.Name(), f.Name)
			walkConfigKeys(t, fv, prefix, out)
			continue
		}
		require.NotEmptyf(t, name, "%s.%s has an unnamed mapstructure tag", st.Name(), f.Name)
		path := prefix + name
		if fv.Kind() == reflect.Struct && strings.HasPrefix(fv.Type().PkgPath(), modulePath) {
			walkConfigKeys(t, fv, path+".", out)
			continue
		}
		*out = append(*out, configKeyInfo{Path: path, Type: shortTypeName(fv.Type()), Default: renderDefault(t, path, fv)})
	}
}

var importPathPrefix = regexp.MustCompile(`[\w.-]+(/[\w.-]+)+/`)

// shortTypeName renders a type the way the documentation names it: package
// qualified, without import paths inside generic parameters.
func shortTypeName(t reflect.Type) string {
	return importPathPrefix.ReplaceAllString(t.String(), "")
}

func renderDefault(t *testing.T, path string, v reflect.Value) string {
	t.Helper()
	if v.Type() == reflect.TypeFor[time.Duration]() {
		return v.Interface().(time.Duration).String()
	}
	switch v.Kind() {
	case reflect.String:
		return strconv.Quote(v.String())
	case reflect.Bool:
		return strconv.FormatBool(v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10)
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'g', -1, 64)
	case reflect.Slice, reflect.Map:
		if v.IsNil() || v.Len() == 0 {
			return defaultUnset
		}
		return fmt.Sprint(v.Interface())
	case reflect.Struct:
		return defaultUpstream
	default:
		t.Fatalf("%s: unsupported config field kind %s", path, v.Kind())
		return ""
	}
}

func indexConfigKeys(keys []configKeyInfo) map[string]configKeyInfo {
	out := make(map[string]configKeyInfo, len(keys))
	for _, k := range keys {
		out[k.Path] = k
	}
	return out
}

// --- the gate --------------------------------------------------------------

// checkConfigInventory compares the live key set with the golden inventory
// and the deprecation registry. It is pure so the tests above can feed it
// deliberately broken inputs.
func checkConfigInventory(live map[string]configKeyInfo, golden map[string]configKeyGolden, rules []deprecatedConfigKey) []error {
	var errs []error
	for _, path := range sortedPaths(golden) {
		g := golden[path]
		if !releasePattern.MatchString(g.Since) {
			errs = append(errs, fmt.Errorf("%s: golden Since %q is not a release tag", path, g.Since))
		}
		if g.Stability != stabilityStable && g.Stability != stabilityExperimental {
			errs = append(errs, fmt.Errorf("%s: golden Stability %q is neither %q nor %q", path, g.Stability, stabilityStable, stabilityExperimental))
		}
		if _, ok := live[path]; ok {
			continue
		}
		if !isRetiredByRule(path, rules) {
			errs = append(errs, fmt.Errorf("%s: key left Config without a deprecatedConfigKeys entry; register the rename or removal in config_deprecation.go and document it in %s", path, migrationGuideDoc))
		}
	}
	for _, path := range sortedPaths(live) {
		if _, ok := golden[path]; !ok {
			errs = append(errs, fmt.Errorf("%s: key is declared in Config but not in configInventoryGolden; add it there and to %s", path, configInventoryDoc))
		}
	}
	for _, r := range rules {
		if hasKeyOrBlock(live, r.OldPath) {
			errs = append(errs, fmt.Errorf("deprecation rule %s: key is still declared in Config; a rule may only retire a key that no longer exists", r.OldPath))
		}
		if r.NewPath != "" {
			if !hasKeyOrBlock(live, r.NewPath) {
				errs = append(errs, fmt.Errorf("deprecation rule %s: replacement %s is not a declared key", r.OldPath, r.NewPath))
			}
		}
	}
	return errs
}

// hasKeyOrBlock reports whether path is an exact leaf key in m or a block
// prefix of at least one "<path>.*" leaf key in m.
func hasKeyOrBlock[V any](m map[string]V, path string) bool {
	if _, ok := m[path]; ok {
		return true
	}
	prefix := path + "."
	for k := range m {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// isRetiredByRule reports whether leaf key path is retired by any rule in
// rules, either by exact OldPath match or by an "<OldPath>." block prefix.
func isRetiredByRule(path string, rules []deprecatedConfigKey) bool {
	for _, r := range rules {
		if r.OldPath == path || strings.HasPrefix(path, r.OldPath+".") {
			return true
		}
	}
	return false
}

// checkConfigInventoryDoc compares docs/config-inventory.md with the code.
func checkConfigInventoryDoc(doc inventoryDoc, live map[string]configKeyInfo, golden map[string]configKeyGolden, rules []deprecatedConfigKey, anchors map[string]struct{}) []error {
	var errs []error
	rows := make(map[string]inventoryDocRow, len(doc.keys))
	for _, r := range doc.keys {
		if _, dup := rows[r.Path]; dup {
			errs = append(errs, fmt.Errorf("%s: listed twice in %s", r.Path, configInventoryDoc))
		}
		rows[r.Path] = r
	}
	for _, path := range sortedPaths(live) {
		row, ok := rows[path]
		if !ok {
			errs = append(errs, fmt.Errorf("%s: missing from the keys table in %s", path, configInventoryDoc))
			continue
		}
		if row.Type != live[path].Type {
			errs = append(errs, fmt.Errorf("%s: documented type %q, code has %q", path, row.Type, live[path].Type))
		}
		if row.Default != live[path].Default {
			errs = append(errs, fmt.Errorf("%s: documented default %q, code has %q", path, row.Default, live[path].Default))
		}
		if g, ok := golden[path]; ok {
			if row.Since != g.Since {
				errs = append(errs, fmt.Errorf("%s: documented Since %q, golden has %q", path, row.Since, g.Since))
			}
			if row.Stability != g.Stability {
				errs = append(errs, fmt.Errorf("%s: documented stability %q, golden has %q", path, row.Stability, g.Stability))
			}
		}
		if strings.TrimSpace(row.Notes) == "" {
			errs = append(errs, fmt.Errorf("%s: notes column is empty in %s", path, configInventoryDoc))
		}
	}
	for _, path := range sortedPaths(rows) {
		if _, ok := live[path]; !ok {
			errs = append(errs, fmt.Errorf("%s: documented in %s but not declared in Config", path, configInventoryDoc))
		}
	}

	docRules := make(map[string]deprecatedDocRow, len(doc.deprecated))
	for _, r := range doc.deprecated {
		docRules[r.OldPath] = r
	}
	for _, r := range rules {
		row, ok := docRules[r.OldPath]
		if !ok {
			errs = append(errs, fmt.Errorf("deprecation rule %s: missing from the deprecated keys table in %s", r.OldPath, configInventoryDoc))
			continue
		}
		want := deprecatedDocRow(r)
		if row != want {
			errs = append(errs, fmt.Errorf("deprecation rule %s: documented as %+v, code has %+v", r.OldPath, row, want))
		}
		if _, ok := anchors[r.Anchor]; !ok {
			errs = append(errs, fmt.Errorf("deprecation rule %s: anchor %q has no heading in %s", r.OldPath, r.Anchor, migrationGuideDoc))
		}
	}
	for _, r := range doc.deprecated {
		if !slices.ContainsFunc(rules, func(rule deprecatedConfigKey) bool { return rule.OldPath == r.OldPath }) {
			errs = append(errs, fmt.Errorf("deprecated keys table lists %s, which has no deprecatedConfigKeys entry", r.OldPath))
		}
	}
	return errs
}

// --- markdown --------------------------------------------------------------

type inventoryDocRow struct {
	Path, Type, Default, Since, Stability, Notes string
}

type deprecatedDocRow struct {
	OldPath, NewPath, DeprecatedIn, RemovalEarliest, Anchor string
}

type inventoryDoc struct {
	keys       []inventoryDocRow
	deprecated []deprecatedDocRow
}

// parseConfigInventoryDoc reads the two tables under "## Keys" and
// "## Deprecated keys". Cells are stripped of surrounding backticks; a
// deprecated-keys row whose first cell is "none" is the empty placeholder.
func parseConfigInventoryDoc(t *testing.T, data []byte) inventoryDoc {
	t.Helper()
	var doc inventoryDoc
	keyRows := markdownTable(t, data, "## Keys")
	for _, cells := range keyRows {
		require.Lenf(t, cells, 6, "keys table row %v must have 6 columns", cells)
		doc.keys = append(doc.keys, inventoryDocRow{
			Path: cells[0], Type: cells[1], Default: cells[2], Since: cells[3], Stability: cells[4], Notes: cells[5],
		})
	}
	for _, cells := range markdownTable(t, data, "## Deprecated keys") {
		require.Lenf(t, cells, 5, "deprecated keys table row %v must have 5 columns", cells)
		if cells[0] == "none" {
			continue
		}
		doc.deprecated = append(doc.deprecated, deprecatedDocRow{
			OldPath: cells[0], NewPath: cells[1], DeprecatedIn: cells[2], RemovalEarliest: cells[3], Anchor: cells[4],
		})
	}
	return doc
}

// markdownTable returns the body rows of the first table under heading.
func markdownTable(t *testing.T, data []byte, heading string) [][]string {
	t.Helper()
	var (
		rows      [][]string
		inSection bool
		inTable   bool
		headerSep bool
	)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == heading:
			inSection = true
			continue
		case !inSection:
			continue
		case strings.HasPrefix(line, "## "):
			require.Truef(t, inTable, "no table found under %q", heading)
			return rows
		case !strings.HasPrefix(line, "|"):
			if inTable {
				return rows
			}
			continue
		}
		inTable = true
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.Trim(strings.TrimSpace(cells[i]), "`")
		}
		if !headerSep {
			if strings.HasPrefix(cells[0], "---") {
				headerSep = true
			}
			continue
		}
		rows = append(rows, cells)
	}
	require.NoError(t, sc.Err())
	require.Truef(t, inTable, "no table found under %q", heading)
	return rows
}

var (
	markdownHeading  = regexp.MustCompile(`^#{1,6}\s+(.*?)\s*$`)
	anchorDropChars  = regexp.MustCompile(`[^a-z0-9 _-]`)
	anchorCollapseWS = regexp.MustCompile(` `)
)

// markdownAnchors returns the GitHub-style anchors of every heading, with a
// numeric suffix for repeated headings, the way GitHub renders them.
func markdownAnchors(data []byte) map[string]struct{} {
	out := make(map[string]struct{})
	seen := make(map[string]int)
	inFence := false
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "```") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		m := markdownHeading.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		title := strings.ReplaceAll(m[1], "`", "")
		slug := anchorDropChars.ReplaceAllString(strings.ToLower(title), "")
		slug = anchorCollapseWS.ReplaceAllString(slug, "-")
		if n := seen[slug]; n > 0 {
			out[fmt.Sprintf("%s-%d", slug, n)] = struct{}{}
		} else {
			out[slug] = struct{}{}
		}
		seen[slug]++
	}
	return out
}

func readRepoFile(t *testing.T, rel string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(".", filepath.FromSlash(rel)))
	require.NoError(t, err)
	return data
}

func sortedPaths[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
