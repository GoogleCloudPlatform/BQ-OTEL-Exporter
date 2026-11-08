// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"context"
	"maps"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/confmap"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// The rules below are fixtures; none of these keys is really deprecated. The
// replacement keys are real so that end-to-end decoding can be checked.
var (
	testRenameRule = deprecatedConfigKey{
		OldPath:         "write.legacy_pool_size",
		NewPath:         "write.stream_pool_size",
		DeprecatedIn:    "v0.0.4",
		RemovalEarliest: "v0.0.6",
		Anchor:          "writelegacy_pool_size--writestream_pool_size-deprecated-in-v004",
	}
	testRemoveRule = deprecatedConfigKey{
		OldPath:         "legacy_flag",
		NewPath:         "",
		DeprecatedIn:    "v0.0.4",
		RemovalEarliest: "v0.0.6",
		Anchor:          "legacy_flag-removed-in-v004",
	}
	testBlockRule = deprecatedConfigKey{
		OldPath:         "legacy_keepalive",
		NewPath:         "write.keepalive",
		DeprecatedIn:    "v0.0.4",
		RemovalEarliest: "v0.0.6",
		Anchor:          "legacy_keepalive--writekeepalive-deprecated-in-v004",
	}
)

func TestDeprecatedConfigKeysRegistryIsValid(t *testing.T) {
	require.NoError(t, validateDeprecationRules(deprecatedConfigKeys))
}

func TestApplyConfigDeprecations(t *testing.T) {
	tests := []struct {
		name        string
		in          map[string]any
		rules       []deprecatedConfigKey
		wantWork    map[string]any
		wantApplied []deprecatedConfigKey
		wantErr     []string
	}{
		{
			name:     "no rules leaves the map alone",
			in:       map[string]any{"project": "p", "write": map[string]any{"stream_pool_size": 2}},
			rules:    nil,
			wantWork: map[string]any{"project": "p", "write": map[string]any{"stream_pool_size": 2}},
		},
		{
			name:     "rule for an unset key is a no-op",
			in:       map[string]any{"project": "p"},
			rules:    []deprecatedConfigKey{testRenameRule, testRemoveRule},
			wantWork: map[string]any{"project": "p"},
		},
		{
			name:        "old key is stripped from work Conf and recorded in applied",
			in:          map[string]any{"project": "p", "write": map[string]any{"legacy_pool_size": 4}},
			rules:       []deprecatedConfigKey{testRenameRule},
			wantWork:    map[string]any{"project": "p"},
			wantApplied: []deprecatedConfigKey{testRenameRule},
		},
		{
			name:     "replacement already set is untouched",
			in:       map[string]any{"write": map[string]any{"stream_pool_size": 3}},
			rules:    []deprecatedConfigKey{testRenameRule},
			wantWork: map[string]any{"write": map[string]any{"stream_pool_size": 3}},
		},
		{
			name:    "both old and new set is an error",
			in:      map[string]any{"write": map[string]any{"legacy_pool_size": 4, "stream_pool_size": 3}},
			rules:   []deprecatedConfigKey{testRenameRule},
			wantErr: []string{"write.legacy_pool_size is deprecated and replaced by write.stream_pool_size, but both are set", migrationGuideURL + "#" + testRenameRule.Anchor},
		},
		{
			name:        "removed key is dropped",
			in:          map[string]any{"project": "p", "legacy_flag": true},
			rules:       []deprecatedConfigKey{testRemoveRule},
			wantWork:    map[string]any{"project": "p"},
			wantApplied: []deprecatedConfigKey{testRemoveRule},
		},
		{
			name:        "whole block is stripped from work Conf while siblings survive",
			in:          map[string]any{"legacy_keepalive": map[string]any{"time": "30s", "permit_without_stream": true}, "write": map[string]any{"compression": "gzip"}},
			rules:       []deprecatedConfigKey{testBlockRule},
			wantWork:    map[string]any{"write": map[string]any{"compression": "gzip"}},
			wantApplied: []deprecatedConfigKey{testBlockRule},
		},
		{
			name:        "several rules apply in registry order",
			in:          map[string]any{"legacy_flag": 1, "write": map[string]any{"legacy_pool_size": 2}},
			rules:       []deprecatedConfigKey{testRenameRule, testRemoveRule},
			wantWork:    map[string]any{},
			wantApplied: []deprecatedConfigKey{testRenameRule, testRemoveRule},
		},
		{
			name:    "invalid registry fails before touching the map",
			in:      map[string]any{"legacy_flag": 1},
			rules:   []deprecatedConfigKey{{OldPath: "legacy_flag", DeprecatedIn: "v0.0.4", RemovalEarliest: "v0.0.5", Anchor: "a"}},
			wantErr: []string{"at least 2 required"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orig := maps.Clone(tt.in)
			conf := confmap.NewFromStringMap(tt.in)
			work, applied, err := applyConfigDeprecations(conf, tt.rules)
			assert.Equal(t, orig, conf.ToStringMap(), "caller confmap.Conf must never be mutated in place")
			if len(tt.wantErr) > 0 {
				require.Error(t, err)
				for _, want := range tt.wantErr {
					assert.ErrorContains(t, err, want)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantWork, work.ToStringMap())
			assert.Equal(t, tt.wantApplied, applied)
		})
	}
}

// TestConfigUnmarshalAppliesDeprecations covers the confmap.Unmarshaler
// path: a deprecated key decodes into the replacement field, the old key does
// not trip the unknown-key check, and the configuration remembers what was
// rewritten so the exporter can warn.
func TestConfigUnmarshalAppliesDeprecations(t *testing.T) {
	t.Run("leaf rename, removed key, and whole block move", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project":          "my-project",
			"dataset":          "otel",
			"legacy_flag":      true,
			"legacy_keepalive": map[string]any{"time": "30s", "permit_without_stream": true},
			"write":            map[string]any{"legacy_pool_size": 4, "connection_pool_size": 4, "compression": "gzip"},
		})
		cfg := createDefaultConfig().(*Config)
		rules := []deprecatedConfigKey{testRenameRule, testRemoveRule, testBlockRule}
		require.NoError(t, cfg.unmarshalWithDeprecations(conf, rules))

		assert.Equal(t, "my-project", cfg.Project)
		assert.Equal(t, 4, cfg.Write.StreamPoolSize)
		assert.Equal(t, "gzip", cfg.Write.Compression)
		assert.Equal(t, 30*time.Second, cfg.Write.Keepalive.Time)
		assert.True(t, cfg.Write.Keepalive.PermitWithoutStream)
		assert.Equal(t, time.Duration(0), cfg.Write.Keepalive.Timeout, "unset fields inside a moved block keep their defaults")
		assert.Equal(t, defaultEnableMultiplexing, cfg.Write.EnableMultiplexing, "unrelated defaults survive")
		require.NotNil(t, cfg.deprecations)
		assert.Equal(t, rules, cfg.deprecations.applied)
		require.NoError(t, cfg.Validate())
	})

	t.Run("top-level conf.Unmarshal invokes Config.Unmarshal with active registry", func(t *testing.T) {
		saved := deprecatedConfigKeys
		deprecatedConfigKeys = []deprecatedConfigKey{testRenameRule, testRemoveRule}
		t.Cleanup(func() { deprecatedConfigKeys = saved })

		conf := confmap.NewFromStringMap(map[string]any{
			"project":     "my-project",
			"dataset":     "otel",
			"legacy_flag": true,
			"write":       map[string]any{"legacy_pool_size": 4, "connection_pool_size": 4},
		})
		cfg := createDefaultConfig().(*Config)
		require.NoError(t, conf.Unmarshal(cfg))

		assert.Equal(t, 4, cfg.Write.StreamPoolSize)
		require.NotNil(t, cfg.deprecations)
		assert.Equal(t, []deprecatedConfigKey{testRenameRule, testRemoveRule}, cfg.deprecations.applied)
		require.NoError(t, cfg.Validate())
	})
}

// TestConfigUnmarshalPreservesExpandedEnvValues verifies that ${env:...}
// expansions whose raw string looks like a YAML int ("123456") or bool
// ("true") preserve confmap's internal ExpandedValue wrapper when moved from
// a deprecated key to a string or configopaque.String field.
func TestConfigUnmarshalPreservesExpandedEnvValues(t *testing.T) {
	inputYAML := strings.Join([]string{
		"project: my-project",
		"dataset: otel",
		"credentials:",
		"  legacy_quota_project: ${env:TEST_NUMERIC_QUOTA_PROJ}",
		"  legacy_json: ${env:TEST_OPAQUE_SECRET}",
		"logs:",
		"  legacy_insert_id_attribute: ${env:TEST_BOOL_INSERT_ATTR}",
		"write:",
		"  legacy_pool_size: ${env:TEST_POOL_SIZE}",
		"  connection_pool_size: 4",
	}, "\n")

	envValues := map[string]string{
		"TEST_NUMERIC_QUOTA_PROJ": "123456",
		"TEST_OPAQUE_SECRET":      "987654",
		"TEST_BOOL_INSERT_ATTR":   "true",
		"TEST_POOL_SIZE":          "4",
	}

	inputProvider := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &staticYAMLProvider{scheme: "input", RetrieveFunc: func(context.Context, string, confmap.WatcherFunc) (*confmap.Retrieved, error) {
			return confmap.NewRetrievedFromYAML([]byte(inputYAML))
		}}
	})
	envProvider := confmap.NewProviderFactory(func(confmap.ProviderSettings) confmap.Provider {
		return &staticYAMLProvider{scheme: "env", RetrieveFunc: func(_ context.Context, uri string, _ confmap.WatcherFunc) (*confmap.Retrieved, error) {
			name := strings.TrimPrefix(uri, "env:")
			return confmap.NewRetrievedFromYAML([]byte(envValues[name]))
		}}
	})

	resolver, err := confmap.NewResolver(confmap.ResolverSettings{
		URIs:              []string{"input:collector.yaml"},
		ProviderFactories: []confmap.ProviderFactory{inputProvider, envProvider},
		DefaultScheme:     "env",
	})
	require.NoError(t, err)
	conf, err := resolver.Resolve(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() { _ = resolver.Shutdown(context.Background()) })

	rules := []deprecatedConfigKey{
		{
			OldPath:         "credentials.legacy_quota_project",
			NewPath:         "credentials.quota_project",
			DeprecatedIn:    "v0.0.4",
			RemovalEarliest: "v0.0.6",
			Anchor:          "a",
		},
		{
			OldPath:         "credentials.legacy_json",
			NewPath:         "credentials.json",
			DeprecatedIn:    "v0.0.4",
			RemovalEarliest: "v0.0.6",
			Anchor:          "b",
		},
		{
			OldPath:         "logs.legacy_insert_id_attribute",
			NewPath:         "logs.insert_id_attribute",
			DeprecatedIn:    "v0.0.4",
			RemovalEarliest: "v0.0.6",
			Anchor:          "c",
		},
		testRenameRule,
	}

	cfg := createDefaultConfig().(*Config)
	require.NoError(t, cfg.unmarshalWithDeprecations(conf, rules))
	assert.Equal(t, "123456", cfg.Credentials.QuotaProject)
	assert.Equal(t, configopaque.String("987654"), cfg.Credentials.JSON)
	assert.Equal(t, "true", cfg.Logs.InsertIDAttribute)
	assert.Equal(t, 4, cfg.Write.StreamPoolSize)
	require.NotNil(t, cfg.deprecations)
	assert.Equal(t, rules, cfg.deprecations.applied)
}

type staticYAMLProvider struct {
	scheme       string
	RetrieveFunc func(context.Context, string, confmap.WatcherFunc) (*confmap.Retrieved, error)
}

func (p *staticYAMLProvider) Retrieve(ctx context.Context, uri string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	return p.RetrieveFunc(ctx, uri, watcher)
}

func (p *staticYAMLProvider) Scheme() string { return p.scheme }

func (p *staticYAMLProvider) Shutdown(context.Context) error { return nil }

func TestConfigUnmarshalWithoutDeprecatedKeys(t *testing.T) {
	t.Run("plain configuration decodes through Unmarshal", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project": "my-project",
			"dataset": "otel",
			"write":   map[string]any{"stream_pool_size": 2},
		})
		cfg := createDefaultConfig().(*Config)
		require.NoError(t, conf.Unmarshal(cfg))
		assert.Equal(t, 2, cfg.Write.StreamPoolSize)
		assert.Nil(t, cfg.deprecations, "nothing to warn about")
	})
	t.Run("unknown keys are still rejected", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project": "my-project",
			"dataset": "otel",
			"write":   map[string]any{"legacy_pool_size": 4},
		})
		cfg := createDefaultConfig().(*Config)
		err := conf.Unmarshal(cfg)
		require.Error(t, err)
		assert.ErrorContains(t, err, "legacy_pool_size")
	})
	t.Run("conflicting keys fail Unmarshal", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"write": map[string]any{"legacy_pool_size": 4, "stream_pool_size": 3},
		})
		cfg := createDefaultConfig().(*Config)
		err := cfg.unmarshalWithDeprecations(conf, []deprecatedConfigKey{testRenameRule})
		require.Error(t, err)
		assert.ErrorContains(t, err, "both are set")

		blockConflict := confmap.NewFromStringMap(map[string]any{
			"legacy_keepalive": map[string]any{"time": "30s"},
			"write":            map[string]any{"keepalive": map[string]any{"timeout": "5s"}},
		})
		err = cfg.unmarshalWithDeprecations(blockConflict, []deprecatedConfigKey{testBlockRule})
		require.Error(t, err)
		assert.ErrorContains(t, err, "both are set")
	})
	t.Run("nil Conf is a no-op and clears stale deprecations", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		cfg.deprecations = &configDeprecations{applied: []deprecatedConfigKey{testRenameRule}}
		require.NoError(t, cfg.Unmarshal(nil))
		assert.Nil(t, cfg.deprecations)
	})
	t.Run("re-unmarshaling a clean configuration clears stale deprecations", func(t *testing.T) {
		cfg := createDefaultConfig().(*Config)
		first := confmap.NewFromStringMap(map[string]any{
			"project": "my-project",
			"dataset": "otel",
			"write":   map[string]any{"legacy_pool_size": 4},
		})
		require.NoError(t, cfg.unmarshalWithDeprecations(first, []deprecatedConfigKey{testRenameRule}))
		require.NotNil(t, cfg.deprecations)

		clean := confmap.NewFromStringMap(map[string]any{
			"project": "my-project",
			"dataset": "otel",
			"write":   map[string]any{"stream_pool_size": 2},
		})
		require.NoError(t, cfg.unmarshalWithDeprecations(clean, []deprecatedConfigKey{testRenameRule}))
		assert.Equal(t, 2, cfg.Write.StreamPoolSize)
		assert.Nil(t, cfg.deprecations, "stale deprecations must not survive re-unmarshal")
	})
	t.Run("caller Conf is not mutated across repeated Unmarshal calls", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project": "my-project",
			"dataset": "otel",
			"write":   map[string]any{"legacy_pool_size": 4},
		})
		cfg1 := createDefaultConfig().(*Config)
		require.NoError(t, cfg1.unmarshalWithDeprecations(conf, []deprecatedConfigKey{testRenameRule}))
		assert.Equal(t, 4, cfg1.Write.StreamPoolSize)
		require.NotNil(t, cfg1.deprecations)

		cfg2 := createDefaultConfig().(*Config)
		require.NoError(t, cfg2.unmarshalWithDeprecations(conf, []deprecatedConfigKey{testRenameRule}))
		assert.Equal(t, 4, cfg2.Write.StreamPoolSize)
		require.NotNil(t, cfg2.deprecations)
		assert.Equal(t, cfg1.deprecations.applied, cfg2.deprecations.applied)
	})
	t.Run("invalid scalar parent is not masked by a deprecated rename", func(t *testing.T) {
		topToNested := deprecatedConfigKey{
			OldPath:         "legacy_pool_size",
			NewPath:         "write.stream_pool_size",
			DeprecatedIn:    "v0.0.4",
			RemovalEarliest: "v0.0.6",
			Anchor:          "a",
		}
		conf := confmap.NewFromStringMap(map[string]any{
			"project":          "my-project",
			"dataset":          "otel",
			"legacy_pool_size": 4,
			"write":            "not-a-map",
		})
		cfg := createDefaultConfig().(*Config)
		err := cfg.unmarshalWithDeprecations(conf, []deprecatedConfigKey{topToNested})
		require.Error(t, err)
		assert.ErrorContains(t, err, "write")
		assert.Nil(t, cfg.deprecations)
	})
	t.Run("null deprecated value matches confmap nil decoding and records warning", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project":          "my-project",
			"dataset":          "otel",
			"legacy_keepalive": nil,
			"write":            map[string]any{"legacy_pool_size": nil},
		})
		cfg := createDefaultConfig().(*Config)
		cfg.Write.Keepalive.Time = 15 * time.Second
		rules := []deprecatedConfigKey{testRenameRule, testBlockRule}
		require.NoError(t, cfg.unmarshalWithDeprecations(conf, rules))
		assert.Equal(t, 0, cfg.Write.StreamPoolSize, "DecodeNil zeroes an explicit nil scalar just like write.stream_pool_size: nil")
		assert.Equal(t, 15*time.Second, cfg.Write.Keepalive.Time, "nil block section leaves struct defaults intact")
		require.NotNil(t, cfg.deprecations)
		assert.Equal(t, rules, cfg.deprecations.applied)
	})
	t.Run("unknown key inside a deprecated block is rejected", func(t *testing.T) {
		conf := confmap.NewFromStringMap(map[string]any{
			"project":          "my-project",
			"dataset":          "otel",
			"legacy_keepalive": map[string]any{"no_such_keepalive_knob": true},
		})
		cfg := createDefaultConfig().(*Config)
		err := cfg.unmarshalWithDeprecations(conf, []deprecatedConfigKey{testBlockRule})
		require.Error(t, err)
		assert.ErrorContains(t, err, "no_such_keepalive_knob")
	})
}

func TestLogConfigDeprecations(t *testing.T) {
	newLogger := func() (*zap.Logger, *observer.ObservedLogs) {
		core, logs := observer.New(zapcore.DebugLevel)
		return zap.New(core), logs
	}
	fieldsOf := func(e observer.LoggedEntry) map[string]any {
		return e.ContextMap()
	}

	t.Run("nothing applied logs nothing", func(t *testing.T) {
		logger, logs := newLogger()
		logConfigDeprecations(logger, &Config{})
		logConfigDeprecations(logger, nil)
		logConfigDeprecations(nil, &Config{deprecations: &configDeprecations{applied: []deprecatedConfigKey{testRenameRule}}})
		assert.Equal(t, 0, logs.Len())
	})

	t.Run("one warning per key, once per configuration", func(t *testing.T) {
		logger, logs := newLogger()
		cfg := &Config{deprecations: &configDeprecations{applied: []deprecatedConfigKey{testRenameRule, testRemoveRule}}}

		logConfigDeprecations(logger, cfg)
		logConfigDeprecations(logger, cfg)
		logConfigDeprecations(logger, cfg)

		entries := logs.All()
		require.Len(t, entries, 2, "second and third calls must not log again")

		rename := entries[0]
		assert.Equal(t, zapcore.WarnLevel, rename.Level)
		assert.Contains(t, rename.Message, `"write.legacy_pool_size" is deprecated`)
		assert.Contains(t, rename.Message, `applied to "write.stream_pool_size"`)
		assert.Contains(t, rename.Message, migrationGuideURL+"#"+testRenameRule.Anchor)
		assert.Equal(t, map[string]any{
			"deprecated_key":   "write.legacy_pool_size",
			"replacement_key":  "write.stream_pool_size",
			"deprecated_in":    "v0.0.4",
			"removal_earliest": "v0.0.6",
			"migration_guide":  "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/main/docs/migration.md#writelegacy_pool_size--writestream_pool_size-deprecated-in-v004",
		}, fieldsOf(rename))

		removed := entries[1]
		assert.Equal(t, zapcore.WarnLevel, removed.Level)
		assert.Contains(t, removed.Message, `"legacy_flag" is deprecated and has no effect`)
		fields := fieldsOf(removed)
		assert.NotContains(t, fields, "replacement_key")
		assert.Equal(t, "legacy_flag", fields["deprecated_key"])
		assert.Equal(t, migrationGuideURL+"#"+testRemoveRule.Anchor, fields["migration_guide"])
	})

	t.Run("signal exporters sharing a configuration warn once", func(t *testing.T) {
		logger, logs := newLogger()
		set := componenttest.NewNopTelemetrySettings()
		set.Logger = logger

		cfg := createDefaultConfig().(*Config)
		cfg.Project = "my-project"
		cfg.Dataset = "otel"
		cfg.deprecations = &configDeprecations{applied: []deprecatedConfigKey{testRenameRule}}

		_, err := newTracesExporter(set, cfg)
		require.NoError(t, err)
		_, err = newLogsExporter(set, cfg)
		require.NoError(t, err)
		_, err = newMetricsExporter(set, cfg)
		require.NoError(t, err)

		warnings := logs.FilterLevelExact(zapcore.WarnLevel).FilterFieldKey("deprecated_key")
		assert.Equal(t, 1, warnings.Len())
	})
}

func TestValidateDeprecationRules(t *testing.T) {
	valid := testRenameRule
	tests := []struct {
		name    string
		mutate  func(r *deprecatedConfigKey)
		rules   []deprecatedConfigKey
		wantErr string
	}{
		{name: "valid rename", mutate: func(*deprecatedConfigKey) {}},
		{name: "valid removal", mutate: func(r *deprecatedConfigKey) { r.NewPath = "" }},
		{name: "valid across minor releases", mutate: func(r *deprecatedConfigKey) { r.DeprecatedIn = "v0.170.0"; r.RemovalEarliest = "v0.172.0" }},
		{name: "valid across a major release", mutate: func(r *deprecatedConfigKey) { r.DeprecatedIn = "v0.0.9"; r.RemovalEarliest = "v1.0.0" }},
		{name: "empty old path", mutate: func(r *deprecatedConfigKey) { r.OldPath = "" }, wantErr: "OldPath must be a dotted key"},
		{name: "upper-case old path", mutate: func(r *deprecatedConfigKey) { r.OldPath = "Write.Pool" }, wantErr: "OldPath must be a dotted key"},
		{name: "confmap delimiter in old path", mutate: func(r *deprecatedConfigKey) { r.OldPath = "write::pool" }, wantErr: "OldPath must be a dotted key"},
		{name: "bad new path", mutate: func(r *deprecatedConfigKey) { r.NewPath = "write.Pool-Size" }, wantErr: "NewPath"},
		{name: "same old and new", mutate: func(r *deprecatedConfigKey) { r.NewPath = r.OldPath }, wantErr: "NewPath must differ"},
		{name: "bad anchor", mutate: func(r *deprecatedConfigKey) { r.Anchor = "#Has Spaces" }, wantErr: "Anchor"},
		{name: "empty anchor", mutate: func(r *deprecatedConfigKey) { r.Anchor = "" }, wantErr: "Anchor"},
		{name: "bad deprecated release", mutate: func(r *deprecatedConfigKey) { r.DeprecatedIn = "0.0.4" }, wantErr: "DeprecatedIn"},
		{name: "bad removal release", mutate: func(r *deprecatedConfigKey) { r.RemovalEarliest = "v0.0" }, wantErr: "RemovalEarliest"},
		{name: "removal one release later", mutate: func(r *deprecatedConfigKey) { r.RemovalEarliest = "v0.0.5" }, wantErr: "at least 2 required"},
		{name: "removal same release", mutate: func(r *deprecatedConfigKey) { r.RemovalEarliest = "v0.0.4" }, wantErr: "at least 2 required"},
		{name: "removal before deprecation", mutate: func(r *deprecatedConfigKey) { r.RemovalEarliest = "v0.0.3" }, wantErr: "precedes"},
		{name: "removal one minor later", mutate: func(r *deprecatedConfigKey) { r.DeprecatedIn = "v0.170.0"; r.RemovalEarliest = "v0.171.0" }, wantErr: "at least 2 required"},
		{
			name:    "duplicate old path",
			rules:   []deprecatedConfigKey{valid, valid},
			wantErr: "listed twice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := tt.rules
			if rules == nil {
				r := valid
				tt.mutate(&r)
				rules = []deprecatedConfigKey{r}
			}
			err := validateDeprecationRules(rules)
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestNestedStringMap(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	root := reflect.ValueOf(cfg).Elem()

	timeoutField, err := lookupConfigField(root, "timeout")
	require.NoError(t, err)
	assert.Equal(t, cfg.TimeoutSettings.Timeout, timeoutField.Interface())

	poolField, err := lookupConfigField(root, "write.stream_pool_size")
	require.NoError(t, err)
	assert.Equal(t, cfg.Write.StreamPoolSize, poolField.Interface())

	_, err = lookupConfigField(root, "write.no_such_field")
	require.Error(t, err)
	assert.Equal(t, "write::keepalive::time", confmapKey("write.keepalive.time"))
}
