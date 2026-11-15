// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// ParseYAMLMap decodes text as a non-empty YAML mapping and fails t on syntax
// errors or an empty document.
func ParseYAMLMap(t testing.TB, name, text string) map[string]any {
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

// YAMLPath returns the value at the given key path of a decoded YAML document,
// or nil when any step is missing.
func YAMLPath(doc any, keys ...string) any {
	for _, key := range keys {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[key]
	}
	return doc
}
