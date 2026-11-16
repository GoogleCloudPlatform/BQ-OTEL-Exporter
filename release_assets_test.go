// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

func TestMetadataYAMLDeclaresGoleakIgnoreMatchingGeneratedPackageTest(t *testing.T) {
	var meta struct {
		Tests struct {
			SkipLifecycle bool `yaml:"skip_lifecycle"`
			Goleak        struct {
				Ignore struct {
					Top []string `yaml:"top"`
				} `yaml:"ignore"`
			} `yaml:"goleak"`
		} `yaml:"tests"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, "metadata.yaml")), &meta); err != nil {
		t.Fatalf("unmarshaling metadata.yaml: %v", err)
	}
	const wantOpenCensusTop = "go.opencensus.io/stats/view.(*worker).start"
	if !slices.Contains(meta.Tests.Goleak.Ignore.Top, wantOpenCensusTop) {
		t.Errorf("metadata.yaml tests.goleak.ignore.top = %v, want %q", meta.Tests.Goleak.Ignore.Top, wantOpenCensusTop)
	}

	genTest := testsupport.ReadRepoText(t, "generated_package_test.go")
	if !strings.Contains(genTest, `goleak.IgnoreTopFunction("`+wantOpenCensusTop+`")`) {
		t.Errorf("generated_package_test.go missing IgnoreTopFunction(%q)", wantOpenCensusTop)
	}
	if !strings.Contains(genTest, "integrationGoleakOptions()...") {
		t.Error("generated_package_test.go must chain integrationGoleakOptions() for build-tag-isolated unit and live integration runs")
	}
}
