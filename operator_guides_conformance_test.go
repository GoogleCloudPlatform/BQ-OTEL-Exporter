// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// operatorGuideFiles is the full set of files the conformance test expects.
var operatorGuideFiles = []string{
	"docs/operator-guides/README.md",
	"docs/operator-guides/quarantine-replay-and-dlq.md",
	"docs/operator-guides/schema-validation-and-backfill.md",
	"docs/operator-guides/load-testbench-and-sizing.md",
	"docs/operator-guides/ocb-otelcol-google-to-contrib-migration.md",
}

// cliFlagDoc maps each cmd/bq-* directory to the guide file that should
// document every flag its main.go defines.
var cliFlagDoc = map[string]string{
	"cmd/bq-quarantine-replay": "docs/operator-guides/quarantine-replay-and-dlq.md",
	"cmd/bq-otel-validate":     "docs/operator-guides/schema-validation-and-backfill.md",
	"cmd/bq-otel-backfill":     "docs/operator-guides/schema-validation-and-backfill.md",
	"cmd/bq-otel-testbench":    "docs/operator-guides/load-testbench-and-sizing.md",
}

// extractFlags parses the Go source of cmd/<dir>/main.go and returns the
// flag names defined via flag.NewFlagSet methods (fs.String, fs.Int, fs.Bool,
// fs.Float64, fs.Duration, fs.Var) and flag package equivalents.
func extractFlags(t *testing.T, dir string) []string {
	t.Helper()
	src := filepath.Join(dir, "main.go")
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}
	var flags []string
	flagMethods := map[string]bool{
		"String": true, "Int": true, "Bool": true,
		"Float64": true, "Duration": true, "Var": true,
		"StringVar": true, "IntVar": true, "BoolVar": true,
		"Float64Var": true, "DurationVar": true,
	}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		method := sel.Sel.Name
		if !flagMethods[method] {
			return true
		}
		// Methods ending in "Var" (StringVar, IntVar, BoolVar, etc.) take
		// the flag name as their SECOND argument; the first is a pointer.
		// Non-Var methods (String, Int, Bool, etc.) take the name first.
		nameIdx := 0
		if strings.HasSuffix(method, "Var") {
			nameIdx = 1
		}
		if len(call.Args) <= nameIdx {
			return true
		}
		lit, ok := call.Args[nameIdx].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name := strings.Trim(lit.Value, `"`)
		if name != "" {
			flags = append(flags, name)
		}
		return true
	})
	return flags
}

func TestOperatorGuidesExistAndNonEmpty(t *testing.T) {
	for _, path := range operatorGuideFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("missing operator guide: %s (%v)", path, err)
			continue
		}
		if len(strings.TrimSpace(string(raw))) == 0 {
			t.Errorf("operator guide is empty: %s", path)
		}
	}
}

func TestOperatorGuidesDocumentEveryCLIFlag(t *testing.T) {
	for dir, guide := range cliFlagDoc {
		flags := extractFlags(t, dir)
		if len(flags) == 0 {
			t.Fatalf("no flags found in %s/main.go", dir)
		}
		raw, err := os.ReadFile(guide)
		if err != nil {
			t.Fatalf("cannot read %s: %v", guide, err)
		}
		doc := string(raw)
		// Each flag should appear in the guide, either as `-flag` or
		// as `| `-flag` ` in a table or in a code block.
		missing := []string{}
		for _, flag := range flags {
			// Check for the flag name in the guide. We look for the bare
			// name (without the leading dash) since the guide might use
			// `-flag` or `--flag` in different contexts.
			needle := flag
			if !strings.Contains(doc, needle) {
				missing = append(missing, flag)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s/main.go defines flags not documented in %s: %v", dir, guide, missing)
		}
	}
}

func TestOperatorGuidesHaveNoBannedStrings(t *testing.T) {
	banned := []string{"google3/"}
	for _, path := range operatorGuideFiles {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, b := range banned {
			if strings.Contains(string(raw), b) {
				t.Errorf("%s contains banned string %q", path, b)
			}
		}
	}
}

func TestOperatorGuidesCollectorConfigsValidate(t *testing.T) {
	// Extract every YAML block tagged as yaml from the migration guide and
	// the runbooks, then verify any block containing an `exporters:` key
	// with a `bigquery:` sub-key unmarshals and has the expected fields.
	guide := "docs/operator-guides/ocb-otelcol-google-to-contrib-migration.md"
	raw, err := os.ReadFile(guide)
	if err != nil {
		t.Fatal(err)
	}
	// Find fenced yaml blocks
	yamlBlockRe := regexp.MustCompile("(?s)```yaml\\n(.*?)```")
	matches := yamlBlockRe.FindAllStringSubmatch(string(raw), -1)
	found := false
	for _, m := range matches {
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(m[1]), &doc); err != nil {
			continue // not a valid YAML map, skip (e.g. partial config)
		}
		exporters, ok := doc["exporters"]
		if !ok {
			continue
		}
		exportersMap, ok := exporters.(map[string]any)
		if !ok {
			continue
		}
		if _, hasBQ := exportersMap["bigquery"]; !hasBQ {
			continue
		}
		found = true
		// Verify the bigquery config has project and dataset fields (the
		// minimum required for the exporter to start).
		bqCfg, ok := exportersMap["bigquery"].(map[string]any)
		if !ok {
			t.Errorf("bigquery exporter config in %s is not a map", guide)
			continue
		}
		if _, ok := bqCfg["project"]; !ok {
			t.Errorf("bigquery exporter config in %s is missing 'project'", guide)
		}
		if _, ok := bqCfg["dataset"]; !ok {
			t.Errorf("bigquery exporter config in %s is missing 'dataset'", guide)
		}
	}
	if !found {
		t.Errorf("%s does not contain any valid exporters: bigquery: YAML block", guide)
	}
}
