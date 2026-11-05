// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package contribcheck_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStagedContribTestbedSpec parses docs/upstream/contrib-testbed-staging.md,
// extracts every fenced Go code block, verifies each has the required copyright
// and SPDX license header, parses the AST with go/parser (zero syntax errors),
// and checks that the required symbols are declared in the appropriate blocks.
func TestStagedContribTestbedSpec(t *testing.T) {
	// Locate the staging doc relative to the repo root.
	stagingDoc := filepath.Join("..", "..", "docs", "upstream", "contrib-testbed-staging.md")

	// Allow override via environment variable for CI flexibility.
	if env := os.Getenv("CONTRIB_TESTBED_STAGING_DOC"); env != "" {
		stagingDoc = env
	}

	content, err := os.ReadFile(stagingDoc)
	require.NoError(t, err, "reading staging doc: %s", stagingDoc)

	blocks := extractGoBlocks(t, string(content))
	require.GreaterOrEqual(t, len(blocks), 2, "expected at least 2 Go code blocks (receiver + test file)")

	// --- License header check for every Go block ---
	for i, block := range blocks {
		assert.True(t,
			strings.Contains(block.src, "// Copyright 2026 Google LLC"),
			"block %d (%s): missing '// Copyright 2026 Google LLC' header", i, block.label,
		)
		assert.True(t,
			strings.Contains(block.src, "// SPDX-License-Identifier: Apache-2.0"),
			"block %d (%s): missing '// SPDX-License-Identifier: Apache-2.0' header", i, block.label,
		)
	}

	// --- AST parse check for every Go block (zero syntax errors) ---
	fset := token.NewFileSet()
	for i, block := range blocks {
		f, err := parser.ParseFile(fset, block.filename, block.src, parser.AllErrors)
		if !assert.NoError(t, err, "block %d (%s): AST parse failed", i, block.label) {
			continue
		}
		require.NotNil(t, f, "block %d (%s): parsed file is nil", i, block.label)

		// --- Ban /internal/ imports from BQ-OTEL-Exporter ---
		// Go forbids importing packages under /internal/ from outside
		// the parent module. The opentelemetry-collector-contrib/testbed
		// module must not import any BQ-OTEL-Exporter/internal/ path.
		for _, imp := range f.Imports {
			importPath := strings.Trim(imp.Path.Value, `"`)
			assert.False(t,
				strings.Contains(importPath, "GoogleCloudPlatform/BQ-OTEL-Exporter/internal"),
				"block %d (%s): import %q is from BQ-OTEL-Exporter/internal — Go forbids /internal/ imports from external modules",
				i, block.label, importPath,
			)
		}

		// Collect all declared top-level identifiers.
		declaredSyms := collectDeclarations(f)

		switch block.label {
		case "receiver":
			require.Contains(t, declaredSyms, "bigQueryDataReceiver",
				"receiver block must declare bigQueryDataReceiver type; got: %v", declaredSyms)
			require.Contains(t, declaredSyms, "NewBigQueryDataReceiver",
				"receiver block must declare NewBigQueryDataReceiver constructor")
			require.Contains(t, declaredSyms, "ProtocolName",
				"receiver block must implement ProtocolName method")
			require.Contains(t, declaredSyms, "GenConfigYAMLStr",
				"receiver block must implement GenConfigYAMLStr method")
			require.Contains(t, declaredSyms, "Start",
				"receiver block must implement Start method")
			require.Contains(t, declaredSyms, "Stop",
				"receiver block must implement Stop method")
			require.Contains(t, declaredSyms, "DataItemsReceived",
				"receiver block must implement DataItemsReceived method")

		case "test":
			require.Contains(t, declaredSyms, "TestTrace10kSPSBigQueryExporter",
				"test block must declare TestTrace10kSPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestLog10kDPSBigQueryExporter",
				"test block must declare TestLog10kDPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestMetric10kDPSBigQueryExporter",
				"test block must declare TestMetric10kDPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestBigQueryExporterDataIntegrity",
				"test block must declare TestBigQueryExporterDataIntegrity function")
		}
	}

	// --- Required symbols across all blocks ---
	allSyms := make(map[string]bool)
	for _, block := range blocks {
		f, err := parser.ParseFile(fset, block.filename, block.src, parser.AllErrors)
		if err != nil {
			continue
		}
		for sym := range collectDeclarations(f) {
			allSyms[sym] = true
		}
	}

	requiredSymbols := []string{
		"NewBigQueryDataReceiver",
		"bigQueryDataReceiver",
		"TestTrace10kSPSBigQueryExporter",
		"TestLog10kDPSBigQueryExporter",
		"TestMetric10kDPSBigQueryExporter",
		"TestBigQueryExporterDataIntegrity",
	}
	for _, sym := range requiredSymbols {
		assert.True(t, allSyms[sym],
			"required symbol %q not found in any Go block", sym)
	}
}

// codeBlock holds an extracted Go code block from the markdown.
type codeBlock struct {
	label    string // heuristic label for the block
	filename string // synthetic filename for AST parser
	src      string // raw Go source
}

// extractGoBlocks finds all ```go fenced code blocks in the markdown
// content and returns them with descriptive labels.
func extractGoBlocks(t *testing.T, content string) []codeBlock {
	t.Helper()

	var blocks []codeBlock
	lines := strings.Split(content, "\n")

	inBlock := false
	var blockLines []string
	var blockStartLine int

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !inBlock && strings.HasPrefix(trimmed, "```go") {
			inBlock = true
			blockStartLine = i + 1
			blockLines = nil
			continue
		}

		if inBlock && trimmed == "```" {
			inBlock = false
			src := strings.Join(blockLines, "\n")

			// Only include blocks that have a Go package declaration.
			if strings.Contains(src, "package ") {
				blocks = append(blocks, codeBlock{
					label:    labelForBlock(src, blockStartLine),
					filename: "block_" + strconv.Itoa(len(blocks)) + ".go",
					src:      src,
				})
			}
			continue
		}

		if inBlock {
			blockLines = append(blockLines, line)
		}
	}

	require.False(t, inBlock, "unterminated code block starting at line %d", blockStartLine)
	return blocks
}

// labelForBlock returns a heuristic label for a Go code block based on
// its content. This is used to apply block-specific symbol assertions.
func labelForBlock(src string, startLine int) string {
	switch {
	case strings.Contains(src, "package bigquerydatareceiver"):
		return "receiver"
	case strings.Contains(src, "package tests"):
		return "test"
	case strings.Contains(src, "package main"):
		return "main"
	default:
		return "block@" + strconv.Itoa(startLine)
	}
}

// collectDeclarations walks the AST and returns a set of all top-level
// declared identifiers (types, functions, methods, vars, consts).
func collectDeclarations(f *ast.File) map[string]bool {
	syms := make(map[string]bool)
	ast.Inspect(f, func(n ast.Node) bool {
		switch decl := n.(type) {
		case *ast.FuncDecl:
			syms[decl.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch vs := spec.(type) {
				case *ast.TypeSpec:
					syms[vs.Name.Name] = true
				case *ast.ValueSpec:
					for _, name := range vs.Names {
						syms[name.Name] = true
					}
				}
			}
		}
		return true
	})
	return syms
}
