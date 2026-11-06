// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package contribcheck_test

import (
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"

	bqotel "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
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
			strings.Contains(block.src, "// Copyright The OpenTelemetry Authors"),
			"block %d (%s): missing '// Copyright The OpenTelemetry Authors' header", i, block.label,
		)
		assert.True(t,
			strings.Contains(block.src, "// SPDX-License-Identifier: Apache-2.0"),
			"block %d (%s): missing '// SPDX-License-Identifier: Apache-2.0' header", i, block.label,
		)
	}

	// --- AST parse and gofmt check for every Go block ---
	fset := token.NewFileSet()
	for i, block := range blocks {
		formatted, fmtErr := format.Source([]byte(block.src))
		if assert.NoError(t, fmtErr, "block %d (%s): gofmt failed", i, block.label) {
			assert.Equal(t, string(formatted), block.src+"\n",
				"block %d (%s): Go code block is not gofmt-formatted", i, block.label)
		}

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
			require.Contains(t, declaredSyms, "RowCount",
				"receiver block must implement RowCount helper")
			assert.False(t, declaredSyms["DataItemsReceived"],
				"receiver block must not declare custom DataItemsReceived; forward rows to MockBackend consumers instead")
			assert.Contains(t, block.src, "var _ testbed.DataReceiver = (*bigQueryDataReceiver)(nil)",
				"receiver block must assert testbed.DataReceiver interface compliance")
			assert.Contains(t, block.src, "storagepb.UnimplementedBigQueryWriteServer",
				"receiver block must embed storagepb.UnimplementedBigQueryWriteServer")
			assert.Contains(t, block.src, `"go.opentelemetry.io/collector/pdata/ptrace"`,
				"receiver block must import pdata/ptrace to forward span rows")
			assert.Contains(t, block.src, `"go.opentelemetry.io/collector/pdata/plog"`,
				"receiver block must import pdata/plog to forward log rows")
			assert.Contains(t, block.src, `"go.opentelemetry.io/collector/pdata/pmetric"`,
				"receiver block must import pdata/pmetric to forward metric rows")
			assert.Contains(t, block.src, "r.tc.ConsumeTraces",
				"AppendRows must forward trace rows to r.tc.ConsumeTraces")
			assert.Contains(t, block.src, "r.lc.ConsumeLogs",
				"AppendRows must forward log rows to r.lc.ConsumeLogs")
			assert.Contains(t, block.src, "r.mc.ConsumeMetrics",
				"AppendRows must forward metric rows to r.mc.ConsumeMetrics")
			assert.NotContains(t, block.src, "r.lis.Addr()",
				"GenConfigYAMLStr must not dereference r.lis before Start")
			assert.Contains(t, block.src, `fmt.Sprintf("127.0.0.1:%d", r.Port)`,
				"GenConfigYAMLStr must format loopback endpoint from r.Port")
			assert.NotContains(t, block.src, "google.golang.org/grpc/credentials/insecure",
				"receiver block must not import unused google.golang.org/grpc/credentials/insecure")

		case "test":
			require.Contains(t, declaredSyms, "TestTrace10kSPSBigQueryExporter",
				"test block must declare TestTrace10kSPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestLog10kDPSBigQueryExporter",
				"test block must declare TestLog10kDPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestMetric10kDPSBigQueryExporter",
				"test block must declare TestMetric10kDPSBigQueryExporter function")
			require.Contains(t, declaredSyms, "TestBigQueryExporterDataIntegrity",
				"test block must declare TestBigQueryExporterDataIntegrity function")
			assert.Contains(t, block.src, "testbed.NewOTLPMetricDataSender",
				"test block must call testbed.NewOTLPMetricDataSender (singular)")
			assert.NotContains(t, block.src, "NewOTLPMetricsDataSender",
				"test block must not call nonexistent NewOTLPMetricsDataSender")
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
	normalized := strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")

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

// TestStagedTestbedReceiverGenConfigValidates extracts the YAML template from
// GenConfigYAMLStr() in docs/upstream/contrib-testbed-staging.md, substitutes a
// loopback test port, unmarshals it into bigqueryexporter.Config, and verifies
// Config.Validate() succeeds (preventing auto_create + without_authentication
// or invalid endpoint URL regressions). It also validates the architecture
// overview YAML snippet in the same document.
func TestStagedTestbedReceiverGenConfigValidates(t *testing.T) {
	stagingDoc := filepath.Join("..", "..", "docs", "upstream", "contrib-testbed-staging.md")
	if env := os.Getenv("CONTRIB_TESTBED_STAGING_DOC"); env != "" {
		stagingDoc = env
	}

	content, err := os.ReadFile(stagingDoc)
	require.NoError(t, err, "reading staging doc: %s", stagingDoc)

	blocks := extractGoBlocks(t, string(content))
	var receiverSrc string
	for _, b := range blocks {
		if b.label == "receiver" {
			receiverSrc = b.src
			break
		}
	}
	require.NotEmpty(t, receiverSrc, "receiver Go block not found in %s", stagingDoc)

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "receiver.go", receiverSrc, 0)
	require.NoError(t, err)

	var rawTmpl string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "GenConfigYAMLStr" {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			lit, ok := inner.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, unquoteErr := strconv.Unquote(lit.Value)
			if unquoteErr == nil && strings.Contains(s, "bigquery/testbed:") {
				rawTmpl = s
				return false
			}
			return true
		})
		return false
	})
	require.NotEmpty(t, rawTmpl, "GenConfigYAMLStr must contain the bigquery/testbed YAML template")
	require.Equal(t, 1, strings.Count(rawTmpl, "%s"), "GenConfigYAMLStr template must have exactly one %%s placeholder")

	renderedYAML := "exporters:" + strings.Replace(rawTmpl, "%s", "127.0.0.1:43210", 1)
	assertTestbedExporterYAMLValid(t, "GenConfigYAMLStr()", renderedYAML)

	// Validate every YAML block in the staging doc parses, and validate every
	// exporters.bigquery/testbed overview YAML snippet against Config.Validate().
	var overviewYAML string
	yamlBlocks := extractYAMLBlocks(t, string(content))
	yamlExamples := 0
	for idx, yamlStr := range yamlBlocks {
		var parsed any
		require.NoError(t, yaml.Unmarshal([]byte(yamlStr), &parsed), "yaml block %d: yaml.Unmarshal failed", idx)

		if strings.Contains(yamlStr, "bigquery/testbed:") {
			yamlExamples++
			candidate := strings.ReplaceAll(yamlStr, "<port>", "43210")
			assertTestbedExporterYAMLValid(t, "overview YAML snippet", candidate)
			if overviewYAML == "" {
				overviewYAML = candidate
			}
		}
	}
	require.GreaterOrEqual(t, yamlExamples, 1, "expected at least one bigquery/testbed YAML example in %s", stagingDoc)

	t.Run("negative_mutation_probes", func(t *testing.T) {
		probes := []struct {
			name    string
			from    string
			to      string
			wantErr string
		}{
			{
				name:    "auto_create_tables_true",
				from:    "tables: false",
				to:      "tables: true",
				wantErr: "auto_create.tables",
			},
			{
				name:    "non_loopback_endpoint_url",
				from:    "127.0.0.1:43210",
				to:      "bigquery.googleapis.com:443",
				wantErr: "loopback",
			},
			{
				name:    "auto_create_dataset_true",
				from:    "dataset: false",
				to:      "dataset: true",
				wantErr: "auto_create.dataset",
			},
			{
				name:    "endpoint_insecure_false",
				from:    "insecure: true",
				to:      "insecure: false",
				wantErr: "endpoint.insecure",
			},
		}

		sources := map[string]string{
			"GenConfigYAMLStr": renderedYAML,
			"overview_YAML":    overviewYAML,
		}
		for srcName, srcYAML := range sources {
			for _, probe := range probes {
				t.Run(srcName+"/"+probe.name, func(t *testing.T) {
					require.Contains(t, srcYAML, probe.from, "probe anchor %q missing in %s", probe.from, srcName)
					mutated := strings.Replace(srcYAML, probe.from, probe.to, 1)

					err := validateTestbedExporterYAML(srcName+"/"+probe.name, mutated)
					require.Error(t, err, "expected validateTestbedExporterYAML to reject %s mutation", probe.name)
					assert.ErrorContains(t, err, probe.wantErr)

					assertHelperFailsOnYAML(t, srcName+"/"+probe.name, mutated, probe.wantErr)
				})
			}
		}
	})
}

// TestExtractGoBlocksNormalizesCRLF verifies CRLF and lone-CR line endings are
// normalized to LF so extracted Go code blocks pass gofmt and AST checks.
func TestExtractGoBlocksNormalizesCRLF(t *testing.T) {
	stagingDoc := filepath.Join("..", "..", "docs", "upstream", "contrib-testbed-staging.md")
	if env := os.Getenv("CONTRIB_TESTBED_STAGING_DOC"); env != "" {
		stagingDoc = env
	}

	content, err := os.ReadFile(stagingDoc)
	require.NoError(t, err, "reading staging doc: %s", stagingDoc)

	lfContent := strings.ReplaceAll(strings.ReplaceAll(string(content), "\r\n", "\n"), "\r", "\n")
	wantBlocks := extractGoBlocks(t, lfContent)
	require.GreaterOrEqual(t, len(wantBlocks), 2)

	for _, tc := range []struct {
		name string
		eol  string
	}{
		{name: "crlf", eol: "\r\n"},
		{name: "lone_cr", eol: "\r"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			converted := strings.ReplaceAll(lfContent, "\n", tc.eol)
			gotBlocks := extractGoBlocks(t, converted)
			require.Equal(t, wantBlocks, gotBlocks)
			for i, b := range gotBlocks {
				assert.NotContains(t, b.src, "\r", "block %d (%s) retained carriage return", i, b.label)
			}
		})
	}
}

func extractYAMLBlocks(t *testing.T, content string) []string {
	t.Helper()

	normalized := strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(normalized, "\n")

	var blocks []string
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "```yaml" {
			continue
		}
		startLine := i + 1
		var body []string
		closed := false
		for i++; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == "```" {
				closed = true
				break
			}
			body = append(body, lines[i])
		}
		require.True(t, closed, "unterminated yaml code block starting at line %d", startLine)
		blocks = append(blocks, strings.Join(body, "\n"))
	}
	return blocks
}

func assertTestbedExporterYAMLValid(t require.TestingT, label, yamlStr string) {
	if h, ok := t.(interface{ Helper() }); ok {
		h.Helper()
	}
	require.NoError(t, validateTestbedExporterYAML(label, yamlStr))
}

func validateTestbedExporterYAML(label, yamlStr string) error {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(yamlStr), &doc); err != nil {
		return fmt.Errorf("%s: yaml.Unmarshal failed: %w", label, err)
	}

	exporters, ok := doc["exporters"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s: missing exporters map", label)
	}

	section, ok := exporters["bigquery/testbed"].(map[string]any)
	if !ok {
		return fmt.Errorf("%s: missing exporters.bigquery/testbed map", label)
	}

	cfg := bqotel.NewFactory().CreateDefaultConfig()
	if err := confmap.NewFromStringMap(section).Unmarshal(cfg); err != nil {
		return fmt.Errorf("%s: unmarshal into bigqueryexporter.Config: %w", label, err)
	}
	if err := confmap.Validate(cfg); err != nil {
		return fmt.Errorf("%s: confmap.Validate failed: %w", label, err)
	}

	bqCfg, ok := cfg.(*bqotel.Config)
	if !ok {
		return fmt.Errorf("%s: expected *bigqueryexporter.Config", label)
	}
	if err := bqCfg.Validate(); err != nil {
		return fmt.Errorf("%s: Config.Validate() failed: %w", label, err)
	}
	if bqCfg.Endpoint.URL != "127.0.0.1:43210" {
		return fmt.Errorf("%s: endpoint.url = %q; want %q", label, bqCfg.Endpoint.URL, "127.0.0.1:43210")
	}
	if !bqCfg.Endpoint.Insecure {
		return fmt.Errorf("%s: endpoint.insecure must be true", label)
	}
	if !bqCfg.Endpoint.WithoutAuthentication {
		return fmt.Errorf("%s: endpoint.without_authentication must be true", label)
	}
	if bqCfg.AutoCreate.Dataset {
		return fmt.Errorf("%s: auto_create.dataset must be false", label)
	}
	if bqCfg.AutoCreate.Tables {
		return fmt.Errorf("%s: auto_create.tables must be false", label)
	}
	return nil
}

type probeTestingT struct {
	failed bool
	msgs   []string
}

func (p *probeTestingT) Errorf(format string, args ...any) {
	p.failed = true
	p.msgs = append(p.msgs, fmt.Sprintf(format, args...))
}

func (p *probeTestingT) FailNow() {
	p.failed = true
	runtime.Goexit()
}

func assertHelperFailsOnYAML(t *testing.T, label, yamlStr, wantSubstr string) {
	t.Helper()

	probe := &probeTestingT{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		assertTestbedExporterYAMLValid(probe, label, yamlStr)
	}()
	<-done

	require.True(t, probe.failed, "expected assertTestbedExporterYAMLValid to fail on %s", label)
	assert.Contains(t, strings.Join(probe.msgs, "\n"), wantSubstr)
}
