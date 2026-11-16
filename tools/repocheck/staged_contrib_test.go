// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

// TestStagedContribReadmesLinkDocumentationAndReferenceValidKeys verifies that
// every staged collector-contrib README in docs/upstream/ links the
// configuration inventory, migration guide, and cost-estimation guide,
// documents known limitations and feature-gate status, and references only
// valid Config keys outside fenced code blocks.
func TestStagedContribReadmesLinkDocumentationAndReferenceValidKeys(t *testing.T) {
	live := exporterKeySet()
	sharedTopics := []string{
		"\n## Known limitations and misuse\n",
		"\n## Feature gates\n",
		"no component-specific feature gates",
		"pkg.exporterhelper.queueBatchEnabled",
		"_dedup",
		"sending_queue.storage",
		"quarantine.enabled",
		"write.stream_pool_size",
		"write.max_request_bytes",
		"auto_create",
		"endpoint.without_authentication",
		"docs/cost-estimation.md",
		"redaction.enabled",
	}

	const (
		contribMigrationURL = "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/migration.md"
		contribInventoryURL = "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/config-inventory.md"
		contribCostURL      = "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/cost-estimation.md"
	)

	stagedDocs := []struct {
		rel     string
		wantPRs int
	}{
		{rel: "docs/upstream/contrib-pr-staging.md", wantPRs: 2},
		{rel: "docs/upstream/contrib-alpha-and-releases.md", wantPRs: 1},
	}

	totalStagedReadmes := 0
	for _, doc := range stagedDocs {
		blocks := extractStagedContribReadmes(docsNormalizeEOL(testsupport.ReadRepoText(t, doc.rel)))
		require.Lenf(t, blocks, doc.wantPRs, "%s must contain %d staged exporter/bigqueryexporter/README.md blocks", doc.rel, doc.wantPRs)
		for i, body := range blocks {
			totalStagedReadmes++
			for _, want := range append([]string{
				contribMigrationURL,
				contribInventoryURL,
				contribCostURL,
			}, sharedTopics...) {
				assert.Containsf(t, body, want, "%s staged README #%d must include %q", doc.rel, i+1, want)
			}
			label := fmt.Sprintf("%s#readme-%d", doc.rel, i+1)
			for _, err := range checkDocumentedConfigKeys(live, label, body) {
				assert.NoError(t, err)
			}
		}
	}
	assert.Equal(t, 3, totalStagedReadmes)

	// Verify Windows CRLF (\r\n) and lone CR (\r) normalization across both
	// extractStagedContribReadmes and checkDocumentedConfigKeys, and confirm
	// that checkDocumentedConfigKeys rejects invalid dotted config keys.
	badDoc := strings.Join([]string{
		"Valid keys: `limits.max_attribute_count`, `write.max_row_bytes`, `limits.*`, `write.keepalive.*`, `sending_queue.storage`, `bigquery.tables.get`, `docs/config-inventory.md`, `cfg.Validate()`.",
		"```yaml",
		"# Fenced snippets are checked by confmap tests, not prose key scanning:",
		"limits.max_attributes: 10",
		"```",
		"Bad keys in prose: `limits.max_attributes`, `limits.max_row_bytes`, `redaction.redact_prompts`, `limits.unknown.*`, `limits.max_*.foo`.",
	}, "\n")
	errs := checkDocumentedConfigKeys(live, "mutant.md", badDoc)
	require.Len(t, errs, 5, "expected all 5 invalid dotted config tokens outside code fences to fail: %v", errs)
	joined := errors.Join(errs...).Error()
	for _, bad := range []string{
		"limits.max_attributes",
		"limits.max_row_bytes",
		"redaction.redact_prompts",
		"limits.unknown.*",
		"limits.max_*.foo",
	} {
		assert.Contains(t, joined, bad)
	}

	stagedCRLFRaw := "<!-- contribcheck:file pr=1 path=exporter/bigqueryexporter/README.md -->\r\n" +
		"````markdown\r\n" +
		"# Header\r\n" +
		"\r\n" +
		"Valid: `redaction.redact_log_body`.\r\n" +
		"\r\n" +
		"## Feature gates\r\r" +
		"Uses `sending_queue.batch`.\r\n" +
		"````\r\n"
	blocks := extractStagedContribReadmes(stagedCRLFRaw)
	require.Len(t, blocks, 1)
	assert.Contains(t, blocks[0], "\n## Feature gates\n")
	assert.NotContains(t, blocks[0], "\r")
	assert.Empty(t, checkDocumentedConfigKeys(live, "crlf.md", blocks[0]))
}

var (
	inlineCodeSpanPattern = regexp.MustCompile("`([^`]+)`")
	dottedKeyTokenPattern = regexp.MustCompile(`(?:^|[^A-Za-z0-9_./-])([a-z][a-z0-9_]*(?:\.[a-z0-9_*]+)+)`)
)

func checkDocumentedConfigKeys(live map[string]bool, docName, markdown string) []error {
	topBlocks := make(map[string]struct{})
	for path := range live {
		if top, _, ok := strings.Cut(path, "."); ok {
			topBlocks[top] = struct{}{}
		}
	}

	var (
		errs     []error
		fenceLen int
	)
	for lineIdx, line := range strings.Split(docsNormalizeEOL(markdown), "\n") {
		trimmed := strings.TrimSpace(line)
		runLen := leadingBackticks(trimmed)
		if fenceLen == 0 {
			if runLen >= 3 {
				fenceLen = runLen
				continue
			}
		} else {
			if runLen >= fenceLen && strings.TrimSpace(trimmed[runLen:]) == "" {
				fenceLen = 0
			}
			continue
		}

		for _, span := range inlineCodeSpanPattern.FindAllStringSubmatch(line, -1) {
			content := span[1]
			for _, idx := range dottedKeyTokenPattern.FindAllStringSubmatchIndex(content, -1) {
				tok := content[idx[2]:idx[3]]
				rest := content[idx[3]:]
				if strings.HasPrefix(rest, "/") || strings.HasPrefix(strings.TrimLeft(rest, " \t"), "(") {
					continue
				}
				top, _, _ := strings.Cut(tok, ".")
				if _, isConfigBlock := topBlocks[top]; !isConfigBlock {
					continue
				}
				if !isValidDocumentedConfigToken(live, tok) {
					errs = append(errs, fmt.Errorf("%s:%d: documented config key %q is not declared in Config", docName, lineIdx+1, tok))
				}
			}
		}
	}
	return errs
}

func isValidDocumentedConfigToken(live map[string]bool, tok string) bool {
	if stem, ok := strings.CutSuffix(tok, ".*"); ok {
		if strings.Contains(stem, "*") {
			return false
		}
		prefix := stem + "."
		for path := range live {
			if strings.HasPrefix(path, prefix) {
				return true
			}
		}
		return false
	}
	if strings.Contains(tok, "*") {
		return false
	}
	if live[tok] {
		return true
	}
	prefix := tok + "."
	for k := range live {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

func leadingBackticks(s string) int {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	return n
}

func extractStagedContribReadmes(doc string) []string {
	const markerPrefix = "<!-- contribcheck:file "
	const targetSuffix = "path=exporter/bigqueryexporter/README.md -->"
	var out []string
	lines := strings.Split(docsNormalizeEOL(doc), "\n")
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, markerPrefix) || !strings.HasSuffix(trimmed, targetSuffix) {
			continue
		}
		if i+1 >= len(lines) {
			break
		}
		fence := strings.TrimSpace(lines[i+1])
		runLen := leadingBackticks(fence)
		if runLen < 3 {
			continue
		}
		closing := strings.Repeat("`", runLen)
		var buf strings.Builder
		for j := i + 2; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == closing {
				i = j
				break
			}
			buf.WriteString(lines[j])
			buf.WriteByte('\n')
		}
		out = append(out, buf.String())
	}
	return out
}
