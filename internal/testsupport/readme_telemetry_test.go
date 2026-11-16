// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseReadmeSelfTelemetrySection(t *testing.T) {
	sample := strings.Join([]string{
		ReadmeSelfTelemetryIntroFull,
		"",
		"| Metric | Type | Unit | Attributes | Meaning |",
		"| --- | --- | --- | --- | --- |",
		"| `otelcol_exporter_bigquery_acknowledged_rows` | `Counter (int)` | `{row}` | `none` | Acknowledged rows. |",
		"| `otelcol_exporter_bigquery_retries` | `Counter (int)` | `{failure}` | `{class}` | Retryable failures. |",
		"",
		"Trailing note.",
		"",
		"### Next Heading",
		"Outside section.",
	}, "\n")

	sec, err := ParseReadmeSelfTelemetrySection(sample)
	require.NoError(t, err)
	require.Len(t, sec.Rows, 2)
	assert.Equal(t, ReadmeTelemetryRow{
		Metric:  "otelcol_exporter_bigquery_acknowledged_rows",
		Type:    "Counter (int)",
		Unit:    "{row}",
		Attrs:   nil,
		Meaning: "Acknowledged rows.",
	}, sec.Rows[0])
	assert.Equal(t, ReadmeTelemetryRow{
		Metric:  "otelcol_exporter_bigquery_retries",
		Type:    "Counter (int)",
		Unit:    "{failure}",
		Attrs:   []string{"class"},
		Meaning: "Retryable failures.",
	}, sec.Rows[1])
	assert.Equal(t, []string{"Trailing note."}, sec.Prose())

	// CRLF line endings must parse identically.
	crlfSec, err := ParseReadmeSelfTelemetrySection(strings.ReplaceAll(sample, "\n", "\r\n"))
	require.NoError(t, err)
	assert.Equal(t, sec.Rows, crlfSec.Rows)
	assert.Equal(t, sec.Prose(), crlfSec.Prose())

	for _, tc := range []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "missing intro",
			mutate:  func(s string) string { return strings.Replace(s, ReadmeSelfTelemetryIntro, "Different intro", 1) },
			wantErr: "missing self-telemetry intro",
		},
		{
			name: "missing table before next heading",
			mutate: func(string) string {
				return ReadmeSelfTelemetryIntroFull + "\n\n### Next Heading\n"
			},
			wantErr: "markdown table not found after intro",
		},
		{
			name: "wrong table header",
			mutate: func(s string) string {
				return strings.Replace(s, "| Metric | Type | Unit | Attributes | Meaning |", "| Name | Type | Unit | Attributes | Meaning |", 1)
			},
			wantErr: "self-telemetry table header",
		},
		{
			name: "malformed separator row",
			mutate: func(s string) string {
				return strings.Replace(s, "| --- | --- | --- | --- | --- |", "| -- | --- | --- | --- | --- |", 1)
			},
			wantErr: "separator row",
		},
		{
			name: "prose directly below table without blank line",
			mutate: func(s string) string {
				return strings.Replace(s, "Retryable failures. |\n\nTrailing note.", "Retryable failures. |\nTrailing note.", 1)
			},
			wantErr: "followed directly by",
		},
		{
			name: "wrong cell count in row",
			mutate: func(s string) string {
				return strings.Replace(s, "| `otelcol_exporter_bigquery_retries` | `Counter (int)` | `{failure}` | `{class}` | Retryable failures. |", "| `otelcol_exporter_bigquery_retries` | `Counter (int)` | `{failure}` | Retryable failures. |", 1)
			},
			wantErr: "has 4 cells, want 5",
		},
		{
			name: "unquoted metric cell",
			mutate: func(s string) string {
				return strings.Replace(s, "`otelcol_exporter_bigquery_retries`", "otelcol_exporter_bigquery_retries", 1)
			},
			wantErr: "must be single inline code",
		},
		{
			name: "invalid attributes cell",
			mutate: func(s string) string {
				return strings.Replace(s, "`{class}`", "`{}`", 1)
			},
			wantErr: "empty attribute braces",
		},
		{
			name: "empty meaning cell",
			mutate: func(s string) string {
				return strings.Replace(s, "Retryable failures.", "", 1)
			},
			wantErr: "meaning cell is empty",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseReadmeSelfTelemetrySection(tc.mutate(sample))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestFormatAndParseReadmeAttrs(t *testing.T) {
	assert.Equal(t, "none", FormatAttrSet(nil))
	assert.Equal(t, "{a, b}", FormatAttrSet([]string{"b", "a"}))

	attrs, err := ParseReadmeMetricAttrs("none")
	require.NoError(t, err)
	assert.Nil(t, attrs)

	attrs, err = ParseReadmeMetricAttrs("{signal, class}")
	require.NoError(t, err)
	assert.Equal(t, []string{"class", "signal"}, attrs)

	_, err = ParseReadmeMetricAttrs("{signal, signal}")
	require.ErrorContains(t, err, "duplicate attribute")
}
