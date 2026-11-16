// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"regexp"
	"strings"
)

// PromMetricPrefix is the Prometheus metric name prefix emitted by the
// BigQuery exporter's self-telemetry.
const PromMetricPrefix = "otelcol_exporter_bigquery_"

var (
	sqlBlockCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)
	sqlLineCommentRE  = regexp.MustCompile(`(?m)--.*$`)
)

// StripSQLComments removes /* ... */ block comments and -- ... line comments
// so tests can inspect the active SQL statement of a template.
func StripSQLComments(sql string) string {
	noBlocks := sqlBlockCommentRE.ReplaceAllString(sql, "")
	return sqlLineCommentRE.ReplaceAllString(noBlocks, "")
}

// Squash removes all whitespace so SQL fragments can be compared regardless of
// indentation or line breaks.
func Squash(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// FirstCapture returns the first capture group of the first match of pattern in
// text, or "" when pattern does not match or defines no capture group.
func FirstCapture(pattern, text string) string {
	m := regexp.MustCompile(pattern).FindStringSubmatch(text)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// TerraformBlock returns the body of the top-level Terraform block that header
// opens (for example `resource "google_bigquery_table" "otel_spans"`), or ""
// when there is none. Nested blocks are indented, so the block ends at the
// first closing brace in the first column.
func TerraformBlock(text, header string) string {
	return FirstCapture(`(?s)(?:^|\n)`+regexp.QuoteMeta(header)+` \{\n(.*?)\n\}`, text)
}

// TerraformAttribute returns the expression of the attribute name set in a
// Terraform block body, at any depth, or "" when the body does not set it.
func TerraformAttribute(body, name string) string {
	return FirstCapture(`(?m)^\s+`+regexp.QuoteMeta(name)+`\s+=\s+(.+)$`, body)
}

// AllLogsCanonicalSeverity models the Cloud Logging LogSeverity name and
// number of an OTLP severity_number (nil for NULL) and severity_text as
// implemented by the otel_logs_as_alllogs view.
func AllLogsCanonicalSeverity(number *int64, text string) (string, int64) {
	t := strings.ToUpper(strings.TrimSpace(text))
	var n int64
	switch {
	case number != nil && *number >= 1 && *number <= 8:
		n = 100
	case number != nil && *number >= 9 && *number <= 10:
		n = 200
	case number != nil && *number >= 11 && *number <= 12:
		n = 300
	case number != nil && *number >= 13 && *number <= 16:
		n = 400
	case number != nil && *number >= 17 && *number <= 20:
		n = 500
	case number != nil && *number >= 21 && *number <= 22:
		n = 600
	case number != nil && *number == 23:
		n = 700
	case number != nil && *number == 24:
		n = 800
	default:
		switch t {
		case "TRACE", "TRACE2", "TRACE3", "TRACE4", "DEBUG", "DEBUG2", "DEBUG3", "DEBUG4":
			n = 100
		case "INFO", "INFO2":
			n = 200
		case "INFO3", "INFO4", "NOTICE":
			n = 300
		case "WARN", "WARN2", "WARN3", "WARN4", "WARNING":
			n = 400
		case "ERROR", "ERROR2", "ERROR3", "ERROR4", "ERR":
			n = 500
		case "FATAL", "FATAL2", "CRITICAL", "CRIT":
			n = 600
		case "FATAL3", "ALERT":
			n = 700
		case "FATAL4", "EMERGENCY", "EMERG":
			n = 800
		}
	}
	names := []string{"DEFAULT", "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL", "ALERT", "EMERGENCY"}
	return names[n/100], n
}
