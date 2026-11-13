// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package schema // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"

import (
	"fmt"
	"maps"
	"strconv"
	"strings"

	"cloud.google.com/go/bigquery/storage/apiv1/storagepb"
)

// Contract identifies an internal BigQuery table schema contract generation.
// It is intentionally scoped to internal/schema and never exposed as a
// user-facing YAML mode switch.
type Contract int

const (
	// ContractV1Candidate is the v0alpha3 / v1.0.0-candidate contract (the active default).
	ContractV1Candidate Contract = iota
)

// DefaultContract is the active schema contract used by the exporter,
// validator, backfill tool, and DDL builders.
const DefaultContract = ContractV1Candidate

// String returns the canonical schema version string for c.
func (c Contract) String() string {
	switch c {
	case ContractV1Candidate:
		return Version
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// VersionCoordinates returns the (major, minor, patch, variant) label values
// corresponding to c.
func (c Contract) VersionCoordinates() (major, minor, patch int, variant string, ok bool) {
	switch c {
	case ContractV1Candidate:
		return 0, 3, 0, SchemaVariantDefault, true
	default:
		return 0, 0, 0, "", false
	}
}

// Reserved BigQuery table label keys and limits for schema contract versioning.
const (
	// MaxBigQueryLabels is the maximum number of labels BigQuery permits on a
	// table resource, including any reserved otel_schema_* labels.
	MaxBigQueryLabels = 64

	LabelSchemaPrefix    = "otel_schema_"
	LabelSchemaMajor     = "otel_schema_major"
	LabelSchemaMinor     = "otel_schema_minor"
	LabelSchemaPatch     = "otel_schema_patch"
	LabelSchemaVariant   = "otel_schema_variant"
	SchemaVariantDefault = "default"
)

// InsertIDPrefixV1 is the compact 4-byte version tag prefixed to synthesized
// insert_id values under ContractV1Candidate:
//
//	"id1:" + base64.RawURLEncoding(SHA-256(canonical_record)[:16])
//
// yielding a fixed 26-byte URL-safe string.
const InsertIDPrefixV1 = "id1:"

// IsReservedSchemaLabelKey reports whether key uses the reserved otel_schema_
// prefix managed by the exporter and Terraform modules.
func IsReservedSchemaLabelKey(key string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(key)), LabelSchemaPrefix)
}

// ContractLabels returns the reserved table labels for c, or nil when c does
// not stamp table labels.
func ContractLabels(c Contract) map[string]string {
	maj, minVer, pat, variant, ok := c.VersionCoordinates()
	if !ok {
		return nil
	}
	return map[string]string{
		LabelSchemaMajor:   strconv.Itoa(maj),
		LabelSchemaMinor:   strconv.Itoa(minVer),
		LabelSchemaPatch:   strconv.Itoa(pat),
		LabelSchemaVariant: variant,
	}
}

// ParsedSchemaLabels holds the parsed otel_schema_* table labels from BigQuery
// table metadata.
type ParsedSchemaLabels struct {
	Present bool
	Major   int
	Minor   int
	Patch   int
	Variant string
}

// ParseSchemaLabels parses otel_schema_* labels from a BigQuery table's label
// map. When no otel_schema_* keys are present, it returns Present=false and a
// nil error. When any otel_schema_* key is present, all four canonical keys
// (major, minor, patch, variant) must be present and valid.
func ParseSchemaLabels(labels map[string]string) (ParsedSchemaLabels, error) {
	hasAny := false
	for k := range labels {
		if IsReservedSchemaLabelKey(k) {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return ParsedSchemaLabels{Present: false}, nil
	}

	rawMajor, ok := labels[LabelSchemaMajor]
	if !ok {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("incomplete otel_schema_* labels: missing %q", LabelSchemaMajor)
	}
	rawMinor, ok := labels[LabelSchemaMinor]
	if !ok {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("incomplete otel_schema_* labels: missing %q", LabelSchemaMinor)
	}
	rawPatch, ok := labels[LabelSchemaPatch]
	if !ok {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("incomplete otel_schema_* labels: missing %q", LabelSchemaPatch)
	}
	variant, ok := labels[LabelSchemaVariant]
	if !ok || strings.TrimSpace(variant) == "" {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("incomplete otel_schema_* labels: missing or empty %q", LabelSchemaVariant)
	}

	major, err := parseStrictLabelInt(rawMajor)
	if err != nil {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("invalid %s=%q: %w", LabelSchemaMajor, rawMajor, err)
	}
	minor, err := parseStrictLabelInt(rawMinor)
	if err != nil {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("invalid %s=%q: %w", LabelSchemaMinor, rawMinor, err)
	}
	patch, err := parseStrictLabelInt(rawPatch)
	if err != nil {
		return ParsedSchemaLabels{Present: true}, fmt.Errorf("invalid %s=%q: %w", LabelSchemaPatch, rawPatch, err)
	}

	return ParsedSchemaLabels{
		Present: true,
		Major:   major,
		Minor:   minor,
		Patch:   patch,
		Variant: variant,
	}, nil
}

func parseStrictLabelInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("value is empty")
	}
	if len(s) > 1 && s[0] == '0' {
		return 0, fmt.Errorf("leading zero is not allowed")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("must be a non-negative integer")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("must be a non-negative integer")
	}
	return n, nil
}

// mergeContractLabels merges user labels with the contract's reserved schema
// labels, stripping any reserved otel_schema_* keys supplied by callers before
// overlaying the contract's canonical labels.
func mergeContractLabels(userLabels map[string]string, c Contract) map[string]string {
	contractLabels := ContractLabels(c)
	if len(userLabels) == 0 && len(contractLabels) == 0 {
		return nil
	}
	out := make(map[string]string, len(userLabels)+len(contractLabels))
	for k, v := range userLabels {
		if IsReservedSchemaLabelKey(k) {
			continue
		}
		out[k] = v
	}
	maps.Copy(out, contractLabels)
	if len(out) == 0 {
		return nil
	}
	return out
}

// ContractForSchema returns the active Contract for s.
func ContractForSchema(_ *storagepb.TableSchema) Contract {
	return ContractV1Candidate
}

// SpansTableSchemaForContract returns the span TableSchema for c.
func SpansTableSchemaForContract(_ Contract) *storagepb.TableSchema {
	return SpansTableSchema()
}

// LogsTableSchemaForContract returns the log TableSchema for c.
func LogsTableSchemaForContract(_ Contract) *storagepb.TableSchema {
	return LogsTableSchema()
}

// MetricsTableSchemaForContract returns the metric TableSchema for c.
func MetricsTableSchemaForContract(_ Contract) *storagepb.TableSchema {
	return MetricsTableSchema()
}

// QuarantineTableSchemaForContract returns the quarantine TableSchema for c.
func QuarantineTableSchemaForContract(_ Contract) *storagepb.TableSchema {
	return QuarantineTableSchema()
}
