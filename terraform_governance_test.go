// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	bq "cloud.google.com/go/bigquery"
	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// columnSecurityGate starts the count of every resource in governance.tf, so
// none of them exists while enable_column_level_security is off.
const columnSecurityGate = "var.enable_column_level_security"

// terraformSensitiveColumns are the columns, by table, that main.tf attaches
// the policy tag to: STRING columns that carry text from the telemetry as it
// was sent.
var terraformSensitiveColumns = map[string][]string{
	"otel_spans":      {"status.message"},
	"otel_logs":       {"severity_text"},
	"otel_metrics":    nil,
	"otel_quarantine": {"error_message", "raw_payload"},
}

// terraformColumnSecurityVariables are the variables of column-level
// security with the type and default variables.tf declares for each: off,
// and no readers, unless set.
var terraformColumnSecurityVariables = []struct{ name, typ, def string }{
	{"enable_column_level_security", "bool", "false"},
	{"policy_taxonomy_display_name", "string", `"otel_telemetry_sensitivity"`},
	{"masking_rule", "string", `"SHA256"`},
	{"fine_grained_reader_members", "list(string)", "[]"},
	{"masked_reader_members", "list(string)", "[]"},
}

// Column-level security is opt-in. Its variables default to off and to no
// readers, the masking rule is one of the three predefined rules, and every
// block governance.tf declares exists only while the option is on, the
// reader bindings only when they have members. The policy tag reaches a table
// only through local.sensitive_column, which is null while the option is
// off, and only on the STRING columns in terraformSensitiveColumns: never on
// a JSON column, a repeated column, or a field of a repeated record. The
// outputs are null while the option is off, and the redacted views return
// none of the tagged or JSON columns.
func TestTerraformColumnSecurityVariablesAndResources(t *testing.T) {
	vars := readRepoText(t, "deploy/terraform/variables.tf")
	for _, v := range terraformColumnSecurityVariables {
		block := terraformBlock(vars, `variable "`+v.name+`"`)
		if block == "" {
			t.Errorf("variables.tf declares no %s", v.name)
			continue
		}
		if got := terraformAttribute(block, "type"); got != v.typ {
			t.Errorf("variables.tf gives %s the type %q, want %q", v.name, got, v.typ)
		}
		if got := terraformAttribute(block, "default"); got != v.def {
			t.Errorf("variables.tf gives %s the default %q, want %q", v.name, got, v.def)
		}
	}
	rules := firstCapture(`(?m)^\s+condition\s+=\s+contains\(\[([^\]]*)\], var\.masking_rule\)$`,
		terraformBlock(vars, `variable "masking_rule"`))
	var accepted []string
	for _, m := range regexp.MustCompile(`"([^"]*)"`).FindAllStringSubmatch(rules, -1) {
		accepted = append(accepted, m[1])
	}
	if want := []string{"SHA256", "ALWAYS_NULL", "DEFAULT_MASKING_VALUE"}; !slices.Equal(accepted, want) {
		t.Errorf("masking_rule accepts %q, want exactly %q", accepted, want)
	}

	governance := readRepoText(t, "deploy/terraform/governance.tf")
	gated := columnSecurityGate + " ? 1 : 0"
	blocks := map[string]map[string]string{
		`resource "google_data_catalog_taxonomy" "otel_sensitivity"`: {
			"count":                  gated,
			"region":                 "lower(var.location)",
			"display_name":           "var.policy_taxonomy_display_name",
			"activated_policy_types": `["FINE_GRAINED_ACCESS_CONTROL"]`,
		},
		`resource "google_data_catalog_policy_tag" "sensitive_payload"`: {
			"count":    gated,
			"taxonomy": "google_data_catalog_taxonomy.otel_sensitivity[0].id",
		},
		`resource "google_bigquery_datapolicy_data_policy" "sensitive_payload_mask"`: {
			"count":                 gated,
			"location":              "lower(var.location)",
			"policy_tag":            "google_data_catalog_policy_tag.sensitive_payload[0].name",
			"data_policy_type":      `"DATA_MASKING_POLICY"`,
			"predefined_expression": "var.masking_rule",
		},
		`resource "google_data_catalog_policy_tag_iam_binding" "fine_grained_readers"`: {
			"count":      columnSecurityGate + " && length(var.fine_grained_reader_members) > 0 ? 1 : 0",
			"policy_tag": "google_data_catalog_policy_tag.sensitive_payload[0].name",
			"role":       `"roles/datacatalog.categoryFineGrainedReader"`,
			"members":    "var.fine_grained_reader_members",
		},
		`resource "google_bigquery_datapolicy_data_policy_iam_binding" "masked_readers"`: {
			"count":          columnSecurityGate + " && length(var.masked_reader_members) > 0 ? 1 : 0",
			"data_policy_id": "google_bigquery_datapolicy_data_policy.sensitive_payload_mask[0].data_policy_id",
			"role":           `"roles/bigquerydatapolicy.maskedReader"`,
			"members":        "var.masked_reader_members",
		},
		`resource "google_bigquery_table" "v_otel_spans_redacted"`: {
			"count":               gated,
			"table_id":            `"v_${var.spans_table}_redacted"`,
			"deletion_protection": "false",
			"labels":              "var.labels",
		},
		`resource "google_bigquery_table" "v_otel_logs_redacted"`: {
			"count":               gated,
			"table_id":            `"v_${var.logs_table}_redacted"`,
			"deletion_protection": "false",
			"labels":              "var.labels",
		},
	}
	headers := regexp.MustCompile(`(?m)^(?:resource|data|module) "[^"]+"(?: "[^"]+")? \{$`).FindAllString(governance, -1)
	if len(headers) != len(blocks) {
		t.Errorf("governance.tf declares %d resources, data sources, and modules, want the %d this test checks: %q", len(headers), len(blocks), headers)
	}
	for _, header := range headers {
		header = strings.TrimSuffix(header, " {")
		want, ok := blocks[header]
		if !ok {
			t.Errorf("governance.tf declares %s, which this test does not check is gated on %s", header, columnSecurityGate)
			continue
		}
		body := terraformBlock(governance, header)
		for name, value := range want {
			if got := terraformAttribute(body, name); got != value {
				t.Errorf("governance.tf %s sets %s = %q, want %q", header, name, got, value)
			}
		}
	}

	if got := strings.Join(strings.Fields(terraformCode(terraformBlock(governance, "locals"))), " "); got !=
		"sensitive_column = "+columnSecurityGate+" ? { policyTags = { names = [google_data_catalog_policy_tag.sensitive_payload[0].id] } } : null" {
		t.Errorf("governance.tf locals are %q, want only sensitive_column, attaching the policy tag while the option is on and null while it is off", got)
	}
	if n := strings.Count(governance, "policyTags"); n != 1 {
		t.Errorf("governance.tf names policyTags %d times, want once, in local.sensitive_column", n)
	}

	outputs := readRepoText(t, "deploy/terraform/outputs.tf")
	for name, value := range map[string]string{
		"policy_tag_id":  columnSecurityGate + " ? google_data_catalog_policy_tag.sensitive_payload[0].id : null",
		"data_policy_id": columnSecurityGate + " ? google_bigquery_datapolicy_data_policy.sensitive_payload_mask[0].name : null",
	} {
		if got := terraformAttribute(terraformBlock(outputs, `output "`+name+`"`), "value"); got != value {
			t.Errorf("outputs.tf %s has the value %q, want %q", name, got, value)
		}
	}

	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	if strings.Contains(mainTF, "policyTags") {
		t.Error("main.tf attaches a policy tag other than through local.sensitive_column")
	}
	goSchemas := terraformTableSchemas(t)
	merged := regexp.MustCompile(`(?m)^( +)merge\(\{ name = "(\w+)", type = "(\w+)", mode = "(\w+)" \}, local\.sensitive_column\),$`)
	record := regexp.MustCompile(`(?m)^      name = "(\w+)"$`)
	attached := 0
	for table, want := range terraformSensitiveColumns {
		body := terraformBlock(mainTF, `resource "google_bigquery_table" "`+table+`"`)
		if body == "" {
			t.Fatalf("main.tf has no %s table", table)
		}
		var got []string
		for _, m := range merged.FindAllStringSubmatchIndex(body, -1) {
			attached++
			indent, name, typ, mode := body[m[2]:m[3]], body[m[4]:m[5]], body[m[6]:m[7]], body[m[8]:m[9]]
			path := name
			// A top-level column is indented four spaces, a field of a record
			// written out in place eight, below that record's name.
			if len(indent) > 4 {
				records := record.FindAllStringSubmatch(body[:m[0]], -1)
				if len(records) == 0 {
					t.Errorf("main.tf %s tags the field %s of no record", table, name)
					continue
				}
				path = records[len(records)-1][1] + "." + name
			}
			got = append(got, path)
			if typ != "STRING" || mode == "REPEATED" {
				t.Errorf("main.tf %s tags %s, a %s %s column; only a scalar STRING column takes the tag", table, path, mode, typ)
			}
			checkTaggableColumn(t, table, goSchemas[table], path)
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("main.tf %s tags %q, want %q", table, got, want)
		}
	}
	if n := strings.Count(mainTF, "local.sensitive_column"); n != attached {
		t.Errorf("main.tf uses local.sensitive_column %d times, but only %d are schema entries of a table this test checks", n, attached)
	}

	for _, view := range []struct{ resource, table string }{
		{"v_otel_spans_redacted", "otel_spans"},
		{"v_otel_logs_redacted", "otel_logs"},
	} {
		query := firstCapture(`(?s)\n    query\s+=\s+<<-EOT\n(.*?)\n\s*EOT\n`,
			terraformBlock(governance, `resource "google_bigquery_table" "`+view.resource+`"`))
		if query == "" {
			t.Errorf("governance.tf %s has no view query", view.resource)
			continue
		}
		checkRedactedViewQuery(t, view.resource, view.table, query, goSchemas[view.table])
	}
}

// deploy/README.md documents column-level security in a section of its own:
// each variable with the default variables.tf declares, the APIs to enable,
// both reader roles, the redacted views, and the outputs.
func TestDeployReadmeDocumentsColumnLevelSecurity(t *testing.T) {
	section := firstCapture(`(?s)\n### Column-Level Security and Data Masking\n(.*?)(?:\n##+ |\z)`, readRepoText(t, "deploy/README.md"))
	if section == "" {
		t.Fatal("deploy/README.md has no Column-Level Security and Data Masking section")
	}
	vars := readRepoText(t, "deploy/terraform/variables.tf")
	for _, v := range terraformColumnSecurityVariables {
		want := strings.Trim(terraformAttribute(terraformBlock(vars, `variable "`+v.name+`"`), "default"), `"`)
		if got := firstCapture("(?m)^\\| `"+v.name+"` \\| `([^`]*)` \\|", section); want == "" || got != want {
			t.Errorf("deploy/README.md gives %s the default %q, but variables.tf declares %q", v.name, got, want)
		}
	}
	for _, want := range []string{
		`-var="enable_column_level_security=true"`,
		"`datacatalog.googleapis.com`",
		"`bigquerydatapolicy.googleapis.com`",
		"Fine-Grained Reader",
		"Masked Reader",
		"`v_otel_spans_redacted`",
		"`v_otel_logs_redacted`",
		"`otel_logs_as_alllogs`",
		"`m_otel_log_volume_rollup`",
		"`policy_tag_id`",
		"`data_policy_id`",
		"`auto_create.tables`",
	} {
		if !strings.Contains(section, want) {
			t.Errorf("the Column-Level Security and Data Masking section does not mention %s", want)
		}
	}
}

// CI checks the Terraform module on every change: its terraform job sets up a
// pinned Terraform release without the wrapper and runs terraform fmt
// -check, terraform init -backend=false, and terraform validate, in that
// order, in deploy/terraform.
func TestTerraformCIJobExists(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Defaults struct {
				Run struct {
					WorkingDirectory string `yaml:"working-directory"`
				} `yaml:"run"`
			} `yaml:"defaults"`
			Steps []struct {
				Uses             string         `yaml:"uses"`
				With             map[string]any `yaml:"with"`
				Run              string         `yaml:"run"`
				WorkingDirectory string         `yaml:"working-directory"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(readRepoText(t, ".github/workflows/ci.yml")), &workflow); err != nil {
		t.Fatalf("unmarshaling ci.yml: %v", err)
	}
	job, ok := workflow.Jobs["terraform"]
	if !ok {
		t.Fatal("ci.yml has no terraform job")
	}
	want := [][]string{
		{"terraform", "fmt", "-check"},
		{"terraform", "init", "-backend=false"},
		{"terraform", "validate"},
		{"terraform", "test"},
	}
	setup, ran := false, 0
	for _, step := range job.Steps {
		if strings.HasPrefix(step.Uses, "hashicorp/setup-terraform@") {
			setup = true
			if version := fmt.Sprint(step.With["terraform_version"]); !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(version) {
				t.Errorf("ci.yml terraform job sets up Terraform %q, want a pinned release", version)
			}
			if wrapper := fmt.Sprint(step.With["terraform_wrapper"]); wrapper != "false" {
				t.Errorf("ci.yml terraform job sets terraform_wrapper to %q, want false", wrapper)
			}
		}
		if step.Run == "" {
			continue
		}
		if dir := cmp.Or(step.WorkingDirectory, job.Defaults.Run.WorkingDirectory); dir != "deploy/terraform" {
			t.Errorf("ci.yml terraform job runs %q in %q, want deploy/terraform", step.Run, dir)
		}
		args := strings.Fields(step.Run)
		if ran < len(want) && slices.Equal(args[:min(len(args), 2)], want[ran][:2]) && hasAll(args, want[ran][2:]) {
			ran++
		}
	}
	if !setup {
		t.Error("ci.yml terraform job does not set up Terraform with hashicorp/setup-terraform")
	}
	if ran != len(want) {
		t.Errorf("ci.yml terraform job runs %d of %q in order", ran, want)
	}
}

// terraformAttribute returns the expression of the attribute name set in a
// Terraform block body, at any depth, or "" when the body does not set it.
func terraformAttribute(body, name string) string {
	return firstCapture(`(?m)^\s+`+regexp.QuoteMeta(name)+`\s+=\s+(.+)$`, body)
}

// terraformCode returns text without its comment lines.
func terraformCode(text string) string {
	return regexp.MustCompile(`(?m)^\s*#.*\n`).ReplaceAllString(text, "")
}

// hasAll reports whether args contains every one of want.
func hasAll(args, want []string) bool {
	for _, w := range want {
		if !slices.Contains(args, w) {
			return false
		}
	}
	return true
}

// terraformTableSchemas returns the exporter's schema of each table main.tf
// provisions, which main.tf matches.
func terraformTableSchemas(t *testing.T) map[string]bq.Schema {
	t.Helper()
	return map[string]bq.Schema{
		"otel_spans":      mustBigQuerySchema(t, schema.SpansTableSchema()),
		"otel_logs":       mustBigQuerySchema(t, schema.LogsTableSchema()),
		"otel_metrics":    mustBigQuerySchema(t, schema.MetricsTableSchema()),
		"otel_quarantine": mustBigQuerySchema(t, schema.QuarantineTableSchema()),
	}
}

// checkTaggableColumn fails the test unless path names a STRING column of s
// that is not repeated and not inside a repeated record.
func checkTaggableColumn(t *testing.T, table string, s bq.Schema, path string) {
	t.Helper()
	parts := strings.Split(path, ".")
	for i, part := range parts {
		idx := slices.IndexFunc(s, func(f *bq.FieldSchema) bool { return f.Name == part })
		if idx < 0 {
			t.Errorf("main.tf %s tags %s, which the exporter's %s schema does not have", table, path, table)
			return
		}
		f := s[idx]
		if f.Repeated {
			t.Errorf("main.tf %s tags %s, but %s is repeated in the exporter's schema", table, path, f.Name)
			return
		}
		s = f.Schema
		if i == len(parts)-1 && f.Type != bq.StringFieldType {
			t.Errorf("main.tf %s tags %s, a %s column in the exporter's schema; only a STRING column takes the tag", table, path, f.Type)
		}
	}
}

// checkRedactedViewQuery fails the test unless query, the query of the
// redacted view of table, reads the table's dedup view and returns every
// column of the table but events, links, and object_refs, which it leaves
// out, with each tagged column and each JSON column, in records too, read as
// NULL of its type and every other column as stored. Its select list names
// no column the table does not have.
func checkRedactedViewQuery(t *testing.T, view, table, query string, s bq.Schema) {
	t.Helper()
	if !strings.Contains(query, "google_bigquery_table."+table+"_dedup.table_id") ||
		strings.Contains(query, "google_bigquery_table."+table+".table_id") {
		t.Errorf("%s does not read %s_dedup alone:\n%s", view, table, query)
	}
	if strings.Contains(query, "*") {
		t.Errorf("%s selects a wildcard, which would return a tagged or JSON column:\n%s", view, query)
	}
	tagged := map[string]bool{}
	for _, path := range terraformSensitiveColumns[table] {
		tagged[path] = true
	}
	// nulled maps each tagged or JSON field name to the type the view reads it
	// as; every mention of such a name must be that NULL.
	nulled := map[string]string{}
	omitted := []string{"events", "links", "object_refs"}
	var walk func(prefix string, s bq.Schema)
	walk = func(prefix string, s bq.Schema) {
		for _, f := range s {
			path := prefix + f.Name
			switch {
			case prefix == "" && slices.Contains(omitted, f.Name):
				if regexp.MustCompile(`\b` + f.Name + `\b`).MatchString(query) {
					t.Errorf("%s reads %s, which it must leave out", view, f.Name)
				}
			case f.Type == bq.JSONFieldType:
				nulled[f.Name] = "JSON"
			case tagged[path]:
				nulled[f.Name] = "STRING"
			case f.Type == bq.RecordFieldType:
				if !strings.Contains(query, ") AS "+f.Name+",") {
					t.Errorf("%s does not rebuild the record %s", view, f.Name)
				}
				walk(path+".", f.Schema)
			case prefix == "":
				if !regexp.MustCompile(`(?m)^\s*` + f.Name + `,?$`).MatchString(query) {
					t.Errorf("%s does not return %s as stored", view, f.Name)
				}
			default:
				if !strings.Contains(query, path+" AS "+f.Name) {
					t.Errorf("%s does not return %s as stored", view, path)
				}
			}
		}
	}
	walk("", s)
	for name, typ := range nulled {
		null := regexp.MustCompile(`CAST\(NULL AS ` + typ + `\) AS ` + name + `\b`)
		mentions := regexp.MustCompile(`\b`+name+`\b`).FindAllStringIndex(query, -1)
		if nulls := null.FindAllStringIndex(query, -1); len(nulls) == 0 || len(nulls) != len(mentions) {
			t.Errorf("%s mentions %s %d times, but returns it as CAST(NULL AS %s) %d times:\n%s", view, name, len(mentions), typ, len(nulls), query)
		}
	}
	known := map[string]bool{}
	var collect func(s bq.Schema)
	collect = func(s bq.Schema) {
		for _, f := range s {
			known[f.Name] = true
			collect(f.Schema)
		}
	}
	collect(s)
	selectList := query
	if loc := regexp.MustCompile(`(?m)^\s*FROM\s`).FindStringIndex(query); loc != nil {
		selectList = query[:loc[0]]
	}
	for _, word := range regexp.MustCompile(`\w+`).FindAllString(selectList, -1) {
		if !known[word] && !slices.Contains([]string{"SELECT", "STRUCT", "CAST", "NULL", "AS", "STRING", "JSON"}, word) {
			t.Errorf("%s names %s, which the exporter's %s schema does not have", view, word, table)
		}
	}
}

func TestTerraformOtelSchemaLabelsContract(t *testing.T) {
	vars := readRepoText(t, "deploy/terraform/variables.tf")
	labelsBlock := terraformBlock(vars, `variable "labels"`)
	if labelsBlock == "" {
		t.Fatal(`variables.tf declares no variable "labels"`)
	}
	if !strings.Contains(labelsBlock, `!startswith(lower(k), "otel_schema_")`) {
		t.Errorf("variables.tf variable \"labels\" validation must reject otel_schema_* keys case-insensitively; got:\n%s", labelsBlock)
	}
	if !strings.Contains(labelsBlock, `length(var.labels) <= 60`) {
		t.Errorf("variables.tf variable \"labels\" validation must cap custom labels at 60; got:\n%s", labelsBlock)
	}

	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	for _, want := range []string{
		`otel_schema_major   = "0"`,
		`otel_schema_minor   = "3"`,
		`otel_schema_patch   = "0"`,
		`otel_schema_variant = "default"`,
	} {
		if !strings.Contains(mainTF, want) {
			t.Errorf("deploy/terraform/main.tf missing %s in local.otel_schema_labels", want)
		}
	}

	for _, table := range []string{"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"} {
		block := terraformBlock(mainTF, `resource "google_bigquery_table" "`+table+`"`)
		if block == "" {
			t.Errorf("main.tf missing table resource %s", table)
			continue
		}
		if got := terraformAttribute(block, "labels"); got != "merge(var.labels, local.otel_schema_labels)" {
			t.Errorf("main.tf %s labels = %q, want %q", table, got, "merge(var.labels, local.otel_schema_labels)")
		}
		for _, legacy := range []string{`"payload_refs"`, `"attributes_schema"`, `"metric_metadata_schema"`, `"filtered_attributes_schema"`, `"record_fingerprint"`, `"schema_version"`} {
			if strings.Contains(block, legacy) {
				t.Errorf("main.tf %s unexpectedly retains retired v0alpha2 field %s", table, legacy)
			}
		}
	}
	for _, table := range []string{"otel_spans", "otel_logs"} {
		block := terraformBlock(mainTF, `resource "google_bigquery_table" "`+table+`"`)
		if !strings.Contains(block, `{ name = "object_refs", type = "RECORD", mode = "REPEATED", fields = local.object_ref_fields }`) {
			t.Errorf("main.tf %s missing v0alpha3 4-field ObjectRef object_refs column", table)
		}
	}
	logsBlock := terraformBlock(mainTF, `resource "google_bigquery_table" "otel_logs"`)
	if !strings.Contains(logsBlock, `{ name = "insert_id", type = "STRING", mode = "NULLABLE" }`) {
		t.Errorf("main.tf otel_logs insert_id must be NULLABLE under v0alpha3")
	}
}

func TestTerraformLayoutSearchIndexesAndBackgroundReservation(t *testing.T) {
	vars := readRepoText(t, "deploy/terraform/variables.tf")
	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	outputs := readRepoText(t, "deploy/terraform/outputs.tf")

	for _, tc := range []struct {
		name string
		typ  string
		def  string
	}{
		{"logs_partition_type", "string", `"DAY"`},
		{"spans_clustering", "list(string)", `["service_name", "trace_id", "name"]`},
		{"logs_clustering", "list(string)", `["service_name", "trace_id", "severity_number"]`},
		{"enable_search_indexes", "bool", "false"},
		{"logs_search_index_columns", "list(string)", `["trace_id", "span_id"]`},
		{"logs_search_index_analyzer", "string", `"NO_OP_ANALYZER"`},
		{"enable_background_reservation", "bool", "false"},
		{"background_reservation_slots", "number", "50"},
		{"background_reservation_edition", "string", `"ENTERPRISE"`},
	} {
		block := terraformBlock(vars, `variable "`+tc.name+`"`)
		if block == "" {
			t.Errorf("variables.tf declares no %s", tc.name)
			continue
		}
		if got := terraformAttribute(block, "type"); got != tc.typ {
			t.Errorf("variables.tf %s type = %q, want %q", tc.name, got, tc.typ)
		}
		if got := terraformAttribute(block, "default"); got != tc.def {
			t.Errorf("variables.tf %s default = %q, want %q", tc.name, got, tc.def)
		}
	}

	// Clustering validation allowlists in variables.tf must stay bounded to the dedup windows.
	logsClusterVar := terraformBlock(vars, `variable "logs_clustering"`)
	for _, allowed := range []string{"service_name", "log_name", "severity_number", "trace_id", "span_id", "insert_id"} {
		if !strings.Contains(logsClusterVar, `"`+allowed+`"`) {
			t.Errorf("variables.tf logs_clustering validation missing dedup-window column %q", allowed)
		}
	}
	for _, forbidden := range []string{`"attributes"`, `"body"`, `"event_name"`} {
		if strings.Contains(logsClusterVar, `contains(`) && strings.Contains(firstCapture(`(?m)contains\(\[([^\]]+)\]`, logsClusterVar), forbidden) {
			t.Errorf("variables.tf logs_clustering allowlist must not permit %s", forbidden)
		}
	}

	spansBlock := terraformBlock(mainTF, `resource "google_bigquery_table" "otel_spans"`)
	if got := terraformAttribute(spansBlock, "clustering"); got != "var.spans_clustering" {
		t.Errorf("main.tf otel_spans clustering = %q, want var.spans_clustering", got)
	}
	logsBlock := terraformBlock(mainTF, `resource "google_bigquery_table" "otel_logs"`)
	if got := terraformAttribute(logsBlock, "type"); got != "var.logs_partition_type" {
		t.Errorf("main.tf otel_logs time_partitioning.type = %q, want var.logs_partition_type", got)
	}
	if got := terraformAttribute(logsBlock, "clustering"); got != "var.logs_clustering" {
		t.Errorf("main.tf otel_logs clustering = %q, want var.logs_clustering", got)
	}

	bgAssign := terraformBlock(mainTF, `resource "google_bigquery_reservation_assignment" "background_indexing"`)
	if got := terraformAttribute(bgAssign, "job_type"); got != `"BACKGROUND"` {
		t.Errorf("main.tf background_indexing job_type = %q, want \"BACKGROUND\"", got)
	}
	if got := terraformAttribute(bgAssign, "count"); got != "var.enable_background_reservation ? 1 : 0" {
		t.Errorf("main.tf background_indexing count = %q, want opt-in on enable_background_reservation", got)
	}

	logsIdxJob := terraformBlock(mainTF, `resource "google_bigquery_job" "otel_logs_search_index"`)
	if got := terraformAttribute(logsIdxJob, "count"); got != "var.enable_search_indexes ? 1 : 0" {
		t.Errorf("main.tf otel_logs_search_index count = %q, want opt-in on enable_search_indexes", got)
	}
	if got := terraformAttribute(logsIdxJob, "ignore_changes"); got != "[query, job_id]" {
		t.Errorf("main.tf otel_logs_search_index ignore_changes = %q, want create-only [query, job_id]", got)
	}
	if terraformBlock(outputs, `output "background_reservation_id"`) == "" ||
		terraformBlock(outputs, `output "search_index_ddl"`) == "" ||
		terraformBlock(outputs, `output "search_index_job_ids"`) == "" {
		t.Error("outputs.tf must expose background_reservation_id, search_index_ddl, and search_index_job_ids")
	}
}

// Each search index job runs once and cannot be updated, so its configuration
// carries four guarantees, which tests/*.tftest.hcl also exercise with a mocked
// provider:
//   - A failure is not silent: the postcondition fails the apply, and every
//     later plan, once the job is DONE with an error_result. The provider
//     records a job as soon as BigQuery accepts it, so a job that is still
//     running passes the postcondition and the check block warns about it.
//   - A retry gets a fresh job ID: BigQuery keeps every job ID in its job
//     history, so job_id ends in a uuid(), which ignore_changes keeps stable
//     between replacements.
//   - The job follows its table: replace_triggered_by on the table's id reruns
//     it whenever the table is replaced, renamed or not, while ignore_changes
//     on the query keeps column and analyzer changes from replacing it.
//   - A differently named existing index is tolerated, and nothing else: the
//     script creates the index only when INFORMATION_SCHEMA.SEARCH_INDEXES
//     lists none on the table, and re-raises any error unless the table has
//     an index afterwards.
//
// BigQuery also rejects a create or write disposition on a script, which the
// provider would otherwise send by default.
func TestTerraformSearchIndexJobsFailLoudlyRetryFreshAndFollowTheirTables(t *testing.T) {
	mainTF := readRepoText(t, "deploy/terraform/main.tf")
	for _, signal := range []string{"spans", "logs", "metrics"} {
		job := terraformBlock(mainTF, `resource "google_bigquery_job" "otel_`+signal+`_search_index"`)
		if job == "" {
			t.Errorf("main.tf has no otel_%s_search_index job", signal)
			continue
		}
		for _, attr := range []struct{ name, want string }{
			{"count", "var.enable_search_indexes ? 1 : 0"},
			{"query", "local.search_index_scripts." + signal},
			{"use_legacy_sql", "false"},
			{"create_disposition", `""`},
			{"write_disposition", `""`},
			{"ignore_changes", "[query, job_id]"},
			{"replace_triggered_by", "[google_bigquery_table.otel_" + signal + ".id]"},
			{"condition", `try(self.status[0].state, "") != "DONE" || length(try(self.status[0].error_result, [])) == 0`},
		} {
			if got := terraformAttribute(job, attr.name); got != attr.want {
				t.Errorf("otel_%s_search_index %s = %q, want %q", signal, attr.name, got, attr.want)
			}
		}
		if got := terraformAttribute(job, "job_id"); !strings.HasPrefix(got, `"otel_search_idx_`+signal+`_`) ||
			!strings.HasSuffix(got, `_${replace(uuid(), "-", "")}"`) {
			t.Errorf("otel_%s_search_index job_id = %s, want an otel_search_idx_%s_ prefix and a uuid() suffix", signal, got, signal)
		}
		message := terraformAttribute(job, "error_message")
		for _, want := range []string{
			"${self.job_id}",
			"self.status[0].error_result[0].reason",
			"self.status[0].error_result[0].message",
			"terraform apply -replace='google_bigquery_job.otel_" + signal + "_search_index[0]'",
		} {
			if !strings.Contains(message, want) {
				t.Errorf("otel_%s_search_index postcondition error_message = %s, want it to contain %s", signal, message, want)
			}
		}
	}

	scripts := firstCapture(`(?s)\n  search_index_scripts = \{\n(.*?)\n  \}\n`, mainTF)
	if scripts == "" {
		t.Fatal("main.tf declares no local search_index_scripts")
	}
	for _, signal := range []string{"spans", "logs", "metrics"} {
		target := `(?m)^\s+` + signal + `\s+= \{ table_id = google_bigquery_table\.otel_` + signal +
			`\.table_id, ddl = local\.` + signal + `_search_index_ddl \}$`
		if !regexp.MustCompile(target).MatchString(scripts) {
			t.Errorf("search_index_scripts does not run local.%s_search_index_ddl on otel_%s", signal, signal)
		}
	}
	const guard = "IF NOT EXISTS (\n" +
		"          SELECT 1 FROM `${var.project_id}.${google_bigquery_dataset.otel.dataset_id}.INFORMATION_SCHEMA.SEARCH_INDEXES`\n" +
		"          WHERE table_name = '${target.table_id}'\n" +
		"        ) THEN\n"
	want := "      BEGIN\n" +
		"        " + guard +
		"          ${replace(target.ddl, \"\\n\", \"\\n    \")}\n" +
		"        END IF;\n" +
		"      EXCEPTION WHEN ERROR THEN\n" +
		"        " + guard +
		"          RAISE;\n" +
		"        END IF;\n" +
		"      END;\n"
	if !strings.Contains(scripts, want) {
		t.Errorf("search_index_scripts does not guard the DDL with INFORMATION_SCHEMA.SEARCH_INDEXES and re-raise other errors:\n%s\nwant:\n%s", scripts, want)
	}

	check := terraformBlock(mainTF, `check "search_index_jobs_finished"`)
	if !strings.Contains(check, `try(job.status[0].state, "") == "DONE"`) {
		t.Errorf("check search_index_jobs_finished does not warn about unfinished jobs:\n%s", check)
	}
	for _, signal := range []string{"spans", "logs", "metrics"} {
		if !strings.Contains(check, "google_bigquery_job.otel_"+signal+"_search_index") {
			t.Errorf("check search_index_jobs_finished does not cover otel_%s_search_index", signal)
		}
	}
}
