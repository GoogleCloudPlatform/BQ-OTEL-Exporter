// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	bq "cloud.google.com/go/bigquery"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

func TestRepoRootAndReadRepoText(t *testing.T) {
	root := RepoRoot(t)
	_, err := os.Stat(filepath.Join(root, "go.mod"))
	require.NoError(t, err)

	// Walking from RepoRoot must remain immune to t.Chdir inside a subpackage.
	t.Chdir(t.TempDir())
	assert.Equal(t, root, RepoRoot(t))
	goMod := ReadRepoText(t, "go.mod")
	assert.Contains(t, goMod, "module github.com/GoogleCloudPlatform/BQ-OTEL-Exporter")

	collectorVer, confmapVer := CollectorVersionsFromGoMod(t, "go.mod")
	assert.Regexp(t, `^v0\.\d+\.\d+$`, collectorVer)
	assert.Regexp(t, `^v1\.\d+\.\d+$`, confmapVer)
}

func TestYAMLHelpers(t *testing.T) {
	doc := ParseYAMLMap(t, "sample.yaml", "outer:\n  inner: value\n")
	assert.Equal(t, "value", YAMLPath(doc, "outer", "inner"))
	assert.Nil(t, YAMLPath(doc, "outer", "missing", "leaf"))
	assert.Nil(t, YAMLPath("not-a-map", "outer"))
}

func TestTextHelpers(t *testing.T) {
	sql := "/* block\ncomment */ SELECT 1 -- trailing\nFROM t"
	assert.Equal(t, "SELECT 1 FROM t", strings.Join(strings.Fields(StripSQLComments(sql)), " "))
	assert.Equal(t, "SELECT1FROMt", Squash("  SELECT  1\n\tFROM t "))
	assert.Equal(t, "bar", FirstCapture(`foo=(\w+)`, "foo=bar baz=qux"))
	assert.Equal(t, "", FirstCapture(`missing=(\w+)`, "foo=bar"))

	tf := `resource "google_bigquery_table" "otel_spans" {
  table_id = "otel_spans"
  nested {
    field = "inner"
  }
}
`
	block := TerraformBlock(tf, `resource "google_bigquery_table" "otel_spans"`)
	assert.Contains(t, block, `table_id = "otel_spans"`)
	assert.Equal(t, `"otel_spans"`, TerraformAttribute(block, "table_id"))
	assert.Equal(t, `"inner"`, TerraformAttribute(block, "field"))
	assert.Equal(t, "", TerraformAttribute(block, "absent"))

	var sev23 int64 = 23
	name, num := AllLogsCanonicalSeverity(&sev23, "")
	assert.Equal(t, "ALERT", name)
	assert.Equal(t, int64(700), num)

	name, num = AllLogsCanonicalSeverity(nil, "warn")
	assert.Equal(t, "WARNING", name)
	assert.Equal(t, int64(400), num)

	assert.Equal(t, "otelcol_exporter_bigquery_", PromMetricPrefix)
}

func TestMustBigQuerySchema(t *testing.T) {
	s := MustBigQuerySchema(t, schema.SpansTableSchema())
	assert.NotEmpty(t, s)
}

func TestEphemeralDatasetHelpers(t *testing.T) {
	assert.True(t, ShouldDeleteDatasetOnCreate(nil))
	assert.False(t, ShouldDeleteDatasetOnCreate(errors.New("409 AlreadyExists")))

	id1 := UniqueEphemeralDatasetID("test_prefix")
	id2 := UniqueEphemeralDatasetID("test_prefix")
	assert.True(t, strings.HasPrefix(id1, "test_prefix_"))
	assert.NotEqual(t, id1, id2)

	var deleted bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"datasetReference":{"datasetId":"ds"}}`))
		case http.MethodDelete:
			deleted = true
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	admin, err := bq.NewClient(ctx, "test-project", option.WithHTTPClient(srv.Client()), option.WithEndpoint(srv.URL), option.WithoutAuthentication())
	require.NoError(t, err)
	defer func() { _ = admin.Close() }()

	var cleanups []func()
	var cleanupErrs []error
	err = CreateOwnedEphemeralDataset(ctx, admin, "ds", "US",
		func(fn func()) { cleanups = append(cleanups, fn) },
		func(e error) { cleanupErrs = append(cleanupErrs, e) },
	)
	require.NoError(t, err)
	require.Len(t, cleanups, 1)
	cleanups[0]()
	assert.True(t, deleted)
	assert.Empty(t, cleanupErrs)
}

func TestContinuousQueryHelpers(t *testing.T) {
	assert.False(t, IsExpectedContinuousQueryDryRunError(nil))
	assert.True(t, IsExpectedContinuousQueryDryRunError(errors.New("googleapi: Error 400: Continuous queries require the project to have a continuous assignment to a reservation, invalidQuery")))

	skipReason, fatalErr := ValidateContinuousExportDryRunJob(&bigqueryapi.Job{
		Status:     &bigqueryapi.JobStatus{},
		Statistics: &bigqueryapi.JobStatistics{},
	}, nil)
	assert.Empty(t, skipReason)
	assert.NoError(t, fatalErr)

	_, fatalErr = ValidateContinuousExportDryRunJob(nil, nil)
	assert.Error(t, fatalErr)
}
