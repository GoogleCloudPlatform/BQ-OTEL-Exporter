// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"context"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
	assert.True(t, filepath.IsAbs(root), "RepoRoot(%q) must be absolute", root)
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

func TestRepoRootTrimpathCWDAndFailureNonCaching(t *testing.T) {
	root := RepoRoot(t)

	// Simulate -trimpath where runtime.Caller returns a trimmed path and CWD is
	// a relative "." at the repo root: locateRepoRoot must resolve an absolute
	// path before caching so a later t.Chdir(t.TempDir()) keeps working.
	t.Chdir(root)
	resolved, err := locateRepoRoot(false, "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport/reporoot.go", func() (string, error) {
		return ".", nil
	})
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(resolved), "locateRepoRoot(%q) must be absolute", resolved)
	assert.Equal(t, root, resolved)

	// Reset the cache, run fresh RepoRoot discovery from the repo root, then
	// move CWD to an unrelated temp dir and verify RepoRoot and ReadRepoText
	// still resolve the repository root.
	repoRootMu.Lock()
	prev := cachedRepoRoot
	cachedRepoRoot = ""
	repoRootMu.Unlock()
	t.Cleanup(func() {
		repoRootMu.Lock()
		cachedRepoRoot = prev
		repoRootMu.Unlock()
	})

	// A failing lookup must not poison subsequent lookups.
	_, err = locateRepoRoot(false, "", func() (string, error) {
		return t.TempDir(), nil
	})
	require.Error(t, err)
	repoRootMu.Lock()
	assert.Empty(t, cachedRepoRoot, "failed lookup must not populate cache")
	repoRootMu.Unlock()

	assert.Equal(t, root, RepoRoot(t))
	t.Chdir(t.TempDir())
	assert.Equal(t, root, RepoRoot(t))
	assert.Contains(t, ReadRepoText(t, "go.mod"), expectedModuleLine)
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
	assert.NotPanics(t, func() {
		assert.Equal(t, "", FirstCapture(`foo`, "foo=bar"))
	})

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

func TestNewLiveBigQueryClientEReturnsErrorWithoutPanic(t *testing.T) {
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing-adc.json"))
	client, httpClient, cleanup, err := NewLiveBigQueryClientE(context.Background(), "test-project")
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Nil(t, httpClient)
	assert.Nil(t, cleanup)
}

func TestCloseLiveBigQueryClientSurfacesCloseError(t *testing.T) {
	wantErr := errors.New("boom close")
	var events []string

	cleanup := closeLiveBigQueryClient(
		func() error {
			events = append(events, "closeClient")
			return wantErr
		},
		func() {
			events = append(events, "closeHTTP")
		},
	)
	err := cleanup()
	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []string{"closeClient", "closeHTTP"}, events)

	events = nil
	cleanupOK := closeLiveBigQueryClient(
		func() error {
			events = append(events, "closeClient")
			return nil
		},
		func() {
			events = append(events, "closeHTTP")
		},
	)
	require.NoError(t, cleanupOK())
	assert.Equal(t, []string{"closeClient", "closeHTTP"}, events)
}

func checkTestsupportImportBoundaries(root string) ([]string, error) {
	const (
		modulePath      = "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
		testsupportPath = modulePath + "/internal/testsupport"
	)
	forbiddenPrefixes := []string{
		modulePath + "/internal/cli",
		modulePath + "/internal/backfill",
		modulePath + "/internal/quarantinereplay",
		modulePath + "/internal/testbench",
		modulePath + "/internal/validate",
	}

	fset := token.NewFileSet()
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}

		inTestsupport := strings.HasPrefix(rel, "internal/testsupport/")
		isNonTestOutsideTestsupport := !strings.HasSuffix(rel, "_test.go") && !inTestsupport

		for _, imp := range f.Imports {
			impPath, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return fmt.Errorf("unquote import in %s: %w", rel, err)
			}
			if inTestsupport {
				forbidden := impPath == modulePath
				for _, prefix := range forbiddenPrefixes {
					if impPath == prefix || strings.HasPrefix(impPath, prefix+"/") {
						forbidden = true
						break
					}
				}
				if forbidden {
					violations = append(violations, fmt.Sprintf("%s imports forbidden package %q", rel, impPath))
				}
			}
			if isNonTestOutsideTestsupport {
				if impPath == testsupportPath || strings.HasPrefix(impPath, testsupportPath+"/") {
					violations = append(violations, fmt.Sprintf("non-test file %s imports %q", rel, impPath))
				}
			}
		}
		return nil
	})
	return violations, err
}

func TestTestsupportImportBoundary(t *testing.T) {
	violations, err := checkTestsupportImportBoundaries(RepoRoot(t))
	require.NoError(t, err)
	assert.Empty(t, violations)

	// Negative check: confirm both boundary rules catch violations.
	tmp := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "internal", "testsupport"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "internal", "prod"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "cmd", "tool"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "tools", "helper"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "root_prod.go"), []byte(
		"package rootprod\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport\"\n",
	), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "internal", "testsupport", "bad.go"), []byte(
		"package testsupport\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter\"\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/cli/validate\"\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/backfill\"\n",
	), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "internal", "prod", "bad.go"), []byte(
		"package prod\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport\"\n",
	), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "cmd", "tool", "bad.go"), []byte(
		"package main\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport\"\n",
	), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "tools", "helper", "bad.go"), []byte(
		"package helper\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport\"\n",
	), 0o600))
	// A _test.go file under tools/ importing testsupport must remain allowed.
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "tools", "helper", "ok_test.go"), []byte(
		"package helper\nimport _ \"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport\"\n",
	), 0o600))

	bad, err := checkTestsupportImportBoundaries(tmp)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{
		`internal/testsupport/bad.go imports forbidden package "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"`,
		`internal/testsupport/bad.go imports forbidden package "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/cli/validate"`,
		`internal/testsupport/bad.go imports forbidden package "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/backfill"`,
		`non-test file root_prod.go imports "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"`,
		`non-test file internal/prod/bad.go imports "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"`,
		`non-test file cmd/tool/bad.go imports "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"`,
		`non-test file tools/helper/bad.go imports "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"`,
	}, bad)
}
