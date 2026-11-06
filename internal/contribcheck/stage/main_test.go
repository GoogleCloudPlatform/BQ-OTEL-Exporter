// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/contribcheck"
)

func repoRootForTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	return filepath.Clean(filepath.Join(wd, "..", "..", ".."))
}

func TestRunStageAllPRs(t *testing.T) {
	repoRoot := repoRootForTest(t)

	for _, tc := range []struct {
		pr               int
		wantFactoryMatch string
		wantStability    string
		wantChlogType    string
	}{
		{
			pr:               1,
			wantFactoryMatch: "errNotImplemented",
			wantStability:    "development: [traces, logs, metrics]",
			wantChlogType:    "change_type: new_component",
		},
		{
			pr:               2,
			wantFactoryMatch: "bqotel.NewFactory().CreateTraces",
			wantStability:    "development: [traces, logs, metrics]",
			wantChlogType:    "change_type: enhancement",
		},
		{
			pr:               3,
			wantFactoryMatch: "bqotel.NewFactory().CreateTraces",
			wantStability:    "alpha: [traces, logs, metrics]",
			wantChlogType:    "change_type: enhancement",
		},
	} {
		t.Run(
			fmt.Sprintf("pr-%d", tc.pr),
			func(t *testing.T) {
				out := t.TempDir()
				chlogPath := filepath.Join(out, ".chloggen", "pr.yaml")
				err := runStage(stageOptions{
					repoDir:        repoRoot,
					pr:             tc.pr,
					outDir:         out,
					libraryVersion: "v0.1.0",
					localRepoDir:   repoRoot,
					chlogOut:       chlogPath,
					issueNumber:    "54321",
				})
				require.NoError(t, err)

				compDir := filepath.Join(out, filepath.FromSlash(contribcheck.ComponentDir))
				factoryBytes, err := os.ReadFile(filepath.Join(compDir, "factory.go"))
				require.NoError(t, err)
				assert.Contains(t, string(factoryBytes), tc.wantFactoryMatch)

				metaBytes, err := os.ReadFile(filepath.Join(compDir, "metadata.yaml"))
				require.NoError(t, err)
				assert.Contains(t, string(metaBytes), tc.wantStability)

				modBytes, err := os.ReadFile(filepath.Join(compDir, "go.mod"))
				require.NoError(t, err)
				assert.Contains(t, string(modBytes), "replace "+contribcheck.LibraryPath+" => "+repoRoot)

				chlogBytes, err := os.ReadFile(chlogPath)
				require.NoError(t, err)
				assert.Contains(t, string(chlogBytes), tc.wantChlogType)
				assert.Contains(t, string(chlogBytes), "issues: [54321]")
				assert.NotContains(t, string(chlogBytes), "<donation-issue>")
			},
		)
	}
}

func TestRunStageLibraryVersionOverrideWithoutLocalReplace(t *testing.T) {
	repoRoot := repoRootForTest(t)
	out := t.TempDir()

	err := runStage(stageOptions{
		repoDir:        repoRoot,
		pr:             1,
		outDir:         out,
		libraryVersion: "v0.2.3",
	})
	require.NoError(t, err)

	modBytes, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(contribcheck.ComponentDir), "go.mod"))
	require.NoError(t, err)
	assert.Contains(t, string(modBytes), contribcheck.LibraryPath+" v0.2.3")
	assert.NotContains(t, string(modBytes), "replace ")
}

func TestRunStageNegativeProbes(t *testing.T) {
	repoRoot := repoRootForTest(t)

	t.Run("invalid PR number", func(t *testing.T) {
		err := runStage(stageOptions{
			repoDir: repoRoot,
			pr:      4,
			outDir:  t.TempDir(),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "pr must be 1, 2, or 3")
	})

	t.Run("missing out directory", func(t *testing.T) {
		err := runStage(stageOptions{
			repoDir: repoRoot,
			pr:      1,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "out directory is required")
	})

	t.Run("invalid local-repo path", func(t *testing.T) {
		badLocal := t.TempDir()
		err := runStage(stageOptions{
			repoDir:      repoRoot,
			pr:           1,
			outDir:       t.TempDir(),
			localRepoDir: badLocal,
		})
		require.Error(t, err)
		assert.Contains(t, strings.ToLower(err.Error()), "go.mod")
	})

	t.Run("invalid library-version rejected", func(t *testing.T) {
		for _, badVer := range []string{
			"0.1.0",
			"v0.1",
			"   ",
			"v0.1.0\nreplace github.com/evil/mod => /tmp/evil",
			"v0.1.0 replace evil => /tmp/evil",
			"v0.1.0\n",
		} {
			err := runStage(stageOptions{
				repoDir:        repoRoot,
				pr:             1,
				outDir:         t.TempDir(),
				libraryVersion: badVer,
			})
			require.Errorf(t, err, "expected invalid libraryVersion %q to fail", badVer)
			assert.Contains(t, err.Error(), "library-version")

			_, modErr := rewriteGoMod("require github.com/GoogleCloudPlatform/BQ-OTEL-Exporter v0.1.0\n", badVer, "")
			require.Errorf(t, modErr, "expected rewriteGoMod to reject %q", badVer)
		}
	})

	t.Run("invalid donation issue rejected", func(t *testing.T) {
		for _, badIssue := range []string{
			"",
			"abc",
			"$1",
			"123abc",
			"123\nfoo: bar",
			"123 ",
		} {
			out := t.TempDir()
			err := runStage(stageOptions{
				repoDir:     repoRoot,
				pr:          1,
				outDir:      out,
				chlogOut:    filepath.Join(out, ".chloggen", "pr.yaml"),
				issueNumber: badIssue,
			})
			require.Errorf(t, err, "expected invalid issueNumber %q to fail", badIssue)
			assert.Contains(t, err.Error(), "issue number")
		}

		err := runStage(stageOptions{
			repoDir:     repoRoot,
			pr:          1,
			outDir:      t.TempDir(),
			issueNumber: "$1",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "issue number")

		_, chErr := extractChangelogEntry("## Pull request 1\n\n### Changelog entry\n\n```yaml\nissues: [<donation-issue>]\n```\n", 1, "$1")
		require.Error(t, chErr)
		assert.Contains(t, chErr.Error(), "issue number")
	})
}

func TestRunStageLibraryVersionPrereleaseAndBuildMetadata(t *testing.T) {
	repoRoot := repoRootForTest(t)
	out := t.TempDir()

	err := runStage(stageOptions{
		repoDir:        repoRoot,
		pr:             1,
		outDir:         out,
		libraryVersion: "v0.2.3-rc.1+build.4",
	})
	require.NoError(t, err)

	modBytes, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(contribcheck.ComponentDir), "go.mod"))
	require.NoError(t, err)
	assert.Contains(t, string(modBytes), contribcheck.LibraryPath+" v0.2.3-rc.1+build.4")
}
