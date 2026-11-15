// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package testsupport provides shared test helpers used across root exporter
// tests and standalone repository verification packages. It must never import
// the root bigqueryexporter package or be imported by production code.
package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

const expectedModuleLine = "module github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"

var findRepoRoot = sync.OnceValues(func() (string, error) {
	if _, file, _, ok := runtime.Caller(0); ok {
		if root, found := walkUpToRepoRoot(filepath.Dir(file)); found {
			return root, nil
		}
	}
	if wd, err := os.Getwd(); err == nil {
		if root, found := walkUpToRepoRoot(wd); found {
			return root, nil
		}
	}
	return "", errors.New("could not locate go.mod for " + expectedModuleLine)
})

func walkUpToRepoRoot(start string) (string, bool) {
	dir := filepath.Clean(start)
	for {
		raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			for line := range strings.SplitSeq(string(raw), "\n") {
				if strings.TrimSpace(line) == expectedModuleLine {
					return dir, true
				}
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

// RepoRoot returns the absolute path to the repository root directory by
// locating the module's go.mod file.
func RepoRoot(t testing.TB) string {
	t.Helper()
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repository root: %v", err)
	}
	return root
}

// ReadRepoText returns the contents of a repository file identified by relPath
// relative to the repository root.
func ReadRepoText(t testing.TB, relPath string) string {
	t.Helper()
	fullPath := filepath.Join(RepoRoot(t), filepath.FromSlash(relPath))
	raw, err := os.ReadFile(fullPath)
	if err != nil {
		t.Fatalf("reading %s: %v", relPath, err)
	}
	return string(raw)
}

// CollectorVersionsFromGoMod reads the Collector release this module builds
// against from the go.mod file at relPath: the v0.x version shared by the
// Collector component and contrib modules (from componentstatus) and the v1.x
// version shared by the stable modules (from confmap).
func CollectorVersionsFromGoMod(t testing.TB, relPath string) (collectorVersion, confmapVersion string) {
	t.Helper()
	goMod := ReadRepoText(t, relPath)
	required := func(module string) string {
		t.Helper()
		version := FirstCapture(fmt.Sprintf(`(?m)^\s*(?:require\s+)?%s (v\d+\.\d+\.\d+)`, regexp.QuoteMeta(module)), goMod)
		if version == "" {
			t.Fatalf("%s has no requirement for %s", relPath, module)
		}
		return version
	}
	return required("go.opentelemetry.io/collector/component/componentstatus"),
		required("go.opentelemetry.io/collector/confmap")
}
