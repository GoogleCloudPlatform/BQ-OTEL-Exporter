// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Package main extracts staged contrib pull request files from docs/upstream
// into an opentelemetry-collector-contrib checkout.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/contribcheck"
)

type stageOptions struct {
	repoDir        string
	pr             int
	outDir         string
	libraryVersion string
	localRepoDir   string
	chlogOut       string
	issueNumber    string
}

type stagedDoc struct {
	relPath string
	prs     []int
}

var stagedDocs = []stagedDoc{
	{relPath: filepath.Join("docs", "upstream", "contrib-pr-staging.md"), prs: []int{1, 2}},
	{relPath: filepath.Join("docs", "upstream", "contrib-alpha-and-releases.md"), prs: []int{3}},
}

func main() {
	var opts stageOptions
	flag.StringVar(&opts.repoDir, "repo", ".", "root of the BQ-OTEL-Exporter repository")
	flag.IntVar(&opts.pr, "pr", 0, "staged pull request number to extract (1, 2, or 3)")
	flag.StringVar(&opts.outDir, "out", "", "target opentelemetry-collector-contrib root directory")
	flag.StringVar(&opts.libraryVersion, "library-version", contribcheck.LibraryVersion, "library version to place in the component go.mod")
	flag.StringVar(&opts.localRepoDir, "local-repo", "", "optional local library checkout path to wire via go.mod replace inside out")
	flag.StringVar(&opts.chlogOut, "chlog-out", "", "optional path to write the PR's changelog YAML entry")
	flag.StringVar(&opts.issueNumber, "issue", "99999", "issue number used to fill <donation-issue> when --chlog-out is set")
	flag.Parse()

	if err := runStage(opts); err != nil {
		fmt.Fprintf(os.Stderr, "contrib stage: %v\n", err)
		os.Exit(1)
	}
}

func runStage(opts stageOptions) error {
	if opts.pr < 1 || opts.pr > 3 {
		return fmt.Errorf("pr must be 1, 2, or 3 (got %d)", opts.pr)
	}
	if strings.TrimSpace(opts.outDir) == "" {
		return errors.New("out directory is required")
	}

	repoAbs, err := filepath.Abs(opts.repoDir)
	if err != nil {
		return fmt.Errorf("resolve repo path: %w", err)
	}
	outAbs, err := filepath.Abs(opts.outDir)
	if err != nil {
		return fmt.Errorf("resolve out path: %w", err)
	}

	var allFiles []contribcheck.File
	docBodies := make(map[int][]byte, len(stagedDocs))
	for _, doc := range stagedDocs {
		p := filepath.Join(repoAbs, doc.relPath)
		raw, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read %s: %w", doc.relPath, readErr)
		}
		extracted, extErr := contribcheck.Extract(raw)
		if extErr != nil {
			return fmt.Errorf("extract %s: %w", doc.relPath, extErr)
		}
		allFiles = append(allFiles, extracted...)
		for _, pr := range doc.prs {
			docBodies[pr] = raw
		}
	}

	tree, err := contribcheck.Tree(allFiles, opts.pr)
	if err != nil {
		return err
	}

	if goMod, ok := tree["go.mod"]; ok {
		updated, modErr := rewriteGoMod(string(goMod), opts.libraryVersion, opts.localRepoDir)
		if modErr != nil {
			return modErr
		}
		tree["go.mod"] = []byte(updated)
	}

	compDir := filepath.Join(outAbs, filepath.FromSlash(contribcheck.ComponentDir))
	if err := contribcheck.WriteTree(compDir, tree); err != nil {
		return fmt.Errorf("write tree to %s: %w", compDir, err)
	}

	if strings.TrimSpace(opts.chlogOut) != "" {
		rawDoc, ok := docBodies[opts.pr]
		if !ok {
			return fmt.Errorf("no staging document mapped for PR %d", opts.pr)
		}
		entry, chErr := extractChangelogEntry(string(rawDoc), opts.pr, opts.issueNumber)
		if chErr != nil {
			return chErr
		}
		if mkErr := os.MkdirAll(filepath.Dir(opts.chlogOut), 0o755); mkErr != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(opts.chlogOut), mkErr)
		}
		if wErr := os.WriteFile(opts.chlogOut, []byte(entry), 0o644); wErr != nil {
			return fmt.Errorf("write %s: %w", opts.chlogOut, wErr)
		}
	}
	return nil
}

func rewriteGoMod(raw, libraryVersion, localRepoDir string) (string, error) {
	out := raw
	if strings.TrimSpace(libraryVersion) != "" && libraryVersion != contribcheck.LibraryVersion {
		oldReq := contribcheck.LibraryPath + " " + contribcheck.LibraryVersion
		newReq := contribcheck.LibraryPath + " " + libraryVersion
		if !strings.Contains(out, oldReq) {
			return "", fmt.Errorf("go.mod does not contain expected requirement %q", oldReq)
		}
		out = strings.Replace(out, oldReq, newReq, 1)
	}
	if strings.TrimSpace(localRepoDir) != "" {
		absLocal, err := filepath.Abs(localRepoDir)
		if err != nil {
			return "", fmt.Errorf("resolve local-repo path: %w", err)
		}
		if _, statErr := os.Stat(filepath.Join(absLocal, "go.mod")); statErr != nil {
			return "", fmt.Errorf("local-repo %s missing go.mod: %w", absLocal, statErr)
		}
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		out += fmt.Sprintf("\nreplace %s => %s\n", contribcheck.LibraryPath, absLocal)
	}
	return out, nil
}

var donationIssuePlaceholderRE = regexp.MustCompile(`<donation-issue>`)

func extractChangelogEntry(markdown string, pr int, issue string) (string, error) {
	if strings.TrimSpace(issue) == "" {
		return "", errors.New("issue number must be non-empty when extracting changelog entry")
	}
	normalized := strings.ReplaceAll(markdown, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	heading := fmt.Sprintf("## Pull request %d", pr)
	startIdx := -1
	for i := 0; i < len(lines); {
		if fChar, fLen, ok := parseFenceOpen(lines[i]); ok {
			i = findFenceClose(lines, i+1, fChar, fLen) + 1
			continue
		}
		if strings.HasPrefix(lines[i], heading) {
			startIdx = i
			break
		}
		i++
	}
	if startIdx < 0 {
		return "", fmt.Errorf("could not find %q section", heading)
	}

	chlogHeader := -1
	for i := startIdx + 1; i < len(lines); {
		if fChar, fLen, ok := parseFenceOpen(lines[i]); ok {
			i = findFenceClose(lines, i+1, fChar, fLen) + 1
			continue
		}
		if strings.HasPrefix(lines[i], "## ") {
			break
		}
		if strings.TrimSpace(lines[i]) == "### Changelog entry" {
			chlogHeader = i
			break
		}
		i++
	}
	if chlogHeader < 0 {
		return "", fmt.Errorf("could not find ### Changelog entry under PR %d", pr)
	}

	fenceStart := -1
	fenceEnd := -1
	for i := chlogHeader + 1; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "### ") {
			break
		}
		if fChar, fLen, ok := parseFenceOpen(lines[i]); ok {
			info := strings.TrimSpace(lines[i][fLen:])
			closeIdx := findFenceClose(lines, i+1, fChar, fLen)
			if strings.HasPrefix(info, "yaml") {
				fenceStart = i + 1
				fenceEnd = closeIdx
				break
			}
			i = closeIdx
		}
	}
	if fenceStart < 0 {
		return "", fmt.Errorf("could not find yaml code fence in PR %d changelog section", pr)
	}
	if fenceEnd >= len(lines) {
		return "", fmt.Errorf("unclosed yaml code fence in PR %d changelog section", pr)
	}

	body := strings.Join(lines[fenceStart:fenceEnd], "\n") + "\n"
	body = donationIssuePlaceholderRE.ReplaceAllString(body, issue)
	return body, nil
}

func parseFenceOpen(line string) (byte, int, bool) {
	if len(line) < 3 {
		return 0, 0, false
	}
	ch := line[0]
	if ch != '`' && ch != '~' {
		return 0, 0, false
	}
	n := 0
	for n < len(line) && line[n] == ch {
		n++
	}
	if n < 3 {
		return 0, 0, false
	}
	if ch == '`' && strings.ContainsRune(line[n:], '`') {
		return 0, 0, false
	}
	return ch, n, true
}

func findFenceClose(lines []string, start int, ch byte, minLen int) int {
	for i := start; i < len(lines); i++ {
		trimmed := strings.TrimRight(lines[i], " \t")
		if len(trimmed) < minLen {
			continue
		}
		allMatch := true
		for j := 0; j < len(trimmed); j++ {
			if trimmed[j] != ch {
				allMatch = false
				break
			}
		}
		if allMatch {
			return i
		}
	}
	return len(lines)
}
