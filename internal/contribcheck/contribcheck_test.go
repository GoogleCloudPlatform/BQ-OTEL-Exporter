// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package contribcheck

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/confmap"
	"go.yaml.in/yaml/v3"

	bqotel "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter"
)

// docsDir is docs/upstream, relative to this package.
const docsDir = "../../docs/upstream"

// stagingDocs maps each draft that stages files to the pull requests it
// stages.
var stagingDocs = map[string][]int{
	"contrib-pr-staging.md":         {1, 2},
	"contrib-alpha-and-releases.md": {3},
}

// stagedPaths lists the files that each staged pull request adds or
// replaces, relative to ComponentDir, sorted.
var stagedPaths = map[int][]string{
	1: {"Makefile", "README.md", "config.go", "config_test.go", "doc.go", "factory.go", "factory_test.go", "go.mod", "metadata.yaml", "testdata/config.yaml"},
	2: {"README.md", "factory.go", "factory_test.go", "go.mod", "metadata.yaml"},
	3: {"README.md", "metadata.yaml"},
}

// expects holds what the metadata.yaml of each staged tree declares.
var expects = []struct {
	pr   int
	want Expect
}{
	{1, Expect{Stability: "development", SkipShutdown: true}},
	{2, Expect{Stability: "development"}},
	{3, Expect{Stability: "alpha", Distributions: []string{"contrib"}}},
}

func readDoc(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(docsDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// stagedFiles returns the files staged in docs/upstream. It fails the test
// when a draft stages a pull request that belongs to the other draft.
func stagedFiles(t *testing.T) []File {
	t.Helper()
	var all []File
	for _, name := range slices.Sorted(maps.Keys(stagingDocs)) {
		files, err := Extract(readDoc(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, f := range files {
			if !slices.Contains(stagingDocs[name], f.PR) {
				t.Fatalf("%s:%d stages pull request %d; want only pull requests %v", name, f.Line, f.PR, stagingDocs[name])
			}
		}
		all = append(all, files...)
	}
	return all
}

func stagedTree(t *testing.T, files []File, pr int) map[string][]byte {
	t.Helper()
	tree, err := Tree(files, pr)
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// writeStaged writes tree into a fresh directory named after the Go package,
// as mdatagen requires, and returns the directory.
func writeStaged(t *testing.T, tree map[string][]byte) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), packageName)
	if err := WriteTree(dir, tree); err != nil {
		t.Fatal(err)
	}
	return dir
}

// mdBlock is a fenced code block of a Markdown document.
type mdBlock struct {
	info   string // the info string of the opening fence, such as "yaml"
	body   string
	line   int  // the line of the opening fence, starting at 1
	staged bool // whether a contribcheck marker directly precedes the block
}

// split separates md into the lines outside fenced code blocks and the
// fenced code blocks that are not nested in another block.
func split(t *testing.T, md []byte) ([]string, []mdBlock) {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(string(md), "\r\n", "\n"), "\n")
	var prose []string
	var blocks []mdBlock
	for i := 0; i < len(lines); i++ {
		f, ok := openingFence(lines[i], 3)
		if !ok {
			prose = append(prose, lines[i])
			continue
		}
		end := closingFence(lines, i+1, f)
		if end < 0 {
			t.Fatalf("line %d: code fence is never closed", i+1)
		}
		blocks = append(blocks, mdBlock{
			info:   strings.TrimSpace(strings.TrimLeft(strings.TrimLeft(lines[i], " "), string(f.char))),
			body:   strings.Join(lines[i+1:end], "\n") + "\n",
			line:   i + 1,
			staged: i > 0 && strings.HasPrefix(lines[i-1], markerPrefix),
		})
		i = end
	}
	return prose, blocks
}

// formatFiles renders files for test failure messages.
func formatFiles(files []File) string {
	var b strings.Builder
	for _, f := range files {
		fmt.Fprintf(&b, "{PR:%d Path:%q Body:%q Line:%d}\n", f.PR, f.Path, f.Body, f.Line)
	}
	return b.String()
}

func replaceOnce(t *testing.T, b []byte, from, to string) []byte {
	t.Helper()
	if n := bytes.Count(b, []byte(from)); n != 1 {
		t.Fatalf("%q occurs %d times; want once", from, n)
	}
	return bytes.Replace(b, []byte(from), []byte(to), 1)
}

func TestExtract(t *testing.T) {
	lines := []string{
		"# Draft",
		"",
		"```text",
		"<!-- contribcheck:file pr=9 path=exporter/bigqueryexporter/shown.go -->",
		"```",
		"   ~~~~",
		"<!-- contribcheck shown in an indented block -->",
		"   ~~~~",
		"<!-- contribcheck:file pr=1 path=exporter/bigqueryexporter/doc.go -->",
		"```go",
		"package bigqueryexporter",
		"```",
		"",
		"<!-- contribcheck:file pr=2 path=exporter/bigqueryexporter/README.md -->",
		"````markdown",
		"# README",
		"",
		"```yaml",
		"a: b",
		"```",
		"````",
		"<!-- contribcheck:file  path=exporter/bigqueryexporter/testdata/config.yaml pr=12 -->",
		"~~~yaml",
		"bigquery:",
		"```",
		"~~~",
	}
	want := []File{
		{PR: 1, Path: "exporter/bigqueryexporter/doc.go", Body: []byte("package bigqueryexporter\n"), Line: 9},
		{PR: 2, Path: "exporter/bigqueryexporter/README.md", Body: []byte("# README\n\n```yaml\na: b\n```\n"), Line: 14},
		{PR: 12, Path: "exporter/bigqueryexporter/testdata/config.yaml", Body: []byte("bigquery:\n```\n"), Line: 22},
	}
	for _, eol := range []string{"\n", "\r\n"} {
		got, err := Extract([]byte(strings.Join(lines, eol) + eol))
		if err != nil {
			t.Fatalf("line ending %q: %v", eol, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("line ending %q: Extract =\n%s\nwant\n%s", eol, formatFiles(got), formatFiles(want))
		}
	}
}

func TestExtractErrors(t *testing.T) {
	const (
		marker = "<!-- contribcheck:file pr=1 path=exporter/bigqueryexporter/a.go -->"
		staged = marker + "\n```go\npackage a\n```\n"
	)
	edit := func(from, to string) string { return strings.Replace(staged, from, to, 1) }
	tests := []struct {
		name, md, want string
	}{
		{"malformed marker", edit("contribcheck:file", "contribcheck:files"), "line 1: malformed marker"},
		{"text after the marker", edit("-->", "--> trailing"), "line 1: malformed marker"},
		{"marker on the last line", marker, "line 1: marker is not followed by a code fence"},
		{"text after the marker line", marker + "\ntext\n", "line 1: marker is not followed by a code fence in column 0"},
		{"blank line after the marker", marker + "\n\n```go\npackage a\n```\n", "line 1: marker is not followed by a code fence in column 0"},
		{"indented fence", marker + "\n ```go\npackage a\n ```\n", "line 1: marker is not followed by a code fence in column 0"},
		{"unclosed staged block", marker + "\n```go\npackage a\n", "line 2: code fence is never closed"},
		{"unclosed block", "```text\nnot staged\n", "line 1: code fence is never closed"},
		{"empty file", marker + "\n```go\n```\n", "line 1: staged file exporter/bigqueryexporter/a.go is empty"},
		{"file staged twice", staged + "\n" + staged, "line 6: pull request 1 stages exporter/bigqueryexporter/a.go again; the first block is at line 1"},
		{"pr zero", edit("pr=1", "pr=0"), `line 1: marker pr "0" is not a positive integer`},
		{"pr with a leading zero", edit("pr=1", "pr=01"), `line 1: marker pr "01" is not a positive integer`},
		{"negative pr", edit("pr=1", "pr=-1"), `line 1: marker pr "-1" is not a positive integer`},
		{"pr that is not a number", edit("pr=1", "pr=x"), `line 1: marker pr "x" is not a positive integer`},
		{"no pr", edit("pr=1 ", ""), "line 1: marker has no pr attribute"},
		{"no path", edit(" path=exporter/bigqueryexporter/a.go", ""), "line 1: marker has no path attribute"},
		{"repeated attribute", edit("pr=1", "pr=1 pr=2"), `line 1: marker attribute "pr" is repeated`},
		{"unknown attribute", edit("pr=1", "pr=1 lang=go"), `line 1: unknown marker attribute "lang"`},
		{"attribute without a value", edit("pr=1", "pr=1 go"), `line 1: marker attribute "go" is not key=value`},
		{"empty attribute value", edit("pr=1", "pr="), `line 1: marker attribute "pr=" is not key=value`},
		{"path that is not clean", edit("bigqueryexporter/a.go", "bigqueryexporter/../a.go"), "is not a clean path under exporter/bigqueryexporter/"},
		{"path outside the component", edit("exporter/bigqueryexporter/a.go", "receiver/otlpreceiver/a.go"), "is not a clean path under exporter/bigqueryexporter/"},
		{"absolute path", edit("path=exporter", "path=/exporter"), "is not a clean path under exporter/bigqueryexporter/"},
		{"component directory as the path", edit("exporter/bigqueryexporter/a.go", "exporter/bigqueryexporter"), "is not a clean path under exporter/bigqueryexporter/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := Extract([]byte(tt.md))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Extract = %s, %v; want an error containing %q", formatFiles(files), err, tt.want)
			}
		})
	}
}

func TestTree(t *testing.T) {
	file := func(pr int, name, body string) File {
		return File{PR: pr, Path: ComponentDir + "/" + name, Body: []byte(body)}
	}
	// Out of order on purpose: a later pull request replaces a file of an
	// earlier one wherever it is listed.
	files := []File{
		file(2, "factory.go", "factory 2"),
		file(1, "factory.go", "factory 1"),
		file(1, "doc.go", "doc 1"),
		file(3, "metadata.yaml", "metadata 3"),
	}
	tests := []struct {
		pr   int
		want map[string]string
	}{
		{1, map[string]string{"doc.go": "doc 1", "factory.go": "factory 1"}},
		{2, map[string]string{"doc.go": "doc 1", "factory.go": "factory 2"}},
		{3, map[string]string{"doc.go": "doc 1", "factory.go": "factory 2", "metadata.yaml": "metadata 3"}},
	}
	for _, tt := range tests {
		tree, err := Tree(files, tt.pr)
		if err != nil {
			t.Fatalf("Tree(%d): %v", tt.pr, err)
		}
		got := make(map[string]string, len(tree))
		for name, body := range tree {
			got[name] = string(body)
		}
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Tree(%d) = %v; want %v", tt.pr, got, tt.want)
		}
	}
	if _, err := Tree(files, 4); err == nil || !strings.Contains(err.Error(), "no files are staged for pull request 4") {
		t.Errorf("Tree(4) error = %v; want no files are staged", err)
	}
}

func TestWriteTree(t *testing.T) {
	dir := t.TempDir()
	if err := WriteTree(dir, map[string][]byte{"testdata/config.yaml": []byte("bigquery:\n")}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "testdata", "config.yaml")); err != nil || string(got) != "bigquery:\n" {
		t.Errorf("testdata/config.yaml = %q, %v; want %q", got, err, "bigquery:\n")
	}
	for _, rel := range []string{"../escape.go", "/absolute.go", ""} {
		if err := WriteTree(dir, map[string][]byte{rel: []byte("x")}); err == nil || !strings.Contains(err.Error(), "is not local") {
			t.Errorf("WriteTree(%q) error = %v; want is not local", rel, err)
		}
	}
}

func TestCheckTreeOnMissingDirectory(t *testing.T) {
	if _, err := CheckTree(filepath.Join(t.TempDir(), "missing"), Expect{}); err == nil {
		t.Error("CheckTree on a missing directory returned no error")
	}
}

func TestProblemString(t *testing.T) {
	p := Problem{Check: "go.mod", Path: "go.mod", Msg: `go "1.26.5"; want "1.26.0"`}
	if got, want := p.String(), `go.mod: go.mod: go "1.26.5"; want "1.26.0"`; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

func TestUpstreamDocs(t *testing.T) {
	entries, err := os.ReadDir(docsDir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// A new draft must be added to stagingDocs or to the drafts below.
	drafts := []string{"new-component-issue-draft.md", "outreach-and-governance.md", "contrib-testbed-staging.md"}
	if want := slices.Sorted(slices.Values(slices.Concat(slices.Collect(maps.Keys(stagingDocs)), drafts))); !slices.Equal(names, want) {
		t.Fatalf("docs/upstream holds %v; want %v", names, want)
	}
	for _, name := range drafts {
		if files, err := Extract(readDoc(t, name)); err != nil || len(files) != 0 {
			t.Errorf("%s: Extract = %d files, %v; want no staged files", name, len(files), err)
		}
	}
}

func TestStagedTrees(t *testing.T) {
	files := stagedFiles(t)
	got := make(map[int][]string)
	for _, f := range files {
		got[f.PR] = append(got[f.PR], strings.TrimPrefix(f.Path, ComponentDir+"/"))
	}
	for _, paths := range got {
		slices.Sort(paths)
	}
	if !reflect.DeepEqual(got, stagedPaths) {
		t.Fatalf("staged files = %v; want %v", got, stagedPaths)
	}
	for _, e := range expects {
		t.Run("pr"+strconv.Itoa(e.pr), func(t *testing.T) {
			problems, err := CheckTree(writeStaged(t, stagedTree(t, files, e.pr)), e.want)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				t.Error(p)
			}
		})
	}
}

func TestPendingCodeowners(t *testing.T) {
	files := stagedFiles(t)
	// haiyuan-eng-google and schan1031 are confirmed; only <sponsor> remains.
	// When it is confirmed, replace it in docs/upstream, including
	// outreach-and-governance.md, and empty this list.
	want := []string{"<sponsor>"}
	for _, e := range expects {
		meta := stagedTree(t, files, e.pr)["metadata.yaml"]
		got, err := PendingCodeowners(meta)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, want) {
			t.Errorf("pull request %d: PendingCodeowners = %q; want %q", e.pr, got, want)
		}
		confirmed := strings.NewReplacer("haiyuan-eng-google", "example-proposer", "<sponsor>", "example-sponsor", "schan1031", "example-owner").Replace(string(meta))
		if got, err := PendingCodeowners([]byte(confirmed)); err != nil || len(got) != 0 {
			t.Errorf("pull request %d with confirmed handles: PendingCodeowners = %q, %v; want none", e.pr, got, err)
		}
	}
	if _, err := PendingCodeowners([]byte("unknown_key: true\n")); err == nil {
		t.Error("PendingCodeowners accepted a key that contribcheck does not model")
	}
}

func TestCheckPromotion(t *testing.T) {
	files := stagedFiles(t)
	before := stagedTree(t, files, 2)["metadata.yaml"]
	after := stagedTree(t, files, 3)["metadata.yaml"]
	if problems := CheckPromotion(before, after); len(problems) != 0 {
		t.Fatalf("CheckPromotion on the staged trees = %v; want none", problems)
	}
	const otherKeys = "changes keys other than status.stability and status.distributions"
	tests := []struct {
		name          string
		before, after []byte
		want          []string // prefixes of the messages
	}{
		{"display name changes", before, replaceOnce(t, after, "display_name: BigQuery Exporter\n", "display_name: BigQuery\n"), []string{otherKeys}},
		{"codeowners change", before, replaceOnce(t, after, "schan1031]", "example-owner]"), []string{otherKeys}},
		{"compared with pull request 1", stagedTree(t, files, 1)["metadata.yaml"], after, []string{otherKeys}},
		{"stays in development", before, replaceOnce(t, after, "    alpha: [traces, logs, metrics]\n", "    development: [traces, logs, metrics]\n"), []string{"after: status.stability level development; want alpha"}},
		{"one signal promoted", before, replaceOnce(t, after, "    alpha: [traces, logs, metrics]\n", "    alpha: [traces]\n    development: [logs, metrics]\n"), []string{"after: status.stability declares 2 levels"}},
		{"no contrib distribution", before, replaceOnce(t, after, "  distributions: [contrib]\n", "  distributions: []\n"), []string{"after: status.distributions []; want [contrib]"}},
		{"already promoted", after, after, []string{"before: status.distributions [contrib]; want []", "before: status.stability level alpha; want development"}},
		{"before does not decode", []byte("unknown_key: true\n"), after, []string{"before: decoding metadata.yaml"}},
		{"after does not decode", before, []byte("unknown_key: true\n"), []string{"after: decoding metadata.yaml"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := CheckPromotion(tt.before, tt.after)
			ok := len(problems) == len(tt.want)
			for i := 0; ok && i < len(problems); i++ {
				p := problems[i]
				ok = p.Check == "promotion" && p.Path == "metadata.yaml" && strings.HasPrefix(p.Msg, tt.want[i])
			}
			if !ok {
				t.Errorf("CheckPromotion = %v; want messages starting with %q", problems, tt.want)
			}
		})
	}
}

// mutation changes a staged tree.
type mutation func(t *testing.T, tree map[string][]byte)

func edit(file, from, to string) mutation {
	return func(t *testing.T, tree map[string][]byte) {
		t.Helper()
		tree[file] = replaceOnce(t, tree[file], from, to)
	}
}

func appendTo(file, text string) mutation {
	return func(_ *testing.T, tree map[string][]byte) {
		tree[file] = append(slices.Clone(tree[file]), text...)
	}
}

func add(file, body string) mutation {
	return func(_ *testing.T, tree map[string][]byte) {
		tree[file] = []byte(body)
	}
}

func remove(file string) mutation {
	return func(_ *testing.T, tree map[string][]byte) {
		delete(tree, file)
	}
}

// TestCheckTreeMutations breaks the pull request 1 tree one way at a time
// and checks that exactly the expected checks fail.
func TestCheckTreeMutations(t *testing.T) {
	const generated = "// Code generated by mdatagen. DO NOT EDIT.\n\n"
	header := headerCopyright + "\n" + headerSPDX + "\n\n"
	importComment := ` // import "` + ModulePath + `"`
	tests := []struct {
		name   string
		mutate mutation
		want   []string // "path: check" of each problem
	}{
		{"unchanged", nil, nil},
		{"missing file", remove("config_test.go"), []string{"config_test.go: files"}},
		{"license header", edit("config.go", headerCopyright+"\n", "// Copyright 2026 Example\n"), []string{"config.go: header"}},
		{"generated file without a license header", add("internal/metadata/generated_status.go", generated+"package metadata\n"), nil},
		{"syntax error", appendTo("config_test.go", "func {\n"), []string{"config_test.go: parse"}},
		{"package name", edit("config_test.go", "\npackage bigqueryexporter\n", "\npackage bqexporter\n"), []string{"config_test.go: package"}},
		{"external test package", edit("config_test.go", "\npackage bigqueryexporter\n", "\npackage bigqueryexporter_test\n"), nil},
		{"generated file in the wrong package", add("internal/metadata/generated_status.go", generated+"package status\n"), []string{"internal/metadata/generated_status.go: package"}},
		{"import comment", edit("config.go", importComment, ""), []string{"config.go: import comment"}},
		{"import comment of a subpackage", add("internal/metadata/doc.go", header+"package metadata"+` // import "`+ModulePath+`/internal/metadata"`+"\n"), nil},
		{"subpackage without an import comment", add("internal/metadata/doc.go", header+"package metadata\n"), []string{"internal/metadata/doc.go: import comment"}},
		{"second go:generate directive", appendTo("factory.go", "\n//go:generate make other\n"), []string{"doc.go: go:generate", "factory.go: go:generate"}},
		{"no go:generate directive", edit("doc.go", goGenerate+"\n", ""), []string{"doc.go: go:generate"}},
		{"other go:generate directive", edit("doc.go", goGenerate, "//go:generate mdatagen metadata.yaml"), []string{"doc.go: go:generate"}},
		{"generated file with a directive and an exported function", add("generated_extra.go", generated+"package bigqueryexporter\n\n//go:generate make other\n\nfunc Extra() {}\n"), nil},
		{"exported function", appendTo("factory.go", "\nfunc Extra() {}\n"), []string{"factory.go: api"}},
		{"NewFactory signature", edit("factory.go", "func NewFactory() exporter.Factory {", "func NewFactory() any {"), []string{"factory.go: api"}},
		{"no NewFactory", edit("factory.go", "func NewFactory() exporter.Factory {", "func newFactory() exporter.Factory {"), []string{".: api"}},
		{"unexported library symbol", edit("factory.go", "bqotel.NewFactory()", "bqotel.UndefinedFactory()"), []string{"factory.go: api"}},
		{"module path", edit("go.mod", "module "+ModulePath+"\n", "module example.com/bigqueryexporter\n"), []string{"go.mod: go.mod"}},
		{"go directive", edit("go.mod", "\ngo 1.26.0\n", "\ngo 1.26.5\n"), []string{"go.mod: go.mod"}},
		{"toolchain directive", edit("go.mod", "\ngo 1.26.0\n", "\ngo 1.26.0\n\ntoolchain go1.27.3\n"), []string{"go.mod: go.mod"}},
		{"library version", edit("go.mod", LibraryPath+" "+LibraryVersion, LibraryPath+" v0.0.9"), []string{"go.mod: go.mod"}},
		{"replace directive", appendTo("go.mod", "\nreplace "+LibraryPath+" => ../../..\n"), []string{"go.mod: go.mod"}},
		{"unclosed require block", edit("go.mod", "\n)\n", "\n"), []string{"go.mod: go.mod"}},
		{"Makefile", appendTo("Makefile", "\nlint:\n"), []string{"Makefile: Makefile"}},
		{"README without the status section", edit("README.md", statusBegin+"\n", ""), []string{"README.md: readme"}},
		{"README with an unterminated status section", edit("README.md", statusEnd+"\n", ""), []string{"README.md: readme"}},
		{"unknown metadata key", appendTo("metadata.yaml", "unknown_key: true\n"), []string{"metadata.yaml: metadata"}},
		{"component type", edit("metadata.yaml", "type: bigquery\n", "type: big_query\n"), []string{"metadata.yaml: metadata"}},
		{"stability level", edit("metadata.yaml", "    development: [traces, logs, metrics]\n", "    alpha: [traces, logs, metrics]\n"), []string{"metadata.yaml: metadata"}},
		{"signals", edit("metadata.yaml", "    development: [traces, logs, metrics]\n", "    development: [traces, logs]\n"), []string{"metadata.yaml: metadata"}},
		{"distributions", edit("metadata.yaml", "  distributions: []\n", "  distributions: [contrib]\n"), []string{"metadata.yaml: metadata"}},
		{"two codeowners", edit("metadata.yaml", ", schan1031]", "]"), []string{"metadata.yaml: metadata"}},
		{"codeowner that is not a handle", edit("metadata.yaml", "schan1031]", "not_a_handle]"), []string{"metadata.yaml: metadata"}},
		{"repeated codeowner", edit("metadata.yaml", "schan1031]", "<sponsor>]"), []string{"metadata.yaml: metadata", "metadata.yaml: metadata"}},
		{"sending queue support", edit("metadata.yaml", "  support: has_overrides\n", "  support: unsupported\n"), []string{"metadata.yaml: metadata"}},
		{"sending queue overrides", edit("metadata.yaml", "    batch:\n      enabled: false\n", ""), []string{"metadata.yaml: metadata"}},
		{"skip_shutdown", edit("metadata.yaml", "  skip_shutdown: true\n", "  skip_shutdown: false\n"), []string{"metadata.yaml: metadata"}},
		{"test configuration", edit("metadata.yaml", "    project: my-project\n", "    project: \"\"\n"), []string{"metadata.yaml: metadata"}},
		{"goleak ignore list", edit("metadata.yaml", opencensusWorker, "example.com/worker.run"), []string{"metadata.yaml: metadata"}},
		{"testdata without the default component ID", edit("testdata/config.yaml", "bigquery:\n  project: my-project\n  dataset: otel\n", ""), []string{"testdata/config.yaml: testdata"}},
		{"testdata that does not parse", appendTo("testdata/config.yaml", "bigquery: [\n"), []string{"testdata/config.yaml: testdata"}},
	}
	files := stagedFiles(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := stagedTree(t, files, 1)
			if tt.mutate != nil {
				tt.mutate(t, tree)
			}
			problems, err := CheckTree(writeStaged(t, tree), expects[0].want)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, p := range problems {
				got = append(got, p.Path+": "+p.Check)
			}
			slices.Sort(got)
			if !slices.Equal(got, slices.Sorted(slices.Values(tt.want))) {
				t.Errorf("CheckTree = %q; want problems %q", problems, tt.want)
			}
		})
	}
}

// issueGates are the gates that item 5.6 of the v0.1.0 milestone issue
// names, in its order.
var issueGates = []string{
	"checkdoc", "checkmetadata", "checkapi", "goporto", "crosslink", "tidylist", "gotidy", "genotelcontribcol",
	"generate", "multimod-verify", "generate-gh-issue-templates", "gengithub", "genlabels", "gencodecov", "addlicense",
}

func TestGates(t *testing.T) {
	sourceRE := regexp.MustCompile(`^Makefile(\.Common)?:[1-9][0-9]*$`)
	var targets, static []string
	for i, g := range Gates() {
		targets = append(targets, g.Target)
		if g.InIssue != (i < len(issueGates)) {
			t.Errorf("%s: InIssue = %t", g.Target, g.InIssue)
		}
		switch g.Status {
		case StaticPrecondition:
			static = append(static, g.Target)
		case NeedsCheckout:
		default:
			t.Errorf("%s: status %q", g.Target, g.Status)
		}
		if !sourceRE.MatchString(g.Source) {
			t.Errorf("%s: source %q is not a Makefile line", g.Target, g.Source)
		}
		if g.Recipe == "" {
			t.Errorf("%s: no recipe excerpt", g.Target)
		}
	}
	if want := slices.Concat(issueGates, []string{"genoteltestbedcol"}); !slices.Equal(targets, want) {
		t.Errorf("gate targets = %q; want %q", targets, want)
	}
	slices.Sort(static)
	if want := []string{"addlicense", "checkapi", "checkdoc", "checkmetadata", "generate", "goporto", "gotidy"}; !slices.Equal(static, want) {
		t.Errorf("gates with a static precondition = %q; want %q", static, want)
	}
}

// TestGateTable checks that the gate table of contrib-pr-staging.md lists
// Gates in order, with the same sources, recipe excerpts, and statuses.
func TestGateTable(t *testing.T) {
	code := func(cell string) string {
		return strings.TrimSuffix(strings.TrimPrefix(cell, "`"), "`")
	}
	var rows []Gate
	for _, line := range strings.Split(string(readDoc(t, "contrib-pr-staging.md")), "\n") {
		if !strings.HasPrefix(line, "| `make ") {
			continue
		}
		cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "| "), " |"), " | ")
		if len(cells) != 5 {
			t.Fatalf("gate row has %d cells; want 5: %s", len(cells), line)
		}
		rows = append(rows, Gate{
			Target: strings.TrimPrefix(code(cells[0]), "make "),
			Source: code(cells[1]),
			Recipe: code(cells[2]),
			Status: Status(cells[3]),
		})
	}
	var want []Gate
	for _, g := range Gates() {
		g.InIssue = false
		want = append(want, g)
	}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("gate table rows =\n%+v\nwant\n%+v", rows, want)
	}
}

// TestUpstreamDiffs checks that the drafts stage the changes to contrib files
// outside the component and to the releases manifest.
func TestUpstreamDiffs(t *testing.T) {
	tests := []struct{ doc, line string }{
		{"contrib-pr-staging.md", "+      - " + ModulePath},
		{"contrib-alpha-and-releases.md", "+    alpha: [traces, logs, metrics]"},
		{"contrib-alpha-and-releases.md", "+  distributions: [contrib]"},
		{"contrib-alpha-and-releases.md", "+  - gomod: " + ModulePath + " v0.159.0"},
		{"contrib-alpha-and-releases.md", "+  - gomod: " + ModulePath + " <first-contrib-release-with-alpha>"},
	}
	for _, tt := range tests {
		_, blocks := split(t, readDoc(t, tt.doc))
		found := false
		for _, b := range blocks {
			found = found || (b.info == "diff" && slices.Contains(strings.Split(b.body, "\n"), tt.line))
		}
		if !found {
			t.Errorf("%s has no diff block with the line %q", tt.doc, tt.line)
		}
	}
}

func TestChangelogEntries(t *testing.T) {
	type entry struct {
		ChangeType string   `yaml:"change_type"`
		Component  string   `yaml:"component"`
		Note       string   `yaml:"note"`
		Issues     []any    `yaml:"issues"`
		Subtext    string   `yaml:"subtext"`
		ChangeLogs []string `yaml:"change_logs"`
	}
	var types []string
	for _, name := range slices.Sorted(maps.Keys(stagingDocs)) {
		_, blocks := split(t, readDoc(t, name))
		for _, b := range blocks {
			if b.info != "yaml" || b.staged || !strings.Contains(b.body, "change_type:") {
				continue
			}
			where := fmt.Sprintf("%s:%d", name, b.line)
			var e entry
			dec := yaml.NewDecoder(strings.NewReader(b.body))
			dec.KnownFields(true)
			if err := dec.Decode(&e); err != nil {
				t.Errorf("%s: %v", where, err)
				continue
			}
			types = append(types, e.ChangeType)
			if e.Component != "exporter/bigquery" || e.Note == "" || !slices.Equal(e.ChangeLogs, []string{"user"}) {
				t.Errorf("%s: component %q, note %q, change_logs %q; want exporter/bigquery, a note, and [user]", where, e.Component, e.Note, e.ChangeLogs)
			}
			if len(e.Issues) == 0 {
				t.Errorf("%s: no issues", where)
			}
			for _, issue := range e.Issues {
				if n, ok := issue.(int); ok && n > 0 || issue == "<donation-issue>" {
					continue
				}
				t.Errorf("%s: issue %v is neither a number nor <donation-issue>", where, issue)
			}
		}
	}
	// contrib-alpha-and-releases.md sorts before contrib-pr-staging.md.
	if want := []string{"enhancement", "new_component", "enhancement"}; !slices.Equal(types, want) {
		t.Errorf("change types = %q; want %q", types, want)
	}
}

func TestIssueDraft(t *testing.T) {
	doc := readDoc(t, "new-component-issue-draft.md")
	prose, _ := split(t, doc)
	// The field labels of .github/ISSUE_TEMPLATE/new_component.yaml at the
	// pinned commit, in form order.
	labels := []string{
		"Building and distributing outside this repository",
		"Existing component implementation",
		"Components covering similar use cases",
		"The purpose and use-cases of the component",
		"Example configuration for the component",
		"Telemetry data types supported",
		"Code Owners",
		"Sponsor (optional)",
		"Additional context",
		"Tip",
	}
	var headings []string
	sections := make(map[string]string)
	inBody, current := false, ""
	for _, line := range prose {
		if strings.HasPrefix(line, "## ") {
			inBody = line == "## Body"
			continue
		}
		if !inBody {
			continue
		}
		if label, ok := strings.CutPrefix(line, "### "); ok {
			headings = append(headings, label)
			current = label
			continue
		}
		sections[current] += line + "\n"
	}
	if !slices.Equal(headings, labels) {
		t.Errorf("body headings = %q; want the form labels %q", headings, labels)
	}
	for _, s := range []string{
		"https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/tag/v0.1.0",
		"https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.1.0/docs/benchmarks/v0.1.0-performance-envelope.md",
		"exporter/googlecloudexporter",
		"`" + ComponentDir + "`",
		"`" + ModulePath + "`",
		"10,404",
		"9,594",
		"9,185",
		"86.8 MiB",
		"1.45–3.87 TiB/day",
	} {
		if !bytes.Contains(doc, []byte(s)) {
			t.Errorf("the issue draft does not mention %s", s)
		}
	}
	if bytes.Contains(doc, []byte("&lt;summary of")) || bytes.Contains(doc, []byte("<summary of")) {
		t.Error("the issue draft still contains the <summary of ...> performance placeholder")
	}
	for _, owner := range []string{"@haiyuan-eng-google", "@&lt;sponsor&gt;", "@schan1031"} {
		if !strings.Contains(sections["Code Owners"], owner) {
			t.Errorf("the Code Owners section does not list %s", owner)
		}
	}
}

var hunkRE = regexp.MustCompile(`^@@ -([1-9][0-9]*)(?:,([0-9]+))? \+[0-9]+(?:,([0-9]+))? @@`)

// applyDiff applies a unified diff of one file to old. It fails the test when
// a context or removed line does not match old, which is when `git apply
// --check` reports that the patch does not apply.
func applyDiff(t *testing.T, old []byte, diff string) []byte {
	t.Helper()
	count := func(s string) int {
		if s == "" {
			return 1
		}
		n, err := strconv.Atoi(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	src := strings.Split(string(old), "\n")
	lines := strings.Split(strings.TrimSuffix(diff, "\n"), "\n")
	if len(lines) < 3 || !strings.HasPrefix(lines[0], "--- a/") || !strings.HasPrefix(lines[1], "+++ b/") {
		t.Fatalf("diff does not start with --- a/ and +++ b/ lines:\n%s", diff)
	}
	var out []string
	next := 0 // the index in src of the next line to copy
	for i := 2; i < len(lines); {
		m := hunkRE.FindStringSubmatch(lines[i])
		if m == nil {
			t.Fatalf("diff line %q is not a hunk header", lines[i])
		}
		start := count(m[1]) - 1
		if start < next || start > len(src) {
			t.Fatalf("hunk %q starts outside the file", m[0])
		}
		out = append(out, src[next:start]...)
		next = start
		oldLines, newLines := 0, 0
		for i++; i < len(lines) && !strings.HasPrefix(lines[i], "@@"); i++ {
			op, text := byte(' '), "" // an empty line is an empty context line
			if lines[i] != "" {
				op, text = lines[i][0], lines[i][1:]
			}
			switch op {
			case ' ', '-':
				if next >= len(src) || src[next] != text {
					t.Fatalf("the diff expects line %d to be %q; the file does not match", next+1, text)
				}
				if op == ' ' {
					out = append(out, text)
					newLines++
				}
				oldLines++
				next++
			case '+':
				out = append(out, text)
				newLines++
			default:
				t.Fatalf("unexpected diff line %q", lines[i])
			}
		}
		if oldLines != count(m[2]) || newLines != count(m[3]) {
			t.Fatalf("hunk %q has %d old and %d new lines", m[0], oldLines, newLines)
		}
	}
	return []byte(strings.Join(append(out, src[next:]...), "\n"))
}

// TestGovernanceDiffsApply checks that the codeowner diffs staged in
// outreach-and-governance.md still apply to this repository and list the
// same placeholders as the staged contrib metadata.yaml. Once the change
// lands, the diffs no longer apply and the page has to record it.
func TestGovernanceDiffsApply(t *testing.T) {
	_, blocks := split(t, readDoc(t, "outreach-and-governance.md"))
	// Only diffs that target local repository files should be applied.
	// External diffs (e.g. for opentelemetry-operations-collector) are
	// documented in other fence types and must not appear as diff blocks.
	allowedRepoPaths := map[string]bool{"CODEOWNERS": true, "metadata.yaml": true}
	applied := make(map[string][]byte)
	for _, b := range blocks {
		if b.info != "diff" {
			continue
		}
		first, _, _ := strings.Cut(b.body, "\n")
		name, ok := strings.CutPrefix(first, "--- a/")
		if !ok {
			t.Fatalf("diff at line %d does not start with a --- a/ line", b.line)
		}
		if !allowedRepoPaths[name] {
			t.Fatalf("diff at line %d targets %q; want only %v", b.line, name, slices.Sorted(maps.Keys(allowedRepoPaths)))
		}
		if _, dup := applied[name]; dup {
			t.Fatalf("diff at line %d changes %s again", b.line, name)
		}
		old, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		applied[name] = applyDiff(t, old, b.body)
	}
	if got := slices.Sorted(maps.Keys(applied)); !slices.Equal(got, []string{"CODEOWNERS", "metadata.yaml"}) {
		t.Fatalf("the diffs change %q; want CODEOWNERS and metadata.yaml", got)
	}

	var meta struct {
		Status struct {
			Codeowners struct {
				Active []string `yaml:"active"`
			} `yaml:"codeowners"`
		} `yaml:"status"`
	}
	if err := yaml.Unmarshal(applied["metadata.yaml"], &meta); err != nil {
		t.Fatal(err)
	}
	active := meta.Status.Codeowners.Active
	var owners []string
	for _, line := range strings.Split(string(applied["CODEOWNERS"]), "\n") {
		if fields := strings.Fields(line); len(fields) > 0 && fields[0] == "*" {
			for _, f := range fields[1:] {
				owners = append(owners, strings.TrimPrefix(f, "@"))
			}
		}
	}
	if !slices.Contains(active, "haiyuan-eng-google") ||
		!slices.Equal(slices.Sorted(slices.Values(owners)), slices.Sorted(slices.Values(active))) {
		t.Errorf("after the diffs, CODEOWNERS lists %q and metadata.yaml lists %q; want the same set, with haiyuan-eng-google", owners, active)
	}
	var placeholders []string
	for _, h := range active {
		if placeholderRE.MatchString(h) {
			placeholders = append(placeholders, h)
		}
	}
	slices.Sort(placeholders)
	pending, err := PendingCodeowners(stagedTree(t, stagedFiles(t), 3)["metadata.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(placeholders, pending) {
		t.Errorf("the diffs add the placeholders %q; the staged contrib metadata.yaml has %q", placeholders, pending)
	}
}

// TestExampleConfigsDecode checks every exporters.bigquery example in the
// staged READMEs and in the issue draft against this library's
// configuration, which the component's Config aliases.
func TestExampleConfigsDecode(t *testing.T) {
	sources := map[string][]byte{"new-component-issue-draft.md": readDoc(t, "new-component-issue-draft.md")}
	for _, f := range stagedFiles(t) {
		if f.Path == ComponentDir+"/README.md" {
			sources[fmt.Sprintf("pull request %d README.md", f.PR)] = f.Body
		}
	}
	if len(sources) != 4 {
		t.Fatalf("found %d sources; want the issue draft and three READMEs", len(sources))
	}
	for _, name := range slices.Sorted(maps.Keys(sources)) {
		_, blocks := split(t, sources[name])
		examples := 0
		for _, b := range blocks {
			if b.info != "yaml" {
				continue
			}
			where := fmt.Sprintf("%s, block at line %d", name, b.line)
			var conf map[string]any
			if err := yaml.Unmarshal([]byte(b.body), &conf); err != nil {
				t.Errorf("%s: %v", where, err)
				continue
			}
			exporters, _ := conf["exporters"].(map[string]any)
			section, ok := exporters["bigquery"].(map[string]any)
			if !ok {
				continue
			}
			examples++
			cfg := bqotel.NewFactory().CreateDefaultConfig()
			if err := confmap.NewFromStringMap(section).Unmarshal(cfg); err != nil {
				t.Errorf("%s: the bigquery section does not decode: %v", where, err)
				continue
			}
			if err := confmap.Validate(cfg); err != nil {
				t.Errorf("%s: the bigquery configuration is invalid: %v", where, err)
			}
		}
		if examples == 0 {
			t.Errorf("%s has no exporters.bigquery example", name)
		}
	}
}

// TestMdatagen runs mdatagen on each staged tree when CONTRIBCHECK_MDATAGEN
// names a binary.
func TestMdatagen(t *testing.T) {
	bin := os.Getenv("CONTRIBCHECK_MDATAGEN")
	if bin == "" {
		t.Skip("set CONTRIBCHECK_MDATAGEN to an mdatagen binary to run it on the staged trees")
	}
	levels := map[string]string{"development": "Development", "alpha": "Alpha"}
	files := stagedFiles(t)
	for _, e := range expects {
		t.Run("pr"+strconv.Itoa(e.pr), func(t *testing.T) {
			tree := stagedTree(t, files, e.pr)
			dir := writeStaged(t, tree)
			cmd := exec.CommandContext(t.Context(), bin, "metadata.yaml")
			cmd.Dir = dir
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("mdatagen metadata.yaml: %v\n%s", err, out)
			}
			readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(readme, tree["README.md"]) {
				t.Errorf("mdatagen rewrote the staged README.md:\n%s", readme)
			}
			status, err := os.ReadFile(filepath.Join(dir, "internal", "metadata", "generated_status.go"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`Type\s+= component\.MustNewType\("bigquery"\)`,
				`ScopeName\s+= "` + regexp.QuoteMeta(ModulePath) + `"`,
				`TracesStability\s+= component\.StabilityLevel` + levels[e.want.Stability],
				`LogsStability\s+= component\.StabilityLevel` + levels[e.want.Stability],
				`MetricsStability\s+= component\.StabilityLevel` + levels[e.want.Stability],
			} {
				if !regexp.MustCompile(`(?m)^\s*` + want + `$`).Match(status) {
					t.Errorf("generated_status.go has no line matching %s:\n%s", want, status)
				}
			}
			problems, err := CheckTree(dir, e.want)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range problems {
				t.Errorf("after mdatagen: %s", p)
			}
		})
	}
}

// TestRootGoModMatchesContribGoVersion asserts that root go.mod declares
// go 1.26.0, matching ContribGoVersion.
func TestRootGoModMatchesContribGoVersion(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)$`).FindStringSubmatch(string(goMod))
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	if m[1] != ContribGoVersion {
		t.Errorf("root go.mod declares go %s; want %s (ContribGoVersion)", m[1], ContribGoVersion)
	}
}

// TestOutreachAndGovernanceMembershipDraftsAndLinks verifies membership drafts
// exist for confirmed codeowners and no internal-path leaks remain.
func TestOutreachAndGovernanceMembershipDraftsAndLinks(t *testing.T) {
	doc := readDoc(t, "outreach-and-governance.md")
	for _, handle := range []string{"haiyuan-eng-google", "schan1031"} {
		if !bytes.Contains(doc, []byte(handle)) {
			t.Errorf("outreach-and-governance.md does not mention %s", handle)
		}
	}
	if !bytes.Contains(doc, []byte("open-telemetry/community")) {
		t.Error("outreach-and-governance.md does not reference open-telemetry/community")
	}
	for _, required := range []string{
		"Title: `REQUEST: New membership for haiyuan-eng-google`",
		"Title: `REQUEST: New membership for schan1031`",
		"### GitHub Username",
		"### Requirements",
		"https://github.com/settings/security",
		"https://cloud-native.slack.com/archives/CJFCJHG4Q",
		"### Sponsors",
		"### List of contributions to the OpenTelemetry project",
		"@open-telemetry/collector-contrib-contributors",
	} {
		if !bytes.Contains(doc, []byte(required)) {
			t.Errorf("outreach-and-governance.md does not contain %q", required)
		}
	}
	if bytes.Contains(doc, []byte("OpenTelemetry calendar")) {
		t.Error("outreach-and-governance.md still contains legacy 'OpenTelemetry calendar' checklist item")
	}
	if bytes.Contains(doc, []byte("### Sponsoring organization")) {
		t.Error("outreach-and-governance.md still contains legacy '### Sponsoring organization' heading")
	}
	metaYAML, err := os.ReadFile(filepath.Join("..", "..", "metadata.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	codeowners, err := os.ReadFile(filepath.Join("..", "..", "CODEOWNERS"))
	if err != nil {
		t.Fatal(err)
	}
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, handle := range []string{"haiyuan-eng-google", "schan1031"} {
		for name, content := range map[string]string{
			"metadata.yaml": string(metaYAML),
			"CODEOWNERS":    string(codeowners),
			"README.md":     string(readme),
		} {
			if !strings.Contains(content, handle) {
				t.Errorf("%s does not list %s", name, handle)
			}
		}
	}
	for _, name := range []string{
		"outreach-and-governance.md",
		"contrib-pr-staging.md",
		"contrib-alpha-and-releases.md",
		"new-component-issue-draft.md",
		"contrib-testbed-staging.md",
	} {
		content := readDoc(t, name)
		for _, banned := range []string{
			"google3/", "issues/64", "Copyright 2025",
			"Single-Vendor Cloud-Destination Exception", "Governance Committee",
			"Release Train to Stable Before Google Cloud Next",
		} {
			if bytes.Contains(content, []byte(banned)) {
				t.Errorf("%s contains %q (banned)", name, banned)
			}
		}
	}
}

// TestOutreachAndGovernanceOtelcolGoogleBundle parses the Go code blocks in
// the bundling section and checks copyright headers and assertion directions.
func TestOutreachAndGovernanceOtelcolGoogleBundle(t *testing.T) {
	_, blocks := split(t, readDoc(t, "outreach-and-governance.md"))
	var goBlocks []mdBlock
	for _, b := range blocks {
		if b.info == "go" && strings.Contains(b.body, "bigqueryexporter") {
			goBlocks = append(goBlocks, b)
		}
	}
	if len(goBlocks) < 3 {
		t.Fatalf("found %d Go blocks in bundling section; want at least 3", len(goBlocks))
	}
	for i, b := range goBlocks {
		if !strings.Contains(b.body, "// Copyright 2026 Google LLC") {
			t.Errorf("Go block %d at line %d does not have Copyright 2026 Google LLC", i, b.line)
		}
		if !strings.Contains(b.body, "// SPDX-License-Identifier: Apache-2.0") {
			t.Errorf("Go block %d at line %d does not have SPDX license header", i, b.line)
		}
	}
	for _, b := range goBlocks {
		if !strings.Contains(b.body, "TestCheckConfigStruct") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "factory_test.go", b.body, 0)
		if err != nil {
			t.Fatalf("factory_test.go block at line %d does not parse: %v", b.line, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok {
				return true
			}
			if fn.Name.Name == "TestCheckConfigStruct" {
				var buf bytes.Buffer
				if err := printer.Fprint(&buf, fset, fn.Body); err != nil {
					t.Fatalf("cannot print TestCheckConfigStruct body: %v", err)
				}
				if strings.Contains(buf.String(), "err == nil") {
					t.Error("TestCheckConfigStruct uses 'err == nil' (inverted); want 'err != nil'")
				}
			}
			if fn.Name.Name == "TestDefaultConfigValidateRequiresProjectAndDataset" {
				var buf bytes.Buffer
				if err := printer.Fprint(&buf, fset, fn.Body); err != nil {
					t.Fatalf("cannot print TestDefaultConfigValidateRequiresProjectAndDataset body: %v", err)
				}
				if !strings.Contains(buf.String(), ".Validate()") {
					t.Error("TestDefaultConfigValidateRequiresProjectAndDataset does not call Validate()")
				}
			}
			return true
		})
	}
}

var (
	collectorModVerRE     = regexp.MustCompile(`go\.opentelemetry\.io/collector(?:/[A-Za-z0-9_./-]+)?\s+(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	snapshotObservationRE = regexp.MustCompile("(?is)(?:`versions\\.yaml`\\s+at\\s+that\\s+commit\\s+is\\s+at\\s+v0\\.163\\.0|`87eb65f5e96d9d70315ee401515c330c105d2a63`\\s+had\\s+`contrib-base:\\s+v0\\.163\\.0`|fa7050c4b41e762f0d986b491438bf46bd3a6005/distributions/otelcol-contrib/manifest\\.yaml\\)\\s*\\(2026-10-22\\)\\.\\s*There,\\s+the\\s+distribution\\s+version\\s+is\\s+0\\.163\\.1\\s+\\(line\\s+5\\),\\s+and\\s+the\\s+contrib\\s+modules\\s+are\\s+at\\s+v0\\.163\\.0\\b)")
)

func validateCollectorVersionParity(docs map[string]string, coreStableVer, coreBetaVer string) error {
	for _, name := range slices.Sorted(maps.Keys(docs)) {
		text := docs[name]
		files, err := Extract([]byte(text))
		if err != nil {
			return fmt.Errorf("%s: extract staged files: %w", name, err)
		}
		for _, f := range files {
			for _, m := range collectorModVerRE.FindAllStringSubmatch(string(f.Body), -1) {
				got := m[1]
				want := coreBetaVer
				if strings.HasPrefix(got, "v1.") {
					want = coreStableVer
				}
				if got != want {
					return fmt.Errorf("%s staged PR %d %s requires Collector %s; want %s", name, f.PR, f.Path, got, want)
				}
			}
		}

		for _, u := range splitParityUnits(text) {
			if u.kind == "fence" {
				firstLine, rest, _ := strings.Cut(u.body, "\n")
				info := strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(firstLine), "`~"))
				if info == "diff" {
					for _, dl := range strings.Split(rest, "\n") {
						if strings.HasPrefix(dl, "+") && !strings.HasPrefix(dl, "+++") {
							for _, stale := range []string{"v0.163.0", "v1.69.0"} {
								if strings.Contains(dl, stale) {
									return fmt.Errorf("%s diff block adds stale Collector version %s; want %s / %s", name, stale, coreBetaVer, coreStableVer)
								}
							}
						}
					}
					continue
				}
				for _, stale := range []string{"v0.163.0", "v1.69.0"} {
					if strings.Contains(u.body, stale) {
						return fmt.Errorf("%s fenced block references stale Collector version %s; want %s / %s", name, stale, coreBetaVer, coreStableVer)
					}
				}
				continue
			}

			if isExplicitHistoricalUnit(u) {
				continue
			}
			scrubbed := snapshotObservationRE.ReplaceAllString(u.body, " ")
			for _, stale := range []string{"v0.163.0", "v1.69.0"} {
				if strings.Contains(scrubbed, stale) {
					return fmt.Errorf("%s active prose references stale Collector version %s without snapshot anchor; want %s / %s", name, stale, coreBetaVer, coreStableVer)
				}
			}
		}
	}
	return nil
}

// TestUpstreamDocsCollectorVersions verifies that active staged and fenced
// Collector module baselines in docs/upstream/*.md match the root go.mod while
// permitting verbatim observations of upstream snapshot commits (87eb65f5,
// fa7050c4).
func TestUpstreamDocsCollectorVersions(t *testing.T) {
	goMod, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	stableMatch := regexp.MustCompile(`go\.opentelemetry\.io/collector/exporter (v1\.\d+\.\d+)`).FindStringSubmatch(string(goMod))
	if stableMatch == nil {
		t.Fatal("cannot find go.opentelemetry.io/collector/exporter version in go.mod")
	}
	betaMatch := regexp.MustCompile(`go\.opentelemetry\.io/collector/exporter/exporterhelper (v0\.\d+\.\d+)`).FindStringSubmatch(string(goMod))
	if betaMatch == nil {
		t.Fatal("cannot find go.opentelemetry.io/collector/exporter/exporterhelper version in go.mod")
	}
	coreStableVer, coreBetaVer := stableMatch[1], betaMatch[1]

	docNames := []string{
		"contrib-pr-staging.md",
		"contrib-alpha-and-releases.md",
		"outreach-and-governance.md",
		"new-component-issue-draft.md",
		"contrib-testbed-staging.md",
	}
	docs := make(map[string]string, len(docNames))
	for _, name := range docNames {
		docs[name] = string(readDoc(t, name))
	}
	if err := validateCollectorVersionParity(docs, coreStableVer, coreBetaVer); err != nil {
		t.Fatalf("live Collector version parity check failed: %v", err)
	}

	mutants := []struct {
		name    string
		doc     string
		mutate  func(string) string
		wantErr string
	}{
		{
			name: "staged_gomod_stale_beta_v01630",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return strings.Replace(s, "exporterhelper "+coreBetaVer, "exporterhelper v0.163.0", 1)
			},
			wantErr: "staged PR 1 exporter/bigqueryexporter/go.mod requires Collector v0.163.0",
		},
		{
			name: "staged_gomod_stale_stable_v1690",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return strings.Replace(s, "collector/exporter "+coreStableVer, "collector/exporter v1.69.0", 1)
			},
			wantErr: "staged PR 1 exporter/bigqueryexporter/go.mod requires Collector v1.69.0",
		},
		{
			name: "active_yaml_fence_stale_v01630",
			doc:  "contrib-testbed-staging.md",
			mutate: func(s string) string {
				return strings.Replace(s, "bigqueryexporter "+coreBetaVer, "bigqueryexporter v0.163.0", 1)
			},
			wantErr: "fenced block references stale Collector version v0.163.0",
		},
		{
			name:    "diff_added_line_stale_v01630",
			doc:     "contrib-alpha-and-releases.md",
			mutate:  func(s string) string { return strings.Replace(s, "<first-contrib-release-with-alpha>", "v0.163.0", 1) },
			wantErr: "diff block adds stale Collector version v0.163.0",
		},
		{
			name: "active_prose_stale_v01630_without_snapshot_anchor",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\nBuild against Collector v0.163.0 and v1.69.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
		{
			name: "CV_E1_87eb65f5_in_unrelated_active_sentence_with_stale_v01630",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\nUnlike commit 87eb65f5, the active Collector target for this release is v0.163.0 and v1.69.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
		{
			name: "CV_E2_pinned_commit_phrase_in_active_sentence_with_stale_v01630",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\nFrom the pinned commit onward, require go.opentelemetry.io/collector/exporter/exporterhelper v0.163.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
		{
			name: "CV_E3_releases_keyword_in_active_sentence_with_stale_v01630",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\nBefore filing in opentelemetry-collector-releases, pin this library to Collector v0.163.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
		{
			name: "CV_E4_snapshot_sentence_plus_second_stale_sentence_in_same_paragraph",
			doc:  "contrib-alpha-and-releases.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\n`87eb65f5e96d9d70315ee401515c330c105d2a63` had `contrib-base: v0.163.0`. Therefore this library's active go.mod also requires v0.163.0 and v1.69.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
		{
			name: "CV_E4b_unquoted_snapshot_sentence_plus_stale_sentence",
			doc:  "contrib-alpha-and-releases.md",
			mutate: func(s string) string {
				return s + "\n## Collector baseline\n\n`versions.yaml` at 87eb65f5 had v0.163.0. Therefore this library's active go.mod also requires v0.163.0 and v1.69.0.\n"
			},
			wantErr: "active prose references stale Collector version v0.163.0",
		},
	}
	for _, tc := range mutants {
		t.Run(tc.name, func(t *testing.T) {
			cp := maps.Clone(docs)
			cp[tc.doc] = tc.mutate(cp[tc.doc])
			err := validateCollectorVersionParity(cp, coreStableVer, coreBetaVer)
			if err == nil {
				t.Fatalf("expected Collector version check to fail on mutant %s, but it passed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}
}

var (
	bqURLVerRE               = regexp.MustCompile(`(?i)BQ-OTEL-Exporter/(?:releases/(?:tag|download)|archive(?:/refs/tags)?|blob|tree)/(v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)`)
	bqInlineVerRE            = regexp.MustCompile("(?i)BQ-OTEL-Exporter(?:`?\\s+`?|@)(v\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)")
	bqProseAtVerRE           = regexp.MustCompile("(?i)BQ-OTEL-Exporter\\)?(?:\\s+library)?\\s+at\\s+`?(v\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)`?")
	numberedListItemRE       = regexp.MustCompile(`^\d+\.\s+`)
	contribURLRE             = regexp.MustCompile(`(?i)opentelemetry-collector-contrib/(?:tree|blob|commit)/([0-9a-f]{7,40})\b`)
	releasesMarkdownLinkRE   = regexp.MustCompile("(?i)\\[`?([0-9a-f]{7,40})`?\\]\\(https://github\\.com/open-telemetry/opentelemetry-collector-releases/(?:tree|blob|commit)/([0-9a-f]{7,40})[^)]*\\)")
	releasesURLRE            = regexp.MustCompile(`(?i)https://github\.com/open-telemetry/opentelemetry-collector-releases/(?:tree|blob|commit)/[0-9a-f]{7,40}`)
	formHistoryCommitRE      = regexp.MustCompile("(?i)that form was\\s+last changed in commit `[0-9a-f]{7,40}` \\(\\d{4}-\\d{2}-\\d{2}\\)")
	goPseudoVerRE            = regexp.MustCompile(`(?i)-0\.\d{14}-[0-9a-f]{12}`)
	w3cContextHintRE         = regexp.MustCompile(`(?i)\b(?:trace[_ -]?ids?|span[_ -]?ids?|traceparent)\b`)
	w3cHexTokenRE            = regexp.MustCompile("(?i)`?\\b(?:00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}|[0-9a-f]{32}|[0-9a-f]{16})\\b`?")
	backtickHexRE            = regexp.MustCompile("(?i)`([0-9a-f]{7,40})`")
	bareHexDigitRE           = regexp.MustCompile(`(?i)\b([0-9a-f]{7,40})\b`)
	explicitHistH2RE         = regexp.MustCompile(`(?i)^##\s+Historical\b`)
	explicitHistH3RE         = regexp.MustCompile(`(?i)^###\s+Historical\b`)
	explicitHistBlockquoteRE = regexp.MustCompile(`(?i)^\s*>\s*\*\*(?:note\s*\(historical|historical\b)`)
	explicitHistTableRowRE   = regexp.MustCompile("(?i)\\|\\s*\\*?\\*?historical\\s+(?:pre-release|dry-run|pre-`?v0\\.1\\.0|record)\\b")
	pinnedRefSHARE           = regexp.MustCompile("(?i)pinned-references\\)\\s*(?:\\(`?([0-9a-f]{7,40})`?\\)|`([0-9a-f]{7,40})`)")
)

type parityUnit struct {
	kind string // "heading", "fence", "blockquote", "tablerow", "prose"
	h2   string
	h3   string
	body string
}

func splitParityUnits(text string) []parityUnit {
	var units []parityUnit
	var h2, h3 string
	var curKind string
	var curLines []string

	flush := func() {
		if len(curLines) > 0 {
			units = append(units, parityUnit{
				kind: curKind,
				h2:   h2,
				h3:   h3,
				body: strings.Join(curLines, "\n"),
			})
			curKind = ""
			curLines = nil
		}
	}

	var fenceChar byte
	var fenceLen int
	for _, line := range strings.Split(text, "\n") {
		trimmedLeft := strings.TrimLeft(line, " \t")
		trimmed := strings.TrimSpace(line)

		if fenceLen > 0 {
			curLines = append(curLines, line)
			if len(trimmed) >= fenceLen && strings.Trim(trimmed, string(fenceChar)) == "" {
				flush()
				fenceChar, fenceLen = 0, 0
			}
			continue
		}

		if len(trimmedLeft) >= 3 && (trimmedLeft[0] == '`' || trimmedLeft[0] == '~') {
			ch := trimmedLeft[0]
			n := 0
			for n < len(trimmedLeft) && trimmedLeft[n] == ch {
				n++
			}
			info := trimmedLeft[n:]
			if ch != '`' || !strings.ContainsRune(info, '`') {
				flush()
				fenceChar, fenceLen = ch, n
				curKind = "fence"
				curLines = []string{line}
				continue
			}
		}

		switch {
		case strings.HasPrefix(line, "# "):
			flush()
			h2, h3 = "", ""
			units = append(units, parityUnit{kind: "heading", h2: h2, h3: h3, body: line})
		case strings.HasPrefix(line, "## "):
			flush()
			h2, h3 = line, ""
			units = append(units, parityUnit{kind: "heading", h2: h2, h3: h3, body: line})
		case strings.HasPrefix(line, "### "):
			flush()
			h3 = line
			units = append(units, parityUnit{kind: "heading", h2: h2, h3: h3, body: line})
		case trimmed == "":
			flush()
		case strings.HasPrefix(trimmedLeft, ">"):
			if curKind != "blockquote" {
				flush()
				curKind = "blockquote"
			}
			curLines = append(curLines, line)
		case strings.HasPrefix(trimmed, "|"):
			flush()
			units = append(units, parityUnit{kind: "tablerow", h2: h2, h3: h3, body: line})
		case strings.HasPrefix(trimmedLeft, "- ") || strings.HasPrefix(trimmedLeft, "* ") || numberedListItemRE.MatchString(trimmedLeft):
			flush()
			curKind = "prose"
			curLines = []string{line}
		default:
			if curKind != "prose" {
				flush()
				curKind = "prose"
			}
			curLines = append(curLines, line)
		}
	}
	flush()
	return units
}

func isExplicitHistoricalUnit(u parityUnit) bool {
	if strings.EqualFold(strings.TrimSpace(u.h2), "## Pinned references") || pinnedRefSHARE.MatchString(u.body) {
		return false
	}
	if explicitHistH2RE.MatchString(u.h2) || explicitHistH3RE.MatchString(u.h3) {
		return true
	}
	if u.kind == "blockquote" && explicitHistBlockquoteRE.MatchString(u.body) {
		return true
	}
	if u.kind == "tablerow" && explicitHistTableRowRE.MatchString(u.body) {
		return true
	}
	return false
}

func extractBQLibVersions(s string) []string {
	var out []string
	for _, re := range []*regexp.Regexp{bqURLVerRE, bqInlineVerRE, bqProseAtVerRE} {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func extractSHATokens(s string) []string {
	s = goPseudoVerRE.ReplaceAllString(s, " ")
	s = releasesMarkdownLinkRE.ReplaceAllStringFunc(s, func(match string) string {
		sub := releasesMarkdownLinkRE.FindStringSubmatch(match)
		if len(sub) == 3 && strings.EqualFold(sub[1], sub[2]) {
			return " "
		}
		return match
	})
	s = releasesURLRE.ReplaceAllString(s, " ")
	s = formHistoryCommitRE.ReplaceAllString(s, " ")
	if w3cContextHintRE.MatchString(s) {
		s = w3cHexTokenRE.ReplaceAllString(s, " ")
	}

	seen := make(map[string]bool)
	var out []string
	add := func(tok string) {
		key := strings.ToLower(tok)
		if !seen[key] {
			seen[key] = true
			out = append(out, tok)
		}
	}
	for _, m := range contribURLRE.FindAllStringSubmatch(s, -1) {
		add(m[1])
	}
	for _, m := range backtickHexRE.FindAllStringSubmatch(s, -1) {
		tok := m[1]
		if len(tok) == 40 || strings.ContainsAny(tok, "abcdefABCDEF") {
			add(tok)
		}
	}
	for _, m := range bareHexDigitRE.FindAllStringSubmatch(s, -1) {
		tok := m[1]
		if len(tok) == 40 || (strings.ContainsAny(tok, "0123456789") && strings.ContainsAny(tok, "abcdefABCDEF")) {
			add(tok)
		}
	}
	return out
}

func isPinnedPrefix(sha string) bool {
	return len(sha) >= 7 && strings.HasPrefix(strings.ToLower(PinnedCommit), strings.ToLower(sha))
}

func validateUpstreamDocsParity(docs map[string]string) error {
	requiredDocs := []string{
		"contrib-pr-staging.md",
		"contrib-alpha-and-releases.md",
		"outreach-and-governance.md",
		"new-component-issue-draft.md",
		"contrib-testbed-staging.md",
	}
	for _, name := range requiredDocs {
		if strings.TrimSpace(docs[name]) == "" {
			return fmt.Errorf("missing or empty upstream doc %s", name)
		}
	}
	wantTreeURL := "https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/" + PinnedCommit
	if !strings.Contains(docs["contrib-pr-staging.md"], wantTreeURL) {
		return fmt.Errorf("contrib-pr-staging.md missing canonical pinned tree URL %s", wantTreeURL)
	}
	for _, name := range []string{"contrib-alpha-and-releases.md", "outreach-and-governance.md", "new-component-issue-draft.md", "contrib-testbed-staging.md"} {
		if !strings.Contains(docs[name], "contrib-pr-staging.md#pinned-references") {
			return fmt.Errorf("%s must link contrib-pr-staging.md#pinned-references", name)
		}
	}
	for _, name := range []string{"contrib-pr-staging.md", "contrib-alpha-and-releases.md", "outreach-and-governance.md", "contrib-testbed-staging.md"} {
		if !strings.Contains(docs[name], PinnedCommit) {
			return fmt.Errorf("%s does not state active PinnedCommit %s", name, PinnedCommit)
		}
	}

	for _, name := range slices.Sorted(maps.Keys(docs)) {
		text := docs[name]
		if strings.Contains(strings.ToLower(text), "sixteen gates") {
			return fmt.Errorf("%s contains stale 'sixteen gates' wording", name)
		}
		if !strings.Contains(text, LibraryVersion) {
			return fmt.Errorf("%s does not reference target LibraryVersion %s", name, LibraryVersion)
		}
		files, err := Extract([]byte(text))
		if err != nil {
			return fmt.Errorf("%s: extract staged files: %w", name, err)
		}
		for _, f := range files {
			for _, v := range extractBQLibVersions(string(f.Body)) {
				if v != LibraryVersion {
					return fmt.Errorf("%s staged PR %d %s requires %s; want %s", name, f.PR, f.Path, v, LibraryVersion)
				}
			}
		}

		for _, m := range pinnedRefSHARE.FindAllStringSubmatch(text, -1) {
			got := m[1]
			if got == "" {
				got = m[2]
			}
			if !isPinnedPrefix(got) {
				return fmt.Errorf("%s pinned-references SHA is %q; want %s", name, got, PinnedCommit)
			}
		}

		units := splitParityUnits(text)
		activeVersionSeen := false
		for _, u := range units {
			isHist := isExplicitHistoricalUnit(u)
			if !isHist && strings.Contains(u.body, LibraryVersion) {
				activeVersionSeen = true
			}
			for _, v := range extractBQLibVersions(u.body) {
				if v == LibraryVersion {
					if !isHist {
						activeVersionSeen = true
					}
					continue
				}
				if isHist && (v == "v0.0.1" || v == "v0.0.2" || v == "v0.0.3") {
					continue
				}
				return fmt.Errorf("%s cites BQ-OTEL-Exporter %s outside explicit historical record (want %s)", name, v, LibraryVersion)
			}
			if !isHist {
				for _, sha := range extractSHATokens(u.body) {
					if !isPinnedPrefix(sha) {
						return fmt.Errorf("%s cites unpinned contrib SHA %q outside explicit historical record (section %q)", name, sha, u.h2)
					}
				}
			}
		}
		if !activeVersionSeen {
			return fmt.Errorf("%s mentions %s only in historical context, not as active target", name, LibraryVersion)
		}
	}
	return nil
}

// TestUpstreamDocsLibraryVersionAndContribSHAParity enforces Issue #36 AC #4:
// all docs/upstream/*.md files must agree on LibraryVersion and PinnedCommit,
// allowing other SHAs/pre-releases only inside explicitly labeled historical
// blocks/headings/rows (with zero doc-wide SHA allowlisting).
func TestUpstreamDocsLibraryVersionAndContribSHAParity(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(docsDir, "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs := make(map[string]string, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		docs[filepath.Base(p)] = string(b)
	}
	if err := validateUpstreamDocsParity(docs); err != nil {
		t.Fatalf("live docs/upstream parity check failed: %v", err)
	}

	mutants := []struct {
		name    string
		doc     string
		mutate  func(string) string
		wantErr string
	}{
		{
			name:    "staged_readme_blob_url_library_version_drift",
			doc:     "contrib-alpha-and-releases.md",
			mutate:  func(s string) string { return strings.Replace(s, "blob/"+LibraryVersion+"/", "blob/v0.2.0/", 1) },
			wantErr: "staged PR 3 exporter/bigqueryexporter/README.md requires v0.2.0",
		},
		{
			name: "prose_blob_url_library_version_drift",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Active docs link\n\nSee https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/v0.2.0/README.md.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.2.0 outside explicit historical record",
		},
		{
			name: "cross_doc_pinned_sha_mismatch",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return strings.Replace(s, PinnedCommit, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", 1)
			},
			wantErr: "does not state active PinnedCommit " + PinnedCommit,
		},
		{
			name: "V1_go_get_at_version_drift",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\n## Active install check\n\nRun `go get github.com/GoogleCloudPlatform/BQ-OTEL-Exporter@v0.2.0`.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.2.0 outside explicit historical record",
		},
		{
			name: "V2_prose_library_version_drift",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Active prose check\n\nThis release wraps BQ-OTEL-Exporter v0.2.0 directly.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.2.0 outside explicit historical record",
		},
		{
			name: "V3_releases_download_url_version_drift",
			doc:  "new-component-issue-draft.md",
			mutate: func(s string) string {
				return s + "\nDownload https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/download/v0.2.0/checksums.txt.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.2.0 outside explicit historical record",
		},
		{
			name: "V4_archive_refs_tags_url_version_drift",
			doc:  "new-component-issue-draft.md",
			mutate: func(s string) string {
				return s + "\nDownload https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/archive/refs/tags/v0.2.0.tar.gz.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.2.0 outside explicit historical record",
		},
		{
			name: "active_releases_tag_prerelease_url_rejected",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Active release link\n\nSee https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/tag/v0.0.3.\n"
			},
			wantErr: "cites BQ-OTEL-Exporter v0.0.3 outside explicit historical record",
		},
		{
			name:    "doc_drops_target_library_version",
			doc:     "contrib-testbed-staging.md",
			mutate:  func(s string) string { return strings.ReplaceAll(s, LibraryVersion, "v0.2.0") },
			wantErr: "does not reference target LibraryVersion " + LibraryVersion,
		},
		{
			name: "staged_gomod_uses_prerelease_version",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return strings.Replace(s, "BQ-OTEL-Exporter "+LibraryVersion, "BQ-OTEL-Exporter v0.0.3", 2)
			},
			wantErr: "staged PR 1 exporter/bigqueryexporter/go.mod requires v0.0.3",
		},
		{
			name: "pinned_references_sha_drift",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\nSee [pinned commit](contrib-pr-staging.md#pinned-references) (`1111111111111111111111111111111111111111`).\n"
			},
			wantErr: "pinned-references SHA is \"1111111111111111111111111111111111111111\"",
		},
		{
			name: "E1_keyword_v003_in_active_sentence_with_wrong_sha",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\n## Active base\n\nUnlike the v0.0.3 pre-release, PR 1 for the v0.1.0 donation baseline is cut from contrib commit `0123456789abcdef0123456789abcdef01234567`.\n"
			},
			wantErr: "cites unpinned contrib SHA \"0123456789abcdef0123456789abcdef01234567\"",
		},
		{
			name: "E2_exempt_sha_promoted_to_active_section_with_pinned_intact",
			doc:  "contrib-alpha-and-releases.md",
			mutate: func(s string) string {
				return s + "\n## Active check\n\nOpen PR 3 against contrib commit `96567c08`.\n"
			},
			wantErr: "cites unpinned contrib SHA \"96567c08\"",
		},
		{
			name: "E2b_custom_40hex_declared_in_historical_note_then_reused_active",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				const customSHA = "fedcba9876543210fedcba9876543210fedcba98"
				return s + "\n> **Note (historical dry-run):** Tested `" + customSHA + "`.\n\n## Active base\n\nCut PR 1 from `" + customSHA + "`.\n"
			},
			wantErr: "cites unpinned contrib SHA \"fedcba9876543210fedcba9876543210fedcba98\"",
		},
		{
			name: "E3_table_active_row_under_historical_row",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\n## Matrix\n\n| Milestone | Commit |\n| --- | --- |\n| Historical dry-run (`v0.0.3`) | `96567c08` |\n| `v0.1.0` (active) | `0123456789abcdef0123456789abcdef01234567` |\n"
			},
			wantErr: "cites unpinned contrib SHA \"0123456789abcdef0123456789abcdef01234567\"",
		},
		{
			name: "E4_wrong_contrib_sha_alongside_releases_url",
			doc:  "contrib-alpha-and-releases.md",
			mutate: func(s string) string {
				return s + "\n## Manifest sync\n\nPair contrib commit `deadbeefcafe1234` with https://github.com/open-telemetry/opentelemetry-collector-releases/blob/fa7050c4b41e762f0d986b491438bf46bd3a6005/distributions/otelcol-contrib/manifest.yaml.\n"
			},
			wantErr: "cites unpinned contrib SHA \"deadbeefcafe1234\"",
		},
		{
			name: "E5_uppercase_hex_sha_drift",
			doc:  "new-component-issue-draft.md",
			mutate: func(s string) string {
				return s + "\n## Active check\n\nVerified against commit `ABCDEF012345`.\n"
			},
			wantErr: "cites unpinned contrib SHA \"ABCDEF012345\"",
		},
		{
			name: "E6_heading_mentions_v003_prerelease_with_wrong_active_sha",
			doc:  "contrib-pr-staging.md",
			mutate: func(s string) string {
				return s + "\n## Upgrading from the v0.0.3 pre-release\n\nPin the active PR 1 branch to `0123456789abcdef0123456789abcdef01234567`.\n"
			},
			wantErr: "cites unpinned contrib SHA \"0123456789abcdef0123456789abcdef01234567\"",
		},
		{
			name: "E7_interim_bridge_prose_with_wrong_contrib_tree_url",
			doc:  "outreach-and-governance.md",
			mutate: func(s string) string {
				return s + "\n## Active bridge note\n\nThe interim bridge and PR 1 both build from https://github.com/open-telemetry/opentelemetry-collector-contrib/tree/0123456789abcdef0123456789abcdef01234567.\n"
			},
			wantErr: "cites unpinned contrib SHA \"0123456789abcdef0123456789abcdef01234567\"",
		},
		{
			name:    "stale_sixteen_gates_regression",
			doc:     "contrib-alpha-and-releases.md",
			mutate:  func(s string) string { return s + "\nRerun the sixteen gates.\n" },
			wantErr: "sixteen gates",
		},
	}
	for _, tc := range mutants {
		t.Run(tc.name, func(t *testing.T) {
			cp := maps.Clone(docs)
			cp[tc.doc] = tc.mutate(cp[tc.doc])
			err := validateUpstreamDocsParity(cp)
			if err == nil {
				t.Fatalf("expected parity check to fail on mutant %s, but it passed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}

	positives := []struct {
		name   string
		doc    string
		append string
	}{
		{
			name:   "short_7char_pinned_sha",
			doc:    "contrib-pr-staging.md",
			append: "\n## Short SHA note\n\nGitHub displays the pinned commit as `" + PinnedCommit[:7] + "`.\n",
		},
		{
			name:   "backticked_decimal_and_date",
			doc:    "new-component-issue-draft.md",
			append: "\n## Sizing note\n\nMax payload bytes default to `1048576` as measured on `20261105`.\n",
		},
		{
			name:   "w3c_trace_and_span_ids",
			doc:    "contrib-testbed-staging.md",
			append: "\n## Trace context note\n\nW3C trace and span IDs such as `4bf92f3577b34da6a3ce929d0e0e4736` and `00f067aa0ba902b7` round-trip unchanged.\n",
		},
		{
			name:   "historical_note_releases_tag_v003",
			doc:    "outreach-and-governance.md",
			append: "\n> **Note (historical pre-`v0.1.0` record):** Published pre-release tag https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/releases/tag/v0.0.3.\n",
		},
		{
			name:   "historical_table_row_explicitly_labeled",
			doc:    "contrib-pr-staging.md",
			append: "\n## Summary matrix\n\n| Record | Commit |\n| --- | --- |\n| Historical dry-run (`v0.0.3`) | `96567c08` |\n| Active donation baseline (`v0.1.0`) | `" + PinnedCommit[:8] + "` |\n",
		},
	}
	for _, tc := range positives {
		t.Run("positive_"+tc.name, func(t *testing.T) {
			cp := maps.Clone(docs)
			cp[tc.doc] += tc.append
			if err := validateUpstreamDocsParity(cp); err != nil {
				t.Fatalf("expected valid content %s to pass, got error: %v", tc.name, err)
			}
		})
	}
}

// TestStagedReadmesBetaDocumentation verifies that every staged contrib
// README links the library migration and configuration docs, documents known
// limitations and feature gates, and includes valid YAML setup snippets for
// common Google Cloud deployments.
func TestStagedReadmesBetaDocumentation(t *testing.T) {
	baseURL := "https://github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/blob/" + LibraryVersion
	requiredSnippets := []string{
		baseURL + "/docs/migration.md",
		baseURL + "/docs/config-inventory.md",
		baseURL + "/docs/cost-estimation.md",
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
		"redaction.enabled",
	}

	readmeCount := 0
	for _, f := range stagedFiles(t) {
		if f.Path != ComponentDir+"/README.md" {
			continue
		}
		readmeCount++
		text := string(f.Body)
		for _, want := range requiredSnippets {
			if !strings.Contains(text, want) {
				t.Errorf("pull request %d README.md is missing %q", f.PR, want)
			}
		}

		_, blocks := split(t, f.Body)
		var (
			sawADC           bool
			sawImpersonation bool
			sawAutoCreate    bool
			sawQuarantine    bool
			sawOffload       bool
		)
		for _, b := range blocks {
			if b.info != "yaml" {
				continue
			}
			var conf map[string]any
			if err := yaml.Unmarshal([]byte(b.body), &conf); err != nil {
				t.Errorf("pull request %d README.md line %d: invalid YAML: %v", f.PR, b.line, err)
				continue
			}
			exporters, _ := conf["exporters"].(map[string]any)
			section, ok := exporters["bigquery"].(map[string]any)
			if !ok {
				continue
			}
			raw := bqotel.NewFactory().CreateDefaultConfig()
			if err := confmap.NewFromStringMap(section).Unmarshal(raw); err != nil {
				t.Errorf("pull request %d README.md line %d: decode error: %v", f.PR, b.line, err)
				continue
			}
			if err := confmap.Validate(raw); err != nil {
				t.Errorf("pull request %d README.md line %d: validate error: %v", f.PR, b.line, err)
				continue
			}
			cfg, ok := raw.(*bqotel.Config)
			if !ok {
				t.Fatalf("unexpected config type %T", raw)
			}
			if cfg.Project != "" && cfg.Dataset != "" &&
				cfg.Credentials.ImpersonateServiceAccount == "" &&
				!cfg.AutoCreate.Dataset && !cfg.AutoCreate.Tables &&
				!cfg.Quarantine.Enabled && !cfg.Offload.Enabled {
				sawADC = true
			}
			if cfg.Credentials.ImpersonateServiceAccount != "" {
				sawImpersonation = true
			}
			if cfg.AutoCreate.Dataset && cfg.AutoCreate.Tables && cfg.Location != "" {
				sawAutoCreate = true
			}
			if cfg.Quarantine.Enabled && cfg.Quarantine.Table != "" {
				sawQuarantine = true
			}
			if cfg.Offload.Enabled && cfg.Offload.Bucket != "" {
				sawOffload = true
			}
		}
		if !sawADC {
			t.Errorf("pull request %d README.md is missing valid ADC/Workload Identity setup YAML snippet", f.PR)
		}
		if !sawImpersonation {
			t.Errorf("pull request %d README.md is missing valid service account impersonation YAML snippet", f.PR)
		}
		if !sawAutoCreate {
			t.Errorf("pull request %d README.md is missing valid auto_create YAML snippet", f.PR)
		}
		if !sawQuarantine {
			t.Errorf("pull request %d README.md is missing valid quarantine YAML snippet", f.PR)
		}
		if !sawOffload {
			t.Errorf("pull request %d README.md is missing valid offload YAML snippet", f.PR)
		}
	}
	if readmeCount != 3 {
		t.Fatalf("checked %d staged READMEs; want 3 (PR 1, 2, and 3)", readmeCount)
	}
}
