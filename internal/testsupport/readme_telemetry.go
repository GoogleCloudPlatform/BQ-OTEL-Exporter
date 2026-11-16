// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	// ReadmeSelfTelemetryIntro is the prefix that identifies the intro
	// paragraph before the self-telemetry table in README.md.
	ReadmeSelfTelemetryIntro = "Use these content-free self-telemetry instruments"
	// ReadmeSelfTelemetryIntroFull is the full intro sentence preceding the
	// self-telemetry table in README.md.
	ReadmeSelfTelemetryIntroFull = "Use these content-free self-telemetry instruments (declared in `metadata.yaml` and `internal/metadata/telemetry.go`) to detect a stuck path:"
)

// ReadmeSelfTelemetryHeader returns the expected column headers of the
// self-telemetry table in README.md.
func ReadmeSelfTelemetryHeader() []string {
	return []string{"Metric", "Type", "Unit", "Attributes", "Meaning"}
}

// NormalizeEOL converts CRLF and CR line endings to LF.
func NormalizeEOL(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
}

// ReadmeTelemetryRow represents one parsed row of the README.md self-telemetry
// table.
type ReadmeTelemetryRow struct {
	Metric  string
	Type    string
	Unit    string
	Attrs   []string
	Meaning string
}

func trailingBackslashes(s string) int {
	n := 0
	for i := len(s) - 1; i >= 0 && s[i] == '\\'; i-- {
		n++
	}
	return n
}

// SplitMarkdownTableRow splits a GitHub Flavored Markdown table row into
// trimmed cells. One leading and one trailing pipe are dropped, and an
// escaped pipe (\|) stays inside its cell. As on GitHub, an unescaped pipe
// inside a code span still ends the cell.
func SplitMarkdownTableRow(line string) []string {
	s := strings.TrimPrefix(strings.TrimSpace(line), "|")
	if strings.HasSuffix(s, "|") && trailingBackslashes(s[:len(s)-1])%2 == 0 {
		s = s[:len(s)-1]
	}
	var cells []string
	var cell strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			if s[i+1] == '|' {
				cell.WriteByte('|')
			} else {
				cell.WriteByte(s[i])
				cell.WriteByte(s[i+1])
			}
			i++
		case s[i] == '|':
			cells = append(cells, strings.TrimSpace(cell.String()))
			cell.Reset()
		default:
			cell.WriteByte(s[i])
		}
	}
	return append(cells, strings.TrimSpace(cell.String()))
}

// IsMarkdownSeparatorRow reports whether every cell in cells is a valid GFM
// table delimiter cell (at least three dashes, optionally flanked by colons).
func IsMarkdownSeparatorRow(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, c := range cells {
		if len(c) < 3 {
			return false
		}
		dashes := 0
		for _, r := range c {
			switch r {
			case '-':
				dashes++
			case ':':
			default:
				return false
			}
		}
		if dashes < 3 {
			return false
		}
	}
	return true
}

// UnwrapInlineCode extracts the trimmed content of a single inline-code span
// (`...`), returning false when cell is not enclosed in single backticks or
// contains an extra backtick inside.
func UnwrapInlineCode(cell string) (string, bool) {
	c := strings.TrimSpace(cell)
	if len(c) < 2 || !strings.HasPrefix(c, "`") || !strings.HasSuffix(c, "`") {
		return "", false
	}
	inner := c[1 : len(c)-1]
	if strings.Contains(inner, "`") {
		return "", false
	}
	return strings.TrimSpace(inner), true
}

// ParseReadmeMetricAttrs parses the Attributes cell content of a README.md
// self-telemetry row ("none" or "{attr1, attr2}") into sorted attribute names.
func ParseReadmeMetricAttrs(spec string) ([]string, error) {
	if spec == "none" {
		return nil, nil
	}
	if !strings.HasPrefix(spec, "{") || !strings.HasSuffix(spec, "}") {
		return nil, fmt.Errorf("attributes %q must be `none` or `{attr1, attr2}`", spec)
	}
	inner := strings.TrimSpace(spec[1 : len(spec)-1])
	if inner == "" {
		return nil, fmt.Errorf("empty attribute braces %q; use `none`", spec)
	}
	seen := map[string]bool{}
	var attrs []string
	for _, part := range strings.Split(inner, ",") {
		attr := strings.TrimSpace(part)
		if attr == "" {
			return nil, fmt.Errorf("empty attribute in %q", spec)
		}
		if seen[attr] {
			return nil, fmt.Errorf("duplicate attribute %q in %q", attr, spec)
		}
		seen[attr] = true
		attrs = append(attrs, attr)
	}
	slices.Sort(attrs)
	return attrs, nil
}

// FormatAttrSet formats a slice of attribute names as "none" or a sorted
// "{a, b}" list.
func FormatAttrSet(attrs []string) string {
	if len(attrs) == 0 {
		return "none"
	}
	sorted := slices.Clone(attrs)
	slices.Sort(sorted)
	return "{" + strings.Join(sorted, ", ") + "}"
}

// MarkdownBlockKind is the kind of a leaf block of a GitHub Flavored Markdown
// document.
type MarkdownBlockKind int

const (
	// MarkdownParagraph is a paragraph block.
	MarkdownParagraph MarkdownBlockKind = iota
	// MarkdownHeading is an ATX or setext heading block.
	MarkdownHeading
	// MarkdownThematicBreak is a thematic break block.
	MarkdownThematicBreak
	// MarkdownFencedCode is a fenced code block.
	MarkdownFencedCode
	// MarkdownIndentedCode is an indented code block.
	MarkdownIndentedCode
	// MarkdownHTML is a raw HTML block.
	MarkdownHTML
	// MarkdownTable is a GFM table block.
	MarkdownTable
)

// String returns the short name of k.
func (k MarkdownBlockKind) String() string {
	switch k {
	case MarkdownParagraph:
		return "paragraph"
	case MarkdownHeading:
		return "heading"
	case MarkdownThematicBreak:
		return "break"
	case MarkdownFencedCode:
		return "fence"
	case MarkdownIndentedCode:
		return "indented"
	case MarkdownHTML:
		return "html"
	case MarkdownTable:
		return "table"
	default:
		return fmt.Sprintf("MarkdownBlockKind(%d)", int(k))
	}
}

// MarkdownBlock is one leaf block of a GitHub Flavored Markdown document as
// GitHub renders it. Lines are the block's lines with block quote markers and
// list item indentation removed, and LineNos their 0-based line numbers. A
// heading's one line is its text. A table's lines are its header row and its
// body rows, which Cells holds split into cells; its delimiter row is Delim.
type MarkdownBlock struct {
	Kind    MarkdownBlockKind
	Lines   []string
	LineNos []int
	Depth   int // block quotes and list items around the block
	Level   int // heading level
	Delim   string
	Cells   [][]string
}

// Text returns the block's text on one line.
func (b MarkdownBlock) Text() string {
	return strings.Join(strings.Fields(strings.Join(b.Lines, " ")), " ")
}

// mdContainer is an open block quote or list item.
type mdContainer struct {
	quote          bool // a block quote; otherwise a list item
	indent         int  // the column a list item's content starts at
	emptyFirstLine bool // a list item whose marker line had no content
}

// mdParser splits a document into leaf blocks by the block rules of the GitHub
// Flavored Markdown spec (https://github.github.com/gfm/): block quotes and
// list items with lazy paragraph continuation, ATX and setext headings,
// thematic breaks, fenced and indented code, HTML blocks, paragraphs and
// tables. Inline content is not parsed. Callers share this one parser across
// README.md, documentation.md, and dashboard checks so they agree on what
// renders as code, a table, or prose.
type mdParser struct {
	containers []mdContainer
	leaf       *MarkdownBlock
	fenceChar  byte
	fenceLen   int
	htmlEnd    *regexp.Regexp // end condition of an HTML block of kinds 1 to 5
	blocks     []MarkdownBlock
}

var (
	mdATXRE           = regexp.MustCompile(`^(#{1,6})(?:[ ]+|$)(.*)$`)
	mdATXCloseRE      = regexp.MustCompile(`(?:^|[ ]+)#+[ ]*$`)
	mdSetextRE        = regexp.MustCompile(`^(=+|-+)[ ]*$`)
	mdThematicBreakRE = regexp.MustCompile(`^(?:(?:\*[ ]*){3,}|(?:-[ ]*){3,}|(?:_[ ]*){3,})$`)
	mdDelimCellRE     = regexp.MustCompile(`^:?-+:?$`)
	mdHTMLRawRE       = regexp.MustCompile(`(?i)^<(script|pre|style|textarea)(?:[ \t>]|$)`)
	mdHTMLRawEndREs   = map[string]*regexp.Regexp{
		"script":   regexp.MustCompile(`(?i)</script>`),
		"pre":      regexp.MustCompile(`(?i)</pre>`),
		"style":    regexp.MustCompile(`(?i)</style>`),
		"textarea": regexp.MustCompile(`(?i)</textarea>`),
	}
	mdHTMLCommentEnd = regexp.MustCompile(`-->`)
	mdHTMLPIEnd      = regexp.MustCompile(`\?>`)
	mdHTMLDeclRE     = regexp.MustCompile(`^<![A-Za-z]`)
	mdHTMLDeclEnd    = regexp.MustCompile(`>`)
	mdHTMLCDATAEnd   = regexp.MustCompile(`\]\]>`)
	mdHTMLBlockTagRE = regexp.MustCompile(`(?i)^</?(?:address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title|tr|track|ul)(?:[ >]|/>|$)`)
	mdHTMLTagLineRE  = regexp.MustCompile("^(?:<[A-Za-z][A-Za-z0-9-]*(?:[ ]+[A-Za-z_:][A-Za-z0-9_.:-]*(?:[ ]*=[ ]*(?:[^ \"'=<>`]+|'[^']*'|\"[^\"]*\"))?)*[ ]*/?>|</[A-Za-z][A-Za-z0-9-]*[ ]*>)[ ]*$")
)

func mdLines(doc string) []string {
	return strings.Split(NormalizeEOL(doc), "\n")
}

// expandTabs expands tabs to the next multiple of four columns, the tab stop
// the GFM spec uses for block structure.
func expandTabs(line string) string {
	if !strings.Contains(line, "\t") {
		return line
	}
	var b strings.Builder
	col := 0
	for _, r := range line {
		if r == '\t' {
			n := 4 - col%4
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		col++
	}
	return b.String()
}

func leadingSpaces(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// ParseMarkdown returns the leaf blocks of a GitHub Flavored Markdown document
// in order.
func ParseMarkdown(doc string) []MarkdownBlock {
	var p mdParser
	for no, line := range mdLines(doc) {
		p.line(no, expandTabs(line))
	}
	p.closeLeaf()
	return p.blocks
}

func (p *mdParser) line(no int, line string) {
	rest, matched := line, 0
match:
	for idx, c := range p.containers {
		ind := leadingSpaces(rest)
		switch {
		case c.quote && ind <= 3 && ind < len(rest) && rest[ind] == '>':
			rest = strings.TrimPrefix(rest[ind+1:], " ")
		case c.quote:
			break match
		case strings.TrimSpace(rest) == "":
			if c.emptyFirstLine {
				break match
			}
			rest = ""
		case ind >= c.indent:
			p.containers[idx].emptyFirstLine = false
			rest = rest[c.indent:]
		default:
			break match
		}
		matched++
	}
	blank := strings.TrimSpace(rest) == ""

	if p.leaf != nil && matched == len(p.containers) {
		switch p.leaf.Kind {
		case MarkdownFencedCode:
			p.add(no, rest)
			if closesFence(rest, p.fenceChar, p.fenceLen) {
				p.closeLeaf()
			}
			return
		case MarkdownHTML:
			if p.htmlEnd == nil && blank {
				p.closeLeaf()
				return
			}
			p.add(no, rest)
			if p.htmlEnd != nil && p.htmlEnd.MatchString(rest) {
				p.closeLeaf()
			}
			return
		case MarkdownIndentedCode:
			if blank || leadingSpaces(rest) >= 4 {
				p.add(no, rest)
				return
			}
			p.closeLeaf()
		}
	}

	if matched < len(p.containers) {
		// A lazy continuation line extends an open paragraph without its
		// block quote markers or list indentation; any other line closes
		// the containers it does not continue.
		if p.leaf != nil && p.leaf.Kind == MarkdownParagraph && !blank && !startsBlock(rest) {
			p.add(no, strings.TrimSpace(rest))
			return
		}
		p.closeLeaf()
		p.containers = p.containers[:matched]
	}
	p.start(no, rest)
}

// start opens the containers and the leaf block that begin on a line, or
// adds the line to the open paragraph or table.
func (p *mdParser) start(no int, rest string) {
	for {
		inPara := p.leaf != nil && p.leaf.Kind == MarkdownParagraph
		inTable := p.leaf != nil && p.leaf.Kind == MarkdownTable
		if strings.TrimSpace(rest) == "" {
			if inPara || inTable {
				p.closeLeaf()
			}
			return
		}
		ind := leadingSpaces(rest)
		if ind >= 4 {
			if inPara {
				p.add(no, strings.TrimSpace(rest))
				return
			}
			// Indented code also ends a table.
			p.closeLeaf()
			p.push(MarkdownIndentedCode, no, rest)
			return
		}
		s := rest[ind:]
		if s[0] == '>' {
			p.closeLeaf()
			p.containers = append(p.containers, mdContainer{quote: true})
			rest = strings.TrimPrefix(s[1:], " ")
			continue
		}
		if m := mdATXRE.FindStringSubmatch(s); m != nil {
			p.closeLeaf()
			p.push(MarkdownHeading, no, strings.TrimSpace(mdATXCloseRE.ReplaceAllString(m[2], "")))
			p.leaf.Level = len(m[1])
			p.closeLeaf()
			return
		}
		if c, n, ok := opensFence(s); ok {
			p.closeLeaf()
			p.push(MarkdownFencedCode, no, rest)
			p.fenceChar, p.fenceLen = c, n
			return
		}
		if end, ok := startsHTML(s, inPara); ok {
			p.closeLeaf()
			p.push(MarkdownHTML, no, rest)
			p.htmlEnd = end
			if end != nil && end.MatchString(s) {
				p.closeLeaf()
			}
			return
		}
		if m := mdSetextRE.FindStringSubmatch(s); m != nil && inPara {
			p.leaf.Kind, p.leaf.Level = MarkdownHeading, 2
			if m[1][0] == '=' {
				p.leaf.Level = 1
			}
			p.closeLeaf()
			return
		}
		if mdThematicBreakRE.MatchString(s) {
			p.closeLeaf()
			p.push(MarkdownThematicBreak, no, s)
			p.closeLeaf()
			return
		}
		if width, content, ok := listMarker(s, inPara); ok {
			p.closeLeaf()
			p.containers = append(p.containers, mdContainer{
				indent:         ind + width,
				emptyFirstLine: strings.TrimSpace(content) == "",
			})
			rest = content
			continue
		}
		if inPara {
			// The paragraph's last line becomes the header row when this
			// line is a delimiter row with the same number of cells.
			if delim, ok := tableDelimiter(s); ok {
				if header := SplitMarkdownTableRow(p.leaf.Lines[len(p.leaf.Lines)-1]); len(header) == len(delim) {
					p.startTable(s, header)
					return
				}
			}
			p.add(no, strings.TrimSpace(rest))
			return
		}
		if inTable {
			// Any line that starts no other block is one more row, with or
			// without pipes.
			p.add(no, strings.TrimSpace(rest))
			p.leaf.Cells = append(p.leaf.Cells, SplitMarkdownTableRow(rest))
			return
		}
		p.closeLeaf()
		p.push(MarkdownParagraph, no, strings.TrimSpace(rest))
		return
	}
}

func (p *mdParser) push(kind MarkdownBlockKind, no int, line string) {
	p.leaf = &MarkdownBlock{Kind: kind, Depth: len(p.containers), Lines: []string{line}, LineNos: []int{no}}
}

func (p *mdParser) add(no int, line string) {
	p.leaf.Lines = append(p.leaf.Lines, line)
	p.leaf.LineNos = append(p.leaf.LineNos, no)
}

func (p *mdParser) startTable(delim string, header []string) {
	para := p.leaf
	last := len(para.Lines) - 1
	table := MarkdownBlock{
		Kind:    MarkdownTable,
		Depth:   para.Depth,
		Delim:   delim,
		Lines:   []string{para.Lines[last]},
		LineNos: []int{para.LineNos[last]},
		Cells:   [][]string{header},
	}
	para.Lines, para.LineNos = para.Lines[:last], para.LineNos[:last]
	if last > 0 {
		p.closeLeaf()
	}
	p.leaf = &table
}

func (p *mdParser) closeLeaf() {
	if p.leaf == nil {
		return
	}
	b := *p.leaf
	if b.Kind == MarkdownIndentedCode {
		for n := len(b.Lines); n > 0 && strings.TrimSpace(b.Lines[n-1]) == ""; n = len(b.Lines) {
			b.Lines, b.LineNos = b.Lines[:n-1], b.LineNos[:n-1]
		}
	}
	p.blocks = append(p.blocks, b)
	p.leaf, p.htmlEnd = nil, nil
}

// opensFence reports whether s, indentation removed, opens a fenced code
// block: three or more backticks whose info string has no backtick, or three
// or more tildes.
func opensFence(s string) (byte, int, bool) {
	if s == "" || (s[0] != '`' && s[0] != '~') {
		return 0, 0, false
	}
	c, n := s[0], 0
	for n < len(s) && s[n] == c {
		n++
	}
	if n < 3 || (c == '`' && strings.Contains(s[n:], "`")) {
		return 0, 0, false
	}
	return c, n, true
}

// closesFence reports whether line closes a fence of n c characters: at most
// three spaces of indentation, at least n of the same character, and nothing
// after them but spaces.
func closesFence(line string, c byte, n int) bool {
	ind := leadingSpaces(line)
	if ind > 3 {
		return false
	}
	s := line[ind:]
	m := 0
	for m < len(s) && s[m] == c {
		m++
	}
	return m >= n && strings.TrimRight(s[m:], " ") == ""
}

// startsHTML reports whether s starts an HTML block and returns the end
// condition of kinds 1 to 5; kinds 6 and 7 end at a blank line and kind 7
// cannot interrupt a paragraph.
func startsHTML(s string, inPara bool) (*regexp.Regexp, bool) {
	if m := mdHTMLRawRE.FindStringSubmatch(s); m != nil {
		return mdHTMLRawEndREs[strings.ToLower(m[1])], true
	}
	switch {
	case strings.HasPrefix(s, "<!--"):
		return mdHTMLCommentEnd, true
	case strings.HasPrefix(s, "<?"):
		return mdHTMLPIEnd, true
	case strings.HasPrefix(s, "<![CDATA["):
		return mdHTMLCDATAEnd, true
	case mdHTMLDeclRE.MatchString(s):
		return mdHTMLDeclEnd, true
	case mdHTMLBlockTagRE.MatchString(s):
		return nil, true
	case !inPara && mdHTMLTagLineRE.MatchString(s):
		return nil, true
	}
	return nil, false
}

// listMarker reports whether s starts a list item and returns the width of
// the marker and its spacing, which is where the item's content starts, and
// the content on this line. Inside a paragraph only a non-empty bullet item or
// an ordered item numbered 1 can start.
func listMarker(s string, inPara bool) (int, string, bool) {
	n := 0
	if s[0] == '-' || s[0] == '+' || s[0] == '*' {
		n = 1
	} else {
		for n < len(s) && n < 9 && s[n] >= '0' && s[n] <= '9' {
			n++
		}
		if n == 0 || n >= len(s) || (s[n] != '.' && s[n] != ')') || (inPara && s[:n] != "1") {
			return 0, "", false
		}
		n++
	}
	after := s[n:]
	if strings.TrimSpace(after) == "" {
		if inPara {
			return 0, "", false
		}
		return n + 1, "", true
	}
	if after[0] != ' ' {
		return 0, "", false
	}
	if spaces := leadingSpaces(after); spaces < 5 {
		return n + spaces, after[spaces:], true
	}
	return n + 1, after[1:], true
}

// tableDelimiter reports whether s is a table delimiter row and returns its
// cells.
func tableDelimiter(s string) ([]string, bool) {
	cells := SplitMarkdownTableRow(s)
	for _, c := range cells {
		if !mdDelimCellRE.MatchString(c) {
			return nil, false
		}
	}
	return cells, true
}

// startsBlock reports whether a line starts a block that interrupts a
// paragraph, which keeps it from being a lazy continuation line.
func startsBlock(line string) bool {
	ind := leadingSpaces(line)
	if ind >= 4 || ind == len(line) {
		return false
	}
	s := line[ind:]
	if s[0] == '>' || mdATXRE.MatchString(s) || mdThematicBreakRE.MatchString(s) {
		return true
	}
	if _, _, ok := opensFence(s); ok {
		return true
	}
	if _, ok := startsHTML(s, true); ok {
		return true
	}
	_, _, ok := listMarker(s, true)
	return ok
}

// SkipMarkdownCodeSpan returns the index just past the code span that opens
// with the backtick run at s[i], or past the run itself when no run of the
// same length closes it, in which case the run is literal text.
func SkipMarkdownCodeSpan(s string, i int) int {
	n := 0
	for i+n < len(s) && s[i+n] == '`' {
		n++
	}
	for j := i + n; j < len(s); {
		if s[j] != '`' {
			j++
			continue
		}
		m := 0
		for j+m < len(s) && s[j+m] == '`' {
			m++
		}
		if m == n {
			return j + m
		}
		j += m
	}
	return i + n
}

// FirstMarkdownPipe returns the index of the first pipe in s that is neither
// escaped nor inside a code span, or -1.
func FirstMarkdownPipe(s string) int {
	for i := 0; i < len(s); {
		switch s[i] {
		case '\\':
			i += 2
		case '`':
			i = SkipMarkdownCodeSpan(s, i)
		case '|':
			return i
		default:
			i++
		}
	}
	return -1
}

// ReadmeSelfTelemetrySection is the self-telemetry table of README.md and the
// blocks from its intro paragraph up to the next heading of level 3 or higher.
type ReadmeSelfTelemetrySection struct {
	Rows   []ReadmeTelemetryRow
	Blocks []MarkdownBlock
	// Intro and Table index the intro paragraph and the table in Blocks, and
	// Blocks[Intro:End] (excluding Table) are the section's blocks.
	Intro, Table, End int
}

// ParseReadmeSelfTelemetrySection locates and strictly parses the README.md
// self-telemetry table and its surrounding section blocks.
func ParseReadmeSelfTelemetrySection(readme string) (ReadmeSelfTelemetrySection, error) {
	blocks := ParseMarkdown(readme)
	intro := slices.IndexFunc(blocks, func(b MarkdownBlock) bool {
		return b.Kind == MarkdownParagraph && b.Depth == 0 && strings.Contains(b.Text(), ReadmeSelfTelemetryIntro)
	})
	if intro < 0 {
		return ReadmeSelfTelemetrySection{}, fmt.Errorf("README.md is missing self-telemetry intro %q", ReadmeSelfTelemetryIntro)
	}
	table := -1
	for i := intro + 1; i < len(blocks) && table < 0; i++ {
		if blocks[i].Kind == MarkdownHeading && blocks[i].Depth == 0 {
			break
		}
		if blocks[i].Kind == MarkdownTable && blocks[i].Depth == 0 {
			table = i
		}
	}
	if table < 0 {
		return ReadmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry markdown table not found after intro")
	}

	wantHeader := ReadmeSelfTelemetryHeader()
	tb := blocks[table]
	if header := tb.Cells[0]; !slices.Equal(header, wantHeader) {
		return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table header = %v, want %v", header, wantHeader)
	}
	if sep := SplitMarkdownTableRow(tb.Delim); len(sep) != len(wantHeader) || !IsMarkdownSeparatorRow(sep) {
		return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry table separator row %v is malformed", sep)
	}

	var rows []ReadmeTelemetryRow
	for r := 1; r < len(tb.Lines); r++ {
		line, cells := tb.Lines[r], tb.Cells[r]
		// GitHub ends a table only at a blank line or the start of another
		// block, so prose right under the last row renders as a row.
		if !strings.HasPrefix(line, "|") {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("README.md self-telemetry table is followed directly by %q; GitHub renders that line as a table row, so leave a blank line", line)
		}
		if len(cells) != len(wantHeader) {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry row %q has %d cells, want %d", line, len(cells), len(wantHeader))
		}
		metricName, ok := UnwrapInlineCode(cells[0])
		if !ok || metricName == "" {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry metric cell %q must be single inline code", cells[0])
		}
		typeLabel, ok := UnwrapInlineCode(cells[1])
		if !ok || typeLabel == "" {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry type cell %q for %s must be single inline code", cells[1], metricName)
		}
		unit, ok := UnwrapInlineCode(cells[2])
		if !ok || unit == "" {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry unit cell %q for %s must be single inline code", cells[2], metricName)
		}
		attrsRaw, ok := UnwrapInlineCode(cells[3])
		if !ok || attrsRaw == "" {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("self-telemetry attributes cell %q for %s must be single inline code", cells[3], metricName)
		}
		attrs, err := ParseReadmeMetricAttrs(attrsRaw)
		if err != nil {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("%s: %w", metricName, err)
		}
		if cells[4] == "" {
			return ReadmeSelfTelemetrySection{}, fmt.Errorf("%s: meaning cell is empty", metricName)
		}
		rows = append(rows, ReadmeTelemetryRow{
			Metric:  metricName,
			Type:    typeLabel,
			Unit:    unit,
			Attrs:   attrs,
			Meaning: cells[4],
		})
	}

	end := table + 1
	for end < len(blocks) && (blocks[end].Kind != MarkdownHeading || blocks[end].Depth > 0 || blocks[end].Level > 3) {
		end++
	}
	return ReadmeSelfTelemetrySection{Rows: rows, Blocks: blocks, Intro: intro, Table: table, End: end}, nil
}

// Prose returns the rendered text of the self-telemetry section outside the
// intro sentence and table, one entry per paragraph, heading, HTML block or
// table cell, wherever block quotes or lists put it. Code is not prose.
func (s ReadmeSelfTelemetrySection) Prose() []string {
	var units []string
	for i := s.Intro; i < s.End; i++ {
		if i == s.Table {
			continue
		}
		b := s.Blocks[i]
		if i == s.Intro {
			if rest := strings.TrimSpace(strings.Replace(b.Text(), ReadmeSelfTelemetryIntroFull, "", 1)); rest != "" {
				units = append(units, rest)
			}
			continue
		}
		switch b.Kind {
		case MarkdownParagraph, MarkdownHeading, MarkdownHTML:
			units = append(units, b.Text())
		case MarkdownTable:
			for _, row := range b.Cells {
				units = append(units, row...)
			}
		}
	}
	return units
}
