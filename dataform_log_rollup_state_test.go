// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package bigqueryexporter

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/schema"
)

// The tests of this file run the Dataform package as Dataform would: they
// select actions by tag (or by name, as --actions does), skip disabled actions,
// order the selection by its dependencies, skip the dependents of a failed
// action, and track the rows of the run window tables. Which window an action
// reads and which window its post_operations commit come from the rendered
// .sqlx files, so a definition that reads or commits the wrong window changes
// the outcome of a run.

// dfxWindowRow is the one row of a run window table.
type dfxWindowRow struct {
	start     time.Time
	committed bool
}

// dfxRunRecord is what one simulated invocation did.
type dfxRunRecord struct {
	executed []string             // the actions that ran to the end, in order
	failed   []string             // the actions that failed
	skipped  []string             // the selected actions that did not run
	reads    map[string]time.Time // the window_start each executed or failed action read
}

// dfxSim is a Dataform project and the run window tables it has written.
type dfxSim struct {
	t        *testing.T
	pkg      *dfxPackage
	vars     map[string]string
	lookback int
	windows  map[string]*dfxWindowRow
}

var dfxEpoch = time.Unix(0, 0).UTC()

func newDfxSim(t *testing.T, files dashFileSet, overrides map[string]string) *dfxSim {
	t.Helper()
	pkg := dfxLoadWithVars(files, overrides)
	lookback, err := dfxLookback(pkg)
	if err != nil {
		t.Fatalf("dfxLookback: %v", err)
	}
	vars := map[string]string{}
	for _, a := range pkg.byName {
		for k, v := range a.vars {
			vars[k] = v
		}
		break
	}
	return &dfxSim{t: t, pkg: pkg, vars: vars, lookback: lookback, windows: map[string]*dfxWindowRow{}}
}

// disabled evaluates the disabled config key of an action with the variables.
func (s *dfxSim) disabled(a *dfxAction) bool {
	switch a.cfg.disabled {
	case "":
		return false
	case dfxLogToggleExpr:
		return s.vars["enable_log_volume_rollup"] != "true"
	}
	s.t.Fatalf("%s: the simulation does not know disabled: %s", a.name, a.cfg.disabled)
	return false
}

// byTag returns the actions dataform run --tags tag selects.
func (s *dfxSim) byTag(tag string) []string {
	var names []string
	for _, name := range dashSortedKeys(s.pkg.byName) {
		if slices.Contains(s.pkg.byName[name].cfg.tags, tag) {
			names = append(names, name)
		}
	}
	return names
}

// all returns the actions an untagged dataform run selects.
func (s *dfxSim) all() []string {
	var names []string
	for _, name := range dashSortedKeys(s.pkg.byName) {
		if s.pkg.byName[name].cfg.typ != "declaration" {
			names = append(names, name)
		}
	}
	return names
}

// upstream returns the actions of the package that a reads or depends on.
func (s *dfxSim) upstream(a *dfxAction) []string {
	var out []string
	for _, name := range slices.Concat(dfxRefs(a), a.cfg.deps) {
		if target := s.pkg.byName[name]; target != nil && target.cfg.typ != "declaration" && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// windowOf returns the run window table whose window_start an incremental run
// of a declares, from its rendered DECLARE window_start.
func (s *dfxSim) windowOf(a *dfxAction) string {
	run, err := dfxRender(a, true)
	if err != nil {
		s.t.Fatalf("%s: %v", a.name, err)
	}
	st := run.find("declare window_start")
	if st == nil {
		return ""
	}
	expr := dfxWindowExpr(st)
	for _, w := range []string{dfxRunWindow, dfxLogsRunWindow} {
		if expr == dfxWindowExprFor(w) {
			return w
		}
	}
	s.t.Fatalf("%s: window_start is %s, which reads no run window", a.name, expr)
	return ""
}

// run simulates one invocation at now over the selected actions. An action in
// fail fails after it has read its window and before its post_operations.
func (s *dfxSim) run(now time.Time, selected []string, fail ...string) dfxRunRecord {
	s.t.Helper()
	rec := dfxRunRecord{reads: map[string]time.Time{}}
	inSel := map[string]bool{}
	for _, n := range selected {
		if s.pkg.byName[n] == nil {
			s.t.Fatalf("no action %s", n)
		}
		inSel[n] = true
	}
	// Topological order of the selection.
	var order []string
	state := map[string]int{}
	var visit func(string)
	visit = func(n string) {
		if state[n] != 0 {
			return
		}
		state[n] = 1
		for _, up := range s.upstream(s.pkg.byName[n]) {
			if inSel[up] {
				visit(up)
			}
		}
		state[n] = 2
		order = append(order, n)
	}
	for _, n := range selected {
		visit(n)
	}
	done := map[string]bool{}
	for _, n := range order {
		a := s.pkg.byName[n]
		blocked := false
		for _, up := range s.upstream(a) {
			if inSel[up] && !done[up] {
				blocked = true
			}
		}
		if s.disabled(a) || blocked {
			rec.skipped = append(rec.skipped, n)
			continue
		}
		if dfxIsRunWindow(n) {
			// stg_run_window and its twin (dfxCheckRunWindowTwin): LEAST of the
			// candidate and an uncommitted previous window_start; a first run
			// or a full refresh seeds the epoch. Always is_committed = FALSE.
			cand := now.Add(-time.Duration(s.lookback) * time.Hour).Truncate(time.Hour)
			start := dfxEpoch
			if row := s.windows[n]; row != nil {
				start = cand
				if !row.committed && row.start.Before(cand) {
					start = row.start
				}
			}
			s.windows[n] = &dfxWindowRow{start: start}
			rec.executed = append(rec.executed, n)
			done[n] = true
			continue
		}
		window := s.windowOf(a)
		incremental := true
		if window != "" {
			row := s.windows[window]
			if row == nil {
				s.t.Fatalf("%s reads %s, which no run has created", n, window)
			}
			rec.reads[n] = row.start
		}
		if slices.Contains(fail, n) {
			rec.failed = append(rec.failed, n)
			continue
		}
		run, err := dfxRender(a, incremental)
		if err != nil {
			s.t.Fatalf("%s: %v", n, err)
		}
		for _, st := range run.post {
			switch st.kind {
			case "commit run_window":
				s.windows[dfxRunWindow].committed = true
			case "commit logs_run_window":
				s.windows[dfxLogsRunWindow].committed = true
			}
		}
		rec.executed = append(rec.executed, n)
		done[n] = true
	}
	return rec
}

func dfxAt(h int) time.Time { return time.Date(2026, 11, 13, h, 5, 0, 0, time.UTC) }

func dfxHour(h int) time.Time { return time.Date(2026, 11, 13, h, 0, 0, 0, time.UTC) }

// TestDataformLogsOnlyRunsAdvanceTheirOwnWindow runs the log rollup alone
// (dataform run --tags otel_log_marts) and checks that its second run starts at
// the bounded lookback cutoff, not at the epoch, that a failed rollup leaves
// the window uncommitted so the next run replays it, and that a logs-only run
// never touches stg_run_window or a trace mart.
func TestDataformLogsOnlyRunsAdvanceTheirOwnWindow(t *testing.T) {
	files := dashLoadFileSet(t)
	sim := newDfxSim(t, files, map[string]string{"enable_log_volume_rollup": "true"})
	sel := sim.byTag(dfxLogTag)
	if want := []string{dfxLogRollup, dfxLogsRunWindow}; !slices.Equal(sel, want) {
		t.Fatalf("--tags %s selects %v, want %v", dfxLogTag, sel, want)
	}

	// Run 1: the first run builds from the epoch and commits.
	r1 := sim.run(dfxAt(10), sel)
	if got := r1.reads[dfxLogRollup]; !got.Equal(dfxEpoch) {
		t.Fatalf("run 1: the rollup read window_start %v, want the epoch", got)
	}
	if row := sim.windows[dfxLogsRunWindow]; !row.committed {
		t.Fatalf("run 1: %s is not committed after a successful rollup", dfxLogsRunWindow)
	}
	// Run 2: the bounded lookback, not the epoch.
	r2 := sim.run(dfxAt(11), sel)
	if got, want := r2.reads[dfxLogRollup], dfxHour(8); !got.Equal(want) {
		t.Fatalf("run 2: the rollup read window_start %v, want the lookback cutoff %v (not the epoch)", got, want)
	}
	// Run 3 fails in the rollup: the window stays uncommitted.
	r3 := sim.run(dfxAt(12), sel, dfxLogRollup)
	if got, want := r3.reads[dfxLogRollup], dfxHour(9); !got.Equal(want) {
		t.Fatalf("run 3: the rollup read window_start %v, want %v", got, want)
	}
	if row := sim.windows[dfxLogsRunWindow]; row.committed || !row.start.Equal(dfxHour(9)) {
		t.Fatalf("run 3: after a failed rollup %s = %+v, want window_start %v uncommitted", dfxLogsRunWindow, *row, dfxHour(9))
	}
	// Run 4 replays the failed window, then commits.
	r4 := sim.run(dfxAt(13), sel)
	if got, want := r4.reads[dfxLogRollup], dfxHour(9); !got.Equal(want) {
		t.Fatalf("run 4: the rollup read window_start %v, want the uncommitted %v replayed", got, want)
	}
	if !sim.windows[dfxLogsRunWindow].committed {
		t.Fatalf("run 4: %s is not committed after the replay", dfxLogsRunWindow)
	}
	// Run 5 is back to the bounded lookback.
	if got, want := sim.run(dfxAt(14), sel).reads[dfxLogRollup], dfxHour(11); !got.Equal(want) {
		t.Fatalf("run 5: the rollup read window_start %v, want %v", got, want)
	}
	if _, touched := sim.windows[dfxRunWindow]; touched {
		t.Fatalf("a logs-only run created or changed %s", dfxRunWindow)
	}
	for _, rec := range []dfxRunRecord{r1, r2, r3, r4} {
		for _, n := range rec.executed {
			if n != dfxLogRollup && n != dfxLogsRunWindow {
				t.Errorf("a logs-only run executed %s", n)
			}
		}
	}

	// The design this replaces: the rollup read stg_run_window, which only
	// the trajectory mart commits, so a logs-only run never committed it and
	// every later run rescanned from the epoch. The simulation reproduces it.
	old := files.clone()
	edited, err := dashReplaceAll(`${ref("stg_logs_run_window")}`, `${ref("stg_run_window")}`)(old[dfxFLogRollup])
	if err == nil {
		edited, err = dfxDropLine(`UPDATE ${ref("stg_run_window")} SET is_committed = TRUE WHERE TRUE`)(edited)
	}
	if err == nil {
		edited, err = dashReplaceFirst(`dependencies: ["stg_logs_run_window"]`, `dependencies: ["stg_run_window"]`)(edited)
	}
	if err != nil {
		t.Fatalf("rebuilding the coupled rollup: %v", err)
	}
	old[dfxFLogRollup] = edited
	oldSim := newDfxSim(t, old, map[string]string{"enable_log_volume_rollup": "true"})
	oldSel := []string{dfxRunWindow, dfxLogRollup} // --actions stg_run_window,m_otel_log_volume_rollup
	oldSim.run(dfxAt(10), oldSel)
	if got := oldSim.run(dfxAt(11), oldSel).reads[dfxLogRollup]; !got.Equal(dfxEpoch) {
		t.Fatalf("the coupled rollup read window_start %v on its second logs-only run; the simulation must reproduce the epoch rescan", got)
	}
}

// TestDataformTracesOnlyDAGNeverReadsLogs checks that dataform run --tags
// otel_marts selects no log action, that nothing it runs reads otel_logs or
// waits on the log rollup, and that it commits stg_run_window on its own; that
// an untagged run with the default settings skips the disabled log actions;
// and that with the rollup enabled, a failed rollup holds back only its own
// window and never the trace window.
func TestDataformTracesOnlyDAGNeverReadsLogs(t *testing.T) {
	files := dashLoadFileSet(t)
	sim := newDfxSim(t, files, nil)
	traces := sim.byTag(dfxTag)
	for _, n := range traces {
		a := sim.pkg.byName[n]
		if n == dfxLogRollup || n == dfxLogsRunWindow {
			t.Fatalf("--tags %s selects the log action %s", dfxTag, n)
		}
		if slices.Contains(dfxRefs(a), dfxLogsSource) {
			t.Errorf("%s (tag %s) reads %s", n, dfxTag, dfxLogsSource)
		}
		for _, up := range sim.upstream(a) {
			if !slices.Contains(traces, up) {
				t.Errorf("%s (tag %s) depends on %s, which --tags %s does not select", n, dfxTag, up, dfxTag)
			}
		}
	}
	r1 := sim.run(dfxAt(10), traces)
	if len(r1.failed)+len(r1.skipped) != 0 || !sim.windows[dfxRunWindow].committed {
		t.Fatalf("traces-only run 1: %+v, committed=%v; want every trace action run and %s committed", r1, sim.windows[dfxRunWindow].committed, dfxRunWindow)
	}
	if got, want := sim.run(dfxAt(11), traces).reads[dfxTraj], dfxHour(8); !got.Equal(want) {
		t.Fatalf("traces-only run 2: the trajectory read %v, want %v", got, want)
	}
	// A failed aggregate mart blocks the trajectory barrier: the trace window
	// stays uncommitted and is replayed.
	r3 := sim.run(dfxAt(12), traces, "m_gen_ai_model_costs_hourly")
	if !slices.Contains(r3.skipped, dfxTraj) || sim.windows[dfxRunWindow].committed {
		t.Fatalf("a failed trace mart must skip %s and leave %s uncommitted: %+v", dfxTraj, dfxRunWindow, r3)
	}
	if got, want := sim.run(dfxAt(13), traces).reads[dfxTraj], dfxHour(9); !got.Equal(want) {
		t.Fatalf("the run after a failed trace mart read %v, want the uncommitted %v", got, want)
	}

	// An untagged run with the default settings: the log actions are disabled.
	untagged := newDfxSim(t, files, nil)
	ru := untagged.run(dfxAt(10), untagged.all())
	if !slices.Contains(ru.skipped, dfxLogRollup) || !slices.Contains(ru.skipped, dfxLogsRunWindow) {
		t.Fatalf("an untagged run with enable_log_volume_rollup=%q ran the log actions: %+v", untagged.vars["enable_log_volume_rollup"], ru)
	}
	if _, ok := ru.reads[dfxLogRollup]; ok || len(ru.failed) != 0 || !untagged.windows[dfxRunWindow].committed {
		t.Fatalf("an untagged traces-only run: %+v; want no log action and %s committed", ru, dfxRunWindow)
	}

	// Enabled and untagged, the rollup fails: the trace window still commits.
	both := newDfxSim(t, files, map[string]string{"enable_log_volume_rollup": "true"})
	rb := both.run(dfxAt(10), both.all(), dfxLogRollup)
	if !both.windows[dfxRunWindow].committed || both.windows[dfxLogsRunWindow].committed {
		t.Fatalf("a failed rollup in a full run: %s committed=%v, %s committed=%v; want true, false (%+v)",
			dfxRunWindow, both.windows[dfxRunWindow].committed, dfxLogsRunWindow, both.windows[dfxLogsRunWindow].committed, rb)
	}
	rb2 := both.run(dfxAt(11), both.all())
	if got, want := rb2.reads[dfxTraj], dfxHour(8); !got.Equal(want) {
		t.Errorf("the trajectory read %v after a failed rollup, want %v", got, want)
	}
	if got := rb2.reads[dfxLogRollup]; !got.Equal(dfxEpoch) {
		t.Errorf("the rollup read %v after its failed first run, want the epoch replayed", got)
	}
}

// TestDataformCustomLogsTableName checks that vars.otel_logs_table renames the
// logs declaration and that the rollup reads the renamed table, and that a
// value that is not a table name fails the compilation of the rollup.
func TestDataformCustomLogsTableName(t *testing.T) {
	files := dashLoadFileSet(t)
	for _, table := range []string{dfxLogsSource, "my_logs", "otel_logs_v2"} {
		t.Run(table, func(t *testing.T) {
			pkg := dfxLoadWithVars(files, map[string]string{"otel_logs_table": table})
			decl := pkg.byFile[dfxFLogsSrc]
			if decl == nil || decl.name != table || decl.cfg.nameExpr != dfxLogsTableExpr {
				t.Fatalf("the logs declaration = %+v, want the name %s from %s", decl, table, dfxLogsTableExpr)
			}
			if pkg.byName[table] != decl {
				t.Fatalf("the action %s is not the logs declaration", table)
			}
			rollup := pkg.byName[dfxLogRollup]
			if refs := dfxRefs(rollup); !dfxSameSet(refs, []string{dfxLogsRunWindow, table}) {
				t.Errorf("the rollup reads %v, want [%s %s]", refs, dfxLogsRunWindow, table)
			}
			for _, ref := range dfxRefs(rollup) {
				if pkg.byName[ref] == nil {
					t.Errorf("the rollup reads %s, which names no action of the package", ref)
				}
			}
			run, err := dfxRender(rollup, true)
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			q, err := dashParseSQL(run.body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if got := dashJoin(dfxCTE(q, "logs").branches[0].clauses["FROM"]); got != "ref."+table {
				t.Errorf("the rollup reads FROM %s, want ref.%s", got, table)
			}
			for _, n := range dashSortedKeys(pkg.byName) {
				if n != dfxLogRollup && slices.Contains(dfxRefs(pkg.byName[n]), table) {
					t.Errorf("%s reads the logs table %s", n, table)
				}
			}
		})
	}
	for _, bad := range []string{"", "my logs", "x`; DROP TABLE y; --"} {
		pkg := dfxLoadWithVars(files, map[string]string{"otel_logs_table": bad})
		if _, err := dfxRender(pkg.byName[dfxLogRollup], true); err == nil || !strings.Contains(err.Error(), "is not a table name") {
			t.Errorf("otel_logs_table=%q: render error = %v, want a table name error", bad, err)
		}
	}
}

// TestDataformLogRollupSeverityAndErrorCount checks that the rollup resolves
// the severity of a log row with exactly the expression of
// otel_logs_as_alllogs and counts as an error every row it groups as ERROR or
// above, including a row with severity_text ERROR and severity_number 0.
func TestDataformLogRollupSeverityAndErrorCount(t *testing.T) {
	files := dashLoadFileSet(t)
	pkg := dfxLoad(files)
	run, err := dfxRender(pkg.byName[dfxLogRollup], true)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got := strings.Count(squash(run.body), squash(schema.LogSeverityNumberSQL)); got != 1 {
		t.Fatalf("the rollup holds LogSeverityNumberSQL %d times, want 1 (resolved once per log row)", got)
	}
	view := fmt.Sprintf(schema.LogsAsAllLogsViewQuery, "p", "d", dfxLogsSource)
	if got := strings.Count(squash(view), squash(schema.LogSeverityNumberSQL)); got != 2 {
		t.Fatalf("otel_logs_as_alllogs holds LogSeverityNumberSQL %d times, want 2", got)
	}
	if strings.Contains(run.body, ">= 17") {
		t.Fatal("the rollup still counts errors from the raw OTLP severity_number")
	}

	ptr := func(n int64) *int64 { return &n }
	isError := func(severity string) bool { return slices.Contains(dfxLogErrorSeverities, severity) }
	for _, tc := range []struct {
		num       *int64
		text      string
		severity  string
		wantError bool
	}{
		{ptr(0), "ERROR", "ERROR", true}, // grouped as ERROR, counted as an error
		{ptr(0), "FATAL", "CRITICAL", true},
		{ptr(0), "ALERT", "ALERT", true},
		{ptr(0), "EMERGENCY", "EMERGENCY", true},
		{nil, "error", "ERROR", true},
		{ptr(17), "", "ERROR", true},
		{ptr(21), "FATAL", "CRITICAL", true},
		{ptr(24), "EMERGENCY", "EMERGENCY", true},
		{ptr(16), "ERROR", "WARNING", false}, // the number band wins
		{ptr(13), "WARN", "WARNING", false},
		{ptr(0), "WARN", "WARNING", false},
		{ptr(9), "INFO", "INFO", false},
		{ptr(0), "", "DEFAULT", false},
	} {
		severity, number := allLogsCanonicalSeverity(tc.num, tc.text)
		if severity != tc.severity || isError(severity) != tc.wantError || (number >= 500) != tc.wantError {
			t.Errorf("(%v, %q): severity %s (%d), counted as an error %v; want %s, %v", tc.num, tc.text, severity, number, isError(severity), tc.severity, tc.wantError)
		}
	}
}
