// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const rlimitHelperEnv = "BQ_QUARANTINE_REPLAY_RLIMIT_HELPER"

func TestCLIRlimitFSizeHelper(t *testing.T) {
	if os.Getenv(rlimitHelperEnv) != "1" {
		return
	}
	inPath := os.Getenv("BQ_RLIMIT_INPUT")
	outPath := os.Getenv("BQ_RLIMIT_OUTPUT")
	cpPath := os.Getenv("BQ_RLIMIT_CHECKPOINT")
	if inPath == "" || outPath == "" || cpPath == "" {
		t.Fatal("missing helper env vars")
	}

	signal.Ignore(syscall.SIGXFSZ)
	bytesLimit, err := strconv.ParseUint(os.Getenv("BQ_RLIMIT_BYTES"), 10, 64)
	if err != nil {
		t.Fatalf("bad BQ_RLIMIT_BYTES: %v", err)
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatalf("Getrlimit: %v", err)
	}
	limit.Cur = bytesLimit
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatalf("Setrlimit: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("expected non-zero exit under RLIMIT_FSIZE=%d, got 0", bytesLimit)
	}
}

func TestCLICheckpointResumeAfterRLimitFSize(t *testing.T) {
	dir := t.TempDir()
	inPath := filepath.Join(dir, "in.ndjson")
	outPath := filepath.Join(dir, "out.ndjson")
	cpPath := filepath.Join(dir, "replay.checkpoint.json")

	pad := strings.Repeat("x", 1024)
	rec0 := quarantineLine(t, "span-zero-"+pad)
	rec1 := quarantineLine(t, "span-one-"+pad)
	rec2 := quarantineLine(t, "span-two-"+pad)
	if err := os.WriteFile(inPath, []byte(rec0+rec1+rec2), 0o600); err != nil {
		t.Fatal(err)
	}

	// Discover the exact serialized output length of rec0 so RLIMIT_FSIZE falls
	// squarely inside rec1's write, forcing a partial short write + EFBIG.
	probeIn := filepath.Join(dir, "probe-in.ndjson")
	if err := os.WriteFile(probeIn, []byte(rec0), 0o600); err != nil {
		t.Fatal(err)
	}
	probeOut := filepath.Join(dir, "probe.ndjson")
	var probeStdout, probeStderr bytes.Buffer
	if code := run([]string{"-input=" + probeIn, "-output=" + probeOut}, strings.NewReader(""), &probeStdout, &probeStderr); code != 0 {
		t.Fatalf("probe failed: code=%d stderr=%s", code, probeStderr.String())
	}
	probeInfo, err := os.Stat(probeOut)
	if err != nil {
		t.Fatal(err)
	}
	fsizeLimit := probeInfo.Size() + 64

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestCLIRlimitFSizeHelper$")
	cmd.Env = append(os.Environ(),
		rlimitHelperEnv+"=1",
		"BQ_RLIMIT_INPUT="+inPath,
		"BQ_RLIMIT_OUTPUT="+outPath,
		"BQ_RLIMIT_CHECKPOINT="+cpPath,
		"BQ_RLIMIT_BYTES="+strconv.FormatInt(fsizeLimit, 10),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("RLIMIT_FSIZE helper failed unexpectedly: %v\n%s", err, out)
	}

	// Partial write during rec1 must have been rolled back immediately so rec0
	// remains intact with no corrupt trailing fragment.
	afterCrash, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(afterCrash)) != probeInfo.Size() {
		t.Fatalf("output size after EFBIG rollback = %d, want %d (rec0 only)", len(afterCrash), probeInfo.Size())
	}

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("resume after RLIMIT_FSIZE failed: code=%d stderr=%s", code, stderr.String())
	}
	resumed, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(resumed), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("resumed line count = %d, want 3", len(lines))
	}
	for i, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("line %d is invalid JSON after resume: %q", i, line)
		}
	}
	for i, wantName := range []string{"span-zero-", "span-one-", "span-two-"} {
		if !strings.Contains(lines[i], wantName) {
			t.Fatalf("line %d missing %q", i, wantName)
		}
	}
}
