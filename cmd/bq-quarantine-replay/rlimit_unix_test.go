// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
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

func TestCLICheckpointFIFOOutputWriteOnly(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "out.fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}
	cpPath := filepath.Join(dir, "replay.checkpoint.json")
	rec0 := quarantineLine(t, "fifo-span-0")

	// Synchronize reader disconnect strictly before sending the first input line:
	// with O_WRONLY, closing the sole reader before Write must trigger EPIPE
	// (exit != 0) without creating/advancing the checkpoint, instead of O_RDWR
	// silently holding the pipe open and discarding unread data on close.
	pr, pw := io.Pipe()
	readerClosed := make(chan error, 1)
	go func() {
		rf, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
		if err != nil {
			readerClosed <- err
			return
		}
		readerClosed <- rf.Close()
	}()

	runDone := make(chan int, 1)
	var errOut bytes.Buffer
	go func() {
		var out bytes.Buffer
		runDone <- run([]string{"-input=-", "-output=" + fifoPath, "-checkpoint-file=" + cpPath}, pr, &out, &errOut)
	}()

	select {
	case err := <-readerClosed:
		if err != nil {
			t.Fatalf("FIFO reader open/close failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		_ = pw.Close()
		t.Fatal("timed out waiting for FIFO reader disconnect")
	}

	if _, err := io.WriteString(pw, rec0); err != nil {
		t.Fatalf("writing input pipe: %v", err)
	}
	_ = pw.Close()

	select {
	case code := <-runDone:
		if code == 0 {
			t.Fatalf("expected non-zero exit when FIFO reader closed before write, got 0 (stderr=%s)", errOut.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for FIFO broken-pipe run to exit")
	}
	if !strings.Contains(strings.ToLower(errOut.String()), "broken pipe") && !strings.Contains(strings.ToLower(errOut.String()), "epipe") {
		t.Fatalf("stderr = %q, want broken pipe error", errOut.String())
	}
	if _, statErr := os.Stat(cpPath); !errors.Is(statErr, fs.ErrNotExist) {
		t.Fatalf("checkpoint %q exists or unexpected error after failed FIFO write: %v", cpPath, statErr)
	}

	// Re-run with an active reader draining the FIFO until EOF.
	inPath := filepath.Join(dir, "in.ndjson")
	if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
		t.Fatal(err)
	}
	type fifoReadResult struct {
		data []byte
		err  error
	}
	readCh := make(chan fifoReadResult, 1)
	go func() {
		rf, err := os.OpenFile(fifoPath, os.O_RDONLY, 0)
		if err != nil {
			readCh <- fifoReadResult{err: err}
			return
		}
		data, rerr := io.ReadAll(rf)
		cerr := rf.Close()
		if rerr == nil {
			rerr = cerr
		}
		readCh <- fifoReadResult{data: data, err: rerr}
	}()

	var out2, err2 bytes.Buffer
	code := run([]string{"-input=" + inPath, "-output=" + fifoPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out2, &err2)
	if code != 0 {
		t.Fatalf("resumed FIFO run failed: code=%d stderr=%s", code, err2.String())
	}
	res := <-readCh
	if res.err != nil {
		t.Fatalf("reading FIFO output failed: %v", res.err)
	}
	line := strings.TrimSuffix(string(res.data), "\n")
	if !json.Valid([]byte(line)) || !strings.Contains(line, "fifo-span-0") {
		t.Fatalf("unexpected FIFO output: %q", string(res.data))
	}
}

func TestCLICheckpointResumeMode0200Output(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores 0200 read permission restrictions")
	}
	rec0 := quarantineLine(t, "wronly-span-0")
	rec1 := quarantineLine(t, "wronly-span-1")

	t.Run("clean resume succeeds when size matches checkpoint output_bytes", func(t *testing.T) {
		dir := t.TempDir()
		inPath := filepath.Join(dir, "in.ndjson")
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "replay.checkpoint.json")
		t.Cleanup(func() { _ = os.Chmod(outPath, 0o600) })

		if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
			t.Fatal(err)
		}
		var out1, err1 bytes.Buffer
		if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out1, &err1); code != 0 {
			t.Fatalf("initial run failed: code=%d stderr=%s", code, err1.String())
		}

		if err := os.Chmod(outPath, 0o200); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(inPath, []byte(rec0+rec1), 0o600); err != nil {
			t.Fatal(err)
		}
		var out2, err2 bytes.Buffer
		if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out2, &err2); code != 0 {
			t.Fatalf("clean mode 0200 resume failed: code=%d stderr=%s", code, err2.String())
		}

		if err := os.Chmod(outPath, 0o600); err != nil {
			t.Fatal(err)
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
			t.Fatalf("corrupt mode 0200 output after clean resume: %q", string(finalBytes))
		}
		if !strings.Contains(lines[0], "wronly-span-0") || !strings.Contains(lines[1], "wronly-span-1") {
			t.Fatalf("unexpected records after clean mode 0200 resume: %q", string(finalBytes))
		}
	})

	t.Run("fails closed without truncation when extra bytes exist under 0200 and resumes after chmod 0600", func(t *testing.T) {
		dir := t.TempDir()
		inPath := filepath.Join(dir, "in.ndjson")
		outPath := filepath.Join(dir, "out.ndjson")
		cpPath := filepath.Join(dir, "replay.checkpoint.json")
		t.Cleanup(func() { _ = os.Chmod(outPath, 0o600) })

		if err := os.WriteFile(inPath, []byte(rec0), 0o600); err != nil {
			t.Fatal(err)
		}
		var out1, err1 bytes.Buffer
		if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out1, &err1); code != 0 {
			t.Fatalf("initial run failed: code=%d stderr=%s", code, err1.String())
		}

		// Append partial crash fragment beyond checkpoint output_bytes, then enforce mode 0200.
		fCrash, err := os.OpenFile(outPath, os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fCrash.WriteString(`{"signal":"traces","otlp":{"partial":`); err != nil {
			_ = fCrash.Close()
			t.Fatal(err)
		}
		_ = fCrash.Close()
		beforeFail, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(outPath, 0o200); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(inPath, []byte(rec0+rec1), 0o600); err != nil {
			t.Fatal(err)
		}
		var out2, err2 bytes.Buffer
		if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out2, &err2); code == 0 {
			t.Fatalf("expected non-zero exit when mode 0200 output exceeds checkpoint output_bytes, got 0 (stdout=%s stderr=%s)", out2.String(), err2.String())
		}

		if err := os.Chmod(outPath, 0o600); err != nil {
			t.Fatal(err)
		}
		afterFail, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(afterFail, beforeFail) {
			t.Fatalf("mode 0200 resume modified output despite failing read check: got %q, want %q", string(afterFail), string(beforeFail))
		}

		// With read permission restored, resume trims the partial fragment and appends rec1.
		var out3, err3 bytes.Buffer
		if code := run([]string{"-input=" + inPath, "-output=" + outPath, "-checkpoint-file=" + cpPath}, strings.NewReader(""), &out3, &err3); code != 0 {
			t.Fatalf("resume after restoring read permission failed: code=%d stderr=%s", code, err3.String())
		}
		finalBytes, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(finalBytes), "\n"), "\n")
		if len(lines) != 2 || !json.Valid([]byte(lines[0])) || !json.Valid([]byte(lines[1])) {
			t.Fatalf("corrupt output after restoring read permission and resuming: %q", string(finalBytes))
		}
		if !strings.Contains(lines[0], "wronly-span-0") || !strings.Contains(lines[1], "wronly-span-1") {
			t.Fatalf("unexpected records after restoring read permission and resuming: %q", string(finalBytes))
		}
	})
}
