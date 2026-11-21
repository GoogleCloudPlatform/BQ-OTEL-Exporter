// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"
)

const (
	// searchIndexJobWaitScript is the script main.tf runs to wait for a
	// search index job.
	searchIndexJobWaitScript = "deploy/terraform/scripts/wait_for_bigquery_job.py"

	// terraformApplyEnv opts in to the tests that run the terraform binary
	// with the google provider. They download the provider, so a plain
	// go test ./... leaves them out; the terraform-apply CI job sets it.
	terraformApplyEnv = "BQ_TEST_TERRAFORM_APPLY"
)

// waitScriptPython returns the python3 that runs the wait script. A machine
// without one skips the test, unless terraformApplyEnv asks for it.
func waitScriptPython(t *testing.T) string {
	t.Helper()
	python3, err := exec.LookPath("python3")
	if err != nil {
		if os.Getenv(terraformApplyEnv) != "" {
			t.Fatalf("%s is set, but python3 is not on PATH: %v", terraformApplyEnv, err)
		}
		t.Skip("python3 is not on PATH")
	}
	return python3
}

// jobsGetResponse is one response of a scripted jobs.get endpoint.
type jobsGetResponse struct {
	code     int
	body     string
	location string // Location header, for a redirect
	// hang leaves the request unanswered until the client gives up on it.
	hang bool
}

// jobsGetRequest is one request a scripted jobs.get endpoint received.
type jobsGetRequest struct {
	method, host, path, query, authorization string
}

// scriptedJobsGet answers each request with the next of its responses and
// repeats the last one, recording every request.
type scriptedJobsGet struct {
	mu        sync.Mutex
	responses []jobsGetResponse
	requests  []jobsGetRequest
}

func (s *scriptedJobsGet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	n := len(s.requests)
	s.requests = append(s.requests, jobsGetRequest{r.Method, r.Host, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	response := jobsGetResponse{code: http.StatusInternalServerError, body: "no response scripted"}
	if len(s.responses) > 0 {
		response = s.responses[min(n, len(s.responses)-1)]
	}
	s.mu.Unlock()
	if response.hang {
		<-r.Context().Done()
		return
	}
	if response.location != "" {
		w.Header().Set("Location", response.location)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(response.code)
	_, _ = io.WriteString(w, response.body)
}

func (s *scriptedJobsGet) received() []jobsGetRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// waitScriptRun is the outcome of one run of the wait script.
type waitScriptRun struct {
	code    int
	output  string
	elapsed time.Duration
}

// runWaitScript runs the wait script with exactly env, plus PATH, as its
// environment.
func runWaitScript(t *testing.T, python3 string, env map[string]string) waitScriptRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	scriptPath := filepath.Join(testsupport.RepoRoot(t), filepath.FromSlash(searchIndexJobWaitScript))
	cmd := exec.CommandContext(ctx, python3, scriptPath)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for name, value := range env {
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	start := time.Now()
	out, err := cmd.CombinedOutput()
	elapsed := time.Since(start)
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("running %s: %v\n%s", searchIndexJobWaitScript, err, out)
	}
	return waitScriptRun{code: cmd.ProcessState.ExitCode(), output: string(out), elapsed: elapsed}
}

// The wait script is how terraform apply learns that a search index job
// failed after the provider recorded it as accepted. It exits 0 only for a
// job that is DONE without an error, 1 for a job that BigQuery reports as
// failed, with the reason, the message, and the retry command, and 2 when it
// cannot tell: a timeout, a rejected token, or invalid input. A job that
// Terraform already read as DONE takes no request. Every request is a
// jobs.get for the job in its location, authorized with the access token,
// which never appears in the output and never follows a redirect.
func TestSearchIndexJobWaitScript(t *testing.T) {
	python3 := waitScriptPython(t)

	const (
		token   = "test-access-token"
		jobID   = "otel_search_idx_logs_0123abcd_00112233445566778899aabbccddeeff"
		address = "google_bigquery_job.otel_logs_search_index[0]"
		denied  = `{"reason":"accessDenied","location":"","message":"Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.createIndex denied"}`
		retry   = "Fix the cause, then run terraform apply -replace='" + address + "' to retry it under a new job ID."
	)
	status := func(state, errorResult string) string {
		if errorResult == "" {
			errorResult = "null"
		}
		return fmt.Sprintf(`{"state":%q,"errorResult":%s}`, state, errorResult)
	}
	job := func(state, errorResult string) jobsGetResponse {
		return jobsGetResponse{code: http.StatusOK, body: `{"status":` + status(state, errorResult) + `}`}
	}
	baseEnv := func(endpoint, jobStatus string) map[string]string {
		return map[string]string{
			"BQ_JOB_PROJECT":                   "test-project",
			"BQ_JOB_LOCATION":                  "us-central1",
			"BQ_JOB_ID":                        jobID,
			"BQ_JOB_STATUS":                    jobStatus,
			"BQ_JOB_WAIT_TIMEOUT_SECONDS":      "30",
			"BQ_JOB_TERRAFORM_ADDRESS":         address,
			"BQ_ACCESS_TOKEN":                  token,
			"BQ_JOB_POLL_INTERVAL_SECONDS":     "0.01",
			"GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT": endpoint,
		}
	}

	for _, tc := range []struct {
		name string
		// status is the job's status as Terraform last read it.
		status string
		// responses are the jobs.get responses, in order; the last repeats.
		responses []jobsGetResponse
		// env overrides baseEnv; an empty value unsets the variable.
		env          map[string]string
		wantCode     int
		wantRequests int
		wantOutput   []string
		// notOutput must not appear in the output.
		notOutput []string
		// minElapsed is how long the script must run, when it is not zero.
		minElapsed time.Duration
	}{
		{
			name:       "a job Terraform read as DONE succeeds without a request",
			status:     status("DONE", ""),
			wantCode:   0,
			wantOutput: []string{"BigQuery job " + jobID + " finished without an error."},
		},
		{
			name:       "a job Terraform read as DONE with an error fails without a request",
			status:     status("DONE", denied),
			wantCode:   1,
			wantOutput: []string{"BigQuery job " + jobID + " failed (accessDenied): Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.createIndex denied. " + retry},
		},
		{
			name:         "a running job is polled until it is DONE",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", ""), job("RUNNING", ""), job("DONE", "")},
			wantCode:     0,
			wantRequests: 3,
			wantOutput:   []string{"Waiting up to 30s for BigQuery job " + jobID + " to finish.", "finished without an error."},
		},
		{
			name:         "a job without a status yet is polled",
			status:       `{"state":null,"errorResult":null}`,
			responses:    []jobsGetResponse{job("PENDING", ""), job("DONE", "")},
			wantCode:     0,
			wantRequests: 2,
		},
		{
			name:         "a job that ends with an error fails with its reason and message",
			status:       status("PENDING", ""),
			responses:    []jobsGetResponse{job("PENDING", ""), job("RUNNING", ""), job("DONE", denied)},
			wantCode:     1,
			wantRequests: 3,
			wantOutput:   []string{"failed (accessDenied): Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.createIndex denied. " + retry},
		},
		{
			name:         "an error on a job that is not DONE yet is not judged",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", denied), job("DONE", "")},
			wantCode:     0,
			wantRequests: 2,
		},
		{
			name:   "failed requests and unusable responses are retried",
			status: status("RUNNING", ""),
			responses: []jobsGetResponse{
				{code: http.StatusServiceUnavailable, body: `{"error":{"code":503,"message":"backend unavailable"}}`},
				{code: http.StatusForbidden, body: `{"error":{"code":403,"message":"Exceeded rate limits"}}`},
				{code: http.StatusNotFound, body: `{"error":{"code":404,"message":"Not found: Job"}}`},
				{code: http.StatusOK, body: `<html>not JSON</html>`},
				{code: http.StatusOK, body: `{"kind":"bigquery#job"}`},
				{code: http.StatusOK, body: `{"status":"DONE"}`},
				job("DONE", ""),
			},
			wantCode:     0,
			wantRequests: 7,
		},
		{
			name:         "a job that is still running at the timeout is not a success",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", "")},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "1"},
			wantCode:     2,
			wantRequests: -1,
			wantOutput: []string{
				"BigQuery job " + jobID + " was not DONE after 1s (last state: RUNNING).",
				"run terraform apply again to keep waiting for it, or raise search_index_job_wait_timeout_seconds.",
			},
		},
		{
			name:         "a timeout reports the last failed request",
			status:       status("PENDING", ""),
			responses:    []jobsGetResponse{{code: http.StatusInternalServerError, body: `{"error":{"code":500,"message":"backend error"}}`}},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "1"},
			wantCode:     2,
			wantRequests: -1,
			wantOutput:   []string{"was not DONE after 1s (last state: PENDING). The last request failed: HTTP 500: backend error."},
		},
		{
			// With a poll interval longer than the whole wait, the second
			// request is the last one: it runs FINAL_POLL_BUDGET_SECONDS (1s)
			// before the deadline instead of the script sleeping out the
			// rest of the wait without asking again.
			name:         "a job that finishes in the last poll interval is seen before the deadline",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", ""), job("DONE", "")},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "3", "BQ_JOB_POLL_INTERVAL_SECONDS": "30"},
			wantCode:     0,
			wantRequests: 2,
			wantOutput:   []string{"finished without an error."},
		},
		{
			name:         "a job still running at the last poll gives up at the deadline",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", "")},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "3", "BQ_JOB_POLL_INTERVAL_SECONDS": "30"},
			wantCode:     2,
			wantRequests: 2,
			wantOutput:   []string{"was not DONE after 3s (last state: RUNNING). The job may still finish:"},
			minElapsed:   3 * time.Second,
		},
		{
			name:         "a deadline that passes before the first request is not reported as in flight",
			status:       status("RUNNING", ""),
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "1e-9"},
			wantCode:     2,
			wantRequests: 0,
			wantOutput:   []string{"was not DONE after 1e-09s (last state: RUNNING). The job may still finish:"},
			notOutput:    []string{"still in flight", "The last request failed"},
		},
		{
			name:         "a request the deadline cuts short is not reported as a failure",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{job("RUNNING", ""), {hang: true}},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "1"},
			wantCode:     2,
			wantRequests: 2,
			wantOutput:   []string{"was not DONE after 1s (last state: RUNNING). The last request was still in flight when the wait deadline passed."},
			notOutput:    []string{"The last request failed"},
		},
		{
			name:         "an earlier failure stays the reported cause when the deadline cuts its retry short",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{{code: http.StatusInternalServerError, body: `{"error":{"code":500,"message":"backend error"}}`}, {hang: true}},
			env:          map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "1"},
			wantCode:     2,
			wantRequests: 2,
			wantOutput:   []string{"was not DONE after 1s (last state: RUNNING). The last request failed: HTTP 500: backend error."},
			notOutput:    []string{"still in flight"},
		},
		{
			name:         "a rejected access token ends the wait at once",
			status:       status("RUNNING", ""),
			responses:    []jobsGetResponse{{code: http.StatusUnauthorized, body: `{"error":{"code":401,"message":"Request had invalid authentication credentials."}}`}},
			wantCode:     2,
			wantRequests: 1,
			wantOutput:   []string{"BigQuery rejected the access token (HTTP 401): Request had invalid authentication credentials."},
		},
		{
			name:       "a missing job ID is invalid input",
			status:     status("RUNNING", ""),
			env:        map[string]string{"BQ_JOB_ID": ""},
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_ID is not set."},
		},
		{
			name:       "a missing access token is invalid input even for a finished job",
			status:     status("DONE", ""),
			env:        map[string]string{"BQ_ACCESS_TOKEN": ""},
			wantCode:   2,
			wantOutput: []string{"BQ_ACCESS_TOKEN is not set."},
		},
		{
			name:       "a missing Terraform address is invalid input",
			status:     status("DONE", ""),
			env:        map[string]string{"BQ_JOB_TERRAFORM_ADDRESS": ""},
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_TERRAFORM_ADDRESS is not set."},
		},
		{
			name:       "a status that is not JSON is invalid input",
			status:     "DONE",
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_STATUS is not JSON"},
		},
		{
			name:       "a status that is not an object is invalid input",
			status:     `["DONE"]`,
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_STATUS is not a JSON object."},
		},
		{
			name:       "a timeout of zero is invalid input",
			status:     status("RUNNING", ""),
			env:        map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "0"},
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_WAIT_TIMEOUT_SECONDS must be a positive number of seconds, got '0'."},
		},
		{
			name:       "a timeout that is not a number is invalid input",
			status:     status("RUNNING", ""),
			env:        map[string]string{"BQ_JOB_WAIT_TIMEOUT_SECONDS": "nan"},
			wantCode:   2,
			wantOutput: []string{"BQ_JOB_WAIT_TIMEOUT_SECONDS must be a positive number of seconds, got 'nan'."},
		},
		{
			name:       "an endpoint that is not http or https is invalid input",
			status:     status("RUNNING", ""),
			env:        map[string]string{"GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT": "file:///etc/passwd"},
			wantCode:   2,
			wantOutput: []string{"GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT must be an http or https URL, got 'file:///etc/passwd'."},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := &scriptedJobsGet{responses: tc.responses}
			server := httptest.NewServer(api)
			defer server.Close()

			env := baseEnv(server.URL+"/bigquery/v2/", tc.status)
			for name, value := range tc.env {
				if value == "" {
					delete(env, name)
				} else {
					env[name] = value
				}
			}
			run := runWaitScript(t, python3, env)

			if run.code != tc.wantCode {
				t.Errorf("exit status = %d, want %d\n%s", run.code, tc.wantCode, run.output)
			}
			for _, want := range tc.wantOutput {
				if !strings.Contains(run.output, want) {
					t.Errorf("output does not contain %q:\n%s", want, run.output)
				}
			}
			for _, unwanted := range tc.notOutput {
				if strings.Contains(run.output, unwanted) {
					t.Errorf("output contains %q:\n%s", unwanted, run.output)
				}
			}
			if run.elapsed < tc.minElapsed {
				t.Errorf("the script ran for %v, want at least %v", run.elapsed, tc.minElapsed)
			}
			if strings.Contains(run.output, token) {
				t.Errorf("output contains the access token:\n%s", run.output)
			}
			if strings.Contains(run.output, "Traceback") {
				t.Errorf("the script raised an exception:\n%s", run.output)
			}

			requests := api.received()
			if tc.wantRequests >= 0 && len(requests) != tc.wantRequests {
				t.Errorf("the script sent %d requests, want %d\n%s", len(requests), tc.wantRequests, run.output)
			}
			if tc.wantRequests < 0 {
				// A timeout: the script kept polling for the whole second, and
				// gave up soon after it.
				if len(requests) < 2 {
					t.Errorf("the script sent %d requests before the timeout, want it to keep polling", len(requests))
				}
				if run.elapsed < time.Second || run.elapsed > 10*time.Second {
					t.Errorf("the script ran for %v, want it to give up after its 1s timeout", run.elapsed)
				}
			}
			for i, got := range requests {
				want := jobsGetRequest{
					method:        http.MethodGet,
					host:          strings.TrimPrefix(server.URL, "http://"),
					path:          "/bigquery/v2/projects/test-project/jobs/" + jobID,
					query:         "location=us-central1&fields=status",
					authorization: "Bearer " + token,
				}
				if got != want {
					t.Errorf("request %d = %+v, want %+v", i, got, want)
				}
			}
		})
	}

	// A redirect is followed, as the provider's own client does, but the
	// token stays with the host it was meant for.
	t.Run("a redirect to another host does not carry the access token", func(t *testing.T) {
		elsewhere := &scriptedJobsGet{responses: []jobsGetResponse{job("DONE", "")}}
		elsewhereServer := httptest.NewServer(elsewhere)
		defer elsewhereServer.Close()
		api := &scriptedJobsGet{responses: []jobsGetResponse{{code: http.StatusTemporaryRedirect, location: elsewhereServer.URL + "/elsewhere"}}}
		server := httptest.NewServer(api)
		defer server.Close()

		run := runWaitScript(t, python3, baseEnv(server.URL+"/bigquery/v2/", status("RUNNING", "")))
		if run.code != 0 {
			t.Errorf("exit status = %d, want 0\n%s", run.code, run.output)
		}
		if got := api.received(); len(got) != 1 || got[0].authorization != "Bearer "+token {
			t.Errorf("the BigQuery endpoint received %+v, want one authorized request", got)
		}
		got := elsewhere.received()
		if len(got) != 1 || got[0].path != "/elsewhere" {
			t.Fatalf("the redirect target received %+v, want one request for /elsewhere", got)
		}
		if got[0].authorization != "" {
			t.Errorf("the redirect target received Authorization %q, want none", got[0].authorization)
		}
	})

	// Without the override the script asks the public BigQuery endpoint. The
	// test proxy refuses the tunnel, so no request leaves the machine.
	t.Run("the default endpoint is the public BigQuery API", func(t *testing.T) {
		proxy := &scriptedJobsGet{responses: []jobsGetResponse{{code: http.StatusBadGateway}}}
		server := httptest.NewServer(proxy)
		defer server.Close()

		env := baseEnv("", status("RUNNING", ""))
		delete(env, "GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT")
		env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "1"
		env["HTTPS_PROXY"] = server.URL
		env["https_proxy"] = server.URL
		run := runWaitScript(t, python3, env)
		if run.code != 2 {
			t.Errorf("exit status = %d, want 2\n%s", run.code, run.output)
		}
		got := proxy.received()
		if len(got) == 0 {
			t.Fatalf("the proxy received no request:\n%s", run.output)
		}
		for i, request := range got {
			if request.method != http.MethodConnect || request.host != "bigquery.googleapis.com:443" {
				t.Errorf("proxy request %d = %s %s, want CONNECT bigquery.googleapis.com:443", i, request.method, request.host)
			}
			if request.authorization != "" {
				t.Errorf("proxy request %d carried Authorization %q, want the token only inside the tunnel", i, request.authorization)
			}
		}
	})

	t.Run("a slow-drip response body respects the total wall-clock timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			flusher, _ := w.(http.Flusher)
			for i := 0; i < 40; i++ {
				select {
				case <-r.Context().Done():
					return
				default:
				}
				if _, err := io.WriteString(w, "{"); err != nil {
					return
				}
				if flusher != nil {
					flusher.Flush()
				}
				time.Sleep(100 * time.Millisecond)
			}
		}))
		defer server.Close()

		env := baseEnv(server.URL+"/bigquery/v2/", status("RUNNING", ""))
		env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "0.4"
		run := runWaitScript(t, python3, env)
		if run.code != 2 {
			t.Errorf("exit status = %d, want 2\n%s", run.code, run.output)
		}
		if run.elapsed >= 2*time.Second {
			t.Errorf("elapsed = %v, want bounded near 0.4s deadline", run.elapsed)
		}
		if !strings.Contains(run.output, "was not DONE after 0.4s") {
			t.Errorf("output missing timeout message:\n%s", run.output)
		}
		if strings.Contains(run.output, "Traceback") || strings.Contains(run.output, token) {
			t.Errorf("output leaked traceback or token:\n%s", run.output)
		}
	})

	t.Run("a delayed DONE payload arriving past the deadline is rejected", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(650 * time.Millisecond):
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"status":{"state":"DONE","errorResult":null}}`)
		}))
		defer server.Close()

		env := baseEnv(server.URL+"/bigquery/v2/", status("RUNNING", ""))
		env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "0.3"
		run := runWaitScript(t, python3, env)
		if run.code != 2 {
			t.Errorf("exit status = %d, want 2 (delayed DONE past deadline must not succeed)\n%s", run.code, run.output)
		}
		if run.elapsed >= 2*time.Second {
			t.Errorf("elapsed = %v, want bounded near 0.3s deadline", run.elapsed)
		}
		if strings.Contains(run.output, "finished without an error") {
			t.Errorf("delayed DONE was accepted as success:\n%s", run.output)
		}
		if !strings.Contains(run.output, "was not DONE after 0.3s") {
			t.Errorf("output missing timeout message:\n%s", run.output)
		}
		if strings.Contains(run.output, "Traceback") || strings.Contains(run.output, token) {
			t.Errorf("output leaked traceback or token:\n%s", run.output)
		}
	})

	t.Run("a slow-drip HTTP response header respects the total wall-clock timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer func() { _ = ln.Close() }()

		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n")
					for i := 0; i < 40; i++ {
						select {
						case <-doneCh:
							return
						case <-time.After(100 * time.Millisecond):
						}
						if _, err := io.WriteString(c, fmt.Sprintf("X-Slow-%d: 1\r\n", i)); err != nil {
							return
						}
					}
					_, _ = io.WriteString(c, "\r\n{\"status\":{\"state\":\"DONE\",\"errorResult\":null}}")
				}(conn)
			}
		}()

		env := baseEnv("http://"+ln.Addr().String()+"/bigquery/v2/", status("RUNNING", ""))
		env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "0.5"
		run := runWaitScript(t, python3, env)
		if run.code != 2 {
			t.Errorf("exit status = %d, want 2\n%s", run.code, run.output)
		}
		if run.elapsed >= 1500*time.Millisecond {
			t.Errorf("elapsed = %v, want bounded near 0.5s deadline (no header slow-drip overshoot)", run.elapsed)
		}
		if strings.Contains(run.output, "finished without an error") {
			t.Errorf("slow-drip header DONE was accepted as success:\n%s", run.output)
		}
		if !strings.Contains(run.output, "was not DONE after 0.5s") {
			t.Errorf("output missing timeout message:\n%s", run.output)
		}
		if strings.Contains(run.output, "Traceback") || strings.Contains(run.output, token) {
			t.Errorf("output leaked traceback or token:\n%s", run.output)
		}
	})

	t.Run("a slow-drip chunked trailer respects the total wall-clock timeout", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.Listen: %v", err)
		}
		defer func() { _ = ln.Close() }()

		doneCh := make(chan struct{})
		defer close(doneCh)
		go func() {
			const payload = `{"status":{"state":"DONE","errorResult":null}}`
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 4096)
					_, _ = c.Read(buf)
					_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n")
					_, _ = io.WriteString(c, fmt.Sprintf("%x\r\n%s\r\n0\r\n", len(payload), payload))
					for i := 0; i < 40; i++ {
						select {
						case <-doneCh:
							return
						case <-time.After(100 * time.Millisecond):
						}
						if _, err := io.WriteString(c, fmt.Sprintf("X-Trailer-%d: slow\r\n", i)); err != nil {
							return
						}
					}
					_, _ = io.WriteString(c, "\r\n")
				}(conn)
			}
		}()

		env := baseEnv("http://"+ln.Addr().String()+"/bigquery/v2/", status("RUNNING", ""))
		env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "0.5"
		run := runWaitScript(t, python3, env)
		if run.code != 2 {
			t.Errorf("exit status = %d, want 2\n%s", run.code, run.output)
		}
		if run.elapsed >= 1500*time.Millisecond {
			t.Errorf("elapsed = %v, want bounded near 0.5s deadline (no trailer slow-drip overshoot)", run.elapsed)
		}
		if strings.Contains(run.output, "finished without an error") {
			t.Errorf("slow-drip trailer DONE was accepted as success:\n%s", run.output)
		}
		if !strings.Contains(run.output, "was not DONE after 0.5s") {
			t.Errorf("output missing timeout message:\n%s", run.output)
		}
		if strings.Contains(run.output, "Traceback") || strings.Contains(run.output, token) {
			t.Errorf("output leaked traceback or token:\n%s", run.output)
		}
	})

	for _, stallKind := range []string{"ok_header_stall", "http_500_error_body_stall"} {
		t.Run("a transient per-request socket timeout retries until DONE/"+stallKind, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen: %v", err)
			}
			defer func() { _ = ln.Close() }()

			var reqCount atomic.Int32
			doneCh := make(chan struct{})
			defer close(doneCh)
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					n := reqCount.Add(1)
					go func(c net.Conn, attempt int32) {
						defer func() { _ = c.Close() }()
						buf := make([]byte, 4096)
						_, _ = c.Read(buf)
						if attempt == 1 {
							if stallKind == "http_500_error_body_stall" {
								_, _ = io.WriteString(c, "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
							}
							select {
							case <-doneCh:
							case <-time.After(600 * time.Millisecond):
							}
							return
						}
						const payload = `{"status":{"state":"DONE","errorResult":null}}`
						_, _ = io.WriteString(c, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(payload), payload))
					}(conn, n)
				}
			}()

			absScript := filepath.Join(testsupport.RepoRoot(t), filepath.FromSlash(searchIndexJobWaitScript))
			env := baseEnv("http://"+ln.Addr().String()+"/bigquery/v2/", status("RUNNING", ""))
			env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "4"

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			const pyRunner = `
import importlib.util, sys
spec = importlib.util.spec_from_file_location("wait_for_bigquery_job", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
mod.REQUEST_TIMEOUT_SECONDS = 0.25
sys.exit(mod.main())
`
			cmd := exec.CommandContext(ctx, python3, "-c", pyRunner, absScript)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "PYTHONDONTWRITEBYTECODE=1"}
			for name, value := range env {
				cmd.Env = append(cmd.Env, name+"="+value)
			}
			out, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if err != nil && !errors.As(err, &exitErr) {
				t.Fatalf("running python wrapper: %v\n%s", err, out)
			}
			code := cmd.ProcessState.ExitCode()
			output := string(out)
			if code != 0 {
				t.Errorf("exit status = %d, want 0 (transient socket timeout must retry)\n%s", code, output)
			}
			if got := reqCount.Load(); got < 2 {
				t.Errorf("request count = %d, want >= 2", got)
			}
			if !strings.Contains(output, "finished without an error.") {
				t.Errorf("output missing success message:\n%s", output)
			}
			if strings.Contains(output, "Traceback") || strings.Contains(output, token) {
				t.Errorf("output leaked traceback or token:\n%s", output)
			}
		})
	}

	// The wait deadline can pass while the body of an error response is still
	// arriving. The status line already says how the request ended, so the
	// script reports that failure, or the rejected token, and never a request
	// still in flight, however the deadline races the read of the body.
	for _, tc := range []struct {
		name, statusLine, want string
	}{
		{
			name:       "HTTP 500",
			statusLine: "HTTP/1.1 500 Internal Server Error",
			want:       "was not DONE after 1s (last state: RUNNING). The last request failed: HTTP 500 (error body timed out at wait deadline).",
		},
		{
			name:       "HTTP 401",
			statusLine: "HTTP/1.1 401 Unauthorized",
			want:       "BigQuery rejected the access token (HTTP 401): error body timed out at wait deadline. The token Terraform passed may have expired: run terraform apply again.",
		},
	} {
		t.Run("an error status whose body the deadline cuts short is reported/"+tc.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("net.Listen: %v", err)
			}
			defer func() { _ = ln.Close() }()

			var requests atomic.Int32
			doneCh := make(chan struct{})
			defer close(doneCh)
			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					requests.Add(1)
					go func(c net.Conn) {
						defer func() { _ = c.Close() }()
						buf := make([]byte, 4096)
						_, _ = c.Read(buf)
						// One byte of a 100-byte body, and then nothing.
						_, _ = io.WriteString(c, tc.statusLine+"\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{")
						<-doneCh
					}(conn)
				}
			}()

			env := baseEnv("http://"+ln.Addr().String()+"/bigquery/v2/", status("RUNNING", ""))
			env["BQ_JOB_WAIT_TIMEOUT_SECONDS"] = "1"
			run := runWaitScript(t, python3, env)
			if run.code != 2 {
				t.Errorf("exit status = %d, want 2\n%s", run.code, run.output)
			}
			if !strings.Contains(run.output, tc.want) {
				t.Errorf("output does not contain %q:\n%s", tc.want, run.output)
			}
			if strings.Contains(run.output, "still in flight") {
				t.Errorf("output reports the request as still in flight although its status had arrived:\n%s", run.output)
			}
			if got := requests.Load(); got != 1 {
				t.Errorf("the script sent %d requests, want 1", got)
			}
			if run.elapsed >= 5*time.Second {
				t.Errorf("elapsed = %v, want bounded near the 1s deadline", run.elapsed)
			}
			if strings.Contains(run.output, "Traceback") || strings.Contains(run.output, token) {
				t.Errorf("output leaked traceback or token:\n%s", run.output)
			}
		})
	}
}

const (
	fakeBigQueryProject = "test-project"
	fakeBigQueryToken   = "fake-bigquery-access-token"
)

// fakeJobOutcome is how a job submitted to a fakeBigQuery ends.
type fakeJobOutcome struct {
	// runningGets is the number of jobs.get requests that see the job
	// RUNNING before it is DONE. The provider sends two when it creates the
	// job, so 3 leaves the job running until the wait script's second
	// request. Negative means the job never finishes.
	runningGets int
	// errorResult is the error the job ends with, or nil for a job that
	// succeeds.
	errorResult map[string]any
}

// fakeJob is a job submitted to a fakeBigQuery.
type fakeJob struct {
	body    map[string]any
	outcome fakeJobOutcome
	// gets counts the jobs.get requests for the job, and waitGets those of
	// them that asked for the status alone, as the wait script does.
	gets, waitGets int
}

func (j *fakeJob) status() map[string]any {
	if j.outcome.runningGets < 0 || j.gets <= j.outcome.runningGets {
		return map[string]any{"state": "RUNNING"}
	}
	if j.outcome.errorResult == nil {
		return map[string]any{"state": "DONE"}
	}
	return map[string]any{"state": "DONE", "errorResult": j.outcome.errorResult, "errors": []any{j.outcome.errorResult}}
}

// fakeBigQuery serves the part of the BigQuery REST API that Terraform's
// google provider and the wait script use to manage datasets, tables, and
// jobs: it stores what is inserted, returns it with the fields BigQuery
// assigns, and finishes each job the way the test decides. It rejects a
// request without the access token and fails the test on a request it does
// not serve.
type fakeBigQuery struct {
	t      *testing.T
	server *httptest.Server

	mu       sync.Mutex
	clock    int64
	datasets map[string]map[string]any
	tables   map[string]map[string]any // by dataset ID + "/" + table ID
	jobs     map[string]*fakeJob
	jobIDs   []string // in submission order
	outcome  func(query string) fakeJobOutcome
}

func newFakeBigQuery(t *testing.T) *fakeBigQuery {
	t.Helper()
	f := &fakeBigQuery{t: t}
	f.reset()
	const project = "/bigquery/v2/projects/{project}"
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+project+"/datasets", f.insertDataset)
	mux.HandleFunc("GET "+project+"/datasets/{dataset}", f.getDataset)
	mux.HandleFunc("POST "+project+"/datasets/{dataset}/tables", f.insertTable)
	mux.HandleFunc("GET "+project+"/datasets/{dataset}/tables/{table}", f.getTable)
	mux.HandleFunc("PUT "+project+"/datasets/{dataset}/tables/{table}", f.updateTable)
	mux.HandleFunc("POST "+project+"/jobs", f.insertJob)
	mux.HandleFunc("GET "+project+"/serviceAccount", f.getServiceAccount)
	mux.HandleFunc("GET "+project+"/jobs/{job}", f.getJob)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+fakeBigQueryToken {
			t.Errorf("fake BigQuery: %s %s carried Authorization %q, want the provider's access token", r.Method, r.URL.Path, got)
			f.writeError(w, http.StatusUnauthorized, "Request had invalid authentication credentials.")
			return
		}
		if _, pattern := mux.Handler(r); pattern == "" {
			t.Errorf("fake BigQuery: does not serve %s %s", r.Method, r.URL.Path)
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(f.server.Close)
	return f
}

// endpoint returns the fake's base URL in the form of the provider's
// GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT.
func (f *fakeBigQuery) endpoint() string { return f.server.URL + "/bigquery/v2/" }

// reset empties the fake and makes every new job finish without an error
// after three jobs.get requests.
func (f *fakeBigQuery) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.datasets = map[string]map[string]any{}
	f.tables = map[string]map[string]any{}
	f.jobs = map[string]*fakeJob{}
	f.jobIDs = nil
	f.outcome = func(string) fakeJobOutcome { return fakeJobOutcome{runningGets: 3} }
}

// finishJobs sets how each job submitted from now on ends, by its query.
func (f *fakeBigQuery) finishJobs(outcome func(query string) fakeJobOutcome) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.outcome = outcome
}

// tick returns a time in milliseconds later than every one before it.
// Callers hold f.mu.
func (f *fakeBigQuery) tick() string {
	f.clock++
	return strconv.FormatInt(1_700_000_000_000+f.clock, 10)
}

func (f *fakeBigQuery) writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		f.t.Errorf("fake BigQuery: encoding a response: %v", err)
	}
}

func (f *fakeBigQuery) writeError(w http.ResponseWriter, code int, message string) {
	f.writeJSON(w, code, map[string]any{"error": map[string]any{"code": code, "message": message}})
}

// readBody decodes a request body, or answers 400 and returns nil.
func (f *fakeBigQuery) readBody(w http.ResponseWriter, r *http.Request) map[string]any {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		f.writeError(w, http.StatusBadRequest, err.Error())
		return nil
	}
	return body
}

// getServiceAccount answers the lookup of the project's BigQuery service
// agent, which the module reads on every plan for the optional CMEK grant.
func (f *fakeBigQuery) getServiceAccount(w http.ResponseWriter, _ *http.Request) {
	f.writeJSON(w, http.StatusOK, map[string]any{
		"kind":  "bigquery#getServiceAccountResponse",
		"email": "bq-123456789012@bigquery-encryption.iam.gserviceaccount.com",
	})
}

func (f *fakeBigQuery) insertDataset(w http.ResponseWriter, r *http.Request) {
	body := f.readBody(w, r)
	if body == nil {
		return
	}
	reference, _ := body["datasetReference"].(map[string]any)
	id, _ := reference["datasetId"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.datasets[id]; exists || id == "" {
		f.writeError(w, http.StatusConflict, "Already Exists: Dataset "+id)
		return
	}
	now := f.tick()
	body["kind"] = "bigquery#dataset"
	body["id"] = r.PathValue("project") + ":" + id
	body["selfLink"] = f.server.URL + r.URL.Path + "/" + id
	body["etag"] = "etag-" + now
	body["creationTime"] = now
	body["lastModifiedTime"] = now
	f.datasets[id] = body
	f.writeJSON(w, http.StatusOK, body)
}

func (f *fakeBigQuery) getDataset(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dataset, ok := f.datasets[r.PathValue("dataset")]
	if !ok {
		f.writeError(w, http.StatusNotFound, "Not found: Dataset "+r.PathValue("dataset"))
		return
	}
	f.writeJSON(w, http.StatusOK, dataset)
}

func (f *fakeBigQuery) insertTable(w http.ResponseWriter, r *http.Request) {
	body := f.readBody(w, r)
	if body == nil {
		return
	}
	reference, _ := body["tableReference"].(map[string]any)
	id, _ := reference["tableId"].(string)
	key := r.PathValue("dataset") + "/" + id
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.tables[key]; exists || id == "" {
		f.writeError(w, http.StatusConflict, "Already Exists: Table "+key)
		return
	}
	now := f.tick()
	body["kind"] = "bigquery#table"
	body["id"] = r.PathValue("project") + ":" + r.PathValue("dataset") + "." + id
	body["selfLink"] = f.server.URL + r.URL.Path + "/" + id
	body["etag"] = "etag-" + now
	body["type"] = "TABLE"
	body["creationTime"] = now
	body["lastModifiedTime"] = now
	f.tables[key] = body
	f.writeJSON(w, http.StatusOK, body)
}

func (f *fakeBigQuery) getTable(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("dataset") + "/" + r.PathValue("table")
	f.mu.Lock()
	defer f.mu.Unlock()
	table, ok := f.tables[key]
	if !ok {
		f.writeError(w, http.StatusNotFound, "Not found: Table "+key)
		return
	}
	f.writeJSON(w, http.StatusOK, table)
}

// updateTable replaces a table's description, as tables.update does, and
// keeps what BigQuery assigned when it created the table.
func (f *fakeBigQuery) updateTable(w http.ResponseWriter, r *http.Request) {
	body := f.readBody(w, r)
	if body == nil {
		return
	}
	key := r.PathValue("dataset") + "/" + r.PathValue("table")
	f.mu.Lock()
	defer f.mu.Unlock()
	table, ok := f.tables[key]
	if !ok {
		f.writeError(w, http.StatusNotFound, "Not found: Table "+key)
		return
	}
	now := f.tick()
	for _, assigned := range []string{"kind", "id", "selfLink", "type", "creationTime"} {
		body[assigned] = table[assigned]
	}
	body["etag"] = "etag-" + now
	body["lastModifiedTime"] = now
	f.tables[key] = body
	f.writeJSON(w, http.StatusOK, body)
}

func (f *fakeBigQuery) insertJob(w http.ResponseWriter, r *http.Request) {
	body := f.readBody(w, r)
	if body == nil {
		return
	}
	reference, _ := body["jobReference"].(map[string]any)
	id, _ := reference["jobId"].(string)
	configuration, _ := body["configuration"].(map[string]any)
	queryConfiguration, _ := configuration["query"].(map[string]any)
	query, _ := queryConfiguration["query"].(string)
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.jobs[id]; exists || id == "" {
		// BigQuery keeps every job ID in its job history.
		f.writeError(w, http.StatusConflict, "Already Exists: Job "+id)
		return
	}
	if configuration != nil {
		configuration["jobType"] = "QUERY"
	}
	body["kind"] = "bigquery#job"
	body["id"] = r.PathValue("project") + ":" + id
	body["selfLink"] = f.server.URL + r.URL.Path + "/" + id
	body["user_email"] = "terraform@test-project.iam.gserviceaccount.com"
	job := &fakeJob{body: body, outcome: f.outcome(query)}
	f.jobs[id] = job
	f.jobIDs = append(f.jobIDs, id)
	f.writeJob(w, job, false)
}

func (f *fakeBigQuery) getJob(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, ok := f.jobs[r.PathValue("job")]
	if !ok {
		f.writeError(w, http.StatusNotFound, "Not found: Job "+r.PathValue("job"))
		return
	}
	job.gets++
	statusOnly := r.URL.Query().Get("fields") == "status"
	if statusOnly {
		job.waitGets++
	}
	f.writeJob(w, job, statusOnly)
}

// writeJob answers with the job and its current status, or with the status
// alone. Callers hold f.mu.
func (f *fakeBigQuery) writeJob(w http.ResponseWriter, job *fakeJob, statusOnly bool) {
	if statusOnly {
		f.writeJSON(w, http.StatusOK, map[string]any{"status": job.status()})
		return
	}
	body := map[string]any{"status": job.status()}
	for name, value := range job.body {
		body[name] = value
	}
	f.writeJSON(w, http.StatusOK, body)
}

// table returns a copy of the fields of a table, or nil when there is none.
func (f *fakeBigQuery) table(dataset, table string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.tables[dataset+"/"+table]
	if !ok {
		return nil
	}
	fields := map[string]any{}
	for name, value := range stored {
		fields[name] = value
	}
	return fields
}

// deleteTable deletes a table the way a user or another tool would, without
// Terraform.
func (f *fakeBigQuery) deleteTable(dataset, table string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.tables[dataset+"/"+table]; !ok {
		f.t.Fatalf("fake BigQuery: no table %s.%s to delete", dataset, table)
	}
	delete(f.tables, dataset+"/"+table)
}

// recreateTable deletes a table and creates it again as it was, the way a
// user or another tool would, without Terraform: BigQuery assigns the new
// table a new creation time.
func (f *fakeBigQuery) recreateTable(dataset, table string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.tables[dataset+"/"+table]
	if !ok {
		f.t.Fatalf("fake BigQuery: no table %s.%s to recreate", dataset, table)
	}
	now := f.tick()
	stored["etag"] = "etag-" + now
	stored["creationTime"] = now
	stored["lastModifiedTime"] = now
}

// submittedJobs returns the IDs of the jobs submitted so far, in order.
func (f *fakeBigQuery) submittedJobs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.jobIDs)
}

// jobGets returns how many jobs.get requests a job has answered, and how
// many of them came from the wait script.
func (f *fakeBigQuery) jobGets(id string) (gets, waitGets int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, ok := f.jobs[id]
	if !ok {
		f.t.Fatalf("fake BigQuery: no job %s", id)
	}
	return job.gets, job.waitGets
}

// finishJob lets a job that never finishes be DONE at its next jobs.get.
func (f *fakeBigQuery) finishJob(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	job, ok := f.jobs[id]
	if !ok {
		f.t.Fatalf("fake BigQuery: no job %s", id)
	}
	job.outcome.runningGets = 0
}

// terraformModule is a copy of deploy/terraform that the terraform binary
// runs in, with a local state file, against a fakeBigQuery.
type terraformModule struct {
	t   *testing.T
	bin string
	dir string
	env []string
}

// newTerraformModule copies the module's configuration and scripts to a
// temporary directory and initializes it. The environment it gives
// terraform holds no Google credentials but the fake's access token, and
// sends every BigQuery request, the wait script's included, to the fake.
func newTerraformModule(t *testing.T, bin string, fake *fakeBigQuery) *terraformModule {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(filepath.Join(testsupport.RepoRoot(t), "deploy", "terraform"))); err != nil {
		t.Fatalf("copying deploy/terraform: %v", err)
	}
	// A checkout that terraform has run in holds its working files.
	for _, leftover := range []string{".terraform", ".terraform.lock.hcl", "terraform.tfstate", "terraform.tfstate.backup"} {
		if err := os.RemoveAll(filepath.Join(dir, leftover)); err != nil {
			t.Fatal(err)
		}
	}
	tf := &terraformModule{t: t, bin: bin, dir: dir, env: []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"TF_IN_AUTOMATION=1",
		"CHECKPOINT_DISABLE=1",
		"GOOGLE_OAUTH_ACCESS_TOKEN=" + fakeBigQueryToken,
		"GOOGLE_BIG_QUERY_CUSTOM_ENDPOINT=" + fake.endpoint(),
		// The wait script inherits terraform's environment; the fake finishes
		// a job after a number of requests, however fast they come.
		"BQ_JOB_POLL_INTERVAL_SECONDS=0.05",
		"NO_PROXY=127.0.0.1,localhost",
		"no_proxy=127.0.0.1,localhost",
	}}
	// What terraform init needs to reach the provider registry, or to skip it.
	for _, name := range []string{"TF_PLUGIN_CACHE_DIR", "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE", "TF_CLI_CONFIG_FILE", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR", "TMPDIR"} {
		if value, ok := os.LookupEnv(name); ok {
			tf.env = append(tf.env, name+"="+value)
		}
	}
	if out, err := tf.run("init", "-input=false", "-no-color"); err != nil {
		t.Fatalf("terraform init: %v\n%s", err, out)
	}
	out, err := tf.run("version")
	if err != nil {
		t.Fatalf("terraform version: %v\n%s", err, out)
	}
	t.Logf("applying deploy/terraform with:\n%s", out)
	return tf
}

// run runs terraform in the module directory and returns its output.
func (tf *terraformModule) run(args ...string) (string, error) {
	tf.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, tf.bin, args...)
	cmd.Dir = tf.dir
	cmd.Env = tf.env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// searchIndexArgs are the arguments of a plan or apply of the search index
// jobs: the module's required variable, the opt-in, and any more.
func searchIndexArgs(command string, args ...string) []string {
	return append([]string{command, "-input=false", "-no-color", "-var=project_id=" + fakeBigQueryProject, "-var=enable_search_indexes=true"}, args...)
}

// searchIndexTargets limits a plan or apply to the search index jobs, their
// waits, and what they depend on: the dataset and the three signal tables.
// The rest of the module manages views and IAM, which the fake does not
// serve.
func searchIndexTargets() []string {
	targets := []string{"-target=terraform_data.search_index_job_wait"}
	for _, signal := range searchIndexSignals {
		targets = append(targets, "-target=google_bigquery_job.otel_"+signal+"_search_index")
	}
	return targets
}

// apply applies the search index jobs and their waits.
func (tf *terraformModule) apply(args ...string) (string, error) {
	tf.t.Helper()
	return tf.run(searchIndexArgs("apply", append([]string{"-auto-approve"}, append(searchIndexTargets(), args...)...)...)...)
}

// mustApply is apply for an apply that has to succeed.
func (tf *terraformModule) mustApply(args ...string) string {
	tf.t.Helper()
	out, err := tf.apply(args...)
	if err != nil {
		tf.t.Fatalf("terraform apply %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	if !strings.Contains(out, "Apply complete!") {
		tf.t.Fatalf("terraform apply %s did not report a complete apply:\n%s", strings.Join(args, " "), out)
	}
	if strings.Contains(out, fakeBigQueryToken) {
		tf.t.Errorf("terraform apply %s printed the access token:\n%s", strings.Join(args, " "), out)
	}
	return out
}

// removeState starts the module over without any resource.
func (tf *terraformModule) removeState() {
	tf.t.Helper()
	for _, name := range []string{"terraform.tfstate", "terraform.tfstate.backup"} {
		if err := os.RemoveAll(filepath.Join(tf.dir, name)); err != nil {
			tf.t.Fatal(err)
		}
	}
}

// terraformInstance is a resource instance in a Terraform state file.
type terraformInstance struct {
	IndexKey   any            `json:"index_key"`
	Status     string         `json:"status"`
	Attributes map[string]any `json:"attributes"`
}

// instances returns the instances of a resource in the state file, by index
// key: "0" for the single instance of a counted resource.
func (tf *terraformModule) instances(resourceType, name string) map[string]terraformInstance {
	tf.t.Helper()
	raw, err := os.ReadFile(filepath.Join(tf.dir, "terraform.tfstate"))
	if err != nil {
		tf.t.Fatalf("reading the Terraform state: %v", err)
	}
	var state struct {
		Resources []struct {
			Mode      string              `json:"mode"`
			Type      string              `json:"type"`
			Name      string              `json:"name"`
			Instances []terraformInstance `json:"instances"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		tf.t.Fatalf("parsing the Terraform state: %v", err)
	}
	instances := map[string]terraformInstance{}
	for _, resource := range state.Resources {
		if resource.Mode != "managed" || resource.Type != resourceType || resource.Name != name {
			continue
		}
		for _, instance := range resource.Instances {
			instances[fmt.Sprint(instance.IndexKey)] = instance
		}
	}
	return instances
}

// searchIndexSignals are the signals whose tables take a search index.
var searchIndexSignals = []string{"spans", "logs", "metrics"}

// searchIndexJob is what the state file records of a search index job and
// of the wait for it.
type searchIndexJob struct {
	// id is the job's ID, and state the status the provider last read.
	id, state string
	// waitedFor is the ID of the job the wait ran for, "" without a wait;
	// waitTainted reports a wait that failed.
	waitedFor   string
	waitTainted bool
}

// searchIndexJobs returns the search index jobs in the state file, by signal.
func (tf *terraformModule) searchIndexJobs() map[string]searchIndexJob {
	tf.t.Helper()
	waits := tf.instances("terraform_data", "search_index_job_wait")
	jobs := map[string]searchIndexJob{}
	for _, signal := range searchIndexSignals {
		instance, ok := tf.instances("google_bigquery_job", "otel_"+signal+"_search_index")["0"]
		if !ok {
			tf.t.Fatalf("the Terraform state has no otel_%s_search_index job", signal)
		}
		job := searchIndexJob{}
		job.id, _ = instance.Attributes["job_id"].(string)
		if statuses, _ := instance.Attributes["status"].([]any); len(statuses) > 0 {
			status, _ := statuses[0].(map[string]any)
			job.state, _ = status["state"].(string)
		}
		if wait, ok := waits[signal]; ok {
			trigger, _ := wait.Attributes["triggers_replace"].(map[string]any)
			job.waitedFor, _ = trigger["value"].(string)
			job.waitTainted = wait.Status == "tainted"
		}
		jobs[signal] = job
	}
	return jobs
}

// searchIndexJobIDs returns the ID of each search index job in the state
// file, by signal.
func (tf *terraformModule) searchIndexJobIDs() map[string]string {
	tf.t.Helper()
	ids := map[string]string{}
	for signal, job := range tf.searchIndexJobs() {
		ids[signal] = job.id
	}
	return ids
}

// unwrapped returns Terraform output with every run of whitespace as one
// space: Terraform wraps the messages it prints to the width of a terminal.
func unwrapped(output string) string {
	return strings.Join(strings.Fields(output), " ")
}

type plannedResourceChange struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Change  struct {
		Actions []string       `json:"actions"`
		After   map[string]any `json:"after"`
	} `json:"change"`
}

func plannedResourceType(change plannedResourceChange) string {
	if change.Type != "" {
		return change.Type
	}
	parts := strings.Split(change.Address, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2]
	}
	return ""
}

func (tf *terraformModule) showPlanChanges(planFile string) []plannedResourceChange {
	tf.t.Helper()
	out, err := tf.run("show", "-json", planFile)
	if err != nil {
		tf.t.Fatalf("terraform show -json %s: %v\n%s", planFile, err, out)
	}
	var plan struct {
		ResourceChanges []plannedResourceChange `json:"resource_changes"`
	}
	if err := json.Unmarshal([]byte(out), &plan); err != nil {
		tf.t.Fatalf("parsing terraform show -json %s: %v\n%s", planFile, err, out)
	}
	return plan.ResourceChanges
}

// plannedActions returns the actions a saved plan holds for each resource
// instance, by address, joined with "," when a replacement takes two.
func (tf *terraformModule) plannedActions(planFile string) map[string]string {
	tf.t.Helper()
	actions := map[string]string{}
	for _, change := range tf.showPlanChanges(planFile) {
		actions[change.Address] = strings.Join(change.Change.Actions, ",")
	}
	return actions
}

// plannedResourceAfterAttrs returns change.after for each resource instance in
// a saved plan, keyed by resource address.
func (tf *terraformModule) plannedResourceAfterAttrs(planFile string) map[string]map[string]any {
	tf.t.Helper()
	after := map[string]map[string]any{}
	for _, change := range tf.showPlanChanges(planFile) {
		after[change.Address] = change.Change.After
	}
	return after
}

func assertPlannedStringAttr(after map[string]map[string]any, addr, key, want string) error {
	attrs, ok := after[addr]
	if !ok {
		return fmt.Errorf("resource %s missing from plan resource_changes", addr)
	}
	if attrs == nil {
		return fmt.Errorf("resource %s has nil change.after", addr)
	}
	raw, ok := attrs[key]
	if !ok {
		return fmt.Errorf("resource %s change.after missing %s", addr, key)
	}
	got, ok := raw.(string)
	if !ok {
		return fmt.Errorf("resource %s change.after.%s has type %T, want string", addr, key, raw)
	}
	if got != want {
		return fmt.Errorf("resource %s change.after.%s = %q, want %q", addr, key, got, want)
	}
	return nil
}

func assertPlannedDatasetID(after map[string]map[string]any, addr, wantDatasetID string) error {
	return assertPlannedStringAttr(after, addr, "dataset_id", wantDatasetID)
}

type kmsCryptoKeyIAMGrant struct {
	cryptoKeyID string
	role        string
	member      string
}

type plannedProjectIAMIdentities struct {
	customRoles     map[string]string
	serviceAccounts map[string]string
	kmsCryptoGrants map[kmsCryptoKeyIAMGrant]string
}

func collectPlannedProjectIAMIdentities(changes []plannedResourceChange, onlyCreates bool) (plannedProjectIAMIdentities, error) {
	identities := plannedProjectIAMIdentities{
		customRoles:     map[string]string{},
		serviceAccounts: map[string]string{},
		kmsCryptoGrants: map[kmsCryptoKeyIAMGrant]string{},
	}
	for _, ch := range changes {
		if onlyCreates {
			if !slices.Contains(ch.Change.Actions, "create") {
				continue
			}
		} else if len(ch.Change.Actions) == 1 && ch.Change.Actions[0] == "delete" {
			continue
		}
		switch plannedResourceType(ch) {
		case "google_project_iam_custom_role":
			roleID, _ := ch.Change.After["role_id"].(string)
			roleID = strings.TrimSpace(roleID)
			if roleID == "" {
				return plannedProjectIAMIdentities{}, fmt.Errorf("resource %s missing non-empty change.after.role_id", ch.Address)
			}
			identities.customRoles[roleID] = ch.Address
		case "google_service_account":
			accountID, _ := ch.Change.After["account_id"].(string)
			accountID = strings.TrimSpace(accountID)
			if accountID == "" {
				return plannedProjectIAMIdentities{}, fmt.Errorf("resource %s missing non-empty change.after.account_id", ch.Address)
			}
			identities.serviceAccounts[accountID] = ch.Address
		case "google_kms_crypto_key_iam_member":
			cryptoKeyID, _ := ch.Change.After["crypto_key_id"].(string)
			cryptoKeyID = strings.TrimSpace(cryptoKeyID)
			if cryptoKeyID == "" {
				return plannedProjectIAMIdentities{}, fmt.Errorf("resource %s missing non-empty change.after.crypto_key_id", ch.Address)
			}
			role, _ := ch.Change.After["role"].(string)
			role = strings.TrimSpace(role)
			if role == "" {
				return plannedProjectIAMIdentities{}, fmt.Errorf("resource %s missing non-empty change.after.role", ch.Address)
			}
			member, _ := ch.Change.After["member"].(string)
			member = strings.TrimSpace(member)
			if member == "" {
				return plannedProjectIAMIdentities{}, fmt.Errorf("resource %s missing non-empty change.after.member", ch.Address)
			}
			grant := kmsCryptoKeyIAMGrant{
				cryptoKeyID: cryptoKeyID,
				role:        role,
				member:      member,
			}
			identities.kmsCryptoGrants[grant] = ch.Address
		}
	}
	if len(identities.customRoles) == 0 {
		return plannedProjectIAMIdentities{}, errors.New("plan contains no google_project_iam_custom_role resources")
	}
	if len(identities.serviceAccounts) == 0 {
		return plannedProjectIAMIdentities{}, errors.New("plan contains no google_service_account resources")
	}
	return identities, nil
}

func assertNoLegacyIAMIdentityCollisions(legacy, cutover []plannedResourceChange) error {
	legacyIDs, err := collectPlannedProjectIAMIdentities(legacy, false)
	if err != nil {
		return fmt.Errorf("collecting legacy IAM identities: %w", err)
	}
	cutoverIDs, err := collectPlannedProjectIAMIdentities(cutover, true)
	if err != nil {
		return fmt.Errorf("collecting cutover planned creates: %w", err)
	}

	roleIDs := make([]string, 0, len(cutoverIDs.customRoles))
	for id := range cutoverIDs.customRoles {
		roleIDs = append(roleIDs, id)
	}
	slices.Sort(roleIDs)

	saIDs := make([]string, 0, len(cutoverIDs.serviceAccounts))
	for id := range cutoverIDs.serviceAccounts {
		saIDs = append(saIDs, id)
	}
	slices.Sort(saIDs)

	kmsGrants := make([]kmsCryptoKeyIAMGrant, 0, len(cutoverIDs.kmsCryptoGrants))
	for grant := range cutoverIDs.kmsCryptoGrants {
		kmsGrants = append(kmsGrants, grant)
	}
	slices.SortFunc(kmsGrants, func(a, b kmsCryptoKeyIAMGrant) int {
		if c := strings.Compare(a.cryptoKeyID, b.cryptoKeyID); c != 0 {
			return c
		}
		if c := strings.Compare(a.role, b.role); c != 0 {
			return c
		}
		return strings.Compare(a.member, b.member)
	})

	var errs []error
	for _, id := range roleIDs {
		if legacyAddr, ok := legacyIDs.customRoles[id]; ok {
			errs = append(errs, fmt.Errorf("custom IAM role %q (%s) collides with legacy workspace (%s)", id, cutoverIDs.customRoles[id], legacyAddr))
		}
	}
	for _, id := range saIDs {
		if legacyAddr, ok := legacyIDs.serviceAccounts[id]; ok {
			errs = append(errs, fmt.Errorf("service account %q (%s) collides with legacy workspace (%s)", id, cutoverIDs.serviceAccounts[id], legacyAddr))
		}
	}
	for _, grant := range kmsGrants {
		if legacyAddr, ok := legacyIDs.kmsCryptoGrants[grant]; ok {
			errs = append(errs, fmt.Errorf("KMS crypto key IAM grant (crypto_key_id=%q, role=%q, member=%q) (%s) collides with legacy workspace (%s)",
				grant.cryptoKeyID, grant.role, grant.member, cutoverIDs.kmsCryptoGrants[grant], legacyAddr))
		}
	}
	return errors.Join(errs...)
}

// The search index jobs do what deploy/README.md says when the terraform
// binary and the google provider apply them. BigQuery is a fake, which starts
// every job RUNNING, as BigQuery does, and ends it the way each step decides;
// nothing else is mocked, so the provider records a job before it has
// finished and only the wait can tell how it ends.
//
//   - An apply waits for running jobs and succeeds once they are DONE.
//   - A job that fails during the wait fails the apply with BigQuery's error;
//     every later plan and apply fails on it and submits nothing, until
//     terraform apply -replace retries it under a new job ID.
//   - A job that is not DONE in time fails the apply; the next apply waits for
//     the same job and submits no other.
//   - A table deleted outside Terraform is created again and its job rerun,
//     and so is the job of a table that was already created again; updating a
//     table in place reruns nothing.
//   - A changed index definition changes no job, and a plan warns about it.
//   - With the wait switched off, an apply ends while its jobs still run, and
//     a plan warns about that.
func TestTerraformSearchIndexJobsOnFakeBigQuery(t *testing.T) {
	if os.Getenv(terraformApplyEnv) == "" {
		t.Skipf("set %s=1 to apply deploy/terraform with terraform and the google provider against a fake BigQuery; it needs terraform and python3 on PATH, and network access to download the provider", terraformApplyEnv)
	}
	waitScriptPython(t)
	bin, err := exec.LookPath("terraform")
	if err != nil {
		t.Fatalf("%s is set, but terraform is not on PATH: %v", terraformApplyEnv, err)
	}
	fake := newFakeBigQuery(t)
	tf := newTerraformModule(t, bin, fake)

	const (
		logsJob      = "google_bigquery_job.otel_logs_search_index[0]"
		deniedReason = "Access Denied: Table test-project:otel.otel_logs: Permission bigquery.tables.createIndex denied"
	)
	// logsJobEnds makes the logs job end as given and every other job succeed.
	logsJobEnds := func(outcome fakeJobOutcome) func(string) fakeJobOutcome {
		return func(query string) fakeJobOutcome {
			if strings.Contains(query, "ON `test-project.otel.otel_logs`") {
				return outcome
			}
			return fakeJobOutcome{runningGets: 3}
		}
	}
	// startOver empties the fake and the Terraform state.
	startOver := func() {
		fake.reset()
		tf.removeState()
	}
	// unchangedExcept fails the test unless exactly the jobs of the given
	// signals have a new ID.
	unchangedExcept := func(t *testing.T, before, after map[string]string, replaced ...string) {
		t.Helper()
		for _, signal := range searchIndexSignals {
			switch changed := before[signal] != after[signal]; {
			case changed && !slices.Contains(replaced, signal):
				t.Errorf("the %s job was replaced: %s became %s", signal, before[signal], after[signal])
			case !changed && slices.Contains(replaced, signal):
				t.Errorf("the %s job %s was not replaced", signal, before[signal])
			}
		}
	}
	submitted := func(t *testing.T, want int) {
		t.Helper()
		if got := fake.submittedJobs(); len(got) != want {
			t.Errorf("BigQuery received %d jobs, want %d: %q", len(got), want, got)
		}
	}

	if !t.Run("an apply waits for running jobs", func(t *testing.T) {
		startOver()
		tf.mustApply()
		submitted(t, 3)
		for signal, job := range tf.searchIndexJobs() {
			// The provider recorded the job while it ran, so Terraform knows
			// that it finished only from the wait.
			if job.state != "RUNNING" {
				t.Errorf("the provider recorded the %s job as %q, want RUNNING for this test to prove anything", signal, job.state)
			}
			if _, waitGets := fake.jobGets(job.id); waitGets < 2 {
				t.Errorf("the wait asked BigQuery for the %s job %d times, want it to ask until the job is DONE", signal, waitGets)
			}
			if job.waitedFor != job.id || job.waitTainted {
				t.Errorf("the %s job %s has the wait %+v, want one that succeeded for that job", signal, job.id, job)
			}
		}

		before := tf.searchIndexJobIDs()
		if out := tf.mustApply(); !strings.Contains(out, "No changes.") {
			t.Errorf("a second apply found changes:\n%s", out)
		}
		submitted(t, 3)
		unchangedExcept(t, before, tf.searchIndexJobIDs())
	}) {
		return
	}

	t.Run("updating a table in place keeps its job", func(t *testing.T) {
		before := tf.searchIndexJobIDs()
		created := fake.table("otel", "otel_logs")["creationTime"]
		tf.mustApply(`-var=logs_clustering=["service_name","trace_id"]`)
		table := fake.table("otel", "otel_logs")
		clustering, _ := table["clustering"].(map[string]any)
		if got := fmt.Sprint(clustering["fields"]); got != "[service_name trace_id]" {
			t.Fatalf("otel_logs is clustered by %s, want the apply to update it to [service_name trace_id]", got)
		}
		if table["creationTime"] != created {
			t.Fatalf("otel_logs was created again: creation time %v became %v", created, table["creationTime"])
		}
		submitted(t, 3)
		unchangedExcept(t, before, tf.searchIndexJobIDs())
	})

	t.Run("a changed index definition changes no job and a plan warns about it", func(t *testing.T) {
		before := tf.searchIndexJobIDs()
		definition := []string{`-var=logs_search_index_columns=["trace_id","span_id","body"]`, "-var=logs_search_index_analyzer=LOG_ANALYZER"}
		tf.mustApply(definition...)
		submitted(t, 3)
		unchangedExcept(t, before, tf.searchIndexJobIDs())

		// A plan of the whole module evaluates its checks; Terraform skips
		// them when it is given targets. Without a refresh, the plan asks the
		// fake for nothing it does not serve.
		out, err := tf.run(searchIndexArgs("plan", append([]string{"-refresh=false", "-out=definition.tfplan"}, definition...)...)...)
		if err != nil {
			t.Fatalf("terraform plan: %v\n%s", err, out)
		}
		for _, want := range []string{
			"Warning: Check block assertion failed",
			`in check "search_index_definitions"`,
			"These search index jobs ran with a different index definition than the one configured now: " + logsJob + ".",
			"To rebuild an index, drop it with DROP SEARCH INDEX, then run terraform apply -replace on its job",
		} {
			if !strings.Contains(unwrapped(out), want) {
				t.Errorf("the plan does not contain %q:\n%s", want, out)
			}
		}
		actions := tf.plannedActions("definition.tfplan")
		for _, signal := range searchIndexSignals {
			for _, address := range []string{
				"google_bigquery_job.otel_" + signal + "_search_index[0]",
				`terraform_data.search_index_job_wait["` + signal + `"]`,
				`terraform_data.search_index_table["` + signal + `"]`,
			} {
				if got := actions[address]; got != "no-op" {
					t.Errorf("the plan holds %q for %s, want no-op", got, address)
				}
			}
		}

		// With the definition the jobs ran with, the same plan does not warn.
		out, err = tf.run(searchIndexArgs("plan", "-refresh=false")...)
		if err != nil {
			t.Fatalf("terraform plan: %v\n%s", err, out)
		}
		if strings.Contains(out, "Check block assertion failed") {
			t.Errorf("a plan with the definition the jobs ran with warns:\n%s", out)
		}
	})

	t.Run("a table deleted outside Terraform is created again with its job", func(t *testing.T) {
		before := tf.searchIndexJobIDs()
		created := fake.table("otel", "otel_logs")["creationTime"]
		fake.deleteTable("otel", "otel_logs")
		tf.mustApply()
		table := fake.table("otel", "otel_logs")
		if table == nil || table["creationTime"] == created {
			t.Fatalf("otel_logs after the apply is %v, want a new table", table)
		}
		submitted(t, 4)
		after := tf.searchIndexJobs()
		unchangedExcept(t, before, tf.searchIndexJobIDs(), "logs")
		if job := after["logs"]; job.waitedFor != job.id || job.waitTainted {
			t.Errorf("the new logs job %s has the wait %+v, want one that succeeded for that job", job.id, job)
		}
	})

	t.Run("a table created again outside Terraform gets its job too", func(t *testing.T) {
		before := tf.searchIndexJobIDs()
		fake.recreateTable("otel", "otel_spans")
		tf.mustApply()
		submitted(t, 5)
		unchangedExcept(t, before, tf.searchIndexJobIDs(), "spans")
	})

	t.Run("a job that fails during the wait fails the apply until it is retried", func(t *testing.T) {
		startOver()
		fake.finishJobs(logsJobEnds(fakeJobOutcome{runningGets: 3, errorResult: map[string]any{"reason": "accessDenied", "location": "", "message": deniedReason}}))
		out, err := tf.apply()
		if err == nil {
			t.Fatalf("terraform apply succeeded although the logs job failed:\n%s", out)
		}
		failed := tf.searchIndexJobs()["logs"]
		for _, want := range []string{
			"Error: local-exec provisioner error",
			"BigQuery job " + failed.id + " failed (accessDenied): " + deniedReason + ". Fix the cause, then run terraform apply -replace='" + logsJob + "' to retry it under a new job ID.",
		} {
			if !strings.Contains(unwrapped(out), want) {
				t.Errorf("the failed apply does not report %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "Apply complete!") || strings.Contains(out, fakeBigQueryToken) {
			t.Errorf("the failed apply reports a complete apply or prints the access token:\n%s", out)
		}
		if failed.state != "RUNNING" || !failed.waitTainted {
			t.Errorf("the state records the logs job as %+v, want a job the provider saw RUNNING and a failed wait", failed)
		}
		before := tf.searchIndexJobIDs()

		// The failure stays: plans and applies fail on the job and submit
		// nothing.
		for _, command := range []string{"plan", "apply"} {
			args := searchIndexTargets()
			if command == "apply" {
				args = append(args, "-auto-approve")
			}
			out, err := tf.run(searchIndexArgs(command, args...)...)
			if err == nil {
				t.Fatalf("terraform %s succeeded with a failed logs job in the state:\n%s", command, out)
			}
			for _, want := range []string{
				"Error: Resource postcondition failed",
				"BigQuery search index job " + failed.id + " failed (accessDenied): " + deniedReason + ". Fix the cause, then run terraform apply -replace='" + logsJob + "' to retry it under a new job ID.",
			} {
				if !strings.Contains(unwrapped(out), want) {
					t.Errorf("terraform %s does not report %q:\n%s", command, want, out)
				}
			}
		}
		submitted(t, 3)
		unchangedExcept(t, before, tf.searchIndexJobIDs())

		// With the cause fixed, -replace retries under a new job ID.
		fake.finishJobs(logsJobEnds(fakeJobOutcome{runningGets: 3}))
		tf.mustApply("-replace=" + logsJob)
		submitted(t, 4)
		unchangedExcept(t, before, tf.searchIndexJobIDs(), "logs")
		if job := tf.searchIndexJobs()["logs"]; job.waitedFor != job.id || job.waitTainted {
			t.Errorf("the retried logs job %s has the wait %+v, want one that succeeded for that job", job.id, job)
		}
	})

	t.Run("a job that is not done in time fails the apply and the next apply waits for it again", func(t *testing.T) {
		startOver()
		fake.finishJobs(logsJobEnds(fakeJobOutcome{runningGets: -1}))
		start := time.Now()
		out, err := tf.apply("-var=search_index_job_wait_timeout_seconds=2")
		if err == nil {
			t.Fatalf("terraform apply succeeded although the logs job was still running:\n%s", out)
		}
		if elapsed := time.Since(start); elapsed > 2*time.Minute {
			t.Errorf("the apply took %v with a 2s wait", elapsed)
		}
		stuck := tf.searchIndexJobs()["logs"]
		if want := "BigQuery job " + stuck.id + " was not DONE after 2s (last state: RUNNING)."; !strings.Contains(unwrapped(out), want) || strings.Contains(out, "Apply complete!") {
			t.Errorf("the apply does not fail with %q:\n%s", want, out)
		}
		if !stuck.waitTainted {
			t.Errorf("the state records the logs job as %+v, want a failed wait", stuck)
		}
		before := tf.searchIndexJobIDs()

		fake.finishJob(stuck.id)
		tf.mustApply("-var=search_index_job_wait_timeout_seconds=2")
		submitted(t, 3)
		unchangedExcept(t, before, tf.searchIndexJobIDs())
		if job := tf.searchIndexJobs()["logs"]; job.waitedFor != job.id || job.waitTainted {
			t.Errorf("the logs job %s has the wait %+v, want one that succeeded for that job", job.id, job)
		}
	})

	t.Run("without the wait an apply ends while jobs run and a plan warns about it", func(t *testing.T) {
		startOver()
		fake.finishJobs(func(string) fakeJobOutcome { return fakeJobOutcome{runningGets: -1} })
		tf.mustApply("-var=search_index_job_wait_timeout_seconds=0")
		submitted(t, 3)
		for signal, job := range tf.searchIndexJobs() {
			if _, waitGets := fake.jobGets(job.id); job.state != "RUNNING" || job.waitedFor != "" || waitGets != 0 {
				t.Errorf("the %s job is %+v after %d requests from a wait, want a running job nothing waited for", signal, job, waitGets)
			}
		}
		out, err := tf.run(searchIndexArgs("plan", "-refresh=false", "-var=search_index_job_wait_timeout_seconds=0")...)
		if err != nil {
			t.Fatalf("terraform plan: %v\n%s", err, out)
		}
		for _, want := range []string{"Warning: Check block assertion failed", `in check "search_index_jobs_finished"`, "and search_index_job_wait_timeout_seconds is 0, so nothing waited to confirm that the indexes were created."} {
			if !strings.Contains(unwrapped(out), want) {
				t.Errorf("the plan does not contain %q:\n%s", want, out)
			}
		}
	})

	t.Run("legacy v0alpha2 state plans table replacement while side-by-side dataset creates cleanly", func(t *testing.T) {
		startOver()
		tableTargets := []string{
			"-target=google_bigquery_dataset.otel",
			"-target=google_bigquery_table.otel_spans",
			"-target=google_bigquery_table.otel_logs",
			"-target=google_bigquery_table.otel_metrics",
			"-target=google_bigquery_table.otel_quarantine",
		}
		tf.mustApply(tableTargets...)

		var golden goldenSchemaDoc
		if err := json.Unmarshal([]byte(testsupport.ReadRepoText(t, "internal/schema/testdata/v0alpha2_golden.json")), &golden); err != nil {
			t.Fatalf("unmarshal v0alpha2_golden.json: %v", err)
		}
		legacyTables := []string{"otel_spans", "otel_logs", "otel_metrics", "otel_quarantine"}
		legacyRESTFields := make(map[string][]map[string]any, len(legacyTables))
		for _, tbl := range golden.Tables {
			legacyRESTFields[tbl.Name] = goldenFieldsToREST(tbl.Fields)
		}
		for _, tbl := range legacyTables {
			if len(legacyRESTFields[tbl]) == 0 {
				t.Fatalf("v0alpha2_golden.json missing fields for table %q", tbl)
			}
		}

		fake.mu.Lock()
		for _, tbl := range legacyTables {
			stored, ok := fake.tables["otel/"+tbl]
			if !ok {
				fake.mu.Unlock()
				t.Fatalf("fake BigQuery missing table otel/%s", tbl)
			}
			stored["schema"] = map[string]any{"fields": legacyRESTFields[tbl]}
			delete(stored, "labels")
		}
		fake.mu.Unlock()

		statePath := filepath.Join(tf.dir, "terraform.tfstate")
		rawState, err := os.ReadFile(statePath)
		if err != nil {
			t.Fatalf("read terraform.tfstate: %v", err)
		}
		var state map[string]any
		if err := json.Unmarshal(rawState, &state); err != nil {
			t.Fatalf("parse terraform.tfstate: %v", err)
		}
		patchedInState := map[string]bool{}
		resources, _ := state["resources"].([]any)
		for _, rawRes := range resources {
			resMap, _ := rawRes.(map[string]any)
			if resMap["mode"] != "managed" || resMap["type"] != "google_bigquery_table" {
				continue
			}
			instances, _ := resMap["instances"].([]any)
			for _, rawInst := range instances {
				instMap, _ := rawInst.(map[string]any)
				attrs, _ := instMap["attributes"].(map[string]any)
				tableID, _ := attrs["table_id"].(string)
				restFields, wantPatch := legacyRESTFields[tableID]
				if !wantPatch {
					continue
				}
				schemaJSON, marshalErr := json.Marshal(restFields)
				if marshalErr != nil {
					t.Fatalf("marshal legacy REST schema for %s: %v", tableID, marshalErr)
				}
				attrs["schema"] = string(schemaJSON)
				for _, labelAttr := range []string{"labels", "effective_labels", "terraform_labels"} {
					lbls, ok := attrs[labelAttr].(map[string]any)
					if !ok {
						continue
					}
					for k := range lbls {
						if strings.HasPrefix(k, "otel_schema_") {
							delete(lbls, k)
						}
					}
				}
				patchedInState[tableID] = true
			}
		}
		for _, tbl := range legacyTables {
			if !patchedInState[tbl] {
				t.Fatalf("terraform.tfstate missing managed google_bigquery_table instance for %s", tbl)
			}
		}
		patchedRaw, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			t.Fatalf("marshal patched terraform.tfstate: %v", err)
		}
		if err := os.WriteFile(statePath, patchedRaw, 0o600); err != nil {
			t.Fatalf("write patched terraform.tfstate: %v", err)
		}

		snapshotETags := make(map[string]any, len(legacyTables))
		snapshotCreationTimes := make(map[string]any, len(legacyTables))
		for _, tbl := range legacyTables {
			cur := fake.table("otel", tbl)
			snapshotETags[tbl] = cur["etag"]
			snapshotCreationTimes[tbl] = cur["creationTime"]
		}

		inplaceArgs := append([]string{
			"plan", "-input=false", "-no-color",
			"-var=project_id=" + fakeBigQueryProject,
			"-out=legacy-inplace.tfplan",
		}, tableTargets...)
		out, err := tf.run(inplaceArgs...)
		if err != nil {
			t.Fatalf("terraform plan legacy-inplace: %v\n%s", err, out)
		}
		inplaceActions := tf.plannedActions("legacy-inplace.tfplan")
		inplaceAfter := tf.plannedResourceAfterAttrs("legacy-inplace.tfplan")
		for _, tbl := range legacyTables {
			addr := "google_bigquery_table." + tbl
			if got := inplaceActions[addr]; got != "delete,create" {
				t.Errorf("in-place plan action for %s = %q, want %q (all actions: %v)", addr, got, "delete,create", inplaceActions)
			}
			if err := assertPlannedDatasetID(inplaceAfter, addr, "otel"); err != nil {
				t.Errorf("in-place plan dataset_id check: %v", err)
			}
		}

		legacyIAMTF := newTerraformModule(t, bin, fake)
		legacyIAMOut, legacyIAMErr := legacyIAMTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=grant_auto_create=true",
			"-out=legacy-iam.tfplan",
		)
		if legacyIAMErr != nil {
			t.Fatalf("terraform plan legacy IAM baseline: %v\n%s", legacyIAMErr, legacyIAMOut)
		}
		legacyIAMChanges := legacyIAMTF.showPlanChanges("legacy-iam.tfplan")
		legacyIDs, iamErr := collectPlannedProjectIAMIdentities(legacyIAMChanges, true)
		if iamErr != nil {
			t.Fatalf("collectPlannedProjectIAMIdentities(legacy): %v", iamErr)
		}
		for _, wantRole := range []string{"otelCollectorWriter", "otelCollectorProvisioner", "otelCollectorJobs"} {
			if _, ok := legacyIDs.customRoles[wantRole]; !ok {
				t.Fatalf("legacy IAM plan missing custom role %q (got %v)", wantRole, legacyIDs.customRoles)
			}
		}
		if _, ok := legacyIDs.serviceAccounts["otel-collector"]; !ok {
			t.Fatalf("legacy IAM plan missing service account otel-collector (got %v)", legacyIDs.serviceAccounts)
		}

		// Negative check: overriding ONLY dataset_id in a second workspace
		// collides on default otelCollectorWriter and otel-collector.
		naiveCutoverTF := newTerraformModule(t, bin, fake)
		naiveOut, naiveErr := naiveCutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-out=naive-cutover.tfplan",
		)
		if naiveErr != nil {
			t.Fatalf("terraform plan naive cutover: %v\n%s", naiveErr, naiveOut)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyIAMChanges, naiveCutoverTF.showPlanChanges("naive-cutover.tfplan")); colErr == nil {
			t.Fatalf("assertNoLegacyIAMIdentityCollisions(dataset_id-only cutover) = nil, want collision error")
		} else if !strings.Contains(colErr.Error(), "otelCollectorWriter") || !strings.Contains(colErr.Error(), "otel-collector") {
			t.Fatalf("naive cutover collision error = %q, want both otelCollectorWriter and otel-collector", colErr.Error())
		}

		// Positive documented cutover plan: isolates dataset_id, service_account_id,
		// and writer_role_id with zero project-scoped IAM identity collisions.
		cutoverTF := newTerraformModule(t, bin, fake)
		cutoverOut, cutoverErr := cutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-var=service_account_id=otel-collector-v1",
			"-var=writer_role_id=otelCollectorWriterV1",
			"-out=cutover.tfplan",
		)
		if cutoverErr != nil {
			t.Fatalf("terraform plan cutover: %v\n%s", cutoverErr, cutoverOut)
		}
		cutoverChanges := cutoverTF.showPlanChanges("cutover.tfplan")
		cutoverActions := cutoverTF.plannedActions("cutover.tfplan")
		cutoverAfter := cutoverTF.plannedResourceAfterAttrs("cutover.tfplan")
		if got := cutoverActions["google_bigquery_dataset.otel"]; got != "create" {
			t.Errorf("cutover plan action for google_bigquery_dataset.otel = %q, want %q", got, "create")
		}
		if err := assertPlannedDatasetID(cutoverAfter, "google_bigquery_dataset.otel", "otel_v1"); err != nil {
			t.Errorf("cutover plan dataset_id check: %v", err)
		}
		// Ensure mismatched dataset_id on cutover.tfplan is caught.
		if err := assertPlannedDatasetID(cutoverAfter, "google_bigquery_dataset.otel", "otel"); err == nil {
			t.Errorf("assertPlannedDatasetID(cutoverAfter, google_bigquery_dataset.otel, \"otel\") = nil, want mismatch error")
		}
		for _, tbl := range legacyTables {
			addr := "google_bigquery_table." + tbl
			if got := cutoverActions[addr]; got != "create" {
				t.Errorf("cutover plan action for %s = %q, want %q", addr, got, "create")
			}
			if err := assertPlannedDatasetID(cutoverAfter, addr, "otel_v1"); err != nil {
				t.Errorf("cutover plan dataset_id check: %v", err)
			}
			if err := assertPlannedDatasetID(cutoverAfter, addr, "otel"); err == nil {
				t.Errorf("assertPlannedDatasetID(cutoverAfter, %s, \"otel\") = nil, want mismatch error", addr)
			}
		}
		if got := cutoverActions["google_project_iam_custom_role.otel_collector_writer"]; got != "create" {
			t.Errorf("cutover plan action for google_project_iam_custom_role.otel_collector_writer = %q, want %q", got, "create")
		}
		if err := assertPlannedStringAttr(cutoverAfter, "google_project_iam_custom_role.otel_collector_writer", "role_id", "otelCollectorWriterV1"); err != nil {
			t.Errorf("cutover plan writer role_id check: %v", err)
		}
		if got := cutoverActions["google_service_account.otel_collector"]; got != "create" {
			t.Errorf("cutover plan action for google_service_account.otel_collector = %q, want %q", got, "create")
		}
		if err := assertPlannedStringAttr(cutoverAfter, "google_service_account.otel_collector", "account_id", "otel-collector-v1"); err != nil {
			t.Errorf("cutover plan service account_id check: %v", err)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyIAMChanges, cutoverChanges); colErr != nil {
			t.Errorf("documented cutover collided with legacy IAM identities: %v", colErr)
		}

		// Verify grant_auto_create=true cutover: omitting provisioner_role_id and
		// jobs_role_id collides, while setting both achieves zero collisions.
		partialAutoOut, partialAutoErr := cutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-var=service_account_id=otel-collector-v1",
			"-var=writer_role_id=otelCollectorWriterV1",
			"-var=grant_auto_create=true",
			"-out=cutover-partial-autocreate.tfplan",
		)
		if partialAutoErr != nil {
			t.Fatalf("terraform plan cutover partial auto_create: %v\n%s", partialAutoErr, partialAutoOut)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyIAMChanges, cutoverTF.showPlanChanges("cutover-partial-autocreate.tfplan")); colErr == nil {
			t.Fatalf("assertNoLegacyIAMIdentityCollisions(grant_auto_create=true without role ID overrides) = nil, want collision error")
		} else if !strings.Contains(colErr.Error(), "otelCollectorProvisioner") || !strings.Contains(colErr.Error(), "otelCollectorJobs") {
			t.Fatalf("partial auto_create collision error = %q, want both otelCollectorProvisioner and otelCollectorJobs", colErr.Error())
		}

		autoOut, autoErr := cutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-var=service_account_id=otel-collector-v1",
			"-var=writer_role_id=otelCollectorWriterV1",
			"-var=grant_auto_create=true",
			"-var=provisioner_role_id=otelCollectorProvisionerV1",
			"-var=jobs_role_id=otelCollectorJobsV1",
			"-out=cutover-autocreate.tfplan",
		)
		if autoErr != nil {
			t.Fatalf("terraform plan cutover auto_create: %v\n%s", autoErr, autoOut)
		}
		autoChanges := cutoverTF.showPlanChanges("cutover-autocreate.tfplan")
		autoActions := cutoverTF.plannedActions("cutover-autocreate.tfplan")
		autoAfter := cutoverTF.plannedResourceAfterAttrs("cutover-autocreate.tfplan")
		if got := autoActions["google_project_iam_custom_role.otel_collector_provisioner[0]"]; got != "create" {
			t.Errorf("auto_create cutover action for google_project_iam_custom_role.otel_collector_provisioner[0] = %q, want %q", got, "create")
		}
		if err := assertPlannedStringAttr(autoAfter, "google_project_iam_custom_role.otel_collector_provisioner[0]", "role_id", "otelCollectorProvisionerV1"); err != nil {
			t.Errorf("auto_create cutover provisioner role_id check: %v", err)
		}
		if got := autoActions["google_project_iam_custom_role.otel_collector_jobs[0]"]; got != "create" {
			t.Errorf("auto_create cutover action for google_project_iam_custom_role.otel_collector_jobs[0] = %q, want %q", got, "create")
		}
		if err := assertPlannedStringAttr(autoAfter, "google_project_iam_custom_role.otel_collector_jobs[0]", "role_id", "otelCollectorJobsV1"); err != nil {
			t.Errorf("auto_create cutover jobs role_id check: %v", err)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyIAMChanges, autoChanges); colErr != nil {
			t.Errorf("documented auto_create cutover collided with legacy IAM identities: %v", colErr)
		}

		// Verify CMEK (kms_key_name) side-by-side collision guard:
		// sharing the same Cloud KMS key collides on google_kms_crypto_key_iam_member.bq_encryptor[0],
		// while passing a distinct v1 key isolates CMEK IAM with zero collisions.
		const (
			legacyKMSKey      = "projects/" + fakeBigQueryProject + "/locations/us/keyRings/otel-ring/cryptoKeys/legacy-key"
			v1KMSKey          = "projects/" + fakeBigQueryProject + "/locations/us/keyRings/otel-ring/cryptoKeys/v1-key"
			cmekRole          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
			fakeCMEKPrincipal = "serviceAccount:bq-123456789012@bigquery-encryption.iam.gserviceaccount.com"
		)
		legacyCMEKOut, legacyCMEKErr := legacyIAMTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=kms_key_name="+legacyKMSKey,
			"-out=legacy-cmek.tfplan",
		)
		if legacyCMEKErr != nil {
			t.Fatalf("terraform plan legacy CMEK: %v\n%s", legacyCMEKErr, legacyCMEKOut)
		}
		legacyCMEKChanges := legacyIAMTF.showPlanChanges("legacy-cmek.tfplan")
		legacyCMEKIDs, cmekIDErr := collectPlannedProjectIAMIdentities(legacyCMEKChanges, true)
		if cmekIDErr != nil {
			t.Fatalf("collectPlannedProjectIAMIdentities(legacy CMEK): %v", cmekIDErr)
		}
		wantLegacyGrant := kmsCryptoKeyIAMGrant{
			cryptoKeyID: legacyKMSKey,
			role:        cmekRole,
			member:      fakeCMEKPrincipal,
		}
		if addr, ok := legacyCMEKIDs.kmsCryptoGrants[wantLegacyGrant]; !ok {
			t.Fatalf("legacy CMEK plan missing %+v (got %v)", wantLegacyGrant, legacyCMEKIDs.kmsCryptoGrants)
		} else if addr != "google_kms_crypto_key_iam_member.bq_encryptor[0]" {
			t.Fatalf("legacy CMEK grant address = %q, want google_kms_crypto_key_iam_member.bq_encryptor[0]", addr)
		}

		sharedCMEKOut, sharedCMEKErr := cutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-var=service_account_id=otel-collector-v1",
			"-var=writer_role_id=otelCollectorWriterV1",
			"-var=kms_key_name="+legacyKMSKey,
			"-out=cutover-shared-cmek.tfplan",
		)
		if sharedCMEKErr != nil {
			t.Fatalf("terraform plan cutover shared CMEK: %v\n%s", sharedCMEKErr, sharedCMEKOut)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyCMEKChanges, cutoverTF.showPlanChanges("cutover-shared-cmek.tfplan")); colErr == nil {
			t.Fatalf("assertNoLegacyIAMIdentityCollisions(shared kms_key_name) = nil, want CMEK collision error")
		} else if !strings.Contains(colErr.Error(), "google_kms_crypto_key_iam_member.bq_encryptor[0]") ||
			!strings.Contains(colErr.Error(), legacyKMSKey) ||
			!strings.Contains(colErr.Error(), cmekRole) ||
			!strings.Contains(colErr.Error(), fakeCMEKPrincipal) {
			t.Fatalf("shared CMEK collision error = %q, want bq_encryptor[0], %q, %q, and %q",
				colErr.Error(), legacyKMSKey, cmekRole, fakeCMEKPrincipal)
		}

		distinctCMEKOut, distinctCMEKErr := cutoverTF.run(
			"plan", "-input=false", "-no-color",
			"-var=project_id="+fakeBigQueryProject,
			"-var=dataset_id=otel_v1",
			"-var=service_account_id=otel-collector-v1",
			"-var=writer_role_id=otelCollectorWriterV1",
			"-var=kms_key_name="+v1KMSKey,
			"-out=cutover-distinct-cmek.tfplan",
		)
		if distinctCMEKErr != nil {
			t.Fatalf("terraform plan cutover distinct CMEK: %v\n%s", distinctCMEKErr, distinctCMEKOut)
		}
		if colErr := assertNoLegacyIAMIdentityCollisions(legacyCMEKChanges, cutoverTF.showPlanChanges("cutover-distinct-cmek.tfplan")); colErr != nil {
			t.Errorf("documented distinct-KMS cutover collided with legacy CMEK/IAM bindings: %v", colErr)
		}
		for _, tbl := range legacyTables {
			cur := fake.table("otel", tbl)
			if cur == nil {
				t.Fatalf("legacy table otel.%s missing from fake BigQuery after cutover plan", tbl)
			}
			if cur["etag"] != snapshotETags[tbl] || cur["creationTime"] != snapshotCreationTimes[tbl] {
				t.Errorf("legacy table otel.%s mutated by cutover plan: etag=%v creationTime=%v, want etag=%v creationTime=%v",
					tbl, cur["etag"], cur["creationTime"], snapshotETags[tbl], snapshotCreationTimes[tbl])
			}
			if _, hasLabels := cur["labels"]; hasLabels {
				t.Errorf("legacy table otel.%s unexpectedly gained labels: %v", tbl, cur["labels"])
			}
		}
	})
}

type goldenSchemaField struct {
	Name      string              `json:"name"`
	Type      string              `json:"type"`
	Mode      string              `json:"mode"`
	MaxLength int64               `json:"max_length"`
	Fields    []goldenSchemaField `json:"fields"`
}

type goldenSchemaDoc struct {
	Version string `json:"version"`
	Tables  []struct {
		Name   string              `json:"name"`
		Fields []goldenSchemaField `json:"fields"`
	} `json:"tables"`
}

func goldenFieldsToREST(fields []goldenSchemaField) []map[string]any {
	out := make([]map[string]any, 0, len(fields))
	for _, f := range fields {
		typ := f.Type
		if typ == "STRUCT" {
			typ = "RECORD"
		}
		entry := map[string]any{
			"name": f.Name,
			"type": typ,
			"mode": f.Mode,
		}
		if f.MaxLength > 0 {
			entry["maxLength"] = strconv.FormatInt(f.MaxLength, 10)
		}
		if len(f.Fields) > 0 {
			entry["fields"] = goldenFieldsToREST(f.Fields)
		}
		out = append(out, entry)
	}
	return out
}

func terraformApplyStepSelectsTests(run, envVal string, tests []string) (bool, error) {
	run = strings.TrimSpace(run)
	if !strings.HasPrefix(run, "go test ") || envVal == "" {
		return false, nil
	}
	pattern := testsupport.FirstCapture(` -run '([^']+)' \./tools/repocheck$`, run)
	if pattern == "" {
		return false, nil
	}
	selected, err := regexp.Compile(pattern)
	if err != nil {
		return false, err
	}
	return !slices.ContainsFunc(tests, func(name string) bool { return !selected.MatchString(name) }), nil
}

// CI applies the search index jobs on every change. The terraform-apply job
// sets up Go and the Terraform release the terraform job pins, without the
// wrapper, and runs the two tests above with terraformApplyEnv set, which
// turns a missing terraform or python3 into a failure instead of a skip.
func TestTerraformApplyCIJobAppliesTheSearchIndexJobs(t *testing.T) {
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string            `yaml:"uses"`
				With map[string]any    `yaml:"with"`
				Env  map[string]string `yaml:"env"`
				Run  string            `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(testsupport.ReadRepoText(t, ".github/workflows/ci.yml")), &workflow); err != nil {
		t.Fatalf("unmarshaling ci.yml: %v", err)
	}
	// terraformSetup returns the Terraform release a job sets up and its
	// wrapper setting, or "" for a job that sets up none.
	terraformSetup := func(job string) (version, wrapper string) {
		for _, step := range workflow.Jobs[job].Steps {
			if strings.HasPrefix(step.Uses, "hashicorp/setup-terraform@") {
				return fmt.Sprint(step.With["terraform_version"]), fmt.Sprint(step.With["terraform_wrapper"])
			}
		}
		return "", ""
	}
	pinned, _ := terraformSetup("terraform")
	job, ok := workflow.Jobs["terraform-apply"]
	if !ok {
		t.Fatal("ci.yml has no terraform-apply job")
	}
	if version, wrapper := terraformSetup("terraform-apply"); version == "" || version != pinned || wrapper != "false" {
		t.Errorf("ci.yml terraform-apply job sets up Terraform %q with terraform_wrapper %q, want the terraform job's release %q without the wrapper", version, wrapper, pinned)
	}

	tests := []string{"TestSearchIndexJobWaitScript", "TestTerraformSearchIndexJobsOnFakeBigQuery"}
	source := testsupport.ReadRepoText(t, "tools/repocheck/terraform_search_index_jobs_test.go")
	for _, name := range tests {
		if !strings.Contains(source, "\nfunc "+name+"(t *testing.T) {\n") {
			t.Fatalf("tools/repocheck/terraform_search_index_jobs_test.go declares no %s", name)
		}
	}
	setsUpGo, applies := false, false
	for _, step := range job.Steps {
		setsUpGo = setsUpGo || strings.HasPrefix(step.Uses, "actions/setup-go@")
		matched, err := terraformApplyStepSelectsTests(step.Run, step.Env[terraformApplyEnv], tests)
		if err != nil {
			t.Fatalf("ci.yml terraform-apply job selects tests with an invalid pattern in %q: %v", step.Run, err)
		}
		applies = applies || matched
	}
	if !setsUpGo {
		t.Error("ci.yml terraform-apply job does not set up Go with actions/setup-go")
	}
	if !applies {
		t.Errorf("ci.yml terraform-apply job has no go test step that sets %s and runs %q in ./tools/repocheck", terraformApplyEnv, tests)
	}

	// Prove the step matcher fails closed if the target package regresses to "."
	// or omits either required test.
	for _, tc := range []struct {
		name string
		run  string
		env  string
	}{
		{
			name: "root package target does not match ./tools/repocheck",
			run:  "go test -count=1 -v -run '^(TestSearchIndexJobWaitScript|TestTerraformSearchIndexJobsOnFakeBigQuery)$' .",
			env:  "1",
		},
		{
			name: "missing BQ_TEST_TERRAFORM_APPLY env does not match",
			run:  "go test -count=1 -v -run '^(TestSearchIndexJobWaitScript|TestTerraformSearchIndexJobsOnFakeBigQuery)$' ./tools/repocheck",
			env:  "",
		},
		{
			name: "pattern missing second test does not match",
			run:  "go test -count=1 -v -run '^TestSearchIndexJobWaitScript$' ./tools/repocheck",
			env:  "1",
		},
	} {
		if matched, err := terraformApplyStepSelectsTests(tc.run, tc.env, tests); err != nil || matched {
			t.Errorf("%s: got (matched=%v, err=%v), want (false, nil)", tc.name, matched, err)
		}
	}
}

func TestAssertPlannedDatasetID(t *testing.T) {
	after := map[string]map[string]any{
		"google_bigquery_dataset.otel":     {"dataset_id": "otel_v1"},
		"google_bigquery_table.otel_spans": {"dataset_id": "otel_v1"},
		"google_bigquery_table.no_key":     {"table_id": "otel_logs"},
		"google_bigquery_table.bad_type":   {"dataset_id": 123},
		"google_bigquery_table.nil_after":  nil,
	}

	if err := assertPlannedDatasetID(after, "google_bigquery_dataset.otel", "otel_v1"); err != nil {
		t.Fatalf("unexpected error for matching dataset_id: %v", err)
	}
	if err := assertPlannedDatasetID(after, "google_bigquery_table.otel_spans", "otel_v1"); err != nil {
		t.Fatalf("unexpected error for matching table dataset_id: %v", err)
	}

	// Verify mismatched, missing, nil, and non-string dataset_id cases return errors.
	negatives := []struct {
		name string
		addr string
		want string
	}{
		{name: "mismatch_dataset_id", addr: "google_bigquery_table.otel_spans", want: "otel"},
		{name: "missing_resource", addr: "google_bigquery_table.missing", want: "otel_v1"},
		{name: "missing_dataset_id_key", addr: "google_bigquery_table.no_key", want: "otel_v1"},
		{name: "non_string_dataset_id", addr: "google_bigquery_table.bad_type", want: "otel_v1"},
		{name: "nil_after_map", addr: "google_bigquery_table.nil_after", want: "otel_v1"},
	}
	for _, tc := range negatives {
		if err := assertPlannedDatasetID(after, tc.addr, tc.want); err == nil {
			t.Errorf("%s: assertPlannedDatasetID(%q, %q) = nil, want error", tc.name, tc.addr, tc.want)
		}
	}
}

func TestAssertNoLegacyIAMIdentityCollisions(t *testing.T) {
	mkRole := func(addr, roleID string, actions ...string) plannedResourceChange {
		var ch plannedResourceChange
		ch.Address = addr
		ch.Type = "google_project_iam_custom_role"
		ch.Change.Actions = actions
		if roleID != "" {
			ch.Change.After = map[string]any{"role_id": roleID}
		}
		return ch
	}
	mkSA := func(addr, accountID string, actions ...string) plannedResourceChange {
		var ch plannedResourceChange
		ch.Address = addr
		ch.Type = "google_service_account"
		ch.Change.Actions = actions
		if accountID != "" {
			ch.Change.After = map[string]any{"account_id": accountID}
		}
		return ch
	}
	mkKMSGrant := func(addr, cryptoKeyID, role, member string, actions ...string) plannedResourceChange {
		var ch plannedResourceChange
		ch.Address = addr
		ch.Type = "google_kms_crypto_key_iam_member"
		ch.Change.Actions = actions
		after := map[string]any{}
		if cryptoKeyID != "" {
			after["crypto_key_id"] = cryptoKeyID
		}
		if role != "" {
			after["role"] = role
		}
		if member != "" {
			after["member"] = member
		}
		if len(after) > 0 {
			ch.Change.After = after
		}
		return ch
	}

	const (
		legacyKMSKey = "projects/test-project/locations/us/keyRings/otel-ring/cryptoKeys/legacy-key"
		v1KMSKey     = "projects/test-project/locations/us/keyRings/otel-ring/cryptoKeys/v1-key"
		cmekRole     = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
		cmekMember   = "serviceAccount:bq-123456789012@bigquery-encryption.iam.gserviceaccount.com"
	)

	legacy := []plannedResourceChange{
		mkRole("google_project_iam_custom_role.otel_collector_writer", "otelCollectorWriter", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_provisioner[0]", "otelCollectorProvisioner", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_jobs[0]", "otelCollectorJobs", "create"),
		mkSA("google_service_account.otel_collector", "otel-collector", "create"),
	}

	// Disjoint custom roles and service account pass with zero collisions.
	cleanCutover := []plannedResourceChange{
		mkRole("google_project_iam_custom_role.otel_collector_writer", "otelCollectorWriterV1", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_provisioner[0]", "otelCollectorProvisionerV1", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_jobs[0]", "otelCollectorJobsV1", "create"),
		mkSA("google_service_account.otel_collector", "otel-collector-v1", "create"),
	}
	if err := assertNoLegacyIAMIdentityCollisions(legacy, cleanCutover); err != nil {
		t.Fatalf("assertNoLegacyIAMIdentityCollisions(cleanCutover) = %v, want nil", err)
	}

	// Distinct KMS keys pass with zero collisions, whereas sharing legacyKMSKey
	// fails closed on google_kms_crypto_key_iam_member.bq_encryptor[0].
	legacyCMEK := append(slices.Clone(legacy),
		mkKMSGrant("google_kms_crypto_key_iam_member.bq_encryptor[0]", legacyKMSKey, cmekRole, cmekMember, "create"),
	)
	distinctCMEKCutover := append(slices.Clone(cleanCutover),
		mkKMSGrant("google_kms_crypto_key_iam_member.bq_encryptor[0]", v1KMSKey, cmekRole, cmekMember, "create"),
	)
	if err := assertNoLegacyIAMIdentityCollisions(legacyCMEK, distinctCMEKCutover); err != nil {
		t.Fatalf("assertNoLegacyIAMIdentityCollisions(distinctCMEKCutover) = %v, want nil", err)
	}

	sharedCMEKCutover := append(slices.Clone(cleanCutover),
		mkKMSGrant("google_kms_crypto_key_iam_member.bq_encryptor[0]", legacyKMSKey, cmekRole, cmekMember, "create"),
	)
	if err := assertNoLegacyIAMIdentityCollisions(legacyCMEK, sharedCMEKCutover); err == nil {
		t.Fatal("assertNoLegacyIAMIdentityCollisions(sharedCMEKCutover) = nil, want collision error")
	} else if !strings.Contains(err.Error(), "google_kms_crypto_key_iam_member.bq_encryptor[0]") ||
		!strings.Contains(err.Error(), legacyKMSKey) ||
		!strings.Contains(err.Error(), cmekRole) ||
		!strings.Contains(err.Error(), cmekMember) {
		t.Fatalf("sharedCMEKCutover error = %q, want bq_encryptor[0], %q, %q, and %q",
			err.Error(), legacyKMSKey, cmekRole, cmekMember)
	}

	// Legacy resources scheduled solely for delete do not collide with new creates.
	legacyDeletingCMEK := append(slices.Clone(legacy),
		mkKMSGrant("google_kms_crypto_key_iam_member.bq_encryptor[0]", legacyKMSKey, cmekRole, cmekMember, "delete"),
	)
	if err := assertNoLegacyIAMIdentityCollisions(legacyDeletingCMEK, sharedCMEKCutover); err != nil {
		t.Fatalf("assertNoLegacyIAMIdentityCollisions(legacyDeletingCMEK, sharedCMEKCutover) = %v, want nil", err)
	}

	// Naive dataset_id-only cutover collides on both writer role and service account.
	naiveCutover := []plannedResourceChange{
		mkRole("google_project_iam_custom_role.otel_collector_writer", "otelCollectorWriter", "create"),
		mkSA("google_service_account.otel_collector", "otel-collector", "create"),
	}
	if err := assertNoLegacyIAMIdentityCollisions(legacy, naiveCutover); err == nil {
		t.Fatal("assertNoLegacyIAMIdentityCollisions(naiveCutover) = nil, want collision error")
	} else if !strings.Contains(err.Error(), "otelCollectorWriter") || !strings.Contains(err.Error(), "otel-collector") {
		t.Fatalf("naiveCutover error = %q, want otelCollectorWriter and otel-collector", err.Error())
	}

	// Partial grant_auto_create override still catches provisioner and jobs role collisions.
	partialAuto := []plannedResourceChange{
		mkRole("google_project_iam_custom_role.otel_collector_writer", "otelCollectorWriterV1", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_provisioner[0]", "otelCollectorProvisioner", "create"),
		mkRole("google_project_iam_custom_role.otel_collector_jobs[0]", "otelCollectorJobs", "create"),
		mkSA("google_service_account.otel_collector", "otel-collector-v1", "create"),
	}
	if err := assertNoLegacyIAMIdentityCollisions(legacy, partialAuto); err == nil {
		t.Fatal("assertNoLegacyIAMIdentityCollisions(partialAuto) = nil, want collision error")
	} else if !strings.Contains(err.Error(), "otelCollectorProvisioner") || !strings.Contains(err.Error(), "otelCollectorJobs") {
		t.Fatalf("partialAuto error = %q, want otelCollectorProvisioner and otelCollectorJobs", err.Error())
	}

	// Fail closed on empty plans or missing identity / CMEK grant attributes.
	if err := assertNoLegacyIAMIdentityCollisions(nil, cleanCutover); err == nil {
		t.Error("assertNoLegacyIAMIdentityCollisions(empty legacy) = nil, want error")
	}
	if err := assertNoLegacyIAMIdentityCollisions(legacy, nil); err == nil {
		t.Error("assertNoLegacyIAMIdentityCollisions(empty cutover) = nil, want error")
	}
	missingAttr := []plannedResourceChange{
		mkRole("google_project_iam_custom_role.otel_collector_writer", "", "create"),
		mkSA("google_service_account.otel_collector", "otel-collector-v1", "create"),
	}
	if err := assertNoLegacyIAMIdentityCollisions(legacy, missingAttr); err == nil {
		t.Error("assertNoLegacyIAMIdentityCollisions(missing role_id) = nil, want error")
	}
	for _, tc := range []struct {
		name                             string
		cryptoKeyID, role, member        string
		wantMissingFieldSubstringMessage string
	}{
		{name: "missing_crypto_key_id", cryptoKeyID: "", role: cmekRole, member: cmekMember, wantMissingFieldSubstringMessage: "crypto_key_id"},
		{name: "missing_role", cryptoKeyID: v1KMSKey, role: "", member: cmekMember, wantMissingFieldSubstringMessage: "role"},
		{name: "missing_member", cryptoKeyID: v1KMSKey, role: cmekRole, member: "", wantMissingFieldSubstringMessage: "member"},
	} {
		badCMEK := append(slices.Clone(cleanCutover),
			mkKMSGrant("google_kms_crypto_key_iam_member.bq_encryptor[0]", tc.cryptoKeyID, tc.role, tc.member, "create"),
		)
		if err := assertNoLegacyIAMIdentityCollisions(legacyCMEK, badCMEK); err == nil {
			t.Errorf("%s: assertNoLegacyIAMIdentityCollisions = nil, want error", tc.name)
		} else if !strings.Contains(err.Error(), tc.wantMissingFieldSubstringMessage) {
			t.Errorf("%s: error = %q, want %q", tc.name, err.Error(), tc.wantMissingFieldSubstringMessage)
		}
	}
}

func TestTerraformSideBySideCustomRoleIDVariablesAndDocs(t *testing.T) {
	vars := testsupport.ReadRepoText(t, "deploy/terraform/variables.tf")
	mainTF := testsupport.ReadRepoText(t, "deploy/terraform/main.tf")

	wantRoleVars := []struct {
		name string
		def  string
	}{
		{name: "writer_role_id", def: `"otelCollectorWriter"`},
		{name: "provisioner_role_id", def: `"otelCollectorProvisioner"`},
		{name: "jobs_role_id", def: `"otelCollectorJobs"`},
	}
	for _, v := range wantRoleVars {
		block := testsupport.TerraformBlock(vars, `variable "`+v.name+`"`)
		if block == "" {
			t.Errorf("variables.tf declares no %s", v.name)
			continue
		}
		if got := testsupport.TerraformAttribute(block, "type"); got != "string" {
			t.Errorf("variables.tf gives %s type %q, want string", v.name, got)
		}
		if got := testsupport.TerraformAttribute(block, "default"); got != v.def {
			t.Errorf("variables.tf gives %s default %q, want %s", v.name, got, v.def)
		}
		if !strings.Contains(block, `regex("^[a-zA-Z0-9_.]{3,64}$", var.`+v.name+`)`) {
			t.Errorf("variables.tf gives %s missing GCP custom role ID regex validation:\n%s", v.name, block)
		}
	}

	writerRole := testsupport.TerraformBlock(mainTF, `resource "google_project_iam_custom_role" "otel_collector_writer"`)
	if got := testsupport.TerraformAttribute(writerRole, "role_id"); got != "var.writer_role_id" {
		t.Errorf("main.tf otel_collector_writer role_id = %q, want var.writer_role_id", got)
	}
	if got := testsupport.TerraformAttribute(writerRole, "count"); got != "" {
		t.Errorf("main.tf otel_collector_writer must not use count (would break existing state address), got count = %q:\n%s", got, writerRole)
	}

	collectorSA := testsupport.TerraformBlock(mainTF, `resource "google_service_account" "otel_collector"`)
	if got := testsupport.TerraformAttribute(collectorSA, "account_id"); got != "var.service_account_id" {
		t.Errorf("main.tf otel_collector account_id = %q, want var.service_account_id", got)
	}
	if got := testsupport.TerraformAttribute(collectorSA, "count"); got != "" {
		t.Errorf("main.tf otel_collector must not use count (would break existing state address), got count = %q:\n%s", got, collectorSA)
	}

	provRole := testsupport.TerraformBlock(mainTF, `resource "google_project_iam_custom_role" "otel_collector_provisioner"`)
	if got := testsupport.TerraformAttribute(provRole, "role_id"); got != "var.provisioner_role_id" {
		t.Errorf("main.tf otel_collector_provisioner role_id = %q, want var.provisioner_role_id", got)
	}
	jobsRole := testsupport.TerraformBlock(mainTF, `resource "google_project_iam_custom_role" "otel_collector_jobs"`)
	if got := testsupport.TerraformAttribute(jobsRole, "role_id"); got != "var.jobs_role_id" {
		t.Errorf("main.tf otel_collector_jobs role_id = %q, want var.jobs_role_id", got)
	}

	wantDocFragments := []string{
		"dataset_id",
		"service_account_id",
		"writer_role_id",
		"provisioner_role_id",
		"jobs_role_id",
		"policy_taxonomy_display_name",
		"enable_background_reservation",
		"kms_key_name",
		"google_kms_crypto_key_iam_member.bq_encryptor[0]",
		"terraform state rm 'google_kms_crypto_key_iam_member.bq_encryptor[0]'",
	}
	for _, docPath := range []string{
		"docs/migration.md",
		"deploy/README.md",
		"docs/adr/0001-schema-v1-and-high-volume-logs.md",
	} {
		text := testsupport.ReadRepoText(t, docPath)
		for _, fragment := range wantDocFragments {
			if !strings.Contains(text, fragment) {
				t.Errorf("%s must document side-by-side variable/CMEK handoff %q", docPath, fragment)
			}
		}
	}
}
