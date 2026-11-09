// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package quarantinereplay

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	bigqueryapi "google.golang.org/api/bigquery/v2"
	"google.golang.org/api/option"
)

type nopLocationSink struct{}

func (nopLocationSink) ExportTraces(context.Context, ptrace.Traces) error    { return nil }
func (nopLocationSink) ExportLogs(context.Context, plog.Logs) error          { return nil }
func (nopLocationSink) ExportMetrics(context.Context, pmetric.Metrics) error { return nil }

type locationFakeBigQuery struct {
	mu                       sync.Mutex
	datasetLocation          string
	datasetStatus            int
	asyncJobCompleteFalse    bool
	omitJobRefLocation       bool
	datasetGetCalls          int
	queryLocations           []string
	getQueryResultsLocations []string
}

func (f *locationFakeBigQuery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/datasets/ds":
		f.datasetGetCalls++
		if f.datasetStatus != 0 {
			http.Error(w, "denied", f.datasetStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&bigqueryapi.Dataset{
			DatasetReference: &bigqueryapi.DatasetReference{ProjectId: "proj", DatasetId: "ds"},
			Location:         f.datasetLocation,
		})
	case r.Method == http.MethodPost && r.URL.Path == "/bigquery/v2/projects/proj/queries":
		var req bigqueryapi.QueryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.queryLocations = append(f.queryLocations, req.Location)
		jobRef := &bigqueryapi.JobReference{ProjectId: "proj", JobId: "job-loc"}
		if !f.omitJobRefLocation {
			jobRef.Location = req.Location
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&bigqueryapi.QueryResponse{
			JobReference: jobRef,
			JobComplete:  !f.asyncJobCompleteFalse,
			Schema:       &bigqueryapi.TableSchema{},
		})
	case r.Method == http.MethodGet && r.URL.Path == "/bigquery/v2/projects/proj/queries/job-loc":
		f.getQueryResultsLocations = append(f.getQueryResultsLocations, r.URL.Query().Get("location"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&bigqueryapi.GetQueryResultsResponse{
			JobReference: &bigqueryapi.JobReference{ProjectId: "proj", JobId: "job-loc"},
			JobComplete:  true,
			Schema:       &bigqueryapi.TableSchema{},
		})
	default:
		http.Error(w, "unexpected request "+r.Method+" "+r.URL.Path, http.StatusNotFound)
	}
}

func TestReplayBigQueryLocationPropagation(t *testing.T) {
	t.Run("auto-detects dataset location via Datasets.Get", func(t *testing.T) {
		fake := &locationFakeBigQuery{datasetLocation: "EU", asyncJobCompleteFalse: true}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		src := BigQuerySource{Project: "proj", Dataset: "ds"}
		if _, err := ReplayBigQuery(context.Background(), src, nopLocationSink{}, Options{},
			option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication()); err != nil {
			t.Fatalf("ReplayBigQuery() error = %v", err)
		}
		if fake.datasetGetCalls != 1 {
			t.Fatalf("Datasets.Get calls = %d, want 1", fake.datasetGetCalls)
		}
		if len(fake.queryLocations) != 1 || fake.queryLocations[0] != "EU" {
			t.Fatalf("QueryRequest locations = %v, want [EU]", fake.queryLocations)
		}
		if len(fake.getQueryResultsLocations) != 1 || fake.getQueryResultsLocations[0] != "EU" {
			t.Fatalf("GetQueryResults locations = %v, want [EU]", fake.getQueryResultsLocations)
		}
	})

	t.Run("explicit Location skips Datasets.Get and sets QueryRequest.Location", func(t *testing.T) {
		fake := &locationFakeBigQuery{
			datasetLocation:       "US",
			asyncJobCompleteFalse: true,
			omitJobRefLocation:    true,
		}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		src := BigQuerySource{Project: "proj", Dataset: "ds", Location: "  europe-west1 "}
		if _, err := ReplayBigQuery(context.Background(), src, nopLocationSink{}, Options{},
			option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication()); err != nil {
			t.Fatalf("ReplayBigQuery() error = %v", err)
		}
		if fake.datasetGetCalls != 0 {
			t.Fatalf("Datasets.Get calls = %d, want 0 when explicit Location is set", fake.datasetGetCalls)
		}
		if len(fake.queryLocations) != 1 || fake.queryLocations[0] != "europe-west1" {
			t.Fatalf("QueryRequest locations = %v, want [europe-west1]", fake.queryLocations)
		}
		if len(fake.getQueryResultsLocations) != 1 || fake.getQueryResultsLocations[0] != "europe-west1" {
			t.Fatalf("GetQueryResults fallback locations = %v, want [europe-west1]", fake.getQueryResultsLocations)
		}
	})

	t.Run("falls back gracefully when Datasets.Get returns 403", func(t *testing.T) {
		fake := &locationFakeBigQuery{datasetStatus: http.StatusForbidden}
		srv := httptest.NewServer(fake)
		defer srv.Close()

		src := BigQuerySource{Project: "proj", Dataset: "ds"}
		if _, err := ReplayBigQuery(context.Background(), src, nopLocationSink{}, Options{},
			option.WithEndpoint(srv.URL+"/bigquery/v2/"), option.WithoutAuthentication()); err != nil {
			t.Fatalf("ReplayBigQuery() error = %v", err)
		}
		if fake.datasetGetCalls != 1 {
			t.Fatalf("Datasets.Get calls = %d, want 1", fake.datasetGetCalls)
		}
		if len(fake.queryLocations) != 1 || fake.queryLocations[0] != "" {
			t.Fatalf("QueryRequest locations = %v, want [\"\"]", fake.queryLocations)
		}
	})
}
