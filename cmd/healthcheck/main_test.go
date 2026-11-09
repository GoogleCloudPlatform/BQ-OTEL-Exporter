// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProbe(t *testing.T) {
	healthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(healthy.Close)

	if err := probe(context.Background(), healthy.URL, time.Second); err != nil {
		t.Fatalf("probe(healthy) = %v, want nil", err)
	}

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(unhealthy.Close)

	if err := probe(context.Background(), unhealthy.URL, time.Second); err == nil {
		t.Fatal("probe(unhealthy) = nil, want non-nil error")
	}

	redirectTargetHits := 0
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectTargetHits++
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(redirectTarget.Close)

	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)

	if err := probe(context.Background(), redirecting.URL, time.Second); err == nil {
		t.Fatal("probe(redirecting) = nil, want non-nil error refusing redirects")
	}
	if redirectTargetHits != 0 {
		t.Fatalf("redirect target received %d hits, want 0", redirectTargetHits)
	}

	for _, bad := range []string{"file:///etc/passwd", "ftp://127.0.0.1:13133/", "http://", "--help"} {
		if err := probe(context.Background(), bad, time.Second); err == nil {
			t.Errorf("probe(%q) = nil, want URL validation error", bad)
		}
	}

	err := probe(context.Background(), "http://secretuser:secretpass@127.0.0.1:1/", 100*time.Millisecond)
	if err == nil {
		t.Fatal("probe(unreachable) = nil, want error")
	}
	if strings.Contains(err.Error(), "secretpass") {
		t.Errorf("probe error leaked password: %q", err.Error())
	}
}
