// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

// Command healthcheck is a minimal, shell-free HTTP readiness/liveness probe
// bundled into distroless container images for Docker healthchecks.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	defaultTargetURL = "http://127.0.0.1:13133/"
	probeTimeout     = 3 * time.Second
)

func main() {
	if len(os.Args) > 2 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: healthcheck [url]")
		os.Exit(2)
	}
	target := defaultTargetURL
	if len(os.Args) == 2 && os.Args[1] != "" {
		target = os.Args[1]
	}
	if err := probe(context.Background(), target, probeTimeout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func validateTargetURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parsing healthcheck URL: %w", err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("invalid healthcheck URL scheme %q: must be http or https", u.Scheme)
	}
	if u.Host == "" {
		return nil, errors.New("invalid healthcheck URL: missing host")
	}
	return u, nil
}

func probe(parent context.Context, target string, timeout time.Duration) error {
	u, err := validateTargetURL(target)
	if err != nil {
		return err
	}
	redactedTarget := u.Redacted()

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("building healthcheck request: %w", err)
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probing %s: %w", redactedTarget, err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("unhealthy status %d from %s", resp.StatusCode, redactedTarget)
	}
	return nil
}
