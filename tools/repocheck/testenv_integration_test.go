// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import "go.uber.org/goleak"

// prepareTestEnvironment preserves ambient Google auth and mTLS configuration
// for live integration runs (such as GOOGLE_APPLICATION_CREDENTIALS set by
// Workload Identity Federation in CI).
func prepareTestEnvironment() {}

func environmentGoleakOptions() []goleak.Option {
	return []goleak.Option{
		// With mTLS or context-aware access configured, the enterprise
		// certificate proxy client reads from its helper process for as long
		// as the process lives.
		goleak.IgnoreAnyFunction("net/rpc.(*Client).input"),
	}
}
