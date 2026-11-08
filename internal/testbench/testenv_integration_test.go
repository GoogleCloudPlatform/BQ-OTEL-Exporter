// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package testbench

import "go.uber.org/goleak"

// prepareTestEnvironment leaves the ambient Google auth configuration alone.
// The live tests in this build authenticate with it, for example with the
// credentials file that workload identity federation writes and names in
// GOOGLE_APPLICATION_CREDENTIALS. Clearing it, as the unit build does, would
// leave them without credentials.
func prepareTestEnvironment() {}

func environmentGoleakOptions() []goleak.Option {
	return []goleak.Option{
		// With mTLS or context-aware access configured, the enterprise
		// certificate proxy client reads from its helper process for as long
		// as the process lives.
		goleak.IgnoreAnyFunction("net/rpc.(*Client).input"),
	}
}
