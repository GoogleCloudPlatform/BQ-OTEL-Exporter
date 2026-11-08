// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testbench

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Unit builds clear the ambient Google auth settings; integration builds
	// keep them for the live tests. See testenv_unit_test.go and
	// testenv_integration_test.go.
	prepareTestEnvironment()
	options := []goleak.Option{
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
		goleak.IgnoreAnyFunction("cloud.google.com/go/bigquery/storage/managedwriter.(*connection).getStream.func1"),
	}
	goleak.VerifyTestMain(m, append(options, environmentGoleakOptions()...)...)
}
