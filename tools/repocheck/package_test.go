// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Unit builds clear ambient Google auth and certificate settings for
	// hermeticity; integration builds preserve them for live BigQuery tests.
	// See testenv_unit_test.go and testenv_integration_test.go.
	prepareTestEnvironment()
	options := []goleak.Option{
		// cloud.google.com/go/bigquery pulls in opencensus, whose stats view
		// worker starts at package init and runs for the life of the process.
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
		// managedwriter cancels a connection's previous context after a fixed
		// 20 s grace period, including on its first open. This timer goroutine
		// exits on its own and holds no HTTP connection pool.
		goleak.IgnoreAnyFunction("cloud.google.com/go/bigquery/storage/managedwriter.(*connection).getStream.func1"),
	}
	goleak.VerifyTestMain(m, append(options, environmentGoleakOptions()...)...)
}
