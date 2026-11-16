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
	}
	goleak.VerifyTestMain(m, append(options, environmentGoleakOptions()...)...)
}
