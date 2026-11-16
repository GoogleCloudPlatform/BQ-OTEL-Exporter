// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"os"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Repository checks never talk to Google APIs, so clear ambient mTLS and
	// certificate-proxy settings that would otherwise start a long-lived
	// enterprise-certificate-proxy helper when BigQuery packages initialize.
	_ = os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	_ = os.Unsetenv("GOOGLE_API_CERTIFICATE_CONFIG")
	_ = os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
	goleak.VerifyTestMain(m,
		// cloud.google.com/go/bigquery pulls in opencensus, whose stats view
		// worker starts at package init and runs for the life of the process.
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)
}
