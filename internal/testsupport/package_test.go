// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/internal/testsupport"

import (
	"os"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	// Unit tests construct a BigQuery client against a no-auth httptest server.
	// When the host sets GOOGLE_API_USE_CLIENT_CERTIFICATE=true or ambient mTLS
	// config, the client library starts an enterprise-certificate-proxy helper
	// whose RPC reader goroutine outlives the test. Unit tests never talk to
	// Google, so clear those settings for the binary.
	_ = os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false")
	_ = os.Unsetenv("GOOGLE_API_CERTIFICATE_CONFIG")
	_ = os.Unsetenv("GOOGLE_APPLICATION_CREDENTIALS")
	goleak.VerifyTestMain(m,
		// cloud.google.com/go/bigquery pulls in opencensus, whose stats view
		// worker starts at package init and runs for the life of the process.
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
	)
}
