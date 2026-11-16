// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package repocheck // import "github.com/GoogleCloudPlatform/BQ-OTEL-Exporter/tools/repocheck"

import (
	"fmt"
	"os"

	"go.uber.org/goleak"
)

// prepareTestEnvironment keeps hermetic repository checks independent of
// ambient Cloudtop or GCE credential and certificate settings.
func prepareTestEnvironment() {
	if err := os.Setenv("GOOGLE_API_USE_CLIENT_CERTIFICATE", "false"); err != nil {
		panic(fmt.Sprintf("setting GOOGLE_API_USE_CLIENT_CERTIFICATE: %v", err))
	}
	for _, k := range []string{"GOOGLE_API_CERTIFICATE_CONFIG", "GOOGLE_APPLICATION_CREDENTIALS"} {
		if err := os.Unsetenv(k); err != nil {
			panic(fmt.Sprintf("unsetting %s: %v", k, err))
		}
	}
}

func environmentGoleakOptions() []goleak.Option {
	return nil
}
