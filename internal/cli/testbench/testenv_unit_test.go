// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package testbench

import (
	"fmt"
	"os"

	"go.uber.org/goleak"
)

// prepareTestEnvironment keeps unit tests deterministic regardless of ambient
// Cloudtop or GCE credential and certificate variables. Unit tests never talk
// to Google.
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

// environmentGoleakOptions adds nothing: with the certificate settings
// cleared, no client starts a certificate helper.
func environmentGoleakOptions() []goleak.Option {
	return nil
}
