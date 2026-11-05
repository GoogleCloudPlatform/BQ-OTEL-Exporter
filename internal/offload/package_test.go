// Copyright 2026 Google LLC
// SPDX-License-Identifier: Apache-2.0

package offload

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),
		// On workstations with ambient enterprise mTLS certificates, the
		// Google HTTP client initializes a net/rpc connection whose input
		// goroutine runs for the process lifetime.
		goleak.IgnoreAnyFunction("net/rpc.(*Client).input"),
	)
}
