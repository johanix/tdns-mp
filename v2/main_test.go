/*
 * Copyright (c) 2026 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package tdnsmp

import (
	"os"
	"testing"

	tdns "github.com/johanix/tdns/v2"
)

// The package's tests stage a change and read the served zone back as if
// every publish were synchronous (CombineWithLocalChanges, the key
// lifecycle driver, ...). Under tdns's publish gate a change to a busy zone
// waits a cadence (DefaultPublishCadence, 5 s). With a zero default cadence
// no zone is ever busy, so the gate publishes in the caller and the tests
// keep their reading. The daemons run with the real default.
func TestMain(m *testing.M) {
	tdns.DefaultPublishCadence = 0
	os.Exit(m.Run())
}
