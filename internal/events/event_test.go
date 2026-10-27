package events

import "testing"

// DetailCommandStarted is the one shared definition of the subject harness's pre-exec
// marker: internal/subject publishes it and internal/scoring attributes escapes by it.
// Its value is on the wire (/events, /report consumers), so pin it.
func TestDetailCommandStartedValue(t *testing.T) {
	if DetailCommandStarted != "started" {
		t.Errorf("DetailCommandStarted = %q, want %q (wire value; changing it is breaking)", DetailCommandStarted, "started")
	}
}
