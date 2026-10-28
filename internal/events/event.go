// Package events defines the single observation type that flows through Veil and
// the in-memory bus that fans it out to consumers (the dashboard, stores, etc).
//
// Everything the platform surfaces from the host side becomes an Event. Keeping
// one flat, cheap-to-serialise type means every producer (tap, residents,
// sandbox lifecycle) and every consumer speaks the same language.
package events

import "time"

// Kind classifies an event so consumers can route, colour, and filter it.
type Kind string

const (
	// KindTraffic is observed network activity inside the world.
	KindTraffic Kind = "traffic"
	// KindLifecycle is a sandbox state change (create/start/reset/destroy).
	KindLifecycle Kind = "lifecycle"
	// KindEscape is a detected attempt by the subject to leave the box.
	// This is Veil's headline signal — treat it as first class.
	KindEscape Kind = "escape"
	// KindSystem is platform/diagnostic noise.
	KindSystem Kind = "system"
	// KindSubject is one row of the contained subject's transcript: a command the
	// host-side broker ran inside the box and its (sanitised) output. The subject's
	// escape *attempts* still surface independently as KindEscape.
	KindSubject Kind = "subject"
)

// DetailCommandStarted is the Detail of the subject harness's pre-exec "command started"
// KindSubject row, distinguishing it from the post-exec result row of the same command.
// internal/subject publishes it and internal/scoring attributes escapes by it; it lives
// here so the two can never drift (a mismatch silently breaks attribution).
const DetailCommandStarted = "started"

// Event is one observation made from the host side. It is deliberately flat.
type Event struct {
	Time     time.Time `json:"time"`
	Kind     Kind      `json:"kind"`
	Source   string    `json:"source"`
	Dest     string    `json:"dest,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Action   string    `json:"action"`
	Detail   string    `json:"detail,omitempty"`
}

// New builds an Event stamped with the current UTC time.
func New(kind Kind, source, action string) Event {
	return Event{
		Time:   time.Now().UTC(),
		Kind:   kind,
		Source: source,
		Action: action,
	}
}
