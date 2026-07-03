//go:build !linux

package netfabric

import (
	"errors"
	"log/slog"

	"github.com/miki-przygoda/veil/internal/events"
)

// ErrHoneypotUnsupported is returned where the transparent honeypot can't run
// (no Linux netfilter). Escape DETECTION still works; only follow-through
// capture is unavailable.
var ErrHoneypotUnsupported = errors.New("transparent honeypot unsupported on this platform")

func InstallHoneypot(bridge, subnet, gateway string, bus *events.Bus, log *slog.Logger) (func(), error) {
	return nil, ErrHoneypotUnsupported
}
