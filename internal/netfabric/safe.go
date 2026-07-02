package netfabric

import (
	"fmt"
	"strings"
)

// safeField reduces an attacker-controlled string to a bus-safe form: capped
// length, then only [A-Za-z0-9.:/_-]; anything else is hex-escaped. It runs at
// the boundary before the value reaches an events.Event ([C1] defense in depth;
// the dashboard also output-encodes). "Printable ASCII" is NOT enough — '<' is
// printable — so this is an allowlist, not a control-char filter.
func safeField(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case strings.IndexByte(".:/_-", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "\\x%02x", c)
		}
	}
	return b.String()
}
