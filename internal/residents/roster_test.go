package residents

import (
	"strings"
	"testing"
)

func TestDefaultRosterConsistency(t *testing.T) {
	r := DefaultRoster()
	if len(r) == 0 {
		t.Fatal("empty roster")
	}
	servers := map[string]bool{}
	offsets := map[int]bool{}
	maxServerOff, minClientOff := 0, 1<<30
	for _, h := range r {
		if offsets[h.Offset] {
			t.Errorf("duplicate offset %d", h.Offset)
		}
		offsets[h.Offset] = true
		if h.IsServer {
			servers[strings.ToLower(h.Name)] = true
			if h.Offset > maxServerOff {
				maxServerOff = h.Offset
			}
		}
		if h.Client != "" && h.Offset < minClientOff {
			minClientOff = h.Offset
		}
	}
	// every client target must be a server FQDN in the roster
	for _, h := range r {
		for _, tgt := range strings.Split(h.Client, ",") {
			if tgt = strings.TrimSpace(tgt); tgt != "" && !servers[strings.ToLower(tgt)] {
				t.Errorf("host %s targets unknown server %q", h.Name, tgt)
			}
		}
	}
	// servers sit below clients in the address space
	if maxServerOff >= minClientOff {
		t.Errorf("server offsets (max %d) must be below client offsets (min %d)", maxServerOff, minClientOff)
	}
}
