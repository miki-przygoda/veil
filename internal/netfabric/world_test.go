package netfabric

import (
	"net"
	"testing"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatalf("bad CIDR %q: %v", s, err)
	}
	return n
}

func testWorld(t *testing.T) World {
	return World{
		Subnet:  mustCIDR(t, "172.20.0.0/16"),
		Gateway: net.ParseIP("172.20.0.1"),
		Zones:   []string{".veil.local"},
		Names:   map[string]net.IP{"web.veil.local": net.ParseIP("172.20.0.10")},
	}
}

func TestOffWorldIP(t *testing.T) {
	w := testWorld(t)
	cases := []struct {
		name string
		ip   string
		want bool
	}{
		{"in-subnet host", "172.20.0.10", false},
		{"gateway infra", "172.20.0.1", false},
		{"public", "8.8.8.8", true},
		{"cross-private", "10.9.9.9", true},
		{"loopback", "127.0.0.1", false},
		{"link-local dhcp/mdns", "169.254.1.2", false},
		{"multicast mdns", "224.0.0.251", false},
		{"unspecified", "0.0.0.0", false},
		{"cloud metadata IS escape", "169.254.169.254", true}, // [M5]
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := w.offWorldIP(net.ParseIP(c.ip)); got != c.want {
				t.Errorf("offWorldIP(%s) = %v, want %v", c.ip, got, c.want)
			}
		})
	}
	if w.offWorldIP(nil) {
		t.Error("offWorldIP(nil) = true, want false")
	}
}

func TestOffWorldName(t *testing.T) {
	w := testWorld(t)
	cases := []struct {
		qname string
		want  bool
	}{
		{"web.veil.local", false},  // served name
		{"api.veil.local", false},  // zone member
		{"api.veil.local.", false}, // trailing dot
		{"WEB.VEIL.LOCAL", false},  // case-insensitive
		{"veil.local", false},      // zone apex itself
		{"pastebin.com", true},     // external
		{"8.8.8.8", true},          // IP literal counts as off-world
		{"", false},                // nothing to resolve
	}
	for _, c := range cases {
		t.Run(c.qname, func(t *testing.T) {
			if got := w.offWorldName(c.qname); got != c.want {
				t.Errorf("offWorldName(%q) = %v, want %v", c.qname, got, c.want)
			}
		})
	}
}
