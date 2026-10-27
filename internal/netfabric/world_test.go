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
		{"limited broadcast", "255.255.255.255", false},
		{"subnet-directed broadcast", "172.20.255.255", false},
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
		{"8.8.8.8", true},          // IP literal: not a world name (see offWorldQuery)
		{"172.20.0.10", true},      // in-world literal is still not a world name on the wire
		{"", false},                // nothing to resolve
		// Reverse (PTR) names judge the decoded IP, not the arpa suffix.
		{"10.0.20.172.in-addr.arpa", false},    // in-subnet host
		{"1.0.20.172.IN-ADDR.ARPA.", false},    // gateway, case + trailing dot
		{"1.0.0.127.in-addr.arpa", false},      // loopback housekeeping
		{"8.8.8.8.in-addr.arpa", true},         // off-world IP
		{"254.169.254.169.in-addr.arpa", true}, // cloud metadata [M5]
		{"20.172.in-addr.arpa", true},          // partial: malformed -> off-world
		{"300.0.20.172.in-addr.arpa", true},    // bad octet
		{"x.0.20.172.in-addr.arpa", true},      // non-numeric
		{"010.0.20.172.in-addr.arpa", true},    // leading zero is not canonical
		{"in-addr.arpa", true},                 // bare suffix
		{"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa", false}, // ::1 loopback
		{"8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.ip6.arpa", true},  // 2000::8888 public
		{"8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.ip6.arpa", true},    // 31 nibbles: malformed
		{"g.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.ip6.arpa", true},  // bad nibble
	}
	for _, c := range cases {
		t.Run(c.qname, func(t *testing.T) {
			if got := w.offWorldName(c.qname); got != c.want {
				t.Errorf("offWorldName(%q) = %v, want %v", c.qname, got, c.want)
			}
		})
	}
}

func TestOffWorldNamePTRNilSubnet(t *testing.T) {
	// No Subnet (stub path): a PTR is judged exactly like offWorldIP judges the
	// decoded IP — housekeeping/gateway stay in-world, anything else is off-world.
	w := World{Gateway: net.ParseIP("172.20.0.1")}
	cases := map[string]bool{
		"1.0.0.127.in-addr.arpa":   false,
		"1.0.20.172.in-addr.arpa":  false,
		"10.0.20.172.in-addr.arpa": true,
	}
	for q, want := range cases {
		if got := w.offWorldName(q); got != want {
			t.Errorf("nil-Subnet offWorldName(%q) = %v, want %v", q, got, want)
		}
	}
}

func TestOffWorldQuery(t *testing.T) {
	// The Classifier's view of a dns/query qname: an IP literal is judged like
	// offWorldIP judges it (as a PTR is); anything else defers to offWorldName.
	w := testWorld(t)
	cases := []struct {
		qname string
		want  bool
	}{
		{"172.20.0.10", false},    // in-subnet host
		{"172.20.0.1.", false},    // gateway, trailing dot
		{"127.0.0.1", false},      // loopback housekeeping
		{"8.8.8.8", true},         // off-world literal
		{"169.254.169.254", true}, // cloud metadata [M5]
		{"10.9.9.9", true},        // cross-private
		{"::1", false},            // v6 loopback
		{"2001:4860::8888", true}, // v6 public
		{"172.020.0.10", true},    // non-canonical: not a literal, not a world name
		{"web.veil.local", false}, // world name still in-world
		{"pastebin.com", true},    // external name still off-world
		{"10.0.20.172.in-addr.arpa", false},
		{"8.8.8.8.in-addr.arpa", true},
		{"", false},
	}
	for _, c := range cases {
		t.Run(c.qname, func(t *testing.T) {
			if got := w.offWorldQuery(c.qname); got != c.want {
				t.Errorf("offWorldQuery(%q) = %v, want %v", c.qname, got, c.want)
			}
		})
	}
	// No Subnet: literals take offWorldIP's nil-Subnet view, like PTRs.
	nw := World{Gateway: net.ParseIP("172.20.0.1")}
	for q, want := range map[string]bool{"127.0.0.1": false, "172.20.0.1": false, "172.20.0.10": true} {
		if got := nw.offWorldQuery(q); got != want {
			t.Errorf("nil-Subnet offWorldQuery(%q) = %v, want %v", q, got, want)
		}
	}
}
