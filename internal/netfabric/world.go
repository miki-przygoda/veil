package netfabric

import (
	"net"
	"strings"
)

// World describes the synthetic world's addressable extent. It is shared by the
// Resolver (which names it answers) and the Classifier (what counts as escape),
// so both agree on where the world ends.
type World struct {
	Subnet  *net.IPNet        // veil-net CIDR (nil on the stub/no-Docker path)
	Gateway net.IP            // gateway == sink IP; in-world infra
	Zones   []string          // served DNS suffixes, e.g. ".veil.local"
	Names   map[string]net.IP // static A records; keys MUST be lowercase FQDNs (lookups lowercase the query, not the key)
}

// metadataIPs are cloud metadata endpoints — the canonical SSRF/escape target,
// so NOT housekeeping even though 169.254.169.254 is link-local ([M5]).
var metadataIPs = []net.IP{net.ParseIP("169.254.169.254"), net.ParseIP("fd00:ec2::254")}

// offWorldIP reports whether dst is outside the world: not in Subnet, not the
// Gateway, and not housekeeping (loopback / link-local / multicast /
// unspecified / limited broadcast; the subnet-directed broadcast is already
// inside Subnet) — EXCEPT the cloud-metadata addresses, which ARE escape. A nil
// Subnet cannot judge in-world membership, so callers gate the IP vector on
// Subnet != nil (see Classifier.classify).
func (w World) offWorldIP(dst net.IP) bool {
	if dst == nil {
		return false
	}
	for _, m := range metadataIPs {
		if dst.Equal(m) {
			return true
		}
	}
	if dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() ||
		dst.IsMulticast() || dst.IsUnspecified() || dst.Equal(net.IPv4bcast) {
		return false
	}
	if w.Gateway != nil && w.Gateway.Equal(dst) {
		return false
	}
	if w.Subnet != nil && w.Subnet.Contains(dst) {
		return false
	}
	return true
}

// offWorldName reports whether qname falls outside every world Zone and is not a
// served Name. Case-insensitive; tolerates a trailing dot. Empty => in-world
// (nothing to resolve). A Zone like ".veil.local" matches the apex and any
// subdomain. A well-formed reverse name (in-addr.arpa / ip6.arpa) is judged by
// its decoded IP via offWorldIP, so a PTR for an in-world host (ping,
// traceroute, ss without -n) is not an escape; a malformed one stays off-world.
// With a nil Subnet that inherits offWorldIP's view: only gateway/housekeeping
// PTRs are in-world, any other IP's PTR counts as off-world (flag, not miss).
func (w World) offWorldName(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if name == "" {
		return false
	}
	if ip, ok := parseReverseName(name); ok {
		return w.offWorldIP(ip)
	}
	if _, ok := w.Names[name]; ok {
		return false
	}
	for _, z := range w.Zones {
		suffix := strings.ToLower(strings.TrimPrefix(z, "."))
		if name == suffix || strings.HasSuffix(name, "."+suffix) {
			return false
		}
	}
	return true
}

// parseReverseName decodes a full PTR name (lowercase, no trailing dot) to its
// IP: four canonical decimal octets under in-addr.arpa, or 32 hex nibbles under
// ip6.arpa. Anything else (partial zones, bad labels) => ok=false.
func parseReverseName(name string) (net.IP, bool) {
	if rest, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		labels := strings.Split(rest, ".")
		if len(labels) != 4 {
			return nil, false
		}
		ip := make(net.IP, 0, 4)
		for i := 3; i >= 0; i-- {
			l := labels[i]
			if l == "" || len(l) > 3 || (len(l) > 1 && l[0] == '0') {
				return nil, false
			}
			n := 0
			for _, ch := range l {
				if ch < '0' || ch > '9' {
					return nil, false
				}
				n = n*10 + int(ch-'0')
			}
			if n > 255 {
				return nil, false
			}
			ip = append(ip, byte(n))
		}
		return net.IPv4(ip[0], ip[1], ip[2], ip[3]), true
	}
	if rest, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		labels := strings.Split(rest, ".")
		if len(labels) != 32 {
			return nil, false
		}
		ip := make(net.IP, 16)
		for i, l := range labels { // labels[0] is the lowest-order nibble
			if len(l) != 1 {
				return nil, false
			}
			v := strings.IndexByte("0123456789abcdef", l[0])
			if v < 0 {
				return nil, false
			}
			pos := 31 - i
			if pos%2 == 0 {
				ip[pos/2] |= byte(v) << 4
			} else {
				ip[pos/2] |= byte(v)
			}
		}
		return ip, true
	}
	return nil, false
}

// offWorldQuery is the Classifier's view of a resolver dns/query qname. An
// IP-literal qname (`dig 172.20.0.10`) is judged by the literal via offWorldIP,
// as a PTR is: an in-world/gateway/housekeeping literal is not an escape, an
// off-world one (8.8.8.8, 169.254.169.254) is. It is still only a lookup, so the
// Classifier labels it external-dns, never egress. Anything else defers to
// offWorldName. Classifier-only on purpose: the Resolver keeps calling
// offWorldName, so its wire answers (AA bit) for a literal stay identical for A
// and AAAA and never reveal which literals count as in-world. With a nil Subnet
// a literal inherits offWorldIP's view, as a PTR does.
func (w World) offWorldQuery(qname string) bool {
	if ip := net.ParseIP(strings.TrimSuffix(qname, ".")); ip != nil {
		return w.offWorldIP(ip)
	}
	return w.offWorldName(qname)
}
