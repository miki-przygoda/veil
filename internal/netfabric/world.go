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
	Names   map[string]net.IP // static A records for world names (FQDN -> IPv4)
}

// metadataIPs are cloud metadata endpoints — the canonical SSRF/escape target,
// so NOT housekeeping even though 169.254.169.254 is link-local ([M5]).
var metadataIPs = []net.IP{net.ParseIP("169.254.169.254"), net.ParseIP("fd00:ec2::254")}

// offWorldIP reports whether dst is outside the world: not in Subnet, not the
// Gateway, and not housekeeping (loopback / link-local / multicast /
// unspecified) — EXCEPT the cloud-metadata addresses, which ARE escape. A nil
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
		dst.IsMulticast() || dst.IsUnspecified() {
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
// subdomain.
func (w World) offWorldName(qname string) bool {
	name := strings.ToLower(strings.TrimSuffix(qname, "."))
	if name == "" {
		return false
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
