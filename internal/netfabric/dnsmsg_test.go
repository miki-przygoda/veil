package netfabric

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// encodeQuery builds a standard A/IN-style query with the given QTYPE. Reused by
// resolver_test.
func encodeQuery(id uint16, name string, qtype uint16) []byte {
	var b []byte
	b = binary.BigEndian.AppendUint16(b, id)
	b = binary.BigEndian.AppendUint16(b, 0x0100) // RD, standard query
	b = binary.BigEndian.AppendUint16(b, 1)      // QDCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ANCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // NSCOUNT
	b = binary.BigEndian.AppendUint16(b, 0)      // ARCOUNT
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0) // root
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, dnsClassIN)
	return b
}

func TestParseQuery(t *testing.T) {
	q, err := parseQuery(encodeQuery(0x1234, "web.veil.local", dnsTypeA))
	if err != nil {
		t.Fatalf("parseQuery: %v", err)
	}
	if q.id != 0x1234 || q.name != "web.veil.local" || q.qtype != dnsTypeA || q.qclass != dnsClassIN {
		t.Errorf("parsed %+v", q)
	}
}

func TestParseQueryMalformed(t *testing.T) {
	good := encodeQuery(1, "x.local", dnsTypeA)
	for _, bad := range [][]byte{
		{},                          // empty
		{0, 0, 0, 0, 0, 1},          // truncated header
		append(append([]byte{}, good[:13]...), 0x40), // truncated: label body then no room for the next length byte
		{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c}, // compression pointer in question
	} {
		if _, err := parseQuery(bad); err == nil {
			t.Errorf("parseQuery(% x) = nil err, want error (no panic)", bad)
		}
	}
}

func TestReplyA(t *testing.T) {
	q, _ := parseQuery(encodeQuery(0x1234, "web.veil.local", dnsTypeA))
	reply := replyA(q, net.ParseIP("172.20.0.10"), true)
	if binary.BigEndian.Uint16(reply[0:2]) != 0x1234 {
		t.Error("id not echoed")
	}
	if reply[2]&0x80 == 0 {
		t.Error("QR not set")
	}
	if reply[2]&0x04 == 0 {
		t.Error("AA not set when requested")
	}
	if binary.BigEndian.Uint16(reply[6:8]) != 1 {
		t.Errorf("ANCOUNT = %d, want 1", binary.BigEndian.Uint16(reply[6:8]))
	}
	nameOff := 12 + len(q.qsection)
	if reply[nameOff] != 0xc0 || reply[nameOff+1] != 0x0c {
		t.Errorf("answer NAME = %02x %02x, want c0 0c", reply[nameOff], reply[nameOff+1])
	}
	if got := net.IP(reply[len(reply)-4:]); !got.Equal(net.ParseIP("172.20.0.10")) {
		t.Errorf("answer RDATA = %v, want 172.20.0.10", got)
	}
}

func TestReplyANonIPv4Degrades(t *testing.T) {
	q, _ := parseQuery(encodeQuery(1, "web.veil.local", dnsTypeA))
	reply := replyA(q, net.ParseIP("::1"), true)
	if reply[3]&0x0f != rcodeNXDomain {
		t.Errorf("non-IPv4 ip: rcode = %d, want NXDOMAIN(%d)", reply[3]&0x0f, rcodeNXDomain)
	}
	if reply[2]&0x04 != 0 {
		t.Error("degraded NXDOMAIN must not be authoritative")
	}
}

func TestReplyRcodeNeverAuthoritativeWhenFalse(t *testing.T) {
	q, _ := parseQuery(encodeQuery(1, "pastebin.com", 15 /* MX: unsupported */))
	reply := replyRcode(q, rcodeRefused, false)
	if reply[3]&0x0f != rcodeRefused {
		t.Errorf("RCODE = %d, want %d", reply[3]&0x0f, rcodeRefused)
	}
	if reply[2]&0x04 != 0 {
		t.Error("AA must not be set when aa=false ([H3])")
	}
	if binary.BigEndian.Uint16(reply[6:8]) != 0 {
		t.Error("ANCOUNT must be 0 on an rcode reply")
	}
}
