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
		{},                 // empty
		{0, 0, 0, 0, 0, 1}, // truncated header
		append(append([]byte{}, good[:13]...), 0x40),     // truncated: label body then no room for the next length byte
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

// withFlags rewrites a query's header flags word (QR/opcode/RD/...).
func withFlags(q []byte, flags uint16) []byte {
	out := append([]byte(nil), q...)
	binary.BigEndian.PutUint16(out[2:4], flags)
	return out
}

func TestHeaderFlags(t *testing.T) {
	// A recursive-resolver persona: RD echoed from the query, RA always set, the
	// opcode echoed, AA only when the caller claims authority ([H3]).
	cases := []struct {
		name   string
		qflags uint16
		aa     bool
		rcode  uint8
		want   uint16
	}{
		{"RD query, non-auth NOERROR", 0x0100, false, rcodeNoError, 0x8180},
		{"RD query, authoritative", 0x0100, true, rcodeNoError, 0x8580},
		{"no RD, REFUSED", 0x0000, false, rcodeRefused, 0x8085},
		{"RD query, NXDOMAIN", 0x0100, false, rcodeNXDomain, 0x8183},
		{"STATUS opcode echoed, NOTIMP", 0x1100, false, rcodeNotImp, 0x9184},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q, err := parseQuery(withFlags(encodeQuery(7, "web.veil.local", dnsTypeA), c.qflags))
			if err != nil {
				t.Fatalf("parseQuery: %v", err)
			}
			h := header(q, c.aa, c.rcode, 0)
			if got := binary.BigEndian.Uint16(h[2:4]); got != c.want {
				t.Errorf("flags = %#04x, want %#04x", got, c.want)
			}
		})
	}
}

func TestParseQueryFlags(t *testing.T) {
	cases := []struct {
		name   string
		flags  uint16
		qr     bool
		opcode uint8
		rd     bool
	}{
		{"standard RD query", 0x0100, false, 0, true},
		{"no RD", 0x0000, false, 0, false},
		{"response bit set", 0x8100, true, 0, true},
		{"NOTIFY opcode (4)", 0x2000, false, 4, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			q, err := parseQuery(withFlags(encodeQuery(1, "x.local", dnsTypeA), c.flags))
			if err != nil {
				t.Fatalf("parseQuery: %v", err)
			}
			if q.qr != c.qr || q.opcode != c.opcode || q.rd != c.rd {
				t.Errorf("qr=%v opcode=%d rd=%v, want qr=%v opcode=%d rd=%v", q.qr, q.opcode, q.rd, c.qr, c.opcode, c.rd)
			}
		})
	}
}
