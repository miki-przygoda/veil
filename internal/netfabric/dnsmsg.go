package netfabric

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
	dnsClassIN  uint16 = 1

	rcodeNoError  uint8 = 0
	rcodeNXDomain uint8 = 3
	rcodeNotImp   uint8 = 4
	rcodeRefused  uint8 = 5

	maxName = 254
)

var errMalformedQuery = errors.New("malformed dns query")

// dnsQuery is the decoded header id + flags + first question. qsection is the
// raw question bytes (labels..0x00 + QTYPE + QCLASS) so replies echo it verbatim;
// a 0xC00C pointer in the answer then points back to it at offset 12. qr, opcode
// and rd are decoded, not judged: respond decides what to do with them.
type dnsQuery struct {
	id       uint16
	name     string // dotted, lower-case, no trailing dot
	qtype    uint16
	qclass   uint16
	qsection []byte
	qr       bool  // the packet claims to be a response
	opcode   uint8 // 0 = standard QUERY
	rd       bool  // recursion desired; echoed in the reply
}

// parseQuery decodes the header + first question. Bounds-checked and panic-free:
// it returns errMalformedQuery on anything it can't safely read, so a hostile
// packet never crashes the serve loop.
func parseQuery(msg []byte) (dnsQuery, error) {
	if len(msg) < 12 {
		return dnsQuery{}, errMalformedQuery
	}
	if binary.BigEndian.Uint16(msg[4:6]) < 1 { // QDCOUNT >= 1
		return dnsQuery{}, errMalformedQuery
	}
	off := 12
	total := 0
	var labels []string
	for {
		if off >= len(msg) {
			return dnsQuery{}, errMalformedQuery
		}
		n := int(msg[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 { // compression pointer not allowed in a question
			return dnsQuery{}, errMalformedQuery
		}
		if off+n > len(msg) {
			return dnsQuery{}, errMalformedQuery
		}
		total += n + 1
		if total > maxName {
			return dnsQuery{}, errMalformedQuery
		}
		labels = append(labels, string(msg[off:off+n]))
		off += n
	}
	if off+4 > len(msg) { // QTYPE + QCLASS
		return dnsQuery{}, errMalformedQuery
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	return dnsQuery{
		id:       binary.BigEndian.Uint16(msg[0:2]),
		qr:       flags&0x8000 != 0,
		opcode:   uint8(flags>>11) & 0x0f,
		rd:       flags&0x0100 != 0,
		name:     strings.ToLower(strings.Join(labels, ".")),
		qtype:    binary.BigEndian.Uint16(msg[off : off+2]),
		qclass:   binary.BigEndian.Uint16(msg[off+2 : off+4]),
		qsection: append([]byte(nil), msg[12:off+4]...),
	}, nil
}

// header builds the 12-byte response header. aa is set ONLY when the caller has
// genuine authority ([H3]); NSCOUNT/ARCOUNT stay zero. The resolver's persona is
// an ordinary recursive resolver: opcode and RD are echoed from the query and RA
// is always set. Without RA, Go's stub resolver reads an empty non-authoritative
// NOERROR (a sinkholed AAAA) as a "lame referral" and dig warns "recursion
// requested but not available" — tells that single out sinkholed names.
func header(q dnsQuery, aa bool, rcode uint8, ancount uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], q.id)
	flags := uint16(0x8000)              // QR
	flags |= uint16(q.opcode&0x0f) << 11 // OPCODE (echoed)
	if aa {
		flags |= 0x0400 // AA
	}
	if q.rd {
		flags |= 0x0100 // RD (echoed)
	}
	flags |= 0x0080 // RA
	flags |= uint16(rcode) & 0x000f
	binary.BigEndian.PutUint16(h[2:4], flags)
	binary.BigEndian.PutUint16(h[4:6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(h[6:8], ancount)
	return h
}

// replyA echoes the question and appends one A answer (NAME=0xC00C, TTL 30). If
// ip is not IPv4 it degrades to NXDOMAIN. aa is the caller's authority claim.
// A non-IPv4 ip always yields a non-authoritative NXDOMAIN regardless of aa.
func replyA(q dnsQuery, ip net.IP, aa bool) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return replyRcode(q, rcodeNXDomain, false)
	}
	out := append(header(q, aa, rcodeNoError, 1), q.qsection...)
	out = append(out, 0xC0, 0x0C, // NAME -> pointer to question
		0x00, 0x01, // TYPE A
		0x00, 0x01, // CLASS IN
		0x00, 0x00, 0x00, 0x1E, // TTL 30
		0x00, 0x04) // RDLENGTH 4
	return append(out, v4...)
}

// replyRcode echoes the question with an rcode and no answer. aa lets the caller
// claim authority for an empty NOERROR of a genuine world name; it is false for
// sinkholed/unsupported ([H3]).
func replyRcode(q dnsQuery, rcode uint8, aa bool) []byte {
	return append(header(q, aa, rcode, 0), q.qsection...)
}
