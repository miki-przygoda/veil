//go:build linux

package netfabric

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// afpacketSource captures on a bridge via a pure-Go AF_PACKET handle (no cgo,
// no libpcap) and decodes each frame into a packet.
type afpacketSource struct {
	handle *pcapgo.EthernetHandle
	out    chan packet
	done   chan struct{}
	once   sync.Once // guards done channel close
}

func openBridge(iface string) (packetSource, error) {
	h, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCaptureUnsupported, err)
	}
	s := &afpacketSource{
		handle: h,
		out:    make(chan packet, 256),
		done:   make(chan struct{}),
	}
	go s.loop()
	return s, nil
}

func (s *afpacketSource) loop() {
	defer close(s.out)
	src := gopacket.NewPacketSource(s.handle, layers.LayerTypeEthernet)
	// safe: pcapgo.EthernetHandle allocates a fresh buffer per read and decode() extracts value-typed fields before the next read. A gopacket/pcap (libpcap) swap reuses the read buffer — drop NoCopy there.
	src.NoCopy = true
	// NOTE: Packets() spawns a reader goroutine blocked in a raw recvfrom; close() shuts the fd but an already-blocked read on a silent bridge may linger until the next frame. Fine for a long-lived veild; revisit if OpenTap is called repeatedly.
	in := src.Packets()
	for {
		select {
		case <-s.done:
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			select {
			case s.out <- decode(pkt):
			case <-s.done:
				return
			}
		}
	}
}

func decode(pkt gopacket.Packet) packet {
	p := packet{Protocol: "eth", Length: len(pkt.Data())}
	p.Time = pkt.Metadata().Timestamp // kernel capture time; trafficEvent normalises to UTC
	if n := pkt.NetworkLayer(); n != nil {
		f := n.NetworkFlow()
		p.Src, p.Dst = f.Src().String(), f.Dst().String()
	}
	if t := pkt.TransportLayer(); t != nil {
		p.Protocol = strings.ToLower(t.LayerType().String())
	} else if pkt.Layer(layers.LayerTypeARP) != nil {
		p.Protocol = "arp"
	}
	return p
}

func (s *afpacketSource) packets() <-chan packet { return s.out }

func (s *afpacketSource) close() error {
	s.once.Do(func() {
		close(s.done)
		s.handle.Close()
	})
	return nil
}
