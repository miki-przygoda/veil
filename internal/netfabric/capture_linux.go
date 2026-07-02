//go:build linux

package netfabric

import (
	"fmt"
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
	src.NoCopy = true
	in := src.Packets()
	for {
		select {
		case <-s.done:
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			s.out <- decode(pkt)
		}
	}
}

func decode(pkt gopacket.Packet) packet {
	p := packet{Protocol: "eth", Length: len(pkt.Data())}
	if n := pkt.NetworkLayer(); n != nil {
		f := n.NetworkFlow()
		p.Src, p.Dst = f.Src().String(), f.Dst().String()
	}
	if t := pkt.TransportLayer(); t != nil {
		p.Protocol = t.LayerType().String() // "TCP"/"UDP"
	} else if pkt.Layer(layers.LayerTypeARP) != nil {
		p.Protocol = "arp"
	}
	return p
}

func (s *afpacketSource) packets() <-chan packet { return s.out }

func (s *afpacketSource) close() error {
	s.once.Do(func() { close(s.done) })
	s.handle.Close()
	return nil
}
