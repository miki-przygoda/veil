//go:build linux

package netfabric

import (
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// TestDecodeCarriesCaptureTime: decode copies gopacket's CaptureInfo.Timestamp
// onto the packet, so the fact is stamped at capture, not at dequeue.
func TestDecodeCarriesCaptureTime(t *testing.T) {
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{
		SrcMAC: []byte{2, 0, 0, 0, 0, 1}, DstMAC: []byte{2, 0, 0, 0, 0, 2},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4,
		HwAddressSize: 6, ProtAddressSize: 4, Operation: layers.ARPRequest,
		SourceHwAddress: eth.SrcMAC, SourceProtAddress: []byte{10, 7, 0, 2},
		DstHwAddress: make([]byte, 6), DstProtAddress: []byte{10, 7, 0, 1},
	}
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{}, eth, arp); err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	captured := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	pkt.Metadata().Timestamp = captured

	p := decode(pkt)
	if !p.Time.Equal(captured) || p.Protocol != "arp" {
		t.Errorf("decode = %+v, want arp at %v", p, captured)
	}
}
