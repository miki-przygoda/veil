package residents

import "testing"

func TestHostIPAndWorldNames(t *testing.T) {
	f := newFleetWithEngine(nil, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())

	if got := f.hostIP(10); got.String() != "172.20.0.10" {
		t.Errorf("hostIP(10) = %v, want 172.20.0.10", got)
	}
	if got := f.hostIP(50); got.String() != "172.20.0.50" {
		t.Errorf("hostIP(50) = %v, want 172.20.0.50", got)
	}
	names := f.WorldNames()
	if ip := names["web.veil.local"]; ip == nil || ip.String() != "172.20.0.10" {
		t.Errorf("WorldNames[web.veil.local] = %v, want 172.20.0.10", ip)
	}
	if _, ok := names["alice-pc"]; ok {
		t.Error("clients must not appear in WorldNames (only IsServer hosts)")
	}
	if len(names) != 4 {
		t.Errorf("WorldNames has %d entries, want 4 servers", len(names))
	}
}

func TestHostIPOtherSubnet(t *testing.T) {
	f := newFleetWithEngine(nil, "img", "10.5.0.0/16", "10.5.0.1", DefaultRoster())
	if got := f.hostIP(12); got.String() != "10.5.0.12" {
		t.Errorf("hostIP(12) = %v, want 10.5.0.12", got)
	}
}
