package residents

import (
	"strings"
	"testing"
)

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

func TestResidentSpec(t *testing.T) {
	f := newFleetWithEngine(nil, "veil-resident:dev", "172.20.0.0/16", "172.20.0.1", DefaultRoster())

	web := f.residentSpec(Host{Name: "web.veil.local", Offset: 10, Serve: "http:80,ssh:22", IsServer: true})
	if web.Name != "veil-resident-web.veil.local" {
		t.Errorf("Name = %q", web.Name)
	}
	if web.Image != "veil-resident:dev" {
		t.Errorf("Image = %q", web.Image)
	}
	joined := strings.Join(web.Cmd, " ")
	for _, want := range []string{"-serve http:80,ssh:22", "-hostname web.veil.local", "-resolver 172.20.0.1:53"} {
		if !strings.Contains(joined, want) {
			t.Errorf("Cmd missing %q: %v", want, web.Cmd)
		}
	}
	if strings.Contains(joined, "-client") {
		t.Errorf("pure server must have no -client: %v", web.Cmd)
	}
	if web.HostConfig.NetworkMode != "veil-net" {
		t.Errorf("NetworkMode = %q", web.HostConfig.NetworkMode)
	}
	if len(web.HostConfig.Dns) != 1 || web.HostConfig.Dns[0] != "172.20.0.1" {
		t.Errorf("Dns = %v, want [172.20.0.1] (UDP resolver seam)", web.HostConfig.Dns)
	}
	if len(web.HostConfig.CapAdd) != 1 || web.HostConfig.CapAdd[0] != "NET_BIND_SERVICE" {
		t.Errorf("CapAdd = %v, want [NET_BIND_SERVICE]", web.HostConfig.CapAdd)
	}
	if len(web.HostConfig.CapDrop) != 1 || web.HostConfig.CapDrop[0] != "ALL" {
		t.Errorf("CapDrop = %v, want [ALL] (inherited hardening)", web.HostConfig.CapDrop)
	}
	if web.NetworkingConfig == nil ||
		web.NetworkingConfig.EndpointsConfig["veil-net"].IPAMConfig.IPv4Address != "172.20.0.10" {
		t.Errorf("static IP not set to 172.20.0.10: %+v", web.NetworkingConfig)
	}
	if web.Labels["com.veil.role"] != "resident" {
		t.Errorf("role label = %q", web.Labels["com.veil.role"])
	}

	// a client host carries -client and no -serve
	alice := f.residentSpec(Host{Name: "alice-pc", Offset: 50, Client: "web.veil.local"})
	aj := strings.Join(alice.Cmd, " ")
	if !strings.Contains(aj, "-client web.veil.local") || strings.Contains(aj, "-serve") {
		t.Errorf("client spec Cmd wrong: %v", alice.Cmd)
	}
}
