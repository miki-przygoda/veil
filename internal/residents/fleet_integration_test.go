package residents

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/miki-przygoda/veil/internal/docker"
	"github.com/miki-przygoda/veil/internal/events"
)

// TestFleetLive spawns the real roster on an existing veil-net and checks that the
// web resident answers on its derived IP, then tears down. On Linux the host can
// reach the internal bridge subnet (the gateway is a host interface). Needs Docker,
// the veil-resident:dev image, and a running veil-net; skipped unless
// VEIL_RESIDENTS_IT is set (plus VEIL_NET_SUBNET + VEIL_NET_GATEWAY).
func TestFleetLive(t *testing.T) {
	if os.Getenv("VEIL_RESIDENTS_IT") == "" {
		t.Skip("set VEIL_RESIDENTS_IT=1 to run (needs Linux + Docker + veil-net + veil-resident:dev)")
	}
	subnet, gateway := os.Getenv("VEIL_NET_SUBNET"), os.Getenv("VEIL_NET_GATEWAY")
	if subnet == "" || gateway == "" {
		t.Skip("set VEIL_NET_SUBNET and VEIL_NET_GATEWAY to the live veil-net values")
	}
	cli, err := docker.New(os.Getenv("DOCKER_HOST"))
	if err != nil {
		t.Fatalf("docker: %v", err)
	}
	f := NewFleet(cli, "veil-resident:dev", subnet, gateway, DefaultRoster())
	ctx := context.Background()
	if err := f.Up(ctx, events.NewBus(64), quietLog()); err != nil {
		t.Fatalf("Up: %v", err)
	}
	defer f.Down(ctx, events.NewBus(1))

	webIP := f.hostIP(10).String()
	deadline := time.Now().Add(15 * time.Second)
	for {
		resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + webIP + "/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return // success: web resident is live at its static IP
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("web resident %s never answered 200: %v", webIP, err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
