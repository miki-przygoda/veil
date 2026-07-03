package main

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func itoa(i int) string { return strconv.Itoa(i) }

// freePort binds :0, records the port, and frees it so run can rebind it.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return p
}

func TestRunServesThenShutsDown(t *testing.T) {
	port := freePort(t)
	cfg := config{
		services: []serviceSpec{{"ssh", port}},
		hostname: "host-01",
		interval: time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfg) }()

	// the ssh service should be reachable
	var c net.Conn
	var err error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if c, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", itoa(port))); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial :%d: %v", port, err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	c.Close()
	if !strings.HasPrefix(line, "SSH-2.0-") {
		t.Errorf("banner = %q", line)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned %v, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after cancel")
	}
}

func TestRunListenFailureErrors(t *testing.T) {
	// bind a port on all interfaces, then ask run to bind the same one -> fatal listen error
	l, _ := net.Listen("tcp", ":0")
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	cfg := config{services: []serviceSpec{{"ssh", port}}, hostname: "h", interval: time.Second}
	if err := run(context.Background(), cfg); err == nil {
		t.Error("run should error when a listener bind fails")
	}
}
