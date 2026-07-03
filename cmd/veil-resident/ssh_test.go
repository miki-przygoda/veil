package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeSSHBanner(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = serveSSH(ctx, ln, "bastion") }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.HasPrefix(line, "SSH-2.0-") {
		t.Errorf("banner = %q, want SSH-2.0- prefix", line)
	}
}
