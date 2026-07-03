package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeSMTPConversation(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = serveSMTP(ctx, ln, "mail.veil.local") }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)

	greet, _ := r.ReadString('\n')
	if !strings.HasPrefix(greet, "220 mail.veil.local") {
		t.Errorf("greeting = %q", greet)
	}
	c.Write([]byte("EHLO client\r\n"))
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "250") {
		t.Errorf("EHLO reply = %q, want 250", line)
	}
	c.Write([]byte("QUIT\r\n"))
	if line, _ := r.ReadString('\n'); !strings.HasPrefix(line, "221") {
		t.Errorf("QUIT reply = %q, want 221", line)
	}
}
