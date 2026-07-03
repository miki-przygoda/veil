package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeIMAPConversation(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = serveIMAP(ctx, ln, "mail.veil.local") }()

	c, _ := net.Dial("tcp", ln.Addr().String())
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)

	greet, _ := r.ReadString('\n')
	if !strings.HasPrefix(greet, "* OK") || !strings.Contains(greet, "IMAP4rev1") {
		t.Errorf("greeting = %q", greet)
	}
	c.Write([]byte("a1 CAPABILITY\r\n"))
	star, _ := r.ReadString('\n') // untagged * CAPABILITY line
	tagged, _ := r.ReadString('\n')
	if !strings.Contains(star, "CAPABILITY") || !strings.HasPrefix(tagged, "a1 OK") {
		t.Errorf("CAPABILITY = %q / %q", star, tagged)
	}
	c.Write([]byte("a2 LOGOUT\r\n"))
	bye, _ := r.ReadString('\n')
	done, _ := r.ReadString('\n')
	if !strings.HasPrefix(bye, "* BYE") || !strings.HasPrefix(done, "a2 OK") {
		t.Errorf("LOGOUT = %q / %q", bye, done)
	}
}
