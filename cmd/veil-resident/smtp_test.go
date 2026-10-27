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

// A subject streaming bytes with no newline must not grow the resident's heap
// without bound: an over-long line (command or DATA) gets a plausible 500 and the
// connection closes, while a line exactly at the RFC 5321 limit is still served.
func TestServeSMTPBoundsLineLength(t *testing.T) {
	atLimit := "MAIL FROM:<" + strings.Repeat("a", maxSMTPLine-len("MAIL FROM:<>\r\n")) + ">\r\n"
	cases := []struct {
		name      string
		prelude   []string // lines sent (each answered by one reply) before payload
		payload   string
		wantReply string
		wantClose bool
	}{
		{"command line over limit", nil, strings.Repeat("A", 4*maxSMTPLine), "500", true},
		{"data line over limit", []string{"EHLO c\r\n", "DATA\r\n"}, strings.Repeat("B", 4*maxSMTPLine), "500", true},
		{"line at limit served", nil, atLimit, "250", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			if _, err := r.ReadString('\n'); err != nil {
				t.Fatalf("greeting: %v", err)
			}
			for _, l := range tc.prelude {
				c.Write([]byte(l))
				if _, err := r.ReadString('\n'); err != nil {
					t.Fatalf("reply to %q: %v", l, err)
				}
			}
			c.Write([]byte(tc.payload))
			line, err := r.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, tc.wantReply) {
				t.Fatalf("reply = %q (%v), want prefix %q", line, err, tc.wantReply)
			}
			if tc.wantClose {
				if _, err := r.ReadString('\n'); err == nil {
					t.Error("connection still open after over-long line, want close")
				} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
					t.Error("connection not closed after over-long line (read timed out)")
				}
			}
		})
	}
}
