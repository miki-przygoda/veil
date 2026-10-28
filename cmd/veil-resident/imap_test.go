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

// An over-long IMAP line gets an untagged BAD + BYE and the connection closes,
// instead of buffering the subject's stream until the resident OOMs.
func TestServeIMAPBoundsLineLength(t *testing.T) {
	cases := []struct {
		name      string
		payload   string
		wantLines []string // reply prefixes, in order
		wantClose bool
	}{
		{"line over limit", strings.Repeat("A", 4*maxIMAPLine), []string{"* BAD", "* BYE"}, true},
		{"long line under limit served", "a1 LOGIN " + strings.Repeat("u", maxIMAPLine/2) + " p\r\n", []string{"a1 OK"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { _ = serveIMAP(ctx, ln, "mail.veil.local") }()

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
			c.Write([]byte(tc.payload))
			for _, want := range tc.wantLines {
				line, err := r.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, want) {
					t.Fatalf("reply = %q (%v), want prefix %q", line, err, want)
				}
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
