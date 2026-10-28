package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestServeHTTPRespondsAndShutsDown(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- serveHTTP(ctx, ln, "web.veil.local") }()

	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ln.Addr().String() + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if resp.Header.Get("Server") != httpServerHeader {
		t.Errorf("Server = %q, want %q", resp.Header.Get("Server"), httpServerHeader)
	}
	if !strings.Contains(string(body), "web.veil.local") {
		t.Errorf("body missing hostname: %q", body)
	}

	// The links advertised on / must not 404 (a crawler following them is a probe).
	for _, path := range []string{"/docs", "/status"} {
		r, err := (&http.Client{Timeout: 2 * time.Second}).Get("http://" + ln.Addr().String() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		if r.StatusCode != 200 {
			t.Errorf("GET %s status = %d, want 200 (advertised link must not 404)", path, r.StatusCode)
		}
		if r.Header.Get("Server") != httpServerHeader {
			t.Errorf("GET %s Server = %q, want %q", path, r.Header.Get("Server"), httpServerHeader)
		}
	}

	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("serveHTTP returned %v, want nil on shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serveHTTP did not return after cancel")
	}
}

// The fake intranet must not hold idle keep-alive or slow connections forever:
// every server timeout is set, so a subject can't pin resident memory with sockets.
func TestNewHTTPServerTimeouts(t *testing.T) {
	srv := newHTTPServer("web.veil.local")
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv.ReadHeaderTimeout, 5 * time.Second},
		{"ReadTimeout", srv.ReadTimeout, 10 * time.Second},
		{"WriteTimeout", srv.WriteTimeout, 10 * time.Second},
		{"IdleTimeout", srv.IdleTimeout, 30 * time.Second},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// limitListener caps concurrently open accepted conns: Accept blocks at the cap,
// resumes when a conn closes (double Close releases once), and unblocks on Close.
func TestLimitListener(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ll := newLimitListener(inner, 2)
	defer ll.Close()

	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := ll.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	for i := 0; i < 4; i++ {
		c, err := net.Dial("tcp", inner.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	recv := func(wait time.Duration) net.Conn {
		select {
		case c := <-accepted:
			return c
		case <-time.After(wait):
			return nil
		}
	}
	a, b := recv(2*time.Second), recv(2*time.Second)
	if a == nil || b == nil {
		t.Fatal("first two conns not accepted")
	}
	if c := recv(200 * time.Millisecond); c != nil {
		t.Fatal("third conn accepted while at cap")
	}
	a.Close()
	a.Close() // a second Close must not free a second slot
	third := recv(2 * time.Second)
	if third == nil {
		t.Fatal("conn not accepted after a slot was released")
	}
	if c := recv(200 * time.Millisecond); c != nil {
		t.Fatal("fourth conn accepted while at cap (double Close released twice?)")
	}
	ll.Close() // must unblock the Accept waiting on the semaphore
	select {
	case _, ok := <-accepted:
		if ok {
			t.Error("unexpected conn after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Accept did not unblock after Close")
	}
	b.Close()
	third.Close()
}
