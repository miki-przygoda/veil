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
