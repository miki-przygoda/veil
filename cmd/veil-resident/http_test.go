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
