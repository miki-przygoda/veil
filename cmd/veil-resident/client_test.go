package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientActMakesHTTPRequests(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://") // host:port

	c := newClient([]string{target}, "", 10*time.Millisecond, 1) // fixed seed = reproducible
	for i := 0; i < 50; i++ {
		c.act(context.Background())
	}
	if hits.Load() == 0 {
		t.Error("client never issued an HTTP GET over 50 actions")
	}
}

func TestRunClientStopsOnCancel(t *testing.T) {
	c := newClient(nil, "", 10*time.Millisecond, 1) // no targets -> waits on ctx
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- c.runClient(ctx) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runClient did not return after cancel")
	}
}
