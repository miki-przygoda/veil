package main

import (
	"bufio"
	"context"
	"net"
	"testing"
	"time"
)

func TestAcceptLoopEchoesAndStops(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- acceptLoop(ctx, ln, func(c net.Conn) {
			line, _ := bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte("echo:" + line))
		})
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte("hi\n"))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	got, _ := bufio.NewReader(c).ReadString('\n')
	if got != "echo:hi\n" {
		t.Errorf("got %q, want echo:hi", got)
	}
	c.Close()

	cancel() // must unblock Accept and return nil
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("acceptLoop returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not return after cancel")
	}
}
