package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
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

func TestBuildServices(t *testing.T) {
	svcs, err := buildServices([]serviceSpec{{"http", 80}, {"ssh", 22}}, "h")
	if err != nil {
		t.Fatalf("buildServices: %v", err)
	}
	if len(svcs) != 2 || svcs[0].port != 80 || svcs[1].port != 22 {
		t.Errorf("svcs = %+v", svcs)
	}
	if svcs[0].run == nil || svcs[1].run == nil {
		t.Error("run funcs must be non-nil")
	}
	if _, err := buildServices([]serviceSpec{{"smb", 445}}, "h"); err == nil {
		t.Error("unknown proto must error")
	}
}

func TestReadLine(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		max     int
		bufSize int
		stall   bool // further reads after in fail with errStalled (a live conn that stops sending)
		want    string
		wantErr error
	}{
		{"short line", "hi\r\nrest", 10, 16, false, "hi\r\n", nil},
		{"exactly max", "abcd\r\n", 6, 16, false, "abcd\r\n", nil},
		{"one over max", "abcde\r\n", 6, 16, false, "", errLineTooLong},
		{"no newline, long stream", strings.Repeat("x", 1000), 100, 16, false, "", errLineTooLong},
		{"spans buffer fills", strings.Repeat("y", 40) + "\n", 64, 16, false, strings.Repeat("y", 40) + "\n", nil},
		{"eof mid-line", "partial", 64, 16, false, "", io.EOF},
		// An over-long burst smaller than r's buffer must be rejected without
		// waiting for more bytes (a stalling subject must not hold the bound off).
		{"over max in one short burst", strings.Repeat("z", 200), 100, 4096, true, "", errLineTooLong},
		{"under max then stall", "abc", 100, 4096, true, "", errStalled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var src io.Reader = strings.NewReader(tc.in)
			if tc.stall {
				src = io.MultiReader(src, stallReader{})
			}
			got, err := readLine(bufio.NewReaderSize(src, tc.bufSize), tc.max)
			if !errors.Is(err, tc.wantErr) || got != tc.want {
				t.Errorf("readLine = %q, %v; want %q, %v", got, err, tc.want, tc.wantErr)
			}
		})
	}
}

var errStalled = errors.New("stalled")

// stallReader stands in for a conn whose peer stopped sending.
type stallReader struct{}

func (stallReader) Read([]byte) (int, error) { return 0, errStalled }
