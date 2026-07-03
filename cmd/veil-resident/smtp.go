package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// serveSMTP greets and answers a minimal command set — enough that a subject's
// HELO/EHLO handshake gets real responses, not a dead socket.
func serveSMTP(ctx context.Context, ln net.Listener, hostname string) error {
	return acceptLoop(ctx, ln, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		w := bufio.NewWriter(c)
		fmt.Fprintf(w, "220 %s ESMTP\r\n", hostname)
		_ = w.Flush()
		r := bufio.NewReader(c)
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			raw := strings.TrimRight(line, "\r\n")
			if inData {
				if raw == "." {
					inData = false
					w.WriteString("250 OK\r\n")
					_ = w.Flush()
				}
				continue
			}
			cmd := strings.ToUpper(strings.TrimSpace(raw))
			switch {
			case strings.HasPrefix(cmd, "HELO"), strings.HasPrefix(cmd, "EHLO"):
				fmt.Fprintf(w, "250 %s\r\n", hostname)
			case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
				w.WriteString("250 OK\r\n")
			case strings.HasPrefix(cmd, "DATA"):
				w.WriteString("354 End data with <CR><LF>.<CR><LF>\r\n")
				inData = true
			case strings.HasPrefix(cmd, "QUIT"):
				w.WriteString("221 Bye\r\n")
				_ = w.Flush()
				return
			default:
				w.WriteString("500 unrecognized\r\n")
			}
			_ = w.Flush()
		}
	})
}
