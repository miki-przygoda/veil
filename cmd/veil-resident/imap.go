package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// serveIMAP greets and answers CAPABILITY/LOGIN/LOGOUT with canned tagged
// responses — enough to look like a real IMAP host under light interaction.
func serveIMAP(ctx context.Context, ln net.Listener, hostname string) error {
	return acceptLoop(ctx, ln, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(30 * time.Second))
		w := bufio.NewWriter(c)
		fmt.Fprintf(w, "* OK %s IMAP4rev1 ready\r\n", hostname)
		_ = w.Flush()
		r := bufio.NewReader(c)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 {
				continue
			}
			tag, cmd := fields[0], strings.ToUpper(fields[1])
			switch cmd {
			case "CAPABILITY":
				w.WriteString("* CAPABILITY IMAP4rev1\r\n")
				fmt.Fprintf(w, "%s OK CAPABILITY completed\r\n", tag)
			case "LOGIN":
				fmt.Fprintf(w, "%s OK LOGIN completed\r\n", tag)
			case "LOGOUT":
				w.WriteString("* BYE logging out\r\n")
				fmt.Fprintf(w, "%s OK LOGOUT completed\r\n", tag)
				_ = w.Flush()
				return
			default:
				fmt.Fprintf(w, "%s BAD unknown command\r\n", tag)
			}
			_ = w.Flush()
		}
	})
}
