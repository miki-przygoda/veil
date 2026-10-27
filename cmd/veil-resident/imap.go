package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// maxIMAPLine bounds one IMAP command line. RFC 3501 sets no limit; RFC 7162 (3.2.1)
// asks servers to accept at least 8192 octets, which is plenty for this canned set.
const maxIMAPLine = 8192

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
			line, err := readLine(r, maxIMAPLine)
			if errors.Is(err, errLineTooLong) {
				w.WriteString("* BAD line too long\r\n")
				w.WriteString("* BYE closing connection\r\n")
				_ = w.Flush()
				hangUp(c)
				return
			}
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
