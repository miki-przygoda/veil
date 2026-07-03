package main

import (
	"context"
	"net"
	"time"
)

// sshBanner is a plausible OpenSSH identification string. serveSSH is banner-only:
// it does not complete a key exchange (out of scope for v1). hostname is unused —
// SSH ident strings don't carry it — but kept for a uniform service signature.
const sshBanner = "SSH-2.0-OpenSSH_8.9p1\r\n"

func serveSSH(ctx context.Context, ln net.Listener, hostname string) error {
	return acceptLoop(ctx, ln, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte(sshBanner))
		buf := make([]byte, 256)
		_, _ = c.Read(buf) // read the client's ident line, then let the loop close us
	})
}
