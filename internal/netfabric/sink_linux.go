//go:build linux

package netfabric

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"syscall"

	"github.com/miki-przygoda/veil/internal/events"
)

var ErrHoneypotUnsupported = errors.New("transparent honeypot unsupported")

const (
	honeypotChain = "VEIL-HONEYPOT"
	soOriginalDst = 80 // SO_ORIGINAL_DST (Linux netfilter)
)

// InstallHoneypot binds a listener on the gateway and installs a scoped,
// reconciled iptables REDIRECT so all TCP from the box to the gateway lands on
// it. Returns a teardown that removes the chain + closes the listener. [H2]
func InstallHoneypot(bridge, subnet, gateway string, bus *events.Bus, log *slog.Logger) (func(), error) {
	if net.ParseIP(gateway) == nil {
		return nil, fmt.Errorf("%w: bad gateway %q", ErrHoneypotUnsupported, gateway)
	}
	if bridge == "" || subnet == "" {
		return nil, fmt.Errorf("%w: missing bridge/subnet", ErrHoneypotUnsupported)
	}
	ln, err := net.Listen("tcp", gateway+":0") // gateway only, ephemeral port; never 0.0.0.0
	if err != nil {
		return nil, fmt.Errorf("%w: listen: %v", ErrHoneypotUnsupported, err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())

	// Reconcile: clear any chain a prior crashed run leaked, then install fresh.
	removeRules(bridge, subnet, gateway)
	if err := installRules(bridge, subnet, gateway, port); err != nil {
		_ = ln.Close()
		removeRules(bridge, subnet, gateway)
		return nil, fmt.Errorf("%w: iptables: %v", ErrHoneypotUnsupported, err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go NewSink(bus, gateway, origDst).serve(ctx, ln)
	log.Info("honeypot listening", "addr", ln.Addr().String())

	return func() {
		cancel()
		_ = ln.Close()
		removeRules(bridge, subnet, gateway)
	}, nil
}

func ipt(args ...string) error {
	out, err := exec.Command("iptables", args...).CombinedOutput() // arg-slice, no shell
	if err != nil {
		return fmt.Errorf("iptables %v: %v: %s", args, err, out)
	}
	return nil
}

func installRules(bridge, subnet, gateway, port string) error {
	if err := ipt("-t", "nat", "-N", honeypotChain); err != nil {
		return err
	}
	if err := ipt("-t", "nat", "-A", honeypotChain,
		"-i", bridge, "-s", subnet, "-d", gateway, "-p", "tcp",
		"-j", "REDIRECT", "--to-ports", port); err != nil {
		return err
	}
	return ipt("-t", "nat", "-A", "PREROUTING",
		"-i", bridge, "-s", subnet, "-d", gateway, "-p", "tcp", "-j", honeypotChain)
}

// removeRules is idempotent (each step tolerates "not found"): unhook the jump,
// flush, delete the chain. Used for both reconcile and teardown.
func removeRules(bridge, subnet, gateway string) {
	_ = ipt("-t", "nat", "-D", "PREROUTING",
		"-i", bridge, "-s", subnet, "-d", gateway, "-p", "tcp", "-j", honeypotChain)
	_ = ipt("-t", "nat", "-F", honeypotChain)
	_ = ipt("-t", "nat", "-X", honeypotChain)
}

// origDst recovers the subject's intended port via SO_ORIGINAL_DST (the pre-
// REDIRECT destination). Returns 0 on any failure.
//
// sockaddr_in layout in Multiaddr: bytes [0:2]=family, [2:4]=port (big-endian),
// [4:8]=IPv4 address. We read only the port bytes [2:4].
func origDst(conn net.Conn) int {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return 0
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return 0
	}
	var port int
	_ = raw.Control(func(fd uintptr) {
		mreq, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, soOriginalDst)
		if err != nil {
			return
		}
		port = int(binary.BigEndian.Uint16(mreq.Multiaddr[2:4]))
	})
	return port
}
