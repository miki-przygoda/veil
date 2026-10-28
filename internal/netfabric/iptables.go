package netfabric

import (
	"errors"
	"strings"
)

// The honeypot's netfilter plumbing as pure argv logic. Only sink_linux.go runs
// it against the real iptables; keeping it untagged lets the reconcile be
// tested everywhere with a fake runner.

const honeypotChain = "VEIL-HONEYPOT"

// iptWaitSeconds bounds how long one real iptables call waits for the xtables
// lock (/run/xtables.lock) that the legacy backend takes around its whole-table
// read-modify-write. Without -w a legacy call fails at once ("Another app is
// currently holding the xtables lock") whenever dockerd or the host is mid-
// update; with it, it queues, so writers serialise instead of racing. iptables-
// nft accepts -w and ignores it (the kernel's nf_tables transactions are atomic).
// Kept short: a teardown makes ~4 calls, and the compose stop_grace_period
// budgets for them.
const iptWaitSeconds = "3"

// iptArgv is the argv sink_linux.go actually execs: the caller's args behind a
// bounded wait for the xtables lock.
func iptArgv(args ...string) []string {
	return concatArgs([]string{"-w", iptWaitSeconds}, args)
}

// iptRunner runs one iptables invocation (argv only, never a shell) and returns
// its combined output.
type iptRunner func(args ...string) (string, error)

// reconcileHoneypotRules clears every trace of a prior run (whatever subnet it
// was installed for), then installs the single correct jump for this one.
func reconcileHoneypotRules(run iptRunner, bridge, subnet, gateway, port string, exemptDNS bool) error {
	removeHoneypotRules(run)
	return installHoneypotRules(run, bridge, subnet, gateway, port, exemptDNS)
}

// installHoneypotRules builds the chain and hooks it into nat PREROUTING. The
// jump is TCP-only, so UDP :53 never enters the chain. exemptDNS (set only when
// the resolver's TCP listener is up) RETURNs gateway tcp/53 ahead of the REDIRECT,
// so DNS-over-TCP (dig +tcp, use-vc, truncation retries) reaches the resolver
// instead of firing a false honeypot-hit and drawing the Sink's "220" banner.
// Without it tcp/53 stays redirected: an unserved port would leave DNS-over-TCP
// unobserved, the Sink at least records it. The exemption lives inside the chain,
// so reconcile-by-chain-name removes it with the rest. Scope (bridge, subnet,
// gateway) is repeated on every rule so each is safe on its own.
func installHoneypotRules(run iptRunner, bridge, subnet, gateway, port string, exemptDNS bool) error {
	scope := []string{"-i", bridge, "-s", subnet, "-d", gateway, "-p", "tcp"}
	steps := [][]string{{"-t", "nat", "-N", honeypotChain}}
	if exemptDNS {
		steps = append(steps, concatArgs([]string{"-t", "nat", "-A", honeypotChain}, scope, []string{"--dport", "53", "-j", "RETURN"}))
	}
	steps = append(steps,
		concatArgs([]string{"-t", "nat", "-A", honeypotChain}, scope, []string{"-j", "REDIRECT", "--to-ports", port}),
		concatArgs([]string{"-t", "nat", "-A", "PREROUTING"}, scope, []string{"-j", honeypotChain}),
	)
	for _, s := range steps {
		if _, err := run(s...); err != nil {
			return err
		}
	}
	return nil
}

// removeHoneypotRules is idempotent (each step tolerates "not found"): unhook
// EVERY PREROUTING jump to the chain — reconciled by chain name, so a jump a
// crashed run left for an older subnet goes too — then flush and delete the
// chain. Rules that don't jump to the chain are never touched. Used for both
// reconcile and teardown.
func removeHoneypotRules(run iptRunner) {
	if out, err := run("-t", "nat", "-S", "PREROUTING"); err == nil {
		for _, spec := range honeypotJumps(out) {
			_, _ = run(concatArgs([]string{"-t", "nat", "-D", "PREROUTING"}, spec)...)
		}
	}
	_, _ = run("-t", "nat", "-F", honeypotChain)
	_, _ = run("-t", "nat", "-X", honeypotChain)
}

// honeypotJumps returns the rule spec (argv after "-A PREROUTING") of every
// PREROUTING rule in `iptables -S` output whose target is exactly the honeypot
// chain. A line that doesn't parse is skipped rather than guessed at.
func honeypotJumps(listing string) [][]string {
	var out [][]string
	for _, line := range strings.Split(listing, "\n") {
		argv, err := splitRuleSpec(line)
		if err != nil || len(argv) < 2 || argv[0] != "-A" || argv[1] != "PREROUTING" {
			continue
		}
		spec := argv[2:]
		for i := 0; i+1 < len(spec); i++ {
			if spec[i] == "-j" && spec[i+1] == honeypotChain {
				out = append(out, spec)
				break
			}
		}
	}
	return out
}

var errUnterminatedQuote = errors.New("unterminated quote")

// splitRuleSpec splits one `iptables -S` line into argv. iptables-save quoting
// is double quotes with backslash escapes inside them; everything else splits
// on whitespace. A quoted "-j X" is one token, so it can't pose as a target.
func splitRuleSpec(line string) ([]string, error) {
	var (
		argv    []string
		cur     strings.Builder
		inToken bool
		quoted  bool
	)
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
		case quoted && c == '"':
			quoted = false
		case quoted:
			cur.WriteByte(c)
		case c == '"':
			quoted, inToken = true, true
		case c == ' ' || c == '\t' || c == '\r':
			if inToken {
				argv = append(argv, cur.String())
				cur.Reset()
				inToken = false
			}
		default:
			cur.WriteByte(c)
			inToken = true
		}
	}
	if quoted {
		return nil, errUnterminatedQuote
	}
	if inToken {
		argv = append(argv, cur.String())
	}
	return argv, nil
}

func concatArgs(parts ...[]string) []string {
	var out []string
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
