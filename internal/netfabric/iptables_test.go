package netfabric

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// fakeIPT records every iptables argv and answers `-S PREROUTING` with canned
// output, so the reconcile logic is testable without netfilter or root.
type fakeIPT struct {
	listing string // returned for "-t nat -S PREROUTING"
	listErr error
	failOn  string // fail any call whose joined argv contains this
	calls   [][]string
}

func (f *fakeIPT) run(args ...string) (string, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	joined := strings.Join(args, " ")
	if f.failOn != "" && strings.Contains(joined, f.failOn) {
		return "", errors.New("boom")
	}
	if joined == "-t nat -S PREROUTING" {
		return f.listing, f.listErr
	}
	return "", nil
}

func (f *fakeIPT) deletes() [][]string {
	var out [][]string
	for _, c := range f.calls {
		if len(c) > 3 && c[2] == "-D" {
			out = append(out, c)
		}
	}
	return out
}

func TestSplitRuleSpec(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
		err  bool
	}{
		{"plain", "-A PREROUTING -i br0 -j VEIL-HONEYPOT", []string{"-A", "PREROUTING", "-i", "br0", "-j", "VEIL-HONEYPOT"}, false},
		{"extra spaces", "  -A  PREROUTING   -j X  ", []string{"-A", "PREROUTING", "-j", "X"}, false},
		{"quoted comment", `-A PREROUTING -m comment --comment "a b" -j X`, []string{"-A", "PREROUTING", "-m", "comment", "--comment", "a b", "-j", "X"}, false},
		{"escaped quote", `-A P --comment "say \"hi\"" -j X`, []string{"-A", "P", "--comment", `say "hi"`, "-j", "X"}, false},
		{"negation", "-A PREROUTING ! -d 10.0.0.1/32 -j X", []string{"-A", "PREROUTING", "!", "-d", "10.0.0.1/32", "-j", "X"}, false},
		{"empty quoted", `-A P --comment "" -j X`, []string{"-A", "P", "--comment", "", "-j", "X"}, false},
		{"unterminated quote", `-A P --comment "oops -j X`, nil, true},
		{"empty", "", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitRuleSpec(tt.in)
			if (err != nil) != tt.err {
				t.Fatalf("err = %v, want err=%v", err, tt.err)
			}
			if !tt.err && !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHoneypotJumps(t *testing.T) {
	listing := strings.Join([]string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
		// current subnet's jump
		"-A PREROUTING -s 10.7.0.0/24 -d 10.7.0.1/32 -i br-new -p tcp -j VEIL-HONEYPOT",
		// leaked by a crashed run on an older subnet
		"-A PREROUTING -s 172.30.0.0/16 -d 172.30.0.1/32 -i br-old -p tcp -j VEIL-HONEYPOT",
		// look-alikes that must never be touched
		"-A PREROUTING -j VEIL-HONEYPOT2",
		`-A PREROUTING -m comment --comment "-j VEIL-HONEYPOT" -j ACCEPT`,
		"-A OTHER -j VEIL-HONEYPOT",
		// unparseable line is skipped, not guessed at
		`-A PREROUTING --comment "broken -j VEIL-HONEYPOT`,
		"",
	}, "\n")
	want := [][]string{
		{"-s", "10.7.0.0/24", "-d", "10.7.0.1/32", "-i", "br-new", "-p", "tcp", "-j", "VEIL-HONEYPOT"},
		{"-s", "172.30.0.0/16", "-d", "172.30.0.1/32", "-i", "br-old", "-p", "tcp", "-j", "VEIL-HONEYPOT"},
	}
	if got := honeypotJumps(listing); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestRemoveHoneypotRulesDeletesEveryJumpByChainName(t *testing.T) {
	f := &fakeIPT{listing: strings.Join([]string{
		"-P PREROUTING ACCEPT",
		"-A PREROUTING -m addrtype --dst-type LOCAL -j DOCKER",
		"-A PREROUTING -s 172.30.0.0/16 -d 172.30.0.1/32 -i br-old -p tcp -j VEIL-HONEYPOT",
		"-A PREROUTING -s 10.7.0.0/24 -d 10.7.0.1/32 -i br-new -p tcp -j VEIL-HONEYPOT",
	}, "\n")}
	removeHoneypotRules(f.run)

	want := [][]string{
		{"-t", "nat", "-S", "PREROUTING"},
		{"-t", "nat", "-D", "PREROUTING", "-s", "172.30.0.0/16", "-d", "172.30.0.1/32", "-i", "br-old", "-p", "tcp", "-j", "VEIL-HONEYPOT"},
		{"-t", "nat", "-D", "PREROUTING", "-s", "10.7.0.0/24", "-d", "10.7.0.1/32", "-i", "br-new", "-p", "tcp", "-j", "VEIL-HONEYPOT"},
		{"-t", "nat", "-F", "VEIL-HONEYPOT"},
		{"-t", "nat", "-X", "VEIL-HONEYPOT"},
	}
	if !reflect.DeepEqual(f.calls, want) {
		t.Fatalf("calls:\n%q\nwant:\n%q", f.calls, want)
	}
}

func TestRemoveHoneypotRulesToleratesFailures(t *testing.T) {
	// Listing fails (no nat table yet) and the chain doesn't exist: still
	// attempts flush + delete, never touches anything else.
	f := &fakeIPT{listErr: errors.New("no chain"), failOn: "VEIL-HONEYPOT"}
	removeHoneypotRules(f.run)
	if d := f.deletes(); len(d) != 0 {
		t.Fatalf("unexpected deletes %q", d)
	}
	if n := len(f.calls); n != 3 {
		t.Fatalf("calls = %q, want list + flush + delete-chain", f.calls)
	}
}

func TestInstallHoneypotRules(t *testing.T) {
	scope := []string{"-i", "br-new", "-s", "10.7.0.0/24", "-d", "10.7.0.1", "-p", "tcp"}
	cat := func(parts ...[]string) []string {
		var out []string
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	create := []string{"-t", "nat", "-N", "VEIL-HONEYPOT"}
	exempt := cat([]string{"-t", "nat", "-A", "VEIL-HONEYPOT"}, scope, []string{"--dport", "53", "-j", "RETURN"})
	redirect := cat([]string{"-t", "nat", "-A", "VEIL-HONEYPOT"}, scope, []string{"-j", "REDIRECT", "--to-ports", "40000"})
	jump := cat([]string{"-t", "nat", "-A", "PREROUTING"}, scope, []string{"-j", "VEIL-HONEYPOT"})
	tests := []struct {
		name      string
		exemptDNS bool
		want      [][]string
	}{
		// The resolver serves TCP :53, so DNS-over-TCP (dig +tcp, truncation retries)
		// must reach it, not the honeypot: a false honeypot-hit and a "220" banner tell.
		// The RETURN precedes the REDIRECT, scoped like every other rule.
		{"resolver serves tcp/53: exempt before REDIRECT", true, [][]string{create, exempt, redirect, jump}},
		// The resolver's TCP listener failed: tcp/53 stays redirected so DNS-over-TCP
		// still lands on the Sink (honeypot-hit) instead of an unserved port.
		{"no tcp resolver: tcp/53 stays redirected", false, [][]string{create, redirect, jump}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeIPT{}
			if err := installHoneypotRules(f.run, "br-new", "10.7.0.0/24", "10.7.0.1", "40000", tt.exemptDNS); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(f.calls, tt.want) {
				t.Fatalf("calls:\n%q\nwant:\n%q", f.calls, tt.want)
			}
		})
	}
}

func TestInstallHoneypotRulesStopsOnError(t *testing.T) {
	f := &fakeIPT{failOn: "REDIRECT"}
	if err := installHoneypotRules(f.run, "br", "10.7.0.0/24", "10.7.0.1", "1", true); err == nil {
		t.Fatal("want error")
	}
	for _, c := range f.calls {
		if c[3] == "PREROUTING" {
			t.Fatalf("jump installed after chain failure: %q", c)
		}
	}
}

func TestReconcileHoneypotRemovesLeakedJumpsThenInstallsOne(t *testing.T) {
	f := &fakeIPT{listing: "-P PREROUTING ACCEPT\n" +
		"-A PREROUTING -s 172.30.0.0/16 -d 172.30.0.1/32 -i br-old -p tcp -j VEIL-HONEYPOT\n"}
	if err := reconcileHoneypotRules(f.run, "br-new", "10.7.0.0/24", "10.7.0.1", "40000", true); err != nil {
		t.Fatal(err)
	}
	var verbs []string
	for _, c := range f.calls {
		verbs = append(verbs, c[2]+" "+c[3])
	}
	want := []string{
		"-S PREROUTING", "-D PREROUTING", "-F VEIL-HONEYPOT", "-X VEIL-HONEYPOT",
		"-N VEIL-HONEYPOT", "-A VEIL-HONEYPOT", "-A VEIL-HONEYPOT", "-A PREROUTING",
	}
	if !reflect.DeepEqual(verbs, want) {
		t.Fatalf("sequence %q, want %q", verbs, want)
	}
}

// TestIPTArgvWaitsForXtablesLock: every real iptables call is prefixed with a
// bounded -w, so a legacy-backend run queues behind dockerd's or the host's
// holder of /run/xtables.lock instead of failing at once (iptables-nft accepts
// and ignores it). The caller's argv follows unchanged.
func TestIPTArgvWaitsForXtablesLock(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"list", []string{"-t", "nat", "-S", "PREROUTING"}, []string{"-w", "3", "-t", "nat", "-S", "PREROUTING"}},
		{"delete chain", []string{"-t", "nat", "-X", honeypotChain}, []string{"-w", "3", "-t", "nat", "-X", honeypotChain}},
		{"no args", nil, []string{"-w", "3"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := iptArgv(tc.in...); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("iptArgv(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
