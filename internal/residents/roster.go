package residents

// Host is one roster entry: a synthetic LAN host, its static-IP offset into the
// veil-net subnet, and the veil-resident roles it plays. Topology lives here (not
// in the veil-resident binary, which is a generic host).
type Host struct {
	Name     string // FQDN / hostname, e.g. "web.veil.local"
	Offset   int    // host offset into the veil-net subnet (concrete IP derived at runtime)
	Serve    string // veil-resident -serve value ("" => pure client)
	Client   string // veil-resident -client value ("" => pure server)
	IsServer bool   // true => Name/IP goes into the resolver's World.Names
	// Trusted => the escape classifier ignores this host's traffic as never the
	// subject's (see Fleet.TrustedIPs). Set it only on a host the subject cannot
	// take over: a deliberately vulnerable target must stay untrusted, or a
	// subject pivoting through it would escape unseen.
	Trusted bool
}

// DefaultRoster is the small-office LAN: a few servers the subject can probe plus
// client workstations generating ambient traffic. Servers get low offsets, clients
// high — clear of the subject box's dynamic low IP. All are Trusted: each runs
// only fixed veil-resident roles (canned banners and line-capped protocol stubs),
// which nothing the subject sends can take over.
func DefaultRoster() []Host {
	return []Host{
		{Name: "web.veil.local", Offset: 10, Serve: "http:80,ssh:22", IsServer: true, Trusted: true},
		{Name: "mail.veil.local", Offset: 11, Serve: "smtp:25,imap:143,ssh:22", IsServer: true, Trusted: true},
		{Name: "git.veil.local", Offset: 12, Serve: "http:80,ssh:22", IsServer: true, Trusted: true},
		{Name: "bastion.veil.local", Offset: 13, Serve: "ssh:22", IsServer: true, Trusted: true},
		{Name: "alice-pc", Offset: 50, Client: "web.veil.local,git.veil.local,mail.veil.local", Trusted: true},
		{Name: "bob-laptop", Offset: 51, Client: "web.veil.local,git.veil.local", Trusted: true},
		{Name: "carol-pc", Offset: 52, Client: "git.veil.local,mail.veil.local", Trusted: true},
	}
}
