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
}

// DefaultRoster is the small-office LAN: a few servers the subject can probe plus
// client workstations generating ambient traffic. Servers get low offsets, clients
// high — clear of the subject box's dynamic low IP.
func DefaultRoster() []Host {
	return []Host{
		{Name: "web.veil.local", Offset: 10, Serve: "http:80,ssh:22", IsServer: true},
		{Name: "mail.veil.local", Offset: 11, Serve: "smtp:25,imap:143,ssh:22", IsServer: true},
		{Name: "git.veil.local", Offset: 12, Serve: "http:80,ssh:22", IsServer: true},
		{Name: "bastion.veil.local", Offset: 13, Serve: "ssh:22", IsServer: true},
		{Name: "alice-pc", Offset: 50, Client: "web.veil.local,git.veil.local,mail.veil.local"},
		{Name: "bob-laptop", Offset: 51, Client: "web.veil.local,git.veil.local"},
		{Name: "carol-pc", Offset: 52, Client: "git.veil.local,mail.veil.local"},
	}
}
