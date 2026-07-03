package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type serviceSpec struct {
	proto string
	port  int
}

type config struct {
	services []serviceSpec
	targets  []string
	hostname string
	resolver string
	interval time.Duration
	seed     int64
}

var supportedProtos = map[string]bool{"http": true, "smtp": true, "imap": true, "ssh": true}

// parseConfig parses the resident's CLI. A bad -serve spec is a hard error so a
// misconfigured resident fails visibly at container start.
func parseConfig(args []string) (config, error) {
	fs := flag.NewFlagSet("veil-resident", flag.ContinueOnError)
	serve := fs.String("serve", "", "comma proto:port list (http,smtp,imap,ssh), e.g. http:80,ssh:22")
	client := fs.String("client", "", "comma target hosts for the traffic loop")
	hostname := fs.String("hostname", "", "this resident's name (feeds banners); default os.Hostname()")
	resolver := fs.String("resolver", "", "DNS server host:port for the client loop; default system resolver")
	interval := fs.Duration("client-interval", 3*time.Second, "base cadence between client actions")
	seed := fs.Int64("seed", 0, "RNG seed for reproducible traffic; 0 = time-based")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	specs, err := parseServices(*serve)
	if err != nil {
		return config{}, err
	}
	hn := *hostname
	if hn == "" {
		if h, _ := os.Hostname(); h != "" {
			hn = h
		} else {
			hn = "resident"
		}
	}
	return config{
		services: specs,
		targets:  splitNonEmpty(*client),
		hostname: hn,
		resolver: *resolver,
		interval: *interval,
		seed:     *seed,
	}, nil
}

func parseServices(s string) ([]serviceSpec, error) {
	var out []serviceSpec
	for _, item := range splitNonEmpty(s) {
		proto, portStr, ok := strings.Cut(item, ":")
		if !ok {
			return nil, fmt.Errorf("bad service spec %q (want proto:port)", item)
		}
		proto = strings.ToLower(proto)
		if !supportedProtos[proto] {
			return nil, fmt.Errorf("unsupported proto %q", proto)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("bad port %q in %q", portStr, item)
		}
		out = append(out, serviceSpec{proto: proto, port: port})
	}
	return out, nil
}

// splitNonEmpty splits on commas, trims whitespace, drops empties.
func splitNonEmpty(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
