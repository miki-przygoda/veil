package main

import (
	"testing"
	"time"
)

func TestParseServices(t *testing.T) {
	specs, err := parseServices("http:80,ssh:22")
	if err != nil {
		t.Fatalf("parseServices: %v", err)
	}
	if len(specs) != 2 || specs[0] != (serviceSpec{"http", 80}) || specs[1] != (serviceSpec{"ssh", 22}) {
		t.Errorf("specs = %+v", specs)
	}
	for _, bad := range []string{"http", "http:0", "http:70000", "smb:445", "http:x"} {
		if _, err := parseServices(bad); err == nil {
			t.Errorf("parseServices(%q) = nil err, want error", bad)
		}
	}
}

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]string{
		"-serve", "smtp:25,imap:143", "-client", "web.veil.local, git.veil.local",
		"-hostname", "mail.veil.local", "-resolver", "172.20.0.1:53",
		"-client-interval", "500ms", "-seed", "7",
	})
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.services) != 2 || cfg.hostname != "mail.veil.local" || cfg.resolver != "172.20.0.1:53" {
		t.Errorf("cfg = %+v", cfg)
	}
	if len(cfg.targets) != 2 || cfg.targets[0] != "web.veil.local" || cfg.targets[1] != "git.veil.local" {
		t.Errorf("targets = %v (whitespace not trimmed?)", cfg.targets)
	}
	if cfg.interval != 500*time.Millisecond || cfg.seed != 7 {
		t.Errorf("interval/seed = %v/%d", cfg.interval, cfg.seed)
	}
	// default hostname is filled when omitted
	d, err := parseConfig(nil)
	if err != nil || d.hostname == "" {
		t.Errorf("default hostname empty: %+v err=%v", d, err)
	}
}
