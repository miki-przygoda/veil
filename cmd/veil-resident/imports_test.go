package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestImportsAreStdlibOnly asserts the veil-resident dependency closure is
// standard-library only. A resident runs inside the world on the subject's
// network; importing any host package (events bus, docker, netfabric, viz) would
// be an inside-out channel to the observer. Stdlib import paths have no dot in
// their first path segment; external ones start with a domain (github.com/...).
func TestImportsAreStdlibOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	const own = "github.com/miki-przygoda/veil/cmd/veil-resident"
	for _, pkg := range strings.Fields(string(out)) {
		if pkg == own {
			continue // the package under test is allowed to be itself
		}
		if first, _, _ := strings.Cut(pkg, "/"); strings.Contains(first, ".") {
			t.Errorf("non-stdlib dependency: %s (resident must import stdlib only)", pkg)
		}
	}
}
