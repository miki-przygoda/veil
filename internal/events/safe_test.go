package events

import "testing"

func TestSafeField(t *testing.T) {
	if got := SafeField("<script>alert(1)</script>", 100); got == "<script>alert(1)</script>" {
		t.Errorf("SafeField left HTML metacharacters intact: %q", got)
	}
	if got := SafeField("web.veil.local:8080/path_a-b", 100); got != "web.veil.local:8080/path_a-b" {
		t.Errorf("SafeField mangled a safe string: %q", got)
	}
	if got := SafeField("aaaaaaaaaaaaaaaa", 4); len(got) > 4 {
		t.Errorf("SafeField did not cap length: %q", got)
	}
}
