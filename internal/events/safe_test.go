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
	// A non-allowlisted byte in the capped window expands to \xNN, so the OUTPUT
	// can exceed max even though max bounds the INPUT.
	if got := SafeField("<<<<", 2); got != `\x3c\x3c` {
		t.Errorf("SafeField(\"<<<<\", 2) = %q, want \\x3c\\x3c (output may exceed max)", got)
	}
}
