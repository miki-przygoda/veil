package subject

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseScript(t *testing.T) {
	in := "# a comment\n\nls -la\n   \n  # indented comment\nwhoami\n"
	cmds, err := ParseScript(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseScript: %v", err)
	}
	want := []string{"ls -la", "whoami"}
	if !reflect.DeepEqual(cmds, want) {
		t.Errorf("ParseScript = %v, want %v", cmds, want)
	}
}
