package subject

import (
	"bufio"
	"io"
	"strings"
)

// ParseScript reads a subject command file: one command per line, order
// preserved. Blank lines and lines whose first non-space rune is '#' are skipped
// (comments). Leading/trailing whitespace on a command is trimmed.
func ParseScript(r io.Reader) ([]string, error) {
	var cmds []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024) // tolerate long command lines
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cmds = append(cmds, line)
	}
	return cmds, sc.Err()
}
