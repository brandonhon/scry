package cli

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/bhoneycutt/scry/internal/script"
)

// runListScripts loads every --script FILE, prints one line per script, and
// returns without running a scan.
func runListScripts(w io.Writer, files []string) error {
	if len(files) == 0 {
		return fmt.Errorf("--list-scripts requires at least one --script FILE")
	}
	for _, f := range files {
		s, err := script.Load(f)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, formatScriptLine(s))
	}
	return nil
}

func formatScriptLine(s *script.Script) string {
	var ports string
	switch {
	case s.AnyPort:
		ports = "any"
	case len(s.Ports) == 0:
		ports = "(none)"
	default:
		parts := make([]string, len(s.Ports))
		for i, p := range s.Ports {
			parts[i] = strconv.Itoa(int(p))
		}
		ports = strings.Join(parts, ",")
	}
	desc := s.Description
	if desc == "" {
		desc = "(no description)"
	}
	return fmt.Sprintf("%-20s  ports=%-30s  %s", s.Name, ports, desc)
}
