package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpListsAllVerbs(t *testing.T) {
	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"init", "set", "list", "masked", "delete", "show", "run", "grants", "audit", "import", "daemon", "service", "mcp", "status"} {
		if !strings.Contains(out.String(), "\n  "+v+" ") {
			t.Errorf("--help does not list %q:\n%s", v, out.String())
		}
	}
}
