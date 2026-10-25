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

func TestVerbsReturnNotImplemented(t *testing.T) {
	for _, args := range [][]string{
		{"set", "A"}, {"list"}, {"masked", "A"}, {"delete", "A"}, {"show", "A"},
		{"run", "--secrets", "A", "--", "true"}, {"grants"}, {"grants", "list"}, {"grants", "revoke", "x"},
		{"audit"}, {"audit", "list"}, {"audit", "verify"}, {"audit", "export", "--csv"},
		{"import", ".env"},
	} {
		root := newRootCmd()
		root.SetOut(&bytes.Buffer{})
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(args)
		if err := root.Execute(); err == nil || err.Error() != "not implemented" {
			t.Errorf("%v: err = %v, want not implemented", args, err)
		}
	}
}
