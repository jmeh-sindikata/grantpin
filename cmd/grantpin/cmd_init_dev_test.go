//go:build grantpin_dev

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitCreatesVault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GRANTPIN_HOME", filepath.Join(home, "g"))
	run := func() (string, error) {
		var out bytes.Buffer
		root := newRootCmd()
		root.SetOut(&out)
		root.SetErr(&out)
		root.SetArgs([]string{"init"})
		err := root.Execute()
		return out.String(), err
	}
	out, err := run()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(home, "g", "vault.db")
	if !strings.Contains(out, p) {
		t.Fatalf("output %q lacks path", out)
	}
	st, err := os.Stat(p)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("stat %v %v", st, err)
	}
	if _, err := run(); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("second init err = %v", err)
	}
}
