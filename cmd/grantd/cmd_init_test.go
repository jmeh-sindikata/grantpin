//go:build !grantd_dev

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInitWithoutKeystoreBackend(t *testing.T) {
	t.Setenv("GRANTD_HOME", t.TempDir())
	root := newRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"init"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "keystore") {
		t.Fatalf("err = %v, want a clear keystore error", err)
	}
}
