//go:build !grantd_dev

package main

import (
	"strings"
	"testing"
)

// Without the dev tag and without the platform backends wired in, the daemon
// must refuse to start (never fall back to a no-human approver).
func TestDaemonRefusesWithoutBackends(t *testing.T) {
	t.Setenv("GRANTD_HOME", t.TempDir())
	err := runDaemon(t.Context(), shortSocket(t), nil)
	if err == nil || !strings.Contains(err.Error(), "start daemon") || !strings.Contains(err.Error(), "yet") {
		t.Fatalf("err = %v", err)
	}
}
