//go:build unix

package mcp

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// A child that exits must be reaped by the shim, not left as a zombie (a
// zombie still answers kill(pid, 0); a reaped pid gives ESRCH).
func TestSpawnDetachedReapsExitedChild(t *testing.T) {
	path, err := exec.LookPath("true")
	if err != nil {
		t.Skip("no true(1)")
	}
	pid, err := spawnDetached(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still exists after exiting: zombie", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSpawnDetachedReportsStartFailure(t *testing.T) {
	if _, err := spawnDetached("/nonexistent/grantd", nil); err == nil {
		t.Fatal("expected an error")
	}
}
