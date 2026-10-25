//go:build darwin || linux

package daemon

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// The positive path: a connection from this very process (same UID) reports
// our UID and passes the check.
func TestPeerCredSameUID(t *testing.T) {
	path := filepath.Join(shortDir(t), "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	client, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	defer server.Close()

	uc := server.(*net.UnixConn)
	uid, err := peerUID(uc)
	if err != nil {
		t.Fatal(err)
	}
	if int(uid) != os.Getuid() {
		t.Errorf("peerUID = %d, want %d", uid, os.Getuid())
	}
	if err := checkPeer(uc); err != nil {
		t.Errorf("checkPeer: %v", err)
	}

	// Closed connection: credential lookup fails closed.
	uc.Close()
	if err := checkPeer(uc); err == nil {
		t.Error("checkPeer on closed conn succeeded")
	}
}
