package daemon

import (
	"fmt"
	"net"
	"os"
)

// checkPeerUID is the pure comparison behind the peer-credential check: the
// connecting process must run as the same user as the daemon.
func checkPeerUID(peer uint32, self int) error {
	if self < 0 || uint64(peer) != uint64(self) {
		return fmt.Errorf("peer uid %d does not match daemon uid %d", peer, self)
	}
	return nil
}

// checkPeer reads the kernel-attested credentials of c and compares the UID
// with ours. It fails closed: any error reading credentials rejects the peer.
func checkPeer(c *net.UnixConn) error {
	uid, err := peerUID(c)
	if err != nil {
		return fmt.Errorf("read peer credentials: %w", err)
	}
	return checkPeerUID(uid, os.Getuid())
}

// controlFD runs f with the raw descriptor of c.
func controlFD(c *net.UnixConn, f func(fd int) error) error {
	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var ferr error
	if err := raw.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}
