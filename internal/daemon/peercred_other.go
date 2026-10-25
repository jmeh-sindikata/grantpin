//go:build !darwin && !linux

package daemon

import (
	"errors"
	"net"
)

// peerUID has no implementation here, so every connection is refused.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are not supported on this platform")
}
