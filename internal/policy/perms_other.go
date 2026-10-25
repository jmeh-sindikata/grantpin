//go:build !unix

package policy

import "os"

// checkOwnerAndMode is a no-op off unix: POSIX ownership/mode bits are not
// meaningful there. Revisit when the Windows backend lands (v0.3).
func checkOwnerAndMode(string, os.FileInfo) error { return nil }
