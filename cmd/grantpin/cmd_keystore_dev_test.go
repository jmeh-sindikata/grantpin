//go:build grantpin_dev

package main

import "testing"

// With the real (dev) key store wired in, there is never key material, so both
// kinds report "not there" with exit 3, and nothing touches a Keychain.
func TestKeystoreDeleteWithTheDevKeystore(t *testing.T) {
	for _, flag := range []string{"--fallback", "--hardware"} {
		out, _, err := cli(t, "", "keystore", "delete", flag, "--yes", "--socket", shortSocket(t))
		if exitCodeOf(err) != 3 || out != "" {
			t.Errorf("%s: code=%d out=%q err=%v", flag, exitCodeOf(err), out, err)
		}
	}
}
