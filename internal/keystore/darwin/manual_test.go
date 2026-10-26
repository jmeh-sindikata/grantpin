//go:build darwin && cgo

package darwin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"testing"

	"grantd/internal/keystore"
)

// Everything here touches the real Secure Enclave / Keychain. It is skipped
// unless GRANTD_MANUAL_TEST=1. See docs/MANUAL-TEST-MACOS.md.
//
// Tests use throwaway, uniquely named keys so they never touch the real vault
// key (tag dev.grantd.vault-kek).

func manual(t *testing.T) {
	t.Helper()
	if os.Getenv("GRANTD_MANUAL_TEST") != "1" {
		t.Skip("set GRANTD_MANUAL_TEST=1 to run (touches the Keychain / Secure Enclave)")
	}
}

func tempNames(t *testing.T) (tag, svc, acc string) {
	t.Helper()
	var r [6]byte
	_, _ = rand.Read(r[:])
	id := hex.EncodeToString(r[:])
	return "dev.grantd.test." + id, "dev.grantd.test", "vault-kek-" + id
}

func openTemp(t *testing.T, fallback bool) *Store {
	t.Helper()
	tag, svc, acc := tempNames(t)
	s, err := newStore(config{allowFallback: fallback}, tag, svc, acc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.deleteKeys(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})
	return s
}

func TestManualSecureEnclaveRoundTrip(t *testing.T) {
	manual(t)
	ctx := context.Background()
	s := openTemp(t, false)
	if s.Mode() != ModeNameUnresolved {
		t.Fatalf("fresh store mode %q", s.Mode())
	}
	dk := bytes.Repeat([]byte{0xAB}, 32)
	blob, err := s.Wrap(ctx, dk)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if s.Mode() != ModeNameSecureEnclave {
		t.Fatalf("mode %q", s.Mode())
	}
	if blob[0] != byte(ModeSecureEnclave) || bytes.Contains(blob, dk) {
		t.Fatal("bad blob")
	}
	got, err := s.Unwrap(ctx, blob)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("unwrap: %v", err)
	}

	// A second Store with the same names finds the existing key.
	s2, err := newStore(config{}, s.tag, s.svc, s.acc)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.Mode() != ModeNameSecureEnclave {
		t.Fatalf("second New did not find key: mode %q", s2.Mode())
	}
	got, err = s2.Unwrap(ctx, blob)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("second store unwrap: %v", err)
	}

	// Tamper: flip a bit in the ECIES payload.
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 1
	if _, err := s2.Unwrap(ctx, bad); err == nil {
		t.Fatal("tampered blob accepted")
	}
}

func TestManualFallbackRoundTrip(t *testing.T) {
	manual(t)
	ctx := context.Background()
	s := openTemp(t, true)
	dk := bytes.Repeat([]byte{0xCD}, 32)
	blob, err := s.kcWrapForTest(dk)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if blob[0] != byte(ModeKeychain) {
		t.Fatal("bad mode byte")
	}
	got, err := s.Unwrap(ctx, blob)
	if err != nil || !bytes.Equal(got, dk) {
		t.Fatalf("unwrap: %v", err)
	}
	bad := append([]byte(nil), blob...)
	bad[len(bad)-1] ^= 1
	if _, err := s.Unwrap(ctx, bad); err == nil {
		t.Fatal("tampered blob accepted")
	}
}

// The Deleter methods remove a throwaway key and report ErrNoKeyMaterial the
// second time. (Unique names: the real vault key is never touched.)
func TestManualDeleteKeyMaterial(t *testing.T) {
	manual(t)
	ctx := context.Background()
	s := openTemp(t, true)
	if err := s.DeleteFallbackKEK(ctx); !errors.Is(err, keystore.ErrNoKeyMaterial) {
		t.Fatalf("delete with no fallback item: %v", err)
	}
	if _, err := s.kcWrapForTest(bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteFallbackKEK(ctx); err != nil {
		t.Fatalf("delete fallback: %v", err)
	}
	if err := s.DeleteFallbackKEK(ctx); !errors.Is(err, keystore.ErrNoKeyMaterial) {
		t.Fatalf("second delete fallback: %v", err)
	}

	if _, err := s.Wrap(ctx, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Skipf("no usable Secure Enclave here: %v", err)
	}
	if err := s.DeleteSecureEnclaveKey(ctx); err != nil {
		t.Fatalf("delete Secure Enclave key: %v", err)
	}
	if err := s.DeleteSecureEnclaveKey(ctx); !errors.Is(err, keystore.ErrNoKeyMaterial) {
		t.Fatalf("second delete Secure Enclave key: %v", err)
	}
}

// TestManualRemoveProductionKey deletes the REAL vault key. Destructive: the
// vault becomes permanently unreadable. Requires an extra explicit opt-in.
func TestManualRemoveProductionKey(t *testing.T) {
	manual(t)
	if os.Getenv("GRANTD_MANUAL_REMOVE_PRODUCTION_KEY") != "yes" {
		t.Skip("set GRANTD_MANUAL_REMOVE_PRODUCTION_KEY=yes to delete the real vault key")
	}
	s, err := newStore(config{allowFallback: true}, KeyTag, KeychainService, KeychainAccount)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.deleteKeys(); err != nil {
		t.Fatal(err)
	}
}
