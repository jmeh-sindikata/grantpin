//go:build darwin && cgo

package darwin

import (
	"context"
	"errors"
	"testing"

	"grantd/internal/presence"
)

// These tests need no Keychain/SE access: they use blobs that are rejected
// before any Security.framework call is made. newStore itself only performs
// non-prompting existence lookups, so we construct Store literals directly to
// keep the unit tests off the Keychain entirely.

func fakeStore(mode Mode, fallback bool) *Store {
	return &Store{cfg: config{allowFallback: fallback}, mode: mode, tag: "x", svc: "x", acc: "x"}
}

func TestTierByMode(t *testing.T) {
	cases := []struct {
		mode     Mode
		fallback bool
		want     presence.PresenceTier
	}{
		{ModeSecureEnclave, false, presence.TierHardware},
		{ModeSecureEnclave, true, presence.TierHardware},
		{ModeKeychain, true, presence.TierDialog},
		{0, false, presence.TierHardware},
		{0, true, presence.TierDialog}, // weakest possible while unresolved
	}
	for _, c := range cases {
		if got := fakeStore(c.mode, c.fallback).Tier(); got != c.want {
			t.Errorf("mode=%v fallback=%v: tier %v, want %v", c.mode, c.fallback, got, c.want)
		}
	}
}

func TestModeNames(t *testing.T) {
	if fakeStore(0, false).Mode() != ModeNameUnresolved ||
		fakeStore(ModeSecureEnclave, false).Mode() != ModeNameSecureEnclave ||
		fakeStore(ModeKeychain, true).Mode() != ModeNameKeychain {
		t.Error("mode names")
	}
}

func TestUnwrapModeMismatch(t *testing.T) {
	ctx := context.Background()
	blobSE := encodeBlob(ModeSecureEnclave, []byte("x"))
	blobKC := encodeBlob(ModeKeychain, []byte("x"))

	// Fallback not enabled: keychain blob refused outright.
	if _, err := fakeStore(0, false).Unwrap(ctx, blobKC); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("kc blob, fallback off: %v", err)
	}
	// Store resolved to keychain: SE blob refused.
	if _, err := fakeStore(ModeKeychain, true).Unwrap(ctx, blobSE); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("se blob on kc store: %v", err)
	}
	// Store resolved to SE: keychain blob refused.
	if _, err := fakeStore(ModeSecureEnclave, true).Unwrap(ctx, blobKC); !errors.Is(err, ErrModeMismatch) {
		t.Errorf("kc blob on se store: %v", err)
	}
}

func TestUnwrapRejectsGarbageAndCancelled(t *testing.T) {
	s := fakeStore(0, true)
	if _, err := s.Unwrap(context.Background(), []byte{1}); !errors.Is(err, ErrBadBlob) {
		t.Errorf("short: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Unwrap(ctx, encodeBlob(ModeKeychain, []byte("x"))); !errors.Is(err, context.Canceled) {
		t.Errorf("unwrap cancelled: %v", err)
	}
	if _, err := s.Wrap(ctx, []byte("k")); !errors.Is(err, context.Canceled) {
		t.Errorf("wrap cancelled: %v", err)
	}
	if _, err := s.Wrap(context.Background(), nil); !errors.Is(err, ErrEmptyKey) {
		t.Errorf("empty: %v", err)
	}
}
