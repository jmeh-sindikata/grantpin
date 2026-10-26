//go:build darwin && cgo

package darwin

import (
	"context"
	"errors"
	"testing"

	"github.com/jmeh-sindikata/grantpin/internal/presence"
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

// Unwrap follows the blob's own mode byte, whatever the store's options or
// resolved mode are. The hooks stand in for Security.framework.
func TestUnwrapFollowsTheBlobsMode(t *testing.T) {
	ctx := context.Background()
	blobSE := encodeBlob(ModeSecureEnclave, []byte("se-payload"))
	blobKC := encodeBlob(ModeKeychain, []byte("kc-payload"))
	for _, fallback := range []bool{false, true} {
		for _, mode := range []Mode{0, ModeSecureEnclave, ModeKeychain} {
			s := fakeStore(mode, fallback)
			var gotSE, gotKC string
			s.unwrapSEHook = func(p []byte) ([]byte, error) { gotSE = string(p); return []byte("key-se"), nil }
			s.unwrapKCHook = func(p, hdr []byte) ([]byte, error) {
				gotKC = string(p)
				if len(hdr) != 2 || hdr[0] != byte(ModeKeychain) {
					t.Errorf("bad header %v", hdr)
				}
				return []byte("key-kc"), nil
			}
			if k, err := s.Unwrap(ctx, blobKC); err != nil || string(k) != "key-kc" || gotKC != "kc-payload" || gotSE != "" {
				t.Errorf("fallback=%v mode=%v: keychain blob -> %q %v (se=%q kc=%q)", fallback, mode, k, err, gotSE, gotKC)
			}
			if k, err := s.Unwrap(ctx, blobSE); err != nil || string(k) != "key-se" || gotSE != "se-payload" {
				t.Errorf("fallback=%v mode=%v: SE blob -> %q %v (se=%q)", fallback, mode, k, err, gotSE)
			}
		}
	}
}

func TestUnwrapRejectsUnknownModeBlob(t *testing.T) {
	s := fakeStore(0, true)
	s.unwrapSEHook = func([]byte) ([]byte, error) { t.Error("hook called"); return nil, nil }
	s.unwrapKCHook = func(_, _ []byte) ([]byte, error) { t.Error("hook called"); return nil, nil }
	if _, err := s.Unwrap(context.Background(), []byte{9, FormatVersion, 1, 2, 3}); !errors.Is(err, ErrBadBlob) {
		t.Errorf("err = %v", err)
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
