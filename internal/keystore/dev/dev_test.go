//go:build grantd_dev

package dev

import (
	"bytes"
	"context"
	"testing"

	"grantd/internal/keystore"
	"grantd/internal/presence"
)

func TestSatisfiesKeyStore(t *testing.T) {
	var ks keystore.KeyStore = New()
	if ks.Tier() != presence.TierNone {
		t.Fatalf("tier = %v, want none", ks.Tier())
	}
	ctx := context.Background()
	key := bytes.Repeat([]byte{7}, 32)
	w, err := ks.Wrap(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w, key) {
		t.Fatal("wrapped blob contains plaintext key")
	}
	got, err := ks.Unwrap(ctx, w)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrap = %x, %v", got, err)
	}
	w[len(w)-1] ^= 1
	if _, err := ks.Unwrap(ctx, w); err == nil {
		t.Fatal("tampered blob must fail")
	}
	if _, err := ks.Unwrap(ctx, []byte{1, 2}); err == nil {
		t.Fatal("short blob must fail")
	}
}

func TestOpenAndEnabled(t *testing.T) {
	if !Enabled {
		t.Fatal("Enabled must be true under grantd_dev")
	}
	if ks, err := Open(); err != nil || ks == nil {
		t.Fatalf("Open = %v, %v", ks, err)
	}
}
