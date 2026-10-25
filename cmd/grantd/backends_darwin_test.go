//go:build !grantd_dev && darwin && cgo

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"grantd/internal/approve"
	approvedarwin "grantd/internal/approve/darwin"
	"grantd/internal/keystore"
	keystoredarwin "grantd/internal/keystore/darwin"
	"grantd/internal/presence"
)

// These tests replace the constructors: nothing here touches the Keychain, the
// Secure Enclave or any prompt.

type spyKS struct{}

func (spyKS) Wrap(_ context.Context, b []byte) ([]byte, error)   { return b, nil }
func (spyKS) Unwrap(_ context.Context, b []byte) ([]byte, error) { return b, nil }
func (spyKS) Tier() presence.PresenceTier                        { return presence.TierHardware }

type spyAP struct{}

func (spyAP) Ask(context.Context, approve.ApprovalRequest) (approve.Decision, error) {
	return approve.Decision{}, errors.New("spy")
}
func (spyAP) Tier() presence.PresenceTier { return presence.TierHardware }

func TestDarwinKeyStoreGetsFallbackOption(t *testing.T) {
	old := newDarwinKeyStore
	t.Cleanup(func() { newDarwinKeyStore = old })
	var gotOpts int
	newDarwinKeyStore = func(opts ...keystoredarwin.Option) (keystore.KeyStore, error) {
		gotOpts = len(opts)
		return spyKS{}, nil
	}
	for _, fb := range []bool{false, true} {
		gotOpts = 0
		ks, err := openKeyStore(backendConfig{KeychainFallback: fb})
		if err != nil || ks.Tier() != presence.TierHardware {
			t.Fatalf("fallback=%v: %v %v", fb, ks, err)
		}
		if gotOpts != 1 {
			t.Errorf("fallback=%v: %d options passed, want exactly the fallback option", fb, gotOpts)
		}
	}
	newDarwinKeyStore = func(...keystoredarwin.Option) (keystore.KeyStore, error) { return nil, errors.New("boom") }
	if _, err := openKeyStore(backendConfig{}); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
}

func TestDarwinApproverIsConstructedWithDefaults(t *testing.T) {
	old := newDarwinApprover
	t.Cleanup(func() { newDarwinApprover = old })
	called := 0
	newDarwinApprover = func(opts ...approvedarwin.Option) (approve.Approver, error) {
		called++
		if len(opts) != 0 {
			t.Errorf("%d options passed; the chooser must be left at its default (on)", len(opts))
		}
		return spyAP{}, nil
	}
	ap, err := openApprover()
	if err != nil || ap.Tier() != presence.TierHardware || called != 1 {
		t.Fatalf("%v %v called=%d", ap, err, called)
	}
	newDarwinApprover = func(...approvedarwin.Option) (approve.Approver, error) { return nil, errors.New("boom") }
	if _, err := openApprover(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Errorf("err = %v", err)
	}
}
