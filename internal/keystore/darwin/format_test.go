package darwin

import (
	"bytes"
	"errors"
	"testing"
)

func TestBlobHeaderRoundTrip(t *testing.T) {
	for _, m := range []Mode{ModeSecureEnclave, ModeKeychain} {
		b := encodeBlob(m, []byte("payload"))
		if b[0] != byte(m) || b[1] != FormatVersion {
			t.Fatalf("bad header % x", b[:2])
		}
		gm, p, err := decodeBlob(b)
		if err != nil || gm != m || string(p) != "payload" {
			t.Fatalf("decode: %v %v %q", gm, err, p)
		}
	}
}

func TestDecodeBlobRejects(t *testing.T) {
	cases := map[string][]byte{
		"nil":          nil,
		"short":        {1, 1},
		"header only":  {1, 1},
		"unknown mode": {9, 1, 0},
		"mode zero":    {0, 1, 0},
		"bad version":  {1, 2, 0},
	}
	for name, b := range cases {
		if _, _, err := decodeBlob(b); !errors.Is(err, ErrBadBlob) {
			t.Errorf("%s: got %v, want ErrBadBlob", name, err)
		}
	}
}

func TestSealOpenKEK(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, KEKSize)
	hdr := []byte{byte(ModeKeychain), FormatVersion}
	pt := []byte("0123456789abcdef0123456789abcdef")
	sealed, err := sealKEK(kek, pt, hdr)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, pt) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := openKEK(kek, sealed, hdr)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("open: %v", err)
	}
	// Nonces must be fresh.
	s2, _ := sealKEK(kek, pt, hdr)
	if bytes.Equal(sealed, s2) {
		t.Fatal("nonce reuse")
	}
}

func TestOpenKEKRefusals(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, KEKSize)
	hdr := []byte{byte(ModeKeychain), FormatVersion}
	sealed, _ := sealKEK(kek, []byte("secret-data-key-secret-data-key!"), hdr)

	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := openKEK(kek, tampered, hdr); err == nil {
		t.Error("tampered ciphertext accepted")
	}
	if _, err := openKEK(kek, sealed, []byte{byte(ModeSecureEnclave), FormatVersion}); err == nil {
		t.Error("header (AAD) change accepted")
	}
	other := bytes.Repeat([]byte{8}, KEKSize)
	_, err := openKEK(other, sealed, hdr)
	if err == nil {
		t.Error("wrong KEK accepted")
	}
	if err != nil && bytes.Contains([]byte(err.Error()), []byte("secret-data-key")) {
		t.Error("error leaks plaintext")
	}
	if _, err := openKEK(kek, sealed[:5], hdr); !errors.Is(err, ErrBadBlob) {
		t.Errorf("short: %v", err)
	}
	if _, err := sealKEK(kek[:16], nil, hdr); err == nil {
		t.Error("short KEK accepted")
	}
}

func TestOptions(t *testing.T) {
	if newConfig(nil).allowFallback {
		t.Error("fallback must default to off")
	}
	if !newConfig([]Option{WithAllowKeychainFallback(true)}).allowFallback {
		t.Error("option not applied")
	}
	c := newConfig([]Option{WithAllowKeychainFallback(true), nil, WithAllowKeychainFallback(false)})
	if c.allowFallback {
		t.Error("last option should win")
	}
}

func TestSecErrorClassification(t *testing.T) {
	for _, code := range []int{statusUnimplemented, statusNotAvailable, statusMissingEntitlement} {
		if !isSEUnavailable(&SecError{Op: "x", Code: code}) {
			t.Errorf("code %d should mean SE unavailable", code)
		}
	}
	for _, code := range []int{statusItemNotFound, statusDuplicateItem, -128, 0} {
		if isSEUnavailable(&SecError{Op: "x", Code: code}) {
			t.Errorf("code %d must not mean SE unavailable", code)
		}
	}
	if isSEUnavailable(errors.New("plain")) {
		t.Error("non-SecError classified")
	}
	e := &SecError{Op: "op", Code: -4, Msg: "nope"}
	if got := e.Error(); got != "darwin keystore: op: nope (OSStatus -4)" {
		t.Errorf("got %q", got)
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3}
	zero(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Error("not zeroed")
	}
}

func TestModeString(t *testing.T) {
	if ModeSecureEnclave.String() != ModeNameSecureEnclave || ModeKeychain.String() != ModeNameKeychain {
		t.Error("names")
	}
}
