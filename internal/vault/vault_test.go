package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"grantd/internal/presence"
)

// fakeKS is a test-only KeyStore (AES-GCM under a random per-instance key).
type fakeKS struct {
	aead       cipher.AEAD
	tier       presence.PresenceTier
	wrapErr    error
	unwrapErr  error
	unwrapOut  []byte // if set, returned instead of the real key
	unwrapCall int
}

func newFakeKS(tier presence.PresenceTier) *fakeKS {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(b)
	return &fakeKS{aead: a, tier: tier}
}

func (f *fakeKS) Wrap(_ context.Context, dk []byte) ([]byte, error) {
	if f.wrapErr != nil {
		return nil, f.wrapErr
	}
	n := make([]byte, f.aead.NonceSize())
	_, _ = rand.Read(n)
	return f.aead.Seal(n, n, dk, nil), nil
}

func (f *fakeKS) Unwrap(_ context.Context, w []byte) ([]byte, error) {
	f.unwrapCall++
	if f.unwrapErr != nil {
		return nil, f.unwrapErr
	}
	if f.unwrapOut != nil {
		return f.unwrapOut, nil
	}
	ns := f.aead.NonceSize()
	if len(w) < ns {
		return nil, errors.New("short")
	}
	return f.aead.Open(nil, w[:ns], w[ns:], nil)
}

func (f *fakeKS) Tier() presence.PresenceTier { return f.tier }

var ctx = context.Background()

func newVault(t *testing.T, opts ...Option) (*Vault, *fakeKS, string) {
	t.Helper()
	ks := newFakeKS(presence.TierHardware)
	path := filepath.Join(t.TempDir(), "sub", "vault.db")
	v, err := Init(ctx, path, ks, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Close() })
	return v, ks, path
}

func TestInitOpenRoundTrip(t *testing.T) {
	v, ks, path := newVault(t)
	if err := v.Set(ctx, Meta{Name: "a/b", Tags: []string{"x"}}, []byte("s3cret-value"), false); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	v2, err := Open(ctx, path, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer v2.Close()
	got, err := v2.Resolve(ctx, []string{"a/b"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got["a/b"]) != "s3cret-value" {
		t.Fatal("round trip mismatch")
	}
	if v2.Info().Version != SchemaVersion || v2.Info().KeystoreTier != presence.TierHardware || v2.Path() != path {
		t.Fatalf("info %+v", v2.Info())
	}
	// Wrong keystore cannot open.
	if _, err := Open(ctx, path, newFakeKS(presence.TierHardware)); err == nil {
		t.Fatal("open with foreign keystore succeeded")
	}
}

func TestFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	v, _, path := newVault(t)
	if err := v.Set(ctx, Meta{Name: "k"}, []byte("v"), false); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %v", st.Mode().Perm())
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", dst.Mode().Perm())
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		if st, err := os.Stat(path + sfx); err == nil && st.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s mode %v", sfx, st.Mode().Perm())
		}
	}
}

func TestOpenRefusesOpenPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	v, ks, path := newVault(t)
	_ = v.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, path, ks); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("err = %v", err)
	}
}

func TestInitRefusesExisting(t *testing.T) {
	v, ks, path := newVault(t)
	_ = v.Close()
	if _, err := Init(ctx, path, ks); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("err = %v", err)
	}
	// An existing non-vault file is also refused and left untouched.
	other := filepath.Join(t.TempDir(), "x.db")
	if err := os.WriteFile(other, []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(ctx, other, ks); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("err = %v", err)
	}
	if b, _ := os.ReadFile(other); string(b) != "hi" {
		t.Fatal("existing file modified")
	}
}

func TestInitErrors(t *testing.T) {
	ks := newFakeKS(presence.TierHardware)
	if _, err := Init(ctx, filepath.Join(t.TempDir(), "v.db"), nil); err == nil {
		t.Fatal("nil keystore")
	}
	ks.wrapErr = errors.New("boom")
	p := filepath.Join(t.TempDir(), "v.db")
	if _, err := Init(ctx, p, ks); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file created despite wrap failure")
	}
	ks.wrapErr = nil
	if _, err := Init(ctx, p, ks, WithDefaultMinTier(presence.PresenceTier(9))); err == nil {
		t.Fatal("invalid tier accepted")
	}
	// Parent is a file: directory creation fails.
	f := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(f, nil, 0o600)
	if _, err := Init(ctx, filepath.Join(f, "v.db"), ks); err == nil {
		t.Fatal("expected mkdir failure")
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := Init(cctx, filepath.Join(t.TempDir(), "v.db"), ks); err == nil {
		t.Fatal("expected context error")
	}
}

func TestOpenErrors(t *testing.T) {
	ks := newFakeKS(presence.TierHardware)
	dir := t.TempDir()
	if _, err := Open(ctx, filepath.Join(dir, "none.db"), ks); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Open(ctx, dir, ks); err == nil {
		t.Fatal("directory accepted")
	}
	if _, err := Open(ctx, filepath.Join(dir, "x"), nil); err == nil {
		t.Fatal("nil keystore")
	}
	// An empty (non-vault) sqlite file.
	empty := filepath.Join(dir, "empty.db")
	_ = os.WriteFile(empty, nil, 0o600)
	if _, err := Open(ctx, empty, ks); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("err = %v", err)
	}
	// Unwrap failure / bad key length / tier downgrade.
	v, ks2, path := newVault(t)
	_ = v.Close()
	ks2.unwrapErr = errors.New("denied")
	if _, err := Open(ctx, path, ks2); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("err = %v", err)
	}
	ks2.unwrapErr = nil
	ks2.unwrapOut = []byte("short")
	if _, err := Open(ctx, path, ks2); err == nil {
		t.Fatal("short key accepted")
	}
	ks2.unwrapOut = nil
	ks2.tier = presence.TierDialog
	if _, err := Open(ctx, path, ks2); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("err = %v", err)
	}
	if _, err := Open(ctx, path, ks2, WithDefaultMinTier(presence.PresenceTier(7))); err == nil {
		t.Fatal("invalid tier accepted")
	}
}

func TestCloseZeroesKey(t *testing.T) {
	v, _, _ := newVault(t)
	key := v.key
	if bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("key already zero")
	}
	if v.DeriveKey("audit-hmac") == nil {
		t.Fatal("derive failed while open")
	}
	_ = v.Close()
	if !bytes.Equal(key, make([]byte, len(key))) {
		t.Fatal("key not zeroed on Close")
	}
	if v.DeriveKey("audit-hmac") != nil {
		t.Fatal("derive after close")
	}
	if err := v.Set(ctx, Meta{Name: "a"}, []byte("v"), false); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.List(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeriveKey(t *testing.T) {
	v, _, _ := newVault(t)
	a, b := v.DeriveKey("audit-hmac"), v.DeriveKey("audit-hmac")
	c := v.DeriveKey("other")
	if len(a) != 32 || !bytes.Equal(a, b) || bytes.Equal(a, c) || bytes.Equal(a, v.key) {
		t.Fatal("derive properties violated")
	}
	if v.DeriveKey("") != nil {
		t.Fatal("empty label")
	}
}

func TestNameValidation(t *testing.T) {
	good := []string{"A", "API_KEY", "aws/access_key", "a.b-c/d_e", "a/b/c", "v1.2", strings.Repeat("a", 256)}
	bad := []string{"", "/a", "a/", "a//b", "..", "a/../b", "a..b", ".", "a/./b", "a b", "a$", "a\x00b", "é", "a\\b", "a*", strings.Repeat("a", 257), "a\nb"}
	for _, n := range good {
		if err := ValidateName(n); err != nil {
			t.Errorf("ValidateName(%q) = %v", n, err)
		}
	}
	for _, n := range bad {
		err := ValidateName(n)
		if !errors.Is(err, ErrInvalidName) {
			t.Errorf("ValidateName(%q) = %v, want ErrInvalidName", n, err)
		} else if len(n) > 3 && strings.Contains(err.Error(), n) {
			t.Errorf("error echoes name %q", n)
		}
	}
	v, _, _ := newVault(t)
	if err := v.Set(ctx, Meta{Name: "bad name"}, []byte("v"), false); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Set: %v", err)
	}
	if _, err := v.Get(ctx, "a//b"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Get: %v", err)
	}
	if _, err := v.Exists(ctx, "/x"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Exists: %v", err)
	}
	if err := v.Delete(ctx, "/x"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := v.Masked(ctx, "/x"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Masked: %v", err)
	}
}

func TestPatternValidation(t *testing.T) {
	for _, p := range []string{"aws/*", "**", "a/**/b", "a?", "a/{x,y}", "[ab]/c"} {
		if err := validatePattern(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"", "/*", "a/*/", "a//*", "../*", `a\*`, "a/[", "*..*", strings.Repeat("*", 300)} {
		if err := validatePattern(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestMasked(t *testing.T) {
	cases := map[string]string{
		"":                  "********",
		"short":             "********",
		"12345678901":       "********", // 11
		"123456789012":      "****9012", // 12
		"sk-live-abcdWXYZ":  "****WXYZ",
		"ünïcödé-secrétXYZ": "****tXYZ"[:0] + "****" + "tXYZ",
	}
	for in, want := range cases {
		if got := MaskedValue([]byte(in)); got != want {
			t.Errorf("MaskedValue(%q) = %q, want %q", in, got, want)
		}
	}
	if MaskedValue([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 1, 2, 3, 4, 5, 6, 7}) != "********" {
		t.Error("non-UTF-8 should be fully masked")
	}
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "long"}, []byte("0123456789ABWXYZ"), false)
	_ = v.Set(ctx, Meta{Name: "short"}, []byte("abc"), false)
	if m, err := v.Masked(ctx, "long"); err != nil || m != "****WXYZ" {
		t.Fatalf("%q %v", m, err)
	}
	if m, err := v.Masked(ctx, "short"); err != nil || m != "********" {
		t.Fatalf("%q %v", m, err)
	}
	if _, err := v.Masked(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestSetGetListDelete(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := now
	v, _, _ := newVault(t, WithClock(func() time.Time { return clock }))
	exp := now.Add(48 * time.Hour)
	m := Meta{Name: "aws/key", Tags: []string{"prod", "aws", "prod"}, URL: "https://x", Notes: "n", ExpiresAt: &exp}
	if err := v.Set(ctx, m, []byte("v1"), false); err != nil {
		t.Fatal(err)
	}
	if err := v.Set(ctx, m, []byte("v2"), false); !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	clock = now.Add(time.Hour)
	m.Notes = "n2"
	if err := v.Set(ctx, m, []byte("v2"), true); err != nil {
		t.Fatal(err)
	}
	got, err := v.Get(ctx, "aws/key")
	if err != nil {
		t.Fatal(err)
	}
	if got.Notes != "n2" || got.URL != "https://x" || strings.Join(got.Tags, ",") != "aws,prod" ||
		!got.CreatedAt.Equal(now) || !got.UpdatedAt.Equal(clock) || got.ExpiresAt == nil || !got.ExpiresAt.Equal(exp) ||
		got.MinTier != presence.TierHardware {
		t.Fatalf("meta %+v", got)
	}
	pt, err := v.Resolve(ctx, []string{"aws/key"})
	if err != nil || string(pt["aws/key"]) != "v2" {
		t.Fatalf("resolve: %v", err)
	}
	if ok, _ := v.Exists(ctx, "aws/key"); !ok {
		t.Fatal("exists")
	}
	if ok, _ := v.Exists(ctx, "zzz"); ok {
		t.Fatal("exists zzz")
	}
	if _, err := v.Get(ctx, "zzz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if err := v.Delete(ctx, "aws/key"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, "aws/key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if l, err := v.List(ctx); err != nil || len(l) != 0 {
		t.Fatalf("list %v %v", l, err)
	}
}

func TestSetValidation(t *testing.T) {
	v, _, _ := newVault(t)
	if err := v.Set(ctx, Meta{Name: "a"}, nil, false); err == nil {
		t.Error("empty value accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a"}, make([]byte, maxValueLen+1), false); err == nil {
		t.Error("huge value accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", Tags: []string{"bad tag"}}, []byte("v"), false); err == nil {
		t.Error("bad tag accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", Tags: []string{"a/b"}}, []byte("v"), false); err == nil {
		t.Error("slash tag accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", Tags: []string{""}}, []byte("v"), false); err == nil {
		t.Error("empty tag accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", Tags: make([]string, 33)}, []byte("v"), false); err == nil {
		t.Error("too many tags accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", MinTier: presence.PresenceTier(5)}, []byte("v"), false); err == nil {
		t.Error("bad tier accepted")
	}
	if err := v.Set(ctx, Meta{Name: "a", Tags: []string{"env:prod", "a.b_c-d"}}, []byte("v"), false); err != nil {
		t.Errorf("good tags: %v", err)
	}
}

func TestMinTierDefaults(t *testing.T) {
	v, ks, path := newVault(t, WithDefaultMinTier(presence.TierDialog))
	_ = v.Set(ctx, Meta{Name: "d"}, []byte("v"), false)
	_ = v.Set(ctx, Meta{Name: "h", MinTier: presence.TierHardware}, []byte("v"), false)
	_ = v.Set(ctx, Meta{Name: "aws/a"}, []byte("v"), false)
	if m, _ := v.Get(ctx, "d"); m.MinTier != presence.TierDialog {
		t.Fatalf("default tier %v", m.MinTier)
	}
	if tier, err := v.MinTierFor(ctx, []string{"d", "aws/*"}); err != nil || tier != presence.TierDialog {
		t.Fatalf("%v %v", tier, err)
	}
	if tier, err := v.MinTierFor(ctx, []string{"d", "h"}); err != nil || tier != presence.TierHardware {
		t.Fatalf("%v %v", tier, err)
	}
	if _, err := v.MinTierFor(ctx, []string{"nope"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.MinTierFor(ctx, []string{"zz/*"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	// Persisted default is picked up by Open; an option overrides it.
	_ = v.Close()
	v2, err := Open(ctx, path, ks)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Info().DefaultMinTier != presence.TierDialog {
		t.Fatalf("persisted default %v", v2.Info().DefaultMinTier)
	}
	_ = v2.Close()
	v3, err := Open(ctx, path, ks, WithDefaultMinTier(presence.TierHardware))
	if err != nil {
		t.Fatal(err)
	}
	defer v3.Close()
	_ = v3.Set(ctx, Meta{Name: "o"}, []byte("v"), false)
	if m, _ := v3.Get(ctx, "o"); m.MinTier != presence.TierHardware {
		t.Fatalf("override %v", m.MinTier)
	}
}

func TestListFilters(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	v, _, _ := newVault(t, WithClock(func() time.Time { return now }))
	in := func(d time.Duration) *time.Time { t := now.Add(d); return &t }
	set := func(n string, exp *time.Time, tags ...string) {
		if err := v.Set(ctx, Meta{Name: n, ExpiresAt: exp, Tags: tags}, []byte("value"), false); err != nil {
			t.Fatal(err)
		}
	}
	set("c", nil, "x")
	set("a", in(24*time.Hour), "x", "y")
	set("b", in(10*24*time.Hour), "y")
	set("old", in(-time.Hour))
	names := func(opts ...ListOption) string {
		l, err := v.List(ctx, opts...)
		if err != nil {
			t.Fatal(err)
		}
		var s []string
		for _, m := range l {
			s = append(s, m.Name)
		}
		return strings.Join(s, ",")
	}
	for got, want := range map[string]string{
		names():                               "a,b,c,old",
		names(ByTag("x")):                     "a,c",
		names(ByTag("y")):                     "a,b",
		names(ByTag("zzz")):                   "",
		names(ExpiringWithin(48 * time.Hour)): "a,old",
		names(ExpiringWithin(30 * 24 * time.Hour)):         "a,b,old",
		names(ExpiringWithin(30*24*time.Hour), ByTag("y")): "a,b",
	} {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestResolveGlobs(t *testing.T) {
	v, _, _ := newVault(t)
	for _, n := range []string{"aws/a", "aws/b", "aws/deep/c", "DB_URL", "gcp/x"} {
		if err := v.Set(ctx, Meta{Name: n}, []byte("val-"+n), false); err != nil {
			t.Fatal(err)
		}
	}
	got, err := v.Resolve(ctx, []string{"aws/*", "DB_URL", "aws/a"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || string(got["aws/b"]) != "val-aws/b" || got["aws/deep/c"] != nil {
		t.Fatalf("got %d entries", len(got))
	}
	got, err = v.Resolve(ctx, []string{"aws/**"})
	if err != nil || len(got) != 3 || got["aws/deep/c"] == nil {
		t.Fatalf("** : %v %d", err, len(got))
	}
	names, err := v.ExpandNames(ctx, []string{"gcp/?", "DB_*"})
	if err != nil || strings.Join(names, ",") != "DB_URL,gcp/x" {
		t.Fatalf("%v %v", names, err)
	}
	// Errors are conservative.
	for _, bad := range [][]string{{"azure/*"}, {"DB_URL", "missing"}, {"aws/*", "nope/*"}, {}, {"/x"}, {"a/["}} {
		if _, err := v.Resolve(ctx, bad); err == nil {
			t.Errorf("Resolve(%v) succeeded", bad)
		}
	}
	if _, err := v.Resolve(ctx, []string{"azure/*"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.Resolve(ctx, []string{"missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveExpired(t *testing.T) {
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	v, _, _ := newVault(t, WithClock(func() time.Time { return now }))
	past := now.Add(-time.Minute)
	_ = v.Set(ctx, Meta{Name: "x/old", ExpiresAt: &past}, []byte("v"), false)
	_ = v.Set(ctx, Meta{Name: "x/new"}, []byte("v"), false)
	if _, err := v.Resolve(ctx, []string{"x/old"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v", err)
	}
	if _, err := v.Resolve(ctx, []string{"x/*"}); !errors.Is(err, ErrExpired) {
		t.Fatalf("glob err = %v", err)
	}
	if _, err := v.Resolve(ctx, []string{"x/new"}); err != nil {
		t.Fatal(err)
	}
}

func TestTamperDetection(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "k"}, []byte("a-secret-value"), false)
	var ct []byte
	if err := v.db.QueryRow(`SELECT ciphertext FROM secrets WHERE name='k'`).Scan(&ct); err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 1
	if _, err := v.db.Exec(`UPDATE secrets SET ciphertext=? WHERE name='k'`, ct); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("flipped ciphertext: %v", err)
	}
	if _, err := v.Masked(ctx, "k"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("masked: %v", err)
	}
	ct[0] ^= 1
	_, _ = v.db.Exec(`UPDATE secrets SET ciphertext=? WHERE name='k'`, ct)
	if _, err := v.Resolve(ctx, []string{"k"}); err != nil {
		t.Fatalf("restored: %v", err)
	}
	// Flip a nonce byte and truncate it.
	var nonce []byte
	_ = v.db.QueryRow(`SELECT nonce FROM secrets WHERE name='k'`).Scan(&nonce)
	bad := append([]byte(nil), nonce...)
	bad[0] ^= 1
	_, _ = v.db.Exec(`UPDATE secrets SET nonce=? WHERE name='k'`, bad)
	if _, err := v.Resolve(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("flipped nonce: %v", err)
	}
	_, _ = v.db.Exec(`UPDATE secrets SET nonce=? WHERE name='k'`, nonce[:5])
	if _, err := v.Resolve(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short nonce: %v", err)
	}
}

func TestAADBindsName(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "one"}, []byte("value-of-one"), false)
	_ = v.Set(ctx, Meta{Name: "two"}, []byte("value-of-two"), false)
	var ct, nonce []byte
	_ = v.db.QueryRow(`SELECT ciphertext, nonce FROM secrets WHERE name='one'`).Scan(&ct, &nonce)
	if _, err := v.db.Exec(`UPDATE secrets SET ciphertext=?, nonce=? WHERE name='two'`, ct, nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(ctx, []string{"two"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("swapped ciphertext accepted: %v", err)
	}
	if got, err := v.Resolve(ctx, []string{"one"}); err != nil || string(got["one"]) != "value-of-one" {
		t.Fatalf("original: %v", err)
	}
}

func TestFreshNonceAndNoPlaintextOnDisk(t *testing.T) {
	v, _, path := newVault(t)
	const plain = "PLAINTEXT-MARKER-0123456789"
	_ = v.Set(ctx, Meta{Name: "k"}, []byte(plain), false)
	var n1, c1 []byte
	_ = v.db.QueryRow(`SELECT nonce, ciphertext FROM secrets WHERE name='k'`).Scan(&n1, &c1)
	_ = v.Set(ctx, Meta{Name: "k"}, []byte(plain), true)
	var n2, c2 []byte
	_ = v.db.QueryRow(`SELECT nonce, ciphertext FROM secrets WHERE name='k'`).Scan(&n2, &c2)
	if bytes.Equal(n1, n2) || bytes.Equal(c1, c2) || len(n1) != 12 {
		t.Fatal("nonce reused on rewrite")
	}
	_ = v.Close() // checkpoints the WAL
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if bytes.Contains(b, []byte(plain)) {
			t.Fatalf("plaintext found in %s", f)
		}
	}
}

func TestSharedDB(t *testing.T) {
	v, _, _ := newVault(t)
	if _, err := v.DB().ExecContext(ctx, `CREATE TABLE IF NOT EXISTS grants_test (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentUse(t *testing.T) {
	v, _, _ := newVault(t)
	done := make(chan error, 8)
	for i := 0; i < 8; i++ {
		go func(i int) {
			n := fmt.Sprintf("c/%d", i)
			for j := 0; j < 5; j++ {
				if err := v.Set(ctx, Meta{Name: n}, []byte("value"), true); err != nil {
					done <- err
					return
				}
				if _, err := v.Resolve(ctx, []string{n}); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(i)
	}
	for i := 0; i < 8; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("GRANTD_HOME", "/tmp/gh")
	t.Setenv("XDG_DATA_HOME", "/tmp/xdg")
	if p, _ := DefaultPath(); p != "/tmp/gh/vault.db" {
		t.Fatal(p)
	}
	t.Setenv("GRANTD_HOME", "")
	if p, _ := DefaultPath(); p != "/tmp/xdg/grantd/vault.db" {
		t.Fatal(p)
	}
	t.Setenv("XDG_DATA_HOME", "relative/ignored")
	t.Setenv("HOME", "/home/u")
	p, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := "/home/u/.local/share/grantd/vault.db"
	if runtime.GOOS == "darwin" {
		want = "/home/u/Library/Application Support/grantd/vault.db"
	}
	if runtime.GOOS != "windows" && p != want {
		t.Fatalf("%s != %s", p, want)
	}
}

// TestNoValueInErrors drives many error paths with random, recognisable values
// and asserts the value never shows up in an error string or String() output.
func TestNoValueInErrors(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "exists"}, []byte("seed-value"), false)
	for i := 0; i < 200; i++ {
		raw := make([]byte, 12)
		_, _ = rand.Read(raw)
		val := fmt.Sprintf("SECRET%x", raw)
		vb := []byte(val)
		var errs []error
		collect := func(err error) { errs = append(errs, err) }

		collect(v.Set(ctx, Meta{Name: "exists"}, vb, false))                               // ErrExists
		collect(v.Set(ctx, Meta{Name: "bad name!"}, vb, false))                            // bad name
		collect(v.Set(ctx, Meta{Name: "n", Tags: []string{"bad tag"}}, vb, false))         // bad tag
		collect(v.Set(ctx, Meta{Name: "n", MinTier: presence.PresenceTier(9)}, vb, false)) // bad tier
		_, err := v.Resolve(ctx, []string{"missing/*"})
		collect(err)
		_, err = v.Resolve(ctx, []string{"bad name"})
		collect(err)
		// ParseDotenv / Import error paths.
		_, err = ParseDotenv(strings.NewReader(val + "\n"))
		collect(err)
		_, err = ParseDotenv(strings.NewReader("K=\"" + val + "\n"))
		collect(err)
		_, err = ParseDotenv(strings.NewReader("K=\"" + val + "\" trailing\n"))
		collect(err)
		_, err = ParseDotenv(strings.NewReader("bad key=" + val + "\n"))
		collect(err)
		_, err = v.Import(ctx, []KV{{Key: "exists", Value: vb}}, ConflictError, false)
		collect(err)
		_, err = v.Import(ctx, []KV{{Key: "bad key", Value: vb}}, ConflictSkip, false)
		collect(err)
		_, err = v.Import(ctx, []KV{{Key: "ok", Value: vb}}, ConflictMode(val), false)
		collect(err)

		for _, err := range errs {
			if err != nil && strings.Contains(err.Error(), val) {
				// Only a name that the caller deliberately set to the value may
				// legitimately appear (names are not secret); it succeeded, not errored.
				t.Fatalf("error leaks value: %v", err)
			}
		}
		kv := KV{Key: "K", Value: vb}
		for _, s := range []string{kv.String(), kv.GoString(), fmt.Sprintf("%v %+v %#v %s", kv, kv, kv, kv)} {
			if strings.Contains(s, val) {
				t.Fatalf("KV formatting leaks value: %s", s)
			}
		}
		meta, _ := v.Get(ctx, "exists")
		if s := fmt.Sprintf("%v %+v %#v", meta, meta, meta); strings.Contains(s, "seed-value") {
			t.Fatal("meta leaks value")
		}
	}
}

func TestDecryptErrorHasNoValue(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "k"}, []byte("very-secret-value"), false)
	_, _ = v.db.Exec(`UPDATE secrets SET ciphertext = x'00' WHERE name='k'`)
	_, err := v.Resolve(ctx, []string{"k"})
	if err == nil || strings.Contains(err.Error(), "very-secret-value") {
		t.Fatalf("err = %v", err)
	}
}

func TestOddPaths(t *testing.T) {
	ks := newFakeKS(presence.TierHardware)
	path := filepath.Join(t.TempDir(), "Application Support", "a#b?c%d", "vault.db")
	v, err := Init(ctx, path, ks)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Set(ctx, Meta{Name: "k"}, []byte("v"), false); err != nil {
		t.Fatal(err)
	}
	_ = v.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	v, err = Open(ctx, path, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	if ok, _ := v.Exists(ctx, "k"); !ok {
		t.Fatal("lost secret")
	}
}

func TestMinTierTamperDetected(t *testing.T) {
	v, _, _ := newVault(t)
	if err := v.Set(ctx, Meta{Name: "k", MinTier: presence.TierHardware}, []byte("a-secret-value"), false); err != nil {
		t.Fatal(err)
	}
	if _, err := v.db.Exec(`UPDATE secrets SET min_tier = ? WHERE name = 'k'`, int(presence.TierNone)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Resolve(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Resolve with lowered min_tier: %v", err)
	}
	if _, err := v.MinTierFor(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("MinTierFor with lowered min_tier: %v", err)
	}
	if _, err := v.Masked(ctx, "k"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("Masked with lowered min_tier: %v", err)
	}
	// Out-of-range tier values never authenticate either.
	_, _ = v.db.Exec(`UPDATE secrets SET min_tier = 1000 WHERE name = 'k'`)
	if _, err := v.MinTierFor(ctx, []string{"k"}); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("out-of-range tier: %v", err)
	}
}

func TestSetOverwriteChangesTierAndReencrypts(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "k", MinTier: presence.TierHardware}, []byte("value"), false)
	var c1 []byte
	_ = v.db.QueryRow(`SELECT ciphertext FROM secrets WHERE name='k'`).Scan(&c1)
	if err := v.Set(ctx, Meta{Name: "k", MinTier: presence.TierDialog}, []byte("value"), true); err != nil {
		t.Fatal(err)
	}
	var c2 []byte
	_ = v.db.QueryRow(`SELECT ciphertext FROM secrets WHERE name='k'`).Scan(&c2)
	if bytes.Equal(c1, c2) {
		t.Fatal("ciphertext unchanged")
	}
	if tier, err := v.MinTierFor(ctx, []string{"k"}); err != nil || tier != presence.TierDialog {
		t.Fatalf("%v %v", tier, err)
	}
}

func TestAADEncoding(t *testing.T) {
	got := aad("a/b", presence.TierDialog)
	if string(got) != "grantd.secret.v1\x00a/b\x00\x01" {
		t.Fatalf("%q", got)
	}
	if bytes.Equal(aad("a", presence.TierNone), aad("a", presence.TierHardware)) || bytes.Equal(aad("a", 300), aad("a", 44)) {
		t.Fatal("aad collision")
	}
}
