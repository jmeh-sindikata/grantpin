//go:build darwin && cgo

package darwin

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <stdlib.h>
#include "sec_darwin.h"
*/
import "C"

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"unsafe"

	"grantd/internal/keystore"
	"grantd/internal/presence"
)

// Store implements keystore.KeyStore with the Secure Enclave, or (opt-in) a
// Keychain-resident KEK. Safe for concurrent use.
type Store struct {
	cfg config
	tag string
	svc string
	acc string

	// Test seams: when set, Unwrap calls these instead of Security.framework.
	unwrapSEHook func(payload []byte) ([]byte, error)
	unwrapKCHook func(payload, hdr []byte) ([]byte, error)

	mu   sync.Mutex
	mode Mode           // 0 = unresolved
	key  unsafe.Pointer // retained SecKeyRef (private) when mode == ModeSecureEnclave
}

var _ keystore.KeyStore = (*Store)(nil)

// New returns a Store. It does not create anything and never prompts: it only
// looks for an existing Secure Enclave key (then, if the fallback is enabled, an
// existing fallback item) so Mode() reflects reality on a machine that already
// has a vault. Keys are created lazily by the first Wrap.
//
// A failure to look (e.g. missing entitlements) is not an error here; it
// surfaces from Wrap/Unwrap with the Security.framework status.
func New(opts ...Option) (keystore.KeyStore, error) {
	return newStore(newConfig(opts), KeyTag, KeychainService, KeychainAccount)
}

func newStore(cfg config, tag, svc, acc string) (*Store, error) {
	s := &Store{cfg: cfg, tag: tag, svc: svc, acc: acc}
	s.mu.Lock()
	defer s.mu.Unlock()
	if k, err := s.findSE(); err == nil && k != nil {
		s.key, s.mode = k, ModeSecureEnclave
	} else if cfg.allowFallback {
		if ok, _ := s.kcExists(); ok {
			s.mode = ModeKeychain
		}
	}
	return s, nil
}

// Mode returns "secure-enclave", "keychain-fallback" or "unresolved" (no key
// exists yet; the first Wrap decides).
func (s *Store) Mode() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.mode {
	case ModeSecureEnclave:
		return ModeNameSecureEnclave
	case ModeKeychain:
		return ModeNameKeychain
	}
	return ModeNameUnresolved
}

// Tier is TierHardware in Secure Enclave mode. In fallback mode it is
// TierDialog. While unresolved it reports the weakest tier this store could
// end up with (TierDialog if the fallback is enabled, else TierHardware), so a
// caller never over-trusts it.
func (s *Store) Tier() presence.PresenceTier {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.mode {
	case ModeSecureEnclave:
		return presence.TierHardware
	case ModeKeychain:
		return presence.TierDialog
	}
	if s.cfg.allowFallback {
		return presence.TierDialog
	}
	return presence.TierHardware
}

// Close releases the cached SecKeyRef. The Store must not be used afterwards.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		C.gd_release(s.key)
		s.key = nil
	}
	return nil
}

// Wrap protects dataKey. It never prompts.
func (s *Store) Wrap(ctx context.Context, dataKey []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(dataKey) == 0 {
		return nil, ErrEmptyKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.mode == 0 || s.mode == ModeSecureEnclave {
		blob, err := s.wrapSE(dataKey)
		if err == nil {
			return blob, nil
		}
		if s.mode == ModeSecureEnclave || !isSEUnavailable(err) {
			return nil, err
		}
		if !s.cfg.allowFallback {
			return nil, fmt.Errorf("%w: %v", ErrSecureEnclaveUnavailable, err)
		}
		// fall through to the keychain fallback
	}
	return s.wrapKeychain(dataKey)
}

// Unwrap recovers the data key. It never prompts and never creates keys. The
// blob's mode byte selects the mechanism, whatever options this Store was built
// with (see the package comment).
func (s *Store) Unwrap(ctx context.Context, wrapped []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, payload, err := decodeBlob(wrapped)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// The blob names the mode that produced it and that mode alone decides how
	// it is opened; WithAllowKeychainFallback only governs what Wrap may create.
	switch m {
	case ModeSecureEnclave:
		if s.unwrapSEHook != nil {
			return s.unwrapSEHook(payload)
		}
		return s.unwrapSE(payload)
	case ModeKeychain:
		if s.unwrapKCHook != nil {
			return s.unwrapKCHook(payload, wrapped[:2])
		}
		return s.unwrapKeychain(payload, wrapped[:2])
	}
	return nil, ErrBadBlob // unreachable: decodeBlob validates
}

// ---- Secure Enclave --------------------------------------------------------

func cerr(op string, e *C.gd_err) error {
	return &SecError{Op: op, Code: int(e.code), Msg: C.GoString(&e.msg[0])}
}

// findSE returns a retained key or (nil, nil) if absent. Caller holds s.mu.
func (s *Store) findSE() (unsafe.Pointer, error) {
	ctag := C.CString(s.tag)
	defer C.free(unsafe.Pointer(ctag))
	var k unsafe.Pointer
	var e C.gd_err
	switch C.gd_se_find(ctag, &k, &e) {
	case 0:
		return k, nil
	case 1:
		return nil, nil
	}
	return nil, cerr("find Secure Enclave key", &e)
}

// ensureSE returns the cached key, finding or creating it. Caller holds s.mu.
func (s *Store) ensureSE() (unsafe.Pointer, error) {
	if s.key != nil {
		return s.key, nil
	}
	k, err := s.findSE()
	if err != nil {
		return nil, err
	}
	if k == nil {
		ctag := C.CString(s.tag)
		defer C.free(unsafe.Pointer(ctag))
		var e C.gd_err
		if C.gd_se_create(ctag, &k, &e) != 0 {
			return nil, cerr("create Secure Enclave key", &e)
		}
	}
	s.key, s.mode = k, ModeSecureEnclave
	return k, nil
}

func (s *Store) wrapSE(dataKey []byte) ([]byte, error) {
	k, err := s.ensureSE()
	if err != nil {
		return nil, err
	}
	out, err := seCrypt(true, k, dataKey)
	if err != nil {
		return nil, err
	}
	return encodeBlob(ModeSecureEnclave, out), nil
}

func (s *Store) unwrapSE(payload []byte) ([]byte, error) {
	k := s.key
	if k == nil {
		var err error
		if k, err = s.findSE(); err != nil {
			return nil, err
		}
		if k == nil {
			return nil, ErrKeyNotFound
		}
		s.key, s.mode = k, ModeSecureEnclave
	}
	return seCrypt(false, k, payload)
}

// seCrypt runs ECIES encrypt/decrypt. The returned slice is Go-owned; the C
// buffer is zeroed and freed.
func seCrypt(enc bool, key unsafe.Pointer, in []byte) ([]byte, error) {
	var e C.gd_err
	var out *C.uint8_t
	var outLen C.size_t
	flag := C.int(0)
	op := "decrypt with Secure Enclave key"
	if enc {
		flag = 1
		op = "encrypt to Secure Enclave key"
	}
	if C.gd_se_crypt(flag, key, (*C.uint8_t)(unsafe.Pointer(&in[0])), C.size_t(len(in)), &out, &outLen, &e) != 0 {
		return nil, cerr(op, &e)
	}
	res := C.GoBytes(unsafe.Pointer(out), C.int(outLen))
	C.gd_free(out, outLen)
	return res, nil
}

// ---- Keychain fallback -----------------------------------------------------

// kcExists reports whether a fallback KEK item exists in either keychain.
func (s *Store) kcExists() (bool, error) {
	cs, ca := C.CString(s.svc), C.CString(s.acc)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var lastErr error
	for _, dp := range []C.int{1, 0} {
		var e C.gd_err
		switch C.gd_kc_get(cs, ca, dp, 0, nil, nil, &e) {
		case 0:
			return true, nil
		case -1:
			lastErr = cerr("look up fallback KEK", &e)
		}
	}
	return false, lastErr
}

// kcGet reads the KEK (data-protection keychain first, then the login
// keychain). Returns (nil, nil) if absent. Caller must zero the result.
func (s *Store) kcGet() ([]byte, error) {
	cs, ca := C.CString(s.svc), C.CString(s.acc)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var lastErr error
	for _, dp := range []C.int{1, 0} {
		var e C.gd_err
		var out *C.uint8_t
		var n C.size_t
		switch C.gd_kc_get(cs, ca, dp, 1, &out, &n, &e) {
		case 0:
			b := C.GoBytes(unsafe.Pointer(out), C.int(n))
			C.gd_free(out, n)
			return b, nil
		case -1:
			if dp == 1 && int(e.code) == statusMissingEntitlement {
				continue // unsigned binary: the DP keychain is closed to us
			}
			lastErr = cerr("read fallback KEK", &e)
		}
	}
	return nil, lastErr
}

// kcCreate generates and stores a fresh KEK, returning a copy. A concurrent
// creator is tolerated: on duplicate we re-read. Caller must zero the result.
func (s *Store) kcCreate() ([]byte, error) {
	kek := make([]byte, KEKSize)
	defer zero(kek)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, fmt.Errorf("darwin keystore: generate KEK: %w", err)
	}
	cs, ca := C.CString(s.svc), C.CString(s.acc)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))

	var lastErr error
	for _, dp := range []C.int{1, 0} {
		var e C.gd_err
		switch C.gd_kc_add(cs, ca, dp, (*C.uint8_t)(unsafe.Pointer(&kek[0])), C.size_t(len(kek)), &e) {
		case 0:
			return append([]byte(nil), kek...), nil
		case 2:
			if got, err := s.kcGet(); err != nil {
				return nil, err
			} else if got != nil {
				return got, nil
			}
			return nil, fmt.Errorf("darwin keystore: fallback KEK exists but cannot be read")
		default:
			lastErr = cerr("store fallback KEK", &e)
			if dp == 1 && int(e.code) == statusMissingEntitlement {
				continue
			}
			return nil, lastErr
		}
	}
	return nil, lastErr
}

func (s *Store) wrapKeychain(dataKey []byte) ([]byte, error) {
	kek, err := s.kcGet()
	if err != nil {
		return nil, err
	}
	if kek == nil {
		if kek, err = s.kcCreate(); err != nil {
			return nil, err
		}
	}
	defer zero(kek)
	hdr := []byte{byte(ModeKeychain), FormatVersion}
	sealed, err := sealKEK(kek, dataKey, hdr)
	if err != nil {
		return nil, err
	}
	s.mode = ModeKeychain
	return encodeBlob(ModeKeychain, sealed), nil
}

func (s *Store) unwrapKeychain(payload, hdr []byte) ([]byte, error) {
	kek, err := s.kcGet()
	if err != nil {
		return nil, err
	}
	if kek == nil {
		return nil, ErrKeyNotFound
	}
	defer zero(kek)
	s.mode = ModeKeychain
	return openKEK(kek, payload, hdr)
}

// ---- test support ----------------------------------------------------------

// deleteKeys removes the SE key and fallback item named by this store. It
// exists for manual tests, which use unique tags so they never touch the real
// vault key.
func (s *Store) deleteKeys() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.key != nil {
		C.gd_release(s.key)
		s.key = nil
	}
	s.mode = 0
	ctag := C.CString(s.tag)
	defer C.free(unsafe.Pointer(ctag))
	cs, ca := C.CString(s.svc), C.CString(s.acc)
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var first error
	var e C.gd_err
	if C.gd_se_delete(ctag, &e) == -1 && !seUnavailable(int(e.code)) {
		first = cerr("delete Secure Enclave key", &e)
	}
	for _, dp := range []C.int{1, 0} {
		var e2 C.gd_err
		if C.gd_kc_delete(cs, ca, dp, &e2) == -1 && int(e2.code) != statusMissingEntitlement && first == nil {
			first = cerr("delete fallback KEK", &e2)
		}
	}
	return first
}

// kcWrapForTest forces the fallback path (manual tests on machines that do have
// a working Secure Enclave).
func (s *Store) kcWrapForTest(dataKey []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wrapKeychain(dataKey)
}
