package vault

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver

	"grantd/internal/keystore"
	"grantd/internal/presence"
)

// SchemaVersion is the on-disk vault format version written by Init.
const SchemaVersion = 1

const dataKeySize = 32

// Sentinel errors. None of them (nor any other error from this package) ever
// contains a secret value.
var (
	ErrNotInitialized     = errors.New("vault: not initialized (run `grantd init`)")
	ErrAlreadyInitialized = errors.New("vault: already initialized")
	ErrClosed             = errors.New("vault: closed")
	ErrNotFound           = errors.New("vault: secret not found")
	ErrExists             = errors.New("vault: secret already exists")
	ErrExpired            = errors.New("vault: secret expired")
	ErrInvalidName        = errors.New("vault: invalid secret name")
	ErrDecrypt            = errors.New("vault: decryption failed (corrupt data or wrong key)")
)

// schema is the DDL owned by this package. The grant and audit packages create
// their own tables in the same file via DB() and their own idempotent
// Migrate(ctx, db); the daemon calls those.
const schema = `
CREATE TABLE vault_meta (
	id               INTEGER PRIMARY KEY CHECK (id = 1),
	version          INTEGER NOT NULL,
	created_at       INTEGER NOT NULL, -- unix milliseconds, UTC
	keystore_tier    INTEGER NOT NULL, -- presence.PresenceTier of the keystore at Init
	default_min_tier INTEGER NOT NULL, -- min_tier given to secrets that do not specify one
	wrapped_key      BLOB    NOT NULL  -- keystore.Wrap(dataKey); the only form of the key on disk
);
CREATE TABLE secrets (
	name       TEXT    PRIMARY KEY,
	ciphertext BLOB    NOT NULL,       -- AES-256-GCM(value), AAD = name
	nonce      BLOB    NOT NULL,       -- 12 random bytes, fresh per write
	tags       TEXT    NOT NULL DEFAULT '[]', -- JSON array of strings
	url        TEXT    NOT NULL DEFAULT '',
	notes      TEXT    NOT NULL DEFAULT '',
	expires_at INTEGER,                -- unix milliseconds, NULL = never
	min_tier   INTEGER NOT NULL,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
);
`

// Info describes the vault file.
type Info struct {
	Version        int
	CreatedAt      time.Time
	KeystoreTier   presence.PresenceTier
	DefaultMinTier presence.PresenceTier
}

// Option configures Init and Open.
type Option func(*config)

type config struct {
	defaultMinTier    presence.PresenceTier
	defaultMinTierSet bool
	now               func() time.Time
}

// WithDefaultMinTier sets the min_tier given to secrets whose Meta.MinTier is
// the zero value. On Init it is persisted in the vault; on Open it overrides
// the persisted value for this handle only. Without it the default is
// TierHardware (the most restrictive). Linux passes TierDialog.
func WithDefaultMinTier(t presence.PresenceTier) Option {
	return func(c *config) { c.defaultMinTier, c.defaultMinTierSet = t, true }
}

// WithClock overrides time.Now (tests).
func WithClock(now func() time.Time) Option {
	return func(c *config) { c.now = now }
}

func newConfig(opts []Option) (*config, error) {
	c := &config{now: time.Now}
	for _, o := range opts {
		o(c)
	}
	if c.defaultMinTierSet && !c.defaultMinTier.Valid() {
		return nil, fmt.Errorf("vault: invalid default min tier %d", int(c.defaultMinTier))
	}
	return c, nil
}

// Vault is the encrypted secret store. It is safe for concurrent use.
type Vault struct {
	db   *sql.DB
	path string
	cfg  *config
	info Info

	mu     sync.RWMutex // guards key and closed; held (R) by every crypto operation
	key    []byte       // data key, memory only
	closed bool
}

func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_txlock", "immediate")
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: path}).EscapedPath(), RawQuery: q.Encode()}
	return u.String()
}

// Init creates a new vault file at path: the directory (0700), the SQLite file
// (0600), a random 32-byte data key wrapped with ks.Wrap, and the metadata row.
// It refuses if a file already exists at path. The returned Vault is open.
func Init(ctx context.Context, path string, ks keystore.KeyStore, opts ...Option) (*Vault, error) {
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	if ks == nil {
		return nil, errors.New("vault: nil keystore")
	}
	if !cfg.defaultMinTierSet {
		cfg.defaultMinTier = presence.TierHardware
	}
	if _, err := os.Lstat(path); err == nil {
		return nil, ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("vault: stat vault file: %w", err)
	}

	key := make([]byte, dataKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("vault: generate data key: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			zero(key)
		}
	}()

	wrapped, err := ks.Wrap(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("vault: wrap data key: %w", err)
	}
	if len(wrapped) == 0 {
		return nil, errors.New("vault: keystore returned an empty wrapped key")
	}

	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("vault: create directory: %w", err)
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			return nil, fmt.Errorf("vault: chmod directory: %w", err)
		}
	}
	// O_EXCL both enforces "refuse if exists" race-free and means the file is
	// never visible with a wider mode than 0600.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, ErrAlreadyInitialized
		}
		return nil, fmt.Errorf("vault: create vault file: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("vault: create vault file: %w", err)
	}
	created := false
	defer func() {
		if !ok && created {
			// Best effort: do not leave a half-initialized vault behind.
			for _, s := range []string{"", "-wal", "-shm"} {
				_ = os.Remove(path + s)
			}
		}
	}()
	created = true
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("vault: chmod vault file: %w", err)
	}

	db, err := openDB(ctx, path)
	if err != nil {
		return nil, err
	}
	now := cfg.now().UTC()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("vault: begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, schema); err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, fmt.Errorf("vault: create schema: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO vault_meta (id, version, created_at, keystore_tier, default_min_tier, wrapped_key) VALUES (1, ?, ?, ?, ?, ?)`,
		SchemaVersion, now.UnixMilli(), int(ks.Tier()), int(cfg.defaultMinTier), wrapped); err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, fmt.Errorf("vault: write metadata: %w", err)
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("vault: commit: %w", err)
	}
	ok = true
	return &Vault{
		db: db, path: path, cfg: cfg, key: key,
		info: Info{Version: SchemaVersion, CreatedAt: time.UnixMilli(now.UnixMilli()).UTC(), KeystoreTier: ks.Tier(), DefaultMinTier: cfg.defaultMinTier},
	}, nil
}

func openDB(ctx context.Context, path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("vault: open database: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("vault: open database: %w", err)
	}
	return db, nil
}

// Open opens an existing vault, unwrapping the data key via ks (which may
// block on human presence). The data key lives in memory only and is zeroed by
// Close. Open refuses a keystore whose tier is weaker than the one the vault
// was created with, and (on unix) a vault file readable by group or others.
func Open(ctx context.Context, path string, ks keystore.KeyStore, opts ...Option) (*Vault, error) {
	cfg, err := newConfig(opts)
	if err != nil {
		return nil, err
	}
	if ks == nil {
		return nil, errors.New("vault: nil keystore")
	}
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("vault: stat vault file: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("vault: vault path is not a regular file")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("vault: vault file permissions %04o are too open (want 0600)", st.Mode().Perm())
	}

	db, err := openDB(ctx, path)
	if err != nil {
		return nil, err
	}
	var (
		info     Info
		created  int64
		kst, dmt int
		wrapped  []byte
	)
	err = db.QueryRowContext(ctx,
		`SELECT version, created_at, keystore_tier, default_min_tier, wrapped_key FROM vault_meta WHERE id = 1`).
		Scan(&info.Version, &created, &kst, &dmt, &wrapped)
	if err != nil {
		_ = db.Close()
		if errors.Is(err, sql.ErrNoRows) || isNoSuchTable(err) {
			return nil, ErrNotInitialized
		}
		return nil, fmt.Errorf("vault: read metadata: %w", err)
	}
	if info.Version != SchemaVersion {
		_ = db.Close()
		return nil, fmt.Errorf("vault: unsupported vault version %d (this build supports %d)", info.Version, SchemaVersion)
	}
	info.CreatedAt = time.UnixMilli(created).UTC()
	info.KeystoreTier = presence.PresenceTier(kst)
	info.DefaultMinTier = presence.PresenceTier(dmt)
	if !info.KeystoreTier.Valid() || !info.DefaultMinTier.Valid() {
		_ = db.Close()
		return nil, errors.New("vault: corrupt metadata (invalid tier)")
	}
	if !ks.Tier().Meets(info.KeystoreTier) {
		_ = db.Close()
		return nil, fmt.Errorf("vault: keystore tier %s is weaker than the %s the vault was created with; refusing to downgrade", ks.Tier(), info.KeystoreTier)
	}
	key, err := ks.Unwrap(ctx, wrapped)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("vault: unwrap data key: %w", err)
	}
	if len(key) != dataKeySize {
		zero(key)
		_ = db.Close()
		return nil, errors.New("vault: unwrapped data key has the wrong length")
	}
	if cfg.defaultMinTierSet {
		info.DefaultMinTier = cfg.defaultMinTier
	} else {
		cfg.defaultMinTier = info.DefaultMinTier
	}
	return &Vault{db: db, path: path, cfg: cfg, key: key, info: info}, nil
}

func isNoSuchTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}

// Close closes the database and zeroes the in-memory data key. It is
// idempotent. Operations after Close return ErrClosed.
func (v *Vault) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	zero(v.key)
	return v.db.Close()
}

// Path returns the vault file path.
func (v *Vault) Path() string { return v.path }

// Info returns vault metadata (version, creation time, keystore tier).
func (v *Vault) Info() Info { return v.info }

// DB returns the underlying database so the grant and audit packages can
// create their own tables in the same file. Callers must not touch the
// vault_meta or secrets tables. The handle is closed by Vault.Close.
func (v *Vault) DB() *sql.DB { return v.db }

// DeriveKey returns a 32-byte key derived from the data key with
// HKDF-SHA256 (no salt, info = label). Different labels give independent keys,
// so the data key itself never leaves the package. Known labels:
//
//	"audit-hmac"  HMAC key for the audit log chain (internal/audit)
//
// It returns nil if label is empty or the vault is closed. The caller owns the
// returned slice and should zero it when done. INTERNAL: never log or send it.
func (v *Vault) DeriveKey(label string) []byte {
	if label == "" {
		return nil
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.closed {
		return nil
	}
	out := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(sha256.New, v.key, nil, []byte(label)), out); err != nil {
		return nil // unreachable: HKDF-SHA256 can produce 32 bytes
	}
	return out
}

// rlock returns an unlock func, or ErrClosed.
func (v *Vault) rlock() (func(), error) {
	v.mu.RLock()
	if v.closed {
		v.mu.RUnlock()
		return nil, ErrClosed
	}
	return v.mu.RUnlock, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
