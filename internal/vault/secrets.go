package vault

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"grantd/internal/presence"
)

// Meta is a secret's non-sensitive metadata (§6). It never contains the value.
type Meta struct {
	Name  string
	Tags  []string
	URL   string
	Notes string
	// ExpiresAt is nil for "never".
	ExpiresAt *time.Time
	// MinTier is the minimum presence tier needed to release the secret. On Set
	// the zero value (TierNone) means "use the vault default" (TierHardware
	// unless configured otherwise), so a secret cannot be stored with TierNone
	// by accident; configure the default with WithDefaultMinTier instead.
	MinTier   presence.PresenceTier
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Expired reports whether the secret is expired at t.
func (m Meta) Expired(t time.Time) bool {
	return m.ExpiresAt != nil && !m.ExpiresAt.After(t)
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func normalizeTags(tags []string) ([]string, error) {
	if len(tags) > maxTags {
		return nil, fmt.Errorf("vault: too many tags (max %d)", maxTags)
	}
	seen := make(map[string]struct{}, len(tags))
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		if err := validateTag(t); err != nil {
			return nil, err
		}
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

func ms(t time.Time) int64 { return t.UnixMilli() }

// Set stores a secret value and its metadata (m.CreatedAt and m.UpdatedAt are
// ignored). If the name exists and overwrite is false it returns ErrExists;
// with overwrite the value is re-encrypted under a fresh nonce and created_at
// is preserved. The value must be non-empty.
func (v *Vault) Set(ctx context.Context, m Meta, value []byte, overwrite bool) error {
	unlock, err := v.rlock()
	if err != nil {
		return err
	}
	defer unlock()
	tx, err := v.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("vault: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := v.setTx(ctx, tx, m, value, overwrite); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("vault: commit: %w", err)
	}
	return nil
}

// setTx is Set's body; the caller holds the read lock and owns the transaction.
func (v *Vault) setTx(ctx context.Context, ex execer, m Meta, value []byte, overwrite bool) error {
	if err := ValidateName(m.Name); err != nil {
		return err
	}
	if len(value) == 0 {
		return errors.New("vault: empty secret value")
	}
	if len(value) > maxValueLen {
		return errors.New("vault: secret value too large")
	}
	tags, err := normalizeTags(m.Tags)
	if err != nil {
		return err
	}
	tier := m.MinTier
	if tier == presence.TierNone {
		tier = v.cfg.defaultMinTier
	}
	if !tier.Valid() {
		return fmt.Errorf("vault: invalid min tier %d", int(tier))
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		return errors.New("vault: encode tags")
	}
	var exp any
	if m.ExpiresAt != nil {
		exp = ms(*m.ExpiresAt)
	}

	var one int
	err = ex.QueryRowContext(ctx, `SELECT 1 FROM secrets WHERE name = ?`, m.Name).Scan(&one)
	switch {
	case err == nil:
		if !overwrite {
			return fmt.Errorf("%w: %s", ErrExists, m.Name)
		}
	case errors.Is(err, sql.ErrNoRows):
	default:
		return fmt.Errorf("vault: lookup: %w", err)
	}

	ct, nonce, err := seal(v.key, m.Name, tier, value)
	if err != nil {
		return err
	}
	now := ms(v.cfg.now())
	_, err = ex.ExecContext(ctx, `
INSERT INTO secrets (name, ciphertext, nonce, tags, url, notes, expires_at, min_tier, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(name) DO UPDATE SET
	ciphertext = excluded.ciphertext, nonce = excluded.nonce, tags = excluded.tags,
	url = excluded.url, notes = excluded.notes, expires_at = excluded.expires_at,
	min_tier = excluded.min_tier, updated_at = excluded.updated_at`,
		m.Name, ct, nonce, string(tagsJSON), m.URL, m.Notes, exp, int(tier), now, now)
	if err != nil {
		return fmt.Errorf("vault: write secret: %w", err)
	}
	return nil
}

const metaCols = `name, tags, url, notes, expires_at, min_tier, created_at, updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanMeta(s scanner) (Meta, error) {
	var (
		m              Meta
		tags           string
		exp            sql.NullInt64
		tier           int
		created, updat int64
	)
	if err := s.Scan(&m.Name, &tags, &m.URL, &m.Notes, &exp, &tier, &created, &updat); err != nil {
		return Meta{}, err
	}
	if err := json.Unmarshal([]byte(tags), &m.Tags); err != nil {
		return Meta{}, errors.New("vault: corrupt tags")
	}
	if m.Tags == nil {
		m.Tags = []string{}
	}
	if exp.Valid {
		t := time.UnixMilli(exp.Int64).UTC()
		m.ExpiresAt = &t
	}
	m.MinTier = presence.PresenceTier(tier)
	m.CreatedAt = time.UnixMilli(created).UTC()
	m.UpdatedAt = time.UnixMilli(updat).UTC()
	return m, nil
}

// Get returns a secret's metadata (never its value) or ErrNotFound.
func (v *Vault) Get(ctx context.Context, name string) (Meta, error) {
	unlock, err := v.rlock()
	if err != nil {
		return Meta{}, err
	}
	defer unlock()
	if err := ValidateName(name); err != nil {
		return Meta{}, err
	}
	m, err := scanMeta(v.db.QueryRowContext(ctx, `SELECT `+metaCols+` FROM secrets WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Meta{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return m, err
}

// ListOption filters List.
type ListOption func(*listFilter)

type listFilter struct {
	tag    string
	within *time.Duration
}

// ByTag keeps only secrets carrying tag.
func ByTag(tag string) ListOption { return func(f *listFilter) { f.tag = tag } }

// ExpiringWithin keeps only secrets that have an expiry at or before now+d
// (already-expired secrets are included). Secrets without expiry are excluded.
func ExpiringWithin(d time.Duration) ListOption { return func(f *listFilter) { f.within = &d } }

// List returns metadata only, never values, sorted by name.
func (v *Vault) List(ctx context.Context, opts ...ListOption) ([]Meta, error) {
	unlock, err := v.rlock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	var f listFilter
	for _, o := range opts {
		o(&f)
	}
	rows, err := v.db.QueryContext(ctx, `SELECT `+metaCols+` FROM secrets ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("vault: list: %w", err)
	}
	defer rows.Close()
	deadline := v.cfg.now().Add(0)
	if f.within != nil {
		deadline = deadline.Add(*f.within)
	}
	out := []Meta{}
	for rows.Next() {
		m, err := scanMeta(rows)
		if err != nil {
			return nil, err
		}
		if f.tag != "" && !hasTag(m.Tags, f.tag) {
			continue
		}
		if f.within != nil && (m.ExpiresAt == nil || m.ExpiresAt.After(deadline)) {
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("vault: list: %w", err)
	}
	return out, nil
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

// Exists reports whether name is stored.
func (v *Vault) Exists(ctx context.Context, name string) (bool, error) {
	unlock, err := v.rlock()
	if err != nil {
		return false, err
	}
	defer unlock()
	if err := ValidateName(name); err != nil {
		return false, err
	}
	var one int
	err = v.db.QueryRowContext(ctx, `SELECT 1 FROM secrets WHERE name = ?`, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("vault: lookup: %w", err)
	}
	return true, nil
}

// Delete removes a secret, or returns ErrNotFound.
func (v *Vault) Delete(ctx context.Context, name string) error {
	unlock, err := v.rlock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := ValidateName(name); err != nil {
		return err
	}
	res, err := v.db.ExecContext(ctx, `DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return fmt.Errorf("vault: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return nil
}

// MaskedValue applies the §7 rule: for values of at least 12 characters, four
// asterisks plus the last four characters ("****WXYZ"); otherwise (and for
// values that are not valid UTF-8) eight asterisks.
func MaskedValue(value []byte) string {
	const full = "********"
	if !utf8.Valid(value) {
		return full
	}
	if utf8.RuneCount(value) < 12 {
		return full
	}
	runes := []rune(string(value))
	return "****" + string(runes[len(runes)-4:])
}

// Masked returns the masked form of the stored value (see MaskedValue). It
// decrypts internally; the plaintext is zeroed before returning.
func (v *Vault) Masked(ctx context.Context, name string) (string, error) {
	unlock, err := v.rlock()
	if err != nil {
		return "", err
	}
	defer unlock()
	if err := ValidateName(name); err != nil {
		return "", err
	}
	pt, _, err := v.decrypt(ctx, name)
	if err != nil {
		return "", err
	}
	defer zero(pt)
	return MaskedValue(pt), nil
}

// decrypt loads and decrypts one secret. Caller holds the read lock.
func (v *Vault) decrypt(ctx context.Context, name string) ([]byte, Meta, error) {
	var (
		ct, nonce []byte
		tags      string
		m         Meta
	)
	var exp sql.NullInt64
	var tier int
	var created, updated int64
	err := v.db.QueryRowContext(ctx,
		`SELECT ciphertext, nonce, `+metaCols+` FROM secrets WHERE name = ?`, name).
		Scan(&ct, &nonce, &m.Name, &tags, &m.URL, &m.Notes, &exp, &tier, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, Meta{}, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, Meta{}, fmt.Errorf("vault: read secret: %w", err)
	}
	if exp.Valid {
		t := time.UnixMilli(exp.Int64).UTC()
		m.ExpiresAt = &t
	}
	m.MinTier = presence.PresenceTier(tier)
	pt, err := open(v.key, name, m.MinTier, ct, nonce)
	if err != nil {
		return nil, Meta{}, fmt.Errorf("%w: %s", err, name)
	}
	return pt, m, nil
}
