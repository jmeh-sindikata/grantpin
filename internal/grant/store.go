package grant

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

// DDL is the schema owned by this package. Times are unix nanoseconds.
// secrets and cmd_prefix are JSON arrays of strings.
const DDL = `CREATE TABLE IF NOT EXISTS grants (
	id             TEXT    PRIMARY KEY,
	caller         TEXT    NOT NULL,
	cwd_prefix     TEXT    NOT NULL,
	secrets        TEXT    NOT NULL,
	cmd_prefix     TEXT    NOT NULL,
	created_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL,
	uses_remaining INTEGER
);
CREATE INDEX IF NOT EXISTS grants_caller_expires ON grants (caller, expires_at);`

// Migrate creates the grants table if needed. It is idempotent.
func Migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, DDL); err != nil {
		return fmt.Errorf("grant: migrate: %w", err)
	}
	return nil
}

// Store persists grants in the shared vault SQLite database. Call Migrate
// first. A Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	now func() time.Time
	mu  sync.Mutex // serialises Match so use-counting never interleaves in-process
}

// NewStore returns a Store over db using the wall clock for Get/List/Purge/Add.
func NewStore(db *sql.DB) *Store { return &Store{db: db, now: time.Now} }

// SetClock overrides the clock used by Add (default CreatedAt), Get, List and
// Purge. Intended for tests. Match always uses Query.Now.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

const cols = `id, caller, cwd_prefix, secrets, cmd_prefix, created_at, expires_at, uses_remaining`

type scanner interface{ Scan(dest ...any) error }

func scan(r scanner, now time.Time) (Grant, error) {
	var (
		g              Grant
		secrets, cmd   string
		created, expir int64
		uses           sql.NullInt64
	)
	if err := r.Scan(&g.ID, &g.Caller, &g.CwdPrefix, &secrets, &cmd, &created, &expir, &uses); err != nil {
		return Grant{}, err
	}
	if err := json.Unmarshal([]byte(secrets), &g.Secrets); err != nil {
		return Grant{}, fmt.Errorf("grant %s: corrupt secrets: %w", g.ID, err)
	}
	if err := json.Unmarshal([]byte(cmd), &g.CmdPrefix); err != nil {
		return Grant{}, fmt.Errorf("grant %s: corrupt cmd_prefix: %w", g.ID, err)
	}
	g.CreatedAt = time.Unix(0, created).UTC()
	g.ExpiresAt = time.Unix(0, expir).UTC()
	if uses.Valid {
		n := int(uses.Int64)
		g.UsesRemaining = &n
	}
	g.Expired = g.expiredAt(now)
	return g, nil
}

// Add validates and stores g, returning the stored grant. The ID is always
// freshly generated (any g.ID is ignored). CwdPrefix must be absolute and is
// cleaned. Secrets must be non-empty with valid patterns, CmdPrefix must be
// non-empty, ExpiresAt must be after CreatedAt (zero CreatedAt = now), and
// UsesRemaining, if set, must be positive.
func (s *Store) Add(ctx context.Context, g Grant) (*Grant, error) {
	bad := func(format string, a ...any) (*Grant, error) {
		return nil, fmt.Errorf("%w: %s", ErrInvalidGrant, fmt.Sprintf(format, a...))
	}
	if !filepath.IsAbs(g.CwdPrefix) {
		return bad("cwd_prefix %q is not absolute", g.CwdPrefix)
	}
	if len(g.Secrets) == 0 {
		return bad("no secrets")
	}
	for _, sec := range g.Secrets {
		if sec == "" || !doublestar.ValidatePattern(sec) {
			return bad("invalid secret %q", sec)
		}
	}
	if len(g.CmdPrefix) == 0 || slices.Contains(g.CmdPrefix, "") {
		return bad("cmd_prefix must be a non-empty argv prefix without empty elements")
	}
	if g.UsesRemaining != nil && *g.UsesRemaining <= 0 {
		return bad("uses_remaining must be positive")
	}
	out := g
	out.Expired = false
	out.CwdPrefix = filepath.Clean(g.CwdPrefix)
	out.Secrets = slices.Clone(g.Secrets)
	out.CmdPrefix = slices.Clone(g.CmdPrefix)
	if g.UsesRemaining != nil {
		n := *g.UsesRemaining
		out.UsesRemaining = &n
	}
	now := s.now()
	if out.CreatedAt.IsZero() {
		out.CreatedAt = now
	}
	if !out.ExpiresAt.After(out.CreatedAt) {
		return bad("expires_at must be after created_at")
	}
	id, err := newID()
	if err != nil {
		return nil, err
	}
	out.ID = id
	secrets, _ := json.Marshal(out.Secrets)
	cmd, _ := json.Marshal(out.CmdPrefix)
	var uses any
	if out.UsesRemaining != nil {
		uses = int64(*out.UsesRemaining)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grants (`+cols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		out.ID, out.Caller, out.CwdPrefix, string(secrets), string(cmd),
		out.CreatedAt.UnixNano(), out.ExpiresAt.UnixNano(), uses)
	if err != nil {
		return nil, fmt.Errorf("grant: add: %w", err)
	}
	out.Expired = out.expiredAt(now)
	return &out, nil
}

// Get returns one grant (expired or not, flagged via Expired) or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*Grant, error) {
	g, err := scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM grants WHERE id = ?`, id), s.now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grant: get: %w", err)
	}
	return &g, nil
}

// List returns every stored grant: non-expired first, then expired (flagged
// with Expired), each group oldest first.
func (s *Store) List(ctx context.Context) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM grants ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("grant: list: %w", err)
	}
	defer rows.Close()
	now := s.now()
	var out []Grant
	for rows.Next() {
		g, err := scan(rows, now)
		if err != nil {
			return nil, fmt.Errorf("grant: list: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grant: list: %w", err)
	}
	sort.SliceStable(out, func(i, j int) bool { return !out[i].Expired && out[j].Expired })
	return out, nil
}

// Revoke deletes one grant, or returns ErrNotFound.
func (s *Store) Revoke(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("grant: revoke: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeAll deletes every grant.
func (s *Store) RevokeAll(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM grants`); err != nil {
		return fmt.Errorf("grant: revoke all: %w", err)
	}
	return nil
}

// Purge deletes expired grants and returns how many were removed.
func (s *Store) Purge(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM grants WHERE expires_at <= ?`, s.now().UnixNano())
	if err != nil {
		return 0, fmt.Errorf("grant: purge: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Match returns the oldest stored grant satisfying q, or ErrNoMatch.
//
// A grant matches iff all of:
//   - caller is equal (informational, not trusted);
//   - q.Cwd is absolute and, after filepath.Clean, equals CwdPrefix or lies
//     below it (lexical only: ".." is collapsed by Clean, symlinks are NOT
//     resolved; "/a/foo" is not under "/a/f");
//   - q.Secrets is non-empty and every entry is covered: a literal name by an
//     equal grant entry or a doublestar glob entry that matches it; a glob
//     request only by a textually identical grant entry;
//   - CmdPrefix is non-empty and an element-wise prefix of q.Argv;
//   - q.Now is before ExpiresAt (a grant is expired at the ExpiresAt instant);
//   - UsesRemaining is nil or > 0.
//
// On success with a finite UsesRemaining, one use is consumed atomically
// (UPDATE ... WHERE uses_remaining > 0, rows affected checked); the returned
// grant reflects the decremented count. If a concurrent request took the last
// use, the next candidate is tried.
func (s *Store) Match(ctx context.Context, q Query) (*Grant, error) {
	if !filepath.IsAbs(q.Cwd) {
		return nil, fmt.Errorf("%w: cwd %q is not absolute", ErrNoMatch, q.Cwd)
	}
	cwd := filepath.Clean(q.Cwd)
	nowNs := q.Now.UnixNano()

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cols+` FROM grants
		 WHERE caller = ? AND expires_at > ? AND (uses_remaining IS NULL OR uses_remaining > 0)
		 ORDER BY created_at, id`, q.Caller, nowNs)
	if err != nil {
		return nil, fmt.Errorf("grant: match: %w", err)
	}
	var cands []Grant
	for rows.Next() {
		g, err := scan(rows, q.Now)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("grant: match: %w", err)
		}
		if g.matches(q, cwd) {
			cands = append(cands, g)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("grant: match: %w", err)
	}

	for _, g := range cands {
		if g.UsesRemaining == nil {
			return &g, nil
		}
		res, err := s.db.ExecContext(ctx,
			`UPDATE grants SET uses_remaining = uses_remaining - 1
			 WHERE id = ? AND uses_remaining > 0 AND expires_at > ?`, g.ID, nowNs)
		if err != nil {
			return nil, fmt.Errorf("grant: match: %w", err)
		}
		if n, err := res.RowsAffected(); err != nil {
			return nil, fmt.Errorf("grant: match: %w", err)
		} else if n == 1 {
			left := *g.UsesRemaining - 1
			g.UsesRemaining = &left
			return &g, nil
		}
	}
	return nil, ErrNoMatch
}
