package grant

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/bmatcuk/doublestar/v4"
)

// DDL is the schema owned by this package. Times are unix nanoseconds.
// secrets and cmd_prefix are JSON arrays of strings. kind is "" for a grant
// created from the approval dialog and "standing" for one the human created
// with `grants add`. mac authenticates the row, kind included (see the
// package comment): a row whose mac does not verify is never matched.
const DDL = `CREATE TABLE IF NOT EXISTS grants (
	id             TEXT    PRIMARY KEY,
	caller         TEXT    NOT NULL,
	cwd_prefix     TEXT    NOT NULL,
	secrets        TEXT    NOT NULL,
	cmd_prefix     TEXT    NOT NULL,
	created_at     INTEGER NOT NULL,
	expires_at     INTEGER NOT NULL,
	uses_remaining INTEGER,
	mac            BLOB    NOT NULL,
	kind           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS grants_caller_expires ON grants (caller, expires_at);`

// Migrate creates the grants table if needed. It is idempotent. A grants table
// from before rows were authenticated (no mac column) is dropped: its rows
// cannot be trusted, and losing grants only means being asked again. A table
// from before standing grants (no kind column) gains it; the existing rows
// are dialog grants (kind "") and their MACs stay valid.
func Migrate(ctx context.Context, db *sql.DB) error {
	var cols, hasMAC, hasKind int
	if err := db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(name = 'mac'), 0), COALESCE(SUM(name = 'kind'), 0) FROM pragma_table_info('grants')`).Scan(&cols, &hasMAC, &hasKind); err != nil {
		return fmt.Errorf("grant: migrate: %w", err)
	}
	if cols > 0 && hasMAC == 0 {
		if _, err := db.ExecContext(ctx, `DROP TABLE grants`); err != nil {
			return fmt.Errorf("grant: migrate: %w", err)
		}
	} else if cols > 0 && hasKind == 0 {
		if _, err := db.ExecContext(ctx, `ALTER TABLE grants ADD COLUMN kind TEXT NOT NULL DEFAULT ''`); err != nil {
			return fmt.Errorf("grant: migrate: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, DDL); err != nil {
		return fmt.Errorf("grant: migrate: %w", err)
	}
	return nil
}

// Store persists grants in the shared vault SQLite database. Call Migrate
// first. A Store is safe for concurrent use.
type Store struct {
	db     *sql.DB
	key    []byte
	now    func() time.Time
	log    *slog.Logger
	mu     sync.Mutex // serialises Consume so use-counting never interleaves in-process
	warned sync.Map   // grant IDs already reported as tampered
}

// NewStore returns a Store over db using the wall clock for Get/List/Purge/Add.
// macKey authenticates every row (the daemon passes vault.DeriveKey("grant-mac"));
// an empty key makes Add fail and every row count as tampered, so nothing ever
// matches.
func NewStore(db *sql.DB, macKey []byte) *Store {
	return &Store{db: db, key: slices.Clone(macKey), now: time.Now, log: slog.New(slog.DiscardHandler)}
}

// SetLogger sets where tampered rows are reported (WARN, once per row, never
// with row content). Default: discard.
func (s *Store) SetLogger(l *slog.Logger) {
	if l != nil {
		s.log = l
	}
}

// canonicalTag versions the MAC input encoding. A row with a kind (standing)
// is encoded under canonicalTagKind and carries the kind after uses_remaining,
// so a dialog row cannot be turned into a standing one (or back) without the
// key. Rows without a kind keep the original v1 encoding, so grants stored
// before kinds existed still verify.
const (
	canonicalTag     = "grantpin.grant.v1\x00"
	canonicalTagKind = "grantpin.grant.v2\x00"
)

// canonical is the MAC input for one row, built from decoded values so that
// JSON whitespace is irrelevant:
//
//	"grantpin.grant.v1\x00"      domain/version tag
//	id, caller, cwd_prefix     string: uint64 big-endian length, then bytes
//	secrets, cmd_prefix        uint64 count, then count strings
//	created_at, expires_at     int64 big-endian, unix nanoseconds
//	uses_remaining             byte 0, or byte 1 followed by int64 big-endian
//	kind                       only under the v2 tag (kind != ""): string
//
// Length prefixes make the encoding injective.
func canonical(id, caller, cwd string, secrets, cmd []string, createdNs, expiresNs int64, uses *int64, kind string) []byte {
	tag := canonicalTag
	if kind != "" {
		tag = canonicalTagKind
	}
	b := []byte(tag)
	str := func(v string) {
		b = binary.BigEndian.AppendUint64(b, uint64(len(v)))
		b = append(b, v...)
	}
	list := func(vs []string) {
		b = binary.BigEndian.AppendUint64(b, uint64(len(vs)))
		for _, v := range vs {
			str(v)
		}
	}
	str(id)
	str(caller)
	str(cwd)
	list(secrets)
	list(cmd)
	b = binary.BigEndian.AppendUint64(b, uint64(createdNs))
	b = binary.BigEndian.AppendUint64(b, uint64(expiresNs))
	if uses == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = binary.BigEndian.AppendUint64(b, uint64(*uses))
	}
	if kind != "" {
		str(kind)
	}
	return b
}

// kindOf is the stored kind for g.
func kindOf(g Grant) string {
	if g.Standing {
		return KindStanding
	}
	return ""
}

func (s *Store) sign(canon []byte) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write(canon)
	return m.Sum(nil)
}

func (s *Store) verify(canon, mac []byte) bool {
	return len(s.key) > 0 && hmac.Equal(s.sign(canon), mac)
}

// SetClock overrides the clock used by Add (default CreatedAt), Get, List,
// Consume and Purge. Intended for tests. Match always uses Query.Now.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

const cols = `id, caller, cwd_prefix, secrets, cmd_prefix, created_at, expires_at, uses_remaining, mac, kind`

type scanner interface{ Scan(dest ...any) error }

// scan decodes one row and verifies its MAC. A row that cannot be decoded or
// whose MAC does not verify is returned with Tampered set (and only the fields
// that could be decoded); it is never an error, so one forged row cannot break
// listing or matching of the genuine ones.
func (s *Store) scan(r scanner, now time.Time) (Grant, error) {
	var (
		g              Grant
		secrets, cmd   string
		created, expir int64
		uses           sql.NullInt64
		mac            []byte
		kind           string
	)
	if err := r.Scan(&g.ID, &g.Caller, &g.CwdPrefix, &secrets, &cmd, &created, &expir, &uses, &mac, &kind); err != nil {
		return Grant{}, err
	}
	g.CreatedAt = time.Unix(0, created).UTC()
	g.ExpiresAt = time.Unix(0, expir).UTC()
	var u *int64
	if uses.Valid {
		n := int(uses.Int64)
		g.UsesRemaining = &n
		u = &uses.Int64
	}
	g.Expired = g.expiredAt(now)
	g.Standing = kind == KindStanding
	if json.Unmarshal([]byte(secrets), &g.Secrets) != nil || json.Unmarshal([]byte(cmd), &g.CmdPrefix) != nil ||
		(kind != "" && kind != KindStanding) ||
		!s.verify(canonical(g.ID, g.Caller, g.CwdPrefix, g.Secrets, g.CmdPrefix, created, expir, u, kind), mac) {
		g.Tampered = true
		s.reportTampered(g.ID)
	}
	return g, nil
}

func (s *Store) reportTampered(id string) {
	if _, seen := s.warned.LoadOrStore(id, struct{}{}); !seen {
		s.log.Warn("grant row failed authentication; ignoring it (the vault file was modified outside grantpin)", "grant_id", id)
	}
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
	if len(s.key) == 0 {
		return nil, fmt.Errorf("%w: store has no MAC key", ErrInvalidGrant)
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
	var u *int64
	if out.UsesRemaining != nil {
		n := int64(*out.UsesRemaining)
		uses, u = n, &n
	}
	kind := kindOf(out)
	mac := s.sign(canonical(out.ID, out.Caller, out.CwdPrefix, out.Secrets, out.CmdPrefix,
		out.CreatedAt.UnixNano(), out.ExpiresAt.UnixNano(), u, kind))
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO grants (`+cols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		out.ID, out.Caller, out.CwdPrefix, string(secrets), string(cmd),
		out.CreatedAt.UnixNano(), out.ExpiresAt.UnixNano(), uses, mac, kind)
	if err != nil {
		return nil, fmt.Errorf("grant: add: %w", err)
	}
	out.Expired = out.expiredAt(now)
	return &out, nil
}

// Get returns one grant (expired or not, flagged via Expired; a row that fails
// authentication is returned with Tampered set) or ErrNotFound.
func (s *Store) Get(ctx context.Context, id string) (*Grant, error) {
	g, err := s.scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM grants WHERE id = ?`, id), s.now())
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("grant: get: %w", err)
	}
	return &g, nil
}

// List returns every stored grant: non-expired first, then expired (flagged
// with Expired), each group oldest first. Rows that fail authentication are
// included, flagged Tampered, so they can be shown to the user.
func (s *Store) List(ctx context.Context) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM grants ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("grant: list: %w", err)
	}
	defer rows.Close()
	now := s.now()
	var out []Grant
	for rows.Next() {
		g, err := s.scan(rows, now)
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
//   - caller is the same caller (proto.SameCaller: equal after normalising case
//     and separators; informational, not trusted). The caller is compared in Go,
//     not in SQL, so rows stored in any spelling keep matching;
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
// Match never changes the store: a use of a finite-use grant is taken by
// Consume, which the caller invokes once the release is really going ahead (a
// request that matches and then fails before releasing must not burn a use).
func (s *Store) Match(ctx context.Context, q Query) (*Grant, error) {
	if !filepath.IsAbs(q.Cwd) {
		return nil, fmt.Errorf("%w: cwd %q is not absolute", ErrNoMatch, q.Cwd)
	}
	cwd := filepath.Clean(q.Cwd)
	nowNs := q.Now.UnixNano()

	rows, err := s.db.QueryContext(ctx,
		`SELECT `+cols+` FROM grants
		 WHERE expires_at > ? AND (uses_remaining IS NULL OR uses_remaining > 0)
		 ORDER BY created_at, id`, nowNs)
	if err != nil {
		return nil, fmt.Errorf("grant: match: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		g, err := s.scan(rows, q.Now)
		if err != nil {
			return nil, fmt.Errorf("grant: match: %w", err)
		}
		if !g.Tampered && g.matches(q, cwd) {
			return &g, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("grant: match: %w", err)
	}
	return nil, ErrNoMatch
}

// consumeAttempts bounds the compare-and-swap retries for one grant when
// several Store values share a database.
const consumeAttempts = 64

// Consume takes one use of grant id. For a grant with unlimited uses it only
// checks that the row still exists and authenticates (a grant revoked since
// Match no longer releases). For a finite-use grant it atomically replaces
// uses_remaining and the row's mac, guarded by the count it read, retrying with
// a fresh read if another writer got there first, so concurrent callers can
// never take more uses than the grant has. It returns ErrNotFound for a missing
// or tampered row and ErrExhausted when no use is left. Expiry is not checked:
// Match did that moments earlier.
func (s *Store) Consume(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range consumeAttempts {
		g, err := s.scan(s.db.QueryRowContext(ctx, `SELECT `+cols+` FROM grants WHERE id = ?`, id), s.now())
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("grant: consume: %w", err)
		}
		switch {
		case g.Tampered:
			return ErrNotFound
		case g.UsesRemaining == nil:
			return nil
		case *g.UsesRemaining <= 0:
			return ErrExhausted
		}
		left := int64(*g.UsesRemaining - 1)
		mac := s.sign(canonical(g.ID, g.Caller, g.CwdPrefix, g.Secrets, g.CmdPrefix,
			g.CreatedAt.UnixNano(), g.ExpiresAt.UnixNano(), &left, kindOf(g)))
		res, err := s.db.ExecContext(ctx,
			`UPDATE grants SET uses_remaining = ?, mac = ? WHERE id = ? AND uses_remaining = ?`,
			left, mac, g.ID, int64(*g.UsesRemaining))
		if err != nil {
			return fmt.Errorf("grant: consume: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return fmt.Errorf("grant: consume: %w", err)
		}
		if n == 1 {
			return nil
		}
		// Lost the race (or the row changed): read it again.
	}
	return fmt.Errorf("grant: consume: too much contention")
}
