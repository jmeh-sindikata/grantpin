package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Decision values.
const (
	DecisionAllowedGrant    = "allowed_grant"
	DecisionAllowedOnce     = "allowed_once"
	DecisionAllowedNewGrant = "allowed_new_grant"
	DecisionDeniedUser      = "denied_user"
	DecisionRefusedPolicy   = "refused_policy"
	DecisionRefusedTier     = "refused_tier"
	DecisionError           = "error"
	// DecisionCompleted closes a run that was released: the broker writes an
	// allowed_* row (reason "released", no exit code) once the secrets are
	// decrypted and before the command is spawned, and a completed row (exit code, duration, same grant ID, and a
	// reason such as "timeout" or "canceled") when the command ends. A
	// released row with no completed row after it means the daemon died mid-run.
	DecisionCompleted = "completed"
)

var validDecisions = map[string]bool{
	DecisionAllowedGrant: true, DecisionAllowedOnce: true, DecisionAllowedNewGrant: true,
	DecisionDeniedUser: true, DecisionRefusedPolicy: true, DecisionRefusedTier: true, DecisionError: true,
	DecisionCompleted: true,
}

// ErrInvalid is returned for malformed entries or constructor arguments.
var ErrInvalid = errors.New("audit: invalid argument")

// Per-row encoding versions (the enc column). Each version has its own
// domain tag, which is part of the HMAC input, so a row whose enc column was
// flipped no longer verifies. Rows written before Expanded existed are enc 1
// (the column's default for them); everything written now is enc 2.
const (
	encV1 = 1
	encV2 = 2

	tagV1       = "grantd.audit.v1\x00"
	tagV2       = "grantd.audit.v2\x00"
	hmacLen     = sha256.Size
	defaultList = 100
)

// DDL is the schema created by Migrate. Exposed for documentation and tests.
const DDL = `
CREATE TABLE IF NOT EXISTS audit (
  id          INTEGER PRIMARY KEY,
  ts          TEXT    NOT NULL,
  caller      TEXT    NOT NULL,
  cwd         TEXT    NOT NULL,
  argv        TEXT    NOT NULL,
  secrets     TEXT    NOT NULL,
  decision    TEXT    NOT NULL,
  grant_id    TEXT    NOT NULL DEFAULT '',
  reason      TEXT    NOT NULL DEFAULT '',
  exit_code   INTEGER,
  duration_ns INTEGER NOT NULL DEFAULT 0,
  prev_hmac   BLOB    NOT NULL,
  hmac        BLOB    NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
`

// Entry is one audit row (§6). It never contains secret values: Secrets holds
// names only.
type Entry struct {
	ID      string // string form of Seq; set by Append/List, ignored on input
	Seq     int64  // monotonic row id; set by Append/List, ignored on input
	TS      time.Time
	Caller  string
	Cwd     string
	Argv    []string
	Secrets []string // names requested as written (may contain globs), never values
	// Expanded is the concrete names Secrets resolved to after glob expansion
	// (equal to Secrets when there are no globs). Empty on rows written before
	// the request was expanded (validation or policy refusals).
	Expanded []string
	Decision string // one of the Decision* constants
	GrantID  string
	ExitCode *int
	Duration time.Duration
	Reason   string // for denials/refusals/errors

	PrevHMAC []byte // set by List; ignored on input
	HMAC     []byte // set by List; ignored on input
}

// VerifyResult reports the outcome of walking the HMAC chain.
type VerifyResult struct {
	OK         bool
	Entries    int // rows examined
	FirstBadID string
}

// Log is the append-only, HMAC-chained audit log.
type Log struct {
	db  *sql.DB
	key []byte
}

// appendMu serializes appends process-wide so concurrent writers (even via
// several Log values over one DB) cannot fork the chain.
var appendMu sync.Mutex

// addedColumns are columns added after the first release, applied by Migrate
// with ALTER TABLE when missing. Existing rows get the defaults, which is what
// they mean: enc 1 (v1 canonical encoding) and no expansion recorded.
var addedColumns = []struct{ name, ddl string }{
	{"enc", `ALTER TABLE audit ADD COLUMN enc INTEGER NOT NULL DEFAULT 1`},
	{"expanded", `ALTER TABLE audit ADD COLUMN expanded TEXT NOT NULL DEFAULT '[]'`},
}

// Migrate idempotently creates the audit table and its append-only triggers,
// and adds the columns introduced after the first release (enc, expanded).
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: nil db", ErrInvalid)
	}
	if _, err := db.ExecContext(ctx, DDL); err != nil {
		return fmt.Errorf("audit: migrate: %w", err)
	}
	have := map[string]bool{}
	rows, err := db.QueryContext(ctx, `SELECT name FROM pragma_table_info('audit')`)
	if err != nil {
		return fmt.Errorf("audit: migrate: %w", err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return fmt.Errorf("audit: migrate: %w", err)
		}
		have[n] = true
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("audit: migrate: %w", err)
	}
	for _, c := range addedColumns {
		if have[c.name] {
			continue
		}
		if _, err := db.ExecContext(ctx, c.ddl); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("audit: migrate: %w", err)
		}
	}
	return nil
}

// New returns a Log over db using hmacKey. It runs Migrate.
func New(ctx context.Context, db *sql.DB, hmacKey []byte) (*Log, error) {
	if db == nil || len(hmacKey) < 16 {
		return nil, fmt.Errorf("%w: need db and key of at least 16 bytes", ErrInvalid)
	}
	if err := Migrate(ctx, db); err != nil {
		return nil, err
	}
	return &Log{db: db, key: append([]byte(nil), hmacKey...)}, nil
}

func putStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint64(b, uint64(len(s)))
	return append(b, s...)
}

func putList(b []byte, l []string) []byte {
	b = binary.BigEndian.AppendUint64(b, uint64(len(l)))
	for _, s := range l {
		b = putStr(b, s)
	}
	return b
}

// canonicalV1 returns the version-1 canonical encoding (see package comment).
// It is only used to verify rows written before Expanded existed; new rows use
// canonicalV2.
func canonicalV1(seq int64, ts string, e *Entry) []byte {
	b := []byte(tagV1)
	b = binary.BigEndian.AppendUint64(b, uint64(seq))
	b = putStr(b, ts)
	b = putStr(b, e.Caller)
	b = putStr(b, e.Cwd)
	b = putList(b, e.Argv)
	b = putList(b, e.Secrets)
	return putTail(b, e)
}

// canonicalV2 is canonicalV1 under the v2 tag with Expanded after Secrets.
func canonicalV2(seq int64, ts string, e *Entry) []byte {
	b := []byte(tagV2)
	b = binary.BigEndian.AppendUint64(b, uint64(seq))
	b = putStr(b, ts)
	b = putStr(b, e.Caller)
	b = putStr(b, e.Cwd)
	b = putList(b, e.Argv)
	b = putList(b, e.Secrets)
	b = putList(b, e.Expanded)
	return putTail(b, e)
}

// putTail encodes the fields that follow the name lists in every version.
func putTail(b []byte, e *Entry) []byte {
	b = putStr(b, e.Decision)
	b = putStr(b, e.GrantID)
	b = putStr(b, e.Reason)
	if e.ExitCode == nil {
		b = append(b, 0)
	} else {
		b = append(b, 1)
		b = binary.BigEndian.AppendUint64(b, uint64(int64(*e.ExitCode)))
	}
	return binary.BigEndian.AppendUint64(b, uint64(int64(e.Duration)))
}

// canonicalFor encodes e with the encoding its enc column names. ok is false
// for an unknown version, or a v1 row that carries an expansion (v1 cannot
// authenticate it), both of which mean the row was tampered with.
func canonicalFor(enc int, seq int64, ts string, e *Entry) (canon []byte, ok bool) {
	switch enc {
	case encV1:
		if len(e.Expanded) != 0 {
			return nil, false
		}
		return canonicalV1(seq, ts, e), true
	case encV2:
		return canonicalV2(seq, ts, e), true
	}
	return nil, false
}

func (l *Log) mac(canon, prev []byte) []byte {
	m := hmac.New(sha256.New, l.key)
	m.Write(canon)
	m.Write(prev)
	return m.Sum(nil)
}

// Append adds an entry, chaining it to the previous row, and returns its ID.
// A zero TS is replaced by the current time. Fields over their caps (Capped)
// are cut and marked "(truncated)" before the row is written. Entry.ID/Seq/PrevHMAC/HMAC inputs
// are ignored.
func (l *Log) Append(ctx context.Context, e Entry) (string, error) {
	if !validDecisions[e.Decision] {
		return "", fmt.Errorf("%w: unknown decision %q", ErrInvalid, e.Decision)
	}
	// Bound every field first: the row, its HMAC and what List and export
	// return are all computed from the bounded copy (see caps.go).
	e = Capped(e)
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	ts := e.TS.UTC().Format(time.RFC3339Nano)
	argvJSON, err := json.Marshal(nonNil(e.Argv))
	if err != nil {
		return "", err
	}
	secJSON, err := json.Marshal(nonNil(e.Secrets))
	if err != nil {
		return "", err
	}
	expJSON, err := json.Marshal(nonNil(e.Expanded))
	if err != nil {
		return "", err
	}

	appendMu.Lock()
	defer appendMu.Unlock()
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prev := make([]byte, hmacLen)
	var lastID int64
	var lastHMAC []byte
	switch err := tx.QueryRowContext(ctx, `SELECT id, hmac FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &lastHMAC); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return "", fmt.Errorf("audit: read last: %w", err)
	default:
		prev = lastHMAC
	}
	seq := lastID + 1
	sum := l.mac(canonicalV2(seq, ts, &e), prev)

	var exit any
	if e.ExitCode != nil {
		exit = int64(*e.ExitCode)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit
(id, ts, caller, cwd, argv, secrets, expanded, decision, grant_id, reason, exit_code, duration_ns, prev_hmac, hmac, enc)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		seq, ts, e.Caller, e.Cwd, string(argvJSON), string(secJSON), string(expJSON), e.Decision, e.GrantID, e.Reason,
		exit, int64(e.Duration), prev, sum, encV2)
	if err != nil {
		return "", fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("audit: commit: %w", err)
	}
	return strconv.FormatInt(seq, 10), nil
}

const selectCols = `id, ts, caller, cwd, argv, secrets, expanded, decision, grant_id, reason, exit_code, duration_ns, prev_hmac, hmac, enc`

// scan reads a row; it returns the stored ts string and the enc column for
// exact HMAC recompute.
func scan(rows *sql.Rows) (e Entry, ts string, enc int, err error) {
	var (
		av, sv, xv string
		exit       sql.NullInt64
		dur        int64
	)
	if err := rows.Scan(&e.Seq, &ts, &e.Caller, &e.Cwd, &av, &sv, &xv, &e.Decision, &e.GrantID, &e.Reason,
		&exit, &dur, &e.PrevHMAC, &e.HMAC, &enc); err != nil {
		return e, "", 0, err
	}
	e.ID = strconv.FormatInt(e.Seq, 10)
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		e.TS = t.UTC()
	}
	// Corrupt JSON is left as nil lists; Verify will then flag the row.
	_ = json.Unmarshal([]byte(av), &e.Argv)
	_ = json.Unmarshal([]byte(sv), &e.Secrets)
	_ = json.Unmarshal([]byte(xv), &e.Expanded)
	if exit.Valid {
		v := int(exit.Int64)
		e.ExitCode = &v
	}
	e.Duration = time.Duration(dur)
	return e, ts, enc, nil
}

// List returns entries newest first. limit <= 0 uses a default of 100.
func (l *Log) List(ctx context.Context, limit, offset int) ([]Entry, error) {
	if limit <= 0 {
		limit = defaultList
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := l.db.QueryContext(ctx, `SELECT `+selectCols+` FROM audit ORDER BY id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, _, _, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: list: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ListBefore is List for paging by ID: the newest limit entries whose Seq is
// below beforeSeq, newest first. beforeSeq <= 0 means no upper bound.
func (l *Log) ListBefore(ctx context.Context, limit int, beforeSeq int64) ([]Entry, error) {
	if limit <= 0 {
		limit = defaultList
	}
	q := `SELECT ` + selectCols + ` FROM audit `
	args := []any{}
	if beforeSeq > 0 {
		q += `WHERE id < ? `
		args = append(args, beforeSeq)
	}
	rows, err := l.db.QueryContext(ctx, q+`ORDER BY id DESC LIMIT ?`, append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, _, _, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("audit: list: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Verify walks the whole chain from the first row, recomputing every HMAC.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT `+selectCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
	}
	defer rows.Close()
	res := VerifyResult{OK: true}
	prev := make([]byte, hmacLen)
	for rows.Next() {
		e, ts, enc, err := scan(rows)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
		}
		res.Entries++
		if res.OK {
			canon, known := canonicalFor(enc, e.Seq, ts, &e)
			if !known || !hmac.Equal(e.PrevHMAC, prev) || !hmac.Equal(e.HMAC, l.mac(canon, prev)) {
				res.OK = false
				res.FirstBadID = e.ID
			}
		}
		prev = e.HMAC
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
	}
	return res, nil
}

// ExportCSV writes every row oldest first as CSV with a header (fields over the
// Append caps are shortened and marked, see Capped). argv and
// secrets are JSON array strings, so spaces and quotes survive intact.
func (l *Log) ExportCSV(ctx context.Context, w io.Writer) error {
	rows, err := l.db.QueryContext(ctx, `SELECT `+selectCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}
	defer rows.Close()
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "ts", "caller", "cwd", "argv", "secrets", "expanded", "decision", "grant_id", "reason", "exit_code", "duration_ms"})
	for rows.Next() {
		e, ts, _, err := scan(rows)
		if err != nil {
			return fmt.Errorf("audit: export: %w", err)
		}
		// Rows written before Append bounded its fields can be huge; the
		// export shows them in the bounded form, marked "(truncated)", so that
		// one of them does not make the whole log unexportable.
		e = Capped(e)
		a, _ := json.Marshal(nonNil(e.Argv))
		s, _ := json.Marshal(nonNil(e.Secrets))
		x, _ := json.Marshal(nonNil(e.Expanded))
		exit := ""
		if e.ExitCode != nil {
			exit = strconv.Itoa(*e.ExitCode)
		}
		_ = cw.Write([]string{e.ID, ts, e.Caller, e.Cwd, string(a), string(s), string(x), e.Decision, e.GrantID, e.Reason,
			exit, strconv.FormatInt(e.Duration.Milliseconds(), 10)})
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}
	cw.Flush()
	return cw.Error()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
