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

const (
	tagV1       = "grantd.audit.v1\x00"
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
	ID       string // string form of Seq; set by Append/List, ignored on input
	Seq      int64  // monotonic row id; set by Append/List, ignored on input
	TS       time.Time
	Caller   string
	Cwd      string
	Argv     []string
	Secrets  []string // names requested, never values
	Decision string   // one of the Decision* constants
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

// Migrate idempotently creates the audit table and its append-only triggers.
func Migrate(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("%w: nil db", ErrInvalid)
	}
	if _, err := db.ExecContext(ctx, DDL); err != nil {
		return fmt.Errorf("audit: migrate: %w", err)
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

// canonical returns the version-1 canonical encoding (see package comment).
func canonical(seq int64, ts string, e *Entry) []byte {
	b := []byte(tagV1)
	b = binary.BigEndian.AppendUint64(b, uint64(seq))
	b = putStr(b, ts)
	b = putStr(b, e.Caller)
	b = putStr(b, e.Cwd)
	b = putList(b, e.Argv)
	b = putList(b, e.Secrets)
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

func (l *Log) mac(canon, prev []byte) []byte {
	m := hmac.New(sha256.New, l.key)
	m.Write(canon)
	m.Write(prev)
	return m.Sum(nil)
}

// Append adds an entry, chaining it to the previous row, and returns its ID.
// A zero TS is replaced by the current time. Entry.ID/Seq/PrevHMAC/HMAC inputs
// are ignored.
func (l *Log) Append(ctx context.Context, e Entry) (string, error) {
	if !validDecisions[e.Decision] {
		return "", fmt.Errorf("%w: unknown decision %q", ErrInvalid, e.Decision)
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	ts := e.TS.UTC().Format(time.RFC3339Nano)
	argv, secrets := e.Argv, e.Secrets
	if argv == nil {
		argv = []string{}
	}
	if secrets == nil {
		secrets = []string{}
	}
	argvJSON, err := json.Marshal(argv)
	if err != nil {
		return "", err
	}
	secJSON, err := json.Marshal(secrets)
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
	sum := l.mac(canonical(seq, ts, &e), prev)

	var exit any
	if e.ExitCode != nil {
		exit = int64(*e.ExitCode)
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit
(id, ts, caller, cwd, argv, secrets, decision, grant_id, reason, exit_code, duration_ns, prev_hmac, hmac)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		seq, ts, e.Caller, e.Cwd, string(argvJSON), string(secJSON), e.Decision, e.GrantID, e.Reason,
		exit, int64(e.Duration), prev, sum)
	if err != nil {
		return "", fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("audit: commit: %w", err)
	}
	return strconv.FormatInt(seq, 10), nil
}

const selectCols = `id, ts, caller, cwd, argv, secrets, decision, grant_id, reason, exit_code, duration_ns, prev_hmac, hmac`

// scan reads a row; it returns the stored ts string for exact HMAC recompute.
func scan(rows *sql.Rows) (Entry, string, error) {
	var (
		e          Entry
		ts, av, sv string
		exit       sql.NullInt64
		dur        int64
	)
	if err := rows.Scan(&e.Seq, &ts, &e.Caller, &e.Cwd, &av, &sv, &e.Decision, &e.GrantID, &e.Reason,
		&exit, &dur, &e.PrevHMAC, &e.HMAC); err != nil {
		return e, "", err
	}
	e.ID = strconv.FormatInt(e.Seq, 10)
	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		e.TS = t.UTC()
	}
	// Corrupt JSON is left as nil lists; Verify will then flag the row.
	_ = json.Unmarshal([]byte(av), &e.Argv)
	_ = json.Unmarshal([]byte(sv), &e.Secrets)
	if exit.Valid {
		v := int(exit.Int64)
		e.ExitCode = &v
	}
	e.Duration = time.Duration(dur)
	return e, ts, nil
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
		e, _, err := scan(rows)
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
		e, ts, err := scan(rows)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
		}
		res.Entries++
		if res.OK {
			want := l.mac(canonical(e.Seq, ts, &e), prev)
			if !hmac.Equal(e.PrevHMAC, prev) || !hmac.Equal(e.HMAC, want) {
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

// ExportCSV writes every row oldest first as CSV with a header. argv and
// secrets are JSON array strings, so spaces and quotes survive intact.
func (l *Log) ExportCSV(ctx context.Context, w io.Writer) error {
	rows, err := l.db.QueryContext(ctx, `SELECT `+selectCols+` FROM audit ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit: export: %w", err)
	}
	defer rows.Close()
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"id", "ts", "caller", "cwd", "argv", "secrets", "decision", "grant_id", "reason", "exit_code", "duration_ms"})
	for rows.Next() {
		e, ts, err := scan(rows)
		if err != nil {
			return fmt.Errorf("audit: export: %w", err)
		}
		a, _ := json.Marshal(nonNil(e.Argv))
		s, _ := json.Marshal(nonNil(e.Secrets))
		exit := ""
		if e.ExitCode != nil {
			exit = strconv.Itoa(*e.ExitCode)
		}
		_ = cw.Write([]string{e.ID, ts, e.Caller, e.Cwd, string(a), string(s), e.Decision, e.GrantID, e.Reason,
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
