package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newLog(t *testing.T) (*Log, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "a.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { db.Close() })
	l, err := New(context.Background(), db, testKey)
	if err != nil {
		t.Fatal(err)
	}
	return l, db
}

func ip(i int) *int { return &i }

func sample(n int) Entry {
	return Entry{
		TS: time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC), Caller: "claude-code", Cwd: "/work/app",
		Argv: []string{"php", "artisan", "migrate x"}, Secrets: []string{"aws/key", "DB_URL"},
		Decision: DecisionAllowedOnce, GrantID: "g1", ExitCode: ip(n), Duration: 1500 * time.Millisecond,
	}
}

func TestGoldenCanonicalHMAC(t *testing.T) {
	l := &Log{key: testKey}
	e := sample(3)
	e.Reason = "r"
	ts := e.TS.UTC().Format(time.RFC3339Nano)
	canon := canonicalV1(7, ts, &e)
	got := hex.EncodeToString(l.mac(canon, make([]byte, 32)))
	const want = "ae0373c4242f70d0d55c9cd9d59f7d1dd28e350795779bdff0ae577f9c510a22"
	if got != want {
		t.Fatalf("v1 canonical encoding changed (existing rows would stop verifying): got %s", got)
	}
}

func TestGoldenCanonicalHMACV2(t *testing.T) {
	l := &Log{key: testKey}
	e := sample(3)
	e.Reason = "r"
	e.Expanded = []string{"aws/key", "aws/secret"}
	ts := e.TS.UTC().Format(time.RFC3339Nano)
	canon := canonicalV2(7, ts, &e)
	if !bytes.HasPrefix(canon, []byte("grantd.audit.v2\x00")) {
		t.Fatalf("v2 tag missing: %q", canon[:16])
	}
	got := hex.EncodeToString(l.mac(canon, make([]byte, 32)))
	const want = "f8dfb7c509fb87957dfa910d86e8cdbd785fc9a684db81ed3898013c38889114"
	if got != want {
		t.Fatalf("v2 canonical encoding changed: got %s", got)
	}
}

// oldSchemaLog builds a database exactly as a pre-Expanded grantpin left it: the
// original table (no enc/expanded columns) with rows written by the v1 encoder.
func oldSchemaLog(t *testing.T, n int) (*sql.DB, *Log) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(ctx, DDL); err != nil {
		t.Fatal(err)
	}
	l := &Log{db: db, key: testKey}
	prev := make([]byte, hmacLen)
	for i := 1; i <= n; i++ {
		e := sample(i)
		ts := e.TS.UTC().Format(time.RFC3339Nano)
		sum := l.mac(canonicalV1(int64(i), ts, &e), prev)
		_, err := db.ExecContext(ctx, `INSERT INTO audit
(id, ts, caller, cwd, argv, secrets, decision, grant_id, reason, exit_code, duration_ns, prev_hmac, hmac)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`, i, ts, e.Caller, e.Cwd, `["php","artisan","migrate x"]`, `["aws/key","DB_URL"]`,
			e.Decision, e.GrantID, e.Reason, int64(*e.ExitCode), int64(e.Duration), prev, sum)
		if err != nil {
			t.Fatal(err)
		}
		prev = sum
	}
	return db, l
}

func TestMixedV1V2Verify(t *testing.T) {
	ctx := context.Background()
	db, l := oldSchemaLog(t, 3)
	if res, err := l.Verify(ctx); err == nil {
		t.Fatalf("verify on the old schema should not know the enc column: %+v", res)
	}
	for i := 0; i < 2; i++ { // idempotent
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if res, err := l.Verify(ctx); err != nil || !res.OK || res.Entries != 3 {
		t.Fatalf("v1 rows after migrate = %+v %v", res, err)
	}
	for i := 0; i < 3; i++ {
		e := sample(10 + i)
		e.Expanded = []string{"aws/key", "aws/other"}
		if _, err := l.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.Verify(ctx)
	if err != nil || !res.OK || res.Entries != 6 {
		t.Fatalf("mixed verify = %+v %v", res, err)
	}
	var encs []int
	rows, _ := db.Query(`SELECT enc FROM audit ORDER BY id`)
	for rows.Next() {
		var v int
		rows.Scan(&v)
		encs = append(encs, v)
	}
	rows.Close()
	if len(encs) != 6 || encs[0] != 1 || encs[2] != 1 || encs[3] != 2 || encs[5] != 2 {
		t.Fatalf("enc column = %v", encs)
	}
	list, _ := l.List(ctx, 1, 0)
	if len(list[0].Expanded) != 2 || list[0].Expanded[1] != "aws/other" {
		t.Fatalf("expanded round trip: %+v", list[0])
	}
	old, _ := l.List(ctx, 1, 5)
	if len(old[0].Expanded) != 0 {
		t.Fatalf("v1 row has expanded: %+v", old[0])
	}
}

func TestVerifyDetectsEncAndExpandedTamper(t *testing.T) {
	ctx := context.Background()
	for name, stmt := range map[string]string{
		"v1 row claims v2":          `UPDATE audit SET enc=2 WHERE id=2`,
		"v2 row claims v1":          `UPDATE audit SET enc=1 WHERE id=5`,
		"unknown enc":               `UPDATE audit SET enc=3 WHERE id=5`,
		"expanded added to v1 row":  `UPDATE audit SET expanded='["x"]' WHERE id=2`,
		"expanded edited on v2 row": `UPDATE audit SET expanded='["x"]' WHERE id=5`,
	} {
		t.Run(name, func(t *testing.T) {
			db, l := oldSchemaLog(t, 3)
			if err := Migrate(ctx, db); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 3; i++ {
				e := sample(i)
				e.Expanded = []string{"aws/key"}
				if _, err := l.Append(ctx, e); err != nil {
					t.Fatal(err)
				}
			}
			db.Exec(`DROP TRIGGER audit_no_update`)
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			res, err := l.Verify(ctx)
			if err != nil || res.OK {
				t.Fatalf("tamper undetected: %+v %v", res, err)
			}
			want := "2"
			if strings.Contains(name, "v2 row") || name == "unknown enc" {
				want = "5"
			}
			if res.FirstBadID != want {
				t.Fatalf("FirstBadID = %q want %q", res.FirstBadID, want)
			}
		})
	}
}

func TestAppendListVerify(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	res, err := l.Verify(ctx)
	if err != nil || !res.OK || res.Entries != 0 {
		t.Fatalf("empty verify = %+v %v", res, err)
	}
	for i := 0; i < 5; i++ {
		id, err := l.Append(ctx, sample(i))
		if err != nil || id != string(rune('1'+i)) {
			t.Fatalf("append %d: %q %v", i, id, err)
		}
	}
	nilEntry := Entry{Decision: DecisionError, Reason: "boom"} // zero TS, nil slices, nil exit
	if _, err := l.Append(ctx, nilEntry); err != nil {
		t.Fatal(err)
	}
	list, err := l.List(ctx, 0, 0)
	if err != nil || len(list) != 6 || list[0].ID != "6" || list[5].ID != "1" {
		t.Fatalf("list = %v %v", len(list), err)
	}
	if list[0].ExitCode != nil || list[0].Reason != "boom" || list[0].TS.IsZero() {
		t.Fatalf("nil entry round trip: %+v", list[0])
	}
	e := list[4] // id 2
	if *e.ExitCode != 1 || e.Duration != 1500*time.Millisecond || e.Argv[2] != "migrate x" || e.Secrets[1] != "DB_URL" ||
		!e.TS.Equal(sample(0).TS) || e.Seq != 2 || len(e.HMAC) != 32 {
		t.Fatalf("round trip: %+v", e)
	}
	page, _ := l.List(ctx, 2, 2)
	if len(page) != 2 || page[0].ID != "4" {
		t.Fatalf("page = %+v", page)
	}
	if neg, _ := l.List(ctx, 1, -5); len(neg) != 1 {
		t.Fatal("negative offset")
	}
	res, err = l.Verify(ctx)
	if err != nil || !res.OK || res.Entries != 6 || res.FirstBadID != "" {
		t.Fatalf("verify = %+v %v", res, err)
	}
}

func TestKnownDecisions(t *testing.T) {
	l, _ := newLog(t)
	all := []string{
		DecisionAllowedGrant, DecisionAllowedOnce, DecisionAllowedNewGrant, DecisionDeniedUser,
		DecisionRefusedPolicy, DecisionRefusedTier, DecisionError, DecisionCompleted,
	}
	if len(validDecisions) != len(all) {
		t.Errorf("validDecisions has %d entries, want %d", len(validDecisions), len(all))
	}
	for _, d := range all {
		if _, err := l.Append(context.Background(), Entry{Decision: d}); err != nil {
			t.Errorf("decision %q rejected: %v", d, err)
		}
	}
	if res, err := l.Verify(context.Background()); err != nil || !res.OK || res.Entries != len(all) {
		t.Fatalf("verify = %+v %v", res, err)
	}
}

func TestAppendValidation(t *testing.T) {
	l, _ := newLog(t)
	if _, err := l.Append(context.Background(), Entry{Decision: "allow"}); err == nil {
		t.Fatal("bad decision accepted")
	}
	if _, err := New(context.Background(), nil, testKey); err == nil {
		t.Fatal("nil db accepted")
	}
	db, _ := sql.Open("sqlite", ":memory:")
	defer db.Close()
	if _, err := New(context.Background(), db, []byte("short")); err == nil {
		t.Fatal("short key accepted")
	}
	if err := Migrate(context.Background(), nil); err == nil {
		t.Fatal("nil db migrate")
	}
}

func TestMigrateIdempotent(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	if _, err := l.Append(ctx, sample(0)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := Migrate(ctx, db); err != nil {
			t.Fatal(err)
		}
	}
	if res, _ := l.Verify(ctx); !res.OK || res.Entries != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestConcurrentAppend(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := l.Append(ctx, sample(i))
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	res, err := l.Verify(ctx)
	if err != nil || !res.OK || res.Entries != 20 {
		t.Fatalf("verify = %+v %v", res, err)
	}
}

func TestAppendOnlyTriggers(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	if _, err := l.Append(ctx, sample(0)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE audit SET caller='evil'`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update err = %v", err)
	}
	if _, err := db.Exec(`DELETE FROM audit`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("delete err = %v", err)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	ctx := context.Background()
	for name, stmt := range map[string]string{
		"edit":     `UPDATE audit SET caller='evil' WHERE id=3`,
		"delete":   `DELETE FROM audit WHERE id=3`,
		"exit":     `UPDATE audit SET exit_code=99 WHERE id=3`,
		"prev":     `UPDATE audit SET prev_hmac=zeroblob(32) WHERE id=3`,
		"renumber": `UPDATE audit SET id=id+10 WHERE id=3`,
	} {
		t.Run(name, func(t *testing.T) {
			l, db := newLog(t)
			for i := 0; i < 5; i++ {
				if _, err := l.Append(ctx, sample(i)); err != nil {
					t.Fatal(err)
				}
			}
			db.Exec(`DROP TRIGGER audit_no_update`)
			db.Exec(`DROP TRIGGER audit_no_delete`)
			if _, err := db.Exec(stmt); err != nil {
				t.Fatal(err)
			}
			res, err := l.Verify(ctx)
			if err != nil || res.OK {
				t.Fatalf("tamper undetected: %+v %v", res, err)
			}
			want := "3"
			switch name {
			case "delete":
				want = "4"
			case "renumber":
				want = "4" // row 4 now follows row 2... and row 3 became 13
			}
			if res.FirstBadID != want {
				t.Fatalf("FirstBadID = %q want %q", res.FirstBadID, want)
			}
		})
	}
}

func TestExportCSV(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	e := sample(2)
	e.Argv = []string{"echo", `a "q", b`}
	e.Expanded = []string{"aws/key", "DB_URL"}
	l.Append(ctx, e)
	l.Append(ctx, Entry{Decision: DecisionDeniedUser, Reason: "no"})
	var buf bytes.Buffer
	if err := l.ExportCSV(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(recs) != 3 {
		t.Fatalf("%v %v", recs, err)
	}
	if recs[0][0] != "id" || recs[1][4] != `["echo","a \"q\", b"]` || recs[1][5] != `["aws/key","DB_URL"]` ||
		recs[1][6] != `["aws/key","DB_URL"]` || recs[2][6] != "[]" ||
		recs[1][10] != "2" || recs[1][11] != "1500" || recs[2][4] != "[]" || recs[2][10] != "" {
		t.Fatalf("csv = %q", recs)
	}
}

type failW struct{}

func (failW) Write([]byte) (int, error) { return 0, context.Canceled }

func TestExportWriterError(t *testing.T) {
	l, _ := newLog(t)
	l.Append(context.Background(), sample(0))
	if err := l.ExportCSV(context.Background(), failW{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestClosedDBErrors(t *testing.T) {
	ctx := context.Background()
	l, db := newLog(t)
	db.Close()
	if _, err := l.Append(ctx, sample(0)); err == nil {
		t.Fatal("append")
	}
	if _, err := l.List(ctx, 1, 0); err == nil {
		t.Fatal("list")
	}
	if _, err := l.Verify(ctx); err == nil {
		t.Fatal("verify")
	}
	if err := l.ExportCSV(ctx, &bytes.Buffer{}); err == nil {
		t.Fatal("export")
	}
	if err := Migrate(ctx, db); err == nil {
		t.Fatal("migrate")
	}
}

func TestCSVCellNeutralisesFormulas(t *testing.T) {
	for in, want := range map[string]string{
		"=1+1": "'=1+1", "+1": "'+1", "-1": "'-1", "@SUM(A1)": "'@SUM(A1)", "\tx": "'\tx", "\rx": "'\rx",
		`=HYPERLINK("http://x","y")`: `'=HYPERLINK("http://x","y")`,
		"":                           "", "claude-code": "claude-code", "a=b": "a=b", "/work/app": "/work/app", `["=x"]`: `["=x"]`, " =x": " =x",
		"'=x": "'=x", "é": "é",
	} {
		if got := csvCell(in); got != want {
			t.Errorf("csvCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportCSVDoesNotEmitFormulas(t *testing.T) {
	ctx := context.Background()
	l, _ := newLog(t)
	e := sample(0)
	e.Caller = `=HYPERLINK("http://evil","x")`
	e.Cwd = "+cmd|' /C calc'!A0"
	e.Reason = "@SUM(1+1)"
	e.GrantID = "-2+3"
	if _, err := l.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := l.ExportCSV(ctx, &buf); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(recs) != 2 {
		t.Fatalf("%v %v", recs, err)
	}
	r := recs[1]
	if r[2] != `'=HYPERLINK("http://evil","x")` || r[3] != "'+cmd|' /C calc'!A0" || r[9] != "'@SUM(1+1)" || r[8] != "'-2+3" {
		t.Fatalf("row = %q", r)
	}
	for i, cell := range r {
		if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
			t.Errorf("cell %d starts like a formula: %q", i, cell)
		}
	}
	// The stored row is untouched: the log still verifies and lists the original.
	if v, err := l.Verify(ctx); err != nil || !v.OK {
		t.Fatalf("verify: %+v %v", v, err)
	}
	if es, _ := l.List(ctx, 1, 0); es[0].Caller != e.Caller {
		t.Errorf("stored caller changed: %q", es[0].Caller)
	}
}
