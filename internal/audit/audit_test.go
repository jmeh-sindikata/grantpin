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
	canon := canonical(7, ts, &e)
	got := hex.EncodeToString(l.mac(canon, make([]byte, 32)))
	const want = "ae0373c4242f70d0d55c9cd9d59f7d1dd28e350795779bdff0ae577f9c510a22"
	if got != want {
		t.Fatalf("canonical encoding changed: got %s", got)
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
		recs[1][9] != "2" || recs[1][10] != "1500" || recs[2][4] != "[]" || recs[2][9] != "" {
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
