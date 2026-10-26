package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func encLen(t *testing.T, l []string) int {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return len(b)
}

func TestCapStringAndUTF8Boundary(t *testing.T) {
	if got := CapString("short", 64); got != "short" {
		t.Fatalf("short string changed: %q", got)
	}
	long := strings.Repeat("a", 500)
	got := CapString(long, 64)
	if len(got) != 64 || !strings.HasSuffix(got, TruncatedMarker) || !strings.HasPrefix(got, "aaaa") {
		t.Fatalf("CapString = %q (%d bytes)", got, len(got))
	}
	// Never cut inside a multi-byte character, at any cut point.
	for n := 12; n < 40; n++ {
		got := CapString(strings.Repeat("é€😀", 40), n)
		if len(got) > n || !utf8.ValidString(got) || !strings.HasSuffix(got, TruncatedMarker) {
			t.Fatalf("n=%d: %q", n, got)
		}
	}
	// A cap below the marker's length still honours the cap.
	if got := CapString(long, 4); len(got) > 4 || !utf8.ValidString(got) {
		t.Fatalf("tiny cap: %q", got)
	}
}

func TestCapListKeepsFittingListsAndMarksCutOnes(t *testing.T) {
	small := []string{"php", "artisan", "migrate"}
	if got := CapList(small, MaxArgvElem, MaxArgvJSON); len(got) != 3 || &got[0] != &small[0] {
		t.Fatalf("a list that fits must be returned as is: %v", got)
	}
	if got := CapList(nil, 10, 100); got != nil {
		t.Fatalf("nil list: %v", got)
	}

	// One huge element: cut to the element cap, marker appended.
	got := CapList([]string{"cmd", strings.Repeat("x", 4<<20)}, MaxArgvElem, MaxArgvJSON)
	if len(got) != 3 || got[0] != "cmd" || len(got[1]) != MaxArgvElem || got[2] != TruncatedMarker {
		t.Fatalf("one huge element: %d elements, lens %d/%d", len(got), len(got[0]), len(got[1]))
	}
	if n := encLen(t, got); n > MaxArgvJSON {
		t.Fatalf("encoded %d > %d", n, MaxArgvJSON)
	}

	// Very many elements: the leading ones are kept, within the encoded cap.
	many := make([]string, 200000)
	for i := range many {
		many[i] = "arg"
	}
	got = CapList(many, MaxArgvElem, MaxArgvJSON)
	if got[len(got)-1] != TruncatedMarker || len(got) < 100 || got[0] != "arg" {
		t.Fatalf("many elements: %d kept", len(got))
	}
	if n := encLen(t, got); n > MaxArgvJSON {
		t.Fatalf("encoded %d > %d", n, MaxArgvJSON)
	}

	// Elements that grow when JSON-encoded (control characters take six bytes)
	// are counted at their encoded size.
	ctl := make([]string, 100)
	for i := range ctl {
		ctl[i] = strings.Repeat("\x01", 4000)
	}
	got = CapList(ctl, MaxArgvElem, MaxArgvJSON)
	if n := encLen(t, got); n > MaxArgvJSON || got[len(got)-1] != TruncatedMarker {
		t.Fatalf("control characters: encoded %d", n)
	}
	// The input is never modified.
	if ctl[0] != strings.Repeat("\x01", 4000) || len(ctl) != 100 {
		t.Fatal("input modified")
	}
}

func TestAppendCapsEveryFieldAndKeepsTheChainValid(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	e := sample(0)
	e.Caller = strings.Repeat("c", 4<<20)
	e.Cwd = strings.Repeat("/d", 2<<20)
	e.Argv = []string{"cmd", strings.Repeat("A", 3<<20), "tail"}
	e.Secrets = []string{strings.Repeat("s", 3<<20)}
	e.Expanded = make([]string, 100000)
	for i := range e.Expanded {
		e.Expanded[i] = "aws/some-secret-name"
	}
	e.Reason = strings.Repeat("r", 3<<20)
	e.GrantID = strings.Repeat("g", 1<<20)
	if _, err := l.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(ctx, sample(1)); err != nil { // a normal row after it
		t.Fatal(err)
	}

	var size int
	if err := db.QueryRow(`SELECT length(caller)+length(cwd)+length(argv)+length(secrets)+length(expanded)+length(reason)+length(grant_id) FROM audit WHERE id=1`).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size > 64<<10*3+4<<10+64+4<<10+128 {
		t.Fatalf("row is %d bytes", size)
	}
	es, err := l.List(ctx, 10, 0)
	if err != nil || len(es) != 2 {
		t.Fatalf("list: %v %v", es, err)
	}
	r := es[1]
	if len(r.Caller) > MaxCaller || len(r.Cwd) > MaxCwd || len(r.Reason) > MaxReason || len(r.GrantID) > MaxGrantID {
		t.Fatalf("string fields not capped: %d %d %d %d", len(r.Caller), len(r.Cwd), len(r.Reason), len(r.GrantID))
	}
	for _, f := range []string{r.Caller, r.Cwd, r.Reason, r.GrantID} {
		if !strings.HasSuffix(f, TruncatedMarker) {
			t.Fatalf("no marker: %q", f[len(f)-20:])
		}
	}
	if r.Argv[0] != "cmd" || r.Argv[len(r.Argv)-1] != TruncatedMarker || encLen(t, r.Argv) > MaxArgvJSON {
		t.Fatalf("argv: %d elements, encoded %d", len(r.Argv), encLen(t, r.Argv))
	}
	if encLen(t, r.Secrets) > MaxSecretsJSON || encLen(t, r.Expanded) > MaxSecretsJSON || r.Expanded[len(r.Expanded)-1] != TruncatedMarker {
		t.Fatalf("secrets/expanded not capped")
	}
	// The HMAC is computed over what is stored, so the chain still verifies.
	if v, err := l.Verify(ctx); err != nil || !v.OK || v.Entries != 2 {
		t.Fatalf("verify = %+v, %v", v, err)
	}
	// A row within the caps is stored untouched.
	if got := es[0]; got.Caller != "claude-code" || len(got.Argv) != 3 {
		t.Fatalf("normal row altered: %+v", got)
	}
}

func TestListBeforePagesByID(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	for i := range 7 {
		if _, err := l.Append(ctx, sample(i)); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(es []Entry) string {
		var s []string
		for _, e := range es {
			s = append(s, e.ID)
		}
		return strings.Join(s, ",")
	}
	for _, tc := range []struct {
		limit  int
		before int64
		want   string
	}{
		{3, 0, "7,6,5"},
		{3, 5, "4,3,2"},
		{3, 2, "1"},
		{3, 1, ""},
		{0, 4, "3,2,1"},
	} {
		es, err := l.ListBefore(ctx, tc.limit, tc.before)
		if err != nil || ids(es) != tc.want {
			t.Errorf("ListBefore(%d, %d) = %q, %v; want %q", tc.limit, tc.before, ids(es), err, tc.want)
		}
	}
}

func TestExportShowsLegacyOversizeRowsInBoundedForm(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	// A row as an older build wrote it: unbounded argv, written straight to the table.
	huge, _ := json.Marshal([]string{"true", strings.Repeat("z", 2<<20)})
	if _, err := db.Exec(`INSERT INTO audit (ts, caller, cwd, argv, secrets, decision, prev_hmac, hmac)
VALUES ('2026-01-01T00:00:00Z','cli','/','`+string(huge)+`','[]','error',x'00',x'00')`); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	if err := l.ExportCSV(ctx, &sb); err != nil {
		t.Fatal(err)
	}
	if sb.Len() > 64<<10 || !strings.Contains(sb.String(), TruncatedMarker) {
		t.Fatalf("export is %d bytes", sb.Len())
	}
}
