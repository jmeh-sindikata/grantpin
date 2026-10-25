package grant

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"grantd/internal/approve"
)

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "g.db") + "?_pragma=busy_timeout(10000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s := NewStore(newDB(t))
	s.SetClock(func() time.Time { return t0 })
	return s
}

func base() Grant {
	return Grant{
		Caller:    "claude-code",
		CwdPrefix: "/a/b",
		Secrets:   []string{"aws/*", "DB_URL"},
		CmdPrefix: []string{"php", "artisan"},
		CreatedAt: t0,
		ExpiresAt: t0.Add(time.Hour),
	}
}

func query() Query {
	return Query{
		Caller:  "claude-code",
		Cwd:     "/a/b",
		Secrets: []string{"DB_URL"},
		Argv:    []string{"php", "artisan", "sync"},
		Now:     t0.Add(time.Minute),
	}
}

func mustAdd(t *testing.T, s *Store, g Grant) *Grant {
	t.Helper()
	out, err := s.Add(context.Background(), g)
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return out
}

func TestMigrateIdempotent(t *testing.T) {
	db := newDB(t)
	for range 3 {
		if err := Migrate(context.Background(), db); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(context.Background(), func() *sql.DB { d := newDB(t); d.Close(); return d }()); err == nil {
		t.Fatal("expected error on closed db")
	}
}

func TestAddGetRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	n := 3
	in := base()
	in.CwdPrefix = "/a/b/" // trailing slash cleaned
	in.UsesRemaining = &n
	in.ID = "ignored"
	got := mustAdd(t, s, in)
	if len(got.ID) != 32 || got.ID == "ignored" {
		t.Fatalf("id = %q", got.ID)
	}
	if got.CwdPrefix != "/a/b" {
		t.Fatalf("cwd = %q", got.CwdPrefix)
	}
	n = 99 // caller mutation must not leak
	if *got.UsesRemaining != 3 {
		t.Fatal("aliasing")
	}
	back, err := s.Get(ctx, got.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.Caller != in.Caller || back.CwdPrefix != "/a/b" ||
		strings.Join(back.Secrets, ",") != "aws/*,DB_URL" ||
		strings.Join(back.CmdPrefix, ",") != "php,artisan" ||
		!back.CreatedAt.Equal(t0) || !back.ExpiresAt.Equal(t0.Add(time.Hour)) ||
		back.UsesRemaining == nil || *back.UsesRemaining != 3 || back.Expired {
		t.Fatalf("round trip: %+v", back)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	// zero CreatedAt defaults to the store clock
	in2 := base()
	in2.CreatedAt = time.Time{}
	if g := mustAdd(t, s, in2); !g.CreatedAt.Equal(t0) {
		t.Fatalf("created = %v", g.CreatedAt)
	}
	// unique ids
	if a, b := mustAdd(t, s, base()), mustAdd(t, s, base()); a.ID == b.ID {
		t.Fatal("duplicate id")
	}
}

func TestAddValidation(t *testing.T) {
	s := newStore(t)
	zero, neg := 0, -1
	mut := map[string]func(*Grant){
		"relative cwd":     func(g *Grant) { g.CwdPrefix = "a/b" },
		"empty cwd":        func(g *Grant) { g.CwdPrefix = "" },
		"no secrets":       func(g *Grant) { g.Secrets = nil },
		"empty secret":     func(g *Grant) { g.Secrets = []string{""} },
		"bad glob":         func(g *Grant) { g.Secrets = []string{"a["} },
		"no cmd":           func(g *Grant) { g.CmdPrefix = nil },
		"empty cmd elem":   func(g *Grant) { g.CmdPrefix = []string{"php", ""} },
		"uses zero":        func(g *Grant) { g.UsesRemaining = &zero },
		"uses negative":    func(g *Grant) { g.UsesRemaining = &neg },
		"expires = create": func(g *Grant) { g.ExpiresAt = g.CreatedAt },
		"expires before":   func(g *Grant) { g.ExpiresAt = g.CreatedAt.Add(-time.Second) },
		"expires zero":     func(g *Grant) { g.ExpiresAt = time.Time{} },
	}
	for name, f := range mut {
		g := base()
		f(&g)
		if _, err := s.Add(context.Background(), g); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if l, _ := s.List(context.Background()); len(l) != 0 {
		t.Fatalf("invalid grants stored: %v", l)
	}
}

func TestAddDBError(t *testing.T) {
	db := newDB(t)
	s := NewStore(db)
	db.Close()
	ctx := context.Background()
	if _, err := s.Add(ctx, base()); err == nil {
		t.Error("Add")
	}
	if _, err := s.Get(ctx, "x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Error("Get")
	}
	if _, err := s.List(ctx); err == nil {
		t.Error("List")
	}
	if err := s.Revoke(ctx, "x"); err == nil || errors.Is(err, ErrNotFound) {
		t.Error("Revoke")
	}
	if err := s.RevokeAll(ctx); err == nil {
		t.Error("RevokeAll")
	}
	if _, err := s.Purge(ctx); err == nil {
		t.Error("Purge")
	}
	if _, err := s.Match(ctx, query()); err == nil || errors.Is(err, ErrNoMatch) {
		t.Error("Match")
	}
}

func TestCorruptRows(t *testing.T) {
	db := newDB(t)
	s := NewStore(db)
	ctx := context.Background()
	for _, col := range []string{"secrets", "cmd_prefix"} {
		secrets, cmd := `["a"]`, `["x"]`
		if col == "secrets" {
			secrets = "not json"
		} else {
			cmd = "not json"
		}
		_, err := db.Exec(`INSERT INTO grants VALUES (?, 'c', '/a', ?, ?, 0, ?, NULL)`,
			"id-"+col, secrets, cmd, time.Now().Add(time.Hour).UnixNano())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(ctx, "id-"+col); err == nil {
			t.Errorf("%s: Get accepted corrupt row", col)
		}
	}
	if _, err := s.List(ctx); err == nil {
		t.Error("List accepted corrupt rows")
	}
	q := Query{Caller: "c", Cwd: "/a", Secrets: []string{"a"}, Argv: []string{"x"}, Now: time.Now()}
	if _, err := s.Match(ctx, q); err == nil || errors.Is(err, ErrNoMatch) {
		t.Errorf("Match err = %v", err)
	}
}

func TestMatchBasic(t *testing.T) {
	s := newStore(t)
	g := mustAdd(t, s, base())
	got, err := s.Match(context.Background(), query())
	if err != nil || got.ID != g.ID {
		t.Fatalf("got %v %v", got, err)
	}
	if got.UsesRemaining != nil {
		t.Fatal("unlimited grant gained a counter")
	}
}

func TestMatchCwd(t *testing.T) {
	cases := []struct {
		name, prefix, cwd string
		want              bool
	}{
		{"equal", "/a/b", "/a/b", true},
		{"child", "/a/b", "/a/b/c", true},
		{"deep child", "/a/b", "/a/b/c/d/e", true},
		{"sibling with shared prefix", "/a/b", "/a/bc", false},
		{"sibling with shared prefix 2", "/home/a/f", "/home/a/foo", false},
		{"parent", "/a/b", "/a", false},
		{"unrelated", "/a/b", "/x/y", false},
		{"trailing slash on request", "/a/b", "/a/b/", true},
		{"trailing slash on child", "/a/b", "/a/b/c/", true},
		{"double slashes", "/a/b", "//a//b///c", true},
		{"dot segments", "/a/b", "/a/b/./c", true},
		{".. escapes", "/a/b", "/a/b/../c", false},
		{".. escapes to parent", "/a/b", "/a/b/..", false},
		{".. stays inside", "/a/b", "/a/b/c/../d", true},
		{".. then back in", "/a/b", "/a/x/../b/c", true},
		{".. through bc", "/a/b", "/a/bc/../b", true},
		{".. above root", "/a/b", "/../a/b", true},
		{"relative", "/a/b", "a/b", false},
		{"relative dot", "/a/b", ".", false},
		{"empty", "/a/b", "", false},
		{"case differs", "/a/b", "/a/B", false},
		{"root prefix any", "/", "/anything/at/all", true},
		{"root prefix root", "/", "/", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			g := base()
			g.CwdPrefix = c.prefix
			mustAdd(t, s, g)
			q := query()
			q.Cwd = c.cwd
			_, err := s.Match(context.Background(), q)
			if c.want && err != nil {
				t.Fatalf("want match, got %v", err)
			}
			if !c.want && !errors.Is(err, ErrNoMatch) {
				t.Fatalf("want ErrNoMatch, got %v", err)
			}
		})
	}
}

func TestMatchCaller(t *testing.T) {
	s := newStore(t)
	mustAdd(t, s, base())
	q := query()
	q.Caller = "codex"
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatal(err)
	}
	q.Caller = ""
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatal(err)
	}
}

func TestMatchSecrets(t *testing.T) {
	cases := []struct {
		name  string
		entry []string
		req   []string
		want  bool
	}{
		{"literal equals literal", []string{"DB_URL"}, []string{"DB_URL"}, true},
		{"literal differs", []string{"DB_URL"}, []string{"DB_URL2"}, false},
		{"literal under glob", []string{"aws/*"}, []string{"aws/key"}, true},
		{"literal not under glob (depth)", []string{"aws/*"}, []string{"aws/a/b"}, false},
		{"literal under ** glob", []string{"aws/**"}, []string{"aws/a/b"}, true},
		{"literal not under glob (prefix)", []string{"aws/*"}, []string{"awsx/key"}, false},
		{"literal vs bare dir", []string{"aws/*"}, []string{"aws"}, false},
		{"glob request textually present", []string{"aws/*"}, []string{"aws/*"}, true},
		{"glob request not present", []string{"aws/key"}, []string{"aws/*"}, false},
		{"glob request narrower than grant glob", []string{"aws/**"}, []string{"aws/*"}, false},
		{"glob request broader than grant", []string{"aws/*"}, []string{"*"}, false},
		{"glob request, literal grant entry", []string{"DB_URL"}, []string{"DB_*"}, false},
		{"glob request among entries", []string{"x", "aws/*"}, []string{"aws/*"}, true},
		{"every secret must be covered", []string{"aws/*"}, []string{"aws/k", "DB_URL"}, false},
		{"all covered across entries", []string{"aws/*", "DB_URL"}, []string{"aws/k", "DB_URL", "aws/*"}, true},
		{"subset of grant is fine", []string{"A", "B", "C"}, []string{"B"}, true},
		{"superset of grant is not", []string{"A"}, []string{"A", "B"}, false},
		{"no requested secrets", []string{"A"}, nil, false},
		{"empty requested secret", []string{"A"}, []string{""}, false},
		{"brace glob entry", []string{"{a,b}/x"}, []string{"b/x"}, true},
		{"class glob entry", []string{"k[0-9]"}, []string{"k7"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			g := base()
			g.Secrets = c.entry
			mustAdd(t, s, g)
			q := query()
			q.Secrets = c.req
			_, err := s.Match(context.Background(), q)
			if c.want && err != nil {
				t.Fatalf("want match, got %v", err)
			}
			if !c.want && !errors.Is(err, ErrNoMatch) {
				t.Fatalf("want ErrNoMatch, got %v", err)
			}
		})
	}
}

func TestMatchArgv(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"exact", []string{"php", "artisan"}, true},
		{"longer", []string{"php", "artisan", "sync", "-v"}, true},
		{"shorter", []string{"php"}, false},
		{"empty", nil, false},
		{"different tail", []string{"php", "composer"}, false},
		{"different head", []string{"node", "artisan"}, false},
		{"not at start", []string{"sudo", "php", "artisan"}, false},
		{"string prefix is not element prefix", []string{"php", "artisanx"}, false},
		{"case", []string{"PHP", "artisan"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newStore(t)
			mustAdd(t, s, base())
			q := query()
			q.Argv = c.argv
			_, err := s.Match(context.Background(), q)
			if c.want && err != nil {
				t.Fatalf("want match, got %v", err)
			}
			if !c.want && !errors.Is(err, ErrNoMatch) {
				t.Fatalf("want ErrNoMatch, got %v", err)
			}
		})
	}
}

func TestEmptyCmdPrefixNeverMatches(t *testing.T) {
	// Add refuses it, but a row inserted behind our back must still not match.
	db := newDB(t)
	s := NewStore(db)
	_, err := db.Exec(`INSERT INTO grants VALUES ('x', 'claude-code', '/a/b', '["DB_URL"]', '[]', 0, ?, NULL)`,
		t0.Add(time.Hour).UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Match(context.Background(), query()); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v", err)
	}
	if argvCovered(nil, []string{"a"}) || argvCovered([]string{}, nil) {
		t.Fatal("empty prefix covered argv")
	}
}

func TestMatchExpiryBoundary(t *testing.T) {
	s := newStore(t)
	mustAdd(t, s, base())
	exp := t0.Add(time.Hour)
	q := query()
	q.Now = exp.Add(-time.Nanosecond)
	if _, err := s.Match(context.Background(), q); err != nil {
		t.Fatalf("1ns before expiry: %v", err)
	}
	q.Now = exp
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("at expiry: %v", err)
	}
	q.Now = exp.Add(time.Nanosecond)
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("after expiry: %v", err)
	}
}

func TestMatchUsesRemaining(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	two := 2
	g := base()
	g.UsesRemaining = &two
	added := mustAdd(t, s, g)

	m1, err := s.Match(ctx, query())
	if err != nil || *m1.UsesRemaining != 1 {
		t.Fatalf("m1 = %+v %v", m1, err)
	}
	m2, err := s.Match(ctx, query())
	if err != nil || *m2.UsesRemaining != 0 {
		t.Fatalf("m2 = %+v %v", m2, err)
	}
	if _, err := s.Match(ctx, query()); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("exhausted: %v", err)
	}
	back, _ := s.Get(ctx, added.ID)
	if *back.UsesRemaining != 0 {
		t.Fatalf("stored = %d", *back.UsesRemaining)
	}
}

func TestNonMatchDoesNotConsumeUse(t *testing.T) {
	s := newStore(t)
	one := 1
	g := base()
	g.UsesRemaining = &one
	added := mustAdd(t, s, g)
	q := query()
	q.Argv = []string{"php"}
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatal(err)
	}
	back, _ := s.Get(context.Background(), added.ID)
	if *back.UsesRemaining != 1 {
		t.Fatalf("use consumed by a non-match: %d", *back.UsesRemaining)
	}
}

func TestMatchConcurrentUses(t *testing.T) {
	const N, workers = 4, 10
	s := newStore(t)
	n := N
	g := base()
	g.UsesRemaining = &n
	added := mustAdd(t, s, g)

	var ok, none atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := s.Match(context.Background(), query())
			switch {
			case err == nil:
				ok.Add(1)
			case errors.Is(err, ErrNoMatch):
				none.Add(1)
			default:
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if ok.Load() != N || none.Load() != workers-N {
		t.Fatalf("ok=%d none=%d, want %d/%d", ok.Load(), none.Load(), N, workers-N)
	}
	back, _ := s.Get(context.Background(), added.ID)
	if *back.UsesRemaining != 0 {
		t.Fatalf("remaining = %d", *back.UsesRemaining)
	}
}

// Two Store values over one DB share no mutex, so this exercises the
// UPDATE ... WHERE uses_remaining > 0 guard itself.
func TestMatchConcurrentUsesAcrossStores(t *testing.T) {
	const N, workers = 3, 10
	db := newDB(t)
	stores := []*Store{NewStore(db), NewStore(db)}
	n := N
	g := base()
	g.UsesRemaining = &n
	mustAdd(t, stores[0], g)

	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := stores[i%2].Match(context.Background(), query()); err == nil {
				ok.Add(1)
			} else if !errors.Is(err, ErrNoMatch) {
				t.Errorf("unexpected: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != N {
		t.Fatalf("successes = %d, want %d", ok.Load(), N)
	}
}

func TestMatchFallsThroughExhaustedToNext(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	one := 1
	a := base()
	a.UsesRemaining = &one
	a.CreatedAt = t0
	b := base()
	b.CreatedAt = t0.Add(time.Second)
	ga, gb := mustAdd(t, s, a), mustAdd(t, s, b)
	m, err := s.Match(ctx, query())
	if err != nil || m.ID != ga.ID {
		t.Fatalf("first should be oldest: %v %v", m, err)
	}
	m, err = s.Match(ctx, query())
	if err != nil || m.ID != gb.ID {
		t.Fatalf("second should fall to unlimited: %v %v", m, err)
	}
}

func TestListRevokePurge(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	exp := base()
	exp.CreatedAt = t0.Add(-2 * time.Hour)
	exp.ExpiresAt = t0.Add(-time.Hour)
	e := mustAdd(t, s, exp)
	if !e.Expired {
		t.Fatal("added expired grant not flagged")
	}
	a := base()
	a.CreatedAt = t0.Add(time.Minute)
	live1 := mustAdd(t, s, a)
	a.CreatedAt = t0.Add(2 * time.Minute)
	live2 := mustAdd(t, s, a)

	l, err := s.List(ctx)
	if err != nil || len(l) != 3 {
		t.Fatalf("%v %v", l, err)
	}
	if l[0].ID != live1.ID || l[1].ID != live2.ID || l[2].ID != e.ID {
		t.Fatalf("order: %s %s %s", l[0].ID, l[1].ID, l[2].ID)
	}
	if l[0].Expired || l[1].Expired || !l[2].Expired {
		t.Fatalf("flags: %v %v %v", l[0].Expired, l[1].Expired, l[2].Expired)
	}
	if g, _ := s.Get(ctx, e.ID); !g.Expired {
		t.Fatal("Get should flag expired")
	}

	n, err := s.Purge(ctx)
	if err != nil || n != 1 {
		t.Fatalf("purge = %d %v", n, err)
	}
	if l, _ = s.List(ctx); len(l) != 2 {
		t.Fatalf("after purge: %d", len(l))
	}
	if n, _ = s.Purge(ctx); n != 0 {
		t.Fatalf("second purge = %d", n)
	}

	if err := s.Revoke(ctx, live1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(ctx, live1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
	if _, err := s.Match(ctx, query()); err != nil { // live2 still matches
		t.Fatal(err)
	}
	if err := s.RevokeAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Match(ctx, query()); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("after revoke all: %v", err)
	}
	if l, _ = s.List(ctx); len(l) != 0 {
		t.Fatalf("list after revoke all: %d", len(l))
	}
	if err := s.RevokeAll(ctx); err != nil { // empty is fine
		t.Fatal(err)
	}
}

func TestPurgeBoundary(t *testing.T) {
	s := newStore(t)
	g := base()
	g.ExpiresAt = t0.Add(time.Second)
	mustAdd(t, s, g)
	now := t0
	s.SetClock(func() time.Time { return now })
	ctx := context.Background()
	now = t0.Add(time.Second - time.Nanosecond)
	if n, _ := s.Purge(ctx); n != 0 {
		t.Fatalf("purged early: %d", n)
	}
	now = t0.Add(time.Second)
	if n, _ := s.Purge(ctx); n != 1 {
		t.Fatalf("not purged at expiry: %d", n)
	}
}

func TestFromDecision(t *testing.T) {
	req := approve.ApprovalRequest{
		Caller:  "claude-code",
		Cwd:     "/a/b/",
		Argv:    []string{"php", "artisan", "sync"},
		Secrets: []string{"aws/*", "DB_URL"},
	}
	g := FromDecision(req, time.Hour, 4*time.Hour, nil, t0)
	if g.Caller != "claude-code" || g.CwdPrefix != "/a/b" ||
		strings.Join(g.Secrets, ",") != "aws/*,DB_URL" ||
		strings.Join(g.CmdPrefix, " ") != "php artisan sync" ||
		!g.CreatedAt.Equal(t0) || !g.ExpiresAt.Equal(t0.Add(time.Hour)) || g.UsesRemaining != nil {
		t.Fatalf("%+v", g)
	}
	// no aliasing of the request
	g.Secrets[0], g.CmdPrefix[0] = "x", "x"
	if req.Secrets[0] != "aws/*" || req.Argv[0] != "php" {
		t.Fatal("aliases request slices")
	}

	// clamp
	if g := FromDecision(req, 10*time.Hour, 4*time.Hour, nil, t0); !g.ExpiresAt.Equal(t0.Add(4 * time.Hour)) {
		t.Fatalf("not clamped: %v", g.ExpiresAt)
	}
	// maxTTL 0 = no clamp
	if g := FromDecision(req, 10*time.Hour, 0, nil, t0); !g.ExpiresAt.Equal(t0.Add(10 * time.Hour)) {
		t.Fatalf("unexpected clamp: %v", g.ExpiresAt)
	}
	// valid policy prefix is used
	g = FromDecision(req, time.Hour, time.Hour, []string{"php", "artisan"}, t0)
	if strings.Join(g.CmdPrefix, " ") != "php artisan" {
		t.Fatalf("prefix = %v", g.CmdPrefix)
	}
	// prefix that is not a prefix of argv (or empty) falls back to full argv
	for _, p := range [][]string{{"php", "composer"}, {"php", "artisan", "sync", "x"}, {}, {"node"}} {
		g = FromDecision(req, time.Hour, time.Hour, p, t0)
		if strings.Join(g.CmdPrefix, " ") != "php artisan sync" {
			t.Errorf("prefix %v: got %v", p, g.CmdPrefix)
		}
	}
	// ttl <= 0 -> already expired, and Store.Add refuses it
	for _, ttl := range []time.Duration{0, -time.Hour} {
		g = FromDecision(req, ttl, time.Hour, nil, t0)
		if !g.ExpiresAt.Equal(t0) {
			t.Errorf("ttl %v: expires %v", ttl, g.ExpiresAt)
		}
		if _, err := newStore(t).Add(context.Background(), g); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("ttl %v: Add err = %v", ttl, err)
		}
	}
	// empty cwd stays empty (Add will reject it)
	req.Cwd = ""
	if g := FromDecision(req, time.Hour, time.Hour, nil, t0); g.CwdPrefix != "" {
		t.Fatalf("cwd = %q", g.CwdPrefix)
	}
}

func TestFromDecisionRoundTripMatches(t *testing.T) {
	s := newStore(t)
	req := approve.ApprovalRequest{
		Caller: "codex", Cwd: "/work/proj", Argv: []string{"aws", "s3", "ls"},
		Secrets: []string{"aws/access_key", "aws/*"},
	}
	mustAdd(t, s, FromDecision(req, time.Hour, time.Hour, nil, t0))
	q := Query{Caller: "codex", Cwd: "/work/proj/sub", Secrets: req.Secrets, Argv: req.Argv, Now: t0.Add(time.Minute)}
	if _, err := s.Match(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	// a different command does not ride on the grant
	q.Argv = []string{"aws", "s3", "rm"}
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v", err)
	}
	// nor does an extra secret
	q.Argv = req.Argv
	q.Secrets = append(slicesClone(req.Secrets), "OTHER")
	if _, err := s.Match(context.Background(), q); !errors.Is(err, ErrNoMatch) {
		t.Fatalf("err = %v", err)
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

func TestNewIDFormat(t *testing.T) {
	id, err := newID()
	if err != nil || len(id) != 32 || strings.Trim(id, "0123456789abcdef") != "" {
		t.Fatalf("%q %v", id, err)
	}
	if fmt.Sprint(isGlob("a/b"), isGlob("a/*")) != "false true" {
		t.Fatal("isGlob")
	}
}
