package vault

import (
	"errors"
	"strings"
	"testing"
)

func TestParseDotenv(t *testing.T) {
	src := "\xef\xbb\xbf# comment\r\n" +
		"\n" +
		"PLAIN=value\n" +
		"  SPACED = padded value  \n" +
		"export EXPORTED=yes\n" +
		"exporter=notprefix\n" +
		"INLINE=abc # trailing comment\n" +
		"HASH=abc#notcomment\n" +
		"DQ=\"a b\\nc \\\"q\\\" \\\\ \\$ \\x\"  # c\n" +
		"SQ='lit\\n $x # kept'\n" +
		"MULTI=\"line1\n" +
		"line2\"\n" +
		"SMULTI='a\n" +
		"b'\n" +
		"EMPTY=\n" +
		"EMPTYQ=\"\"\n" +
		"EQ=a=b=c\n" +
		"LAST=end"
	kvs, err := ParseDotenv(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	want := []KV{
		{"PLAIN", []byte("value")},
		{"SPACED", []byte("padded value")},
		{"EXPORTED", []byte("yes")},
		{"exporter", []byte("notprefix")},
		{"INLINE", []byte("abc")},
		{"HASH", []byte("abc#notcomment")},
		{"DQ", []byte("a b\nc \"q\" \\ $ \\x")},
		{"SQ", []byte(`lit\n $x # kept`)},
		{"MULTI", []byte("line1\nline2")},
		{"SMULTI", []byte("a\nb")},
		{"EMPTY", nil},
		{"EMPTYQ", nil},
		{"EQ", []byte("a=b=c")},
		{"LAST", []byte("end")},
	}
	if len(kvs) != len(want) {
		t.Fatalf("got %d entries, want %d", len(kvs), len(want))
	}
	for i := range want {
		if kvs[i].Key != want[i].Key || string(kvs[i].Value) != string(want[i].Value) {
			t.Errorf("entry %d: key %q value %q, want %q %q", i, kvs[i].Key, kvs[i].Value, want[i].Key, want[i].Value)
		}
	}
}

func TestParseDotenvErrors(t *testing.T) {
	for in, wantLine := range map[string]string{
		"JUSTAWORD\n":              "line 1",
		"A=1\n1BAD=x\n":            "line 2",
		"A=1\n\nbad key=x\n":       "line 3",
		"=x\n":                     "line 1",
		"A=\"unterminated\nmore\n": "line 1",
		"A='unterminated":          "line 1",
		"A=\"x\" junk\n":           "line 1",
		"export =x":                "line 1",
	} {
		_, err := ParseDotenv(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), wantLine) {
			t.Errorf("%q: err = %v, want %s", in, err, wantLine)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("io") }

func TestParseDotenvReadError(t *testing.T) {
	if _, err := ParseDotenv(errReader{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseConflictMode(t *testing.T) {
	for _, s := range []string{"skip", "overwrite", "error"} {
		if _, err := ParseConflictMode(s); err != nil {
			t.Error(s, err)
		}
	}
	if _, err := ParseConflictMode("merge"); err == nil {
		t.Error("merge accepted")
	}
}

func TestImport(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "OLD"}, []byte("old-value-1"), false)
	kvs := []KV{
		{"NEW", []byte("n1")}, {"OLD", []byte("replaced")}, {"BLANK", nil}, {"DUP", []byte("first")}, {"DUP", []byte("second")},
	}

	// Dry run: report, no writes.
	rep, err := v.Import(ctx, kvs, ConflictSkip, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.DryRun || strings.Join(rep.Added, ",") != "DUP,NEW" || strings.Join(rep.Skipped, ",") != "OLD" || strings.Join(rep.Empty, ",") != "BLANK" {
		t.Fatalf("%+v", rep)
	}
	if ok, _ := v.Exists(ctx, "NEW"); ok {
		t.Fatal("dry run wrote")
	}

	// Skip.
	rep, err = v.Import(ctx, kvs, ConflictSkip, false)
	if err != nil || len(rep.Added) != 2 || len(rep.Skipped) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	got, _ := v.Resolve(ctx, []string{"OLD", "DUP"})
	if string(got["OLD"]) != "old-value-1" || string(got["DUP"]) != "second" {
		t.Fatal("skip semantics / last-wins broken")
	}

	// Overwrite.
	rep, err = v.Import(ctx, kvs, ConflictOverwrite, false)
	if err != nil || strings.Join(rep.Overwritten, ",") != "DUP,NEW,OLD" || len(rep.Added) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	got, _ = v.Resolve(ctx, []string{"OLD"})
	if string(got["OLD"]) != "replaced" {
		t.Fatal("overwrite did not replace")
	}
}

func TestImportErrorModeIsAtomic(t *testing.T) {
	v, _, _ := newVault(t)
	_ = v.Set(ctx, Meta{Name: "B"}, []byte("keep"), false)
	_, err := v.Import(ctx, []KV{{"A", []byte("1")}, {"B", []byte("2")}}, ConflictError, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err = %v", err)
	}
	if ok, _ := v.Exists(ctx, "A"); ok {
		t.Fatal("partial import happened")
	}
	// Same check in dry-run.
	if _, err := v.Import(ctx, []KV{{"B", []byte("2")}}, ConflictError, true); !errors.Is(err, ErrExists) {
		t.Fatalf("dry-run err = %v", err)
	}
	// Invalid name anywhere rejects everything.
	if _, err := v.Import(ctx, []KV{{"GOOD", []byte("1")}, {"bad key", []byte("2")}}, ConflictSkip, false); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("err = %v", err)
	}
	if ok, _ := v.Exists(ctx, "GOOD"); ok {
		t.Fatal("partial import happened")
	}
	if _, err := v.Import(ctx, nil, ConflictMode("bogus"), false); err == nil {
		t.Fatal("bad mode accepted")
	}
	_ = v.Close()
	if _, err := v.Import(ctx, nil, ConflictSkip, false); !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
}

func TestKVFormattingRedacts(t *testing.T) {
	kv := KV{Key: "K", Value: []byte("topsecret")}
	if strings.Contains(kv.String()+kv.GoString(), "topsecret") {
		t.Fatal("leak")
	}
}
