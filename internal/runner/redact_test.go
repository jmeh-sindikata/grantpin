package runner

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

func redactChunks(t *testing.T, secrets map[string]string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	w := NewRedactingWriter(&out, secrets)
	for _, c := range chunks {
		n, err := w.Write([]byte(c))
		if err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return out.String()
}

func TestRedactingWriterBasic(t *testing.T) {
	sec := map[string]string{"API_KEY": "s3cr3t-value", "aws/id": "AKIA123"}
	tests := []struct {
		name   string
		chunks []string
		want   string
	}{
		{"none", []string{"hello world\n"}, "hello world\n"},
		{"single", []string{"key=s3cr3t-value!\n"}, "key=[REDACTED:API_KEY]!\n"},
		{"two", []string{"s3cr3t-value AKIA123"}, "[REDACTED:API_KEY] [REDACTED:aws/id]"},
		{"repeated", []string{"AKIA123AKIA123"}, "[REDACTED:aws/id][REDACTED:aws/id]"},
		{"split in two", []string{"x s3cr3t", "-value y"}, "x [REDACTED:API_KEY] y"},
		{"split bytewise", strings.Split("a s3cr3t-value b AKIA123", ""), "a [REDACTED:API_KEY] b [REDACTED:aws/id]"},
		{"partial at end flushed on close", []string{"abc s3cr3t-val"}, "abc s3cr3t-val"},
		{"partial then diverge", []string{"s3cr3t-", "valXe"}, "s3cr3t-valXe"},
		{"empty chunks", []string{"", "AKIA", "", "123", ""}, "[REDACTED:aws/id]"},
		{"false start", []string{"AKIAAKIA123"}, "AKIA[REDACTED:aws/id]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := redactChunks(t, sec, tc.chunks...); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestRedactingWriterLongestMatchFirst(t *testing.T) {
	sec := map[string]string{"SHORT": "abc", "LONG": "abcdef"}
	for _, chunks := range [][]string{
		{"xabcdefx"},
		{"xabc", "defx"},
		{"xab", "c", "d", "e", "f", "x"},
	} {
		if got := redactChunks(t, sec, chunks...); got != "x[REDACTED:LONG]x" {
			t.Errorf("%q: got %q", chunks, got)
		}
	}
	// longer value is a near-miss: the short one must still win, even when the
	// writer had to wait for more input to find out.
	for _, chunks := range [][]string{
		{"xabcdeg"},
		{"xabcde", "g"},
		{"xabc", "dez"},
	} {
		got := redactChunks(t, sec, chunks...)
		if !strings.HasPrefix(got, "x[REDACTED:SHORT]de") {
			t.Errorf("%q: got %q", chunks, got)
		}
	}
	// partial longer value at end of stream, short match must be flushed.
	if got := redactChunks(t, sec, "xabcde"); got != "x[REDACTED:SHORT]de" {
		t.Errorf("got %q", got)
	}
}

func TestRedactingWriterSharedValue(t *testing.T) {
	got := redactChunks(t, map[string]string{"B": "same-value", "A": "same-value"}, "same-value")
	if got != "[REDACTED:A]" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactingWriterEmptyAndShortValues(t *testing.T) {
	// empty value skipped entirely (would otherwise match everywhere)
	if got := redactChunks(t, map[string]string{"E": ""}, "abc"); got != "abc" {
		t.Fatalf("got %q", got)
	}
	// 1-byte value is redacted (documented false-positive risk)
	if got := redactChunks(t, map[string]string{"ONE": "1"}, "a1b11"); got != "a[REDACTED:ONE]b[REDACTED:ONE][REDACTED:ONE]" {
		t.Fatalf("got %q", got)
	}
	if got := redactChunks(t, nil, "plain"); got != "plain" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactingWriterBinaryAndNewlines(t *testing.T) {
	sec := map[string]string{"BIN": "\x00\xff\x01line1\nline2"}
	in := "pre\x00\xff\x01line1\nline2post"
	if got := redactChunks(t, sec, in[:7], in[7:]); got != "pre[REDACTED:BIN]post" {
		t.Fatalf("got %q", got)
	}
}

func TestRedactingWriterStreamsNonSecretBytesImmediately(t *testing.T) {
	var out bytes.Buffer
	w := NewRedactingWriter(&out, map[string]string{"K": strings.Repeat("Z", 64)})
	if _, err := w.Write([]byte("first line\n")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "first line\n" {
		t.Fatalf("expected immediate forward, got %q", out.String())
	}
	// A trailing byte that could start a secret is withheld until resolved.
	if _, err := w.Write([]byte("abZ")); err != nil {
		t.Fatal(err)
	}
	if out.String() != "first line\nab" {
		t.Fatalf("got %q", out.String())
	}
	_ = w.Close()
	if out.String() != "first line\nabZ" {
		t.Fatalf("got %q", out.String())
	}
}

func TestRedactingWriterDoesNotAliasCallerBuffer(t *testing.T) {
	var out bytes.Buffer
	w := NewRedactingWriter(&out, map[string]string{"K": "secretvalue"})
	buf := []byte("xx secret")
	_, _ = w.Write(buf)
	copy(buf, "YYYYYYYYY") // caller reuses its buffer
	_, _ = w.Write([]byte("value"))
	_ = w.Close()
	if out.String() != "xx [REDACTED:K]" {
		t.Fatalf("got %q", out.String())
	}
}

type errWriter struct{ err error }

func (e errWriter) Write([]byte) (int, error) { return 0, e.err }

func TestRedactingWriterErrors(t *testing.T) {
	boom := errors.New("boom")
	w := NewRedactingWriter(errWriter{boom}, map[string]string{"K": "secretvalue"})
	if _, err := w.Write([]byte("hello")); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, err := w.Write([]byte("again")); !errors.Is(err, boom) {
		t.Fatalf("sticky err = %v", err)
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("close err = %v", err)
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("second close err = %v", err)
	}

	// no secrets: passthrough still reports errors
	w = NewRedactingWriter(errWriter{boom}, nil)
	if _, err := w.Write([]byte("x")); !errors.Is(err, boom) {
		t.Fatalf("passthrough err = %v", err)
	}

	// error surfacing at Close (flush of withheld bytes)
	cw := &failAfter{n: 1, err: boom}
	w = NewRedactingWriter(cw, map[string]string{"K": "secretvalue"})
	if _, err := w.Write([]byte("ok secret")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); !errors.Is(err, boom) {
		t.Fatalf("flush err = %v", err)
	}

	// write after close
	var sink bytes.Buffer
	w = NewRedactingWriter(&sink, map[string]string{"K": "secretvalue"})
	_ = w.Close()
	if _, err := w.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after close err = %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("double close = %v", err)
	}
}

type failAfter struct {
	n   int
	err error
}

func (f *failAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, f.err
	}
	f.n--
	return len(p), nil
}

func TestRedactString(t *testing.T) {
	r := NewRedactor(map[string]string{"TOKEN": "tok-12345", "a/b": "xyz789"})
	tests := []struct{ in, want string }{
		{"", ""},
		{"nothing here", "nothing here"},
		{"failed: auth tok-12345 rejected", "failed: auth [REDACTED:TOKEN] rejected"},
		{"xyz789tok-12345", "[REDACTED:a/b][REDACTED:TOKEN]"},
		{"tok-1234", "tok-1234"}, // incomplete prefix at end of string is emitted verbatim
	}
	for _, tc := range tests {
		if got := r.RedactString(tc.in); got != tc.want {
			t.Errorf("RedactString(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	var nilR *Redactor
	if got := nilR.RedactString("abc"); got != "abc" {
		t.Errorf("nil redactor: %q", got)
	}
	if got := NewRedactor(nil).RedactString("abc"); got != "abc" {
		t.Errorf("empty redactor: %q", got)
	}
}

// reference is the single-shot oracle: strings.NewReplacer with the longest
// values first has the same leftmost, longest-first, non-overlapping
// semantics.
func reference(secrets map[string]string, in string) string {
	type nv struct{ n, v string }
	var all []nv
	for n, v := range secrets {
		if v != "" {
			all = append(all, nv{n, v})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if len(all[i].v) != len(all[j].v) {
			return len(all[i].v) > len(all[j].v)
		}
		if all[i].v != all[j].v {
			return all[i].v < all[j].v
		}
		return all[i].n < all[j].n
	})
	var args []string
	for _, e := range all {
		args = append(args, e.v, "[REDACTED:"+e.n+"]")
	}
	if len(args) == 0 {
		return in
	}
	return strings.NewReplacer(args...).Replace(in)
}

// TestRedactingWriterProperty: for random secrets and random chunking, the
// streamed output equals the single-shot result. A tiny alphabet makes
// overlaps, prefixes and near-misses frequent.
func TestRedactingWriterProperty(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabets := []string{"ab", "abc", "abcdefghijklmnopqrstuvwxyz0123456789-_/=+"}
	iters := 3000
	if testing.Short() {
		iters = 300
	}
	for it := 0; it < iters; it++ {
		alpha := alphabets[rng.Intn(len(alphabets))]
		rs := func(n int) string {
			b := make([]byte, n)
			for i := range b {
				b[i] = alpha[rng.Intn(len(alpha))]
			}
			return string(b)
		}
		secrets := map[string]string{}
		for i, k := 0, 1+rng.Intn(4); i < k; i++ {
			secrets["S"+string(rune('A'+i))] = rs(1 + rng.Intn(64))
		}
		// build input from noise and secret values (some mutated)
		var sb strings.Builder
		for sb.Len() < 400 {
			switch rng.Intn(4) {
			case 0:
				sb.WriteString(rs(rng.Intn(20)))
			case 1, 2:
				for _, v := range secrets {
					sb.WriteString(v)
					break
				}
			case 3:
				for _, v := range secrets {
					if len(v) > 1 {
						sb.WriteString(v[:len(v)-1]) // near miss
					}
					break
				}
			}
		}
		in := sb.String()
		want := reference(secrets, in)

		var out bytes.Buffer
		w := NewRedactingWriter(&out, secrets)
		for rest := in; len(rest) > 0; {
			n := 1 + rng.Intn(70)
			if rng.Intn(5) == 0 {
				n = 1
			}
			if n > len(rest) {
				n = len(rest)
			}
			if _, err := w.Write([]byte(rest[:n])); err != nil {
				t.Fatal(err)
			}
			rest = rest[n:]
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if out.String() != want {
			t.Fatalf("iter %d secrets=%q\n in=%q\ngot =%q\nwant=%q", it, secrets, in, out.String(), want)
		}
		if got := NewRedactor(secrets).RedactString(in); got != want {
			t.Fatalf("iter %d RedactString mismatch", it)
		}
	}
}

// Single-secret case against plain strings.ReplaceAll, as a sanity check of the
// oracle itself.
func TestRedactingWriterPropertySingleVsReplaceAll(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for it := 0; it < 1000; it++ {
		n := 1 + rng.Intn(64)
		b := make([]byte, n)
		for i := range b {
			b[i] = byte('a' + rng.Intn(3))
		}
		val := string(b)
		in := strings.Repeat("ab"+val+"c", 1+rng.Intn(6)) + val[:n/2]
		want := strings.ReplaceAll(in, val, "[REDACTED:X]")
		var out bytes.Buffer
		w := NewRedactingWriter(&out, map[string]string{"X": val})
		for rest := in; len(rest) > 0; {
			k := 1 + rng.Intn(9)
			if k > len(rest) {
				k = len(rest)
			}
			_, _ = w.Write([]byte(rest[:k]))
			rest = rest[k:]
		}
		_ = w.Close()
		if out.String() != want {
			t.Fatalf("val=%q in=%q got=%q want=%q", val, in, out.String(), want)
		}
	}
}

func FuzzRedactingWriter(f *testing.F) {
	f.Add("secret", "xx secret yy", uint8(3))
	f.Add("a", "aaaa", uint8(1))
	f.Fuzz(func(t *testing.T, val, in string, chunk uint8) {
		if val == "" {
			return
		}
		secrets := map[string]string{"X": val, "Y": val + "!"}
		want := reference(secrets, in)
		var out bytes.Buffer
		w := NewRedactingWriter(&out, secrets)
		step := int(chunk%16) + 1
		for rest := in; len(rest) > 0; {
			k := step
			if k > len(rest) {
				k = len(rest)
			}
			_, _ = w.Write([]byte(rest[:k]))
			rest = rest[k:]
		}
		_ = w.Close()
		if out.String() != want {
			t.Fatalf("got %q want %q", out.String(), want)
		}
	})
}
