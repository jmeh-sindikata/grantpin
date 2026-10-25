package darwin

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeExec struct {
	path   string
	args   []string
	stdout string
	stderr string
	code   int
	err    error
	calls  int
}

func (f *fakeExec) run(ctx context.Context, path string, args []string) ([]byte, []byte, int, error) {
	f.calls++
	f.path, f.args = path, args
	return []byte(f.stdout), []byte(f.stderr), f.code, f.err
}

func newFake(f *fakeExec) *chooser { return &chooser{exec: f.run} }

func TestDialogArgsShape(t *testing.T) {
	r := req()
	r.Caller = "-e"
	r.Argv = []string{"x'\" & (do shell script \"id\") & \""}
	args := dialogArgs(r, time.Hour)
	if len(args) != 5 || args[0] != "-e" || args[1] != chooserScript || args[2] != "--" {
		t.Fatalf("shape: %q", args)
	}
	text, label := args[3], args[4]
	if label != "Allow for 1h" {
		t.Errorf("label %q", label)
	}
	if strings.HasPrefix(text, "-") || !strings.HasPrefix(text, "An agent is asking grantd") {
		t.Errorf("text must start with trusted words: %q", text)
	}
	if !strings.Contains(text, "do shell script") {
		t.Errorf("untrusted text should appear verbatim as data in argv: %q", text)
	}
	if strings.Contains(args[1], "do shell script") || strings.Contains(args[1], "claude-code") {
		t.Error("untrusted text leaked into script source")
	}
	if !strings.Contains(text, "-e wants to run") {
		t.Errorf("caller missing: %q", text)
	}
}

func TestDialogArgsNoTTL(t *testing.T) {
	args := dialogArgs(req(), 0)
	if args[4] != "" || strings.Contains(args[3], "Allow for") {
		t.Errorf("no TTL => no third button: %q", args)
	}
}

func TestScriptIsStaticAndHasRequiredShape(t *testing.T) {
	for _, want := range []string{
		"on run argv", `default button "Deny"`, `cancel button "Deny"`,
		"with icon caution", "giving up after 120", `{"Deny", "Allow once"}`,
	} {
		if !strings.Contains(chooserScript, want) {
			t.Errorf("script missing %q", want)
		}
	}
}

func TestParseChoice(t *testing.T) {
	const f = "Allow for 1h"
	cases := []struct {
		in    string
		label string
		want  choice
	}{
		{"button returned:Allow once, gave up:false\n", f, choiceOnce},
		{"button returned:Allow for 1h, gave up:false\n", f, choiceFor},
		{"button returned:Deny, gave up:false\n", f, choiceDeny},
		{"button returned:, gave up:true\n", f, choiceDeny},
		{"button returned:Allow once, gave up:true\n", f, choiceDeny},
		{"button returned:allow once, gave up:false\n", f, choiceDeny},
		{"button returned:Allow once , gave up:false\n", f, choiceDeny},
		{"button returned:Allow for 2h, gave up:false\n", f, choiceDeny},
		{"button returned:Allow for 1h, gave up:false\n", "", choiceDeny}, // no such button offered
		{"xbutton returned:Allow once, gave up:false", f, choiceDeny},
		{"Allow once", f, choiceDeny},
		{"button returned:Allow once", f, choiceDeny},
		{"", f, choiceDeny},
		{"button returned:Allow once, gave up:false\nbutton returned:Deny, gave up:false", f, choiceDeny},
	}
	for _, c := range cases {
		if got := parseChoice(c.in, c.label); got != c.want {
			t.Errorf("parseChoice(%q,%q)=%v want %v", c.in, c.label, got, c.want)
		}
	}
}

func TestChooserAsk(t *testing.T) {
	ctx := context.Background()

	f := &fakeExec{stdout: "button returned:Allow for 1h, gave up:false\n"}
	got, err := newFake(f).ask(ctx, req(), time.Hour)
	if err != nil || got != choiceFor {
		t.Fatalf("got %v %v", got, err)
	}
	if f.path != "/usr/bin/osascript" {
		t.Errorf("path %q must be absolute /usr/bin/osascript", f.path)
	}

	f = &fakeExec{stdout: "button returned:Allow once, gave up:false\n"}
	if got, err := newFake(f).ask(ctx, req(), time.Hour); err != nil || got != choiceOnce {
		t.Fatalf("got %v %v", got, err)
	}

	// Cancel button => osascript exits 1 with error -128: a Deny, not an error.
	f = &fakeExec{code: 1, stderr: "0:17: execution error: User canceled. (-128)\n"}
	if got, err := newFake(f).ask(ctx, req(), time.Hour); err != nil || got != choiceDeny {
		t.Fatalf("cancel: %v %v", got, err)
	}

	// Any other failure is an error, never an allow.
	f = &fakeExec{code: 1, stderr: "execution error: something else (-1743)"}
	if got, err := newFake(f).ask(ctx, req(), time.Hour); !errors.Is(err, ErrChooserFailed) || got != choiceDeny {
		t.Fatalf("failure: %v %v", got, err)
	}
	f = &fakeExec{err: errors.New("fork/exec: no such file")}
	if got, err := newFake(f).ask(ctx, req(), 0); !errors.Is(err, ErrChooserFailed) || got != choiceDeny {
		t.Fatalf("exec error: %v %v", got, err)
	}

	// Garbage output with exit 0 => Deny.
	f = &fakeExec{stdout: "hello"}
	if got, err := newFake(f).ask(ctx, req(), time.Hour); err != nil || got != choiceDeny {
		t.Fatalf("garbage: %v %v", got, err)
	}
}

func TestChooserAskCancelledContext(t *testing.T) {
	f := &fakeExec{stdout: "button returned:Allow once, gave up:false\n"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := newFake(f).ask(ctx, req(), time.Hour)
	if !errors.Is(err, context.Canceled) || got != choiceDeny || f.calls != 0 {
		t.Fatalf("got %v %v calls=%d", got, err, f.calls)
	}
	// Cancelled while running: result discarded even if the fake "answered allow".
	ctx2, cancel2 := context.WithCancel(context.Background())
	c := &chooser{exec: func(ctx context.Context, p string, a []string) ([]byte, []byte, int, error) {
		cancel2()
		return []byte("button returned:Allow once, gave up:false\n"), nil, 0, nil
	}}
	got, err = c.ask(ctx2, req(), time.Hour)
	if !errors.Is(err, context.Canceled) || got != choiceDeny {
		t.Fatalf("mid-run cancel: %v %v", got, err)
	}
}

func TestAllowForLabel(t *testing.T) {
	if allowForLabel(0) != "" || allowForLabel(-1) != "" {
		t.Error("no label without TTL")
	}
	if allowForLabel(30*time.Minute) != "Allow for 30m" {
		t.Error("label")
	}
}

func TestLimitedBuffer(t *testing.T) {
	l := &limitedBuffer{max: 4}
	n, err := l.Write([]byte("abcdefgh"))
	if n != 8 || err != nil || l.buf.String() != "abcd" {
		t.Errorf("%d %v %q", n, err, l.buf.String())
	}
	_, _ = l.Write([]byte("zz"))
	if l.buf.String() != "abcd" {
		t.Error("exceeded max")
	}
}

func TestDialogArgsStateGrantScope(t *testing.T) {
	r := req()
	r.Argv = []string{"php", "artisan", "sync"}
	r.GrantCmdPrefix = []string{"php", "artisan"}
	r.GrantCwdPrefix = "/Users/me/projects/foo"
	args := dialogArgs(r, time.Hour)
	if !strings.HasSuffix(args[3], "\n\nAllow for 1h covers: php artisan … in /Users/me/projects/foo and subfolders.") {
		t.Errorf("text = %q", args[3])
	}
	if args[4] != "Allow for 1h" {
		t.Errorf("label = %q", args[4])
	}
	// No third button, no scope sentence.
	if a := dialogArgs(r, 0); strings.Contains(a[3], "covers") || a[4] != "" {
		t.Errorf("scope without Allow for N: %q", a)
	}
}
