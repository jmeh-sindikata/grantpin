package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantpin/internal/presence"
)

func TestRequestRoundTrip(t *testing.T) {
	exp := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tier := presence.TierHardware
	in := Request{
		V: Version, Op: OpSet, Caller: "cli", Name: "aws/access_key", Value: "s3cr3t-value",
		Tags: []string{"aws", "prod"}, URL: "https://example.com", Notes: "n",
		Expires: &exp, MinTier: &tier, Overwrite: true,
	}
	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(buf.String(), "\n") || strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("not exactly one line: %q", buf.String())
	}
	out, err := NewReader(&buf).ReadRequest()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*out, in) {
		t.Fatalf("round trip mismatch\n got %+v\nwant %+v", *out, in)
	}
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRunRequestMatchesSpecExample(t *testing.T) {
	// §7 example, verbatim.
	const line = `{"v":1,"op":"run","caller":"claude-code","cwd":"/abs/path","argv":["php","artisan","sync"],"secrets":["API_KEY","aws/*"],"env_prefix":"","timeout_s":600}`
	req, err := NewReader(strings.NewReader(line + "\n")).ReadRequest()
	if err != nil {
		t.Fatal(err)
	}
	want := Request{V: 1, Op: OpRun, Caller: "claude-code", Cwd: "/abs/path",
		Argv: []string{"php", "artisan", "sync"}, Secrets: []string{"API_KEY", "aws/*"}, TimeoutS: 600}
	if !reflect.DeepEqual(*req, want) {
		t.Fatalf("got %+v", *req)
	}
	// Re-encoding keeps the §7 key names (env_prefix omitted when empty).
	b, _ := json.Marshal(want)
	for _, k := range []string{`"v":1`, `"op":"run"`, `"caller":"claude-code"`, `"cwd":"/abs/path"`, `"argv":[`, `"secrets":[`, `"timeout_s":600`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("encoded request missing %s: %s", k, b)
		}
	}
}

func TestStreamAndResponseRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	frames := []StreamFrame{{StreamStdout, "hello [REDACTED:API_KEY]\n"}, {StreamStderr, "warn"}}
	for _, f := range frames {
		if err := Write(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	ok := Response{OK: true, ExitCode: IntPtr(0), GrantID: "g1", AuditID: "a1"}
	denied := Response{OK: false, Error: ErrDenied, Reason: ReasonUserDenied}
	res, err := NewResult([]SecretInfo{{Name: "x", MinTier: presence.TierDialog}})
	if err != nil {
		t.Fatal(err)
	}
	withResult := Response{OK: true, Result: res}
	for _, r := range []Response{ok, denied, withResult} {
		if err := Write(&buf, r); err != nil {
			t.Fatal(err)
		}
	}

	rd := NewReader(&buf)
	for i, want := range frames {
		m, err := rd.ReadMessage()
		if err != nil || m.Frame == nil || m.Response != nil || *m.Frame != want {
			t.Fatalf("frame %d = %+v, %v", i, m, err)
		}
	}
	m, err := rd.ReadMessage()
	if err != nil || m.Response == nil || !m.Response.OK || m.Response.ExitCode == nil || *m.Response.ExitCode != 0 ||
		m.Response.GrantID != "g1" || m.Response.AuditID != "a1" {
		t.Fatalf("ok response = %+v, %v", m, err)
	}
	m, err = rd.ReadMessage()
	if err != nil || m.Response == nil || m.Response.OK || m.Response.ExitCode != nil ||
		m.Response.Error != "denied" || m.Response.Reason != "user_denied" {
		t.Fatalf("denied response = %+v, %v", m, err)
	}
	m, err = rd.ReadMessage()
	if err != nil || m.Response == nil {
		t.Fatalf("result response = %+v, %v", m, err)
	}
	var infos []SecretInfo
	if err := json.Unmarshal(m.Response.Result, &infos); err != nil || len(infos) != 1 || infos[0].Name != "x" || infos[0].MinTier != presence.TierDialog {
		t.Fatalf("result = %+v, %v", infos, err)
	}
}

func TestSpecFinalLinesExact(t *testing.T) {
	// §7 final lines, byte-for-byte after compaction.
	var b bytes.Buffer
	_ = Write(&b, Response{OK: true, ExitCode: IntPtr(0), GrantID: "...", AuditID: "..."})
	if got, want := b.String(), `{"ok":true,"exit_code":0,"grant_id":"...","audit_id":"..."}`+"\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	b.Reset()
	_ = Write(&b, Response{Error: ErrDenied, Reason: ReasonUserDenied})
	if got, want := b.String(), `{"ok":false,"error":"denied","reason":"user_denied"}`+"\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	b.Reset()
	_ = Write(&b, StreamFrame{StreamStdout, "x"})
	if got, want := b.String(), `{"stream":"stdout","data":"x"}`+"\n"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestValidate(t *testing.T) {
	if err := (&Request{V: 2, Op: OpRun}).Validate(); err == nil {
		t.Error("bad version accepted")
	}
	if err := (&Request{V: 1, Op: "fetch"}).Validate(); err == nil {
		t.Error("unknown op accepted")
	}
	for _, op := range Ops {
		if err := (&Request{V: 1, Op: op}).Validate(); err != nil {
			t.Errorf("op %s rejected: %v", op, err)
		}
	}
}

func TestSecretValuesNeverFormatted(t *testing.T) {
	const secret = "hunter2-very-secret"
	r := Request{V: 1, Op: OpSet, Name: "n", Value: secret}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), r.String()} {
		if strings.Contains(s, secret) {
			t.Fatalf("formatted Request leaked value: %s", s)
		}
	}
	sr := ShowResult{Value: secret}
	for _, s := range []string{fmt.Sprint(sr), fmt.Sprintf("%+v", sr), fmt.Sprintf("%#v", sr)} {
		if strings.Contains(s, secret) {
			t.Fatalf("formatted ShowResult leaked value: %s", s)
		}
	}
	// JSON on the wire still carries it (that is the point of OpSet / OpShow).
	if b, _ := json.Marshal(r); !strings.Contains(string(b), secret) {
		t.Fatal("wire encoding must carry value for set")
	}
}

func TestReaderEdgeCases(t *testing.T) {
	rd := NewReader(strings.NewReader("\n\n"))
	if _, err := rd.ReadRequest(); err == nil {
		t.Fatal("expected EOF")
	}
	if _, err := NewReader(strings.NewReader("{bad\n")).ReadRequest(); err == nil {
		t.Fatal("expected decode error")
	}
	if _, err := NewReader(strings.NewReader(`{"x":1}` + "\n")).ReadMessage(); err == nil {
		t.Fatal("expected unknown-message error")
	}
	huge := strings.Repeat("a", MaxLineBytes+10)
	var sink bytes.Buffer
	if err := Write(&sink, StreamFrame{StreamStdout, huge}); !errors.Is(err, ErrLineTooLong) || sink.Len() != 0 {
		t.Fatalf("oversize write: err=%v, wrote %d bytes", err, sink.Len())
	}
	if _, err := Encode(StreamFrame{StreamStdout, huge}); !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("Encode oversize: %v", err)
	}
	if _, err := Encode(make(chan int)); err == nil || errors.Is(err, ErrLineTooLong) {
		t.Fatalf("an unencodable value is not a size error: %v", err)
	}
	if b, err := Encode(Response{OK: true}); err != nil || b[len(b)-1] != '\n' {
		t.Fatalf("Encode: %q %v", b, err)
	}
	if _, err := NewReader(strings.NewReader(huge + "\n")).ReadRequest(); err == nil {
		t.Fatal("expected oversize read error")
	}
}

func TestUpdateRequestWire(t *testing.T) {
	exp := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	tier := presence.TierDialog
	in := Request{V: Version, Op: OpUpdate, Caller: "grantpin-app", Name: "aws/key",
		Tags: []string{"a"}, URL: "https://x", Notes: "n", Expires: &exp, MinTier: &tier, Clear: []string{"notes"}}
	var buf bytes.Buffer
	if err := Write(&buf, in); err != nil {
		t.Fatal(err)
	}
	const want = `{"v":1,"op":"update","caller":"grantpin-app","name":"aws/key","tags":["a"],"url":"https://x","notes":"n","expires":"2026-11-01T12:00:00Z","min_tier":"dialog","clear":["notes"]}` + "\n"
	if buf.String() != want {
		t.Errorf("wire form\n got %s want %s", buf.String(), want)
	}
	out, err := NewReader(&buf).ReadRequest()
	if err != nil || !reflect.DeepEqual(*out, in) {
		t.Fatalf("round trip: %+v, %v", out, err)
	}
	if err := out.Validate(); err != nil {
		t.Fatal(err)
	}
}
