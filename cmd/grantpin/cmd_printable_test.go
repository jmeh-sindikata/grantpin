package main

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// fakeDaemon answers every request with the given result, ignoring the request.
func fakeDaemon(t *testing.T, result any) string {
	t.Helper()
	sock := shortSocket(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = bufio.NewReader(c).ReadBytes('\n')
				line, _ := json.Marshal(proto.Response{OK: true, Result: raw})
				_, _ = c.Write(append(line, '\n'))
			}()
		}
	}()
	return sock
}

func TestPrintableDefusesBidiOverrides(t *testing.T) {
	for _, r := range "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069" {
		if got := printable("a" + string(r) + "b"); got != "a?b" {
			t.Errorf("U+%04X: %q", r, got)
		}
	}
	// Neighbours of the ranges, and ordinary non-ASCII text, are kept.
	for _, s := range []string{"\u2029", "\u202f", "\u2065", "\u206a", "héllo wörld € 日本語 😀"} {
		if got := printable(s); got != s {
			t.Errorf("%q changed to %q", s, got)
		}
	}
	// C1 controls: 0x9b is CSI on some terminals.
	if got := printable("a\u009b31mb"); strings.ContainsRune(got, 0x9b) {
		t.Errorf("C1 kept: %q", got)
	}
}

const hostile = "\x1b[2J\x1b]0;pwned\x07evil\u202etxt.exe\r\x7f"

func assertClean(t *testing.T, what, out string) {
	t.Helper()
	for _, bad := range []string{"\x1b", "\x07", "\r", "\x7f", "\u202e"} {
		if strings.Contains(out, bad) {
			t.Errorf("%s: output contains %q:\n%q", what, bad, out)
		}
	}
	if !strings.Contains(out, "evil") {
		t.Errorf("%s: the text itself is gone: %q", what, out)
	}
}

func TestListPrintsUntrustedFieldsSafely(t *testing.T) {
	sock := fakeDaemon(t, []proto.SecretInfo{{Name: "N" + hostile, URL: "https://x/" + hostile, Tags: []string{"t" + hostile}}})
	out := mustCLI(t, "", "list", "--socket", sock)
	assertClean(t, "list", out)
}

func TestGrantsListPrintsUntrustedFieldsSafely(t *testing.T) {
	sock := fakeDaemon(t, []proto.GrantInfo{{
		ID: "g" + hostile, Caller: "c" + hostile, CwdPrefix: "/p/" + hostile,
		Secrets: []string{"s" + hostile}, CmdPrefix: []string{"echo", hostile},
	}})
	out := mustCLI(t, "", "grants", "list", "--socket", sock)
	assertClean(t, "grants list", out)
}

func TestAuditListPrintsUntrustedFieldsSafely(t *testing.T) {
	sock := fakeDaemon(t, proto.AuditListResult{Entries: []proto.AuditInfo{{
		ID: "1", Decision: "error" + hostile, Caller: "c" + hostile, Cwd: "/" + hostile,
		Argv: []string{"echo", hostile}, Secrets: []string{"s" + hostile}, Expanded: []string{"x" + hostile},
		Reason: "r" + hostile,
	}}})
	out := mustCLI(t, "", "audit", "list", "--socket", sock)
	assertClean(t, "audit list", out)
}
