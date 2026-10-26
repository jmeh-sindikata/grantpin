package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

func TestSecretsCell(t *testing.T) {
	for _, tc := range []struct {
		name string
		e    proto.AuditInfo
		want string
	}{
		{"no expansion recorded", proto.AuditInfo{Secrets: []string{"aws/*"}}, "aws/*"},
		{"literal names", proto.AuditInfo{Secrets: []string{"A", "B"}, Expanded: []string{"A", "B"}}, "A,B"},
		{"glob", proto.AuditInfo{Secrets: []string{"aws/*", "A"}, Expanded: []string{"A", "aws/a", "aws/b"}}, "aws/*,A → A, aws/a, aws/b"},
	} {
		if got := secretsCell(tc.e); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestDecodeAuditList(t *testing.T) {
	obj := &proto.Response{OK: true, Result: json.RawMessage(`{"entries":[{"id":"2"},{"id":"1"}],"truncated":true,"skipped":3,"next_before_id":"1"}`)}
	r, err := decodeAuditList(obj)
	if err != nil || !r.Truncated || len(r.Entries) != 2 || r.Entries[0].ID != "2" || r.Skipped != 3 || r.NextBeforeID != "1" {
		t.Fatalf("object: %+v %v", r, err)
	}
	// An older daemon sends a bare array.
	arr := &proto.Response{OK: true, Result: json.RawMessage(` [{"id":"7"}]`)}
	r, err = decodeAuditList(arr)
	if err != nil || r.Truncated || len(r.Entries) != 1 || r.Entries[0].ID != "7" {
		t.Fatalf("array: %+v %v", r, err)
	}
	if _, err := decodeAuditList(&proto.Response{OK: true}); err == nil {
		t.Fatal("missing result accepted")
	}
}

func TestPrintableDefusesControlCharacters(t *testing.T) {
	got := printable("a\x1b[2Jb\tc\nd\x7fé")
	if got != "a?[2Jb c?d?é" || strings.ContainsAny(got, "\x1b\n\t\x7f") {
		t.Fatalf("printable = %q", got)
	}
}
