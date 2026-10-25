package main

import (
	"encoding/json"
	"strings"
	"testing"

	"grantd/internal/proto"
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
	obj := &proto.Response{OK: true, Result: json.RawMessage(`{"entries":[{"id":"2"},{"id":"1"}],"truncated":true}`)}
	es, trunc, err := decodeAuditList(obj)
	if err != nil || !trunc || len(es) != 2 || es[0].ID != "2" {
		t.Fatalf("object: %v %v %v", es, trunc, err)
	}
	// An older daemon sends a bare array.
	arr := &proto.Response{OK: true, Result: json.RawMessage(` [{"id":"7"}]`)}
	es, trunc, err = decodeAuditList(arr)
	if err != nil || trunc || len(es) != 1 || es[0].ID != "7" {
		t.Fatalf("array: %v %v %v", es, trunc, err)
	}
	if _, _, err := decodeAuditList(&proto.Response{OK: true}); err == nil {
		t.Fatal("missing result accepted")
	}
}

func TestPrintableDefusesControlCharacters(t *testing.T) {
	got := printable("a\x1b[2Jb\tc\nd\x7fé")
	if got != "a?[2Jb c?d?é" || strings.ContainsAny(got, "\x1b\n\t\x7f") {
		t.Fatalf("printable = %q", got)
	}
}
