package main

import (
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
