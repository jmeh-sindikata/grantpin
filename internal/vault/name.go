package vault

import (
	"fmt"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
)

const (
	maxNameLen  = 256
	maxTagLen   = 64
	maxTags     = 32
	maxValueLen = 1 << 20 // 1 MiB
)

func nameErr(reason string) error {
	// The offending name is deliberately not echoed: a user who pastes a value
	// where a name belongs must not see it in an error or log line.
	return fmt.Errorf("%w: %s", ErrInvalidName, reason)
}

func nameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '/' || c == '.' || c == '-'
}

// ValidateName checks a secret name: [A-Za-z0-9_/.-]+, at most 256 bytes, no
// empty segments ("a//b"), no leading or trailing "/", and no "." / ".."
// segments or ".." anywhere (conservative).
func ValidateName(name string) error {
	if name == "" {
		return nameErr("empty")
	}
	if len(name) > maxNameLen {
		return nameErr("too long")
	}
	for i := 0; i < len(name); i++ {
		if !nameChar(name[i]) {
			return nameErr("characters must be A-Z a-z 0-9 _ / . -")
		}
	}
	return validateShape(name)
}

func validateShape(s string) error {
	if strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return nameErr("must not start or end with '/'")
	}
	if strings.Contains(s, "..") {
		return nameErr("must not contain '..'")
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" {
			return nameErr("empty path segment")
		}
		if seg == "." {
			return nameErr("'.' path segment")
		}
	}
	return nil
}

// IsPattern reports whether s contains glob metacharacters. Valid secret names
// never do, so the split is unambiguous.
func IsPattern(s string) bool { return strings.ContainsAny(s, `*?[]{}\`) }

// validatePattern checks a name or doublestar glob such as "aws/*".
func validatePattern(p string) error {
	if !IsPattern(p) {
		return ValidateName(p)
	}
	if p == "" || len(p) > maxNameLen {
		return nameErr("bad length")
	}
	if strings.Contains(p, `\`) {
		return nameErr("escapes are not allowed in patterns")
	}
	if !doublestar.ValidatePattern(p) {
		return nameErr("malformed glob")
	}
	return validateShape(p)
}

func validateTag(t string) error {
	if t == "" || len(t) > maxTagLen {
		return fmt.Errorf("%w (length)", ErrInvalidTag)
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		if !(nameChar(c) && c != '/' || c == ':') {
			return fmt.Errorf("%w (characters must be A-Z a-z 0-9 _ . - :)", ErrInvalidTag)
		}
	}
	return nil
}
