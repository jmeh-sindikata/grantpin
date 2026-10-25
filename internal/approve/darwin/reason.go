package darwin

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"

	"grantd/internal/approve"
)

const (
	// MaxReasonRunes is the soft length budget for the prompt text. Secret
	// names are never truncated, so the result can exceed it only when the
	// secret list alone does.
	MaxReasonRunes = 250

	minArgvRunes   = 24
	minCwdRunes    = 24
	maxCallerRunes = 32
	ellipsis       = "…"
)

// BuildReason renders the LocalAuthentication localizedReason for req:
//
//	<caller> wants to run `<argv>` with <secrets> in <cwd>[ (approval lasts 1h)][ (no policy)]
//
// grantTTL > 0 means approving will create a grant for that long, which the
// text must disclose. All request fields are untrusted: they are sanitised and
// the argv is truncated in the middle (never the secret names).
func BuildReason(req approve.ApprovalRequest, grantTTL time.Duration) string {
	caller := truncateMiddle(clean(req.Caller), maxCallerRunes)
	if caller == "" {
		caller = "unknown caller"
	}
	cwd := clean(req.Cwd)
	if cwd == "" {
		cwd = "unknown directory"
	}
	secrets := renderSecrets(req.Secrets, req.Expanded)
	args := make([]string, len(req.Argv))
	for i, a := range req.Argv {
		args[i] = strings.ReplaceAll(clean(a), "`", "'")
	}
	argv := strings.Join(args, " ")
	if argv == "" {
		argv = "(empty command)"
	}

	suffix := ""
	if scope := GrantScope(req, grantTTL); scope != "" {
		suffix += " (" + scope + ")"
	} else if grantTTL > 0 {
		suffix += " (approval lasts " + formatTTL(grantTTL) + ")"
	}
	if !req.PolicyPresent {
		suffix += " (no policy)"
	}

	assemble := func(argv, cwd string) string {
		return caller + " wants to run `" + argv + "` with " + secrets + " in " + cwd + suffix
	}
	out := assemble(argv, cwd)
	over := utf8.RuneCountInString(out) - MaxReasonRunes
	if over <= 0 {
		return out
	}
	// Shrink argv first, down to its floor.
	argvLen := utf8.RuneCountInString(argv)
	newArgv := max(argvLen-over, minArgvRunes)
	argv = truncateMiddle(argv, newArgv)
	out = assemble(argv, cwd)
	over = utf8.RuneCountInString(out) - MaxReasonRunes
	if over <= 0 {
		return out
	}
	// Then the cwd, down to its floor. Secrets are left alone.
	cwdLen := utf8.RuneCountInString(cwd)
	cwd = truncateMiddle(cwd, max(cwdLen-over, minCwdRunes))
	return assemble(argv, cwd)
}

// GrantScope states what an "Allow for N" answer covers, e.g.
//
//	Allow for 1h covers: php artisan … in /Users/me/projects/foo and subfolders
//
// The "…" says any further arguments are covered. It is empty when ttl is not
// positive or the request carries no grant scope. The command prefix and
// directory are the security-relevant part of the text and are never
// truncated; they are sanitised like every other untrusted string.
func GrantScope(req approve.ApprovalRequest, ttl time.Duration) string {
	if ttl <= 0 {
		return ""
	}
	parts := make([]string, len(req.GrantCmdPrefix))
	for i, a := range req.GrantCmdPrefix {
		parts[i] = strings.ReplaceAll(clean(a), "`", "'")
	}
	cmd := strings.Join(parts, " ")
	cwd := clean(req.GrantCwdPrefix)
	if cmd == "" || cwd == "" {
		return ""
	}
	return "Allow for " + formatTTL(ttl) + " covers: " + cmd + " … in " + cwd + " and subfolders"
}

// renderSecrets lists the requested secrets. A glob that expanded to concrete
// names is followed by them: `aws/* (aws/access_key, aws/secret_key)`. When
// Expanded is empty or identical to Secrets only the requested names are shown.
// Names are never shortened or dropped.
func renderSecrets(secrets, expanded []string) string {
	if len(secrets) == 0 {
		return "no secrets"
	}
	show := len(expanded) > 0 && !slices.Equal(secrets, expanded)
	out := make([]string, len(secrets))
	for i, s := range secrets {
		out[i] = clean(s)
		if !show || !strings.ContainsAny(s, "*?[{") {
			continue
		}
		var matched []string
		for _, e := range expanded {
			if ok, _ := doublestar.Match(s, e); ok {
				matched = append(matched, clean(e))
			}
		}
		if len(matched) > 0 {
			out[i] += " (" + strings.Join(matched, ", ") + ")"
		}
	}
	return strings.Join(out, ", ")
}

// clean makes untrusted text safe to embed in a single-line prompt: invalid
// UTF-8 is replaced, control and format characters (newlines, bidi overrides)
// become spaces, and surrounding space is trimmed.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

// truncateMiddle shortens s to at most n runes by replacing the middle with an
// ellipsis, keeping the start and the end (the end of a path or command is
// usually the interesting part).
func truncateMiddle(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return ellipsis
	}
	keep := n - 1
	head := (keep + 1) / 2
	tail := keep - head
	return string(r[:head]) + ellipsis + string(r[len(r)-tail:])
}

// formatTTL renders d like "1h", "30m", "1h30m", rounded to minutes.
func formatTTL(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "under a minute"
	}
	h := int(d / time.Hour)
	m := int(d % time.Hour / time.Minute)
	switch {
	case h > 0 && m > 0:
		return strconv.Itoa(h) + "h" + strconv.Itoa(m) + "m"
	case h > 0:
		return strconv.Itoa(h) + "h"
	default:
		return strconv.Itoa(m) + "m"
	}
}
