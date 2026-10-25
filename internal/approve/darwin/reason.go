package darwin

import (
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

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
	secrets := "no secrets"
	if len(req.Secrets) > 0 {
		names := make([]string, len(req.Secrets))
		for i, s := range req.Secrets {
			names[i] = clean(s)
		}
		secrets = strings.Join(names, ", ")
	}
	args := make([]string, len(req.Argv))
	for i, a := range req.Argv {
		args[i] = strings.ReplaceAll(clean(a), "`", "'")
	}
	argv := strings.Join(args, " ")
	if argv == "" {
		argv = "(empty command)"
	}

	suffix := ""
	if grantTTL > 0 {
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
