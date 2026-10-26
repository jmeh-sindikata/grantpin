package darwin

import (
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bmatcuk/doublestar/v4"

	"github.com/jmeh-sindikata/grantd/internal/approve"
)

const (
	// MaxReasonRunes is the soft length budget for the prompt text. Secret
	// names are never truncated, so the result can exceed it only when the
	// secret list alone does.
	MaxReasonRunes = 250

	// MaxDialogArgvRunes is the most of the command the release dialog shows
	// in one piece. Longer commands show the first and last half of this
	// budget with an explicit "omitted" marker and a line stating the full
	// length (see ReleaseText); the omission is never silent.
	MaxDialogArgvRunes = 2000

	minArgvRunes   = 24
	minCwdRunes    = 24
	maxCallerRunes = 32
	ellipsis       = "…"
)

// BuildReason renders the LocalAuthentication localizedReason for req. It is
// for the Touch ID sheet only, whose text has a hard length budget; the dialog
// shows the command through ReleaseText instead, which never cuts the middle
// silently:
//
//	<caller> wants to run `<argv>` with <secrets> in <cwd>[ (approval lasts 1h)][ (no policy)]
//
// grantTTL > 0 means approving will create a grant for that long, which the
// text must disclose. All request fields are untrusted: they are sanitised and
// the argv is truncated in the middle (never the secret names).
//
// For KindStandingGrant the text is different on purpose, so the Touch ID sheet
// cannot be mistaken for a release prompt, and grantTTL is ignored in favour of
// req.RequestedTTL:
//
//	Create standing grant for 30 days: <caller> may run `<cmd prefix> …` with <secrets> in <cwd> and subfolders[ (at most N runs)][ (no policy)]
func BuildReason(req approve.ApprovalRequest, grantTTL time.Duration) string {
	if req.Kind == approve.KindLowerTier {
		return lowerTierQuestion(req)
	}
	standing := req.Kind == approve.KindStandingGrant
	caller := truncateMiddle(clean(req.Caller), maxCallerRunes)
	if caller == "" {
		caller = "unknown caller"
	}
	cwd := clean(req.Cwd)
	if cwd == "" {
		cwd = "unknown directory"
	}
	secrets := renderSecrets(req.Secrets, req.Expanded)
	cmd := req.Argv
	if standing && len(req.GrantCmdPrefix) > 0 {
		cmd = req.GrantCmdPrefix
	}
	argv := cleanArgv(cmd)

	suffix := ""
	if standing {
		suffix += usesSuffix(req.RequestedUses)
	} else if scope := GrantScope(req, grantTTL); scope != "" {
		suffix += " (" + scope + ")"
	} else if grantTTL > 0 {
		suffix += " (approval lasts " + formatTTL(grantTTL) + ")"
	}
	if !req.PolicyPresent {
		suffix += " (no policy)"
	}

	assemble := func(argv, cwd string) string {
		if standing {
			return "Create standing grant for " + formatSpan(req.RequestedTTL) + ": " + caller +
				" may run `" + argv + " …` with " + secrets + " in " + cwd + " and subfolders" + suffix
		}
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

// cleanArgv sanitises and joins a command for display: every argument is
// cleaned (control and bidi characters become spaces), backticks become
// apostrophes so the argv cannot close the code span it is shown in, and an
// empty command is named.
func cleanArgv(cmd []string) string {
	args := make([]string, len(cmd))
	for i, a := range cmd {
		args[i] = strings.ReplaceAll(clean(a), "`", "'")
	}
	argv := strings.Join(args, " ")
	if argv == "" {
		argv = "(empty command)"
	}
	return argv
}

// dialogArgv returns the command for the release dialog and, when it had to be
// shortened, a sentence stating the full length. A command of at most
// MaxDialogArgvRunes is returned whole with an empty note. A longer one keeps
// its first and last MaxDialogArgvRunes/2 runes around a
// "[… N characters omitted …]" marker, and the note repeats N and the total.
func dialogArgv(cmd []string) (argv, note string) {
	argv = cleanArgv(cmd)
	r := []rune(argv)
	if len(r) <= MaxDialogArgvRunes {
		return argv, ""
	}
	half := MaxDialogArgvRunes / 2
	omitted := len(r) - 2*half
	marker := "[" + ellipsis + " " + strconv.Itoa(omitted) + " characters omitted " + ellipsis + "]"
	argv = string(r[:half]) + marker + string(r[len(r)-half:])
	note = "The command is " + strconv.Itoa(len(r)) + " characters long. The " + strconv.Itoa(omitted) +
		" in the middle are not shown here. Deny unless you know what the whole command does."
	return argv, note
}

// ReleaseText is the body of the release (and show) dialog:
//
//	An agent is asking grantd to release secrets:
//
//	<caller> wants to run `<argv>` with <secrets> in <cwd>[ (no policy)]
//
//	[<length note>]
//
//	[Allow for 1h covers: <cmd prefix> … in <cwd> and subfolders.]
//
// Unlike BuildReason it carries the whole command: this dialog is the place
// where the human reads it, and a payload hidden in the middle of a long
// command must not be cut away. The only cap is MaxDialogArgvRunes, and a cut
// is announced in the text (marker and length note). Secrets and the
// directory are never shortened. ttl is the duration the "Allow for N" button
// offers (0 = none) and decides the scope sentence.
func ReleaseText(req approve.ApprovalRequest, ttl time.Duration) string {
	caller := truncateMiddle(clean(req.Caller), maxCallerRunes)
	if caller == "" {
		caller = "unknown caller"
	}
	cwd := clean(req.Cwd)
	if cwd == "" {
		cwd = "unknown directory"
	}
	argv, note := dialogArgv(req.Argv)
	text := "An agent is asking grantd to release secrets:\n\n" + caller + " wants to run `" + argv +
		"` with " + renderSecrets(req.Secrets, req.Expanded) + " in " + cwd
	if !req.PolicyPresent {
		text += " (no policy)"
	}
	if note != "" {
		text += "\n\n" + note
	}
	if scope := GrantScope(req, ttl); scope != "" {
		text += "\n\n" + scope + "."
	} else if ttl > 0 {
		text += "\n\n\"" + allowForLabel(ttl) + "\" lets the same request run again for that long."
	}
	return text
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

// StandingText is the body of the standing-grant dialog:
//
//	Create a standing grant?
//
//	<caller> may run `<cmd prefix> …` with <secrets> in <cwd> and subfolders for the next 30 days, without further prompts.
//
//	Only continue if you just asked for this yourself.
//
// The whole request is untrusted and sanitised like BuildReason. The command
// prefix, secrets (with globs expanded) and directory are the scope of the
// grant and are never truncated; the caller is shown as claimed. The last
// line is there because any process of yours can ask for this dialog: the
// answer is only safe when the human started the request.
func StandingText(req approve.ApprovalRequest) string {
	caller := truncateMiddle(clean(req.Caller), maxCallerRunes)
	if caller == "" {
		caller = "unknown caller"
	}
	cmd := req.GrantCmdPrefix
	if len(cmd) == 0 {
		cmd = req.Argv
	}
	parts := make([]string, len(cmd))
	for i, a := range cmd {
		parts[i] = strings.ReplaceAll(clean(a), "`", "'")
	}
	prefix := strings.Join(parts, " ")
	if prefix == "" {
		prefix = "(empty command)"
	}
	cwd := clean(req.GrantCwdPrefix)
	if cwd == "" {
		cwd = clean(req.Cwd)
	}
	if cwd == "" {
		cwd = "unknown directory"
	}
	text := "Create a standing grant?\n\n" + caller + " may run `" + prefix + " …` with " +
		renderSecrets(req.Secrets, req.Expanded) + " in " + cwd + " and subfolders for the next " +
		formatSpan(req.RequestedTTL) + usesSuffix(req.RequestedUses) + ", without further prompts."
	if !req.PolicyPresent {
		text += " (No policy file applies.)"
	}
	return text + "\n\nOnly continue if you just asked for this yourself."
}

// lowerTierQuestion is the headline of the lower-protection prompt, also the
// Touch ID reason:
//
//	Lower the protection of API_KEY from hardware to dialog?
//
// The secret name is shown whole (names are validated, but the request is
// untrusted and sanitised like every other string).
func lowerTierQuestion(req approve.ApprovalRequest) string {
	name := "(unknown secret)"
	if len(req.Secrets) > 0 {
		name = clean(req.Secrets[0])
	}
	return "Lower the protection of " + name + " from " + req.FromTier.String() + " to " + req.ToTier.String() + "?"
}

// LowerTierText is the body of the lower-protection dialog:
//
//	Lower the protection of API_KEY from hardware to dialog?
//
//	Afterwards a program that is allowed to ask for this secret needs less proof that you are there. The stored value does not change.
//
//	Only continue if you just asked for this yourself.
//
// The last line is there because any process of yours can send the update
// that produces this dialog.
func LowerTierText(req approve.ApprovalRequest) string {
	return lowerTierQuestion(req) +
		"\n\nAfterwards a program that asks for this secret needs less proof that you are there. The stored value does not change." +
		"\n\nOnly continue if you just asked for this yourself."
}

// usesSuffix discloses a use limit, e.g. " (at most 3 runs)"; empty when
// unlimited.
func usesSuffix(uses int) string {
	switch {
	case uses == 1:
		return " (at most 1 run)"
	case uses > 1:
		return " (at most " + strconv.Itoa(uses) + " runs)"
	}
	return ""
}

// formatSpan renders a duration in words for the standing-grant texts:
// "30 days", "1 day", "8 hours", "1 day 12 hours", "90 minutes". Rounded to
// minutes.
func formatSpan(d time.Duration) string {
	d = d.Round(time.Minute)
	if d < time.Minute {
		return "under a minute"
	}
	unit := func(n int, one string) string {
		if n == 1 {
			return "1 " + one
		}
		return strconv.Itoa(n) + " " + one + "s"
	}
	days := int(d / (24 * time.Hour))
	h := int(d % (24 * time.Hour) / time.Hour)
	m := int(d % time.Hour / time.Minute)
	var out []string
	if days > 0 {
		out = append(out, unit(days, "day"))
	}
	if h > 0 {
		out = append(out, unit(h, "hour"))
	}
	if m > 0 {
		out = append(out, unit(m, "minute"))
	}
	return strings.Join(out, " ")
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
