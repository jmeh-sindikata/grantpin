package audit

import (
	"encoding/json"
	"unicode/utf8"
)

// Field caps. Every audit row is written from request data an untrusted client
// controls, and a single row must never be able to outgrow what the list and
// export ops can send back (one protocol line), so Append bounds every field.
// A bounded field ends in TruncatedMarker (a list gets it as a last element),
// so a cut is visible in the log and never silent.
const (
	// TruncatedMarker marks a field or list that was cut.
	TruncatedMarker = "(truncated)"

	MaxArgvJSON    = 64 << 10 // encoded JSON of the argv list
	MaxArgvElem    = 16 << 10 // one argv element, in bytes before encoding
	MaxSecretsJSON = 64 << 10 // encoded JSON of secrets, and of expanded
	MaxSecretElem  = 1 << 10  // one secret name or glob
	MaxCwd         = 4 << 10
	MaxCaller      = 64
	MaxReason      = 4 << 10
	MaxGrantID     = 128
)

// CapString returns s unchanged if it is at most max bytes, else a prefix cut
// at a character boundary and ended with TruncatedMarker, max bytes in all.
func CapString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	keep := max - len(TruncatedMarker)
	if keep < 0 {
		return cutUTF8(TruncatedMarker, max)
	}
	return cutUTF8(s, keep) + TruncatedMarker
}

// CapList returns l unchanged if every element is at most maxElem bytes and the
// JSON encoding of the list is at most maxJSON bytes. Otherwise it returns a
// copy that keeps the leading elements that fit (each cut to maxElem at a
// character boundary) followed by one TruncatedMarker element, whose encoding
// is within maxJSON as well. l itself is never modified.
func CapList(l []string, maxElem, maxJSON int) []string {
	if listFits(l, maxElem, maxJSON) {
		return l
	}
	// cur is the encoded size of what is kept so far plus the marker element.
	cur := 2 + jsonLen(TruncatedMarker)
	out := make([]string, 0, min(len(l), 64)+1)
	for _, s := range l {
		if len(s) > maxElem {
			s = cutUTF8(s, maxElem)
		}
		n := jsonLen(s) + 1 // the element and a comma
		if cur+n > maxJSON {
			break
		}
		out = append(out, s)
		cur += n
	}
	return append(out, TruncatedMarker)
}

// Capped returns a copy of e whose fields are within the caps above. Slices
// that need no cut are shared with e, not copied. Append applies it to every
// row; the broker applies it early to the entry of a request it is about to
// refuse, so that an oversized request is never held in an entry.
func Capped(e Entry) Entry {
	e.Caller = CapString(e.Caller, MaxCaller)
	e.Cwd = CapString(e.Cwd, MaxCwd)
	e.Argv = CapList(e.Argv, MaxArgvElem, MaxArgvJSON)
	e.Secrets = CapList(e.Secrets, MaxSecretElem, MaxSecretsJSON)
	e.Expanded = CapList(e.Expanded, MaxSecretElem, MaxSecretsJSON)
	e.Reason = CapString(e.Reason, MaxReason)
	e.GrantID = CapString(e.GrantID, MaxGrantID)
	return e
}

func listFits(l []string, maxElem, maxJSON int) bool {
	n := 2 // brackets
	for i, s := range l {
		if len(s) > maxElem {
			return false
		}
		n += jsonLen(s)
		if i > 0 {
			n++ // comma
		}
		if n > maxJSON {
			return false
		}
	}
	return true
}

// jsonLen is the length of s as a JSON string, quotes included.
func jsonLen(s string) int {
	b, _ := json.Marshal(s)
	return len(b)
}

// cutUTF8 returns the longest prefix of s of at most n bytes that does not end
// inside a multi-byte character.
func cutUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
