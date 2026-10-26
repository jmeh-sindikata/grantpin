package vault

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"unicode"
)

// KV is one parsed .env entry. Its formatting methods never print the value.
type KV struct {
	Key   string
	Value []byte
}

// String implements fmt.Stringer without the value.
func (kv KV) String() string { return kv.Key + "=<redacted>" }

// GoString implements fmt.GoStringer without the value.
func (kv KV) GoString() string {
	return "vault.KV{Key:" + fmt.Sprintf("%q", kv.Key) + ", Value:<redacted>}"
}

func isEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i := 0; i < len(k); i++ {
		c := k[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// ParseDotenv parses .env syntax:
//
//	KEY=value            unquoted: trimmed; " #" starts a comment
//	export KEY=value     optional export prefix
//	KEY="a b\n"          double quotes: escapes \n \r \t \\ \" \$; may span lines
//	KEY='literal'        single quotes: no escapes; may span lines
//	# comment / blank    ignored
//
// There is no ${VAR} expansion. Keys must match [A-Za-z_][A-Za-z0-9_]*. Entries
// are returned in file order (duplicates included; Import lets the last win).
// Error messages carry line numbers only, never file content.
func ParseDotenv(r io.Reader) ([]KV, error) {
	data, err := io.ReadAll(bufio.NewReader(r))
	if err != nil {
		return nil, fmt.Errorf("vault: read dotenv: %w", err)
	}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	s := string(data)

	var out []KV
	line := 1
	for len(s) > 0 {
		var l string
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			l, s = s[:i], s[i+1:]
		} else {
			l, s = s, ""
		}
		startLine := line
		line++
		if t := strings.TrimSpace(l); t == "" || t[0] == '#' {
			continue
		}
		// Trim only before the key (and the opening quote): the rest of the
		// line is the start of a quoted value, whose trailing whitespace is
		// part of it when the value continues on the next line.
		t := strings.TrimLeftFunc(l, unicode.IsSpace)
		if rest, ok := strings.CutPrefix(t, "export"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			t = strings.TrimLeftFunc(rest, unicode.IsSpace)
		}
		eq := strings.IndexByte(t, '=')
		if eq < 0 {
			return nil, fmt.Errorf("vault: dotenv line %d: expected KEY=value", startLine)
		}
		key := strings.TrimSpace(t[:eq])
		if !isEnvKey(key) {
			return nil, fmt.Errorf("vault: dotenv line %d: invalid key", startLine)
		}
		val := strings.TrimLeft(t[eq+1:], " \t")

		switch {
		case strings.HasPrefix(val, `"`), strings.HasPrefix(val, `'`):
			q := val[0]
			// The value may continue on following lines: reassemble from the
			// text after the opening quote.
			body := val[1:]
			rest := s
			var value []byte
			for {
				tail, closed := scanQuoted(body, q, &value)
				if closed {
					tail = strings.TrimSpace(tail)
					if tail != "" && tail[0] != '#' {
						return nil, fmt.Errorf("vault: dotenv line %d: unexpected text after closing quote", startLine)
					}
					break
				}
				if rest == "" {
					return nil, fmt.Errorf("vault: dotenv line %d: unterminated quote", startLine)
				}
				value = append(value, '\n')
				if i := strings.IndexByte(rest, '\n'); i >= 0 {
					body, rest = rest[:i], rest[i+1:]
				} else {
					body, rest = rest, ""
				}
				line++
			}
			s = rest
			out = append(out, KV{Key: key, Value: value})
		default:
			if i := commentStart(val); i >= 0 {
				val = val[:i]
			}
			out = append(out, KV{Key: key, Value: []byte(strings.TrimSpace(val))})
		}
	}
	return out, nil
}

// commentStart returns the index of a " #" / "\t#" inline comment, or -1.
func commentStart(v string) int {
	for i := 1; i < len(v); i++ {
		if v[i] == '#' && (v[i-1] == ' ' || v[i-1] == '\t') {
			return i - 1
		}
	}
	return -1
}

// scanQuoted consumes body up to the closing quote q, appending the decoded
// text to *value. It returns whether the quote closed and the text after it.
func scanQuoted(body string, q byte, value *[]byte) (string, bool) {
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == q {
			return body[i+1:], true
		}
		if q == '"' && c == '\\' && i+1 < len(body) {
			i++
			switch body[i] {
			case 'n':
				*value = append(*value, '\n')
			case 'r':
				*value = append(*value, '\r')
			case 't':
				*value = append(*value, '\t')
			case '\\', '"', '$':
				*value = append(*value, body[i])
			default:
				*value = append(*value, '\\', body[i])
			}
			continue
		}
		*value = append(*value, c)
	}
	return "", false
}
