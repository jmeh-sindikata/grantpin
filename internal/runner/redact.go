package runner

import (
	"bytes"
	"io"
	"sort"
)

// MinSafeValueLen is the length below which a secret value is considered too
// short to redact without a meaningful risk of false positives. Values shorter
// than this (but non-empty) are still redacted; values of length 0 are skipped.
const MinSafeValueLen = 4

// Redactor replaces exact occurrences of secret values with [REDACTED:NAME].
//
// Matching is leftmost, longest-first: when one value is a prefix of another,
// the longer one wins at a given position. Matches never overlap and the
// replacement text is not rescanned. If two names share the same value, the
// lexicographically smallest name is used. A Redactor is immutable and safe
// for concurrent use.
type Redactor struct {
	pairs []redactPair // sorted by len(value) desc, then name asc; no empty/dup values
	first [256]bool    // first bytes of any value
	maxL  int
}

type redactPair struct {
	value       []byte
	placeholder []byte
}

// NewRedactor builds a Redactor from name -> value. Empty values are ignored.
func NewRedactor(secrets map[string]string) *Redactor {
	r := &Redactor{}
	seen := make(map[string]bool, len(secrets))
	type nv struct{ name, value string }
	all := make([]nv, 0, len(secrets))
	for name, value := range secrets {
		if value == "" {
			continue
		}
		all = append(all, nv{name, value})
	}
	sort.Slice(all, func(i, j int) bool {
		if len(all[i].value) != len(all[j].value) {
			return len(all[i].value) > len(all[j].value)
		}
		if all[i].value != all[j].value {
			return all[i].value < all[j].value
		}
		return all[i].name < all[j].name
	})
	for _, e := range all {
		if seen[e.value] {
			continue
		}
		seen[e.value] = true
		r.pairs = append(r.pairs, redactPair{
			value:       []byte(e.value),
			placeholder: []byte("[REDACTED:" + e.name + "]"),
		})
		r.first[e.value[0]] = true
		if len(e.value) > r.maxL {
			r.maxL = len(e.value)
		}
	}
	return r
}

// RedactString returns s with every secret value replaced. Use it to scrub the
// daemon's own error messages before they leave the process.
func (r *Redactor) RedactString(s string) string {
	if r == nil || len(r.pairs) == 0 || s == "" {
		return s
	}
	out, _ := r.scan(nil, []byte(s), true)
	return string(out)
}

// Writer returns a WriteCloser that redacts everything written through it
// before passing it to w. Close flushes any held-back bytes; it does not close
// w. See [NewRedactingWriter].
func (r *Redactor) Writer(w io.Writer) io.WriteCloser {
	return &redactingWriter{w: w, r: r}
}

// scan appends the redacted form of buf to dst. When final is false, a trailing
// part of buf that could still grow into (a longer) match is withheld and its
// start offset is returned as hold; the caller must prepend buf[hold:] to the
// next input. When final is true, hold == len(buf).
func (r *Redactor) scan(dst, buf []byte, final bool) (out []byte, hold int) {
	i, start := 0, 0
	for i < len(buf) {
		if !r.first[buf[i]] {
			i++
			continue
		}
		rest := buf[i:]
		matched := -1  // index into r.pairs of the longest complete match
		partial := false // some value could still match, longer than what we have
		for k := range r.pairs {
			v := r.pairs[k].value
			if len(v) <= len(rest) {
				if matched < 0 && bytes.HasPrefix(rest, v) {
					matched = k
				}
			} else if !final && bytes.HasPrefix(v, rest) {
				partial = true
			}
			// pairs are sorted longest-first, so once we have a match no
			// shorter value can beat it; only longer partials matter, and
			// those all precede it.
			if matched >= 0 {
				break
			}
		}
		if partial {
			// A longer value may still complete: wait for more input.
			dst = append(dst, buf[start:i]...)
			return dst, i
		}
		if matched >= 0 {
			dst = append(dst, buf[start:i]...)
			dst = append(dst, r.pairs[matched].placeholder...)
			i += len(r.pairs[matched].value)
			start = i
			continue
		}
		i++
	}
	dst = append(dst, buf[start:]...)
	return dst, len(buf)
}

type redactingWriter struct {
	w       io.Writer
	r       *Redactor
	pending []byte
	err     error
	closed  bool
	out     []byte
}

// NewRedactingWriter wraps w, replacing exact matches of any value in secrets
// (name -> value) with [REDACTED:NAME], correctly across Write boundaries.
//
// Only the shortest necessary suffix is withheld between writes: bytes that
// are a proper prefix of some secret value (so a value split across chunks is
// still caught) while everything else is forwarded immediately. Output that
// cannot start a secret therefore streams with no added latency. Close must be
// called to flush withheld bytes; it does not close w.
//
// Write returns len(p) on success even though fewer or more bytes reach w. The
// writer is not safe for concurrent use.
func NewRedactingWriter(w io.Writer, secrets map[string]string) io.WriteCloser {
	return NewRedactor(secrets).Writer(w)
}

func (rw *redactingWriter) Write(p []byte) (int, error) {
	if rw.err != nil {
		return 0, rw.err
	}
	if rw.closed {
		return 0, io.ErrClosedPipe
	}
	if len(rw.r.pairs) == 0 {
		if _, err := rw.w.Write(p); err != nil {
			rw.err = err
			return 0, err
		}
		return len(p), nil
	}
	var buf []byte
	if len(rw.pending) == 0 {
		buf = p
	} else {
		buf = append(rw.pending, p...)
	}
	out, hold := rw.r.scan(rw.out[:0], buf, false)
	rw.out = out
	rest := buf[hold:]
	// pending must not alias p (the caller may reuse it) nor out.
	rw.pending = append(make([]byte, 0, len(rest)), rest...)
	if len(rw.out) > 0 {
		if _, err := rw.w.Write(rw.out); err != nil {
			rw.err = err
			return 0, err
		}
	}
	return len(p), nil
}

// Close flushes withheld bytes (which, being an incomplete value prefix, are
// emitted verbatim) and marks the writer closed. It does not close the
// underlying writer.
func (rw *redactingWriter) Close() error {
	if rw.closed {
		return rw.err
	}
	rw.closed = true
	if rw.err != nil {
		return rw.err
	}
	if len(rw.pending) > 0 {
		out, _ := rw.r.scan(rw.out[:0], rw.pending, true)
		rw.pending = nil
		if _, err := rw.w.Write(out); err != nil {
			rw.err = err
			return err
		}
	}
	return nil
}
