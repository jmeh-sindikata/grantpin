package proto

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxLineBytes bounds a single protocol line (request, frame or response).
const MaxLineBytes = 4 << 20

// ErrLineTooLong is wrapped by Encode and Write when a message does not fit in
// MaxLineBytes.
var ErrLineTooLong = errors.New("proto: line exceeds limit")

// Encode returns v as one JSON line (compact, '\n'-terminated). It fails, before
// anything is written, if v cannot be encoded or the line would exceed
// MaxLineBytes (the error then wraps ErrLineTooLong).
func Encode(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("proto: encode: %w", err)
	}
	b = append(b, '\n')
	if len(b) > MaxLineBytes {
		return nil, fmt.Errorf("%w: %d bytes, limit %d", ErrLineTooLong, len(b), MaxLineBytes)
	}
	return b, nil
}

// Write encodes v as one JSON line (see Encode) to w. v is normally a Request,
// StreamFrame or Response.
func Write(w io.Writer, v any) error {
	b, err := Encode(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// Message is one decoded server->client line: exactly one of Frame or Response
// is non-nil.
type Message struct {
	Frame    *StreamFrame
	Response *Response
}

// Reader reads newline-delimited protocol lines.
type Reader struct{ sc *bufio.Scanner }

// NewReader returns a Reader over r.
func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	return &Reader{sc: sc}
}

func (r *Reader) line() ([]byte, error) {
	for r.sc.Scan() {
		if b := r.sc.Bytes(); len(b) > 0 {
			return b, nil
		}
	}
	if err := r.sc.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// ReadRequest reads and structurally validates one Request line.
func (r *Reader) ReadRequest() (*Request, error) {
	b, err := r.line()
	if err != nil {
		return nil, err
	}
	var req Request
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("proto: decode request: %w", err)
	}
	return &req, nil
}

// ReadMessage reads one server->client line. A line with a "stream" key is a
// StreamFrame; anything else is the final Response.
func (r *Reader) ReadMessage() (Message, error) {
	b, err := r.line()
	if err != nil {
		return Message{}, err
	}
	var probe struct {
		Stream *string `json:"stream"`
		OK     *bool   `json:"ok"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Message{}, fmt.Errorf("proto: decode message: %w", err)
	}
	switch {
	case probe.Stream != nil:
		var f StreamFrame
		if err := json.Unmarshal(b, &f); err != nil {
			return Message{}, fmt.Errorf("proto: decode frame: %w", err)
		}
		return Message{Frame: &f}, nil
	case probe.OK != nil:
		var resp Response
		if err := json.Unmarshal(b, &resp); err != nil {
			return Message{}, fmt.Errorf("proto: decode response: %w", err)
		}
		return Message{Response: &resp}, nil
	default:
		return Message{}, errors.New("proto: message is neither a stream frame nor a response")
	}
}
