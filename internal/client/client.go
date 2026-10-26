package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/proto"
)

// ErrNotRunning means nothing is listening on the daemon socket (it does not
// exist or refuses connections). The CLI prints a hint; the MCP shim may
// choose to start the daemon and retry. Test with errors.Is.
var ErrNotRunning = errors.New("grantd daemon is not running")

// ErrUsed is returned by Do on a Client that already carried a request.
var ErrUsed = errors.New("client: connection already used (one request per connection)")

// ErrNoResponse means the daemon closed the connection without a final
// response (for example it crashed or was shut down mid-request).
var ErrNoResponse = errors.New("client: connection closed before a response was received")

// DialTimeout bounds connecting to the socket.
const DialTimeout = 5 * time.Second

// Error is a not-OK daemon Response as a Go error. See ResponseError.
type Error struct {
	Category string // proto.Err*
	Reason   string // proto.Reason*
}

func (e *Error) Error() string {
	if e.Reason != "" && e.Reason != e.Category {
		return e.Category + ": " + e.Reason
	}
	return e.Category
}

// ResponseError returns nil for an OK response and an *Error otherwise.
func ResponseError(resp *proto.Response) error {
	if resp == nil {
		return ErrNoResponse
	}
	if resp.OK {
		return nil
	}
	return &Error{Category: resp.Error, Reason: resp.Reason}
}

// Client is one connection to the daemon, good for one request.
type Client struct {
	path string
	conn net.Conn

	mu   sync.Mutex
	used bool
}

// Dial connects to the daemon socket at socketPath. A missing socket or a
// refused connection yields an error wrapping ErrNotRunning.
func Dial(socketPath string) (*Client, error) {
	return DialContext(context.Background(), socketPath)
}

// DialContext is Dial with a context.
func DialContext(ctx context.Context, socketPath string) (*Client, error) {
	d := net.Dialer{Timeout: DialTimeout}
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("%w (socket %s)", ErrNotRunning, socketPath)
		}
		return nil, fmt.Errorf("client: dial %s: %w", socketPath, err)
	}
	return &Client{path: socketPath, conn: conn}, nil
}

// Close closes the connection. It is safe to call more than once.
func (c *Client) Close() error { return c.conn.Close() }

// Do sends req and reads until the final response, calling onStream (if not
// nil) for each stream frame in order. A not-OK response is returned as
// (resp, nil); use ResponseError to turn it into an error. If req.V is zero it
// is set to proto.Version.
//
// Cancelling ctx closes the connection (the daemon then cancels the request)
// and Do returns ctx.Err().
func (c *Client) Do(ctx context.Context, req *proto.Request, onStream func(proto.StreamFrame)) (*proto.Response, error) {
	c.mu.Lock()
	if c.used {
		c.mu.Unlock()
		return nil, ErrUsed
	}
	c.used = true
	c.mu.Unlock()

	r := *req
	if r.V == 0 {
		r.V = proto.Version
	}

	stop := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case <-ctx.Done():
			_ = c.conn.Close()
		case <-stop:
		}
	}()
	defer func() { close(stop); <-finished }()

	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	}
	// ctxErr prefers the context's error over the resulting I/O error.
	ctxErr := func(err error) error {
		if ce := ctx.Err(); ce != nil {
			return ce
		}
		// The conn deadline (copied from ctx) can fire a hair before ctx does.
		if _, ok := ctx.Deadline(); ok && errors.Is(err, os.ErrDeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return err
	}

	if err := proto.Write(c.conn, &r); err != nil {
		return nil, ctxErr(fmt.Errorf("client: send request: %w", err))
	}
	rd := proto.NewReader(c.conn)
	for {
		m, err := rd.ReadMessage()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ctxErr(ErrNoResponse)
			}
			return nil, ctxErr(fmt.Errorf("client: read response: %w", err))
		}
		if m.Frame != nil {
			if onStream != nil {
				onStream(*m.Frame)
			}
			continue
		}
		return m.Response, nil
	}
}

// Call dials socketPath, performs one request and closes the connection.
func Call(ctx context.Context, socketPath string, req *proto.Request, onStream func(proto.StreamFrame)) (*proto.Response, error) {
	c, err := DialContext(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Do(ctx, req, onStream)
}

// Status asks the daemon for its status over this connection.
func (c *Client) Status(ctx context.Context) (*proto.StatusResult, error) {
	resp, err := c.Do(ctx, &proto.Request{Op: proto.OpStatus}, nil)
	if err != nil {
		return nil, err
	}
	if err := ResponseError(resp); err != nil {
		return nil, err
	}
	var st proto.StatusResult
	if err := json.Unmarshal(resp.Result, &st); err != nil {
		return nil, fmt.Errorf("client: decode status: %w", err)
	}
	return &st, nil
}

// Status dials socketPath and returns the daemon status.
func Status(ctx context.Context, socketPath string) (*proto.StatusResult, error) {
	c, err := DialContext(ctx, socketPath)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.Status(ctx)
}
