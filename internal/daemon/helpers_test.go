package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jmeh-sindikata/grantd/internal/proto"
)

// shortDir returns a short temp dir under /tmp (macOS limits sun_path to 104
// bytes, which t.TempDir often exceeds).
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "g")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

type running struct {
	srv    *Server
	path   string
	cancel context.CancelFunc
	done   chan error // buffered; Serve's result
	once   sync.Once
	err    error
}

// stop cancels the server and waits for Serve to return.
func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	r.once.Do(func() {
		select {
		case r.err = <-r.done:
		case <-time.After(10 * time.Second):
			t.Error("Serve did not return")
		}
	})
	return r.err
}

// start builds, listens and serves a Server with cfg (SocketPath defaults to a
// fresh short path) and registers cleanup.
func start(t *testing.T, cfg Config) *running {
	t.Helper()
	if cfg.SocketPath == "" {
		cfg.SocketPath = filepath.Join(shortDir(t), "s.sock")
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{srv: srv, path: cfg.SocketPath, cancel: cancel, done: make(chan error, 1)}
	go func() { r.done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		_ = r.stop(t)
	})
	return r
}

// exchange sends one raw line and collects frames and the final response.
func exchange(t *testing.T, path string, line []byte) ([]proto.StreamFrame, *proto.Response) {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if line != nil {
		if _, err := c.Write(append(append([]byte{}, line...), '\n')); err != nil {
			t.Fatal(err)
		}
	}
	return readAll(t, c)
}

func readAll(t *testing.T, c net.Conn) ([]proto.StreamFrame, *proto.Response) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	rd := proto.NewReader(c)
	var frames []proto.StreamFrame
	for {
		m, err := rd.ReadMessage()
		if err != nil {
			t.Fatalf("read: %v (frames so far: %v)", err, frames)
		}
		if m.Frame != nil {
			frames = append(frames, *m.Frame)
			continue
		}
		return frames, m.Response
	}
}

func call(t *testing.T, path string, req proto.Request) ([]proto.StreamFrame, *proto.Response) {
	t.Helper()
	if req.V == 0 {
		req.V = proto.Version
	}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return exchange(t, path, b)
}

// syncBuf is a goroutine-safe bytes.Buffer for capturing logs.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func okResp() *proto.Response { return &proto.Response{OK: true} }
