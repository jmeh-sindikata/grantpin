package daemon

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

// Handler serves one validated request. It must send exactly one final
// response via w.Finish; it may call w.Stream any number of times before that.
//
// The ctx carries the per-connection deadline (the request's timeout_s capped
// by Config.MaxTimeout, plus Config.ApprovalGrace for human approval) and is
// cancelled when the client goes away or the daemon's shutdown grace period
// expires. Handlers must honour it. CommandTimeout(ctx) is the budget for the
// command itself.
//
// Handlers must not retain req or w after returning.
type Handler interface {
	Handle(ctx context.Context, req *proto.Request, w ResponseWriter)
}

// HandlerFunc adapts a function to a Handler.
type HandlerFunc func(ctx context.Context, req *proto.Request, w ResponseWriter)

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, req *proto.Request, w ResponseWriter) {
	f(ctx, req, w)
}

// ResponseWriter writes the reply for one connection. Calls are serialised;
// it is safe to call Stream from several goroutines (e.g. stdout and stderr
// pumps).
type ResponseWriter interface {
	// Stream sends one redacted output frame. stream must be proto.StreamStdout
	// or proto.StreamStderr. It fails after Finish or once the connection broke.
	Stream(stream string, data []byte) error
	// Finish sends the final response. It may be called once.
	Finish(resp *proto.Response) error
}

// ErrFinished is returned by ResponseWriter methods after Finish.
var ErrFinished = errors.New("daemon: response already finished")

// Router maps ops to Handlers. The zero value is not usable; use NewRouter.
type Router struct {
	mu       sync.RWMutex
	handlers map[string]Handler
}

// NewRouter returns an empty Router.
func NewRouter() *Router { return &Router{handlers: map[string]Handler{}} }

// Register installs h for op. It panics (programmer error, like
// http.ServeMux) if op is not a proto op, h is nil, or op is already
// registered.
func (r *Router) Register(op string, h Handler) {
	if !slices.Contains(proto.Ops, op) {
		panic(fmt.Sprintf("daemon: Register of unknown op %q", op))
	}
	if h == nil {
		panic("daemon: Register of nil handler for op " + op)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.handlers[op]; dup {
		panic("daemon: duplicate handler for op " + op)
	}
	r.handlers[op] = h
}

// Lookup returns the handler registered for op.
func (r *Router) Lookup(op string) (Handler, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	h, ok := r.handlers[op]
	return h, ok
}

// Ops returns the registered op names, sorted.
func (r *Router) Ops() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.handlers))
	for op := range r.handlers {
		out = append(out, op)
	}
	slices.Sort(out)
	return out
}

// Failure builds a not-OK Response. Handy for handlers.
func Failure(category, reason string) *proto.Response {
	return &proto.Response{OK: false, Error: category, Reason: reason}
}
