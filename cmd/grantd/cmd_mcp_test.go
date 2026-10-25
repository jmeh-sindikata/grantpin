package main

import (
	"context"
	"io"
	"log/slog"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// runMCP must expose the four tools without needing the daemon (listing tools
// never touches the socket, so nothing is auto-started here).
func TestRunMCPListsFourTools(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	t1, t2 := sdk.NewInMemoryTransports()
	done := make(chan error, 1)
	go func() {
		done <- runMCP(ctx, "/nonexistent/grantd.sock", slog.New(slog.NewTextHandler(io.Discard, nil)), t1)
	}()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "test", Version: "1"}, nil).Connect(ctx, t2, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 4 {
		t.Errorf("got %d tools, want 4", len(res.Tools))
	}
	_ = cs.Close()
	<-done
}
