package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantpin/internal/mcp"
)

func newMCPCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the stdio MCP server (thin shim over the daemon socket)",
		Long: "Run a Model Context Protocol server on stdin/stdout exposing secret_list, secret_exists,\n" +
			"secret_masked and secret_run. No tool returns a secret value. Logs go to stderr only.\n" +
			"If the daemon is not running the shim tries to start it once.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveSocket(socket)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			// stdout is the protocol channel: log to stderr only, op names only.
			logger := slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil))
			return runMCP(ctx, path, logger, &sdk.StdioTransport{})
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "socket path (default: $GRANTPIN_SOCKET or the platform default)")
	return cmd
}

// runMCP serves MCP over t until the client disconnects or ctx is cancelled.
func runMCP(ctx context.Context, socket string, logger *slog.Logger, t sdk.Transport) error {
	return mcp.Serve(ctx, mcp.Config{
		SocketPath: socket,
		Starter:    mcp.ExecStarter(socket),
		Logger:     logger,
		Version:    version,
	}, t)
}
