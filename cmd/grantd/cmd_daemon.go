package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"grantd/internal/daemon"
)

func newDaemonCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the grantd daemon in the foreground",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveSocket(socket)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runDaemon(ctx, path, slog.New(slog.NewTextHandler(cmd.ErrOrStderr(), nil)))
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "socket path (default: $GRANTD_SOCKET or the platform default)")
	return cmd
}

// runDaemon serves until ctx is cancelled.
func runDaemon(ctx context.Context, socket string, logger *slog.Logger) error {
	srv, err := daemon.New(daemon.Config{
		SocketPath: socket,
		Router:     buildRouter(),
		Logger:     logger,
		StatusFunc: buildStatusFunc(),
		Version:    version,
	})
	if err != nil {
		return err
	}
	if err := srv.Listen(); err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	return srv.Serve(ctx)
}

// resolveSocket returns the --socket flag value or the default path.
func resolveSocket(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return daemon.DefaultSocketPath()
}
