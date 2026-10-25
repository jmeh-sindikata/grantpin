package main

import (
	"context"
	"errors"
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

// runDaemon opens the build's backends and serves until ctx is cancelled.
func runDaemon(ctx context.Context, socket string, logger *slog.Logger) error {
	be, err := openBackends()
	if err != nil {
		return fmt.Errorf("start daemon: %w", err)
	}
	return serveDaemon(ctx, socket, logger, be)
}

// serveDaemon wires vault, broker and socket server together and serves until
// ctx is cancelled. If the vault already exists it is opened up front, so a
// permanently unusable vault (wrong keystore mode, tampered file, downgraded
// tier) stops the daemon at start instead of at the first request. A keystore
// that is only transiently unavailable (screen locked, session not unlocked
// yet after login) does not: the daemon listens anyway, answers vault_locked and
// keeps retrying, because exiting would only make launchd respawn it into the
// same failure while the socket never appears.
func serveDaemon(ctx context.Context, socket string, logger *slog.Logger, be backends) error {
	h, err := newBrokerHolder(be, socket, logger)
	if err != nil {
		return err
	}
	defer h.close()
	var locked *errVaultLocked
	if _, err := h.get(ctx); errors.As(err, &locked) {
		h.startRetry()
	} else if err != nil && !errors.Is(err, errVaultMissing) {
		return fmt.Errorf("start daemon: open vault %s: %w", h.path, err)
	}
	srv, err := daemon.New(daemon.Config{
		SocketPath: socket,
		Router:     h.buildRouter(),
		Logger:     logger,
		StatusFunc: h.statusFunc(),
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
