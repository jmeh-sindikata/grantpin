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

	"github.com/jmeh-sindikata/grantpin/internal/daemon"
)

func newDaemonCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "Run the grantpin daemon in the foreground",
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
	cmd.Flags().StringVar(&socket, "socket", "", "socket path (default: $GRANTPIN_SOCKET or the platform default)")
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
// ctx is cancelled.
//
// It listens first and opens the vault afterwards, in the background: the
// keystore call can block (Keychain, Secure Enclave), and until the socket
// exists a client sees "not running" and a second daemon could start. While
// the first open runs, requests wait a few seconds for it and are then
// answered vault_locked; status answers at once. A permanently unusable vault
// (wrong keystore mode, tampered file, downgraded tier) still stops the daemon
// at start, instead of at the first request. A keystore that is only
// transiently unavailable (screen locked, session not unlocked yet after
// login) does not: the daemon stays up, answers vault_locked and keeps
// retrying, because exiting would only make launchd respawn it into the same
// failure.
func serveDaemon(ctx context.Context, socket string, logger *slog.Logger, be backends) error {
	h, err := newBrokerHolder(be, socket, logger)
	if err != nil {
		return err
	}
	defer h.close()
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

	sctx, stopServing := context.WithCancel(ctx)
	defer stopServing()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(sctx) }()

	opened := make(chan error, 1)
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		_, err := h.get(ctx)
		opened <- err
	}()
	for {
		select {
		case err := <-opened:
			opened = nil
			var locked *errVaultLocked
			if errors.As(err, &locked) {
				h.startRetry()
			} else if err != nil && !errors.Is(err, errVaultMissing) && ctx.Err() == nil {
				stopServing()
				<-served
				return fmt.Errorf("start daemon: open vault %s: %w", h.path, err)
			}
		case err := <-served:
			return err
		}
	}
}

// resolveSocket returns the --socket flag value or the default path.
func resolveSocket(flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	return daemon.DefaultSocketPath()
}
