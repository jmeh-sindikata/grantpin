package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"grantd/internal/client"
)

func newStatusCmd() *cobra.Command {
	var socket string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show daemon, vault and backend status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			path, err := resolveSocket(socket)
			if err != nil {
				return err
			}
			st, err := client.Status(cmd.Context(), path)
			if errors.Is(err, client.ErrNotRunning) {
				return fmt.Errorf("%w (socket %s); start it with `grantd daemon`", client.ErrNotRunning, path)
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "daemon:       running (pid %d)\n", st.PID)
			fmt.Fprintf(out, "version:      %s (protocol v%d)\n", st.Version, st.ProtoV)
			fmt.Fprintf(out, "socket:       %s\n", path)
			fmt.Fprintf(out, "uptime:       %s\n", time.Since(st.StartedAt).Round(time.Second))
			switch {
			case st.VaultLocked:
				fmt.Fprintf(out, "vault:        locked (retrying, last error: %s)\n", st.VaultLockedError)
			case st.VaultInitialized:
				fmt.Fprintf(out, "vault:        initialized\n")
			default:
				fmt.Fprintf(out, "vault:        not initialized\n")
			}
			fmt.Fprintf(out, "keystore:     %s\n", st.KeyStoreTier)
			fmt.Fprintf(out, "approver:     %s\n", st.ApproverTier)
			fmt.Fprintf(out, "secrets:      %d\n", st.Secrets)
			fmt.Fprintf(out, "grants:       %d active\n", st.ActiveGrants)
			if st.TamperedGrants > 0 {
				fmt.Fprintf(out, "WARNING:      %d grant row(s) failed authentication and are ignored (vault file modified outside grantd); see `grantd grants`\n", st.TamperedGrants)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "socket path (default: $GRANTD_SOCKET or the platform default)")
	return cmd
}
