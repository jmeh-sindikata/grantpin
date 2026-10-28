package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantpin/internal/client"
	"github.com/jmeh-sindikata/grantpin/internal/proto"
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
			st, inFlightKnown, err := fetchStatus(cmd.Context(), path)
			if errors.Is(err, client.ErrNotRunning) {
				return fmt.Errorf("%w (socket %s); start it with `grantpin daemon`", client.ErrNotRunning, path)
			}
			if err != nil {
				return err
			}
			printStatus(cmd.OutOrStdout(), st, inFlightKnown, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "socket path (default: $GRANTPIN_SOCKET or the platform default)")
	return cmd
}

// fetchStatus asks the daemon for its status and also reports whether the
// answer carried in_flight_runs at all: a daemon from before the field omits
// it, and that is "unknown", not zero (docs/PROTOCOL.md `status`).
func fetchStatus(ctx context.Context, path string) (st *proto.StatusResult, inFlightKnown bool, err error) {
	c, err := client.DialContext(ctx, path)
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	resp, err := c.Do(ctx, &proto.Request{Op: proto.OpStatus}, nil)
	if err != nil {
		return nil, false, err
	}
	if err := client.ResponseError(resp); err != nil {
		return nil, false, err
	}
	return decodeStatus(resp.Result)
}

// decodeStatus decodes a status result and whether in_flight_runs was present.
func decodeStatus(raw json.RawMessage) (st *proto.StatusResult, inFlightKnown bool, err error) {
	var s proto.StatusResult
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, false, fmt.Errorf("decode status: %w", err)
	}
	var presence struct {
		InFlightRuns *int `json:"in_flight_runs"`
	}
	if err := json.Unmarshal(raw, &presence); err != nil {
		return nil, false, fmt.Errorf("decode status: %w", err)
	}
	return &s, presence.InFlightRuns != nil, nil
}

// printStatus writes the status lines. inFlightKnown is false for a daemon
// that does not report its requests in flight (before 0.2.5).
func printStatus(out io.Writer, st *proto.StatusResult, inFlightKnown bool, path string) {
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
	// Requests that hold or may ask for an approval: run, show, standing grant
	// creation, update (docs/PROTOCOL.md `status`).
	if inFlightKnown {
		fmt.Fprintf(out, "runs:         %d in flight\n", st.InFlightRuns)
	} else {
		fmt.Fprintf(out, "runs:         unknown (daemon predates 0.2.5)\n")
	}
	if st.TamperedGrants > 0 {
		fmt.Fprintf(out, "WARNING:      %d grant row(s) failed authentication and are ignored (vault file modified outside grantpin); see `grantpin grants`\n", st.TamperedGrants)
	}
}
