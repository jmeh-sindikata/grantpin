package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"grantd/internal/proto"
)

func newAuditCmd() *cobra.Command {
	var socket string
	var limit int
	// A run that was released appears as two rows, newest first: "completed"
	// (exit code, duration, reason such as timeout or canceled) above the
	// allowed_* row with reason "released" that was written before the
	// command was spawned (secrets already decrypted). A released row with no completed row above it
	// means the daemon died mid-run.
	list := func(cmd *cobra.Command, _ []string) error {
		resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpAudit, Caller: "cli", Action: proto.ActionList, Limit: limit})
		if err != nil {
			return err
		}
		var es []proto.AuditInfo
		if err := decodeResult(resp, &es); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTIME\tDECISION\tCALLER\tCOMMAND\tSECRETS\tGRANT\tEXIT\tTOOK\tREASON")
		for _, e := range es {
			exit, took := "-", "-"
			if e.ExitCode != nil {
				exit = strconv.Itoa(*e.ExitCode)
			}
			if e.DurationMS > 0 {
				took = (time.Duration(e.DurationMS) * time.Millisecond).String()
			}
			grant := "-"
			if e.GrantID != "" {
				grant = e.GrantID[:min(8, len(e.GrantID))]
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.ID, e.TS.Local().Format("2006-01-02 15:04:05"),
				e.Decision, e.Caller, strings.Join(e.Argv, " "), secretsCell(e), grant, exit, took, dash(e.Reason))
		}
		return tw.Flush()
	}
	c := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the audit log",
		Args:  cobra.NoArgs,
		RunE:  list, // bare `audit` behaves like `audit list`
	}
	listCmd := &cobra.Command{Use: "list", Short: "List recent audit entries (newest first; a run is a completed row above its released row)", Args: cobra.NoArgs, RunE: list}
	for _, x := range []*cobra.Command{c, listCmd} {
		x.Flags().IntVar(&limit, "limit", 0, "maximum entries to show (default 100)")
	}
	verify := &cobra.Command{
		Use: "verify", Short: "Verify the HMAC chain", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpAudit, Caller: "cli", Action: proto.ActionVerify})
			if err != nil {
				return err
			}
			var r proto.AuditVerifyResult
			if err := decodeResult(resp, &r); err != nil {
				return err
			}
			if !r.OK {
				return &exitError{code: exitGeneric, msg: fmt.Sprintf("audit chain BROKEN at entry %s (%d entries examined)", r.FirstBadID, r.Entries)}
			}
			fmt.Fprintf(cmd.OutOrStdout(), "audit chain ok (%d entries)\n", r.Entries)
			return nil
		},
	}
	export := &cobra.Command{
		Use: "export", Short: "Export the audit log (CSV)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpAudit, Caller: "cli", Action: proto.ActionExport})
			if err != nil {
				return err
			}
			var r proto.AuditExportResult
			if err := decodeResult(resp, &r); err != nil {
				return err
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), r.CSV)
			return err
		},
	}
	export.Flags().Bool("csv", true, "export as CSV (the only format)")
	for _, x := range []*cobra.Command{c, listCmd, verify, export} {
		addSocketFlag(x, &socket)
	}
	c.AddCommand(listCmd, verify, export)
	return c
}

// secretsCell is what the SECRETS column shows: the secrets as requested, and
// "→ a, b" with the concrete names they expanded to when that differs (a glob
// such as aws/* released something specific).
func secretsCell(e proto.AuditInfo) string {
	req := strings.Join(e.Secrets, ",")
	if len(e.Expanded) == 0 || slices.Equal(e.Expanded, e.Secrets) {
		return req
	}
	return req + " → " + strings.Join(e.Expanded, ", ")
}
