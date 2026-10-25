package main

import "github.com/spf13/cobra"

func newAuditCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "audit",
		Short: "Inspect and verify the audit log",
		Args:  cobra.NoArgs,
		RunE:  notImplemented, // bare `audit` behaves like `audit list`
	}
	export := &cobra.Command{Use: "export", Short: "Export the audit log", Args: cobra.NoArgs, RunE: notImplemented}
	export.Flags().Bool("csv", false, "export as CSV")
	c.AddCommand(
		&cobra.Command{Use: "list", Short: "List recent audit entries", Args: cobra.NoArgs, RunE: notImplemented},
		&cobra.Command{Use: "verify", Short: "Verify the HMAC chain", Args: cobra.NoArgs, RunE: notImplemented},
		export,
	)
	return c
}
