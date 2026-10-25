package main

import "github.com/spf13/cobra"

func newGrantsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "grants",
		Short: "List or revoke grants",
		Args:  cobra.NoArgs,
		RunE:  notImplemented, // bare `grants` behaves like `grants list`
	}
	c.AddCommand(
		&cobra.Command{Use: "list", Short: "List active grants", Args: cobra.NoArgs, RunE: notImplemented},
		revokeCmd(),
	)
	return c
}

func revokeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "revoke [ID]",
		Short: "Revoke one grant by ID, or all with --all",
		Args:  cobra.MaximumNArgs(1),
		RunE:  notImplemented,
	}
	c.Flags().Bool("all", false, "revoke every grant")
	return c
}
