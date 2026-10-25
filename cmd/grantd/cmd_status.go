package main

import "github.com/spf13/cobra"

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show daemon, vault and backend status",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}
}
