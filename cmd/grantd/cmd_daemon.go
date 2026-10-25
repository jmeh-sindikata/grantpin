package main

import "github.com/spf13/cobra"

func newDaemonCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "daemon",
		Short: "Run the grantd daemon in the foreground",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}
}
