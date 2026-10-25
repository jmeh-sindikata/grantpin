package main

import "github.com/spf13/cobra"

func newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}
}
