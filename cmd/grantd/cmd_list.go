package main

import "github.com/spf13/cobra"

func newListCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "list",
		Short: "List secret names and metadata (never values)",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}
	c.Flags().String("tag", "", "only secrets with this tag")
	c.Flags().String("expiring", "", "only secrets expiring within this duration, e.g. 7d")
	return c
}
