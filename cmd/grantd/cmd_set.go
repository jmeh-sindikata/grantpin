package main

import "github.com/spf13/cobra"

func newSetCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret (value from stdin or hidden prompt)",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}
	c.Flags().StringSlice("tags", nil, "comma-separated tags")
	c.Flags().String("url", "", "URL associated with the secret")
	c.Flags().String("expires", "", "expiry, e.g. 30d")
	c.Flags().String("min-tier", "", "minimum presence tier: none, dialog, hardware")
	return c
}
