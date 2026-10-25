package main

import "github.com/spf13/cobra"

func newMaskedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "masked NAME",
		Short: "Show a masked form of a secret (last 4 characters at most)",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}
}
