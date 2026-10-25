package main

import "github.com/spf13/cobra"

func newShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show NAME",
		Short: "Print a secret to the terminal (presence-gated, TTY only)",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}
}
