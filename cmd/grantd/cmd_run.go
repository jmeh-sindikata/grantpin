package main

import "github.com/spf13/cobra"

func newRunCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "run --secrets A,b/* [flags] -- cmd args...",
		Short: "Run a command with secrets injected as env vars (output redacted)",
		Args:  cobra.MinimumNArgs(1),
		RunE:  notImplemented,
	}
	c.Flags().StringSlice("secrets", nil, "secret names or globs to inject (comma-separated)")
	c.Flags().String("caller", "", "caller label recorded in grants and audit (informational)")
	c.Flags().String("env-prefix", "", "prefix for injected env var names")
	c.Flags().Duration("timeout", 0, "kill the command after this duration, e.g. 10m")
	return c
}
