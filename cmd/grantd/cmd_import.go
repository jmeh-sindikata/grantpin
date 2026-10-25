package main

import "github.com/spf13/cobra"

func newImportCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "import FILE",
		Short: "Import secrets from a .env file",
		Args:  cobra.ExactArgs(1),
		RunE:  notImplemented,
	}
	c.Flags().Bool("dry-run", false, "show what would be imported without writing")
	c.Flags().String("on-conflict", "error", "when a name already exists: skip, overwrite or error")
	return c
}
