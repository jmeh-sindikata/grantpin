package main

import "github.com/spf13/cobra"

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the vault and wrap its data key in the KeyStore",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}
}
