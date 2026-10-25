package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"grantd/internal/vault"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Create the vault and wrap its data key in the KeyStore",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ks, err := openKeyStore()
			if err != nil {
				return err
			}
			path, err := vault.DefaultPath()
			if err != nil {
				return err
			}
			// New secrets default to the keystore's own tier: Hardware on
			// macOS/Windows, Dialog on Linux (§6), None only for dev builds.
			v, err := vault.Init(cmd.Context(), path, ks, vault.WithDefaultMinTier(ks.Tier()))
			if err != nil {
				return err
			}
			if err := v.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "vault created at %s (keystore tier: %s)\n", path, ks.Tier())
			return nil
		},
	}
}
