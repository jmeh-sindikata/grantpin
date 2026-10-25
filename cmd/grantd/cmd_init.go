package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"grantd/internal/vault"
)

func newInitCmd() *cobra.Command {
	var bcfg backendConfig
	c := &cobra.Command{
		Use:   "init",
		Short: "Create the vault and wrap its data key in the KeyStore",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ks, err := openKeyStore(bcfg)
			if err != nil {
				return err
			}
			path, err := vault.DefaultPath()
			if err != nil {
				return err
			}
			if bcfg.KeychainFallback {
				// With the fallback enabled an unresolved macOS keystore reports
				// the weakest tier it might end up with. Let it pick its mode
				// now (vault.Init would do the same next) so the default
				// min_tier below reflects what it really provides.
				if _, err := ks.Wrap(cmd.Context(), make([]byte, 32)); err != nil {
					return err
				}
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
	addInitFlags(c, &bcfg)
	return c
}
