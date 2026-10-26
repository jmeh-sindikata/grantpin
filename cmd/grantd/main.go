package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "grantd",
		Short:         "Local secrets broker for AI coding agents",
		Long:          "grantd lets agents run commands that need secrets without ever receiving a plaintext secret, and without any release happening unapproved by a human.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newSetCmd(),
		newListCmd(),
		newMaskedCmd(),
		newDeleteCmd(),
		newUpdateCmd(),
		newShowCmd(),
		newRunCmd(),
		newGrantsCmd(),
		newAuditCmd(),
		newImportCmd(),
		newDaemonCmd(),
		newServiceCmd(),
		newKeystoreCmd(),
		newMCPCmd(),
		newStatusCmd(),
	)
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		if err.Error() != "" { // an empty message relays a child's exit status
			fmt.Fprintln(os.Stderr, "grantd:", err)
		}
		os.Exit(exitCodeOf(err))
	}
}
