package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// errNotImplemented is returned by every verb until its milestone step lands.
var errNotImplemented = errors.New("not implemented")

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
		newShowCmd(),
		newRunCmd(),
		newGrantsCmd(),
		newAuditCmd(),
		newImportCmd(),
		newDaemonCmd(),
		newServiceCmd(),
		newMCPCmd(),
		newStatusCmd(),
	)
	return root
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "grantd:", err)
		os.Exit(1)
	}
}

// notImplemented is a RunE for verbs that are not built yet.
func notImplemented(*cobra.Command, []string) error { return errNotImplemented }
