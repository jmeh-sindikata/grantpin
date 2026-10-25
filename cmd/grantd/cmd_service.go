package main

import "github.com/spf13/cobra"

func newServiceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "service",
		Short: "Manage the background service (launchd / systemd --user / Windows task)",
		Args:  cobra.NoArgs,
	}
	c.AddCommand(
		&cobra.Command{Use: "install", Short: "Install and start the service", Args: cobra.NoArgs, RunE: notImplemented},
		&cobra.Command{Use: "uninstall", Short: "Stop and remove the service", Args: cobra.NoArgs, RunE: notImplemented},
		&cobra.Command{Use: "status", Short: "Show service status", Args: cobra.NoArgs, RunE: notImplemented},
	)
	return c
}
