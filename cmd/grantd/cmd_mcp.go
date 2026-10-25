package main

import "github.com/spf13/cobra"

func newMCPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the stdio MCP server (thin shim over the daemon socket)",
		Args:  cobra.NoArgs,
		RunE:  notImplemented,
	}
}
