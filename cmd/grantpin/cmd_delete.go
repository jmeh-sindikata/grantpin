package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

func newDeleteCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpDelete, Caller: "cli", Name: args[0]}); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", args[0])
			return nil
		},
	}
	addSocketFlag(c, &socket)
	return c
}
