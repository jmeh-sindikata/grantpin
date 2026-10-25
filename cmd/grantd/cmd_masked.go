package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"grantd/internal/proto"
)

func newMaskedCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "masked NAME",
		Short: "Show a secret's masked form (last 4 characters only)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpMasked, Caller: "cli", Name: args[0]})
			if err != nil {
				return err
			}
			var r proto.MaskedResult
			if err := decodeResult(resp, &r); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), r.Masked)
			return nil
		},
	}
	addSocketFlag(c, &socket)
	return c
}
