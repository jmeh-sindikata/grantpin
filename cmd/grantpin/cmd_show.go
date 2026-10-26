package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantd/internal/proto"
)

func newShowCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "show NAME",
		Short: "Print a secret to the terminal (presence-gated, TTY only)",
		Long: "Print a secret's value. Requires human presence approval every time and " +
			"refuses unless stdout is a terminal, so the value cannot be piped into an " +
			"agent's context or a file.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if !isTerminal(out) {
				return &exitError{code: exitRefused, msg: "refused (" + proto.ReasonNotTTY + "): show only prints to an interactive terminal"}
			}
			cwd, _ := os.Getwd()
			resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpShow, Caller: "cli", Cwd: cwd, Name: args[0]})
			if err != nil {
				return err
			}
			var r proto.ShowResult
			if err := decodeResult(resp, &r); err != nil {
				return err
			}
			_, err = fmt.Fprintln(out, r.Value)
			return err
		},
	}
	addSocketFlag(c, &socket)
	return c
}
