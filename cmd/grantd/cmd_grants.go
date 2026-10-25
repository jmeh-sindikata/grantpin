package main

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"grantd/internal/proto"
)

func newGrantsCmd() *cobra.Command {
	var socket string
	list := func(cmd *cobra.Command, _ []string) error {
		resp, err := simpleCall(cmd.Context(), socket, &proto.Request{Op: proto.OpGrants, Caller: "cli", Action: proto.ActionList})
		if err != nil {
			return err
		}
		var gs []proto.GrantInfo
		if err := decodeResult(resp, &gs); err != nil {
			return err
		}
		tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tCALLER\tCWD\tSECRETS\tCOMMAND\tEXPIRES")
		for _, g := range gs {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.Caller, g.CwdPrefix,
				strings.Join(g.Secrets, ","), strings.Join(g.CmdPrefix, " "),
				time.Until(g.ExpiresAt).Round(time.Second))
		}
		return tw.Flush()
	}
	c := &cobra.Command{
		Use:   "grants",
		Short: "List or revoke grants",
		Args:  cobra.NoArgs,
		RunE:  list, // bare `grants` behaves like `grants list`
	}
	listCmd := &cobra.Command{Use: "list", Short: "List active grants", Args: cobra.NoArgs, RunE: list}
	revoke := &cobra.Command{
		Use:   "revoke [ID]",
		Short: "Revoke one grant by ID, or all with --all",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			all, _ := cmd.Flags().GetBool("all")
			req := &proto.Request{Op: proto.OpGrants, Caller: "cli"}
			switch {
			case all && len(args) > 0:
				return errors.New("give either a grant ID or --all, not both")
			case all:
				req.Action = proto.ActionRevokeAll
			case len(args) == 1:
				req.Action, req.GrantID = proto.ActionRevoke, args[0]
			default:
				return errors.New("give a grant ID or --all")
			}
			if _, err := simpleCall(cmd.Context(), socket, req); err != nil {
				return err
			}
			if all {
				fmt.Fprintln(cmd.OutOrStdout(), "revoked all grants")
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "revoked %s\n", args[0])
			}
			return nil
		},
	}
	revoke.Flags().Bool("all", false, "revoke every grant")
	for _, x := range []*cobra.Command{c, listCmd, revoke} {
		addSocketFlag(x, &socket)
	}
	c.AddCommand(listCmd, revoke)
	return c
}
