package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
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
		fmt.Fprintln(tw, "ID\tCALLER\tCWD\tSECRETS\tCOMMAND\tSTANDING\tEXPIRES")
		for _, g := range gs {
			if g.Tampered {
				// The row's content is untrusted; show only that it exists.
				fmt.Fprintf(tw, "%s\t-\t-\t-\t-\t-\tTAMPERED: failed authentication, ignored (revoke it)\n", g.ID)
				continue
			}
			kind := "-"
			if g.Standing {
				kind = "standing"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.Caller, g.CwdPrefix,
				strings.Join(g.Secrets, ","), strings.Join(g.CmdPrefix, " "), kind,
				formatRemaining(time.Until(g.ExpiresAt)))
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
	add := newGrantsAddCmd(&socket)
	for _, x := range []*cobra.Command{c, listCmd, revoke, add} {
		addSocketFlag(x, &socket)
	}
	c.AddCommand(listCmd, add, revoke)
	return c
}

// formatRemaining renders the time left on a grant: whole seconds below two
// days (as before), "Nd Nh" above (rounded to the minute first, so a fresh
// 30-day grant reads "30d 0h" and not "719h59m59s"). Past expiry it is "expired".
func formatRemaining(d time.Duration) string {
	switch {
	case d.Round(time.Second) <= 0:
		return "expired"
	case d < 48*time.Hour:
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	days := int(d / (24 * time.Hour))
	return fmt.Sprintf("%dd %dh", days, int(d%(24*time.Hour)/time.Hour))
}

func newGrantsAddCmd(socket *string) *cobra.Command {
	c := &cobra.Command{
		Use:   "add --caller NAME --secrets A,b/* --ttl 30d [--cwd DIR] [--uses N] -- cmd args...",
		Short: "Create a standing grant (long-lived, you approve it once)",
		Long: `Create a standing grant: for the next --ttl, requests from --caller to run a
command starting with the given prefix, in --cwd or below it, asking only for
the listed secrets, are released without a prompt.

  grantd grants add --caller claude-code --secrets DB_URL,aws/* --ttl 30d -- php artisan

Everything after -- (or after --cmd, which must then be the last flag) is the
command prefix, so "php artisan" covers "php artisan migrate" but not "php x".
--caller has no default: say who the grant is for. --cwd defaults to the
current directory. --uses N ends the grant after N releases.

You approve it once, in a dialog that says "standing grant" and states the
duration, followed by Touch ID. The repo policy's max_grant_ttl limits only
the "Allow for N" button of a normal prompt, not this. A standing grant lasts
at most 90 days, or less if the policy sets max_standing_grant_ttl; a longer
--ttl is refused, not shortened. Revoke it with "grantd grants revoke ID".

Any program that can reach the daemon socket can send this request, so only
approve a standing-grant dialog that you started yourself.

Exit status: 77 when you cancelled or the dialog could not be shown, 78 when
the repo policy or the secret's presence tier refused it.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			caller, _ := f.GetString("caller")
			if strings.TrimSpace(caller) == "" {
				return errors.New("--caller is required: name who the grant is for (e.g. claude-code)")
			}
			secrets, _ := f.GetStringSlice("secrets")
			var clean []string
			for _, s := range secrets {
				if s = strings.TrimSpace(s); s != "" {
					clean = append(clean, s)
				}
			}
			if len(clean) == 0 {
				return errors.New("--secrets is required (names or globs, comma-separated)")
			}
			if len(args) == 0 {
				return errors.New("give the command prefix after --, e.g. -- php artisan")
			}
			ttlStr, _ := f.GetString("ttl")
			if strings.TrimSpace(ttlStr) == "" {
				return errors.New("--ttl is required, e.g. --ttl 30d")
			}
			ttl, err := parseDuration(ttlStr)
			if err != nil {
				return fmt.Errorf("--ttl: %w", err)
			}
			if ttl <= 0 {
				return errors.New("--ttl must be positive")
			}
			uses, _ := f.GetInt("uses")
			if uses < 0 {
				return errors.New("--uses must not be negative")
			}
			cwd, _ := f.GetString("cwd")
			if cwd == "" {
				if cwd, err = os.Getwd(); err != nil {
					return err
				}
			} else if cwd, err = filepath.Abs(cwd); err != nil {
				return err
			}
			req := &proto.Request{
				Op: proto.OpGrants, Action: proto.ActionAdd, Caller: "cli",
				GrantCaller: strings.TrimSpace(caller), Cwd: cwd, Secrets: clean, Argv: args,
				TTLS: int64(math.Ceil(ttl.Seconds())), Uses: uses,
			}
			fmt.Fprintln(cmd.ErrOrStderr(), "Waiting for you to confirm the standing grant in the dialog (then Touch ID)...")
			resp, err := simpleCall(cmd.Context(), *socket, req)
			if err != nil {
				return err
			}
			var g proto.GrantInfo
			if err := decodeResult(resp, &g); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "created standing grant %s\n", g.ID)
			fmt.Fprintf(out, "  %s may run `%s ...` with %s in %s and below\n", g.Caller,
				strings.Join(g.CmdPrefix, " "), strings.Join(g.Secrets, ","), g.CwdPrefix)
			fmt.Fprintf(out, "  until %s (%s)", g.ExpiresAt.Local().Format("2006-01-02 15:04"), formatRemaining(time.Until(g.ExpiresAt)))
			if g.UsesRemaining != nil {
				fmt.Fprintf(out, ", %d use(s)", *g.UsesRemaining)
			}
			fmt.Fprintln(out)
			return nil
		},
	}
	c.Flags().SetInterspersed(false) // everything after the first non-flag (or --) is the command prefix
	c.Flags().String("caller", "", "who the grant is for, e.g. claude-code (required, no default)")
	c.Flags().StringSlice("secrets", nil, "secret names or globs the grant covers (comma-separated)")
	c.Flags().String("ttl", "", "how long the grant lasts, e.g. 30d, 12h (required; at most 90d)")
	c.Flags().String("cwd", "", "directory the grant covers, with its subfolders (default: current directory)")
	c.Flags().Int("uses", 0, "end the grant after N releases (default: unlimited within --ttl)")
	// --cmd is accepted as a marker for readability: "--cmd php artisan" is the
	// same as "-- php artisan". It must be the last flag.
	c.Flags().Bool("cmd", false, "the rest of the line is the command prefix (same as --)")
	return c
}
