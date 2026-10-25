package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"grantd/internal/presence"
	"grantd/internal/proto"
)

func newUpdateCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "update NAME",
		Short: "Change a secret's metadata without touching its value",
		Long: "Change the tags, URL, notes, expiry or minimum presence tier of an existing secret. " +
			"The value is never read or sent. Give any subset of the flags; fields you leave out " +
			"stay as they are. An empty --tags, --url or --notes clears that field, and " +
			"--clear-expires removes the expiry. Changing --min-tier re-encrypts the stored value; " +
			"lowering it asks for confirmation (dialog and Touch ID).",
		Example: "  grantd update API_KEY --tags prod,billing --expires 90d\n" +
			"  grantd update API_KEY --url \"\" --clear-expires",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			req := &proto.Request{Op: proto.OpUpdate, Caller: "cli", Name: args[0]}
			if f.Changed("tags") {
				tags, _ := f.GetStringSlice("tags")
				if len(tags) == 0 {
					req.Clear = append(req.Clear, "tags")
				} else {
					req.Tags = tags
				}
			}
			if f.Changed("url") {
				req.URL, _ = f.GetString("url")
				if req.URL == "" {
					req.Clear = append(req.Clear, "url")
				}
			}
			if f.Changed("notes") {
				req.Notes, _ = f.GetString("notes")
				if req.Notes == "" {
					req.Clear = append(req.Clear, "notes")
				}
			}
			clearExp, _ := f.GetBool("clear-expires")
			switch {
			case clearExp && f.Changed("expires"):
				return errors.New("--expires and --clear-expires cannot be combined")
			case clearExp:
				req.Clear = append(req.Clear, "expires")
			case f.Changed("expires"):
				s, _ := f.GetString("expires")
				d, err := parseDuration(s)
				if err != nil {
					return err
				}
				if d <= 0 {
					return errors.New("--expires must be positive")
				}
				t := time.Now().Add(d)
				req.Expires = &t
			}
			if s, _ := f.GetString("min-tier"); f.Changed("min-tier") {
				t, err := presence.ParseTier(s)
				if err != nil {
					return err
				}
				req.MinTier = &t
			}
			if req.Tags == nil && req.URL == "" && req.Notes == "" && req.Expires == nil && req.MinTier == nil && len(req.Clear) == 0 {
				return errors.New("nothing to update: give at least one of --tags, --url, --notes, --expires, --clear-expires, --min-tier")
			}
			if _, err := simpleCall(cmd.Context(), socket, req); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "updated %s\n", req.Name)
			return nil
		},
	}
	c.Flags().StringSlice("tags", nil, "replace the tags (comma-separated; empty clears them)")
	c.Flags().String("url", "", "replace the URL (empty clears it)")
	c.Flags().String("notes", "", "replace the notes (empty clears them)")
	c.Flags().String("expires", "", "new expiry from now, e.g. 30d")
	c.Flags().Bool("clear-expires", false, "remove the expiry")
	c.Flags().String("min-tier", "", "minimum presence tier: none, dialog, hardware (none means the vault default); re-encrypts the value")
	addSocketFlag(c, &socket)
	return c
}
