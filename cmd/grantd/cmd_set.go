package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantd/internal/presence"
	"github.com/jmeh-sindikata/grantd/internal/proto"
)

func newSetCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret (value from stdin or hidden prompt)",
		Long: "Store a secret. The value is read from stdin when it is not a terminal " +
			"(`printf %s \"$V\" | grantd set NAME`; one trailing newline is stripped), " +
			"otherwise from a hidden prompt. It is never accepted as an argument.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			req := &proto.Request{Op: proto.OpSet, Caller: "cli", Name: args[0]}
			req.Tags, _ = f.GetStringSlice("tags")
			req.URL, _ = f.GetString("url")
			req.Notes, _ = f.GetString("notes")
			req.Overwrite, _ = f.GetBool("overwrite")
			if s, _ := f.GetString("expires"); s != "" {
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
			if s, _ := f.GetString("min-tier"); s != "" {
				t, err := presence.ParseTier(s)
				if err != nil {
					return err
				}
				req.MinTier = &t
			}
			val, err := readValue(cmd.InOrStdin(), cmd.ErrOrStderr(), req.Name)
			if err != nil {
				return err
			}
			defer zeroBytes(val)
			if len(val) == 0 {
				return errors.New("empty value; nothing stored")
			}
			req.Value = string(val)
			if _, err := simpleCall(cmd.Context(), socket, req); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "stored %s\n", req.Name)
			return nil
		},
	}
	c.Flags().StringSlice("tags", nil, "comma-separated tags")
	c.Flags().String("url", "", "URL associated with the secret")
	c.Flags().String("notes", "", "free-form notes")
	c.Flags().String("expires", "", "expiry, e.g. 30d")
	c.Flags().String("min-tier", "", "minimum presence tier: none, dialog, hardware (none means the vault default)")
	c.Flags().Bool("overwrite", false, "replace the secret if it already exists")
	addSocketFlag(c, &socket)
	return c
}
