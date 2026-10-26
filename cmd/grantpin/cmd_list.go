package main

import (
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantpin/internal/proto"
)

func newListCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "list",
		Short: "List secret names and metadata (never values)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			req := &proto.Request{Op: proto.OpList, Caller: "cli"}
			req.Tag, _ = cmd.Flags().GetString("tag")
			if s, _ := cmd.Flags().GetString("expiring"); s != "" {
				d, err := parseDuration(s)
				if err != nil {
					return err
				}
				if d <= 0 {
					return fmt.Errorf("--expiring must be positive")
				}
				req.ExpiringWithinS = int64(d / time.Second)
			}
			resp, err := simpleCall(cmd.Context(), socket, req)
			if err != nil {
				return err
			}
			var infos []proto.SecretInfo
			if err := decodeResult(resp, &infos); err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tTIER\tEXPIRES\tTAGS\tURL")
			for _, s := range infos {
				exp := "-"
				if s.ExpiresAt != nil {
					exp = s.ExpiresAt.Local().Format("2006-01-02")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", printable(s.Name), s.MinTier, exp, dash(printable(strings.Join(s.Tags, ","))), dash(printable(s.URL)))
			}
			return tw.Flush()
		},
	}
	c.Flags().String("tag", "", "only secrets with this tag")
	c.Flags().String("expiring", "", "only secrets expiring within this duration, e.g. 7d")
	addSocketFlag(c, &socket)
	return c
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
