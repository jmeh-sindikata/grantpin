package main

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantd/internal/proto"
	"github.com/jmeh-sindikata/grantd/internal/vault"
)

func newImportCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "import FILE",
		Short: "Import secrets from a .env file",
		Long: "Import KEY=value pairs from a .env file (FILE may be - for stdin). Each key " +
			"becomes a secret with default metadata. The file is parsed here; values go " +
			"to the daemon one `set` at a time. Names are validated and conflicts " +
			"detected before anything is written, but a daemon error midway can leave " +
			"a partial import.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dry, _ := cmd.Flags().GetBool("dry-run")
			modeS, _ := cmd.Flags().GetString("on-conflict")
			mode, err := vault.ParseConflictMode(modeS)
			if err != nil {
				return err
			}
			var r io.Reader = cmd.InOrStdin()
			if args[0] != "-" {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer f.Close()
				r = f
			}
			kvs, err := vault.ParseDotenv(r)
			if err != nil {
				return err
			}
			defer func() {
				for _, kv := range kvs {
					vault.Zero(kv.Value)
				}
			}()
			return importKVs(cmd, socket, kvs, mode, dry)
		},
	}
	c.Flags().Bool("dry-run", false, "show what would be imported without writing")
	c.Flags().String("on-conflict", "error", "when a name already exists: skip, overwrite or error")
	addSocketFlag(c, &socket)
	return c
}

func importKVs(cmd *cobra.Command, socket string, kvs []vault.KV, mode vault.ConflictMode, dry bool) error {
	ctx := cmd.Context()
	// Duplicates: the last one wins (same as vault.Import).
	last := map[string][]byte{}
	var order []string
	for _, kv := range kvs {
		if err := vault.ValidateName(kv.Key); err != nil {
			return fmt.Errorf("key %q: %w", kv.Key, err)
		}
		if _, seen := last[kv.Key]; !seen {
			order = append(order, kv.Key)
		}
		last[kv.Key] = kv.Value
	}
	for _, k := range order {
		if err := vault.ValidateValue(k, last[k]); err != nil {
			return err
		}
	}
	var added, overwritten, skipped, empty, conflicts []string
	var todo []string
	for _, k := range order {
		if len(last[k]) == 0 {
			empty = append(empty, k)
			continue
		}
		exists, err := secretExists(ctx, socket, k)
		if err != nil {
			return err
		}
		switch {
		case !exists:
			added = append(added, k)
			todo = append(todo, k)
		case mode == vault.ConflictSkip:
			skipped = append(skipped, k)
		case mode == vault.ConflictOverwrite:
			overwritten = append(overwritten, k)
			todo = append(todo, k)
		default:
			conflicts = append(conflicts, k)
		}
	}
	if len(conflicts) > 0 {
		return fmt.Errorf("already exist (use --on-conflict skip|overwrite): %s", strings.Join(conflicts, ", "))
	}
	if !dry {
		for _, k := range todo {
			req := &proto.Request{Op: proto.OpSet, Caller: "cli", Name: k, Value: string(last[k]),
				Overwrite: slices.Contains(overwritten, k)}
			if _, err := simpleCall(ctx, socket, req); err != nil {
				return fmt.Errorf("importing %s: %w", k, err)
			}
		}
	}
	out := cmd.OutOrStdout()
	prefix := ""
	if dry {
		prefix = "(dry run) would be "
	}
	report := func(label string, names []string) {
		if len(names) > 0 {
			fmt.Fprintf(out, "%s%s: %d (%s)\n", prefix, label, len(names), strings.Join(names, ", "))
		}
	}
	report("added", added)
	report("overwritten", overwritten)
	report("skipped (exists)", skipped)
	report("ignored (empty value)", empty)
	if len(added)+len(overwritten)+len(skipped)+len(empty) == 0 {
		fmt.Fprintln(out, "nothing to import")
	}
	return nil
}
