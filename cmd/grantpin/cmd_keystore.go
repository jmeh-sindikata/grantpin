package main

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantd/internal/client"
	"github.com/jmeh-sindikata/grantd/internal/keystore"
)

// Exit codes of `grantd keystore delete` (besides 0 and 1).
const (
	exitKeystoreRefused = 2 // not confirmed, or the daemon is still running
	exitKeystoreMissing = 3 // there was no such key material
)

// errKeystoreUnsupported means this platform or build has no key store that can
// delete its key material.
var errKeystoreUnsupported = errors.New("unsupported")

// openKeyDeleter opens the build's key store for deletion. It creates nothing
// and never prompts. Tests replace it, so that no test touches a Keychain.
var openKeyDeleter = func() (keystore.Deleter, error) {
	ks, err := openKeyStore(backendConfig{})
	if err != nil {
		if runtime.GOOS != "darwin" {
			return nil, errKeystoreUnsupported
		}
		return nil, err
	}
	d, ok := ks.(keystore.Deleter)
	if !ok {
		return nil, errKeystoreUnsupported
	}
	return d, nil
}

// daemonAnswering reports whether a daemon answers on the socket.
var daemonAnswering = func(ctx context.Context, socket string) bool {
	_, err := client.Status(ctx, socket)
	return err == nil
}

func newKeystoreCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "keystore",
		Short: "Manage the key material that protects the vault",
		Args:  cobra.NoArgs,
	}
	c.AddCommand(newKeystoreDeleteCmd())
	return c
}

// keystoreDeleteWarning goes to stderr before anything is deleted, and with a
// refusal.
const keystoreDeleteWarning = "grantd: this deletes the key that protects the vault: the vault, and every secret in it, becomes permanently unreadable"

func newKeystoreDeleteCmd() *cobra.Command {
	var socket string
	c := &cobra.Command{
		Use:   "delete (--fallback | --hardware) --yes",
		Short: "Delete the vault's key material (the vault becomes permanently unreadable)",
		Long: `Delete the key material that protects the vault, for uninstalling. Afterwards the vault file can never be opened again, and nothing can recover its secrets.

--fallback removes the Keychain item that holds the key-encryption key of a vault created with the Keychain fallback. --hardware removes the Secure Enclave key reference. Give exactly one. --yes is required; there is no prompt.

Exit status: 0 deleted; 3 there was no such key material; 2 refused (no --yes, or the daemon is still answering on its socket, unless --force); 1 any other failure. Nothing is printed on stdout.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			f := cmd.Flags()
			fallback, _ := f.GetBool("fallback")
			hardware, _ := f.GetBool("hardware")
			yes, _ := f.GetBool("yes")
			force, _ := f.GetBool("force")
			if fallback == hardware {
				return fmt.Errorf("give exactly one of --fallback and --hardware")
			}
			d, err := openKeyDeleter()
			if err != nil {
				return err // unsupported, or a real failure to open the key store
			}
			stderr := cmd.ErrOrStderr()
			fmt.Fprintln(stderr, keystoreDeleteWarning)
			if !yes {
				fmt.Fprintln(stderr, "grantd: refusing without --yes")
				return &exitError{code: exitKeystoreRefused}
			}
			if !force {
				path, err := resolveSocket(socket)
				if err != nil {
					return err
				}
				if daemonAnswering(cmd.Context(), path) {
					fmt.Fprintf(stderr, "grantd: the daemon is running (socket %s); stop it first, or pass --force\n", path)
					return &exitError{code: exitKeystoreRefused}
				}
			}
			if fallback {
				err = d.DeleteFallbackKEK(cmd.Context())
			} else {
				err = d.DeleteSecureEnclaveKey(cmd.Context())
			}
			switch {
			case err == nil:
				return nil
			case errors.Is(err, keystore.ErrNoKeyMaterial):
				return &exitError{code: exitKeystoreMissing}
			}
			return err
		},
	}
	c.Flags().Bool("fallback", false, "delete the Keychain fallback key-encryption key")
	c.Flags().Bool("hardware", false, "delete the Secure Enclave key")
	c.Flags().Bool("yes", false, "confirm that the vault may become permanently unreadable (required)")
	c.Flags().Bool("force", false, "delete even if the daemon is running")
	addSocketFlag(c, &socket)
	return c
}
