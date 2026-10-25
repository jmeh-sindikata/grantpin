package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"grantd/internal/service"
)

// Exit codes for `grantd service status`.
const exitServiceNotInstalled = 3

// Seams for tests: the real manager talks to launchd, and status exits the
// process directly because main() only knows exit code 1.
var (
	newServiceManager = service.New
	serviceExit       = os.Exit
)

func newServiceCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "service",
		Short: "Manage the background service (launchd / systemd --user / Windows task)",
		Args:  cobra.NoArgs,
	}

	var opts service.Options
	install := &cobra.Command{
		Use:   "install",
		Short: "Install and start the service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newServiceManager()
			if err != nil {
				return err
			}
			if err := m.Install(cmd.Context(), opts); err != nil {
				return err
			}
			st, err := m.Status(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "service installed and started")
			printServiceStatus(cmd, st)
			return nil
		},
	}
	install.Flags().StringVar(&opts.Exe, "exe", "", "grantd binary the service runs (default: this executable)")
	install.Flags().StringVar(&opts.Socket, "socket", "", "socket path to export to the daemon as GRANTD_SOCKET")
	install.Flags().BoolVar(&opts.KeychainFallback, "keychain-fallback", false, "run the daemon with --keychain-fallback (macOS: allow a Keychain-resident key when the Secure Enclave is unavailable; must match how the vault was created)")
	install.Flags().StringVar(&opts.LogDir, "log-dir", "", "directory for daemon logs (default: ~/Library/Logs/grantd)")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newServiceManager()
			if err != nil {
				return err
			}
			if err := m.Uninstall(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "service stopped and removed")
			return nil
		},
	}

	status := &cobra.Command{
		Use:   "status",
		Short: "Show service status (exit 3 if not installed)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newServiceManager()
			if err != nil {
				return err
			}
			st, err := m.Status(cmd.Context())
			if err != nil {
				return err
			}
			printServiceStatus(cmd, st)
			if !st.Installed {
				serviceExit(exitServiceNotInstalled)
			}
			return nil
		},
	}

	c.AddCommand(install, uninstall, status)
	return c
}

func printServiceStatus(cmd *cobra.Command, st service.Status) {
	w := cmd.OutOrStdout()
	yn := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}
	fmt.Fprintf(w, "label:     %s\n", st.Label)
	fmt.Fprintf(w, "installed: %s\n", yn(st.Installed))
	if !st.Installed {
		return
	}
	fmt.Fprintf(w, "plist:     %s\n", st.PlistPath)
	fmt.Fprintf(w, "loaded:    %s\n", yn(st.Loaded))
	if st.Running {
		fmt.Fprintf(w, "running:   yes (pid %d)\n", st.PID)
	} else {
		fmt.Fprintf(w, "running:   no\n")
	}
	if st.ExePath != "" {
		fmt.Fprintf(w, "exe:       %s\n", st.ExePath)
	}
	if st.KeychainFallback {
		fmt.Fprintf(w, "options:   --keychain-fallback\n")
	}
	if st.ExeMissing {
		fmt.Fprintf(w, "warning:   executable no longer exists; re-run `grantd service install`\n")
	}
}
