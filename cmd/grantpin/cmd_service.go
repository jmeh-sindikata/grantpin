package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/jmeh-sindikata/grantpin/internal/client"
	"github.com/jmeh-sindikata/grantpin/internal/daemon"
	"github.com/jmeh-sindikata/grantpin/internal/service"
	"github.com/jmeh-sindikata/grantpin/internal/vault"
)

// Exit codes for `grantpin service status`.
const exitServiceNotInstalled = 3

// Seams for tests: the real manager talks to launchd, and status exits the
// process directly because main() only knows exit code 1.
var (
	newServiceManager = service.New
	serviceExit       = os.Exit
	daemonStatus      = client.Status
)

// serviceDataDir is the grantpin data directory (the one holding vault.db),
// where the service.wanted marker lives.
func serviceDataDir() (string, error) {
	p, err := vault.DefaultPath()
	if err != nil {
		return "", err
	}
	return filepath.Dir(p), nil
}

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
			w := cmd.OutOrStdout()
			// The launchd daemon sees neither this shell's GRANTPIN_SOCKET nor
			// its XDG_RUNTIME_DIR. If the socket this shell would use is not
			// the platform default, record it in the plist so the daemon, the
			// readiness check and the CLI all agree.
			if opts.Socket == "" {
				resolved, err := resolveSocket("")
				if err != nil {
					return err
				}
				platform, err := daemon.PlatformSocketPath()
				if err != nil {
					return err
				}
				if resolved != platform {
					opts.Socket = resolved
					fmt.Fprintf(w, "socket:    %s (recorded as GRANTPIN_SOCKET in the service; differs from the default %s)\n", resolved, platform)
				}
			}
			notReady := m.Install(cmd.Context(), opts)
			if notReady != nil && !errors.Is(notReady, service.ErrNotReady) {
				return notReady
			}
			// The job is installed and loaded (a not-ready daemon is only a
			// warning): remember that the user wants it, so it can be restored
			// after a package manager removes the launchd definition.
			dataDir, err := serviceDataDir()
			if err != nil {
				return err
			}
			if err := service.SetWanted(dataDir, true); err != nil {
				return err
			}
			st, err := m.Status(cmd.Context())
			if err != nil {
				return err
			}
			fmt.Fprintln(w, "service installed and started")
			printServiceStatus(cmd, st)
			if notReady != nil {
				fmt.Fprintf(w, "WARNING:   %v\n", notReady)
				return nil
			}
			socket := opts.Socket
			if socket == "" {
				if socket, err = resolveSocket(""); err != nil {
					return err
				}
			}
			ds, err := daemonStatus(cmd.Context(), socket)
			if err != nil {
				fmt.Fprintf(w, "WARNING:   daemon status: %v\n", err)
				return nil
			}
			fmt.Fprintf(w, "daemon:    running (pid %d, version %s)\n", ds.PID, ds.Version)
			return nil
		},
	}
	install.Flags().StringVar(&opts.Exe, "exe", "", "grantpin binary or .app bundle the service runs; a menu-bar grantpin.app resolves to its Helpers/grantpin-daemon.app binary (default: this executable)")
	install.Flags().StringVar(&opts.Socket, "socket", "", "socket path to export to the daemon as GRANTPIN_SOCKET (default: your $GRANTPIN_SOCKET / $XDG_RUNTIME_DIR socket, recorded only if it differs from the platform default)")
	install.Flags().StringVar(&opts.Path, "path", "", "PATH the daemon (and the commands it runs) get (default: PATH of this shell)")
	install.Flags().StringVar(&opts.LogDir, "log-dir", "", "directory for daemon logs (default: ~/Library/Logs/grantpin)")

	uninstall := &cobra.Command{
		Use:   "uninstall",
		Short: "Stop and remove the service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newServiceManager()
			if err != nil {
				return err
			}
			// Whatever launchctl says, the user no longer wants the service.
			uerr := m.Uninstall(cmd.Context())
			dataDir, err := serviceDataDir()
			if err == nil {
				err = service.SetWanted(dataDir, false)
			}
			if err := errors.Join(uerr, err); err != nil {
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
			printServiceWanted(cmd)
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
	if st.ExeMissing {
		fmt.Fprintf(w, "warning:   executable no longer exists; re-run `grantpin service install`\n")
	}
}

// printServiceWanted appends the "wanted:" line (the service.wanted marker).
// It comes last, also when the service is not installed, so the lines above
// keep their names and order.
func printServiceWanted(cmd *cobra.Command) {
	wanted := false
	if dir, err := serviceDataDir(); err == nil {
		wanted = service.Wanted(dir)
	}
	if wanted {
		fmt.Fprintf(cmd.OutOrStdout(), "wanted:    yes\n")
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "wanted:    no\n")
	}
}
