package main

import "grantd/internal/daemon"

// buildRouter returns the op router the daemon serves. The built-in status op
// is provided by the daemon itself and needs no registration here.
//
// TODO(integration): register handlers for run, list, exists, masked, set,
// delete, show, grants and audit, e.g. r.Register(proto.OpList, listHandler),
// and pass a daemon.StatusFunc (vault/backends/grants info) via buildStatusFunc.
func buildRouter() *daemon.Router {
	return daemon.NewRouter()
}

// buildStatusFunc returns the hook that adds vault, backend and grant details
// to the status reply. nil means the daemon reports only the basics.
//
// TODO(integration): fill VaultInitialized, KeyStoreTier, ApproverTier,
// Secrets and ActiveGrants.
func buildStatusFunc() daemon.StatusFunc { return nil }
