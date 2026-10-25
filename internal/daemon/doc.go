// Package daemon implements the grantd socket server and request router.
//
// The daemon runs as the invoking user (never root), accepts newline-delimited
// JSON requests (see package proto) on a Unix domain socket, verifies the peer
// UID, and routes each request through policy, grant matching, the Approver,
// the vault, the runner and the audit log.
package daemon
