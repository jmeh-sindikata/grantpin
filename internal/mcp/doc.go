// Package mcp implements the stdio MCP server, a thin shim over the daemon
// socket. It deliberately exposes no tool that returns a secret value.
//
// Exactly four tools exist: secret_list, secret_exists, secret_masked and
// secret_run. Each is a translation to one proto.Request sent through
// internal/client. See README.md in this directory for the Claude Code
// configuration and how to try it.
package mcp
