// Package client is the library the grantpin CLI (and later the MCP shim) uses to
// talk to the daemon over its Unix socket.
//
// The protocol is one request per connection: Dial opens a connection, Do sends
// one request and reads stream frames until the final response, and the
// connection is then spent. Use Call for the common dial+do+close sequence.
package client
