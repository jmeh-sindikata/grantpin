//go:build tools

// Package tools pins dependencies that later milestone steps will import, so
// parallel work does not race on go.mod and `go mod tidy` does not drop them.
// Delete an import here once real code imports that module.
package tools

import (
	_ "github.com/bmatcuk/doublestar/v4"
	_ "github.com/modelcontextprotocol/go-sdk/mcp"
	_ "github.com/spf13/cobra"
	_ "golang.org/x/crypto/argon2"
	_ "golang.org/x/sys/unix"
	_ "gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)
