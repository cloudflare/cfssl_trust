// Package config contains the default configuration options for the
// CFSSL trust tooling.
package config

import (
	"os"
	"path/filepath"
)

// GoPath returns the current GOPATH.
func GoPath() string {
	if path := os.Getenv("GOPATH"); path != "" {
		return path
	}
	// https://github.com/golang/go/issues/17262
	return filepath.Join(os.Getenv("HOME"), "go")
}

// DatabaseName records the default name for the database.
var DatabaseName = "cfssl-trust.db"
