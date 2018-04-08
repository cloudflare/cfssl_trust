#!/bin/sh

set -e

PKGS=$(go list ./... | grep -v /vendor/)
go test -cover $PKGS
go vet $PKGS
golint $PKGS
