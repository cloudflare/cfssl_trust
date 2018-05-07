#!/bin/sh
set -e

go test -cover ./...
./golint $(go list ./...)
