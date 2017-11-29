#!/bin/sh
set -e

go test -cover $(glide nv)
go vet $(glide nv)
golint $(glide nv)

