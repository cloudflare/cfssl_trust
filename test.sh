#!/bin/sh

go get github.com/Masterminds/glide
go get github.com/cloudflare/cfssl_trust/cmd/cfssl-trust
go test -cover $(glide nv)
go vet $(glide nv)
golint $(glide nv)

