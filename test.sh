#!/bin/sh

go test -cover $(glide nv)
go vet $(glide nv)
golint $(glide nv)

