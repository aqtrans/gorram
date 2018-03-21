#!/bin/sh
#protoc -I gorram/ gorram/gorram.proto --go_out=plugins=grpc:gorram
go generate
