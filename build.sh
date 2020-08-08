#!/bin/bash

set -e 

function build_proto()
{
    protoc proto/gorram.proto --go_out=plugins=grpc:.
}

while [ "$1" != "" ]; do 
    PARAM=$1
    shift
    case $PARAM in
        run-server)
            build_proto
            go run -race server/main.go -ssl-path "./" -debug -conf "./config.yml" $@
            ;;
        run-client)
            build_proto
            go run -race client/main.go -ssl-path "./" -debug -conf "./client.yml" $@
            ;;            
        proto)
            build_proto
            exit
            ;;
        build)
            build_proto
            GO111MODULE=on go build -o gorram-server ./server
            GO111MODULE=on go build -o gorram-client ./client
            exit
            ;;
        generate-ca)
            GO111MODULE=on go run server/main.go -generate-ca -ssl-path "./"
            exit
            ;;
    esac
done
