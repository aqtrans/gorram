#!/bin/bash

set -euo pipefail

DEBVERSION=1.0.$(date +'%s')
APPNAME=gorram

function build_debian()
{
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-server ./server
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-client ./client
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -o gorram-cli ./cli
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
}

function test_it() {
    go test -race
    go test -cover
    go test -bench=.
}

# Build Debian package inside a container
function build_package() {
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp debian:buster ./build-pkg.sh $DEBVERSION
}

function build_proto()
{
    protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/gorram.proto
}


while [ "$1" != "" ]; do 
    case $1 in
        run-server)
            build_proto
            go run -race server/main.go -ssl-path "./" -debug -conf "./server.yml" $@
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
            GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-server ./server
            GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-client ./client
            GO111MODULE=on go build -buildmode=pie -o gorram-cli ./cli
            GO111MODULE=on go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
            exit
            ;;
        generate-ca)
            GO111MODULE=on go run server/main.go -generate-ca -ssl-path "./"
            exit
            ;;
        test)
            build_proto
            cd client/
            test_it
            cd ../server/
            test_it
            exit
            ;;
## Old stuff
        pkg)
            if [ "$(which dch)" != "" ]; then 
                build_proto
                test_it
                GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-server ./server
                GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-client ./client
                GO111MODULE=on go build -buildmode=pie -o gorram-cli ./cli
                GO111MODULE=on go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
                ./build-pkg.sh $DEBVERSION
            else
                echo "dch not found. building inside container."
                build_proto
                test_it
                build_debian
                build_package
            fi
            exit
            ;;
        build-debian)
            echo "Building binary inside Debian container..."
            build_proto
            test_it
            build_debian
            exit
            ;;
        deploy-binary)
            build_proto
            test_it
            build_debian
            ansible-playbook -i bob.jba.io, deploy.yml
            exit
            ;;
        deploy)
            build_proto
            test_it
            build_debian
            build_package
            scp gorram-$DEBVERSION.deb bob:
            ssh bob sudo dpkg -i gorram-$DEBVERSION.deb
            scp gorram-$DEBVERSION.deb rick:
            ssh rick sudo dpkg -i gorram-$DEBVERSION.deb            
            exit
            ;;            
    esac
done
