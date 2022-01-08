#!/bin/bash

set -euo pipefail

DEBVERSION=1.0.$(date +'%s')-$(git rev-parse --short HEAD)
APPNAME=gorram

function build_debian()
{
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-server ./server
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-client ./client
    podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -o gorram-cli ./cli
    #podman run --rm -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang:buster go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
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
    go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.26
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1
    protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proto/gorram.proto
}

function test_all() {
    cd client/
    test_it
    cd ../server/
    test_it
    cd ../certs/
    test_it
    cd ../cli/
    test_it
    cd ../checks/
    test_it
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
            #GO111MODULE=on go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
            exit
            ;;
        generate-ca)
            GO111MODULE=on go run server/main.go -generate-ca -ssl-path "./"
            exit
            ;;
        test)
            test_all
            exit
            ;;
## Old stuff
        pkg)
            if [ "$(which dch)" != "" ]; then 
                build_proto
                test_all
                GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-server ./server
                GO111MODULE=on go build -buildmode=pie -ldflags "-X main.sha1ver=$(git rev-parse HEAD) -X main.buildTime=$(date +'%Y-%m-%d_%T')" -o gorram-client ./client
                GO111MODULE=on go build -buildmode=pie -o gorram-cli ./cli
                #GO111MODULE=on go build -buildmode=pie -o gorram-certs ./certs/gorram-certs
                ./build-pkg.sh $DEBVERSION
            else
                echo "dch not found. building inside container."
                build_proto
                test_all
                build_debian
                build_package
            fi
            exit
            ;;
        build-debian)
            echo "Building binary inside Debian container..."
            build_proto
            test_all
            build_debian
            exit
            ;;
        deploy-binary)
            build_proto
            test_all
            build_debian
            ansible-playbook -i bob.jba.io, deploy.yml
            exit
            ;;
        deploy)
            build_proto
            test_all
            build_debian
            build_package
            scp gorram-$DEBVERSION.deb bob:
            ssh bob sudo dpkg -i gorram-$DEBVERSION.deb
            scp gorram-$DEBVERSION.deb rick:
            ssh rick sudo dpkg -i gorram-$DEBVERSION.deb
            sleep 5
            ssh bob sudo systemctl status gorram-server gorram-client
            ssh rick sudo systemctl status gorram-client
            exit
            ;;            
    esac
done
