#!/bin/sh
go build -o gorram-client
debuild -us -uc -b
