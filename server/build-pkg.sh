#!/bin/sh
go build -o gorram-server
debuild -us -uc -b
