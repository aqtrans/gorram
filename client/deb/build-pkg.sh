#!/bin/sh
cd ../
go build -o deb/gorram-client
cd deb/
debuild -us -uc -b
