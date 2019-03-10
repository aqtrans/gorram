#!/bin/sh
cd ../
go build -o deb/gorram-server
cd debbuild/
debuild -us -uc -b
