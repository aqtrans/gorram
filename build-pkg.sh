#!/bin/bash

## Build a very minimal .deb without installing devscripts

set -euo pipefail

VERSION=$1

mkdir -p dpkg/usr/bin
cp gorram-server gorram-client gorram-cli gorram-certs dpkg/usr/bin/

mkdir -p dpkg/lib/systemd/system
cp gorram-server.service gorram-client.service dpkg/lib/systemd/system/

mkdir -p dpkg/etc/gorram/conf.d
cp server.yml.dist client.yml.dist dpkg/etc/
cp clientname.yml.dist dpkg/etc/gorram/conf.d

mkdir -p dpkg/DEBIAN

cp debian/control debian/preinst debian/postinst debian/prerm debian/postrm dpkg/DEBIAN/

sed -i "s/Version: *.*/Version: 1.0."$(date +%s)"/g" dpkg/DEBIAN/control

chmod +x dpkg/DEBIAN/preinst dpkg/DEBIAN/postinst dpkg/DEBIAN/prerm dpkg/DEBIAN/postrm
chmod +x dpkg/usr/bin/gorram-server dpkg/usr/bin/gorram-client dpkg/usr/bin/gorram-cli dpkg/usr/bin/gorram-certs

dpkg-deb --build --root-owner-group dpkg 
mv dpkg.deb gorram-$VERSION.deb

echo "Package built at gorram-$VERSION.deb"

rm -rf dpkg/
