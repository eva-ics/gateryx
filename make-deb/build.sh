#!/bin/bash -xe

GATERYX=..

VERSION=$(grep ^version ../Cargo.toml|awk '{ print $3 }'|tr -d '"')

[ -z "$VERSION" ] && exit 1

[ -z "${RUST_TARGET}" ] && exit 1
[ -z "${TARGET_DIR}" ] && exit 1

[ -z "${DEB_ARCH}" ] && exit 1

DEB="gateryx-server-${VERSION}-${DEB_ARCH}"

rm -rf "./${DEB}"
mkdir -p "./${DEB}/usr/sbin"
mkdir -p "./${DEB}/usr/share"
mkdir -p "./${DEB}/lib/systemd/system"
mkdir -p "./${DEB}/DEBIAN"
mkdir -p "./${DEB}/etc/gateryx/icons"
mkdir -p "./${DEB}/usr/share/gateryx/www"
mkdir -p "./${DEB}/var/gateryx/www/plain/.well-known"
echo "Used for ACME challenges" > "./${DEB}/var/gateryx/www/plain/.well-known/README.txt"
chmod -R 755 "./${DEB}/var/gateryx/www"
cp -rvf ../auth/dist "./${DEB}/usr/share/gateryx/www/auth"
cp -rvf ../system/dist "./${DEB}/usr/share/gateryx/www/system"
cp -vf "../${TARGET_DIR}/${RUST_TARGET}/release/gateryx-server" "./${DEB}/usr/sbin/"
cp -vf ../systemd/gateryx.service "./${DEB}/lib/systemd/system/"
cp -vf ../etc/config.toml.default "./${DEB}/etc/gateryx/"
cp -rvf ../etc/app.d "./${DEB}/etc/gateryx/"
cp -rvf ../icons/* "./${DEB}/etc/gateryx/icons/"
cp -rvf ../share/* "./${DEB}/usr/share/gateryx/"
(
cat << EOF
Package: gateryx-server
Version: ${VERSION}
Section: base
Priority: optional
Depends: libssl3, gateryx-client
Architecture: ${DEB_ARCH}
Maintainer: Serhij S. <div@altertech.com>
Description: Secure WAF for IoT and Industrial applications
EOF
) > "./${DEB}/DEBIAN/control"
cp -vf ./debian-server/* "./${DEB}/DEBIAN/"
dpkg-deb --build --root-owner-group -Zxz "./${DEB}"

DEB="gateryx-client-${VERSION}-${DEB_ARCH}"
rm -rf "./${DEB}"
mkdir -p "./${DEB}/usr/bin"
mkdir -p "./${DEB}/etc/gateryx"
mkdir -p "./${DEB}/DEBIAN"
cp -vf ../etc/client.toml.default "./${DEB}/etc/gateryx/"
cp -vf "../${TARGET_DIR}/${RUST_TARGET}/release/gateryx" "./${DEB}/usr/bin/"
(
cat << EOF
Package: gateryx-client
Version: ${VERSION}
Section: base
Priority: optional
Depends: libssl3 openssl
Architecture: ${DEB_ARCH}
Maintainer: Serhij S. <div@altertech.com>
Description: WAF for IoT and Industrial applications
EOF
) > "./${DEB}/DEBIAN/control"
cp -vf ./debian-client/* "./${DEB}/DEBIAN/"
dpkg-deb --build --root-owner-group -Zxz "./${DEB}"
