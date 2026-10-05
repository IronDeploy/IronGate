#!/bin/sh
# Roda DENTRO do container de build: compila e monta /out/irongate_<versão>_<arch>.deb.
set -eu
VERSION="${VERSION:-0.1.0}"
MAINTAINER="${MAINTAINER:-Iron Deploy}"
ARCH="$(dpkg --print-architecture)"
ROOT=/tmp/pkg
rm -rf "$ROOT" && mkdir -p "$ROOT/usr/bin" "$ROOT/lib/systemd/system" "$ROOT/usr/share/applications" "$ROOT/DEBIAN"

CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$ROOT/usr/bin/irongate" ./cmd/irongate
go build -trimpath -ldflags "-s -w" -tags "desktop,production" -o "$ROOT/usr/bin/irongate-gui" ./gui
"$ROOT/usr/bin/irongate" setup --export-units "$ROOT/lib/systemd/system" /usr/bin/irongate

install -m 0644 packaging/deb/irongate.desktop "$ROOT/usr/share/applications/irongate.desktop"
install -m 0755 packaging/deb/postinst packaging/deb/prerm packaging/deb/postrm "$ROOT/DEBIAN/"
install -D -m 0644 LICENSE "$ROOT/usr/share/doc/irongate/copyright"
install -m 0644 NOTICE "$ROOT/usr/share/doc/irongate/NOTICE"

SIZE="$(du -sk "$ROOT/usr" "$ROOT/lib" | awk '{s+=$1} END {print s}')"
cat > "$ROOT/DEBIAN/control" <<CTRL
Package: irongate
Version: $VERSION
Architecture: $ARCH
Maintainer: $MAINTAINER
Installed-Size: $SIZE
Section: net
Priority: optional
Depends: strongswan-swanctl, charon-systemd, libcharon-extra-plugins, libcharon-extauth-plugins, libgtk-3-0, libwebkit2gtk-4.0-37
Recommends: gnome-keyring | kwalletmanager
Homepage: https://github.com/irondeploy/iron-gate
Description: A VPN corporativa em um clique
 Importe o perfil que o TI enviou, informe usuário e senha e conecte.
 Linux primeiro; credenciais no cofre do sistema; mensagens de erro em
 português. Inclui um serviço privilegiado de acesso restrito ao strongSwan.
CTRL

mkdir -p /out
dpkg-deb --root-owner-group --build "$ROOT" "/out/irongate_${VERSION}_${ARCH}.deb"
