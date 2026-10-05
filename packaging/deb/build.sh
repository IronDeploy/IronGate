#!/bin/sh
# Gera o .deb em ./dist. Uso: packaging/deb/build.sh [versão]   (VERSION, MAINTAINER e PLATFORM por ambiente)
set -eu
cd "$(dirname "$0")/../.."
VERSION="${1:-${VERSION:-0.1.0}}"
mkdir -p dist
docker build ${PLATFORM:+--platform "$PLATFORM"} -t irongate-deb-build -f packaging/deb/Dockerfile packaging/deb
docker run --rm ${PLATFORM:+--platform "$PLATFORM"} -e VERSION="$VERSION" -e MAINTAINER="${MAINTAINER:-Iron Deploy}" -e GOTOOLCHAIN=auto \
  -v "$PWD":/src -v "$PWD/dist":/out irongate-deb-build sh packaging/deb/make-deb.sh
ls -la dist/*.deb
