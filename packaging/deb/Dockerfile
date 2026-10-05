# Ambiente de build do pacote .deb (Ubuntu 22.04 / WebKitGTK 4.0). A arquitetura é a do Docker em uso;
# para outra, use PLATFORM=linux/amd64 packaging/deb/build.sh (emulado, mais lento).
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config libgtk-3-dev libwebkit2gtk-4.0-dev dpkg-dev curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ARG GOVERSION=1.27.1
RUN arch="$(dpkg --print-architecture)" \
 && curl -fsSL "https://go.dev/dl/go${GOVERSION}.linux-${arch}.tar.gz" | tar -C /usr/local -xz
ENV PATH=/usr/local/go/bin:$PATH
WORKDIR /src
