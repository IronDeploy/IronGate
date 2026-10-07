# Ambiente de teste ponta a ponta: servidor strongSwan (IKEv2 + EAP-MSCHAPv2) e cliente com o irongate.
# Os certificados são gerados no build e valem só para teste.

FROM debian:bookworm-slim AS pki
RUN apt-get update && apt-get install -y --no-install-recommends strongswan-pki ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /pki
RUN pki --gen --type rsa --size 2048 --outform pem > ca.key \
 && pki --self --ca --lifetime 3650 --in ca.key --type rsa --dn "CN=Iron Gate Test CA" --outform pem > ca.pem \
 && pki --gen --type rsa --size 2048 --outform pem > server.key \
 && pki --req --type rsa --in server.key --dn "CN=gateway" --san gateway --outform pem > server.req \
 && pki --issue --cacert ca.pem --cakey ca.key --type pkcs10 --in server.req --san gateway --flag serverAuth --lifetime 3650 --outform pem > server.pem

# Um segundo CA, sem relação com o servidor: serve para provar que o CA de um perfil não valida o servidor de outro.
RUN pki --gen --type rsa --size 2048 --outform pem > other.key \
 && pki --self --ca --lifetime 3650 --in other.key --type rsa --dn "CN=Outro CA de Teste" --outform pem > other-ca.pem

FROM golang:1.24 AS build
ENV GOTOOLCHAIN=auto CGO_ENABLED=0
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /irongate ./cmd/irongate

FROM debian:bookworm-slim AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
      strongswan-charon strongswan-swanctl libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-extra-plugins libstrongswan-standard-plugins iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*

FROM base AS server
COPY --from=pki /pki/ca.pem /etc/swanctl/x509ca/ca.pem
COPY --from=pki /pki/server.pem /etc/swanctl/x509/server.pem
COPY --from=pki /pki/server.key /etc/swanctl/private/server.key
COPY test/e2e/server.swanctl.conf /etc/swanctl/swanctl.conf
COPY test/e2e/server-psk.swanctl.conf /etc/swanctl/server-psk.swanctl.conf
COPY test/e2e/server-entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

FROM base AS client
# O CA fica fora de /etc/swanctl de propósito: o irongate deve carregá-lo a partir do perfil.
COPY --from=pki /pki/ca.pem /etc/test-ca.pem
COPY --from=pki /pki/other-ca.pem /etc/test-other-ca.pem
COPY --from=build /irongate /usr/local/bin/irongate
# tester está no grupo do helper; intruso não. Nenhum dos dois é root nem acessa o VICI.
RUN groupadd --system irongate && useradd -m -G irongate tester && useradd -m intruso
COPY test/e2e/run-tests.sh /run-tests.sh
ENTRYPOINT ["/run-tests.sh"]
