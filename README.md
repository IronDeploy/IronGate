# Iron Gate

A VPN corporativa em um clique.

Estado atual: núcleo Go + CLI da Fase 1 (Linux, FortiGate IPsec/IKEv2 com EAP-MSCHAPv2). Sem interface gráfica ainda.

    go build -o irongate ./cmd/irongate
    ./irongate import examples/empresa-x.json
    ./irongate connect "Empresa X"

## Requisitos (Linux)

- strongSwan em execução (`charon-systemd` e `swanctl`).
- No Debian/Ubuntu, instale também `libcharon-extauth-plugins`: é ele que fornece o `eap-mschapv2`. Sem ele o servidor recusa o login.
- Secret Service (GNOME Keyring, KWallet) para salvar credenciais. Sem ele o app não grava a senha.

## Perfil

Perfis nunca contêm senha; a senha vai ao strongSwan pelo socket VICI, sem arquivo nem argv.
Veja [examples/empresa-x.json](examples/empresa-x.json).

| Campo | Descrição |
|---|---|
| `name` | Nome do perfil |
| `engine` | Motor (hoje só `ipsec-ikev2`) |
| `gateway` | Endereço do servidor VPN |
| `auth` | Autenticação (hoje só `eap-mschapv2`) |
| `username` | Opcional: usuário fixo |
| `allowSavePassword` | `false` impede o app de salvar a senha |
| `caCert` | Opcional: certificado (PEM) da autoridade que assinou o certificado do servidor. O app o carrega no strongSwan só em memória. Sem ele vale o que o sistema já confia |

## Testes

    go test ./...
    docker compose -f test/e2e/docker-compose.yml up --build --abort-on-container-exit --exit-code-from client

O segundo comando sobe um servidor strongSwan de teste e conecta o `irongate` nele. Precisa de Docker (os containers rodam como `privileged`).
Para ver o erro técnico por trás de uma mensagem, rode com `IRONGATE_DEBUG=1`.

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
