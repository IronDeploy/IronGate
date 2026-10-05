# Iron Gate

A VPN corporativa em um clique.

Estado atual: núcleo Go + CLI da Fase 1 (Linux, FortiGate IPsec/IKEv2 com EAP-MSCHAPv2). Sem interface gráfica ainda.

    go build -o irongate ./cmd/irongate
    ./irongate import examples/empresa-x.json
    ./irongate connect "Empresa X"

Requer strongSwan (charon-systemd / swanctl) em execução e Secret Service para salvar credenciais.
Perfis nunca contêm senha; a senha vai ao strongSwan pelo socket VICI, sem arquivo nem argv.
