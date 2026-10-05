# Iron Gate

A VPN corporativa em um clique.

Estado atual: Linux, com dois motores: IPsec/IKEv2 com EAP-MSCHAPv2 (strongSwan) e SSL-VPN (openconnect: FortiGate, AnyConnect, GlobalProtect, Pulse, NetScaler, F5 e Array), inclusive FortiGate com login único (SAML) pelo navegador.

    go build -o irongate ./cmd/irongate
    ./irongate import examples/empresa-x.json
    ./irongate connect "Empresa X"

## Instalação (Linux)

O jeito mais simples é o pacote `.deb` (veja "Empacotamento" abaixo):

    sudo apt install ./irongate_0.1.0_arm64.deb

Ele instala as dependências, cria o grupo `irongate`, adiciona você a ele e ativa o serviço de acesso ao strongSwan. **Saia da sessão e entre de novo** para o grupo valer. Para outros usuários: `sudo usermod -aG irongate NOME`.

Sem o pacote (compilando do código-fonte), instale as dependências abaixo e rode uma vez `sudo irongate setup`. Para desfazer, `sudo irongate setup --undo`.

### Dependências

- `strongswan-swanctl` e `charon-systemd` (o strongSwan com a interface VICI). Não deixe o `strongswan-starter` rodando junto: são dois daemons disputando o mesmo socket.
- `openconnect` (motor SSL-VPN).
- `libcharon-extra-plugins` (fornece o `eap-identity`) e `libcharon-extauth-plugins` (fornece o `eap-mschapv2`). Sem eles o login falha mesmo com a senha certa.
- Secret Service (GNOME Keyring, KWallet) para salvar a senha. Sem ele o app só lembra o usuário.

### Como o acesso ao strongSwan é protegido

O socket do strongSwan (`/var/run/charon.vici`) equivale a root: quem fala com ele pode definir scripts (`updown`) que o charon executa como administrador. Por isso o Iron Gate **não** libera esse socket para o seu usuário. Em vez disso:

- Um pequeno serviço root (`irongate-helper`, ativado por socket do systemd) atende só três operações: conectar, desconectar e consultar o estado.
- Ele revalida o perfil (campos desconhecidos, senha no perfil e caracteres perigosos são recusados) e monta a configuração sozinho. O cliente não consegue mandar `updown` nem outra opção.
- Só quem está no grupo `irongate` fala com o helper (`/run/irongate/helper.sock`, modo `0660`). Estar no grupo não dá acesso ao VICI.
- A CLI e a janela rodam como o seu usuário comum e usam o helper automaticamente. Como root, falam direto com o strongSwan. `IRONGATE_DIRECT=1` força o acesso direto.

## Interface gráfica (Wails)

A janela fica em [gui/](gui/) e usa a mesma lógica da CLI (`internal/app`). No Ubuntu 24.04:

    sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev build-essential pkg-config
    go build -tags "desktop,production,webkit2_41" -o irongate-gui ./gui
    ./irongate-gui

(No Ubuntu 22.04 troque `libwebkit2gtk-4.1-dev` por `libwebkit2gtk-4.0-dev` e remova a tag `webkit2_41`.)
Para desenvolver com recarga automática: `wails dev -tags webkit2_41` dentro de `gui/`.

## Empacotamento

    packaging/deb/build.sh 0.1.0

Gera `dist/irongate_0.1.0_<arquitetura>.deb` dentro de um container Ubuntu 22.04 (a arquitetura é a do seu Docker; `PLATFORM=linux/amd64` gera amd64, emulado). Defina `MAINTAINER="Nome <email>"` para preencher o campo de mantenedor. O AppImage ainda não existe.

## Perfil

Perfis nunca contêm senha; a senha vai ao strongSwan pelo socket VICI, sem arquivo nem argv.
Veja [examples/empresa-x.json](examples/empresa-x.json).

| Campo | Descrição |
|---|---|
| `name` | Nome do perfil |
| `engine` | Motor: `ipsec-ikev2` (IPsec, IKEv1 e IKEv2) ou `openconnect` (SSL-VPN) |
| `gateway` | Endereço do servidor VPN |
| `auth` | `eap-mschapv2` (IKEv2) ou `xauth` (IKEv1) no IPsec; `password` ou `saml` (openconnect; padrão de cada motor se omitido) |
| `username` | Opcional: usuário fixo |
| `allowSavePassword` | `false` impede o app de salvar a senha |
| `caCert` | Opcional: certificado (PEM) da autoridade que assinou o certificado do servidor. O app o carrega no strongSwan só em memória. Sem ele vale o que o sistema já confia |

Campos do IPsec (`ipsec-ikev2`), equivalentes aos do FortiClient em "VPN IPsec":

| Campo | Descrição |
|---|---|
| `serverAuth` | `cert` (padrão, certificado do servidor) ou `psk` (chave pré-compartilhada). A PSK é pedida na primeira conexão e guardada só no cofre do sistema, nunca no perfil |
| `serverId` | Nome que o certificado do servidor apresenta, quando difere do `gateway` (por exemplo, o gateway é um IP). Só vale com `serverAuth: cert` |
| `ikeVersion` | `2` (padrão, com EAP) ou `1` (exige `serverAuth: psk` e `auth: xauth`) |
| `aggressive` | IKEv1: modo agressivo |
| `localId` | IKEv1: ID de grupo/local (o "ID local" do FortiClient) |
| `ike`, `esp` | Propostas de criptografia, no formato do strongSwan (ex.: `aes256-sha256-modp2048`). Copie dos ajustes avançados do FortiClient |

Exemplos: [IKEv2 com PSK e EAP](examples/fortigate-ipsec-psk-ikev2.json), [IKEv1 com PSK e XAuth](examples/fortigate-ipsec-ikev1-xauth.json).

Campos do motor `openconnect` (SSL-VPN):

| Campo | Descrição |
|---|---|
| `protocol` | Obrigatório: `fortinet`, `anyconnect`, `gp`, `pulse`, `nc`, `f5` ou `array` |
| `port` | Porta do gateway (ex.: 8443 no FortiGate). Sem ela vale a padrão do protocolo |
| `auth` | `password` (usuário e senha) ou `saml` (login único no navegador, só `fortinet`) |
| `authGroup` | Grupo/realm de login (AnyConnect, GlobalProtect) |
| `serverCertPin` | `pin-sha256:...` do certificado do servidor, para quem não tem o `caCert` |
| `samlPort` | Porta local do retorno do login único; padrão 8020 (a mesma do FortiClient) |

Com `auth: saml` o app abre o navegador, você entra com a conta da empresa e ele conclui sozinho: não pede usuário nem senha e nada é salvo. A sessão obtida vai ao openconnect pela entrada padrão, sem arquivo nem argv. Exemplos: [fortigate-ssl-vpn-sso.json](examples/fortigate-ssl-vpn-sso.json), [fortigate-ssl-vpn-senha.json](examples/fortigate-ssl-vpn-senha.json), [anyconnect.json](examples/anyconnect.json).

Ainda não há suporte a código MFA digitado no app (token/TOTP fora do SAML), nem a certificado de cliente.

## Testes

    go test ./...
    docker compose -f test/e2e/docker-compose.yml up --build --abort-on-container-exit --exit-code-from client

O segundo comando sobe um servidor strongSwan de teste e conecta o `irongate` nele. Precisa de Docker (os containers rodam como `privileged`).
Para conectar um cliente de fora (por exemplo, a janela em uma VM), suba só o servidor com as portas IKE publicadas:

    docker compose -f test/e2e/docker-compose.server.yml up --build

O cliente deve resolver o nome `gateway` para o IP desta máquina (uma linha no `/etc/hosts`). Usuário `maria`, senha `senha123`. O CA de teste está dentro da imagem em `/etc/swanctl/x509ca/ca.pem`.

Para ver o erro técnico por trás de uma mensagem, rode com `IRONGATE_DEBUG=1`.

## Licença

Apache License 2.0. Veja [LICENSE](LICENSE).
