# Como contribuir com o Iron Gate

Obrigado por querer ajudar. Este guia diz como preparar o ambiente, rodar os testes e propor mudanças.

## Antes de começar

- **Abra uma issue antes de uma mudança grande.** Assim evitamos trabalho duplicado e alinhamos o desenho. Para correções pequenas (erro de digitação, bug óbvio), pode ir direto ao PR.
- **Nunca inclua dados reais da sua empresa** em issues, commits, logs ou exemplos: nome do gateway, IPs, PSK, usuários, senhas, certificados privados. Use `vpn.empresa.com.br` e valores fictícios. Veja "Segurança" abaixo.

## Preparando o ambiente

Você precisa do Go na versão indicada em [go.mod](go.mod) (use o instalador oficial em go.dev; o pacote do `apt` costuma ser mais antigo).

```bash
git clone https://github.com/IronDeploy/IronGate.git
cd IronGate
go build -o irongate ./cmd/irongate
```

Para compilar a janela (Ubuntu 24.04):

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev build-essential pkg-config
go build -tags "desktop,production,webkit2_41" -o irongate-gui ./gui
```

No Ubuntu 22.04 troque `libwebkit2gtk-4.1-dev` por `libwebkit2gtk-4.0-dev` e remova a tag `webkit2_41`. O motor e a CLI só rodam no Linux por enquanto. Você pode desenvolver e rodar os testes unitários no macOS.

Dependências de execução no Linux: `strongswan-swanctl`, `charon-systemd`, `libcharon-extra-plugins`, `libcharon-extauth-plugins` e `openconnect`. Veja o [README](README.md).

## Rodando os testes

```bash
go vet ./...
go vet -tags "desktop,production,webkit2_41" ./gui   # exige as bibliotecas da janela
go test ./...
```

O teste ponta a ponta sobe um servidor strongSwan de teste e conecta o `irongate` nele. Precisa de Docker (os containers rodam como `privileged`):

```bash
docker compose -f test/e2e/docker-compose.yml up --build --abort-on-container-exit --exit-code-from client
```

Alguns testes só rodam no Linux (arquivos `*_linux_test.go`). Se você está em outro sistema, confie no CI para eles.

**Toda mudança de comportamento precisa de teste.** Para o que depende de equipamento real (um FortiGate, por exemplo), escreva o teste que dá para automatizar e diga no PR o que foi e o que não foi testado no equipamento.

## Convenção de commits

Mensagens em português, no formato `tipo: descrição curta`, com o escopo entre parênteses quando ajudar:

```
feat: login único (SAML) no SSL-VPN do FortiGate
fix: não descarta a senha salva quando a PSK está errada (errmsg, app)
docs: explica o campo serverAuth no README
test: cobre a ordem das rodadas de autenticação do IKEv1
refactor: separa a montagem da conexão VICI
chore: atualiza dependências
```

Tipos usados: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`. Prefira commits pequenos e com uma intenção cada.

## Propondo mudanças (pull requests)

1. Crie uma branch a partir de `main`, com um nome que diga o assunto (`fix/psk-incorreta`, `feat/kill-switch`).
2. Faça as mudanças com testes e rode `go vet` e `go test ./...`.
3. Atualize o [README](README.md) e os exemplos em [examples/](examples/) se o comportamento ou o perfil mudou.
4. Abra o PR usando o modelo. Liste as issues que ele fecha (`Closes #123`).
5. Responda à revisão com novos commits; o histórico é ajustado no merge.

## Segurança

O Iron Gate lida com credenciais e roda um serviço privilegiado. Por isso:

- **Senha, PSK, cookie de sessão e código MFA nunca vão a disco** fora do cofre do sistema, **nem em argumento de linha de comando**, **nem em log**. O perfil JSON nunca contém segredo.
- Todo valor que entra em arquivo de configuração ou em comando é validado em `internal/profile` (veja os testes de injeção).
- Mudanças no helper (`internal/helper`) merecem atenção extra: ele roda como root e não pode confiar no que vem do cliente.
- **Não abra issue pública para uma vulnerabilidade.** Siga o [SECURITY.md](SECURITY.md) (relato privado). O que o helper permite e recusa está lá e no [modelo de ameaças](docs/modelo-de-ameacas.md).

## Código de conduta

Ao participar, você concorda em seguir o [Código de Conduta](CODE_OF_CONDUCT.md).

## Licença

Ao contribuir, você concorda que o seu código seja distribuído sob a [Apache License 2.0](LICENSE).
