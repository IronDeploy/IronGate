# Modelo de ameaças do Iron Gate

Descreve o que o Iron Gate protege, de quem, e onde os limites estão. Vale para o Linux (a única plataforma suportada hoje) e para a versão em desenvolvimento 0.x. Foi escrito a partir do código, e o que não foi verificado está marcado como tal. A política de divulgação de vulnerabilidades está no [SECURITY.md](../SECURITY.md).

## O que se protege

| Ativo | Por quê importa |
|---|---|
| Usuário e senha da VPN | Dão acesso à rede da empresa |
| Chave pré-compartilhada (PSK) | Autentica o servidor para todos os usuários do perfil |
| Cookie de sessão do login único (SAML) | Vale como senha enquanto a sessão durar |
| Código MFA/OTP | **Nunca é salvo** |
| O tráfego da máquina | A VPN decide para onde ele vai |
| O que roda como root | O helper, o strongSwan e o openconnect |
| Perfis | Não têm segredos, mas revelam gateway e CA da empresa |

## Componentes e fronteiras

```
[janela / CLI]  --socket Unix, 0660, grupo irongate-->  [helper (root)]  -->  [strongSwan via VICI / openconnect]  -->  servidor VPN
 (seu usuário)                                            valida e monta        (root)                                (rede)
      |
      +--> cofre do sistema (Secret Service): senhas e PSK
```

Três fronteiras importam: **usuário comum → helper** (o socket), **helper → strongSwan/openconnect** (o que o helper deixa passar) e **máquina → servidor VPN** (a rede).

## Quem é confiável

- **Root** e o sistema operacional.
- **Quem emite o perfil e o servidor VPN da empresa**, dentro do que o perfil diz.
- **Membros do grupo `irongate`**: confiáveis *para a rede da máquina*. Eles não ganham root, mas podem conectar a VPN a qualquer servidor (ver "O que o helper permite").

## Atacantes considerados

| # | Atacante | O que tentaria |
|---|---|---|
| 1 | Usuário local **fora** do grupo | Usar o helper, ler segredos de outro usuário, alcançar o socket do strongSwan |
| 2 | Usuário local **no** grupo, mal-intencionado | Virar root pelo helper; redirecionar o tráfego da máquina; ler segredos dos outros |
| 3 | Servidor VPN malicioso ou comprometido, ou ataque na rede (MITM) | Fingir ser o servidor; mandar rotas e DNS maliciosos; entregar dados que viram entrada de um script de root |
| 4 | Perfil malicioso (arquivo recebido por e-mail ou chat) | Injetar valores em arquivos de configuração ou comandos; carregar uma CA hostil |
| 5 | Outro processo local durante o login único (SAML) | Ocupar a porta local e receber o retorno do login |
| 6 | Quem vê logs, mensagens de erro e issues públicas | Achar segredos ou dados da empresa |

## Fora do escopo

- **Root comprometido** ou kernel comprometido.
- **Malware rodando como o mesmo usuário**: ele alcança o cofre já aberto e a memória do processo.
- Vulnerabilidades do **strongSwan, do openconnect, do NetworkManager** e do sistema (relate a quem mantém).
- Ataques físicos e engenharia social.
- Falhas de MFA do servidor.

## O que o helper permite e o que recusa

**Membro do grupo consegue:**
- conectar, desconectar e consultar o estado de qualquer perfil válido;
- escolher **qualquer servidor, CA, pin de certificado ou PSK**: isso pode redirecionar o tráfego da máquina para um servidor escolhido por ele;
- no IPsec, receber do servidor endereço virtual, DNS e rotas (túnel completo `0.0.0.0/0` por padrão);
- no `openconnect`, fazer o script padrão de rotas e DNS rodar **como root** com dados que vêm do servidor (endereços, rotas, DNS).

**O helper recusa:**
- perfil com campo desconhecido, com senha dentro, com valor fora do formato ou com chave privada no `caCert` (validação estrita em `internal/profile`, a mesma na janela, na CLI e no helper);
- qualquer operação além de conectar, desconectar e consultar o estado;
- configuração livre: o helper monta sozinho a mensagem do strongSwan e **não aceita** `updown`, comandos ou scripts; os argumentos do `openconnect` vêm só de campos validados, com `--` antes do gateway;
- devolver segredos: não existe operação de leitura.

**O helper não faz hoje:**
- identificar o processo cliente (vale só a permissão `0660` do grupo);
- limitar destinos, rotas ou conexões simultâneas;
- registrar as operações no journal nem encerrar por inatividade (issue #21).

## Como os segredos circulam

| Segredo | Caminho | Onde nunca vai |
|---|---|---|
| Senha | Digitada na janela ou CLI (memória) → helper (JSON pelo socket local) → strongSwan (VICI, memória) ou openconnect (entrada padrão). Só vai ao **cofre do sistema** se o usuário escolher lembrar | Arquivo em disco, argumento de linha de comando, log. Sem cofre, a senha não é gravada |
| PSK | Cadastrada no formulário → cofre → helper → VICI (memória); removida do strongSwan ao fim da conexão | Arquivo do perfil, argumento, log |
| Cookie SAML | Obtido no navegador → entrada padrão do openconnect | Arquivo, argumento |
| Código MFA | Digitado quando pedido | Qualquer lugar: nunca é salvo |
| Usuário | Cofre; sem cofre, arquivo `0600` no diretório de configuração (não é segredo) | |
| CA, pin do certificado | No perfil (informação pública). No `openconnect`, uma cópia temporária `0600` em `/run/irongate`, apagada após a conexão | |

## Controles que existem

- **Socket do strongSwan não é liberado ao usuário.** O VICI equivale a root (scripts `updown`); só o helper fala com ele. (E2E confere que um usuário comum não alcança o socket.)
- **Helper com API mínima**, socket `0660` do grupo `irongate`, leitura limitada a 64 KB com limite de 10 s.
- **Validação estrita e única do perfil**, com testes de injeção.
- **Unidades do systemd endurecidas** (`NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectKernelModules`, `ProtectKernelTunables`, `ProtectControlGroups`, `RestrictSUIDSGID`).
- **Binário do serviço em local confiável**: se o binário estiver fora de um diretório de sistema (`/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/usr/local/sbin`), o `setup` o copia para `/usr/local/bin`, porque um serviço root não pode executar um arquivo que o usuário consiga trocar.
- **CA por perfil**: carregado como autoridade do perfil e descarregado ao desconectar, coberto por teste E2E.
- **Mensagens de erro separam o motivo** (senha, PSK, certificado, identidade do servidor), para que um erro de rede não leve a descartar a senha salva.
- **Janela sem conteúdo remoto**: a interface só carrega arquivos locais.

## Riscos conhecidos e limites

1. **O grupo `irongate` equivale a poder sobre a rede** da máquina (acima). Em máquina com vários usuários, o grupo precisa ser de pessoas de confiança. Issue #53.
2. **Servidor malicioso influencia um script de root.** No `openconnect`, endereços, rotas e DNS entregues pelo servidor viram entrada do script padrão, que roda como root. Issues #53 e #9.
3. **Porta local previsível no login único.** O retorno do SAML chega em `127.0.0.1:8020` (porta que o FortiGate espera). Outro usuário local que ocupe essa porta antes pode receber o identificador do login e trocá-lo por uma sessão. Ainda **não mitigado**.
4. **Memória.** Senhas passam como `string` em Go, que não pode ser zerada com garantia. Issue #17.
5. **Mesmo usuário.** Malware com o seu usuário alcança o cofre aberto (fora do escopo).
6. **Negação de serviço local.** O helper atende cada conexão em uma goroutine, sem limite de conexões simultâneas (cada uma é limitada a 64 KB e 10 s de leitura).
7. **CA durante a conexão.** Enquanto um perfil está conectado, o CA dele vale para o daemon inteiro; só deixa de valer ao desconectar.
8. **Distribuição.** O pacote `.deb` não é assinado e ainda não há atualização automática (issue #34).
9. **Logs.** O "detalhe técnico" não tem segredos, mas mostra IPs e identidades do servidor (issue #54).
10. **Revogação.** Não foi verificado se o certificado do servidor é conferido contra listas de revogação (CRL ou OCSP).
11. **Sem auditoria independente.** Este documento e o helper foram escritos por quem escreveu o código (issue #9).
