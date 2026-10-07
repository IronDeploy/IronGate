# Política de segurança

O Iron Gate guarda credenciais de VPN e roda um serviço privilegiado (o *helper*). Levamos relatos de segurança a sério.

## Versões com correção

O projeto está em desenvolvimento (0.x). Só a versão mais recente da branch `main` recebe correções.

## Como relatar uma vulnerabilidade

**Não abra uma issue pública.** Use o relato privado do GitHub:

> [Relatar uma vulnerabilidade](https://github.com/IronDeploy/IronGate/security/advisories/new)

Inclua, sem dados reais de nenhuma empresa (gateways, IPs, PSK, usuários, senhas, certificados privados):

- a versão (ou o commit) e o sistema operacional;
- o que acontece e o que deveria acontecer;
- os passos para reproduzir, de preferência com um perfil de teste;
- o impacto que você enxerga.

### O que esperar

- **Resposta inicial em até 7 dias corridos** (é uma meta, não uma garantia: o projeto é mantido por poucas pessoas).
- Confirmamos o problema, combinamos com você um prazo razoável de correção e publicamos o aviso junto com a correção, creditando quem relatou (se você quiser).
- Se não concordarmos que é uma vulnerabilidade, explicamos o motivo.

## O que conta como vulnerabilidade

Por exemplo:

- um usuário comum (fora do grupo `irongate`) ou um membro do grupo conseguir **executar código como root** ou ler arquivos que não deveria pelo helper;
- **vazamento de senha, PSK, cookie de sessão ou código MFA** (em arquivo, em argumento de linha de comando, em log, em mensagem de erro);
- contornar a validação do perfil de modo que um valor chegue sem validar a um arquivo de configuração ou a um comando;
- o CA ou a confiança de um perfil valer para outro;
- o helper aceitar uma operação que não está na lista abaixo.

Fora do escopo deste projeto (relate a quem mantém o componente): falhas do próprio strongSwan, do openconnect, do NetworkManager ou do sistema operacional.

## O que o helper permite e o que recusa

Resumo. O detalhe, com os atacantes considerados e os riscos conhecidos, está no [modelo de ameaças](docs/modelo-de-ameacas.md).

O helper roda como root e só atende por um socket Unix (`/run/irongate/helper.sock`, modo `0660`, grupo `irongate`). **Estar no grupo não dá root, mas dá poder sobre a rede da máquina.**

**Um membro do grupo `irongate` consegue:**

- conectar, desconectar e consultar o estado de **qualquer perfil válido**, com **qualquer servidor, CA, pin de certificado ou PSK**, o que pode redirecionar o tráfego da máquina para um servidor escolhido por ele;
- no IPsec, receber do servidor endereço virtual, DNS e rotas; no `openconnect`, fazer o script padrão de rotas e DNS rodar como root com dados vindos do servidor.

**O helper recusa:**

- perfil com campo desconhecido, com senha dentro, com valor fora do formato esperado (nome, gateway, protocolo, propostas, pin, ID local) ou com chave privada no `caCert`;
- qualquer operação além de conectar, desconectar e consultar o estado;
- configuração que o cliente escolha livremente: o helper monta sozinho a mensagem do strongSwan e **não aceita** `updown`, comandos, scripts nem chaves arbitrárias;
- devolver segredos: não existe operação para ler senha, PSK ou cookie de volta.

**O helper não faz (hoje):** identificar o processo que fala com o socket (vale só a permissão do grupo), limitar para onde se conecta, limitar conexões simultâneas ou registrar as operações.

Por isso, em uma máquina com vários usuários, **o grupo `irongate` deve ter só quem é de confiança para a rede**.

## Revisão

Este documento e o helper foram escritos por quem desenvolve o projeto e **ainda não passaram por auditoria independente**.
