## O que muda

<!-- Explique em poucas linhas o que o PR faz e por quê. -->

## Issues

<!-- Uma por linha. Closes #123 fecha a issue no merge; Refs #123 só referencia. -->
Closes #

## Como foi testado

- [ ] `go vet ./...` e `go test ./...`
- [ ] E2E (`docker compose -f test/e2e/docker-compose.yml ...`), se mexeu em motor, helper ou perfil
- [ ] Testei na janela ou na CLI, se mexeu na interface

<!-- Diga o que NÃO foi testado em equipamento real (FortiGate, por exemplo). -->

## Checklist

- [ ] Mudança de comportamento tem teste
- [ ] README e `examples/` atualizados, se o perfil ou o uso mudou
- [ ] Nenhum dado real (gateway, IP, PSK, usuário, senha, certificado privado) no código, nos testes ou nos logs
- [ ] Senha, PSK, cookie e código MFA não vão a disco, a argumento de linha de comando nem a log
