#!/bin/sh
# Roda os cenários do irongate contra o servidor de teste. Sai com erro no primeiro que falhar.
export HOME=/root XDG_CONFIG_HOME=/root/.config
fail() { echo "FALHOU: $*"; exit 1; }

/usr/lib/ipsec/charon &
for i in $(seq 1 30); do swanctl --stats >/dev/null 2>&1 && break; sleep 1; done
export IRONGATE_DEBUG=1
for i in $(seq 1 30); do getent hosts gateway >/dev/null && break; sleep 1; done

mkdir -p /test
# O CA vai dentro do perfil (como o TI faria), não em /etc/swanctl.
ca=$(awk 'BEGIN{ORS="\\n"} 1' /etc/test-ca.pem)
printf '{"name":"Empresa X","engine":"ipsec-ikev2","gateway":"gateway","auth":"eap-mschapv2","allowSavePassword":true,"caCert":"%s"}' "$ca" > /test/perfil.json
irongate import /test/perfil.json || fail "import"

echo "== senha errada"
out=$(printf 'maria\nerrada\nn\n' | irongate connect "Empresa X" 2>&1) && fail "senha errada deveria falhar"
echo "$out"
echo "$out" | grep -q "Erro: Senha ou usuário incorretos" || fail "mensagem de senha incorreta ausente"

echo "== senha correta"
printf 'maria\nsenha123\nu\n' | irongate connect "Empresa X" || fail "connect"
irongate status "Empresa X" | grep -q "conectado" || fail "status deveria ser conectado"
swanctl --list-sas | grep -q ESTABLISHED || fail "SA não estabelecida"
ping -c 1 -W 3 10.10.10.1 >/dev/null 2>&1 || echo "(aviso: ping ao IP do túnel não respondeu)"

echo "== desconectar"
irongate disconnect "Empresa X" || fail "disconnect"
irongate status "Empresa X" | grep -q "desconectado" || fail "status deveria ser desconectado"
irongate disconnect "Empresa X" || fail "disconnect sem sessão deveria ser ok"

echo "== reconectar lembrando só o usuário (sem cofre no container)"
printf 'senha123\nn\n' | irongate connect "Empresa X" || fail "reconectar com usuário salvo"
irongate status "Empresa X" | grep -q "conectado" || fail "status deveria ser conectado"
irongate disconnect "Empresa X" || fail "disconnect"
grep -rq "senha123" /root/.config 2>/dev/null && fail "senha gravada em arquivo"

echo "== esquecer credenciais"
irongate forget "Empresa X" || fail "forget"
[ -z "$(ls /root/.config/iron-gate/users 2>/dev/null)" ] || fail "usuário não foi esquecido"

echo "== usuário comum: sem acesso direto ao strongSwan, mas conecta pelo helper"
[ "$(stat -c %a /var/run/charon.vici)" = "770" ] || fail "o socket VICI deveria ser 770 (só root)"
runuser -u tester -- swanctl --stats >/dev/null 2>&1 && fail "usuário comum não deveria alcançar o socket VICI"
irongate helper &
for i in $(seq 1 10); do [ -S /run/irongate/helper.sock ] && break; sleep 1; done
as() { u=$1; shift; runuser -u "$u" -- env HOME=/home/$u XDG_CONFIG_HOME=/home/$u/.config IRONGATE_DEBUG=1 "$@"; }
as tester irongate import /test/perfil.json || fail "import (tester)"
printf 'maria\nsenha123\nn\n' | as tester irongate connect "Empresa X" || fail "connect pelo helper"
as tester irongate status "Empresa X" | grep -q "conectado" || fail "status pelo helper"
swanctl --list-sas | grep -q ESTABLISHED || fail "SA não estabelecida pelo helper"
as tester irongate disconnect "Empresa X" || fail "disconnect pelo helper"
as tester irongate status "Empresa X" | grep -q "desconectado" || fail "status deveria ser desconectado"

echo "== senha errada pelo helper"
out=$(printf 'maria\nerrada\nn\n' | as tester irongate connect "Empresa X" 2>&1) && fail "senha errada deveria falhar"
echo "$out" | grep -q "Erro: Senha ou usuário incorretos" || fail "mensagem de senha incorreta pelo helper"

echo "== o CA de um perfil não vale para os outros perfis (nem depois de desconectar)"
# O perfil "Empresa X" traz o CA e acabou de conectar e desconectar. Um perfil sem CA, para o mesmo servidor,
# não pode herdar essa confiança: sem isso, o caCert não restringiria nada.
printf '{"name":"Sem CA","engine":"ipsec-ikev2","gateway":"gateway","auth":"eap-mschapv2","allowSavePassword":false}' > /test/sem-ca.json
as tester irongate import /test/sem-ca.json || fail "import (sem CA)"
out=$(printf 'maria\nsenha123\nn\n' | as tester irongate connect "Sem CA" 2>&1) && fail "perfil sem CA conectou: o CA de outro perfil vazou"
echo "$out" | grep -q "Erro: O certificado do servidor não é confiável" || fail "mensagem de certificado ausente: $out"
echo "$out" | grep -q "Senha ou usuário incorretos" && fail "certificado não confiável foi tratado como senha errada"
swanctl --list-authorities 2>/dev/null | grep -q irongate && fail "autoridade do perfil ficou carregada depois de desconectar"

echo "== o CA do servidor carregado no daemon não vale para um perfil que confia em outro CA"
# Com o CA do servidor confiável para todo o daemon (como fica enquanto outro perfil está conectado), o perfil
# "CA errado", que confia só em outro CA, precisa falhar. Não dá para conectar os dois pela CLI: o app bloqueia
# a segunda conexão, então o CA entra direto no daemon.
other=$(awk 'BEGIN{ORS="\\n"} 1' /etc/test-other-ca.pem)
printf '{"name":"CA errado","engine":"ipsec-ikev2","gateway":"gateway","auth":"eap-mschapv2","allowSavePassword":false,"caCert":"%s"}' "$other" > /test/ca-errado.json
as tester irongate import /test/ca-errado.json || fail "import (CA errado)"
mkdir -p /etc/swanctl/x509ca && cp /etc/test-ca.pem /etc/swanctl/x509ca/test-ca.pem
swanctl --load-creds >/dev/null || fail "load-creds (CA do servidor)"
out=$(printf 'maria\nsenha123\nn\n' | as tester irongate connect "CA errado" 2>&1) && fail "o CA do daemon validou o servidor para um perfil que confia em outro CA"
echo "$out" | grep -q "Erro: O certificado do servidor não é confiável" || fail "mensagem de certificado ausente: $out"
rm -f /etc/swanctl/x509ca/test-ca.pem
swanctl --load-creds --clear >/dev/null || fail "limpar credenciais"

echo "== gateway por IP: o serverId diz o nome que o certificado apresenta"
ip=$(getent hosts gateway | awk '{print $1}')
ca=$(awk 'BEGIN{ORS="\\n"} 1' /etc/test-ca.pem)
printf '{"name":"Por IP","engine":"ipsec-ikev2","gateway":"%s","auth":"eap-mschapv2","allowSavePassword":false,"caCert":"%s"}' "$ip" "$ca" > /test/por-ip.json
printf '{"name":"Por IP com nome","engine":"ipsec-ikev2","gateway":"%s","serverId":"gateway","auth":"eap-mschapv2","allowSavePassword":false,"caCert":"%s"}' "$ip" "$ca" > /test/por-ip-nome.json
as tester irongate import /test/por-ip.json || fail "import (por IP)"
as tester irongate import /test/por-ip-nome.json || fail "import (por IP com nome)"
out=$(printf 'maria\nsenha123\nn\n' | as tester irongate connect "Por IP" 2>&1) && fail "conectar por IP sem serverId deveria falhar"
echo "$out" | grep -q "Erro: O servidor recusou a identificação" || fail "mensagem de identidade ausente: $out"
echo "$out" | grep -q "Senha ou usuário incorretos" && fail "recusa de identidade foi tratada como senha errada"
printf 'maria\nsenha123\nn\n' | as tester irongate connect "Por IP com nome" || fail "conectar por IP com serverId deveria funcionar"
as tester irongate status "Por IP com nome" | grep -q "conectado" || fail "status por IP com serverId"
as tester irongate disconnect "Por IP com nome" || fail "disconnect por IP com serverId"

echo "== usuário fora do grupo recebe orientação clara"
as intruso irongate import /test/perfil.json || fail "import (intruso)"
out=$(as intruso irongate status "Empresa X" 2>&1) && fail "intruso não deveria conseguir"
echo "$out" | grep -q "saia da sessão" || fail "mensagem de permissão ausente: $out"

echo "TUDO OK"
