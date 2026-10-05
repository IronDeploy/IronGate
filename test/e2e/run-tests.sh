#!/bin/sh
# Roda os cenários do irongate contra o servidor de teste. Sai com erro no primeiro que falhar.
export HOME=/root XDG_CONFIG_HOME=/root/.config
fail() { echo "FALHOU: $*"; exit 1; }

/usr/lib/ipsec/charon &
for i in $(seq 1 30); do swanctl --stats >/dev/null 2>&1 && break; sleep 1; done
swanctl --load-creds || fail "carregar CA"
export IRONGATE_DEBUG=1
for i in $(seq 1 30); do getent hosts gateway >/dev/null && break; sleep 1; done

irongate import /test/perfil.json || fail "import"
sed -i 's/vpn.empresa.com.br/gateway/' /root/.config/iron-gate/profiles/*.json

echo "== senha errada"
out=$(printf 'maria\nerrada\nn\n' | irongate connect "Empresa X" 2>&1) && fail "senha errada deveria falhar"
echo "$out"
echo "$out" | grep -q "Erro: Senha ou usuário incorretos" || fail "mensagem de senha incorreta ausente"

echo "== senha correta"
printf 'maria\nsenha123\nn\n' | irongate connect "Empresa X" || fail "connect"
irongate status "Empresa X" | grep -q "conectado" || fail "status deveria ser conectado"
swanctl --list-sas | grep -q ESTABLISHED || fail "SA não estabelecida"
ping -c 1 -W 3 10.10.10.1 >/dev/null 2>&1 || echo "(aviso: ping ao IP do túnel não respondeu)"

echo "== desconectar"
irongate disconnect "Empresa X" || fail "disconnect"
irongate status "Empresa X" | grep -q "desconectado" || fail "status deveria ser desconectado"
irongate disconnect "Empresa X" || fail "disconnect sem sessão deveria ser ok"

echo "TUDO OK"
