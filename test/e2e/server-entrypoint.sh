#!/bin/sh
set -e
# SERVER_MODE=psk troca a configuração para PSK no servidor + EAP no usuário.
[ "$SERVER_MODE" = psk ] && cp /etc/swanctl/server-psk.swanctl.conf /etc/swanctl/swanctl.conf
/usr/lib/ipsec/charon &
for i in $(seq 1 30); do swanctl --stats >/dev/null 2>&1 && break; sleep 1; done
swanctl --load-all
echo "servidor pronto"
wait
