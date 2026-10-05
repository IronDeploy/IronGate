#!/bin/sh
set -e
/usr/lib/ipsec/charon &
for i in $(seq 1 30); do swanctl --stats >/dev/null 2>&1 && break; sleep 1; done
swanctl --load-all
echo "servidor pronto"
wait
