// Package diag testa o que costuma falhar numa conexão e diz o que fazer.
package diag

import (
	"context"
	"fmt"
	"net"
	"time"
)

type Result struct {
	Check string
	OK    bool
	Hint  string
}

// Run testa DNS e a abertura de socket UDP 500/4500 (IKE). UDP não confirma resposta do servidor.
func Run(ctx context.Context, gateway string) []Result {
	var out []Result

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, gateway)
	if err != nil || len(addrs) == 0 {
		out = append(out, Result{"DNS", false, "Não encontrei o endereço " + gateway + ". Confira o endereço no perfil e sua internet."})
		return out
	}
	out = append(out, Result{"DNS", true, fmt.Sprintf("%s -> %s", gateway, addrs[0])})

	for _, port := range []string{"500", "4500"} {
		c, err := net.DialTimeout("udp", net.JoinHostPort(addrs[0], port), 3*time.Second)
		if err != nil {
			out = append(out, Result{"UDP " + port, false, "Não consegui enviar para a porta " + port + ". Sua rede ou firewall pode estar bloqueando VPN."})
			continue
		}
		c.Close()
		out = append(out, Result{"UDP " + port, true, "porta acessível localmente (UDP não confirma resposta do servidor)"})
	}
	return out
}
