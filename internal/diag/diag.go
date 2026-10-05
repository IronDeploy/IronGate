// Package diag testa o que costuma falhar numa conexão e diz o que fazer.
package diag

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strconv"
	"time"

	"github.com/irondeploy/iron-gate/internal/profile"
)

type Result struct {
	Check string
	OK    bool
	Hint  string
}

// Run testa o DNS e a porta do perfil: TCP no SSL-VPN (openconnect) e UDP 500/4500 no IKE.
// UDP não confirma resposta do servidor; TCP confirma que a porta aceita conexão.
func Run(ctx context.Context, p *profile.Profile) []Result {
	gateway := p.Gateway
	var out []Result

	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, gateway)
	if err != nil || len(addrs) == 0 {
		out = append(out, Result{"DNS", false, "Não encontrei o endereço " + gateway + ". Confira o endereço no perfil e sua internet."})
		return out
	}
	out = append(out, Result{"DNS", true, fmt.Sprintf("%s -> %s", gateway, addrs[0])})

	out = append(out, localChecks(p)...)

	if p.Engine == profile.EngineOpenConnect {
		port := "443"
		if p.Port != 0 {
			port = strconv.Itoa(p.Port)
		}
		c, err := net.DialTimeout("tcp", net.JoinHostPort(addrs[0], port), 5*time.Second)
		if err != nil {
			return append(out, Result{"TCP " + port, false, "Não consegui abrir a porta " + port + " do servidor. Confira a porta no perfil; sua rede ou firewall pode estar bloqueando."})
		}
		c.Close()
		return append(out, Result{"TCP " + port, true, "a porta do servidor aceita conexão"})
	}

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

// localChecks confere o que precisa estar instalado e rodando neste computador para o motor do perfil.
func localChecks(p *profile.Profile) []Result {
	var out []Result
	switch p.Engine {
	case profile.EngineIPsecIKEv2:
		if runtime.GOOS != "linux" {
			return nil
		}
		if r := checkPlugins(pluginDirs, requiredPlugins(p)); r != nil {
			out = append(out, *r)
		}
		if r := checkDaemons("/proc"); r != nil {
			out = append(out, *r)
		}
	case profile.EngineOpenConnect:
		if _, err := exec.LookPath("openconnect"); err != nil {
			out = append(out, Result{"openconnect", false, "O openconnect não está instalado. Instale: sudo apt install openconnect"})
		} else {
			out = append(out, Result{"openconnect", true, "instalado"})
		}
	}
	return out
}
