// Package engine define o contrato dos motores de VPN. Cada perfil escolhe um motor pelo campo "engine".
package engine

import (
	"fmt"

	"github.com/irondeploy/iron-gate/internal/profile"
)

type State string

const (
	Disconnected State = "desconectado"
	Connected    State = "conectado"
)

// Credentials existem só em memória, durante a chamada de Connect.
type Credentials struct {
	Username string
	Password string
	// Cookie é a sessão obtida pelo login único (SAML). Vale como senha: nunca vai a disco nem a argv.
	Cookie string
	// PSK é a chave pré-compartilhada do servidor (serverAuth psk). Só em memória.
	PSK string
}

type Engine interface {
	// Connect sobe o túnel. A senha segue ao motor sem passar por disco nem por argumento de linha de comando.
	Connect(p *profile.Profile, c Credentials) error
	Disconnect(p *profile.Profile) error
	Status(p *profile.Profile) (State, error)
}

// ForProfile escolhe o motor do perfil para o sistema atual.
func ForProfile(p *profile.Profile) (Engine, error) {
	switch p.Engine {
	case profile.EngineIPsecIKEv2:
		return newIPsec()
	case profile.EngineOpenConnect:
		return newOpenConnect()
	}
	return nil, fmt.Errorf("motor %q não suportado", p.Engine)
}
