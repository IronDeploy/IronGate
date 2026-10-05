//go:build linux

package app

import (
	"fmt"
	"os"

	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/helper"
	"github.com/irondeploy/iron-gate/internal/profile"
)

// defaultEngine: root fala direto com o strongSwan; usuário comum passa pelo helper, que valida tudo.
// IRONGATE_DIRECT=1 força o acesso direto (para quem já liberou o socket VICI por conta própria).
func defaultEngine(p *profile.Profile) (engine.Engine, error) {
	if os.Geteuid() == 0 || os.Getenv("IRONGATE_DIRECT") != "" {
		return engine.ForProfile(p)
	}
	if p.Engine != profile.EngineIPsecIKEv2 && p.Engine != profile.EngineOpenConnect {
		return nil, fmt.Errorf("motor %q não suportado", p.Engine)
	}
	return helper.NewClient(), nil
}
