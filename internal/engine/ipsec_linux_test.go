//go:build linux

package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/profile"
)

func TestConnMessageNaoContemSenha(t *testing.T) {
	p := &profile.Profile{Name: "Empresa X", Engine: profile.EngineIPsecIKEv2, Gateway: "vpn.empresa.com.br", Auth: profile.AuthEAPMSCHAPv2}
	msg := ConnMessage(p, "maria")

	conn, ok := msg["irongate-Empresa_X"].(map[string]any)
	if !ok {
		t.Fatalf("conexão irongate-Empresa_X ausente: %v", msg)
	}
	if conn["version"] != "2" {
		t.Errorf("version = %v, want 2", conn["version"])
	}
	local := conn["local"].(map[string]any)
	if local["auth"] != "eap-mschapv2" || local["eap_id"] != "maria" {
		t.Errorf("local = %v", local)
	}
	for k := range local {
		if strings.Contains(strings.ToLower(k), "pass") || strings.Contains(strings.ToLower(k), "secret") {
			t.Errorf("campo de segredo na configuração: %s", k)
		}
	}
}

func TestNoSession(t *testing.T) {
	if !noSession(errors.New("terminate failed: no matching SAs to terminate found")) {
		t.Error("deveria tratar 'no matching' como sem sessão")
	}
	if noSession(errors.New("permission denied")) {
		t.Error("outros erros não devem ser ignorados")
	}
}
