//go:build linux

package engine

import (
	"errors"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/profile"
	"github.com/strongswan/govici/vici"
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

func TestConnMessagePSKeProposals(t *testing.T) {
	p := &profile.Profile{Name: "X", Engine: profile.EngineIPsecIKEv2, Gateway: "g.exemplo.com", Auth: profile.AuthEAPMSCHAPv2,
		ServerAuth: "psk", IKE: "aes256-sha256-modp2048", ESP: "aes256-sha256"}
	conn := ConnMessage(p, "maria")["irongate-X"].(map[string]any)
	if r := conn["remote"].(map[string]any); r["auth"] != "psk" || r["id"] != "%any" {
		t.Errorf("remote = %v", r)
	}
	if conn["proposals"].([]string)[0] != "aes256-sha256-modp2048" {
		t.Errorf("proposals = %v", conn["proposals"])
	}
}

func TestConnMessageIKEv1RodadasEmOrdem(t *testing.T) {
	p := &profile.Profile{Name: "X", Engine: profile.EngineIPsecIKEv2, Gateway: "g.exemplo.com", Auth: profile.AuthXAuth,
		ServerAuth: "psk", IKEVersion: 1, Aggressive: true, LocalID: "grupo"}
	for i := 0; i < 20; i++ { // o mapa do Go muda de ordem a cada volta; a mensagem não pode
		m, err := connMessage(p, "maria")
		if err != nil {
			t.Fatal(err)
		}
		body := m.Get("irongate-X").(*vici.Message)
		var rounds []string
		for _, k := range body.Keys() {
			if strings.HasPrefix(k, "local") {
				rounds = append(rounds, k)
			}
		}
		if len(rounds) != 2 || rounds[0] != "local-1" || rounds[1] != "local-2" {
			t.Fatalf("rodadas fora de ordem: %v", body.Keys())
		}
		if body.Get("version") != "1" || body.Get("aggressive") != "yes" {
			t.Fatalf("version/aggressive: %v", body.Keys())
		}
		if l2 := body.Get("local-2").(*vici.Message); l2.Get("auth") != "xauth" || l2.Get("xauth_id") != "maria" {
			t.Fatalf("local-2 = %v", l2.Keys())
		}
	}
}

func TestConnMessageUsaServerIDComoIdentidadeDoServidor(t *testing.T) {
	p := &profile.Profile{Name: "X", Engine: profile.EngineIPsecIKEv2, Gateway: "192.0.2.10", Auth: profile.AuthEAPMSCHAPv2}
	remote := func() map[string]any {
		return ConnMessage(p, "maria")["irongate-X"].(map[string]any)["remote"].(map[string]any)
	}
	if remote()["id"] != "192.0.2.10" {
		t.Errorf("sem serverId deveria usar o gateway, veio %v", remote()["id"])
	}
	p.ServerID = "gateway.empresa.com.br"
	if r := remote(); r["id"] != "gateway.empresa.com.br" || r["auth"] != "pubkey" {
		t.Errorf("com serverId, remote = %v", r)
	}
	// O endereço de conexão continua sendo o gateway.
	if addrs := ConnMessage(p, "maria")["irongate-X"].(map[string]any)["remote_addrs"].([]string); addrs[0] != "192.0.2.10" {
		t.Errorf("remote_addrs = %v", addrs)
	}
}

func TestConnMessageRestringeOCAPorConexao(t *testing.T) {
	p := &profile.Profile{Name: "X", Engine: profile.EngineIPsecIKEv2, Gateway: "g.exemplo.com", Auth: profile.AuthEAPMSCHAPv2, CACert: "PEM-DO-CA"}
	remote := ConnMessage(p, "maria")["irongate-X"].(map[string]any)["remote"].(map[string]any)
	if got, _ := remote["cacerts"].([]string); len(got) != 1 || got[0] != "PEM-DO-CA" {
		t.Errorf("cacerts = %v", remote["cacerts"])
	}

	p.CACert = ""
	remote = ConnMessage(p, "maria")["irongate-X"].(map[string]any)["remote"].(map[string]any)
	if _, ok := remote["cacerts"]; ok {
		t.Errorf("perfil sem CA não deve fixar cacerts: %v", remote)
	}

	p.CACert, p.ServerAuth = "PEM-DO-CA", "psk"
	remote = ConnMessage(p, "maria")["irongate-X"].(map[string]any)["remote"].(map[string]any)
	if _, ok := remote["cacerts"]; ok {
		t.Errorf("PSK não usa CA: %v", remote)
	}
}
