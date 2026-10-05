//go:build linux

package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/irondeploy/iron-gate/internal/profile"
	"github.com/strongswan/govici/vici"
)

type ipsec struct{}

func newIPsec() (Engine, error) { return &ipsec{}, nil }

// ConnMessage monta a conexão IKEv2 + EAP-MSCHAPv2 no formato VICI. Não contém senha.
func ConnMessage(p *profile.Profile, username string) map[string]any {
	child := p.ConnName()
	return map[string]any{
		p.ConnName(): map[string]any{
			"version":      "2",
			"remote_addrs": []string{p.Gateway},
			"vips":         []string{"0.0.0.0"},
			"local": map[string]any{
				"auth":   "eap-mschapv2",
				"eap_id": username,
			},
			"remote": map[string]any{
				"auth": "pubkey",
				"id":   p.Gateway,
			},
			"children": map[string]any{
				child: map[string]any{
					"remote_ts":    []string{"0.0.0.0/0"},
					"start_action": "none",
				},
			},
		},
	}
}

func (*ipsec) Connect(p *profile.Profile, c Credentials) error {
	s, err := vici.NewSession()
	if err != nil {
		return fmt.Errorf("vici: %w", err)
	}
	defer s.Close()

	if p.CACert != "" {
		// Confiança só em memória, sem escrever em /etc/swanctl.
		cert, err := vici.MarshalMessage(map[string]any{"type": "X509", "flag": "CA", "data": p.CACert})
		if err != nil {
			return err
		}
		if err := check(s.CommandRequest("load-cert", cert)); err != nil {
			return err
		}
	}

	conn, err := vici.MarshalMessage(ConnMessage(p, c.Username))
	if err != nil {
		return err
	}
	if err := check(s.CommandRequest("load-conn", conn)); err != nil {
		return err
	}

	// A senha vai direto pelo socket VICI (memória), sem arquivo e sem argv.
	secret, err := vici.MarshalMessage(map[string]any{
		"id":     "irongate-" + p.ConnName(),
		"type":   "EAP",
		"data":   c.Password,
		"owners": []string{c.Username},
	})
	if err != nil {
		return err
	}
	if err := check(s.CommandRequest("load-shared", secret)); err != nil {
		return err
	}
	// Remove o segredo do strongSwan ao terminar, com sucesso ou não: o túnel já negociou (ou falhou).
	defer func() {
		del, _ := vici.MarshalMessage(map[string]any{"id": "irongate-" + p.ConnName()})
		_, _ = s.CommandRequest("unload-shared", del)
	}()

	init, _ := vici.MarshalMessage(map[string]any{"child": p.ConnName(), "ike": p.ConnName()})
	var logs []string
	for m, err := range s.CallStreaming(context.Background(), "initiate", "control-log", init) {
		if err != nil {
			// O motivo real da falha só aparece no log do charon; anexa para o errmsg traduzir.
			return fmt.Errorf("%w: %s", err, strings.Join(logs, "; "))
		}
		if msg, ok := m.Get("msg").(string); ok {
			logs = append(logs, msg)
		}
	}
	return nil
}

func (*ipsec) Disconnect(p *profile.Profile) error {
	s, err := vici.NewSession()
	if err != nil {
		return err
	}
	defer s.Close()
	m, _ := vici.MarshalMessage(map[string]any{"ike": p.ConnName()})
	if err := check(s.CommandRequest("terminate", m)); err != nil && !noSession(err) {
		return err
	}
	unl, _ := vici.MarshalMessage(map[string]any{"name": p.ConnName()})
	_, _ = s.CommandRequest("unload-conn", unl)
	return nil
}

func (*ipsec) Status(p *profile.Profile) (State, error) {
	s, err := vici.NewSession()
	if err != nil {
		return Disconnected, err
	}
	defer s.Close()
	m, _ := vici.MarshalMessage(map[string]any{"ike": p.ConnName()})
	msgs, err := s.StreamedCommandRequest("list-sas", "list-sa", m)
	if err != nil {
		return Disconnected, err
	}
	if len(msgs) > 0 {
		return Connected, nil
	}
	return Disconnected, nil
}

// noSession indica que não havia conexão ativa para encerrar, o que não é um erro para o usuário.
func noSession(err error) bool {
	return strings.Contains(err.Error(), "no matching")
}

func check(m *vici.Message, err error) error {
	if err != nil {
		return err
	}
	return m.Err()
}
