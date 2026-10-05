//go:build linux

package engine

import (
	"fmt"

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

	init, _ := vici.MarshalMessage(map[string]any{"child": p.ConnName(), "ike": p.ConnName()})
	msgs, err := s.StreamedCommandRequest("initiate", "control-log", init)
	if err != nil {
		return err
	}
	// Remove o segredo do strongSwan; o túnel já negociou (ou falhou).
	del, _ := vici.MarshalMessage(map[string]any{"id": "irongate-" + p.ConnName()})
	_, _ = s.CommandRequest("unload-shared", del)

	for _, m := range msgs {
		if e := m.Err(); e != nil {
			return e
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
	if err := check(s.CommandRequest("terminate", m)); err != nil {
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

func check(m *vici.Message, err error) error {
	if err != nil {
		return err
	}
	return m.Err()
}
