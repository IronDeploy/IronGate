//go:build linux

package engine

import (
	"context"
	"errors"
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
	remote := map[string]any{"auth": "pubkey", "id": p.ExpectedServerID()}
	if p.UsesPSK() {
		// O servidor se prova pela PSK. Sem id fixo: o identificador do FortiGate varia (IP, nome ou vazio).
		remote = map[string]any{"auth": "psk", "id": "%any"}
	}
	conn := map[string]any{
		"version":      "2",
		"remote_addrs": []string{p.Gateway},
		"vips":         []string{"0.0.0.0"},
		"local": map[string]any{
			"auth":   "eap-mschapv2",
			"eap_id": username,
		},
		"remote": remote,
	}
	if p.IKE != "" {
		conn["proposals"] = strings.Split(p.IKE, ",")
	}
	ch := map[string]any{"remote_ts": []string{"0.0.0.0/0"}, "start_action": "none"}
	if p.ESP != "" {
		ch["esp_proposals"] = strings.Split(p.ESP, ",")
	}
	conn["children"] = map[string]any{child: ch}
	return map[string]any{p.ConnName(): conn}
}

func (*ipsec) Connect(p *profile.Profile, c Credentials) (retErr error) {
	s, err := vici.NewSession()
	if err != nil {
		return fmt.Errorf("vici: %w", err)
	}
	defer s.Close()

	if p.CACert != "" {
		// O CA entra como autoridade do perfil, só em memória. Diferente de um certificado solto, a
		// autoridade pode ser descarregada: sem isso, o CA de um perfil continuaria confiável para
		// todos os outros depois de desconectar.
		auth, err := vici.MarshalMessage(map[string]any{p.ConnName(): map[string]any{"cacert": p.CACert}})
		if err != nil {
			return err
		}
		if err := check(s.CommandRequest("load-authority", auth)); err != nil {
			return err
		}
		defer func() {
			if retErr != nil { // falhou: não deixa o CA para trás (conectado, ele sai no Disconnect)
				unloadAuthority(s, p)
			}
		}()
	}

	conn, err := connMessage(p, c.Username)
	if err != nil {
		return err
	}
	if err := check(s.CommandRequest("load-conn", conn)); err != nil {
		return err
	}

	// A senha vai direto pelo socket VICI (memória), sem arquivo e sem argv.
	secret, err := vici.MarshalMessage(map[string]any{
		"id":     "irongate-" + p.ConnName(),
		"type":   secretType(p),
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

	if p.UsesPSK() {
		if c.PSK == "" {
			return errors.New("faltou a chave pré-compartilhada (PSK)")
		}
		psk, err := vici.MarshalMessage(map[string]any{"id": "irongate-psk-" + p.ConnName(), "type": "IKE", "data": c.PSK})
		if err != nil {
			return err
		}
		if err := check(s.CommandRequest("load-shared", psk)); err != nil {
			return err
		}
		defer func() {
			del, _ := vici.MarshalMessage(map[string]any{"id": "irongate-psk-" + p.ConnName()})
			_, _ = s.CommandRequest("unload-shared", del)
		}()
	}

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
	unloadAuthority(s, p)
	return nil
}

// unloadAuthority descarrega o CA do perfil (erro ignorado: o perfil pode não ter CA próprio).
func unloadAuthority(s *vici.Session, p *profile.Profile) {
	m, _ := vici.MarshalMessage(map[string]any{"name": p.ConnName()})
	_, _ = s.CommandRequest("unload-authority", m)
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

func secretType(p *profile.Profile) string {
	if p.IKEVersion == 1 {
		return "XAUTH"
	}
	return "EAP"
}

// connMessage devolve a conexão no formato VICI. O IKEv1 usa duas rodadas de autenticação (PSK, depois
// XAuth) que precisam seguir em ordem, e o mapa do Go não a garante: por isso monta a mensagem passo a passo.
func connMessage(p *profile.Profile, username string) (*vici.Message, error) {
	if p.IKEVersion != 1 {
		return vici.MarshalMessage(ConnMessage(p, username))
	}
	section := func(kv ...string) (*vici.Message, error) {
		m := vici.NewMessage()
		for i := 0; i < len(kv); i += 2 {
			if err := m.Set(kv[i], kv[i+1]); err != nil {
				return nil, err
			}
		}
		return m, nil
	}
	local1 := []string{"auth", "psk"}
	if p.LocalID != "" {
		local1 = append(local1, "id", p.LocalID)
	}
	l1, err := section(local1...)
	if err != nil {
		return nil, err
	}
	l2, err := section("auth", "xauth", "xauth_id", username)
	if err != nil {
		return nil, err
	}
	r1, err := section("auth", "psk", "id", "%any")
	if err != nil {
		return nil, err
	}
	child, err := section("start_action", "none")
	if err != nil {
		return nil, err
	}
	_ = child.Set("remote_ts", []string{"0.0.0.0/0"})
	if p.ESP != "" {
		_ = child.Set("esp_proposals", strings.Split(p.ESP, ","))
	}
	children := vici.NewMessage()
	_ = children.Set(p.ConnName(), child)

	body := vici.NewMessage()
	_ = body.Set("version", "1")
	if p.Aggressive {
		_ = body.Set("aggressive", "yes")
	}
	_ = body.Set("remote_addrs", []string{p.Gateway})
	_ = body.Set("vips", []string{"0.0.0.0"})
	if p.IKE != "" {
		_ = body.Set("proposals", strings.Split(p.IKE, ","))
	}
	_ = body.Set("local-1", l1)
	_ = body.Set("local-2", l2)
	_ = body.Set("remote-1", r1)
	_ = body.Set("children", children)

	msg := vici.NewMessage()
	if err := msg.Set(p.ConnName(), body); err != nil {
		return nil, err
	}
	return msg, nil
}
