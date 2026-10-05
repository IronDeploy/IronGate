package errmsg

import (
	"errors"
	"strings"
	"testing"
)

func TestFriendly(t *testing.T) {
	cases := map[string]string{
		"received EAP_FAILURE":           "Senha",
		"retransmit giving up":           "não respondeu",
		"dial unix /var/run/charon.vici": "strongSwan",
		// Regressões: erros que não são do strongSwan não podem virar "serviço parado".
		"vici: command failed: establishing CHILD_SA failed": "Falhou:",
		"open /x/perfil.json: no such file or directory":     "Falhou:",
	}
	for in, want := range cases {
		if got := Friendly(errors.New(in)); !strings.Contains(got, want) {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if !IsAuthFailure(errors.New("EAP_FAILURE")) {
		t.Error("deveria ser falha de autenticação")
	}
}

func TestPluginAusenteNaoEhSenhaErrada(t *testing.T) {
	// Log real de um cliente sem o plugin eap-identity: traz EAP_FAILURE junto.
	err := errors.New("vici: command failed: EAP_IDENTITY not supported, sending EAP_NAK; received EAP_FAILURE, EAP authentication failed")
	if got := Friendly(err); !strings.Contains(got, "libcharon-extra-plugins") {
		t.Errorf("mensagem = %q", got)
	}
	if IsAuthFailure(err) {
		t.Error("plugin ausente não pode descartar a senha salva")
	}
	if !IsAuthFailure(errors.New("received EAP_FAILURE, EAP authentication failed")) {
		t.Error("senha errada de verdade deve continuar contando")
	}
}
