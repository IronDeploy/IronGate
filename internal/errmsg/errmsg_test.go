package errmsg

import (
	"errors"
	"strings"
	"testing"
)

func TestFriendly(t *testing.T) {
	cases := map[string]string{
		"received EAP_FAILURE":                     "Senha",
		"retransmit giving up":                     "não respondeu",
		"dial unix /var/run/charon.vici":           "strongSwan",
		"Failed to complete authentication":        "Senha",
		"Failed to open HTTPS connection to vpn.x": "conexão segura",
		"Server certificate verify failed":         "certificado",
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

func TestErrosDoHelper(t *testing.T) {
	if got := Friendly(errors.New("dial unix /run/irongate/helper.sock: connect: permission denied")); !strings.Contains(got, "saia da sessão") {
		t.Errorf("permissão: %q", got)
	}
	if got := Friendly(errors.New("dial unix /run/irongate/helper.sock: connect: no such file or directory")); !strings.Contains(got, "sudo irongate setup") {
		t.Errorf("ausente: %q", got)
	}
}

func TestPSKErradaNaoEhSenhaErrada(t *testing.T) {
	err := errors.New("tried 1 shared key for 'x' - 'y', but MAC mismatched; N(AUTH_FAILED)")
	if IsAuthFailure(err) || !IsPSKFailure(err) {
		t.Error("PSK errada não deve descartar a senha do usuário")
	}
}

func TestCertificadoNaoConfiavelNaoEhSenhaErrada(t *testing.T) {
	// Log real de um servidor de teste com certificado, cliente sem o CA: traz AUTH_FAILED junto.
	err := errors.New(`vici: command failed: no issuer certificate found for "CN=gateway"; issuer is "CN=Test CA"; no trusted RSA public key found for 'gateway'; generating INFORMATIONAL request 2 [ N(AUTH_FAILED) ]`)
	if got := Friendly(err); !strings.Contains(got, "certificado") {
		t.Errorf("mensagem = %q", got)
	}
	if IsAuthFailure(err) {
		t.Error("certificado não confiável não pode descartar a senha salva")
	}
}

func TestRecusaDeIdentidadeNaoEhSenhaErrada(t *testing.T) {
	// Log real: o servidor responde AUTH_FAILED ao primeiro IKE_AUTH, antes de qualquer etapa de EAP.
	err := errors.New("vici: command failed: parsed IKE_AUTH response 1 [ N(AUTH_FAILED) ]; received AUTHENTICATION_FAILED notify error")
	if got := Friendly(err); !strings.Contains(got, "identificação") || !strings.Contains(got, "serverId") {
		t.Errorf("mensagem = %q", got)
	}
	if IsAuthFailure(err) {
		t.Error("recusa de identidade não pode descartar a senha salva")
	}
	// Senha errada de verdade passa por EAP e continua sendo falha de senha.
	senha := errors.New("parsed IKE_AUTH response 1 [ IDr AUTH EAP/REQ/ID ]; EAP-MS-CHAPv2 failed; received EAP_FAILURE")
	if !IsAuthFailure(senha) {
		t.Error("senha errada deveria continuar sendo falha de autenticação")
	}
}
