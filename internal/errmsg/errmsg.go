// Package errmsg traduz saídas técnicas (strongSwan, rede) em mensagens claras em português.
package errmsg

import "strings"

type rule struct {
	needles []string
	msg     string
}

// Plugins do strongSwan ausentes: o log também traz EAP_FAILURE, então esta regra vem antes da de senha
// e nunca deve contar como senha errada (a senha salva não pode ser descartada por isso).
var pluginNeedles = []string{"EAP_NAK", "not supported, sending", "loading EAP_MSCHAPV2 method failed"}

var authNeedles = []string{"EAP_FAILURE", "authentication failed", "AUTH_FAILED", "MSCHAPv2 failed", "eap-mschapv2 failed"}

var rules = []rule{
	{pluginNeedles,
		"O strongSwan não tem os plugins de autenticação. Instale 'libcharon-extra-plugins' e 'libcharon-extauth-plugins' e reinicie o serviço."},
	{authNeedles,
		"Senha ou usuário incorretos (ou a senha expirou). Confira os dados e tente de novo."},
	{[]string{"no trusted", "certificate", "issuer certificate"},
		"O certificado do servidor não é confiável. Peça ao TI o certificado da empresa."},
	{[]string{"retransmit", "timeout", "timed out", "no response", "giving up after"},
		"O servidor não respondeu. Verifique sua internet e se o endereço do servidor está certo."},
	{[]string{"NO_PROPOSAL_CHOSEN", "no proposal chosen"},
		"O servidor recusou o tipo de criptografia. Peça ao TI um perfil atualizado."},
	{[]string{"unable to resolve", "no such host", "name resolution", "lookup"},
		"Não consegui encontrar o endereço do servidor. Verifique o endereço e sua internet."},
	{[]string{"connection refused", "dial unix"},
		"O serviço de VPN (strongSwan) não está rodando. Instale e inicie: sudo systemctl start strongswan"},
	{[]string{"permission denied", "access denied"},
		"Sem permissão para controlar a VPN. Execute como administrador ou ajuste as permissões do strongSwan."},
}

// Friendly devolve uma mensagem amigável; sem correspondência, devolve o erro original.
func Friendly(err error) string {
	if err == nil {
		return ""
	}
	low := strings.ToLower(err.Error())
	for _, r := range rules {
		for _, n := range r.needles {
			if strings.Contains(low, strings.ToLower(n)) {
				return r.msg
			}
		}
	}
	return "Falhou: " + err.Error()
}

func matchesAny(low string, needles []string) bool {
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// IsAuthFailure indica falha de credencial (o app deve pedir nova senha).
func IsAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	low := strings.ToLower(err.Error())
	if matchesAny(low, pluginNeedles) {
		return false // problema de instalação, não de senha
	}
	return matchesAny(low, authNeedles)
}
