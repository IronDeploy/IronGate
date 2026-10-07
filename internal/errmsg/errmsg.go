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

// PSK errada: o log também traz AUTH_FAILED, então vem antes da regra de senha e não conta como senha errada.
var pskNeedles = []string{"MAC mismatched", "no shared key found"}

// Certificado do servidor não confiável: o log também traz AUTH_FAILED, então vem antes da regra de senha
// e não conta como senha errada (a senha salva não pode ser descartada por isso).
var certNeedles = []string{"no trusted RSA public key found", "no trusted ECDSA public key found", "no issuer certificate found", "not authenticated by CA"}

// O servidor recusa já na primeira resposta de autenticação, antes de pedir usuário e senha: costuma ser o
// endereço do perfil que não bate com o nome do certificado (por exemplo, o IP em vez do nome). Também traz
// AUTH_FAILED, então vem antes da regra de senha e não conta como senha errada.
var identityNeedles = []string{"response 1 [ N(AUTH_FAILED) ]"}

var authNeedles = []string{"EAP_FAILURE", "authentication failed", "AUTH_FAILED", "MSCHAPv2 failed", "eap-mschapv2 failed",
	"XAuth authentication failed", "Failed to complete authentication", "cookie was rejected"}

var rules = []rule{
	// Helper do Iron Gate (usuário comum): precisa estar instalado e o usuário no grupo.
	{[]string{"helper.sock: connect: permission denied"},
		"Seu usuário ainda não tem acesso ao Iron Gate. Rode 'sudo irongate setup', depois saia da sessão e entre de novo."},
	{[]string{"helper.sock: connect: no such file", "helper.sock: connect: connection refused"},
		"O serviço do Iron Gate não está instalado. Rode 'sudo irongate setup' uma vez para ativá-lo."},
	{pluginNeedles,
		"O strongSwan não tem os plugins de autenticação. Instale 'libcharon-extra-plugins' e 'libcharon-extauth-plugins' e reinicie o serviço."},
	{certNeedles,
		"O certificado do servidor não é confiável. Confira o certificado da empresa (CA) no perfil ou peça o correto ao TI."},
	{identityNeedles,
		"O servidor recusou a identificação antes de pedir a senha. Use no perfil o mesmo nome do certificado do servidor, ou informe esse nome no campo serverId (o nome do servidor no certificado)."},
	{pskNeedles,
		"A chave pré-compartilhada (PSK) está incorreta. Confira com o TI e informe de novo."},
	{authNeedles,
		"Senha ou usuário incorretos (ou a senha expirou). Confira os dados e tente de novo."},
	{[]string{"no trusted", "certificate", "issuer certificate", "verify failed"},
		"O certificado do servidor não é confiável. Peça ao TI o certificado da empresa."},
	{[]string{"Failed to open HTTPS connection", "SSL connection failure"},
		"Não consegui abrir a conexão segura com o servidor. Confira o endereço, a porta e sua internet."},
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

// Friendly devolve uma mensagem amigável; sem correspondência, devolve o erro original
// sem prefixo (a CLI acrescenta o seu "Erro: ").
func Friendly(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "desconecte antes de removê-lo") || strings.Contains(err.Error(), "desconecte antes de conectar outro") {
		return err.Error() // já é uma mensagem para o usuário
	}
	low := strings.ToLower(err.Error())
	for _, r := range rules {
		for _, n := range r.needles {
			if strings.Contains(low, strings.ToLower(n)) {
				return r.msg
			}
		}
	}
	return err.Error()
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
	if matchesAny(low, pluginNeedles) || matchesAny(low, pskNeedles) || matchesAny(low, certNeedles) || matchesAny(low, identityNeedles) {
		return false // instalação, PSK, certificado ou identidade do servidor, não a senha do usuário
	}
	return matchesAny(low, authNeedles)
}

// IsPSKFailure indica que o servidor não aceitou a chave pré-compartilhada.
func IsPSKFailure(err error) bool {
	return err != nil && matchesAny(strings.ToLower(err.Error()), pskNeedles)
}
