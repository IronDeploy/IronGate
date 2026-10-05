// Package profile lê, valida e guarda perfis de VPN. Um perfil nunca contém senha.
package profile

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	EngineIPsecIKEv2  = "ipsec-ikev2"
	EngineOpenConnect = "openconnect"

	AuthEAPMSCHAPv2 = "eap-mschapv2"
	// AuthXAuth é o usuário e senha do IKEv1 (XAuth), usado com chave pré-compartilhada.
	AuthXAuth    = "xauth"
	AuthPassword = "password"
	// AuthSAML abre o navegador do usuário para o login único (SSO). Só existe para o FortiGate.
	AuthSAML = "saml"
)

// Protocolos que o motor openconnect fala. O valor vai direto para --protocol.
var openConnectProtocols = map[string]bool{
	"fortinet": true, "anyconnect": true, "gp": true, "pulse": true, "nc": true, "f5": true, "array": true,
}

// DefaultSAMLPort é a porta local que o FortiGate espera para devolver o login único ao cliente.
const DefaultSAMLPort = 8020

type Profile struct {
	Name              string `json:"name"`
	Engine            string `json:"engine"`
	Gateway           string `json:"gateway"`
	Auth              string `json:"auth"`
	Username          string `json:"username"`
	AllowSavePassword bool   `json:"allowSavePassword"`
	// CACert é o certificado (PEM) da autoridade que assinou o certificado do servidor. Opcional:
	// sem ele vale o que o strongSwan já confia no sistema. Certificado público, nunca chave privada.
	CACert string `json:"caCert,omitempty"`

	// ServerAuth diz como o servidor se prova ao cliente no ipsec-ikev2: "cert" (padrão, certificado)
	// ou "psk" (chave pré-compartilhada, pedida ao usuário e guardada no cofre, nunca no perfil).
	ServerAuth string `json:"serverAuth,omitempty"`
	// ServerID é o nome que o certificado do servidor apresenta, quando difere do gateway (por exemplo, o
	// gateway é um IP e o certificado foi emitido para um nome). Só vale com serverAuth cert.
	ServerID string `json:"serverId,omitempty"`
	// IKEVersion é 1 ou 2 (padrão 2). O IKEv1 exige serverAuth psk e auth xauth.
	IKEVersion int `json:"ikeVersion,omitempty"`
	// Aggressive liga o modo agressivo do IKEv1 (o FortiClient usa quando não há "main mode").
	Aggressive bool `json:"aggressive,omitempty"`
	// LocalID é o ID de grupo/par local do IKEv1 (campo "ID local" do FortiClient). Opcional.
	LocalID string `json:"localId,omitempty"`
	// IKE e ESP restringem as propostas de criptografia (sintaxe do strongSwan, ex.: aes256-sha256-modp2048).
	IKE string `json:"ike,omitempty"`
	ESP string `json:"esp,omitempty"`

	// Campos do motor openconnect (SSL-VPN). Não valem para ipsec-ikev2.
	Protocol string `json:"protocol,omitempty"` // fortinet, anyconnect, gp, pulse, nc, f5 ou array
	Port     int    `json:"port,omitempty"`     // porta do gateway; 0 usa a padrão do protocolo
	// AuthGroup escolhe o grupo ou realm de login (AnyConnect, GlobalProtect).
	AuthGroup string `json:"authGroup,omitempty"`
	// ServerCertPin fixa o certificado do servidor (pin-sha256:...), para quem não tem o CA da empresa.
	ServerCertPin string `json:"serverCertPin,omitempty"`
	// SAMLPort é a porta local do retorno do login único (só SAML); 0 usa 8020.
	SAMLPort int `json:"samlPort,omitempty"`
}

var (
	nameRe     = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,64}$`)
	localIDRe  = regexp.MustCompile(`^[A-Za-z0-9@._-]{1,64}$`)
	proposalRe = regexp.MustCompile(`^[a-z0-9_-]+(,[a-z0-9_-]+){0,7}$`)
	pinRe      = regexp.MustCompile(`^pin-sha256:[A-Za-z0-9+/]{43}=$`)
	gatewayRe  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$|^[0-9a-fA-F:]+$`)
)

// Parse decodifica um perfil. Campos desconhecidos (inclusive "password") são rejeitados.
func Parse(data []byte) (*Profile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var p Profile
	if err := dec.Decode(&p); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return nil, fmt.Errorf("perfil inválido: %v (perfis não podem conter senha nem campos desconhecidos)", err)
		}
		return nil, fmt.Errorf("perfil inválido: %w", err)
	}
	if p.Engine == "" {
		p.Engine = EngineIPsecIKEv2
	}
	if p.Auth == "" {
		p.Auth = AuthEAPMSCHAPv2
		switch {
		case p.Engine == EngineOpenConnect:
			p.Auth = AuthPassword
		case p.IKEVersion == 1:
			p.Auth = AuthXAuth
		}
	}
	return &p, p.Validate()
}

// Validate garante valores seguros, pois eles entram em arquivos de configuração.
func (p *Profile) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return errors.New("perfil inválido: 'name' deve ter até 64 letras, números, espaço, ponto, hífen ou sublinhado")
	}
	if err := p.validateEngine(); err != nil {
		return err
	}
	if !gatewayRe.MatchString(p.Gateway) {
		return errors.New("perfil inválido: 'gateway' deve ser um nome de host ou IP, sem espaços nem http://")
	}
	if strings.ContainsAny(p.Username, "\r\n\"\\{}#") {
		return errors.New("perfil inválido: 'username' contém caracteres não permitidos")
	}
	if p.CACert != "" {
		if err := validateCA(p.CACert); err != nil {
			return err
		}
	}
	return nil
}

func (p *Profile) validateEngine() error {
	switch p.Engine {
	case EngineIPsecIKEv2:
		switch p.IKEVersion {
		case 0, 2:
			if p.Auth != AuthEAPMSCHAPv2 || p.Aggressive || p.LocalID != "" {
				return fmt.Errorf("perfil inválido: no IKEv2 use auth %s (aggressive e localId são do IKEv1)", AuthEAPMSCHAPv2)
			}
		case 1:
			if p.Auth != AuthXAuth || p.ServerAuth != "psk" {
				return fmt.Errorf("perfil inválido: IKEv1 exige auth %s e serverAuth psk", AuthXAuth)
			}
			if p.LocalID != "" && !localIDRe.MatchString(p.LocalID) {
				return errors.New("perfil inválido: 'localId' contém caracteres não permitidos")
			}
		default:
			return errors.New("perfil inválido: 'ikeVersion' deve ser 1 ou 2")
		}
		switch p.ServerAuth {
		case "", "cert", "psk":
		default:
			return errors.New("perfil inválido: 'serverAuth' deve ser cert ou psk")
		}
		if p.ServerID != "" {
			if !gatewayRe.MatchString(p.ServerID) {
				return errors.New("perfil inválido: 'serverId' deve ser um nome de host ou IP, sem espaços nem http://")
			}
			if p.ServerAuth == "psk" || p.IKEVersion == 1 {
				return errors.New("perfil inválido: 'serverId' só vale com serverAuth cert (com PSK o servidor não é identificado por certificado)")
			}
		}
		for _, v := range []string{p.IKE, p.ESP} {
			if v != "" && !proposalRe.MatchString(v) {
				return errors.New("perfil inválido: 'ike' e 'esp' devem ser propostas do strongSwan, como aes256-sha256-modp2048")
			}
		}
		if p.Protocol != "" || p.Port != 0 || p.AuthGroup != "" || p.ServerCertPin != "" || p.SAMLPort != 0 {
			return fmt.Errorf("perfil inválido: protocol, port, authGroup, serverCertPin e samlPort são do motor %s", EngineOpenConnect)
		}
	case EngineOpenConnect:
		if p.ServerAuth != "" || p.ServerID != "" || p.IKE != "" || p.ESP != "" || p.IKEVersion != 0 || p.Aggressive || p.LocalID != "" {
			return fmt.Errorf("perfil inválido: serverAuth, serverId, ikeVersion, aggressive, localId, ike e esp são do motor %s", EngineIPsecIKEv2)
		}
		if !openConnectProtocols[p.Protocol] {
			return errors.New("perfil inválido: 'protocol' deve ser fortinet, anyconnect, gp, pulse, nc, f5 ou array")
		}
		switch p.Auth {
		case AuthPassword:
		case AuthSAML:
			if p.Protocol != "fortinet" {
				return errors.New("perfil inválido: login único (saml) só é suportado no protocolo fortinet")
			}
		default:
			return fmt.Errorf("perfil inválido: autenticação %q não existe no motor %s (disponível: %s, %s)", p.Auth, p.Engine, AuthPassword, AuthSAML)
		}
		if p.Port < 0 || p.Port > 65535 {
			return errors.New("perfil inválido: 'port' deve estar entre 1 e 65535")
		}
		if p.SAMLPort < 0 || p.SAMLPort > 65535 || (p.SAMLPort != 0 && p.Auth != AuthSAML) {
			return errors.New("perfil inválido: 'samlPort' só vale com auth saml e deve estar entre 1 e 65535")
		}
		if p.AuthGroup != "" && !nameRe.MatchString(p.AuthGroup) {
			return errors.New("perfil inválido: 'authGroup' deve ter até 64 letras, números, espaço, ponto, hífen ou sublinhado")
		}
		if p.ServerCertPin != "" && !pinRe.MatchString(p.ServerCertPin) {
			return errors.New("perfil inválido: 'serverCertPin' deve ser pin-sha256:<hash em base64>")
		}
	default:
		return fmt.Errorf("perfil inválido: motor %q não existe (disponíveis: %s, %s)", p.Engine, EngineIPsecIKEv2, EngineOpenConnect)
	}
	return nil
}

// ExpectedServerID é a identidade que o certificado do servidor deve apresentar: o serverId, se houver,
// senão o próprio gateway.
func (p *Profile) ExpectedServerID() string {
	if p.ServerID != "" {
		return p.ServerID
	}
	return p.Gateway
}

// UsesPSK diz se o servidor se autentica por chave pré-compartilhada.
func (p *Profile) UsesPSK() bool { return p.Engine == EngineIPsecIKEv2 && p.ServerAuth == "psk" }

// Addr é o gateway com a porta, quando houver, no formato host:porta ([v6]:porta para IPv6).
func (p *Profile) Addr() string {
	if p.Port == 0 {
		return p.Gateway
	}
	if strings.Contains(p.Gateway, ":") {
		return fmt.Sprintf("[%s]:%d", p.Gateway, p.Port)
	}
	return fmt.Sprintf("%s:%d", p.Gateway, p.Port)
}

// SAMLListenPort devolve a porta local do retorno do login único.
func (p *Profile) SAMLListenPort() int {
	if p.SAMLPort != 0 {
		return p.SAMLPort
	}
	return DefaultSAMLPort
}

// validateCA exige exatamente um certificado de CA em PEM, e recusa qualquer chave privada.
func validateCA(data string) error {
	bad := errors.New("perfil inválido: 'caCert' deve ser um certificado de CA em formato PEM")
	block, rest := pem.Decode([]byte(data))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) > 0 {
		return bad
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA {
		return bad
	}
	return nil
}

// ConnName é o nome da conexão no strongSwan.
func (p *Profile) ConnName() string {
	return "irongate-" + regexp.MustCompile(`[^A-Za-z0-9_-]+`).ReplaceAllString(p.Name, "_")
}

func Dir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "iron-gate", "profiles"), nil
}

func path(name string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, regexp.MustCompile(`[^\p{L}\p{N}_-]+`).ReplaceAllString(name, "_")+".json"), nil
}

func Save(p *Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	f, err := path(p.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(f, append(b, '\n'), 0o600)
}

func Load(name string) (*Profile, error) {
	f, err := path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(f)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("perfil %q não encontrado (use 'irongate list')", name)
	}
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

func List() ([]*Profile, error) {
	d, err := Dir()
	if err != nil {
		return nil, err
	}
	files, _ := filepath.Glob(filepath.Join(d, "*.json"))
	var out []*Profile
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil {
			if p, err := Parse(b); err == nil {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

func Delete(name string) error {
	f, err := path(name)
	if err != nil {
		return err
	}
	return os.Remove(f)
}
