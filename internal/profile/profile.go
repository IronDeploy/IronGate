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
	EngineIPsecIKEv2 = "ipsec-ikev2"
	AuthEAPMSCHAPv2  = "eap-mschapv2"
)

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
}

var (
	nameRe    = regexp.MustCompile(`^[\p{L}\p{N} ._-]{1,64}$`)
	gatewayRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$|^[0-9a-fA-F:]+$`)
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
	}
	return &p, p.Validate()
}

// Validate garante valores seguros, pois eles entram em arquivos de configuração.
func (p *Profile) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return errors.New("perfil inválido: 'name' deve ter até 64 letras, números, espaço, ponto, hífen ou sublinhado")
	}
	if p.Engine != EngineIPsecIKEv2 {
		return fmt.Errorf("perfil inválido: motor %q ainda não é suportado (disponível: %s)", p.Engine, EngineIPsecIKEv2)
	}
	if p.Auth != AuthEAPMSCHAPv2 {
		return fmt.Errorf("perfil inválido: autenticação %q ainda não é suportada (disponível: %s)", p.Auth, AuthEAPMSCHAPv2)
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
