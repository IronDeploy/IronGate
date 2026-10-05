// Package saml faz o login único (SSO) do FortiGate pelo navegador do usuário: o mesmo fluxo do
// FortiClient com "usar navegador externo". O gateway devolve o navegador a uma porta local com um
// identificador, que o cliente troca pelo cookie da sessão (SVPNCOOKIE).
package saml

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"time"

	"github.com/irondeploy/iron-gate/internal/profile"
)

const (
	cookieName = "SVPNCOOKIE"
	// Timeout dá tempo de digitar senha e aprovar o MFA no navegador.
	Timeout = 5 * time.Minute
)

var idRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{1,256}$`)

// Opener abre uma URL no navegador do usuário.
type Opener func(url string) error

// OpenBrowser abre a URL no navegador padrão do sistema.
func OpenBrowser(u string) error {
	name := "xdg-open"
	if runtime.GOOS == "darwin" {
		name = "open"
	}
	return exec.Command(name, u).Start()
}

// Login devolve o cookie da sessão no formato "SVPNCOOKIE=valor". O cookie vale como senha:
// quem o chama deve entregá-lo ao motor sem gravar em disco nem em argumento de linha de comando.
func Login(ctx context.Context, p *profile.Profile, open Opener) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()

	// Escuta antes de abrir o navegador, para o retorno nunca chegar a uma porta fechada.
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p.SAMLListenPort()))
	if err != nil {
		return "", fmt.Errorf("não consegui abrir a porta local %d para o login único: %w", p.SAMLListenPort(), err)
	}
	defer l.Close()

	ids := make(chan string, 1)
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if !idRe.MatchString(id) {
			http.NotFound(w, r) // favicon e visitas sem o retorno do gateway
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<!doctype html><meta charset=utf-8><title>Iron Gate</title><p>Login concluído. Pode fechar esta janela e voltar ao Iron Gate.</p>")
		select {
		case ids <- id:
		default:
		}
	}), ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(l)
	defer srv.Close()

	start := (&url.URL{Scheme: "https", Host: p.Addr(), Path: "/remote/saml/start", RawQuery: "redirect=1"}).String()
	if err := open(start); err != nil {
		return "", fmt.Errorf("não consegui abrir o navegador: %w", err)
	}

	select {
	case id := <-ids:
		return exchange(ctx, p, id)
	case <-ctx.Done():
		return "", errors.New("tempo esgotado esperando o login no navegador")
	}
}

func exchange(ctx context.Context, p *profile.Profile, id string) (string, error) {
	tlsCfg, err := tlsConfig(p)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Transport:     &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u := (&url.URL{Scheme: "https", Host: p.Addr(), Path: "/remote/saml/auth_id", RawQuery: url.Values{"id": {id}}.Encode()}).String()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == cookieName && c.Value != "" {
			return cookieName + "=" + c.Value, nil
		}
	}
	return "", fmt.Errorf("o gateway não devolveu a sessão (HTTP %d): o login único não foi concluído", resp.StatusCode)
}

// tlsConfig valida o gateway pelo CA do perfil, pelo pin do certificado ou pelo que o sistema confia.
func tlsConfig(p *profile.Profile) (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: p.Gateway}
	if p.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(p.CACert)) {
			return nil, errors.New("caCert inválido")
		}
		cfg.RootCAs = pool
	}
	if p.ServerCertPin != "" {
		// O pin substitui a validação por CA: fixa a chave pública do servidor.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			for _, der := range raw {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
				if "pin-sha256:"+base64.StdEncoding.EncodeToString(sum[:]) == p.ServerCertPin {
					return nil
				}
			}
			return errors.New("o certificado do servidor não confere com o serverCertPin do perfil")
		}
	}
	return cfg, nil
}
