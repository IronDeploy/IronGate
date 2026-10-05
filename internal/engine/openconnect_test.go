package engine

import (
	"slices"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/profile"
)

func TestOpenConnectArgsSenha(t *testing.T) {
	p := &profile.Profile{Protocol: "anyconnect", Auth: profile.AuthPassword, Gateway: "vpn.exemplo.com", Port: 443, AuthGroup: "Func"}
	a := OpenConnectArgs(p, "ana", "/run/x.pid", "/run/x.ca")
	for _, w := range []string{"--protocol=anyconnect", "--user=ana", "--passwd-on-stdin", "--authgroup=Func", "--cafile=/run/x.ca", "--pid-file=/run/x.pid"} {
		if !slices.Contains(a, w) {
			t.Errorf("faltou %s em %v", w, a)
		}
	}
	if a[len(a)-2] != "--" || a[len(a)-1] != "vpn.exemplo.com:443" {
		t.Errorf("fim dos argumentos: %v", a[len(a)-2:])
	}
}

func TestOpenConnectArgsSAMLUsaCookieNaEntrada(t *testing.T) {
	p := &profile.Profile{Protocol: "fortinet", Auth: profile.AuthSAML, Gateway: "vpn.exemplo.com"}
	a := OpenConnectArgs(p, "", "/run/x.pid", "")
	if !slices.Contains(a, "--cookie-on-stdin") || strings.Contains(strings.Join(a, " "), "--user") {
		t.Errorf("args = %v", a)
	}
}

func TestSegredoNuncaVaiNosArgumentos(t *testing.T) {
	p := &profile.Profile{Protocol: "fortinet", Auth: profile.AuthPassword, Gateway: "g.exemplo.com"}
	a := strings.Join(OpenConnectArgs(p, "ana", "/p", ""), " ")
	if strings.Contains(a, "s3cr3t") {
		t.Fatal("segredo na linha de comando")
	}
	if _, err := openConnectSecret(p, Credentials{Username: "ana"}); err == nil {
		t.Error("senha vazia deveria falhar")
	}
	s := &profile.Profile{Protocol: "fortinet", Auth: profile.AuthSAML, Gateway: "g.exemplo.com"}
	if _, err := openConnectSecret(s, Credentials{}); err == nil {
		t.Error("cookie vazio deveria falhar")
	}
}
