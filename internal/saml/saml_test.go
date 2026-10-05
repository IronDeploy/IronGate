package saml

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/profile"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// fakeGateway imita o FortiGate: o "navegador" é o Opener, que devolve o id à porta local.
func fakeGateway(t *testing.T) (*profile.Profile, *httptest.Server) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/remote/saml/auth_id" && r.URL.Query().Get("id") == "abc123" {
			http.SetCookie(w, &http.Cookie{Name: "SVPNCOOKIE", Value: "sessao-secreta"})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	host, port, _ := net.SplitHostPort(u.Host)
	portN, _ := strconv.Atoi(port)
	sum := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	p := &profile.Profile{
		Name: "T", Engine: profile.EngineOpenConnect, Protocol: "fortinet", Auth: profile.AuthSAML,
		Gateway: host, Port: portN, SAMLPort: freePort(t),
		ServerCertPin: "pin-sha256:" + base64.StdEncoding.EncodeToString(sum[:]),
	}
	return p, srv
}

func TestLoginTrocaIdPeloCookie(t *testing.T) {
	p, _ := fakeGateway(t)
	var started string
	cookie, err := Login(context.Background(), p, func(u string) error {
		started = u
		go http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/?id=abc123")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "SVPNCOOKIE=sessao-secreta" {
		t.Errorf("cookie = %q", cookie)
	}
	if !strings.HasSuffix(started, "/remote/saml/start?redirect=1") {
		t.Errorf("URL de início = %q", started)
	}
}

func TestLoginRecusaCertificadoComPinErrado(t *testing.T) {
	p, _ := fakeGateway(t)
	p.ServerCertPin = "pin-sha256:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, err := Login(context.Background(), p, func(string) error {
		go http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/?id=abc123")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "serverCertPin") {
		t.Fatalf("esperava recusa pelo pin, veio %v", err)
	}
}

func TestLoginIgnoraRetornoSemIdValido(t *testing.T) {
	p, _ := fakeGateway(t)
	cookie, err := Login(context.Background(), p, func(string) error {
		go func() {
			http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/favicon.ico")
			http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/?id=../../etc")
			http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/?id=abc123")
		}()
		return nil
	})
	if err != nil || cookie == "" {
		t.Fatalf("%q, %v", cookie, err)
	}
}

func TestLoginSemSessaoNoGateway(t *testing.T) {
	p, _ := fakeGateway(t)
	_, err := Login(context.Background(), p, func(string) error {
		go http.Get("http://127.0.0.1:" + strconv.Itoa(p.SAMLPort) + "/?id=outro")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "não devolveu a sessão") {
		t.Fatalf("%v", err)
	}
}

func TestLoginCancelado(t *testing.T) {
	p, _ := fakeGateway(t)
	ctx, cancel := context.WithCancel(context.Background())
	_, err := Login(ctx, p, func(string) error { cancel(); return nil })
	if err == nil {
		t.Fatal("esperava erro")
	}
}
