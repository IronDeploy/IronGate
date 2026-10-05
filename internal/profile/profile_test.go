package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParseOK(t *testing.T) {
	p, err := Parse([]byte(`{"name":"Empresa X","engine":"ipsec-ikev2","gateway":"vpn.empresa.com.br","auth":"eap-mschapv2","allowSavePassword":true}`))
	if err != nil || p.Gateway != "vpn.empresa.com.br" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestRejectsPassword(t *testing.T) {
	if _, err := Parse([]byte(`{"name":"X","gateway":"a.b","password":"123"}`)); err == nil {
		t.Fatal("perfil com senha deveria ser rejeitado")
	}
}

func TestRejectsInjection(t *testing.T) {
	for _, g := range []string{"a.b\nrm", "http://a.b", "a b", "a.b{x}"} {
		if _, err := Parse([]byte(`{"name":"X","gateway":"` + g + `"}`)); err == nil {
			t.Errorf("gateway %q deveria falhar", g)
		}
	}
}

func testCA(t *testing.T, isCA bool) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Teste"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: isCA, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func profileWithCA(t *testing.T, ca string) []byte {
	b, _ := json.Marshal(map[string]any{"name": "X", "gateway": "a.b", "caCert": ca})
	return b
}

func TestCACert(t *testing.T) {
	if _, err := Parse(profileWithCA(t, testCA(t, true))); err != nil {
		t.Errorf("CA válida deveria passar: %v", err)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	kb, _ := x509.MarshalECPrivateKey(key)
	privada := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
	for nome, ca := range map[string]string{
		"não é CA":      testCA(t, false),
		"chave privada": privada,
		"lixo":          "não é pem",
		"dois":          testCA(t, true) + testCA(t, true),
	} {
		if _, err := Parse(profileWithCA(t, ca)); err == nil {
			t.Errorf("%s deveria ser rejeitado", nome)
		}
	}
}

func TestOpenConnectPerfis(t *testing.T) {
	ok := []string{
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"vpn.exemplo.com","port":8443}`,
		`{"name":"A","engine":"openconnect","protocol":"fortinet","auth":"saml","gateway":"vpn.exemplo.com","samlPort":8020}`,
		`{"name":"A","engine":"openconnect","protocol":"anyconnect","gateway":"vpn.exemplo.com","authGroup":"Funcionarios","serverCertPin":"pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"name":"A","engine":"openconnect","protocol":"gp","gateway":"2001:db8::1","port":443}`,
	}
	for _, j := range ok {
		if _, err := Parse([]byte(j)); err != nil {
			t.Errorf("%s: %v", j, err)
		}
	}
	bad := []string{
		`{"name":"A","engine":"openconnect","gateway":"vpn.exemplo.com"}`,                                           // sem protocolo
		`{"name":"A","engine":"openconnect","protocol":"--script=x","gateway":"vpn.exemplo.com"}`,                   // injeção
		`{"name":"A","engine":"openconnect","protocol":"gp","auth":"saml","gateway":"vpn.exemplo.com"}`,             // saml só no fortinet
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"vpn.exemplo.com","port":70000}`,        // porta
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"vpn.exemplo.com","samlPort":8020}`,     // samlPort sem saml
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"vpn.exemplo.com","serverCertPin":"x"}`, // pin inválido
		`{"name":"A","engine":"ipsec-ikev2","gateway":"vpn.exemplo.com","port":8443}`,                               // campo do outro motor
		`{"name":"A","engine":"wireguard","gateway":"vpn.exemplo.com"}`,
	}
	for _, j := range bad {
		if _, err := Parse([]byte(j)); err == nil {
			t.Errorf("deveria falhar: %s", j)
		}
	}
}

func TestAddr(t *testing.T) {
	for _, c := range []struct {
		gw   string
		port int
		want string
	}{{"a.b", 0, "a.b"}, {"a.b", 8443, "a.b:8443"}, {"2001:db8::1", 443, "[2001:db8::1]:443"}} {
		if got := (&Profile{Gateway: c.gw, Port: c.port}).Addr(); got != c.want {
			t.Errorf("%s:%d -> %s", c.gw, c.port, got)
		}
	}
}

func TestIPsecPSKeIKEv1(t *testing.T) {
	ok := []string{
		`{"name":"A","gateway":"vpn.exemplo.com","serverAuth":"psk"}`,
		`{"name":"A","gateway":"vpn.exemplo.com","serverAuth":"psk","ike":"aes256-sha256-modp2048","esp":"aes256-sha256"}`,
		`{"name":"A","gateway":"vpn.exemplo.com","ikeVersion":1,"serverAuth":"psk","aggressive":true,"localId":"grupo-ti"}`,
	}
	for _, j := range ok {
		if _, err := Parse([]byte(j)); err != nil {
			t.Errorf("%s: %v", j, err)
		}
	}
	p, _ := Parse([]byte(ok[2]))
	if p.Auth != AuthXAuth || !p.UsesPSK() {
		t.Errorf("IKEv1 deveria assumir xauth e psk: %+v", p)
	}
	bad := []string{
		`{"name":"A","gateway":"vpn.exemplo.com","ikeVersion":1}`,                                     // v1 sem psk
		`{"name":"A","gateway":"vpn.exemplo.com","ikeVersion":3,"serverAuth":"psk"}`,                  // versão
		`{"name":"A","gateway":"vpn.exemplo.com","aggressive":true}`,                                  // agressivo é do v1
		`{"name":"A","gateway":"vpn.exemplo.com","serverAuth":"psk","ike":"aes;rm -rf"}`,              // injeção
		`{"name":"A","gateway":"vpn.exemplo.com","ikeVersion":1,"serverAuth":"psk","localId":"a b{"}`, // id
		`{"name":"A","gateway":"vpn.exemplo.com","serverAuth":"senha"}`,
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"vpn.exemplo.com","serverAuth":"psk"}`,
	}
	for _, j := range bad {
		if _, err := Parse([]byte(j)); err == nil {
			t.Errorf("deveria falhar: %s", j)
		}
	}
}

func TestServerID(t *testing.T) {
	ok := `{"name":"A","gateway":"192.0.2.10","serverId":"gateway.empresa.com.br"}`
	p, err := Parse([]byte(ok))
	if err != nil {
		t.Fatal(err)
	}
	if p.ExpectedServerID() != "gateway.empresa.com.br" {
		t.Errorf("ExpectedServerID = %q", p.ExpectedServerID())
	}
	if sem, _ := Parse([]byte(`{"name":"A","gateway":"vpn.exemplo.com"}`)); sem.ExpectedServerID() != "vpn.exemplo.com" {
		t.Errorf("sem serverId deveria usar o gateway, veio %q", sem.ExpectedServerID())
	}
	bad := []string{
		`{"name":"A","gateway":"a.b","serverId":"http://a.b"}`,                                     // formato
		`{"name":"A","gateway":"a.b","serverId":"a b"}`,                                            // espaço
		`{"name":"A","gateway":"a.b","serverId":"x.com\n"}`,                                        // injeção
		`{"name":"A","gateway":"a.b","serverAuth":"psk","serverId":"x.com"}`,                       // PSK não usa certificado
		`{"name":"A","gateway":"a.b","ikeVersion":1,"serverAuth":"psk","serverId":"x.com"}`,        // IKEv1 exige PSK
		`{"name":"A","engine":"openconnect","protocol":"fortinet","gateway":"a.b","serverId":"x"}`, // outro motor
	}
	for _, j := range bad {
		if _, err := Parse([]byte(j)); err == nil {
			t.Errorf("deveria falhar: %s", j)
		}
	}
}
