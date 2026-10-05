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
