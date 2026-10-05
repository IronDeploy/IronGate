package profile

import "testing"

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
