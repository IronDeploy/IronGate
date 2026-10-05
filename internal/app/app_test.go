package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/creds"
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/profile"
	"github.com/zalando/go-keyring"
)

type fakeVault map[string]string

func (f fakeVault) Get(s, u string) (string, error) {
	if v, ok := f[s+u]; ok {
		return v, nil
	}
	return "", keyring.ErrNotFound
}
func (f fakeVault) Set(s, u, p string) error { f[s+u] = p; return nil }
func (f fakeVault) Delete(s, u string) error { delete(f, s+u); return nil }

type fakeEngine struct {
	err    error
	user   string
	pw     string
	cookie string
	psk    string
	// status é o estado devolvido por Status; vazio mantém o padrão dos testes antigos (conectado).
	status engine.State
}

func (e *fakeEngine) Connect(_ *profile.Profile, c engine.Credentials) error {
	e.user, e.pw, e.cookie, e.psk = c.Username, c.Password, c.Cookie, c.PSK
	return e.err
}
func (e *fakeEngine) Disconnect(*profile.Profile) error { return nil }
func (e *fakeEngine) Status(*profile.Profile) (engine.State, error) {
	if e.status != "" {
		return e.status, nil
	}
	return engine.Connected, nil
}

func setup(t *testing.T, allowSave bool) (*Service, *fakeEngine, fakeVault) {
	t.Helper()
	t.Setenv("HOME", t.TempDir()) // perfis vão para a pasta de configuração do usuário
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	vault := fakeVault{}
	eng := &fakeEngine{}
	svc := &Service{Store: creds.NewWith(vault, t.TempDir()), Engine: func(*profile.Profile) (engine.Engine, error) { return eng, nil }}
	data := `{"name":"Empresa X","gateway":"vpn.exemplo.com","allowSavePassword":true}`
	if !allowSave {
		data = `{"name":"Empresa X","gateway":"vpn.exemplo.com","allowSavePassword":false}`
	}
	if _, err := svc.Import([]byte(data)); err != nil {
		t.Fatal(err)
	}
	return svc, eng, vault
}

func TestConnectPedeCredenciais(t *testing.T) {
	svc, _, _ := setup(t, true)
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X"}); !errors.Is(err, ErrNeedCredentials) {
		t.Fatalf("err = %v, want ErrNeedCredentials", err)
	}
}

func TestRememberPasswordEReconecta(t *testing.T) {
	svc, eng, _ := setup(t, true)
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "s3", Remember: RememberPassword}); err != nil {
		t.Fatal(err)
	}
	info, _ := svc.Profile("Empresa X")
	if info.SavedUsername != "ana" || !info.HasSavedPassword {
		t.Fatalf("info = %+v", info)
	}
	// Segunda vez: sem digitar nada, usa o cofre.
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X"}); err != nil {
		t.Fatal(err)
	}
	if eng.user != "ana" || eng.pw != "s3" {
		t.Fatalf("usou %q/%q", eng.user, eng.pw)
	}
}

func TestRememberNoneNaoSalva(t *testing.T) {
	svc, _, vault := setup(t, true)
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "s3", Remember: RememberNone}); err != nil {
		t.Fatal(err)
	}
	if len(vault) != 0 {
		t.Fatalf("nada deveria ser salvo: %v", vault)
	}
}

func TestPoliticaDoPerfilImpedeSalvarSenha(t *testing.T) {
	svc, _, vault := setup(t, false)
	res, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "s3", Remember: RememberPassword})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := vault["iron-gateprofile:Empresa X:pass"]; ok {
		t.Fatal("senha salva apesar de allowSavePassword=false")
	}
	if len(res.Warnings) == 0 {
		t.Error("deveria avisar que a política não permite salvar a senha")
	}
}

func TestSenhaSalvaErradaEDescartada(t *testing.T) {
	svc, eng, _ := setup(t, true)
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "velha", Remember: RememberPassword}); err != nil {
		t.Fatal(err)
	}
	eng.err = errors.New("received EAP_FAILURE")
	res, err := svc.Connect(ConnectRequest{Profile: "Empresa X"})
	if err == nil {
		t.Fatal("deveria falhar")
	}
	if len(res.Warnings) == 0 {
		t.Error("deveria avisar que a senha salva foi descartada")
	}
	info, _ := svc.Profile("Empresa X")
	if info.HasSavedPassword {
		t.Error("senha salva errada deveria ter sido descartada")
	}
	if info.SavedUsername != "ana" {
		t.Error("o usuário deveria ser mantido")
	}
}

func TestSenhaDigitadaErradaNaoApagaNada(t *testing.T) {
	svc, eng, _ := setup(t, true)
	eng.err = errors.New("received EAP_FAILURE")
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "x", Remember: RememberPassword}); err == nil {
		t.Fatal("deveria falhar")
	}
	info, _ := svc.Profile("Empresa X")
	if info.SavedUsername != "" || info.HasSavedPassword {
		t.Errorf("não deve salvar quando a conexão falha: %+v", info)
	}
}

// proibido falha o teste se o cofre for consultado.
type proibido struct{ t *testing.T }

func (p proibido) Get(s, u string) (string, error) { p.t.Error("cofre consultado"); return "", nil }
func (p proibido) Set(s, u, v string) error        { p.t.Error("cofre consultado"); return nil }
func (p proibido) Delete(s, u string) error        { p.t.Error("cofre consultado"); return nil }

func TestListarPerfisNaoConsultaOCofre(t *testing.T) {
	svc, _, _ := setup(t, true)
	svc.Store = creds.NewWith(proibido{t}, t.TempDir())
	if ps := svc.Profiles(); len(ps) != 1 || ps[0].Name != "Empresa X" {
		t.Fatalf("perfis = %+v", ps)
	}
}

func TestLoginUnicoNaoPedeSenhaNemUsaCofre(t *testing.T) {
	svc, eng, vault := setup(t, true)
	if _, err := svc.Import([]byte(`{"name":"SSO","engine":"openconnect","protocol":"fortinet","auth":"saml","gateway":"vpn.exemplo.com","port":8443}`)); err != nil {
		t.Fatal(err)
	}
	svc.SAML = func(context.Context, *profile.Profile) (string, error) { return "SVPNCOOKIE=x", nil }
	if _, err := svc.Connect(ConnectRequest{Profile: "SSO", Remember: RememberPassword}); err != nil {
		t.Fatal(err)
	}
	if eng.cookie != "SVPNCOOKIE=x" || eng.user != "" || eng.pw != "" {
		t.Errorf("motor recebeu user=%q pw=%q cookie=%q", eng.user, eng.pw, eng.cookie)
	}
	if len(vault) != 0 {
		t.Errorf("nada deveria ir ao cofre: %v", vault)
	}
	svc.SAML = func(context.Context, *profile.Profile) (string, error) { return "", errors.New("tempo esgotado") }
	if _, err := svc.Connect(ConnectRequest{Profile: "SSO"}); err == nil {
		t.Error("falha no navegador deveria virar erro")
	}
}

func conectar(t *testing.T, svc *Service, user, pw string) {
	t.Helper()
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: user, Password: pw, Remember: RememberPassword}); err != nil {
		t.Fatal(err)
	}
}

func TestVariosUsuariosCadaUmComASuaSenha(t *testing.T) {
	svc, eng, _ := setup(t, true)
	conectar(t, svc, "ana", "senha-ana")
	conectar(t, svc, "bia", "senha-bia")

	info, _ := svc.Profile("Empresa X")
	if len(info.SavedUsers) != 2 || info.SavedUsers[0] != "bia" || info.SavedUsername != "bia" || !info.HasSavedPassword {
		t.Fatalf("info = %+v", info)
	}
	// Trocar para a ana: a tela pergunta se ela tem senha, e conectar sem digitar usa a dela.
	if ok, _ := svc.UserHasPassword("Empresa X", "ana"); !ok {
		t.Fatal("ana deveria ter senha salva")
	}
	if ok, _ := svc.UserHasPassword("Empresa X", "novo"); ok {
		t.Fatal("usuário novo não tem senha salva")
	}
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana"}); err != nil {
		t.Fatal(err)
	}
	if eng.user != "ana" || eng.pw != "senha-ana" {
		t.Fatalf("usou %q/%q", eng.user, eng.pw)
	}
	if info, _ = svc.Profile("Empresa X"); info.SavedUsername != "ana" {
		t.Fatalf("a ana deveria ser a última usada: %v", info.SavedUsers)
	}
}

func TestSenhaNovaQueConectouSubstituiAAntiga(t *testing.T) {
	svc, eng, _ := setup(t, true)
	conectar(t, svc, "ana", "velha")
	// Digita outra senha, mesmo sem marcar nada em "lembrar".
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "nova", Remember: RememberNone}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana"}); err != nil {
		t.Fatal(err)
	}
	if eng.pw != "nova" {
		t.Fatalf("a senha salva deveria ser a nova, veio %q", eng.pw)
	}
}

func TestSenhaNovaQueFalhouNaoSubstituiAAntiga(t *testing.T) {
	svc, eng, _ := setup(t, true)
	conectar(t, svc, "ana", "boa")
	eng.err = errors.New("rede fora do ar")
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana", Password: "digitada-errado"}); err == nil {
		t.Fatal("esperava erro")
	}
	eng.err = nil
	if _, err := svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana"}); err != nil {
		t.Fatal(err)
	}
	if eng.pw != "boa" {
		t.Fatalf("a senha salva não pode mudar quando a conexão falha, veio %q", eng.pw)
	}
}

func TestSenhaErradaSalvaDescartaSoDaqueleUsuario(t *testing.T) {
	svc, eng, _ := setup(t, true)
	conectar(t, svc, "ana", "a")
	conectar(t, svc, "bia", "b")
	eng.err = errors.New("received EAP_FAILURE")
	_, _ = svc.Connect(ConnectRequest{Profile: "Empresa X", Username: "ana"})
	if ok, _ := svc.UserHasPassword("Empresa X", "ana"); ok {
		t.Error("a senha da ana deveria ter sido descartada")
	}
	if ok, _ := svc.UserHasPassword("Empresa X", "bia"); !ok {
		t.Error("a senha da bia deveria continuar salva")
	}
}

func TestCadastroEdicaoEExclusaoDePerfil(t *testing.T) {
	svc, eng, _ := setup(t, true)
	eng.status = engine.Disconnected
	novo := []byte(`{"name":"Filial","engine":"ipsec-ikev2","gateway":"vpn.filial.com.br","serverAuth":"psk","allowSavePassword":true}`)
	if name, err := svc.SaveProfile(novo, "", ""); err != nil || name != "Filial" {
		t.Fatalf("%q, %v", name, err)
	}
	if _, err := svc.SaveProfile(novo, "", ""); err == nil {
		t.Error("perfil novo com nome repetido deveria falhar")
	}
	if _, err := svc.SaveProfile([]byte(`{"name":"Filial","gateway":"a b"}`), "Filial", ""); err == nil {
		t.Error("perfil inválido deveria falhar")
	}
	// Editar mantendo o nome é permitido.
	if _, err := svc.SaveProfile(novo, "Filial", ""); err != nil {
		t.Fatal(err)
	}
	// Renomear para um nome que já existe não pode sobrescrever o outro.
	if _, err := svc.SaveProfile([]byte(`{"name":"Empresa X","gateway":"x.com"}`), "Filial", ""); err == nil {
		t.Error("renomear sobre outro perfil deveria falhar")
	}
	renomeado := []byte(`{"name":"Filial SP","engine":"ipsec-ikev2","gateway":"vpn.filial.com.br","serverAuth":"psk"}`)
	if _, err := svc.SaveProfile(renomeado, "Filial", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Profile("Filial"); err == nil {
		t.Error("o nome antigo deveria ter sumido")
	}
	if j, err := svc.ProfileJSON("Filial SP"); err != nil || !strings.Contains(j, `"serverAuth": "psk"`) {
		t.Fatalf("%q, %v", j, err)
	}
	if err := svc.DeleteProfile("Filial SP"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Profile("Filial SP"); err == nil {
		t.Error("perfil excluído ainda existe")
	}
}

func TestPSKDoCadastroVaiAoCofreENaoPedeNoLogin(t *testing.T) {
	svc, eng, vault := setup(t, false) // mesmo sem permissão de salvar senha de usuário
	perfil := []byte(`{"name":"Matriz","engine":"ipsec-ikev2","gateway":"vpn.matriz.com.br","serverAuth":"psk","allowSavePassword":false}`)
	if _, err := svc.SaveProfile(perfil, "", "psk-da-empresa"); err != nil {
		t.Fatal(err)
	}
	if vault["iron-gateprofile:Matriz:psk"] != "psk-da-empresa" {
		t.Fatalf("a PSK deveria estar no cofre: %v", vault)
	}
	if b, _ := os.ReadFile(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "iron-gate", "profiles", "Matriz.json")); strings.Contains(string(b), "psk-da-empresa") {
		t.Fatal("a PSK vazou para o arquivo do perfil")
	}
	info, _ := svc.Profile("Matriz")
	if !info.NeedsPSK || !info.HasSavedPSK {
		t.Fatalf("info = %+v", info)
	}
	// Conectar com usuário e senha apenas: a PSK vem do cofre.
	if _, err := svc.Connect(ConnectRequest{Profile: "Matriz", Username: "ana", Password: "s3"}); err != nil {
		t.Fatal(err)
	}
	if eng.psk != "psk-da-empresa" {
		t.Fatalf("o motor recebeu a PSK %q", eng.psk)
	}
	// Editar sem informar a PSK mantém a salva; renomear leva a PSK junto.
	renomeado := []byte(`{"name":"Matriz SP","engine":"ipsec-ikev2","gateway":"vpn.matriz.com.br","serverAuth":"psk"}`)
	if _, err := svc.SaveProfile(renomeado, "Matriz", ""); !errors.Is(err, ErrConnected) {
		t.Fatalf("renomear um perfil conectado deveria falhar com ErrConnected, veio %v", err)
	}
	eng.status = engine.Disconnected
	if _, err := svc.SaveProfile(renomeado, "Matriz", ""); err != nil {
		t.Fatal(err)
	}
	if vault["iron-gateprofile:Matriz SP:psk"] != "psk-da-empresa" {
		t.Fatalf("a PSK deveria acompanhar o novo nome: %v", vault)
	}
	if _, ok := vault["iron-gateprofile:Matriz:psk"]; ok {
		t.Error("a PSK do nome antigo deveria ter sido apagada")
	}
	// Trocar para certificado apaga a PSK.
	cert := []byte(`{"name":"Matriz SP","engine":"ipsec-ikev2","gateway":"vpn.matriz.com.br","serverAuth":"cert"}`)
	if _, err := svc.SaveProfile(cert, "Matriz SP", ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := vault["iron-gateprofile:Matriz SP:psk"]; ok {
		t.Error("PSK não deveria sobrar num perfil por certificado")
	}
}

func TestNaoRemovePerfilConectado(t *testing.T) {
	svc, eng, vault := setup(t, true)
	conectar(t, svc, "ana", "s3")
	eng.status = engine.Connected
	if err := svc.DeleteProfile("Empresa X"); !errors.Is(err, ErrConnected) {
		t.Fatalf("esperava ErrConnected, veio %v", err)
	}
	if _, err := svc.Profile("Empresa X"); err != nil {
		t.Fatal("o perfil conectado não pode ser removido")
	}
	// Desconectado, remove o perfil e tudo o que foi salvo dele.
	eng.status = engine.Disconnected
	if err := svc.DeleteProfile("Empresa X"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Profile("Empresa X"); err == nil {
		t.Error("o perfil deveria ter sido removido")
	}
	for k := range vault {
		if strings.Contains(k, "Empresa X") {
			t.Errorf("sobrou credencial no cofre: %s", k)
		}
	}
}
