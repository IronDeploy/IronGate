package app

import (
	"errors"
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
	err  error
	user string
	pw   string
}

func (e *fakeEngine) Connect(_ *profile.Profile, c engine.Credentials) error {
	e.user, e.pw = c.Username, c.Password
	return e.err
}
func (e *fakeEngine) Disconnect(*profile.Profile) error             { return nil }
func (e *fakeEngine) Status(*profile.Profile) (engine.State, error) { return engine.Connected, nil }

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
