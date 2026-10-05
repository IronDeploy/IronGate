package creds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

type fake map[string]string

func (f fake) Get(s, u string) (string, error) {
	if v, ok := f[s+u]; ok {
		return v, nil
	}
	return "", keyring.ErrNotFound
}
func (f fake) Set(s, u, p string) error { f[s+u] = p; return nil }
func (f fake) Delete(s, u string) error {
	if _, ok := f[s+u]; !ok {
		return keyring.ErrNotFound
	}
	delete(f, s+u)
	return nil
}

func TestForget(t *testing.T) {
	s := NewWith(fake{}, t.TempDir())
	_ = s.AddUser("p", "ana")
	_ = s.SavePassword("p", "ana", "x")
	_ = s.AddUser("p", "bia")
	_ = s.SavePassword("p", "bia", "y")
	if err := s.Forget("p"); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"ana", "bia"} {
		if _, err := s.Password("p", u); !errors.Is(err, ErrNotFound) {
			t.Fatalf("senha de %s deveria ter sido apagada", u)
		}
	}
	if len(s.Users("p")) != 0 {
		t.Fatal("usuários deveriam ter sido esquecidos")
	}
}

// semCofre simula Linux sem Secret Service: qualquer acesso falha com erro que não é "não encontrado".
type semCofre struct{}

func (semCofre) Get(s, u string) (string, error) { return "", errors.New("dbus: sem Secret Service") }
func (semCofre) Set(s, u, p string) error        { return errors.New("dbus: sem Secret Service") }
func (semCofre) Delete(s, u string) error        { return errors.New("dbus: sem Secret Service") }

func TestSemCofreGuardaSoUsuario(t *testing.T) {
	dir := t.TempDir()
	s := NewWith(semCofre{}, dir)
	if s.Available() {
		t.Fatal("cofre deveria estar indisponível")
	}
	if err := s.AddUser("Empresa X", "ana"); err != nil {
		t.Fatal(err)
	}
	if us := s.Users("Empresa X"); len(us) != 1 || us[0] != "ana" {
		t.Fatalf("usuários = %v", us)
	}
	if err := s.SavePassword("Empresa X", "ana", "segredo"); err == nil {
		t.Fatal("senha não pode ser salva sem cofre")
	}
	// Nenhum arquivo pode conter a senha.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if strings.Contains(string(b), "segredo") {
			t.Fatalf("senha vazou em %s", e.Name())
		}
	}
	if err := s.Forget("Empresa X"); err != nil {
		t.Fatal(err)
	}
	if len(s.Users("Empresa X")) != 0 {
		t.Fatal("usuário deveria ter sido esquecido")
	}
}

// bloqueado simula um cofre trancado que nunca responde.
type bloqueado struct{ release chan struct{} }

func (b bloqueado) Get(s, u string) (string, error) { <-b.release; return "", nil }
func (b bloqueado) Set(s, u, p string) error        { <-b.release; return nil }
func (b bloqueado) Delete(s, u string) error        { <-b.release; return nil }

func TestCofreBloqueadoNaoTravaOApp(t *testing.T) {
	old := vaultTimeout
	vaultTimeout = 50 * time.Millisecond
	defer func() { vaultTimeout = old }()
	b := bloqueado{release: make(chan struct{})}
	defer close(b.release)

	s := NewWith(b, t.TempDir())
	start := time.Now()
	if s.Available() {
		t.Fatal("cofre que não responde deve contar como indisponível")
	}
	if len(s.Users("p")) != 0 {
		t.Fatal("sem cofre e sem arquivo não há usuários")
	}
	if err := s.AddUser("p", "ana"); err != nil {
		t.Fatal(err) // cai no arquivo
	}
	if us := s.Users("p"); len(us) != 1 || us[0] != "ana" {
		t.Fatalf("usuários = %v", us)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("demorou %v: o app travaria", d)
	}
}

func TestVariosUsuariosUltimoUsadoPrimeiro(t *testing.T) {
	s := NewWith(fake{}, t.TempDir())
	for _, u := range []string{"ana", "bia", "caio", "ana"} {
		if err := s.AddUser("p", u); err != nil {
			t.Fatal(err)
		}
	}
	if got := strings.Join(s.Users("p"), ","); got != "ana,caio,bia" {
		t.Fatalf("ordem = %s", got)
	}
	_ = s.SavePassword("p", "ana", "a1")
	_ = s.SavePassword("p", "bia", "b1")
	_ = s.SavePassword("p", "ana", "a2") // senha nova substitui a antiga
	if v, _ := s.Password("p", "ana"); v != "a2" {
		t.Errorf("senha da ana = %q", v)
	}
	if v, _ := s.Password("p", "bia"); v != "b1" {
		t.Errorf("senha da bia = %q (cada usuário tem a sua)", v)
	}
	if err := s.AddUser("p", "x\ny"); err == nil {
		t.Error("usuário com quebra de linha deveria ser recusado")
	}
}

func TestPerfilAntigoComUmUsuarioContinuaFuncionando(t *testing.T) {
	f := fake{"iron-gateprofile:p:user": "ana", "iron-gateprofile:p:pass": "velha"}
	s := NewWith(f, t.TempDir())
	if us := s.Users("p"); len(us) != 1 || us[0] != "ana" {
		t.Fatalf("usuários = %v", us)
	}
	if v, err := s.Password("p", "ana"); err != nil || v != "velha" {
		t.Fatalf("senha antiga = %q, %v", v, err)
	}
}
