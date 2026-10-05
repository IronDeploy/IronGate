package creds

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	_ = s.SaveUsername("p", "ana")
	_ = s.SavePassword("p", "x")
	if err := s.Forget("p"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Password("p"); !errors.Is(err, ErrNotFound) {
		t.Fatal("senha deveria ter sido apagada")
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
	if err := s.SaveUsername("Empresa X", "ana"); err != nil {
		t.Fatal(err)
	}
	if u, err := s.Username("Empresa X"); err != nil || u != "ana" {
		t.Fatalf("usuário = %q, %v", u, err)
	}
	if err := s.SavePassword("Empresa X", "segredo"); err == nil {
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
	if _, err := s.Username("Empresa X"); !errors.Is(err, ErrNotFound) {
		t.Fatal("usuário deveria ter sido esquecido")
	}
}
