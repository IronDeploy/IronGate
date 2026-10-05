package creds

import (
	"errors"
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
	s := NewWith(fake{})
	_ = s.SaveUsername("p", "ana")
	_ = s.SavePassword("p", "x")
	if err := s.Forget("p"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Password("p"); !errors.Is(err, ErrNotFound) {
		t.Fatal("senha deveria ter sido apagada")
	}
}
