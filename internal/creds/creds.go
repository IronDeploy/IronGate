// Package creds guarda credenciais no cofre do sistema (Secret Service, Credential Manager, Keychain).
// Nunca grava senha em arquivo. O código MFA/OTP nunca é salvo.
package creds

import (
	"errors"
	"fmt"

	"github.com/zalando/go-keyring"
)

const service = "iron-gate"

var ErrNotFound = errors.New("credencial não encontrada")

// Backend abstrai o cofre para permitir testes.
type Backend interface {
	Get(service, user string) (string, error)
	Set(service, user, secret string) error
	Delete(service, user string) error
}

type systemBackend struct{}

func (systemBackend) Get(s, u string) (string, error) { return keyring.Get(s, u) }
func (systemBackend) Set(s, u, p string) error        { return keyring.Set(s, u, p) }
func (systemBackend) Delete(s, u string) error        { return keyring.Delete(s, u) }

type Store struct{ b Backend }

func New() *Store              { return &Store{b: systemBackend{}} }
func NewWith(b Backend) *Store { return &Store{b: b} }

func key(profile string) string { return "profile:" + profile }

func (s *Store) SaveUsername(profile, user string) error {
	return s.b.Set(service, key(profile)+":user", user)
}

func (s *Store) Username(profile string) (string, error) {
	v, err := s.b.Get(service, key(profile)+":user")
	return v, mapErr(err)
}

func (s *Store) SavePassword(profile, pw string) error {
	if err := s.b.Set(service, key(profile)+":pass", pw); err != nil {
		return fmt.Errorf("não foi possível usar o cofre do sistema (não vou gravar a senha em arquivo): %w", err)
	}
	return nil
}

func (s *Store) Password(profile string) (string, error) {
	v, err := s.b.Get(service, key(profile)+":pass")
	return v, mapErr(err)
}

// Forget apaga usuário e senha salvos do perfil.
func (s *Store) Forget(profile string) error {
	var first error
	for _, k := range []string{":user", ":pass"} {
		if err := s.b.Delete(service, key(profile)+k); err != nil && !errors.Is(err, keyring.ErrNotFound) && first == nil {
			first = err
		}
	}
	return first
}

func mapErr(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
