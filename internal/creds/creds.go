// Package creds guarda credenciais no cofre do sistema (Secret Service, Credential Manager, Keychain).
// Nunca grava senha em arquivo. O código MFA/OTP nunca é salvo.
package creds

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

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

// Store usa o cofre do sistema. Sem cofre (ex.: Linux sem Secret Service), só o usuário, que não é segredo,
// é guardado em arquivo em dir; a senha nunca é gravada fora do cofre.
type Store struct {
	b   Backend
	dir string

	once  sync.Once
	avail bool
}

// vaultTimeout evita que um cofre bloqueado (esperando um prompt de desbloqueio que pode nunca aparecer)
// congele o app. Cofre que não responde conta como indisponível.
var vaultTimeout = 5 * time.Second

var errVaultTimeout = errors.New("o cofre de senhas do sistema não respondeu (talvez esteja bloqueado)")

func withTimeout[T any](f func() (T, error)) (T, error) {
	type result struct {
		v   T
		err error
	}
	ch := make(chan result, 1)
	go func() {
		v, err := f()
		ch <- result{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(vaultTimeout):
		var zero T
		return zero, errVaultTimeout
	}
}

var errVaultUnavailable = errors.New("cofre de senhas do sistema indisponível")

func (s *Store) get(k string) (string, error) {
	if !s.Available() {
		return "", errVaultUnavailable
	}
	return withTimeout(func() (string, error) { return s.b.Get(service, k) })
}

func (s *Store) set(k, v string) error {
	if !s.Available() {
		return errVaultUnavailable
	}
	_, err := withTimeout(func() (struct{}, error) { return struct{}{}, s.b.Set(service, k, v) })
	return err
}

func (s *Store) del(k string) error {
	if !s.Available() {
		return errVaultUnavailable
	}
	_, err := withTimeout(func() (struct{}, error) { return struct{}{}, s.b.Delete(service, k) })
	return err
}

func New() *Store {
	base, err := os.UserConfigDir()
	if err != nil {
		return &Store{b: systemBackend{}}
	}
	return &Store{b: systemBackend{}, dir: filepath.Join(base, "iron-gate", "users")}
}

func NewWith(b Backend, dir string) *Store { return &Store{b: b, dir: dir} }

// Available diz se o cofre do sistema está acessível. "Não encontrado" para uma chave de teste conta como disponível.
// O resultado é guardado: um cofre que não responde não deve atrasar cada consulta.
func (s *Store) Available() bool {
	s.once.Do(func() {
		_, err := withTimeout(func() (string, error) { return s.b.Get(service, "probe") })
		s.avail = err == nil || errors.Is(err, keyring.ErrNotFound)
	})
	return s.avail
}

var unsafeName = regexp.MustCompile(`[^\p{L}\p{N}_-]+`)

func (s *Store) userFile(profile string) string {
	return filepath.Join(s.dir, unsafeName.ReplaceAllString(profile, "_")+".user")
}

func key(profile string) string { return "profile:" + profile }

func (s *Store) SaveUsername(profile, user string) error {
	if s.Available() {
		return s.set(key(profile)+":user", user)
	}
	if s.dir == "" {
		return errors.New("sem cofre do sistema e sem pasta de configuração para guardar o usuário")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.userFile(profile), []byte(user+"\n"), 0o600)
}

func (s *Store) Username(profile string) (string, error) {
	if s.Available() {
		v, err := s.get(key(profile) + ":user")
		return v, mapErr(err)
	}
	b, err := os.ReadFile(s.userFile(profile))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	return strings.TrimSpace(string(b)), err
}

func (s *Store) SavePassword(profile, pw string) error {
	if err := s.set(key(profile)+":pass", pw); err != nil {
		return fmt.Errorf("não foi possível usar o cofre do sistema (não vou gravar a senha em arquivo): %w", err)
	}
	return nil
}

func (s *Store) Password(profile string) (string, error) {
	v, err := s.get(key(profile) + ":pass")
	return v, mapErr(err)
}

// ForgetPassword apaga só a senha salva, mantendo o usuário.
func (s *Store) ForgetPassword(profile string) error {
	err := s.del(key(profile) + ":pass")
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// Forget apaga usuário e senha salvos do perfil.
func (s *Store) Forget(profile string) error {
	var first error
	if err := os.Remove(s.userFile(profile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		first = err
	}
	for _, k := range []string{":user", ":pass"} {
		if err := s.del(key(profile) + k); err != nil && !errors.Is(err, keyring.ErrNotFound) && first == nil && s.Available() {
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
