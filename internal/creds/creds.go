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
var vaultTimeout = 3 * time.Second

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

func passKey(profile, user string) string { return key(profile) + ":pass:" + user }

// maxUsers limita a lista de usuários lembrados por perfil.
const maxUsers = 20

// Users devolve os usuários lembrados do perfil, o mais recente primeiro. Perfis antigos, com um usuário
// só, continuam valendo. Sem cofre, a lista vem do arquivo de usuários (não é segredo).
func (s *Store) Users(profile string) []string {
	var raw string
	if s.Available() {
		raw, _ = s.get(key(profile) + ":users")
		if raw == "" {
			raw, _ = s.get(key(profile) + ":user") // formato antigo: um usuário só
		}
	} else if b, err := os.ReadFile(s.userFile(profile)); err == nil {
		raw = string(b)
	}
	var out []string
	for _, u := range strings.Split(raw, "\n") {
		if u = strings.TrimSpace(u); u != "" {
			out = append(out, u)
		}
	}
	return out
}

func (s *Store) writeUsers(profile string, users []string) error {
	raw := strings.Join(users, "\n")
	if s.Available() {
		return s.set(key(profile)+":users", raw)
	}
	if s.dir == "" {
		return errors.New("sem cofre do sistema e sem pasta de configuração para guardar o usuário")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(s.userFile(profile), []byte(raw+"\n"), 0o600)
}

// AddUser lembra o usuário e o coloca no topo da lista (o último usado vem primeiro).
func (s *Store) AddUser(profile, user string) error {
	user = strings.TrimSpace(user)
	if user == "" || strings.ContainsAny(user, "\r\n") {
		return errors.New("usuário inválido")
	}
	users := []string{user}
	for _, u := range s.Users(profile) {
		if u != user && len(users) < maxUsers {
			users = append(users, u)
		}
	}
	return s.writeUsers(profile, users)
}

// SavePassword guarda a senha do usuário no cofre, trocando a anterior desse usuário.
func (s *Store) SavePassword(profile, user, pw string) error {
	if err := s.set(passKey(profile, user), pw); err != nil {
		return fmt.Errorf("não foi possível usar o cofre do sistema (não vou gravar a senha em arquivo): %w", err)
	}
	return nil
}

// Password devolve a senha salva do usuário. Perfis antigos guardavam uma senha só, do único usuário.
func (s *Store) Password(profile, user string) (string, error) {
	v, err := s.get(passKey(profile, user))
	if errors.Is(err, keyring.ErrNotFound) {
		if us := s.Users(profile); len(us) == 1 && us[0] == user {
			v, err = s.get(key(profile) + ":pass")
		}
	}
	return v, mapErr(err)
}

// ForgetPassword apaga só a senha salva do usuário, mantendo o usuário na lista.
func (s *Store) ForgetPassword(profile, user string) error {
	err := s.del(passKey(profile, user))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// SavePSK guarda a chave pré-compartilhada do perfil no cofre do sistema (nunca em arquivo).
func (s *Store) SavePSK(profile, psk string) error { return s.set(key(profile)+":psk", psk) }

func (s *Store) PSK(profile string) (string, error) { return s.get(key(profile) + ":psk") }

func (s *Store) ForgetPSK(profile string) error {
	err := s.del(key(profile) + ":psk")
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// Forget apaga todos os usuários, senhas e a PSK salvos do perfil.
func (s *Store) Forget(profile string) error {
	var first error
	note := func(err error) {
		if err != nil && !errors.Is(err, keyring.ErrNotFound) && first == nil && s.Available() {
			first = err
		}
	}
	for _, u := range s.Users(profile) {
		note(s.del(passKey(profile, u)))
	}
	if err := os.Remove(s.userFile(profile)); err != nil && !errors.Is(err, os.ErrNotExist) && first == nil {
		first = err
	}
	for _, k := range []string{":users", ":user", ":pass", ":psk"} {
		note(s.del(key(profile) + k))
	}
	return first
}

func mapErr(err error) error {
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
