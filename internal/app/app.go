// Package app concentra a lógica de uso do Iron Gate (perfis, credenciais salvas, conexão).
// A CLI e a interface gráfica são só camadas finas em cima dele.
package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/irondeploy/iron-gate/internal/creds"
	"github.com/irondeploy/iron-gate/internal/diag"
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/errmsg"
	"github.com/irondeploy/iron-gate/internal/profile"
)

// Remember é o nível de lembrança escolhido pelo usuário. O código MFA/OTP nunca é salvo.
type Remember string

const (
	RememberNone     Remember = "none"
	RememberUser     Remember = "user"
	RememberPassword Remember = "password"
)

// ErrNeedCredentials indica que faltam usuário ou senha: a interface deve perguntar.
var ErrNeedCredentials = errors.New("informe usuário e senha")

type ProfileInfo struct {
	Name              string
	Engine            string
	Gateway           string
	AllowSavePassword bool
	SavedUsername     string
	HasSavedPassword  bool
}

type ConnectRequest struct {
	Profile  string
	Username string // vazio: usa o salvo
	Password string // vazio: usa a salva, se o perfil permitir
	Remember Remember
}

// Result leva avisos que não impedem a conexão (ex.: senha não pôde ser salva).
type Result struct{ Warnings []string }

type Service struct {
	Store  *creds.Store
	Engine func(*profile.Profile) (engine.Engine, error)
}

func New() *Service { return &Service{Store: creds.New(), Engine: engine.ForProfile} }

func (s *Service) info(p *profile.Profile) ProfileInfo {
	i := ProfileInfo{Name: p.Name, Engine: p.Engine, Gateway: p.Gateway, AllowSavePassword: p.AllowSavePassword, SavedUsername: p.Username}
	if i.SavedUsername == "" {
		i.SavedUsername, _ = s.Store.Username(p.Name)
	}
	if p.AllowSavePassword {
		pw, _ := s.Store.Password(p.Name)
		i.HasSavedPassword = pw != ""
	}
	return i
}

func (s *Service) Profile(name string) (ProfileInfo, error) {
	p, err := profile.Load(name)
	if err != nil {
		return ProfileInfo{}, err
	}
	return s.info(p), nil
}

func (s *Service) Profiles() []ProfileInfo {
	ps, _ := profile.List()
	out := make([]ProfileInfo, 0, len(ps))
	for _, p := range ps {
		out = append(out, s.info(p))
	}
	return out
}

// Import valida e salva um perfil, devolvendo o nome.
func (s *Service) Import(data []byte) (string, error) {
	p, err := profile.Parse(data)
	if err != nil {
		return "", err
	}
	return p.Name, profile.Save(p)
}

// VaultAvailable diz se a senha pode ser salva (cofre do sistema acessível).
func (s *Service) VaultAvailable() bool { return s.Store.Available() }

func (s *Service) Connect(req ConnectRequest) (Result, error) {
	var res Result
	p, err := profile.Load(req.Profile)
	if err != nil {
		return res, err
	}
	eng, err := s.Engine(p)
	if err != nil {
		return res, err
	}

	user := req.Username
	if user == "" {
		user = p.Username
	}
	if user == "" {
		user, _ = s.Store.Username(p.Name)
	}
	pw, fromVault := req.Password, false
	if pw == "" && p.AllowSavePassword {
		pw, _ = s.Store.Password(p.Name)
		fromVault = pw != ""
	}
	if user == "" || pw == "" {
		return res, ErrNeedCredentials
	}

	if err := eng.Connect(p, engine.Credentials{Username: user, Password: pw}); err != nil {
		if fromVault && errmsg.IsAuthFailure(err) {
			// A senha salva está errada ou expirou: descarta para o app pedir a nova.
			_ = s.Store.ForgetPassword(p.Name)
			res.Warnings = append(res.Warnings, "A senha salva foi descartada. Informe a nova senha.")
		}
		return res, err
	}

	if !fromVault {
		res.Warnings = append(res.Warnings, s.remember(p, user, pw, req.Remember)...)
	}
	return res, nil
}

// remember grava conforme o nível pedido. allowSavePassword=false (política do TI) vale sobre a escolha.
func (s *Service) remember(p *profile.Profile, user, pw string, level Remember) (warn []string) {
	if level != RememberUser && level != RememberPassword {
		return nil
	}
	if err := s.Store.SaveUsername(p.Name, user); err != nil {
		warn = append(warn, fmt.Sprintf("Não consegui lembrar o usuário: %v", err))
	}
	if level != RememberPassword {
		return warn
	}
	switch {
	case !p.AllowSavePassword:
		warn = append(warn, "A política deste perfil não permite salvar a senha.")
	case !s.Store.Available():
		warn = append(warn, "Não encontrei o cofre de senhas do sistema; a senha não foi salva.")
	default:
		if err := s.Store.SavePassword(p.Name, pw); err != nil {
			warn = append(warn, err.Error())
		}
	}
	return warn
}

func (s *Service) withEngine(name string, f func(*profile.Profile, engine.Engine) error) error {
	p, err := profile.Load(name)
	if err != nil {
		return err
	}
	e, err := s.Engine(p)
	if err != nil {
		return err
	}
	return f(p, e)
}

func (s *Service) Disconnect(name string) error {
	return s.withEngine(name, func(p *profile.Profile, e engine.Engine) error { return e.Disconnect(p) })
}

func (s *Service) Status(name string) (st engine.State, err error) {
	err = s.withEngine(name, func(p *profile.Profile, e engine.Engine) error {
		st, err = e.Status(p)
		return err
	})
	return st, err
}

// Forget apaga usuário e senha salvos do perfil.
func (s *Service) Forget(name string) error { return s.Store.Forget(name) }

func (s *Service) Diag(ctx context.Context, name string) ([]diag.Result, error) {
	p, err := profile.Load(name)
	if err != nil {
		return nil, err
	}
	return diag.Run(ctx, p.Gateway), nil
}
