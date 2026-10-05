// Package app concentra a lógica de uso do Iron Gate (perfis, credenciais salvas, conexão).
// A CLI e a interface gráfica são só camadas finas em cima dele.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/irondeploy/iron-gate/internal/creds"
	"github.com/irondeploy/iron-gate/internal/diag"
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/errmsg"
	"github.com/irondeploy/iron-gate/internal/profile"
	"github.com/irondeploy/iron-gate/internal/saml"
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
	Auth              string // "saml": o login é no navegador, sem usuário e senha no app
	Gateway           string
	AllowSavePassword bool
	SavedUsername     string   // o último usuário usado (o primeiro de SavedUsers)
	SavedUsers        []string // usuários lembrados, o mais recente primeiro
	HasSavedPassword  bool     // há senha salva para SavedUsername
	NeedsPSK          bool     // o servidor exige chave pré-compartilhada (serverAuth psk)
	HasSavedPSK       bool
}

type ConnectRequest struct {
	Profile  string
	Username string // vazio: usa o salvo
	Password string // vazio: usa a salva, se o perfil permitir
	PSK      string // chave pré-compartilhada; vazia: usa a salva, se o perfil permitir
	Remember Remember
}

// Result leva avisos que não impedem a conexão (ex.: senha não pôde ser salva).
type Result struct{ Warnings []string }

type Service struct {
	Store  *creds.Store
	Engine func(*profile.Profile) (engine.Engine, error)
	// SAML faz o login único no navegador e devolve a sessão. Troque em testes.
	SAML func(context.Context, *profile.Profile) (string, error)
}

func New() *Service {
	return &Service{Store: creds.New(), Engine: defaultEngine, SAML: func(ctx context.Context, p *profile.Profile) (string, error) {
		return saml.Login(ctx, p, saml.OpenBrowser)
	}}
}

// basicInfo não consulta o cofre: é instantâneo, mesmo com o cofre bloqueado.
func basicInfo(p *profile.Profile) ProfileInfo {
	return ProfileInfo{NeedsPSK: p.UsesPSK(), Name: p.Name, Engine: p.Engine, Auth: p.Auth, Gateway: p.Gateway, AllowSavePassword: p.AllowSavePassword, SavedUsername: p.Username}
}

// info completa o perfil com o que está salvo no cofre, o que pode demorar até o tempo limite do cofre.
func (s *Service) info(p *profile.Profile) ProfileInfo {
	i := basicInfo(p)
	i.SavedUsers = s.Store.Users(p.Name)
	if i.SavedUsername == "" && len(i.SavedUsers) > 0 {
		i.SavedUsername = i.SavedUsers[0]
	}
	if i.SavedUsername != "" {
		i.HasSavedPassword = s.HasSavedPassword(p, i.SavedUsername)
	}
	if p.UsesPSK() {
		k, _ := s.Store.PSK(p.Name) // a PSK é do perfil: vale mesmo sem salvar senhas de usuário
		i.HasSavedPSK = k != ""
	}
	return i
}

// HasSavedPassword diz se há senha no cofre para o usuário (a tela troca de usuário e pergunta).
func (s *Service) HasSavedPassword(p *profile.Profile, user string) bool {
	if !p.AllowSavePassword || user == "" {
		return false
	}
	pw, _ := s.Store.Password(p.Name, user)
	return pw != ""
}

// UserHasPassword é HasSavedPassword para a tela, que só conhece o nome do perfil.
func (s *Service) UserHasPassword(name, user string) (bool, error) {
	p, err := profile.Load(name)
	if err != nil {
		return false, err
	}
	return s.HasSavedPassword(p, user), nil
}

func (s *Service) Profile(name string) (ProfileInfo, error) {
	p, err := profile.Load(name)
	if err != nil {
		return ProfileInfo{}, err
	}
	return s.info(p), nil
}

// Profiles lista os perfis sem consultar o cofre (SavedUsername só traz o usuário fixo do perfil).
// Use Profile para os dados salvos.
func (s *Service) Profiles() []ProfileInfo {
	ps, _ := profile.List()
	out := make([]ProfileInfo, 0, len(ps))
	for _, p := range ps {
		out = append(out, basicInfo(p))
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

	if p.Auth == profile.AuthSAML {
		// O login é no navegador: nada de usuário, senha nem cofre.
		cookie, err := s.SAML(context.Background(), p)
		if err != nil {
			return res, err
		}
		return res, eng.Connect(p, engine.Credentials{Cookie: cookie})
	}

	user := req.Username
	if user == "" {
		user = p.Username
	}
	if user == "" {
		if us := s.Store.Users(p.Name); len(us) > 0 {
			user = us[0]
		}
	}
	// hadSaved: este usuário já tinha senha salva. Se o usuário digitar outra e a conexão funcionar,
	// a nova substitui a antiga.
	hadSaved := s.HasSavedPassword(p, user)
	pw, fromVault := req.Password, false
	if pw == "" && hadSaved {
		pw, _ = s.Store.Password(p.Name, user)
		fromVault = pw != ""
	}
	psk, pskFromVault := req.PSK, false
	if p.UsesPSK() && psk == "" {
		psk, _ = s.Store.PSK(p.Name)
		pskFromVault = psk != ""
	}
	if user == "" || pw == "" || (p.UsesPSK() && psk == "") {
		return res, ErrNeedCredentials
	}

	if err := eng.Connect(p, engine.Credentials{Username: user, Password: pw, PSK: psk}); err != nil {
		if pskFromVault && errmsg.IsPSKFailure(err) {
			_ = s.Store.ForgetPSK(p.Name)
			res.Warnings = append(res.Warnings, "A chave pré-compartilhada salva foi descartada. Informe a correta.")
		}
		if fromVault && errmsg.IsAuthFailure(err) {
			// A senha salva está errada ou expirou: descarta para o app pedir a nova.
			_ = s.Store.ForgetPassword(p.Name, user)
			res.Warnings = append(res.Warnings, "A senha salva foi descartada. Informe a nova senha.")
		}
		return res, err
	}

	level := req.Remember
	if hadSaved && !fromVault {
		level = RememberPassword // senha nova de quem já tinha senha salva: troca a antiga
	}
	if !fromVault || (p.UsesPSK() && !pskFromVault) {
		res.Warnings = append(res.Warnings, s.remember(p, user, pw, psk, level)...)
	} else if len(s.Store.Users(p.Name)) > 0 {
		_ = s.Store.AddUser(p.Name, user) // só atualiza quem foi usado por último
	}
	return res, nil
}

// remember grava conforme o nível pedido. allowSavePassword=false (política do TI) vale sobre a escolha.
func (s *Service) remember(p *profile.Profile, user, pw, psk string, level Remember) (warn []string) {
	if level != RememberUser && level != RememberPassword {
		return nil
	}
	if err := s.Store.AddUser(p.Name, user); err != nil {
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
		if err := s.Store.SavePassword(p.Name, user, pw); err != nil {
			warn = append(warn, err.Error())
		}
		if p.UsesPSK() {
			if err := s.Store.SavePSK(p.Name, psk); err != nil {
				warn = append(warn, err.Error())
			}
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
	return diag.Run(ctx, p), nil
}

// ProfileJSON devolve o perfil em JSON (sem segredos), para a tela de edição.
func (s *Service) ProfileJSON(name string) (string, error) {
	p, err := profile.Load(name)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	return string(b), err
}

// SaveProfile valida e grava um perfil vindo do formulário. psk, se informada, vai ao cofre do sistema
// (nunca ao arquivo do perfil); vazia, mantém a que já estava salva. Se o nome mudou (previous), o perfil
// antigo é removido, a PSK acompanha o novo nome e as senhas de usuário salvas são esquecidas.
func (s *Service) SaveProfile(data []byte, previous, psk string) (string, error) {
	p, err := profile.Parse(data)
	if err != nil {
		return "", err
	}
	if previous != "" && previous != p.Name && s.isConnected(previous) {
		return "", ErrConnected // renomear apagaria o perfil antigo com o túnel ainda de pé
	}
	if previous != p.Name { // novo, ou renomeado: não pode sobrescrever outro perfil
		if _, err := profile.Load(p.Name); err == nil {
			return "", fmt.Errorf("já existe um perfil chamado %q", p.Name)
		}
	}
	if p.UsesPSK() && psk == "" && previous != "" && previous != p.Name {
		psk, _ = s.Store.PSK(previous) // renomear não pode perder a PSK
	}
	if p.UsesPSK() && psk != "" {
		if err := s.Store.SavePSK(p.Name, psk); err != nil {
			return "", fmt.Errorf("não consegui guardar a chave pré-compartilhada no cofre do sistema (não vou gravá-la em arquivo): %w", err)
		}
	}
	if err := profile.Save(p); err != nil {
		return "", err
	}
	if !p.UsesPSK() {
		_ = s.Store.ForgetPSK(p.Name) // trocou para certificado: a PSK antiga não serve mais
	}
	if previous != "" && previous != p.Name {
		_ = s.DeleteProfile(previous)
	}
	return p.Name, nil
}

// ErrConnected impede remover um perfil enquanto a VPN dele está conectada: a janela e a CLI perderiam o
// controle de um túnel que continuaria de pé.
var ErrConnected = errors.New("este perfil está conectado: desconecte antes de removê-lo")

// isConnected diz se a VPN do perfil está conectada. Se o estado não puder ser consultado, não bloqueia.
func (s *Service) isConnected(name string) bool {
	st, err := s.Status(name)
	return err == nil && st == engine.Connected
}

// DeleteProfile apaga o perfil e tudo o que foi salvo dele (usuários, senhas e PSK).
func (s *Service) DeleteProfile(name string) error {
	if s.isConnected(name) {
		return ErrConnected
	}
	_ = s.Store.Forget(name)
	return profile.Delete(name)
}
