package main

import (
	"context"
	"errors"
	"os"

	"github.com/irondeploy/iron-gate/internal/app"
	"github.com/irondeploy/iron-gate/internal/diag"
	"github.com/irondeploy/iron-gate/internal/errmsg"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// App é o objeto exposto à tela. Os erros chegam à tela já em português claro.
type App struct {
	ctx context.Context
	svc *app.Service
}

func NewApp() *App { return &App{svc: app.New()} }

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.svc.VaultAvailable() // começa a sondar o cofre já na abertura, em paralelo com a tela
}

// friendly traduz o erro técnico; a senha nunca entra em mensagem.
func friendly(err error) error {
	if err == nil || errors.Is(err, app.ErrNeedCredentials) {
		return err
	}
	return errors.New(errmsg.Friendly(err))
}

func (a *App) Profiles() []app.ProfileInfo { return a.svc.Profiles() }

func (a *App) Profile(name string) (app.ProfileInfo, error) {
	i, err := a.svc.Profile(name)
	return i, friendly(err)
}

func (a *App) VaultAvailable() bool { return a.svc.VaultAvailable() }

// ImportFromFile abre o seletor de arquivo e importa o perfil. Devolve "" se o usuário cancelar.
func (a *App) ImportFromFile() (string, error) {
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title:   "Escolha o perfil da VPN",
		Filters: []runtime.FileFilter{{DisplayName: "Perfil Iron Gate (*.json)", Pattern: "*.json"}},
	})
	if err != nil || path == "" {
		return "", friendly(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", friendly(err)
	}
	name, err := a.svc.Import(b)
	return name, friendly(err)
}

// Connect devolve avisos que não impedem a conexão. remember: "none", "user" ou "password".
func (a *App) Connect(name, user, password, remember, psk string) ([]string, error) {
	res, err := a.svc.Connect(app.ConnectRequest{Profile: name, Username: user, Password: password, PSK: psk, Remember: app.Remember(remember)})
	return res.Warnings, friendly(err)
}

func (a *App) Disconnect(name string) error { return friendly(a.svc.Disconnect(name)) }

func (a *App) Status(name string) (string, error) {
	st, err := a.svc.Status(name)
	return string(st), friendly(err)
}

func (a *App) Forget(name string) error { return friendly(a.svc.Forget(name)) }

func (a *App) Diag(name string) ([]diag.Result, error) {
	rs, err := a.svc.Diag(a.ctx, name)
	return rs, friendly(err)
}

// UserHasPassword diz se o usuário tem senha salva (a tela troca de usuário e pergunta).
func (a *App) UserHasPassword(name, user string) (bool, error) {
	ok, err := a.svc.UserHasPassword(name, user)
	return ok, friendly(err)
}

// ProfileJSON devolve o perfil para o formulário de edição. Perfis nunca têm segredos.
func (a *App) ProfileJSON(name string) (string, error) {
	j, err := a.svc.ProfileJSON(name)
	return j, friendly(err)
}

// SaveProfile grava o perfil do formulário. previous é o nome antes da edição ("" para um perfil novo).
// Os erros de validação já vêm em português, então seguem sem passar por errmsg.Friendly.
func (a *App) SaveProfile(data, previous, psk string) (string, error) {
	return a.svc.SaveProfile([]byte(data), previous, psk)
}

func (a *App) DeleteProfile(name string) error { return friendly(a.svc.DeleteProfile(name)) }
