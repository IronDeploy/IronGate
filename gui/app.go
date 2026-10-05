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

func (a *App) startup(ctx context.Context) { a.ctx = ctx }

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
func (a *App) Connect(name, user, password, remember string) ([]string, error) {
	res, err := a.svc.Connect(app.ConnectRequest{Profile: name, Username: user, Password: password, Remember: app.Remember(remember)})
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
