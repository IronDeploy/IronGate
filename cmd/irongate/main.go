// irongate: a VPN corporativa em um clique (CLI da Fase 1).
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/irondeploy/iron-gate/internal/creds"
	"github.com/irondeploy/iron-gate/internal/diag"
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/errmsg"
	"github.com/irondeploy/iron-gate/internal/profile"
	"golang.org/x/term"
)

const usage = `Iron Gate - a VPN corporativa em um clique

Uso:
  irongate import <arquivo.json>   importa um perfil
  irongate list                    lista perfis
  irongate connect <perfil>        conecta (pergunta usuário/senha se preciso)
  irongate disconnect <perfil>     desconecta
  irongate status <perfil>         mostra o estado
  irongate forget <perfil>         esquece usuário e senha salvos
  irongate diag <perfil>           diagnostica problemas de conexão
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "import":
		err = need(args, 1, cmdImport)
	case "list":
		err = cmdList()
	case "connect":
		err = need(args, 1, cmdConnect)
	case "disconnect":
		err = need(args, 1, cmdDisconnect)
	case "status":
		err = need(args, 1, cmdStatus)
	case "forget":
		err = need(args, 1, cmdForget)
	case "diag":
		err = need(args, 1, cmdDiag)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Erro:", errmsg.Friendly(err))
		if os.Getenv("IRONGATE_DEBUG") != "" {
			fmt.Fprintln(os.Stderr, "Detalhe técnico:", err) // nunca contém senha
		}
		os.Exit(1)
	}
}

func need(args []string, n int, f func([]string) error) error {
	if len(args) != n {
		return errors.New("argumentos inválidos; veja 'irongate help'")
	}
	return f(args)
}

func cmdImport(a []string) error {
	b, err := os.ReadFile(a[0])
	if err != nil {
		return err
	}
	p, err := profile.Parse(b)
	if err != nil {
		return err
	}
	if err := profile.Save(p); err != nil {
		return err
	}
	fmt.Printf("Perfil %q importado.\n", p.Name)
	return nil
}

func cmdList() error {
	ps, _ := profile.List()
	if len(ps) == 0 {
		fmt.Println("Nenhum perfil. Use 'irongate import <arquivo.json>'.")
	}
	for _, p := range ps {
		fmt.Printf("%s\t%s\t%s\n", p.Name, p.Engine, p.Gateway)
	}
	return nil
}

func cmdConnect(a []string) error {
	p, err := profile.Load(a[0])
	if err != nil {
		return err
	}
	eng, err := engine.ForProfile(p)
	if err != nil {
		return err
	}
	store := creds.New()

	user := p.Username
	if user == "" {
		user, _ = store.Username(p.Name)
	}
	pw := ""
	if p.AllowSavePassword {
		pw, _ = store.Password(p.Name)
	}
	fromVault := pw != ""

	if user == "" {
		user = prompt("Usuário: ")
	}
	if pw == "" {
		pw = promptSecret("Senha: ")
	}

	err = eng.Connect(p, engine.Credentials{Username: user, Password: pw})
	if err != nil {
		if errmsg.IsAuthFailure(err) && fromVault {
			_ = store.Forget(p.Name) // senha salva está errada/expirada: pede de novo na próxima
			fmt.Fprintln(os.Stderr, "A senha salva foi descartada. Rode 'connect' de novo para informar a nova.")
		}
		return err
	}
	fmt.Println("Conectado.")

	if !fromVault {
		offerSave(p, store, user, pw)
	}
	return nil
}

// offerSave pergunta o nível de lembrança. allowSavePassword=false do TI desativa a senha.
func offerSave(p *profile.Profile, store *creds.Store, user, pw string) {
	opts := "[n] não lembrar  [u] só usuário"
	if p.AllowSavePassword {
		opts += "  [s] usuário e senha"
	}
	switch strings.ToLower(prompt("Lembrar? " + opts + ": ")) {
	case "u":
		_ = store.SaveUsername(p.Name, user)
	case "s":
		if p.AllowSavePassword {
			_ = store.SaveUsername(p.Name, user)
			fmt.Println("Para salvar a senha, informe-a novamente.")
			pw := promptSecret("Senha: ")
			if err := store.SavePassword(p.Name, pw); err != nil {
				fmt.Fprintln(os.Stderr, "Aviso:", err)
			}
		}
	}
}

func cmdDisconnect(a []string) error {
	return withEngine(a[0], func(p *profile.Profile, e engine.Engine) error {
		if err := e.Disconnect(p); err != nil {
			return err
		}
		fmt.Println("Desconectado.")
		return nil
	})
}

func cmdStatus(a []string) error {
	return withEngine(a[0], func(p *profile.Profile, e engine.Engine) error {
		st, err := e.Status(p)
		if err != nil {
			return err
		}
		fmt.Println(st)
		return nil
	})
}

func cmdForget(a []string) error {
	if err := creds.New().Forget(a[0]); err != nil {
		return err
	}
	fmt.Println("Credenciais esquecidas.")
	return nil
}

func cmdDiag(a []string) error {
	p, err := profile.Load(a[0])
	if err != nil {
		return err
	}
	for _, r := range diag.Run(context.Background(), p.Gateway) {
		mark := "OK "
		if !r.OK {
			mark = "ERRO"
		}
		fmt.Printf("[%s] %s: %s\n", mark, r.Check, r.Hint)
	}
	return nil
}

func withEngine(name string, f func(*profile.Profile, engine.Engine) error) error {
	p, err := profile.Load(name)
	if err != nil {
		return err
	}
	e, err := engine.ForProfile(p)
	if err != nil {
		return err
	}
	return f(p, e)
}

// stdin é compartilhado para que a entrada via pipe não se perca entre perguntas.
var stdin = bufio.NewReader(os.Stdin)

func prompt(msg string) string {
	fmt.Print(msg)
	s, _ := stdin.ReadString('\n')
	return strings.TrimSpace(s)
}

// promptSecret não ecoa a senha num terminal; sem terminal (pipe, testes), lê uma linha da entrada.
func promptSecret(msg string) string {
	if !term.IsTerminal(int(syscall.Stdin)) {
		return prompt(msg)
	}
	fmt.Print(msg)
	b, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return string(b)
}
