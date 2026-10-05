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

	"github.com/irondeploy/iron-gate/internal/app"
	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/errmsg"
	"github.com/irondeploy/iron-gate/internal/helper"
	"github.com/irondeploy/iron-gate/internal/setup"
	"golang.org/x/term"
)

var svc = app.New()

const usage = `Iron Gate - a VPN corporativa em um clique

Uso:
  irongate import <arquivo.json>   importa um perfil
  irongate list                    lista perfis
  irongate connect <perfil>        conecta (pergunta usuário/senha se preciso)
  irongate disconnect <perfil>     desconecta
  irongate status <perfil>         mostra o estado
  irongate forget <perfil>         esquece usuário e senha salvos
  irongate diag <perfil>           diagnostica problemas de conexão
  sudo irongate setup [--user NOME] [--undo]
                                   instala (ou remove) o serviço que dá acesso seguro ao strongSwan
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
	case "setup":
		err = cmdSetup(args)
	case "helper": // serviço interno, iniciado pelo systemd
		err = cmdHelper()
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Print(usage)
		os.Exit(2)
	}
	if err != nil {
		msg := errmsg.Friendly(err)
		if errors.Is(err, app.ErrNeedCredentials) {
			msg = err.Error() // já é uma mensagem para o usuário
		}
		fmt.Fprintln(os.Stderr, "Erro:", msg)
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
	name, err := svc.Import(b)
	if err != nil {
		return err
	}
	fmt.Printf("Perfil %q importado.\n", name)
	return nil
}

func cmdList() error {
	ps := svc.Profiles()
	if len(ps) == 0 {
		fmt.Println("Nenhum perfil. Use 'irongate import <arquivo.json>'.")
	}
	for _, p := range ps {
		fmt.Printf("%s\t%s\t%s\n", p.Name, p.Engine, p.Gateway)
	}
	return nil
}

func cmdConnect(a []string) error {
	info, err := svc.Profile(a[0])
	if err != nil {
		return err
	}
	req := app.ConnectRequest{Profile: info.Name}
	if info.Auth == "saml" {
		fmt.Println("Abrindo o navegador para o login...")
		return finishConnect(svc.Connect(req))
	}
	if info.SavedUsername == "" {
		req.Username = prompt("Usuário: ")
	}
	if info.NeedsPSK && !info.HasSavedPSK {
		req.PSK = promptSecret("Chave pré-compartilhada (PSK): ")
	}
	if !info.HasSavedPassword {
		req.Password = promptSecret("Senha: ")
		req.Remember = askRemember(info)
	}

	return finishConnect(svc.Connect(req))
}

func finishConnect(res app.Result, err error) error {
	for _, w := range res.Warnings {
		fmt.Fprintln(os.Stderr, "Aviso:", w)
	}
	if err != nil {
		return err
	}
	fmt.Println("Conectado.")
	return nil
}

// askRemember pergunta o nível de lembrança. allowSavePassword=false do TI e a falta de cofre tiram a opção da senha.
func askRemember(info app.ProfileInfo) app.Remember {
	canSavePassword := info.AllowSavePassword && svc.VaultAvailable()
	if info.AllowSavePassword && !canSavePassword {
		fmt.Println("Não encontrei o cofre de senhas do sistema (Secret Service). Posso lembrar só o usuário; a senha não é gravada em arquivo.")
	}
	opts := "[n] não lembrar  [u] só usuário"
	if canSavePassword {
		opts += "  [s] usuário e senha"
	}
	switch strings.ToLower(prompt("Lembrar? " + opts + ": ")) {
	case "u":
		return app.RememberUser
	case "s":
		if canSavePassword {
			return app.RememberPassword
		}
	}
	return app.RememberNone
}

func cmdDisconnect(a []string) error {
	if err := svc.Disconnect(a[0]); err != nil {
		return err
	}
	fmt.Println("Desconectado.")
	return nil
}

func cmdStatus(a []string) error {
	st, err := svc.Status(a[0])
	if err != nil {
		return err
	}
	fmt.Println(st)
	return nil
}

func cmdForget(a []string) error {
	if err := svc.Forget(a[0]); err != nil {
		return err
	}
	fmt.Println("Credenciais esquecidas.")
	return nil
}

// cmdSetup instala o helper. Sem --user, usa quem chamou o sudo.
func cmdSetup(args []string) error {
	var username string
	undo := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--undo":
			undo = true
		case "--export-units": // uso do empacotamento: grava as units e sai
			if i+2 >= len(args) {
				return errors.New("--export-units precisa de DIRETÓRIO e CAMINHO-DO-BINÁRIO")
			}
			return setup.ExportUnits(args[i+1], args[i+2])
		case "--user":
			if i+1 >= len(args) {
				return errors.New("--user precisa de um nome")
			}
			username = args[i+1]
			i++
		default:
			return fmt.Errorf("opção desconhecida %q; veja 'irongate help'", args[i])
		}
	}
	if undo {
		return setup.Uninstall()
	}
	if username == "" {
		username = os.Getenv("SUDO_USER")
	}
	return setup.Install(username)
}

// cmdHelper roda o serviço privilegiado: usa o socket do systemd ou abre o seu próprio.
func cmdHelper() error {
	if os.Geteuid() != 0 {
		return errors.New("o helper precisa rodar como root (é iniciado pelo systemd)")
	}
	l, err := helper.ListenFromSystemd()
	if err != nil {
		return err
	}
	if l == nil {
		if l, err = helper.Listen(helper.SocketPath()); err != nil {
			return err
		}
	}
	return (&helper.Server{Engine: engine.ForProfile}).Serve(l)
}

func cmdDiag(a []string) error {
	rs, err := svc.Diag(context.Background(), a[0])
	if err != nil {
		return err
	}
	for _, r := range rs {
		mark := "OK "
		if !r.OK {
			mark = "ERRO"
		}
		fmt.Printf("[%s] %s: %s\n", mark, r.Check, r.Hint)
	}
	return nil
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
