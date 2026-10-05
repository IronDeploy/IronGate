//go:build linux

// Package setup instala (e remove) o helper do Iron Gate no sistema: grupo, binário e units do systemd.
// Precisa de root. Num pacote .deb isso é feito pelo postinst; aqui serve para instalação manual.
package setup

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/irondeploy/iron-gate/internal/helper"
)

const (
	installedBin = "/usr/local/bin/irongate"
	unitDir      = "/etc/systemd/system"
)

//go:embed units/irongate-helper.socket
var socketUnit string

//go:embed units/irongate-helper.service
var serviceTemplate string

func serviceUnit(bin string) string { return strings.ReplaceAll(serviceTemplate, "@BIN@", bin) }

// ExportUnits grava as units em dir, apontando para bin. Usado para montar o pacote .deb sem duplicar o texto.
func ExportUnits(dir, bin string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "irongate-helper.socket"), []byte(socketUnit), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "irongate-helper.service"), []byte(serviceUnit(bin)), 0o644)
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// trustedBin: um serviço root não pode executar um binário que um usuário comum consegue trocar.
func trustedBin(path string) bool {
	for _, d := range []string{"/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/usr/local/sbin/"} {
		if strings.HasPrefix(path, d) {
			return true
		}
	}
	return false
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// Install cria o grupo, coloca o binário em local confiável, escreve as units e ativa o socket.
// username entra no grupo irongate (vazio: ninguém é adicionado).
func Install(username string) error {
	if os.Geteuid() != 0 {
		return errors.New("precisa de administrador: rode 'sudo irongate setup'")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return err
	}

	bin := self
	if !trustedBin(self) {
		if err := copyFile(self, installedBin); err != nil {
			return fmt.Errorf("copiar o binário para %s: %w", installedBin, err)
		}
		bin = installedBin
		fmt.Printf("Binário copiado para %s (um serviço root não pode rodar um arquivo que você consegue alterar).\n", bin)
	}

	if err := run("getent", "group", helper.Group); err != nil {
		if err := run("groupadd", "--system", helper.Group); err != nil {
			return err
		}
		fmt.Printf("Grupo %q criado.\n", helper.Group)
	}
	if username != "" && username != "root" {
		if err := run("usermod", "-aG", helper.Group, username); err != nil {
			return err
		}
		fmt.Printf("Usuário %q adicionado ao grupo %q (vale após sair e entrar de novo na sessão).\n", username, helper.Group)
	}

	if err := ExportUnits(unitDir, bin); err != nil {
		return err
	}
	if err := run("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := run("systemctl", "enable", "--now", "irongate-helper.socket"); err != nil {
		return err
	}
	fmt.Println("Helper do Iron Gate instalado e ativo.")
	return nil
}

// Uninstall remove as units e o binário copiado. O grupo é mantido.
func Uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("precisa de administrador: rode 'sudo irongate setup --undo'")
	}
	_ = run("systemctl", "disable", "--now", "irongate-helper.socket")
	_ = run("systemctl", "stop", "irongate-helper.service")
	for _, f := range []string{
		filepath.Join(unitDir, "irongate-helper.socket"),
		filepath.Join(unitDir, "irongate-helper.service"),
		installedBin,
	} {
		if err := os.Remove(f); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	_ = run("systemctl", "daemon-reload")
	fmt.Println("Helper do Iron Gate removido.")
	return nil
}
