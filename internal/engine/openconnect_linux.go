//go:build linux

package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/irondeploy/iron-gate/internal/profile"
)

// runDir guarda pidfile e CA temporário. Só root escreve nele.
const runDir = "/run/irongate"

type openConnect struct{}

func newOpenConnect() (Engine, error) {
	if _, err := exec.LookPath("openconnect"); err != nil {
		return nil, errors.New("openconnect não instalado: sudo apt install openconnect")
	}
	return &openConnect{}, nil
}

func pidFile(p *profile.Profile) string { return filepath.Join(runDir, p.ConnName()+".pid") }

// running devolve o pid do openconnect deste perfil, ou 0. Confere o nome do processo para não
// matar outro que reaproveitou o pid.
func running(p *profile.Profile) int {
	b, err := os.ReadFile(pidFile(p))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		return 0
	}
	comm, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil || strings.TrimSpace(string(comm)) != "openconnect" {
		return 0
	}
	return pid
}

func (*openConnect) Connect(p *profile.Profile, c Credentials) error {
	secret, err := openConnectSecret(p, c)
	if err != nil {
		return err
	}
	if running(p) != 0 {
		return nil
	}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return err
	}
	caFile := ""
	if p.CACert != "" {
		caFile = filepath.Join(runDir, p.ConnName()+".ca.pem")
		if err := os.WriteFile(caFile, []byte(p.CACert), 0o600); err != nil {
			return err
		}
		defer os.Remove(caFile) // o openconnect já leu o CA quando o processo vai para segundo plano
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "openconnect", OpenConnectArgs(p, c.Username, pidFile(p), caFile)...)
	cmd.Stdin = strings.NewReader(secret + "\n")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = 5 * time.Second // o processo em segundo plano pode segurar o pipe
	if err := cmd.Run(); err != nil && !errors.Is(err, exec.ErrWaitDelay) {
		// O log do openconnect não traz a senha; vai anexado para o errmsg traduzir.
		return fmt.Errorf("%w: %s", err, strings.Join(strings.Fields(out.String()), " "))
	}
	return nil
}

func (*openConnect) Disconnect(p *profile.Profile) error {
	pid := running(p)
	if pid == 0 {
		_ = os.Remove(pidFile(p))
		return nil
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	for i := 0; i < 100; i++ { // o openconnect desfaz rotas e DNS antes de sair
		if running(p) == 0 {
			_ = os.Remove(pidFile(p))
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("o openconnect não encerrou a tempo")
}

func (*openConnect) Status(p *profile.Profile) (State, error) {
	if running(p) != 0 {
		return Connected, nil
	}
	return Disconnected, nil
}
