//go:build linux

package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportUnits(t *testing.T) {
	dir := t.TempDir()
	if err := ExportUnits(dir, "/usr/bin/irongate"); err != nil {
		t.Fatal(err)
	}
	svc, _ := os.ReadFile(filepath.Join(dir, "irongate-helper.service"))
	if !strings.Contains(string(svc), "ExecStart=/usr/bin/irongate helper") || strings.Contains(string(svc), "@BIN@") {
		t.Errorf("service sem o caminho do binário:\n%s", svc)
	}
	sock, _ := os.ReadFile(filepath.Join(dir, "irongate-helper.socket"))
	for _, want := range []string{"SocketGroup=irongate", "SocketMode=0660", "/run/irongate/helper.sock"} {
		if !strings.Contains(string(sock), want) {
			t.Errorf("socket sem %q:\n%s", want, sock)
		}
	}
}

func TestTrustedBin(t *testing.T) {
	for p, want := range map[string]bool{
		"/usr/bin/irongate":               true,
		"/usr/local/bin/irongate":         true,
		"/home/ubuntu/iron-gate/irongate": false, // o usuário consegue trocar este arquivo
		"/tmp/irongate":                   false,
	} {
		if got := trustedBin(p); got != want {
			t.Errorf("trustedBin(%q) = %v", p, got)
		}
	}
}
