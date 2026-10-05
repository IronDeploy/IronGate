package diag

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/profile"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestPluginsAusentesAvisamOQueInstalar(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "plugins")
	touch(t, filepath.Join(dir, "libstrongswan-eap-identity.so")) // falta o eap-mschapv2
	r := checkPlugins([]string{dir}, []plugin{pluginEAPIdentity, pluginEAPMSCHAPv2})
	if r == nil || r.OK {
		t.Fatalf("deveria acusar plugin ausente: %+v", r)
	}
	if !strings.Contains(r.Hint, "eap-mschapv2") || !strings.Contains(r.Hint, "libcharon-extauth-plugins") {
		t.Errorf("a dica deveria citar o plugin e o pacote: %q", r.Hint)
	}
	if strings.Contains(r.Hint, "eap-identity") {
		t.Errorf("o eap-identity está instalado e não deveria ser citado: %q", r.Hint)
	}
}

func TestPluginsPresentesEmQualquerDiretorio(t *testing.T) {
	base := t.TempDir()
	touch(t, filepath.Join(base, "usr/lib/x86_64-linux-gnu/ipsec/plugins/libstrongswan-eap-identity.so"))
	touch(t, filepath.Join(base, "usr/lib/x86_64-linux-gnu/ipsec/plugins/libstrongswan-eap-mschapv2.so"))
	// O diretório pode ter o nome da arquitetura no meio (Debian multiarch): precisa de glob.
	r := checkPlugins([]string{filepath.Join(base, "usr/lib/*/ipsec/plugins")}, []plugin{pluginEAPIdentity, pluginEAPMSCHAPv2})
	if r == nil || !r.OK {
		t.Fatalf("deveria achar os plugins: %+v", r)
	}
}

func TestPluginsExigidosPorPerfil(t *testing.T) {
	v2 := &profile.Profile{Engine: profile.EngineIPsecIKEv2}
	v1 := &profile.Profile{Engine: profile.EngineIPsecIKEv2, IKEVersion: 1}
	oc := &profile.Profile{Engine: profile.EngineOpenConnect}
	if got := requiredPlugins(v2); len(got) != 2 {
		t.Errorf("IKEv2 exige eap-identity e eap-mschapv2, veio %v", got)
	}
	if got := requiredPlugins(v1); len(got) != 1 || got[0].name != "xauth-generic" {
		t.Errorf("IKEv1 exige xauth-generic, veio %v", got)
	}
	if got := requiredPlugins(oc); got != nil {
		t.Errorf("openconnect não usa plugins do strongSwan, veio %v", got)
	}
}

// fakeProc cria um diretório /proc de mentira com os processos dados (pid -> nome).
func fakeProc(t *testing.T, procs map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for pid, name := range procs {
		touch(t, filepath.Join(dir, pid, "comm"))
		if err := os.WriteFile(filepath.Join(dir, pid, "comm"), []byte(name+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	touch(t, filepath.Join(dir, "cpuinfo")) // arquivo que não é processo
	return dir
}

func TestDaemonUnicoEstaOk(t *testing.T) {
	r := checkDaemons(fakeProc(t, map[string]string{"100": "charon-systemd", "200": "bash"}))
	if r == nil || !r.OK {
		t.Fatalf("um daemon só é o esperado: %+v", r)
	}
}

func TestDaemonsDuplicadosSaoAvisados(t *testing.T) {
	// strongswan-starter (starter + charon) junto com o charon-systemd: o caso real da VM de teste.
	r := checkDaemons(fakeProc(t, map[string]string{"100": "charon-systemd", "101": "starter", "102": "charon"}))
	if r == nil || r.OK {
		t.Fatalf("deveria avisar de daemons duplicados: %+v", r)
	}
	if !strings.Contains(r.Hint, "strongswan-starter") {
		t.Errorf("a dica deveria dizer o que desligar: %q", r.Hint)
	}
}

func TestStarterJuntoComCharonSystemdSemOutroCharon(t *testing.T) {
	r := checkDaemons(fakeProc(t, map[string]string{"100": "charon-systemd", "101": "starter"}))
	if r == nil || r.OK {
		t.Fatalf("starter + charon-systemd é conflito: %+v", r)
	}
}

func TestCharonNMConflitaComOCharonSystemd(t *testing.T) {
	r := checkDaemons(fakeProc(t, map[string]string{"100": "charon-systemd", "101": "charon-nm"}))
	if r == nil || r.OK || !strings.Contains(r.Hint, "NetworkManager") {
		t.Fatalf("charon-nm junto com charon-systemd é conflito: %+v", r)
	}
}

func TestNenhumDaemonEmExecucao(t *testing.T) {
	r := checkDaemons(fakeProc(t, map[string]string{"200": "bash"}))
	if r == nil || r.OK || !strings.Contains(r.Hint, "systemctl start strongswan") {
		t.Fatalf("deveria orientar a iniciar o serviço: %+v", r)
	}
}

func TestSemProcNaoVerifica(t *testing.T) {
	if r := checkDaemons(filepath.Join(t.TempDir(), "nao-existe")); r != nil {
		t.Errorf("sem /proc não há o que verificar: %+v", r)
	}
}
