package diag

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/irondeploy/iron-gate/internal/profile"
)

// plugin é um plugin do strongSwan que o perfil exige, e o pacote (Debian e Ubuntu) que o traz.
type plugin struct{ file, name, pkg string }

var (
	pluginEAPIdentity = plugin{"libstrongswan-eap-identity.so", "eap-identity", "libcharon-extra-plugins"}
	pluginEAPMSCHAPv2 = plugin{"libstrongswan-eap-mschapv2.so", "eap-mschapv2", "libcharon-extauth-plugins"}
	pluginXAuth       = plugin{"libstrongswan-xauth-generic.so", "xauth-generic", "libcharon-extauth-plugins"}
)

// pluginDirs são os lugares onde as distribuições instalam os plugins (Debian, Ubuntu, Arch, Fedora e SUSE).
var pluginDirs = []string{
	"/usr/lib/ipsec/plugins",
	"/usr/lib/strongswan/plugins",
	"/usr/lib64/strongswan/plugins",
	"/usr/lib64/ipsec/plugins",
	"/usr/libexec/strongswan/plugins",
	"/usr/lib/*/ipsec/plugins",
}

// requiredPlugins são os plugins que o perfil exige no cliente: EAP no IKEv2 e XAuth no IKEv1.
func requiredPlugins(p *profile.Profile) []plugin {
	if p.Engine != profile.EngineIPsecIKEv2 {
		return nil
	}
	if p.IKEVersion == 1 {
		return []plugin{pluginXAuth}
	}
	return []plugin{pluginEAPIdentity, pluginEAPMSCHAPv2}
}

// checkPlugins confere se os arquivos dos plugins existem em algum dos diretórios. Ter o arquivo não prova que
// o daemon o carregou, mas é o que falta na prática: o login falha mesmo com a senha certa quando eles somem.
func checkPlugins(dirs []string, need []plugin) *Result {
	if len(need) == 0 {
		return nil
	}
	var search []string
	for _, d := range dirs {
		if m, err := filepath.Glob(d); err == nil {
			search = append(search, m...)
		}
	}
	var missing []plugin
	for _, pl := range need {
		found := false
		for _, d := range search {
			if _, err := os.Stat(filepath.Join(d, pl.file)); err == nil {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, pl)
		}
	}
	if len(missing) == 0 {
		return &Result{"strongSwan: plugins", true, "os plugins de autenticação estão instalados"}
	}
	var names, pkgs []string
	seen := map[string]bool{}
	for _, m := range missing {
		names = append(names, m.name)
		if !seen[m.pkg] {
			seen[m.pkg] = true
			pkgs = append(pkgs, m.pkg)
		}
	}
	return &Result{"strongSwan: plugins", false,
		"Faltam os plugins " + strings.Join(names, " e ") + ": o login falha mesmo com a senha certa. " +
			"No Debian e no Ubuntu: sudo apt install " + strings.Join(pkgs, " ") + ", e reinicie o serviço do strongSwan."}
}

// daemons que respondem pelo IKE e disputam as portas UDP 500/4500 (e, os dois primeiros, o socket do VICI).
var ikeDaemons = map[string]string{
	"charon-systemd": "charon-systemd",
	"charon":         "charon",
	"charon-nm":      "charon-nm (plugin do NetworkManager)",
}

// checkDaemons olha os processos em procDir e avisa quando há mais de um daemon IKE ativo.
func checkDaemons(procDir string) *Result {
	entries, err := os.ReadDir(procDir)
	if err != nil {
		return nil // sem /proc (outro sistema): não há o que verificar
	}
	running := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || e.Name()[0] < '0' || e.Name()[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join(procDir, e.Name(), "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(b))
		if _, ok := ikeDaemons[name]; ok || name == "starter" {
			running[name] = true
		}
	}
	// O "starter" do strongswan-starter sobe o próprio "charon": os dois contam como um daemon legado.
	var active []string
	for name, label := range ikeDaemons {
		if running[name] {
			active = append(active, label)
		}
	}
	sort.Strings(active)
	switch {
	case len(active) > 1:
		return &Result{"strongSwan: daemons", false,
			"Há mais de um daemon IKE ativo (" + strings.Join(active, " e ") + "). Eles disputam as portas UDP 500/4500 e o socket, e a conexão falha de formas confusas. " +
				"Deixe só o charon-systemd: sudo systemctl disable --now strongswan-starter (e desligue a VPN do NetworkManager que usa o strongSwan)."}
	case running["starter"] && running["charon-systemd"]:
		return &Result{"strongSwan: daemons", false,
			"O strongswan-starter e o charon-systemd estão rodando juntos. Deixe só o charon-systemd: sudo systemctl disable --now strongswan-starter."}
	case len(active) == 0:
		return &Result{"strongSwan: daemons", false,
			"Nenhum daemon do strongSwan está em execução. Inicie: sudo systemctl start strongswan (pacote charon-systemd)."}
	}
	return &Result{"strongSwan: daemons", true, "um daemon strongSwan ativo (" + active[0] + ")"}
}
