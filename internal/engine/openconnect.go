package engine

import (
	"fmt"

	"github.com/irondeploy/iron-gate/internal/profile"
)

// OpenConnectArgs monta a linha de comando do openconnect. Segredos (senha ou cookie) nunca entram
// aqui: vão pela entrada padrão. caFile é o caminho do CA do perfil, se houver.
func OpenConnectArgs(p *profile.Profile, username, pidFile, caFile string) []string {
	args := []string{"--protocol=" + p.Protocol, "--non-inter", "--background", "--pid-file=" + pidFile}
	if p.Auth == profile.AuthSAML {
		args = append(args, "--cookie-on-stdin")
	} else {
		args = append(args, "--user="+username, "--passwd-on-stdin")
	}
	if p.AuthGroup != "" {
		args = append(args, "--authgroup="+p.AuthGroup)
	}
	if p.ServerCertPin != "" {
		args = append(args, "--servercert="+p.ServerCertPin)
	}
	if caFile != "" {
		args = append(args, "--cafile="+caFile)
	}
	// "--" impede que um gateway seja lido como opção.
	return append(args, "--", p.Addr())
}

// openConnectSecret escolhe o que vai à entrada padrão do openconnect.
func openConnectSecret(p *profile.Profile, c Credentials) (string, error) {
	if p.Auth == profile.AuthSAML {
		if c.Cookie == "" {
			return "", fmt.Errorf("faltou a sessão do login único")
		}
		return c.Cookie, nil
	}
	if c.Username == "" || c.Password == "" {
		return "", fmt.Errorf("informe usuário e senha")
	}
	return c.Password, nil
}
