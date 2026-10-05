package helper

import (
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/profile"
)

type fakeEngine struct {
	state    engine.State
	err      error
	user, pw string
	calls    []string
}

func (f *fakeEngine) Connect(p *profile.Profile, c engine.Credentials) error {
	f.calls = append(f.calls, "connect:"+p.Name)
	f.user, f.pw = c.Username, c.Password
	return f.err
}
func (f *fakeEngine) Disconnect(p *profile.Profile) error {
	f.calls = append(f.calls, "disconnect:"+p.Name)
	return f.err
}
func (f *fakeEngine) Status(p *profile.Profile) (engine.State, error) { return f.state, f.err }

func start(t *testing.T, eng *fakeEngine) (*Client, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "h.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &Server{Engine: func(*profile.Profile) (engine.Engine, error) { return eng, nil }}
	go srv.Serve(l)
	return &Client{Socket: sock}, sock
}

func prof() *profile.Profile {
	return &profile.Profile{Name: "Empresa X", Engine: profile.EngineIPsecIKEv2, Gateway: "vpn.exemplo.com", Auth: profile.AuthEAPMSCHAPv2}
}

func TestConnectDisconnectStatus(t *testing.T) {
	eng := &fakeEngine{state: engine.Connected}
	c, _ := start(t, eng)
	if err := c.Connect(prof(), engine.Credentials{Username: "ana", Password: "s3"}); err != nil {
		t.Fatal(err)
	}
	if eng.user != "ana" || eng.pw != "s3" {
		t.Errorf("motor recebeu %q/%q", eng.user, eng.pw)
	}
	if st, err := c.Status(prof()); err != nil || st != engine.Connected {
		t.Errorf("status = %v, %v", st, err)
	}
	if err := c.Disconnect(prof()); err != nil {
		t.Fatal(err)
	}
	if strings.Join(eng.calls, ",") != "connect:Empresa X,disconnect:Empresa X" {
		t.Errorf("chamadas = %v", eng.calls)
	}
}

func TestErroDoMotorChegaAoCliente(t *testing.T) {
	c, _ := start(t, &fakeEngine{err: errors.New("received EAP_FAILURE")})
	err := c.Connect(prof(), engine.Credentials{Username: "ana", Password: "x"})
	if err == nil || !strings.Contains(err.Error(), "EAP_FAILURE") {
		t.Fatalf("err = %v", err)
	}
}

// raw envia JSON bruto, como faria um cliente malicioso, sem passar pelo Client.
func raw(t *testing.T, sock, body string) response {
	t.Helper()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	var r response
	if err := json.NewDecoder(conn).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServidorNaoConfiaNoCliente(t *testing.T) {
	eng := &fakeEngine{}
	_, sock := start(t, eng)
	casos := map[string]string{
		"senha dentro do perfil":      `{"op":"connect","profile":{"name":"X","gateway":"a.b","password":"123"},"username":"u","password":"p"}`,
		"gateway com injeção":         `{"op":"connect","profile":{"name":"X","gateway":"a.b\nupdown=/tmp/x"},"username":"u","password":"p"}`,
		"campo desconhecido (updown)": `{"op":"connect","profile":{"name":"X","gateway":"a.b","updown":"/tmp/x"},"username":"u","password":"p"}`,
		"operação inventada":          `{"op":"load-conn","profile":{"name":"X","gateway":"a.b"}}`,
		"sem senha":                   `{"op":"connect","profile":{"name":"X","gateway":"a.b"},"username":"u"}`,
		"não é JSON":                  `isto não é json`,
	}
	for nome, body := range casos {
		if r := raw(t, sock, body); r.OK {
			t.Errorf("%s: deveria ser recusado", nome)
		}
	}
	if len(eng.calls) != 0 {
		t.Errorf("o motor não pode ser chamado com pedido inválido: %v", eng.calls)
	}
}

func TestSocketAusenteDaErroClaro(t *testing.T) {
	c := &Client{Socket: filepath.Join(t.TempDir(), "nao-existe.sock")}
	if _, err := c.Status(prof()); err == nil {
		t.Fatal("deveria falhar")
	}
}
