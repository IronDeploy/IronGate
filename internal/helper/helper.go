// Package helper isola o acesso privilegiado ao strongSwan. O socket VICI do charon equivale a root
// (um cliente pode definir scripts que o charon executa), então o usuário comum nunca fala com ele.
// Em vez disso, um serviço root com API mínima (conectar, desconectar, consultar) valida o perfil e
// monta a configuração sozinho; CLI e janela são clientes dele.
package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/irondeploy/iron-gate/internal/engine"
	"github.com/irondeploy/iron-gate/internal/profile"
)

const (
	DefaultSocket = "/run/irongate/helper.sock"
	// Group é o grupo que pode falar com o helper. Estar nele não dá acesso ao VICI, só a esta API.
	Group = "irongate"

	maxRequest = 64 << 10 // o perfil com o CA cabe com folga
	opConnect  = "connect"
	opDisc     = "disconnect"
	opStatus   = "status"
)

type request struct {
	Op       string          `json:"op"`
	Profile  json.RawMessage `json:"profile"`
	Username string          `json:"username,omitempty"`
	Password string          `json:"password,omitempty"`
}

type response struct {
	OK    bool   `json:"ok"`
	State string `json:"state,omitempty"`
	Error string `json:"error,omitempty"`
}

// SocketPath devolve o socket do helper; IRONGATE_HELPER_SOCKET existe para testes.
func SocketPath() string {
	if p := os.Getenv("IRONGATE_HELPER_SOCKET"); p != "" {
		return p
	}
	return DefaultSocket
}

// Server atende pedidos. Roda como root, então não confia em nada que vem do cliente.
type Server struct {
	Engine func(*profile.Profile) (engine.Engine, error)
}

func (s *Server) Serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var req request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		_ = json.NewEncoder(c).Encode(response{Error: "pedido inválido"})
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	_ = json.NewEncoder(c).Encode(s.do(req))
}

func (s *Server) do(req request) response {
	// Parse é estrito: campos desconhecidos, senha no perfil e valores perigosos são recusados.
	p, err := profile.Parse(req.Profile)
	if err != nil {
		return response{Error: err.Error()}
	}
	eng, err := s.Engine(p)
	if err != nil {
		return response{Error: err.Error()}
	}
	switch req.Op {
	case opConnect:
		if req.Username == "" || req.Password == "" {
			return response{Error: "informe usuário e senha"}
		}
		err = eng.Connect(p, engine.Credentials{Username: req.Username, Password: req.Password})
	case opDisc:
		err = eng.Disconnect(p)
	case opStatus:
		st, serr := eng.Status(p)
		if serr != nil {
			return response{Error: serr.Error()}
		}
		return response{OK: true, State: string(st)}
	default:
		return response{Error: fmt.Sprintf("operação desconhecida: %q", req.Op)}
	}
	if err != nil {
		return response{Error: err.Error()}
	}
	return response{OK: true}
}

// Client implementa engine.Engine falando com o helper, para quem não é root.
type Client struct{ Socket string }

func NewClient() *Client { return &Client{Socket: SocketPath()} }

func (c *Client) call(req request) (response, error) {
	conn, err := net.DialTimeout("unix", c.Socket, 5*time.Second)
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second)) // o connect espera o túnel negociar
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{}, err
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return response{}, fmt.Errorf("resposta inválida do helper: %w", err)
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func newRequest(op string, p *profile.Profile) (request, error) {
	raw, err := json.Marshal(p)
	return request{Op: op, Profile: raw}, err
}

func (c *Client) Connect(p *profile.Profile, cr engine.Credentials) error {
	req, err := newRequest(opConnect, p)
	if err != nil {
		return err
	}
	req.Username, req.Password = cr.Username, cr.Password
	_, err = c.call(req)
	return err
}

func (c *Client) Disconnect(p *profile.Profile) error {
	req, err := newRequest(opDisc, p)
	if err != nil {
		return err
	}
	_, err = c.call(req)
	return err
}

func (c *Client) Status(p *profile.Profile) (engine.State, error) {
	req, err := newRequest(opStatus, p)
	if err != nil {
		return engine.Disconnected, err
	}
	resp, err := c.call(req)
	if err != nil {
		return engine.Disconnected, err
	}
	return engine.State(resp.State), nil
}

// ListenFromSystemd devolve o socket recebido do systemd (socket activation), ou nil se não houver.
func ListenFromSystemd() (net.Listener, error) {
	if os.Getenv("LISTEN_PID") != strconv.Itoa(os.Getpid()) || os.Getenv("LISTEN_FDS") != "1" {
		return nil, nil
	}
	return net.FileListener(os.NewFile(3, "irongate-helper"))
}

// Listen abre o socket do helper sem systemd (uso manual e testes): diretório acessível, socket 0660
// e, se o grupo existir, do grupo irongate.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	_ = os.Remove(path) // sobra de uma execução anterior
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		l.Close()
		return nil, err
	}
	if g, err := user.LookupGroup(Group); err == nil {
		if gid, err := strconv.Atoi(g.Gid); err == nil {
			_ = os.Chown(path, 0, gid)
		}
	}
	return l, nil
}
