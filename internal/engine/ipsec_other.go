//go:build !linux

package engine

import "errors"

// Windows e macOS entram nas Fases 2 e 3 do plano.
func newIPsec() (Engine, error) {
	return nil, errors.New("este sistema ainda não é suportado (por enquanto só Linux)")
}
