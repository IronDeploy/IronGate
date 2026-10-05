//go:build !linux

package engine

import "errors"

func newOpenConnect() (Engine, error) {
	return nil, errors.New("este sistema ainda não é suportado (por enquanto só Linux)")
}
