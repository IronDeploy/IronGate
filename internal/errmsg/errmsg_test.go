package errmsg

import (
	"errors"
	"strings"
	"testing"
)

func TestFriendly(t *testing.T) {
	cases := map[string]string{
		"received EAP_FAILURE":           "Senha",
		"retransmit giving up":           "não respondeu",
		"dial unix /var/run/charon.vici": "strongSwan",
	}
	for in, want := range cases {
		if got := Friendly(errors.New(in)); !strings.Contains(got, want) {
			t.Errorf("%q -> %q", in, got)
		}
	}
	if !IsAuthFailure(errors.New("EAP_FAILURE")) {
		t.Error("deveria ser falha de autenticação")
	}
}
