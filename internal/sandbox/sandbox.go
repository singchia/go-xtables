package sandbox

import (
	"io"

	"github.com/gliderlabs/ssh"
)

type Sandbox struct {
	server *ssh.Server
}

func NewSandbox(addr, user, password string) *Sandbox {
	server := &ssh.Server{
		Addr: addr,
		Handler: func(sn ssh.Session) {
			io.WriteString(sn, "sandbox")
		},
	}
	opt := ssh.PasswordAuth(func(ctx ssh.Context, pass string) bool {
		return pass == password
	})
	server.SetOption(opt)
	return &Sandbox{server}
}

func (sandbox *Sandbox) SetReturnString(str string) {
	sandbox.server.Handler = func(sn ssh.Session) {
		io.WriteString(sn, str)
	}
}

func (sandbox *Sandbox) ListenAndServe() error {
	return sandbox.server.ListenAndServe()
}

func (sandbox *Sandbox) Close() error {
	return sandbox.server.Close()
}
