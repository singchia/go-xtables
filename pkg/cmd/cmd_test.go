package cmd

import (
	"testing"
	"time"

	"github.com/singchia/go-xtables/internal/sandbox"
	"github.com/stretchr/testify/assert"
)

const (
	user     = "root"
	password = "password"
	addr     = "localhost:2222"
)

func TestSSHCmdPassword(t *testing.T) {
	sb := sandbox.NewSandbox(addr, user, password)
	sb.SetReturnString("hi")
	go func() {
		sb.ListenAndServe()
	}()
	// wait for the sandbox ready
	time.Sleep(100 * time.Millisecond)
	t.Cleanup(func() {
		sb.Close()
	})
	stdout, _, _ := SSHCmdPassword(addr, user, password, "hello")
	assert.Equal(t, "hi", string(stdout))
}
