package cmd

import (
	"bytes"
	"os/exec"
)

func Cmd(name string, arg ...string) ([]byte, []byte, error) {
	cmd := exec.Command(name, arg...)
	infoO := new(bytes.Buffer)
	infoE := new(bytes.Buffer)
	cmd.Stdout = infoO
	cmd.Stderr = infoE
	err := cmd.Run()
	return infoO.Bytes(), infoE.Bytes(), err
}
