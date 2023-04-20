package cmd

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/singchia/go-xtables/pkg/log"
	"golang.org/x/crypto/ssh"
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

func SSHCmdPassword(addr string, user, password string,
	name string, arg ...string) ([]byte, []byte, error) {

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer session.Close()

	infoO := new(bytes.Buffer)
	infoE := new(bytes.Buffer)
	session.Stdout = infoO
	session.Stderr = infoE

	cmd := name
	if arg != nil {
		cmd += " " + strings.Join(arg, " ")
	}
	log.Debugf("session to run: %s", cmd)
	err = session.Run(cmd)

	return infoO.Bytes(), infoE.Bytes(), err
}

func SSHCmdPublicKey(addr string, user string, privateKey []byte,
	name string, arg ...string) ([]byte, []byte, error) {

	key, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return nil, nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, nil, err
	}
	defer session.Close()

	infoO := new(bytes.Buffer)
	infoE := new(bytes.Buffer)
	session.Stdout = infoO
	session.Stderr = infoE

	cmd := name
	if arg != nil {
		cmd += " " + strings.Join(arg, " ")
	}
	err = session.Run(cmd)
	return infoO.Bytes(), infoE.Bytes(), err
}
