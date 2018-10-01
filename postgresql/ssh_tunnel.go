package postgresql

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
)

type sshTunnel struct {
	Local  *net.TCPAddr
	Server string
	Remote string
	Config *ssh.ClientConfig
}

func (tunnel *sshTunnel) Start() error {
	listener, err := net.Listen("tcp", tunnel.Local.String())
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go tunnel.forward(conn)
	}
}

func (tunnel *sshTunnel) forward(localConn net.Conn) {
	serverConn, err := ssh.Dial("tcp", tunnel.Server, tunnel.Config)
	if err != nil {
		fmt.Printf("Server dial error: %s\n", err)
		return
	}

	remoteConn, err := serverConn.Dial("tcp", tunnel.Remote)
	if err != nil {
		fmt.Printf("Remote dial error: %s\n", err)
		return
	}

	copyConn := func(writer, reader net.Conn) {
		_, err := io.Copy(writer, reader)
		if err != nil {
			fmt.Printf("io.Copy error: %s", err)
		}
	}

	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
}

func parseConf(conf map[string]string, dbAddr string) (*sshTunnel, error) {
	//bastion_host - Setting this enables the bastion Host connection. This host will be connected to first, and then the host connection will be made from there.
	//bastion_host_key - The public key from the remote host or the signing CA, used to verify the host connection.
	//bastion_port - The port to use connect to the bastion host. Defaults to the value of the port field.
	//bastion_user - The user for the connection to the bastion host. Defaults to the value of the user field.
	//bastion_password - The password we should use for the bastion host. Defaults to the value of the password field.
	//bastion_private_key

	bastionHost, ok := conf["bastion_host"]
	if !ok {
		return nil, errors.New("")
	}

	bastionPort, ok := conf["bastion_port"]
	if !ok {
		return nil, errors.New("")
	}

	bastionAddr := bastionHost + ":" + string(bastionPort)

	bastionUser, ok := conf["bastion_user"]
	if !ok {
		return nil, errors.New("")
	}

	// bastionHostKey, ok := conf["bastion_host_key"]

	bastionPassword, havePassword := conf["bastion_password"]
	bastionPrivateKey, havePrivateKey := conf["bastion_private_key"]

	var auth []ssh.AuthMethod

	if havePrivateKey {
		signer, err := ssh.ParsePrivateKey([]byte(bastionPrivateKey))
		if err != nil {
			log.Fatalf("unable to parse private key: %v", err)
		}
		auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}
	} else if havePassword {
		auth = []ssh.AuthMethod{
			ssh.Password(bastionPassword),
		}
	} else {
		return nil, errors.New("")
	}

	freeListenAddr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	return &sshTunnel{
		Local:  freeListenAddr,
		Server: bastionAddr,
		Remote: dbAddr,
		Config: &ssh.ClientConfig{
			User: bastionUser,
			Auth: auth,
		},
	}, nil
}

func StartSSHTunnel(conf map[string]string, dbHost string, dbPort int) (string, int, error) {
	dbAddr := dbHost + ":" + string(dbPort)

	tunnel, err := parseConf(conf, dbAddr)

	if err != nil {
		return "", 0, err
	}

	go tunnel.Start()

	return tunnel.Local.IP.String(), tunnel.Local.Port, nil
}
