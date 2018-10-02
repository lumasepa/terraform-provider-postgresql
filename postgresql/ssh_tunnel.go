package postgresql

import (
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
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

func loadConf(conf map[string]string, remoteAddr string) (*sshTunnel, error) {
	//bastion_host - This host will be connected to first, and then the host connection will be made from there.
	//bastion_host_key - The public key from the remote host or the signing CA, used to verify the host connection.
	//bastion_port - The port to use connect to the bastion host.
	//bastion_user - The user for the connection to the bastion host.
	//bastion_password - The password we should use for the bastion host.
	//bastion_private_key - The private key we should use for the bastion host.

	bastionAddr, bastionUser, err := getBastionConf(conf)
	if err != nil {
		return nil, err
	}

	hostKeyValidation, err := getHostKeyCallback(conf)
	if err != nil {
		return nil, err
	}

	auth, err := getAuthMethod(conf)
	if err != nil {
		return nil, err
	}

	freeListenAddr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return nil, err
	}

	return &sshTunnel{
		Local:  freeListenAddr,
		Server: bastionAddr,
		Remote: remoteAddr,
		Config: &ssh.ClientConfig{
			User:            bastionUser,
			Auth:            auth,
			HostKeyCallback: hostKeyValidation,
		},
	}, nil
}

func getBastionConf(conf map[string]string) (string, string, error) {
	bastionHost, ok := conf["bastion_host"]
	if !ok {
		return "", "", errors.New("bastion_host is a required field in ssh_tunnel block")
	}

	bastionPort, ok := conf["bastion_port"]
	if !ok {
		return "", "", errors.New("bastion_port is a required field in ssh_tunnel block")
	}

	bastionAddr := bastionHost + ":" + string(bastionPort)

	bastionUser, ok := conf["bastion_user"]
	if !ok {
		return "", "", errors.New("bastion_user is a required field in ssh_tunnel block")
	}

	return bastionAddr, bastionUser, nil
}

func getAuthMethod(conf map[string]string) ([]ssh.AuthMethod, error) {
	bastionPassword, havePassword := conf["bastion_password"]
	bastionPrivateKey, havePrivateKey := conf["bastion_private_key"]

	if havePrivateKey {
		signer, err := ssh.ParsePrivateKey([]byte(bastionPrivateKey))
		if err != nil {
			return nil, err
		}
		return []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}, nil
	} else if havePassword {
		return []ssh.AuthMethod{
			ssh.Password(bastionPassword),
		}, nil
	}

	return nil, errors.New("one of bastion_password or bastion_private_key is required in block ssh_tunnel")
}

func getHostKeyCallback(conf map[string]string) (ssh.HostKeyCallback, error) {
	bastionHostKey, haveBastionHostKey := conf["bastion_host_key"]

	if haveBastionHostKey {
		publicHostKey, err := ssh.ParsePublicKey([]byte(bastionHostKey))

		if err != nil {
			return nil, err
		}

		return ssh.FixedHostKey(publicHostKey), nil
	}

	return ssh.InsecureIgnoreHostKey(), nil
}

func StartSSHTunnel(conf map[string]string, remoteHost string, remotePort int) (string, int, error) {
	remoteAddr := remoteHost + ":" + string(remotePort)

	tunnel, err := loadConf(conf, remoteAddr)

	if err != nil {
		return "", 0, err
	}

	go tunnel.Start()

	return tunnel.Local.IP.String(), tunnel.Local.Port, nil
}
