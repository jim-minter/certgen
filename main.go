package main

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"sync"
)

// for i in *.crt; do echo FILE:$i; diff -du <(openssl x509 -in $i -noout -text -certopt no_serial,no_sigdump,no_pubkey,no_validity) <(openssl x509 -in example/master/$i -noout -text -certopt no_serial,no_sigdump,no_pubkey,no_validity); done

type Config struct {
	Master Master
	Nodes  []Node
	serial serial
	cas    map[string]CertAndKey
}

type Master struct {
	IPs         []net.IP
	Port        int16
	Hostname    string
	certs       map[string]CertAndKey
	kubeconfigs map[string]KubeConfig
}

type Node struct {
	IPs         []net.IP
	Hostname    string
	certs       map[string]CertAndKey
	kubeconfigs map[string]KubeConfig
}

type CertAndKey struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
}

type serial struct {
	m sync.Mutex
	i int64
}

func (s *serial) Get() *big.Int {
	s.m.Lock()
	defer s.m.Unlock()

	s.i++
	return big.NewInt(s.i)
}

func main() {
	err := run()
	if err != nil {
		panic(err)
	}
}

func run() error {
	c := Config{
		Master: Master{
			IPs: []net.IP{
				net.ParseIP("192.168.121.191"),
				net.ParseIP("127.0.0.1"),
				net.ParseIP("172.17.0.1"),
			},
			Port:     8443,
			Hostname: "localhost",
		},
		Nodes: []Node{
			{
				IPs: []net.IP{
					net.ParseIP("192.168.121.191"),
					net.ParseIP("127.0.0.1"),
					net.ParseIP("172.17.0.1"),
				},
				Hostname: "default",
			},
		},
	}

	err := c.PrepareMasterCerts()
	if err != nil {
		return err
	}

	err = c.PrepareMasterKubeConfigs()
	if err != nil {
		return err
	}

	for i := range c.Nodes {
		err = c.PrepareNodeCerts(&c.Nodes[i])
		if err != nil {
			return err
		}

		err = c.PrepareNodeKubeConfig(&c.Nodes[i])
		if err != nil {
			return err
		}
	}

	fw, err := NewTGZFile("master.tgz")
	if err != nil {
		return err
	}

	err = c.WriteMaster(fw)
	if err != nil {
		return err
	}

	err = fw.Close()
	if err != nil {
		return err
	}

	for i, node := range c.Nodes {
		fw, err := NewTGZFile(fmt.Sprintf("node-%s.tgz", node.Hostname))
		if err != nil {
			return err
		}

		err = c.WriteNode(fw, &c.Nodes[i])
		if err != nil {
			return err
		}

		err = fw.Close()
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteMaster(fw FileWriter) error {
	err := fw.Mkdir("master", 0777)
	if err != nil {
		return err
	}

	err = c.WriteMasterCerts(fw)
	if err != nil {
		return err
	}

	err = c.WriteMasterKeypair(fw)
	if err != nil {
		return err
	}

	err = c.WriteMasterKubeConfigs(fw)
	if err != nil {
		return err
	}

	err = c.WriteMasterConfig(fw)
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) WriteNode(fw FileWriter, node *Node) error {
	err := fw.Mkdir(fmt.Sprintf("node-%s", node.Hostname), 0777)
	if err != nil {
		return err
	}

	err = c.WriteNodeCerts(fw, node)
	if err != nil {
		return err
	}

	err = c.WriteNodeKubeConfig(fw, node)
	if err != nil {
		return err
	}

	err = c.WriteNodeConfig(fw, node)
	if err != nil {
		return err
	}

	return nil
}
