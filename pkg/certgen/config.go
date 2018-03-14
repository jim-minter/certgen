package certgen

import (
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net"
	"sync"

	"github.com/jim-minter/certgen/pkg/filesystem"
)

type Config struct {
	Nodes                  []Node
	ExternalRouterIP       net.IP
	ExternalMasterHostname string
	serial                 serial
	cas                    map[string]CertAndKey
	AuthSecret             string
	EncSecret              string
}

type openShiftConfig struct {
	certs       map[string]CertAndKey
	kubeconfigs map[string]KubeConfig
}

type Node struct {
	Hostname string
	IPs      []net.IP
	Master   *Master
	openShiftConfig
}

type Master struct {
	Port int16
	openShiftConfig
	etcdcerts map[string]CertAndKey
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

func (c *Config) writeMaster(fs filesystem.Filesystem, node *Node) error {
	err := c.WriteMasterCerts(fs, node)
	if err != nil {
		return err
	}

	err = c.WriteMasterKeypair(fs, node)
	if err != nil {
		return err
	}

	err = c.WriteMasterKubeConfigs(fs, node)
	if err != nil {
		return err
	}

	err = c.WriteMasterFiles(fs, node)
	if err != nil {
		return err
	}

	return nil
}

func (c *Config) WriteNode(fs filesystem.Filesystem, node *Node) error {
	if node.Master != nil {
		err := c.writeMaster(fs, node)
		if err != nil {
			return err
		}
	}

	err := c.WriteNodeCerts(fs, node)
	if err != nil {
		return err
	}

	err = c.WriteNodeKubeConfig(fs, node)
	if err != nil {
		return err
	}

	err = c.WriteNodeFiles(fs, node)
	if err != nil {
		return err
	}

	return nil
}
