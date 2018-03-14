package main

import (
	"fmt"
	"net"

	"github.com/jim-minter/certgen/pkg/certgen"
	"github.com/jim-minter/certgen/pkg/filesystem"
)

func main() {
	err := run()
	if err != nil {
		panic(err)
	}
}

func run() error {
	c := certgen.Config{
		Nodes: []certgen.Node{
			{
				Hostname: "master",
				IPs: []net.IP{
					net.ParseIP("10.0.0.10"),
				},
				Master: &certgen.Master{
					Port: 8443,
				},
			},
			{
				Hostname: "node1",
				IPs: []net.IP{
					net.ParseIP("10.0.0.11"),
				},
			},
		},
		ExternalMasterHostname: "jminter2ose.eastus.cloudapp.azure.com",
		ExternalRouterIP:       net.ParseIP("52.186.12.236"),
	}

	for i, node := range c.Nodes {
		if node.Master == nil {
			continue
		}
		err := c.PrepareMasterCerts(&c.Nodes[i])
		if err != nil {
			return err
		}
		err = c.PrepareMasterKubeConfigs(&c.Nodes[i])
		if err != nil {
			return err
		}
		err = c.PrepareMasterFiles(&c.Nodes[i])
		if err != nil {
			return err
		}
	}

	for i := range c.Nodes {
		err := c.PrepareNodeCerts(&c.Nodes[i])
		if err != nil {
			return err
		}

		err = c.PrepareNodeKubeConfig(&c.Nodes[i])
		if err != nil {
			return err
		}
	}

	for i, node := range c.Nodes {
		/*
			f, err := os.Create(fmt.Sprintf("%s.tgz", node.Hostname))
			if err != nil {
				return err
			}
			defer f.Close()

			fs, err := filesystem.NewTGZFile(f)
			if err != nil {
				return err
			}
		*/
		fs, err := filesystem.NewFilesystem(fmt.Sprintf("%s/%s", c.ExternalMasterHostname, node.Hostname))

		err = c.WriteNode(fs, &c.Nodes[i])
		if err != nil {
			return err
		}

		err = fs.Close()
		if err != nil {
			return err
		}
	}

	return nil
}
