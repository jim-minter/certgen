package main

import (
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v2"
)

type KubeConfig struct {
	APIVersion     string                 `yaml:"apiVersion,omitempty"`
	Kind           string                 `yaml:"kind,omitempty"`
	Clusters       []Cluster              `yaml:"clusters,omitempty"`
	Contexts       []Context              `yaml:"contexts,omitempty"`
	CurrentContext string                 `yaml:"current-context,omitempty"`
	Preferences    map[string]interface{} `yaml:"preferences,omitempty"`
	Users          []User                 `yaml:"users,omitempty"`
}

type Cluster struct {
	Name    string      `yaml:"name,omitempty"`
	Cluster ClusterInfo `yaml:"cluster,omitempty"`
}

type ClusterInfo struct {
	Server                   string `yaml:"server,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
}

type Context struct {
	Name    string      `yaml:"name,omitempty"`
	Context ContextInfo `yaml:"context,omitempty"`
}

type ContextInfo struct {
	Cluster   string `yaml:"cluster,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
	User      string `yaml:"user,omitempty"`
}

type User struct {
	Name string   `yaml:"name,omitempty"`
	User UserInfo `yaml:"user,omitempty"`
}

type UserInfo struct {
	ClientCertificateData string `yaml:"client-certificate-data,omitempty"`
	ClientKeyData         string `yaml:"client-key-data,omitempty"`
}

func (c *Config) PrepareMasterKubeConfigs() error {
	ep := fmt.Sprintf("%s:%d", c.Master.IPs[0].String(), c.Master.Port)
	epName := strings.Replace(ep, ".", "-", -1)

	adminkey, err := privateKeyAsBytes(c.Master.certs["admin"].key)
	if err != nil {
		return err
	}
	masterkey, err := privateKeyAsBytes(c.Master.certs["openshift-master"].key)
	if err != nil {
		return err
	}

	c.Master.kubeconfigs = map[string]KubeConfig{
		"admin.kubeconfig": KubeConfig{
			APIVersion: "v1",
			Kind:       "Config",
			Clusters: []Cluster{
				{
					Name: epName,
					Cluster: ClusterInfo{
						Server: fmt.Sprintf("https://%s", ep),
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(c.cas["ca"].cert.Raw),
					},
				},
			},
			Contexts: []Context{
				{
					Name: fmt.Sprintf("default/%s/system:admin", epName),
					Context: ContextInfo{
						Cluster:   epName,
						Namespace: "default",
						User:      fmt.Sprintf("system:admin/%s", epName),
					},
				},
			},
			CurrentContext: fmt.Sprintf("default/%s/system:admin", epName),
			Users: []User{
				{
					Name: fmt.Sprintf("system:admin/%s", epName),
					User: UserInfo{
						ClientCertificateData: base64.StdEncoding.EncodeToString(c.Master.certs["admin"].cert.Raw),
						ClientKeyData:         base64.StdEncoding.EncodeToString(adminkey),
					},
				},
			},
		},
		"openshift-master.kubeconfig": KubeConfig{
			APIVersion: "v1",
			Kind:       "Config",
			Clusters: []Cluster{
				{
					Name: epName,
					Cluster: ClusterInfo{
						Server: fmt.Sprintf("https://%s", ep),
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(c.cas["ca"].cert.Raw),
					},
				},
			},
			Contexts: []Context{
				{
					Name: fmt.Sprintf("default/%s/system:openshift-master", epName),
					Context: ContextInfo{
						Cluster:   epName,
						Namespace: "default",
						User:      fmt.Sprintf("system:openshift-master/%s", epName),
					},
				},
			},
			CurrentContext: fmt.Sprintf("default/%s/system:openshift-master", epName),
			Users: []User{
				{
					Name: fmt.Sprintf("system:openshift-master/%s", epName),
					User: UserInfo{
						ClientCertificateData: base64.StdEncoding.EncodeToString(c.Master.certs["openshift-master"].cert.Raw),
						ClientKeyData:         base64.StdEncoding.EncodeToString(masterkey),
					},
				},
			},
		},
	}

	return nil
}

func (c *Config) PrepareNodeKubeConfig(node *Node) error {
	ep := fmt.Sprintf("%s:%d", c.Master.IPs[0].String(), c.Master.Port)
	epName := strings.Replace(ep, ".", "-", -1)

	masterclientkey, err := privateKeyAsBytes(node.certs["master-client"].key)
	if err != nil {
		return err
	}

	node.kubeconfigs = map[string]KubeConfig{
		"node.kubeconfig": KubeConfig{
			APIVersion: "v1",
			Kind:       "Config",
			Clusters: []Cluster{
				{
					Name: epName,
					Cluster: ClusterInfo{
						Server: fmt.Sprintf("https://%s", ep),
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(c.cas["ca"].cert.Raw),
					},
				},
			},
			Contexts: []Context{
				{
					Name: fmt.Sprintf("default/%s/system:node:%s", epName, node.Hostname),
					Context: ContextInfo{
						Cluster:   epName,
						Namespace: "default",
						User:      fmt.Sprintf("system:node:%s/%s", node.Hostname, epName),
					},
				},
			},
			CurrentContext: fmt.Sprintf("default/%s/system:node:%s", epName, node.Hostname),
			Users: []User{
				{
					Name: fmt.Sprintf("system:node:%s/%s", node.Hostname, epName),
					User: UserInfo{
						ClientCertificateData: base64.StdEncoding.EncodeToString(node.certs["master-client"].cert.Raw),
						ClientKeyData:         base64.StdEncoding.EncodeToString(masterclientkey),
					},
				},
			},
		},
	}

	return nil
}

func (c *Config) WriteMasterKubeConfigs(fw FileWriter) error {
	for filename, kubeconfig := range c.Master.kubeconfigs {
		b, err := yaml.Marshal(&kubeconfig)
		if err != nil {
			return err
		}
		err = fw.WriteFile(fmt.Sprintf("master/%s", filename), b, 0600)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteNodeKubeConfig(fw FileWriter, node *Node) error {
	for filename, kubeconfig := range node.kubeconfigs {
		b, err := yaml.Marshal(&kubeconfig)
		if err != nil {
			return err
		}
		err = fw.WriteFile(fmt.Sprintf("node-%s/%s", node.Hostname, filename), b, 0600)
		if err != nil {
			return err
		}
	}

	return nil
}
