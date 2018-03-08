package main

import (
	"fmt"
)

var nodeConfig = []byte(`allowDisabledDocker: false
apiVersion: v1
authConfig:
  authenticationCacheSize: 1000
  authenticationCacheTTL: 5m
  authorizationCacheSize: 1000
  authorizationCacheTTL: 5m
dnsBindAddress: 192.168.121.191:53
dnsDomain: cluster.local
dnsIP: 192.168.121.191
dnsNameservers: null
dnsRecursiveResolvConf: ""
dockerConfig:
  dockerShimRootDirectory: /var/lib/dockershim
  dockerShimSocket: /var/run/dockershim.sock
  execHandlerName: native
enableUnidling: true
imageConfig:
  format: openshift/origin-${component}:${version}
  latest: false
iptablesSyncPeriod: 30s
kind: NodeConfig
kubeletArguments:
  fail-swap-on:
  - "false"
masterClientConnectionOverrides:
  acceptContentTypes: application/vnd.kubernetes.protobuf,application/json
  burst: 40
  contentType: application/vnd.kubernetes.protobuf
  qps: 20
masterKubeConfig: node.kubeconfig
networkConfig:
  mtu: 1450
  networkPluginName: ""
nodeIP: ""
nodeName: default
podManifestConfig: null
servingInfo:
  bindAddress: 0.0.0.0:10250
  bindNetwork: tcp4
  certFile: server.crt
  clientCA: node-client-ca.crt
  keyFile: server.key
  namedCertificates: null
volumeConfig:
  localQuota:
    perFSGroup: null
volumeDirectory: /openshift.local.volumes
`)

func (c *Config) WriteNodeConfig(fw FileWriter, node *Node) error {
	return fw.WriteFile(fmt.Sprintf("node-%s/node-config.yaml", node.Hostname), nodeConfig, 0666)
}
