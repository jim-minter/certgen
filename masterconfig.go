package main

var masterConfig = []byte(`admissionConfig:
pluginConfig: null
aggregatorConfig:
proxyClientInfo:
  certFile: openshift-aggregator.crt
  keyFile: openshift-aggregator.key
apiLevels:
- v1
apiVersion: v1
auditConfig:
auditFilePath: ""
enabled: true
logFormat: ""
maximumFileRetentionDays: 0
maximumFileSizeMegabytes: 0
maximumRetainedFiles: 0
policyConfiguration: null
policyFile: ""
webHookKubeConfig: ""
webHookMode: ""
authConfig:
requestHeader:
  clientCA: frontproxy-ca.crt
  clientCommonNames:
  - system:openshift-aggregator
  extraHeaderPrefixes:
  - X-Remote-Extra-
  groupHeaders:
  - X-Remote-Group
  usernameHeaders:
  - X-Remote-User
controllerConfig:
controllers:
- '*'
election: null
serviceServingCert:
  signer:
	certFile: service-signer.crt
	keyFile: service-signer.key
controllerLeaseTTL: 0
controllers: '*'
corsAllowedOrigins:
- //127\.0\.0\.1(:|$)
- //192\.168\.121\.191:8443$
- //localhost(:|$)
disabledFeatures: null
dnsConfig:
allowRecursiveQueries: true
bindAddress: 0.0.0.0:8053
bindNetwork: tcp4
etcdClientInfo:
ca: ca.crt
certFile: master.etcd-client.crt
keyFile: master.etcd-client.key
urls:
- https://192.168.121.191:4001
etcdConfig:
address: 192.168.121.191:4001
peerAddress: 192.168.121.191:7001
peerServingInfo:
  bindAddress: 0.0.0.0:7001
  bindNetwork: tcp4
  certFile: etcd.server.crt
  clientCA: ca.crt
  keyFile: etcd.server.key
  namedCertificates: null
servingInfo:
  bindAddress: 0.0.0.0:4001
  bindNetwork: tcp4
  certFile: etcd.server.crt
  clientCA: ca.crt
  keyFile: etcd.server.key
  namedCertificates: null
storageDirectory: /openshift.local.etcd
etcdStorageConfig:
kubernetesStoragePrefix: kubernetes.io
kubernetesStorageVersion: v1
openShiftStoragePrefix: openshift.io
openShiftStorageVersion: v1
imageConfig:
format: openshift/origin-${component}:${version}
latest: false
imagePolicyConfig:
allowedRegistriesForImport:
- domainName: docker.io
- domainName: '*.docker.io'
- domainName: '*.redhat.com'
- domainName: gcr.io
- domainName: quay.io
- domainName: registry.centos.org
- domainName: registry.redhat.io
- domainName: '*.amazonaws.com'
disableScheduledImport: false
maxImagesBulkImportedPerRepository: 5
maxScheduledImageImportsPerMinute: 60
scheduledImageImportMinimumIntervalSeconds: 900
jenkinsPipelineConfig:
autoProvisionEnabled: true
parameters: null
serviceName: jenkins
templateName: jenkins-ephemeral
templateNamespace: openshift
kind: MasterConfig
kubeletClientInfo:
ca: ca.crt
certFile: master.kubelet-client.crt
keyFile: master.kubelet-client.key
port: 10250
kubernetesMasterConfig:
admissionConfig:
  pluginConfig: null
apiLevels: null
apiServerArguments:
  storage-backend:
  - etcd3
  storage-media-type:
  - application/vnd.kubernetes.protobuf
controllerArguments: null
disabledAPIGroupVersions: {}
masterCount: 1
masterEndpointReconcileTTL: 15
masterIP: 192.168.121.191
podEvictionTimeout: 5m
proxyClientInfo:
  certFile: master.proxy-client.crt
  keyFile: master.proxy-client.key
schedulerArguments: null
schedulerConfigFile: ""
servicesNodePortRange: 30000-32767
servicesSubnet: 172.30.0.0/16
staticNodeNames: null
masterClients:
externalKubernetesClientConnectionOverrides:
  acceptContentTypes: application/vnd.kubernetes.protobuf,application/json
  burst: 400
  contentType: application/vnd.kubernetes.protobuf
  qps: 200
externalKubernetesKubeConfig: ""
openshiftLoopbackClientConnectionOverrides:
  acceptContentTypes: application/vnd.kubernetes.protobuf,application/json
  burst: 600
  contentType: application/vnd.kubernetes.protobuf
  qps: 300
openshiftLoopbackKubeConfig: openshift-master.kubeconfig
masterPublicURL: https://192.168.121.191:8443
networkConfig:
clusterNetworkCIDR: 10.128.0.0/14
clusterNetworks:
- cidr: 10.128.0.0/14
  hostSubnetLength: 9
externalIPNetworkCIDRs: null
hostSubnetLength: 9
ingressIPNetworkCIDR: 172.29.0.0/16
networkPluginName: ""
serviceNetworkCIDR: 172.30.0.0/16
oauthConfig:
alwaysShowProviderSelection: false
assetPublicURL: https://192.168.121.191:8443/console/
grantConfig:
  method: auto
  serviceAccountMethod: prompt
identityProviders:
- challenge: true
  login: true
  mappingMethod: claim
  name: anypassword
  provider:
	apiVersion: v1
	kind: AllowAllPasswordIdentityProvider
masterCA: ca-bundle.crt
masterPublicURL: https://192.168.121.191:8443
masterURL: https://192.168.121.191:8443
sessionConfig:
  sessionMaxAgeSeconds: 300
  sessionName: ssn
  sessionSecretsFile: ""
templates: null
tokenConfig:
  accessTokenMaxAgeSeconds: 86400
  authorizeTokenMaxAgeSeconds: 300
pauseControllers: false
policyConfig:
bootstrapPolicyFile: policy.json
openshiftInfrastructureNamespace: openshift-infra
openshiftSharedResourcesNamespace: openshift
userAgentMatchingConfig:
  defaultRejectionMessage: ""
  deniedClients: null
  requiredClients: null
projectConfig:
defaultNodeSelector: ""
projectRequestMessage: ""
projectRequestTemplate: ""
securityAllocator:
  mcsAllocatorRange: s0:/2
  mcsLabelsPerProject: 5
  uidAllocatorRange: 1000000000-1999999999/10000
routingConfig:
subdomain: router.default.svc.cluster.local
serviceAccountConfig:
limitSecretReferences: false
managedNames:
- default
- builder
- deployer
masterCA: ca-bundle.crt
privateKeyFile: serviceaccounts.private.key
publicKeyFiles:
- serviceaccounts.public.key
servingInfo:
bindAddress: 0.0.0.0:8443
bindNetwork: tcp4
certFile: master.server.crt
clientCA: ca.crt
keyFile: master.server.key
maxRequestsInFlight: 1200
namedCertificates: null
requestTimeoutSeconds: 3600
volumeConfig:
dynamicProvisioningEnabled: true
`)

func (c *Config) WriteMasterConfig(fw FileWriter) error {
	return fw.WriteFile("master/master-config.yaml", masterConfig, 0666)
}
