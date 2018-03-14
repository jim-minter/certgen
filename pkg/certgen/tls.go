package certgen

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/jim-minter/certgen/pkg/filesystem"
)

type authKeyId struct {
	KeyIdentifier             []byte      `asn1:"optional,tag:0"`
	AuthorityCertIssuer       generalName `asn1:"optional,tag:1"`
	AuthorityCertSerialNumber *big.Int    `asn1:"optional,tag:2"`
}

type generalName struct {
	DirectoryName pkix.RDNSequence `asn1:"optional,explicit,tag:4"`
}

func newCertAndKey(filename string, template, signingcert *x509.Certificate, signingkey *rsa.PrivateKey, etcdcaspecial, etcdclientspecial bool) (CertAndKey, error) {
	bits := 2048
	if etcdcaspecial {
		bits = 4096
	}

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return CertAndKey{}, err
	}

	if signingcert == nil {
		// make it self-signed
		signingcert = template
		signingkey = key
	}

	if etcdcaspecial {
		template.SubjectKeyId = intsha1(key.N)
		ext := pkix.Extension{
			Id: []int{2, 5, 29, 35},
		}
		var err error
		ext.Value, err = asn1.Marshal(authKeyId{
			AuthorityCertIssuer:       generalName{DirectoryName: signingcert.Subject.ToRDNSequence()},
			AuthorityCertSerialNumber: signingcert.SerialNumber,
		})
		if err != nil {
			return CertAndKey{}, err
		}
		template.ExtraExtensions = append(template.Extensions, ext)
		template.MaxPathLenZero = true
	}

	if etcdclientspecial {
		template.SubjectKeyId = intsha1(key.N)
		ext := pkix.Extension{
			Id: []int{2, 5, 29, 35},
		}
		var err error
		ext.Value, err = asn1.Marshal(authKeyId{
			KeyIdentifier:             intsha1(signingkey.N),
			AuthorityCertIssuer:       generalName{DirectoryName: signingcert.Subject.ToRDNSequence()},
			AuthorityCertSerialNumber: signingcert.SerialNumber,
		})
		if err != nil {
			return CertAndKey{}, err
		}
		template.ExtraExtensions = append(template.Extensions, ext)
	}

	b, err := x509.CreateCertificate(rand.Reader, template, signingcert, key.Public(), signingkey)
	if err != nil {
		return CertAndKey{}, err
	}

	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return CertAndKey{}, err
	}

	return CertAndKey{cert: cert, key: key}, nil
}

func certAsBytes(cert *x509.Certificate) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writeCert(fs filesystem.Filesystem, filename string, cert *x509.Certificate) error {
	b, err := certAsBytes(cert)
	if err != nil {
		return err
	}

	return fs.WriteFile(filename, b, 0666)
}

func privateKeyAsBytes(key *rsa.PrivateKey) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writePrivateKey(fs filesystem.Filesystem, filename string, key *rsa.PrivateKey) error {
	b, err := privateKeyAsBytes(key)
	if err != nil {
		return err
	}

	return fs.WriteFile(filename, b, 0600)
}

func writePublicKey(fs filesystem.Filesystem, filename string, key *rsa.PublicKey) error {
	buf := &bytes.Buffer{}

	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	err = pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b})
	if err != nil {
		return err
	}

	return fs.WriteFile(filename, buf.Bytes(), 0666)
}

func (c *Config) PrepareMasterCerts(node *Node) error {
	if c.cas == nil {
		c.cas = map[string]CertAndKey{}
	}

	if node.Master.certs == nil {
		node.Master.certs = map[string]CertAndKey{}
	}

	if node.Master.etcdcerts == nil {
		node.Master.etcdcerts = map[string]CertAndKey{}
	}

	ips := append([]net.IP{}, node.IPs...)
	ips = append(ips, net.ParseIP("172.30.0.1"))

	dns := []string{
		c.ExternalMasterHostname, "kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local", node.Hostname, "openshift",
		"openshift.default", "openshift.default.svc",
		"openshift.default.svc.cluster.local",
	}
	for _, ip := range ips {
		dns = append(dns, ip.String())
	}

	now := time.Now()

	cacerts := []struct {
		filename string
		template *x509.Certificate
	}{
		{
			filename: "ca",
			template: &x509.Certificate{
				Subject: pkix.Name{CommonName: fmt.Sprintf("openshift-signer@%d", now.Unix())},
			},
		},
		{
			filename: "frontproxy-ca",
			template: &x509.Certificate{
				Subject: pkix.Name{CommonName: fmt.Sprintf("openshift-signer@%d", now.Unix())},
			},
		},
		{
			filename: "master.etcd-ca",
			template: &x509.Certificate{
				Subject: pkix.Name{CommonName: fmt.Sprintf("etcd-signer@%d", now.Unix())},
			},
		},
		{
			filename: "service-signer",
			template: &x509.Certificate{
				Subject: pkix.Name{CommonName: fmt.Sprintf("openshift-service-serving-signer@%d", now.Unix())},
			},
		},
	}

	for _, cacert := range cacerts {
		template := &x509.Certificate{
			SerialNumber:          c.serial.Get(),
			NotBefore:             now,
			NotAfter:              now.AddDate(5, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
			IsCA: true,
		}
		template.Subject = cacert.template.Subject

		certAndKey, err := newCertAndKey(cacert.filename, template, nil, nil, cacert.filename == "master.etcd-ca", false)
		if err != nil {
			return err
		}

		c.cas[cacert.filename] = certAndKey
	}

	certs := []struct {
		filename string
		template *x509.Certificate
		signer   string
	}{
		{
			filename: "admin",
			template: &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"system:cluster-admins"}, CommonName: "system:admin"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "aggregator-front-proxy",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "aggregator-front-proxy"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "etcd.server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.IPs[0].String()},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    dns,
				IPAddresses: ips,
			},
		},
		{
			filename: "master.etcd-client",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.Hostname},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
				DNSNames:    []string{node.Hostname}, // TODO
				IPAddresses: []net.IP{node.IPs[0]},   // TODO
			},
			signer: "master.etcd-ca",
		},
		{
			filename: "master.kubelet-client",
			template: &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"system:node-admins"}, CommonName: "system:openshift-node-admin"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "master.proxy-client",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "system:master-proxy"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "master.server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.IPs[0].String()},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    dns,
				IPAddresses: ips,
			},
		},
		{
			filename: "openshift-aggregator",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "system:openshift-aggregator"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
			signer: "frontproxy-ca",
		},
		{
			filename: "openshift-master",
			template: &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"system:masters", "system:openshift-master"}, CommonName: "system:openshift-master"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "openshift-router",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: fmt.Sprintf("*.%s.nip.io", c.ExternalRouterIP.String())},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    []string{fmt.Sprintf("*.%s.nip.io", c.ExternalRouterIP.String()), fmt.Sprintf("%s.nip.io", c.ExternalRouterIP.String())},
			},
		},
		// TODO: registry cert?
	}

	for _, cert := range certs {
		template := &x509.Certificate{
			SerialNumber:          c.serial.Get(),
			NotBefore:             now,
			NotAfter:              now.AddDate(2, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
		}
		template.Subject = cert.template.Subject
		template.ExtKeyUsage = cert.template.ExtKeyUsage
		template.DNSNames = cert.template.DNSNames
		template.IPAddresses = cert.template.IPAddresses

		if cert.signer == "" {
			cert.signer = "ca"
		}

		certAndKey, err := newCertAndKey(cert.filename, template, c.cas[cert.signer].cert, c.cas[cert.signer].key, false, cert.filename == "master.etcd-client")
		if err != nil {
			return err
		}

		node.Master.certs[cert.filename] = certAndKey
	}

	etcdcerts := []struct {
		filename string
		template *x509.Certificate
		signer   string
	}{
		{
			filename: "peer",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.Hostname},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
				DNSNames:    []string{node.Hostname}, // TODO
				IPAddresses: []net.IP{node.IPs[0]},   // TODO
			},
			signer: "master.etcd-ca",
		},
		{
			filename: "server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.Hostname},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    []string{node.Hostname}, // TODO
				IPAddresses: []net.IP{node.IPs[0]},   // TODO
			},
			signer: "master.etcd-ca",
		},
	}

	for _, cert := range etcdcerts {
		template := &x509.Certificate{
			SerialNumber:          c.serial.Get(),
			NotBefore:             now,
			NotAfter:              now.AddDate(5, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
		}
		template.Subject = cert.template.Subject
		template.ExtKeyUsage = cert.template.ExtKeyUsage
		template.DNSNames = cert.template.DNSNames
		template.IPAddresses = cert.template.IPAddresses

		certAndKey, err := newCertAndKey(cert.filename, template, c.cas[cert.signer].cert, c.cas[cert.signer].key, false, true)
		if err != nil {
			return err
		}

		node.Master.etcdcerts[cert.filename] = certAndKey
	}

	return nil
}

func (c *Config) PrepareNodeCerts(node *Node) error {
	if node.certs == nil {
		node.certs = map[string]CertAndKey{}
	}

	dns := []string{node.Hostname}
	for _, ip := range node.IPs {
		dns = append(dns, ip.String())
	}

	now := time.Now()

	certs := []struct {
		filename string
		template *x509.Certificate
		signer   string
	}{
		{
			filename: "server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: node.IPs[0].String()},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    dns,
				IPAddresses: node.IPs,
			},
		},
		{
			filename: fmt.Sprintf("system:node:%s", node.Hostname),
			template: &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"system:nodes"}, CommonName: fmt.Sprintf("system:node:%s", node.Hostname)},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
	}

	for _, cert := range certs {
		template := &x509.Certificate{
			SerialNumber:          c.serial.Get(),
			NotBefore:             now,
			NotAfter:              now.AddDate(2, 0, 0),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			BasicConstraintsValid: true,
		}
		template.Subject = cert.template.Subject
		template.ExtKeyUsage = cert.template.ExtKeyUsage
		template.IPAddresses = cert.template.IPAddresses
		template.DNSNames = cert.template.DNSNames

		if cert.signer == "" {
			cert.signer = "ca"
		}

		certAndKey, err := newCertAndKey(cert.filename, template, c.cas[cert.signer].cert, c.cas[cert.signer].key, false, false)
		if err != nil {
			return err
		}

		node.certs[cert.filename] = certAndKey
	}

	return nil
}

func (c *Config) WriteMasterCerts(fs filesystem.Filesystem, node *Node) error {
	for filename, ca := range c.cas {
		err := writeCert(fs, fmt.Sprintf("etc/origin/master/%s.crt", filename), ca.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fs, fmt.Sprintf("etc/origin/master/%s.key", filename), ca.key)
		if err != nil {
			return err
		}
	}

	err := writeCert(fs, "etc/origin/master/ca-bundle.crt", c.cas["ca"].cert)
	if err != nil {
		return err
	}

	err = writeCert(fs, "etc/origin/master/client-ca-bundle.crt", c.cas["ca"].cert) // TODO: confirm if needed
	if err != nil {
		return err
	}

	err = writeCert(fs, "etc/origin/master/front-proxy-ca.crt", c.cas["frontproxy-ca"].cert) // TODO: confirm if needed
	if err != nil {
		return err
	}

	err = writePrivateKey(fs, "etc/origin/master/front-proxy-ca.key", c.cas["frontproxy-ca"].key) // TODO: confirm if needed
	if err != nil {
		return err
	}

	err = writeCert(fs, "etc/etcd/ca.crt", c.cas["master.etcd-ca"].cert)
	if err != nil {
		return err
	}

	for filename, cert := range node.Master.certs {
		err := writeCert(fs, fmt.Sprintf("etc/origin/master/%s.crt", filename), cert.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fs, fmt.Sprintf("etc/origin/master/%s.key", filename), cert.key)
		if err != nil {
			return err
		}
	}

	for filename, cert := range node.Master.etcdcerts {
		err := writeCert(fs, fmt.Sprintf("etc/etcd/%s.crt", filename), cert.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fs, fmt.Sprintf("etc/etcd/%s.key", filename), cert.key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteNodeCerts(fs filesystem.Filesystem, node *Node) error {
	for _, filename := range []string{"ca", "node-client-ca"} {
		err := writeCert(fs, fmt.Sprintf("etc/origin/node/%s.crt", filename), c.cas["ca"].cert)
		if err != nil {
			return err
		}
	}

	for filename, cert := range node.certs {
		err := writeCert(fs, fmt.Sprintf("etc/origin/node/%s.crt", filename), cert.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fs, fmt.Sprintf("etc/origin/node/%s.key", filename), cert.key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteMasterKeypair(fs filesystem.Filesystem, node *Node) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = writePrivateKey(fs, "etc/origin/master/serviceaccounts.private.key", key)
	if err != nil {
		return err
	}

	return writePublicKey(fs, "etc/origin/master/serviceaccounts.public.key", &key.PublicKey)
}

func intsha1(n *big.Int) []byte {
	h := sha1.New()
	h.Write(n.Bytes())
	return h.Sum(nil)
}
