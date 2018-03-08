package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

func newCertAndKey(filename string, template, signingcert *x509.Certificate, signingkey *rsa.PrivateKey) (CertAndKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return CertAndKey{}, err
	}

	if signingcert == nil {
		// make it self-signed
		signingcert = template
		signingkey = key
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

func writeCert(fw FileWriter, filename string, cert *x509.Certificate) error {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err != nil {
		return err
	}

	return fw.WriteFile(filename, buf.Bytes(), 0666)
}

func privateKeyAsBytes(key *rsa.PrivateKey) ([]byte, error) {
	buf := &bytes.Buffer{}

	err := pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writePrivateKey(fw FileWriter, filename string, key *rsa.PrivateKey) error {
	b, err := privateKeyAsBytes(key)
	if err != nil {
		return err
	}

	return fw.WriteFile(filename, b, 0600)
}

func writePublicKey(fw FileWriter, filename string, key *rsa.PublicKey) error {
	buf := &bytes.Buffer{}

	b, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return err
	}

	err = pem.Encode(buf, &pem.Block{Type: "PUBLIC KEY", Bytes: b})
	if err != nil {
		return err
	}

	return fw.WriteFile(filename, buf.Bytes(), 0666)
}

func (c *Config) PrepareMasterCerts() error {
	if c.cas == nil {
		c.cas = map[string]CertAndKey{}
	}

	if c.Master.certs == nil {
		c.Master.certs = map[string]CertAndKey{}
	}

	ips := append([]net.IP{net.ParseIP("172.30.0.1")}, c.Master.IPs...)

	dns := []string{
		"kubernetes", "kubernetes.default", "kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local", "openshift",
		"openshift.default", "openshift.default.svc",
		"openshift.default.svc.cluster.local",
	}
	dns = append(dns, c.Master.Hostname)
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
				Subject: pkix.Name{CommonName: fmt.Sprintf("aggregator-proxy-ca@%d", now.Unix())},
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

		certAndKey, err := newCertAndKey(cacert.filename, template, nil, nil)
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
				Subject:     pkix.Name{Organization: []string{"system:cluster-admins", "system:masters"}, CommonName: "system:admin"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "etcd.server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "127.0.0.1"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    dns,
				IPAddresses: ips,
			},
		},
		{
			filename: "master.etcd-client",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "system:master"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
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
				Subject:     pkix.Name{CommonName: "127.0.0.1"},
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
				Subject:     pkix.Name{Organization: []string{"system:masters"}, CommonName: "system:openshift-master"},
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
		template.DNSNames = cert.template.DNSNames
		template.IPAddresses = cert.template.IPAddresses

		if cert.signer == "" {
			cert.signer = "ca"
		}

		certAndKey, err := newCertAndKey(cert.filename, template, c.cas[cert.signer].cert, c.cas[cert.signer].key)
		if err != nil {
			return err
		}

		c.Master.certs[cert.filename] = certAndKey
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
			filename: "master-client",
			template: &x509.Certificate{
				Subject:     pkix.Name{Organization: []string{"system:nodes"}, CommonName: fmt.Sprintf("system:node:%s", node.Hostname)},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			},
		},
		{
			filename: "server",
			template: &x509.Certificate{
				Subject:     pkix.Name{CommonName: "127.0.0.1"},
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
				DNSNames:    dns,
				IPAddresses: node.IPs,
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

		certAndKey, err := newCertAndKey(cert.filename, template, c.cas[cert.signer].cert, c.cas[cert.signer].key)
		if err != nil {
			return err
		}

		node.certs[cert.filename] = certAndKey
	}

	return nil
}

func (c *Config) WriteMasterCerts(fw FileWriter) error {
	for filename, ca := range c.cas {
		err := writeCert(fw, fmt.Sprintf("master/%s.crt", filename), ca.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fw, fmt.Sprintf("master/%s.key", filename), ca.key)
		if err != nil {
			return err
		}
	}

	err := writeCert(fw, "master/ca-bundle.crt", c.cas["ca"].cert)
	if err != nil {
		return err
	}

	for filename, cert := range c.Master.certs {
		err := writeCert(fw, fmt.Sprintf("master/%s.crt", filename), cert.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fw, fmt.Sprintf("master/%s.key", filename), cert.key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteNodeCerts(fw FileWriter, node *Node) error {
	for _, filename := range []string{"ca", "node-client-ca"} {
		err := writeCert(fw, fmt.Sprintf("node-%s/%s.crt", node.Hostname, filename), c.cas["ca"].cert)
		if err != nil {
			return err
		}
	}

	for filename, cert := range node.certs {
		err := writeCert(fw, fmt.Sprintf("node-%s/%s.crt", node.Hostname, filename), cert.cert)
		if err != nil {
			return err
		}

		err = writePrivateKey(fw, fmt.Sprintf("node-%s/%s.key", node.Hostname, filename), cert.key)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Config) WriteMasterKeypair(fw FileWriter) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	err = writePrivateKey(fw, "master/serviceaccounts.private.key", key)
	if err != nil {
		return err
	}

	return writePublicKey(fw, "master/serviceaccounts.public.key", &key.PublicKey)
}
