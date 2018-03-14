package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jim-minter/certgen/pkg/certgen"
	"gopkg.in/yaml.v2"
)

func main() {
	err := run()
	if err != nil {
		panic(err)
	}
}

func run() error {
	files, err := filepath.Glob("example/*/*/*/*")
	if err != nil {
		return err
	}

	for _, origfile := range files {
		fmt.Printf("=== %s\n", origfile)

		newfile := strings.TrimPrefix(origfile, "example/")

		_, err = os.Stat(newfile)
		switch {
		case os.IsNotExist(err):
			if !strings.HasSuffix(newfile, ".serial.txt") {
				fmt.Println("missing")
			}
			continue
		case err != nil:
			return err
		}

		switch {
		case strings.HasSuffix(newfile, ".key") && !strings.HasSuffix(newfile, ".public.key"):
			err = diffPrivateKey(origfile, newfile)
		case strings.HasSuffix(newfile, ".key"):
			err = diffPublicKey(origfile, newfile)
		case strings.HasSuffix(newfile, ".kubeconfig"):
			err = diffKubeConfig(origfile, newfile)
		case strings.HasSuffix(newfile, ".crt"):
			err = diffCertificate(origfile, newfile)
		case strings.HasSuffix(newfile, "/htpasswd"):
		default:
			cmd := exec.Command("diff", "-du", origfile, newfile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				if _, ok := err.(*exec.ExitError); !ok {
					return err
				}
			}
			os.Stdout.Write(out)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func readPrivateKey(filename string) (*rsa.PrivateKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		return key.(*rsa.PrivateKey), err
	default:
		panic("unimplemented")
	}
}

func readPublicKey(filename string) (*rsa.PublicKey, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)

	i, err := x509.ParsePKIXPublicKey(block.Bytes)
	return i.(*rsa.PublicKey), err
}

func readCertificate(filename string) (*x509.Certificate, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	cert.Raw = nil
	cert.RawTBSCertificate = nil
	cert.RawSubjectPublicKeyInfo = nil
	cert.RawSubject = nil
	cert.RawIssuer = nil
	cert.Signature = nil
	cert.PublicKey = nil
	cert.SubjectKeyId = nil
	cert.AuthorityKeyId = nil

	trimS := func(s *string) {
		*s = regexp.MustCompile("@[0-9]+$").ReplaceAllString(*s, "")
	}
	trimI := func(i *interface{}) {
		s := (*i).(string)
		trimS(&s)
		*i = s
	}

	trimS(&cert.Subject.CommonName)
	trimS(&cert.Issuer.CommonName)
	for i := range cert.Subject.Names {
		trimI(&cert.Subject.Names[i].Value)
	}
	for i := range cert.Issuer.Names {
		trimI(&cert.Issuer.Names[i].Value)
	}

	return cert, nil
}

func readKubeConfig(filename string) (*certgen.KubeConfig, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var kubeconfig *certgen.KubeConfig
	err = yaml.Unmarshal(b, &kubeconfig)

	kubeconfig.Clusters[0].Cluster.CertificateAuthorityData = ""
	kubeconfig.Users[0].User.ClientCertificateData = ""
	kubeconfig.Users[0].User.ClientKeyData = ""

	return kubeconfig, err
}

func diffPrivateKey(origfile, newfile string) error {
	origkey, err := readPrivateKey(origfile)
	if err != nil {
		return err
	}

	newkey, err := readPrivateKey(newfile)
	if err != nil {
		return err
	}

	Diff(origkey.N.BitLen(), newkey.N.BitLen())
	Diff(origkey.E, newkey.E)

	return nil
}

func diffPublicKey(origfile, newfile string) error {
	origkey, err := readPublicKey(origfile)
	if err != nil {
		return err
	}

	newkey, err := readPublicKey(newfile)
	if err != nil {
		return err
	}

	Diff(origkey.N.BitLen(), newkey.N.BitLen())
	Diff(origkey.E, newkey.E)

	return nil
}

func diffKubeConfig(origfile, newfile string) error {
	origkc, err := readKubeConfig(origfile)
	if err != nil {
		return err
	}

	newkc, err := readKubeConfig(newfile)
	if err != nil {
		return err
	}

	Diff(origkc, newkc)

	return nil
}

func diffCertificate(origfile, newfile string) error {
	origcert, err := readCertificate(origfile)
	if err != nil {
		return err
	}

	newcert, err := readCertificate(newfile)
	if err != nil {
		return err
	}

	Diff(origcert, newcert)

	return nil
}
