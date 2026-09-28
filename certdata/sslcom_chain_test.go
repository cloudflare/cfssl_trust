package main

import (
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/helpers"
)

const (
	intBundleFile     = "../int-bundle.crt"
	caBundleFile      = "../ca-bundle.crt"
	aaaRootCommonName = "AAA Certificate Services"
)

func loadBundle(t *testing.T, file string) []*x509.Certificate {
	t.Helper()
	contents, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	certificates, err := helpers.ParseCertificatesPEM(contents)
	if err != nil {
		t.Fatal(err)
	}
	return certificates
}

func aaaRootPool(t *testing.T) *x509.CertPool {
	t.Helper()
	for _, root := range loadBundle(t, caBundleFile) {
		if root.Subject.CommonName == aaaRootCommonName {
			pool := x509.NewCertPool()
			pool.AddCert(root)
			return pool
		}
	}
	t.Fatalf("%s does not contain %q", caBundleFile, aaaRootCommonName)
	return nil
}

func isSSLcomTLSIssuingOrTransitCA(cert *x509.Certificate) bool {
	name := cert.Subject.CommonName
	return cert.IsCA && strings.HasPrefix(name, "SSL.com ") &&
		(strings.Contains(name, " TLS Issuing ") || strings.Contains(name, " TLS Transit "))
}

// SSL.com TLS Issuing/Transit CAs in the intermediate bundle must not be
// copies issued by AAA Certificate Services. AAA has been removed from Chrome
// and Mozilla, and an AAA-issued copy of the CA that signs the leaf makes the
// whole chain depend on AAA (SECENG-14034). An AAA cross-sign of SSL.com TLS
// Root CA 2022 is allowed: clients that trust Root CA 2022 stop there, and
// only legacy clients use the AAA path.
func TestSSLcomTLSIssuingAndTransitCAsAreNotIssuedByAAARoot(t *testing.T) {
	aaa := aaaRootPool(t)
	checked := 0
	for _, cert := range loadBundle(t, intBundleFile) {
		if !isSSLcomTLSIssuingOrTransitCA(cert) {
			continue
		}
		checked++
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     aaa,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err == nil {
			t.Errorf("%q (serial %X) is issued by %q",
				cert.Subject.CommonName, cert.SerialNumber, aaaRootCommonName)
		}
	}
	if checked == 0 {
		t.Fatalf("%s contains no SSL.com TLS Issuing or Transit CAs", intBundleFile)
	}
}
