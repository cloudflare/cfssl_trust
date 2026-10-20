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

func isSSLcomTLSIssuingOrTransitCA(cert *x509.Certificate) bool {
	name := cert.Subject.CommonName
	return cert.IsCA && strings.HasPrefix(name, "SSL.com ") &&
		(strings.Contains(name, " TLS Issuing ") || strings.Contains(name, " TLS Transit "))
}

// SSL.com TLS Issuing/Transit CAs must chain to SSL.com roots without
// depending on the distrusted AAA Certificate Services root.
func TestSSLcomTLSIssuingAndTransitCAsAreNotIssuedByAAARoot(t *testing.T) {
	checked := 0
	for _, cert := range loadBundle(t, intBundleFile) {
		if !isSSLcomTLSIssuingOrTransitCA(cert) {
			continue
		}
		checked++
		if cert.Issuer.CommonName == aaaRootCommonName {
			t.Errorf("%q (serial %X) is issued by %q",
				cert.Subject.CommonName, cert.SerialNumber, aaaRootCommonName)
		}
	}
	if checked == 0 {
		t.Fatalf("%s contains no SSL.com TLS Issuing or Transit CAs", intBundleFile)
	}
}
