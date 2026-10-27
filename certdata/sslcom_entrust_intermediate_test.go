package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
)

const sslcomRSARoot2022CommonName = "SSL.com TLS RSA Root CA 2022"

// SSL.com operates Entrust's public TLS hierarchy and issues Entrust-branded
// leaves from these intermediates. Without them in the intermediate bundle,
// compatible-mode bundling cannot build a chain for those leaves (GitHub
// issue #308).
func TestSSLcomEntrustIssuingCAsChainToSSLcomRSARoot2022(t *testing.T) {
	want := map[string]string{
		"345c0cf70370a56d465b8e6ed531b55cc8eb1da5b26880775c589a2f43358d83": "Entrust OV TLS Issuing RSA CA 1",
		"d5612c7ed743b64cd8db432cedfea582608d4223f119eface7a6753534392ac8": "Entrust EV TLS Issuing RSA CA 1",
	}

	roots := x509.NewCertPool()
	for _, root := range loadBundle(t, caBundleFile) {
		if root.Subject.CommonName == sslcomRSARoot2022CommonName {
			roots.AddCert(root)
		}
	}

	for _, cert := range loadBundle(t, intBundleFile) {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		name, found := want[fingerprint]
		if !found {
			continue
		}
		delete(want, fingerprint)
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:     roots,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Errorf("%q does not chain to %q: %v", name, sslcomRSARoot2022CommonName, err)
		}
	}
	for fingerprint, name := range want {
		t.Errorf("%s is missing %q (%s)", intBundleFile, name, fingerprint)
	}
}
