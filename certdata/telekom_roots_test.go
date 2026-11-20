package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"testing"
	"time"
)

const (
	// Serial 219C542DE8F6EC7177FA4EE8C3705797.
	telekomRSARoot2023Fingerprint = "efc65cadbb59adb6efe84da22311b35624b71b3b1ea0da8b6655174ec8978646"
	// Serial 363A968CC95CB258CDD0015DC5E55700.
	telekomECCRoot2020Fingerprint = "578af4ded0853f4e5998db4aeaf9cbea8d945f60b620a38d1a3c13b2bc7ba8e1"
	// Telekom Security OV RSA CA 26A, serial 118282E70C01C7416642DD8576CED055.
	telekomOVRSACA26AFingerprint = "c76e23dfa0014b885a6ded8e6d64c295af4991dc7872c1af8b0fef527e263929"
	// The chain that origins using Telekom Security OV RSA CA 26A send after
	// their leaf: 26A, then the self-signed RSA Root 2023.
	telekomServedChainFile = "testdata/telekom-ov-rsa-ca-26a-served-chain.pem"
)

// telekomVerificationTime is inside the validity period of both certificates
// in the served chain (26A is valid 2026-03-19 to 2029-03-18), so the chain
// tests do not depend on the date they run.
var telekomVerificationTime = time.Date(2026, time.November, 20, 0, 0, 0, 0, time.UTC)

// Both Telekom Security TLS roots are in the Mozilla, Chrome and Microsoft
// root stores and are trusted as self-signed anchors. For the RSA root, the
// T-TeleSec GlobalRoot Class 3 cross-sign is not a substitute: servers send
// the self-signed root in their chains, and OpenSSL rejects such a chain when
// that root is not itself a trust anchor.
func TestTelekomSecurityTLSRootsAreSelfSignedTrustAnchors(t *testing.T) {
	expected := map[string]string{
		telekomRSARoot2023Fingerprint: "Telekom Security TLS RSA Root 2023",
		telekomECCRoot2020Fingerprint: "Telekom Security TLS ECC Root 2020",
	}

	for _, cert := range loadBundle(t, caBundleFile) {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		name, found := expected[fingerprint]
		if !found {
			continue
		}
		if cert.Subject.CommonName != name {
			t.Errorf("certificate %s has common name %q, want %q", fingerprint, cert.Subject.CommonName, name)
		}
		if !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			t.Errorf("%q is not a self-issued CA certificate", name)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Errorf("%q is not self-signed: %v", name, err)
		}
		delete(expected, fingerprint)
	}
	for fingerprint, name := range expected {
		t.Errorf("%s is missing trust anchor %q (%s)", caBundleFile, name, fingerprint)
	}
}

// Origins using Telekom Security OV RSA CA 26A send 26A followed by the
// self-signed Telekom Security TLS RSA Root 2023. OpenSSL rejects that chain
// with error 19 (self-signed certificate in certificate chain) unless the root
// is a trust anchor, so 26A, with the served root as an intermediate, must
// verify against the root bundle alone and anchor at the self-signed root.
func TestTelekomOVRSACA26AServedChainVerifiesAgainstRootBundle(t *testing.T) {
	served := loadBundle(t, telekomServedChainFile)
	wantServed := []string{telekomOVRSACA26AFingerprint, telekomRSARoot2023Fingerprint}
	if len(served) != len(wantServed) {
		t.Fatalf("%s has %d certificates, want %d", telekomServedChainFile, len(served), len(wantServed))
	}
	for i, cert := range served {
		if got := fmt.Sprintf("%x", sha256.Sum256(cert.Raw)); got != wantServed[i] {
			t.Fatalf("%s certificate %d fingerprint = %s, want %s", telekomServedChainFile, i, got, wantServed[i])
		}
	}
	issuingCA := served[0]
	intermediates := x509.NewCertPool()
	intermediates.AddCert(served[1])

	roots := x509.NewCertPool()
	for _, cert := range loadBundle(t, caBundleFile) {
		roots.AddCert(cert)
	}

	chains, err := issuingCA.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   telekomVerificationTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Fatalf("%s chain does not verify against %s: %v", telekomServedChainFile, caBundleFile, err)
	}

	wantChain := []string{
		telekomOVRSACA26AFingerprint,
		telekomRSARoot2023Fingerprint,
	}
	for _, chain := range chains {
		var got []string
		for _, cert := range chain {
			got = append(got, fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
		}
		if !slices.Equal(got, wantChain) {
			t.Errorf("verified chain = %v, want %v", got, wantChain)
		}
	}
}
