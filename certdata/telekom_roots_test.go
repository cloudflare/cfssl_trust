package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	// Serial 219C542DE8F6EC7177FA4EE8C3705797.
	telekomRSARoot2023Fingerprint = "efc65cadbb59adb6efe84da22311b35624b71b3b1ea0da8b6655174ec8978646"
	// Serial 363A968CC95CB258CDD0015DC5E55700.
	telekomECCRoot2020Fingerprint = "578af4ded0853f4e5998db4aeaf9cbea8d945f60b620a38d1a3c13b2bc7ba8e1"
	// Telekom Security OV RSA CA 26A, serial 118282E70C01C7416642DD8576CED055.
	telekomOVRSACA26AFingerprint = "c76e23dfa0014b885a6ded8e6d64c295af4991dc7872c1af8b0fef527e263929"
	// T-TeleSec GlobalRoot Class 3, serial 1.
	telesecGlobalRootClass3Fingerprint = "fd73dad31c644ff1b43bef0ccdda96710b9cd9875eca7e31707af3e96d522bbd"
	// RSA Root 2023 cross-signed by T-TeleSec GlobalRoot Class 3, serial
	// 238B36076DF8ACDACF7EB300492781B3, valid 2026-03-19 to 2033-09-30.
	telekomRSARoot2023Class3CrossSignFingerprint = "6306c491f9d1cecedef46420e028601922c0106dd0b48a61a7454f9ed38cd649"

	telekomRSARoot2023CommonName      = "Telekom Security TLS RSA Root 2023"
	telesecGlobalRootClass3CommonName = "T-TeleSec GlobalRoot Class 3"

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

// Apple platforms and older clients trust T-TeleSec GlobalRoot Class 3 but not
// the RSA Root 2023, so the int bundle carries the Class 3 cross-sign of the
// RSA Root 2023 to give compatible-mode bundling a path to the older root.
func TestTelekomRSARoot2023HasClass3CrossSign(t *testing.T) {
	rsaRoot := findSelfSignedRoot(t, telekomRSARoot2023CommonName)
	class3 := findSelfSignedRoot(t, telesecGlobalRootClass3CommonName)
	if got := fmt.Sprintf("%x", sha256.Sum256(class3.Raw)); got != telesecGlobalRootClass3Fingerprint {
		t.Fatalf("%q fingerprint = %s, want %s", telesecGlobalRootClass3CommonName, got, telesecGlobalRootClass3Fingerprint)
	}

	var crossSign *x509.Certificate
	for _, cert := range loadBundle(t, intBundleFile) {
		if fmt.Sprintf("%x", sha256.Sum256(cert.Raw)) == telekomRSARoot2023Class3CrossSignFingerprint {
			crossSign = cert
			break
		}
	}
	if crossSign == nil {
		t.Fatalf("%s is missing the %q cross-sign of %q (%s)", intBundleFile,
			telesecGlobalRootClass3CommonName, telekomRSARoot2023CommonName, telekomRSARoot2023Class3CrossSignFingerprint)
	}

	if !crossSign.IsCA {
		t.Errorf("cross-sign is not a CA certificate")
	}
	if !bytes.Equal(crossSign.RawSubject, rsaRoot.RawSubject) {
		t.Errorf("cross-sign subject is %q, want %q", crossSign.Subject.CommonName, telekomRSARoot2023CommonName)
	}
	if !bytes.Equal(crossSign.RawIssuer, class3.RawSubject) {
		t.Errorf("cross-sign issuer is %q, want %q", crossSign.Issuer.CommonName, telesecGlobalRootClass3CommonName)
	}
	if !bytes.Equal(crossSign.RawSubjectPublicKeyInfo, rsaRoot.RawSubjectPublicKeyInfo) {
		t.Errorf("cross-sign does not share the %q key", telekomRSARoot2023CommonName)
	}
	if err := crossSign.CheckSignatureFrom(class3); err != nil {
		t.Errorf("cross-sign is not signed by %q: %v", telesecGlobalRootClass3CommonName, err)
	}
}

// With the served chain and the int bundle as intermediates, Telekom Security
// OV RSA CA 26A must reach T-TeleSec GlobalRoot Class 3 through the
// cross-sign, and compatible (ubiquitous) bundling must prefer that anchor
// over the RSA Root 2023, which none of the metadata keystores trust.
func TestTelekomOVRSACA26AAnchorsAtClass3InUbiquitousChains(t *testing.T) {
	savedPlatforms := ubiquity.Platforms
	ubiquity.Platforms = nil
	t.Cleanup(func() { ubiquity.Platforms = savedPlatforms })
	if err := ubiquity.LoadPlatforms(metadataFile); err != nil {
		t.Fatal(err)
	}

	served := loadBundle(t, telekomServedChainFile)
	if len(served) == 0 {
		t.Fatalf("%s has no certificates", telekomServedChainFile)
	}
	issuingCA := served[0]
	intermediates := x509.NewCertPool()
	for _, cert := range served {
		intermediates.AddCert(cert)
	}
	for _, cert := range loadBundle(t, intBundleFile) {
		intermediates.AddCert(cert)
	}
	class3 := findSelfSignedRoot(t, telesecGlobalRootClass3CommonName)

	verify := func(roots *x509.CertPool) [][]*x509.Certificate {
		t.Helper()
		chains, err := issuingCA.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   telekomVerificationTime,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if err != nil {
			t.Fatalf("%q does not verify: %v", issuingCA.Subject.CommonName, err)
		}
		return chains
	}

	class3Only := x509.NewCertPool()
	class3Only.AddCert(class3)
	wantChain := []string{
		telekomOVRSACA26AFingerprint,
		telekomRSARoot2023Class3CrossSignFingerprint,
		telesecGlobalRootClass3Fingerprint,
	}
	for _, chain := range verify(class3Only) {
		var got []string
		for _, cert := range chain {
			got = append(got, fmt.Sprintf("%x", sha256.Sum256(cert.Raw)))
		}
		if !slices.Equal(got, wantChain) {
			t.Errorf("chain to %q = %v, want %v", telesecGlobalRootClass3CommonName, got, wantChain)
		}
	}

	roots := x509.NewCertPool()
	for _, cert := range loadBundle(t, caBundleFile) {
		roots.AddCert(cert)
	}
	chains := verify(roots)
	chains = ubiquity.Filter(chains, ubiquity.ComparePlatformUbiquity)
	chains = ubiquity.Filter(chains, ubiquity.CompareSHA2Homogeneity)
	chains = ubiquity.Filter(chains, ubiquity.CompareChainLength)
	for _, chain := range chains {
		if anchor := chain[len(chain)-1]; !anchor.Equal(class3) {
			t.Errorf("ubiquitous chain anchors at %q, want %q", anchor.Subject.CommonName, telesecGlobalRootClass3CommonName)
		}
	}
}
