package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/cloudflare/cfssl/ubiquity"
)

const (
	digiCertG5RSA4096RootCommonName = "DigiCert TLS RSA4096 Root G5"
	digiCertGlobalRootG2CommonName  = "DigiCert Global Root G2"
	metadataFile                    = "../ca-bundle.crt.metadata"

	// DigiCert TLS RSA4096 Root G5 cross-signed by DigiCert Global Root G2,
	// valid 2026-03-31 to 2036-03-30 (serial 07A1278A2127F2B4C42170ECEC734B4E).
	// This variant uses anyPolicy and the digicert.com AIA/CRL endpoints.
	digiCertG5ByG2CrossSignFingerprint = "60c2666da5e2332170e1d3bfcd95bf8c9a6d4e63473f3a8bbb8cf42b3f9f038a"
)

func findSelfSignedRoot(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	for _, cert := range loadBundle(t, caBundleFile) {
		if cert.Subject.CommonName == commonName && bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			return cert
		}
	}
	t.Fatalf("%s is missing self-signed root %q", caBundleFile, commonName)
	return nil
}

// Exactly one G5-by-G2 cross-sign must be present. With several, ubiquitous
// bundling would pick among them on tie-breakers alone, which can select a
// digicert.cn variant or one of the 2023 cross-signs DigiCert revoked.
func TestDigiCertG5RSA4096HasSingleG2CrossSign(t *testing.T) {
	g5 := findSelfSignedRoot(t, digiCertG5RSA4096RootCommonName)
	g2 := findSelfSignedRoot(t, digiCertGlobalRootG2CommonName)

	var crossSigns []*x509.Certificate
	for _, cert := range loadBundle(t, intBundleFile) {
		if bytes.Equal(cert.RawSubject, g5.RawSubject) && bytes.Equal(cert.RawIssuer, g2.RawSubject) {
			crossSigns = append(crossSigns, cert)
		}
	}
	if len(crossSigns) != 1 {
		t.Fatalf("%s has %d %q certificates issued by %q, want 1",
			intBundleFile, len(crossSigns), digiCertG5RSA4096RootCommonName, digiCertGlobalRootG2CommonName)
	}

	crossSign := crossSigns[0]
	if got := fmt.Sprintf("%x", sha256.Sum256(crossSign.Raw)); got != digiCertG5ByG2CrossSignFingerprint {
		t.Errorf("G5-by-G2 cross-sign fingerprint = %s, want %s", got, digiCertG5ByG2CrossSignFingerprint)
	}
	if !bytes.Equal(crossSign.RawSubjectPublicKeyInfo, g5.RawSubjectPublicKeyInfo) {
		t.Error("G5-by-G2 cross-sign does not share the G5 root's key")
	}
	if err := crossSign.CheckSignatureFrom(g2); err != nil {
		t.Errorf("G5-by-G2 cross-sign is not signed by %q: %v", digiCertGlobalRootG2CommonName, err)
	}
}

// Compatible (ubiquitous) bundling ranks candidate chains by platform
// ubiquity first, then chain length. No keystore in the metadata trusts the
// G5 root, so chains for G5-issued certificates must anchor at G2 through the
// cross-sign.
func TestDigiCertG5RSA4096IssuersAnchorAtG2InUbiquitousChains(t *testing.T) {
	savedPlatforms := ubiquity.Platforms
	ubiquity.Platforms = nil
	t.Cleanup(func() { ubiquity.Platforms = savedPlatforms })
	if err := ubiquity.LoadPlatforms(metadataFile); err != nil {
		t.Fatal(err)
	}

	g5 := findSelfSignedRoot(t, digiCertG5RSA4096RootCommonName)
	g2 := findSelfSignedRoot(t, digiCertGlobalRootG2CommonName)

	roots := x509.NewCertPool()
	for _, cert := range loadBundle(t, caBundleFile) {
		roots.AddCert(cert)
	}
	intermediates := x509.NewCertPool()
	intBundle := loadBundle(t, intBundleFile)
	for _, cert := range intBundle {
		intermediates.AddCert(cert)
	}

	checked := 0
	for _, cert := range intBundle {
		if !bytes.Equal(cert.RawIssuer, g5.RawSubject) || bytes.Equal(cert.RawSubject, g5.RawSubject) {
			continue
		}
		checked++
		chains, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			t.Errorf("%q does not verify: %v", cert.Subject.CommonName, err)
			continue
		}
		chains = ubiquity.Filter(chains, ubiquity.ComparePlatformUbiquity)
		chains = ubiquity.Filter(chains, ubiquity.CompareSHA2Homogeneity)
		chains = ubiquity.Filter(chains, ubiquity.CompareChainLength)
		for _, chain := range chains {
			if anchor := chain[len(chain)-1]; !anchor.Equal(g2) {
				t.Errorf("ubiquitous chain for %q anchors at %q, want %q",
					cert.Subject.CommonName, anchor.Subject.CommonName, digiCertGlobalRootG2CommonName)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("%s contains no CAs issued by %q", intBundleFile, digiCertG5RSA4096RootCommonName)
	}
}
