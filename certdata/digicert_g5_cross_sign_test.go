package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/cloudflare/cfssl/ubiquity"
)

const metadataFile = "../ca-bundle.crt.metadata"

// digiCertG5CrossSign describes the single cross-sign carried for a DigiCert
// G5 TLS root so compatible-mode bundling can anchor its chains at an older,
// more widely trusted DigiCert root. No keystore in the metadata trusts the
// G5 roots themselves.
type digiCertG5CrossSign struct {
	g5Root      string
	olderRoot   string
	fingerprint string
}

// Both cross-signs are valid 2026-03-31 to 2036-03-30, assert anyPolicy, and
// use the digicert.com AIA/CRL endpoints. Other cross-signs of these roots
// are revoked (2022/2023 issuances), restrict certificate policies (2026-06-10
// issuances), or point at digicert.cn endpoints.
var digiCertG5CrossSigns = []digiCertG5CrossSign{
	{
		// Serial 07A1278A2127F2B4C42170ECEC734B4E.
		g5Root:      "DigiCert TLS RSA4096 Root G5",
		olderRoot:   "DigiCert Global Root G2",
		fingerprint: "60c2666da5e2332170e1d3bfcd95bf8c9a6d4e63473f3a8bbb8cf42b3f9f038a",
	},
	{
		// Serial 0DF2A81F6BBE9A48DACFF728F67AB1FC.
		g5Root:      "DigiCert TLS ECC P384 Root G5",
		olderRoot:   "DigiCert Global Root G3",
		fingerprint: "3142f99d358d9b500e5cdd2dff8f719a8ccecf589652334848522cca807d0807",
	},
}

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

// Exactly one cross-sign per G5 root must be present. With several,
// ubiquitous bundling would pick among them on tie-breakers alone, which can
// select a digicert.cn variant or a revoked cross-sign.
func TestDigiCertG5RootsHaveSingleCrossSign(t *testing.T) {
	intBundle := loadBundle(t, intBundleFile)
	for _, tc := range digiCertG5CrossSigns {
		t.Run(tc.g5Root, func(t *testing.T) {
			g5 := findSelfSignedRoot(t, tc.g5Root)
			older := findSelfSignedRoot(t, tc.olderRoot)

			var crossSigns []*x509.Certificate
			for _, cert := range intBundle {
				if bytes.Equal(cert.RawSubject, g5.RawSubject) && bytes.Equal(cert.RawIssuer, older.RawSubject) {
					crossSigns = append(crossSigns, cert)
				}
			}
			if len(crossSigns) != 1 {
				t.Fatalf("%s has %d %q certificates issued by %q, want 1",
					intBundleFile, len(crossSigns), tc.g5Root, tc.olderRoot)
			}

			crossSign := crossSigns[0]
			if got := fmt.Sprintf("%x", sha256.Sum256(crossSign.Raw)); got != tc.fingerprint {
				t.Errorf("cross-sign fingerprint = %s, want %s", got, tc.fingerprint)
			}
			if !bytes.Equal(crossSign.RawSubjectPublicKeyInfo, g5.RawSubjectPublicKeyInfo) {
				t.Errorf("cross-sign does not share the %q key", tc.g5Root)
			}
			if err := crossSign.CheckSignatureFrom(older); err != nil {
				t.Errorf("cross-sign is not signed by %q: %v", tc.olderRoot, err)
			}
		})
	}
}

// Compatible (ubiquitous) bundling ranks candidate chains by platform
// ubiquity first, then chain length. Chains for G5-issued CAs must anchor at
// the older root through the cross-sign.
func TestDigiCertG5IssuersAnchorAtOlderRootInUbiquitousChains(t *testing.T) {
	savedPlatforms := ubiquity.Platforms
	ubiquity.Platforms = nil
	t.Cleanup(func() { ubiquity.Platforms = savedPlatforms })
	if err := ubiquity.LoadPlatforms(metadataFile); err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	for _, cert := range loadBundle(t, caBundleFile) {
		roots.AddCert(cert)
	}
	intermediates := x509.NewCertPool()
	intBundle := loadBundle(t, intBundleFile)
	for _, cert := range intBundle {
		intermediates.AddCert(cert)
	}

	for _, tc := range digiCertG5CrossSigns {
		t.Run(tc.g5Root, func(t *testing.T) {
			g5 := findSelfSignedRoot(t, tc.g5Root)
			older := findSelfSignedRoot(t, tc.olderRoot)

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
					if anchor := chain[len(chain)-1]; !anchor.Equal(older) {
						t.Errorf("ubiquitous chain for %q anchors at %q, want %q",
							cert.Subject.CommonName, anchor.Subject.CommonName, tc.olderRoot)
					}
				}
			}
			if checked == 0 {
				t.Fatalf("%s contains no CAs issued by %q", intBundleFile, tc.g5Root)
			}
		})
	}
}
