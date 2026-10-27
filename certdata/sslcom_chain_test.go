package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/ubiquity"
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

const secureTrustRootCommonName = "SecureTrust CA"

// sslcomRoot2022CrossSign describes the single non-self-signed copy of an
// SSL.com TLS Root CA 2022 carried in the intermediate bundle. Both are
// issued by SecureTrust CA and valid 2025-12-17 to 2029-12-30.
type sslcomRoot2022CrossSign struct {
	root        string
	fingerprint string
}

var sslcomRoot2022CrossSigns = []sslcomRoot2022CrossSign{
	{
		// Serial 07EB4274FC1D305BE94C9883277F8467E2144F.
		root:        "SSL.com TLS RSA Root CA 2022",
		fingerprint: "1b1de06990cd0b305e2e124806103b1adcffc499f212504dc77f48dd0ad62209",
	},
	{
		// Serial 07EB4281BE1A1011E552C13831E2947E9AF848.
		root:        "SSL.com TLS ECC Root CA 2022",
		fingerprint: "469a5624cbf125c29b1c73aa4d05d4b2bf4f8400b5d569e9a4ca554ab4c4faf5",
	},
}

// The pre-loaded path for SSL.com Root 2022 issued CAs must go through the
// SecureTrust CA cross-sign. A second copy of the Root 2022 (issued by an
// SSL.com EV root or by AAA) would compete with it on name match in
// verifiers without issuer backtracking.
func TestSSLcomRoot2022HasSingleSecureTrustCrossSign(t *testing.T) {
	intBundle := loadBundle(t, intBundleFile)
	secureTrust := findSelfSignedRoot(t, secureTrustRootCommonName)
	for _, tc := range sslcomRoot2022CrossSigns {
		t.Run(tc.root, func(t *testing.T) {
			root := findSelfSignedRoot(t, tc.root)

			var copies []*x509.Certificate
			for _, cert := range intBundle {
				if bytes.Equal(cert.RawSubject, root.RawSubject) && !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
					copies = append(copies, cert)
				}
			}
			if len(copies) != 1 {
				t.Fatalf("%s has %d non-self-signed %q certificates, want 1",
					intBundleFile, len(copies), tc.root)
			}

			crossSign := copies[0]
			if got := fmt.Sprintf("%x", sha256.Sum256(crossSign.Raw)); got != tc.fingerprint {
				t.Errorf("cross-sign fingerprint = %s, want %s", got, tc.fingerprint)
			}
			if !bytes.Equal(crossSign.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) {
				t.Errorf("cross-sign does not share the %q key", tc.root)
			}
			if err := crossSign.CheckSignatureFrom(secureTrust); err != nil {
				t.Errorf("cross-sign is not signed by %q: %v", secureTrustRootCommonName, err)
			}
		})
	}
}

// Compatible (ubiquitous) bundling must anchor chains for CAs issued by the
// SSL.com Root 2022 at SecureTrust CA through the cross-sign.
func TestSSLcomRoot2022IssuersAnchorAtSecureTrustInUbiquitousChains(t *testing.T) {
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
	secureTrust := findSelfSignedRoot(t, secureTrustRootCommonName)

	for _, tc := range sslcomRoot2022CrossSigns {
		t.Run(tc.root, func(t *testing.T) {
			root := findSelfSignedRoot(t, tc.root)

			checked := 0
			for _, cert := range intBundle {
				if !bytes.Equal(cert.RawIssuer, root.RawSubject) || bytes.Equal(cert.RawSubject, root.RawSubject) {
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
					if anchor := chain[len(chain)-1]; !anchor.Equal(secureTrust) {
						t.Errorf("ubiquitous chain for %q anchors at %q, want %q",
							cert.Subject.CommonName, anchor.Subject.CommonName, secureTrustRootCommonName)
					}
				}
			}
			if checked == 0 {
				t.Fatalf("%s contains no CAs issued by %q", intBundleFile, tc.root)
			}
		})
	}
}
