package main

import (
	"bytes"
	"crypto/x509"
	"slices"
	"testing"
)

// Cross-signs must provide paths to the older root without allowing issuer
// selection to cycle between the older root and G2.
func TestEPKICrossSignsDoNotFormLoop(t *testing.T) {
	var older, g2 *x509.Certificate
	for _, cert := range loadBundle(t, caBundleFile) {
		// Trust anchors do not depend on their historical self-signature algorithm.
		if !cert.IsCA || !bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			continue
		}
		if slices.Contains(cert.Subject.OrganizationalUnit, "ePKI Root Certification Authority") {
			older = cert
		}
		if cert.Subject.CommonName == "ePKI Root Certification Authority - G2" {
			g2 = cert
		}
	}
	if older == nil || g2 == nil {
		t.Fatal("both self-signed ePKI roots must remain in the root bundle")
	}

	reverseCrossSigns := 0
	for _, cert := range loadBundle(t, intBundleFile) {
		if bytes.Equal(cert.RawSubject, older.RawSubject) && bytes.Equal(cert.RawIssuer, g2.RawSubject) {
			t.Errorf("older ePKI root issued by G2 can form a loop (serial %X)", cert.SerialNumber)
		}
		if bytes.Equal(cert.RawSubject, g2.RawSubject) && bytes.Equal(cert.RawIssuer, older.RawSubject) {
			if !bytes.Equal(cert.RawSubjectPublicKeyInfo, g2.RawSubjectPublicKeyInfo) {
				t.Error("ePKI G2 cross-sign does not share the retained G2 root's key")
			}
			if err := cert.CheckSignatureFrom(older); err != nil {
				t.Errorf("ePKI G2 cross-sign cannot terminate at the older root: %v", err)
			}
			reverseCrossSigns++
		}
	}
	if reverseCrossSigns == 0 {
		t.Error("missing ePKI G2 cross-signs supporting clients that trust only the older root")
	}
}
