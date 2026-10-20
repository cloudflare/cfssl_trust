package main

import (
	"bytes"
	"testing"
)

// Keep the independently trusted roots, but not their dead-end AAA cross-signs.
// Verifiers without issuer backtracking can otherwise select an AAA-issued
// copy instead of the self-signed root and fail after AAA is distrusted.
func TestUSERTrustAndCOMODORootsDoNotDependOnAAA(t *testing.T) {
	roots := map[string]bool{
		"USERTrust RSA Certification Authority": false,
		"USERTrust ECC Certification Authority": false,
		"COMODO RSA Certification Authority":    false,
		"COMODO ECC Certification Authority":    false,
	}

	for _, cert := range loadBundle(t, intBundleFile) {
		if _, checked := roots[cert.Subject.CommonName]; checked && cert.Issuer.CommonName == aaaRootCommonName {
			t.Errorf("%s contains AAA-issued cross-sign %q (serial %X)",
				intBundleFile, cert.Subject.CommonName, cert.SerialNumber)
		}
	}

	for _, cert := range loadBundle(t, caBundleFile) {
		if _, checked := roots[cert.Subject.CommonName]; !checked {
			continue
		}
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) && cert.CheckSignatureFrom(cert) == nil {
			roots[cert.Subject.CommonName] = true
		}
	}
	for name, found := range roots {
		if !found {
			t.Errorf("%s is missing self-signed root %q", caBundleFile, name)
		}
	}
}
