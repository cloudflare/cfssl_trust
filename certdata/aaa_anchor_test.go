package main

import (
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"testing"
)

// These intermediates are explicitly trusted so their paths can terminate
// without the distrusted AAA root. Fingerprints identify exact certificates,
// including the two COMODO certificates that share one public key.
func TestAAAOnlyIntermediatesAreTrustAnchors(t *testing.T) {
	expected := map[string]string{
		"0b405cfe9a6beb098ffb969121c5f6710f3f7fa9ea101a6418f7af201d3d3938": "Apple Public Server RSA CA 12 - G1",
		"0c37d499c45792941c62f1e19f06e9755625ce11633a2e8db869c7ab2d78c319": "TrustAsia RSA OV TLS CA G2",
		"0d4d3a2f6dac222175ba1df78b4817b469095bf02f47919512353115902265fb": "TrustAsia ECC EV TLS CA G2",
		"1286173e6f0102f7bdd32c2f830910953489bf22c16295d84dd90a3da137164a": "COMODO SHA-2 Pro Series Secure Server CA",
		"38a7525022c9658caafc6060764fd51c6a5c5bef232d3e6c7e48af07a098df1e": "Comodo Japan RSA DV CA",
		"3a739e1902626352c3337e94db2075998c456cf65c95f5a9632b12d0b7c89dcb": "TrustAsia RSA DV TLS CA G2",
		"5251e2a5b3a42021667994b04e195b693b9b71b752267c44dc310a77979bdc00": "TrustAsia ECC DV TLS CA G2",
		"70db9ded944dd35d474ea15ff2aa4e25f393a893ecda54359d305bc319649817": "Apple Public Server ECC CA 12 - G1",
		"7f814cd1454900ac1331364b6b6de06b87cc8cb9936ec583100822721057d3a3": "Sectigo SHA-256 DV Secure Server CA",
		"97a718082b78ee7480979b2116d4ba0215c61aaa520b46ca6b9c2ab378f40821": "Sectigo SHA-256 OV Secure Server CA",
		"9a6962cd8c21b5dcf1f70b39a836c7f397ec495f880be9b9b69b8b27288ecb14": "KICA RSA OV CA",
		"aafdcee5793b5cf4bf2d0c5f6042d8a422bcc33b3965ac6283d273cc69b48375": "Sectigo SHA-256 EV Secure Server CA",
		"b0547fd468fbb6e337fe01b010834e53b4c5b12649ecee76faec38b8640f8878": "Sectigo RSA Pro Series Secure Server CA",
		"d158333e02b10c80f6966b7705ab79570b17da38b1e392145940ed7e67ee4fd8": "TrustAsia RSA EV TLS CA G2",
		"da4792604e554a3894efc97489cc4b64831b2cf7e5512b3395ef9963d6efdd7f": "TrustAsia ECC OV TLS CA G2",
		"e11e06861c4d308fd944bf17be5e9072a034c4f93034cb59c02d512d30f7fc45": "COMODO SHA-2 Pro Series Secure Server CA",
		"f606d8deb27c0401f34e7b6a37c8e2a51db8da026be58a07e854b686de74c69a": "KICA RSA DV CA",
	}

	roots := x509.NewCertPool()
	var anchors []*x509.Certificate
	for _, cert := range loadBundle(t, caBundleFile) {
		fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		name, found := expected[fingerprint]
		if found == false {
			continue
		}
		if cert.IsCA == false || cert.Issuer.CommonName != aaaRootCommonName {
			t.Errorf("%q is not an AAA-issued CA", name)
		}
		roots.AddCert(cert)
		anchors = append(anchors, cert)
		delete(expected, fingerprint)
	}
	for fingerprint, name := range expected {
		t.Errorf("%s is missing trust anchor %q (%s)", caBundleFile, name, fingerprint)
	}

	for _, cert := range anchors {
		chains, err := cert.Verify(x509.VerifyOptions{Roots: roots})
		if err != nil {
			t.Errorf("%q cannot be trusted without AAA: %v", cert.Subject.CommonName, err)
			continue
		}
		for _, chain := range chains {
			if len(chain) != 1 {
				t.Errorf("%q does not terminate directly at its configured anchor", cert.Subject.CommonName)
			}
		}
	}
}
