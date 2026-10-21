package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// These intermediates are issued by CAs that are not in either bundle, so no
// path through them reaches a trust anchor. Verifiers without issuer
// backtracking select the first certificate matching an issuer's name, so a
// dead-end copy listed before a working one breaks chains depending on bundle
// order. The emSign ECC G3 and AAA-issued certificates lost their issuer when
// those roots were distrusted.
func TestDeadEndIntermediatesAreExcluded(t *testing.T) {
	excluded := map[string]string{
		"b4dae2869f79bc77c29ad1a2a88a3932af3a9593fe820fb263c0db89843e9559": "StartCom Class 3 OV Server CA (WoSign G2)",
		"7b464dc384fdb1a525c2cc279ed0c7cfad24becf72c46a7d7093d157c217607e": "JCAN Public CA1 - G4 (Trusted Root CA SHA256 G2)",
		"0116f17f97cdef4ade2e63cf2c1b064fd99f404d2b914100bc241f0781853323": "emSign ECC EV SSL CA - G3",
		"4e9b731567177e1776a96d66d9120b3deb28b800937ea4662565b3ef5ec8000b": "emSign ECC Class 2 CA - G3",
		"6b51d1dcf4eb7aee424185cb1b9580574b39cb963863de3ec1ad31ddb076ce9f": "emSign ECC SSL CA - G3",
		"7066a0f42f530e0db5afee72a3b04de614e7d2305c67d12c756bb215e37cb975": "emSign ECC Class 3 CA - G3",
		"70b9ba595412cf8614b76747fd683cca2759f42642164834fbefdd88505c4f1c": "emSign ECC Device CA - G3",
		"aba6a65dce8955baf0685ab88809b7699c174496ef9ee991533251494f43ce10": "emSign ECC Class 1 CA - G3",
		"14e384649aa401f1d1cabd5fa3d08abe82f14b7dae6c5615b1cd7dd41e9750e3": "UTN-USERFirst-Client Authentication and Email (AAA)",
		"ad61327ee99b40613e480751b56691a096412c68f74f4012b29fa0f48bb924c9": "COMODO SHA-256 Client Authentication and Secure Email CA 3 (AAA)",
		"eb62bffa6cbc802e4dae6f8c53908020be7f07774a55e67bbd63ecc37679dec8": "Apple Public Client RSA CA 12 - G1 (AAA)",
	}
	// Copies of the same CAs that chain to a trusted root must remain.
	retained := map[string]string{
		"ea4e5d2b9c99560f13dd094b8121a623bfdd902038dfd6d772ce32ffabec094d": "StartCom Class 3 OV Server CA (StartCom Certification Authority)",
		"9ac4c8e358c095c998122add17a336c0ac597ecbecb7edc3f58a75040cf94a5f": "JCAN Public CA1 - G4 (Trusted Root nonTLS CA SHA256 G3)",
	}

	for _, file := range []string{intBundleFile, caBundleFile} {
		for _, cert := range loadBundle(t, file) {
			fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
			if name, found := excluded[fingerprint]; found {
				t.Errorf("%s contains dead-end intermediate %q (%s)", file, name, fingerprint)
			}
			delete(retained, fingerprint)
		}
	}
	for fingerprint, name := range retained {
		t.Errorf("bundles are missing working intermediate %q (%s)", name, fingerprint)
	}
}
