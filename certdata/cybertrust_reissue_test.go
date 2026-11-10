package main

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

// SECOM revoked the 2019 Cybertrust Japan SureServer CA G4 and SureServer EV
// CA G3 intermediates on 2026-11-06 (reason: superseded). The 2023 reissues
// keep the same subject, key and SKI, so a verifier holding both copies can
// pick either one. Only the reissues may be present.
func TestCybertrustSureServerUsesReissuedIntermediates(t *testing.T) {
	revoked := map[string]string{
		"0207056d172c80bdfb6dc45be9e5808846078d1e6eef1b6ed70259ab332a64c1": "Cybertrust Japan SureServer CA G4 (2019, serial 22B9B1630CECB43C2E)",
		"fece9ada7aa49d4fea9eff123542095a880c004fd6933f9364b02b2e3574ea38": "Cybertrust Japan SureServer EV CA G3 (2019, serial 22B9B16488BCE695FC)",
	}
	reissued := map[string]string{
		"8346922cb8730bb6ae71ab03bfc42462f4160423d9079be64385621ac5877672": "Cybertrust Japan SureServer CA G4 (2023, serial 22B9B1A074641857F7A01332DB42B9EC)",
		"b723273a3506c6bed85f083da562734be09f2c47ade47317831d63aa8be278a5": "Cybertrust Japan SureServer EV CA G3 (2023, serial 22B9B1A12D91F181AD7A7B6DBEB38EA7)",
	}

	for _, file := range []string{intBundleFile, caBundleFile} {
		for _, cert := range loadBundle(t, file) {
			fingerprint := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
			if name, found := revoked[fingerprint]; found {
				t.Errorf("%s contains revoked intermediate %q (%s)", file, name, fingerprint)
			}
			delete(reissued, fingerprint)
		}
	}
	for fingerprint, name := range reissued {
		t.Errorf("bundles are missing reissued intermediate %q (%s)", name, fingerprint)
	}
}
