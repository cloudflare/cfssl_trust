package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/ubiquity"
)

var metadataFiles = []string{
	"../ca-bundle.crt.metadata",
}

func TestMetadataFormat(t *testing.T) {
	for _, file := range metadataFiles {
		if err := ubiquity.LoadPlatforms(file); err != nil {
			t.Fatal(err)
		}
	}
}

var bundleFiles = []string{
	"../ca-bundle.crt",
	"../int-bundle.crt",
}

func TestParseBundles(t *testing.T) {
	for _, file := range bundleFiles {
		if _, err := helpers.LoadPEMCertPool(file); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBundleCertificatesAreValid(t *testing.T) {
	now := time.Now()
	for _, file := range bundleFiles {
		contents, err := ioutil.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		certificates, err := helpers.ParseCertificatesPEM(contents)
		if err != nil {
			t.Fatal(err)
		}

		for _, certificate := range certificates {
			if now.Before(certificate.NotBefore) {
				t.Errorf(
					"%s contains certificate %q that is not valid until %s",
					file,
					certificate.Subject.String(),
					certificate.NotBefore,
				)
			}
			if !now.Before(certificate.NotAfter) {
				t.Errorf(
					"%s contains certificate %q that expired at %s",
					file,
					certificate.Subject.String(),
					certificate.NotAfter,
				)
			}
		}
	}
}

var trustedRootDirs = []string{
	"trusted_roots",
}

func TestParseTrustedRoots(t *testing.T) {
	for _, dir := range trustedRootDirs {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}

			if _, err := helpers.LoadPEMCertPool(path); err != nil {
				t.Fatal(err)
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
