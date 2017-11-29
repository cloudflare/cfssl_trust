package info

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/cloudflare/cfssl_trust/common"
	"github.com/cloudflare/cfssl_trust/model/certdb"
)

func writeBasicInformation(w io.Writer, cert *x509.Certificate) error {
	_, err := fmt.Fprintf(w, `Subject: %s
Issuer: %s
	Not Before: %s
	Not After: %s
`, common.NameToString(cert.Subject),
		common.NameToString(cert.Issuer),
		cert.NotBefore.UTC().Format(common.DateFormat),
		cert.NotAfter.UTC().Format(common.DateFormat),
	)
	return err
}

func writeCertificateReleases(w io.Writer, tx *sql.Tx, cert *certdb.Certificate) error {
	releases, err := cert.Releases(tx)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "Releases:\n")
	if err != nil {
		return err
	}

	for _, rel := range releases {
		_, err = fmt.Fprintf(w, "\t- %s %s (%s)\n",
			rel.Version, rel.Bundle,
			time.Unix(rel.ReleasedAt, 0).UTC().Format(common.DateFormat))
		if err != nil {
			break
		}
	}

	return err
}

// WriteCertificateInformation pretty prints details about the given certificate
// to the given io.Writer.
func WriteCertificateInformation(w io.Writer, db *sql.DB, cert *certdb.Certificate) error {
	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}
	defer certdb.Finalize(&err, tx)

	err = writeBasicInformation(w, cert.X509())
	if err != nil {
		return err
	}

	err = writeCertificateReleases(w, tx, cert)
	if err != nil {
		return err
	}

	return nil
}

// CertificateMetadata pairs the AKI, SKI, and Serial Number with
// string versions of the subject and issuer fields.
type CertificateMetadata struct {
	SKI, AKI string
	Serial   *big.Int
	Subject  string
	Issuer   string
	Releases []*certdb.Release
	cert     *certdb.Certificate
}

// LoadCertificateMetadata returns the metadata for a given certificate.
func LoadCertificateMetadata(tx *sql.Tx, cert *certdb.Certificate) (*CertificateMetadata, error) {
	x509Cert := cert.X509()
	cm := &CertificateMetadata{
		SKI:     cert.SKI,
		AKI:     cert.AKI,
		Serial:  x509Cert.SerialNumber,
		Subject: common.NameToString(x509Cert.Subject),
		Issuer:  common.NameToString(x509Cert.Issuer),
		cert:    cert,
	}

	var err error
	cm.Releases, err = cert.Releases(tx)
	return cm, err
}

// WriteCertificateMetadata pretty prints the certificate metadata to
// the given io.Writer.
func WriteCertificateMetadata(w io.Writer, cert *CertificateMetadata) error {
	x509Cert := cert.cert.X509()
	_, err := fmt.Fprintf(w, `Subject: %s
Issuer: %s
	Not Before: %s
	Not After: %s
`, (cert.Subject),
		(cert.Issuer),
		x509Cert.NotBefore.UTC().Format(common.DateFormat),
		x509Cert.NotAfter.UTC().Format(common.DateFormat),
	)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(w, "\tReleases:\n")
	if err != nil {
		return err
	}

	for _, rel := range cert.Releases {
		_, err = fmt.Fprintf(w, "\t\t- %s %s (%s)\n",
			rel.Version, rel.Bundle,
			time.Unix(rel.ReleasedAt, 0).UTC().Format(common.DateFormat))
		if err != nil {
			break
		}
	}

	return err
}
