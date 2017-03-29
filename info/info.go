package info

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/cloudflare/cfssl_trust/model/certdb"
)

func writeBasicInformation(w io.Writer, cert *x509.Certificate) error {
	_, err := fmt.Fprintf(w, `Subject: %s
Issuer: %s
	Not Before: %s
	Not After: %s
`, displayName(cert.Subject), displayName(cert.Issuer),
		cert.NotBefore.Format(dateFormat),
		cert.NotAfter.Format(dateFormat),
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
			time.Unix(rel.ReleasedAt, 0).Format(dateFormat))
		if err != nil {
			break
		}
	}

	return err
}

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
