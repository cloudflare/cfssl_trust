// Package dump contains functions for extracting single certificates
// from the database.
package dump

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
)

// CertPEM returns a slice of certificates for the given SKI. In most
// cases, this will be a single certificate (as SKIs tend to be
// unique); according to the RFC, they only need to be unique for a
// given signer, and therefore there is a chance that there will be
// multiple certificates with the same SKI.
func CertPEM(tx *sql.Tx, ski string) ([]byte, error) {
	rows, err := tx.Query("SELECT raw FROM certificates WHERE ski = ?", ski)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}

	for rows.Next() {
		var raw []byte
		err = rows.Scan(&raw)
		if err != nil {
			return nil, err
		}

		// Make sure it's actually a valid certificate.
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}

		p := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		err = pem.Encode(buf, p)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}
