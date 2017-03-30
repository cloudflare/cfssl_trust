package certdb

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
)

// CollectRelease grabs all the certificates in a release, ordering
// them by the oldest.
func CollectRelease(bundle, version string, tx *sql.Tx) ([]*Certificate, error) {
	rel, err := NewRelease(bundle, version)
	if err != nil {
		return nil, err
	}

	err = rel.Select(tx)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errors.New("model/certdb: invalid release " + version)
		}
		return nil, err
	}

	var certs []*Certificate
	tbl := rel.table()
	query := fmt.Sprintf(`
SELECT certificates.ski, aki, certificates.serial, not_before, not_after, raw
	FROM certificates
	INNER JOIN %ss ON certificates.ski = %ss.ski AND
			    certificates.serial = %ss.serial AND
			    %ss.release = ?
	ORDER BY certificates.not_before`,
		tbl, tbl, tbl, tbl)
	rows, err := tx.Query(query, rel.Version)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		cert := &Certificate{}

		err = rows.Scan(&cert.SKI, &cert.AKI, &cert.Serial, &cert.NotBefore, &cert.NotAfter, &cert.Raw)
		if err != nil {
			return nil, err
		}

		cert.cert, err = x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, err
		}

		certs = append(certs, cert)
	}

	return certs, nil
}
