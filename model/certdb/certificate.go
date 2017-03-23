// Package cert contains Go definitions for the database
// representation of certificates, as well as associated code for
// putting it into the database.
package certdb

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Table provides an interface for mapping a struct to a table in the
// database.
type Table interface {
	// Insert stores a value in the database; it doesn't check
	// whether the value exists in the database already and isn't
	// idempotent --- calling it twice on the same value will
	// likely violate UNIQUE constraints.
	Insert(tx *sql.Tx) error

	// Select fills in the value given certain primary fields
	// being filled in. The function comment for each struct's
	// implementation should note which fields should be filled in
	// prior to calling this. It should also return sql.ErrNoRows
	// if the item doesn't exist in the database.
	Select(tx *sql.Tx) error

	// Not used yet, but might be useful in the future.
	// Delete(tx *sql.Tx) error
	// Update(tx *sql.Tx) error
}

// Ensure ensures the value is present in the database. It calls
// Select, and if no rows are returned, it calls Insert. The boolean
// will be true if the value was inserted. This value is meaningless
// if err is non-nil.
func Ensure(table Table, tx *sql.Tx) (bool, error) {
	var inserted bool
	err := table.Select(tx)
	if err == sql.ErrNoRows {
		err = table.Insert(tx)
		inserted = true
	}
	return inserted, err
}

// Certificate models the certificate table.
type Certificate struct {
	SKI       string
	AKI       string
	Serial    []byte
	NotBefore int64
	NotAfter  int64
	Raw       []byte
	cert      *x509.Certificate
} // UNIQUE(ski, serial)

// Insert stores the Certificate in the database.
func (cert *Certificate) Insert(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO certificates (ski, aki, serial, not_before, not_after, raw) values (?, ?, ?, ?, ?, ?)`, cert.SKI, cert.AKI, cert.Serial, cert.NotBefore, cert.NotAfter, cert.Raw)
	return err
}

// Select requires the SKI and Serial fields to be filled in.
func (cert *Certificate) Select(tx *sql.Tx) error {
	row := tx.QueryRow(`SELECT aki, not_before, not_after, raw FROM certificates WHERE ski=? and serial=?`, cert.SKI, cert.Serial)
	err := row.Scan(&cert.AKI, &cert.NotBefore, &cert.NotAfter, &cert.Raw)
	if err != nil {
		return err
	}

	cert.cert, err = x509.ParseCertificate(cert.Raw)
	return err
}

var nullSerial = big.NewInt(0)

// NewCertificate creates a Certificate from a crypto/x509 Certificate
// strucutre.
func NewCertificate(cert *x509.Certificate) *Certificate {
	c := &Certificate{
		SKI:       fmt.Sprintf("%x", cert.SubjectKeyId),
		AKI:       fmt.Sprintf("%x", cert.AuthorityKeyId),
		Serial:    cert.SerialNumber.Bytes(),
		NotBefore: cert.NotBefore.Unix(),
		NotAfter:  cert.NotAfter.Unix(),
		Raw:       cert.Raw,
	}

	// Workaround the NOT NULL constraint.
	if cert.SerialNumber.Cmp(nullSerial) == 0 {
		c.Serial = []byte{0}
	}

	c.cert = cert

	return c
}

// AIA models the aia table.
type AIA struct {
	SKI string // Primary key.
	URL string
}

// Insert stores the release in the database.
func (aia *AIA) Insert(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO aia (ski, url) values (?, ?)`, aia.SKI, aia.URL)
	return err
}

// Select requires the SKI field to be filled in.
func (aia *AIA) Select(tx *sql.Tx) error {
	row := tx.QueryRow(`SELECT url FROM aia WHERE ski=?`, aia.SKI)
	err := row.Scan(&aia.URL)
	if err != nil {
		return err
	}

	return nil
}

// AIA populates an AIA structure from a Certificate.
func NewAIA(cert *Certificate) *AIA {
	if len(cert.cert.IssuingCertificateURL) == 0 {
		return nil
	}

	// Arbitrary choice: store the first HTTP URL. We can always
	// look up the other URLs later and replace this one if
	// need be.
	return &AIA{
		SKI: cert.AKI,
		URL: cert.cert.IssuingCertificateURL[0],
	}
}

// Release models the root_releases and intermediate_releases tables.
type Release struct {
	Bundle     string // Is this a CA or intermediate release?
	Version    string
	ReleasedAt int64
}

func (r *Release) validBundle() bool {
	switch r.Bundle {
	case "ca", "int":
		return true
	default:
		return false
	}

}

func (r *Release) table() string {
	switch r.Bundle {
	case "ca":
		return "root"
	case "int":
		return "intermediate"
	default:
		// The bundle should have been validated by here; it's better
		// to panic and stop the world (generating a stack trace)
		// than to continue.
		panic("certdb: bundle should have been validated before the table selection")
		return ""
	}

}

func (r *Release) errInvalidBundle() error {
	return errors.New("certdb: invalid bundle" + r.Bundle + " (valid bundles are ca|int)")
}

// NewRelease verifies the bundle is valid, and creates a new Release
// with the current time stamp.
func NewRelease(bundle, version string) (*Release, error) {
	r := &Release{
		Bundle:     bundle,
		Version:    version,
		ReleasedAt: time.Now().Unix(),
	}

	if !r.validBundle() {
		return nil, r.errInvalidBundle()
	}

	return r, nil
}

// Insert stores the Release in the database.
func (r *Release) Insert(tx *sql.Tx) error {
	if !r.validBundle() {
		return r.errInvalidBundle()
	}

	query := fmt.Sprintf("INSERT INTO %s_releases (version, released_at) VALUES (?, ?)",
		r.table())
	_, err := tx.Exec(query, r.Version, r.ReleasedAt)
	return err
}

// Select requires the Version field to have been populated.
func (r *Release) Select(tx *sql.Tx) error {
	if !r.validBundle() {
		return r.errInvalidBundle()
	}

	query := fmt.Sprintf("SELECT released_at FROM %s_releases WHERE version=?", r.table())
	row := tx.QueryRow(query, r.Version)
	return row.Scan(&r.ReleasedAt)
}

// A CertificateRelease pairs a Certificate and Release to enable adding
// certificates to the relevant release tables.
type CertificateRelease struct {
	Certificate *Certificate
	Release     *Release
}

// NewCertificateRelease is a convenience function for building a
// CertificateRelease structure.
func NewCertificateRelease(c *Certificate, r *Release) *CertificateRelease {
	return &CertificateRelease{
		Certificate: c,
		Release:     r,
	}
}

// Insert stores the CertificateRelease in the database. It does no
// checking to determine if the CertificateRelease is already in the
// database, and will fail if it's already present in the database
// (due to UNIQUE constraints).
func (cr *CertificateRelease) Insert(tx *sql.Tx) error {
	query := fmt.Sprintf("INSERT INTO %ss (ski, serial, release) VALUES (?, ?, ?)", cr.Release.table())
	_, err := tx.Exec(query, cr.Certificate.SKI, cr.Certificate.Serial, cr.Release.Version)
	return err
}

// Select requires the Certificate field to have the SKI and Serial
// filled in, and the Release field to have the Version field filled
// in.
func (cr *CertificateRelease) Select(tx *sql.Tx) error {
	var count int
	query := fmt.Sprintf("SELECT count(*) FROM %ss WHERE ski=? AND serial=? AND release=?", cr.Release.table())
	row := tx.QueryRow(query, cr.Certificate.SKI, cr.Certificate.Serial, cr.Release.Version)
	err := row.Scan(&count)
	if err == nil && count == 0 {
		return sql.ErrNoRows
	}
	return err
}
