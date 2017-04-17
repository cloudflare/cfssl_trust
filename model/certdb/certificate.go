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
	"os"
	"time"

	"github.com/bjt79/cfssl/signer"
)

// Finalize finishes a transaction, committing it if needed or rolling
// back on error.
func Finalize(err *error, tx *sql.Tx) {
	if *err == nil {
		*err = tx.Commit()
		if *err != nil {
			fmt.Fprintf(os.Stderr, "[!] failed to commit transaction: %s\n", *err)
			os.Exit(1)
		}
	} else {
		tx.Rollback()
	}
}

// FindCertificateBySKI returns all the certificates with the given
// SKI.
func FindCertificateBySKI(db *sql.DB, ski string) ([]*Certificate, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer Finalize(&err, tx)

	var certificates []*Certificate
	rows, err := tx.Query(`
SELECT aki, serial, not_before, not_after, raw
	FROM certificates
	WHERE ski=?`,
		ski)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		cert := &Certificate{
			SKI: ski,
		}

		err = rows.Scan(&cert.AKI, &cert.Serial, &cert.NotBefore,
			&cert.NotAfter, &cert.Raw)
		if err != nil {
			return nil, err
		}

		cert.cert, err = x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, cert)
	}

	return certificates, nil
}

// AllCertificates loads all the certificates in the database.
func AllCertificates(tx *sql.Tx) ([]*Certificate, error) {
	rows, err := tx.Query("SELECT * FROM certificates")
	if err != nil {
		return nil, err
	}

	var certificates []*Certificate
	for rows.Next() {
		cert := &Certificate{}
		err = rows.Scan(&cert.SKI, &cert.AKI, &cert.Serial, &cert.NotBefore,
			&cert.NotAfter, &cert.Raw)
		if err != nil {
			return nil, err
		}

		cert.cert, err = x509.ParseCertificate(cert.Raw)
		if err != nil {
			return nil, err
		}

		certificates = append(certificates, cert)
	}

	return certificates, err
}

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

// Releases looks up all the releases for a certificate.
func (cert *Certificate) Releases(tx *sql.Tx) ([]*Release, error) {
	var releases []*Release

	rows, err := tx.Query("SELECT release FROM roots WHERE ski=? AND serial=?", cert.SKI, cert.Serial)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		rel := &Release{
			Bundle: "ca",
		}

		err = rows.Scan(&rel.Version)
		if err != nil {
			return nil, err
		}

		releases = append(releases, rel)
	}
	rows.Close()

	rows, err = tx.Query("SELECT release FROM intermediates WHERE ski=? AND serial=?", cert.SKI, cert.Serial)
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		rel := &Release{
			Bundle: "int",
		}

		err = rows.Scan(&rel.Version)
		if err != nil {
			return nil, err
		}

		releases = append(releases, rel)
	}

	for _, rel := range releases {
		err = rel.Select(tx)
		if err != nil {
			return nil, err
		}
	}

	return releases, nil
}

// Revoked returns true if the certificate was revoked before the
// timestamp passed in.
func (cert *Certificate) Revoked(tx *sql.Tx, when int64) (bool, error) {
	if err := cert.Select(tx); err != nil {
		return true, err
	}

	var count int
	row := tx.QueryRow(`SELECT count(*) FROM revocations WHERE ski=? AND revoked_at <= ?`, cert.SKI, when)
	err := row.Scan(&count)
	if err != nil {
		return true, err
	}

	return count > 0, nil
}

// Revoke marks the certificate as revoked.
func (cert *Certificate) Revoke(tx *sql.Tx, mechanism, reason string, when int64) error {
	if err := cert.Select(tx); err != nil {
		return err
	}

	rev := &Revocation{
		SKI:       cert.SKI,
		RevokedAt: when,
		Mechanism: mechanism,
		Reason:    reason,
	}

	// We ignore the inserted value because if it returns false, that means
	// the certificate has already been revoked.
	_, err := Ensure(rev, tx)
	return err
}

// X509 returns the *crypto/x509.Certificate from the certificate.
func (cert *Certificate) X509() *x509.Certificate {
	return cert.cert
}

var nullSerial = big.NewInt(0)

// NewCertificate creates a Certificate from a crypto/x509 Certificate
// structure.
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

	// Work around the fact that many early CA roots don't have an
	// SKI. This uses the method found in RFC 5280 Section 4.2.1.2
	// (1).
	if c.SKI == "" {
		ski, err := signer.ComputeSKI(cert)
		if err != nil {
			panic("invalid public key in root certificate")
		}

		c.SKI = fmt.Sprintf("%x", ski)
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

func validBundle(bundle string) bool {
	switch bundle {
	case "ca", "int":
		return true
	default:
		return false
	}
}

func tableForBundle(bundle string) string {
	switch bundle {
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

// Release models the root_releases and intermediate_releases tables.
type Release struct {
	Bundle     string // Is this a CA or intermediate release?
	Version    string
	ReleasedAt int64
}

func (r *Release) validBundle() bool {
	return validBundle(r.Bundle)
}

func (r *Release) table() string {
	return tableForBundle(r.Bundle)
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

// Count requires the Release to be Selectable, and will return the
// number of certificates in the release.
func (r *Release) Count(db *sql.DB) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	err = r.Select(tx)
	if err != nil {
		if err == sql.ErrNoRows {
			err = errors.New("model/certdb: release doesn't exist")
		}
		return 0, err
	}

	var count int
	q := fmt.Sprintf("SELECT count(*) FROM %ss WHERE release = ?", r.table())
	row := tx.QueryRow(q, r.Version)
	err = row.Scan(&count)
	if err == nil {
		err = tx.Commit()
	}
	return count, err
}

func AllReleases(db *sql.DB, bundle string) ([]*Release, error) {
	if !validBundle(bundle) {
		return nil, errors.New("model/certdb: invalid bundle " + bundle)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // nop if commit is called.

	tbl := tableForBundle(bundle)
	var releases []*Release

	rows, err := tx.Query(fmt.Sprintf(`SELECT version,released_at FROM %s_releases ORDER BY released_at DESC`, tbl))
	if err != nil {
		return nil, err
	}

	for rows.Next() {
		release := &Release{Bundle: bundle}
		err = rows.Scan(&release.Version, &release.ReleasedAt)
		if err != nil {
			break
		}
		releases = append(releases, release)
	}

	if err == nil {
		err = tx.Commit()
	}

	return releases, err
}

// LatestRelease returns the latest release.
func LatestRelease(db *sql.DB, bundle string) (*Release, error) {
	if !validBundle(bundle) {
		return nil, errors.New("model/certdb: invalid bundle " + bundle)
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // nop if commit is called.

	release := &Release{Bundle: bundle}
	tbl := tableForBundle(bundle)
	q := fmt.Sprintf(`SELECT version,released_at FROM %s_releases ORDER BY released_at DESC LIMIT 1`, tbl)

	row := tx.QueryRow(q)
	err = row.Scan(&release.Version, &release.ReleasedAt)
	if err == nil {
		err = tx.Commit()
	}

	return release, err
}

// FetchRelease looks for the specified release. It does its own
// transaction to match the style of the other release fetching
// functions.
func FetchRelease(db *sql.DB, bundle, version string) (*Release, error) {
	rel, err := NewRelease(bundle, version)
	if err != nil {
		return nil, err
	}

	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback() // nop if commit is called.

	err = rel.Select(tx)
	if err != nil {
		return nil, err
	}

	err = tx.Commit()
	if err != nil {
		return nil, err
	}

	return rel, nil
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

// Revocation models the revocations table.
type Revocation struct {
	SKI       string
	RevokedAt int64
	Mechanism string
	Reason    string
}

// Select requires the SKI field to be filled in. Note that only one
// revocation per SKI should exist.
func (rev *Revocation) Select(tx *sql.Tx) error {
	row := tx.QueryRow(`SELECT revoked_at, mechanism, reason FROM revocations WHERE ski=?`, rev.SKI)
	err := row.Scan(&rev.RevokedAt, &rev.Mechanism, &rev.Reason)
	if err != nil {
		return err
	}

	return nil
}

// Insert adds the revocation to the database if no revocation exists
// yet.
func (rev *Revocation) Insert(tx *sql.Tx) error {
	_, err := tx.Exec(`INSERT INTO revocations (ski, revoked_at, mechanism, reason) VALUES (?, ?, ?, ?)`, rev.SKI, rev.RevokedAt, rev.Mechanism, rev.Reason)
	return err
}
