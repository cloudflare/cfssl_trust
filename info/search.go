package info

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"

	"github.com/cloudflare/cfssl_trust/model/certdb"
)

// A CertificateFilter is a predicate that returns true if the
// certificate matches some predicate.
type CertificateFilter func(*CertificateMetadata) bool

func filter(certs []*CertificateMetadata, pred CertificateFilter) []*CertificateMetadata {
	filtered := []*CertificateMetadata{}
	for i := range certs {
		if pred(certs[i]) {
			filtered = append(filtered, certs[i])
		}
	}
	return filtered
}

// filterCertificates applies the filters to the list of certificates,
// returning only those certificates that match all the filters.
func filterCertificates(certs []*CertificateMetadata, filters []CertificateFilter) []*CertificateMetadata {
	filtered := certs
	for _, f := range filters {
		filtered = filter(filtered, f)
	}
	return filtered
}

// FilterBySKI is a CertificateFilter that returns true if the SKI in
// a certificate matches the regular expression passed in.
func FilterBySKI(ski string) (CertificateFilter, error) {
	skiFilter, err := regexp.Compile(ski)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		return skiFilter.MatchString(cm.SKI)
	}, nil
}

// FilterByAKI is a CertificateFilter that returns true if the AKI in
// a certificate matches the regular expression passed in.
func FilterByAKI(aki string) (CertificateFilter, error) {
	akiFilter, err := regexp.Compile(aki)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		return akiFilter.MatchString(cm.AKI)
	}, nil
}

// FilterBySubject is a CertificateFilter that returns true if the
// Subject in a certificate matches the regular expression passed in.
func FilterBySubject(subj string) (CertificateFilter, error) {
	subjFilter, err := regexp.Compile(subj)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		return subjFilter.MatchString(cm.Subject)
	}, nil
}

// FilterByIssuer is a CertificateFilter that returns true if the
// Issuer in a certificate matches the regular expression passed in.
func FilterByIssuer(iss string) (CertificateFilter, error) {
	issFilter, err := regexp.Compile(iss)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		return issFilter.MatchString(cm.Issuer)
	}, nil
}

// FilterByRelease is a CertificateFilter that returns true if the
// release version matches the regular expression passed in.
func FilterByRelease(version string) (CertificateFilter, error) {
	verFilter, err := regexp.Compile(version)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		for _, rel := range cm.Releases {
			if verFilter.MatchString(rel.Version) {
				return true
			}
		}
		return false
	}, nil
}

// FilterByBundle is a CertificateFilter that returns true if the
// release bundle matches the regular expression passed in.
func FilterByBundle(bundle string) (CertificateFilter, error) {
	bundleFilter, err := regexp.Compile(bundle)
	if err != nil {
		return nil, err
	}

	return func(cm *CertificateMetadata) bool {
		for _, rel := range cm.Releases {
			if bundleFilter.MatchString(rel.Bundle) {
				return true
			}
		}
		return false
	}, nil
}

var filters = map[string]func(string) (CertificateFilter, error){
	"ski":     FilterBySKI,
	"aki":     FilterByAKI,
	"subject": FilterBySubject,
	"issuer":  FilterByIssuer,
	"release": FilterByRelease,
	"bundle":  FilterByBundle,
}

// ParseQuery attempts to parse a query in the form "type:regexp",
// returning a filter if successful.
func ParseQuery(query string) (CertificateFilter, error) {
	parts := strings.SplitN(query, ":", 2)
	if len(parts) != 2 {
		return nil, errors.New("info: expected a query in the form type:regexp")
	}

	// parts[0]: type
	// parts[1]: regexp
	f, ok := filters[parts[0]]
	if !ok {
		return nil, errors.New("info: unknown filter type " + parts[0])
	}

	return f(parts[1])
}

// Query searches the database for all certificates matching the search terms.
func Query(db *sql.DB, terms []string) ([]*CertificateMetadata, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	certs, err := certdb.AllCertificates(tx)
	if err != nil {
		return nil, err
	}

	results := make([]*CertificateMetadata, len(certs))
	for i := range certs {
		results[i], err = LoadCertificateMetadata(tx, certs[i])
		if err != nil {
			return nil, err
		}
	}

	filters := make([]CertificateFilter, 0, len(terms))
	for _, term := range terms {
		f, err := ParseQuery(term)
		if err != nil {
			return nil, err
		}

		filters = append(filters, f)
	}

	err = tx.Commit()
	return filterCertificates(results, filters), err
}
