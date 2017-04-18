package certdb

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/cfssl_trust/release"
	_ "github.com/mattes/migrate/driver/sqlite3"
)

var sourceFiles = []string{
	"1485991500_revision_1.up.sql",
}

const latestRevision = 1

var (
	testCert1PEM = `-----BEGIN CERTIFICATE-----
MIIEujCCAqKgAwIBAgIUE88us8tr5RRFX4RlooTtDDKao5owDQYJKoZIhvcNAQEN
BQAwZDELMAkGA1UEBhMCVVMxKDAmBgNVBAsTH0Ryb3Bzb25kZSBDZXJ0aWZpY2F0
ZSBBdXRob3JpdHkxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNh
bGlmb3JuaWEwHhcNMTcwMzIyMjEyNDAwWhcNMTgwMzIyMjEyNDAwWjA7MQswCQYD
VQQGEwJVUzEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEUMBIGA1UEChMLRXhhbXBs
ZSBPcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDS8xbhnhoS9S8h
fOoyS5UEpRa/qxqe8+CrQ/hlLmND3p9igSaMpmDzz6rhgadPSOAhU4eNkuXU+0gL
c2qUny8TMZllS3bUzEVydRerDlz4ILsm0Pm/vvvOQxg+wAidKTpq6Mt9TjoXhqZW
FyZzYArGecIQhofl8Z0aHhBQx3vSLCl6i+5FdBHLbrE6WKSo5nWN+lImOVBOUDoe
KQvp9q3pX1WSzB02IEymBlMUfYuPx/Ak7q/ipgEcgQ9EkUQBR5G1fuuNzW/1WT8b
RdduT7quEOEOTB672g4zY+DG+oo3UjgvZNSkxS9MuAHD/vC0quTKSWYqOUFsW4wO
w+ymWO3dAgMBAAGjgYwwgYkwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDg3gWdPbhl4INGDMdU/RCig
1PrXMB8GA1UdIwQYMBaAFJs7c+/33EDkoip7EOnUrU1dDOw9MBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDANBgkqhkiG9w0BAQ0FAAOCAgEA3aqTKWrTgD3cZVuBTSz7nWRG
k5LyVYA1wlAD1o/msPwtO1eJ/doSc+gTUyzIYoUD3wyAkTrA3UJosYiY6BYdJvsh
AC5B/Kr+qwUjqqiE8ejPW/UzPjJldSa1zrhOMPDVDjnD+GMm9hLtxB7Mw0EWM3jn
+noiPjz6RFsbo4jhZigWrHmR1FKBoCWKEAJEzE0k5n0RljzyCk2nH6jfE1tHLaoe
njJ6XVu3RpW9RBJJcIyfyprhrG96ch8eet0VjV3Dn746sTKYY4yDMnvTc51aXc88
CeV6RxiqYObVbfyH8jX5v3rdJUA5FTTQU1IXx8Lt80L12Zhh+NqODlqJnnKVFAen
KpGINr31d0x2QE5C4uhb03OUgcQDT9pOu/VyLqZo7HUPZ/0HCUhPyvZrdiCAQCkQ
zjdxJ7iTVJibIjXjblURGsZnJ0TX1XdGcMOzQHsguNpZcDCE5lri+MlMX5Q7UVc8
2AOP0tNzvDb/dtaKJOYHC5vF+A8mC7ypoWqIPRpgl4Q1fNor92tlAXv+EbUQ+X4s
5IsbInK07y3bWprTUXCl9h2C3ZvZpnTDOhcwA2LppN7HRa0z86yrxMtTKXrRwzp7
cykDEvBNRzSMW4/JLLxWXX8xkgyof0FLOvKn6Vpa8yj3PO3LKPDYKXkMzMkyquAA
XHXWOlG/EIvvGpRRLGA=
-----END CERTIFICATE-----`
	testCert2PEM = `-----BEGIN CERTIFICATE-----
MIIEujCCAqKgAwIBAgIURax0FoxRFjsPw80NCPsLKlnTsTAwDQYJKoZIhvcNAQEN
BQAwZDELMAkGA1UEBhMCVVMxKDAmBgNVBAsTH0Ryb3Bzb25kZSBDZXJ0aWZpY2F0
ZSBBdXRob3JpdHkxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNh
bGlmb3JuaWEwHhcNMTcwMzIyMjM0NTAwWhcNMTgwMzIyMjM0NTAwWjA7MQswCQYD
VQQGEwJVUzEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEUMBIGA1UEChMLRXhhbXBs
ZSBPcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr3D/yKjwbNzBx
TkpbwKfdX7X7waApVFJnb8tBytwX+xgUEIjb/t7J5/HvILsQzL6rTXoqKj9xqF4n
oYNZP1OWI9HAIILaVU/pKk7HAr7Yj3voAh4eWB0nrwSrn72lCzJZc6WJHD1juEps
E1kH57WlsjMxyFddfknLvscQtDgKy+bEM3txklwwbj2FObyYfEbq3dK+/q3CiUra
ksU8v1QAeSvgpLnXS50j5TyaZFRIn3xHKzI/v2spA1/gaL3Yjw9vynmhH1ZMcOhQ
tKmqS1SZyU8WJnwE7WwA5+dAXWV1VT3q8dUAAi+bbw+jeT6+dlTFOSSYlzUhXeWL
syxhMGD3AgMBAAGjgYwwgYkwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFBLL3Acf8DziXVDxjO7RV7pb
TU/8MB8GA1UdIwQYMBaAFJs7c+/33EDkoip7EOnUrU1dDOw9MBQGA1UdEQQNMAuC
CWxvY2FsaG9zdDANBgkqhkiG9w0BAQ0FAAOCAgEAbmOCiB7B0e3KCWv3cwmz3FM4
WNTBeui0RPRdxoOYwKRjiRoHoFTlomWZrq9a4dG/lvrX4QZ6KUgriMWQTuVV8z7K
h/Ztz3o50zgEuhhIp2cAt9c3iQetJXwo/NSAn7XgkpnEiTPV9czGyAcAxUnLQfsT
NA3UhQ8KR4zam0IXRmZrmmx1cM+x+jtmJ1zSVgR0HRWCPYHPQ0eUPyKg8Y6C2BYT
J1CerMLyvZv77HhSOA7c2ycm00nM8zIzTgIXbVIgE0Iqc1nSh+fXMSH9XFsznS26
/b5akeqy+5FXTpvmEA8fLaUvqfp14MYfVjnJupcUPa80pzva1RdzKDH+cIkc0ock
9LMRk1n8hRUJ1OZPlGyZQR9AWeaRRdPcsvSQK21ZGgKgCMTu8MbgRBPYCC/CXB77
5MnQJUDBY4/iqGXoR083p9XRX4h17ztLFQqR7jcRW2uoHKJVdQ6KNNqzToxIwmWI
jhi/eGG9q+OQlWsLdlgPg+oMBpDlS5BKTSUMA6SRYAHqySNAQ+OLbNsbjVfcFR09
GH+eBfE/3+enc7fuwA4PMGXXaVa535xCanfphRyJ8KUdJldhqBREV3pUjhNqi7Xu
pPj5xf7ixOYOf8Dn+KLRhTHuxrns2jwOwum+a7SMsq8FFoAc0ns+DbLMVzIyXZ8M
YG/B7dZNlSdEmuy/8Ls=
-----END CERTIFICATE-----`
	testCert3PEM = `-----BEGIN CERTIFICATE-----
MIIE8TCCAtmgAwIBAgIUNf3QnXcvRrC+qV98F5/fqX7sSEYwDQYJKoZIhvcNAQEN
BQAwZDELMAkGA1UEBhMCVVMxKDAmBgNVBAsTH0Ryb3Bzb25kZSBDZXJ0aWZpY2F0
ZSBBdXRob3JpdHkxFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xEzARBgNVBAgTCkNh
bGlmb3JuaWEwHhcNMTcwMzIyMjM1NzAwWhcNMTgwMzIyMjM1NzAwWjA7MQswCQYD
VQQGEwJVUzEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEUMBIGA1UEChMLRXhhbXBs
ZSBPcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDVuvrIyN2KZd8V
LVrgydKirLSWTXLL4SnwhUElGd0Ng3mkm3+B/+bRqfku43oTgcCXSn2RBGO8FZ2h
tKLus2sE3lSiJeFIz+x6mjfxHQ0teAtcaZr8H3JzbFfP3G04DvszyOr2hUmZz3Zg
k+nJXwjBgXCswWJxIZ8b/PeWRsc3shUWSVED6IZIa/bBILbKPXi62cdDJxmHdMT3
8qIieamvP0EJemOQVSXPbUapVddOsZk9iXDJFYrmj89ngmyN/L+5XntVDELKKHFm
MN5PSFQ8Dc9In9xQfsWJQBS39iOUOwzj3aB3r8qapnJsJBEyaNnU71NQ/rOI7sbN
lPBiT/mDAgMBAAGjgcMwgcAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsG
AQUFBwMBMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFFoBtOYL2Aoxvqkin/dG0kyK
pKGGMB8GA1UdIwQYMBaAFJs7c+/33EDkoip7EOnUrU1dDOw9MDUGCCsGAQUFBwEB
BCkwJzAlBggrBgEFBQcwAoYZaHR0cDovL2xvY2FsaG9zdC9pc3N1YW5jZTAUBgNV
HREEDTALgglsb2NhbGhvc3QwDQYJKoZIhvcNAQENBQADggIBAEug5xSH5B62LDup
soBnGcpiup6778O9pNlmln7h2Lh538S33JPYLp1SYqLieQ0Ww/9CCFMg/VxKDuKE
vbF7n2ZDjLCgXNQpJwBRwCbSFiWY5lYyC4+wbKp04GywcV7HVct1YtqBlvRF+lO7
TXmeEmE15IdyZRjONLv1FMhRXKkU6CpU6Dfn++UcE9EQq2xgFWXYzKZVGrkWv4Gp
33fbCY7nuBSF3FAGyjHq+zBJM0ftcBkg1OrbTWqgJB4h41SXA5DT4dovBZ0AWuuv
84ft8FxFLwVqRMtH8Trc8qXhBmDUYfa4Iv51NF1Ji8xkiusuqt8z6kiTo+VJw1hj
z3ZQoYaj1Yk9UCHCbqHN3PxW+N/K451ib+i7CiSG8hhaxZMpX+cP8o3C65fVDquH
2gpcrHLt5CAGRk3YY+uMkBGLvSYhQ2By8tpX1YXcmAYleF6h7a5E5xTqR9ek9Nhj
PWnfrp07jugIsv2nFlYZjBaa1p1lWgabAaGHG47V0HRTFvKdtaxXCTMKofc3g0he
44Wg1V0EcvsLeDAmjBgBtnwFyeV33y1ytDwvl7/EAlX9OWdaDOSXnzotocSzFpKh
vxbpF0Bdu5S04wN5Qzc5sIQWCyPwtUsiq7A+xqqOCU9770bqraG3T7aBM7VuUm6O
huB5zfRBKm6VY4UQEj7kHjQO8nxW
-----END CERTIFICATE-----`
	testCert1  *x509.Certificate
	testCert2  *x509.Certificate
	testCert3  *x509.Certificate
	testDB     *sql.DB
	curRelease = release.New()
)

func mustParseCertificate(in string) *x509.Certificate {
	p, rest := pem.Decode([]byte(in))
	if len(rest) != 0 || p == nil {
		panic("couldn't parse certificate")
	}

	if p.Type != "CERTIFICATE" {
		panic("invalid certificate")
	}

	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		panic(err.Error())
	}

	return cert
}

func execSQLFile(path string) error {
	data, err := ioutil.ReadFile("../" + path)
	if err != nil {
		return err
	}

	split := strings.Split(string(data), ";")
	var statements []string
	for i := range split {
		statement := strings.TrimSpace(split[i])
		if statement != "" {
			statements = append(statements, statement)
		}
	}

	for _, statement := range statements {
		_, err := testDB.Exec(statement)
		if err != nil {
			return err
		}
	}

	return nil
}

func dbInit() {
	var err error
	testDB, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		panic(err.Error())
	}

	for _, source := range sourceFiles {
		err = execSQLFile(source)
		if err != nil {
			panic(err.Error())
		}
	}

	var revision int
	row := testDB.QueryRow("SELECT max(revision) FROM schema_version")
	err = row.Scan(&revision)
	if err != nil {
		panic(err.Error())
	}

	if revision != latestRevision {
		panic(fmt.Sprintf("schema version is currently %d, but expected %d",
			revision, latestRevision))
	}
}

func init() {
	testCert1 = mustParseCertificate(testCert1PEM)
	testCert2 = mustParseCertificate(testCert2PEM)
	testCert3 = mustParseCertificate(testCert3PEM)
	dbInit()
}

// TestCertEnsure verifies the Ensure function with the Certificate
// type. It does three tests: first, it calls Ensure with the first
// test certificate to make sure it was inserted. Next, it makes the
// same call; the certificate shouldn't be inserted twice. Finally,
// it tries to Ensure the second test certificate. It also calls
// Ensure on any other certificates that should be in the database.
func TestCertEnsure(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	cert := NewCertificate(testCert1)
	inserted, err := Ensure(cert, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate should have been inserted")
	}

	cert = NewCertificate(testCert1)
	inserted, err = Ensure(cert, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: certificate should not have been inserted")
	}

	cert = NewCertificate(testCert2)
	inserted, err = Ensure(cert, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate should have been inserted")
	}

	cert = NewCertificate(testCert3)
	inserted, err = Ensure(cert, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate should have been inserted")
	}
}

// TestAIAEnsure verifies that Ensuring an AIA works.
func TestAIAEnsure(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	cert := NewCertificate(testCert1)
	aia := NewAIA(cert)
	if aia != nil {
		t.Fatal("certdb: certificate with no AIA shouldn't return a valid AIA")
	}

	cert = NewCertificate(testCert3)
	aia = NewAIA(cert)
	if aia == nil {
		t.Fatal("certdb: certificate should have returned a valid AIA")
	}

	inserted, err := Ensure(aia, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: AIA should have been inserted")
	}

	cert = NewCertificate(testCert3)
	aia = NewAIA(cert)
	if aia == nil {
		t.Fatal("certdb: certificate should have returned a valid AIA")
	}

	inserted, err = Ensure(aia, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: AIA shouldn't have been inserted")
	}
}

// TestReleaseEnsure verifies that Ensuring a release works.
func TestReleaseEnsure(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	caRelease, err := NewRelease("ca", curRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	inserted, err := Ensure(caRelease, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: release should have been inserted")
	}

	inserted, err = Ensure(caRelease, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: release shouldn't have been inserted")
	}

	intRelease, err := NewRelease("int", curRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	inserted, err = Ensure(intRelease, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: release should have been inserted")
	}

	inserted, err = Ensure(intRelease, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: release shouldn't have been inserted")
	}

	_, err = NewRelease("something", curRelease.String())
	if err == nil {
		t.Fatal("certdb: 'something' shouldn't be a valid release name")
	}
	err = nil // This is needed to prevent the database from rolling back.
}

// TestCREnsure verifies certificate releases work as intended.
func TestCREnsure(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	caRelease, err := NewRelease("ca", curRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	intRelease, err := NewRelease("int", curRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	cert := NewCertificate(testCert1)
	cr := NewCertificateRelease(cert, caRelease)

	inserted, err := Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate release should have been inserted")
	}

	inserted, err = Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: certificate release shouldn't have been inserted")
	}

	cert = NewCertificate(testCert3)
	cr = NewCertificateRelease(cert, caRelease)

	inserted, err = Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate release should have been inserted")
	}

	inserted, err = Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: certificate release shouldn't have been inserted")
	}

	cert = NewCertificate(testCert2)
	cr = NewCertificateRelease(cert, intRelease)

	inserted, err = Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if !inserted {
		t.Fatal("certdb: certificate release should have been inserted")
	}

	inserted, err = Ensure(cr, tx)
	if err != nil {
		t.Fatal(err)
	} else if inserted {
		t.Fatal("certdb: certificate release shouldn't have been inserted")
	}
}

func TestBundle(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	certs, err := CollectRelease("ca", curRelease.String(), tx)
	if err != nil {
		t.Fatalf("%s", err)
	}

	if len(certs) != 2 {
		t.Fatalf("unexpected number of certificates in bundle: have %d, want 2", len(certs))
	}
}

func TestCertReleases(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		switch err {
		case nil:
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
		default:
			tx.Rollback()
			t.Fatal("database was rolled back")
		}
	}()

	cert := NewCertificate(testCert1)
	releases, err := cert.Releases(tx)
	if err != nil {
		t.Fatal(err)
	}

	if len(releases) != 1 {
		t.Fatal("certificate should be in a release")
	}

	rel := releases[0]
	if rel.Bundle != "ca" {
		t.Fatalf("certificate is in the wrong release: it should be a ca curRelease.String(), but it is %s", rel.Bundle)
	}

	if rel.Version != curRelease.String() {
		t.Fatalf("certificate's release is the wrong version; it should be %s but is %s", curRelease.String(), rel.Version)
	}
}

func TestFindCertificateBySKI(t *testing.T) {
	ski := "383781674f6e197820d18331d53f4428a0d4fad7"
	certs, err := FindCertificateBySKI(testDB, ski)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 1 {
		t.Fatal("only one certificate should have been found, have ", len(certs))
	}

	serialBytes := []byte{
		19, 207, 46, 179, 203, 107, 229, 20,
		69, 95, 132, 101, 162, 132, 237, 12,
		50, 154, 163, 154,
	}

	expectedSerial := big.NewInt(0).SetBytes(serialBytes)

	if expectedSerial.Cmp(certs[0].cert.SerialNumber) != 0 {
		t.Fatalf("serial numbers don't match: have %s, but want %s",
			certs[0].cert.SerialNumber, expectedSerial)
	}
}

func TestAllCertificates(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	certs, err := AllCertificates(tx)
	if err != nil {
		t.Fatal(err)
	}

	if len(certs) != 3 {
		t.Fatal("expected 3 certificates from AllCertificates, but have", len(certs))
	}
}
func TestAllReleases(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	nextRelease, err := curRelease.Inc()
	if err != nil {
		t.Fatal(err)
	}

	anotherRelease, err := nextRelease.Inc()
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(time.Second) // Ensure the released_at timestamp is bumped.
	rel, err := NewRelease("ca", nextRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	ok, err := Ensure(rel, tx)
	if err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("release wasn't entered into database")
	}

	time.Sleep(time.Second) // Ensure the released_at timestamp is bumped.
	rel, err = NewRelease("ca", anotherRelease.String())
	if err != nil {
		t.Fatal(err)
	}

	ok, err = Ensure(rel, tx)
	if err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("release wasn't entered into database")
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	releases, err := AllReleases(testDB, "ca")
	if err != nil {
		t.Fatal(err)
	}

	if len(releases) != 3 {
		t.Fatalf("expected 3 releases, but have %d", len(releases))
	}

	// Verify that the releases are properly ordered.
	if releases[0].Version != anotherRelease.String() {
		t.Fatalf("expected release[0] to be %s, but have %s", anotherRelease.String(), releases[0].Version)
	}
	if releases[1].Version != nextRelease.String() {
		t.Fatalf("expected release[1] to be %s, but have %s", nextRelease.String(), releases[1].Version)
	}
	if releases[2].Version != curRelease.String() {
		t.Fatalf("expected release[2] to be %s, but have %s", curRelease.String(), releases[2].Version)
	}

	tx, err = testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	rel = &Release{Bundle: "ca", Version: curRelease.String()}
	err = rel.Select(tx)
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	n, err := rel.Count(testDB)
	if err != nil {
		t.Fatal(err)
	}

	if n != 2 {
		t.Fatalf("expected 2 certificates in the %s release, but have %d", rel.Version, n)
	}

	rel, err = LatestRelease(testDB, "ca")
	if err != nil {
		t.Fatal(err)
	}

	if rel.Version != anotherRelease.String() {
		t.Fatalf("expected the latest release to be %s, but it's %s", anotherRelease.String(), rel.Version)
	}
}

func TestCertificateRevoked(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	cert := NewCertificate(testCert1)
	revoked, err := cert.Revoked(tx, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}

	if revoked {
		t.Fatal("certificate should not be revoked, but has been revoked")
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	tx, err = testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	err = cert.Revoke(tx, "test", "test", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	tx, err = testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}

	revoked, err = cert.Revoked(tx, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}

	if !revoked {
		t.Fatal("certificate not be revoked, but has not been revoked")
	}

	_, err = tx.Exec(`DELETE FROM revocations WHERE ski=?`, cert.SKI)
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}
}

func TestPreviousRelease(t *testing.T) {
	tx, err := testDB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	nextRelease, err := curRelease.Inc()
	if err != nil {
		t.Fatal(err)
	}

	next := &Release{
		Bundle:  "ca",
		Version: nextRelease.String(),
	}

	cur := &Release{
		Bundle:  "ca",
		Version: curRelease.String(),
	}

	err = next.Select(tx)
	if err != nil {
		t.Fatal(err)
	}

	err = cur.Select(tx)
	if err != nil {
		t.Fatal(err)
	}

	err = tx.Commit()
	if err != nil {
		t.Fatal(err)
	}

	prev, err := next.Previous(testDB)
	if err != nil {
		t.Fatal(err)
	}

	if prev.Version != curRelease.String() {
		t.Fatalf("the call to Previous() should return %s, but returned %s",
			curRelease.String(), prev.Version)
	}

	_, err = cur.Previous(testDB)
	if err != sql.ErrNoRows {
		t.Fatal("there shouldn't be a release prior to the current release, but there is")
	}
}
