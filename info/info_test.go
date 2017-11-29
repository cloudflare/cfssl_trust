package info

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/cloudflare/cfssl_trust/model/certdb"

	sqlmock "gopkg.in/DATA-DOG/go-sqlmock.v1"
)

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
	testCert1X509 *x509.Certificate
	testCert1     *certdb.Certificate
	release       = &certdb.Release{
		Bundle:     "ca",
		Version:    "2017.3.0",
		ReleasedAt: 1490827656,
	}
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

func init() {
	testCert1X509 = mustParseCertificate(testCert1PEM)
	testCert1 = certdb.NewCertificate(testCert1X509)
}

func TestWriteTestCert1(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}

	columns := []string{"release"}
	mock.ExpectBegin()
	mock.ExpectQuery("SELECT (.+) FROM roots (.+)").
		WithArgs(testCert1.SKI, testCert1.Serial).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(release.Version))
	mock.ExpectQuery("SELECT (.+) FROM intermediates (.+)").
		WithArgs(testCert1.SKI, testCert1.Serial).
		WillReturnRows(sqlmock.NewRows(columns))
	mock.ExpectQuery("SELECT (.+) FROM root_releases (.+)").
		WithArgs(release.Version).
		WillReturnRows(sqlmock.NewRows(columns).AddRow(release.ReleasedAt))
	mock.ExpectCommit()

	buf := &bytes.Buffer{}
	err = WriteCertificateInformation(buf, db, testCert1)
	if err != nil {
		t.Fatal(err)
	}

	err = mock.ExpectationsWereMet()
	if err != nil {
		t.Fatal(err)
	}

	expected := `Subject: /C=US/O=Example Org/L=San Francisco
Issuer: /C=US/OU=Dropsonde Certificate Authority/L=San Francisco/ST=California
	Not Before: 2017-03-22T21:24:00+0000
	Not After: 2018-03-22T21:24:00+0000
Releases:
	- 2017.3.0 ca (2017-03-29T22:47:36+0000)`
	out := strings.TrimSpace(buf.String())

	if out != expected {
		t.Fatalf(`certificate information wrote unexpected information:
expected:
%s

have:
%s
`, expected, out)
	}
}
