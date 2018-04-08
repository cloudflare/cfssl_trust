package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kr/text"
)

// following two lifted from CFSSL, (replace-regexp "\(.+\): \(.+\),"
// "\2: \1,")

var keyUsage = map[x509.KeyUsage]string{
	x509.KeyUsageDigitalSignature:  "digital signature",
	x509.KeyUsageContentCommitment: "content committment",
	x509.KeyUsageKeyEncipherment:   "key encipherment",
	x509.KeyUsageKeyAgreement:      "key agreement",
	x509.KeyUsageDataEncipherment:  "data encipherment",
	x509.KeyUsageCertSign:          "cert sign",
	x509.KeyUsageCRLSign:           "crl sign",
	x509.KeyUsageEncipherOnly:      "encipher only",
	x509.KeyUsageDecipherOnly:      "decipher only",
}

var extKeyUsages = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageAny:                        "any",
	x509.ExtKeyUsageServerAuth:                 "server auth",
	x509.ExtKeyUsageClientAuth:                 "client auth",
	x509.ExtKeyUsageCodeSigning:                "code signing",
	x509.ExtKeyUsageEmailProtection:            "s/mime",
	x509.ExtKeyUsageIPSECEndSystem:             "ipsec end system",
	x509.ExtKeyUsageIPSECTunnel:                "ipsec tunnel",
	x509.ExtKeyUsageIPSECUser:                  "ipsec user",
	x509.ExtKeyUsageTimeStamping:               "timestamping",
	x509.ExtKeyUsageOCSPSigning:                "ocsp signing",
	x509.ExtKeyUsageMicrosoftServerGatedCrypto: "microsoft sgc",
	x509.ExtKeyUsageNetscapeServerGatedCrypto:  "netscape sgc",
}

func pubKeyAlgo(a x509.PublicKeyAlgorithm) string {
	switch a {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.DSA:
		return "DSA"
	default:
		return "unknown public key algorithm"
	}
}

func sigAlgoPK(a x509.SignatureAlgorithm) string {
	switch a {

	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
		return "RSA"
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "ECDSA"
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return "DSA"
	default:
		return "unknown public key algorithm"
	}
}

func sigAlgoHash(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "MD2"
	case x509.MD5WithRSA:
		return "MD5"
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		return "SHA1"
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256, x509.DSAWithSHA256:
		return "SHA256"
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return "SHA384"
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return "SHA512"
	default:
		return "unknown hash algorithm"
	}
}

// TranslateCFSSLError turns a CFSSL error into a more readable string.
func TranslateCFSSLError(err error) error {
	if err == nil {
		return nil
	}

	// printing errors as json is terrible
	if cfsslError, ok := err.(*cferr.Error); ok {
		err = errors.New(cfsslError.Message)
	}
	return err
}

// Warnx displays a formatted error message to standard error, à la
// warnx(3).
func Warnx(format string, a ...interface{}) (int, error) {
	format += "\n"
	return fmt.Fprintf(os.Stderr, format, a...)
}

// Warn displays a formatted error message to standard output,
// appending the error string, à la warn(3).
func Warn(err error, format string, a ...interface{}) (int, error) {
	format += ": %v\n"
	a = append(a, err)
	return fmt.Fprintf(os.Stderr, format, a...)
}

const maxLine = 78

func makeIndent(n int) string {
	s := "    "
	for i := 0; i < n; i++ {
		s += "        "
	}
	return s
}

func indentLen(n int) int {
	return 4 + (8 * n)
}

// this isn't real efficient, but that's not a problem here
func wrap(s string, indent int) string {
	if indent > 3 {
		indent = 3
	}

	wrapped := text.Wrap(s, maxLine)
	lines := strings.SplitN(wrapped, "\n", 2)
	if len(lines) == 1 {
		return lines[0]
	}

	if (maxLine - indentLen(indent)) <= 0 {
		panic("too much indentation")
	}

	rest := strings.Join(lines[1:], " ")
	wrapped = text.Wrap(rest, maxLine-indentLen(indent))
	return lines[0] + "\n" + text.Indent(wrapped, makeIndent(indent))
}

func dumpHex(in []byte) string {
	var s string
	for i := range in {
		s += fmt.Sprintf("%02X:", in[i])
	}

	return strings.Trim(s, ":")
}

// permissiveConfig returns a maximally-accepting TLS configuration;
// the purpose is to look at the cert, not verify the security properties
// of the connection.
func permissiveConfig() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}

// verifyConfig returns a config that will verify the connection.
func verifyConfig(hostname string) *tls.Config {
	return &tls.Config{
		ServerName: hostname,
	}
}

type connInfo struct {
	// The original URI provided.
	URI string

	// The hostname of the server.
	Host string

	// The port to connect on.
	Port string

	// The address to connect to.
	Addr string
}

func getConnInfo(uri string) *connInfo {
	ci := &connInfo{URI: uri}
	ci.Host = uri[len("https://"):]

	host, port, err := net.SplitHostPort(ci.Host)
	if err != nil {
		ci.Port = "443"
	} else {
		ci.Host = host
		ci.Port = port
	}
	ci.Addr = net.JoinHostPort(ci.Host, ci.Port)
	return ci
}
