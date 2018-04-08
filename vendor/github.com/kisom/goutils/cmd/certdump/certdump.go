package main

import (
	"bytes"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/cloudflare/cfssl/helpers"
)

func certPublic(cert *x509.Certificate) string {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA-%d", pub.N.BitLen())
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P256():
			return "ECDSA-prime256v1"
		case elliptic.P384():
			return "ECDSA-secp384r1"
		case elliptic.P521():
			return "ECDSA-secp521r1"
		default:
			return "ECDSA (unknown curve)"
		}
	case *dsa.PublicKey:
		return "DSA"
	default:
		return "Unknown"
	}
}

func displayName(name pkix.Name) string {
	var ns []string

	if name.CommonName != "" {
		ns = append(ns, name.CommonName)
	}

	for i := range name.Country {
		ns = append(ns, fmt.Sprintf("C=%s", name.Country[i]))
	}

	for i := range name.Organization {
		ns = append(ns, fmt.Sprintf("O=%s", name.Organization[i]))
	}

	for i := range name.OrganizationalUnit {
		ns = append(ns, fmt.Sprintf("OU=%s", name.OrganizationalUnit[i]))
	}

	for i := range name.Locality {
		ns = append(ns, fmt.Sprintf("L=%s", name.Locality[i]))
	}

	for i := range name.Province {
		ns = append(ns, fmt.Sprintf("ST=%s", name.Province[i]))
	}

	if len(ns) > 0 {
		return "/" + strings.Join(ns, "/")
	}

	return "*** no subject information ***"
}

func keyUsages(ku x509.KeyUsage) string {
	var uses []string

	for u, s := range keyUsage {
		if (ku & u) != 0 {
			uses = append(uses, s)
		}
	}

	return strings.Join(uses, ", ")
}

func extUsage(ext []x509.ExtKeyUsage) string {
	ns := make([]string, 0, len(ext))
	for i := range ext {
		ns = append(ns, extKeyUsages[ext[i]])
	}

	return strings.Join(ns, ", ")
}

func showBasicConstraints(cert *x509.Certificate) {
	fmt.Printf("\tBasic constraints: ")
	if cert.BasicConstraintsValid {
		fmt.Printf("valid")
	} else {
		fmt.Printf("invalid")
	}

	if cert.IsCA {
		fmt.Printf(", is a CA certificate")
	}

	if (cert.MaxPathLen == 0 && cert.MaxPathLenZero) || (cert.MaxPathLen > 0) {
		fmt.Printf(", max path length %d", cert.MaxPathLen)
	}

	fmt.Printf("\n")
}

const oneTrueDateFormat = "2006-01-02T15:04:05-0700"

var (
	dateFormat string
	showHash   bool // if true, print a SHA256 hash of the certificate's Raw field
)

func wrapPrint(text string, indent int) {
	tabs := ""
	for i := 0; i < indent; i++ {
		tabs += "\t"
	}

	fmt.Printf(tabs+"%s\n", wrap(text, indent))
}

func displayCert(cert *x509.Certificate) {
	fmt.Println("CERTIFICATE")
	if showHash {
		fmt.Println(wrap(fmt.Sprintf("SHA256: %x", sha256.Sum256(cert.Raw)), 0))
	}
	fmt.Println(wrap("Subject: "+displayName(cert.Subject), 0))
	fmt.Println(wrap("Issuer: "+displayName(cert.Issuer), 0))
	fmt.Printf("\tSignature algorithm: %s / %s\n", sigAlgoPK(cert.SignatureAlgorithm),
		sigAlgoHash(cert.SignatureAlgorithm))
	fmt.Println("Details:")
	wrapPrint("Public key: "+certPublic(cert), 1)
	fmt.Printf("\tSerial number: %s\n", cert.SerialNumber)

	if len(cert.AuthorityKeyId) > 0 {
		fmt.Printf("\t%s\n", wrap("AKI: "+dumpHex(cert.AuthorityKeyId), 1))
	}
	if len(cert.SubjectKeyId) > 0 {
		fmt.Printf("\t%s\n", wrap("SKI: "+dumpHex(cert.SubjectKeyId), 1))
	}

	wrapPrint("Valid from: "+cert.NotBefore.Format(dateFormat), 1)
	fmt.Printf("\t     until: %s\n", cert.NotAfter.Format(dateFormat))
	fmt.Printf("\tKey usages: %s\n", keyUsages(cert.KeyUsage))

	if len(cert.ExtKeyUsage) > 0 {
		fmt.Printf("\tExtended usages: %s\n", extUsage(cert.ExtKeyUsage))
	}

	showBasicConstraints(cert)

	validNames := make([]string, 0, len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses))
	for i := range cert.DNSNames {
		validNames = append(validNames, "dns:"+cert.DNSNames[i])
	}

	for i := range cert.EmailAddresses {
		validNames = append(validNames, "email:"+cert.EmailAddresses[i])
	}

	for i := range cert.IPAddresses {
		validNames = append(validNames, "ip:"+cert.IPAddresses[i].String())
	}

	sans := fmt.Sprintf("SANs (%d): %s\n", len(validNames), strings.Join(validNames, ", "))
	wrapPrint(sans, 1)

	l := len(cert.IssuingCertificateURL)
	if l != 0 {
		var aia string
		if l == 1 {
			aia = "AIA"
		} else {
			aia = "AIAs"
		}
		wrapPrint(fmt.Sprintf("%d %s:", l, aia), 1)
		for _, url := range cert.IssuingCertificateURL {
			wrapPrint(url, 2)
		}
	}

	l = len(cert.OCSPServer)
	if l > 0 {
		title := "OCSP server"
		if l > 1 {
			title += "s"
		}
		wrapPrint(title+":\n", 1)
		for _, ocspServer := range cert.OCSPServer {
			wrapPrint(fmt.Sprintf("- %s\n", ocspServer), 2)
		}
	}
}

func displayAllCerts(in []byte, leafOnly bool) {
	certs, err := helpers.ParseCertificatesPEM(in)
	if err != nil {
		certs, _, err = helpers.ParseCertificatesDER(in, "")
		if err != nil {
			Warn(TranslateCFSSLError(err), "failed to parse certificates")
			return
		}
	}

	if len(certs) == 0 {
		Warnx("no certificates found")
		return
	}

	if leafOnly {
		displayCert(certs[0])
		return
	}

	for i := range certs {
		displayCert(certs[i])
	}
}

func displayAllCertsWeb(uri string, leafOnly bool) {
	ci := getConnInfo(uri)
	conn, err := tls.Dial("tcp", ci.Addr, permissiveConfig())
	if err != nil {
		Warn(err, "couldn't connect to %s", ci.Addr)
		return
	}
	defer conn.Close()

	state := conn.ConnectionState()
	conn.Close()

	conn, err = tls.Dial("tcp", ci.Addr, verifyConfig(ci.Host))
	if err == nil {
		err = conn.VerifyHostname(ci.Host)
		if err == nil {
			state = conn.ConnectionState()
		}
		conn.Close()
	} else {
		Warn(err, "TLS verification error with server name %s", ci.Host)
	}

	if len(state.PeerCertificates) == 0 {
		Warnx("no certificates found")
		return
	}

	if leafOnly {
		displayCert(state.PeerCertificates[0])
		return
	}

	if len(state.VerifiedChains) == 0 {
		Warnx("no verified chains found; using peer chain")
		for i := range state.PeerCertificates {
			displayCert(state.PeerCertificates[i])
		}
	} else {
		fmt.Println("TLS chain verified successfully.")
		for i := range state.VerifiedChains {
			fmt.Printf("--- Verified certificate chain %d ---\n", i+1)
			for j := range state.VerifiedChains[i] {
				displayCert(state.VerifiedChains[i][j])
			}
		}
	}
}

func main() {
	var leafOnly bool
	flag.BoolVar(&showHash, "d", false, "show hashes of raw DER contents")
	flag.StringVar(&dateFormat, "s", oneTrueDateFormat, "date `format` in Go time format")
	flag.BoolVar(&leafOnly, "l", false, "only show the leaf certificate")
	flag.Parse()

	if flag.NArg() == 0 || (flag.NArg() == 1 && flag.Arg(0) == "-") {
		certs, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			Warn(err, "couldn't read certificates from standard input")
			os.Exit(1)
		}

		// This is needed for getting certs from JSON/jq.
		certs = bytes.TrimSpace(certs)
		certs = bytes.Replace(certs, []byte(`\n`), []byte{0xa}, -1)
		certs = bytes.Trim(certs, `"`)
		displayAllCerts(certs, leafOnly)
	} else {
		for _, filename := range flag.Args() {
			fmt.Printf("--%s ---\n", filename)
			if strings.HasPrefix(filename, "https://") {
				displayAllCertsWeb(filename, leafOnly)
			} else {
				in, err := ioutil.ReadFile(filename)
				if err != nil {
					Warn(err, "couldn't read certificate")
					continue
				}

				displayAllCerts(in, leafOnly)
			}
		}
	}
}
