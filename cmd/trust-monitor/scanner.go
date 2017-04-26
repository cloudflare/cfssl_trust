package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/helpers"
)

var trustStores = map[string]string{
	"roots":         "ca-bundle.crt",
	"intermediates": "int-bundle.crt",
}

func wrapHTTPError(msg string, status int) error {
	return fmt.Errorf("received HTTP status code %d: %s", status, msg)
}

func fetchStore(store string) ([]byte, error) {
	resp, err := http.Get(trustBaseURL + store)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, wrapHTTPError(string(body), resp.StatusCode)
	}

	return body, nil
}

func scanStore(store string) ([]*x509.Certificate, int64, error) {
	var expiring []*x509.Certificate
	var next int64

	cutoff := time.Now().Add(window)
	certPEM, err := fetchStore(trustStores[store])
	if err != nil {
		return nil, 0, err
	}

	certs, err := helpers.ParseCertificatesPEM(certPEM)
	if err != nil {
		return nil, 0, err
	}

	log.Printf("loaded %d %s", len(certs), store)
	for _, cert := range certs {
		expiresAt := cert.NotAfter.Unix()
		if next == 0 || next > expiresAt {
			next = expiresAt
		}

		if cert.NotAfter.After(cutoff) {
			continue
		}

		expiring = append(expiring, cert)
	}

	return expiring, next, nil
}

func scanTrustStores() {
	log.Println("scanning root store")
	for {
		expiring, next, err := scanStore("roots")
		if err != nil {
			errorf(err)
			time.Sleep(time.Minute)
			continue
		}

		expiringRootsCount.Set(float64(len(expiring)))
		expiringRoots.Set(expiring)
		nextExpiringRoot.Set(float64(next))
		lastRootScan.Set(float64(time.Now().Unix()))
		break
	}

	log.Println("scanning intermediate store")
	for {
		expiring, next, err := scanStore("intermediates")
		if err != nil {
			errorf(err)
			time.Sleep(time.Minute)
			continue
		}

		expiringIntermediatesCount.Set(float64(len(expiring)))
		expiringIntermediates.Set(expiring)
		nextExpiringIntermediate.Set(float64(next))
		lastIntermediateScan.Set(float64(time.Now().Unix()))
		break
	}
}
