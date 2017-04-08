package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/bjt79/cfssl/helpers"
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

func scanStore(store string) ([]*x509.Certificate, error) {
	var expiring []*x509.Certificate

	cutoff := time.Now().Add(window)
	certPEM, err := fetchStore(trustStores[store])
	if err != nil {
		return nil, err
	}

	certs, err := helpers.ParseCertificatesPEM(certPEM)
	if err != nil {
		return nil, err
	}

	log.Printf("loaded %d %s", len(certs), store)
	for _, cert := range certs {
		if cert.NotAfter.After(cutoff) {
			continue
		}

		expiring = append(expiring, cert)
	}

	return expiring, nil
}

func scanTrustStores() {
	log.Println("scanning root store")
	for {
		expiring, err := scanStore("roots")
		if err != nil {
			errorf(err)
			time.Sleep(time.Minute)
			continue
		}

		expiringRootsCount.Set(float64(len(expiring)))
		expiringRoots.Set(expiring)
		break
	}

	log.Println("scanning intermediate store")
	for {
		expiring, err := scanStore("intermediates")
		if err != nil {
			errorf(err)
			time.Sleep(time.Minute)
			continue
		}

		expiringIntermediatesCount.Set(float64(len(expiring)))
		expiringIntermediates.Set(expiring)
		break
	}
}
