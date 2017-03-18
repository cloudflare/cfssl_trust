package cli

import (
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl_trust/model/certdb"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import certificates into the database.",
	Long:  "Import certificates into the database, marking them under a release as needed.",
	Run:   importer,
}

func init() {
	RootCmd.AddCommand(importCmd)
}

func importCertificate(db *sql.DB, cert *x509.Certificate, rel *certdb.Release) error {
	fmt.Printf("- importing serial %s AKI %x\n", cert.SerialNumber, cert.AuthorityKeyId)
	c := certdb.NewCertificate(cert)
	err := certdb.Ensure(c, db)
	if err != nil {
		return err
	}

	aia := certdb.NewAIA(c)
	if aia != nil {
		err = certdb.Ensure(aia, db)
		if err != nil {
			return err
		}
	}

	// The rest of the function deals with inserting the
	// certificate into the relevant release table. The assumption
	// here is that the release exists in the DB.
	if rel == nil {
		return nil
	}

	cr := certdb.NewCertificateRelease(c, rel)
	return certdb.Ensure(cr, db)

}

func importer(cmd *cobra.Command, args []string) {
	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	var rel *certdb.Release
	if bundleRelease != "" {
		rel, err = certdb.NewRelease(bundle, bundleRelease)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}

		err = certdb.Ensure(rel, db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}

	for _, path := range args {
		fileContents, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}

		certs, err := helpers.ParseCertificatesPEM(fileContents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}

		for _, x509Cert := range certs {
			err := importCertificate(db, x509Cert, rel)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] %s\n", err)
				os.Exit(1)
			}
		}
	}

	db.Close()
}
