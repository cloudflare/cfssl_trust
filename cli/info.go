package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl_trust/info"
	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var infoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display information about a certificate.",
	Long:  "Display information about a certificate give its SKI.",
	Run:   showInfo,
}

func init() {
	RootCmd.AddCommand(infoCmd)
}

func showInfoForCertificates(db *sql.DB, certs []*certdb.Certificate) error {
	for _, cert := range certs {
		err := info.WriteCertificateInformation(os.Stdout, db, cert)
		if err != nil {
			return err
		}
	}

	return nil
}

func showInfo(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		os.Exit(0)
	}

	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	for _, ski := range args {
		certs, err := certdb.FindCertificateBySKI(db, ski)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}

		err = showInfoForCertificates(db, certs)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}
}
