package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl_trust/common"
	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/cloudflare/cfssl_trust/release"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var releaseInfoCmd = &cobra.Command{
	Use:   "release-info",
	Short: "Display a list of the certificates in a release.",
	Long:  "Display a list of the certificates in a release.",
	Run:   releaseInfo,
}

func init() {
	rootCmd.AddCommand(releaseInfoCmd)
}

func releaseInfo(cmd *cobra.Command, args []string) {
	switch len(args) {
	case 0: // Don't do anything.
	case 1:
		_, err := release.Parse(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid release '%s'.\n", bundleRelease)
			fmt.Fprintf(os.Stderr, "\tReason: %s\n", err)
			os.Exit(1)
		}
		bundleRelease = args[0]
	default:
		fmt.Fprintln(os.Stderr, "[!] Too many arguments passed to 'release'.")
	}

	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	var rel *certdb.Release
	if bundleRelease == "" {
		rel, err = certdb.LatestRelease(db, bundle)
	} else {
		rel, err = certdb.FetchRelease(db, bundle, bundleRelease)
	}

	if err == sql.ErrNoRows {
		fmt.Fprintf(os.Stderr, "[!] release %s-%s doesn't exist.\n",
			rel.Bundle, rel.Version)
		os.Exit(1)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}
	defer tx.Rollback()

	certs, err := certdb.CollectRelease(rel.Bundle, rel.Version, tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("%d certificates in release %s-%s:\n", len(certs),
		rel.Bundle, rel.Version)
	for _, cert := range certs {
		xc := cert.X509()
		fmt.Printf("SKI: %s\tSerial: %s\tSubject: %s\n",
			cert.SKI, xc.SerialNumber, common.NameToString(xc.Subject))
	}
	tx.Commit()
}
