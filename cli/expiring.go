package cli

import (
	"database/sql"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/cloudflare/cfssl_trust/common"
	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var expiringCmd = &cobra.Command{
	Use:   "expiring",
	Short: "Show expiring (and revoked) certificates.",
	Long: `Show certificates that will not be included in the next release, whether
due to certificate expiry or revocation.`,
	Run: expiring,
}

func init() {
	RootCmd.AddCommand(expiringCmd)
}

func showExpiredCert(cert *certdb.Certificate, reason string) {
	serial := big.NewInt(0)
	serial.SetBytes(cert.Serial)
	fmt.Printf("%s (SKI=%s, serial=%s, subject='%s')\n", reason, cert.SKI, serial, common.NameToString(cert.X509().Subject))
}

func scanBundleForExpirations(db *sql.DB, window time.Duration) (expired int, revoked int, err error) {
	tx, err := db.Begin()
	if err != nil {
		return expired, revoked, err
	}
	defer tx.Rollback()

	rel := &certdb.Release{
		Bundle:  bundle,
		Version: bundleRelease,
	}

	err = rel.Select(tx)
	if err != nil {
		return expired, revoked, err
	}

	certs, err := certdb.CollectRelease(rel.Bundle, rel.Version, tx)
	if err != nil {
		return expired, revoked, err
	}

	expiresAt := time.Now().Add(window)
	for _, cert := range certs {
		if isRevoked, err := cert.Revoked(tx, rel.ReleasedAt); err != nil {
			return expired, revoked, err
		} else if isRevoked {
			showExpiredCert(cert, "revoked certificate")
			revoked++
			continue
		}

		if cert.NotAfter <= expiresAt.Unix() {
			showExpiredCert(cert, "expired certificate")
			expired++
			continue
		}

		if cert.NotBefore > rel.ReleasedAt {
			showExpiredCert(cert, "certificate that isn't valid at the time of release")
			expired++
			continue
		}
	}

	err = tx.Commit()
	if err != nil {
		return expired, revoked, err
	}

	return expired, revoked, err
}

func expiring(cmd *cobra.Command, args []string) {
	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	if bundleRelease == "" {
		latest, err := certdb.LatestRelease(db, bundle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
		bundleRelease = latest.Version
	}

	window := 30 * 24 * time.Hour
	if len(args) > 0 {
		window, err = time.ParseDuration(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}

	expired, revoked, err := scanBundleForExpirations(db, window)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Release:", bundle, bundleRelease)
	fmt.Printf("%d certificates expiring.\n%d certificates revoked.\n",
		expired, revoked)
}
