package cli

import (
	"database/sql"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/cloudflare/cfssl_trust/common"
	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/cloudflare/cfssl_trust/release"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var releaseCmd = &cobra.Command{
	Use:   "release",
	Short: "Roll a new release.",
	Long: `Roll a new release by copying all certificates from the previous release
into the new release, skipping any certificates that have expired or been
revoked.

If a release is provided (e.g. with -r), 'release' will copy the
certificates from the previous release into the specified release. If
no release is provided, the latest release will be rolled into a new
release.

Examples:

Assuming the following:

	cfssl-trust releases
	- 2017.1.0
	- 2017.1.1
	- 2017.2.0

To copy all the certificates from 2017.1.1 to 2017.2.0 that haven't
been revoked or expired:

	$ cfssl-trust -r 2017.2.0 -b ca release
	Successfully rolled new ca release 2017.2.0

To create a new release and copy the unrevoked and unexpired
certificates from 2017.2.0 into this new release:

	$ cfssl-trust -b ca release
	Successfully rolled new ca release 2017.4.0

Note that this command will print the SKI, serial number, and subject
of any certificates that were skipped, and will print a count of the
certificates included and skipped.
 `, Run: rollRelease}

func init() {
	rootCmd.AddCommand(releaseCmd)
}

func getReleaseForRoll(db *sql.DB, releaseName string) (from, to *certdb.Release, err error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	var rel release.Release

	// An empty release version implies that cfssl-trust should
	// roll a release from the latest version to a new version.
	if releaseName == "" {
		from, err = certdb.LatestRelease(db, bundle)
		if err != nil {
			return nil, nil, err
		}

		rel, err = release.Parse(from.Version)
		if err != nil {
			return nil, nil, err
		}

		rel, err = rel.Inc()
		if err != nil {
			return nil, nil, err
		}

		to, err = certdb.NewRelease(bundle, rel.String())
		if err != nil {
			return nil, nil, err
		}

		_, err = certdb.Ensure(to, tx)
		if err != nil {
			return nil, nil, err
		}

		err = tx.Commit()
		if err != nil {
			return nil, nil, err
		}
	} else {
		// If a release version is provided, then take that as
		// the version to roll the certificates into, and use
		// the previous version as the source. This is, for
		// example, in the case where new certificates have
		// been imported into a new release, and you want to
		// bring all the old certificates over too.
		to, err = certdb.FetchRelease(db, bundle, bundleRelease)
		if err != nil {
			return nil, nil, err
		}

		from, err = to.Previous(db)
		if err != nil {
			return nil, nil, err
		}
	}

	return from, to, err
}

func showSkippedCert(cert *certdb.Certificate, reason string) {
	serial := big.NewInt(0)
	serial.SetBytes(cert.Serial)
	fmt.Printf("skipping %s (SKI=%s, serial=%s, subject='%s')\n", reason, cert.SKI, serial, common.NameToString(cert.X509().Subject))
}

func copyCertificates(db *sql.DB, from, to *certdb.Release, window time.Duration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	certs, err := certdb.CollectRelease(from.Bundle, from.Version, tx)
	if err != nil {
		return err
	}

	var skipped, included int
	releaseWindow := to.ReleasedAt + int64(window.Seconds())
	for _, cert := range certs {
		if isRevoked, err := cert.Revoked(tx, releaseWindow); err != nil {
			return err
		} else if isRevoked {
			showSkippedCert(cert, "revoked certificate")
			skipped++
			continue
		}

		if cert.NotAfter <= releaseWindow {
			showSkippedCert(cert, "expired certificate")
			skipped++
			continue
		}

		if cert.NotBefore > to.ReleasedAt {
			showSkippedCert(cert, "certificate that isn't valid at the time of release")
			skipped++
			continue
		}

		cr := certdb.NewCertificateRelease(cert, to)
		_, err = certdb.Ensure(cr, tx)
		if err != nil {
			return err
		}
		included++
	}

	err = tx.Commit()
	if err != nil {
		return err
	}

	fmt.Printf("%d certificates rolled\n%d certificates skipped\n", included, skipped)
	return nil
}

func rollRelease(cmd *cobra.Command, args []string) {
	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	var window time.Duration
	if len(args) > 0 {
		window, err = time.ParseDuration(args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}

	from, to, err := getReleaseForRoll(db, bundleRelease)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	err = copyCertificates(db, from, to, window)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully rolled new", bundle, "release", to.Version)
}
