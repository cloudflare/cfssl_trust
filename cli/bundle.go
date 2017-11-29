package cli

import (
	"bytes"
	"database/sql"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "Emit a certificate bundle.",
	Long: `Emit either a root or intermediate bundle for a given release. If given a
filename, the bundle will be written to that file.`,
	Run: buildBundle,
}

func init() {
	rootCmd.AddCommand(bundleCmd)
}

func encodeBundle(certs []*certdb.Certificate) string {
	var buf = &bytes.Buffer{}
	for _, cert := range certs {
		p := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		err := pem.Encode(buf, p)
		if err != nil {
			// A bytes.Buffer write should never fail.
			panic("cfssl-trust: write to *bytes.Buffer should never fail")
		}
	}

	return buf.String()
}

func buildBundle(cmd *cobra.Command, args []string) {
	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	tx, err := db.Begin()
	if err != nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}
	defer func() {
		if err == nil {
			err = tx.Commit()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] failed to commit transaction: %s\n", err)
				os.Exit(1)
			}
		} else {
			tx.Rollback()
		}
	}()

	certs, err := certdb.CollectRelease(bundle, bundleRelease, tx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	fmt.Printf("Selected %d certificates for this release.\n", len(certs))

	pemBundle := encodeBundle(certs)
	switch len(args) {
	case 0:
		fmt.Println(pemBundle)
	case 1:
		err = ioutil.WriteFile(args[0], []byte(pemBundle), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, `[!] %d arguments were passed to 'bundle, but the command only accepts a
    single, optional file name. Refusing to proceed.`, len(args))
		os.Exit(1)
	}

}
