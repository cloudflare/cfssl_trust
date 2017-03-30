package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl_trust/info"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var searchCmd = &cobra.Command{
	Use:   "search",
	Short: "Search for certificates.",
	Long: `
Search for certificates that match a set of search terms. Search terms
have the form type:regexp, e.g. ski:01234567. The supported types are:

	- ski
	- aki
	- subject
	- issuer
	- release
	- bundle

Multiple search terms are supported; for example "ski:1234567 issuer:Example".

The subject and example use the string form of the issuer as produced
by the info command; for example, a certificate with 'Example' in the
subject's organisation field can be search for using

	subject:O=Example

The support regular expression syntax is the RE2 syntax used by the Go
programming language described at https://golang.org/s/re2syntax.
`,
	Run: search,
}

func init() {
	RootCmd.AddCommand(searchCmd)
}

func search(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		os.Exit(0)
	}

	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	results, err := info.Query(db, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	for _, cert := range results {
		err = info.WriteCertificateMetadata(os.Stdout, cert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}
}
