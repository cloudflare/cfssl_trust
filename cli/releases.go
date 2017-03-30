package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl_trust/model/certdb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var releasesCmd = &cobra.Command{
	Use:   "releases",
	Short: "List all releases for a bundle.",
	Long:  "List all releases for a bundle.",
	Run:   listReleases,
}

func init() {
	RootCmd.AddCommand(releasesCmd)
}

func listReleases(cmd *cobra.Command, args []string) {
	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	releases, err := certdb.AllReleases(db, bundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	for _, rel := range releases {
		fmt.Println("-", rel.Version)
	}
}
