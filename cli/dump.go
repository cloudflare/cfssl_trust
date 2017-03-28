package cli

import (
	"database/sql"
	"fmt"
	"os"

	"github.com/cloudflare/cfssl_trust/dump"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var dumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Dump a certificate to standard output or file.",
	Long:  "Dump a certificate to standard output or file given its SKI.",
	Run:   dumper,
}

func init() {
	RootCmd.AddCommand(dumpCmd)
}

func dumper(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		os.Exit(0)
	}

	dbPath := viper.GetString("database.path")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
	}

	tx, err := db.Begin()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] %s\n", err)
		os.Exit(1)
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

	for _, ski := range args {
		cert, err := dump.CertPEM(tx, ski)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}

		fmt.Println(string(cert))
	}
}
