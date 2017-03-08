package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl_trust/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	_ "github.com/mattes/migrate/driver/sqlite3"
	"github.com/mattes/migrate/migrate"
)

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up the trust database.",
	Long:  "`Set up the trust database.",
	Run:   setup,
}

func setup(cmd *cobra.Command, args []string) {
	var sourceDir string

	// First argument: the path to the migration files.
	if len(args) == 0 {
		sourceDir = filepath.Join(config.GoPath(), "src", "github.com", "cloudflare", "cfssl_trust", "model")
	} else {
		sourceDir = args[0]
	}

	var err error
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath, err = os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] %s\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("Migration directory:", sourceDir)
	fmt.Println("Database path:", dbPath)
	errs, ok := migrate.UpSync("sqlite3://"+dbPath, sourceDir)
	if !ok {
		fmt.Fprintf(os.Stderr, "[!] Failed to set up database:\n")
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "\t%s\n", err)
		}
		os.Exit(1)
	}
}

func init() {
	RootCmd.AddCommand(setupCmd)
}
