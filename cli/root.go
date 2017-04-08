package cli

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl_trust/config"
	"github.com/cloudflare/cfssl_trust/release"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile       string
	dbFile        string
	bundle        string
	bundleRelease string
)

func root(cmd *cobra.Command, args []string) {
	err := cmd.Help()
	if err != nil {
		os.Exit(1)
	}
}

var configLocations = []string{
	"/etc/cfssl",
	"/usr/local/cfssl",
	filepath.Join(config.GoPath(), "src", "github.com", "cloudflare", "cfssl_trust"),
}

var RootCmd = &cobra.Command{
	Use:   "cfssl-trust",
	Short: "Manage a trust database for root and intermediate bundles.",
	Long:  ``,
	Run:   root,
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

// If err isn't nil, this should rollback the transaction. If err is
// nil, it should commit the transaction. Finally, it should close the
// database.
func cleanup(tx *sql.Tx, db *sql.DB, err error) {
	if tx != nil {
		if err != nil {
			err = tx.Rollback()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] error while rolling back transaction: %s\n", err)
				os.Exit(1)
			}
		} else {
			err = tx.Commit()
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] error while committing transaction: %s\n", err)
				os.Exit(1)
			}
		}
	}

	if db != nil {
		err = db.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] error while closing database: %s\n", err)
			os.Exit(1)
		}
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVarP(&bundle, "bundle", "b", "int", "select a bundle (ca or int)")
	RootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "f", "", "config file (default is /etc/cfssl/cfssl-trust.yaml)")
	RootCmd.PersistentFlags().StringVarP(&dbFile, "db", "d", "", "path to trust database")
	RootCmd.PersistentFlags().StringVarP(&bundleRelease, "release", "r", "", "select a release")

	viper.BindPFlag("database.path", RootCmd.PersistentFlags().Lookup("db"))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("cfssl-trust") // name of config file (without extension)
		for _, dir := range configLocations {
			viper.AddConfigPath(dir)
		}
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("CFSSL_TRUST")
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	err := viper.ReadInConfig()
	if err == nil {
		log.Info("cfssl-trust: loading from config file ", viper.ConfigFileUsed())
	}

	if bundleRelease != "" {
		rel, err := release.Parse(bundleRelease)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Invalid release '%s'.\n", bundleRelease)
			fmt.Fprintf(os.Stderr, "\tReason: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("selected release", rel)
	}
}
