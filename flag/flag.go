package flags

import (
	"fmt"
	"log"
	"os"

	"github.com/JA3G3R/agneyastra/flag/auth/authcmd"
	"github.com/JA3G3R/agneyastra/flag/database/databasecmd"
	"github.com/JA3G3R/agneyastra/flag/firestore/firestorecmd"
	"github.com/JA3G3R/agneyastra/flag/storage/storagecmd"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var Debug bool
var allServices bool
var ApiKey string
var ConfigPath string

// RootCmd is the base command for the CLI
var RootCmd = &cobra.Command{
	Use:   "agneyastra",
	Short: "Agneyastra is a Firebase misconfiguration detection tool",
	Long: `Agneyastra detects misconfigurations in Firebase services like Authentication,
Realtime Database, Firestore, and Storage Buckets. It provides detailed insights 
and remediation recommendations for each service.`,
	Run: func(cmd *cobra.Command, args []string) {
		if ApiKey == "" {
			fmt.Println("Error: API key is required. Use the -key flag to provide your API key.")
			os.Exit(1)
		}
		if Debug {
			log.Println("Debug mode enabled")
		}
		if allServices {
			log.Println("Checking all services for misconfigurations")
			for _, subCmd := range cmd.Commands() {
				if subCmd.Run != nil {
					log.Printf("Running subcommand: %s", subCmd.Name())
					subCmd.Run(subCmd, nil)
				}
			}
			// Call all services' "all" commands
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func GetApiKey() string {
	return ApiKey
}


func ApplyExitOnHelp(c *cobra.Command, exitCode int) {
	helpFunc := c.HelpFunc()
	c.SetHelpFunc(func(c *cobra.Command, s []string) {
		helpFunc(c, s)
		os.Exit(exitCode)
	})
}

func InitConfig() {

    if ConfigPath != "" {
        viper.SetConfigFile(ConfigPath) // Use custom config path
    } else {
        viper.SetConfigName("config")  // Default config name
        viper.SetConfigType("yaml")
        viper.AddConfigPath(".")
        viper.AddConfigPath("$HOME/.agneyastra")
    }

    viper.SetEnvPrefix("AGNEYASTRA")
    viper.AutomaticEnv()

    if err := viper.ReadInConfig(); err != nil {
        log.Printf("Warning: Config file not found: %s\n", err)
    } else {
        log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
    }
}


func init() {
	
	ApplyExitOnHelp(RootCmd, 0)
	RootCmd.PersistentFlags().StringVar(&ApiKey, "key", "", "Firebase API key (required)")
	RootCmd.MarkFlagRequired("key")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable Debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Custom config file path")


	log.Println("Initializing config...")
	InitConfig()

	// Add subcommands
	RootCmd.AddCommand(authcmd.AuthCmd)
	RootCmd.AddCommand(firestorecmd.FirestoreCmd)
	RootCmd.AddCommand(storagecmd.StorageCmd)
	RootCmd.AddCommand(databasecmd.DatabaseCmd)
	

	// Bind Viper to flags
    viper.BindPFlag("api_key", RootCmd.PersistentFlags().Lookup("key"))
    viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("Debug"))

}
