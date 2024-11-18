package flags

import (
	"fmt"
	"log"
	"os"

	"github.com/JA3G3R/agneyastra/flag/auth"
	"github.com/JA3G3R/agneyastra/flag/bucket"
	"github.com/JA3G3R/agneyastra/flag/firestore"
	"github.com/JA3G3R/agneyastra/flag/rtdb"
	"github.com/JA3G3R/agneyastra/pkg/config"
	rtdbService "github.com/JA3G3R/agneyastra/services/rtdb"
	"github.com/JA3G3R/agneyastra/utils"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allServices bool
var ConfigPath string

// RootCmd is the base command for the CLI
var RootCmd = &cobra.Command{
	Use:   "agneyastra",
	Short: "Agneyastra is a Firebase misconfiguration detection tool",
	Long: `Agneyastra detects misconfigurations in Firebase services like Authentication,
Realtime Database, Firestore, and Storage Buckets. It provides detailed insights 
and remediation recommendations for each service.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Check if the API key is provided
		if config.ApiKey == "" {
			return fmt.Errorf("Error: API key is required. Use the -key flag to provide your API key.")
		}
		// Fetch project config
		var err error
		fmt.Printf("Fetching project config using API key: %s\n", config.ApiKey)
		projectConfig, err := utils.GetProjectConfig(config.ApiKey)
		if err != nil {
			return fmt.Errorf("Error fetching project config: %v", err)
		}
		config.ProjectConfig = *projectConfig
		config.ProjectIds = utils.ExtractDomainsForStorage(*projectConfig)
		config.RTDBUrls = rtdbService.CreateRTDBURLs(config.ProjectIds)
		log.Printf("RTDB URLs: %v\n", config.RTDBUrls)
		log.Println("Initializing config...")
		InitConfig()
		// Enable debug mode if required
		if config.Debug {
			log.Println("Debug mode enabled")
		}


		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Logic for RootCmd execution
		if allServices {
			log.Println("Checking all services for misconfigurations")
			for _, subCmd := range cmd.Commands() {
				if subCmd.Name() != "help" && subCmd.Name() != "completion" {
					if subCmd.Run != nil {
						log.Printf("Running subcommand: %s", subCmd.Name())
						subCmd.Run(subCmd, nil)
					}
				}
			}
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
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
	RootCmd.PersistentFlags().StringVar(&config.ApiKey, "key", "", "Firebase API key (required)")
	RootCmd.MarkFlagRequired("key")
	RootCmd.PersistentFlags().BoolVarP(&config.Debug,"debug","d", false, "Enable Debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Custom config file path")
	// Add subcommands
	RootCmd.AddCommand(auth.AuthCmd)
	RootCmd.AddCommand(firestore.FirestoreCmd)
	RootCmd.AddCommand(bucket.BucketCmd)
	RootCmd.AddCommand(rtdb.RtdbCmd)

	// Bind Viper to flags
    viper.BindPFlag("api_key", RootCmd.PersistentFlags().Lookup("key"))
    viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("Debug"))

	auth.Init()
	bucket.Init()
	firestore.Init()
	rtdb.Init()

}
