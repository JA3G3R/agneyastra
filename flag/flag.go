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

var apiKey string
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
		if apiKey == "" && config.ApiKeyFile == "" {
			return fmt.Errorf("Error: API key is required. Use the -key flag to provide your API key or the -kf to provide a file containing list of apiKeys.")
		}

		if apiKey != "" && config.ApiKeyFile != "" {
			return fmt.Errorf("Error: Both API key and API key file cannot be provided. Use either -key or -kf flag.")
		}
		if apiKey != "" {
			config.ApiKeys = append(config.ApiKeys, apiKey)
		} else {
			// Read API keys from file
			keys, err := utils.ReadApiKeysFromFile(config.ApiKeyFile)
			if err != nil {
				return fmt.Errorf("Error reading API keys from file: %v", err)
			}
			config.ApiKeys = append(config.ApiKeys, keys...)
		}

		// Fetch project config

		// fmt.Printf("Fetching project config using API key: %s\n", apiKey)
		for _, key := range config.ApiKeys {
			projectConfig, err := utils.GetProjectConfig(key)
			if err != nil {
				log.Printf("Error fetching project config for key %s: %v", key, err)
				continue
			}
			config.ProjectConfig[key] = *projectConfig
			config.ProjectIds[key] = utils.ExtractDomainsForStorage(*projectConfig)
			config.RTDBUrls[key] = rtdbService.CreateRTDBURLs(config.ProjectIds[key])
			// log.Printf("RTDB URLs: %v\n", config.RTDBUrls)
		}

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
						// log.Printf("Running subcommand: %s", subCmd.Name())
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
     }// else {
    //     log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
    // }
}


func init() {

	// log.Println("Initializing config...")
	InitConfig()

	ApplyExitOnHelp(RootCmd, 0)
	RootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "Firebase API key (required)")
	RootCmd.PersistentFlags().StringVar(&config.ReportPath, "report-path", "./report.html", "Path to store the HTML report (default: ./report.html)")
	RootCmd.PersistentFlags().StringVar(&config.TemplateFile, "template-file", "./template.html", "Template file to use for report (default: ./template.html)")
	RootCmd.PersistentFlags().StringVar(&config.PentestDataFilePath, "pentest-data", "", "Path to the pentest data file")
	RootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Custom config file path")
	RootCmd.PersistentFlags().StringVar(&config.ApiKeyFile, "key-file", "", "Path to a file containing Firebase API keys")
	RootCmd.PersistentFlags().StringVar(&config.SecretsRegexFile, "secrets-regex-file", "", "Path to a file containing secrets regexes")

	RootCmd.PersistentFlags().BoolVar(&config.Correlate, "correlate", false, "Correlate the results with the API key used")
	RootCmd.PersistentFlags().BoolVarP(&config.Debug,"debug","d", false, "Enable Debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().BoolVar(&config.SecretsExtract, "secrets-extract", false, "Extract secrets from extracted data")

	// Add subcommands
	RootCmd.AddCommand(auth.AuthCmd)
	RootCmd.AddCommand(firestore.FirestoreCmd)
	RootCmd.AddCommand(bucket.BucketCmd)
	RootCmd.AddCommand(rtdb.RtdbCmd)
	RootCmd.CompletionOptions.DisableDefaultCmd = true

	// Bind Viper to flags
    viper.BindPFlag("api_key", RootCmd.PersistentFlags().Lookup("key"))
    viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("Debug"))

	auth.Init()
	bucket.Init()
	firestore.Init()
	rtdb.Init()

}
