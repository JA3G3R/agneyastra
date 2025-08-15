package flags

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

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
var projectId string

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
			return fmt.Errorf("Error: API key is required. Use the --key flag to provide your API key or the --key-file to provide a file containing list of apiKeys.")
		}

		var projectIdsFromFile = make(map[string][]string)

		if apiKey != "" {
			config.ApiKeys = append(config.ApiKeys, apiKey)
			if projectId != "" {
				idsfromcli := strings.Split(projectId, ",")
				var res []string
				for _, str := range idsfromcli {
					if str != "" {
						res = append(res, str)
					}
				}
				projectIdsFromFile[apiKey] = res
			}
		} else {
			// Read API keys from file
			keys, pIdsFromFile, err := utils.ReadApiKeysFromFile(config.ApiKeyFile)
			projectIdsFromFile = pIdsFromFile
			if err != nil {
				return fmt.Errorf("Error reading API keys from file: %v", err)
			}
			config.ApiKeys = append(config.ApiKeys, keys...)
		}

		if !config.Debug {
			log.SetOutput(ioutil.Discard)
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
			if len(projectIdsFromFile[key]) == 0 {
				config.ProjectIds[key] = utils.ExtractDomainsFromProjectConfig(*projectConfig)
			} else {
				config.ProjectIds[key] = projectIdsFromFile[key]
			}
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
		viper.SetConfigName("config") // Default config name
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.agneyastra")
	}

	if config.TemplateFile != "" {
		viper.Set("template_file", config.TemplateFile)
	} else {
		viper.Set("templatefile", "~/.agneyastra/template.html")
	}
	viper.SetEnvPrefix("AGNEYASTRA")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		log.Printf("Warning: Config file not found: %s\n", err)
	} // else {
	//     log.Printf("Using config file: %s\n", viper.ConfigFileUsed())
	// }
}

func init() {

	// log.Println("Initializing config...")
	InitConfig()

	ApplyExitOnHelp(RootCmd, 0)
	RootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "Firebase API key (required)")
	RootCmd.PersistentFlags().StringVar(&projectId, "project-id", "", "Firebase project ID")
	RootCmd.PersistentFlags().StringVar(&config.ReportPath, "report-path", "./report.html", "Path to store the HTML report (default: ./report.html)")
	RootCmd.PersistentFlags().StringVar(&config.TemplateFile, "template-file", "~/.agneyastra/template.html", "Template file to use for report (default: ./template.html)")
	RootCmd.PersistentFlags().StringVar(&config.PentestDataFilePath, "pentest-data", "", "Path to the pentest data file")
	RootCmd.PersistentFlags().StringVar(&ConfigPath, "config", "", "Custom config file path")
	RootCmd.PersistentFlags().StringVar(&config.ApiKeyFile, "key-file", "", "Path to a file containing Firebase API keys")
	RootCmd.PersistentFlags().StringVar(&config.SecretsRegexFile, "secrets-regex-file", "", "Path to a file containing secrets regexes")

	RootCmd.PersistentFlags().BoolVar(&config.Correlate, "correlate", false, "Correlate the results with the API key used")
	RootCmd.PersistentFlags().BoolVarP(&config.Debug, "debug", "d", false, "Enable Debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().BoolVar(&config.SecretsExtract, "secrets-extract", false, "Extract secrets from extracted data")
	RootCmd.PersistentFlags().BoolVar(&config.AssetExtract, "assets-extract", false, "Extract assets(domains,ips,emails etc.) from extracted data")

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
