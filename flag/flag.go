package flags

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

)

var debug bool
var allServices bool
var apiKey string
var configPath string

// RootCmd is the base command for the CLI
var RootCmd = &cobra.Command{
	Use:   "agneyastra",
	Short: "Agneyastra is a Firebase misconfiguration detection tool",
	Long: `Agneyastra detects misconfigurations in Firebase services like Authentication,
Realtime Database, Firestore, and Storage Buckets. It provides detailed insights 
and remediation recommendations for each service.`,
	Run: func(cmd *cobra.Command, args []string) {
		if apiKey == "" {
			fmt.Println("Error: API key is required. Use the -key flag to provide your API key.")
			os.Exit(1)
		}
		if debug {
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

func GetAPIKey() string {
	return apiKey
}

var HelpCmd = &cobra.Command{
	Use:   "help",
	Short: "Help menu",
	Long: `Help menu for Agneyastra. Use this command to get detailed information about the tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Custom help command")
		RootCmd.Help()
		os.Exit(0)
	},
}

func ApplyExitOnHelp(c *cobra.Command, exitCode int) {
	helpFunc := c.HelpFunc()
	c.SetHelpFunc(func(c *cobra.Command, s []string) {
		helpFunc(c, s)
		os.Exit(exitCode)
	})
}

func initConfig() {

    if configPath != "" {
        viper.SetConfigFile(configPath) // Use custom config path
    } else {
        viper.SetConfigName("config")  // Default config name
        viper.SetConfigType("yaml")
        viper.AddConfigPath(".")
        viper.AddConfigPath("$HOME/.agneyastra")
    }

    viper.SetEnvPrefix("AGNEYASTRA")
    viper.AutomaticEnv()

    if err := viper.ReadInConfig(); err != nil {
        fmt.Printf("Warning: Config file not found: %s\n", err)
    } else {
        fmt.Printf("Using config file: %s\n", viper.ConfigFileUsed())
    }
}


func init() {
	
	ApplyExitOnHelp(RootCmd, 0)
	RootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "Firebase API key (required)")
	RootCmd.MarkFlagRequired("key")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Custom config file path")

	// Bind Viper to flags
    viper.BindPFlag("api_key", RootCmd.PersistentFlags().Lookup("key"))
    viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))


	cobra.OnInitialize(initConfig)
}
