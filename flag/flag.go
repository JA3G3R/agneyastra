package flags

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
)

var debug bool
var allServices bool
var apiKey string

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

func init() {
	
	ApplyExitOnHelp(RootCmd, 0)
	RootCmd.PersistentFlags().StringVar(&apiKey, "key", "", "Firebase API key (required)")
	RootCmd.MarkFlagRequired("key")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")


}
