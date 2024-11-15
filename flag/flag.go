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
var help bool
// RootCmd is the base command for the CLI
var RootCmd = &cobra.Command{
	Use:   "agneyastra",
	Short: "Agneyastra is a Firebase misconfiguration detection tool",
	Long: `Agneyastra detects misconfigurations in Firebase services like Authentication,
Realtime Database, Firestore, and Storage Buckets. It provides detailed insights 
and remediation recommendations for each service.`,
	Run: func(cmd *cobra.Command, args []string) {
		if help {
			log.Println("Help Menu")
			cmd.Help()
			os.Exit(0)
		}
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


func init() {
	RootCmd.PersistentFlags().StringVar(&apiKey, "key", "k", "Firebase API key (required)")
	RootCmd.PersistentFlags().Bool("debug", false, "Enable debug mode for detailed logging")
	RootCmd.PersistentFlags().BoolVarP(&allServices, "all", "a", false, "Check all misconfigurations in all services")
	RootCmd.PersistentFlags().BoolVarP(&help,"help","h", false, "Prints the Help Menu")

}
