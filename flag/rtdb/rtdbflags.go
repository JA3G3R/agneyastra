package rtdb

import (
	"log"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/spf13/cobra"
)

var allFlag bool

var RtdbCmd = &cobra.Command{
	Use:   "rtdb",	
	Short: "Perform misconfiguration checks on Firebase Realtime Database",
	Long:  "Commands to test Firebase Realtime Database misconfigurations like read or write access.",
	Run: func(cmd *cobra.Command, args []string) {
		if allFlag || len(args) == 0 {
			log.Println("Running all firebase storage bucket misconfiguration checks")
			for _, subCmd := range cmd.Commands() {
				if subCmd.Run != nil {
					log.Printf("Running subcommand: %s", subCmd.Name())
					subCmd.Run(subCmd, nil)
				}
			}
		}
	},
}

// Read Command
var rtdbreadCmd = &cobra.Command{

	Use:   "read",
	Short: "Read data from Firebase RTDB",
	Long:  "Checks if the Firebase Realtime Database allows unrestricted reading of its data.",
	Run: func(cmd *cobra.Command, args []string) {
		dump, _ := cmd.Flags().GetString("dump")
		for _, apiKey := range config.ApiKeys {
			run.RunRtdbRead(dump, apiKey)
		}

	},
}


// Write Command
var rtdbwriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Write data to Firebase RTDB",
	Long:  "Checks if the Firebase Realtime Database allows unrestricted writing of data.",
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		jsonData, _ := cmd.Flags().GetString("json")
		for _, apiKey := range config.ApiKeys {
			run.RunRtdbWrite(jsonData, file, apiKey)
		}
	},
}

var rtdbdeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete data from Firebase RTDB",
	Long:  "Checks if the Firebase Realtime Database allows deletion of data.",
	Run: func(cmd *cobra.Command, args []string) {
		for _, apiKey := range config.ApiKeys {
			run.RunRtdbDelete(apiKey)
		}
	},
}

func Init(){

	RtdbCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")

	rtdbwriteCmd.Flags().String("file", "", "Path to a file containing the data to write")
	rtdbwriteCmd.Flags().String("json", "", "Raw JSON data to write")
	rtdbwriteCmd.MarkFlagsMutuallyExclusive("json", "file")

	rtdbreadCmd.Flags().Bool("dump", false, "specify the file to dump database contents to")

	RtdbCmd.AddCommand(rtdbreadCmd, rtdbwriteCmd, rtdbdeleteCmd)
}
