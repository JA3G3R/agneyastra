package rtdb

import (
	"log"
	"os"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/JA3G3R/agneyastra/flag/auth"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/spf13/cobra"
)

var allFlag bool
var authFlag bool
var readAuthFlag string
var uploadAuthFlag string
var deleteAuthFlag string

var RtdbCmd = &cobra.Command{
	Use:   "rtdb",	
	Short: "Perform misconfiguration checks on Firebase Realtime Database",
	Long:  "Commands to test Firebase Realtime Database misconfigurations like read or write access.",
	Run: func(cmd *cobra.Command, args []string) {
		if allFlag || len(args) == 0 {
			log.Println("Running all firebase rtdb misconfiguration checks")
			for _, subCmd := range cmd.Commands() {
				if subCmd.Run != nil {
					// log.Printf("Running subcommand: %s", subCmd.Name())
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
		if readAuthFlag != "" {
			runAuthSubcommands(readAuthFlag)
		}
		dump, _ := cmd.Flags().GetBool("dump")
		
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
		if uploadAuthFlag != "" {
			runAuthSubcommands(uploadAuthFlag)
		}
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
		if deleteAuthFlag != "" {
			runAuthSubcommands(deleteAuthFlag)
		}
		for _, apiKey := range config.ApiKeys {
			run.RunRtdbDelete(apiKey)
		}
	},
}

func runAuthSubcommands(authFlag string) {
	authCmdMap := map[string]*cobra.Command{
		"anon-auth":         auth.AnonAuthCmd,
		"sign-up":           auth.SignUpCmd,
		"send-signin-link":  auth.SendSigninLinkCmd,
		"custom-token-login": auth.CustomTokenLoginCmd,
		"sign-in":           auth.SignInCmd,
	}
	args := []string{"no-report"}
	if authFlag == "all" {
		log.Println("Running all auth subcommands...")
		for _, cmd := range authCmdMap {
			// log.Printf("Running subcommand: %s\n", name)
			cmd.SetArgs(args)
			cmd.Run(cmd,args)	}
	} else if cmd, exists := authCmdMap[authFlag]; exists {
		log.Printf("Running specific auth subcommand: %s\n", authFlag)
		cmd.SetArgs(args)
		cmd.Run(cmd,args)} else {
		log.Printf("Invalid auth flag: %s. Valid options: all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in\n", authFlag)
		os.Exit(1)
	}
}


func Init(){

	RtdbCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")
	// RtdbCmd.PersistentFlags().StringVar(&authFlag
	rtdbwriteCmd.Flags().String("file", "", "Path to a file containing the data to write")
	rtdbwriteCmd.Flags().String("json", "", "Raw JSON data to write")
	rtdbwriteCmd.MarkFlagsMutuallyExclusive("json", "file")

	rtdbreadCmd.Flags().Bool("dump", false, "specify the file to dump database contents to")
	// rtdbreadCmd.Flags().Bool("correlate", false, "correlate the data with other services")
	rtdbreadCmd.Flags().StringVar(&readAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	rtdbwriteCmd.Flags().StringVar(&uploadAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	rtdbdeleteCmd.Flags().StringVar(&deleteAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	RtdbCmd.AddCommand(rtdbreadCmd, rtdbwriteCmd, rtdbdeleteCmd)
}
