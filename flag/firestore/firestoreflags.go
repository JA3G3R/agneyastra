package firestore

import (
	"log"
	"os"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/JA3G3R/agneyastra/flag/auth"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/spf13/cobra"
)

var allFlag bool
var authFlag string
var rootAuthFlag string
var readAuthFlag string
var uploadAuthFlag string
var deleteAuthFlag string

var FirestoreCmd = &cobra.Command{
	Use:   "firestore",
	Short: "Perform misconfiguration checks on Firestore",
	Long:  "Commands to test Firestore misconfigurations like read or write access.",
	Run: func(cmd *cobra.Command, args []string) {
	if allFlag || len(args) == 0 {
		if authFlag != "" {
			runAuthSubcommands(authFlag)
		}
		log.Println("Running all firebase firestore misconfiguration checks")
		for _, subCmd := range cmd.Commands() {
			if subCmd.Run != nil {
				log.Printf("Running subcommand: %s", subCmd.Name())
				subCmd.Run(subCmd, nil)
			}
		}
	}
},
}

// Read Document Command
var firestorereadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read a Firestore document",
	Long:  "Checks if a Firestore document can be read using the provided document ID.",
	Run: func(cmd *cobra.Command, args []string) {
		if readAuthFlag != "" {
			runAuthSubcommands(readAuthFlag)
		}
		// docID, _ := cmd.Flags().GetString("document-id")
		// if docID == "" {
		// 	log.Println("Error: --document-id is required.")
		// 	return
		// }
		// log.Printf("Attempting to read document with ID: %s\n", docID)
		// Add your function call here, e.g., ReadDocument(docID)
		for _, apiKey := range config.ApiKeys {
			run.RunFirestoreRead(apiKey)
		}
	},
}

// Write Document Command
var firestorewriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Write a Firestore document",
	Long:  "Checks if a Firestore document can be written using the provided data.",
	Run: func(cmd *cobra.Command, args []string) {
		if uploadAuthFlag != "" {
			runAuthSubcommands(uploadAuthFlag)
		}
		// file, _ := cmd.Flags().GetString("file")
		// jsonData, _ := cmd.Flags().GetString("json")
		// if file == "" && jsonData == "" {
		// 	log.Println("Error: Either --file or --json must be provided.")
		// 	return
		// }
		// if file != "" {
		// 	log.Printf("Loading document from file: %s\n", file)
		// 	// Add your function call here, e.g., WriteDocumentFromFile(file)
		// 	} else {
			// 		log.Printf("Writing document with data: %s\n", jsonData)
			// 		// Add your function call here, e.g., WriteDocumentFromJSON(jsonData)
		// 	}
		for _, apiKey := range config.ApiKeys {
			run.RunFirestoreWrite(apiKey)
		}
	},
}

var firestoredeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a Firestore document",
	Long:  "Checks if a Firestore document can be deleted using the provided data.",
	Run: func(cmd *cobra.Command, args []string) {
		if deleteAuthFlag != "" {
			runAuthSubcommands(deleteAuthFlag)
		}
		// file, _ := cmd.Flags().GetString("file")
		// jsonData, _ := cmd.Flags().GetString("json")
		// if file == "" && jsonData == "" {
		// 	log.Println("Error: Either --file or --json must be provided.")
		// 	return
		// }
		// if file != "" {
		// 	log.Printf("Loading document from file: %s\n", file)
		// 	// Add your function call here, e.g., WriteDocumentFromFile(file)
		// 	} else {
			// 		log.Printf("Writing document with data: %s\n", jsonData)
			// 		// Add your function call here, e.g., WriteDocumentFromJSON(jsonData)
		// 	}
		for _, apiKey := range config.ApiKeys {
			run.RunFirestoreDelete(apiKey)
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

	
func Init() {

	FirestoreCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")
	FirestoreCmd.PersistentFlags().StringVar(&authFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	// FirestoreCmd.Flags().StringVar(&rootAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")

	firestorereadCmd.Flags().StringVar(&readAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	firestorewriteCmd.Flags().StringVar(&uploadAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	firestoredeleteCmd.Flags().StringVar(&deleteAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	firestorereadCmd.Flags().String("document-id", "", "ID of the document to read")

	firestorewriteCmd.Flags().String("file", "", "Path to a file containing the document data")
	firestorewriteCmd.Flags().String("json", "", "Raw JSON data for the document")
	// firestorewriteCmd.MarkFlagsMutuallyExclusive("file","json")
	// firestorewriteCmd.MarkFlagsOneRequired("file","json")

	FirestoreCmd.AddCommand(firestorereadCmd, firestorewriteCmd, firestoredeleteCmd)

}