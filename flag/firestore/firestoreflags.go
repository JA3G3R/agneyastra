package firestore

import (
	"log"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/spf13/cobra"
)

var allFlag bool

var FirestoreCmd = &cobra.Command{
	Use:   "firestore",
	Short: "Perform misconfiguration checks on Firestore",
	Long:  "Commands to test Firestore misconfigurations like read or write access.",
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

// Read Document Command
var firestorereadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read a Firestore document",
	Long:  "Checks if a Firestore document can be read using the provided document ID.",
	Run: func(cmd *cobra.Command, args []string) {
		// docID, _ := cmd.Flags().GetString("document-id")
		// if docID == "" {
		// 	log.Println("Error: --document-id is required.")
		// 	return
		// }
		// log.Printf("Attempting to read document with ID: %s\n", docID)
		// Add your function call here, e.g., ReadDocument(docID)
		run.RunFirestoreRead()
	},
}

// Write Document Command
var firestorewriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Write a Firestore document",
	Long:  "Checks if a Firestore document can be written using the provided data.",
	Run: func(cmd *cobra.Command, args []string) {
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
		run.RunFirestoreWrite()
	},
}

var firestoredeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete a Firestore document",
	Long:  "Checks if a Firestore document can be deleted using the provided data.",
	Run: func(cmd *cobra.Command, args []string) {
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
		run.RunFirestoreDelete()
	},
}
	

	
func Init() {
	FirestoreCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")

	firestorereadCmd.Flags().String("document-id", "", "ID of the document to read")

	firestorewriteCmd.Flags().String("file", "", "Path to a file containing the document data")
	firestorewriteCmd.Flags().String("json", "", "Raw JSON data for the document")
	// firestorewriteCmd.MarkFlagsMutuallyExclusive("file","json")
	// firestorewriteCmd.MarkFlagsOneRequired("file","json")

	FirestoreCmd.AddCommand(firestorereadCmd, firestorewriteCmd, firestoredeleteCmd)

}