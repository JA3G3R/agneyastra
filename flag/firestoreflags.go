package flags

import (
	"log"

	"github.com/spf13/cobra"
)


var firestoreCmd = &cobra.Command{
	Use:   "firestore",
	Short: "Perform misconfiguration checks on Firestore",
	Long:  "Commands to test Firestore misconfigurations like read or write access.",
}

// Read Document Command
var firestorereadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read a Firestore document",
	Long:  "Checks if a Firestore document can be read using the provided document ID.",
	Run: func(cmd *cobra.Command, args []string) {
		docID, _ := cmd.Flags().GetString("document-id")
		if docID == "" {
			log.Println("Error: --document-id is required.")
			return
		}
		log.Printf("Attempting to read document with ID: %s\n", docID)
		// Add your function call here, e.g., ReadDocument(docID)
	},
}

// Write Document Command
var firestorewriteCmd = &cobra.Command{
	Use:   "write",
	Short: "Write a Firestore document",
	Long:  "Checks if a Firestore document can be written using the provided data.",
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		jsonData, _ := cmd.Flags().GetString("json")
		if file == "" && jsonData == "" {
			log.Println("Error: Either --file or --json must be provided.")
			return
		}
		if file != "" {
			log.Printf("Loading document from file: %s\n", file)
			// Add your function call here, e.g., WriteDocumentFromFile(file)
			} else {
				log.Printf("Writing document with data: %s\n", jsonData)
				// Add your function call here, e.g., WriteDocumentFromJSON(jsonData)
			}
		},
	}
	
	
	
	var firestoreAllCmd = &cobra.Command{
		Use:   "all",
		Short: "Check all Firestore misconfigurations",
		Run: func(cmd *cobra.Command, args []string) {
			if debug {
				log.Println("Debug: Checking all Firestore misconfigurations")
			}
			// Add logic for all Firestore checks
		},
	}
	
func init() {
	
	firestorereadCmd.Flags().String("document-id", "", "ID of the document to read")
	firestorereadCmd.MarkFlagRequired("document-id")
	firestorewriteCmd.Flags().String("file", "", "Path to a file containing the document data")
	firestorewriteCmd.Flags().String("json", "", "Raw JSON data for the document")
	firestoreCmd.AddCommand(firestorereadCmd, firestorewriteCmd, firestoreAllCmd)
}