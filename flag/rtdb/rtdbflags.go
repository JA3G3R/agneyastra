package rtdb

import (
	"log"

	"github.com/spf13/cobra"
)


var RtdbCmd = &cobra.Command{
	Use:   "rtdb",	
	Short: "Perform misconfiguration checks on Firebase Realtime Database",
	Long:  "Commands to test Firebase Realtime Database misconfigurations like read or write access.",
}

// Read Command
var rtdbreadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read data from Firebase RTDB",
	Long:  "Checks if the Firebase Realtime Database allows unrestricted reading of its data.",
	Run: func(cmd *cobra.Command, args []string) {
		dump, _ := cmd.Flags().GetBool("dump")
		file, _ := cmd.Flags().GetString("file")
		if dump && file == "" {
			log.Println("Error: --file must be specified when using --dump.")
			return
		}
		if dump {
			log.Printf("Dumping database contents to file: %s\n", file)
			// Add your function call here, e.g., DumpRTDB(file)
		} else {
			log.Println("Reading database contents...")
			// Add your function call here, e.g., ReadRTDB()
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
		if file == "" && jsonData == "" {
			log.Println("Error: Either --file or --json must be provided.")
			return
		}
		if file != "" {
			log.Printf("Loading data from file: %s\n", file)
			// Add your function call here, e.g., WriteRTDBFromFile(file)
		} else {
			log.Printf("Writing data with JSON: %s\n", jsonData)
			// Add your function call here, e.g., WriteRTDBFromJSON(jsonData)
		}
	},
}


var rtdbAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Check all RTDB misconfigurations",
	Run: func(cmd *cobra.Command, args []string) {
		if debug {
			log.Println("Debug: Checking all RTDB misconfigurations")
		}
		// Add logic for all RTDB checks
	},
}


func init(){
	log.Println("RTDB flags initialized")
	rtdbwriteCmd.Flags().String("file", "", "Path to a file containing the data to write")
	rtdbwriteCmd.Flags().String("json", "", "Raw JSON data to write")
	rtdbwriteCmd.MarkFlagsMutuallyExclusive("json", "file")
	rtdbwriteCmd.MarkFlagsOneRequired("json", "file")

	rtdbreadCmd.Flags().Bool("dump", false, "Dump the contents of the database to a file")
	rtdbreadCmd.Flags().String("file", "", "Path to the file to dump database contents into")
	rtdbreadCmd.MarkFlagsRequiredTogether("file", "dump")

	RtdbCmd.AddCommand(rtdbreadCmd, rtdbwriteCmd, rtdbAllCmd)
}
