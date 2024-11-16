package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

var bucketCmd = &cobra.Command{
	Use:   "bucket",
	Short: "Perform Storage Bucket misconfiguration checks",
	Long: `Bucket commands for identifying misconfigurations in read, write, and delete operations.`,
}

var bucketReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Check for public read access",
	Run: func(cmd *cobra.Command, args []string) {
		dumpDir, _ := cmd.Flags().GetString("dump")
		fmt.Printf("Checking public read access. Dump directory: %s\n", dumpDir)
	},
}

var bucketUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Check for public upload access",
	Run: func(cmd *cobra.Command, args []string) {
		file, _ := cmd.Flags().GetString("file")
		fmt.Printf("Uploading file: %s\n", file)
	},
}

var bucketDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Check for public delete access",
	Run: func(cmd *cobra.Command, args []string) {
		filename, _ := cmd.Flags().GetString("filename")
		fmt.Printf("Deleting file: %s\n", filename)
	},
}

func init() {
	bucketCmd.AddCommand(bucketReadCmd, bucketUploadCmd, bucketDeleteCmd)
	
	bucketReadCmd.Flags().String("dump", "", "Directory to dump files (optional)")

	bucketUploadCmd.Flags().String("file", "", "File to upload (required)")
	bucketUploadCmd.MarkFlagRequired("file")

	bucketDeleteCmd.Flags().String("filename", "", "Filename to delete (required)")
	bucketDeleteCmd.MarkFlagRequired("filename")

	RootCmd.AddCommand(bucketCmd)
	
}
