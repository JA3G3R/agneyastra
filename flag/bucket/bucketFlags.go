package bucket

import (
	"log"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allFlag bool

var BucketCmd = &cobra.Command{
	Use:   "bucket",
	Short: "Perform Storage Bucket misconfiguration checks",
	Long: `Bucket commands for identifying misconfigurations in read, write, and delete operations.`,
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

var bucketReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Check for public read access",
	Run: func(cmd *cobra.Command, args []string) {
		dumpDir, _ := cmd.Flags().GetString("dump")
		log.Printf("Checking public read access. Dump directory: %s\n", dumpDir)
		run.RunBucketRead(dumpDir)
	},
}

var bucketUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Check for public upload access",
	Run: func(cmd *cobra.Command, args []string) {
		file := viper.GetString("services.bucket.upload.filename")
		log.Printf("Uploading file: %s\n", file)
		run.RunBucketWrite(file)
	},
}

var bucketDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Check for public delete access",
	Run: func(cmd *cobra.Command, args []string) {
		log.Println("Checking public delete access")
		run.RunBucketDelete()
	},
}

func Init() {
	BucketCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")

	bucketReadCmd.Flags().String("dump", "", "Directory to dump files (optional)")
	
	bucketUploadCmd.Flags().String("file", "", "File to upload (required)")
	viper.BindPFlag("services.bucket.upload.filename", bucketUploadCmd.Flags().Lookup("file"))
	bucketUploadCmd.MarkFlagRequired("file")
	BucketCmd.AddCommand(bucketReadCmd, bucketUploadCmd, bucketDeleteCmd)
	
}
