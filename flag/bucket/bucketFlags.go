package bucket

import (
	"log"
	"os"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/JA3G3R/agneyastra/flag/auth"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allFlag bool
var authFlag string
var readAuthFlag string
var uploadAuthFlag string
var deleteAuthFlag string

var BucketCmd = &cobra.Command{
	Use:   "bucket",
	Short: "Perform Storage Bucket misconfiguration checks",
	Long: `Bucket commands for identifying misconfigurations in read, write, and delete operations.`,
	Run: func(cmd *cobra.Command, args []string) {
		if authFlag != "" {
			runAuthSubcommands(authFlag)
		}
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
		if readAuthFlag != "" {
			runAuthSubcommands(readAuthFlag)
		}
		dumpDir, _ := cmd.Flags().GetString("dump")
		log.Printf("Checking public read access. Dump directory: %s\n", dumpDir)
		for _, apiKey := range config.ApiKeys {
			run.RunBucketRead(dumpDir, apiKey)
		}
	},
}

var bucketUploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Check for public upload access",
	Run: func(cmd *cobra.Command, args []string) {
		if uploadAuthFlag != "" {
			runAuthSubcommands(uploadAuthFlag)
		}
		file := viper.GetString("services.bucket.upload.filename")
		log.Printf("Uploading file: %s\n", file)
		for _, apiKey := range config.ApiKeys {
			run.RunBucketWrite(file, apiKey)
		}

	},
}

var bucketDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Check for public delete access",
	Run: func(cmd *cobra.Command, args []string) {
		if deleteAuthFlag != "" {
			runAuthSubcommands(deleteAuthFlag)
		}
		log.Println("Checking public delete access")
		for _, apiKey := range config.ApiKeys {
			run.RunBucketDelete(apiKey)
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

	if authFlag == "all" {
		log.Println("Running all auth subcommands...")
		for name, cmd := range authCmdMap {
			log.Printf("Running subcommand: %s\n", name)
			cmd.Run(cmd, nil)
		}
	} else if cmd, exists := authCmdMap[authFlag]; exists {
		log.Printf("Running specific auth subcommand: %s\n", authFlag)
		cmd.Run(cmd, nil)
	} else {
		log.Printf("Invalid auth flag: %s. Valid options: all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in\n", authFlag)
		os.Exit(1)
	}
}

func Init() {

	BucketCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")
	BucketCmd.Flags().StringVar(&authFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	bucketReadCmd.Flags().String("dump", "", "Directory to dump files (optional)")
	bucketReadCmd.Flags().StringVar(&readAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	bucketUploadCmd.Flags().StringVar(&uploadAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	bucketDeleteCmd.Flags().StringVar(&deleteAuthFlag, "auth", "", "Run specific auth subcommand(s): [all, anon-auth, sign-up, send-signin-link, custom-token-login, sign-in]")
	bucketUploadCmd.Flags().String("file", "", "File to upload (required)")
	viper.BindPFlag("services.bucket.upload.filename", bucketUploadCmd.Flags().Lookup("file"))
	bucketUploadCmd.MarkFlagRequired("file")
	BucketCmd.AddCommand(bucketReadCmd, bucketUploadCmd, bucketDeleteCmd)
	
}
