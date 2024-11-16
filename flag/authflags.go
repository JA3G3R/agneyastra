package flags

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allFlag bool

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Perform Authentication misconfiguration checks",
	Long: `Authentication commands for identifying potential misconfigurations.
Subcommands include checks for anonymous authentication, sign-up issues, 
sign-in link handling, and custom token logins.`,
	Run: func(cmd *cobra.Command, args []string) {
		if allFlag {
			for _, subCmd := range cmd.Commands() {
				if subCmd.Run != nil {
					log.Printf("Running subcommand: %s", subCmd.Name())
                    subCmd.Run(subCmd, nil)
				}
			}
		}
	},
}

var anonAuthCmd = &cobra.Command{
	Use:   "anon-auth",
	Short: "Check for anonymous authentication misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Checking anonymous authentication misconfiguration...")
		
	},
}

var signUpCmd = &cobra.Command{
	Use:   "sign-up",
	Short: "Check for sign-up misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		fmt.Printf("Checking sign-up misconfiguration with email: %s, password: %s\n", email, password)
	},
}

var sendSigninLinkCmd = &cobra.Command{
	Use:   "send-signin-link",
	Short: "Check for sign-in link misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		email, _ := cmd.Flags().GetString("email")
		fmt.Printf("Sending sign-in link to: %s\n", email)
	},
}

var customTokenLoginCmd = &cobra.Command{
	Use:   "custom-token-login",
	Short: "Check for custom token login misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		token, _ := cmd.Flags().GetString("token")
		fmt.Printf("Logging in with custom token: %s\n", token)
	},
}

var signInCmd = &cobra.Command{
	Use:  "sign-in",
	Short: "Check for sign-in with user defined credentials",
	Run: func(cmd *cobra.Command, args []string) {
		email, _ := cmd.Flags().GetString("email")
		password, _ := cmd.Flags().GetString("password")
		fmt.Printf("Signing in with email: %s, password: %s\n", email, password)
	},
}

func init() {
	
	authCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")

	authCmd.AddCommand(anonAuthCmd, signUpCmd, sendSigninLinkCmd, customTokenLoginCmd)
	// authCmd.MarkFlagsMutuallyExclusive("anon-auth", "sign-up","send-signin-link","custom-token-login")
	
	signInCmd.Flags().String("email", "", "Email address for signing in")
	signInCmd.Flags().String("password", "", "Password for signing in")
	
	viper.BindPFlag("services.auth.signin.email", signInCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signin.password", signInCmd.Flags().Lookup("password"))

	signInCmd.MarkFlagRequired("email")
	signInCmd.MarkFlagRequired("password")

	signUpCmd.Flags().String("email", "", "Email address for signing up")
	signUpCmd.Flags().String("password", "", "Password for signing up")

	viper.BindPFlag("services.auth.signup.email", signUpCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signup.password", signUpCmd.Flags().Lookup("password"))

	signUpCmd.MarkFlagRequired("email")
	signUpCmd.MarkFlagRequired("password")

	sendSigninLinkCmd.Flags().String("email", "", "Email address to send the sign-in link to")

	viper.BindPFlag("services.auth.send-link.email", signUpCmd.Flags().Lookup("email"))

	sendSigninLinkCmd.MarkFlagRequired("email")

	customTokenLoginCmd.Flags().String("token", "", "Custom token for login")

	viper.BindPFlag("services.auth.custom-token.token", signUpCmd.Flags().Lookup("token"))

	customTokenLoginCmd.MarkFlagRequired("token")

	RootCmd.AddCommand(authCmd)
	RootCmd.MarkFlagsMutuallyExclusive("all", "auth")

}
