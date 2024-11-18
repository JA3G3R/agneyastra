package auth

import (
	"log"

	"github.com/JA3G3R/agneyastra/cmd/run"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var allFlag bool


var AuthCmd = &cobra.Command{
	Use:   "auth",
	Short: "Perform Authentication misconfiguration checks",
	Long: `Authentication commands for identifying potential misconfigurations.
Subcommands include checks for anonymous authentication, sign-up issues, 
sign-in link handling, and custom token logins.`,
	Run: func(cmd *cobra.Command, args []string) {
		if allFlag || len(args) == 0 {
			log.Println("Checking all authentication methods for misconfigurations1")
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
		log.Println("Checking anonymous authentication misconfiguration...")
		run.AnonymousAuth(config.ApiKey)

	},
}


var signUpCmd = &cobra.Command{
	Use:   "sign-up",
	Short: "Check for sign-up misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		email := viper.GetString("services.auth.signup.email")
		password:= viper.GetString("services.auth.signup.password")
		log.Printf("Checking sign-up misconfiguration with email: %s, password: %s\n", email, password)
		run.SignUp(email, password, config.ApiKey)
	},
}

var sendSigninLinkCmd = &cobra.Command{
	Use:   "send-signin-link",
	Short: "Check for sign-in link misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		email:= viper.GetString("services.auth.send-link.email")
		log.Printf("Sending sign-in link to: %s\n", email)
		run.SendSignInLink(email, config.ApiKey)
	},
}

var customTokenLoginCmd = &cobra.Command{
	Use:   "custom-token-login",
	Short: "Check for custom token login misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		token, _ := cmd.Flags().GetString("token")
		log.Printf("Logging in with custom token: %s\n", token)
		run.CustomTokenLogin(token, config.ApiKey)
	},
}

var signInCmd = &cobra.Command{
	Use:  "sign-in",
	Short: "Check for sign-in with user defined credentials",
	Run: func(cmd *cobra.Command, args []string) {
		email := viper.GetString("services.auth.signin.email")
		password := viper.GetString("services.auth.signin.password")
		log.Printf("Signing in with email: %s, password: %s\n", email, password)
		run.SignIn(email, password, config.ApiKey)
	},
}

func Init() {
	
	AuthCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", true, "Check all services for misconfigurations")

	AuthCmd.AddCommand(anonAuthCmd, signUpCmd, sendSigninLinkCmd, customTokenLoginCmd)
	// AuthCmd.MarkFlagsMutuallyExclusive("anon-auth", "sign-up","send-signin-link","custom-token-login")
	
	signInCmd.Flags().String("email", "", "Email address for signing in")
	signInCmd.Flags().String("password", "", "Password for signing in")
	signInCmd.MarkFlagRequired("email")
	signInCmd.MarkFlagRequired("password")

	viper.BindPFlag("services.auth.signin.email", signInCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signin.password", signInCmd.Flags().Lookup("password"))

	signUpCmd.Flags().String("email", "", "Email address for signing up")
	signUpCmd.Flags().String("password", "", "Password for signing up")
	signUpCmd.MarkFlagRequired("email")
	signUpCmd.MarkFlagRequired("password")


	viper.BindPFlag("services.auth.signup.email", signUpCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signup.password", signUpCmd.Flags().Lookup("password"))

	sendSigninLinkCmd.Flags().String("email", "", "Email address to send the sign-in link to")
	sendSigninLinkCmd.MarkFlagRequired("email")

	viper.BindPFlag("services.auth.send-link.email", sendSigninLinkCmd.Flags().Lookup("email"))

	customTokenLoginCmd.Flags().String("token", "", "Custom token for login")
	customTokenLoginCmd.MarkFlagRequired("token")

	viper.BindPFlag("services.auth.custom-token.token", customTokenLoginCmd.Flags().Lookup("token"))

}
