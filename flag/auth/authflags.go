package auth

import (
	"slices"

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
			// log.Println("Checking all authentication methods for misconfigurations1")
			for _, subCmd := range cmd.Commands() {
				if subCmd.Run != nil {
					// log.Printf("Running subcommand: %s", subCmd.Name())
					subCmd.Run(subCmd, nil)
				}
			}
		}
	},
}

var AnonAuthCmd = &cobra.Command{
	Use:   "anon-auth",
	Short: "Check for anonymous authentication misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		//check if no-report is found in args
		noReport := slices.Contains(args, "no-report")

		for _, apiKey := range config.ApiKeys {
			run.AnonymousAuth(apiKey, noReport)
		}
	},
}


var SignUpCmd = &cobra.Command{
	Use:   "sign-up",
	Short: "Check for sign-up misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		noReport := slices.Contains(args, "no-report")
		email := viper.GetString("services.auth.signup.email")
		password:= viper.GetString("services.auth.signup.password")
		for _, apiKey := range config.ApiKeys {
			run.SignUp(email, password, apiKey, noReport)
		}
		
	},
}

var SendSigninLinkCmd = &cobra.Command{
	Use:   "send-signin-link",
	Short: "Check for sign-in link misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		noReport := slices.Contains(args, "no-report")
		email:= viper.GetString("services.auth.send-link.email")
		// log.Printf("Sending sign-in link to: %s\n", email)
		for _, apiKey := range config.ApiKeys {
			run.SendSignInLink(email, apiKey, noReport)
		}

	},
}

var CustomTokenLoginCmd = &cobra.Command{
	Use:   "custom-token-login",
	Short: "Check for custom token login misconfiguration",
	Run: func(cmd *cobra.Command, args []string) {
		noReport := slices.Contains(args, "no-report")
		token, _ := cmd.Flags().GetString("token")
		// log.Printf("Logging in with custom token: %s\n", token)
		for _, apiKey := range config.ApiKeys {
			run.CustomTokenLogin(token, apiKey, noReport)
		}
	},
}

var SignInCmd = &cobra.Command{
	Use:  "sign-in",
	Short: "Check for sign-in with user defined credentials",
	Run: func(cmd *cobra.Command, args []string) {
		email := viper.GetString("services.auth.signin.email")
		password := viper.GetString("services.auth.signin.password")
		// log.Printf("Signing in with email: %s, password: %s\n", email, password)
		for _, apiKey := range config.ApiKeys {
			run.SignIn(email, password, apiKey)
		}
		
	},
}

func Init() {
	
	AuthCmd.PersistentFlags().BoolVarP(&allFlag, "all", "a", false, "Check all services for misconfigurations")

	AuthCmd.AddCommand(AnonAuthCmd, SignUpCmd, SendSigninLinkCmd, CustomTokenLoginCmd)
	// AuthCmd.MarkFlagsMutuallyExclusive("anon-auth", "sign-up","send-signin-link","custom-token-login")
	SignUpCmd.Flags().Bool("no-report", false, "Disable report generation")
	SendSigninLinkCmd.Flags().Bool("no-report", false, "Disable report generation")
	CustomTokenLoginCmd.Flags().Bool("no-report", false, "Disable report generation")
	AnonAuthCmd.Flags().Bool("no-report", false, "Disable report generation")

	if !viper.IsSet("services.auth.signin.email") {
		SignInCmd.Flags().String("email", "", "Email address for signing in")
		SignInCmd.MarkFlagRequired("email")
	}
	if !viper.IsSet("services.auth.signin.password") {
		SignInCmd.Flags().String("password", "", "Password for signing in")
		SignInCmd.MarkFlagRequired("password")
	}

	viper.BindPFlag("services.auth.signin.email", SignInCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signin.password", SignInCmd.Flags().Lookup("password"))

	if !viper.IsSet("services.auth.signup.email") {

		SignUpCmd.Flags().String("email", "", "Email address for signing in")
		SignUpCmd.MarkFlagRequired("email")
	}
	if !viper.IsSet("services.auth.signup.password") {

		SignUpCmd.Flags().String("password", "", "Password for signing in")
		SignUpCmd.MarkFlagRequired("password")
	}
	
	viper.BindPFlag("services.auth.signup.email", SignUpCmd.Flags().Lookup("email"))
	viper.BindPFlag("services.auth.signup.password", SignUpCmd.Flags().Lookup("password"))

	if !viper.IsSet("services.auth.send-link.email") {
		SendSigninLinkCmd.Flags().String("email", "", "Email address for signing in")
		SendSigninLinkCmd.MarkFlagRequired("email")
	}

	viper.BindPFlag("services.auth.send-link.email", SendSigninLinkCmd.Flags().Lookup("email"))

	if !viper.IsSet("services.auth.custom-token.email") {
		CustomTokenLoginCmd.Flags().String("email", "", "Email address for signing in")
		CustomTokenLoginCmd.MarkFlagRequired("email")
	}

	viper.BindPFlag("services.auth.custom-token.token", CustomTokenLoginCmd.Flags().Lookup("token"))

}
