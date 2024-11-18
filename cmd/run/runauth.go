package run

import (
	"log"

	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services/auth"
)


func AnonymousAuth(apiKey string) {
	
	isVulnerable, sessionInfo, err := auth.AnonymousAuth(apiKey)
	if err != nil {
		log.Printf("Error checking anonymous auth: %v", err)
	}

	if isVulnerable {
		report.GlobalReport.AddServiceReport(apiKey, "auth", "anon-auth", map[string]any{
			"vulnerable": isVulnerable,
			"details": map[string]interface{}{
				"idToken": sessionInfo.IDToken,
				"refreshToken": sessionInfo.RefreshToken,
				"expiresIn": sessionInfo.ExpiresIn,
				"localId": sessionInfo.LocalID,
			},
		})
	} else {
		log.Println("Anonymous auth is not enabled.")
		report.GlobalReport.AddServiceReport(apiKey, "auth", "anon-auth", map[string]any{
			"vulnerable": isVulnerable,
		},	
		)
	}

}

func SignUp(email, password, apiKey string) {

	
	isVulnerable, sessionInfo, err := auth.SignUp(apiKey, email, password)

	if err != nil {
			log.Printf("Error checking new user sign up check: %v", err)
	}
	if isVulnerable {
		report.GlobalReport.AddServiceReport(apiKey,"auth", "signup", map[string]any{
			"vulnerable": isVulnerable,
			"details": map[string]interface{}{
				"idToken": sessionInfo.IDToken,
				"refreshToken": sessionInfo.RefreshToken,
				"expiresIn": sessionInfo.ExpiresIn,
				"localId": sessionInfo.LocalID,
				"email": sessionInfo.Email,
				"password": password,
			},
		})
	} else {
		log.Println("Sign-up is not enabled.")
		report.GlobalReport.AddServiceReport(apiKey, "auth", "signup", map[string]any{
			"vulnerable": isVulnerable,
		})
	}

}

func SendSignInLink(email, apiKey string) {
	
	isVulnerable, sessionInfo, err := auth.SendSignInLink(apiKey, email)

	if err != nil {
		log.Printf("Error checking send sign in link check: %v", err)
	}
	if isVulnerable {
		report.GlobalReport.AddServiceReport(apiKey, "auth", "send-signin-link", map[string]any{
			"vulnerable": isVulnerable,
			"details": map[string]interface{}{
				"email": sessionInfo.Email,
			},
		})
	} else {
		log.Println("Send sign-in link is not enabled.")
		report.GlobalReport.AddServiceReport(apiKey, "auth", "send-signin-link", map[string]any{
			"vulnerable": isVulnerable,
		})
	}
}

func CustomTokenLogin(token, apiKey string) {
	
	isVulnerable, sessionInfo, err := auth.LoginWithCustomToken(apiKey, token)

	if err != nil {
		log.Printf("Error checking custom token login check: %v", err)
	}
	if isVulnerable {
		
		report.GlobalReport.AddServiceReport(apiKey, "auth", "custom-token-login", map[string]any{
			"vulnerable": isVulnerable,
			"details": map[string]interface{}{
				"idToken": sessionInfo.IDToken,
				"refreshToken": sessionInfo.RefreshToken,
				"expiresIn": sessionInfo.ExpiresIn,
				"localId": sessionInfo.LocalID,
			},
		})
	} else {
		log.Println("Custom token login is not enabled.")
		report.GlobalReport.AddServiceReport(apiKey, "auth", "custom-token-login", map[string]any{
			"vulnerable": isVulnerable,
		})
	}
	

}

func SignIn(email, password, apiKey string) {
	
	_ , _, err := auth.SignInWithPassword(apiKey, email, password)

	if	err != nil {
		log.Printf("Error checking anonymous auth: %v", err)
	}

}
