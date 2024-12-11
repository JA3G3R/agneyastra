package run

import (
	"log"

	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/services/auth"
)


func AnonymousAuth(apiKey string, noReport bool) {
	var err_ string
	isVulnerable, sessionInfo, err := auth.AnonymousAuth(apiKey)
	if err != nil {
		err_ = err.Error()
	}
	if !noReport {
		if isVulnerable == "vulnerable:true" {
			report.GlobalReport.AddServiceReport(apiKey, "auth", "anon-auth", report.ServiceResult{
				Vulnerable: isVulnerable,
				Details: map[string]interface{}{
					"idToken": sessionInfo.IDToken,
					"refreshToken": sessionInfo.RefreshToken,
					"expiresIn": sessionInfo.ExpiresIn,
					"localId": sessionInfo.LocalID,
				},
				Error: err_,
				Remedy: services.Remedies["auth"]["anon"]["remedy"],
				VulnConfig : services.VulnConfigs["auth"]["anon"]["config"],
			}, map[string][]report.ServiceResult{},)
		} else {
			// log.Println("Anonymous auth is not enabled.")
			report.GlobalReport.AddServiceReport(apiKey, "auth", "anon-auth", report.ServiceResult{
				Vulnerable: isVulnerable,
				Error: err_,
				Remedy: "",
				VulnConfig : "",
			},	map[string][]report.ServiceResult{},
			)
		}
	}

}

func SignUp(email, password, apiKey string, noReport bool) {

	var err_ string
	isVulnerable, sessionInfo, err := auth.SignUp(apiKey, email, password)
	if err != nil {
		err_ = err.Error()
	}
	if !noReport {
		if isVulnerable == "vulnerable:true" {
			report.GlobalReport.AddServiceReport(apiKey,"auth", "signup", report.ServiceResult{
				Vulnerable: isVulnerable,
				Details:  map[string]interface{}{
					"idToken": sessionInfo.IDToken,
					"refreshToken": sessionInfo.RefreshToken,
					"expiresIn": sessionInfo.ExpiresIn,
					"localId": sessionInfo.LocalID,
					"email": sessionInfo.Email,
					"password": password,
				},
				Error: err_,
				Remedy:services.Remedies["auth"]["signup"]["remedy"],
				VulnConfig: services.VulnConfigs["auth"]["signup"]["config"],
			}, map[string][]report.ServiceResult{},)
		} else {
			report.GlobalReport.AddServiceReport(apiKey, "auth", "signup", report.ServiceResult{
				Vulnerable: isVulnerable,
				Error: err_,
				Remedy:  "",
				VulnConfig:   "",
			}, map[string][]report.ServiceResult{},)
		}
	}

}

func SendSignInLink(email, apiKey string, noReport bool) {
	var err_ string
	isVulnerable, sessionInfo, err := auth.SendSignInLink(apiKey, email)
	if err != nil {
		err_ = err.Error()
	}
	if !noReport {

		if isVulnerable == "vulnerable:true" {
			report.GlobalReport.AddServiceReport(apiKey, "auth", "send-signin-link", report.ServiceResult{
				Vulnerable: isVulnerable,
				Details: map[string]interface{}{
					"email": sessionInfo.Email,
				},
				Error: err_,
				Remedy:  services.Remedies["auth"]["send-signin-link"]["remedy"],
				VulnConfig:   services.VulnConfigs["auth"]["send-signin-link"]["config"],

			}, map[string][]report.ServiceResult{},)
		} else {
			log.Println("Send sign-in link is not enabled.")
			report.GlobalReport.AddServiceReport(apiKey, "auth", "send-signin-link", report.ServiceResult{
				Vulnerable: isVulnerable,
				Error: err_,
				Remedy:  "",
				VulnConfig:   "",

			}, map[string][]report.ServiceResult{},)
		}
	}
}

func CustomTokenLogin(token, apiKey string, noReport bool) {
	var err_ string
	isVulnerable, sessionInfo, err := auth.LoginWithCustomToken(apiKey, token)
	if err != nil {
		err_ = err.Error()
	}
	if !noReport {
		if isVulnerable == "vulnerable:true" {
			
			report.GlobalReport.AddServiceReport(apiKey, "auth", "custom-token-login", report.ServiceResult{
				Vulnerable: isVulnerable,
				Details: map[string]interface{}{
					"idToken": sessionInfo.IDToken,
					"refreshToken": sessionInfo.RefreshToken,
					"expiresIn": sessionInfo.ExpiresIn,
					"localId": sessionInfo.LocalID,
					
				},
				Error: err_,
				Remedy:  services.Remedies["auth"]["custom-token-login"]["remedy"],
				VulnConfig:   services.VulnConfigs["auth"]["custom-token-login"]["config"],

			}, map[string][]report.ServiceResult{},)
		} else {
			report.GlobalReport.AddServiceReport(apiKey, "auth", "custom-token-login", report.ServiceResult{
				Vulnerable: isVulnerable,
				Error: err_,
				Remedy:  "",
				VulnConfig:   "",
			}, map[string][]report.ServiceResult{},)
		}
	}

}

func SignIn(email, password, apiKey string) {
	
	_ , _, err := auth.SignInWithPassword(apiKey, email, password)

	if	err != nil {
		log.Printf("Error checking anonymous auth: %v", err)
	}

}
