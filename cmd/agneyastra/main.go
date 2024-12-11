package main

import (
	"fmt"
	"log"

	flags "github.com/JA3G3R/agneyastra/flag"
	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/correlation"
	"github.com/JA3G3R/agneyastra/pkg/report"
	"github.com/JA3G3R/agneyastra/pkg/secrets"
)

func main() {
	
	// fmt.Println("executing flags")
	flags.Execute()

	if config.Correlate {
		fmt.Println("Correlating data...")
		correlation.AddCorelationScore()
	}
	if config.SecretsExtract {
		fmt.Println("Extracting secrets...")
		secrets.ExtractSecrets()
	}
	finalReport, err := report.GlobalReport.ReportToJSON()
	if err != nil {
		log.Println("Error converting report to JSON: ", err)
		return
	}
	fmt.Printf("%v\n", finalReport)
	// fmt.Println("Generating HTML Report")
	err = report.GlobalReport.GenerateHTMLReport(config.ReportPath, config.TemplateFile)
	if err != nil {
		log.Println("Error generating HTML report: ", err)
		return
	}
	// Access the API Key
	// apiKey := flags.GetAPIKey()

	// var configFilePath string = ""
	// if *configFilePathArg == "" {s
	// 	configFilePath = "."
	// } else {
	// 	configFilePath = *configFilePathArg
	// }

	// Load the config file
	// config, err := utils.LoadConfig(configFilePath)
	// if err != nil {
	// 	fmt.Println("encountered error when reading config file: ",err)
	// }
	
	
	// // Step 1: Fetch the project config using the API key
	// fmt.Println("Fetching project config...")
	// projectConfig, err := utils.GetProjectConfig(apiKey)
	// fmt.Println("Got config!")
	// log.Printf("Project ID: %s\n", projectConfig.ProjectID)
	// log.Printf("Authorized Domains: %v\n\n", projectConfig.AuthorizedDomains)
	// if err != nil {
	// 	log.Fatalf("Error fetching project config: %v", err)
	// }

	// domains := utils.ExtractDomainsFromProjectConfig(*projectConfig)

	// // Firebase auth checks:
	// bearer_token :=  ""

	// isVulnerable2AnonAuth, sessionInfoAnonymousLogin, err := services.CheckAnonymousAuth(apiKey)
	// if err != nil {
	// 	log.Fatalf("Error checking anonymous auth: %v", err)
	// }

	// if isVulnerable2AnonAuth {
	// 	fmt.Println("Anonymous authentication is enabled and the project is vulnerable!\n")
	// 	bearer_token = sessionInfoAnonymousLogin.IDToken
	// 	log.Printf("Bearer token: %s\n", bearer_token)
	// } else {
	// 	fmt.Println("Anonymous authentication is not enabled.\n")
	// }

	// email := config.Services["auth"]["signin_email"]
	// emailStr, _ := email.(string)

	// password := config.Services["auth"]["signin_pass"]
	// passwordStr, _ := password.(string)

	// isVulnerable2SignUp, sessionInfoEmailPassSignup, err := services.SignUp(apiKey, emailStr, passwordStr)

	// if err != nil {
	// 	log.Fatalf("Error checking email/password auth: %v", err)
	// }

	// if isVulnerable2SignUp {
	// 	fmt.Println("New User signup is enabled and the project is vulnerable!\n")
	// 	bearer_token = sessionInfoEmailPassSignup.IDToken
	// 	log.Printf("Bearer token: %s\n", bearer_token)
	// } else {
	// 	fmt.Println("Email/Password authentication is not enabled.\n")
	// }

	// emailStr := ""
	// isVulnerable2SendSignInLink, responseInfoSendSignInLink, err := auth.SendSignInLink(apiKey, emailStr)
	// if err != nil {
	// 	log.Fatalf("Error checking SendSignInLink: %v", err)
	// }

	// if isVulnerable2SendSignInLink {
	// 	fmt.Println("SendSignInLink is enabled and the project is vulnerable!")
	// 	log.Printf("Response Info: %+v\n", responseInfoSendSignInLink)
	// } else {
	// 	fmt.Println("SendSignInLink is not enabled.")
	// }

	// What is this below, NOT A BUG

	// isVulnerable, responseInfoSignInEmailPass, err := services.CheckSignInWithPassword(apiKey, emailStr, passwordStr)
	// if err != nil {
	// 	log.Fatalf("Error checking sign-in with email/password: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("Sign-in with email/password is enabled and the project is vulnerable!\n")
	// 	log.Printf("Response Info: %+v\n", responseInfoSignInEmailPass)
	// } else {
	// 	fmt.Println("Sign-in with email/password is not enabled.\n")
	// }

	// Storage bucket checks
	// flags
	// -dump-bucket-data : reads all the folders,directories and subdirectories of the public bucket and dumps it to a file.

	// results := services.BucketRead(apiKey, domains)
	// if err != nil {
	// 	log.Fatalf("Error checking Firebase storage: %v", err)
	// }

	// for _, result := range results {
	// 	log.Printf("Bucket: %s\n", result.Bucket)
	// 	log.Printf("Bucket Data: %+v\n", result.Data)
	// }

	// resultsUpload := services.BucketUpload(domains, apiKey)

	// for _, result := range resultsUpload {
	// 	if result.Success {
	// 		log.Printf("Upload to bucket %s was successful.\n", result.Bucket)
	// 	} else {
	// 		log.Printf("Upload to bucket %s failed. Error: %s\n", result.Bucket, result.Error)
	// 	}
	// }
	// resultsDelete := services.BucketDelete(domains, "poc.txt")

	// for _, result := range resultsDelete {
	// 	if result.Success {
	// 		log.Printf("File '%s' successfully deleted from bucket %s.\n", result.FileName, result.Bucket)
	// 	} else {
	// 		log.Printf("Failed to delete file '%s' from bucket %s. Error: %s\n", result.FileName, result.Bucket, result.Error)
	// 	}
	// }

	// Firestore Checks

	// for _, domain := range domains {

	// 	log.Printf("Checking Firestore Write document for domain: %s\n", domain)
	// 	isVulnerable, documentDetails, err := services.FirestoreAddDocument(domain)
	// 	if err != nil {
	// 		log.Printf("Error checking Firestore Write document: %v", err)
	// 		continue
	// 	}
	// 	if isVulnerable {

	// 		log.Printf("Firestore Write document POC successful with document id: %s, content: %s\n", documentDetails.DocumentID, documentDetails.DocumentContent)

	// 	} else {
	// 		fmt.Println("Firestore Write document POC failed.")
	// 	}
	// }

	// for _, domain := range domains {
		
	// 	log.Printf("Checking Firestore Read document for domain: %s\n", domain)
	// 	isVulnerable, documentDetails, err := services.FirestoreReadDocument(domains, documentDetails.DocumentID)
	// 	if err != nil {
	// 		log.Printf("Error checking Firestore Read document: %v", err)
	// 		continue
	// 	}
	// 	if isVulnerable {

	// 		log.Printf("Firestore Read document POC successful with document id: %s, content: %s\n", documentDetails.DocumentID, documentDetails.DocumentContent)

	// 	} else {
	// 		fmt.Println("Firestore Read document POC failed.")
	// 	}
	// }


}	


