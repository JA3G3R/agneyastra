package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/JA3G3R/agneyastra/pkg/services"
	"github.com/JA3G3R/agneyastra/utils"
	"github.com/JA3G3R/agneyastra/flags"
)

func main() {

	// Define the API key flag
	apiKey := flag.String("key", "", "Firebase project API key")
	// configFilePathArg := flag.String("config", "", "Path to the config file")
	flag.Parse()
	
	// Validate API key
	if *apiKey == "" {
		log.Fatal("API key is required. Use -key to provide the Firebase API key.")
	}

	// var configFilePath string = ""
	// if *configFilePathArg == "" {
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
	fmt.Println("Fetching project config...")
	projectConfig, err := utils.GetProjectConfig(*apiKey)
	fmt.Println("Got config!")
	fmt.Printf("Project ID: %s\n", projectConfig.ProjectID)
	fmt.Printf("Authorized Domains: %v\n\n", projectConfig.AuthorizedDomains)
	if err != nil {
		log.Fatalf("Error fetching project config: %v", err)
	}

	domains := utils.ExtractDomainsForStorage(*projectConfig)

	// // Firebase auth checks:
	// bearer_token :=  ""

	// isVulnerable2AnonAuth, sessionInfoAnonymousLogin, err := services.CheckAnonymousAuth(*apiKey)
	// if err != nil {
	// 	log.Fatalf("Error checking anonymous auth: %v", err)
	// }

	// if isVulnerable2AnonAuth {
	// 	fmt.Println("Anonymous authentication is enabled and the project is vulnerable!\n")
	// 	bearer_token = sessionInfoAnonymousLogin.IDToken
	// 	fmt.Printf("Bearer token: %s\n", bearer_token)
	// } else {
	// 	fmt.Println("Anonymous authentication is not enabled.\n")
	// }

	// email := config.Services["auth"]["signin_email"]
	// emailStr, _ := email.(string)

	// password := config.Services["auth"]["signin_pass"]
	// passwordStr, _ := password.(string)

	// isVulnerable2SignUp, sessionInfoEmailPassSignup, err := services.SignUp(*apiKey, emailStr, passwordStr)

	// if err != nil {
	// 	log.Fatalf("Error checking email/password auth: %v", err)
	// }

	// if isVulnerable2SignUp {
	// 	fmt.Println("New User signup is enabled and the project is vulnerable!\n")
	// 	bearer_token = sessionInfoEmailPassSignup.IDToken
	// 	fmt.Printf("Bearer token: %s\n", bearer_token)
	// } else {
	// 	fmt.Println("Email/Password authentication is not enabled.\n")
	// }

	
	// isVulnerable2SendSignInLink, responseInfoSendSignInLink, err := services.CheckSendSignInLink(*apiKey, emailStr)
	// if err != nil {
	// 	log.Fatalf("Error checking SendSignInLink: %v", err)
	// }

	// if isVulnerable2SendSignInLink {
	// 	fmt.Println("SendSignInLink is enabled and the project is vulnerable!")
	// 	fmt.Printf("Response Info: %+v\n", responseInfoSendSignInLink)
	// } else {
	// 	fmt.Println("SendSignInLink is not enabled.")
	// }

	// What is this below, NOT A BUG

	// isVulnerable, responseInfoSignInEmailPass, err := services.CheckSignInWithPassword(*apiKey, emailStr, passwordStr)
	// if err != nil {
	// 	log.Fatalf("Error checking sign-in with email/password: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("Sign-in with email/password is enabled and the project is vulnerable!\n")
	// 	fmt.Printf("Response Info: %+v\n", responseInfoSignInEmailPass)
	// } else {
	// 	fmt.Println("Sign-in with email/password is not enabled.\n")
	// }

	// Storage bucket checks
	// flags
	// -dump-bucket-data : reads all the folders,directories and subdirectories of the public bucket and dumps it to a file.

	results := services.BucketRead(*apiKey, domains)
	if err != nil {
		log.Fatalf("Error checking Firebase storage: %v", err)
	}

	for _, result := range results {
		fmt.Printf("Bucket: %s\n", result.Bucket)
		fmt.Printf("Bucket Data: %+v\n", result.Data)
	}

	// resultsUpload := services.BucketUpload(domains, *apiKey)

	// for _, result := range resultsUpload {
	// 	if result.Success {
	// 		fmt.Printf("Upload to bucket %s was successful.\n", result.Bucket)
	// 	} else {
	// 		fmt.Printf("Upload to bucket %s failed. Error: %s\n", result.Bucket, result.Error)
	// 	}
	// }
	// resultsDelete := services.BucketDelete(domains, "poc.txt")

	// for _, result := range resultsDelete {
	// 	if result.Success {
	// 		fmt.Printf("File '%s' successfully deleted from bucket %s.\n", result.FileName, result.Bucket)
	// 	} else {
	// 		fmt.Printf("Failed to delete file '%s' from bucket %s. Error: %s\n", result.FileName, result.Bucket, result.Error)
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

	// 		fmt.Printf("Firestore Write document POC successful with document id: %s, content: %s\n", documentDetails.DocumentID, documentDetails.DocumentContent)

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

	// 		fmt.Printf("Firestore Read document POC successful with document id: %s, content: %s\n", documentDetails.DocumentID, documentDetails.DocumentContent)

	// 	} else {
	// 		fmt.Println("Firestore Read document POC failed.")
	// 	}
	// }


}	

