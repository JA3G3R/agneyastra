package main

import (
	"flag"
	"fmt"
	"log"
	"github.com/JA3G3R/agneyastra/utils"
	"github.com/JA3G3R/agneyastra/services"
)



func main() {

	// Define the API key flag
	apiKey := flag.String("key", "", "Firebase project API key")
	flag.Parse()
	
	// Validate API key
	if *apiKey == "" {
		log.Fatal("API key is required. Use -key to provide the Firebase API key.")
	}
	
	// Step 1: Fetch the project config using the API key
	fmt.Println("Fetching project config...")
	projectConfig, err := getProjectConfig(*apiKey)
	fmt.Println("Got config!")
	fmt.Printf("Project ID: %s\n", projectConfig.ProjectID)
	fmt.Printf("Authorized Domains: %v\n\n", projectConfig.AuthorizedDomains)
	if err != nil {
		log.Fatalf("Error fetching project config: %v", err)
	}

	domains := ExtractDomainsForStorage(*projectConfig)

	// isVulnerable, sessionInfoAnonymousLogin, err := CheckAnonymousAuth(*apiKey)
	// if err != nil {
	// 	log.Fatalf("Error checking anonymous auth: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("Anonymous authentication is enabled and the project is vulnerable!\n")
	// 	fmt.Printf("Session Info: %+v\n", sessionInfoAnonymousLogin)
	// } else {
	// 	fmt.Println("Anonymous authentication is not enabled.\n")
	// }


	// email := "bhavarth1905kr@gmail.com"      // Replace with the email to be tested
	// password := "TestPassword123"        // Replace with the password to be tested

	// isVulnerable, sessionInfoEmailPassSignup, err := CheckEmailPasswordAuth(*apiKey, email, password)

	// if err != nil {
	// 	log.Fatalf("Error checking email/password auth: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("Email/Password authentication is enabled and the project is vulnerable!\n")
	// 	fmt.Printf("Session Info: %+v\n", sessionInfoEmailPassSignup)
	// } else {
	// 	fmt.Println("Email/Password authentication is not enabled.\n")
	// }

	// isVulnerable, responseInfoSendSignInLink, err := CheckSendSignInLink(*apiKey, email)
	// if err != nil {
	// 	log.Fatalf("Error checking SendSignInLink: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("SendSignInLink is enabled and the project is vulnerable!")
	// 	fmt.Printf("Response Info: %+v\n", responseInfoSendSignInLink)
	// } else {
	// 	fmt.Println("SendSignInLink is not enabled.")
	// }

	// isVulnerable, responseInfoSignInEmailPass, err := CheckSignInWithPassword(*apiKey, email, password)
	// if err != nil {
	// 	log.Fatalf("Error checking sign-in with email/password: %v", err)
	// }

	// if isVulnerable {
	// 	fmt.Println("Sign-in with email/password is enabled and the project is vulnerable!\n")
	// 	fmt.Printf("Response Info: %+v\n", responseInfoSignInEmailPass)
	// } else {
	// 	fmt.Println("Sign-in with email/password is not enabled.\n")
	// }

	// results, err := CheckFirebaseStorage(*apiKey, domains)
	// if err != nil {
	// 	log.Fatalf("Error checking Firebase storage: %v", err)
	// }

	// // Print the results
	// for _, result := range results {
	// 	fmt.Printf("Bucket: %s\n", result.Domain)
	// 	fmt.Printf("Prefixes (folders): %+v\n", result.Keys.Prefixes)
	// 	for _, item := range result.Keys.Items {
	// 		fmt.Printf("File: %s (Bucket: %s)\n", item.Name, item.Bucket)
	// 	}
	// 	fmt.Println()
	// }

	// resultsUpload := CheckFirebaseUpload(domains, *apiKey)

	// // Print the results
	// for _, result := range resultsUpload {
	// 	if result.Success {
	// 		fmt.Printf("Upload to bucket %s was successful.\n", result.Bucket)
	// 	} else {
	// 		fmt.Printf("Upload to bucket %s failed. Error: %s\n", result.Bucket, result.Error)
	// 	}
	// }
	// resultsDelete := CheckFirebaseDelete(domains, "poc.txt")

	// // Print the results
	// for _, result := range resultsDelete {
	// 	if result.Success {
	// 		fmt.Printf("File '%s' successfully deleted from bucket %s.\n", result.FileName, result.Bucket)
	// 	} else {
	// 		fmt.Printf("Failed to delete file '%s' from bucket %s. Error: %s\n", result.FileName, result.Bucket, result.Error)
	// 	}
	// }

	// isVulnerable, projectID := CheckFirestoreAddDocument(domains)
	// if isVulnerable {
	// 	fmt.Println("Firestore Write document POC successful!")
	// 	fmt.Printf("Project ID: %s\n", projectID)
	// } else {
	// 	fmt.Println("Firestore Write document POC failed.")
	// }

}	


