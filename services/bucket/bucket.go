package bucket

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/JA3G3R/agneyastra/pkg/credentials"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/utils"
)

// CheckFirebaseDelete tries to delete a file from a list of Firebase Storage buckets
func BucketDelete(buckets []string) []DeleteCheckResult {
	var results []DeleteCheckResult
	fileName := "agneyastradeletetest"+utils.RandomString(8)
	// Loop through each bucket		
	for _, bucket := range buckets {
		result := DeleteCheckResult{Bucket: bucket, FileName: fileName}

		// Construct the Firebase Storage API URL with the bucket name and file name
		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o/%s", bucket, fileName)

		// Create the HTTP DELETE request
		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("Request creation failed: %v", err)
			results = append(results, result)
			continue
		}

		// Execute the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("HTTP request failed: %v", err)
			results = append(results, result)
			continue
		}
		defer resp.Body.Close()

		// Read the response body
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Errorf("Failed to read response body: %v", err)
			results = append(results, result)
			continue
		}

		// Check if the delete was successful [NOT RELIABLE FOR A NON-EXISTENT PROJECT]
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
			result.Success = services.StatusVulnerable
		} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			credentialStore := credentials.GetCredentialStore()
			isVulnerable := false
			var authType string
			for authTypeIdx := 0; authTypeIdx < len(credentials.CredTypes); authTypeIdx++ {
				authType = credentials.CredTypes[authTypeIdx]
				cred := credentialStore.GetToken(authType)
				if cred != "" {
					req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cred))
				}
				resp, err = http.DefaultClient.Do(req)
				if err != nil || (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
					// log.Printf("Failed with auth type: %s, err: %v", authType, err)
					continue

				} else if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
					result.Success = services.StatusVulnerable
					result.Error = fmt.Errorf("")
					result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
					result.AuthType = authType
					isVulnerable = true
					break
				} else {
					result.Success = services.StatusUnknown
					result.Error = fmt.Errorf("", err)
					result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
				}
			}
			if !isVulnerable {
				result.Success = services.StatusSafe
				result.Error = fmt.Errorf("")
				result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
				result.AuthType = "public"
			} 
		} else {
			result.Success = services.StatusUnknown
			result.Error = fmt.Errorf("Status: %d, Response: %s", resp.StatusCode, string(respBody))
		}

		// Append the result to the list
		results = append(results, result)
	}

	return results
}



func BucketUpload(buckets []string, filePath string) ([]UploadCheckResult, error){

	var results []UploadCheckResult
	// Loop through each bucket
	for _, bucket := range buckets {
		result := UploadCheckResult{Bucket: bucket}

		// file, err := os.Open(filePath) // Open your file
		
		// defer file.Close()
		
		// //fetch the fileContent
		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?name=poc.txt", bucket)
		req, err := getBucketReq(filePath, url, "")
		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("Failed to read file: %v", err)
			results = append(results, result)
			continue
		}

		// Set the required headers
		// req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{}
		// Execute the request
		resp, err := client.Do(req)
		defer resp.Body.Close()
		if err != nil {	
			result.Success = services.StatusError
			result.Error = fmt.Errorf("HTTP request failed: %v", err)
			result.StatusCode = ""
			results = append(results, result)
			continue
		}

		// Check if the upload was successful
		if resp.StatusCode == http.StatusOK {
			result.Success = services.StatusVulnerable
			result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
			result.Error = fmt.Errorf("")
		} else if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
			credentialStore := credentials.GetCredentialStore()
			isVulnerable := false
			var authType string
			for authTypeIdx := 0; authTypeIdx < len(credentials.CredTypes); authTypeIdx++ {
				authType = credentials.CredTypes[authTypeIdx]
				cred := credentialStore.GetToken(authType) 
				req, err = getBucketReq(filePath, url, cred)
				if err != nil {	
					continue
				}
				resp, err = http.DefaultClient.Do(req)
				if err != nil || (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
					continue
				} else if resp.StatusCode == http.StatusOK {
					result.Success = services.StatusVulnerable
					result.Error = fmt.Errorf("")
					result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
					result.AuthType = authType
					isVulnerable = true
					err = nil
					break
				} else {
					_, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						log.Printf("Failed to read response body: %v", err)
					}
					// log.Printf("Response body: %s", string(respBody))
					result.Success = services.StatusUnknown
					result.Error = fmt.Errorf("", err)
					result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
				}
			}
			if !isVulnerable {
				result.Success = services.StatusSafe
				result.Error = fmt.Errorf("")
				result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
				result.AuthType = "public"
			} 
		} else {
			_, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				log.Printf("Failed to read response body: %v", err)
			}
			// log.Printf("Response body: %s", string(respBody))
			result.Success = services.StatusUnknown
			result.Error = fmt.Errorf("")
			result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
		}

		// Append the result to the list
		results = append(results, result)
	}

	return results, nil
}

// Function to check whether we can list files/folders in Firebase Storage bucket
func BucketRead(buckets []string) ([]BucketData) {

	var bucketResults []BucketData

	for _, bucket := range buckets {
		// fmt.Printf("Attempting to read bucket %s\n", bucket)
		bucketContents, vulnerable,authType, err := recursiveContentReadFromBucket(bucket, "","public", false)
		if vulnerable && err != nil {
			log.Printf("Error reading bucket %s: %v", bucket, err)
			bucketResults = append(bucketResults, BucketData{Bucket: bucket,AuthType: authType, Success: services.StatusError, Error: err, Data: KeysResponseRecursive{}})
			continue
		} else if vulnerable{
			bucketResults = append(bucketResults, BucketData{Bucket: bucket, AuthType: authType, Data: bucketContents,Success: services.StatusVulnerable, Error: fmt.Errorf("")})
		} else {
			bucketResults = append(bucketResults, BucketData{Bucket: bucket, AuthType: authType, Data: bucketContents,Success: services.StatusSafe, Error: fmt.Errorf("")})
		}
	}

	return bucketResults
}
