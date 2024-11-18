package bucket

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

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

		// Check if the delete was successful
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
			result.Success = services.StatusVulnerable
		} else if resp.StatusCode == http.StatusForbidden {
			result.Success = services.StatusSafe
			result.Error = fmt.Errorf("Status: %d, Response: %s", resp.StatusCode, string(respBody))
		} else {
			result.Success = services.StatusUnknown
			result.Error = fmt.Errorf("Status: %d, Response: %s", resp.StatusCode, string(respBody))
		}

		// Append the result to the list
		results = append(results, result)
	}

	return results
}


// CheckFirebaseUpload tries to upload a file to a list of Firebase Storage buckets
func BucketUpload(buckets []string, filePath string) ([]UploadCheckResult, error){

	var results []UploadCheckResult
	fileContent, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file(%s): %v",filePath, err)
	}

	// Loop through each bucket
	for _, bucket := range buckets {
		result := UploadCheckResult{Bucket: bucket}

		// Construct the Firebase Storage API URL with the bucket name

		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?name=poc.txt", bucket)

		// Create the multipart message body
			body := fmt.Sprintf(`--00047502390770604039595222756427073
Content-Type: application/json; charset=utf-8

{"name":"uploads/textfile.txt","contentType":"application/octet-stream"}

--00047502390770604039595222756427073
Content-Type: application/octet-stream

%s

--00047502390770604039595222756427073--`, fileContent)

		// Create the HTTP request
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("Request creation failed: %v", err)
			result.StatusCode = ""
			results = append(results, result)
			continue
		}

		// Set the required headers
		req.Header.Set("Content-Type", "multipart/related; boundary=00047502390770604039595222756427073")
		req.Header.Set("x-goog-upload-protocol", "multipart")

		// Execute the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("HTTP request failed: %v", err)
			result.StatusCode = ""
			results = append(results, result)
			continue
		}
		defer resp.Body.Close()

		// Read the response
		// respBody, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			result.Success = services.StatusError
			result.Error = fmt.Errorf("Failed to read response body: %v", err)
			result.StatusCode = ""
			results = append(results, result)
			continue
		}

		// Check if the upload was successful
		if resp.StatusCode == http.StatusOK {
			result.Success = services.StatusVulnerable
			result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
			result.Error = fmt.Errorf("")
		} else if resp.StatusCode == http.StatusForbidden {
			result.Success = services.StatusSafe
			result.Error = fmt.Errorf("")
			result.StatusCode = fmt.Sprintf("%d", resp.StatusCode)
		} else {
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
		fmt.Printf("Attempting to read bucket %s\n", bucket)
		bucketContents, err := recursiveContentReadFromBucket(bucket, "")
		if err != nil {
			log.Printf("Error reading bucket %s: %v", bucket, err)
			bucketResults = append(bucketResults, BucketData{Bucket: bucket, Success: services.StatusError, Error: err, Data: KeysResponseRecursive{}})
			continue
		} else {
			bucketResults = append(bucketResults, BucketData{Bucket: bucket, Data: bucketContents,Success: services.StatusVulnerable, Error: fmt.Errorf("")})
		}
	}

	return bucketResults
}
