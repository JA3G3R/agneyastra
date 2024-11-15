package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

// CheckFirebaseDelete tries to delete a file from a list of Firebase Storage buckets
func BucketDelete(buckets []string, fileName string) []DeleteCheckResult {
	var results []DeleteCheckResult

	// Loop through each bucket
	for _, bucket := range buckets {
		result := DeleteCheckResult{Bucket: bucket, FileName: fileName}

		// Construct the Firebase Storage API URL with the bucket name and file name
		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o/%s", bucket, fileName)

		// Create the HTTP DELETE request
		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			result.Error = fmt.Sprintf("Request creation failed: %v", err)
			results = append(results, result)
			continue
		}

		// Execute the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			result.Error = fmt.Sprintf("HTTP request failed: %v", err)
			results = append(results, result)
			continue
		}
		defer resp.Body.Close()

		// Read the response body
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to read response body: %v", err)
			results = append(results, result)
			continue
		}

		// Check if the delete was successful
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
			result.Success = true
		} else {
			result.Success = false
			result.Error = fmt.Sprintf("Status: %d, Response: %s", resp.StatusCode, string(respBody))
		}

		// Append the result to the list
		results = append(results, result)
	}

	return results
}


// CheckFirebaseUpload tries to upload a file to a list of Firebase Storage buckets
func BucketUpload(buckets []string, apiKey string) []UploadCheckResult {

	var results []UploadCheckResult

	// Loop through each bucket
	for _, bucket := range buckets {
		result := UploadCheckResult{Bucket: bucket}

		// Construct the Firebase Storage API URL with the bucket name
		url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?name=poc.txt", bucket)

		// Create the multipart message body
		body := `--00047502390770604039595222756427073
Content-Type: application/json; charset=utf-8

{"name":"uploads/textfile.txt","contentType":"application/octet-stream"}

--00047502390770604039595222756427073
Content-Type: application/octet-stream

hello world

--00047502390770604039595222756427073--`

		// Create the HTTP request
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(body)))
		if err != nil {
			result.Error = fmt.Sprintf("Request creation failed: %v", err)
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
			result.Error = fmt.Sprintf("HTTP request failed: %v", err)
			results = append(results, result)
			continue
		}
		defer resp.Body.Close()

		// Read the response
		respBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			result.Error = fmt.Sprintf("Failed to read response body: %v", err)
			results = append(results, result)
			continue
		}

		// Check if the upload was successful
		if resp.StatusCode == http.StatusOK {
			result.Success = true
		} else {
			result.Success = false
			result.Error = fmt.Sprintf("Status: %d, Response: %s", resp.StatusCode, string(respBody))
		}

		// Append the result to the list
		results = append(results, result)
	}

	return results
}

func recursiveContentReadFromBucket(bucket string, prefix string) (KeysResponseRecursive, error) {
	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?prefix=%s&delimiter=%%2F", bucket, prefix)

	// Send GET request to the Firebase Storage API
	resp, err := http.Get(url)
	if err != nil {
		return KeysResponseRecursive{}, fmt.Errorf("failed to make request for bucket %s: %w", bucket, err)
	}
	defer resp.Body.Close()

	// Handle non-200 status codes (e.g., 404)
	if resp.StatusCode != http.StatusOK {
		return KeysResponseRecursive{}, fmt.Errorf("Bucket %s: received status code %d, skipping...", bucket, resp.StatusCode)
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return KeysResponseRecursive{}, fmt.Errorf("failed to read response body for bucket %s: %w", bucket, err)
	}

	// Parse JSON response
	var keys KeysResponse
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return KeysResponseRecursive{}, fmt.Errorf("failed to parse response JSON for bucket %s: %w", bucket, err)
	}
	recPrefix := make(map[string]KeysResponseRecursive)
	if keys.Prefixes == nil {
		return KeysResponseRecursive{Prefixes: nil, Items: keys.Items} , nil
	}
	for _, respprefix := range keys.Prefixes {
		keysRec, err := recursiveContentReadFromBucket(bucket, respprefix)
		if err != nil {
			log.Printf("Error reading prefix content for %s from bucket %s: %v",respprefix, bucket, err)
		}
		recPrefix[respprefix] = keysRec
	}
	return KeysResponseRecursive{Prefixes: recPrefix, Items: keys.Items}, nil
}


// Function to check whether we can list files/folders in Firebase Storage bucket
func BucketRead(apiKey string, buckets []string) []BucketData {
	
	var bucketResults []BucketData 
	for _, bucket := range buckets {
		bucketContents, err := recursiveContentReadFromBucket(bucket, "")
		if err != nil {
			log.Printf("Error reading bucket %s: %v", bucket, err)
			continue
		}
		bucketResults = append(bucketResults, BucketData{Bucket: bucket, Data: bucketContents})
	}

	return bucketResults
}
