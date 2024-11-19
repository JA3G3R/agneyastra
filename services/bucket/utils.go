package bucket

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/JA3G3R/agneyastra/pkg/credentials"
	"github.com/JA3G3R/agneyastra/services"
)

func recursiveContentReadFromBucket(bucket string, prefix string, authType string, isVulnerable bool) (KeysResponseRecursive,bool,string, error) {
	url := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o?prefix=%s&delimiter=%%2F", bucket, prefix)
	req,err  := http.NewRequest("GET", url, nil)
	if err != nil {
		return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to create request: %w", err)
	}

	// Send GET request to the Firebase Storage API
	resp , err := http.DefaultClient.Do(req)
	if err != nil {
		return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to make request: %w",  err)
	}
	defer resp.Body.Close()

	// Handle non-200 status codes (e.g., 404)
	log.Printf("Bucket: %s, Prefix: %s, Status: %d", bucket, prefix, resp.StatusCode)
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		credentialStore := credentials.GetCredentialStore()
		for authTypeIdx := 0; authTypeIdx < len(credentials.CredTypes); authTypeIdx++ {

			cred := credentialStore.GetToken(credentials.CredTypes[authTypeIdx])
			req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cred))
			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to make request: %w", err)
			}
			if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
				continue
			} else if resp.StatusCode == http.StatusOK {
				isVulnerable = true
				authType = credentials.CredTypes[authTypeIdx]
				break
			}
		} 
		if !isVulnerable {
			return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to make request: %w", err)
		}
	} else if resp.StatusCode != http.StatusOK {
		return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("Unexpected response code: %w", err)
	}

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse JSON response
	var keys KeysResponse
	err = json.Unmarshal(body, &keys)
	if err != nil {
		return KeysResponseRecursive{},isVulnerable,authType, fmt.Errorf("failed to parse response JSON: %w", err)
	}
	recPrefix := make(map[string]KeysResponseRecursive)
	if keys.Prefixes == nil {
		return KeysResponseRecursive{Prefixes: nil, Items: keys.Items},isVulnerable,authType , nil
	}
	for _, respprefix := range keys.Prefixes {
		keysRec,_,_, err := recursiveContentReadFromBucket(bucket, respprefix, authType, isVulnerable)
		if err != nil {
			return KeysResponseRecursive{},isVulnerable,authType , err
		}
		recPrefix[respprefix] = keysRec
	}
	return KeysResponseRecursive{Prefixes: recPrefix, Items: keys.Items},isVulnerable,authType, nil
}

// downloadBucketContents downloads all the contents from a bucket into the parent folder.
func DownloadBucketContents(parentFolder string, bucketData []BucketData) error {
	// Create the parent folder if it doesn't exist
	if err := os.MkdirAll(parentFolder, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create parent folder: %v", err)
	}

	// Iterate through each BucketData
	for _, bucket := range bucketData {
		if bucket.Success == services.StatusVulnerable {
			// Create a folder for the bucket
			bucketFolder := filepath.Join(parentFolder, bucket.Bucket)
			if err := os.MkdirAll(bucketFolder, os.ModePerm); err != nil {
				return fmt.Errorf("failed to create bucket folder: %v", err)
			}

			// Recursively process prefixes and download items
			if err := processKeysRecursive(bucketFolder, bucket.Bucket, bucket.Data); err != nil {
				return fmt.Errorf("failed to process keys for bucket %s: %v", bucket.Bucket, err)
			}
		}
	}

	return nil
}

// processKeysRecursive processes the KeysResponseRecursive structure.
func processKeysRecursive(currentPath, bucketName string, keys KeysResponseRecursive) error {
	// Process items (files)
	for _, item := range keys.Items {
		filePath := filepath.Join(currentPath, item.Name)

		// Fetch the download URL for the file
		fileURL := getFirebaseFileURL(bucketName, item.Name)

		// Download the file
		if err := downloadFile(filePath, fileURL); err != nil {
			return fmt.Errorf("failed to download file %s: %v", item.Name, err)
		}
	}

	// Process prefixes (folders)
	for prefix, subKeys := range keys.Prefixes {
		subFolderPath := filepath.Join(currentPath, prefix)

		// Create the folder
		if err := os.MkdirAll(subFolderPath, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create folder %s: %v", subFolderPath, err)
		}

		// Recursively process the sub-folder
		if err := processKeysRecursive(subFolderPath, bucketName, subKeys); err != nil {
			return err
		}
	}

	return nil
}

// getFirebaseFileURL constructs the download URL for a file in Firebase Storage.
func getFirebaseFileURL(bucketName, fileName string) string {
	// Firebase Storage URL format
	encodedFileName := strings.ReplaceAll(fileName, " ", "%20") // Encoding spaces in the file name
	return fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o/%s?alt=media", bucketName, encodedFileName)
}

// downloadFile downloads a file from the given URL and saves it to the specified path.
func downloadFile(filePath, url string) error {
	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filePath, err)
	}
	defer out.Close()

	// Fetch the file from the URL
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch URL %s: %v", url, err)
	}
	defer resp.Body.Close()

	// Check for HTTP errors
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download file %s: HTTP %d", url, resp.StatusCode)
	}

	// Write the file content
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %v", filePath, err)
	}

	return nil
}