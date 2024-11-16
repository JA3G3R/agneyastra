package bucket

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

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