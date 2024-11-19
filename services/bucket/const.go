package bucket

import "github.com/JA3G3R/agneyastra/services"



type KeysResponse struct {
	Prefixes []string `json:"prefixes"`
	Items    []Item   `json:"items"`
}

type KeysResponseRecursive struct {
	Prefixes map[string]KeysResponseRecursive `json:"prefixes"`
	Items    []Item   `json:"items"`
}
// Struct to represent each item (file)
type Item struct {
	Name   string `json:"name"`
	Bucket string `json:"bucket"`
}

type UploadCheckResult struct {
	Bucket string
	Success services.Status
	Error error
	StatusCode string
	AuthType string
}

type BucketData struct {
	Bucket string
	AuthType string
	Success services.Status
	Error error
	Data   KeysResponseRecursive
}

type DeleteCheckResult struct {
	Bucket   string
	Success  services.Status
	Error    error
	FileName string
	StatusCode string
	AuthType string
}
