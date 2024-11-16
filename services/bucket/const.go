package bucket

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
	Success bool
	Error string
}

type BucketData struct {
	Bucket string
	Data   KeysResponseRecursive
}

type DeleteCheckResult struct {
	Bucket   string
	Success  bool
	Error    string
	FileName string
}
