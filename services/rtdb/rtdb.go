package rtdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func ReadFromRTDB(url string) bool {
    // Append /.json to the URL
    fullURL := fmt.Sprintf("%s/.json", url)

    // Make a GET request
    response, err := http.Get(fullURL)
    if err != nil {
        log.Printf("Error making request to %s: %v\n", fullURL, err)
        return false
    }
    defer response.Body.Close()

    // Check if the response status is 200 (OK)
    if response.StatusCode == http.StatusOK {
        body, _ := ioutil.ReadAll(response.Body)
        log.Printf("Potential Misconfiguration found at %s: %s\n", fullURL, body)
        return true
    }

    log.Printf("No misconfiguration at %s, Status: %d\n", fullURL, response.StatusCode)
    return false
}



func WriteToRTDB(rtdbURL, path string, data interface{}) bool {
	url := fmt.Sprintf("%s/%s.json", rtdbURL, path)
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error marshaling data:", err)
		return false
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		fmt.Println("Write succeeded")
		return true
	} else if resp.StatusCode == 401 {
		fmt.Println("Write failed: Permission denied")
		return false
	}
	
	fmt.Println("Unexpected status code:", resp.StatusCode)
	return false
}