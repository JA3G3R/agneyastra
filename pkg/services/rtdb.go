package services

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/gorilla/websocket"
)

func CheckRTDBReadMisconfiguration(url string) bool {
    // Append /.json to the URL
    fullURL := fmt.Sprintf("%s/.json", url)

    // Make a GET request
    response, err := http.Get(fullURL)
    if err != nil {
        fmt.Printf("Error making request to %s: %v\n", fullURL, err)
        return false
    }
    defer response.Body.Close()

    // Check if the response status is 200 (OK)
    if response.StatusCode == http.StatusOK {
        body, _ := ioutil.ReadAll(response.Body)
        fmt.Printf("Potential Misconfiguration found at %s: %s\n", fullURL, body)
        return true
    }

    fmt.Printf("No misconfiguration at %s, Status: %d\n", fullURL, response.StatusCode)
    return false
}

func CheckFirebaseURLs(domains []string) []string {
    var urls []string
	var validUrls []string
    // Generate URLs with .firebaseio.com and -default-rtdb.firebaseio.com
    for _, domain := range domains {
        urls = append(urls, fmt.Sprintf("https://%s.firebaseio.com", domain))
        urls = append(urls, fmt.Sprintf("https://%s-default-rtdb.firebaseio.com", domain))
    }

    // Iterate over the URLs and check for misconfiguration
    for _, url := range urls {
        if CheckRTDBMisconfiguration(url){
			validUrls = append(validUrls, url)
		}
    }
	return validUrls
}

func WriteToFirebase(firebaseURL string,path string, data interface{}) bool {
    // Create a new WebSocket connection
    conn, _, err := websocket.DefaultDialer.Dial(firebaseURL, nil)
    if err != nil {
        log.Println("Error connecting to WebSocket:", err)
        return false
    }
    defer conn.Close()

    // Prepare the message for writing data
    message := Message{
        T: "d",
        D: Data{
            R: 2, // Request ID
            A: "p", // Action: put
            B: map[string]interface{}{
                "p": fmt.Sprintf("%s",path), // Path in the database
                "d": data, // Data to write
            },
        },
    }

    // Send the message as JSON
    err = conn.WriteJSON(message)
    if err != nil {
        log.Println("Error sending message:", err)
        return false
    }

    // Read the response from Firebase
    _, response, err := conn.ReadMessage()
    if err != nil {
        log.Println("Error reading response:", err)
        return false
    }

    // Check if the response indicates success or failure
    var respData map[string]interface{}
    if err := json.Unmarshal(response, &respData); err != nil {
        log.Println("Error unmarshalling response:", err)
        return false
    }

    // Check for success status in the response
    if respData["t"] == "d" {
        if respData["d"].(map[string]interface{})["b"].(map[string]interface{})["s"] == "ok" {
            fmt.Println("Data written successfully.")
            return true
        } else {
            // Handle specific error cases
            status := respData["d"].(map[string]interface{})["b"].(map[string]interface{})["s"]
            errorMsg := respData["d"].(map[string]interface{})["b"].(map[string]interface{})["d"]
            log.Printf("Failed to write data: %s - %s\n", status, errorMsg)
            return false
        }
    }

    log.Println("Unexpected response format:", string(response))
    return false
}
