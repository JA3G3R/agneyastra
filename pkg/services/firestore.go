package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"github.com/JA3G3R/agneyastra/utils"
)



func CheckFirestoreAddDocument(projectIDs []string) (bool, string) {
	// First Request

	for _, projectID := range projectIDs {
		url1 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=33570&CVER=22&X-HTTP-Session-Id=gsessionid&zx=7dl3c7vkmrvq&t=1", projectID)
		data := "headers=X-Goog-Api-Client:gl-js/%20fire/11.0.0%0D%0AContent-Type:text/plain%0D%0AX-Firebase-GMPID:111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22:%22projects/" + projectID + "/databases/(default)%22%7D"

		req1, err := http.NewRequest("POST", url1, bytes.NewBuffer([]byte(data)))
		if err != nil {
			// return false, fmt.Errorf("failed to create first request: %v", err)
			continue
		}
		client := &http.Client{}
		resp1, err := client.Do(req1)
		if err != nil {
			// return false, fmt.Errorf("failed to execute first request: %v", err)
			continue
		}
		defer resp1.Body.Close()

		body1, err := ioutil.ReadAll(resp1.Body)
		if err != nil {
			// return false, fmt.Errorf("failed to read first response body: %v", err)
			continue
		}
		gsessionid := resp1.Header.Get("x-http-session-id")
		// Extract SID from the first response
		sidRegex := regexp.MustCompile(`\["c","(.*?)",""`)
		matches := sidRegex.FindStringSubmatch(string(body1))
		if len(matches) < 2 {
			// return false, fmt.Errorf("failed to extract SID from response")
			continue
		}
		sid := matches[1]
		fmt.Printf("SID: %v\ngsessionid: %v\n", sid, gsessionid)

		// Second Request
		url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?gsessionid=%s&VER=8&database=projects/%s/databases/(default)&RID=rpc&SID=%s&CI=0&TYPE=xmlhttp&zx=ijirluezcha5&t=1",gsessionid, projectID, sid)

		req2, err := http.NewRequest("GET", url2, nil)
		if err != nil {
			// return false, fmt.Errorf("failed to create second request: %v", err)
			continue
		}

		resp2, err := client.Do(req2)
		if err != nil {
			// return false, fmt.Errorf("failed to execute second request: %v", err)
			continue
		}
		defer resp2.Body.Close()

		body2, err := ioutil.ReadAll(resp2.Body)
		if err != nil {
			// return false, fmt.Errorf("failed to read second response body: %v", err)
			continue
		}

		re := regexp.MustCompile(`"streamToken":\s*"(.*?)"`)
		match := re.FindStringSubmatch(string(body2))

		if len(match) < 2 {
			continue
			// return false, fmt.Errorf("streamToken not found in the response")
			// continue
		} 

		streamToken := match[1]
		fmt.Println("Extracted streamToken:", streamToken)

		randomID := "agneyastratestpoc"           // Replace with your random ID
		zxValue := "79no8op6xwvi"          // Example zx value

		url := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&gsessionid=%s&SID=%s&RID=33571&AID=1&zx=%s&t=1", projectID, gsessionid, sid, zxValue)

		data = fmt.Sprintf("count=1&ofs=1&req0___data__={\"streamToken\":\"%s\",\"writes\":[{\"update\":{\"name\":\"projects/%s/databases/(default)/documents/test/%s\",\"fields\":{\"poc\":{\"stringValue\":\"Firestore Write document POC\"}}},\"currentDocument\":{\"exists\":false}}]}", streamToken, projectID, randomID)

		// fmt.Println("Data for 3rd request:", data)
		// Make the next request
		req, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
		if err != nil {
			
			// return false, fmt.Errorf("Error creating 3rd request:", err)
			continue
		}

		// Set headers
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept", "*/*")

		resp, err := client.Do(req)
		if err != nil {
			
			// return false, fmt.Errorf("Error making 3rd request:", err)
			continue
		}
		defer resp.Body.Close()

		// Read and print the response body
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			
			// return false, fmt.Errorf("Error reading 3rd req response:", err)
			continue
		}
		if resp.StatusCode != 200 {	
			// return false, fmt.Errorf("Error in 3rd request: %s", body3)
			continue
		}
		return true, projectID
	}
	return false, ""
}

func CheckFirestoreReadDocument(projectIDs []string, itemID string) (bool, string) {
	// First Request

	for _, projectID := range projectIDs {
		url1 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=16781&CVER=22&X-HTTP-Session-Id=gsessionid&zx=rps0oi3uq7d3&t=1", projectID)
		data := "headers=X-Goog-Api-Client%3Agl-js%2F%20fire%2F11.0.0%0D%0AContent-Type%3Atext%2Fplain%0D%0AX-Firebase-GMPID%3A111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22%3A%22projects%2F"+projectID+"%2Fdatabases%2F(default)%22%2C%22addTarget%22%3A%7B%22documents%22%3A%7B%22documents%22%3A%5B%22projects%2F"+projectID+"%2Fdatabases%2F(default)%2Fdocuments%2Ftest%2F"+itenID+"%22%5D%7D%2C%22targetId%22%3A2%7D%7D"

		req1, err := http.NewRequest("POST", url1, bytes.NewBuffer([]byte(data)))
		if err != nil {
			// return false, fmt.Errorf("failed to create first request: %v", err)
			continue
		}
		client := &http.Client{}
		resp1, err := client.Do(req1)
		if err != nil {
			// return false, fmt.Errorf("failed to execute first request: %v", err)
			continue
		}
		defer resp1.Body.Close()

		body1, err := ioutil.ReadAll(resp1.Body)
		if err != nil {
			// return false, fmt.Errorf("failed to read first response body: %v", err)
			continue
		}
		gsessionid := resp1.Header.Get("x-http-session-id")
		// Extract SID from the first response
		sidRegex := regexp.MustCompile(`\["c","(.*?)",""`)
		matches := sidRegex.FindStringSubmatch(string(body1))
		if len(matches) < 2 {
			// return false, fmt.Errorf("failed to extract SID from response")
			continue
		}
		sid := matches[1]
		fmt.Printf("SID: %v\ngsessionid: %v\n", sid, gsessionid)

		// Second Request
		url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?gsessionid=%s&VER=8&database=projects/%s/databases/(default)&RID=rpc&SID=%s&CI=0&TYPE=xmlhttp&zx=ijirluezcha5&t=1",gsessionid, projectID, sid)

		req2, err := http.NewRequest("GET", url2, nil)
		if err != nil {
			// return false, fmt.Errorf("failed to create second request: %v", err)
			continue
		}

		resp2, err := client.Do(req2)
		if err != nil {
			// return false, fmt.Errorf("failed to execute second request: %v", err)
			continue
		}
		defer resp2.Body.Close()

		body2, err := ioutil.ReadAll(resp2.Body)
		if err != nil {
			// return false, fmt.Errorf("failed to read second response body: %v", err)
			continue
		}

		re := regexp.MustCompile(`(?s)\{.*?"documentChange":\s*\{.*?\}\s*\}`)

		matchedJSON := re.FindString(string(body2))

		if matchedJSON != "" {
			type DocumentChange struct {
				Document struct {
					Fields map[string]struct {
						StringValue string `json:"stringValue"`
					} `json:"fields"`
				} `json:"document"`
			}

			type Root struct {
				DocumentChange DocumentChange `json:"documentChange"`
			}
			// Unmarshal the JSON structure into the Root struct
			var root Root

			err := json.Unmarshal([]byte(matchedJSON), &root)
			if err != nil {
				fmt.Println("Error unmarshalling JSON:", err)
				continue
			}

			// Access the "fields" field and print it
			for key, value := range root.DocumentChange.Document.Fields {
				fmt.Printf("Field: %s, Value: %s\n", key, value.StringValue)
			}
			
		} else {
			fmt.Println("No matching JSON structure found")
		}
	}
	return false, ""
}