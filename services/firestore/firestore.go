package firestore

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/JA3G3R/agneyastra/pkg/credentials"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/utils"
)

func FirestoreAddDocument(projectIDs []string) []Result {
	// First Request
	var results []Result
	credStore := credentials.GetCredentialStore()
	var authType string
	for _, projectID := range projectIDs {
		for _, credType := range credentials.CredTypes {
			auth := credStore.GetToken(credType)
			if auth == "" && credType != "public" {
				continue
			}
			// if credType != "public" {
			// 	//log.Printf("Found token for authtype: %s\n", credType)
			// }
			authType = credType

			url1 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=33570&CVER=22&X-HTTP-Session-Id=gsessionid&zx=7dl3c7vkmrvq&t=1", projectID)

			data := "headers=X-Goog-Api-Client:gl-js/%20fire/11.0.0%0D%0AContent-Type:text/plain%0D%0AX-Firebase-GMPID:111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22:%22projects/" + projectID + "/databases/(default)%22%7D"

			req1, err := http.NewRequest("POST", url1, bytes.NewBuffer([]byte(data)))
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create first request: %v", err), Success: services.StatusError})
				continue
			}
			if auth != "" {

				req1.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}
			client := &http.Client{}
			resp1, err := client.Do(req1)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute first request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp1.Body.Close()
			body1, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to read response from first request: %v", err), Success: services.StatusError})
				// continue
			}
			gsessionid := resp1.Header.Get("x-http-session-id")
			// Extract SID from the first response
			sidRegex := regexp.MustCompile(`\["c","(.*?)",""`)
			matches := sidRegex.FindStringSubmatch(string(body1))
			if len(matches) < 2 {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to extract SID from response"), Success: services.StatusError})
				continue
			}

			sid := matches[1]
			// log.Printf("SID: %v\ngsessionid: %v\n", sid, gsessionid)

			// Second Request
			// url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?gsessionid=%s&VER=8&database=projects/%s/databases/(default)&RID=rpc&SID=%s&CI=0&TYPE=xmlhttp&zx=ijirluezcha5&t=1",gsessionid, projectID, sid)
			url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?gsessionid=%s&VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=rpc&SID=%s&AID=0&CI=0&TYPE=xmlhttp&zx=cs7qqy879ulh&t=1", gsessionid, projectID, sid)
			// log.Printf("URL2: %v\n", url2)CLEAR

			req2, err := http.NewRequest("GET", url2, nil)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create second request: %v", err), Success: services.StatusError})
				continue
			}
			if auth != "" {
				req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}

			badRequestRegex := regexp.MustCompile(`Error 400 \(Bad Request\)\!\!1`)
			// permissionDeniedRegex := regexp.MustCompile(`Missing or insufficient permissions`)
			permissionDeniedRegex := regexp.MustCompile(`Missing or insufficient permissions\.|Permission denied on resource|"status":"PERMISSION_DENIED"`)
			reStreamToken := regexp.MustCompile(`"streamToken":\s*"(.*?)"`)

			resp2, err := client.Do(req2)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute second request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp2.Body.Close()

			tokenChannel := make(chan string)
			permissionDeniedChannel := make(chan bool)
			badRequestChannel := make(chan bool)
			writeResultRegex := regexp.MustCompile(`"writeResults":`)
			var wg sync.WaitGroup

			// Start a goroutine to read the response body line by line
			wg.Add(1)
			go func() {
				defer wg.Done()
				timeout := time.After(15 * time.Second)
				scanner := bufio.NewScanner(resp2.Body)
				timedout := true
				foundToken := false
				permissionSent := false
				for {
					if timedout || permissionSent {
						break
					}
					select {
					case <-timeout:
						log.Printf("Timeout waiting for response data")
						permissionDeniedChannel <- true // fake permission denied
						permissionSent = true
						timedout = true
					default:
						if !scanner.Scan() {
							if !permissionSent {
								permissionDeniedChannel <- false
							}
							close(tokenChannel)
							close(badRequestChannel)
							return
						}
						line := scanner.Text()
						if !foundToken {

							matches := reStreamToken.FindStringSubmatch(line)
							if len(matches) > 1 {
								tokenChannel <- matches[1]
								foundToken = true // Send matched line to channel
							}
							matches = badRequestRegex.FindStringSubmatch(line)
							if len(matches) != 0 {
								badRequestChannel <- true
							}
						}
						// } else {
						matches = writeResultRegex.FindStringSubmatch(line)
						if len(matches) != 0 {
							permissionDeniedChannel <- false
							permissionSent = true
							break
						}
						matches = permissionDeniedRegex.FindStringSubmatch(line)
						if len(matches) != 0 {
							permissionDeniedChannel <- true
							permissionSent = true
							break
						}
						// }
					}
				}
				if !permissionSent {
					permissionDeniedChannel <- false
				}
				close(tokenChannel)
				close(badRequestChannel)
				// Close the channel when done
			}()
			var streamToken string


			select {

			case <-permissionDeniedChannel:
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
				log.Printf("Permission denied for project ID: %s with auth type: %s\n", projectID, authType)
				continue
			case token := <-tokenChannel:
				streamToken = token
				if streamToken == "" {
					log.Printf("Could not find the stream token continuing")
					results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("stream token not found in response"), Success: services.StatusError})
					continue
				}
			case <-badRequestChannel:
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("bad request error in 2nd request"), Success: services.StatusError})
				log.Printf("Bad request error in 2nd request for project ID: %s with auth type: %s\n", projectID, authType)
				continue
			}

			docID := "agneyastratestpoc" + utils.RandomString(6) // Replace with your random ID
			zxValue := "79no8op6xwvi"                            // Example zx value

			url := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&gsessionid=%s&SID=%s&RID=33571&AID=1&zx=%s&t=1", projectID, gsessionid, sid, zxValue)
			payload := utils.RandomString(10)
			data = fmt.Sprintf("count=1&ofs=1&req0___data__={\"streamToken\":\"%s\",\"writes\":[{\"update\":{\"name\":\"projects/%s/databases/(default)/documents/agneyastra/%s\",\"fields\":{\"poc\":{\"stringValue\":\"%s\"}}},\"currentDocument\":{\"exists\":false}}]}", streamToken, projectID, docID, payload)

			// fmt.Println("Data for 3rd request:", data)
			// Make the next request
			req3, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
			if err != nil {

				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error creating 3rd request: %s", err), Success: services.StatusError})
				continue
			}

			// Set headers
			req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req3.Header.Set("Accept", "*/*")
			if auth != "" {
				req3.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}
			resp, err := client.Do(req3)
			if err != nil {

				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error making 3rd request: %s", err), Success: services.StatusError})
				continue
			}

			if resp.StatusCode != 200 {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error in 3rd request, status code: %s\n", resp.StatusCode), Success: services.StatusError})
				continue
			}
			permissionDenied := <-permissionDeniedChannel
			close(permissionDeniedChannel)
			wg.Wait()
			if permissionDenied {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
				continue
			} else {

				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusVulnerable, AuthType: authType})
				break
			}
		}
	}
	return results
}

func FirestoreDeleteDocument(projectIDs []string) []Result {
	// First Request
	var results []Result
	credstore := credentials.GetCredentialStore()
	var authType string

	for _, projectID := range projectIDs {
		log.Printf("Processing project ID: %s\n", projectID)
		for _, credType := range credentials.CredTypes {
			log.Printf("Checking credential type: %s\n", credType)
			auth := credstore.GetToken(credType)
			if auth == "" && credType != "public" {
				continue
			}

			if credType != "public" {
				log.Printf("Found token for authtype: %s\n", credType)
			}

			authType = credType

			url1 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=33570&CVER=22&X-HTTP-Session-Id=gsessionid&zx=7dl3c7vkmrvq&t=1", projectID)
			data := "headers=X-Goog-Api-Client:gl-js/%20fire/11.0.0%0D%0AContent-Type:text/plain%0D%0AX-Firebase-GMPID:111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22:%22projects/" + projectID + "/databases/(default)%22%7D"

			req1, err := http.NewRequest("POST", url1, bytes.NewBuffer([]byte(data)))
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create first request: %v", err), Success: services.StatusError})
				continue
			}
			if auth != "" {
				req1.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}
			client := &http.Client{}

			resp1, err := client.Do(req1)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute first request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp1.Body.Close()
			body1, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to read response from first request: %v", err), Success: services.StatusError})
				continue
			}
			gsessionid := resp1.Header.Get("x-http-session-id")
			// Extract SID from the first response
			sidRegex := regexp.MustCompile(`\["c","(.*?)",""`)
			matches := sidRegex.FindStringSubmatch(string(body1))
			if len(matches) < 2 {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to extract SID from response"), Success: services.StatusError})
				continue
			}
			sid := matches[1]
			// log.Printf("SID: %v\ngsessionid: %v\n", sid, gsessionid)

			// Second Request
			url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?gsessionid=%s&VER=8&database=projects/%s/databases/(default)/test/&RID=rpc&SID=%s&CI=0&TYPE=xmlhttp&zx=ijirluezcha5&t=1", gsessionid, projectID, sid)

			req2, err := http.NewRequest("GET", url2, nil)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create second request: %v", err), Success: services.StatusError})
				continue
			}
			if auth != "" {
				req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}
			reStreamToken := regexp.MustCompile(`"streamToken":\s*"([^"]+)"`)
			// permissionDeniedRegex := regexp.MustCompile(`Missing or insufficient permissions\.`)
			permissionDeniedRegex := regexp.MustCompile(`Missing or insufficient permissions\.|Permission denied on resource|"status":"PERMISSION_DENIED"`)
			badRequestRegex := regexp.MustCompile(`Error 400 \(Bad Request\)\!\!1`)
			writeResultRegex := regexp.MustCompile(`"writeResults":`)
			resp2, err := client.Do(req2)

			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute second request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp2.Body.Close()
			tokenChannel := make(chan string)
			permissionDeniedChannel := make(chan bool)
			badRequestChannel := make(chan bool)
			var wg sync.WaitGroup
			permissionSent := false
			// Start a goroutine to read the response body line by line
			wg.Add(1)
			go func() {
				defer wg.Done()
				timeout := time.After(20 * time.Second)
				scanner := bufio.NewScanner(resp2.Body)
				timedout := false
				foundToken := false
				for {
					if timedout || permissionSent {
						break
					}
					select {
					case <-timeout:
						log.Printf("Timeout waiting for response data")
						permissionDeniedChannel <- true // fake permission denied
						permissionSent = true
						timedout = true
					default:
						if !scanner.Scan() {
							return
						}
						line := scanner.Text()
						// log.Printf("Line: %s\n", line)

						if !foundToken {

							matches := reStreamToken.FindStringSubmatch(line)
							if len(matches) > 1 {
								tokenChannel <- matches[1]
								foundToken = true // Send matched line to channel
							}
							matches = badRequestRegex.FindStringSubmatch(line)
							if len(matches) != 0 {
								badRequestChannel <- true
								break
							}
						}

						// } else {
						matches = writeResultRegex.FindStringSubmatch(line)
						if len(matches) != 0 {
							permissionDeniedChannel <- false
							permissionSent = true
							break
						}
						// log.Printf("Matching with permission denied regex: %s\n", line)
						matches = permissionDeniedRegex.FindStringSubmatch(line)
						log.Printf("Matches: %d\n", len(matches))
						if len(matches) != 0 {
							permissionDeniedChannel <- true
							permissionSent = true

						}
					}
				}

				close(tokenChannel)
				close(badRequestChannel)
				if !permissionSent {
					permissionDeniedChannel <- false
				}
			}()

			var streamToken string
			select {
			case <-permissionDeniedChannel:
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
				log.Printf("Permission denied for project ID: %s with auth type: %s\n", projectID, authType)
				continue
			case token := <-tokenChannel:
				streamToken = token
				if streamToken == "" {
					results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("stream token not found in response"), Success: services.StatusError})
					log.Printf("Could not find the stream token continuing")
					continue
				}
				log.Printf("Found stream token: %s\n", streamToken)

			case <-badRequestChannel:
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("bad request error in 2nd request"), Success: services.StatusError})
				continue
			}

			docID := "agneyastratestpoc" + utils.RandomString(6) // Replace with your random ID
			zxValue := "79no8op6xwvi"                            // Example zx value

			url := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Write/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&gsessionid=%s&SID=%s&RID=33571&AID=1&zx=%s&t=1", projectID, gsessionid, sid, zxValue)

			data = fmt.Sprintf("count=1&ofs=1&req0___data__={\"streamToken\":\"%s\",\"writes\":[{\"delete\":\"projects/%s/databases/(default)/documents/poc/%s\"}]}", streamToken, projectID, docID)

			// fmt.Println("Data for 3rd request:", data)
			// Make the next request
			req3, err := http.NewRequest("POST", url, bytes.NewBuffer([]byte(data)))
			if err != nil {

				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error creating 3rd request: %s", err), Success: services.StatusError})
				continue
			}

			// Set headers
			req3.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req3.Header.Set("Accept", "*/*")
			if auth != "" {
				req3.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}
			resp3, err := client.Do(req3)

			if err != nil {

				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error making 3rd request: %s", err), Success: services.StatusError})
				continue
			}
			if resp3.StatusCode != 200 {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("error in 3rd request, status code: %s\n", resp3.StatusCode), Success: services.StatusError})
				continue
			}
			permissionDenied := <-permissionDeniedChannel
			close(permissionDeniedChannel)
			wg.Wait()
			if permissionDenied {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
				continue
			} else {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusVulnerable, AuthType: authType})
				break
			}

		}
	}
	return results
}

func FirestoreReadDocument(projectIDs []string) []Result {
	// First Request
	var results []Result

	credStore := credentials.GetCredentialStore()
	log.Printf("Project IDs: %v\n", projectIDs)
	for _, projectID := range projectIDs {
		log.Printf("Processing project ID: %s\n", projectID)
		var auth string
		var authType string
		for _, credType := range credentials.CredTypes {
			log.Printf("Checking credential type: %s\n", credType)
			auth = credStore.GetToken(credType)
			if auth == "" && credType != "public" {
				continue
			}

			if credType != "public" {
				log.Printf("Found token for authtype: %s\n", credType)
			}

			authType = credType

			itemID := "agneyastratestpoc" + utils.RandomString(6)
			url1 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)%%2Ftest%%2F&RID=16781&CVER=22&X-HTTP-Session-Id=gsessionid&zx=rps0oi3uq7d3&t=1", projectID)

			data := "headers=X-Goog-Api-Client%3Agl-js%2F%20fire%2F11.0.0%0D%0AContent-Type%3Atext%2Fplain%0D%0AX-Firebase-GMPID%3A111%0D%0A&count=1&ofs=0&req0___data__=%7B%22database%22%3A%22projects%2F" + projectID + "%2Fdatabases%2F(default)%22%2C%22addTarget%22%3A%7B%22documents%22%3A%7B%22documents%22%3A%5B%22projects%2F" + projectID + "%2Fdatabases%2F(default)%2Fdocuments%2Fagneyastratest%2F" + itemID + "%22%5D%7D%2C%22targetId%22%3A2%7D%7D"

			req1, err := http.NewRequest("POST", url1, bytes.NewBuffer([]byte(data)))

			if auth != "" {
				req1.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}

			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create first request: %v", err), Success: services.StatusError})
				continue
			}

			client := &http.Client{}
			resp1, err := client.Do(req1)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute first request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp1.Body.Close()

			body1, err := ioutil.ReadAll(resp1.Body)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to read response from first request: %v", err), Success: services.StatusError})
				continue
			}
			gsessionid := resp1.Header.Get("x-http-session-id")
			// Extract SID from the first response
			sidRegex := regexp.MustCompile(`\["c","(.*?)",""`)
			matches := sidRegex.FindStringSubmatch(string(body1))
			if len(matches) < 2 {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to extract SID from response"), Success: services.StatusError})
				continue
			}
			sid := matches[1]
			log.Printf("SID: %v, gsessionid: %v\n", sid, gsessionid)

			// Second Request
			url2 := fmt.Sprintf("https://firestore.googleapis.com/google.firestore.v1.Firestore/Listen/channel?gsessionid=%s&VER=8&database=projects%%2F%s%%2Fdatabases%%2F(default)&RID=rpc&SID=%s&CI=0&TYPE=xmlhttp&zx=ijirluezcha5&t=1", gsessionid, projectID, sid)

			req2, err := http.NewRequest("GET", url2, nil)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to create second request: %v", err), Success: services.StatusError})
				continue
			}

			if auth != "" {
				req2.Header.Set("Authorization", fmt.Sprintf("Bearer %s", auth))
			}

			resp2, err := client.Do(req2)
			if err != nil {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("failed to execute second request: %v", err), Success: services.StatusError})
				continue
			}
			defer resp2.Body.Close()
			permissionDeniedRegex := regexp.MustCompile(`Missing or insufficient permissions\.|Permission denied on resource|"status":"PERMISSION_DENIED"`)
			badRequestRegex := regexp.MustCompile(`Error 400 \(Bad Request\)\!\!1`)
			scanner := bufio.NewScanner(resp2.Body)
			permissionDenied := false
			badRequest := false
			for scanner.Scan() {

				line := scanner.Text()
				permissionDeniedMatches := permissionDeniedRegex.FindStringSubmatch(line)
				if len(permissionDeniedMatches) != 0 {
					results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
					permissionDenied = true
					break
				}
				badRequestMatches := badRequestRegex.FindStringSubmatch(line)
				if len(badRequestMatches) != 0 {
					results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("bad request error in 2nd request"), Success: services.StatusError})
					badRequest = true
					break
				}

			}

			if permissionDenied {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusSafe})
				continue
			}

			if badRequest {
				results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf("bad request error in 2nd request"), Success: services.StatusError})
				continue
			}

			results = append(results, Result{ProjectId: projectID, Error: fmt.Errorf(""), Success: services.StatusVulnerable, AuthType: authType})
			break
		}

	}
	return results
}
