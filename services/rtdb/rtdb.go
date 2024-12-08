package rtdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/JA3G3R/agneyastra/pkg/config"
	"github.com/JA3G3R/agneyastra/pkg/credentials"
	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/utils"
)


func ReadFromRTDB(rtdbURLs map[string][]string, dump bool, apiKey string) []Result {
	var results []Result
	log.Printf("RTDB URLs: %v\n", rtdbURLs)
	for domain,urls := range rtdbURLs {
		credStore := credentials.GetCredentialStore()
		var authType string

		for _, url := range urls {
			for _, credType := range credentials.CredTypes {
				auth := credStore.GetToken(credType)
				if auth == "" && credType != "public" {
					continue
				}
				// if credType != "public" {
				// 	//log.Printf("Found token for authtype: %s\n", credType)
				// }
				authType = credType

				url := fmt.Sprintf("%s/.json", url)
				req, err := http.NewRequest("GET", url, nil)
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error creating request: %v", err), Body: nil})
					continue
				}

				req.Header.Set("Authorization", "Bearer "+auth)
				client := &http.Client{}
				log.Printf("Trying bucket read from url: %s, for projectid: %s, auth type: %s\n", url, domain, authType)
				resp, err := client.Do(req)
				log.Printf("Got response from url: %s, for projectid: %s, status_code: %d\n", url, domain, resp.StatusCode)
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error marshaling data: %v", err), Body: nil})
					continue
				}

				if resp.StatusCode == 200 {
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error reading response body: %v", err), Body: nil})
						continue
					}
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable, Error: fmt.Errorf(""), Body: body, AuthType: authType})
					if dump || config.Correlate || config.SecretsExtract {
						// Ensure the directories exist
						baseDir := "dump/rtdb"
						if err := os.MkdirAll(baseDir, 0755); err != nil {
							log.Printf("Error creating directories: %v", err)
							continue
						}

						// Generate the filepath for the dump file
						filepath := filepath.Join(baseDir, apiKey)// + "-" + domain + ".json")

						// Write the body to the file
						if err := os.WriteFile(filepath, body, 0644); err != nil {
							log.Printf("Error writing to file: %v", err)
							continue
						}

						log.Printf("Dumped data to file: %s", filepath)
					}
				
				} else if resp.StatusCode == 401 {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf(""), Body: nil})
				}
				
				// fmt.Println("Unexpected status code:", resp.StatusCode)
			}
		}
	}
	return results
}



func WriteToRTDB(rtdbURLs map[string][]string, data,filePath string) ([]Result, error) {

	var results []Result
	path := "agneyastrapoc"+utils.RandomString(6)
	var jsonData []byte
	var checkFormat map[string]interface{}

	if data == "" && filePath != "" {

		data = "{\"poc\": \"You are vulnerable to public write!}\"}"

	} else if data == "" && filePath != "" {
		jsonData, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("error reading file: %v", err)
		}
		err = json.Unmarshal(jsonData, &checkFormat)
		if err != nil {
			return nil, fmt.Errorf("error writing data from file(%s): %v", err)
		}
	}

	jsonData, err := json.Marshal([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("error marshaling data: %v", err)
	}
	credStore := credentials.GetCredentialStore()
	var authType string
	for domain,urls := range rtdbURLs {
		for _, url := range urls {
			for _, credType := range credentials.CredTypes {
				auth := credStore.GetToken(credType)
				if auth == "" && credType != "public" {
					continue
				}
				// if credType != "public" {
				// 	//log.Printf("Found token for authtype: %s\n", credType)
				// }
				authType = credType

				url := fmt.Sprintf("%s/%s.json", url, path)

				req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error creating request: %v", err)})
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+auth)
				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error making request: %v", err)})
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == 200 {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable, Error: fmt.Errorf(""), AuthType: authType})
				
				} else if resp.StatusCode == 401 {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf("")})
				}
				
			}
		}
		
	}
	return results,nil
}

func DeleteFromRTDB(rtdbURLs map[string][]string) []Result {

	var results []Result
	path := "agneyastrapoc"+utils.RandomString(6)
	credStore := credentials.GetCredentialStore()
	var authType string
	for domain,urls := range rtdbURLs {

		for _, url := range urls {
			for _, credType := range credentials.CredTypes {
				auth := credStore.GetToken(credType)
				if auth == "" && credType != "public" {
					continue
				}
				// if credType != "public" {
				// 	//log.Printf("Found token for authtype: %s\n", credType)
				// }
				authType = credType

				url := fmt.Sprintf("%s/%s.json", url, path)

				req, err := http.NewRequest("DELETE", url, nil)
				
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error creating request: %v", err)})
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Authorization", "Bearer "+auth)

				client := &http.Client{}
				resp, err := client.Do(req)
				if err != nil {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error making request: %v", err)})
					continue
				}
				defer resp.Body.Close()

				if resp.StatusCode == 200 || resp.StatusCode == 404 {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable,AuthType: authType, Error: fmt.Errorf(""), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
				
				} else if resp.StatusCode == 401 {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf(""), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
				} else {
					results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Unexpected status code: %d", resp.StatusCode), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
				}
			}
		}
		
	}
	return results
}