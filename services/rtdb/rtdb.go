package rtdb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/JA3G3R/agneyastra/services"
	"github.com/JA3G3R/agneyastra/utils"
)


func ReadFromRTDB(rtdbURLs map[string][]string, filepath string) []Result {

	var results []Result
	for domain,urls := range rtdbURLs {

		for _, url := range urls {
			url := fmt.Sprintf("%s/.json", url)
			resp, err := http.Get(url)
			if err != nil {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error marshaling data: %v", err), Body: nil})
				continue
			}

			if resp.StatusCode == 200 {
				body, err := ioutil.ReadAll(resp.Body)
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable, Error: fmt.Errorf(""), Body: body})
				if filepath != "" {
					if err != nil {
						log.Printf("Error reading response body: %v", err)
					}
					err = os.WriteFile(filepath, body, 0644)
					if err != nil {
						log.Printf("Error writing to file: %v", err)
					}
				}
			
			} else if resp.StatusCode == 401 {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf(""), Body: nil})
			}
			
			fmt.Println("Unexpected status code:", resp.StatusCode)
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
	for domain,urls := range rtdbURLs {

		for _, url := range urls {
			url := fmt.Sprintf("%s/%s.json", url, path)

			req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
			if err != nil {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error creating request: %v", err)})
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error making request: %v", err)})
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable, Error: fmt.Errorf("")})
			
			} else if resp.StatusCode == 401 {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf("")})
			}
			
			fmt.Println("Unexpected status code:", resp.StatusCode)
		}
		
	}
	return results,nil
}

func DeleteFromRTDB(rtdbURLs map[string][]string) []Result {

	var results []Result
	path := "agneyastrapoc"+utils.RandomString(6)
	for domain,urls := range rtdbURLs {

		for _, url := range urls {
			url := fmt.Sprintf("%s/%s.json", url, path)

			req, err := http.NewRequest("DELETE", url, nil)
			if err != nil {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error creating request: %v", err)})
				continue
			}
			req.Header.Set("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Error making request: %v", err)})
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode == 200 || resp.StatusCode == 404 {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusVulnerable, Error: fmt.Errorf(""), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
			
			} else if resp.StatusCode == 401 {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusSafe,Error: fmt.Errorf(""), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
			} else {
				results = append(results, Result{ProjectId: domain,RTDBUrl: url, Success: services.StatusError,Error: fmt.Errorf("Unexpected status code: %d", resp.StatusCode), StatusCode: fmt.Sprintf("%d", resp.StatusCode)})
			}

		}
		
	}
	return results
}