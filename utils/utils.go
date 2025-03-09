package utils

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	githubRawURL = "https://raw.githubusercontent.com/JA3G3R/agneyastra/main/config.yaml"
)

func downloadConfigFile() error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	configPath := filepath.Join(homeDir, ".agneyastra", "config.yaml")

	// Skip download if the file already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("Config file already exists at:", configPath)
		return nil
	}

	// Ensure the directory exists
	if err := os.MkdirAll(filepath.Dir(configPath), 0755); err != nil {
		return err
	}

	// Download file
	resp, err := http.Get(githubRawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Check for successful HTTP response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download config: HTTP %d", resp.StatusCode)
	}

	// Write the downloaded file to disk
	out, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	fmt.Println("Config file downloaded to:", configPath)
	return nil
}

func Init() {

	downloadConfigFile()

}

func ReadApiKeysFromFile(filePath string) ([]string, map[string][]string, error) {
	var apiKeys []string
	projectMap := make(map[string][]string)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			// Split the line by commas
			parts := strings.Split(line, ",")
			var res []string 
			for _, str := range parts { 
				if str != "" { 
					res = append(res, str) 
				} 
			}
			parts = res
			apiKey := strings.TrimSpace(parts[0]) // The first part is the API key

			// Append the API key to the list of keys
			apiKeys = append(apiKeys, apiKey)

			// If there are project IDs (i.e., more than one part)
			if len(parts) > 1 {
				projectIds := []string{}
				for i := 1; i < len(parts); i++ {
					projectId := strings.TrimSpace(parts[i])
					if projectId != "" {
						projectIds = append(projectIds, projectId)
					}
				}
				// Map the API key to the list of project IDs
				projectMap[apiKey] = projectIds
			} else {
				// If no project IDs are present, map the API key to an empty slice
				projectMap[apiKey] = []string{}
			}
		}
	}

	return apiKeys, projectMap, scanner.Err()
}

func GetProjectConfig(apiKey string) (*ProjectConfig, error) {
	
	url := fmt.Sprintf("https://www.googleapis.com/identitytoolkit/v3/relyingparty/getProjectConfig?key=%s", apiKey)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch project config, status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var projectConfig ProjectConfig
	err = json.Unmarshal(body, &projectConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}

	return &projectConfig, nil
}


func ExtractDomainsFromProjectConfig(config ProjectConfig) []string {
	domainSet := make(map[string]struct{}) // Use a map to track unique domains
	var domains []string

	// Add the projectId as the first element (unique by default)
	domainSet[config.ProjectID] = struct{}{}
	domains = append(domains, config.ProjectID)

	// Iterate over the authorized domains
	for _, domain := range config.AuthorizedDomains {
		// Check if the domain ends with "firebaseapp.com" or "web.app"
		if strings.HasSuffix(domain, ".firebaseapp.com") || strings.HasSuffix(domain, ".web.app") {
			// Extract the subdomain part (before ".firebaseapp.com" or ".web.app")
			parts := strings.Split(domain, ".")
			if len(parts) > 0 {
				subdomain := parts[0]
				// Add to the map if it is not already present
				if _, exists := domainSet[subdomain]; !exists {
					domainSet[subdomain] = struct{}{}
					domains = append(domains, subdomain)
				}
			}
		}
	}

	return domains
}


func LoadConfig(path string) (Config, error) {
    var config Config

    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(path)

    if err := viper.ReadInConfig(); err != nil {
        return config, fmt.Errorf("error reading config file: %w", err)
    }

    if err := viper.Unmarshal(&config); err != nil {
        return config, fmt.Errorf("error unmarshaling config: %w", err)
    }

    return config, nil
}

func RandomString(length int) string {

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)

	// Seed the random number generator
	rand.Seed(time.Now().UnixNano())

	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}